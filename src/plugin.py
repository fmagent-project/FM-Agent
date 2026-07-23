"""FM-Agent plugin loading and Python hook validation."""

import importlib.util
import inspect
import json
from dataclasses import dataclass, field
from pathlib import Path
from types import ModuleType
from typing import Callable, Dict, List, Optional, get_type_hints


@dataclass
class PluginStageConfig:
    """Configuration and resolved Python hooks for one pipeline stage."""

    type: str = ""  # "pass", "replace", or "modify"
    replace_function: Optional[str] = None
    input_function: Optional[str] = None
    output_function: Optional[str] = None
    replace_hook: Optional[Callable] = field(default=None, repr=False)
    input_hook: Optional[Callable] = field(default=None, repr=False)
    output_hook: Optional[Callable] = field(default=None, repr=False)

    @staticmethod
    def from_dict(data: dict) -> "PluginStageConfig":
        return PluginStageConfig(
            type=data.get("type", ""),
            replace_function=data.get("replace_function"),
            input_function=data.get("input_function"),
            output_function=data.get("output_function"),
        )

    def validated(self) -> List[str]:
        """Return configuration errors before resolving Python functions."""
        errors = []
        if self.type not in ("pass", "replace", "modify"):
            errors.append(
                "stage type must be 'pass', 'replace', or 'modify', "
                f"got '{self.type}'"
            )
            return errors

        function_fields = {
            "replace_function": self.replace_function,
            "input_function": self.input_function,
            "output_function": self.output_function,
        }
        for field_name, function_name in function_fields.items():
            if function_name is not None and (
                not isinstance(function_name, str) or not function_name.strip()
            ):
                errors.append(f"'{field_name}' must be a non-empty string")

        if errors:
            return errors

        if self.type == "pass":
            declared = [
                name for name, value in function_fields.items() if value is not None
            ]
            if declared:
                errors.append(
                    "type=pass cannot declare Python functions: "
                    + ", ".join(declared)
                )
        elif self.type == "replace":
            if not self.replace_function:
                errors.append("type=replace requires 'replace_function'")
            if self.input_function or self.output_function:
                errors.append(
                    "type=replace cannot declare "
                    "'input_function' or 'output_function'"
                )
        elif self.type == "modify":
            if self.replace_function:
                errors.append("type=modify cannot declare 'replace_function'")
            if not self.input_function and not self.output_function:
                errors.append(
                    "type=modify requires at least one of "
                    "'input_function' or 'output_function'"
                )

        return errors


@dataclass
class PluginConfig:
    """Parsed plugin.json with resolved plugin root path and stage hooks."""

    name: str
    version: str
    root: Path
    stages: Dict[str, PluginStageConfig] = field(default_factory=dict)

    def get_stage(self, stage_name: str) -> Optional[PluginStageConfig]:
        """Return the stage config for *stage_name*, or None if not configured."""
        return self.stages.get(stage_name)


def _load_plugin_module(
    plugin_dir: Path, plugin_name: str
) -> Optional[ModuleType]:
    """Load ``<plugin_dir>/plugin.py``, returning None after a clear error."""
    module_path = plugin_dir / "plugin.py"
    if not module_path.is_file():
        print(f"Invalid plugin '{plugin_name}': plugin.py not found")
        return None

    safe_name = "".join(
        character if character.isalnum() else "_" for character in plugin_name
    )
    module_name = f"_fm_agent_plugin_{safe_name}"
    spec = importlib.util.spec_from_file_location(module_name, module_path)
    if spec is None or spec.loader is None:
        print(
            f"Invalid plugin '{plugin_name}': could not create an import "
            f"specification for '{module_path}'"
        )
        return None

    module = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(module)
    except Exception as exc:
        print(
            f"Invalid plugin '{plugin_name}': failed to import plugin.py — {exc}"
        )
        return None

    return module


def _validate_hook_signature(
    function: Callable,
    function_name: str,
    parameter_types: List[object],
    return_type: object,
) -> List[str]:
    """Validate positional parameters and resolved type annotations."""
    signature = inspect.signature(function)
    parameters = list(signature.parameters.values())
    if len(parameters) != len(parameter_types):
        return [
            f"function '{function_name}' must accept {len(parameter_types)} "
            f"parameter(s), got {len(parameters)}"
        ]

    try:
        type_hints = get_type_hints(function)
    except Exception as exc:
        return [
            f"function '{function_name}' has invalid type annotations: {exc}"
        ]

    errors = []
    for parameter, expected_type in zip(parameters, parameter_types):
        if parameter.kind not in (
            inspect.Parameter.POSITIONAL_ONLY,
            inspect.Parameter.POSITIONAL_OR_KEYWORD,
        ):
            errors.append(
                f"function '{function_name}' parameter '{parameter.name}' "
                "must be positional"
            )
            continue

        actual_type = type_hints.get(parameter.name, inspect.Signature.empty)
        if actual_type != expected_type:
            errors.append(
                f"function '{function_name}' parameter '{parameter.name}' "
                f"must be annotated as {expected_type}, got {actual_type}"
            )

    actual_return = type_hints.get("return", inspect.Signature.empty)
    if actual_return != return_type:
        errors.append(
            f"function '{function_name}' must return {return_type}, "
            f"got {actual_return}"
        )

    return errors


def _bind_stage_hooks(
    stage: PluginStageConfig, module: ModuleType
) -> List[str]:
    """Resolve JSON function names and validate their interfaces."""
    errors = []
    hook_specs = (
        ("replace_function", "replace_hook", [list[str], str], list[str]),
        ("input_function", "input_hook", [str], type(None)),
        ("output_function", "output_hook", [str], type(None)),
    )

    for function_field, hook_field, parameter_types, return_type in hook_specs:
        function_name = getattr(stage, function_field)
        if function_name is None:
            continue

        function = getattr(module, function_name, None)
        if function is None:
            errors.append(
                f"function '{function_name}' declared by '{function_field}' "
                "is missing from plugin.py"
            )
            continue
        if not callable(function):
            errors.append(
                f"'{function_name}' declared by '{function_field}' is not callable"
            )
            continue

        signature_errors = _validate_hook_signature(
            function, function_name, parameter_types, return_type
        )
        errors.extend(signature_errors)
        if not signature_errors:
            setattr(stage, hook_field, function)

    return errors


def _validate_plugin_json_content(
    plugin_dir: Path, name: str, data: dict, module: ModuleType
) -> Optional[PluginConfig]:
    """Validate parsed plugin.json and bind its declared Python functions."""
    plugin_name = data.get("name", "")
    if plugin_name != name:
        print(
            f"Invalid plugin '{name}': plugin name mismatch "
            f"(expected '{name}', got '{plugin_name}')"
        )
        return None

    if not data.get("version"):
        print(f"Invalid plugin '{name}': 'version' field is missing or empty")
        return None

    stages = {}
    stages_data = data.get("stages", {})
    if not isinstance(stages_data, dict):
        print(f"Invalid plugin '{name}': 'stages' must be a JSON object")
        return None

    for stage_name, stage_data in stages_data.items():
        if not isinstance(stage_data, dict):
            print(
                f"Invalid plugin '{name}': stage '{stage_name}' "
                "must be a JSON object"
            )
            return None

        stage = PluginStageConfig.from_dict(stage_data)
        errors = stage.validated()
        if not errors:
            errors.extend(_bind_stage_hooks(stage, module))
        if errors:
            for error in errors:
                print(
                    f"Invalid plugin '{name}': stage '{stage_name}' — {error}"
                )
            return None
        stages[stage_name] = stage

    return PluginConfig(
        name=plugin_name,
        version=data["version"],
        root=plugin_dir,
        stages=stages,
    )


def validate_plugin(plugin_dir: Path) -> Optional[PluginConfig]:
    """Validate one plugin directory and resolve its declared Python hooks."""
    name = plugin_dir.name
    plugin_json = plugin_dir / "plugin.json"
    plugin_config_json = plugin_dir / "plugin.config.json"

    if not plugin_json.is_file():
        if plugin_config_json.is_file():
            print(
                f"Invalid plugin '{name}': found plugin.config.json "
                "but expected plugin.json"
            )
        else:
            print(f"Invalid plugin '{name}': plugin.json not found")
        return None

    try:
        with open(plugin_json, "r") as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError) as exc:
        print(f"Invalid plugin '{name}': failed to parse plugin.json — {exc}")
        return None

    if not isinstance(data, dict):
        print(f"Invalid plugin '{name}': plugin.json must be a JSON object")
        return None

    module = _load_plugin_module(plugin_dir, name)
    if module is None:
        return None

    return _validate_plugin_json_content(plugin_dir, name, data, module)


def load_plugins(plugins_dir: Path) -> Dict[str, PluginConfig]:
    """Scan *plugins_dir*, validate each subdirectory, and return valid plugins."""
    if not plugins_dir.is_dir():
        return {}

    plugins = {}
    for entry in sorted(plugins_dir.iterdir()):
        if not entry.is_dir():
            continue
        if entry.name.startswith(".") or entry.name == "__pycache__":
            continue
        config = validate_plugin(entry)
        if config is not None:
            plugins[config.name] = config
    return plugins

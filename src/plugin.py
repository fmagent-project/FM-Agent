"""FM-Agent plugin loading and Python hook validation."""

import importlib.util
import inspect
import json
from dataclasses import dataclass, field
from pathlib import Path
from types import ModuleType
from typing import Callable, Dict, List, Optional, get_type_hints


@dataclass(frozen=True)
class HookContract:
    """Required Python signature for one stage hook."""

    parameter_types: tuple[object, ...]
    return_type: object


@dataclass
class PluginStageConfig:
    """Configuration and resolved Python hooks for one pipeline stage."""

    type: str = ""  # "pass", "replace", or "modify"
    replace_function: Optional[str] = None
    input_function: Optional[str] = None
    output_function: Optional[str] = None
    replace_md: Optional[str] = None
    modify_md: Optional[str] = None
    replace_hook: Optional[Callable] = field(default=None, repr=False)
    input_hook: Optional[Callable] = field(default=None, repr=False)
    output_hook: Optional[Callable] = field(default=None, repr=False)
    replace_md_path: Optional[Path] = field(default=None, repr=False)
    modify_md_path: Optional[Path] = field(default=None, repr=False)

    @staticmethod
    def from_dict(data: dict) -> "PluginStageConfig":
        return PluginStageConfig(
            type=data.get("type", ""),
            replace_function=data.get("replace_function"),
            input_function=data.get("input_function"),
            output_function=data.get("output_function"),
            replace_md=data.get("replace_md"),
            modify_md=data.get("modify_md"),
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
        markdown_fields = {
            "replace_md": self.replace_md,
            "modify_md": self.modify_md,
        }
        for field_name, function_name in function_fields.items():
            if function_name is not None and (
                not isinstance(function_name, str) or not function_name.strip()
            ):
                errors.append(f"'{field_name}' must be a non-empty string")
        for field_name, markdown_path in markdown_fields.items():
            if markdown_path is not None and (
                not isinstance(markdown_path, str) or not markdown_path.strip()
            ):
                errors.append(f"'{field_name}' must be a non-empty string")

        if errors:
            return errors

        declared_fields = {
            **function_fields,
            **markdown_fields,
        }
        if self.type == "pass":
            declared = [
                name
                for name, value in declared_fields.items()
                if value is not None
            ]
            if declared:
                errors.append(
                    "type=pass cannot declare modification fields: "
                    + ", ".join(declared)
                )
        elif self.type == "replace":
            if not self.replace_function:
                errors.append("type=replace requires 'replace_function'")
            forbidden = [
                name
                for name in (
                    "input_function",
                    "output_function",
                    "replace_md",
                    "modify_md",
                )
                if getattr(self, name) is not None
            ]
            if forbidden:
                errors.append(
                    "type=replace cannot declare modification fields: "
                    + ", ".join(forbidden)
                )
        elif self.type == "modify":
            if self.replace_function:
                errors.append("type=modify cannot declare 'replace_function'")
            if self.replace_md and self.modify_md:
                errors.append(
                    "'replace_md' and 'modify_md' cannot be declared together"
                )
            if not any(
                (
                    self.input_function,
                    self.output_function,
                    self.replace_md,
                    self.modify_md,
                )
            ):
                errors.append(
                    "type=modify requires at least one input, output, "
                    "or Markdown modification"
                )

        return errors


STAGE_WORKFLOW_MARKDOWN = {
    "generate_phase_plan",
    "generate_domain_context",
    "generate_specs_and_verification",
}


STAGE_HOOK_CONTRACTS = {
    "generate_phase_plan": {
        "replace_function": HookContract(
            parameter_types=(str, str),
            return_type=str,
        ),
        "input_function": HookContract(
            parameter_types=(list[str],),
            return_type=list[str],
        ),
        "output_function": HookContract(
            parameter_types=(str,),
            return_type=type(None),
        ),
    },
    "generate_domain_context": {
        "replace_function": HookContract(
            parameter_types=(str, str, str),
            return_type=list[str],
        ),
        "input_function": HookContract(
            parameter_types=(dict,),
            return_type=dict,
        ),
        "output_function": HookContract(
            parameter_types=(str,),
            return_type=type(None),
        ),
    },
    "extract_functions": {
        "replace_function": HookContract(
            parameter_types=(list[str], str),
            return_type=list[str],
        ),
        "input_function": HookContract(
            parameter_types=(str,),
            return_type=type(None),
        ),
        "output_function": HookContract(
            parameter_types=(str,),
            return_type=type(None),
        ),
    },
    "collect_file_list": {
        "replace_function": HookContract(
            parameter_types=(str, str),
            return_type=list[str],
        ),
        "input_function": HookContract(
            parameter_types=(list[str],),
            return_type=list[str],
        ),
        "output_function": HookContract(
            parameter_types=(str,),
            return_type=type(None),
        ),
    },
    "generate_topdown_layers": {
        "replace_function": HookContract(
            parameter_types=(str, str),
            return_type=list[str],
        ),
        "input_function": HookContract(
            parameter_types=(list[str],),
            return_type=list[str],
        ),
        "output_function": HookContract(
            parameter_types=(list[str],),
            return_type=type(None),
        ),
    },
    "generate_specs_and_verification": {
        "replace_function": HookContract(
            parameter_types=(str, str, bool),
            return_type=list[str],
        ),
        "input_function": HookContract(
            parameter_types=(list[str],),
            return_type=list[str],
        ),
        "output_function": HookContract(
            parameter_types=(list[str],),
            return_type=type(None),
        ),
    },
}


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


def apply_stage_workflow_markdown(
    plugin_stage: Optional[PluginStageConfig],
    workflow_path: str,
) -> None:
    """Apply one stage's replace_md or modify_md configuration."""
    if plugin_stage is None:
        return
    if (
        plugin_stage.replace_md_path is None
        and plugin_stage.modify_md_path is None
    ):
        return

    if plugin_stage.replace_md_path is not None:
        field_name = "replace_md"
        markdown_path = plugin_stage.replace_md_path
    else:
        field_name = "modify_md"
        markdown_path = plugin_stage.modify_md_path

    target_path = Path(workflow_path)
    try:
        if not target_path.is_file():
            raise FileNotFoundError(
                f"workflow file does not exist: {target_path}"
            )

        markdown = markdown_path.read_text(encoding="utf-8")
        if field_name == "replace_md":
            content = markdown
        else:
            original = target_path.read_text(encoding="utf-8")
            content = (
                original.rstrip()
                + "\n\n---\n\n"
                + markdown.strip()
                + "\n"
            )

        target_path.write_text(content, encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise RuntimeError(
            f"Failed to apply '{field_name}' to '{workflow_path}': {exc}"
        ) from exc

    if not target_path.is_file():
        raise RuntimeError(
            f"Failed to apply '{field_name}' to '{workflow_path}': "
            "workflow file is missing"
        )


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
    stage_name: str,
    stage: PluginStageConfig,
    module: Optional[ModuleType],
) -> List[str]:
    """Resolve and validate functions declared for one pipeline stage."""
    errors = []
    hook_contracts = STAGE_HOOK_CONTRACTS[stage_name]
    hook_fields = (
        ("replace_function", "replace_hook"),
        ("input_function", "input_hook"),
        ("output_function", "output_hook"),
    )

    for function_field, hook_field in hook_fields:
        function_name = getattr(stage, function_field)
        if function_name is None:
            continue
        if module is None:
            errors.append(
                f"function '{function_name}' declared by '{function_field}' "
                "requires plugin.py"
            )
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

        hook_contract = hook_contracts[function_field]
        signature_errors = _validate_hook_signature(
            function,
            function_name,
            list(hook_contract.parameter_types),
            hook_contract.return_type,
        )
        errors.extend(signature_errors)
        if not signature_errors:
            setattr(stage, hook_field, function)

    return errors


def _resolve_stage_markdown(
    plugin_dir: Path,
    stage_name: str,
    stage: PluginStageConfig,
) -> List[str]:
    """Resolve and validate Markdown files declared for one stage."""
    errors = []
    for field_name, path_field in (
        ("replace_md", "replace_md_path"),
        ("modify_md", "modify_md_path"),
    ):
        configured_path = getattr(stage, field_name)
        if configured_path is None:
            continue
        if stage_name not in STAGE_WORKFLOW_MARKDOWN:
            errors.append(
                f"stage '{stage_name}' does not support '{field_name}'"
            )
            continue

        relative_path = Path(configured_path)
        if relative_path.is_absolute():
            errors.append(f"'{field_name}' must be relative to the plugin")
            continue
        if relative_path.suffix.lower() != ".md":
            errors.append(f"'{field_name}' must reference a .md file")
            continue

        plugin_root = plugin_dir.resolve()
        resolved_path = (plugin_root / relative_path).resolve()
        try:
            resolved_path.relative_to(plugin_root)
        except ValueError:
            errors.append(f"'{field_name}' escapes the plugin directory")
            continue
        if not resolved_path.is_file():
            errors.append(
                f"'{field_name}' file does not exist: {configured_path}"
            )
            continue
        try:
            resolved_path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as exc:
            errors.append(
                f"'{field_name}' must be a readable UTF-8 file: {exc}"
            )
            continue

        setattr(stage, path_field, resolved_path)

    return errors


def _validate_plugin_json_content(
    plugin_dir: Path,
    name: str,
    data: dict,
    module: Optional[ModuleType],
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
        if stage_name not in STAGE_HOOK_CONTRACTS:
            errors.append(f"unknown stage '{stage_name}'")
        if not errors:
            errors.extend(
                _resolve_stage_markdown(plugin_dir, stage_name, stage)
            )
        if not errors:
            errors.extend(_bind_stage_hooks(stage_name, stage, module))
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

    stages_data = data.get("stages", {})
    function_fields = (
        "replace_function",
        "input_function",
        "output_function",
    )
    declares_python = (
        isinstance(stages_data, dict)
        and any(
            isinstance(stage_data, dict)
            and any(
                stage_data.get(field_name) is not None
                for field_name in function_fields
            )
            for stage_data in stages_data.values()
        )
    )
    module = None
    if declares_python:
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

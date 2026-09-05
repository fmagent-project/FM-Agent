"""FM-Agent plugin loading, validation, and execution."""

import hashlib
import importlib.util
import inspect
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from types import ModuleType
from typing import Callable, Dict, List, Optional, get_type_hints


Hook = Callable[[str], None]

SUPPORTED_STAGES = {
    "generate_phase_plan",
    "generate_domain_context",
    "extract_functions",
    "collect_file_list",
    "generate_topdown_layers",
    "generate_specs_and_verification",
}

PLUGIN_OPTION_NAMES = (
    "resume",
    "incremental",
    "isolate",
    "one_phase",
    "all_bugs",
    "only_spec",
    "estimate",
    "domain_knowledge",
    "submodule",
    "end_func",
    "extra_edge",
    "bug_validator",
)

_STAGE_FUNCTION_FIELDS = {
    "replace_function",
    "input_function",
    "output_function",
}


class PluginValidationError(ValueError):
    """Raised when a plugin does not satisfy the public plugin contract."""


@dataclass
class PluginStageConfig:
    """Validated Python hooks for one pipeline stage."""

    type: str
    replace_function: Optional[str] = None
    input_function: Optional[str] = None
    output_function: Optional[str] = None
    replace_hook: Optional[Hook] = field(default=None, repr=False)
    input_hook: Optional[Hook] = field(default=None, repr=False)
    output_hook: Optional[Hook] = field(default=None, repr=False)


@dataclass
class PluginConfig:
    """Loaded plugin metadata and resolved Python hooks."""

    name: str
    version: str
    root: Path
    stages: Dict[str, PluginStageConfig] = field(default_factory=dict)
    configure_function: Optional[str] = None
    configure_hook: Optional[Hook] = field(default=None, repr=False)
    unsupported_options: frozenset[str] = field(default_factory=frozenset)

    def get_stage(self, stage_name: str) -> Optional[PluginStageConfig]:
        """Return the stage config for *stage_name*, or None if not configured."""
        return self.stages.get(stage_name)


def get_unsupported_plugin_options(
    plugin_config: PluginConfig,
    option_names,
) -> tuple[str, ...]:
    """Return active options explicitly rejected by a plugin in stable order."""
    active = set(option_names)
    return tuple(
        option_name
        for option_name in PLUGIN_OPTION_NAMES
        if option_name in active
        and option_name in plugin_config.unsupported_options
    )


def _validate_function_name(
    plugin_name: str,
    field_name: str,
    value: object,
    stage_name: Optional[str] = None,
) -> Optional[str]:
    """Validate one optional function-name field."""
    if value is None:
        return None
    if not isinstance(value, str) or not value:
        location = f" stage '{stage_name}'" if stage_name else ""
        raise PluginValidationError(
            f"Plugin '{plugin_name}'{location} field '{field_name}' "
            "must be a non-empty string"
        )
    return value


def _validate_stage_fields(
    plugin_name: str,
    stage_name: str,
    data: dict,
) -> None:
    """Validate the legal field combinations for one stage mode."""
    stage_type = data.get("type")

    if stage_type not in {"pass", "replace", "modify"}:
        raise PluginValidationError(
            f"Plugin '{plugin_name}' stage '{stage_name}' has invalid "
            f"type {stage_type!r}; expected 'pass', 'replace', or 'modify'"
        )

    unknown_fields = set(data) - {"type"} - _STAGE_FUNCTION_FIELDS
    if unknown_fields:
        raise PluginValidationError(
            f"Plugin '{plugin_name}' stage '{stage_name}' contains "
            f"unsupported field(s): {', '.join(sorted(unknown_fields))}"
        )

    declared = {
        field_name
        for field_name in _STAGE_FUNCTION_FIELDS
        if data.get(field_name) is not None
    }

    if stage_type == "pass":
        forbidden = declared
    elif stage_type == "replace":
        if "replace_function" not in declared:
            raise PluginValidationError(
                f"Plugin '{plugin_name}' stage '{stage_name}' type=replace "
                "requires 'replace_function'"
            )
        forbidden = declared - {"replace_function"}
    else:
        modify_fields = declared & {"input_function", "output_function"}
        if not modify_fields:
            raise PluginValidationError(
                f"Plugin '{plugin_name}' stage '{stage_name}' type=modify "
                "requires 'input_function' or 'output_function'"
            )
        forbidden = declared - {"input_function", "output_function"}

    if forbidden:
        raise PluginValidationError(
            f"Plugin '{plugin_name}' stage '{stage_name}' type={stage_type} "
            f"does not allow: {', '.join(sorted(forbidden))}"
        )

    for field_name in _STAGE_FUNCTION_FIELDS:
        _validate_function_name(
            plugin_name,
            field_name,
            data.get(field_name),
            stage_name=stage_name,
        )


def _validate_unsupported_options(
    plugin_name: str,
    value: object,
) -> frozenset[str]:
    """Validate and normalize the optional plugin option denylist."""
    if not isinstance(value, list):
        raise PluginValidationError(
            f"Plugin '{plugin_name}' field 'unsupported_options' "
            "must be a JSON array"
        )

    invalid_options = [
        option_name
        for option_name in value
        if not isinstance(option_name, str) or not option_name
    ]
    if invalid_options:
        raise PluginValidationError(
            f"Plugin '{plugin_name}' field 'unsupported_options' "
            "must contain non-empty strings"
        )

    if len(value) != len(set(value)):
        raise PluginValidationError(
            f"Plugin '{plugin_name}' field 'unsupported_options' "
            "must not contain duplicates"
        )

    unknown_options = set(value) - set(PLUGIN_OPTION_NAMES)
    if unknown_options:
        raise PluginValidationError(
            f"Plugin '{plugin_name}' field 'unsupported_options' contains "
            f"unsupported option(s): {', '.join(sorted(unknown_options))}"
        )

    return frozenset(value)


def _load_plugin_module(
    plugin_name: str,
    plugin_dir: Path,
) -> ModuleType:
    """Load a plugin's trusted Python module under a collision-safe name."""
    plugin_file = plugin_dir / "plugin.py"
    if not plugin_file.is_file():
        raise PluginValidationError(
            f"Plugin '{plugin_name}' is missing plugin.py"
        )

    module_name = (
        "_fm_agent_plugin_"
        + re.sub(r"[^0-9A-Za-z_]", "_", plugin_name)
        + "_"
        + hashlib.sha256(
            str(plugin_dir.resolve()).encode()
        ).hexdigest()[:12]
    )
    spec = importlib.util.spec_from_file_location(module_name, plugin_file)
    if spec is None or spec.loader is None:
        raise PluginValidationError(
            f"Plugin '{plugin_name}' could not load plugin.py"
        )

    module = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(module)
    except Exception as exc:
        raise PluginValidationError(
            f"Plugin '{plugin_name}' failed while importing plugin.py: {exc}"
        ) from exc
    return module


def _resolve_hook(
    plugin_name: str,
    function_name: str,
    module: ModuleType,
) -> Hook:
    """Resolve one declared function and validate its exact public signature."""
    value = getattr(module, function_name, None)
    if value is None:
        raise PluginValidationError(
            f"Plugin '{plugin_name}' function "
            f"'{function_name}' was not found in plugin.py"
        )
    if not callable(value):
        raise PluginValidationError(
            f"Plugin '{plugin_name}' object "
            f"'{function_name}' is not callable"
        )

    signature = inspect.signature(value)
    parameters = list(signature.parameters.values())
    if (
        len(parameters) != 1
        or parameters[0].name != "proj_dir"
        or parameters[0].kind
        not in {
            inspect.Parameter.POSITIONAL_ONLY,
            inspect.Parameter.POSITIONAL_OR_KEYWORD,
        }
    ):
        raise PluginValidationError(
            f"Plugin '{plugin_name}' function '{function_name}' "
            "must have signature (proj_dir: str) -> None"
        )

    try:
        hints = get_type_hints(value)
    except Exception as exc:
        raise PluginValidationError(
            f"Plugin '{plugin_name}' function '{function_name}' "
            f"has invalid type annotations: {exc}"
        ) from exc

    if (
        hints.get("proj_dir") is not str
        or hints.get("return") not in {None, type(None)}
    ):
        raise PluginValidationError(
            f"Plugin '{plugin_name}' function '{function_name}' "
            "must have signature (proj_dir: str) -> None"
        )

    return value


def _load_and_validate_plugin(plugin_dir: Path) -> PluginConfig:
    """Load and validate one plugin directory or raise a contract error."""
    plugin_name = plugin_dir.name
    plugin_json = plugin_dir / "plugin.json"
    plugin_config_json = plugin_dir / "plugin.config.json"

    if not plugin_json.is_file():
        if plugin_config_json.is_file():
            raise PluginValidationError(
                f"Plugin '{plugin_name}' found plugin.config.json "
                "but expected plugin.json"
            )
        raise PluginValidationError(
            f"Plugin '{plugin_name}' is missing plugin.json"
        )

    try:
        with open(plugin_json, "r", encoding="utf-8") as file:
            data = json.load(file)
    except (OSError, json.JSONDecodeError) as exc:
        raise PluginValidationError(
            f"Plugin '{plugin_name}' failed to parse plugin.json: {exc}"
        ) from exc

    if not isinstance(data, dict):
        raise PluginValidationError(
            f"Plugin '{plugin_name}' plugin.json must be a JSON object"
        )
    if data.get("name") != plugin_name:
        raise PluginValidationError(
            f"Plugin '{plugin_name}' name mismatch "
            f"(got {data.get('name')!r})"
        )
    version = data.get("version")
    if not isinstance(version, str) or not version:
        raise PluginValidationError(
            f"Plugin '{plugin_name}' field 'version' must be a non-empty string"
        )

    allowed_top_level_fields = {
        "name",
        "version",
        "configure_function",
        "unsupported_options",
        "stages",
    }
    unknown_top_level_fields = set(data) - allowed_top_level_fields
    if unknown_top_level_fields:
        raise PluginValidationError(
            f"Plugin '{plugin_name}' contains unsupported field(s): "
            f"{', '.join(sorted(unknown_top_level_fields))}"
        )

    unsupported_options = _validate_unsupported_options(
        plugin_name,
        data.get("unsupported_options", []),
    )

    stages_data = data.get("stages", {})
    if not isinstance(stages_data, dict):
        raise PluginValidationError(
            f"Plugin '{plugin_name}' field 'stages' must be a JSON object"
        )

    configure_function = _validate_function_name(
        plugin_name,
        "configure_function",
        data.get("configure_function"),
    )
    module = _load_plugin_module(plugin_name, plugin_dir)
    configure_hook = (
        _resolve_hook(plugin_name, configure_function, module)
        if configure_function
        else None
    )

    stages = {}
    for stage_name, stage_data in stages_data.items():
        if stage_name not in SUPPORTED_STAGES:
            raise PluginValidationError(
                f"Plugin '{plugin_name}' declares unsupported stage "
                f"'{stage_name}'"
            )
        if not isinstance(stage_data, dict):
            raise PluginValidationError(
                f"Plugin '{plugin_name}' stage '{stage_name}' "
                "must be a JSON object"
            )

        _validate_stage_fields(plugin_name, stage_name, stage_data)
        replace_function = stage_data.get("replace_function")
        input_function = stage_data.get("input_function")
        output_function = stage_data.get("output_function")
        stages[stage_name] = PluginStageConfig(
            type=stage_data["type"],
            replace_function=replace_function,
            input_function=input_function,
            output_function=output_function,
            replace_hook=(
                _resolve_hook(plugin_name, replace_function, module)
                if replace_function
                else None
            ),
            input_hook=(
                _resolve_hook(plugin_name, input_function, module)
                if input_function
                else None
            ),
            output_hook=(
                _resolve_hook(plugin_name, output_function, module)
                if output_function
                else None
            ),
        )

    return PluginConfig(
        name=plugin_name,
        version=version,
        root=plugin_dir,
        stages=stages,
        unsupported_options=unsupported_options,
        configure_function=configure_function,
        configure_hook=configure_hook,
    )


def validate_plugin(plugin_dir: Path) -> Optional[PluginConfig]:
    """Validate one plugin, printing its error and returning None on failure."""
    try:
        return _load_and_validate_plugin(plugin_dir)
    except PluginValidationError as exc:
        print(f"Invalid plugin '{plugin_dir.name}': {exc}")
        return None


def load_plugins(plugins_dir: Path) -> Dict[str, PluginConfig]:
    """Scan *plugins_dir* and return every valid plugin by name."""
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


def run_plugin_hook(
    plugin_name: str,
    stage_name: str,
    function_name: str,
    hook: Hook,
    proj_dir: str,
) -> None:
    """Run one trusted plugin hook and enforce its return contract."""
    try:
        result = hook(proj_dir)
    except Exception as exc:
        raise RuntimeError(
            f"Plugin '{plugin_name}' function '{function_name}' "
            f"failed for stage '{stage_name}': {exc}"
        ) from exc

    if result is not None:
        raise RuntimeError(
            f"Plugin '{plugin_name}' function '{function_name}' "
            f"for stage '{stage_name}' must return None"
        )

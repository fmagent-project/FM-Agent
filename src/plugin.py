"""FM-Agent plugin loading, validation, and execution."""

import importlib.util
import inspect
import json
import os
import sys
from dataclasses import dataclass, field
from pathlib import Path
from types import ModuleType
from typing import Dict, List, Optional, get_args, get_origin


# ---------------------------------------------------------------------------
# Plugin data models
# ---------------------------------------------------------------------------


@dataclass
class PluginStageConfig:
    """Configuration for a single pipeline stage modification."""

    type: str = ""  # "pass", "replace", or "modify"
    input_md: Optional[str] = None  # relative to plugin root; optional for modify

    @staticmethod
    def from_dict(data: dict) -> "PluginStageConfig":
        return PluginStageConfig(
            type=data.get("type", ""),
            input_md=data.get("input_md"),
        )

    def validated(self) -> List[str]:
        """Return a list of validation error strings (empty = valid)."""
        errors = []
        if self.type not in ("pass", "replace", "modify"):
            errors.append(
                "stage type must be 'pass', 'replace', or 'modify', "
                f"got '{self.type}'"
            )
        return errors


@dataclass
class PluginConfig:
    """Parsed plugin.json with resolved plugin root path and loaded module."""

    name: str
    version: str
    root: Path
    stages: Dict[str, PluginStageConfig] = field(default_factory=dict)
    module: Optional[ModuleType] = None

    def get_stage(self, stage_name: str) -> Optional[PluginStageConfig]:
        return self.stages.get(stage_name)

    # ── invoke helpers ─────────────────────────────────────────────

    def invoke_replace(
        self, stage_name: str, input_files: List[str], context: dict
    ) -> List[str]:
        fn = getattr(self.module, f"replace_{stage_name}")
        return fn(input_files, context)

    def invoke_modify_input(self, stage_name: str, input_file: str) -> None:
        fn = getattr(self.module, f"modify_{stage_name}_input")
        fn(input_file)

    def invoke_modify_output(
        self, stage_name: str, output_files: List[str]
    ) -> None:
        fn = getattr(self.module, f"modify_{stage_name}_output")
        fn(output_files)


# ---------------------------------------------------------------------------
# Function signature validation (inspect-based)
# ---------------------------------------------------------------------------

# Stage name → (param_types_tuple, return_type)
_REPLACE_SPEC: Dict[str, tuple] = {
    "generate_phase_plan": (
        (List[str], dict),
        List[str],
    ),
    "generate_domain_context": (
        (List[str], dict),
        List[str],
    ),
}

_MODIFY_SPEC: Dict[str, tuple] = {
    "generate_phase_plan": (
        (str,),
        (List[str],),
    ),
    "generate_domain_context": (
        (str,),
        (List[str],),
    ),
}


def _types_match(actual, expected) -> bool:
    """Compare two type annotations robustly across typing variants.

    Handles ``list[str]`` vs ``typing.List[str]``, ``None`` vs ``type(None)``,
    and nested generics.
    """
    origin_a = get_origin(actual)
    origin_e = get_origin(expected)

    # None vs NoneType
    if actual is type(None) and expected is type(None):
        return True
    if actual is None and expected is type(None):
        return True
    if actual is type(None) and expected is None:
        return True

    # Resolve None originating from bare type(None) annotation
    if actual is type(None):
        actual = None
    if expected is type(None):
        expected = None

    if (origin_a or actual) != (origin_e or expected):
        return False
    if origin_a is not None and origin_e is not None:
        return get_args(actual) == get_args(expected)
    return True


def _check_fn(module, fn_name: str, param_types: tuple, return_type) -> List[str]:
    """Validate a single plugin function's signature.

    Checks: existence → callable → inspectable → param count → param types → return type.
    Returns a list of error strings (empty on success).
    """
    errors: List[str] = []

    fn = getattr(module, fn_name, None)
    if fn is None:
        return [f"  {fn_name}: function not found"]
    if not callable(fn):
        return [f"  {fn_name}: is not callable"]

    try:
        sig = inspect.signature(fn)
    except (ValueError, TypeError):
        return [f"  {fn_name}: cannot inspect signature"]

    params = list(sig.parameters.values())
    if len(params) != len(param_types):
        errors.append(
            f"  {fn_name}: expected {len(param_types)} parameter(s), "
            f"got {len(params)}"
        )

    for i, param in enumerate(params):
        if i >= len(param_types):
            break
        ann = param.annotation
        if ann is inspect.Parameter.empty:
            errors.append(
                f"  {fn_name}: parameter '{param.name}' missing type annotation"
            )
        elif not _types_match(ann, param_types[i]):
            errors.append(
                f"  {fn_name}: parameter '{param.name}' type mismatch "
                f"(expected {param_types[i]}, got {ann})"
            )

    if sig.return_annotation is inspect.Signature.empty:
        errors.append(f"  {fn_name}: missing return type annotation")
    elif not _types_match(sig.return_annotation, return_type):
        errors.append(
            f"  {fn_name}: return type mismatch "
            f"(expected {return_type}, got {sig.return_annotation})"
        )

    return errors


def _validate_stage_functions(
    module: ModuleType, stages: Dict[str, PluginStageConfig]
) -> List[str]:
    """Check that every stage declared in plugin.json has matching functions."""
    errors: List[str] = []

    for stage_name, config in stages.items():
        if config.type == "replace":
            spec = _REPLACE_SPEC.get(stage_name)
            if spec is not None:
                errors += _check_fn(
                    module, f"replace_{stage_name}", spec[0], spec[1]
                )
        elif config.type == "modify":
            spec = _MODIFY_SPEC.get(stage_name)
            if spec is not None:
                errors += _check_fn(
                    module, f"modify_{stage_name}_input", spec[0], type(None)
                )
                errors += _check_fn(
                    module, f"modify_{stage_name}_output", spec[1], type(None)
                )
        # pass: nothing to validate

    return errors


# ---------------------------------------------------------------------------
# Plugin loading
# ---------------------------------------------------------------------------


def _validate_plugin_json_content(
    plugin_dir: Path, name: str, data: dict
) -> Optional[PluginConfig]:
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

    stages: Dict[str, PluginStageConfig] = {}
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
        if errors:
            for err in errors:
                print(
                    f"Invalid plugin '{name}': stage '{stage_name}' — {err}"
                )
            return None
        if stage.type == "modify" and stage.input_md:
            input_path = plugin_dir / stage.input_md
            if not input_path.is_file():
                print(
                    f"Invalid plugin '{name}': stage '{stage_name}' — "
                    f"input_md '{stage.input_md}' not found in plugin directory"
                )
                return None
        stages[stage_name] = stage

    return PluginConfig(
        name=plugin_name,
        version=data["version"],
        root=plugin_dir,
        stages=stages,
    )


def _load_plugin_module(plugin_dir: Path, name: str) -> Optional[ModuleType]:
    """Import ``plugin.py`` from *plugin_dir* and return the module object.

    Returns None after printing errors when the file is missing or unimportable.
    """
    plugin_py = plugin_dir / "plugin.py"
    if not plugin_py.is_file():
        print(
            f"Invalid plugin '{name}': plugin.py not found — "
            "every plugin must include a plugin.py file"
        )
        return None

    module_name = f"fm_agent_plugin_{name}"
    spec = importlib.util.spec_from_file_location(module_name, str(plugin_py))
    if spec is None or spec.loader is None:
        print(
            f"Invalid plugin '{name}': could not create module spec "
            f"for {plugin_py}"
        )
        return None

    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    try:
        spec.loader.exec_module(module)
    except Exception as exc:
        print(
            f"Invalid plugin '{name}': plugin.py raised an error during import: {exc}"
        )
        del sys.modules[module_name]
        return None

    return module


def validate_plugin(plugin_dir: Path) -> Optional[PluginConfig]:
    """Validate a single plugin directory.

    Checks plugin.json, imports plugin.py, and validates function signatures.
    Returns a ``PluginConfig`` if valid, otherwise ``None``.
    """
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
        print(
            f"Invalid plugin '{name}': failed to parse plugin.json — {exc}"
        )
        return None

    if not isinstance(data, dict):
        print(
            f"Invalid plugin '{name}': plugin.json must be a JSON object"
        )
        return None

    config = _validate_plugin_json_content(plugin_dir, name, data)
    if config is None:
        return None

    module = _load_plugin_module(plugin_dir, name)
    if module is None:
        return None

    func_errors = _validate_stage_functions(module, config.stages)
    if func_errors:
        print(
            f"Invalid plugin '{name}': function signature errors:\n"
            + "\n".join(func_errors)
        )
        return None

    config.module = module
    return config


def load_plugins(plugins_dir: Path) -> Dict[str, PluginConfig]:
    """Scan *plugins_dir* for subdirectories, validate each, return valid plugins."""
    if not plugins_dir.is_dir():
        return {}

    plugins: Dict[str, PluginConfig] = {}
    for entry in sorted(plugins_dir.iterdir()):
        if not entry.is_dir():
            continue
        if entry.name.startswith(".") or entry.name == "__pycache__":
            continue
        config = validate_plugin(entry)
        if config is not None:
            plugins[config.name] = config
    return plugins

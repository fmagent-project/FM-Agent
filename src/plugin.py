"""FM-Agent plugin loading, validation, and execution."""

import json
import os
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional


@dataclass
class PluginStageConfig:
    """Configuration for a single pipeline stage modification."""

    type: str = ""  # "pass", "replace", or "modify"
    replace_cmd: Optional[str] = None
    input_md: Optional[str] = None  # relative to plugin root
    output_process: Optional[str] = None

    @staticmethod
    def from_dict(data: dict) -> "PluginStageConfig":
        return PluginStageConfig(
            type=data.get("type", ""),
            replace_cmd=data.get("replace_cmd"),
            input_md=data.get("input_md"),
            output_process=data.get("output_process"),
        )

    def validated(self) -> List[str]:
        """Return a list of validation error strings (empty = valid)."""
        errors = []
        if self.type not in ("pass", "replace", "modify"):
            errors.append(
                "stage type must be 'pass', 'replace', or 'modify', "
                f"got '{self.type}'"
            )
        if self.type == "replace" and not self.replace_cmd:
            errors.append("type=replace requires 'replace_cmd'")
        if (
            self.type == "modify"
            and not self.input_md
            and not self.output_process
        ):
            errors.append(
                "type=modify requires at least one of 'input_md' or 'output_process'"
            )
        return errors


@dataclass
class PluginConfig:
    """Parsed plugin.json with resolved plugin root path."""

    name: str
    version: str
    root: Path
    stages: Dict[str, PluginStageConfig] = field(default_factory=dict)

    def get_stage(self, stage_name: str) -> Optional[PluginStageConfig]:
        """Return the stage config for *stage_name*, or None if not configured."""
        return self.stages.get(stage_name)


def _resolve_command(cmd: str, plugin_root: Path) -> str:
    """Rewrite relative file paths in *cmd* to absolute paths under *plugin_root*.

    Each whitespace-delimited token in *cmd* is checked: if ``plugin_root / token``
    points to an existing file, the token is replaced with its absolute path.
    Tokens starting with ``/``, ``$``, or ``-`` are left unchanged.
    """
    tokens = cmd.split()
    resolved = []
    for token in tokens:
        if token.startswith("/") or token.startswith("$"):
            resolved.append(token)
            continue
        candidate = plugin_root / token
        if candidate.is_file():
            resolved.append(str(candidate))
        else:
            resolved.append(token)
    return " ".join(resolved)


def run_plugin_command(
    cmd: str, plugin_root: Path, proj_dir: str, label: str = "",
    work_dir: Optional[str] = None,
) -> None:
    """Execute a plugin bash command with ``check=True`` so failure stops the pipeline.

    Relative file paths in *cmd* are resolved under *plugin_root*. The command runs
    in *proj_dir* with ``FM_AGENT_PLUGIN_ROOT`` set to the plugin root. When a
    run workspace is available, ``FM_AGENT_WORK_DIR`` contains its absolute
    path and ``FM_AGENT_WORK_DIR_REL`` contains its project-relative path.
    """
    resolved = _resolve_command(cmd, plugin_root)
    env = dict(os.environ, FM_AGENT_PLUGIN_ROOT=str(plugin_root))
    if work_dir is not None:
        env["FM_AGENT_WORK_DIR"] = os.path.abspath(work_dir)
        env["FM_AGENT_WORK_DIR_REL"] = os.path.relpath(work_dir, proj_dir)
    try:
        subprocess.run(resolved, shell=True, check=True, cwd=proj_dir, env=env)
    except subprocess.CalledProcessError as e:
        label_prefix = f"Plugin {label}: " if label else ""
        print(
            f"[Pipeline] ERROR: {label_prefix}command exited with code {e.returncode}: "
            f"{resolved}"
        )
        raise


def _validate_plugin_json_content(
    plugin_dir: Path, name: str, data: dict
) -> Optional[PluginConfig]:
    """Validate the content of a parsed plugin.json; returns PluginConfig or None."""
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


def validate_plugin(plugin_dir: Path) -> Optional[PluginConfig]:
    """Validate a single plugin directory.

    Returns a ``PluginConfig`` if the plugin is valid, otherwise ``None``
    (after printing validation errors to stdout).
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

    return _validate_plugin_json_content(plugin_dir, name, data)


def load_plugins(plugins_dir: Path) -> Dict[str, PluginConfig]:
    """Scan *plugins_dir* for subdirectories, validate each, return valid plugins.

    Invalid plugins are printed with their error reason and skipped.
    """
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

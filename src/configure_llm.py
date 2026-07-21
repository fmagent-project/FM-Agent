from __future__ import annotations

import json
import os
import re
import shutil
import sys
import tempfile
from copy import deepcopy
from dataclasses import dataclass
from datetime import datetime
from getpass import getpass
from pathlib import Path
from typing import Literal
from urllib.parse import urlparse

try:
    import tomllib  # type: ignore[attr-defined]
except ModuleNotFoundError:  # pragma: no cover - exercised only on Python < 3.11
    try:
        import tomli as tomllib  # type: ignore[no-redef]
    except ModuleNotFoundError as exc:  # pragma: no cover - environment-specific
        raise RuntimeError(
            "configure_llm.py requires tomllib (Python 3.11+) or tomli installed."
        ) from exc


SCHEMA_URL = "https://opencode.ai/config.json"
ENV_SECRET_KEY = "LLM_API_KEY"
ENV_LEGACY_LLM_KEYS = (
    "LLM_API_BASE_URL",
    "LLM_MODEL",
    "FM_AGENT_MODEL_BACKEND",
    "OPENCODE_MODEL_PROVIDER",
    "LLM_API_STYLE",
)


class ConfigWizardError(RuntimeError):
    pass


ApiStyle = Literal["openai", "anthropic"]


@dataclass(frozen=True)
class LLMConfigInput:
    provider_id: str
    provider_name: str
    api_style: ApiStyle
    base_url: str
    model_id: str
    api_key: str
    backend: str = "opencode"


@dataclass(frozen=True)
class WizardPaths:
    project_root: Path
    env_path: Path
    toml_path: Path
    opencode_config_path: Path


def adapter_for_api_style(api_style: ApiStyle) -> str:
    if api_style == "anthropic":
        return "@ai-sdk/anthropic"
    if api_style == "openai":
        return "@ai-sdk/openai-compatible"
    raise ConfigWizardError(f"Unsupported API style: {api_style}")


def validate_base_url(url: str) -> None:
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        raise ConfigWizardError(
            f"Base URL must be an absolute http(s) URL, got: {url!r}"
        )


def validate_input(config: LLMConfigInput) -> None:
    if not config.provider_id.strip():
        raise ConfigWizardError("Provider ID must not be empty.")
    if not config.provider_name.strip():
        raise ConfigWizardError("Provider name must not be empty.")
    if not config.model_id.strip():
        raise ConfigWizardError("Model ID must not be empty.")
    if not config.api_key.strip():
        raise ConfigWizardError("API key must not be empty.")
    validate_base_url(config.base_url.strip())
    adapter_for_api_style(config.api_style)


def detect_opencode_config_path(home: Path | None = None) -> Path:
    home = home or Path.home()
    if sys.platform == "darwin":
        return home / "Library" / "Application Support" / "opencode" / "opencode.json"
    if os.name == "nt":
        appdata = os.environ.get("APPDATA")
        if appdata:
            return Path(appdata) / "opencode" / "opencode.json"
        return home / "AppData" / "Roaming" / "opencode" / "opencode.json"
    xdg = os.environ.get("XDG_CONFIG_HOME")
    if xdg:
        return Path(xdg) / "opencode" / "opencode.json"
    return home / ".config" / "opencode" / "opencode.json"


def default_paths(project_root: Path) -> WizardPaths:
    return WizardPaths(
        project_root=project_root,
        env_path=project_root / ".env",
        toml_path=project_root / "fm-agent.toml",
        opencode_config_path=detect_opencode_config_path(),
    )


def mask_secret(secret: str) -> str:
    if not secret:
        return ""
    if len(secret) <= 4:
        return "*" * len(secret)
    return "*" * (len(secret) - 4) + secret[-4:]


def build_provider_entry(config: LLMConfigInput) -> dict:
    return {
        "npm": adapter_for_api_style(config.api_style),
        "options": {
            "baseURL": config.base_url,
            "apiKey": "{env:LLM_API_KEY}",
        },
        "models": {
            config.model_id: {},
        },
    }


def parse_existing_opencode_config(text: str) -> dict:
    if not text.strip():
        return {}
    try:
        loaded = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ConfigWizardError(
            "Existing OpenCode config is invalid JSON; refusing to overwrite it."
        ) from exc
    if not isinstance(loaded, dict):
        raise ConfigWizardError(
            "Existing OpenCode config must be a JSON object at the top level."
        )
    return loaded


def merge_opencode_config(existing: dict, config: LLMConfigInput) -> dict:
    merged = deepcopy(existing)
    if "$schema" not in merged:
        merged["$schema"] = SCHEMA_URL

    providers = merged.get("provider")
    if providers is None:
        providers = {}
    if not isinstance(providers, dict):
        raise ConfigWizardError("OpenCode config field 'provider' must be an object.")

    entry = providers.get(config.provider_id)
    if entry is None:
        entry = {}
    if not isinstance(entry, dict):
        raise ConfigWizardError(
            f"OpenCode provider '{config.provider_id}' must be a JSON object."
        )

    merged_entry = deepcopy(entry)
    merged_entry["npm"] = adapter_for_api_style(config.api_style)

    options = merged_entry.get("options")
    if options is None:
        options = {}
    if not isinstance(options, dict):
        raise ConfigWizardError(
            f"OpenCode provider '{config.provider_id}.options' must be an object."
        )
    options = dict(options)
    options["baseURL"] = config.base_url
    options["apiKey"] = "{env:LLM_API_KEY}"
    merged_entry["options"] = options

    models = merged_entry.get("models")
    if models is None:
        models = {}
    if not isinstance(models, dict):
        raise ConfigWizardError(
            f"OpenCode provider '{config.provider_id}.models' must be an object."
        )
    models = dict(models)
    existing_model = models.get(config.model_id)
    if existing_model is None:
        existing_model = {}
    if not isinstance(existing_model, dict):
        raise ConfigWizardError(
            f"OpenCode model entry '{config.provider_id}/{config.model_id}' must be an object."
        )
    models[config.model_id] = existing_model
    merged_entry["models"] = models

    providers = dict(providers)
    providers[config.provider_id] = merged_entry
    merged["provider"] = providers
    return merged


_SECTION_RE = re.compile(r"^\s*\[([A-Za-z0-9_.-]+)\]\s*(?:#.*)?$")
_KV_RE = re.compile(r"^(\s*)([A-Za-z0-9_]+)(\s*=\s*)(.*?)(\s*(#.*)?)$")


def _quote_toml_string(value: str) -> str:
    return json.dumps(value, ensure_ascii=False)


def update_fm_agent_toml_text(text: str, config: LLMConfigInput) -> str:
    try:
        loaded = tomllib.loads(text)
    except tomllib.TOMLDecodeError as exc:
        raise ConfigWizardError(
            "Existing fm-agent.toml is invalid TOML; refusing to overwrite it."
        ) from exc
    if loaded and not isinstance(loaded, dict):
        raise ConfigWizardError("Existing fm-agent.toml must decode to a table/object.")

    target = {
        "name": _quote_toml_string(config.model_id),
        "provider": _quote_toml_string(config.provider_id),
        "base_url": _quote_toml_string(config.base_url),
        "backend": _quote_toml_string(config.backend),
        "api_style": _quote_toml_string(config.api_style),
    }

    lines = text.splitlines(keepends=True)
    if not lines:
        lines = ["[llm]\n"]

    new_lines: list[str] = []
    current_section: str | None = None
    in_llm = False
    llm_found = False
    seen_keys: set[str] = set()

    for line in lines:
        section_match = _SECTION_RE.match(line)
        if section_match:
            if in_llm:
                for key, value in target.items():
                    if key not in seen_keys:
                        new_lines.append(f"{key:<9} = {value}\n")
                seen_keys.clear()
            current_section = section_match.group(1)
            in_llm = current_section == "llm"
            llm_found = llm_found or in_llm
            new_lines.append(line)
            continue

        if in_llm:
            kv_match = _KV_RE.match(line)
            if kv_match and kv_match.group(2) in target:
                indent, key, sep, _old_value, trailer, _comment = kv_match.groups()
                new_lines.append(f"{indent}{key}{sep}{target[key]}{trailer}\n")
                seen_keys.add(key)
                continue
        new_lines.append(line)

    if in_llm:
        for key, value in target.items():
            if key not in seen_keys:
                new_lines.append(f"{key:<9} = {value}\n")
    elif not llm_found:
        if new_lines and not new_lines[-1].endswith("\n"):
            new_lines[-1] += "\n"
        if new_lines and new_lines[-1].strip():
            new_lines.append("\n")
        new_lines.append("[llm]\n")
        for key, value in target.items():
            new_lines.append(f"{key:<9} = {value}\n")

    return "".join(new_lines)


def update_env_text(text: str, api_key: str) -> str:
    lines = text.splitlines(keepends=True)
    new_lines: list[str] = []
    key_written = False

    for line in lines:
        stripped = line.lstrip()
        if not stripped or stripped.startswith("#"):
            new_lines.append(line)
            continue

        key, sep, _value = line.partition("=")
        if not sep:
            new_lines.append(line)
            continue
        env_key = key.strip()
        if env_key == ENV_SECRET_KEY:
            new_lines.append(f"{ENV_SECRET_KEY}={api_key}\n")
            key_written = True
            continue
        if env_key in ENV_LEGACY_LLM_KEYS:
            continue
        new_lines.append(line)

    if not key_written:
        if new_lines and new_lines[-1].strip():
            new_lines.append("\n")
        if not new_lines:
            new_lines.extend(
                [
                    "# fm-agent secrets — gitignored, do not commit.\n",
                    "# Only the LLM API key belongs here.\n",
                ]
            )
        new_lines.append(f"{ENV_SECRET_KEY}={api_key}\n")
    return "".join(new_lines)


def validate_generated_state(
    config: LLMConfigInput,
    merged_opencode: dict,
    updated_toml: str,
) -> None:
    validate_input(config)
    json.dumps(merged_opencode)
    tomllib.loads(updated_toml)

    providers = merged_opencode.get("provider")
    if not isinstance(providers, dict) or config.provider_id not in providers:
        raise ConfigWizardError(
            f"Generated OpenCode config is missing provider '{config.provider_id}'."
        )
    entry = providers[config.provider_id]
    if not isinstance(entry, dict):
        raise ConfigWizardError(
            f"Generated OpenCode provider '{config.provider_id}' is not an object."
        )
    if entry.get("npm") != adapter_for_api_style(config.api_style):
        raise ConfigWizardError(
            "Generated OpenCode adapter does not match the selected API protocol."
        )
    models = entry.get("models")
    if not isinstance(models, dict) or config.model_id not in models:
        raise ConfigWizardError(
            f"Generated OpenCode config is missing model '{config.model_id}'."
        )


def backup_file(path: Path, now: datetime | None = None) -> Path | None:
    if not path.exists():
        return None
    now = now or datetime.now()
    suffix = now.strftime("%Y%m%d-%H%M%S")
    if path.name == ".env":
        backup_dir = Path(tempfile.gettempdir()) / "fm-agent-config-backups"
        backup_dir.mkdir(parents=True, exist_ok=True)
        path_slug = str(path.parent.resolve()).strip(os.sep).replace(os.sep, "_") or "project"
        backup = backup_dir / f"{path_slug}__env.bak.{suffix}"
    else:
        backup = path.with_name(f"{path.name}.bak.{suffix}")
    shutil.copy2(path, backup)
    return backup


def atomic_write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        "w",
        encoding="utf-8",
        dir=path.parent,
        prefix=f".{path.name}.",
        delete=False,
    ) as tmp:
        tmp.write(text)
        tmp.flush()
        os.fsync(tmp.fileno())
        tmp_path = Path(tmp.name)
    os.replace(tmp_path, path)


def _read_text_if_exists(path: Path) -> str:
    if not path.exists():
        return ""
    return path.read_text(encoding="utf-8")


def _preview(config: LLMConfigInput, paths: WizardPaths) -> str:
    return "\n".join(
        [
            "FM-Agent LLM configuration",
            "",
            f"Provider ID:   {config.provider_id}",
            f"Provider name: {config.provider_name}",
            f"API protocol:  {config.api_style}",
            f"Base URL:      {config.base_url}",
            f"Model ID:      {config.model_id}",
            f"API key:       {mask_secret(config.api_key)}",
            "",
            "The following files will be updated:",
            f"  - {paths.toml_path}",
            f"  - {paths.env_path}",
            f"  - {paths.opencode_config_path}",
        ]
    )


def apply_configuration(
    config: LLMConfigInput,
    paths: WizardPaths,
    *,
    validate: bool = True,
) -> list[tuple[Path, Path | None]]:
    validate_input(config)

    env_text = _read_text_if_exists(paths.env_path)
    toml_text = _read_text_if_exists(paths.toml_path)
    if not toml_text:
        raise ConfigWizardError(
            f"fm-agent.toml not found at {paths.toml_path}; refusing to guess a new project config."
        )
    opencode_text = _read_text_if_exists(paths.opencode_config_path)

    updated_env = update_env_text(env_text, config.api_key)
    updated_toml = update_fm_agent_toml_text(toml_text, config)
    merged_opencode = merge_opencode_config(
        parse_existing_opencode_config(opencode_text),
        config,
    )
    if validate:
        validate_generated_state(config, merged_opencode, updated_toml)

    backups = [
        (paths.toml_path, backup_file(paths.toml_path)),
        (paths.env_path, backup_file(paths.env_path)),
        (paths.opencode_config_path, backup_file(paths.opencode_config_path)),
    ]
    atomic_write(paths.toml_path, updated_toml)
    atomic_write(paths.env_path, updated_env)
    atomic_write(
        paths.opencode_config_path,
        json.dumps(merged_opencode, indent=2, ensure_ascii=False) + "\n",
    )
    return backups


def _prompt(prompt: str, default: str | None = None) -> str:
    suffix = f" [{default}]" if default is not None else ""
    raw = input(f"{prompt}{suffix}: ").strip()
    return raw or (default or "")


def _prompt_yes_no(prompt: str, default: bool = True) -> bool:
    hint = "Y/n" if default else "y/N"
    choice = _prompt(f"{prompt} [{hint}]").lower()
    if not choice:
        return default
    if choice in ("y", "yes"):
        return True
    if choice in ("n", "no"):
        return False
    raise ConfigWizardError("Please answer yes or no.")


def prompt_for_config() -> tuple[LLMConfigInput, bool]:
    print("FM-Agent LLM configuration")
    print()
    provider_id = _prompt("Provider ID", "openrouter")
    provider_name = _prompt("Provider name", provider_id.title())
    print()
    print("API protocol:")
    print("  1. OpenAI-compatible")
    print("  2. Anthropic-compatible")
    selected = _prompt("Select", "1")
    api_style: ApiStyle
    if selected == "2":
        api_style = "anthropic"
    elif selected == "1":
        api_style = "openai"
    else:
        raise ConfigWizardError("Protocol selection must be 1 or 2.")

    default_base = (
        "https://openrouter.ai/api/v1"
        if api_style == "openai"
        else "https://api.anthropic.com/v1"
    )
    base_url = _prompt("API base URL", default_base)
    model_id = _prompt("Model ID")
    api_key = getpass("API key: ").strip()
    validate = _prompt_yes_no("Validate generated configuration?", default=True)
    config = LLMConfigInput(
        provider_id=provider_id,
        provider_name=provider_name,
        api_style=api_style,
        base_url=base_url,
        model_id=model_id,
        api_key=api_key,
    )
    return config, validate


def run_wizard(project_root: Path) -> int:
    paths = default_paths(project_root)
    config, validate = prompt_for_config()
    print()
    print(_preview(config, paths))
    print()
    if not _prompt_yes_no("Continue?", default=True):
        print("Aborted.")
        return 1

    backups = apply_configuration(config, paths, validate=validate)
    print(f"✓ Updated {paths.toml_path}")
    print(f"✓ Updated {paths.env_path}")
    print(f"✓ Updated {paths.opencode_config_path}")
    for path, backup in backups:
        if backup is not None:
            print(f"✓ Backed up {path} -> {backup}")
    if validate:
        print("✓ Configuration syntax is valid")
    return 0

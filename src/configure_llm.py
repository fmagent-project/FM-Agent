from __future__ import annotations

import argparse
import json
import hashlib
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

from dotenv import dotenv_values

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
    "LLM_EFFORT",
    "OPENCODE_MODEL_PROVIDER",
    "LLM_API_STYLE",
)
_LLM_ENV_KEYS = (ENV_SECRET_KEY, *ENV_LEGACY_LLM_KEYS)


class ConfigWizardError(RuntimeError):
    pass


ApiStyle = Literal["openai", "anthropic"]
_BACKENDS = ("opencode", "auto", "codex-cli", "claude-cli")
_EFFORTS = ("", "low", "medium", "high")
_LLM_TOML_KEYS = ("name", "provider", "base_url", "backend", "effort", "api_style")
_TOML_KEY_BY_ENV_KEY = {
    "LLM_API_BASE_URL": "base_url",
    "LLM_MODEL": "name",
    "FM_AGENT_MODEL_BACKEND": "backend",
    "LLM_EFFORT": "effort",
    "OPENCODE_MODEL_PROVIDER": "provider",
    "LLM_API_STYLE": "api_style",
}


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
    validate_llm_setting("backend", config.backend)


def validate_llm_setting(key: str, value: str) -> None:
    """Validate one non-secret [llm] setting accepted by the lightweight CLI."""
    if key not in _LLM_TOML_KEYS:
        raise ConfigWizardError(f"Unsupported LLM setting: {key}")
    if key == "provider" and not value.strip():
        raise ConfigWizardError("Provider ID must not be empty.")
    if key == "base_url":
        validate_base_url(value.strip())
    elif key == "backend" and value not in _BACKENDS:
        supported = ", ".join(_BACKENDS)
        raise ConfigWizardError(
            f"Backend must be one of: {supported}; got: {value!r}"
        )
    elif key == "api_style":
        adapter_for_api_style(value)  # type: ignore[arg-type]


def detect_opencode_config_path(home: Path | None = None) -> Path:
    custom_config = os.environ.get("OPENCODE_CONFIG")
    if custom_config:
        return Path(custom_config).expanduser()
    custom_config_dir = os.environ.get("OPENCODE_CONFIG_DIR")
    if custom_config_dir:
        config_dir = Path(custom_config_dir).expanduser()
        jsonc = config_dir / "opencode.jsonc"
        return jsonc if jsonc.exists() else config_dir / "opencode.json"
    home = home or Path.home()
    if os.name == "nt":
        appdata = os.environ.get("APPDATA")
        config_dir = (
            Path(appdata) / "opencode"
            if appdata
            else home / "AppData" / "Roaming" / "opencode"
        )
    else:
        xdg = os.environ.get("XDG_CONFIG_HOME")
        config_dir = Path(xdg) / "opencode" if xdg else home / ".config" / "opencode"
    jsonc = config_dir / "opencode.jsonc"
    if jsonc.exists():
        return jsonc
    return config_dir / "opencode.json"


def default_paths(project_root: Path) -> WizardPaths:
    return WizardPaths(
        project_root=project_root,
        env_path=project_root / ".env",
        toml_path=_fm_agent_config_path(project_root),
        opencode_config_path=detect_opencode_config_path(),
    )


def _fm_agent_config_path(project_root: Path) -> Path:
    """Match config.py's FM_AGENT_CONFIG path selection exactly."""
    explicit_config = os.environ.get("FM_AGENT_CONFIG")
    if explicit_config is None:
        # config.py loads the project .env without replacing a real process value.
        explicit_config = dotenv_values(project_root / ".env").get("FM_AGENT_CONFIG")
    return Path(explicit_config) if explicit_config else project_root / "fm-agent.toml"


def mask_secret(secret: str) -> str:
    if not secret:
        return ""
    if len(secret) <= 4:
        return "*" * len(secret)
    return "*" * (len(secret) - 4) + secret[-4:]


def build_provider_entry(config: LLMConfigInput, opencode_secret_path: Path) -> dict:
    return {
        "npm": adapter_for_api_style(config.api_style),
        "options": {
            "baseURL": config.base_url,
            "apiKey": f"{{file:{opencode_secret_path}}}",
        },
        "models": {
            config.model_id: {},
        },
    }


def parse_existing_opencode_config(text: str) -> dict:
    if not text.strip():
        return {}
    try:
        loaded = json.loads(_strip_jsonc(text))
    except json.JSONDecodeError as exc:
        raise ConfigWizardError(
            "Existing OpenCode config is invalid JSON/JSONC; refusing to overwrite it."
        ) from exc
    if not isinstance(loaded, dict):
        raise ConfigWizardError(
            "Existing OpenCode config must be a JSON object at the top level."
        )
    return loaded


def _strip_jsonc(text: str) -> str:
    out: list[str] = []
    in_string = False
    escape = False
    i = 0
    while i < len(text):
        ch = text[i]
        nxt = text[i + 1] if i + 1 < len(text) else ""
        if in_string:
            out.append(ch)
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == '"':
                in_string = False
            i += 1
            continue

        if ch == '"':
            in_string = True
            out.append(ch)
            i += 1
            continue

        if ch == "/" and nxt == "/":
            i += 2
            while i < len(text) and text[i] not in "\r\n":
                i += 1
            continue
        if ch == "/" and nxt == "*":
            i += 2
            terminated = False
            while i < len(text) - 1:
                if text[i] == "*" and text[i + 1] == "/":
                    i += 2
                    terminated = True
                    break
                if text[i] in "\r\n":
                    out.append(text[i])
                i += 1
            if not terminated:
                raise ConfigWizardError(
                    "Existing OpenCode config has an unterminated JSONC block comment."
                )
            continue

        out.append(ch)
        i += 1

    return _remove_trailing_commas("".join(out))


def _remove_trailing_commas(text: str) -> str:
    out: list[str] = []
    in_string = False
    escape = False
    i = 0
    while i < len(text):
        ch = text[i]
        if in_string:
            out.append(ch)
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == '"':
                in_string = False
            i += 1
            continue

        if ch == '"':
            in_string = True
            out.append(ch)
            i += 1
            continue

        if ch == ",":
            j = i + 1
            while j < len(text) and text[j] in " \t\r\n":
                j += 1
            if j < len(text) and text[j] in "}]":
                i += 1
                continue

        out.append(ch)
        i += 1

    return "".join(out)


def merge_opencode_config(
    existing: dict,
    config: LLMConfigInput,
    *,
    opencode_secret_path: Path,
) -> dict:
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
    options["apiKey"] = f"{{file:{opencode_secret_path}}}"
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
_ENV_EXPORT_PREFIX_RE = re.compile(r"^export[^\S\r\n]+")


def _quote_toml_string(value: str) -> str:
    return json.dumps(value, ensure_ascii=False)


def update_llm_settings_toml_text(text: str, updates: dict[str, str]) -> str:
    if not updates:
        raise ConfigWizardError("Provide at least one LLM setting to update.")
    for key, value in updates.items():
        validate_llm_setting(key, value)

    try:
        loaded = tomllib.loads(text)
    except tomllib.TOMLDecodeError as exc:
        raise ConfigWizardError(
            "Existing fm-agent.toml is invalid TOML; refusing to overwrite it."
        ) from exc
    if loaded and not isinstance(loaded, dict):
        raise ConfigWizardError("Existing fm-agent.toml must decode to a table/object.")

    target = {key: _quote_toml_string(value) for key, value in updates.items()}

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


def update_fm_agent_toml_text(text: str, config: LLMConfigInput) -> str:
    return update_llm_settings_toml_text(
        text,
        {
            "name": config.model_id,
            "provider": config.provider_id,
            "base_url": config.base_url,
            "backend": config.backend,
            "api_style": config.api_style,
        },
    )


def update_env_text(text: str, api_key: str) -> str:
    lines = text.splitlines(keepends=True)
    new_lines: list[str] = []
    key_written = False

    for line in lines:
        stripped = line.lstrip()
        if not stripped or stripped.startswith("#"):
            new_lines.append(line)
            continue

        export_prefix = ""
        working = line
        leading = line[: len(line) - len(stripped)]
        export_match = _ENV_EXPORT_PREFIX_RE.match(stripped)
        if export_match:
            export_prefix = leading + export_match.group()
            working = leading + stripped[export_match.end() :]

        key, sep, _value = working.partition("=")
        if not sep:
            new_lines.append(line)
            continue
        env_key = key.strip()
        if env_key == ENV_SECRET_KEY:
            new_lines.append(f"{export_prefix}{ENV_SECRET_KEY}={api_key}\n")
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


def remove_legacy_llm_env_overrides(text: str) -> tuple[str, tuple[str, ...]]:
    """Remove non-secret LLM settings from dotenv text, including ``export`` lines."""
    new_lines: list[str] = []
    removed: list[str] = []
    for line in text.splitlines(keepends=True):
        stripped = line.lstrip()
        if not stripped or stripped.startswith("#"):
            new_lines.append(line)
            continue

        export_match = _ENV_EXPORT_PREFIX_RE.match(stripped)
        working = stripped[export_match.end() :] if export_match else stripped
        key, sep, _value = working.partition("=")
        env_key = key.strip() if sep else ""
        if env_key in ENV_LEGACY_LLM_KEYS:
            if env_key not in removed:
                removed.append(env_key)
            continue
        new_lines.append(line)
    return "".join(new_lines), tuple(removed)


def local_backend_toml_updates(env_path: Path, backend: str) -> dict[str, str]:
    """Keep local CLI model choices when migrating dotenv settings into TOML."""
    validate_llm_setting("backend", backend)
    dotenv_settings = dotenv_values(env_path)
    updates = {"backend": backend}
    for env_key, toml_key in (("LLM_MODEL", "name"), ("LLM_EFFORT", "effort")):
        value = dotenv_settings.get(env_key)
        if value is not None:
            updates[toml_key] = value
    for key, value in updates.items():
        validate_llm_setting(key, value)
    return updates


def live_llm_environment_overrides() -> tuple[str, ...]:
    """Return real process overrides; the wizard must not alter its caller's shell."""
    return tuple(name for name in _LLM_ENV_KEYS if name in os.environ)


def warn_live_llm_environment_overrides() -> None:
    overrides = live_llm_environment_overrides()
    if not overrides:
        return
    print("Warning: these shell environment variables override the saved LLM settings:")
    print(f"  {', '.join(overrides)}")
    print("The wizard cannot change the shell that launched it. Before starting FM-Agent")
    print("in this shell, unset them to use the saved configuration:")
    print(f"  unset {' '.join(overrides)}")


def warn_dotenv_overrides_for_updates(
    env_path: Path,
    updates: dict[str, str],
) -> bool:
    """Warn when the focused TOML update remains shadowed by project dotenv."""
    _updated_env, legacy_overrides = remove_legacy_llm_env_overrides(
        _read_text_if_exists(env_path)
    )
    shadowing = tuple(
        name
        for name in legacy_overrides
        if _TOML_KEY_BY_ENV_KEY[name] in updates
    )
    if not shadowing:
        return False
    print("Warning: these project .env variables still override this TOML update:")
    print(f"  {', '.join(shadowing)}")
    print("The set command does not modify .env. Remove those lines, or run the")
    print("interactive wizard to migrate legacy LLM overrides.")
    return True


def validate_generated_state(
    config: LLMConfigInput,
    merged_opencode: dict,
    updated_toml: str,
    *,
    opencode_secret_path: Path,
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
    options = entry.get("options")
    if (
        not isinstance(options, dict)
        or options.get("apiKey") != f"{{file:{opencode_secret_path}}}"
    ):
        raise ConfigWizardError(
            "Generated OpenCode config does not reference the saved key file."
        )
    models = entry.get("models")
    if not isinstance(models, dict) or config.model_id not in models:
        raise ConfigWizardError(
            f"Generated OpenCode config is missing model '{config.model_id}'."
        )


def backup_file(
    path: Path,
    now: datetime | None = None,
    *,
    private: bool = False,
) -> Path | None:
    if not path.exists():
        return None
    now = now or datetime.now()
    suffix = now.strftime("%Y%m%d-%H%M%S")
    if private:
        backup_dir = _private_backup_root()
        backup_dir.mkdir(parents=True, exist_ok=True)
        backup_dir.chmod(0o700)
        path_slug = str(path.parent.resolve()).strip(os.sep).replace(os.sep, "_") or "project"
        backup_base = backup_dir / f"{path_slug}__{path.name}.bak.{suffix}"
    else:
        backup_base = path.with_name(f"{path.name}.bak.{suffix}")

    # Reserve a distinct destination before copying so rapid or concurrent
    # configuration changes never overwrite an earlier backup.
    mode = 0o600 if private or path.name == ".env" else 0o644
    attempt = 0
    while True:
        backup = (
            backup_base
            if attempt == 0
            else backup_base.with_name(f"{backup_base.name}.{attempt}")
        )
        try:
            fd = os.open(backup, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
        except FileExistsError:
            attempt += 1
            continue
        else:
            os.close(fd)
            break

    try:
        shutil.copy2(path, backup)
    except Exception:
        backup.unlink(missing_ok=True)
        raise
    if private or path.name == ".env":
        backup.chmod(0o600)
    return backup


def _private_backup_root() -> Path:
    if hasattr(os, "getuid"):
        user_component = f"uid-{os.getuid()}"
    else:
        user_component = os.environ.get("USERNAME") or os.environ.get("USER") or "user"
    safe = re.sub(r"[^A-Za-z0-9._-]+", "_", user_component).strip("._-") or "user"
    return Path(tempfile.gettempdir()) / f"fm-agent-config-backups-{safe}"


def _private_opencode_secret_dir() -> Path:
    if os.name == "nt":
        appdata = os.environ.get("APPDATA")
        base_dir = Path(appdata) if appdata else Path.home() / "AppData" / "Roaming"
    else:
        xdg_state = os.environ.get("XDG_STATE_HOME")
        xdg_state_path = Path(xdg_state).expanduser() if xdg_state else None
        base_dir = (
            xdg_state_path
            if xdg_state_path and xdg_state_path.is_absolute()
            else Path.home() / ".local" / "state"
        )
    return base_dir / "fm-agent" / "opencode"


def secret_path_for_provider(config: LLMConfigInput) -> Path:
    safe_provider_id = re.sub(r"[^A-Za-z0-9._-]+", "_", config.provider_id).strip("._-")
    if not safe_provider_id:
        safe_provider_id = "provider"
    digest = hashlib.sha256(config.provider_id.encode("utf-8")).hexdigest()[:10]
    return _private_opencode_secret_dir() / (
        f"fm-agent-opencode-api-key.{safe_provider_id}.{digest}"
    )


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
    secret_path = secret_path_for_provider(config)
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
            f"  - {secret_path}",
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
    opencode_secret_path = secret_path_for_provider(config)

    updated_env = update_env_text(env_text, config.api_key)
    updated_toml = update_fm_agent_toml_text(toml_text, config)
    merged_opencode = merge_opencode_config(
        parse_existing_opencode_config(opencode_text),
        config,
        opencode_secret_path=opencode_secret_path,
    )
    if validate:
        validate_generated_state(
            config,
            merged_opencode,
            updated_toml,
            opencode_secret_path=opencode_secret_path,
        )

    backups = [
        (paths.toml_path, backup_file(paths.toml_path)),
        (paths.env_path, backup_file(paths.env_path, private=True)),
        (
            paths.opencode_config_path,
            backup_file(paths.opencode_config_path, private=True),
        ),
        (opencode_secret_path, backup_file(opencode_secret_path, private=True)),
    ]
    atomic_write(paths.toml_path, updated_toml)
    atomic_write(paths.env_path, updated_env)
    opencode_secret_path.parent.mkdir(parents=True, exist_ok=True)
    opencode_secret_path.parent.chmod(0o700)
    atomic_write(opencode_secret_path, config.api_key + "\n")
    opencode_secret_path.chmod(0o600)
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


def _prompt_backend() -> str:
    print()
    print("Model backend:")
    print("  1. OpenCode")
    print("  2. Auto-detect local Codex or Claude CLI")
    print("  3. Codex CLI")
    print("  4. Claude CLI")
    selected = _prompt("Select", "1")
    backends = {
        "1": "opencode",
        "2": "auto",
        "3": "codex-cli",
        "4": "claude-cli",
    }
    try:
        return backends[selected]
    except KeyError as exc:
        raise ConfigWizardError("Backend selection must be 1, 2, 3, or 4.") from exc


def prompt_for_config() -> tuple[LLMConfigInput, bool]:
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
    print("FM-Agent LLM configuration")
    backend = _prompt_backend()
    if backend != "opencode":
        print()
        print(
            "Local CLI backends use their own authentication; no API key or OpenCode "
            "provider configuration is required."
        )
        return run_local_backend_configuration(project_root, backend)

    paths = default_paths(project_root)
    print()
    config, validate = prompt_for_config()
    print()
    print(_preview(config, paths))
    print()
    warn_live_llm_environment_overrides()
    if live_llm_environment_overrides():
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


def _preview_local_backend_configuration(
    backend: str,
    paths: WizardPaths,
    removed_overrides: tuple[str, ...],
    toml_updates: dict[str, str],
) -> str:
    lines = [
        "FM-Agent local CLI backend configuration",
        "",
        f"Backend: {backend}",
        "",
        "The following files will be updated:",
        f"  - {paths.toml_path}",
    ]
    if removed_overrides:
        lines.extend(
            [
                f"  - {paths.env_path}",
                "",
                "The following legacy dotenv overrides will be removed so they do not",
                f"shadow the selected backend: {', '.join(removed_overrides)}",
            ]
        )
        migrated = [
            f"{key}: {value!r}"
            for key, value in toml_updates.items()
            if key in {"name", "effort"}
        ]
        if migrated:
            lines.extend(
                [
                    "",
                    "The local CLI model settings retained from .env will be written to TOML:",
                    *[f"  - {item}" for item in migrated],
                ]
            )
    else:
        lines.extend(
            [
                "",
                "No legacy LLM overrides were found in the project .env file.",
            ]
        )
    lines.extend(
        [
            "",
            "No API key or OpenCode provider configuration will be changed.",
        ]
    )
    return "\n".join(lines)


def apply_local_backend_configuration(
    backend: str,
    paths: WizardPaths,
) -> tuple[list[tuple[Path, Path | None]], tuple[str, ...]]:
    toml_text = _read_text_if_exists(paths.toml_path)
    if not toml_text:
        raise ConfigWizardError(
            f"fm-agent.toml not found at {paths.toml_path}; refusing to guess a new project config."
        )
    toml_updates = local_backend_toml_updates(paths.env_path, backend)
    updated_toml = update_llm_settings_toml_text(toml_text, toml_updates)
    try:
        tomllib.loads(updated_toml)
    except tomllib.TOMLDecodeError as exc:  # Defensive: the text editor should preserve TOML.
        raise ConfigWizardError("Generated fm-agent.toml is invalid TOML.") from exc

    updated_env, removed_overrides = remove_legacy_llm_env_overrides(
        _read_text_if_exists(paths.env_path)
    )
    backups = [(paths.toml_path, backup_file(paths.toml_path))]
    if removed_overrides:
        backups.append((paths.env_path, backup_file(paths.env_path, private=True)))

    atomic_write(paths.toml_path, updated_toml)
    if removed_overrides:
        atomic_write(paths.env_path, updated_env)
    return backups, removed_overrides


def run_local_backend_configuration(project_root: Path, backend: str) -> int:
    paths = default_paths(project_root)
    _updated_env, removed_overrides = remove_legacy_llm_env_overrides(
        _read_text_if_exists(paths.env_path)
    )
    toml_updates = local_backend_toml_updates(paths.env_path, backend)
    print(
        _preview_local_backend_configuration(
            backend,
            paths,
            removed_overrides,
            toml_updates,
        )
    )
    print()
    warn_live_llm_environment_overrides()
    if live_llm_environment_overrides():
        print()
    if not _prompt_yes_no("Continue?", default=True):
        print("Aborted.")
        return 1

    backups, removed_overrides = apply_local_backend_configuration(backend, paths)
    print(f"Updated {paths.toml_path}")
    if removed_overrides:
        print(f"Removed legacy LLM overrides from {paths.env_path}")
    for path, backup in backups:
        if backup is not None:
            print(f"Backed up {path} -> {backup}")
    return 0


def _preview_llm_settings_update(updates: dict[str, str], toml_path: Path) -> str:
    labels = {
        "name": "Model ID",
        "provider": "Provider ID",
        "base_url": "Base URL",
        "backend": "Backend",
        "effort": "Reasoning effort",
        "api_style": "API protocol",
    }
    settings = [f"{labels[key]}: {value!r}" for key, value in updates.items()]
    return "\n".join(
        [
            "FM-Agent LLM settings update",
            "",
            *settings,
            "",
            "Only the following file will be updated:",
            f"  - {toml_path}",
            "",
            "This command does not change .env or the standalone OpenCode config.",
        ]
    )


def apply_llm_settings_update(
    updates: dict[str, str],
    toml_path: Path,
) -> Path | None:
    toml_text = _read_text_if_exists(toml_path)
    if not toml_text:
        raise ConfigWizardError(
            f"fm-agent.toml not found at {toml_path}; refusing to guess a new project config."
        )
    updated_toml = update_llm_settings_toml_text(toml_text, updates)
    try:
        tomllib.loads(updated_toml)
    except tomllib.TOMLDecodeError as exc:  # Defensive: the text editor should preserve TOML.
        raise ConfigWizardError("Generated fm-agent.toml is invalid TOML.") from exc

    backup = backup_file(toml_path)
    atomic_write(toml_path, updated_toml)
    return backup


def run_llm_settings_update(
    project_root: Path,
    updates: dict[str, str],
    *,
    assume_yes: bool = False,
) -> int:
    paths = default_paths(project_root)
    toml_path = paths.toml_path
    print(_preview_llm_settings_update(updates, toml_path))
    print()
    has_dotenv_override = warn_dotenv_overrides_for_updates(paths.env_path, updates)
    warn_live_llm_environment_overrides()
    if has_dotenv_override or live_llm_environment_overrides():
        print()
    if not assume_yes and not _prompt_yes_no("Continue?", default=True):
        print("Aborted.")
        return 1

    backup = apply_llm_settings_update(updates, toml_path)
    print(f"Updated {toml_path}")
    if backup is not None:
        print(f"Backed up {toml_path} -> {backup}")
    return 0


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Configure FM-Agent's LLM provider or update individual LLM settings."
    )
    subcommands = parser.add_subparsers(dest="command")
    set_parser = subcommands.add_parser(
        "set",
        help="update only the specified non-secret [llm] settings in fm-agent.toml",
    )
    set_parser.add_argument("--name", help="LLM model ID (LLM_MODEL)")
    set_parser.add_argument("--provider", help="OpenCode provider ID (OPENCODE_MODEL_PROVIDER)")
    set_parser.add_argument("--base-url", dest="base_url", help="API base URL (LLM_API_BASE_URL)")
    set_parser.add_argument(
        "--backend",
        choices=_BACKENDS,
        help="model backend: opencode, auto, codex-cli, or claude-cli",
    )
    set_parser.add_argument(
        "--effort",
        choices=_EFFORTS,
        help="reasoning effort: empty, low, medium, or high",
    )
    set_parser.add_argument(
        "--api-style",
        dest="api_style",
        choices=("openai", "anthropic"),
        help="OpenCode adapter API style",
    )
    set_parser.add_argument(
        "--yes",
        action="store_true",
        help="write without asking for confirmation",
    )
    args = parser.parse_args(argv)
    if args.command == "set":
        updates = {
            key: getattr(args, key)
            for key in _LLM_TOML_KEYS
            if getattr(args, key) is not None
        }
        if not updates:
            set_parser.error("provide at least one setting to update")
        args.updates = updates
    return args


def main(argv: list[str] | None = None) -> int:
    try:
        args = _parse_args(argv)
        project_root = Path(__file__).resolve().parents[1]
        if args.command == "set":
            return run_llm_settings_update(
                project_root,
                args.updates,
                assume_yes=args.yes,
            )
        return run_wizard(project_root)
    except KeyboardInterrupt:
        print("\nAborted.")
        return 1
    except ConfigWizardError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())

"""Configure FM-Agent's DeepSeek Harness model route without storing secrets in TOML."""

from __future__ import annotations

import argparse
import os
import re
import shutil
import sys
import tempfile
from getpass import getpass
from pathlib import Path
from urllib.parse import urlparse

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover
    import tomli as tomllib


class ConfigWizardError(RuntimeError):
    pass


_EDITABLE = ("name", "base_url", "api_style", "tool_compat_mode")


def _default_paths() -> tuple[Path, Path]:
    root = Path(__file__).resolve().parents[1]
    explicit_config = os.environ.get("FM_AGENT_CONFIG")
    config_path = Path(explicit_config or root / "fm-agent.toml")
    default_secret = config_path.with_name("secrets.env") if explicit_config else root / ".env"
    secret_path = Path(os.environ.get("FM_AGENT_SECRET_FILE", default_secret))
    return config_path.expanduser(), secret_path.expanduser()


def _validate_url(value: str) -> str:
    value = value.strip().rstrip("/")
    parsed = urlparse(value)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ConfigWizardError("base URL must be an absolute http(s) URL")
    return value


def _replace_toml_value(text: str, key: str, value: str) -> str:
    pattern = re.compile(
        rf'(?m)^(?P<indent>\s*{re.escape(key)}\s*=\s*)"(?:[^"\\]|\\.)*"(?P<tail>\s*(?:#.*)?)$'
    )
    escaped = value.replace("\\", "\\\\").replace('"', '\\"')
    replacement = rf'\g<indent>"{escaped}"\g<tail>'
    updated, count = pattern.subn(replacement, text, count=1)
    if count != 1:
        raise ConfigWizardError(f"[llm].{key} was not found in {key!r} configuration")
    return updated


def _atomic_write(path: Path, content: str, mode: int | None = None) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as output:
            output.write(content)
        if mode is not None:
            os.chmod(temporary, mode)
        os.replace(temporary, path)
    except Exception:
        try:
            os.unlink(temporary)
        except OSError:
            pass
        raise


def _update_secret(path: Path, api_key: str) -> None:
    lines = []
    if path.is_file():
        lines = path.read_text(encoding="utf-8").splitlines()
    replacement = f"LLM_API_KEY={api_key}"
    updated = []
    found = False
    for line in lines:
        if re.match(r"^\s*(?:export\s+)?LLM_API_KEY\s*=", line):
            if not found:
                updated.append(replacement)
                found = True
        else:
            updated.append(line)
    if not found:
        updated.append(replacement)
    _atomic_write(path, "\n".join(updated).rstrip() + "\n", 0o600)


def apply_configuration(
    config_path: Path,
    secret_path: Path,
    *,
    model: str | None,
    base_url: str | None,
    api_style: str | None,
    api_key: str | None,
    tool_compat_mode: str | None = None,
) -> None:
    if not config_path.is_file():
        raise ConfigWizardError(f"configuration file does not exist: {config_path}")
    updates = {}
    if model is not None:
        if not model.strip():
            raise ConfigWizardError("model must not be empty")
        updates["name"] = model.strip()
    if base_url is not None:
        updates["base_url"] = _validate_url(base_url)
    if api_style is not None:
        if api_style not in {"openai", "anthropic"}:
            raise ConfigWizardError("api style must be openai or anthropic")
        updates["api_style"] = api_style
    if tool_compat_mode is not None:
        if tool_compat_mode not in {"qwen-text", "native"}:
            raise ConfigWizardError("tool compatibility mode must be qwen-text or native")
        updates["tool_compat_mode"] = tool_compat_mode
    if api_key is not None and not api_key.strip():
        raise ConfigWizardError("API key must not be empty")

    if updates:
        text = config_path.read_text(encoding="utf-8")
        for key, value in updates.items():
            text = _replace_toml_value(text, key, value)
        # Validate before replacing the current configuration.
        tomllib.loads(text)
        shutil.copy2(config_path, config_path.with_suffix(config_path.suffix + ".bak"))
        _atomic_write(config_path, text)
    if api_key is not None:
        _update_secret(secret_path, api_key.strip())


def _mask(value: str) -> str:
    return "" if not value else "*" * max(4, len(value) - 4) + value[-4:]


def _read_key(path: Path) -> str:
    if not path.is_file():
        return ""
    for line in path.read_text(encoding="utf-8").splitlines():
        match = re.match(r"^\s*(?:export\s+)?LLM_API_KEY\s*=\s*(.*)$", line)
        if match:
            return match.group(1).strip().strip("'\"")
    return ""


def show_configuration(config_path: Path, secret_path: Path) -> None:
    data = tomllib.loads(config_path.read_text(encoding="utf-8"))["llm"]
    print(f"Backend:   {data.get('backend', 'deepseek-harness')}")
    print(f"Model:     {data.get('name', '')}")
    print(f"Base URL:  {data.get('base_url', '')}")
    print(f"API style: {data.get('api_style', '')}")
    print(f"Tool mode: {data.get('tool_compat_mode', 'native')}")
    print(f"API key:   {_mask(_read_key(secret_path)) or '(not set)'}")
    print(f"Config:    {config_path}")
    print(f"Secret:    {secret_path}")


def run_wizard(config_path: Path, secret_path: Path) -> int:
    current = tomllib.loads(config_path.read_text(encoding="utf-8"))["llm"]
    model = input(f"Model [{current.get('name', '')}]: ").strip() or current.get("name", "")
    base_url = input(f"Base URL [{current.get('base_url', '')}]: ").strip() or current.get("base_url", "")
    style = input(f"API style openai/anthropic [{current.get('api_style', 'openai')}]: ").strip() or current.get("api_style", "openai")
    tool_mode = input(
        "Tool compatibility qwen-text/native "
        f"[{current.get('tool_compat_mode', 'native')}]: "
    ).strip() or current.get("tool_compat_mode", "native")
    api_key = getpass("API key (leave empty to keep current): ").strip() or None
    apply_configuration(
        config_path,
        secret_path,
        model=model,
        base_url=base_url,
        api_style=style,
        tool_compat_mode=tool_mode,
        api_key=api_key,
    )
    show_configuration(config_path, secret_path)
    return 0


def _parse_args(argv=None):
    config_path, secret_path = _default_paths()
    parser = argparse.ArgumentParser(description="Configure the DeepSeek Harness model route")
    parser.add_argument("--config", type=Path, default=config_path)
    parser.add_argument("--secret-file", type=Path, default=secret_path)
    sub = parser.add_subparsers(dest="command")
    set_parser = sub.add_parser("set", help="update model settings and/or API key")
    set_parser.add_argument("--model", "--name", dest="model")
    set_parser.add_argument("--base-url")
    set_parser.add_argument("--api-style", choices=("openai", "anthropic"))
    set_parser.add_argument("--tool-compat-mode", choices=("qwen-text", "native"))
    set_parser.add_argument("--api-key")
    sub.add_parser("show", help="show effective stored values with a masked key")
    return parser.parse_args(argv)


def main(argv=None) -> int:
    try:
        args = _parse_args(argv)
        config_path = args.config.expanduser().resolve()
        secret_path = args.secret_file.expanduser().resolve()
        if args.command == "show":
            show_configuration(config_path, secret_path)
            return 0
        if args.command == "set":
            if not any((args.model, args.base_url, args.api_style, args.tool_compat_mode, args.api_key)):
                raise ConfigWizardError("provide at least one value to update")
            apply_configuration(
                config_path,
                secret_path,
                model=args.model,
                base_url=args.base_url,
                api_style=args.api_style,
                tool_compat_mode=args.tool_compat_mode,
                api_key=args.api_key,
            )
            show_configuration(config_path, secret_path)
            return 0
        return run_wizard(config_path, secret_path)
    except (ConfigWizardError, OSError, KeyError, tomllib.TOMLDecodeError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())

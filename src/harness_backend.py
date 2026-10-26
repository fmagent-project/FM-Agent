"""DeepSeek Harness headless backend used by every FM-Agent model call."""

from __future__ import annotations

import os
import shlex
import shutil
import subprocess
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Optional

from config import settings


@dataclass(frozen=True)
class AgentCommand:
    """One non-interactive Harness invocation and its private environment."""

    argv: list[str]
    stdin: Optional[str]
    env: dict[str, str]
    backend: str = "deepseek-harness"


def resolve_model_backend() -> str:
    """Return the only supported model backend."""
    return settings.llm.backend


def is_harness_backend_enabled() -> bool:
    """Return whether model calls are routed through DeepSeek Harness."""
    return resolve_model_backend() == "deepseek-harness"


def _package_root() -> Path:
    return Path(__file__).resolve().parent.parent


def resolve_harness_binary() -> str:
    """Resolve the bundled runtime first, then a developer PATH installation."""
    configured = settings.llm.harness_bin.strip()
    if configured:
        path = Path(configured).expanduser().resolve()
        if path.is_file() and os.access(path, os.X_OK):
            return str(path)
        raise FileNotFoundError(f"DeepSeek Harness executable is not usable: {path}")

    bundled = _package_root() / "vendor" / "deepseek-harness" / "dsh"
    if bundled.is_file() and os.access(bundled, os.X_OK):
        return str(bundled)

    found = shutil.which("dsh")
    if found:
        return found
    raise FileNotFoundError(
        "DeepSeek Harness executable not found; install the offline bundle or set FM_AGENT_DSH_BIN"
    )


def resolve_harness_patch() -> str:
    """Resolve the checked-in FM-Agent provider overlay."""
    configured = settings.llm.harness_patch.strip()
    path = (
        Path(configured).expanduser().resolve()
        if configured
        else _package_root() / "config" / "dsh-fm-agent.patch.yml"
    )
    if not path.is_file():
        raise FileNotFoundError(f"DeepSeek Harness FM-Agent patch not found: {path}")
    return str(path)


def _compat_runner_argv() -> list[str]:
    """Return the bundled Python runner used for Qwen text-tool compatibility."""
    root = _package_root()
    python = root / "vendor" / "python" / "bin" / "python3"
    runner = root / "scripts" / "run_harness_with_tool_proxy.py"
    if not python.is_file() or not os.access(python, os.X_OK):
        raise FileNotFoundError(f"Bundled Python executable is not usable: {python}")
    if not runner.is_file():
        raise FileNotFoundError(f"FM-Agent tool compatibility runner is missing: {runner}")
    return [str(python), str(runner), "--"]


def _compose_stdin(prompt: str, files: list[str]) -> str:
    if not files:
        return prompt
    file_list = "\n".join(f"- {path}" for path in files)
    return f"Read these file(s) before acting:\n{file_list}\n\n{prompt}"


def build_harness_environment(cwd: str) -> dict[str, str]:
    """Build a deterministic, non-interactive environment for one invocation."""
    env = os.environ.copy()
    env["LLM_API_KEY"] = settings.llm.api_key
    env["LLM_API_BASE_URL"] = settings.llm.base_url.rstrip("/")
    env["LLM_MODEL"] = settings.llm.name
    env["LLM_API_STYLE"] = settings.llm.api_style
    env["DSH_HOME"] = os.environ.get(
        "FM_AGENT_DSH_HOME",
        os.path.join(os.path.abspath(cwd), "fm_agent", ".dsh"),
    )
    env["DSH_TELEMETRY_DISABLED"] = "1"
    env["DSH_PERMISSION_MODE"] = "danger-full-access"
    env["PWD"] = os.path.abspath(cwd)
    return env


def build_agent_command(model, prompt, cwd, files=None, backend=None, effort=None):
    """Build one headless Harness task while retaining the legacy call shape."""
    resolved = (backend or resolve_model_backend()).strip().lower()
    if resolved != "deepseek-harness":
        raise ValueError(f"unsupported model backend: {resolved}")
    cwd = os.path.abspath(cwd)
    env = build_harness_environment(cwd)
    if model:
        env["LLM_MODEL"] = str(model).strip()
    harness_argv = [
        resolve_harness_binary(),
        "--profile",
        "headless",
        "--patch",
        resolve_harness_patch(),
        "-",
    ]
    if settings.llm.tool_compat_mode == "qwen-text":
        if settings.llm.api_style != "openai":
            raise ValueError("qwen-text tool compatibility requires api_style=openai")
        argv = [*_compat_runner_argv(), *harness_argv]
    else:
        argv = harness_argv
    return AgentCommand(
        argv=argv,
        stdin=_compose_stdin(prompt, list(files or [])),
        env=env,
    )


def command_argv(command):
    return command.argv if isinstance(command, AgentCommand) else list(command)


def command_stdin(command):
    return command.stdin if isinstance(command, AgentCommand) else None


def command_env(command, cwd):
    return command.env if isinstance(command, AgentCommand) else build_harness_environment(cwd)


def command_display(command):
    suffix = " <stdin>" if command_stdin(command) is not None else ""
    return shlex.join(command_argv(command)) + suffix


def command_with_json_events(command):
    """Return a traced headless command that emits NDJSON lifecycle events.

    Normal message-style calls must keep stdout as the final assistant text,
    but file-oriented Stage 1/2/6 calls do not consume stdout.  Enabling
    Harness ``--json`` for those calls prevents an empty trace when a model
    returns reasoning without final content.
    """

    argv = list(command_argv(command))
    if "--json" in argv:
        return command
    try:
        profile_index = argv.index("--profile")
        is_headless = argv[profile_index + 1] == "headless"
    except (ValueError, IndexError):
        is_headless = False
    if not is_headless:
        return command
    input_index = len(argv) - 1 if argv and argv[-1] == "-" else len(argv)
    argv.insert(input_index, "--json")
    if isinstance(command, AgentCommand):
        return replace(command, argv=argv)
    return argv


def messages_to_prompt(messages):
    parts = []
    for message in messages:
        role = message.get("role", "user")
        content = message.get("content", "")
        if not isinstance(content, str):
            content = "\n".join(
                block.get("text", "")
                for block in content
                if isinstance(block, dict)
            )
        parts.append(f"{role.upper()}:\n{content}")
    return "\n\n".join(parts)


def run_agent_for_messages(
    model,
    messages,
    *,
    text_only=False,
    proxy_audit_path=None,
):
    """Run a message-style request through the same Harness backend.

    ``text_only`` retains DeepSeek Harness as the provider/runtime boundary but
    prevents its general-purpose tools from being advertised to structured JSON
    calls.  Those calls are reasoning requests, not file-writing Agent turns.
    """
    prompt = (
        "Answer the following conversation directly. Preserve requested output tags "
        "exactly and do not add unrelated commentary.\n\n"
        f"{messages_to_prompt(messages)}"
    )
    cwd = os.path.abspath(os.getcwd())
    command = build_agent_command(model=model, prompt=prompt, cwd=cwd)
    child_env = dict(command.env)
    if text_only:
        child_env["FM_AGENT_TOOL_PROXY_TEXT_ONLY"] = "1"
    if proxy_audit_path:
        child_env["FM_AGENT_TOOL_PROXY_TRACE_PATH"] = os.path.abspath(
            proxy_audit_path
        )
    command = replace(command, env=child_env)
    result = subprocess.run(
        command.argv,
        input=command.stdin,
        cwd=cwd,
        env=command.env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=settings.runtime.agent_timeout_s,
        check=False,
    )
    if result.returncode != 0:
        output = "\n".join(
            part.strip()
            for part in (result.stdout or "", result.stderr or "")
            if part.strip()
        )[-4000:]
        raise RuntimeError(
            f"deepseek-harness exited with code {result.returncode}: {output}"
        )
    return (result.stdout or "").strip(), {}

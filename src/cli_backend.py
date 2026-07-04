import os
import shlex
import subprocess
from dataclasses import dataclass
from typing import Optional

from dotenv import load_dotenv


load_dotenv()


_BACKEND_ALIASES = {
    "codex": "codex-cli",
    "codex-cli": "codex-cli",
    "claude": "claude-cli",
    "claude-cli": "claude-cli",
    "opencode": "opencode",
    "open-code": "opencode",
}


@dataclass(frozen=True)
class AgentCommand:
    argv: list[str]
    stdin: Optional[str] = None
    backend: str = "opencode"


def _normalize_backend(value):
    backend = (value or "").strip().lower()
    if not backend or backend in {"0", "false", "no", "off"}:
        return "opencode"
    if backend == "auto":
        return "auto"
    return _BACKEND_ALIASES.get(backend, backend)


def resolve_model_backend():
    backend = _normalize_backend(os.environ.get("FM_AGENT_MODEL_BACKEND"))
    if backend != "auto":
        return backend

    host_hint = (os.environ.get("FM_AGENT_HOST") or os.environ.get("FM_AGENT_CLIENT") or "").lower()
    if "claude" in host_hint:
        return "claude-cli"
    if "codex" in host_hint:
        return "codex-cli"

    claude_markers = ("CLAUDE_PLUGIN_ROOT", "CLAUDE_CODE_ENTRYPOINT")
    if any(os.environ.get(name) for name in claude_markers):
        return "claude-cli"

    codex_markers = ("CODEX_HOME", "CODEX_SANDBOX", "CODEX_EXECUTION_MODE")
    if any(os.environ.get(name) for name in codex_markers):
        return "codex-cli"

    return "codex-cli"


def is_cli_backend_enabled():
    return resolve_model_backend() in {"codex-cli", "claude-cli"}


def cli_effort():
    return os.environ.get("LLM_EFFORT", "").strip()


def _compose_stdin(prompt, files):
    if not files:
        return prompt
    file_list = "\n".join(f"- {path}" for path in files)
    return (
        "Read these file(s) before acting:\n"
        f"{file_list}\n\n"
        f"{prompt}"
    )


def build_agent_command(model, prompt, cwd, files=None, backend=None, effort=None):
    resolved = _normalize_backend(backend) if backend else resolve_model_backend()
    if resolved == "auto":
        resolved = resolve_model_backend()
    if resolved not in {"codex-cli", "claude-cli"}:
        raise ValueError(f"unsupported CLI backend: {resolved}")

    cwd = os.path.abspath(cwd)
    stdin = _compose_stdin(prompt, files or [])
    model = (model or "").strip()
    effort = (effort if effort is not None else cli_effort()).strip()

    if resolved == "codex-cli":
        argv = [
            "codex",
            "exec",
            "--sandbox",
            "danger-full-access",
            "--dangerously-bypass-approvals-and-sandbox",
            "--skip-git-repo-check",
            "-C",
            cwd,
        ]
        if model:
            argv += ["--model", model]
        if effort:
            argv += ["-c", f'model_reasoning_effort="{effort}"']
        argv.append("-")
        return AgentCommand(argv=argv, stdin=stdin, backend=resolved)

    argv = [
        "claude",
        "-p",
        "--output-format",
        "text",
        "--no-session-persistence",
        "--dangerously-skip-permissions",
        "--permission-mode",
        "bypassPermissions",
        "--add-dir",
        cwd,
    ]
    if model:
        argv += ["--model", model]
    if effort:
        argv += ["--effort", effort]
    return AgentCommand(argv=argv, stdin=stdin, backend=resolved)


def command_argv(command):
    if isinstance(command, AgentCommand):
        return command.argv
    return list(command)


def command_stdin(command):
    if isinstance(command, AgentCommand):
        return command.stdin
    return None


def command_display(command):
    argv = command_argv(command)
    suffix = " <stdin>" if command_stdin(command) is not None else ""
    return shlex.join(argv) + suffix


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


def run_agent_for_messages(model, messages):
    prompt = (
        "Answer the following conversation directly. Preserve any requested output tags "
        "exactly and do not add unrelated commentary.\n\n"
        f"{messages_to_prompt(messages)}"
    )
    cwd = os.path.abspath(os.getcwd())
    command = build_agent_command(model=model, prompt=prompt, cwd=cwd)
    result = subprocess.run(
        command.argv,
        input=command.stdin,
        cwd=cwd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=1800,
        check=False,
    )
    if result.returncode != 0:
        output = (result.stdout or "")[-4000:]
        raise RuntimeError(
            f"{command.backend} exited with code {result.returncode}: {output}"
        )
    return result.stdout.strip(), {}

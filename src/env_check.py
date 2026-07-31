"""
Pre-flight environment checks for FM-Agent.
Verifies the runtime setup is suitable before launching the pipeline,
informing the user of missing configuration and potential issues.
"""

import os
import json
import sys
import logging

OH_MY_OPENAGENT_CONFIG = os.path.expanduser("~/.config/opencode/oh-my-openagent.json")


def _check_llm_api_key(config):
    ok = bool(config.LLM_API_KEY and config.LLM_API_KEY not in (
        "", "YOUR_LLM_API_KEY",
        "sk-or-v1-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    ))
    return ok, "LLM_API_KEY is not set in .env file" if not ok else None


def _check_oh_my_openagent():
    import subprocess
    try:
        subprocess.run(
            ["bunx", "oh-my-openagent", "--version"],
            capture_output=True, text=True, timeout=10,
        )
        return True, None
    except Exception:
        return False, "oh-my-openagent is not installed (bunx unavailable or timed out)"


def _check_comment_checker():
    if not os.path.exists(OH_MY_OPENAGENT_CONFIG):
        return False, f"oh-my-openagent config not found at {OH_MY_OPENAGENT_CONFIG}"

    try:
        with open(OH_MY_OPENAGENT_CONFIG, "r") as f:
            cfg = json.load(f)
    except (json.JSONDecodeError, IOError) as e:
        return False, f"Failed to read {OH_MY_OPENAGENT_CONFIG}: {e}"

    if "comment-checker" not in cfg.get("disabled_hooks", []):
        return False, (
            "comment-checker hook is NOT disabled. FM-Agent writes function "
            "specifications as comment blocks, which the comment-checker may "
            "intercept, wasting tokens or deleting specs. Add "
            '"disabled_hooks": ["comment-checker"] to ' + OH_MY_OPENAGENT_CONFIG
        )

    return True, None


def _check_codegraph_version(config):
    """Surface a missing or stale codegraph pinned build so the user knows to
    re-run ./install.sh — otherwise C/C++ extraction silently degrades to the
    regex fallback (or uses a wrong version). Non-blocking, like every check here.
    """
    import subprocess
    from src.languages.codegraph import _codegraph_cmd

    want = config.settings.codegraph.version.strip().removeprefix("v")
    if not want:
        return True, None  # no version pinned -> nothing to verify

    cmd = _codegraph_cmd()
    try:
        got = subprocess.run(
            [cmd, "--version"], capture_output=True, text=True, timeout=10
        ).stdout.strip()
    except (OSError, subprocess.SubprocessError):
        got = ""

    bin_dir = os.path.expanduser(config.settings.codegraph.bin_dir)
    if not got:
        return False, (
            f"codegraph (pinned v{want}) is not installed at {bin_dir} — run "
            "./install.sh (C/C++ extraction falls back to the regex extractor otherwise)."
        )
    if got != want:
        return False, (
            f"codegraph {got} is installed but v{want} is pinned in fm-agent.toml — "
            "re-run ./install.sh to install the pinned build."
        )
    return True, None


def _memory_path(work_dir):
    return os.path.join(work_dir, ".env_check_memory")


def _load_ignored(work_dir):
    path = _memory_path(work_dir)
    if os.path.exists(path):
        try:
            with open(path, "r") as f:
                return set(line.strip() for line in f if line.strip())
        except IOError:
            pass
    return set()


def _save_ignored(work_dir, ignored):
    path = _memory_path(work_dir)
    with open(path, "w") as f:
        for item in sorted(ignored):
            f.write(item + "\n")


def is_interactive():
    return sys.stdin.isatty()


def run(proj_dir, config):
    """Run all env checks.  Return True to proceed, False to abort."""
    from src.cli_backend import is_cli_backend_enabled

    work_dir = os.path.join(proj_dir, "fm_agent")
    os.makedirs(work_dir, exist_ok=True)
    ignored = _load_ignored(work_dir)

    checks = [
        ("codegraph-version", "codegraph pinned build installed",
         lambda: _check_codegraph_version(config)),
    ]
    if not is_cli_backend_enabled():
        checks[:0] = [
            ("llm_key", "LLM API Key configured",
             lambda: _check_llm_api_key(config)),
            ("oh-my-openagent", "oh-my-openagent installed",
             _check_oh_my_openagent),
            ("comment-checker-disabled", "comment-checker hook disabled",
             _check_comment_checker),
        ]

    warnings = []
    for check_id, label, fn in checks:
        if check_id in ignored:
            continue
        ok, msg = fn()
        if not ok:
            warnings.append((check_id, label, msg))

    if not warnings:
        return True

    lines = [
        "",
        "=" * 62,
        "  FM-Agent environment check — potential issues found:",
        "=" * 62,
    ]
    for _, label, msg in warnings:
        lines.append(f"  [!] {label}: {msg}")
    lines.append("=" * 62)
    lines.append("")
    for line in lines:
        logging.warning(line)

    if not is_interactive():
        logging.warning(
            "Non-interactive session — proceeding with warnings. "
            "Fix the issues above for best results."
        )
        return True

    print("\n".join(lines))
    print("These issues may cause FM-Agent to fail or produce wrong results.\n")
    print("  [p] proceed anyway (warn again next run)")
    print("  [i] ignore — don't warn again (saved to fm_agent/.env_check_memory)")
    print("  [q] quit — fix the issues first\n")

    while True:
        choice = input("Your choice [p/i/q]: ").strip().lower()
        if choice == "p":
            return True
        elif choice == "i":
            _save_ignored(work_dir, ignored | {cid for cid, _, _ in warnings})
            return True
        elif choice == "q":
            print("\n[FM-Agent] Aborted. Fix the issues listed above and run again.\n")
            return False
        else:
            print("Invalid choice — enter p, i, or q.")

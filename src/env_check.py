"""
Pre-flight environment checks for FM-Agent.
Verifies the runtime setup is suitable before launching the pipeline,
informing the user of missing configuration and potential issues.
"""

import os
import sys
import logging


def _check_llm_api_key(config):
    ok = bool(config.LLM_API_KEY and config.LLM_API_KEY not in (
        "", "YOUR_LLM_API_KEY",
    ))
    return (
        ok,
        "LLM_API_KEY is not set in the configured secret file or environment"
        if not ok
        else None,
    )


def _check_harness():
    import subprocess
    from src.harness_backend import resolve_harness_binary

    try:
        executable = resolve_harness_binary()
        result = subprocess.run(
            [executable, "--version"],
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return False, f"DeepSeek Harness runtime is unavailable: {exc}"
    if result.returncode != 0:
        return False, f"DeepSeek Harness --version exited {result.returncode}"
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
    work_dir = os.path.join(proj_dir, "fm_agent")
    os.makedirs(work_dir, exist_ok=True)
    ignored = _load_ignored(work_dir)

    checks = [
        ("llm-key", "LLM API key configured", lambda: _check_llm_api_key(config)),
        ("deepseek-harness", "DeepSeek Harness runtime available", _check_harness),
        ("codegraph-version", "codegraph pinned build installed",
         lambda: _check_codegraph_version(config)),
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

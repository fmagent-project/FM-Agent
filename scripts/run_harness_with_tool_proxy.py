#!/usr/bin/env python3
"""Run one DeepSeek Harness process behind the Qwen text-tool proxy."""

from __future__ import annotations

import os
import signal
import subprocess
import sys
import threading
from pathlib import Path


APP_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(APP_ROOT))

from src.tool_compat_proxy import ProxyConfig, create_server  # noqa: E402


def _positive_int(value: str, default: int) -> int:
    try:
        parsed = int(value)
    except ValueError:
        return default
    return parsed if parsed > 0 else default


def main(argv: list[str] | None = None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    if arguments[:1] == ["--"]:
        arguments = arguments[1:]
    if not arguments:
        print("FM-Agent tool compatibility runner: missing Harness command", file=sys.stderr)
        return 2

    upstream_url = os.environ.get("LLM_API_BASE_URL", "").strip()
    api_key = os.environ.get("LLM_API_KEY", "")
    if not upstream_url:
        print("FM-Agent tool compatibility runner: LLM_API_BASE_URL is empty", file=sys.stderr)
        return 2
    if os.environ.get("LLM_API_STYLE", "openai") != "openai":
        print("FM-Agent Qwen text-tool mode requires LLM_API_STYLE=openai", file=sys.stderr)
        return 2

    config = ProxyConfig(
        upstream_base_url=upstream_url,
        api_key=api_key,
        timeout_seconds=_positive_int(
            os.environ.get("FM_AGENT_TOOL_PROXY_TIMEOUT_SECONDS", "1800"), 1800
        ),
        ca_bundle=os.environ.get("FM_AGENT_UPSTREAM_CA_BUNDLE", ""),
        insecure_tls=os.environ.get("FM_AGENT_UPSTREAM_INSECURE_TLS", "0") == "1",
        audit_path=os.environ.get("FM_AGENT_TOOL_PROXY_TRACE_PATH", ""),
        text_only=os.environ.get("FM_AGENT_TOOL_PROXY_TEXT_ONLY", "0") == "1",
    )
    server = create_server(config)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    child_env = os.environ.copy()
    child_env["LLM_API_BASE_URL"] = f"http://127.0.0.1:{server.server_port}/v1"
    child_env["LLM_API_KEY"] = "fm-agent-loopback-tool-proxy"
    for key in ("NO_PROXY", "no_proxy"):
        current = child_env.get(key, "")
        entries = [entry for entry in current.split(",") if entry]
        for local in ("127.0.0.1", "localhost"):
            if local not in entries:
                entries.append(local)
        child_env[key] = ",".join(entries)

    child: subprocess.Popen | None = None

    def forward(signum: int, _frame: object) -> None:
        if child is not None and child.poll() is None:
            child.send_signal(signum)

    old_handlers: dict[int, object] = {}
    for signum in (signal.SIGTERM, signal.SIGINT):
        old_handlers[signum] = signal.getsignal(signum)
        signal.signal(signum, forward)
    try:
        child = subprocess.Popen(arguments, env=child_env)
        return child.wait()
    except OSError as exc:
        print(f"FM-Agent could not start DeepSeek Harness: {exc}", file=sys.stderr)
        return 127
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
        for signum, handler in old_handlers.items():
            signal.signal(signum, handler)


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""Test text connectivity and the Harness tool round trip."""

from __future__ import annotations

import argparse
import json
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import config
from src.harness_backend import run_agent_for_messages


MARKER = "FM_AGENT_MODEL_CONNECTIVITY_OK"
TOOL_MARKER = "FM_AGENT_MODEL_TOOL_OK"
WRITE_MARKER = "FM_AGENT_MODEL_WRITE_OK"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--text-only",
        action="store_true",
        help="skip the bash tool round-trip test",
    )
    args = parser.parse_args(argv)
    print("Backend: deepseek-harness", file=sys.stderr)
    print(f"Model:   {config.LLM_MODEL}", file=sys.stderr)
    print(f"URL:     {config.LLM_API_BASE_URL}", file=sys.stderr)
    print(f"Tools:   {config.settings.llm.tool_compat_mode}", file=sys.stderr)
    try:
        text, _usage = run_agent_for_messages(
            config.LLM_MODEL,
            [{
                "role": "user",
                "content": f"Return exactly {MARKER} and nothing else.",
            }],
        )
    except Exception as exc:
        print(f"Connectivity test failed: {exc}", file=sys.stderr)
        return 1
    text_value = text.strip()
    reasoning_only = (
        config.settings.llm.tool_compat_mode == "qwen-text" and not text_value
    )
    if text_value != MARKER and not reasoning_only:
        print(f"Connectivity test returned unexpected text: {text!r}", file=sys.stderr)
        return 1
    if args.text_only:
        if reasoning_only:
            print(
                "Connectivity request returned no final content; rerun without "
                "--text-only so the tool proof can verify the model path.",
                file=sys.stderr,
            )
            return 1
        print(MARKER)
        return 0
    if reasoning_only:
        print(
            "Text request returned reasoning without final content; continuing "
            "with the executable tool proof.",
            file=sys.stderr,
        )

    with tempfile.TemporaryDirectory(prefix="fm-agent-model-tool-") as directory:
        proof = Path(directory) / "tool-proof.txt"
        prompt = (
            "You must use the bash tool exactly once to run this command:\n"
            f"printf {TOOL_MARKER} > {proof}\n"
            f"After the command succeeds, return exactly {TOOL_MARKER} and nothing else."
        )
        try:
            text, _usage = run_agent_for_messages(
                config.LLM_MODEL,
                [{"role": "user", "content": prompt}],
            )
        except Exception as exc:
            print(f"Tool round-trip test failed: {exc}", file=sys.stderr)
            return 1
        try:
            proof_text = proof.read_text(encoding="utf-8")
        except OSError:
            proof_text = ""
        tool_text = text.strip()
        acceptable_text = tool_text in {"", TOOL_MARKER}
        if not acceptable_text or proof_text != TOOL_MARKER:
            print(
                "Tool round-trip did not execute the required bash command "
                f"(model text={text!r}, proof={proof_text!r}).",
                file=sys.stderr,
            )
            return 1

        write_proof = Path(directory) / "tool-write-proof.json"
        write_prompt = (
            "You must use the write tool exactly once to create this file:\n"
            f"{write_proof}\n"
            f"Its exact content must be {{\"status\":\"{WRITE_MARKER}\"}}.\n"
            f"After the write succeeds, return exactly {WRITE_MARKER} and nothing else."
        )
        try:
            write_text, _usage = run_agent_for_messages(
                config.LLM_MODEL,
                [{"role": "user", "content": write_prompt}],
            )
        except Exception as exc:
            print(f"Write-tool round-trip test failed: {exc}", file=sys.stderr)
            return 1
        try:
            write_data = json.loads(write_proof.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            write_data = None
        if write_text.strip() not in {"", WRITE_MARKER} or write_data != {
            "status": WRITE_MARKER
        }:
            print(
                "Write-tool round-trip did not create the required JSON file "
                f"(model text={write_text!r}, proof={write_data!r}).",
                file=sys.stderr,
            )
            return 1
    print(MARKER)
    print(TOOL_MARKER)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

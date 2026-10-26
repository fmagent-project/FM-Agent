#!/usr/bin/env python3
"""One-response loopback-only OpenAI-compatible server for offline verification."""

from __future__ import annotations

import argparse
import json
import re
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


class Handler(BaseHTTPRequestHandler):
    response_text = "FM_AGENT_HARNESS_OFFLINE_OK"
    request_log: Path
    mode = "normal"

    def do_POST(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        length = int(self.headers.get("content-length", "0"))
        raw = self.rfile.read(length)
        try:
            body = json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError):
            self.send_error(400, "invalid JSON")
            return
        record = {
            "path": self.path,
            "authorization_present": bool(self.headers.get("authorization")),
            "model": body.get("model"),
            "stream": body.get("stream"),
            "tools_present": "tools" in body,
            "tool_count": len(body.get("tools", [])) if isinstance(body.get("tools"), list) else 0,
            "chat_template_kwargs": body.get("chat_template_kwargs"),
            "messages_text": json.dumps(body.get("messages"), ensure_ascii=False),
        }
        with self.request_log.open("a", encoding="utf-8") as stream:
            stream.write(json.dumps(record, sort_keys=True) + "\n")
        if not self.path.endswith("/chat/completions"):
            self.send_error(404)
            return
        messages_text = record["messages_text"]
        response_text = self.response_text
        finish_reason = "stop"
        tool_marker = None
        if self.mode == "unparsed":
            response_text = (
                "<tool_call><function=not_advertised>"
                "<parameter=x>1</parameter></function></tool_call>"
            )
        elif "FM_AGENT_MODEL_CONNECTIVITY_OK" in messages_text:
            response_text = "FM_AGENT_MODEL_CONNECTIVITY_OK"
        elif "FM_AGENT_MODEL_TOOL_OK" in messages_text and "<tools>" in messages_text:
            tool_marker = "FM_AGENT_MODEL_TOOL_OK"
        elif "FM_AGENT_PROXY_TOOL_OK" in messages_text and "<tools>" in messages_text:
            tool_marker = "FM_AGENT_PROXY_TOOL_OK"
        elif "FM_AGENT_PROXY_WRITE_OK" in messages_text and "<tools>" in messages_text:
            tool_marker = "FM_AGENT_PROXY_WRITE_OK"
        elif "FM_AGENT_MODEL_WRITE_OK" in messages_text and "<tools>" in messages_text:
            tool_marker = "FM_AGENT_MODEL_WRITE_OK"
        elif "FM_AGENT_PROXY_SIDECARS_OK" in messages_text and "<tools>" in messages_text:
            tool_marker = "FM_AGENT_PROXY_SIDECARS_OK"

        completed_tool = '\\"status\\":\\"completed\\"' in messages_text
        phases_workflow = re.search(
            r"(/[^\\\"\s]*/fm_agent/workflow_generate_phases\.md)", messages_text
        )
        context_workflow = re.search(
            r"(/[^\\\"\s]*/fm_agent/workflow_generate_domain_context\.md)",
            messages_text,
        )
        spec_workflow = re.search(
            r"(/[^\\\"\s]*/fm_agent/workflow_spec_step4_batch\.md)",
            messages_text,
        )

        if phases_workflow:
            if completed_tool:
                response_text = "Stage 1 outputs created."
            else:
                project_root = Path(phases_workflow.group(1)).parents[1]
                phases_path = project_root / "fm_agent" / "phases.json"
                phases_content = json.dumps(
                    {
                        "project": project_root.name,
                        "languages": ["c"],
                        "file_extensions": ["c"],
                        "phases": [{
                            "phase": 1,
                            "name": "Core",
                            "description": "Core source files.",
                            "modules": [{
                                "name": "core",
                                "description": "Core implementation.",
                                "source_files": ["plain.c"],
                            }],
                            "depends_on_phases": [],
                        }],
                    },
                    separators=(",", ":"),
                )
                arguments = json.dumps(
                    {"file_path": str(phases_path), "content": phases_content},
                    separators=(",", ":"),
                )
                response_text = (
                    "<tool_call>\n"
                    f'{{"function=write", "arguments": {arguments}}}\n'
                    "</tool_call>"
                )
        elif context_workflow:
            if completed_tool:
                response_text = "Stage 2 outputs created."
            else:
                project_root = Path(context_workflow.group(1)).parents[1]
                domain = project_root / "fm_agent" / "spec_prompts" / "domain_context"
                engine_arguments = json.dumps(
                    {
                        "file_path": str(domain / "engine_overview.txt"),
                        "content": "Single-function C project with no global state.",
                    },
                    separators=(",", ":"),
                )
                types_arguments = json.dumps(
                    {
                        "file_path": str(domain / "phase_01_types.txt"),
                        "content": "int answer(void) returns the constant 42.",
                    },
                    separators=(",", ":"),
                )
                response_text = (
                    "<tool_call>\n"
                    f'{{"function=write", "arguments": {engine_arguments}}}\n'
                    "</tool_call>\n"
                    "<tool_call>\n"
                    f'<function=write", "arguments": {types_arguments}</parameter>\n'
                    "</tool_call>"
                )
        elif spec_workflow:
            if completed_tool:
                response_text = "Stage 6 sidecars created."
            else:
                project_root = Path(spec_workflow.group(1)).parents[1]
                function_path = (
                    project_root / "fm_agent" / "extracted_functions" /
                    "plain-c" / "answer.c"
                )
                spec_arguments = json.dumps(
                    {
                        "file_path": str(function_path) + ".spec.json",
                        "content": json.dumps({
                            "signature": "answer(void) -> int",
                            "pre_condition": "true",
                            "post_condition": "return_value == 42",
                        }, separators=(",", ":")),
                    },
                    separators=(",", ":"),
                )
                info_arguments = json.dumps(
                    {
                        "file_path": str(function_path) + ".info.json",
                        "content": '{"callees":[]}',
                    },
                    separators=(",", ":"),
                )
                response_text = (
                    "<tool_call>\n"
                    f'{{"function=write", "arguments": {spec_arguments}}}\n'
                    "</tool_call>\n"
                    "<tool_call>\n<function=write>\n"
                    f"<parameter=file_path>{str(function_path)}.info.json</parameter>\n"
                    '<parameter=content>{"callees":[]}</parameter>\n'
                    "</function>\n</tool_call>"
                )
        elif "Generate the post-condition" in messages_text:
            response_text = '{"post_condition":"return_value == 42"}'
        elif "concrete valid input" in messages_text and "Condition A" in messages_text:
            response_text = (
                '{"verdict":"MATCH","counterexample":null,'
                '"offending_statements":null,"reason":"Implementation matches."}'
            )
        elif tool_marker:
            if '\\"status\\":\\"completed\\"' in messages_text:
                response_text = tool_marker
            elif tool_marker == "FM_AGENT_PROXY_SIDECARS_OK":
                proof = re.search(r"(/[^\\\"\s]*/proxy-spec\.json)", messages_text)
                spec_path = proof.group(1) if proof else "/tmp/fm-agent-proxy-spec.json"
                info_path = str(Path(spec_path).with_name("proxy-info.json"))
                spec_arguments = json.dumps(
                    {
                        "file_path": spec_path,
                        "content": json.dumps(
                            {
                                "signature": "f()",
                                "pre_condition": "true",
                                "post_condition": "result >= 0",
                            },
                            separators=(",", ":"),
                        ),
                    },
                    separators=(",", ":"),
                )
                response_text = (
                    "<tool_call>\n"
                    f'{{"function=write", "arguments": {spec_arguments}}}\n'
                    "</tool_call>\n"
                    "<tool_call>\n<function=write>\n"
                    f"<parameter=file_path>{info_path}</parameter>\n"
                    '<parameter=content>{"callees":[]}</parameter>\n'
                    "</function>\n</tool_call>"
                )
            elif tool_marker in {"FM_AGENT_PROXY_WRITE_OK", "FM_AGENT_MODEL_WRITE_OK"}:
                filename = (
                    "proxy-write.json"
                    if tool_marker == "FM_AGENT_PROXY_WRITE_OK"
                    else "tool-write-proof.json"
                )
                proof = re.search(
                    rf"(/[^\\\"\s]*/{re.escape(filename)})", messages_text
                )
                target = proof.group(1) if proof else f"/tmp/fm-agent-{filename}"
                response_text = (
                    "<tool_call>\n<function=write>\n"
                    f"<parameter=file_path>{target}</parameter>\n"
                    f'<parameter=content>{{"status":"{tool_marker}"}}</parameter>\n'
                    "</function>\n</tool_call>"
                )
            else:
                command = f"printf {tool_marker}"
                proof = re.search(
                    rf"printf {re.escape(tool_marker)} > ([^\\\"\s]+)",
                    messages_text,
                )
                if proof:
                    command += f" > {proof.group(1)}"
                response_text = (
                    "<tool_call>\n<function=bash>\n"
                    f"<parameter=command>{json.dumps(command)}</parameter>\n"
                    "<parameter=description>\"Print proxy verification marker\"</parameter>\n"
                    "</function>\n</tool_call>"
                )
                finish_reason = "stop"

        if body.get("stream") is not True:
            reasoning_only = (
                self.mode in {"reasoning-only", "always-reasoning"}
                and (
                    self.mode == "always-reasoning"
                    or not (
                        isinstance(body.get("chat_template_kwargs"), dict)
                        and body["chat_template_kwargs"].get("enable_thinking") is False
                    )
                )
            )
            message = {"role": "assistant", "content": "" if reasoning_only else response_text}
            if reasoning_only:
                message["reasoning_content"] = response_text
            payload = {
                "id": "chatcmpl-fm-agent-mock",
                "object": "chat.completion",
                "created": int(time.time()),
                "model": body.get("model", "offline-smoke-model"),
                "choices": [{
                    "index": 0,
                    "message": message,
                    "finish_reason": finish_reason,
                }],
                "usage": {"prompt_tokens": 3, "completion_tokens": 1, "total_tokens": 4},
            }
            encoded = json.dumps(payload, separators=(",", ":")).encode()
            self.send_response(200)
            self.send_header("content-type", "application/json")
            self.send_header("content-length", str(len(encoded)))
            self.end_headers()
            self.wfile.write(encoded)
            return

        self.send_response(200)
        self.send_header("content-type", "text/event-stream")
        self.end_headers()
        events = (
            {"choices": [{"delta": {"role": "assistant", "content": ""}, "index": 0, "finish_reason": None}]},
            {"choices": [{"delta": {"content": response_text}, "index": 0, "finish_reason": None}]},
            {"choices": [{"delta": {}, "index": 0, "finish_reason": finish_reason}], "usage": {"prompt_tokens": 3, "completion_tokens": 1}},
        )
        for event in events:
            self.wfile.write(f"data: {json.dumps(event, separators=(',', ':'))}\n\n".encode())
        self.wfile.write(b"data: [DONE]\n\n")
        self.wfile.flush()

    def log_message(self, _format: str, *_args: object) -> None:
        return


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--port-file", type=Path, required=True)
    parser.add_argument("--request-log", type=Path, required=True)
    parser.add_argument(
        "--mode",
        choices=("normal", "reasoning-only", "always-reasoning", "unparsed"),
        default="normal",
    )
    args = parser.parse_args()
    Handler.request_log = args.request_log
    Handler.mode = args.mode
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    args.port_file.write_text(str(server.server_address[1]), encoding="ascii")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

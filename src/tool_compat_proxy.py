"""Loopback OpenAI proxy that bypasses a mismatched upstream tool parser."""

from __future__ import annotations

import copy
import json
import logging
import os
import re
import ssl
import threading
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Mapping

from .qwen_tool_parser import openai_tool_calls, parse_tool_calls, prepare_upstream_payload


LOG = logging.getLogger("fm-agent-qwen-tool-proxy")
MAX_REQUEST_BYTES = 32 * 1024 * 1024
_AUDIT_TEXT_LIMIT = 256 * 1024
_AUDIT_LOCK = threading.Lock()
_TOOL_NAME_HINT_RES = (
    re.compile(r"<function\s*=\s*[\"']?([A-Za-z_][\w.:-]*)", re.I),
    re.compile(
        r"[\"']?(?:function|function_name|tool|tool_name|name)[\"']?\s*[:=]\s*"
        r"[\"']?([A-Za-z_][\w.:-]*)",
        re.I,
    ),
    re.compile(r"\bAction\s*:\s*([A-Za-z_][\w.:-]*)", re.I),
)


@dataclass(frozen=True)
class ProxyConfig:
    upstream_base_url: str
    api_key: str
    timeout_seconds: int = 1800
    ca_bundle: str = ""
    insecure_tls: bool = False
    audit_path: str = ""
    text_only: bool = False

    @property
    def chat_url(self) -> str:
        base = self.upstream_base_url.rstrip("/")
        if base.endswith("/chat/completions"):
            return base
        if base.endswith("/v1"):
            return base + "/chat/completions"
        return base + "/v1/chat/completions"

    def ssl_context(self) -> ssl.SSLContext | None:
        if not self.upstream_base_url.lower().startswith("https://"):
            return None
        if self.insecure_tls:
            return ssl._create_unverified_context()  # explicit operator opt-in
        return ssl.create_default_context(cafile=self.ca_bundle or None)


def _audit_text(value: Any) -> Any:
    if not isinstance(value, str) or len(value) <= _AUDIT_TEXT_LIMIT:
        return value
    half = _AUDIT_TEXT_LIMIT // 2
    return (
        value[:half]
        + f"\n...[truncated {len(value) - _AUDIT_TEXT_LIMIT} characters]...\n"
        + value[-half:]
    )


def _audit_response(
    config: ProxyConfig,
    *,
    phase: str,
    status: int,
    response: dict[str, Any],
    raw_message: dict[str, Any] | None,
    parsed_message: dict[str, Any] | None,
    allowed: Mapping[str, Mapping[str, Any]],
) -> None:
    """Persist upstream model text and the parser decision without credentials."""

    if not config.audit_path:
        return
    choice = (response.get("choices") or [{}])[0]
    calls = parsed_message.get("tool_calls") if isinstance(parsed_message, dict) else None
    unparsed = _looks_like_unparsed_tool_call(parsed_message)
    reasoning_only = _reasoning_only(parsed_message)
    empty_response = _empty_response(parsed_message)
    raw_text = "\n".join(
        value
        for value in (
            raw_message.get("content") if raw_message else None,
            raw_message.get("reasoning_content") if raw_message else None,
        )
        if isinstance(value, str)
    )
    detected_names = sorted(
        {
            match.group(1)
            for pattern in _TOOL_NAME_HINT_RES
            for match in pattern.finditer(raw_text)
        }
    )
    if config.text_only and unparsed:
        parser_decision = "text_only_unexpected_tool_syntax"
    elif unparsed:
        parser_decision = "rejected_unparsed_tool_syntax"
    elif reasoning_only:
        parser_decision = "rejected_reasoning_only"
    elif empty_response:
        parser_decision = "rejected_empty_response"
    elif config.text_only:
        parser_decision = "text_only_final_response"
    elif isinstance(calls, list) and calls:
        parser_decision = "recognized_tool_calls"
    else:
        parser_decision = "ordinary_final_text"
    record = {
        "timestamp": time.time(),
        "phase": phase,
        "upstream_status": status,
        "finish_reason": choice.get("finish_reason") if isinstance(choice, dict) else None,
        "allowed_tools": sorted(allowed),
        "content": _audit_text(raw_message.get("content")) if raw_message else None,
        "reasoning_content": (
            _audit_text(raw_message.get("reasoning_content")) if raw_message else None
        ),
        "recognized_tool_names": [
            call.get("function", {}).get("name")
            for call in calls
            if isinstance(call, dict) and isinstance(call.get("function"), dict)
        ] if isinstance(calls, list) else [],
        "detected_tool_name_hints": detected_names,
        "parser_decision": parser_decision,
        "reasoning_only": reasoning_only,
        "unparsed_tool_syntax": unparsed,
        "empty_response": empty_response,
        "text_only": config.text_only,
    }
    audit_dir = os.path.dirname(config.audit_path)
    if audit_dir:
        os.makedirs(audit_dir, exist_ok=True)
    with _AUDIT_LOCK:
        with open(config.audit_path, "a", encoding="utf-8") as stream:
            stream.write(json.dumps(record, ensure_ascii=False) + "\n")


def _choice_message(response: dict[str, Any]) -> tuple[dict[str, Any] | None, str]:
    choices = response.get("choices")
    if not isinstance(choices, list) or not choices or not isinstance(choices[0], dict):
        return None, ""
    message = choices[0].get("message")
    if not isinstance(message, dict):
        return None, ""
    content = message.get("content")
    return message, content if isinstance(content, str) else ""


def _parse_message_calls(
    message: dict[str, Any], allowed: Mapping[str, Mapping[str, Any]]
) -> tuple[str, list[dict[str, Any]]]:
    """Parse content first, then reasoning_content for Qwen thinking variants."""

    content = message.get("content")
    text = content if isinstance(content, str) else ""
    remaining, calls = parse_tool_calls(text, allowed)
    if calls:
        return remaining, openai_tool_calls(calls)

    reasoning = message.get("reasoning_content")
    if isinstance(reasoning, str):
        reasoning_remaining, calls = parse_tool_calls(reasoning, allowed)
        if calls:
            message["reasoning_content"] = reasoning_remaining or None
            return text, openai_tool_calls(calls)
    return text, []


def _apply_text_tool_calls(
    response: dict[str, Any], allowed: Mapping[str, Mapping[str, Any]]
) -> dict[str, Any] | None:
    """Promote validated text calls and return the first assistant message."""

    message, _content = _choice_message(response)
    if message is None:
        return None
    native_calls = message.get("tool_calls")
    if allowed and not (isinstance(native_calls, list) and native_calls):
        remaining, calls = _parse_message_calls(message, allowed)
        if calls:
            message["content"] = remaining or None
            message["tool_calls"] = calls
            choices = response.get("choices")
            if isinstance(choices, list) and choices and isinstance(choices[0], dict):
                choices[0]["finish_reason"] = "tool_calls"
    return message


def _reasoning_only(message: dict[str, Any] | None) -> bool:
    if message is None:
        return False
    content = message.get("content")
    calls = message.get("tool_calls")
    reasoning = message.get("reasoning_content")
    return (
        not (isinstance(content, str) and content.strip())
        and not (isinstance(calls, list) and calls)
        and isinstance(reasoning, str)
        and bool(reasoning.strip())
    )


def _empty_response(message: dict[str, Any] | None) -> bool:
    """Return whether the assistant produced neither text, reasoning nor calls."""

    if message is None:
        return True
    return not any(
        (
            isinstance(message.get("content"), str) and message["content"].strip(),
            isinstance(message.get("reasoning_content"), str)
            and message["reasoning_content"].strip(),
            isinstance(message.get("tool_calls"), list) and message["tool_calls"],
        )
    )


def _looks_like_unparsed_tool_call(message: dict[str, Any] | None) -> bool:
    """Return whether model text appears to contain an unpromoted tool call."""

    if message is None:
        return False
    for field in ("content", "reasoning_content"):
        value = message.get(field)
        if not isinstance(value, str):
            continue
        lowered = value.lower()
        if (
            "<tool_call" in lowered
            or "<function=" in lowered
            or '"function=' in lowered
            or '"tool_name"' in lowered
        ):
            # Successfully promoted blocks were removed from content by the
            # parser. Any marker that remains is therefore an unresolved extra
            # call, even when another block in the same response was valid.
            return True
    return False


def _upstream_post(
    config: ProxyConfig, payload: dict[str, Any]
) -> tuple[int, str, bytes]:
    request = urllib.request.Request(
        config.chat_url,
        data=json.dumps(payload, ensure_ascii=False).encode(),
        headers={
            "Content-Type": "application/json",
            **(
                {"Authorization": f"Bearer {config.api_key}"}
                if config.api_key
                else {}
            ),
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(
            request,
            timeout=config.timeout_seconds,
            context=config.ssl_context(),
        ) as upstream:
            status = upstream.status
            content_type = upstream.headers.get("Content-Type", "application/json")
            raw = upstream.read(MAX_REQUEST_BYTES + 1)
    except urllib.error.HTTPError as exc:
        status = exc.code
        content_type = exc.headers.get("Content-Type", "application/json")
        raw = exc.read(MAX_REQUEST_BYTES + 1)
    if len(raw) > MAX_REQUEST_BYTES:
        raise ValueError("upstream response is too large")
    return status, content_type, raw


def _decode_upstream(raw: bytes) -> dict[str, Any]:
    response = json.loads(raw)
    if not isinstance(response, dict):
        raise ValueError("upstream response is not an object")
    return response


def _sse_response(response: dict[str, Any]) -> bytes:
    """Turn one buffered Chat Completions response into valid SSE chunks."""

    message, content = _choice_message(response)
    choice = (response.get("choices") or [{}])[0]
    response_id = response.get("id", "chatcmpl-fm-agent-qwen-proxy")
    model = response.get("model", "")
    created = response.get("created", int(time.time()))

    def chunk(delta: dict[str, Any], finish_reason: str | None = None) -> bytes:
        body = {
            "id": response_id,
            "object": "chat.completion.chunk",
            "created": created,
            "model": model,
            "choices": [{"index": 0, "delta": delta, "finish_reason": finish_reason}],
        }
        return b"data: " + json.dumps(body, ensure_ascii=False).encode() + b"\n\n"

    output = bytearray(chunk({"role": "assistant", "content": ""}))
    if message and isinstance(message.get("reasoning_content"), str):
        output.extend(chunk({"reasoning_content": message["reasoning_content"]}))
    if message and isinstance(message.get("tool_calls"), list):
        for index, call in enumerate(message["tool_calls"]):
            output.extend(chunk({"tool_calls": [{"index": index, **call}]}))
        output.extend(chunk({}, "tool_calls"))
    else:
        output.extend(chunk({"content": content}))
        output.extend(chunk({}, choice.get("finish_reason") or "stop"))
    usage = response.get("usage")
    if isinstance(usage, dict):
        body = {
            "id": response_id,
            "object": "chat.completion.chunk",
            "created": created,
            "model": model,
            "choices": [],
            "usage": usage,
        }
        output.extend(b"data: " + json.dumps(body).encode() + b"\n\n")
    output.extend(b"data: [DONE]\n\n")
    return bytes(output)


class ProxyHTTPServer(ThreadingHTTPServer):
    daemon_threads = True


def handler_for(config: ProxyConfig) -> type[BaseHTTPRequestHandler]:
    """Create an isolated handler class so concurrent proxy processes cannot mix config."""

    class Handler(BaseHTTPRequestHandler):
        server_version = "FMAToolCompatProxy/1.0"

        def log_message(self, fmt: str, *args: object) -> None:
            LOG.debug("%s %s", self.client_address[0], fmt % args)

        def _json(self, status: int, body: dict[str, Any]) -> None:
            encoded = json.dumps(body, ensure_ascii=False).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(encoded)))
            self.end_headers()
            self.wfile.write(encoded)

        def do_GET(self) -> None:  # noqa: N802
            if self.path.rstrip("/") in {"/health", "/healthz", "/v1/health"}:
                self._json(200, {"status": "ok", "parser": "qwen-text-tool-v1"})
                return
            self._json(404, {"error": {"message": "not found", "type": "proxy_error"}})

        def do_POST(self) -> None:  # noqa: N802
            if self.path.split("?", 1)[0].rstrip("/") != "/v1/chat/completions":
                self._json(404, {"error": {"message": "not found", "type": "proxy_error"}})
                return
            try:
                length = int(self.headers.get("Content-Length", "0"))
            except ValueError:
                length = 0
            if length <= 0 or length > MAX_REQUEST_BYTES:
                self._json(413, {"error": {"message": "invalid request size", "type": "proxy_error"}})
                return
            try:
                incoming = json.loads(self.rfile.read(length))
                if not isinstance(incoming, dict):
                    raise ValueError("request is not an object")
            except (json.JSONDecodeError, ValueError):
                self._json(400, {"error": {"message": "invalid JSON", "type": "proxy_error"}})
                return

            wants_stream = incoming.get("stream") is True
            outgoing, allowed = prepare_upstream_payload(
                incoming, text_only=config.text_only
            )
            try:
                status, content_type, raw = _upstream_post(config, outgoing)
                if status >= 400:
                    self.send_response(status)
                    self.send_header("Content-Type", content_type)
                    self.send_header("Content-Length", str(len(raw)))
                    self.end_headers()
                    self.wfile.write(raw)
                    return
                response = _decode_upstream(raw)
            except (urllib.error.URLError, TimeoutError, ssl.SSLError) as exc:
                LOG.warning("upstream unavailable: %s", type(exc).__name__)
                self._json(
                    502,
                    {"error": {"message": "FM-Agent tool proxy upstream unavailable", "type": "proxy_error"}},
                )
                return
            except (json.JSONDecodeError, ValueError):
                self._json(
                    502,
                    {"error": {"message": "invalid upstream response", "type": "proxy_error"}},
                )
                return

            raw_message, _raw_content = _choice_message(response)
            raw_message = copy.deepcopy(raw_message)
            message = _apply_text_tool_calls(response, allowed)
            _audit_response(
                config,
                phase="initial",
                status=status,
                response=response,
                raw_message=raw_message,
                parsed_message=message,
                allowed=allowed,
            )

            # A Qwen thinking response can occasionally contain only
            # reasoning_content. Harness correctly keeps reasoning off stdout,
            # which previously made `test-model` see an empty final answer. If
            # there is neither content nor a tool call, retry once with the
            # model chat template's thinking mode disabled. This extension is
            # understood by vLLM; an endpoint that rejects it simply falls back
            # to the original valid response.
            if _reasoning_only(message) or _empty_response(message):
                retry_payload = copy.deepcopy(outgoing)
                kwargs = retry_payload.get("chat_template_kwargs")
                if not isinstance(kwargs, dict):
                    kwargs = {}
                retry_payload["chat_template_kwargs"] = {
                    **kwargs,
                    "enable_thinking": False,
                }
                try:
                    retry_status, _retry_type, retry_raw = _upstream_post(
                        config, retry_payload
                    )
                    if retry_status < 400:
                        retry_response = _decode_upstream(retry_raw)
                        retry_raw_message, _retry_content = _choice_message(retry_response)
                        retry_raw_message = copy.deepcopy(retry_raw_message)
                        retry_message = _apply_text_tool_calls(retry_response, allowed)
                        _audit_response(
                            config,
                            phase="non_thinking_retry",
                            status=retry_status,
                            response=retry_response,
                            raw_message=retry_raw_message,
                            parsed_message=retry_message,
                            allowed=allowed,
                        )
                        if not _reasoning_only(retry_message) and not _empty_response(
                            retry_message
                        ):
                            response = retry_response
                            message = retry_message
                            status = retry_status
                except (
                    urllib.error.URLError,
                    TimeoutError,
                    ssl.SSLError,
                    json.JSONDecodeError,
                    ValueError,
                ) as exc:
                    LOG.warning(
                        "non-thinking retry unavailable; rejecting reasoning-only response: %s",
                        type(exc).__name__,
                    )

            # Do not let Harness report process success when there is no final
            # content and no executable call.  Likewise, visible tool syntax
            # that the defensive parser still cannot recognize is a protocol
            # error, not a valid final answer.  Returning a typed HTTP error
            # makes the agent trace and Stage retry reflect the real failure.
            if _reasoning_only(message):
                self._json(
                    422,
                    {
                        "error": {
                            "message": (
                                "FM-Agent Qwen compatibility proxy received reasoning "
                                "without final content or a recognized tool call after "
                                "the non-thinking retry"
                            ),
                            "type": "fm_agent_reasoning_only",
                        }
                    },
                )
                return
            if _empty_response(message):
                self._json(
                    422,
                    {
                        "error": {
                            "message": (
                                "FM-Agent Qwen compatibility proxy received no final "
                                "content, reasoning, or recognized tool call after retry"
                            ),
                            "type": "fm_agent_empty_response",
                        }
                    },
                )
                return
            if allowed and _looks_like_unparsed_tool_call(message):
                self._json(
                    422,
                    {
                        "error": {
                            "message": (
                                "FM-Agent Qwen compatibility proxy detected tool-call "
                                "syntax that it could not parse safely"
                            ),
                            "type": "fm_agent_unparsed_tool_call",
                        }
                    },
                )
                return

            if wants_stream:
                encoded = _sse_response(response)
                self.send_response(status)
                self.send_header("Content-Type", "text/event-stream")
                self.send_header("Cache-Control", "no-cache")
                self.send_header("Connection", "close")
                self.send_header("Content-Length", str(len(encoded)))
                self.end_headers()
                self.wfile.write(encoded)
            else:
                self._json(status, response)
                return

    return Handler


def create_server(config: ProxyConfig) -> ProxyHTTPServer:
    return ProxyHTTPServer(("127.0.0.1", 0), handler_for(config))

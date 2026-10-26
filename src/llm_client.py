"""Structured LLM calls routed exclusively through DeepSeek Harness."""

import json
import os

from config import MAX_SPC_ITER
from .harness_backend import build_agent_command, run_agent_for_messages
from .trace_writer import new_event_id, record_llm_exchange, utc_now_iso


# Kept as a compatibility argument for callers that historically passed an
# OpenAI client. DeepSeek Harness now owns all provider I/O and retries.
_llm_provider_client = None


def build_llm_agent_command(model, prompt, cwd, files=None):
    """Build the configured DeepSeek Harness command for a file-oriented task."""
    return build_agent_command(model=model, prompt=prompt, cwd=cwd, files=files)


def _proxy_audit_path(trace_dir, event_id):
    if not trace_dir or not event_id:
        return None
    payload_dir = os.path.join(trace_dir, "payloads")
    os.makedirs(payload_dir, exist_ok=True)
    return os.path.join(payload_dir, f"{event_id}_proxy.jsonl")


def _retry_create(client, model, messages, *, trace_dir=None, event_id=None):
    """Run one message conversation through Harness.

    Harness implements provider retries and emits only the final assistant text
    on stdout in headless mode. Usage is currently unavailable at this wrapper
    boundary, so the trace contains an empty usage mapping.
    """
    del client
    text, usage = run_agent_for_messages(
        model,
        messages,
        text_only=True,
        proxy_audit_path=_proxy_audit_path(trace_dir, event_id),
    )
    return text, usage, None


def _parse_json_response(response):
    """Parse the only JSON object or array in an LLM response.

    Prefer a complete JSON response, but tolerate Markdown fences or explanatory
    prose when they surround exactly one valid structured JSON value. Multiple
    structured values are rejected because choosing one would be ambiguous.
    """
    if not isinstance(response, str):
        raise ValueError("LLM response must be a JSON string")
    text = response.strip()
    try:
        data = json.loads(text)
    except json.JSONDecodeError as direct_exc:
        decoder = json.JSONDecoder()
        values = []
        index = 0
        while index < len(text):
            object_start = text.find("{", index)
            array_start = text.find("[", index)
            starts = [start for start in (object_start, array_start) if start != -1]
            if not starts:
                break
            start = min(starts)
            try:
                data, end = decoder.raw_decode(text, start)
            except json.JSONDecodeError:
                index = start + 1
                continue
            if isinstance(data, (dict, list)):
                values.append(data)
            index = end

        if len(values) == 1:
            return values[0]
        if len(values) > 1:
            raise ValueError("LLM response contains multiple JSON values")
        raise ValueError(f"LLM response is not valid JSON: {direct_exc}") from direct_exc

    if not isinstance(data, (dict, list)):
        raise ValueError("LLM response must contain a JSON object or array")
    return data


def _llm_json_call(client, model, messages, validator, schema_description,
                   max_retries=MAX_SPC_ITER, trace_dir=None, trace_meta=None):
    """Call Harness until it returns structured JSON accepted by ``validator``."""
    trace_meta = trace_meta or {}
    for attempt in range(1, max_retries + 1):
        event_id = new_event_id("llm")
        started = utc_now_iso()
        response = None
        usage = {}
        reasoning = None
        proxy_log_path = _proxy_audit_path(trace_dir, event_id)
        try:
            response, usage, reasoning = _retry_create(
                client,
                model,
                messages,
                trace_dir=trace_dir,
                event_id=event_id,
            )
        except Exception as exc:
            event = {
                "event_id": event_id,
                "type": "llm_call",
                "stage": "verification",
                "status": "error",
                "start_time": started,
                "end_time": utc_now_iso(),
                "summary": f"LLM call failed: {exc}",
                "metadata": {
                    **trace_meta,
                    "backend": "deepseek-harness",
                    "model": model,
                    "attempt": attempt,
                    "error": str(exc),
                },
            }
            record_llm_exchange(
                trace_dir,
                event_id,
                event,
                messages,
                proxy_log_path=proxy_log_path,
            )
            raise

        parsed_json = None
        result = None
        parse_error = None
        try:
            parsed_json = _parse_json_response(response)
            result = validator(parsed_json)
            status = "success"
        except ValueError as exc:
            parse_error = str(exc)
            status = "format_error"

        event = {
            "event_id": event_id,
            "type": "llm_call",
            "stage": "verification",
            "status": status,
            "start_time": started,
            "end_time": utc_now_iso(),
            "summary": trace_meta.get("summary", "LLM JSON call"),
            "metadata": {
                **trace_meta,
                "backend": "deepseek-harness",
                "model": model,
                "attempt": attempt,
                "usage": usage,
                "parsed_json": parsed_json,
                "parse_error": parse_error,
            },
        }
        record_llm_exchange(
            trace_dir,
            event_id,
            event,
            messages,
            response,
            reasoning,
            proxy_log_path=proxy_log_path,
        )
        if status == "success":
            return result

        messages = messages + [
            {"role": "assistant", "content": response or ""},
            {"role": "user", "content": (
                f"Your previous response was invalid: {parse_error}. "
                f"Return only valid JSON matching this schema: {schema_description}. "
                "Do not include Markdown, tags, or prose."
            )},
        ]
    return None

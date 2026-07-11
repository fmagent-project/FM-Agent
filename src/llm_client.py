import re
import time
import json
import random
import os
import urllib.request
import urllib.error
import urllib.parse
import logging
from config import *
from .cli_backend import is_cli_backend_enabled, run_agent_for_messages
from openai import OpenAI, RateLimitError, BadRequestError
from .trace_writer import (
    new_event_id,
    record_llm_exchange,
    utc_now_iso,
)

_openrouter_client = OpenAI(api_key=LLM_API_KEY, base_url=LLM_API_BASE_URL)
_llm_provider_client = _openrouter_client

_MAX_RATE_LIMIT_RETRIES = 20
_MAX_LLM_RETRIES = 5

# Maximum output tokens for anthropic-native /v1/messages calls.
# Anthropic requires this field; OpenAI-compatible layers often hide it, but the native endpoint needs it.
_ANTHROPIC_MAX_TOKENS = 8192


def _is_anthropic_model(model):
    """True if model should be routed through anthropic-native /v1/messages."""
    m = (model or "").lower()
    return m.startswith("claude") or m.startswith("anthropic/")


_DEFAULT_INJECT_USER_ID = "stable-user-or-session-id-xxxxxxx123"


def _stable_user_id():
    return os.environ.get("INJECT_ID") or _DEFAULT_INJECT_USER_ID


def _inject_targets():
    return [s.strip() for s in (os.environ.get("INJECT_HOST") or "").split(",") if s.strip()]


def _matches_inject_target(url, target):
    if target.lower().startswith(("http://", "https://")):
        return url.startswith(target)
    try:
        host = urllib.parse.urlparse(url).hostname or ""
    except Exception:
        return False
    return host == target or host.endswith("." + target)


def _should_inject_user_id(base_url):
    url = (base_url or "").rstrip("/")
    return any(_matches_inject_target(url, target) for target in _inject_targets())


def _metadata_body():
    return {"metadata": {"user_id": _stable_user_id()}}


def _messages_to_anthropic(messages):
    """Split OpenAI-style messages into (system_text, anthropic_messages list)."""
    system_text = ""
    out = []
    for m in messages:
        role = m.get("role")
        content = m.get("content", "")
        if not isinstance(content, str):
            # Already a list-of-blocks; flatten to text to keep this path simple.
            content = "\n".join(c.get("text", "") for c in content if isinstance(c, dict))
        if role == "system":
            # Concatenate multiple system messages if present.
            system_text = (system_text + "\n\n" + content).strip() if system_text else content
        elif role in ("user", "assistant"):
            out.append({"role": role, "content": content})
    return system_text, out


def _anthropic_create(model, messages):
    """Send messages via an Anthropic-native /v1/messages endpoint with prompt caching.

    Returns (text, usage_dict). usage_dict matches anthropic-style:
      {input_tokens, cache_creation_input_tokens, cache_read_input_tokens, output_tokens, ...}
    """
    system_text, an_msgs = _messages_to_anthropic(messages)

    sys_blocks = []
    if system_text:
        # cache_control marks the prefix as cacheable; ephemeral = 5-minute TTL.
        sys_blocks.append({
            "type": "text",
            "text": system_text,
            "cache_control": {"type": "ephemeral"},
        })

    body = {
        "model": model,
        "max_tokens": _ANTHROPIC_MAX_TOKENS,
        "system": sys_blocks,
        "messages": an_msgs or [{"role": "user", "content": ""}],
    }

    url = LLM_API_BASE_URL.rstrip("/") + "/messages"
    if _should_inject_user_id(LLM_API_BASE_URL):
        body.update(_metadata_body())
    req = urllib.request.Request(
        url,
        data=json.dumps(body).encode("utf-8"),
        headers={
            "Authorization": f"Bearer {LLM_API_KEY}",
            "Content-Type": "application/json",
            "anthropic-version": "2023-06-01",
        },
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=600) as r:
        status = getattr(r, "status", None) or r.getcode()
        body_bytes = r.read()
    try:
        data = json.loads(body_bytes)
    except json.JSONDecodeError as exc:
        # The relay returned a non-JSON / empty body (e.g. an empty 200 or an
        # HTML error page truncated by the proxy under load). Surface the raw
        # body + status — otherwise only "Expecting value: line 1 column 1" leaks
        # and the actual relay response is lost.
        snippet = body_bytes[:800].decode("utf-8", "replace")
        raise RuntimeError(
            f"non-JSON response from relay (HTTP {status}, {len(body_bytes)} bytes): {snippet!r}"
        ) from exc
    # Anthropic content is a list of blocks; concatenate text blocks.
    text = "".join(c.get("text", "") for c in data.get("content", []) if c.get("type") == "text")
    usage = data.get("usage", {}) or {}
    return text, usage


def _http_status_from_exc(exc):
    """Extract HTTP status from a urllib HTTPError, else None."""
    if isinstance(exc, urllib.error.HTTPError):
        return exc.code
    return None


def _read_error_body(exc, limit=800):
    """The raw response body of an HTTPError (the relay's actual error page),
    which str(exc) drops — only `HTTP Error 504: Gateway Time-out` survives
    otherwise. Read-once and tolerant; returns '' if unavailable."""
    try:
        raw = exc.read()
    except Exception:
        return ""
    if not raw:
        return ""
    text = raw.decode("utf-8", "replace").strip()
    return text[:limit] + ("…" if len(text) > limit else "")


def _retry_create(client, model, messages):
    """Call the LLM with retries. Returns (text, usage_dict).

    - Anthropic-family models go via the native /v1/messages endpoint.
    - Other models go through the OpenAI-compat client.
    - When LLM_API_BASE_URL matches INJECT_HOST, metadata.user_id is attached so
      third-party relays that support it can keep prompt-cache routing sticky.
    """
    if is_cli_backend_enabled():
        return run_agent_for_messages(model, messages)

    rate_limit_attempts = 0
    transient_attempts = 0
    use_anthropic = _is_anthropic_model(model)
    extra = {}
    if _should_inject_user_id(LLM_API_BASE_URL):
        extra["extra_body"] = _metadata_body()
    while True:
        try:
            if use_anthropic:
                return _anthropic_create(model, messages)
            response = client.chat.completions.create(model=model, messages=messages, **extra)
            text = response.choices[0].message.content
            usage = response.usage.model_dump() if response.usage else {}
            return text, usage
        except BadRequestError:
            raise
        except urllib.error.HTTPError as exc:
            status = exc.code
            body = _read_error_body(exc)  # the relay's raw error page (str(exc) drops it)
            detail = f"HTTP {status} {exc.reason}" + (f"; body={body!r}" if body else "")
            if status == 400:
                raise
            if status == 429:
                rate_limit_attempts += 1
                if rate_limit_attempts >= _MAX_RATE_LIMIT_RETRIES:
                    raise RuntimeError(
                        f"Rate limited after {_MAX_RATE_LIMIT_RETRIES} retries: {detail}"
                    ) from exc
                wait = min(2 ** (rate_limit_attempts - 1) * 5, 300) + random.uniform(1, 10)
                logging.warning(f"LLM 429 ({detail}), sleeping {wait:.1f}s (attempt {rate_limit_attempts})")
                time.sleep(wait)
                continue
            # 5xx and other → treat as transient
            transient_attempts += 1
            if transient_attempts >= _MAX_LLM_RETRIES:
                raise RuntimeError(
                    f"LLM request failed after {_MAX_LLM_RETRIES} retries: {detail}"
                ) from exc
            wait = min(2 ** (transient_attempts - 1) * 5, 60) + random.uniform(1, 3)
            logging.warning(f"LLM {detail}, sleeping {wait:.1f}s (attempt {transient_attempts})")
            time.sleep(wait)
        except RateLimitError as exc:
            rate_limit_attempts += 1
            if rate_limit_attempts >= _MAX_RATE_LIMIT_RETRIES:
                raise RuntimeError(
                    f"Rate limited after {_MAX_RATE_LIMIT_RETRIES} retries: {exc}"
                ) from exc
            wait = min(2 ** (rate_limit_attempts - 1) * 5, 300) + random.uniform(1, 10)
            logging.warning(f"LLM rate-limited, sleeping {wait:.1f}s (attempt {rate_limit_attempts})")
            time.sleep(wait)
        except Exception as exc:
            transient_attempts += 1
            if transient_attempts >= _MAX_LLM_RETRIES:
                raise RuntimeError(
                    f"LLM request failed after {_MAX_LLM_RETRIES} retries: {exc}"
                ) from exc
            wait = min(2 ** (transient_attempts - 1) * 5, 60) + random.uniform(1, 3)
            logging.warning(
                f"LLM error ({type(exc).__name__}: {str(exc)[:120]}), "
                f"sleeping {wait:.1f}s (attempt {transient_attempts})")
            time.sleep(wait)


def _extract_tagged(text, start_tag, end_tag):
    pattern = rf"\[{re.escape(start_tag)}\](.*?)\[{re.escape(end_tag)}\]"
    match = re.search(pattern, text, re.DOTALL)
    return match.group(1).strip() if match else None


def _llm_call(client, model, messages, start_tag, end_tag, max_retries=MAX_SPC_ITER,
              trace_dir=None, trace_meta=None):
    trace_meta = trace_meta or {}
    for attempt in range(1, max_retries + 1):
        event_id = new_event_id("llm")
        started = utc_now_iso()
        response = None
        usage = {}
        try:
            response, usage = _retry_create(client, model, messages)
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
                    "model": model,
                    "attempt": attempt,
                    "start_tag": start_tag,
                    "end_tag": end_tag,
                    "error": str(exc),
                },
            }
            record_llm_exchange(trace_dir, event_id, event, messages)
            raise
        result = _extract_tagged(response, start_tag, end_tag)
        status = "success" if result is not None else "format_error"
        event = {
            "event_id": event_id,
            "type": "llm_call",
            "stage": "verification",
            "status": status,
            "start_time": started,
            "end_time": utc_now_iso(),
            "summary": trace_meta.get("summary", f"LLM call for {start_tag}"),
            "metadata": {
                **trace_meta,
                "model": model,
                "attempt": attempt,
                "start_tag": start_tag,
                "end_tag": end_tag,
                "usage": usage,
                "parsed": result,
            },
        }
        record_llm_exchange(trace_dir, event_id, event, messages, response)
        if result is not None:
            return result
        messages = messages + [
            {"role": "assistant", "content": response},
            {"role": "user", "content": f"Your output format is wrong. Please wrap your answer within [{start_tag}] and [{end_tag}]."}
        ]
    return None

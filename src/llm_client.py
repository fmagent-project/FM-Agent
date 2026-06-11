import re
import time
import json
import random
import hashlib
import urllib.request
import urllib.error
import logging
from config import *
from openai import OpenAI, RateLimitError, BadRequestError
from .trace_writer import (
    new_event_id,
    record_llm_exchange,
    utc_now_iso,
)

_llm_provider_client = OpenAI(api_key=LLM_API_KEY, base_url=LLM_API_BASE_URL)

_MAX_RATE_LIMIT_RETRIES = 20
_MAX_LLM_RETRIES = 5

# Maximum output tokens for anthropic-native /v1/messages calls.
# Anthropic requires this field; svip's OpenAI-compat layer hides it but the native endpoint needs it.
_ANTHROPIC_MAX_TOKENS = 8192


def _is_anthropic_model(model):
    """True if model should be routed through anthropic-native /v1/messages."""
    m = (model or "").lower()
    return m.startswith("claude") or m.startswith("anthropic/")


def _stable_user_id():
    """Stable id used in metadata.user_id for sticky cache routing on svip.

    Without a stable id, svip round-robins requests across Anthropic sub-accounts and
    each one has cold cache, so cache_read stays 0. With it, cache_read climbs to ~90%.
    """
    override = os.environ.get("FM_AGENT_USER_ID", "").strip()
    if override:
        return override
    # Derive from API key so multi-tenant deployments don't collide.
    key = LLM_API_KEY or "no-key"
    return "fm-agent-" + hashlib.sha256(key.encode()).hexdigest()[:12]


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
    """Send messages via svip's anthropic-native /v1/messages endpoint with prompt caching.

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
        # metadata.user_id makes svip's multi-tenant routing sticky for the same caller
        # so the cache prefix written by call N is visible to call N+1.
        "metadata": {"user_id": _stable_user_id()},
    }

    url = LLM_API_BASE_URL.rstrip("/") + "/messages"
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
        body_bytes = r.read()
    data = json.loads(body_bytes)
    # Anthropic content is a list of blocks; concatenate text blocks.
    text = "".join(c.get("text", "") for c in data.get("content", []) if c.get("type") == "text")
    usage = data.get("usage", {}) or {}
    return text, usage


def _http_status_from_exc(exc):
    """Extract HTTP status from a urllib HTTPError, else None."""
    if isinstance(exc, urllib.error.HTTPError):
        return exc.code
    return None


def _retry_create(client, model, messages):
    """Call the LLM with retries. Returns (text, usage_dict).

    - Anthropic-family models go via svip's anthropic-native /v1/messages endpoint
      (enables prompt caching via cache_control + metadata.user_id).
    - Other models go through the OpenAI-compat client as before.
    """
    rate_limit_attempts = 0
    transient_attempts = 0
    use_anthropic = _is_anthropic_model(model)
    while True:
        try:
            if use_anthropic:
                return _anthropic_create(model, messages)
            response = client.chat.completions.create(model=model, messages=messages)
            text = response.choices[0].message.content
            usage = response.usage.model_dump() if response.usage else {}
            return text, usage
        except BadRequestError:
            raise
        except urllib.error.HTTPError as exc:
            status = exc.code
            if status == 400:
                raise
            if status == 429:
                rate_limit_attempts += 1
                if rate_limit_attempts >= _MAX_RATE_LIMIT_RETRIES:
                    raise RuntimeError(
                        f"Rate limited after {_MAX_RATE_LIMIT_RETRIES} retries: {exc}"
                    ) from exc
                wait = min(2 ** (rate_limit_attempts - 1) * 5, 300) + random.uniform(1, 10)
                logging.warning(f"LLM 429, sleeping {wait:.1f}s (attempt {rate_limit_attempts})")
                time.sleep(wait)
                continue
            # 5xx and other → treat as transient
            transient_attempts += 1
            if transient_attempts >= _MAX_LLM_RETRIES:
                raise RuntimeError(
                    f"LLM request failed after {_MAX_LLM_RETRIES} retries: {exc}"
                ) from exc
            wait = min(2 ** (transient_attempts - 1) * 5, 60) + random.uniform(1, 3)
            logging.warning(f"LLM HTTP {status}, sleeping {wait:.1f}s (attempt {transient_attempts})")
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

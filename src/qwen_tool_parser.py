"""Qwen text-tool protocol used when the upstream vLLM parser is unusable.

Some OpenAI-compatible vLLM deployments are fixed to ``--tool-call-parser
mistral`` even though they serve a Qwen checkpoint.  Sending the normal
``tools`` field to such a service can fail before generation.  The compatibility
proxy therefore renders tool schemas as ordinary prompt text, removes the
server-side tool fields, and converts Qwen's textual calls back to the OpenAI
``message.tool_calls`` shape expected by DeepSeek Harness.

The primary grammar follows Qwen/vLLM's XML protocol.  Hermes JSON, fenced JSON
and a common Markdown pseudo-call are accepted as defensive fallbacks.  Tool
names are always checked against the schemas supplied by Harness before a call
is promoted to executable data.
"""

from __future__ import annotations

import ast
import copy
import json
import re
import uuid
from dataclasses import dataclass
from typing import Any, Iterable, Mapping


_TOOL_BLOCK_RE = re.compile(
    r"<tool_call\b[^>]*>(.*?)(?:</tool_call>|(?=<tool_call\b)|\Z)", re.I | re.S
)
_QWEN_FUNCTION_RE = re.compile(
    r"<function\s*=\s*([^>\s]+)\s*>(.*?)(?:</function>|(?=<function\s*=)|\Z)",
    re.I | re.S,
)
# Seen from Qwen3.6 in long agent turns: the opening tag is accidentally closed
# as ``<function=name</function>`` and its parameters follow as siblings.  It is
# unambiguous inside one <tool_call> block, so accept it defensively.
_QWEN_SIBLING_FUNCTION_RE = re.compile(
    r"<function\s*=\s*([^<>\s]+)\s*</function>\s*(.*)", re.I | re.S
)
_QWEN_HYBRID_FUNCTION_RE = re.compile(
    r'<function\s*=\s*([A-Za-z_][\w.:-]*)["\']?\s*,\s*'
    r'"arguments"\s*:\s*(\{.*?\})\s*\}?\s*(?:parameter\s*=|</function>|\Z)',
    re.I | re.S,
)
_QWEN_HYBRID_HEAD_RE = re.compile(
    r'<function\s*=\s*([A-Za-z_][\w.:-]*)["\']?\s*,\s*'
    r'"arguments"\s*:\s*',
    re.I | re.S,
)
# Qwen can also start a would-be JSON object but merge the function key and
# value into one quoted token: ``{"function=write", "arguments": {...}}``.
# It is not valid JSON, but the tool name and the balanced arguments object are
# still unambiguous inside a <tool_call> block.
_QWEN_PSEUDO_JSON_HEAD_RE = re.compile(
    r'\{\s*"function\s*=\s*([A-Za-z_][\w.:-]*)["\']?\s*,\s*'
    r'"arguments"\s*:\s*',
    re.I | re.S,
)
_XML_FUNCTION_RE = re.compile(
    r"<function(?:\s+name\s*=\s*[\"']?([^>\"']+)[\"']?)?\s*>(.*?)</function>",
    re.I | re.S,
)
_PARAM_RE = re.compile(
    r"<parameter\s*=\s*([^>\s]+)\s*>(.*?)</parameter>", re.I | re.S
)
_NAME_RE = re.compile(r"<name\s*>(.*?)</name>", re.I | re.S)
_ARGS_RE = re.compile(r"<arguments\s*>(.*?)</arguments>", re.I | re.S)
_MARKDOWN_RE = re.compile(
    r"\[\s*tool_(?:use|call)\s*:\s*([A-Za-z_][\w.:-]*)\s*,\s*"
    r"(?:input|arguments|args)\s*:\s*(\{.*?\})\s*\]",
    re.I | re.S,
)
_JSON_FENCE_RE = re.compile(r"```(?:json|tool|tool_call)?\s*(.*?)```", re.I | re.S)
_LOOSE_TOOL_NAME_RES = (
    re.compile(r"<function\s*(?:=|:)\s*[\"']?([A-Za-z_][\w.:-]*)", re.I),
    re.compile(
        r"[\"']?(?:function|function_name|tool|tool_name|name)[\"']?\s*[:=]\s*"
        r"[\"']?([A-Za-z_][\w.:-]*)",
        re.I,
    ),
)
_LOOSE_ARGUMENTS_RE = re.compile(
    r"[\"']?(?:arguments|parameters|input|args)[\"']?\s*[:=]\s*",
    re.I,
)
_RELAXED_PARAM_RE = re.compile(
    r"<parameter\s*=\s*([^>\s]+)\s*>(.*?)"
    r"(?=</parameter>|<parameter\s*=|</function>|</tool_call>|\Z)",
    re.I | re.S,
)


@dataclass(frozen=True)
class ParsedToolCall:
    name: str
    arguments: dict[str, Any]


def _clean_tool_name(value: str) -> str:
    """Keep the identifier prefix and discard Qwen's stray quote/tag suffix."""

    match = re.match(r"[A-Za-z_][\w.:-]*", value.strip().lstrip('"\'`'))
    return match.group(0) if match else value.strip()


def _jsonish(value: str) -> Any:
    text = value.strip()
    if not text:
        return ""
    for loader in (json.loads, ast.literal_eval):
        try:
            return loader(text)
        except (ValueError, SyntaxError, TypeError, json.JSONDecodeError):
            pass
    lowered = text.lower()
    if lowered == "true":
        return True
    if lowered == "false":
        return False
    if lowered == "null":
        return None
    return text


def _normalize_arguments(value: Any) -> dict[str, Any] | None:
    if isinstance(value, str):
        value = _jsonish(value)
    if value is None:
        return {}
    return value if isinstance(value, dict) else None


def _xml_parameter_value(value: str) -> Any:
    """Decode quoted strings but preserve unquoted XML bodies for schema coercion.

    Qwen commonly emits the JSON document for ``write.content`` directly between
    the parameter tags. Treating every JSON-looking value as a structured object
    changes that tool argument from ``string`` to ``object`` and makes Harness
    reject the call. The advertised tool schema is applied after parsing, so raw
    XML bodies must remain strings until then.
    """

    text = value.strip()
    if len(text) >= 2 and text[0] in {'"', "'"} and text[-1] == text[0]:
        decoded = _jsonish(text)
        return decoded if isinstance(decoded, str) else text
    return text


def _schema_type(schema: Mapping[str, Any]) -> str:
    value = schema.get("type")
    if isinstance(value, str):
        return value
    if isinstance(value, list):
        return next((item for item in value if isinstance(item, str) and item != "null"), "")
    for keyword in ("anyOf", "oneOf"):
        variants = schema.get(keyword)
        if isinstance(variants, list):
            for variant in variants:
                if isinstance(variant, Mapping):
                    resolved = _schema_type(variant)
                    if resolved and resolved != "null":
                        return resolved
    return ""


def _coerce_schema_value(value: Any, schema: Mapping[str, Any]) -> Any:
    expected = _schema_type(schema)
    if expected == "string":
        if isinstance(value, str):
            return value
        if isinstance(value, (dict, list, bool)) or value is None:
            return json.dumps(value, ensure_ascii=False, separators=(",", ":"))
        return str(value)
    if not isinstance(value, str):
        return value
    if expected == "boolean":
        lowered = value.strip().lower()
        if lowered in {"true", "false"}:
            return lowered == "true"
        return value
    if expected in {"integer", "number"}:
        try:
            parsed = json.loads(value)
        except json.JSONDecodeError:
            return value
        if isinstance(parsed, bool):
            return value
        if expected == "integer" and isinstance(parsed, int):
            return parsed
        if expected == "number" and isinstance(parsed, (int, float)):
            return parsed
        return value
    if expected in {"object", "array"}:
        parsed = _jsonish(value)
        if expected == "object" and isinstance(parsed, dict):
            return parsed
        if expected == "array" and isinstance(parsed, list):
            return parsed
    return value


def _coerce_call_arguments(
    call: ParsedToolCall, tool_schemas: Mapping[str, Mapping[str, Any]]
) -> ParsedToolCall:
    schema = tool_schemas.get(call.name)
    if not isinstance(schema, Mapping):
        return call
    properties = schema.get("properties")
    if not isinstance(properties, Mapping):
        return call
    arguments = {
        name: _coerce_schema_value(value, properties.get(name, {}))
        if isinstance(properties.get(name), Mapping)
        else value
        for name, value in call.arguments.items()
    }
    return ParsedToolCall(call.name, arguments)


def _call_from_object(obj: Any) -> list[ParsedToolCall]:
    if isinstance(obj, str):
        decoded = _jsonish(obj)
        if decoded is not obj and not isinstance(decoded, str):
            return _call_from_object(decoded)
        return []
    if isinstance(obj, list):
        calls: list[ParsedToolCall] = []
        for item in obj:
            calls.extend(_call_from_object(item))
        return calls
    if not isinstance(obj, dict):
        return []
    if isinstance(obj.get("tool_calls"), list):
        return _call_from_object(obj["tool_calls"])
    if isinstance(obj.get("function_call"), dict):
        return _call_from_object(obj["function_call"])

    function = obj.get("function")
    if isinstance(function, dict):
        name = function.get("name")
        arguments = function.get("arguments", function.get("parameters", {}))
    elif isinstance(function, str):
        name = function
        arguments = obj.get("arguments", obj.get("parameters", obj.get("input", {})))
    else:
        name = obj.get("name") or obj.get("tool") or obj.get("tool_name")
        arguments = obj.get(
            "arguments", obj.get("parameters", obj.get("input", obj.get("args", {})))
        )
    normalized = _normalize_arguments(arguments)
    if not isinstance(name, str) or not name.strip() or normalized is None:
        return []
    return [ParsedToolCall(name.strip(), normalized)]


def _parse_hybrid_function(block: str) -> ParsedToolCall | None:
    """Recover Qwen calls whose function tag turns into a JSON prefix.

    Long generations sometimes produce
    ``<function=write\", \"arguments\": {...}}</parameter>``. The suffix is
    malformed, but the arguments object is complete. JSONDecoder.raw_decode
    finds its balanced end without being confused by nested braces inside the
    string-valued file content.
    """

    match = _QWEN_HYBRID_HEAD_RE.search(block)
    if not match:
        return None
    tail = block[match.end():].lstrip()
    try:
        value, _end = json.JSONDecoder().raw_decode(tail)
    except json.JSONDecodeError:
        return None
    arguments = _normalize_arguments(value)
    if arguments is None:
        return None
    return ParsedToolCall(match.group(1).strip(), arguments)


def _parse_pseudo_json_function(block: str) -> ParsedToolCall | None:
    """Recover ``{"function=NAME", "arguments": {...}}`` calls.

    Only the arguments object is decoded.  The caller still validates NAME
    against the exact tool schemas advertised by Harness before execution.
    """

    match = _QWEN_PSEUDO_JSON_HEAD_RE.search(block)
    if not match:
        return None
    tail = block[match.end():].lstrip()
    try:
        value, _end = json.JSONDecoder().raw_decode(tail)
    except json.JSONDecodeError:
        return None
    arguments = _normalize_arguments(value)
    if arguments is None:
        return None
    return ParsedToolCall(match.group(1).strip(), arguments)


def _arguments_from_body(body: str) -> dict[str, Any] | None:
    """Decode a direct function body, unwrapping an arguments container."""

    value = _normalize_arguments(body)
    if not isinstance(value, dict):
        return None
    for key in ("arguments", "parameters", "input", "args"):
        nested = _normalize_arguments(value.get(key)) if key in value else None
        if nested is not None:
            return nested
    return value


def _parse_loose_function(block: str) -> ParsedToolCall | None:
    """Recover common punctuation damage around a complete arguments object."""

    name_match = next(
        (match for pattern in _LOOSE_TOOL_NAME_RES if (match := pattern.search(block))),
        None,
    )
    if name_match is None:
        return None
    arguments_match = _LOOSE_ARGUMENTS_RE.search(block, name_match.end())
    if arguments_match is not None:
        tail = block[arguments_match.end():].lstrip()
        try:
            value, _end = json.JSONDecoder().raw_decode(tail)
        except json.JSONDecodeError:
            value = None
        arguments = _normalize_arguments(value)
        if arguments is not None:
            return ParsedToolCall(_clean_tool_name(name_match.group(1)), arguments)

    relaxed_parameters = {
        name.strip().strip('"\''): _xml_parameter_value(value)
        for name, value in _RELAXED_PARAM_RE.findall(block)
        if name.strip()
    }
    if relaxed_parameters:
        return ParsedToolCall(
            _clean_tool_name(name_match.group(1)), relaxed_parameters
        )
    return None


def _parse_bare_named_body(block: str) -> ParsedToolCall | None:
    """Recover ``write\n{...}`` inside an explicit tool-call envelope."""

    match = re.match(
        r"\s*([A-Za-z_][\w.:-]*)\s*(?::|\n)\s*", block, re.I | re.S
    )
    if not match:
        return None
    tail = block[match.end():].lstrip()
    try:
        value, _end = json.JSONDecoder().raw_decode(tail)
    except json.JSONDecodeError:
        return None
    arguments = _arguments_from_body(value) if isinstance(value, str) else _normalize_arguments(value)
    if arguments is None:
        return None
    return ParsedToolCall(_clean_tool_name(match.group(1)), arguments)


def _parse_xml_block(block: str) -> list[ParsedToolCall]:
    calls: list[ParsedToolCall] = []
    pseudo_json = _parse_pseudo_json_function(block)
    if pseudo_json is not None:
        return [pseudo_json]
    balanced_hybrid = _parse_hybrid_function(block)
    if balanced_hybrid is not None:
        return [balanced_hybrid]
    hybrid = _QWEN_HYBRID_FUNCTION_RE.search(block)
    if hybrid:
        arguments = _normalize_arguments(hybrid.group(2))
        if arguments is not None:
            return [ParsedToolCall(hybrid.group(1).strip(), arguments)]

    sibling = _QWEN_SIBLING_FUNCTION_RE.search(block)
    if sibling:
        arguments = {
            name.strip(): _xml_parameter_value(value)
            for name, value in _PARAM_RE.findall(sibling.group(2))
            if name.strip()
        }
        return [ParsedToolCall(_clean_tool_name(sibling.group(1)), arguments)]

    for match in _QWEN_FUNCTION_RE.finditer(block):
        arguments = {
            name.strip(): _xml_parameter_value(value)
            for name, value in _PARAM_RE.findall(match.group(2))
            if name.strip()
        }
        if not arguments:
            arguments = {
                name.strip().strip('"\''): _xml_parameter_value(value)
                for name, value in _RELAXED_PARAM_RE.findall(match.group(2))
                if name.strip()
            }
        if not arguments:
            direct = _arguments_from_body(match.group(2))
            if direct is not None:
                arguments = direct
        calls.append(ParsedToolCall(_clean_tool_name(match.group(1)), arguments))
    if calls:
        return calls

    for match in _XML_FUNCTION_RE.finditer(block):
        body = match.group(2)
        name = (match.group(1) or "").strip()
        if not name:
            found = _NAME_RE.search(body)
            name = found.group(1).strip() if found else ""
        arg_match = _ARGS_RE.search(body)
        arguments = (
            _normalize_arguments(arg_match.group(1))
            if arg_match
            else {
                key.strip(): _xml_parameter_value(value)
                for key, value in _PARAM_RE.findall(body)
                if key.strip()
            }
        )
        if name and arguments is not None:
            calls.append(ParsedToolCall(name, arguments))
    if calls:
        return calls
    loose = _parse_loose_function(block)
    if loose is not None:
        return [loose]
    bare = _parse_bare_named_body(block)
    if bare is not None:
        return [bare]
    return _call_from_object(_jsonish(block))


def _balanced_json_values(text: str) -> Iterable[Any]:
    decoder = json.JSONDecoder()
    index = 0
    while index < len(text):
        starts = [pos for pos in (text.find("{", index), text.find("[", index)) if pos >= 0]
        if not starts:
            return
        start = min(starts)
        try:
            value, end = decoder.raw_decode(text, start)
        except json.JSONDecodeError:
            index = start + 1
            continue
        yield value
        index = end


def parse_tool_calls(
    text: str,
    allowed_tools: Iterable[str] | Mapping[str, Mapping[str, Any]] | None = None,
) -> tuple[str, list[ParsedToolCall]]:
    """Parse calls and reject the whole set if any name is not advertised."""

    if not isinstance(text, str) or not text:
        return text if isinstance(text, str) else "", []
    tool_schemas: Mapping[str, Mapping[str, Any]] = (
        allowed_tools if isinstance(allowed_tools, Mapping) else {}
    )
    allowed = set(tool_schemas) if tool_schemas else set(allowed_tools or ())
    calls: list[ParsedToolCall] = []
    spans: list[tuple[int, int]] = []

    for match in _TOOL_BLOCK_RE.finditer(text):
        parsed = _parse_xml_block(match.group(1))
        if parsed:
            calls.extend(parsed)
            spans.append(match.span())

    if not calls:
        for match in _MARKDOWN_RE.finditer(text):
            arguments = _normalize_arguments(match.group(2))
            if arguments is not None:
                calls.append(ParsedToolCall(match.group(1), arguments))
                spans.append(match.span())

    if not calls and allowed:
        candidates = [(match.group(1), match.span()) for match in _JSON_FENCE_RE.finditer(text)]
        candidates.append((text.strip(), (0, len(text))))
        for candidate, span in candidates:
            parsed: list[ParsedToolCall] = []
            for value in _balanced_json_values(candidate):
                parsed.extend(_call_from_object(value))
            if parsed:
                calls = parsed
                spans = [span]
                break

    calls = [ParsedToolCall(_clean_tool_name(call.name), call.arguments) for call in calls]
    if not calls or (allowed and any(call.name not in allowed for call in calls)):
        return text, []
    if tool_schemas:
        calls = [_coerce_call_arguments(call, tool_schemas) for call in calls]
    remaining = text
    for start, end in reversed(spans):
        remaining = remaining[:start] + remaining[end:]
    return remaining.strip(), calls


def openai_tool_calls(calls: Iterable[ParsedToolCall]) -> list[dict[str, Any]]:
    return [
        {
            "id": "call_" + uuid.uuid4().hex[:24],
            "type": "function",
            "function": {
                "name": call.name,
                "arguments": json.dumps(
                    call.arguments, ensure_ascii=False, separators=(",", ":")
                ),
            },
        }
        for call in calls
    ]


def _render_prior_tool_call(call: dict[str, Any]) -> str:
    function = call.get("function") if isinstance(call, dict) else None
    if not isinstance(function, dict) or not isinstance(function.get("name"), str):
        return ""
    arguments = function.get("arguments", "{}")
    if not isinstance(arguments, str):
        arguments = json.dumps(arguments, ensure_ascii=False)
    value = {"name": function["name"], "arguments": _jsonish(arguments)}
    return f"<tool_call>\n{json.dumps(value, ensure_ascii=False)}\n</tool_call>"


def _prior_tool_names(messages: list[dict[str, Any]]) -> dict[str, str]:
    result: dict[str, str] = {}
    for message in messages:
        if message.get("role") != "assistant" or not isinstance(message.get("tool_calls"), list):
            continue
        for call in message["tool_calls"]:
            function = call.get("function") if isinstance(call, dict) else None
            if (
                isinstance(call, dict)
                and isinstance(call.get("id"), str)
                and isinstance(function, dict)
                and isinstance(function.get("name"), str)
            ):
                result[call["id"]] = function["name"]
    return result


def _render_tool_result(message: dict[str, Any], known_names: dict[str, str]) -> str:
    call_id = message.get("tool_call_id")
    name = message.get("name")
    if not isinstance(name, str) or not name:
        name = known_names.get(call_id, "tool") if isinstance(call_id, str) else "tool"
    body = {
        "status": "completed",
        "name": name,
        "tool_call_id": call_id if isinstance(call_id, str) else "",
        "content": message.get("content", ""),
    }
    return (
        "The preceding tool call has completed. Treat this as its observation, not "
        "as a new request.\n<tool_response>\n"
        f"{json.dumps(body, ensure_ascii=False, separators=(',', ':'))}\n"
        "</tool_response>\nDo not repeat an identical successful call. Continue with "
        "another tool only when necessary; otherwise answer in ordinary text."
    )


def tool_protocol_prompt(tools: list[dict[str, Any]]) -> str:
    functions = [
        tool["function"]
        for tool in tools
        if isinstance(tool, dict)
        and tool.get("type") == "function"
        and isinstance(tool.get("function"), dict)
    ]
    schema = json.dumps(functions, ensure_ascii=False, separators=(",", ":"))
    return (
        "Disable thinking for this tool-driven turn and act directly. /no_think\n"
        "You can call the functions in <tools>. When a function is needed, emit only "
        "this exact strict-JSON grammar. Emit exactly one block in each assistant "
        "turn, then wait for its tool result:\n"
        "<tool_call>\n"
        "{\"name\":\"TOOL_NAME\",\"arguments\":{\"ARGUMENT_NAME\":JSON_VALUE}}\n"
        "</tool_call>\n"
        "The object inside <tool_call> must be valid JSON: quote every key and every "
        "string value. Never emit `function=TOOL_NAME` or XML parameter tags. "
        "Use only advertised function names and satisfy their JSON schemas. Tool "
        "results arrive inside <tool_response>. Never repeat an identical successful "
        "call. When no function is needed, answer normally without tool-call markup.\n"
        f"<tools>{schema}</tools>"
    )


def text_only_protocol_prompt() -> str:
    """Instruction for structured calls that must never enter the Agent loop."""

    return (
        "This is a text-only structured-response turn. /no_think\n"
        "Do not call, mention, simulate, or emit any tool, function, action, "
        "<tool_call> block, XML tool tag, or shell command. Return only the final "
        "answer requested by the conversation. If JSON is requested, emit one valid "
        "JSON value with no Markdown fence, analysis, planning, or prose."
    )


def prepare_upstream_payload(
    payload: dict[str, Any], *, text_only: bool = False
) -> tuple[dict[str, Any], dict[str, Mapping[str, Any]]]:
    """Remove server tool fields and render their semantics into text messages."""

    outgoing = copy.deepcopy(payload)
    tools = outgoing.pop("tools", [])
    outgoing.pop("tool_choice", None)
    outgoing.pop("parallel_tool_calls", None)
    outgoing.pop("stream_options", None)
    outgoing["stream"] = False
    tool_schemas = {} if text_only else {
        function["name"]: (
            function.get("parameters")
            if isinstance(function.get("parameters"), Mapping)
            else {}
        )
        for tool in tools
        if isinstance(tool, dict)
        and isinstance((function := tool.get("function")), dict)
        and isinstance(function.get("name"), str)
    }

    raw_messages = [
        message for message in outgoing.get("messages", []) if isinstance(message, dict)
    ]
    known_names = _prior_tool_names(raw_messages)
    messages: list[dict[str, Any]] = []
    for message in raw_messages:
        role = message.get("role")
        if role == "tool":
            messages.append({"role": "user", "content": _render_tool_result(message, known_names)})
            continue
        clean = {
            key: value
            for key, value in message.items()
            if key not in {"tool_calls", "function_call"}
        }
        prior_calls = message.get("tool_calls")
        if role == "assistant" and isinstance(prior_calls, list):
            rendered = "\n".join(filter(None, map(_render_prior_tool_call, prior_calls)))
            clean["content"] = "\n".join(filter(None, (clean.get("content") or "", rendered)))
        messages.append(clean)

    if tools or text_only:
        # vLLM's Qwen chat template understands this extension.  Apply it on the
        # first request instead of waiting for a reasoning-only response: long
        # Stage 1/2/6 turns otherwise can spend the whole generation budget in
        # reasoning and exit successfully without executing a tool.
        template_kwargs = outgoing.get("chat_template_kwargs")
        if not isinstance(template_kwargs, dict):
            template_kwargs = {}
        outgoing["chat_template_kwargs"] = {
            **template_kwargs,
            "enable_thinking": False,
        }
        instruction = (
            text_only_protocol_prompt() if text_only else tool_protocol_prompt(tools)
        )
        system_index = next(
            (index for index, message in enumerate(messages) if message.get("role") == "system"),
            None,
        )
        if system_index is None:
            messages.insert(0, {"role": "system", "content": instruction})
        else:
            existing = messages[system_index].get("content") or ""
            messages[system_index]["content"] = f"{existing}\n\n{instruction}"
    outgoing["messages"] = messages
    return outgoing, tool_schemas

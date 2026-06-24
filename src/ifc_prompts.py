"""IFC (Information Flow Control) prompts — parametric flow-signature inference.

Design (validated by Oracle consult, see docs/ifc_design.md):

- We do NOT thread a scalar pc-label across blocks (unsound for nested branches,
  break/continue, early return, exceptions). Instead we ask the LLM to derive a
  *parametric flow signature* for the WHOLE function at once. The LLM sees the
  full body, so nested control flow and implicit flows are reasoned about
  internally; we never have to pop a pc-frame across a block boundary.

- A flow signature is parametric: each output channel's label is expressed as a
  DEPENDENCY SET over input sources (params/globals/receiver), NOT a hard-coded
  High/Low. e.g. identity(x) -> return depends on {param:x}. This is what makes
  cross-function composition (assume-guarantee) sound: a caller instantiates the
  callee signature with the caller's actual argument labels.

- Label inference (which inputs are High) is done by the LLM from naming/domain,
  but enforcement is deterministic and fail-closed (see ifc_reasoner.eval_label).

- Declassification is only ever PROPOSED here; it becomes a DECLASSIFIED verdict
  requiring human review, never auto-accepted.

The model returns a single JSON object wrapped in [FLOW_JSON] ... [/FLOW_JSON].
"""

import json

from config import IFC_FLOW_SIGNATURE_MODEL, MAX_IFC_ITER
from .llm_client import _openrouter_client, _retry_create
from .prompts import _LANGUAGE_EXPERTISE
from .trace_writer import new_event_id, record_llm_exchange, utc_now_iso


# Output channels every signature must address (those that apply to the function).
# These mirror the channels Oracle flagged as leak vectors.
_CHANNELS_DOC = (
    "  - \"return\": label-dependency of the returned value\n"
    "  - \"exception\": dependency of WHETHER an exception/abrupt error is raised.\n"
    "      List a source ONLY if the exception is raised based on that source's VALUE\n"
    "      (e.g. `if secret < 0: raise`). Do NOT list a source merely because a generic\n"
    "      type/runtime error (TypeError, NullPointer, etc.) could occur — those depend on\n"
    "      the input's TYPE, not its secret value, and are not a value-dependent flow.\n"
    "  - \"param:<name>.*\": dependency written INTO a mutable parameter/receiver attribute\n"
    "  - \"global:<name>\": dependency written into a global\n"
    "  - \"io:<sink>\": dependency of an observable side effect (log/stdout/network/db)\n"
    "  - \"termination\": dependency of whether the function terminates (loops/early exit).\n"
    "      Recorded for completeness only; out of scope for the leak verdict\n"
    "      (termination-insensitive non-interference).\n"
)


def _extract_flow_json(text):
    """Pull the JSON object wrapped in [FLOW_JSON] ... [/FLOW_JSON]. Returns dict or None."""
    if not text:
        return None
    start_tag, end_tag = "[FLOW_JSON]", "[/FLOW_JSON]"
    s = text.find(start_tag)
    e = text.rfind(end_tag)
    if s == -1 or e == -1 or e <= s:
        # Fallback: try to locate a bare JSON object.
        s2 = text.find("{")
        e2 = text.rfind("}")
        if s2 == -1 or e2 == -1 or e2 <= s2:
            return None
        candidate = text[s2 : e2 + 1]
    else:
        candidate = text[s + len(start_tag) : e]
    try:
        return json.loads(candidate.strip())
    except (json.JSONDecodeError, ValueError):
        return None


def _system_prompt(language):
    lang_expertise = _LANGUAGE_EXPERTISE.get(
        language.lower(),
        f"You are an expert in logic, formal verification, and {language} programming. ",
    )
    return (
        lang_expertise
        + "You are performing static INFORMATION FLOW CONTROL (IFC) analysis with a "
        "two-level lattice: High (secret/sensitive) and Low (public/observable). "
        "Non-interference requires that Low-observable outputs must not depend on High inputs.\n\n"
        "Your job is to derive a PARAMETRIC FLOW SIGNATURE for one function: for each "
        "output channel, the SET of input sources whose values it depends on — including "
        "IMPLICIT flows (a value assigned or an effect performed under a branch/loop/early-"
        "return/exception whose guard depends on an input also depends on that input).\n\n"
        "CRITICAL rules:\n"
        "1. Dependencies are PARAMETRIC: list the input SOURCES (param:<name>, global:<name>, "
        "receiver.<attr>), NOT a hard High/Low. A pass-through like identity(x) has return depends "
        "on {param:x} regardless of whether x happens to be secret.\n"
        "2. RECEIVER ATTRIBUTES ARE PER-ATTRIBUTE, NOT ONE BLOB. When a method reads instance "
        "attributes via `self`/`this`, treat EACH accessed attribute as its OWN distinct source "
        "named `receiver.<attr>` (e.g. `self.client_secret` -> `receiver.client_secret`, "
        "`self.base_url` -> `receiver.base_url`). NEVER collapse them into a single `receiver` "
        "source, and NEVER let one secret attribute taint the whole receiver. Label each "
        "`receiver.<attr>` independently: `receiver.client_secret` is High, but `receiver.base_url` "
        "or `receiver.timeout` is Low. An output depends only on the SPECIFIC attributes it "
        "actually reads, not on `self` as a whole.\n"
        "3. CONTAINER FIELD ACCESS IS PER-FIELD. When a value is extracted from a "
        "parameter/global/receiver by a NAMED field or key (e.g. `request.get(\"password\")`, "
        "`params[\"token\"]`, `body.api_key`, `config.db_password`), treat that extracted value as "
        "its OWN source named `<container>.<field>` (e.g. `param:request.password`, "
        "`param:body.api_key`) and label it by the FIELD name, NOT the container. A Low container "
        "(like a generic `request`/`params`/`body`) can still yield a High field: "
        "`request.get(\"password\")` is `param:request.password` = High even though `request` "
        "itself is Low. Never let a Low container mask a sensitive field, and never let one "
        "sensitive field taint the whole container. If a flow's notes describe a secret field "
        "reaching a sink, the structured `deps` MUST list that field source.\n"
        "4. Capture IMPLICIT flows. If `if (secret) out=1 else out=0`, then return depends on "
        "{the guard's sources}. If a value is written under a High-dependent branch, it depends "
        "on the guard. break/continue/return/throw under a guard taint the affected channel.\n"
        "5. INFER an initial label (High/Low) for each input source from naming "
        "conventions (password/secret/token/key/hash/ssn/credential => High; "
        "id/name/url/host/port/path/timeout/count/index/flag => Low), types, and any provided "
        "domain context. When genuinely unsure, mark it \"Unknown\" (the checker treats Unknown "
        "as High, fail-closed). Do NOT guess Low to be lenient, but DO label clearly-public "
        "fields (urls, hosts, public ids, timeouts, counts) as Low.\n"
        "6. DECLASSIFICATION: if a High->Low flow is INTENTIONAL and semantically necessary "
        "(e.g. password check returning a 1-bit match result, publishing a one-way hash), record "
        "it under \"declassifications\" with an anchor (the exact statement) and a reason. Do NOT "
        "use declassification to excuse releasing a full secret value. A declassification is a "
        "PROPOSAL for human review, not a pass.\n"
    )


def _user_prompt(func, signature_line, language, callee_summaries):
    callee_ctx = ""
    if callee_summaries:
        callee_ctx = (
            "\n\nCallee flow signatures (already derived; instantiate them at call sites):\n"
            + callee_summaries
        )
    return (
        f"Programming language: {language}\n\n"
        f"Function under analysis:\n{signature_line}\n"
        f"```{language.lower()}\n{func}\n```\n"
        f"{callee_ctx}\n\n"
        "Output channels to address (include only those that occur in this function):\n"
        + _CHANNELS_DOC
        + "\nReturn EXACTLY ONE JSON object wrapped in [FLOW_JSON] and [/FLOW_JSON] with this schema:\n"
        "{\n"
        '  "inputs": {"param:<name>": "High|Low|Unknown", "global:<name>": "...", "receiver.<attr>": "..."},\n'
        '  "outputs": {\n'
        '     "<channel>": {"deps": ["param:<name>", "receiver.<attr>", "global:<g>", ...], "const": null,\n'
        '                    "declass": [{"anchor": "<exact stmt>", "reason": "<why intended>"}]}\n'
        "  },\n"
        '  "notes": "<one-line summary of the dominant flow>"\n'
        "}\n"
        "Rules for the JSON: \"deps\" lists input SOURCES only (never High/Low literals). "
        "For instance attributes use a SEPARATE `receiver.<attr>` source per attribute actually "
        "read (e.g. `receiver.client_secret`, `receiver.base_url`) — never a bare `receiver`. "
        "Use \"const\":\"High\" only for a value that is intrinsically secret regardless of inputs "
        "(rare). Omit channels that do not occur. Include \"declass\" only for intentional, "
        "anchored High->Low releases; otherwise use an empty list or omit it."
    )


def derive_flow_signature(func, signature_line, language, callee_summaries=None,
                          trace_dir=None, trace_meta=None):
    """Derive a parametric flow signature (dict) for one function.

    Returns the parsed JSON dict, or None if the model never produced valid JSON
    after MAX_IFC_ITER attempts (caller MUST treat None as fail-closed, not pass).
    """
    messages = [
        {"role": "system", "content": _system_prompt(language)},
        {"role": "user", "content": _user_prompt(func, signature_line, language, callee_summaries)},
    ]
    trace_meta = trace_meta or {}
    for attempt in range(1, MAX_IFC_ITER + 1):
        event_id = new_event_id("ifc")
        started = utc_now_iso()
        response = None
        usage = {}
        try:
            response, usage = _retry_create(_openrouter_client, IFC_FLOW_SIGNATURE_MODEL, messages)
        except Exception as exc:
            event = {
                "event_id": event_id,
                "type": "llm_call",
                "stage": "ifc_flow_signature",
                "status": "error",
                "start_time": started,
                "end_time": utc_now_iso(),
                "summary": f"IFC flow-signature call failed: {exc}",
                "metadata": {**trace_meta, "model": IFC_FLOW_SIGNATURE_MODEL,
                             "attempt": attempt, "error": str(exc)},
            }
            record_llm_exchange(trace_dir, event_id, event, messages)
            raise
        parsed = _extract_flow_json(response)
        status = "success" if parsed is not None else "format_error"
        event = {
            "event_id": event_id,
            "type": "llm_call",
            "stage": "ifc_flow_signature",
            "status": status,
            "start_time": started,
            "end_time": utc_now_iso(),
            "summary": "Derived parametric flow signature",
            "metadata": {**trace_meta, "model": IFC_FLOW_SIGNATURE_MODEL,
                         "attempt": attempt, "usage": usage, "parsed": parsed},
        }
        record_llm_exchange(trace_dir, event_id, event, messages, response)
        if parsed is not None:
            return parsed
        # Retry with an explicit format correction (never default to a pass).
        messages = messages + [
            {"role": "assistant", "content": response or ""},
            {"role": "user", "content": "Your output was not valid JSON wrapped in [FLOW_JSON] "
                                         "and [/FLOW_JSON]. Re-emit ONLY that JSON object."},
        ]
    return None

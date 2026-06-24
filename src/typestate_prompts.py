"""Typestate / temporal-protocol prompts — derive a per-function ordered event
trace for detecting ORDERING bugs (TOCTOU, CSRF-before-state-change, TLS-verify-
before-use, resource open/close lifecycle, auth-before-privileged-action).

Theory (Strom-Yemini typestate / Ball-Rajamani property automata / safety LTL):
a property is "a bad event must not occur before/without a required event." The
LLM does NOT author automata; it only emits OBSERVED security-relevant events
mapped to a fixed abstract alphabet, in order, each tagged with the resource it
acts on and a PATH-COVERAGE tag. A deterministic checker runs the built-in
automata over that trace.

The crux (per Oracle): a flat event list is insufficient — ORDER + PATH COVERAGE
+ RESOURCE CORRELATION matter. So each event carries: order, kind, resource,
path_coverage (must/may/guarded/unknown), predecessors_must (the minimal CFG
substitute), and control_depends_on (for TOCTOU). Keep it from exploding: only
security-relevant events, collapse loops, never enumerate paths.

The model returns ONE JSON object wrapped in [TYPESTATE_JSON] ... [/TYPESTATE_JSON].
"""

import json

from config import TYPESTATE_MODEL, MAX_TYPESTATE_ITER  # noqa: F401 (model used by driver)
from .prompts import _LANGUAGE_EXPERTISE


def _extract_typestate_json(text):
    """Pull the JSON object wrapped in [TYPESTATE_JSON] ... [/TYPESTATE_JSON]."""
    if not text:
        return None
    start_tag, end_tag = "[TYPESTATE_JSON]", "[/TYPESTATE_JSON]"
    s = text.find(start_tag)
    e = text.rfind(end_tag)
    if s == -1 or e == -1 or e <= s:
        s2 = text.find("{")
        e2 = text.rfind("}")
        if s2 == -1 or e2 == -1 or e2 <= s2:
            return None
        candidate = text[s2:e2 + 1]
    else:
        candidate = text[s + len(start_tag):e]
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
        + "You are performing static TYPESTATE / TEMPORAL-PROTOCOL analysis to find ORDERING bugs: "
        "TOCTOU (check-then-use races), CSRF (a state-changing request handler that writes without "
        "a preceding CSRF-token validation), TLS verification disabled before a network use, "
        "resource lifecycle bugs (a resource opened must be closed on all paths; no use-after-close; "
        "no double-close), and privileged actions performed without a preceding auth check.\n\n"
        "For ONE function, emit an ORDERED list of security-relevant EVENTS plus resource lifecycle "
        "facts. You report FACTS only; a separate deterministic checker runs property automata and "
        "decides the verdict. Do NOT declare a verdict, and do NOT author automata.\n\n"
        "EVENT ALPHABET (use ONLY these kinds):\n"
        "- CALL — a call to another analyzed function (so callee events can be spliced in)\n"
        "- FS_CHECK — a filesystem check on a path (os.path.exists/access/stat/isfile)\n"
        "- FS_USE — a non-atomic use of a path that was checked (open/read/write by path)\n"
        "- FS_ATOMIC_USE — an atomic create/use that needs no separate pre-check "
        "(os.open with O_CREAT|O_EXCL, open(x,'x'))\n"
        "- CSRF_VALIDATE — a CSRF token validation (validate_csrf, check_csrf, csrf.protect)\n"
        "- STATE_CHANGE — a state-changing side effect in a request handler (DB write/insert/update/"
        "delete, filesystem write, privilege change) reachable from a POST/PUT/DELETE\n"
        "- TLS_VERIFY_DISABLE — disabling TLS verification (verify=False, CERT_NONE, "
        "check_hostname=False, _create_unverified_context)\n"
        "- TLS_VERIFY_ENABLE / TLS_HANDSHAKE_VERIFY — enabling/performing TLS verification\n"
        "- NETWORK_USE — an outbound network request (requests.get/post, urlopen, socket send); set "
        "tls_verify=verified|disabled|unknown|not_applicable. IMPORTANT: a default secure library "
        "call (e.g. requests.get(url) with no verify=False) is tls_verify='verified', NOT unknown.\n"
        "- RESOURCE_OPEN / RESOURCE_USE / RESOURCE_CLOSE / RESOURCE_ESCAPE — resource lifecycle "
        "(file/socket/lock/db connection/cursor). ESCAPE = the resource is returned, stored in a "
        "global, or handed off so the caller owns it.\n"
        "- AUTH_CHECK — an authentication/authorization check; set auth_kind\n"
        "- PRIVILEGED_ACTION — an action requiring prior auth\n\n"
        "RESOURCE CORRELATION: give each security-relevant value a resource with a stable `id` and a "
        "`canonical` name so the checker can tell that check(path) and use(path) act on the SAME "
        "resource. Set origin (param/local/return/global), formal (the parameter name if origin="
        "param), mutability (external_mutable for filesystem paths an attacker can swap; stable for "
        "constants), and escapes (none/return/global/field/argument).\n\n"
        "PATH COVERAGE (the key to soundness): for each event set path_coverage to: must (on ALL "
        "paths), may (on at least one path), guarded (only under a condition — set guard_id), or "
        "unknown (you cannot tell — the checker will fail closed). Use predecessors_must to list "
        "prior event ids that DEFINITELY occur before this event on every path (the minimal "
        "substitute for a control-flow graph). For TOCTOU, set control_depends_on to the FS_CHECK "
        "event id whose result controls whether the FS_USE happens.\n\n"
        "EXIT STATES: for every LOCAL resource you RESOURCE_OPEN, emit exit_states describing its "
        "state (open/closed/released/escaped) on the normal path AND the exception path. A resource "
        "left 'open' on an exception path (e.g. open() then read() then close() with NO finally/with) "
        "is a leak. If you cannot determine exit state, say unknown (the checker fails closed).\n\n"
        "Keep it SMALL and FAIL-CLOSED: only security-relevant events; collapse loops into one event; "
        "never enumerate paths; do not invent resources for ordinary locals. If order/coverage/"
        "resource identity is unclear, mark unknown rather than guessing — the checker treats unknown "
        "as needs-review, never as safe."
    )


def _user_prompt(numbered_src, signature_line, language, callee_summaries, function_role_hint):
    callee_ctx = ""
    if callee_summaries:
        callee_ctx = (
            "\n\nCallee typestate summaries (already derived; if you CALL one of these, emit a CALL "
            "event with the callee name and arg_resources mapping the callee's formal params to your "
            "resources, so the checker can splice the callee's events — e.g. a callee that performs "
            "the CSRF check or returns an open resource):\n" + callee_summaries
        )
    return (
        f"Programming language: {language}\n\n"
        f"Function under analysis:\n{signature_line}\n"
        f"```{language.lower()}\n{numbered_src}\n```\n"
        f"{callee_ctx}\n\n"
        "Return EXACTLY ONE JSON object wrapped in [TYPESTATE_JSON] and [/TYPESTATE_JSON]. Use [] for "
        "absent lists. Schema:\n"
        "{\n"
        '  "schema_version": "typestate.v1",\n'
        '  "function": "<name>",\n'
        '  "function_role": "entrypoint|request_handler|middleware|internal_helper|unknown",\n'
        '  "language": "' + language.lower() + '",\n'
        '  "resources": [\n'
        '    {"id": "r_path", "kind": "filesystem_path|file_handle|socket|lock|database_connection|'
        'cursor|http_request|session|csrf_token|tls_session|http_client|principal|security_context|'
        'generic_resource|unknown", "canonical": "<expr>", "origin": "param|local|return|global|'
        'literal|call_return|unknown", "formal": "<param|null>", "mutability": "stable|'
        'external_mutable|internal_mutable|unknown", "escapes": "none|return|global|field|argument|'
        'unknown"}\n'
        "  ],\n"
        '  "ambient_contexts": [\n'
        '    {"kind": "csrf_validated|auth_checked|tls_verify_disabled", "resource": "<rid>", '
        '"coverage": "must|may|unknown", "source": "<@decorator|middleware>"}\n'
        "  ],\n"
        '  "entry_states": [\n'
        '    {"resource": "<rid>", "state": "open|closed|released|verified|disabled|unknown", '
        '"source": "param_contract|decorator|framework|inferred|unknown", "caller_dependent": '
        '<true|false>}\n'
        "  ],\n"
        '  "events": [\n'
        '    {"id": "e1", "order": 1, "kind": "<EVENT_KIND>", "resource": "<rid>", '
        '"operation": "<exact stmt>", "path_coverage": "must|may|guarded|unknown", '
        '"guard_id": "<id|null>", "predecessors_must": ["<eid>"], "control_depends_on": ["<eid>"], '
        '"atomicity": "atomic|non_atomic|not_applicable|unknown", '
        '"tls_verify": "verified|disabled|unknown|not_applicable", "http_methods": ["POST"], '
        '"auth_kind": "authentication|authorization|either|not_applicable|unknown", '
        '"state_change_kind": "database_write|filesystem_write|external_side_effect|session_mutation|'
        'privilege_change|unknown", "callee": "<fn|null>", "arg_resources": {"<callee_param>": '
        '"<caller_rid>"}, "return_resource": "<rid|null>", "notes": ""}\n'
        "  ],\n"
        '  "exit_states": [\n'
        '    {"resource": "<rid>", "state": "open|closed|released|escaped|unknown", '
        '"path_coverage": "must|may|unknown", "condition": "normal|exception|early_return|all|'
        'unknown", "source_event": "<eid>"}\n'
        "  ],\n"
        '  "calls": [\n'
        '    {"event_id": "e5", "callee": "<fn>", "arg_resources": {"<callee_param>": "<caller_rid>"}, '
        '"return_resource": "<rid|null>", "path_coverage": "must|may|guarded|unknown"}\n'
        "  ],\n"
        '  "uncertainties": []\n'
        "}\n"
        "Every CALL event must also appear in `calls` with the same event_id. Mark request-handler "
        "writes as STATE_CHANGE with the http_methods. For a default-secure HTTPS call set "
        "tls_verify='verified'. For a LOCAL opened resource ALWAYS emit its exit_states (normal AND "
        "exception). When unsure, use 'unknown' — never omit a relevant event to make it look safe."
    )

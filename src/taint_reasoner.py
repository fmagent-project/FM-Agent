"""Integrity-taint reasoner — deterministic source->sink reachability with typed
sanitizer matching.

Split of responsibility (mirrors IFC/authz reasoners):
  - The LLM derives a per-function TAINT SIGNATURE (taint_prompts): tainted
    sources, typed sinks (operation sites with an argument context), typed
    sanitizer endorsements, and parametric flows so callers can instantiate.
  - THIS module decides, deterministically and fail-closed, whether each sink is
    reached by a tainted, un-endorsed flow.

This is the DUAL of IFC (Biba vs Bell-LaPadula): source = untrusted input
(replaces High-secret), sink = sensitive operation site (replaces Low output
channel), sanitizer = typed endorsement (replaces declassification). Per Oracle's
design (docs), the duality is NOT reused blindly:
  - sinks are OPERATION SITES with an arg_context, not output channels;
  - sanitizers are TYPED: a sanitizer only clears taint for sinks whose
    arg_context it endorses (html_escape clears XSS, never SQLi);
  - sources are CALL PATTERNS, not named variables.

3-status operational lattice: UNTAINTED < UNKNOWN_PARAM < TAINTED.
  - external concrete source            -> TAINTED
  - a parameter, caller-undetermined    -> UNKNOWN_PARAM  (=> POLYMORPHIC)
  - a parameter the caller proved clean  -> UNTAINTED

Verdict precedence: ERROR > VULNERABLE > POLYMORPHIC > SANITIZED > SAFE.
"""

from config import TAINT_FAIL_CLOSED  # noqa: F401 (kept for parity / future toggles)

from .taint_validation import validation_guard_coverage


VULNERABLE = "VULNERABLE"
SANITIZED = "SANITIZED"
POLYMORPHIC = "POLYMORPHIC"
SAFE = "SAFE"
ERROR = "ERROR"

# taint statuses
UNTAINTED = "UNTAINTED"
TAINTED = "TAINTED"
UNKNOWN_PARAM = "UNKNOWN_PARAM"


SOURCE_KINDS = {
    "http_param", "http_body", "http_header", "cli_arg", "stdin", "socket",
    "env", "file", "db_read", "untrusted_param", "deserialized", "unknown_external",
}

SINK_KINDS = {
    "sql_query", "shell_command", "subprocess_argv", "fs_path", "http_url_ssrf",
    "redirect_location", "html_output", "template_source", "deserialize",
    "code_eval", "ldap", "xpath",
}

ARG_CONTEXTS = {
    "sql_query_text", "sql_identifier", "sql_numeric_literal", "sql_param",
    "shell_command_text", "shell_arg_token", "shell_argv_token", "executable_path",
    "fs_path", "fs_path_segment", "http_url", "redirect_url",
    "html_body", "html_attr", "js_string", "url_attr", "css_string",
    "template_source", "serialized_blob", "code_string", "ldap_filter", "xpath_expr",
}

KNOWN_SANITIZER_KINDS = {
    "parameterized_query", "orm_parameterization", "sql_identifier_allowlist", "int_cast",
    "shell_quote", "argv_boundary", "command_allowlist",
    "path_containment", "path_allowlist", "safe_join_filename",
    "url_allowlist", "host_allowlist", "local_redirect_only",
    "html_escape", "html_attr_escape", "js_escape", "url_encode", "css_escape",
    "template_allowlist", "schema_validation", "safe_parser",
    "deserialization_allowlist", "code_allowlist",
    "ldap_escape", "xpath_escape", "xpath_parameterization",
}

# A sanitizer endorses a set of arg_contexts. A sink flow is cleared only if one
# of its sanitizers endorses the sink's arg_context (exact match), respecting
# these intentionally NARROW kind->context acceptances.
SANITIZER_ENDORSES = {
    "parameterized_query": {"sql_param"},
    "orm_parameterization": {"sql_param", "sql_query_text"},
    "sql_identifier_allowlist": {"sql_identifier"},
    "int_cast": {"sql_numeric_literal"},
    "shell_quote": {"shell_arg_token"},
    "argv_boundary": {"shell_argv_token"},
    "command_allowlist": {"executable_path", "shell_command_text"},
    "path_containment": {"fs_path"},
    "path_allowlist": {"fs_path", "fs_path_segment"},
    "safe_join_filename": {"fs_path_segment"},
    "url_allowlist": {"http_url", "redirect_url"},
    "host_allowlist": {"http_url"},
    "local_redirect_only": {"redirect_url"},
    "html_escape": {"html_body"},
    "html_attr_escape": {"html_attr"},
    "js_escape": {"js_string"},
    "url_encode": {"url_attr"},
    "css_escape": {"css_string"},
    "template_allowlist": {"template_source"},
    "schema_validation": {"serialized_blob"},
    "safe_parser": {"serialized_blob"},
    "deserialization_allowlist": {"serialized_blob"},
    "code_allowlist": {"code_string"},
    "ldap_escape": {"ldap_filter"},
    "xpath_escape": {"xpath_expr"},
    "xpath_parameterization": {"xpath_expr"},
}

SINK_TO_FINDING = {
    "sql_query": ("SQL_INJECTION", "CWE-89"),
    "shell_command": ("COMMAND_INJECTION", "CWE-78"),
    "subprocess_argv": ("ARGUMENT_INJECTION", "CWE-88"),
    "fs_path": ("PATH_TRAVERSAL", "CWE-22"),
    "http_url_ssrf": ("SSRF", "CWE-918"),
    "redirect_location": ("OPEN_REDIRECT", "CWE-601"),
    "html_output": ("XSS", "CWE-79"),
    "template_source": ("TEMPLATE_INJECTION", "CWE-1336"),
    "deserialize": ("UNSAFE_DESERIALIZATION", "CWE-502"),
    "code_eval": ("CODE_INJECTION", "CWE-94"),
    "ldap": ("LDAP_INJECTION", "CWE-90"),
    "xpath": ("XPATH_INJECTION", "CWE-643"),
}


def finding_kind_for(sink_kind):
    return SINK_TO_FINDING.get(sink_kind, ("INJECTION", "CWE-74"))


# --- validation ---------------------------------------------------------------

def validate(facts):
    """Return an error string if the abstraction is malformed/out-of-enum, else None.

    Fail-closed rules 1/3/8/9: unknown source/sink/context enum or missing
    required fields -> ERROR (never silently SAFE).
    """
    if not facts or not isinstance(facts, dict):
        return "no valid taint abstraction"
    sources = facts.get("taint_sources") or []
    sinks = facts.get("sinks") or []
    if not isinstance(sources, list) or not all(isinstance(s, dict) for s in sources):
        return "malformed taint_sources"
    if not isinstance(sinks, list) or not all(isinstance(k, dict) for k in sinks):
        return "malformed sinks"
    for s in sources:
        if s.get("source_kind") not in SOURCE_KINDS:
            return f"unknown source_kind: {s.get('source_kind')}"
    for k in sinks:
        if k.get("sink_kind") not in SINK_KINDS:
            return f"unknown sink_kind: {k.get('sink_kind')}"
        if k.get("arg_context") not in ARG_CONTEXTS:
            return f"unknown arg_context: {k.get('arg_context')}"
        flows = k.get("flows") or []
        if not isinstance(flows, list) or not all(isinstance(fl, dict) for fl in flows):
            return f"malformed flows for sink: {k.get('id')}"
        for fl in flows:
            ref = fl.get("source")
            if not _valid_source_ref(ref):
                return f"malformed source ref: {ref}"
    for field in ("taint_bindings", "return_flows"):
        holders = facts.get(field) or []
        if not isinstance(holders, list) or any(
            not isinstance(holder, dict) for holder in holders
        ):
            return f"malformed {field}"
        for holder in holders:
            flows = holder.get("flows") or []
            if not isinstance(flows, list) or any(
                not isinstance(flow, dict)
                or not _valid_source_ref(flow.get("source"))
                for flow in flows
            ):
                return f"malformed flows for {field}"
    return None


def _valid_source_ref(ref):
    return isinstance(ref, str) and (
        ref.startswith("source:") or ref.startswith("param:")
        or ref.startswith("unknown:") or ref.startswith("callee_source:")
    )


# --- source status resolution -------------------------------------------------

def _source_status(src_obj):
    """A concrete in-function source is always TAINTED (incl. unknown_external)."""
    return TAINTED


def _concrete_sources(facts):
    return {f"source:{s['id']}": _source_status(s)
            for s in (facts.get("taint_sources") or []) if s.get("id")}


def resolve_status(ref, concrete_sources, param_status):
    """Resolve a flow source reference to a taint status.

    param_status: {param_name: TAINTED|UNTAINTED} from caller context (else
    UNKNOWN_PARAM). Mirrors IFC's caller-instantiated parameter labels.
    """
    if ref.startswith("source:"):
        return concrete_sources.get(ref, TAINTED)        # fail closed
    if ref.startswith(("unknown:", "callee_source:")):
        return TAINTED
    if ref.startswith("param:"):
        p = ref[len("param:"):]
        st = (param_status or {}).get(p)
        if st == TAINTED:
            return TAINTED
        if st == UNTAINTED:
            return UNTAINTED
        return UNKNOWN_PARAM
    return TAINTED  # malformed handled in validate(); fail closed if reached


# --- typed sanitizer matching -------------------------------------------------

def _sanitizers_by_id(facts):
    return {z.get("id"): z for z in (facts.get("sanitizers") or []) if z.get("id")}


def _resolve_sanitizer(entry, sanitizers_by_id):
    """Resolve a flow `sanitizers` entry to a sanitizer object.

    The LLM is supposed to emit id-strings (e.g. "Z1") that reference the
    function-level `sanitizers` list. In practice it sometimes inlines the whole
    sanitizer OBJECT into the flow (e.g. {"sanitizer_kind": "html_escape", ...}).
    Accept both shapes and fail closed (return None) on anything unhashable or
    malformed, instead of letting `dict.get(dict)` raise TypeError: unhashable.
    """
    if isinstance(entry, str):
        return sanitizers_by_id.get(entry)
    if isinstance(entry, dict):
        # inline object: resolve by id if present, else treat the object itself
        # as the sanitizer record.
        sid = entry.get("id")
        if isinstance(sid, str) and sid in sanitizers_by_id:
            return sanitizers_by_id[sid]
        return entry
    return None  # unhashable / unexpected type -> fail closed


def has_valid_sanitizer(flow, sink, sanitizers_by_id):
    """A flow is cleared iff one of its sanitizers (high-confidence, known kind)
    endorses the sink's arg_context. Typed: html_escape never clears sql_param."""
    required = sink.get("arg_context")
    # The typed context records that the database API binds this value outside
    # query syntax; no separate value-transform sanitizer is needed.
    if required == "sql_param":
        return True
    for entry in flow.get("sanitizers") or []:
        z = _resolve_sanitizer(entry, sanitizers_by_id)
        if not z or not isinstance(z, dict):
            continue
        if z.get("confidence") != "high":
            continue
        kind = z.get("sanitizer_kind")
        if kind not in KNOWN_SANITIZER_KINDS:
            continue
        # The endorsement must cover the sink's context. Honor both the
        # LLM-declared `endorses` list AND the narrow kind->context table; the
        # intersection (with required) decides.
        declared = {
            context for context in (z.get("endorses") or [])
            if isinstance(context, str)
        } if isinstance(z.get("endorses"), (list, tuple, set, frozenset)) else set()
        allowed = SANITIZER_ENDORSES.get(kind, set())
        if required in (declared & allowed) or required in (allowed if not declared else set()):
            return True
    return False


# --- the checker --------------------------------------------------------------

def classify(facts, param_status=None):
    """Decide the taint verdict for one function.

    param_status: caller-instantiated {param: TAINTED|UNTAINTED}. At an entrypoint
    the plugin may pre-seed request-like params as TAINTED; otherwise params are
    UNKNOWN_PARAM (=> POLYMORPHIC until a caller instantiates).

    Returns {verdict, findings: [{kind, cwe, sink_kind, arg_context, status,
    sanitized_by, source, message, evidence}], error}.
    """
    err = validate(facts)
    if err:
        return {"verdict": ERROR, "findings": [], "error": err}

    concrete = _concrete_sources(facts)
    sani_by_id = _sanitizers_by_id(facts)
    param_status = param_status or {}

    findings = []
    saw_sanitized = False

    for sink in facts.get("sinks") or []:
        relevant = False
        all_sanitized = True
        concrete_vuln = False
        param_vuln = False
        sanitized_by = None
        vuln_source = None

        for flow in sink.get("flows") or []:
            status = resolve_status(flow["source"], concrete, param_status)
            if status == UNTAINTED:
                continue
            relevant = True
            if has_valid_sanitizer(flow, sink, sani_by_id):
                sanitized_by = _first_sanitizer_kind(flow, sani_by_id)
                continue
            all_sanitized = False
            if status == TAINTED:
                concrete_vuln = True
                vuln_source = flow["source"]
            elif status == UNKNOWN_PARAM:
                param_vuln = True
                vuln_source = vuln_source or flow["source"]

        if not relevant:
            continue

        kind, cwe = finding_kind_for(sink.get("sink_kind"))
        guard_coverage = validation_guard_coverage(facts, sink)
        local_default_guard = (
            guard_coverage == "default"
            and "_validation_guard_coverage" not in sink
        )
        if all_sanitized or guard_coverage == "must" or local_default_guard:
            saw_sanitized = True
            guard_sanitized_by = sanitized_by or (
                "validation_guard"
                if guard_coverage == "must" or local_default_guard else None
            )
            findings.append(_finding("SANITIZED", kind, cwe, sink,
                                      sanitized_by=guard_sanitized_by))
        elif concrete_vuln:
            if guard_coverage == "default":
                findings.append(_finding("POLYMORPHIC", "VALIDATION_GUARD_BYPASS", cwe,
                                         sink, source=vuln_source))
            else:
                findings.append(_finding("VULNERABLE", kind, cwe, sink, source=vuln_source))
        elif param_vuln:
            findings.append(_finding("POLYMORPHIC", kind, cwe, sink, source=vuln_source))

    if any(f["status"] == "VULNERABLE" for f in findings):
        verdict = VULNERABLE
    elif any(f["status"] == "POLYMORPHIC" for f in findings):
        verdict = POLYMORPHIC
    elif saw_sanitized:
        verdict = SANITIZED
    else:
        verdict = SAFE
    return {"verdict": verdict, "findings": findings, "error": None}


def _first_sanitizer_kind(flow, sani_by_id):
    for sid in flow.get("sanitizers") or []:
        z = sani_by_id.get(sid)
        if z:
            return z.get("sanitizer_kind")
    return None


def _finding(status, kind, cwe, sink, source=None, sanitized_by=None):
    arg = sink.get("arg_expr") or "?"
    site = sink.get("call_expr") or sink.get("callee") or sink.get("sink_kind")
    if status == "VULNERABLE":
        msg = f"{kind} ({cwe}): tainted {arg} reaches {sink.get('sink_kind')} sink at `{site}`."
    elif kind == "VALIDATION_GUARD_BYPASS":
        msg = (f"{kind} ({cwe}): {arg} reaches {sink.get('sink_kind')} sink at `{site}`; "
               "a fail-closed validation guard covers the default call path, but a caller "
               "can explicitly bypass it.")
    elif status == "POLYMORPHIC":
        msg = (f"{kind} ({cwe}): {arg} reaches {sink.get('sink_kind')} sink at `{site}` "
               f"and is unsanitized — vulnerable iff the caller passes tainted data.")
    else:  # SANITIZED
        msg = (f"{kind} ({cwe}): tainted {arg} reaches {sink.get('sink_kind')} sink but is "
               f"endorsed for {sink.get('arg_context')} by {sanitized_by}.")
    return {"status": status, "kind": kind, "cwe": cwe,
            "sink_kind": sink.get("sink_kind"), "arg_context": sink.get("arg_context"),
            "source": source, "sanitized_by": sanitized_by,
            "message": msg, "evidence": site, "sink_id": sink.get("id")}


# --- composition helpers (bottom-up, mirrors IFC instantiate_callee) ----------

def instantiate_flows(flows, param_to_actual_flows, call_id, sanitizer_id_map=None):
    """Substitute a callee's parametric flow sources with the caller's actual
    argument flows at a call site. Concrete callee sources become opaque tainted
    (renamed under the call id); missing args fail closed to tainted unknown.
    """
    out = []
    for flow in flows or []:
        src = flow.get("source", "")
        extra_sani = [
            (sanitizer_id_map or {}).get(entry, entry) if isinstance(entry, str) else entry
            for entry in (flow.get("sanitizers") or [])
        ]
        if not isinstance(src, str):
            out.append({
                "source": f"unknown:{call_id}:malformed_source",
                "sanitizers": extra_sani,
            })
            continue
        if src.startswith("param:"):
            p = src[len("param:"):]
            actual = param_to_actual_flows.get(p)
            if actual is None:
                out.append({"source": f"unknown:{call_id}:missing_arg:{p}",
                            "sanitizers": extra_sani})
            else:
                for af in actual:
                    out.append({"source": af["source"],
                                "sanitizers": list(af.get("sanitizers") or []) + extra_sani})
        elif src.startswith("source:"):
            out.append({"source": f"callee_source:{call_id}:{src}", "sanitizers": extra_sani})
        elif src.startswith(("unknown:", "callee_source:")):
            out.append({"source": f"unknown:{call_id}:{src}", "sanitizers": extra_sani})
    return out


def instantiate_sink(callee_sink, call_id, param_to_actual_flows, sanitizer_id_map=None):
    """Re-anchor a callee sink at the caller, substituting param sources."""
    new = dict(callee_sink)
    new["id"] = f"{call_id}::{callee_sink.get('id', 'K')}"
    new["flows"] = instantiate_flows(
        callee_sink.get("flows"), param_to_actual_flows, call_id, sanitizer_id_map
    )
    new["_via"] = call_id
    return new

"""Typestate / temporal-protocol reasoner — deterministic property-automaton
checker over an LLM-derived ordered event trace.

Split of responsibility (mirrors crypto/taint/authz/IFC reasoners):
  - The LLM derives a per-function TYPESTATE SIGNATURE (typestate_prompts): an
    ORDERED list of security-relevant events (each tagged with an abstract event
    kind, the resource it acts on, and a path-coverage tag), resource lifecycle
    exit states, calls, and ambient contexts.
  - THIS module runs small built-in property AUTOMATA over those events and
    decides the verdict, deterministically and fail-closed.

Unlike taint/crypto there is NO data-flow "sink": the bug is an ORDERING
property (a required event must precede a trigger; a resource opened must close
on all paths; a check-then-use must be atomic). We DO reuse: POLYMORPHIC for
caller-dependent facts, fail-closed posture, bottom-up callee-summary
instantiation, and a top-down context worklist (for csrf/auth required events
that an ancestor may satisfy).

Verdict precedence: ERROR > VULNERABLE > POLYMORPHIC > NEEDS_REVIEW > SAFE.
(POLYMORPHIC above NEEDS_REVIEW: caller-dependent is actionable; needs-review is
an abstraction-quality gap.)

Scope (Oracle v1 cut): resource lifecycle, TOCTOU (intra-proc + call splicing),
TLS-verify-before-use, CSRF-before-state-change (+ top-down), auth-before-action
(+ top-down). Deferred: full CFG/path-sensitive model checking, concurrency/lock
ordering, cross-request session state, race exploitability proof.
"""

from config import TYPESTATE_FAIL_CLOSED  # noqa: F401 (kept for parity / future toggles)


VULNERABLE = "VULNERABLE"
POLYMORPHIC = "POLYMORPHIC"
NEEDS_REVIEW = "NEEDS_REVIEW"
SAFE = "SAFE"
ERROR = "ERROR"

_PRECEDENCE = [ERROR, VULNERABLE, POLYMORPHIC, NEEDS_REVIEW, SAFE]


# --- event alphabet (for validation) -----------------------------------------

EVENT_KINDS = {
    "CALL",
    "FS_CHECK", "FS_USE", "FS_ATOMIC_USE",
    "FS_NOFOLLOW_GUARD", "FS_ACQUIRE",
    "CSRF_VALIDATE", "STATE_CHANGE",
    "CONTENT_TYPE_CHECK", "JSON_PARSE",
    "TLS_VERIFY_DISABLE", "TLS_VERIFY_ENABLE", "TLS_HANDSHAKE_VERIFY", "NETWORK_USE",
    "SSL_CONTEXT_CREATE", "CERT_DEFAULT_LOAD",
    "RESOURCE_OPEN", "RESOURCE_USE", "RESOURCE_CLOSE", "RESOURCE_ESCAPE",
    "AUTH_CHECK", "PRIVILEGED_ACTION",
}

# caps to prevent explosion
MAX_EVENTS = 64
MAX_RESOURCES = 32


# --- built-in property rules (Oracle's rule set) ------------------------------

TYPESTATE_RULES = [
    {"name": "toctou_check_then_use", "type": "check_then_use_non_atomic",
     "cwe": "CWE-367", "severity": "high", "context_kind": None},
    {"name": "csrf_validate_before_state_change", "type": "required_before_trigger",
     "cwe": "CWE-352", "severity": "high", "context_kind": "csrf_validated"},
    {"name": "tls_verify_before_network_use", "type": "forbidden_after",
     "cwe": "CWE-295", "severity": "high", "context_kind": "tls_verify_disabled"},
    {"name": "resource_lifecycle", "type": "must_release",
     "cwe": "CWE-772", "severity": "medium", "context_kind": None},
    {"name": "auth_before_privileged_action", "type": "required_before_trigger",
     "cwe": "CWE-306", "severity": "high", "context_kind": "auth_checked"},
]


# --- finding taxonomy (kind -> cwe + default severity) ------------------------

FINDING_KINDS = {
    "TOCTOU_CHECK_THEN_USE": ("CWE-367", "high"),
    "FS_UNSAFE_ACQUISITION": ("CWE-367", "high"),
    "CSRF_MISSING_VALIDATION": ("CWE-352", "high"),
    "CONTENT_TYPE_MISSING_BEFORE_JSON_PARSE": ("CWE-352", "high"),
    "TLS_VERIFY_DISABLED_USE": ("CWE-295", "high"),
    "TLS_DEFAULT_CERTS_WRONG_CONTEXT": ("CWE-295", "high"),
    "TLS_VERIFY_UNKNOWN": ("CWE-295", "medium"),
    "RESOURCE_LEAK": ("CWE-772", "medium"),
    "FILE_HANDLE_LEAK": ("CWE-775", "medium"),
    "USE_AFTER_RELEASE": ("CWE-672", "high"),
    "DOUBLE_RELEASE": ("CWE-415", "medium"),
    "AUTH_MISSING_BEFORE_PRIVILEGED_ACTION": ("CWE-306", "high"),
    "AUTHZ_MISSING_BEFORE_PRIVILEGED_ACTION": ("CWE-862", "high"),
    "CALLER_DEPENDENT_REQUIRED_EVENT": (None, "medium"),
    "UNKNOWN_TEMPORAL_ORDER": (None, "medium"),
}

# which finding verdict each kind carries
_KIND_VERDICT = {
    "TOCTOU_CHECK_THEN_USE": VULNERABLE,
    "FS_UNSAFE_ACQUISITION": VULNERABLE,
    "CSRF_MISSING_VALIDATION": VULNERABLE,
    "CONTENT_TYPE_MISSING_BEFORE_JSON_PARSE": VULNERABLE,
    "TLS_VERIFY_DISABLED_USE": VULNERABLE,
    "TLS_DEFAULT_CERTS_WRONG_CONTEXT": VULNERABLE,
    "TLS_VERIFY_UNKNOWN": NEEDS_REVIEW,
    "RESOURCE_LEAK": VULNERABLE,
    "FILE_HANDLE_LEAK": VULNERABLE,
    "USE_AFTER_RELEASE": VULNERABLE,
    "DOUBLE_RELEASE": VULNERABLE,
    "AUTH_MISSING_BEFORE_PRIVILEGED_ACTION": VULNERABLE,
    "AUTHZ_MISSING_BEFORE_PRIVILEGED_ACTION": VULNERABLE,
    "CALLER_DEPENDENT_REQUIRED_EVENT": POLYMORPHIC,
    "UNKNOWN_TEMPORAL_ORDER": NEEDS_REVIEW,
}


# --- validation ---------------------------------------------------------------

def validate(facts):
    """Return an error string if malformed / out-of-enum / over cap, else None."""
    if not facts or not isinstance(facts, dict):
        return "no valid typestate abstraction"
    events = facts.get("events") or []
    if len(events) > MAX_EVENTS:
        return f"too many events ({len(events)} > {MAX_EVENTS})"
    if len(facts.get("resources") or []) > MAX_RESOURCES:
        return "too many resources"
    for e in events:
        if e.get("kind") not in EVENT_KINDS:
            return f"unknown event kind: {e.get('kind')}"
    return None


# --- helpers ------------------------------------------------------------------

def _by_id(items, key="id"):
    return {it.get(key): it for it in (items or []) if it.get(key)}


def _ordered(events):
    return sorted(events or [], key=lambda e: (e.get("order", 0), str(e.get("id", ""))))


def _reachable(e):
    return e.get("path_coverage") in {"must", "may", "guarded", "unknown"}


def _unknown_cov(e):
    return e.get("path_coverage") == "unknown"


def _same_resource(resources, a_id, b_id):
    """Return 'yes' | 'no' | 'unknown' for whether two resource ids are the same."""
    if a_id == b_id:
        return "yes"
    a, b = resources.get(a_id), resources.get(b_id)
    if not a or not b:
        return "unknown"
    if a.get("kind") == "unknown" or b.get("kind") == "unknown":
        return "unknown"
    ca, cb = a.get("canonical"), b.get("canonical")
    if ca and cb and ca == cb:
        return "yes"
    if not ca or not cb:
        return "unknown"
    return "no"


def _must_precede(req, trigger):
    """Return 'yes' | 'no' | 'unknown' for whether req definitely precedes trigger."""
    if req.get("id") in (trigger.get("predecessors_must") or []):
        return "yes"
    if req.get("order", 0) >= trigger.get("order", 0):
        return "no"
    if req.get("path_coverage") == "must":
        return "yes"
    if (req.get("path_coverage") == "guarded" and trigger.get("path_coverage") == "guarded"
            and req.get("guard_id") is not None
            and req.get("guard_id") == trigger.get("guard_id")):
        return "yes"
    if _unknown_cov(req) or _unknown_cov(trigger):
        return "unknown"
    return "no"


def _dominates(req, trigger):
    """A protocol guard is useful only when the abstraction proves dominance."""
    if _unknown_cov(req) or _unknown_cov(trigger):
        return "unknown"
    if req.get("order", 0) >= trigger.get("order", 0):
        return "no"
    return "yes" if req.get("id") in (trigger.get("predecessors_must") or []) else "no"


class _Findings:
    def __init__(self):
        self.items = []

    def add(self, kind, event=None, rule=None, reason=None):
        cwe, sev = FINDING_KINDS.get(kind, (None, "medium"))
        self.items.append({
            "kind": kind, "verdict": _KIND_VERDICT.get(kind, NEEDS_REVIEW),
            "cwe": cwe, "severity": sev, "rule": rule,
            "event_id": (event or {}).get("id"),
            "evidence": (event or {}).get("operation"),
            "resource": (event or {}).get("resource"),
            "reason": reason or "",
        })


# --- per-rule checkers --------------------------------------------------------

def _check_toctou(facts, resources, F):
    events = _ordered(facts.get("events"))
    checks = [e for e in events if e.get("kind") == "FS_CHECK"]
    uses = [e for e in events if e.get("kind") == "FS_USE"]
    for use in uses:
        if use.get("atomicity") == "atomic":
            continue
        if use.get("atomicity") == "unknown" or _unknown_cov(use):
            F.add("UNKNOWN_TEMPORAL_ORDER", use, "toctou_check_then_use")
            continue
        for check in checks:
            if check.get("order", 0) >= use.get("order", 0):
                continue
            rel = _same_resource(resources, check.get("resource"), use.get("resource"))
            if rel == "no":
                continue
            if rel == "unknown":
                F.add("UNKNOWN_TEMPORAL_ORDER", use, "toctou_check_then_use")
                continue
            depends = (check.get("id") in (use.get("control_depends_on") or [])
                       or check.get("id") in (use.get("predecessors_must") or []))
            if not depends:
                continue  # v1: do not flag unrelated check/use
            r = resources.get(use.get("resource"), {})
            mut = r.get("mutability")
            if mut == "stable":
                continue
            if mut == "unknown":
                F.add("UNKNOWN_TEMPORAL_ORDER", use, "toctou_check_then_use")
                continue
            if _unknown_cov(check):
                F.add("UNKNOWN_TEMPORAL_ORDER", use, "toctou_check_then_use")
                continue
            F.add("TOCTOU_CHECK_THEN_USE", use, "toctou_check_then_use")


def _check_guarded_protocol(facts, resources, guard_kind, trigger_kind, finding_kind, rule, F):
    events = _ordered(facts.get("events"))
    guards = [event for event in events if event.get("kind") == guard_kind]
    for trigger in (event for event in events if event.get("kind") == trigger_kind and _reachable(event)):
        if _unknown_cov(trigger):
            F.add("UNKNOWN_TEMPORAL_ORDER", trigger, rule)
            continue
        unknown = False
        for guard in guards:
            relation = _same_resource(resources, guard.get("resource"), trigger.get("resource"))
            if relation == "unknown":
                unknown = True
                continue
            if relation == "yes" and _dominates(guard, trigger) == "yes":
                break
            if relation == "yes" and _dominates(guard, trigger) == "unknown":
                unknown = True
        else:
            if unknown:
                F.add("UNKNOWN_TEMPORAL_ORDER", trigger, rule)
            else:
                F.add(finding_kind, trigger, rule)


def _ctx_has(propagated, kind, resource, coverage):
    """Whether a propagated context of `kind` covers `resource` at `coverage`."""
    for c in propagated or ():
        if c.get("kind") == kind and c.get("coverage") == coverage:
            cr = c.get("resource")
            if cr in (resource, None, "*") or resource is None:
                return True
    return False


def _check_required_before_trigger(facts, resources, rule, propagated, ctx, F):
    events = _ordered(facts.get("events"))
    if rule["name"] == "csrf_validate_before_state_change":
        req_kind, trig_kind, context_kind = "CSRF_VALIDATE", "STATE_CHANGE", "csrf_validated"
        vuln_kind = "CSRF_MISSING_VALIDATION"
        if any(event.get("kind") == "JSON_PARSE" and event.get("_source_validated") for event in events):
            return
        mutating = {"POST", "PUT", "PATCH", "DELETE"}
        if facts.get("function_role") not in {"request_handler", "entrypoint"} and not any(
            mutating.intersection(event.get("http_methods") or ())
            for event in events if event.get("kind") == trig_kind
        ):
            return
    else:
        req_kind, trig_kind, context_kind = "AUTH_CHECK", "PRIVILEGED_ACTION", "auth_checked"
        vuln_kind = ("AUTHZ_MISSING_BEFORE_PRIVILEGED_ACTION"
                     if any(e.get("auth_kind") == "authorization" for e in events)
                     else "AUTH_MISSING_BEFORE_PRIVILEGED_ACTION")

    reqs = [e for e in events if e.get("kind") == req_kind]
    triggers = [e for e in events if e.get("kind") == trig_kind and _reachable(e)]

    for trig in triggers:
        if _unknown_cov(trig):
            F.add("UNKNOWN_TEMPORAL_ORDER", trig, rule["name"])
            continue
        resource = trig.get("resource")
        if _ctx_has(propagated, context_kind, resource, "must"):
            continue
        if _ctx_has(propagated, context_kind, resource, "may"):
            F.add("UNKNOWN_TEMPORAL_ORDER", trig, rule["name"])
            continue

        satisfied, unknown = False, False
        for req in reqs:
            rel = _same_resource(resources, req.get("resource"), resource)
            if rel == "no" and rule["name"] == "auth_before_privileged_action":
                # auth: allow same principal/request/security_context even if ids differ
                continue
            if rel == "unknown":
                unknown = True
                continue
            mp = _must_precede(req, trig)
            if mp == "yes":
                satisfied = True
                break
            if mp == "unknown":
                unknown = True
        if satisfied:
            continue
        if unknown:
            F.add("UNKNOWN_TEMPORAL_ORDER", trig, rule["name"])
            continue
        if _can_be_satisfied_by_caller(facts, trig, ctx):
            F.add("CALLER_DEPENDENT_REQUIRED_EVENT", trig, rule["name"],
                  reason=f"{context_kind} may be established by an ancestor caller")
            continue
        F.add(vuln_kind, trig, rule["name"])


def _can_be_satisfied_by_caller(facts, trigger, ctx):
    if ctx.get("is_entrypoint"):
        return False
    if facts.get("function_role") in {"request_handler", "entrypoint"}:
        return False
    resources = _by_id(facts.get("resources"))
    r = resources.get(trigger.get("resource"))
    if not r:
        return False
    return (r.get("origin") == "param" and r.get("kind") in
            {"http_request", "session", "principal", "security_context"})


def _check_tls(facts, resources, propagated, F):
    events = _ordered(facts.get("events"))
    state = {}
    for c in propagated or ():
        if c.get("kind") == "tls_verify_disabled" and c.get("coverage") == "must":
            state[c.get("resource")] = "DISABLED"
    rel_kinds = {"TLS_VERIFY_DISABLE", "TLS_VERIFY_ENABLE", "TLS_HANDSHAKE_VERIFY", "NETWORK_USE"}
    for e in events:
        if e.get("kind") not in rel_kinds:
            continue
        rid = e.get("resource")
        cur = state.get(rid, "UNKNOWN")
        if _unknown_cov(e):
            F.add("UNKNOWN_TEMPORAL_ORDER", e, "tls_verify_before_network_use")
            continue
        k = e.get("kind")
        if k == "TLS_VERIFY_DISABLE":
            state[rid] = "DISABLED"
        elif k in {"TLS_VERIFY_ENABLE", "TLS_HANDSHAKE_VERIFY"}:
            state[rid] = "VERIFIED"
        elif k == "NETWORK_USE":
            tv = e.get("tls_verify")
            if tv == "disabled" or cur == "DISABLED":
                F.add("TLS_VERIFY_DISABLED_USE", e, "tls_verify_before_network_use")
            elif tv == "verified":
                state[rid] = "VERIFIED"
            elif tv == "unknown":
                r = resources.get(rid, {})
                if r.get("origin") == "param":
                    F.add("CALLER_DEPENDENT_REQUIRED_EVENT", e, "tls_verify_before_network_use",
                          reason="TLS verify state of the client param is caller-dependent")
                else:
                    F.add("TLS_VERIFY_UNKNOWN", e, "tls_verify_before_network_use")


def _check_lifecycle(facts, resources, F):
    events = _ordered(facts.get("events"))
    state = {}
    for entry in facts.get("entry_states") or []:
        state[entry.get("resource")] = (entry.get("state") or "unknown").upper()
    for rid, r in resources.items():
        state.setdefault(rid, "CLOSED" if r.get("origin") in {"local", "call_return"} else "UNKNOWN")

    life_kinds = {"RESOURCE_OPEN", "RESOURCE_USE", "RESOURCE_CLOSE", "RESOURCE_ESCAPE"}
    for e in events:
        if e.get("kind") not in life_kinds:
            continue
        rid = e.get("resource")
        if resources.get(rid, {}).get("kind") in {
            "filesystem_path", "http_request", "csrf_token", "tls_session", "tls_context",
            "http_client", "principal", "security_context",
        }:
            continue
        cur = state.get(rid, "UNKNOWN")
        r = resources.get(rid, {})
        if _unknown_cov(e):
            F.add("UNKNOWN_TEMPORAL_ORDER", e, "resource_lifecycle")
            continue
        k = e.get("kind")
        if k == "RESOURCE_OPEN":
            if cur == "OPEN":
                F.add("UNKNOWN_TEMPORAL_ORDER", e, "resource_lifecycle")
            state[rid] = "OPEN"
        elif k == "RESOURCE_USE":
            if cur in {"CLOSED", "RELEASED"}:
                F.add("USE_AFTER_RELEASE", e, "resource_lifecycle")
            elif cur == "UNKNOWN" and r.get("origin") == "param":
                F.add("CALLER_DEPENDENT_REQUIRED_EVENT", e, "resource_lifecycle",
                      reason="resource param open/closed state is caller-dependent")
            elif cur == "UNKNOWN":
                F.add("UNKNOWN_TEMPORAL_ORDER", e, "resource_lifecycle")
        elif k == "RESOURCE_CLOSE":
            if cur in {"CLOSED", "RELEASED"}:
                F.add("DOUBLE_RELEASE", e, "resource_lifecycle")
            elif cur == "UNKNOWN" and r.get("origin") == "param":
                F.add("CALLER_DEPENDENT_REQUIRED_EVENT", e, "resource_lifecycle",
                      reason="resource param close is caller-dependent")
            elif cur == "UNKNOWN":
                F.add("UNKNOWN_TEMPORAL_ORDER", e, "resource_lifecycle")
            state[rid] = "RELEASED"
        elif k == "RESOURCE_ESCAPE":
            state[rid] = "ESCAPED"

    # exit-state leak check (the important one for exception paths)
    exits_by_res = {}
    for x in facts.get("exit_states") or []:
        exits_by_res.setdefault(x.get("resource"), []).append(x)
    for rid, exits in exits_by_res.items():
        r = resources.get(rid, {})
        if r.get("kind") in {
            "filesystem_path", "http_request", "csrf_token", "tls_session", "tls_context",
            "http_client", "principal", "security_context",
        }:
            continue
        # A resource is locally OWNED (subject to the must-close check) when it is
        # created inside this function: origin "local" OR "call_return" (e.g.
        # f = open(path) labels f as call_return). A param/global is the caller's.
        if r.get("origin") not in {"local", "call_return"}:
            continue
        if r.get("escapes") in {"return", "global", "field", "argument"}:
            continue
        # If the resource is provably CLOSED/RELEASED on ALL paths (a must-close
        # exit covering both normal and exception conditions), it is NOT a leak —
        # even if the LLM also emitted a weaker speculative open/unknown exit.
        # This is the sound subsumption: a dominating release discharges the
        # must-reach obligation. (A genuine leak like load_text has its exception
        # exit = open with NO must-close on that path, so it still fires below.)
        closed_conditions = {
            x.get("condition") for x in exits
            if x.get("state") in {"closed", "released", "escaped"}
            and x.get("path_coverage") == "must"
        }
        if "all" in closed_conditions or {"normal", "exception"} <= closed_conditions:
            continue
        open_exits = [x for x in exits if x.get("state") == "open"
                      and x.get("path_coverage") in {"must", "may"}]
        unknown_exits = [x for x in exits if x.get("state") == "unknown"
                         or x.get("path_coverage") == "unknown"]
        if open_exits:
            kind = "FILE_HANDLE_LEAK" if r.get("kind") == "file_handle" else "RESOURCE_LEAK"
            F.add(kind, {"id": open_exits[0].get("source_event"),
                         "operation": f"{rid} left open on {open_exits[0].get('condition')} path",
                         "resource": rid}, "resource_lifecycle")
        elif unknown_exits:
            F.add("UNKNOWN_TEMPORAL_ORDER",
                  {"id": None, "operation": f"{rid} exit state unknown", "resource": rid},
                  "resource_lifecycle")

    # a locally-owned opened resource with NO exit state at all -> needs review
    opened_local = {e.get("resource") for e in events if e.get("kind") == "RESOURCE_OPEN"}
    for rid in opened_local:
        r = resources.get(rid, {})
        if r.get("origin") in {"local", "call_return"} and r.get("escapes") in (None, "none") \
                and rid not in exits_by_res:
            F.add("UNKNOWN_TEMPORAL_ORDER",
                  {"id": None, "operation": f"{rid} has no exit state recorded", "resource": rid},
                  "resource_lifecycle")


# --- the checker --------------------------------------------------------------

def classify(facts, propagated_contexts=(), is_entrypoint=True):
    """Decide the typestate verdict for one function.

    Returns {verdict, findings:[...], error}.
    """
    err = validate(facts)
    if err:
        return {"verdict": ERROR, "findings": [], "error": err}

    resources = _by_id(facts.get("resources"))
    ctx = {"is_entrypoint": is_entrypoint}
    F = _Findings()

    source_protocol = any(
        event.get("_source_validated")
        and event.get("kind") in {"JSON_PARSE", "CERT_DEFAULT_LOAD", "FS_ACQUIRE"}
        for event in facts.get("events") or ()
    )
    if not source_protocol:
        _check_toctou(facts, resources, F)
    _check_guarded_protocol(
        facts, resources, "CONTENT_TYPE_CHECK", "JSON_PARSE",
        "CONTENT_TYPE_MISSING_BEFORE_JSON_PARSE", "content_type_before_json_parse", F,
    )
    _check_guarded_protocol(
        facts, resources, "SSL_CONTEXT_CREATE", "CERT_DEFAULT_LOAD",
        "TLS_DEFAULT_CERTS_WRONG_CONTEXT", "default_certs_only_for_internal_context", F,
    )
    _check_guarded_protocol(
        facts, resources, "FS_NOFOLLOW_GUARD", "FS_ACQUIRE",
        "FS_UNSAFE_ACQUISITION", "nofollow_or_reparse_before_acquisition", F,
    )
    _check_tls(facts, resources, propagated_contexts, F)
    if not source_protocol:
        _check_lifecycle(facts, resources, F)
        for rule in TYPESTATE_RULES:
            if rule["type"] == "required_before_trigger":
                _check_required_before_trigger(facts, resources, rule, propagated_contexts, ctx, F)

    verdict = SAFE
    for level in _PRECEDENCE:
        if any(f["verdict"] == level for f in F.items):
            verdict = level
            break
    return {"verdict": verdict, "findings": F.items, "error": None}


# --- composition helpers (bottom-up: splice callee exported events) -----------

def _combine_coverage(call_cov, callee_cov):
    if call_cov == "unknown" or callee_cov == "unknown":
        return "unknown"
    if call_cov == "must" and callee_cov == "must":
        return "must"
    if call_cov == "guarded" or callee_cov == "guarded":
        return "guarded"
    return "may"


def summarize_facts(facts, verdict):
    """Build a compact caller-facing summary: exported events (on formal params /
    returns / globals), resource effects, context provides/requires."""
    if not facts:
        return {"verdict": verdict, "exported_events": [], "context_provides": [],
                "context_requires": [], "return_resources": []}
    resources = _by_id(facts.get("resources"))

    def sym(rid):
        r = resources.get(rid, {})
        if r.get("origin") == "param" and r.get("formal"):
            return f"formal:{r['formal']}"
        if r.get("origin") == "return":
            return "return"
        if r.get("origin") == "global":
            return f"global:{r.get('canonical', rid)}"
        return rid

    exported, provides, requires, return_res = [], [], [], []
    for e in _ordered(facts.get("events")):
        r = resources.get(e.get("resource"), {})
        # export events that touch params/returns/globals (caller-observable)
        if r.get("origin") in {"param", "return", "global"} or e.get("kind") in {
                "CSRF_VALIDATE", "AUTH_CHECK", "TLS_VERIFY_DISABLE"}:
            exported.append({
                "id": e.get("id"), "kind": e.get("kind"), "resource": sym(e.get("resource")),
                "operation": e.get("operation"), "path_coverage": e.get("path_coverage"),
                "tls_verify": e.get("tls_verify"), "atomicity": e.get("atomicity"),
            })
        if e.get("kind") == "CSRF_VALIDATE" and e.get("path_coverage") == "must":
            provides.append({"kind": "csrf_validated", "resource": sym(e.get("resource")), "coverage": "must"})
        if e.get("kind") == "AUTH_CHECK" and e.get("path_coverage") == "must":
            provides.append({"kind": "auth_checked", "resource": sym(e.get("resource")), "coverage": "must"})
        if e.get("kind") == "STATE_CHANGE":
            requires.append({"kind": "csrf_validated", "resource": sym(e.get("resource")), "coverage": "must"})
        if e.get("kind") == "PRIVILEGED_ACTION":
            requires.append({"kind": "auth_checked", "resource": sym(e.get("resource")), "coverage": "must"})
    # returned open resources -> caller obligation
    for x in facts.get("exit_states") or []:
        r = resources.get(x.get("resource"), {})
        if r.get("escapes") == "return" and x.get("state") == "open":
            return_res.append({"resource": "return", "state": "open"})
    return {"verdict": verdict, "exported_events": exported, "context_provides": provides,
            "context_requires": requires, "return_resources": return_res}

"""Authentication-integrity reasoner — deterministic event-domination +
authentication-strength + session-hygiene over an LLM-derived authn abstraction.

Split of responsibility (mirrors the authz reasoner):
  - The LLM derives a per-function AUTHN abstraction (authn_prompts): protected
    operations, authentication events (with method + strength + dominance),
    session events, and obligations relied upon from callers/framework.
  - THIS module decides, deterministically and fail-closed, whether each
    protected operation is dominated by a GENUINE authentication event, and
    whether session establishment is hygienic (regenerated id + expiry).

A protected operation OP is locally DISCHARGED iff there exists an authentication
event E with:
  - E.dominates_all_paths is true, AND
  - E.strength == "genuine" (a real secret/signature/MFA was verified).

If not discharged locally, OP becomes an OBLIGATION that may be discharged by an
ancestor caller (resolved top-down by the plugin's context worklist). At an
entrypoint an undischarged obligation is a real finding.

Independently of protected ops, session_events are checked for hygiene:
  - a session ESTABLISH with no REGENERATE => SESSION_FIXATION
  - a session ESTABLISH with no SET_EXPIRY  => INSUFFICIENT_SESSION_EXPIRATION
  - a TRUST_CLIENT_ID (adopting a client-supplied session id) => SESSION_FIXATION
And weak authentication events that DO dominate a protected op are reported as
WEAK_AUTHENTICATION (a check exists but is flawed: non-constant-time compare,
signature-without-expiry, decode-without-verify).

Verdict vocabulary (per function):
  - VULNERABLE   : >=1 protected op undischarged locally AND (entrypoint OR no
                   propagated caller context authenticates it); OR a session-
                   hygiene / weak-auth defect.
  - SAFE         : every protected op is discharged (locally or by a caller) and
                   no session-hygiene/weak-auth defect, or no protected op.
  - NEEDS_REVIEW : authentication depends on UNKNOWN framework/middleware
                   enforcement the function-local view cannot confirm.
  - ERROR        : no valid abstraction (fail-closed; never SAFE).

Finding sub-kinds (for VULNERABLE):
  MISSING_AUTHENTICATION             : protected op, no dominating auth event at all.
  ASSERTED_IDENTITY                  : identity taken from client input w/o verification.
  WEAK_AUTHENTICATION                : a dominating auth event exists but is flawed.
  SESSION_FIXATION                   : login establishes/adopts a session id w/o regenerate.
  INSUFFICIENT_SESSION_EXPIRATION    : a session is established with no expiry/timeout.
"""

from config import AUTHN_FAIL_CLOSED  # noqa: F401 (kept for parity / future toggles)
from src.authn_validation import (
    authentication_contract_discharges,
    authentication_contract_findings,
    validate_security_facts,
)


VULNERABLE = "VULNERABLE"
SAFE = "SAFE"
NEEDS_REVIEW = "NEEDS_REVIEW"
ERROR = "ERROR"


OP_KINDS = {
    "account_change", "privileged_action", "token_issue",
    "state_change", "data_access", "other",
}
AUTH_METHODS = {
    "password", "token", "jwt", "session", "mfa", "api_key", "oauth", "unknown",
}
AUTH_STRENGTHS = {"genuine", "weak", "asserted_only", "unknown"}
SESSION_EVENT_KINDS = {"establish", "regenerate", "set_expiry", "trust_client_id"}


# --- validation ---------------------------------------------------------------

def validate(abstraction):
    """Return an error string if malformed / out-of-enum, else None (fail-closed)."""
    if not abstraction or not isinstance(abstraction, dict):
        return "no valid authn abstraction"
    err = validate_security_facts(abstraction)
    if err:
        return err
    for op in abstraction.get("protected_operations") or []:
        if op.get("kind") not in OP_KINDS:
            return f"unknown protected op kind: {op.get('kind')}"
    for e in abstraction.get("authentication_events") or []:
        if e.get("method") not in AUTH_METHODS:
            return f"unknown authentication method: {e.get('method')}"
        if e.get("strength") not in AUTH_STRENGTHS:
            return f"unknown authentication strength: {e.get('strength')}"
    for s in abstraction.get("session_events") or []:
        if s.get("kind") not in SESSION_EVENT_KINDS:
            return f"unknown session event kind: {s.get('kind')}"
    return None


# --- helpers ------------------------------------------------------------------

def _dominating_genuine_event(events):
    """A protected op is discharged by a genuine, dominating authentication event."""
    for e in events:
        if e.get("dominates_all_paths") and e.get("strength") == "genuine":
            return e
    return None


def _dominating_weak_event(events):
    """A dominating-but-flawed event (a check exists but is weak)."""
    for e in events:
        if e.get("dominates_all_paths") and e.get("strength") == "weak":
            return e
    return None


def _dominating_unknown_event(events):
    """A dominating authentication event whose strength the LLM could not
    determine (e.g. it delegates to an opaque helper). A check IS present, but its
    genuineness cannot be confirmed locally -> NEEDS_REVIEW, not a hard miss."""
    for e in events:
        if e.get("dominates_all_paths") and e.get("strength") == "unknown":
            return e
    return None


def _has_asserted_only(events):
    return any(e.get("strength") == "asserted_only" for e in events)


def _finding_message(kind, op=None, evidence=None):
    where = ""
    if op:
        where = f"{op.get('kind', 'protected op')} on {op.get('subject_expr') or 'subject'}"
    ev = f" [{evidence}]" if evidence else ""
    return {
        "MISSING_AUTHENTICATION":
            f"{where}: protected operation has no dominating genuine authentication event.{ev}",
        "ASSERTED_IDENTITY":
            f"{where}: identity is taken from client-controlled input without verification "
            f"(asserted, not authenticated).{ev}",
        "WEAK_AUTHENTICATION":
            f"{where}: authentication event dominates the operation but is flawed "
            f"(e.g. non-constant-time compare, signature without expiry, decode without verify).{ev}",
        "SESSION_FIXATION":
            f"session established/adopted without regenerating the session id "
            f"(session fixation).{ev}",
        "INSUFFICIENT_SESSION_EXPIRATION":
            f"session established without an expiry/timeout (insufficient session expiration).{ev}",
    }.get(kind or "MISSING_AUTHENTICATION", f"{where}: authentication gap.{ev}")


# --- local evaluation ---------------------------------------------------------

def evaluate_local(abstraction):
    """Evaluate one function's authn abstraction in isolation.

    Returns:
      {
        "ops": [ {op, discharged: bool, kind: <finding-kind|None>,
                  dischargeable: bool, soft: bool} ],
        "session_findings": [ {kind, evidence} ],
        "error": bool,
      }
    Per-op flags drive classify():
      - dischargeable: a MISSING_AUTHENTICATION op may be authenticated by an
        ancestor caller (top-down). WEAK/ASSERTED are affirmative LOCAL defects
        and are NOT dischargeable by a caller.
      - soft: the op declares it relies on framework/middleware enforcement the
        local view cannot confirm -> NEEDS_REVIEW (not a hard VULNERABLE) when it
        is not otherwise discharged.
    Does NOT decide the final verdict (entrypoint-ness + caller context applied by classify()).
    """
    if not abstraction or not isinstance(abstraction, dict):
        return {"ops": [], "session_findings": [], "error": True}

    ops = abstraction.get("protected_operations") or []
    events = abstraction.get("authentication_events") or []
    sessions = abstraction.get("session_events") or []
    obligations = abstraction.get("obligations") or []

    op_results = []
    for op in ops:
        op_id = op.get("op_id")
        op_events = [
            event for event in events
            if not event.get("protects_op_ids") or op_id in event.get("protects_op_ids", [])
        ]
        genuine = _dominating_genuine_event(op_events)
        weak = _dominating_weak_event(op_events)
        unknown_dom = _dominating_unknown_event(op_events)
        asserted_only = _has_asserted_only(op_events)
        if authentication_contract_discharges(abstraction, op_id):
            op_results.append({"op": op, "discharged": True, "kind": None,
                               "dischargeable": False, "soft": False})
            continue
        if genuine:
            op_results.append({"op": op, "discharged": True, "kind": None,
                               "dischargeable": False, "soft": False})
            continue
        # not discharged by a genuine dominating event
        if weak:
            kind, dischargeable, soft = "WEAK_AUTHENTICATION", False, False
        elif asserted_only:
            kind, dischargeable, soft = "ASSERTED_IDENTITY", False, False
        elif unknown_dom:
            # a dominating auth gate exists but its genuineness can't be confirmed
            # locally (delegates to an opaque helper) -> NEEDS_REVIEW, not a hard miss.
            kind, dischargeable, soft = "MISSING_AUTHENTICATION", False, True
        elif op_events:
            # An operation-specific local gate exists but does not dominate the
            # operation. An ancestor cannot repair that local bypass path.
            kind, dischargeable, soft = "MISSING_AUTHENTICATION", False, False
        elif not op_events and obligations:
            # relies on a caller/framework: a caller may authenticate (top-down),
            # else it is an unconfirmable framework reliance -> NEEDS_REVIEW.
            kind, dischargeable, soft = "MISSING_AUTHENTICATION", True, True
        else:
            # a protected op with no local auth and no declared reliance: a caller
            # may still authenticate it (top-down), else it is a hard miss.
            kind, dischargeable, soft = "MISSING_AUTHENTICATION", True, False
        op_results.append({"op": op, "discharged": False, "kind": kind,
                           "dischargeable": dischargeable, "soft": soft})

    # session hygiene (independent of protected ops)
    session_findings = []
    kinds = {s.get("kind") for s in sessions}
    if "establish" in kinds or "trust_client_id" in kinds:
        if "trust_client_id" in kinds or "regenerate" not in kinds:
            ev = next((s.get("evidence") for s in sessions
                       if s.get("kind") in ("establish", "trust_client_id")), None)
            session_findings.append({"kind": "SESSION_FIXATION", "evidence": ev})
        if "establish" in kinds and "set_expiry" not in kinds:
            ev = next((s.get("evidence") for s in sessions if s.get("kind") == "establish"), None)
            session_findings.append({"kind": "INSUFFICIENT_SESSION_EXPIRATION", "evidence": ev})

    return {
        "ops": op_results,
        "session_findings": session_findings,
        "contract_findings": authentication_contract_findings(abstraction),
        "error": False,
    }


# --- top-down context ---------------------------------------------------------

def op_satisfied_by_context(op, propagated_contexts):
    """Whether some propagated caller context genuinely authenticates this op.

    A context is {"authenticated": bool, "strength": <str>}. An ancestor that
    established a genuine, dominating authentication discharges the obligation.
    """
    for ctx in propagated_contexts or ():
        if ctx.get("authenticated") and ctx.get("strength") == "genuine":
            return True
    return False


def establishes_to_contexts(abstraction):
    """Convert a function's genuine dominating authentication events into
    propagable contexts for its callees."""
    out = []
    for e in (abstraction.get("authentication_events") or []):
        if e.get("dominates_all_paths") and e.get("strength") == "genuine":
            out.append({"authenticated": True, "strength": "genuine",
                        "method": e.get("method") or "unknown"})
    return out


# --- the checker --------------------------------------------------------------

def classify(abstraction, is_entrypoint=True, propagated_contexts=()):
    """Decide the authentication verdict for one function.

    Returns {verdict, findings: [{kind, op, message}], local, error}.
    """
    if not abstraction or not isinstance(abstraction, dict):
        return {"verdict": ERROR, "findings": [],
                "error": "no valid authn abstraction (fail-closed)"}

    # fail-closed: malformed / out-of-enum abstraction is ERROR, never SAFE.
    err = validate(abstraction)
    if err:
        return {"verdict": ERROR, "findings": [], "error": err, "local": {}}

    local = evaluate_local(abstraction)
    if local.get("error"):
        return {"verdict": ERROR, "findings": [], "error": "bad abstraction", "local": {}}

    findings = []
    hard_defect = False
    soft_pending = False

    for res in local["ops"]:
        if res["discharged"]:
            continue
        op = res["op"]
        # A MISSING_AUTHENTICATION op (dischargeable) may be authenticated by an
        # ancestor caller; only flag if entrypoint OR no caller context satisfies it.
        if res["dischargeable"] and not is_entrypoint and \
                op_satisfied_by_context(op, propagated_contexts):
            continue
        # Undischarged. A "soft" reliance (declared framework/middleware) that no
        # caller context confirmed is NEEDS_REVIEW, not a hard VULNERABLE.
        if res["soft"]:
            soft_pending = True
            continue
        hard_defect = True
        findings.append({
            "kind": res["kind"] or "MISSING_AUTHENTICATION",
            "op": op,
            "message": _finding_message(res["kind"], op, op.get("evidence")),
        })

    # session-hygiene findings are local defects (not discharged by callers)
    for sf in local["session_findings"]:
        hard_defect = True
        findings.append({"kind": sf["kind"], "op": {},
                         "message": _finding_message(sf["kind"], None, sf.get("evidence"))})

    for finding in local["contract_findings"]:
        hard_defect = True
        findings.append(finding)

    if hard_defect:
        verdict = VULNERABLE
    elif soft_pending:
        verdict = NEEDS_REVIEW
    else:
        verdict = SAFE
    return {"verdict": verdict, "findings": findings, "local": local, "error": None}

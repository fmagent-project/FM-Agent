"""Access-control reasoner — deterministic guard-domination + binding-equality.

Split of responsibility (mirrors the IFC reasoner design):
  - The LLM derives a per-function authorization abstraction (authz_prompts):
    authenticated subject, sensitive operations (with resource identity), guards
    (with the subject/resource/action they bind and whether they dominate), and
    obligations relied upon from callers/framework.
  - THIS module decides, deterministically and fail-closed, whether each
    sensitive operation is properly authorized.

A sensitive operation OP is locally DISCHARGED iff there exists a guard G with:
  - G.dominates_all_paths is true, AND
  - G binds the authenticated subject (G.subject present / authentication kind), AND
  - G constrains the SAME resource the op touches:
        either G.resource_id_expr matches OP.resource_id_expr (ownership/tenant),
        or  G.kind == "role"/"admin" and OP.kind == "admin" (role guards an admin
            action even without a per-object id), AND
  - G.action_scope covers OP.action (or is "any").

If not discharged locally, OP becomes an OBLIGATION that may be discharged by an
ancestor caller (resolved top-down by the plugin's context worklist). At an
entrypoint an undischarged obligation is a real finding.

Verdict vocabulary (per function):
  - VULNERABLE   : >=1 sensitive op undischarged locally AND (this is an
                   entrypoint OR no propagated caller context discharges it).
  - SAFE         : every sensitive op is discharged (locally or by a caller), or
                   the function has no sensitive operation.
  - NEEDS_REVIEW : a sensitive op's authorization depends on UNKNOWN policy
                   enforcement (framework/middleware/ORM row-level) that the
                   function-local view cannot confirm — reported, not a hard bug.
  - ERROR        : no valid abstraction (fail-closed; never SAFE).

Finding sub-kinds (for VULNERABLE):
  MISSING_AUTHORIZATION            : sensitive op, no dominating guard at all.
  RESOURCE_BINDING_MISMATCH        : a dominating guard exists but binds a
                                     DIFFERENT resource id than the op touches
                                     (the classic IDOR shape).
  MISSING_AUTHENTICATION           : op present, no authenticated subject and no
                                     authentication guard/obligation.
  ROLE_ONLY_GUARD_FOR_OBJECT_ACTION: a role guard exists but the op is an
                                     object-specific access needing per-object
                                     ownership (role alone is insufficient).
  AUTHZ_AFTER_EFFECT               : a guard exists but does not dominate all
                                     paths (e.g. checked after the write).
"""

from config import AUTHZ_FAIL_CLOSED


VULNERABLE = "VULNERABLE"
SAFE = "SAFE"
NEEDS_REVIEW = "NEEDS_REVIEW"
ERROR = "ERROR"


def _norm(expr):
    """Normalize a resource-id expression for equality comparison.

    Conservative: lowercase, strip whitespace. We deliberately do NOT canonicalize
    aliases (a.id vs id) — treating syntactically different ids as different is
    what surfaces IDOR. Returns "" for falsy/null.
    """
    if not expr or expr in ("null", "None"):
        return ""
    return "".join(str(expr).split()).lower()


def _has_authenticated_subject(abstraction):
    subj = (abstraction.get("authenticated_subject") or {})
    expr = subj.get("expr")
    return bool(expr) and expr not in ("null", "None")


def _guard_binds_subject(guard):
    if guard.get("kind") == "authentication":
        return True
    s = guard.get("subject")
    return bool(s) and s not in ("null", "None")


def _action_covers(scope, action):
    if not scope or scope == "any":
        return True
    if not action:
        return True
    return _norm(scope) == _norm(action)


def _is_self_access(op):
    """True if the op's resource is identified BY the authenticated subject.

    A read/write keyed on current_user.id (origin "subject") is self-access: it
    is inherently authorized and needs no separate ownership guard. This is the
    dual of IDOR — the id is NOT attacker-controlled. Primary signal is
    resource_id_origin == "subject"; a conservative expr-prefix check backstops it.
    """
    origin = (op.get("resource_id_origin") or "").lower()
    if origin == "subject":
        return True
    rid = (op.get("resource_id_expr") or "").strip().lower()
    return (rid.startswith("current_user.") or rid.startswith("request.user.")
            or rid.startswith("self.user."))


def _discharges(guard, op):
    """Does guard G discharge sensitive op OP?

    Returns (discharged: bool, reason: str|None). reason names the gap when not
    discharged so the checker can pick a finding sub-kind.

    Dominance semantics depend on op kind: for a READ, fetching the row to
    evaluate an ownership guard NECESSARILY precedes that guard, and the only
    sink that matters (the disclosure/return) is downstream of the check — so a
    same-resource ownership/tenant guard discharges a read even if it does not
    dominate the FETCH. For write/delete/admin, a non-dominating guard means the
    effect may occur before authorization (AUTHZ_AFTER_EFFECT), so dominance is
    required.
    """
    op_kind = (op.get("kind") or "").lower()
    is_read = op_kind == "read"
    if not guard.get("dominates_all_paths") and not is_read:
        return False, "not_dominating"
    if not _guard_binds_subject(guard):
        return False, "no_subject_binding"
    if not _action_covers(guard.get("action_scope"), op.get("action")):
        return False, "action_not_covered"

    op_id = _norm(op.get("resource_id_expr"))
    g_id = _norm(guard.get("resource_id_expr"))
    kind = guard.get("kind")

    # Object-specific access (has a concrete resource id) needs a guard that
    # binds THAT id (ownership/tenant). A role/authentication guard alone does
    # not authorize a per-object action.
    if op_id:
        if kind in ("ownership", "tenant", "other") and g_id and g_id == op_id:
            return True, None
        if kind in ("ownership", "tenant") and g_id and g_id != op_id:
            return False, "binding_mismatch"
        if kind in ("role", "authentication"):
            # role guard for an object-specific access: insufficient unless the
            # op is an admin action (handled below).
            if op.get("kind") == "admin":
                return True, None
            return False, "role_only_for_object"
        if not g_id:
            # dominating guard but no resource id recorded -> cannot confirm binding
            return False, "binding_unknown"
        return False, "binding_mismatch"

    # No concrete resource id on the op (e.g. an admin/list action). A role or
    # authentication guard that dominates is acceptable.
    if kind in ("role", "authentication", "tenant", "ownership", "other"):
        return True, None
    return False, "binding_unknown"


def _best_finding_kind(reasons):
    """Pick the most informative finding sub-kind from collected gap reasons."""
    if "binding_mismatch" in reasons:
        return "RESOURCE_BINDING_MISMATCH"
    if "role_only_for_object" in reasons:
        return "ROLE_ONLY_GUARD_FOR_OBJECT_ACTION"
    if "not_dominating" in reasons:
        return "AUTHZ_AFTER_EFFECT"
    if "binding_unknown" in reasons:
        return "RESOURCE_BINDING_MISMATCH"
    return "MISSING_AUTHORIZATION"


def evaluate_local(abstraction):
    """Evaluate a single function's authorization abstraction in isolation.

    Returns a dict:
      {
        "ops": [ {op, discharged: bool, reasons: [...], kind: <finding-kind|None>} ],
        "undischarged": [op_id, ...],
        "needs_review": bool,
        "has_subject": bool,
      }
    Does NOT decide the final verdict (entrypoint-ness and caller context are
    applied by classify()).
    """
    if not abstraction or not isinstance(abstraction, dict):
        return {"ops": [], "undischarged": [], "needs_review": False,
                "has_subject": False, "error": True}

    ops = abstraction.get("sensitive_operations") or []
    guards = abstraction.get("guards") or []
    has_subject = _has_authenticated_subject(abstraction)
    auth_obligation = any(
        (o.get("action") in (None, "any") or True) and o
        for o in (abstraction.get("obligations") or [])
    )

    op_results = []
    undischarged = []
    needs_review = False

    for op in ops:
        reasons = []
        discharged = False
        # Self-access: a resource keyed by the authenticated subject (e.g.
        # current_user.id) is inherently authorized — the id is not
        # attacker-controlled, so no separate ownership guard is required.
        if has_subject and _is_self_access(op):
            op_results.append({"op": op, "discharged": True,
                               "reasons": ["self_access"], "kind": None})
            continue
        for g in guards:
            ok, reason = _discharges(g, op)
            if ok:
                discharged = True
                break
            if reason:
                reasons.append(reason)

        kind = None
        if not discharged:
            # Authentication gap: object access with neither subject nor any guard.
            if not has_subject and not guards and not auth_obligation:
                kind = "MISSING_AUTHENTICATION"
            else:
                kind = _best_finding_kind(reasons)
            # If the only uncertainty is unknown policy enforcement, soften.
            if reasons == ["binding_unknown"] and not guards:
                needs_review = True
            undischarged.append(op.get("op_id") or op.get("evidence") or "op")
        op_results.append({"op": op, "discharged": discharged,
                           "reasons": reasons, "kind": kind})

    return {"ops": op_results, "undischarged": undischarged,
            "needs_review": needs_review, "has_subject": has_subject,
            "error": False}


def op_satisfied_by_context(op, propagated_contexts):
    """Whether some propagated caller context discharges this op's obligation.

    A context is a dict {"resource_id_expr": <expr>, "action": <verb|any>,
    "subject_bound": bool, "kind": <guard kind>}. An ancestor that established a
    matching ownership/tenant guard (same resource id, covering action) discharges
    the op; a role/auth context discharges only non-object or admin ops.
    """
    op_id = _norm(op.get("resource_id_expr"))
    for ctx in propagated_contexts or ():
        if not ctx.get("subject_bound"):
            continue
        if not _action_covers(ctx.get("action"), op.get("action")):
            continue
        c_id = _norm(ctx.get("resource_id_expr"))
        kind = ctx.get("kind")
        if op_id:
            if kind in ("ownership", "tenant", "other") and c_id and c_id == op_id:
                return True
            if kind in ("role", "authentication") and op.get("kind") == "admin":
                return True
        else:
            return True
    return False


def classify(abstraction, is_entrypoint=True, propagated_contexts=()):
    """Decide the access-control verdict for one function.

    Returns {verdict, findings: [{kind, op, message}], local, error}.
    """
    if not abstraction or not isinstance(abstraction, dict):
        return {"verdict": ERROR, "findings": [],
                "error": "no valid authorization abstraction (fail-closed)"}

    local = evaluate_local(abstraction)
    if local.get("error"):
        return {"verdict": ERROR, "findings": [], "error": "bad abstraction"}

    findings = []
    real_undischarged = False
    for res in local["ops"]:
        if res["discharged"]:
            continue
        op = res["op"]
        # An internally-called function may have the obligation discharged by an
        # ancestor; only flag if entrypoint OR no caller context satisfies it.
        if not is_entrypoint and op_satisfied_by_context(op, propagated_contexts):
            continue
        # If non-entrypoint and we have NO propagated context at all, the op is an
        # unresolved obligation: at a true entrypoint it's a bug; mid-chain with no
        # context yet it's still suspicious -> report (fail-closed) but the worklist
        # will have given contexts to those reachable from an entrypoint.
        real_undischarged = True
        findings.append({
            "kind": res["kind"] or "MISSING_AUTHORIZATION",
            "op": op,
            "message": _finding_message(res["kind"], op),
        })

    if real_undischarged:
        verdict = VULNERABLE
    elif local["needs_review"]:
        verdict = NEEDS_REVIEW
    else:
        verdict = SAFE
    return {"verdict": verdict, "findings": findings, "local": local, "error": None}


def _finding_message(kind, op):
    rid = op.get("resource_id_expr") or "?"
    rtype = op.get("resource_type") or "resource"
    act = op.get("action") or op.get("kind") or "access"
    base = f"{act} on {rtype}[{rid}]"
    return {
        "RESOURCE_BINDING_MISMATCH":
            f"IDOR: {base} is guarded by a check on a DIFFERENT resource id "
            f"(authorization does not bind {rid}).",
        "MISSING_AUTHORIZATION":
            f"{base} has no dominating authorization guard.",
        "MISSING_AUTHENTICATION":
            f"{base} performed with no authenticated subject and no guard.",
        "ROLE_ONLY_GUARD_FOR_OBJECT_ACTION":
            f"{base} is object-specific but only a role guard is present "
            f"(no per-object ownership check).",
        "AUTHZ_AFTER_EFFECT":
            f"{base} has an authorization check that does not dominate all paths "
            f"(possible check-after-use).",
    }.get(kind or "MISSING_AUTHORIZATION", f"{base} authorization gap.")


def establishes_to_contexts(abstraction):
    """Convert a function's `establishes` + dominating guards into propagable
    contexts for its callees (used by the plugin's propagate_context)."""
    out = []
    subj_present = _has_authenticated_subject(abstraction)
    for g in (abstraction.get("guards") or []):
        if not g.get("dominates_all_paths"):
            continue
        out.append({
            "resource_id_expr": g.get("resource_id_expr"),
            "action": g.get("action_scope") or "any",
            "subject_bound": _guard_binds_subject(g) or subj_present,
            "kind": g.get("kind") or "other",
        })
    return out

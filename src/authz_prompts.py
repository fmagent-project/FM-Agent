"""Access-control (guarded-Hoare) prompts — derive a per-function authorization
abstraction for missing-authorization / IDOR-BOLA detection.

Theory (see docs/security_portfolio_roadmap.md §3, docs/plugin_architecture.md):

  Model every sensitive resource operation as a guarded Hoare triple
      { authenticated(subject) ∧ authorized(subject, resource, action) }
          sensitive_operation(resource, action)
      { effect_allowed }
  A function is VULNERABLE if some sensitive operation is NOT dominated, on all
  paths, by a guard that binds the AUTHENTICATED subject to the SAME resource
  the operation touches, with an action that covers the operation's action.

What the LLM is good at here (and is asked to extract):
  - recognizing a "sensitive operation" (DB read/write/delete of a user/tenant
    -owned resource, file/object access by request-derived id, admin action,
    cross-tenant query) and the RESOURCE IDENTITY it touches (e.g. invoice_id
    from request.path).
  - recognizing a "guard": an authorization check (ownership/role/tenant) and
    WHICH subject + resource + action it binds, and whether it dominates the op.
  - recognizing "obligations": a requirement this function relies on a CALLER to
    have established (e.g. "@login_required is applied by the route", "caller
    already checked ownership"). These flow UP the call chain.

What the LLM must NOT do:
  - decide the final verdict. The deterministic reasoner does guard-domination +
    binding-equality. The LLM only reports the structured facts + evidence.

The model returns a single JSON object wrapped in [AUTHZ_JSON] ... [/AUTHZ_JSON].
"""

import json

from config import AUTHZ_MODEL, MAX_AUTHZ_ITER  # noqa: F401 (model used by driver)
from .prompts import _LANGUAGE_EXPERTISE


def _extract_authz_json(text):
    """Pull the JSON object wrapped in [AUTHZ_JSON] ... [/AUTHZ_JSON]."""
    if not text:
        return None
    start_tag, end_tag = "[AUTHZ_JSON]", "[/AUTHZ_JSON]"
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
        + "You are performing static ACCESS-CONTROL analysis using a guarded-Hoare model. "
        "Goal: find missing-authorization and IDOR/BOLA bugs — where a sensitive "
        "operation on a resource is performed WITHOUT verifying that the authenticated "
        "subject is allowed to act on THAT SPECIFIC resource.\n\n"
        "For ONE function, extract a structured authorization abstraction. You report "
        "FACTS and EVIDENCE only; a separate deterministic checker decides the verdict "
        "(guard-domination + subject/resource/action binding equality). Do NOT declare a "
        "verdict yourself.\n\n"
        "Definitions:\n"
        "1. AUTHENTICATED SUBJECT: the acting principal, e.g. current_user, request.user, "
        "session['uid'], ctx.caller. Identify how it enters (a parameter, a receiver "
        "attribute, a framework global, or an authentication decorator/middleware).\n"
        "2. SENSITIVE OPERATION: an access to a user/tenant-owned or privileged resource — "
        "DB read/write/delete (ORM .get/.filter/.save/.delete, raw SQL), file/object access "
        "by a request-derived path/id, an administrative action, a cross-tenant query, or "
        "returning another principal's data. For EACH, record:\n"
        "   - kind: read | write | delete | admin | other\n"
        "   - resource_type: e.g. Invoice, User, File\n"
        "   - resource_id_expr: the EXACT expression identifying which resource (e.g. "
        "invoice_id, request.path.id, user_id). This is the key for IDOR.\n"
        "   - resource_id_origin: where that id comes from (request param/path/body, "
        "parameter, derived from subject, constant).\n"
        "   - action: a verb (read/update/delete/list/...).\n"
        "   - evidence: the exact statement.\n"
        "3. GUARD: an authorization check that, if it fails, blocks the operation. For EACH:\n"
        "   - predicate_nl: the check in words (e.g. 'invoice.owner_id == current_user.id', "
        "'current_user.is_admin', 'tenant filter on query').\n"
        "   - subject: which principal it binds (e.g. current_user) or null.\n"
        "   - resource_type / resource_id_expr: which resource it constrains, if any.\n"
        "   - action_scope: which actions it authorizes (or 'any').\n"
        "   - kind: ownership | role | tenant | authentication | other.\n"
        "   - dominates_all_paths: true if EVERY path to the sensitive operation passes "
        "this guard first (it returns/raises/aborts on failure BEFORE the op). If the guard "
        "is only on some branches, false.\n"
        "   - evidence: the exact statement.\n"
        "   FRAMEWORK-ENFORCED GUARDS (CRITICAL — do NOT misfile these as obligations): "
        "a decorator or dependency-injection declaration attached to THIS function that "
        "performs an authorization/permission check IS a guard, and it dominates all paths "
        "(the framework runs it before the function body executes). Treat these as guards "
        "with dominates_all_paths=true:\n"
        "     * FastAPI/Starlette: a route decorator carrying an authorization dependency, "
        "e.g. `@router.delete(..., dependencies=[Depends(requires_access_dag(method=\"DELETE\", "
        "access_entity=...))])`, or a `subject = Depends(get_current_user)` / "
        "`_ = Depends(requires_access_*)` parameter default. The permission/access-entity/"
        "method arguments tell you the action_scope and resource_type it authorizes.\n"
        "     * Flask / Flask-AppBuilder / Django: `@has_access`, `@has_access_api`, "
        "`@permission_name(...)`, `@login_required`, `@user_passes_test(...)`, "
        "`@permission_required(...)`.\n"
        "     * Java/Spring: `@PreAuthorize(...)`, `@Secured(...)`, `@RolesAllowed(...)`.\n"
        "   For such a guard, set kind='role' when it checks a role/permission name, "
        "kind='authentication' when it only proves identity, or kind='ownership'/'tenant' "
        "when it binds a specific resource id. Set resource_id_expr to the resource id the "
        "check binds if one is named (e.g. the `dag_id` in a DAG-level access check), else "
        "null. Record the decorator/Depends line as evidence. Only file something under "
        "`obligations` when the authorization is genuinely NOT attached to this function and "
        "must come from an ancestor caller — a decorator/DI dependency present ON this "
        "function is LOCAL enforcement, i.e. a guard, never an obligation.\n"
        "4. OBLIGATIONS: authorization this function does NOT perform locally but RELIES ON a "
        "caller/framework to have established. Record what is assumed and why (e.g. "
        "'route applies @login_required so current_user is authenticated', or 'callers must "
        "pass an already-owner-checked invoice'). These are discharged up the call chain.\n"
        "5. ESTABLISHES: guards this function performs that it could offer to its CALLEES "
        "(e.g. it checks ownership then calls a helper that does the write). List the guard "
        "predicates established before each internal call, if any.\n\n"
        "Be precise about resource_id_expr: an IDOR is exactly the case where the guard's "
        "resource_id_expr differs from (or is absent for) the sensitive op's resource_id_expr. "
        "If a guard checks one id but the op touches another, report BOTH ids faithfully — do "
        "not normalize them to look equal.\n"
        "If the function performs NO sensitive operation, return empty sensitive_operations. "
        "When unsure whether something is sensitive or whether a guard dominates, be "
        "CONSERVATIVE (report the op as sensitive; report dominates_all_paths=false if not "
        "clearly dominating) — the checker is fail-closed.\n"
    )


def _user_prompt(numbered_src, signature_line, language, callee_summaries, is_entrypoint):
    callee_ctx = ""
    if callee_summaries:
        callee_ctx = (
            "\n\nCallee authorization summaries (already derived; a callee may REQUIRE an "
            "authorization obligation that this function must discharge before calling it):\n"
            + callee_summaries
        )
    entry_note = (
        "This function IS an external entry point (e.g. a route/RPC handler): there is no "
        "internal caller to discharge its obligations, so any undischarged authorization "
        "requirement on a sensitive op is a real exposure."
        if is_entrypoint else
        "This function is called internally: an obligation it cannot satisfy locally may be "
        "discharged by an ancestor caller (the checker resolves this top-down)."
    )
    return (
        f"Programming language: {language}\n\n"
        f"{entry_note}\n\n"
        f"Function under analysis:\n{signature_line}\n"
        f"```{language.lower()}\n{numbered_src}\n```\n"
        f"{callee_ctx}\n\n"
        "Return EXACTLY ONE JSON object wrapped in [AUTHZ_JSON] and [/AUTHZ_JSON]:\n"
        "{\n"
        '  "authenticated_subject": {"expr": "<e.g. current_user>|null", '
        '"origin": "param|receiver|framework_global|decorator|none"},\n'
        '  "sensitive_operations": [\n'
        '    {"op_id": "<short id>", "kind": "read|write|delete|admin|other", '
        '"resource_type": "<Type>", "resource_id_expr": "<expr>|null", '
        '"resource_id_origin": "request|param|subject|constant|unknown", '
        '"action": "<verb>", "evidence": "<exact stmt>"}\n'
        "  ],\n"
        '  "guards": [\n'
        '    {"predicate_nl": "<check>", "subject": "<expr>|null", '
        '"resource_type": "<Type>|null", "resource_id_expr": "<expr>|null", '
        '"action_scope": "<verb|any>", "kind": "ownership|role|tenant|authentication|other", '
        '"source": "in_body|decorator|dependency_injection", '
        '"dominates_all_paths": true, "evidence": "<exact stmt>"}\n'
        "  ],\n"
        '  "obligations": [\n'
        '    {"requires_nl": "<what authorization is assumed of the caller/framework>", '
        '"resource_type": "<Type>|null", "resource_id_expr": "<expr>|null", '
        '"action": "<verb|any>", "reason": "<why assumed>"}\n'
        "  ],\n"
        '  "establishes": [\n'
        '    {"callee_name": "<fn>", "guard_predicate_nl": "<guard established before the call>", '
        '"resource_id_expr": "<expr>|null"}\n'
        "  ],\n"
        '  "notes": "<one-line summary of the authorization posture>"\n'
        "}\n"
        "Omit arrays that are empty (or use []). Report resource_id_expr verbatim; never "
        "equate two different ids. Mark dominates_all_paths=false unless the guard truly "
        "precedes the op on every path. EXCEPTION: a decorator/dependency-injection guard "
        "attached to this function ALWAYS has dominates_all_paths=true and source="
        "'decorator' or 'dependency_injection' — the framework enforces it before the body "
        "runs. Set source='in_body' for ordinary inline checks."
    )

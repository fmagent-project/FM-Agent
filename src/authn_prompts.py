"""Authentication-integrity (guarded-Hoare) prompts — derive a per-function
authentication abstraction for improper-authentication detection (missing/weak
authentication, session fixation, insufficient session expiration, credential
exposure, authentication replay, password-change/recovery without re-auth).

Theory (sibling of the authz plugin; see docs/security_portfolio_roadmap.md):

  Model every PROTECTED operation as a guarded Hoare triple
      { genuinely_authenticated(subject) }  protected_operation  { effect_allowed }
  where authz asks "is THIS subject allowed on THIS resource", authn asks the
  PRIOR question "was the subject's identity actually VERIFIED at all (and not
  merely asserted / replayable / left from a fixed or stale session)".
  A function is VULNERABLE if a protected operation is NOT dominated, on all
  paths, by a GENUINE authentication event — or if it establishes/uses a session
  in a way that is fixable, replayable, or never expires.

What the LLM is good at here (and is asked to extract):
  - recognizing a "protected operation": an action that should require a verified
    identity (account/password change, privileged/admin action, accessing a
    user's own data, a state-changing API behind login, issuing a token/session).
  - recognizing an "authentication event": a check that genuinely verifies an
    identity — password/secret verified with a constant-time compare, a token/JWT
    whose signature+expiry are verified, an MFA step, an established framework
    session that was created by a real login. Record HOW strong it is and whether
    it dominates the op.
  - recognizing "session events": creating/establishing a session (login),
    regenerating the session id, setting expiry/timeout, or trusting a
    client-supplied session id (fixation risk).
  - recognizing "obligations": authentication this function relies on a
    CALLER/framework to have performed (e.g. "@login_required is applied by the
    route"). These flow UP the call chain.

What the LLM must NOT do:
  - decide the final verdict. The deterministic checker does event-domination +
    authentication-strength + session-hygiene rules. The LLM reports FACTS only.

The model returns a single JSON object wrapped in [AUTHN_JSON] ... [/AUTHN_JSON].
"""

import json

from config import AUTHN_MODEL, MAX_AUTHN_ITER  # noqa: F401 (model used by driver)
from .prompts import _LANGUAGE_EXPERTISE


def _extract_authn_json(text):
    """Pull the JSON object wrapped in [AUTHN_JSON] ... [/AUTHN_JSON]."""
    if not text:
        return None
    start_tag, end_tag = "[AUTHN_JSON]", "[/AUTHN_JSON]"
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
        + "You are performing static AUTHENTICATION-INTEGRITY analysis using a guarded-Hoare "
        "model. Goal: find IMPROPER-AUTHENTICATION bugs — where a protected operation runs "
        "without the subject's identity having been GENUINELY verified, or where a session/"
        "credential is handled so it can be fixed, replayed, or never expires. This is the "
        "PRIOR question to access control: authz asks 'may this subject act on this "
        "resource'; authn asks 'was the identity actually verified at all'.\n\n"
        "For ONE function, extract a structured authentication abstraction. You report FACTS "
        "and EVIDENCE only; a separate deterministic checker decides the verdict "
        "(event-domination + authentication-strength + session-hygiene). Do NOT declare a "
        "verdict yourself.\n\n"
        "Definitions:\n"
        "1. PROTECTED OPERATION: an action that should require a verified identity — account/"
        "password change, email change, privileged/admin action, issuing or returning a "
        "token/session/API key, a state-changing operation expected to be behind login, "
        "accessing a principal's private data. For EACH, record:\n"
        "   - op_id, kind: account_change | privileged_action | token_issue | "
        "state_change | data_access | other\n"
        "   - subject_expr: the identity it acts as/for (e.g. current_user, user_id) or null\n"
        "   - evidence: the exact statement.\n"
        "2. AUTHENTICATION EVENT: a check that genuinely verifies identity. For EACH:\n"
        "   - method: password | token | jwt | session | mfa | api_key | oauth | unknown\n"
        "   - verifies_nl: what is verified in words (e.g. 'bcrypt.checkpw(pw, hash)', "
        "'jwt.decode with verify=True and exp checked', 'request.user from a real login session')\n"
        "   - strength: genuine | weak | asserted_only. genuine = a real secret/signature/"
        "MFA is checked (constant-time where relevant, signature AND expiry verified). "
        "weak = a check exists but is flawed (non-constant-time compare, signature verified "
        "but not expiry, password compared with ==). asserted_only = identity is taken from "
        "client-controlled input WITHOUT verification (e.g. user_id from request body, "
        "decode-without-verify, trusting an unsigned header).\n"
        "   - dominates_all_paths: true if EVERY path to the protected op passes this event "
        "first (returns/raises on failure BEFORE the op). If only on some branches, false.\n"
        "   - evidence: the exact statement.\n"
        "3. SESSION EVENTS: record session lifecycle facts. For EACH:\n"
        "   - kind: establish (login creates a session/token) | regenerate (new session id "
        "issued on privilege change) | set_expiry (timeout/exp set) | trust_client_id "
        "(a client-supplied session id is adopted without regeneration — FIXATION risk)\n"
        "   - evidence: the exact statement.\n"
        "4. OBLIGATIONS: authentication this function does NOT perform locally but RELIES ON "
        "a caller/framework to have established (e.g. 'route applies @login_required'). "
        "Record what is assumed and why. These are discharged up the call chain.\n"
        "5. ESTABLISHES: authentication events this function performs that it could offer to "
        "its CALLEES (e.g. it verifies login then calls a helper). List the event before each "
        "internal call, if any.\n\n"
        "Be precise about STRENGTH and DOMINANCE: the classic bugs are (a) a protected op "
        "with no dominating genuine authentication event (missing/asserted-only auth), "
        "(b) a login that establishes a session but never regenerates the id (fixation), "
        "(c) a session never given an expiry, (d) a credential/token compared non-constant-"
        "time or decoded without verifying its signature. When unsure whether an op is "
        "protected or whether an event is genuine/dominating, be CONSERVATIVE (report the op "
        "as protected; mark strength=asserted_only or dominates_all_paths=false if not "
        "clearly genuine/dominating) — the checker is fail-closed.\n"
    )


def _user_prompt(numbered_src, signature_line, language, callee_summaries, is_entrypoint):
    callee_ctx = ""
    if callee_summaries:
        callee_ctx = (
            "\n\nCallee authentication summaries (already derived; a callee may REQUIRE an "
            "authentication obligation that this function must discharge before calling it):\n"
            + callee_summaries
        )
    entry_note = (
        "This function IS an external entry point (e.g. a route/RPC handler): there is no "
        "internal caller to authenticate the subject, so any undischarged authentication "
        "requirement on a protected op is a real exposure."
        if is_entrypoint else
        "This function is called internally: an authentication obligation it cannot satisfy "
        "locally may be discharged by an ancestor caller (the checker resolves this top-down)."
    )
    return (
        f"Programming language: {language}\n\n"
        f"{entry_note}\n\n"
        f"Function under analysis:\n{signature_line}\n"
        f"```{language.lower()}\n{numbered_src}\n```\n"
        f"{callee_ctx}\n\n"
        "Return EXACTLY ONE JSON object wrapped in [AUTHN_JSON] and [/AUTHN_JSON]:\n"
        "{\n"
        '  "protected_operations": [\n'
        '    {"op_id": "<short id>", "kind": "account_change|privileged_action|token_issue|'
        'state_change|data_access|other", "subject_expr": "<expr>|null", '
        '"evidence": "<exact stmt>"}\n'
        "  ],\n"
        '  "authentication_events": [\n'
        '    {"method": "password|token|jwt|session|mfa|api_key|oauth|unknown", '
        '"verifies_nl": "<what is verified>", "strength": "genuine|weak|asserted_only", '
        '"dominates_all_paths": true, "evidence": "<exact stmt>"}\n'
        "  ],\n"
        '  "session_events": [\n'
        '    {"kind": "establish|regenerate|set_expiry|trust_client_id", '
        '"evidence": "<exact stmt>"}\n'
        "  ],\n"
        '  "obligations": [\n'
        '    {"requires_nl": "<what authentication is assumed of the caller/framework>", '
        '"reason": "<why assumed>"}\n'
        "  ],\n"
        '  "establishes": [\n'
        '    {"callee_name": "<fn>", "event_nl": "<auth event established before the call>"}\n'
        "  ],\n"
        '  "notes": "<one-line summary of the authentication posture>"\n'
        "}\n"
        "Omit arrays that are empty (or use []). Report strength faithfully: identity taken "
        "from client input without verification is asserted_only, NOT genuine. Mark "
        "dominates_all_paths=false unless the event truly precedes the op on every path."
    )

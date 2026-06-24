"""IFC reasoner — deterministic lattice evaluation over LLM-derived flow signatures.

Split of responsibility (per Oracle consult, docs/ifc_design.md):
  - The LLM derives a PARAMETRIC flow signature (ifc_prompts.derive_flow_signature):
    which input sources each output channel depends on, plus inferred input labels
    and proposed declassifications. The LLM is good at "what depends on what",
    including implicit flows.
  - THIS module makes the security decision deterministically and fail-closed:
    it evaluates each output channel's label by joining the labels of its
    dependency sources, then classifies the function.

Two-level lattice: Low < High. join(High, anything) = High.

Verdict per function:
  - LEAK         : a Low-observable channel is High due to a GENUINE source
                   (a parameter labelled High by policy/naming, a High global, or
                   const:High) and is not declassified.
  - DECLASSIFIED : the High->Low flow(s) are covered by an anchored declassification
                   proposal (human review required).
  - POLYMORPHIC  : a Low-observable channel is High ONLY because of an Unknown-
                   labelled PARAMETER. Whether this is a real leak depends on the
                   caller's actual argument, so it cannot be judged in isolation;
                   it is resolved at call sites via instantiate_callee(). This is
                   why pure pass-throughs like identity(x) are not false LEAKs.
  - SECURE       : all Low-observable channels are Low.
  - ERROR        : no valid signature (fail-closed: never silently SECURE).

Cross-function (assume-guarantee, change-point B):
  A callee signature is parametric. At a call site the caller instantiates it by
  substituting the actual argument labels for the callee's formal-parameter
  sources -- see instantiate_callee(). A parameter's label in isolation is an
  ASSUMPTION, not a fact: the only caller-independent ("genuine") High sources are
  const:High channels, High globals, and parameters the policy labels High by name.
"""

from config import IFC_FAIL_CLOSED

HIGH = "High"
LOW = "Low"
UNKNOWN = "Unknown"

# Output channels observable by a Low attacker. A genuine-High value reaching any
# of these is a leak (unless declassified).
#
# NOTE: "termination" is intentionally EXCLUDED. The documented guarantee is
# termination-INSENSITIVE non-interference (see docs/ifc_design.md scope), so a
# High-dependent termination/timing channel is out of scope and must not be
# treated as Low-observable.
def _is_low_observable(channel):
    return (
        channel == "return"
        or channel == "exception"
        or channel.startswith("global:")
        or channel.startswith("io:")
    )


def _raw_input_labels(signature):
    """Return {source: raw_label} preserving High/Low/Unknown exactly as inferred."""
    out = {}
    for src, raw in (signature.get("inputs") or {}).items():
        out[src] = raw if raw in (HIGH, LOW, UNKNOWN) else UNKNOWN
    return out


def _normalize_label(raw):
    """Collapse a raw label to High/Low for enforcement, fail-closed on Unknown."""
    if raw == LOW:
        return LOW
    if raw == HIGH:
        return HIGH
    return HIGH if IFC_FAIL_CLOSED else LOW


# --- channel status: distinguish genuine-High from Unknown-parameter-conditional ---

GENUINE_HIGH = "genuine_high"   # High regardless of caller (named-High param / global / const High)
CONDITIONAL = "conditional"     # High only because an Unknown PARAMETER is fail-closed to High
LOW_STATUS = "low"


def _classify_channel(spec, raw_labels):
    """Classify one output channel.

    Returns (status, declassified_bool) where status is GENUINE_HIGH / CONDITIONAL / LOW_STATUS.

    A dependency source is:
      - genuine High   : raw label High, OR a non-param source missing from inputs
                         (undeclared global/intrinsic -> conservative), OR const:High
      - conditional    : an Unknown-labelled PARAMETER (param:*) -- caller decides
      - low            : raw label Low
    """
    if not isinstance(spec, dict):
        return (GENUINE_HIGH if IFC_FAIL_CLOSED else LOW_STATUS), False

    declassified = bool(spec.get("declass"))

    const = spec.get("const")
    if const == HIGH:
        return GENUINE_HIGH, declassified
    if const == LOW:
        return LOW_STATUS, declassified

    any_genuine = False
    any_conditional = False
    for src in spec.get("deps", []) or []:
        raw = raw_labels.get(src)
        if raw == HIGH:
            any_genuine = True
        elif raw == LOW:
            continue
        elif raw == UNKNOWN:
            if src.startswith("param:"):
                any_conditional = True          # caller decides this param's sensitivity
            else:
                any_genuine = True              # Unknown global/receiver -> conservative
        else:
            # Source not declared in inputs at all.
            if src.startswith("param:"):
                # An undeclared formal is genuinely unknown -> treat as conditional
                # so a pure helper is not a false LEAK; still resolved at call sites.
                any_conditional = True
            else:
                any_genuine = True              # undeclared global/io -> conservative

    if any_genuine:
        return GENUINE_HIGH, declassified
    if any_conditional:
        return CONDITIONAL, declassified
    return LOW_STATUS, declassified


def _is_low_observable_for(channel, raw_labels, is_entrypoint=True):
    """Whether a High value on this channel reaches a Low-observable EXTERNAL sink.

    Trust-boundary model (Task A precision fix):
      - io:* / global:*                : ALWAYS external sinks (log/network/stdout/db,
                                         shared globals). A secret here is a real leak.
      - param:<name>.*  (write INTO a param) : external only if the destination param
                                         is Low (writing into a High param is fine).
      - return / exception             : these hand a value back to the CALLER. For a
                                         library that is only an EXTERNAL sink when the
                                         function is an ENTRYPOINT (no internal caller) —
                                         then the return crosses the trust boundary to the
                                         outside world (e.g. an HTTP handler's response).
                                         When the function HAS an internal caller, the
                                         return is propagation-only: the caller decides
                                         (handled by instantiate_callee), so it is NOT an
                                         independent leak here. This removes the dominant
                                         false-positive class ("returns a secret to its
                                         own trusted caller") without losing real leaks,
                                         which surface at the io sink or at the entrypoint.
      - termination                    : out of scope (termination-insensitive).
    """
    if channel.startswith("param:"):
        base = channel.split(".", 1)[0]
        dest = raw_labels.get(base)
        if dest == HIGH:
            return False               # writing into a High param is not a Low leak
        if dest == LOW:
            return True
        return bool(IFC_FAIL_CLOSED)   # Unknown destination -> observable when fail-closed
    if channel == "return" or channel == "exception":
        return bool(is_entrypoint)     # caller-facing: external sink only at an entrypoint
    return _is_low_observable(channel)


def classify(signature, is_entrypoint=True):
    """Deterministically classify a function's flow signature.

    is_entrypoint: whether this function is an external entry point (no internal
      caller in the analyzed set). When True, its return/exception channels are
      treated as external Low-observable sinks (the value crosses the trust
      boundary to the outside world). When False, return/exception are
      propagation-only (the caller decides via instantiate_callee), so a secret
      merely returned to a trusted internal caller is NOT an independent leak.
      Defaults True (fail-closed: treat as boundary unless told otherwise).

    Returns a dict with keys:
      verdict: LEAK | DECLASSIFIED | POLYMORPHIC | SECURE | ERROR
      input_labels: {source: raw_label}
      violations: [ {channel, deps, declass} ]            # genuine-High, not declassified
      conditional_channels: [ {channel, deps, unknown_params} ]
      declassified_channels: [ {channel, deps, declass} ]
    """
    if not signature or not isinstance(signature, dict):
        return {"verdict": "ERROR", "input_labels": {}, "violations": [],
                "conditional_channels": [], "declassified_channels": [],
                "error": "no valid flow signature"}

    raw_labels = _raw_input_labels(signature)
    outputs = signature.get("outputs") or {}

    violations = []
    conditional_channels = []
    declassified_channels = []

    for channel, spec in outputs.items():
        if not _is_low_observable_for(channel, raw_labels, is_entrypoint):
            continue
        status, declassified = _classify_channel(spec, raw_labels)
        if status == LOW_STATUS:
            continue
        entry = {
            "channel": channel,
            "deps": (spec or {}).get("deps", []),
            "declass": (spec or {}).get("declass", []),
        }
        if declassified:
            declassified_channels.append(entry)
        elif status == GENUINE_HIGH:
            violations.append(entry)
        else:  # CONDITIONAL
            entry["unknown_params"] = [
                d for d in entry["deps"] if raw_labels.get(d) == UNKNOWN or raw_labels.get(d) is None
            ]
            conditional_channels.append(entry)

    if violations:
        verdict = "LEAK"
    elif declassified_channels:
        verdict = "DECLASSIFIED"
    elif conditional_channels:
        verdict = "POLYMORPHIC"
    else:
        verdict = "SECURE"

    return {
        "verdict": verdict,
        "input_labels": raw_labels,
        "violations": violations,
        "conditional_channels": conditional_channels,
        "declassified_channels": declassified_channels,
    }


# --- cross-function instantiation (the "instantiate" primitive) ---------------

def instantiate_callee(callee_sig, arg_binding):
    """Instantiate a parametric callee flow signature at one call site.

    This is the deterministic counterpart of the assume-guarantee step: it
    substitutes the caller's ACTUAL argument labels for the callee's formal
    parameter sources, then evaluates each callee output channel.

    Args:
      callee_sig: the callee's flow signature dict ('inputs' + 'outputs').
      arg_binding: {callee_formal_source: actual_label} e.g. {"param:x": "High"}.
        Formal sources absent from the binding fall back to the callee's own
        inferred input label (fail-closed via _normalize_label). Non-parameter
        sources (globals/receiver) always use the callee's inferred label.

    Returns:
      {channel: {"label": "High"|"Low", "declassified": bool}} -- the callee's
      output labels AS OBSERVED AT THIS CALL SITE.
    """
    if not callee_sig or not isinstance(callee_sig, dict):
        # Unknown callee -> fail closed: every channel High.
        return {}

    callee_inputs = _raw_input_labels(callee_sig)

    def label_of(src):
        if src in arg_binding:
            return _normalize_label(arg_binding[src])
        if src in callee_inputs:
            return _normalize_label(callee_inputs[src])
        # Undeclared source at the callee -> fail closed.
        return HIGH if IFC_FAIL_CLOSED else LOW

    result = {}
    for channel, spec in (callee_sig.get("outputs") or {}).items():
        if not isinstance(spec, dict):
            result[channel] = {"label": HIGH if IFC_FAIL_CLOSED else LOW, "declassified": False}
            continue
        const = spec.get("const")
        if const == HIGH:
            label = HIGH
        elif const == LOW:
            label = LOW
        else:
            label = LOW
            for src in spec.get("deps", []) or []:
                if label_of(src) == HIGH:
                    label = HIGH
                    break
        result[channel] = {"label": label, "declassified": bool(spec.get("declass"))}
    return result


def render_gaps(classification, signature):
    """Build the IFC 'gaps' dict for the result JSON (change-point D)."""
    viols = classification.get("violations", [])
    decls = classification.get("declassified_channels", [])
    conds = classification.get("conditional_channels", [])
    primary = (viols or decls or conds or [None])[0]
    raw = classification.get("input_labels", {})
    return {
        "high_sources": [s for s, l in raw.items() if l == HIGH],
        "unknown_params": [s for s, l in raw.items() if l == UNKNOWN],
        "leaking_channel": primary["channel"] if primary else None,
        "flow_deps": primary.get("deps", []) if primary else [],
        "declass_note": (primary.get("declass") if (primary and decls and not viols) else None),
        "notes": signature.get("notes", ""),
    }

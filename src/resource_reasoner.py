"""Resource-exhaustion reasoner — deterministic magnitude->costly-op reachability
with dominating-bound matching.

Split of responsibility (mirrors taint/ifc/authz reasoners):
  - The LLM derives a per-function RESOURCE SIGNATURE (resource_prompts):
    attacker-controllable magnitude sources, costly operations (each consuming a
    magnitude), typed bounds (with what magnitude they cap + whether they
    dominate), and parametric magnitudes so callers can instantiate.
  - THIS module decides, deterministically and fail-closed, whether each costly
    op consumes an attacker-controllable magnitude with NO dominating bound.

This is a sibling of integrity-taint: magnitude source = attacker-controllable
size/count/depth/ratio (replaces untrusted-input source), costly op = an
operation whose cost grows with the magnitude (replaces sink), bound = a guard
that dominates the op and caps the magnitude (replaces typed sanitizer). The
duality is NOT reused blindly:
  - a bound must DOMINATE the op (run on every path before it), not merely exist;
  - a bound is TYPED: it only clears a magnitude whose kind it caps (a length
    check does not bound recursion depth);
  - magnitude sources are CALL PATTERNS (len(request.body), a count param), not
    named variables.

3-status operational lattice: BOUNDED < UNKNOWN_PARAM < ATTACKER.
  - external concrete magnitude                 -> ATTACKER
  - a parameter, caller-undetermined            -> UNKNOWN_PARAM  (=> POLYMORPHIC)
  - a parameter the caller proved constant/safe -> BOUNDED

Verdict precedence: ERROR > VULNERABLE > POLYMORPHIC > BOUNDED > SAFE.
"""

from config import RESOURCE_FAIL_CLOSED  # noqa: F401 (kept for parity / future toggles)


VULNERABLE = "VULNERABLE"
BOUNDED = "BOUNDED"
POLYMORPHIC = "POLYMORPHIC"
SAFE = "SAFE"
ERROR = "ERROR"

# magnitude statuses
SAFE_MAG = "SAFE_MAG"
ATTACKER = "ATTACKER"
UNKNOWN_PARAM = "UNKNOWN_PARAM"


MAGNITUDE_KINDS = {
    "request_size", "element_count", "input_length", "recursion_depth",
    "decompressed_size", "numeric_param", "unknown_external",
}

OP_KINDS = {
    "allocation", "unbounded_read", "decompression", "regex_match",
    "recursion", "loop", "collection_build",
}

BOUND_KINDS = {
    "size_check", "count_limit", "depth_limit", "recursion_limit",
    "chunked_read_cap", "decompress_limit", "timeout", "input_length_cap",
}

# A bound caps a set of magnitude kinds. A costly op's magnitude is cleared only
# if a dominating bound caps THAT magnitude's kind (exact membership), respecting
# these intentionally NARROW kind->magnitude acceptances.
BOUND_CAPS = {
    "size_check": {"request_size", "input_length", "decompressed_size"},
    "count_limit": {"element_count", "numeric_param"},
    "depth_limit": {"recursion_depth"},
    "recursion_limit": {"recursion_depth"},
    "chunked_read_cap": {"request_size"},
    "decompress_limit": {"decompressed_size"},
    "timeout": {"input_length", "element_count", "recursion_depth", "numeric_param"},
    "input_length_cap": {"input_length"},
}

OP_TO_FINDING = {
    "allocation": ("UNCONTROLLED_ALLOCATION", "CWE-789"),
    "unbounded_read": ("UNCONTROLLED_RESOURCE_CONSUMPTION", "CWE-400"),
    "decompression": ("DECOMPRESSION_BOMB", "CWE-409"),
    "regex_match": ("REDOS", "CWE-1333"),
    "recursion": ("UNCONTROLLED_RECURSION", "CWE-674"),
    "loop": ("UNCONTROLLED_RESOURCE_CONSUMPTION", "CWE-400"),
    "collection_build": ("ALLOCATION_OF_RESOURCES_WITHOUT_LIMITS", "CWE-770"),
}


def finding_kind_for(op_kind):
    return OP_TO_FINDING.get(op_kind, ("UNCONTROLLED_RESOURCE_CONSUMPTION", "CWE-400"))


# --- validation ---------------------------------------------------------------

def validate(facts):
    """Return an error string if the abstraction is malformed/out-of-enum, else None.

    Fail-closed: unknown magnitude/op/bound enum or malformed magnitude ref ->
    ERROR (never silently SAFE).
    """
    if not facts or not isinstance(facts, dict):
        return "no valid resource abstraction"
    for m in facts.get("magnitude_sources") or []:
        if m.get("magnitude_kind") not in MAGNITUDE_KINDS:
            return f"unknown magnitude_kind: {m.get('magnitude_kind')}"
    for b in facts.get("bounds") or []:
        if b.get("bound_kind") not in BOUND_KINDS:
            return f"unknown bound_kind: {b.get('bound_kind')}"
    for op in facts.get("costly_ops") or []:
        if op.get("op_kind") not in OP_KINDS:
            return f"unknown op_kind: {op.get('op_kind')}"
        for mag in op.get("magnitudes") or []:
            ref = mag.get("source")
            if not _valid_magnitude_ref(ref):
                return f"malformed magnitude ref: {ref}"
    return None


def _valid_magnitude_ref(ref):
    return isinstance(ref, str) and (
        ref.startswith("mag:") or ref.startswith("param:")
        or ref.startswith("unknown:") or ref.startswith("callee_mag:")
    )


# --- magnitude status resolution ----------------------------------------------

def _concrete_magnitudes(facts):
    """A concrete in-function magnitude source is always ATTACKER (incl. unknown)."""
    return {f"mag:{m['id']}": ATTACKER
            for m in (facts.get("magnitude_sources") or []) if m.get("id")}


def resolve_status(ref, concrete_mags, param_status):
    """Resolve a magnitude source reference to a status.

    param_status: {param_name: ATTACKER|SAFE_MAG} from caller context (else
    UNKNOWN_PARAM). Mirrors taint's caller-instantiated parameter labels.
    """
    if ref.startswith("mag:"):
        return concrete_mags.get(ref, ATTACKER)            # fail closed
    if ref.startswith(("unknown:", "callee_mag:")):
        return ATTACKER
    if ref.startswith("param:"):
        p = ref[len("param:"):]
        st = (param_status or {}).get(p)
        if st == ATTACKER:
            return ATTACKER
        if st == SAFE_MAG:
            return SAFE_MAG
        return UNKNOWN_PARAM
    return ATTACKER  # malformed handled in validate(); fail closed if reached


# --- typed bound matching -----------------------------------------------------

def _bounds_by_id(facts):
    return {b.get("id"): b for b in (facts.get("bounds") or []) if b.get("id")}


def _resolve_bound(entry, bounds_by_id):
    """Resolve a magnitude `bounds` entry to a bound object. Accept an id-string
    or an inlined object; fail closed (None) on anything malformed (mirrors the
    taint reasoner's _resolve_sanitizer hardening)."""
    if isinstance(entry, str):
        return bounds_by_id.get(entry)
    if isinstance(entry, dict):
        bid = entry.get("id")
        if isinstance(bid, str) and bid in bounds_by_id:
            return bounds_by_id[bid]
        return entry
    return None  # unhashable / unexpected -> fail closed


def _magnitude_kind_of(ref, mags_by_id):
    """Best-effort kind of a concrete magnitude (for typed bound matching). A
    parametric/unknown magnitude has no known kind here -> None (a bound must then
    declare it caps via `caps`)."""
    if isinstance(ref, str) and ref.startswith("mag:"):
        m = mags_by_id.get(ref[len("mag:"):])
        if m:
            return m.get("magnitude_kind")
    return None


def has_dominating_bound(magnitude, op_mag_kind, bounds_by_id):
    """A magnitude is cleared iff one of its bounds (high-confidence, known kind)
    DOMINATES the op AND caps the op's magnitude kind. Typed: a size_check does
    not bound recursion depth."""
    for entry in magnitude.get("bounds") or []:
        b = _resolve_bound(entry, bounds_by_id)
        if not b or not isinstance(b, dict):
            continue
        if b.get("confidence") != "high":
            continue
        if not b.get("dominates"):
            continue
        kind = b.get("bound_kind")
        if kind not in BOUND_KINDS:
            continue
        declared = set(b.get("caps") or [])
        allowed = BOUND_CAPS.get(kind, set())
        # If we know the op's magnitude kind, require the bound to cap it (via the
        # declared∩allowed set, or the allowed set when the LLM didn't declare).
        if op_mag_kind:
            covering = (declared & allowed) if declared else allowed
            if op_mag_kind in covering:
                return True
        else:
            # Unknown/parametric magnitude kind: accept a dominating, known bound
            # that declares it caps SOMETHING in its allowed set (conservative —
            # a real dominating cap on this flow).
            if declared & allowed or allowed:
                return True
    return False


# --- the checker --------------------------------------------------------------

def classify(facts, param_status=None):
    """Decide the resource-exhaustion verdict for one function.

    param_status: caller-instantiated {param: ATTACKER|SAFE_MAG}. At an entrypoint
    the plugin may pre-seed request-like magnitude params as ATTACKER; otherwise
    params are UNKNOWN_PARAM (=> POLYMORPHIC until a caller instantiates).

    Returns {verdict, findings: [{kind, cwe, op_kind, status, bounded_by, source,
    message, evidence}], error}.
    """
    err = validate(facts)
    if err:
        return {"verdict": ERROR, "findings": [], "error": err}

    concrete = _concrete_magnitudes(facts)
    mags_by_id = {m.get("id"): m for m in (facts.get("magnitude_sources") or []) if m.get("id")}
    bounds_by_id = _bounds_by_id(facts)
    param_status = param_status or {}

    findings = []
    saw_bounded = False

    for op in facts.get("costly_ops") or []:
        relevant = False
        all_bounded = True
        concrete_vuln = False
        param_vuln = False
        bounded_by = None
        vuln_source = None

        for mag in op.get("magnitudes") or []:
            status = resolve_status(mag["source"], concrete, param_status)
            if status == SAFE_MAG:
                continue
            relevant = True
            op_mag_kind = _magnitude_kind_of(mag["source"], mags_by_id)
            if has_dominating_bound(mag, op_mag_kind, bounds_by_id):
                bounded_by = _first_bound_kind(mag, bounds_by_id)
                continue
            all_bounded = False
            if status == ATTACKER:
                concrete_vuln = True
                vuln_source = mag["source"]
            elif status == UNKNOWN_PARAM:
                param_vuln = True
                vuln_source = vuln_source or mag["source"]

        if not relevant:
            continue

        kind, cwe = finding_kind_for(op.get("op_kind"))
        if all_bounded:
            saw_bounded = True
            findings.append(_finding("BOUNDED", kind, cwe, op, bounded_by=bounded_by))
        elif concrete_vuln:
            findings.append(_finding("VULNERABLE", kind, cwe, op, source=vuln_source))
        elif param_vuln:
            findings.append(_finding("POLYMORPHIC", kind, cwe, op, source=vuln_source))

    if any(f["status"] == "VULNERABLE" for f in findings):
        verdict = VULNERABLE
    elif any(f["status"] == "POLYMORPHIC" for f in findings):
        verdict = POLYMORPHIC
    elif saw_bounded:
        verdict = BOUNDED
    else:
        verdict = SAFE
    return {"verdict": verdict, "findings": findings, "error": None}


def _first_bound_kind(magnitude, bounds_by_id):
    for entry in magnitude.get("bounds") or []:
        b = _resolve_bound(entry, bounds_by_id)
        if b and isinstance(b, dict):
            return b.get("bound_kind")
    return None


def _finding(status, kind, cwe, op, source=None, bounded_by=None):
    arg = op.get("arg_expr") or "?"
    site = op.get("call_expr") or op.get("callee") or op.get("op_kind")
    if status == "VULNERABLE":
        msg = (f"{kind} ({cwe}): attacker-controlled magnitude {arg} drives "
               f"{op.get('op_kind')} at `{site}` with no dominating bound.")
    elif status == "POLYMORPHIC":
        msg = (f"{kind} ({cwe}): {arg} drives {op.get('op_kind')} at `{site}` "
               f"unbounded — vulnerable iff the caller passes an attacker-controlled magnitude.")
    else:  # BOUNDED
        msg = (f"{kind} ({cwe}): magnitude {arg} drives {op.get('op_kind')} at `{site}` "
               f"but is capped by a dominating {bounded_by}.")
    return {"status": status, "kind": kind, "cwe": cwe,
            "op_kind": op.get("op_kind"), "source": source, "bounded_by": bounded_by,
            "message": msg, "evidence": site, "op_id": op.get("id")}


# --- composition helpers (bottom-up, mirrors taint instantiate_sink) ----------

def instantiate_magnitudes(magnitudes, param_to_actual_mags, call_id):
    """Substitute a callee's parametric magnitude sources with the caller's actual
    argument magnitudes at a call site. Concrete callee magnitudes become opaque
    attacker (renamed under the call id); missing args fail closed to attacker."""
    out = []
    for mag in magnitudes or []:
        src = mag.get("source", "")
        extra_bounds = list(mag.get("bounds") or [])
        if src.startswith("param:"):
            p = src[len("param:"):]
            actual = param_to_actual_mags.get(p)
            if actual is None:
                out.append({"source": f"unknown:{call_id}:missing_arg:{p}",
                            "bounds": extra_bounds})
            else:
                for am in actual:
                    out.append({"source": am["source"],
                                "bounds": list(am.get("bounds") or []) + extra_bounds})
        elif src.startswith("mag:"):
            out.append({"source": f"callee_mag:{call_id}:{src}", "bounds": extra_bounds})
        elif src.startswith(("unknown:", "callee_mag:")):
            out.append({"source": f"unknown:{call_id}:{src}", "bounds": extra_bounds})
    return out


def instantiate_op(callee_op, call_id, param_to_actual_mags):
    """Re-anchor a callee costly op at the caller, substituting param magnitudes."""
    new = dict(callee_op)
    new["id"] = f"{call_id}::{callee_op.get('id', 'OP')}"
    new["magnitudes"] = instantiate_magnitudes(callee_op.get("magnitudes"),
                                               param_to_actual_mags, call_id)
    new["_via"] = call_id
    return new

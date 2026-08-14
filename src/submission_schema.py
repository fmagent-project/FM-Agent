"""Strict result.json schemas for boundary-witness bug validation.

Design: docs/superpowers/specs/2026-07-10-boundary-witness-bug-validation-design.md §5.3
A `confirmed` submission must carry a witness pointing at a concrete captured
boundary record; `not_confirmed` needs only identity + attempts + notes.
"""

try:
    from .compiler_recipe import COMPILE_MODES, C_STANDARDS
except ImportError:  # flat import for direct test/script use
    from compiler_recipe import COMPILE_MODES, C_STANDARDS

class SchemaError(ValueError):
    pass


_CONFIRMED_KEYS_V3 = {
    "schema_version", "id", "function_id", "confirmation_status", "grade",
    "witness", "phenomenon", "l1_patch", "attempts", "notes",
}
_NOT_CONFIRMED_KEYS_V3 = {
    "schema_version", "id", "function_id", "confirmation_status", "attempts", "notes",
}
_WITNESS_KEYS_V3 = {
    "probe", "call_index", "captured_input", "actual_output",
    "spec_violation_claim",
}
# PIN: agent-evidence-is-non-executable
_PHENOMENON_KEYS_V3 = {"mode", "standard", "extra_args", "expected_kind"}
_PHENOMENON_MODES = COMPILE_MODES
_C_STANDARDS = C_STANDARDS
_PHENOMENON_KINDS = {
    "preprocess_differs", "accept_reject_differs",
    "build_accept_reject_differs", "run_exit_differs", "stdout_differs",
}


def _require_exact_type(d, key, typ, where):
    if key not in d:
        raise SchemaError(f"{where}.{key} missing")
    if type(d[key]) is not typ:
        raise SchemaError(f"{where}.{key} wrong type: {type(d[key]).__name__}")


def _require_nonempty_string(d, key, where):
    _require_exact_type(d, key, str, where)
    if not d[key].strip():
        raise SchemaError(f"{where}.{key} must be non-empty")


def _require_exact_keys(d, expected, where):
    if type(d) is not dict:
        raise SchemaError(f"{where} wrong type: {type(d).__name__}")
    missing = expected - set(d)
    if missing:
        raise SchemaError(f"{where}.{sorted(missing)[0]} missing")
    extra = set(d) - expected
    if extra:
        raise SchemaError(f"{where} unexpected field: {sorted(extra)[0]}")


def _validate_json_value(value, where):
    if value is None or type(value) in (str, int, float, bool):
        return
    if type(value) is list:
        for index, item in enumerate(value):
            _validate_json_value(item, f"{where}[{index}]")
        return
    if type(value) is dict:
        for key, item in value.items():
            if type(key) is not str:
                raise SchemaError(f"{where} has non-string key")
            _validate_json_value(item, f"{where}.{key}")
        return
    raise SchemaError(f"{where} is not a JSON value")


# PIN: confirmed-results-require-complete-evidence
def validate_v3(doc: dict) -> None:
    """Validate the declarative schema without trusting any supplied value."""
    if type(doc) is not dict:
        raise SchemaError(f"doc wrong type: {type(doc).__name__}")
    if type(doc.get("schema_version")) is not int or doc.get("schema_version") != 3:
        raise SchemaError("schema_version must be integer 3")
    status = doc.get("confirmation_status")
    expected = _NOT_CONFIRMED_KEYS_V3 if status == "not_confirmed" else _CONFIRMED_KEYS_V3
    _require_exact_keys(doc, expected, "doc")
    _require_nonempty_string(doc, "id", "doc")
    _require_nonempty_string(doc, "function_id", "doc")
    _require_exact_type(doc, "confirmation_status", str, "doc")
    if status not in ("confirmed", "not_confirmed"):
        raise SchemaError(f"confirmation_status invalid: {status}")
    _require_exact_type(doc, "attempts", int, "doc")
    if doc["attempts"] < 1:
        raise SchemaError("doc.attempts must be positive")
    _require_exact_type(doc, "notes", str, "doc")
    if status == "not_confirmed":
        return

    _require_exact_type(doc, "grade", str, "doc")
    if doc["grade"] not in ("L0", "L1"):
        raise SchemaError(f"grade invalid: {doc['grade']}")
    _require_exact_type(doc, "witness", dict, "doc")
    witness = doc["witness"]
    _require_exact_keys(witness, _WITNESS_KEYS_V3, "witness")
    _require_nonempty_string(witness, "probe", "witness")
    _require_exact_type(witness, "call_index", int, "witness")
    if witness["call_index"] < 0:
        raise SchemaError("witness.call_index must be non-negative")
    _require_exact_type(witness, "captured_input", dict, "witness")
    _validate_json_value(witness["captured_input"], "witness.captured_input")
    if "actual_output" not in witness:
        raise SchemaError("witness.actual_output missing")
    if type(witness["actual_output"]) not in (str, int, bool, dict, list):
        raise SchemaError("witness.actual_output wrong type")
    _validate_json_value(witness["actual_output"], "witness.actual_output")
    _require_nonempty_string(witness, "spec_violation_claim", "witness")

    _require_exact_type(doc, "phenomenon", dict, "doc")
    phenomenon = doc["phenomenon"]
    _require_exact_keys(phenomenon, _PHENOMENON_KEYS_V3, "phenomenon")
    _require_nonempty_string(phenomenon, "mode", "phenomenon")
    if phenomenon["mode"] not in _PHENOMENON_MODES:
        raise SchemaError(f"phenomenon.mode invalid: {phenomenon['mode']}")
    _require_nonempty_string(phenomenon, "standard", "phenomenon")
    if phenomenon["standard"] not in _C_STANDARDS:
        raise SchemaError(f"phenomenon.standard invalid: {phenomenon['standard']}")
    _require_exact_type(phenomenon, "extra_args", list, "phenomenon")
    if any(type(arg) is not str or not arg for arg in phenomenon["extra_args"]):
        raise SchemaError("phenomenon.extra_args must contain non-empty strings")
    _require_nonempty_string(phenomenon, "expected_kind", "phenomenon")
    if phenomenon["expected_kind"] not in _PHENOMENON_KINDS:
        raise SchemaError(
            f"phenomenon.expected_kind invalid: {phenomenon['expected_kind']}"
        )

    l1_patch = doc["l1_patch"]
    if doc["grade"] == "L1":
        if type(l1_patch) is not str or not l1_patch.strip():
            raise SchemaError("grade L1 requires l1_patch path")
    elif l1_patch is not None:
        raise SchemaError("grade L0 requires l1_patch null")


_WITNESS_REQUIRED = {
    "probe": str,
    "audit_log": str,
    "call_index": int,
    "captured_input": dict,
    "actual_output": (str, int, bool, dict, list),
    "spec_violation_claim": str,
    "postcondition_check": str,
}
_PHENOMENON_REQUIRED = {
    "kind": str,
    "ccc_invocation": str,
    "gcc_invocation": str,
    "ccc_rc": int,
    "gcc_rc": int,
}


def _require(d, key, typ, where):
    if key not in d:
        raise SchemaError(f"{where}.{key} missing")
    if not isinstance(d[key], typ):
        raise SchemaError(f"{where}.{key} wrong type: {type(d[key]).__name__}")


def validate_v2(doc: dict) -> None:
    for k in ("id", "function_id", "confirmation_status", "attempts"):
        if k not in doc:
            raise SchemaError(f"{k} missing")
    status = doc["confirmation_status"]
    if status not in ("confirmed", "not_confirmed"):
        raise SchemaError(f"confirmation_status invalid: {status}")
    if status == "not_confirmed":
        return
    if doc.get("grade") not in ("L0", "L1"):
        raise SchemaError(f"grade invalid: {doc.get('grade')}")
    _require(doc, "witness", dict, "doc")
    for k, t in _WITNESS_REQUIRED.items():
        _require(doc["witness"], k, t, "witness")
    _require(doc, "phenomenon", dict, "doc")
    for k, t in _PHENOMENON_REQUIRED.items():
        _require(doc["phenomenon"], k, t, "phenomenon")
    if doc["grade"] == "L1" and not doc.get("l1_patch"):
        raise SchemaError("grade L1 requires l1_patch path")

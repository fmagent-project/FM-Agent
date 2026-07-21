"""Deterministic validation-guard evaluator for taint sink facts.

Validation guards are not general sanitizers.  They only discharge a sink when
the guard is high-confidence, fail-closed, tied to the exact sink id, validates
the same expression the sink consumes, and endorses the sink's argument context
through both its declaration and this narrow allowlist.
"""

import re

from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Literal, TypeAlias


Coverage: TypeAlias = Literal["must", "default"] | None
JSONScalar: TypeAlias = str | int | float | bool | None
JSONValue: TypeAlias = JSONScalar | Mapping[str, "JSONValue"] | Sequence["JSONValue"]
JSONMapping: TypeAlias = Mapping[str, JSONValue]
JSONSequence: TypeAlias = Sequence[JSONValue]


# Intentionally narrow: unknown guard kinds and unsupported contexts do not make
# a flow safe.  In particular, content scanning only says anything useful about a
# serialized blob; it does not validate SQL, shell, paths, URLs, HTML, or code.
GUARD_ENDORSES: Mapping[str, frozenset[str]] = {
    "schema_validation": frozenset({"serialized_blob"}),
    "deserialization_allowlist": frozenset({"serialized_blob"}),
    "content_scan": frozenset({"serialized_blob"}),
}

VALID_COVERAGE = frozenset({"must", "default"})


def source_rel_from_extracted(rel: str) -> str:
    """Map ``path/file-py/function.py`` back to source path ``path/file.py``."""
    path = Path(rel)
    if len(path.parts) < 2:
        return rel
    encoded = path.parent.name
    extension = path.suffix.lstrip(".")
    suffix = "-" + extension
    if not extension or not encoded.endswith(suffix):
        return rel
    return (path.parent.parent / (encoded[:-len(suffix)] + "." + extension)).as_posix()


def validation_guard_coverage(
    facts: JSONMapping,
    sink: JSONMapping,
) -> Coverage:
    """Return the strongest validation coverage for ``sink``.

    ``"must"`` means the guard is unavoidable for this sink.  ``"default"`` is
    caller-dependent: the omitted/default call path is guarded, but a caller may
    explicitly use the guard's bypass parameter, so the caller must decide
    whether the sink is protected in that invocation.  Malformed, unknown,
    conditional, fail-open, or low-confidence guards are ignored fail-closed.
    """
    internal = sink.get("_validation_guard_coverage")
    if internal in VALID_COVERAGE:
        return internal if isinstance(internal, str) else None

    best: Coverage = None
    for guard in _accepted_guards(facts, sink):
        coverage = _guard_coverage(guard)
        if coverage == "must":
            return "must"
        if coverage == "default":
            best = "default"
    return best


def validation_guard_coverage_for_call(
    facts: JSONMapping,
    sink: JSONMapping,
    args: Sequence[JSONMapping],
) -> Coverage:
    best: Coverage = None
    for guard in _accepted_guards(facts, sink):
        coverage = _guard_coverage(guard)
        if coverage != "default":
            return coverage
        resolved = _default_coverage_for_call(guard, args)
        if resolved == "must":
            return "must"
        if resolved == "default":
            best = "default"
    return best


def call_args_from_bindings(
    arg_bindings: Mapping[str, str] | None,
) -> list[JSONMapping]:
    args = []
    for formal, actual_expr in (arg_bindings or {}).items():
        param_name = formal[len("param:"):] if formal.startswith("param:") else formal
        expr = actual_expr
        if isinstance(expr, str):
            keyword = re.match(rf"^\s*{re.escape(param_name)}\s*=\s*(.+)$", expr)
            if keyword:
                expr = keyword.group(1)
        args.append({"param_name": param_name, "expr": expr})
    return args


def merge_call_args_with_bindings(
    args: Sequence[JSONMapping],
    arg_bindings: Mapping[str, str] | None,
) -> list[JSONMapping]:
    merged = list(args)
    present = {arg.get("param_name") for arg in merged}
    for arg in call_args_from_bindings(arg_bindings):
        if arg.get("param_name") not in present:
            merged.append(arg)
    return merged


def _accepted_guards(
    facts: JSONMapping,
    sink: JSONMapping,
) -> Sequence[JSONMapping]:
    sink_id = _string_field(sink, "id")
    arg_expr = _string_field(sink, "arg_expr")
    arg_context = _string_field(sink, "arg_context")
    if sink_id is None or arg_expr is None or arg_context is None:
        return ()
    return tuple(
        guard for guard in _guard_records(facts)
        if _accepted_guard_coverage(guard, sink_id, arg_expr, arg_context) is not None
    )


def _accepted_guard_coverage(
    guard: JSONMapping,
    sink_id: str,
    arg_expr: str,
    arg_context: str,
) -> Coverage:
    if guard.get("confidence") != "high":
        return None
    if guard.get("failure_mode") != "closed":
        return None
    coverage = guard.get("coverage")
    if coverage not in VALID_COVERAGE:
        return None
    if coverage == "default" and not _is_non_empty_string(guard.get("bypass_param")):
        return None
    if guard.get("input_expr") != arg_expr:
        return None
    if not _sequence_contains_str(guard.get("protects_sink_ids"), sink_id):
        return None

    kind = guard.get("guard_kind")
    if not isinstance(kind, str):
        return None
    allowed = GUARD_ENDORSES.get(kind)
    if allowed is None or arg_context not in allowed:
        return None
    if not _sequence_contains_str(guard.get("endorses"), arg_context):
        return None
    return coverage if isinstance(coverage, str) else None


def _guard_coverage(guard: JSONMapping) -> Coverage:
    coverage = guard.get("coverage")
    return coverage if coverage in VALID_COVERAGE and isinstance(coverage, str) else None


def _default_coverage_for_call(
    guard: JSONMapping,
    args: Sequence[JSONMapping],
) -> Coverage:
    bypass_param = _string_field(guard, "bypass_param")
    if bypass_param is None:
        return None
    arg = _arg_for_param(args, bypass_param)
    if arg is None:
        return "must"
    expr = arg.get("expr")
    if _is_literal_true(expr):
        return "must"
    if _is_literal_false(expr):
        return None
    return "default"


def _arg_for_param(
    args: Sequence[JSONMapping],
    param_name: str,
) -> JSONMapping | None:
    for arg in args:
        if isinstance(arg, Mapping) and arg.get("param_name") == param_name:
            return arg
    return None


def _is_literal_true(value: JSONValue) -> bool:
    if isinstance(value, str):
        return value.strip().lower() in {"true", "1"}
    return value is True or value == 1


def _is_literal_false(value: JSONValue) -> bool:
    if isinstance(value, str):
        return value.strip().lower() in {"false", "0"}
    return value is False or value == 0


def _guard_records(facts: JSONMapping) -> Sequence[JSONMapping]:
    guards = facts.get("validation_guards")
    if not isinstance(guards, Sequence) or isinstance(guards, (str, bytes)):
        return ()
    return tuple(guard for guard in guards if isinstance(guard, Mapping))


def _string_field(record: JSONMapping, key: str) -> str | None:
    value = record.get(key)
    return value if isinstance(value, str) else None


def _is_non_empty_string(value: JSONValue) -> bool:
    return isinstance(value, str) and bool(value)


def _sequence_contains_str(value: JSONValue, item: str) -> bool:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes)):
        return False
    return any(entry == item for entry in value if isinstance(entry, str))

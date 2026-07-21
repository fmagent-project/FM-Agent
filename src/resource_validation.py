"""Deterministic validation of resource facts and bounds.

The LLM may identify a candidate bound, but only this module decides whether it
can discharge a resource finding. New abstractions state placement, enforcement,
limit provenance, and exact protected operation ids. Legacy bounds used
``dominates=True`` to mean an enforcing pre-operation check and remain valid.
"""

from __future__ import annotations

import ast
import copy
import re
import textwrap
from collections.abc import Mapping, Sequence
from pathlib import Path


BOUND_CAPS = {
    "size_check": frozenset({"request_size", "input_length", "decompressed_size"}),
    "count_limit": frozenset({"element_count", "numeric_param"}),
    "depth_limit": frozenset({"recursion_depth"}),
    "recursion_limit": frozenset({"recursion_depth"}),
    "chunked_read_cap": frozenset({"request_size"}),
    "decompress_limit": frozenset({"decompressed_size"}),
    "timeout": frozenset({
        "input_length", "element_count", "recursion_depth", "numeric_param",
        "request_frequency",
    }),
    "input_length_cap": frozenset({"input_length"}),
    "arithmetic_limit": frozenset({"logical_size"}),
    "rate_limit": frozenset({"request_frequency"}),
}

TRUSTED_LIMIT_ORIGINS = frozenset({
    "constant", "trusted_config", "trusted_system", "type_limit",
})
HARD_ENFORCEMENTS = frozenset({"reject", "cap", "truncate"})
KNOWN_BOUND_KINDS = frozenset(BOUND_CAPS)
KNOWN_OPERATION_KINDS = frozenset({
    "allocation", "unbounded_read", "decompression", "regex_match",
    "recursion", "loop", "collection_build", "expensive_call",
    "regex_compile", "logical_allocation",
})
RESOURCE_VALIDATION_VERSION = 16


def source_rel_from_extracted(rel: str) -> str:
    """Map ``path/file-py/function.py`` back to ``path/file.py``."""
    path = Path(rel)
    if len(path.parts) < 2:
        return rel
    encoded = path.parent.name
    extension = path.suffix.lstrip(".")
    suffix = "-" + extension
    if not extension or not encoded.endswith(suffix):
        return rel
    return (path.parent.parent / (encoded[:-len(suffix)] + "." + extension)).as_posix()


def validate_and_enrich(facts, unit):
    """Replace model guesses that source syntax can settle deterministically."""
    if not isinstance(facts, Mapping):
        return facts
    if facts.get("_resource_validated") == RESOURCE_VALIDATION_VERSION:
        return copy.deepcopy(facts)

    out = {
        key: copy.deepcopy(value)
        for key, value in facts.items()
        if not str(key).startswith("_")
    }
    source = textwrap.dedent(getattr(unit, "source", "") or "")
    tree = _parse(source)
    bounds = [
        copy.deepcopy(bound) for bound in (out.get("bounds") or [])
        if isinstance(bound, Mapping) and bound.get("bound_kind") in KNOWN_BOUND_KINDS
    ]
    valid_bound_ids = {
        bound.get("id") for bound in bounds if isinstance(bound.get("id"), str)
    }

    operations = []
    for raw in out.get("costly_ops") or []:
        if not isinstance(raw, Mapping):
            operations.append(copy.deepcopy(raw))
            continue
        op = {key: copy.deepcopy(value) for key, value in raw.items()
              if not str(key).startswith("_")}
        _remove_unknown_bound_refs(op, valid_bound_ids)
        op = _normalize_operation(
            op, source, getattr(unit.id, "language", ""), tree
        )
        if op is not None:
            operations.append(op)

    out["bounds"] = bounds
    out["costly_ops"] = operations
    _normalize_call_sites(out)
    _normalize_magnitude_sources(out, tree)
    _filter_unsupported_magnitude_flows(out, tree)
    _derive_source_operations(out, source, tree)
    _bind_concrete_magnitudes(out)
    _add_source_bounds(out, source, tree)
    out["_resource_cached"] = _has_cache_decorator(tree)
    out["_resource_exact_extents"] = _has_exact_extent_allocation(tree)
    out["_resource_validated"] = RESOURCE_VALIDATION_VERSION
    return out


def _parse(source):
    try:
        return ast.parse(source)
    except (SyntaxError, TypeError, ValueError):
        return None


def _remove_unknown_bound_refs(op, valid_ids):
    for magnitude in op.get("magnitudes") or []:
        if not isinstance(magnitude, dict):
            continue
        magnitude["bounds"] = [
            entry for entry in (magnitude.get("bounds") or [])
            if not isinstance(entry, str) or entry in valid_ids
        ]


def _normalize_operation(op, source, language, tree):
    kind = op.get("op_kind")
    call = str(op.get("call_expr") or "")
    callee = str(op.get("callee") or "")
    lowered = (call + " " + callee).lower()

    if call and not _operation_appears_in_source(call, source, language):
        return None

    if _operation_has_precision_losing_extent(call):
        op["op_kind"] = "logical_allocation"
        op["callee"] = "arithmetic"
        return op
    if _uses_exact_rounding(tree, call):
        return None

    extent_operation = bool(re.search(
        r"\b(?:allocate|reserve)[a-z0-9_]*\b", lowered
    ))
    if extent_operation and _operation_has_exact_integral_extent(tree, op):
        return None
    if _is_compile_expression(lowered):
        op["op_kind"] = "regex_compile"
        return op
    if kind == "regex_compile":
        return None
    if kind == "regex_match":
        if language.lower() == "rust" or _source_has_compile(source):
            return None
        if re.search(r"(?:^|\.)(?:match|search|fullmatch)$", callee, re.I):
            op["op_kind"] = "expensive_call"
            return op
        return None
    if kind == "logical_allocation":
        if "warnings.warn" in source and not re.search(
            r"\+=|\bmath\.ceil\s*\(|\b(?:allocate|reserve)\w*\s*\(", source
        ):
            return None
        if _has_logical_arithmetic(source, call):
            return op
        return None
    if kind == "allocation" and not _is_explicit_allocation(lowered):
        return None
    if kind == "collection_build" and not re.search(
        r"\b(?:list|dict|set|tuple|range)\s*\(|\[[^]]*\bfor\b", call
    ):
        return None
    if kind == "loop" and not _source_has_compile(source):
        return None
    if kind == "unbounded_read" and not re.search(r"\.(?:read|recv)\s*\(\s*\)", call):
        return None
    if kind == "expensive_call" and re.search(
        r"(?:^|\.)(?:get|find|fetch|lookup|load)_[a-z0-9_]+$", callee, re.I
    ):
        return None
    if kind == "expensive_call" and re.search(
        r"(?:^|\.|::)(?:from_str|int|float|bool|str|split|rsplit)$",
        callee, re.I,
    ):
        return None
    if kind == "expensive_call" and _is_non_recipient_delivery_operation(op):
        return None
    return op if kind in KNOWN_OPERATION_KINDS else None


def _operation_appears_in_source(expression, source, language):
    compact_expression = re.sub(r"\s+", "", expression)
    if compact_expression and compact_expression in re.sub(r"\s+", "", source):
        return True
    if language.lower() != "python":
        return False
    try:
        candidate = ast.parse(expression.strip(), mode="eval").body
    except (SyntaxError, TypeError, ValueError):
        return False
    if not isinstance(candidate, ast.Call):
        return False
    tree = _parse(source)
    signature = ast.dump(candidate, include_attributes=False)
    return any(
        ast.dump(node, include_attributes=False) == signature
        for node in ast.walk(tree) if isinstance(node, ast.Call)
    ) if tree is not None else False


def _is_compile_expression(value):
    return bool(re.search(
        r"(?:^|\W)(?:re\.|regex\.)?compile\s*\(|"
        r"\b(?:glob|pattern)[a-z0-9_]*_to_regex\s*\(", value, re.I
    ))


def _source_has_compile(source):
    return _is_compile_expression(source)


def _is_explicit_allocation(value):
    return bool(re.search(
        r"\b(?:bytes|bytearray|list|dict|set|tuple|range)\s*\(|"
        r"\.join\s*\(|\[[^]]*\]\s*\*|\*\s*['\"]", value
    ))


def _uses_exact_rounding(tree, operation):
    """Prove operation-linked integer round-up syntax or a local helper body."""
    if tree is None:
        return False
    functions = {
        node.name: node
        for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    }
    assignments = _assignment_expressions(tree)
    roots = _operation_expressions(operation)
    seen_names = set()

    def proven(expression):
        if _round_up_parts(expression) is not None:
            return True
        if isinstance(expression, ast.Call):
            name = _call_name(expression.func)
            function = functions.get(name)
            if function is not None and _function_is_exact_round_up(function):
                return True
        for node in ast.walk(expression):
            if not isinstance(node, ast.Name) or node.id in seen_names:
                continue
            seen_names.add(node.id)
            assigned = assignments.get(node.id)
            if assigned is not None and proven(assigned):
                return True
        return False

    return any(proven(root) for root in roots)


def _operation_has_precision_losing_extent(operation):
    return any(
        _is_precision_losing_extent(node)
        for root in _operation_expressions(operation)
        for node in ast.walk(root)
    )


def _has_exact_extent_allocation(tree):
    """Return whether every allocation-like call consumes integral expressions."""
    if tree is None:
        return False
    calls = [
        node for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and re.search(
            r"(?:^|\.)(?:allocate|reserve)[a-z0-9_]*$",
            _call_name(node.func),
            re.I,
        )
    ]
    assignments = _assignment_expressions(tree)
    return bool(calls) and all(
        bool(_extent_arguments(call, assignments))
        and all(
            _is_exact_integral_extent(argument, assignments, set())
            for argument in _extent_arguments(call, assignments)
        )
        for call in calls
    )


def _operation_has_exact_integral_extent(tree, operation):
    """Trace one reported extent through source assignments without guessing types."""
    if tree is None:
        return False
    assignments = _assignment_expressions(tree)
    position = operation.get("arg_position")
    candidates = []
    for expression in _operation_expressions(operation.get("call_expr")):
        if isinstance(expression, ast.Call):
            if isinstance(position, int) and 0 <= position < len(expression.args):
                argument = expression.args[position]
                if not _is_source_proven_string(argument, assignments, set()):
                    candidates.append(argument)
            else:
                candidates.extend(_extent_arguments(expression, assignments))
        elif isinstance(expression, ast.AugAssign):
            candidates.append(expression.value)
    reported = _parse_expression(operation.get("arg_expr"))
    if reported is not None:
        candidates.append(reported)
    return bool(candidates) and all(
        _is_exact_integral_extent(candidate, assignments, set())
        for candidate in candidates
    )


def _extent_arguments(call, assignments):
    return [
        argument for argument in call.args
        if not _is_source_proven_string(argument, assignments, set())
    ]


def _is_source_proven_string(expression, assignments, seen):
    if isinstance(expression, ast.Name):
        if expression.id in seen:
            return False
        assigned = assignments.get(expression.id)
        return assigned is not None and _is_source_proven_string(
            assigned, assignments, seen | {expression.id}
        )
    if isinstance(expression, ast.Constant):
        return isinstance(expression.value, (str, bytes))
    if isinstance(expression, ast.JoinedStr):
        return True
    if isinstance(expression, ast.BinOp) and isinstance(expression.op, ast.Mod):
        return _is_source_proven_string(expression.left, assignments, seen)
    return False


def _assignment_expressions(tree):
    assignments = {}
    for node in ast.walk(tree):
        if isinstance(node, (ast.Assign, ast.AnnAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            value = node.value
            for target in targets:
                if isinstance(target, ast.Name) and value is not None:
                    assignments[target.id] = value
    return assignments


def _operation_expressions(expression):
    if not isinstance(expression, str) or not expression.strip():
        return []
    parsed = _parse_expression(expression)
    if parsed is not None:
        return [parsed]
    try:
        module = ast.parse(expression.strip())
    except (SyntaxError, TypeError, ValueError):
        return []
    return [
        node.value if isinstance(node, ast.Expr) else node
        for node in module.body
        if isinstance(node, (ast.Expr, ast.Assign, ast.AnnAssign, ast.AugAssign))
    ]


def _is_exact_integral_extent(expression, assignments, seen):
    if isinstance(expression, ast.Name):
        if expression.id in seen:
            return False
        assigned = assignments.get(expression.id)
        if assigned is None:
            return True
        return _is_exact_integral_extent(assigned, assignments, seen | {expression.id})
    if isinstance(expression, (ast.Attribute, ast.Subscript)):
        return True
    if isinstance(expression, ast.Constant):
        return isinstance(expression.value, int) and not isinstance(expression.value, bool)
    if isinstance(expression, ast.UnaryOp) and isinstance(
        expression.op, (ast.UAdd, ast.USub, ast.Invert)
    ):
        return _is_exact_integral_extent(expression.operand, assignments, seen)
    if isinstance(expression, ast.BinOp) and isinstance(
        expression.op,
        (
            ast.Add, ast.Sub, ast.Mult, ast.FloorDiv, ast.Mod,
            ast.LShift, ast.RShift, ast.BitAnd, ast.BitOr, ast.BitXor,
        ),
    ):
        return (
            _is_exact_integral_extent(expression.left, assignments, seen)
            and _is_exact_integral_extent(expression.right, assignments, seen)
        )
    return False


def _function_is_exact_round_up(function):
    parameters = {
        argument.arg
        for argument in [*function.args.posonlyargs, *function.args.args]
    }
    returns = [node.value for node in ast.walk(function) if isinstance(node, ast.Return)]
    if not parameters or not returns or any(value is None for value in returns):
        return False
    bases = [_round_up_parts(value) for value in returns]
    return all(
        base is not None
        and any(
            isinstance(node, ast.Name) and node.id in parameters
            for node in ast.walk(base)
        )
        for base in bases
    )


def _round_up_parts(expression):
    """Return the base of ``(base + width - 1) // width [* width]``."""
    quotient = expression
    scale = None
    if isinstance(expression, ast.BinOp) and isinstance(expression.op, ast.Mult):
        if (
            isinstance(expression.left, ast.BinOp)
            and isinstance(expression.left.op, ast.FloorDiv)
        ):
            quotient, scale = expression.left, expression.right
        elif (
            isinstance(expression.right, ast.BinOp)
            and isinstance(expression.right.op, ast.FloorDiv)
        ):
            quotient, scale = expression.right, expression.left
    if not isinstance(quotient, ast.BinOp) or not isinstance(quotient.op, ast.FloorDiv):
        return None
    divisor = quotient.right
    if not (
        isinstance(divisor, ast.Constant)
        and isinstance(divisor.value, int)
        and not isinstance(divisor.value, bool)
        and divisor.value > 0
    ):
        return None
    if scale is not None and not _same_expression(scale, divisor):
        return None
    return _rounded_base(quotient.left, divisor.value)


def _rounded_base(numerator, divisor):
    adjustment = divisor - 1
    if isinstance(numerator, ast.BinOp) and isinstance(numerator.op, ast.Add):
        if _integer_constant(numerator.right) == adjustment:
            return numerator.left
        if _integer_constant(numerator.left) == adjustment:
            return numerator.right
    if (
        isinstance(numerator, ast.BinOp)
        and isinstance(numerator.op, ast.Sub)
        and _integer_constant(numerator.right) == 1
        and isinstance(numerator.left, ast.BinOp)
        and isinstance(numerator.left.op, ast.Add)
    ):
        if _integer_constant(numerator.left.right) == divisor:
            return numerator.left.left
        if _integer_constant(numerator.left.left) == divisor:
            return numerator.left.right
    return None


def _integer_constant(expression):
    if (
        isinstance(expression, ast.Constant)
        and isinstance(expression.value, int)
        and not isinstance(expression.value, bool)
    ):
        return expression.value
    return None


def _same_expression(left, right):
    return ast.dump(left, include_attributes=False) == ast.dump(
        right, include_attributes=False
    )


def _has_logical_arithmetic(source, call):
    text = source + "\n" + call
    return bool(
        re.search(r"\bmath\.ceil\s*\([^\n]*/", text)
        or re.search(r"(?:\+=|\+\s*[a-zA-Z_][\w.]*)", text)
        or re.search(r"\b(?:allocate|reserve)[a-zA-Z_]*\s*\(", text, re.I)
    )


def _bind_concrete_magnitudes(facts):
    sources = [
        source for source in (facts.get("magnitude_sources") or [])
        if isinstance(source, Mapping) and isinstance(source.get("id"), str)
    ]
    params = {str(param) for param in (facts.get("params") or [])}
    for op in facts.get("costly_ops") or []:
        if not isinstance(op, Mapping):
            continue
        for magnitude in op.get("magnitudes") or []:
            if not isinstance(magnitude, dict):
                continue
            ref = magnitude.get("source")
            if isinstance(ref, str) and ref.startswith("mag:"):
                declared = next((item for item in sources if item["id"] == ref[4:]), None)
                expression = str(declared.get("expr") or "") if declared else ""
                parameter = next((param for param in params if re.search(
                    rf"\b{re.escape(param)}\b", expression
                )), None)
                if parameter is not None:
                    magnitude["source"] = "param:" + parameter
                    ref = magnitude["source"]
            if isinstance(ref, str) and ref.startswith("param:"):
                param = ref[len("param:"):]
                matching = [
                    source for source in sources
                    if _expression_references_name(source.get("expr"), param)
                ]
                kinds = {source.get("magnitude_kind") for source in matching}
                kinds.discard(None)
                if len(kinds) == 1:
                    magnitude["magnitude_kind"] = next(iter(kinds))
            ref = magnitude.get("source")
            if isinstance(ref, str) and ref.startswith("mag:"):
                source = next((item for item in sources if item["id"] == ref[4:]), None)
                if source is not None:
                    magnitude["magnitude_kind"] = source.get("magnitude_kind")


def _derive_source_operations(facts, source, tree):
    if tree is None:
        return
    existing = "\n".join(
        str(op.get("call_expr") or "") for op in (facts.get("costly_ops") or [])
        if isinstance(op, Mapping)
    )
    assignments = {
        target.id: ast.unparse(node.value)
        for node in ast.walk(tree) if isinstance(node, ast.Assign)
        for target in node.targets if isinstance(target, ast.Name)
    }
    for node in ast.walk(tree):
        if isinstance(node, ast.AugAssign) and isinstance(node.op, ast.Add):
            value = ast.unparse(node.value)
            resolved = assignments.get(value, value)
            expression = ast.unparse(node)
            if "math.ceil(" in resolved and "/" in resolved:
                _append_source_op(facts, resolved, expression)
        elif isinstance(node, ast.Assign) and len(node.targets) == 1:
            target = node.targets[0]
            value = ast.unparse(node.value)
            if isinstance(target, ast.Name) and _is_precision_losing_extent(node.value):
                _append_source_op(facts, value, ast.unparse(node))
                continue
            if not isinstance(target, ast.Attribute) or "warnings.warn" in source:
                continue
            magnitudes = [item for item in (facts.get("magnitude_sources") or [])
                          if isinstance(item, Mapping)]
            extent_name = target.attr.lower()
            matching = [
                item for item in magnitudes
                if str(item.get("expr") or "").strip() in {value, f"len({value})"}
            ]
            if any(word in extent_name for word in ("length", "size", "count", "slot", "offset")) and matching:
                for magnitude in matching:
                    magnitude["magnitude_kind"] = "logical_size"
                expression = ast.unparse(node)
                if expression not in existing:
                    _append_source_op(facts, value, expression)
    _derive_request_recipient_sources(facts, tree)
    _derive_regex_compile_operations(facts, tree)
    _derive_email_recipient_operations(facts, tree)


def _derive_request_recipient_sources(facts, tree):
    assignments = _assignment_expressions(tree)
    parameters = {str(parameter) for parameter in (facts.get("params") or [])}
    existing = [
        source for source in (facts.get("magnitude_sources") or [])
        if isinstance(source, Mapping)
    ]
    aliases = _simple_aliases(tree)
    for call in ast.walk(tree):
        if not isinstance(call, ast.Call) or not _is_delivery_call(_call_name(call.func)):
            continue
        for argument in [*call.args, *(keyword.value for keyword in call.keywords)]:
            expression = ast.unparse(argument)
            if not _is_recipient_argument(expression, None):
                continue
            if _source_for_expression(existing, expression, aliases) is not None:
                continue
            extracted = _request_extracted_expression(
                argument, assignments, parameters, set()
            )
            if extracted is None:
                continue
            source = {
                "id": f"SRC_REQUEST_MAG_{len(existing) + 1}",
                "magnitude_kind": "input_length", "expr": ast.unparse(extracted),
                "introduced_by": "source request extraction", "confidence": "high",
            }
            facts.setdefault("magnitude_sources", []).append(source)
            existing.append(source)


def _request_extracted_expression(expression, assignments, parameters, seen):
    if isinstance(expression, ast.Name):
        if expression.id in seen:
            return None
        assigned = assignments.get(expression.id)
        if assigned is None:
            return None
        extracted = _request_extracted_expression(
            assigned, assignments, parameters, seen | {expression.id}
        )
        return assigned if extracted is not None else None
    if not isinstance(expression, ast.Subscript) or not isinstance(expression.value, ast.Name):
        return None
    key = expression.slice
    if not isinstance(key, ast.Constant) or not isinstance(key.value, str):
        return None
    extractor = assignments.get(expression.value.id)
    if not isinstance(extractor, ast.Call):
        return None
    tokens = _semantic_tokens(_call_name(extractor.func))
    if not tokens.intersection({"decode", "extract", "get", "parse", "read"}):
        return None
    request_parameters = {
        parameter for parameter in parameters
        if _semantic_tokens(parameter).intersection({"body", "input", "payload", "request"})
    }
    if not any(
        isinstance(node, ast.Name) and node.id in request_parameters
        for argument in [*extractor.args, *(item.value for item in extractor.keywords)]
        for node in ast.walk(argument)
    ):
        return None
    declared = {
        item.value
        for argument in [*extractor.args, *(entry.value for entry in extractor.keywords)]
        for item in ast.walk(argument)
        if isinstance(item, ast.Constant) and isinstance(item.value, str)
    }
    return expression if key.value in declared else None


def _derive_regex_compile_operations(facts, tree):
    aliases = _simple_aliases(tree)
    sources = [
        source for source in (facts.get("magnitude_sources") or [])
        if isinstance(source, Mapping) and isinstance(source.get("id"), str)
    ]
    parameters = {str(parameter) for parameter in (facts.get("params") or [])}
    for call in ast.walk(tree):
        if not isinstance(call, ast.Call) or not call.args:
            continue
        call_expr = ast.unparse(call)
        if not _is_compile_expression(call_expr):
            continue
        argument_expr = ast.unparse(call.args[0])
        parameter = aliases.get(argument_expr, argument_expr)
        source = _source_for_expression(sources, argument_expr, aliases)
        if parameter in parameters:
            flow = {
                "source": "param:" + parameter, "bounds": [],
                "magnitude_kind": "input_length",
            }
        elif source is not None:
            flow = {
                "source": "mag:" + source["id"], "bounds": [],
                "magnitude_kind": source.get("magnitude_kind"),
            }
        else:
            continue
        existing = next((
            operation for operation in (facts.get("costly_ops") or [])
            if isinstance(operation, dict)
            and operation.get("op_kind") == "regex_compile"
            and operation.get("call_expr") == call_expr
        ), None)
        if existing is not None:
            references = {
                magnitude.get("source")
                for magnitude in (existing.get("magnitudes") or [])
                if isinstance(magnitude, Mapping)
            }
            if flow["source"] not in references:
                existing.setdefault("magnitudes", []).append(flow)
            continue
        facts.setdefault("costly_ops", []).append({
            "id": f"SRC_OP_{len(facts.get('costly_ops') or []) + 1}",
            "op_kind": "regex_compile", "callee": _call_name(call.func),
            "call_expr": call_expr, "arg_position": 0,
            "arg_expr": argument_expr, "magnitudes": [flow],
        })


def _derive_email_recipient_operations(facts, tree):
    aliases = _simple_aliases(tree)
    sources = [
        source for source in (facts.get("magnitude_sources") or [])
        if isinstance(source, Mapping) and isinstance(source.get("id"), str)
    ]
    sources_by_id = {source["id"]: source for source in sources}
    candidates = []
    for call_site in facts.get("call_sites") or []:
        if not isinstance(call_site, Mapping):
            continue
        candidates.append((call_site.get("call_expr"), call_site.get("args") or []))
    candidates.extend(
        (ast.unparse(call), [])
        for call in ast.walk(tree)
        if isinstance(call, ast.Call) and _is_delivery_call(_call_name(call.func))
    )
    for operation in list(facts.get("costly_ops") or []):
        if isinstance(operation, Mapping) and operation.get("op_kind") == "expensive_call":
            candidates.append((operation.get("call_expr"), []))

    seen = set()
    for call_expr, argument_facts in candidates:
        call = _source_call(tree, call_expr)
        if call is None or not _is_delivery_call(_call_name(call.func)):
            continue
        indexed_arguments = {
            argument.get("position"): argument
            for argument in argument_facts
            if isinstance(argument, Mapping) and isinstance(argument.get("position"), int)
        }
        call_arguments = [
            (position, argument, None)
            for position, argument in enumerate(call.args)
        ] + [
            (len(call.args) + offset, keyword.value, keyword.arg)
            for offset, keyword in enumerate(call.keywords)
        ]
        for position, argument, keyword_name in call_arguments:
            argument_expr = ast.unparse(argument)
            argument_fact = indexed_arguments.get(position, {})
            parameter_name = argument_fact.get("param_name") or keyword_name
            if not _is_recipient_argument(argument_expr, parameter_name):
                continue
            source, bounds = _recipient_source(
                sources, sources_by_id, argument_expr, argument_fact, aliases
            )
            if source is None:
                continue
            key = (ast.dump(call, include_attributes=False), position, source["id"])
            if key in seen:
                continue
            seen.add(key)
            _add_recipient_operation(
                facts, call, str(call_expr), position, argument_expr, source, bounds
            )


def _source_call(tree, expression):
    parsed = _parse_expression(expression)
    if not isinstance(parsed, ast.Call):
        return None
    signature = ast.dump(parsed, include_attributes=False)
    return next((
        node for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and ast.dump(node, include_attributes=False) == signature
    ), None)


def _semantic_tokens(value):
    split_camel = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", str(value or ""))
    return {
        token.lower() for token in re.findall(r"[A-Za-z]+", split_camel)
    }


def _is_delivery_call(name):
    tokens = _semantic_tokens(name)
    if tokens.intersection({"send", "deliver", "dispatch", "notify"}):
        return True
    return bool(
        tokens.intersection({"email", "mail"})
        and not tokens.intersection({
            "check", "match", "normalize", "parse", "redact", "validate", "verify",
        })
    )


def _is_non_recipient_delivery_operation(operation):
    call = _parse_expression(operation.get("call_expr"))
    return bool(
        isinstance(call, ast.Call)
        and _is_delivery_call(_call_name(call.func))
        and not _is_recipient_argument(operation.get("arg_expr"), None)
    )


def _is_recipient_argument(expression, parameter):
    tokens = _semantic_tokens(expression) | _semantic_tokens(parameter)
    return bool(tokens.intersection({
        "address", "destination", "email", "mailbox", "recipient", "recipients", "to",
    }))


def _recipient_source(sources, indexed, expression, argument, aliases):
    for magnitude in argument.get("magnitudes") or []:
        if not isinstance(magnitude, Mapping):
            continue
        reference = magnitude.get("source")
        source = indexed.get(reference[4:]) if (
            isinstance(reference, str) and reference.startswith("mag:")
        ) else None
        if source is not None and source.get("magnitude_kind") == "input_length":
            return source, list(magnitude.get("bounds") or [])
    source = _source_for_expression(sources, expression, aliases)
    if source is not None and source.get("magnitude_kind") == "input_length":
        return source, []
    return None, []


def _add_recipient_operation(
    facts, call, call_expr, position, argument_expr, source, bounds,
):
    existing = next((
        item for item in (facts.get("costly_ops") or [])
        if isinstance(item, dict)
        and item.get("op_kind") == "expensive_call"
        and item.get("call_expr") == call_expr
        and str(item.get("arg_expr") or "").strip() == argument_expr
    ), None)
    flow = {
        "source": "mag:" + source["id"], "bounds": bounds,
        "magnitude_kind": source.get("magnitude_kind"),
    }
    if existing is not None:
        if not existing.get("magnitudes"):
            existing["magnitudes"] = [flow]
        return
    facts.setdefault("costly_ops", []).append({
        "id": f"SRC_OP_{len(facts.get('costly_ops') or []) + 1}",
        "op_kind": "expensive_call", "callee": _call_name(call.func),
        "call_expr": call_expr, "arg_position": position,
        "arg_expr": argument_expr, "magnitudes": [flow],
    })


def _source_for_expression(sources, expression, aliases):
    compact = re.sub(r"\s+", "", expression)
    alias = re.sub(r"\s+", "", aliases.get(expression, ""))
    candidates = {compact, alias, f"len({compact})", f"len({alias})"}
    candidates.discard("")
    candidates.discard("len()")
    exact = [
        source for source in sources
        if re.sub(r"\s+", "", str(source.get("expr") or "")) in candidates
    ]
    return exact[0] if exact else None


def _append_source_op(facts, magnitude_expr, operation_expr):
    sources = [item for item in (facts.get("magnitude_sources") or [])
               if isinstance(item, Mapping)]
    source = next((item for item in sources
                   if item.get("magnitude_kind") == "logical_size"
                   and str(item.get("expr") or "") in magnitude_expr), None)
    if source is None:
        source = {
            "id": f"SRC_MAG_{len(sources) + 1}", "magnitude_kind": "logical_size",
            "expr": magnitude_expr, "introduced_by": "source arithmetic",
            "confidence": "high",
        }
        facts.setdefault("magnitude_sources", []).append(source)
    existing = next((
        op for op in (facts.get("costly_ops") or [])
        if isinstance(op, dict) and str(op.get("call_expr") or "") == operation_expr
    ), None)
    if existing is not None:
        if not existing.get("magnitudes"):
            existing["magnitudes"] = [{"source": "mag:" + source["id"], "bounds": []}]
        return
    facts.setdefault("costly_ops", []).append({
        "id": f"SRC_OP_{len(facts.get('costly_ops') or []) + 1}",
        "op_kind": "logical_allocation", "callee": "arithmetic",
        "call_expr": operation_expr, "arg_position": -1,
        "arg_expr": magnitude_expr,
        "magnitudes": [{"source": "mag:" + source["id"], "bounds": []}],
    })


def _normalize_call_sites(facts):
    for call in facts.get("call_sites") or []:
        if not isinstance(call, Mapping):
            continue
        for arg in call.get("args") or []:
            if not isinstance(arg, dict):
                continue
            expression = str(arg.get("expr") or "").strip()
            try:
                literal = ast.literal_eval(expression)
            except (SyntaxError, ValueError):
                continue
            if isinstance(literal, (str, bytes, int, float, bool, type(None))):
                arg["magnitudes"] = []


def _normalize_magnitude_sources(facts, tree):
    if tree is None:
        return
    normalized = []
    for source in facts.get("magnitude_sources") or []:
        if not isinstance(source, Mapping):
            normalized.append(source)
            continue
        expression = _grounded_magnitude_expression(source, tree)
        if expression is None:
            continue
        record = dict(source)
        record["expr"] = ast.unparse(expression)
        if (
            record.get("magnitude_kind") == "input_length"
            and re.search(r"\bnumeric\b", str(record.get("introduced_by") or ""), re.I)
        ):
            record["magnitude_kind"] = "numeric_param"
        normalized.append(record)
    facts["magnitude_sources"] = normalized


def _grounded_magnitude_expression(source, tree):
    raw = str(source.get("expr") or "").strip()
    kind = source.get("magnitude_kind")
    direct = _parse_expression(raw)
    if direct is not None:
        return direct if _expression_is_grounded(direct, tree, kind) else None

    provenance = re.fullmatch(
        r"(.+?)\s+\((?:from|derived from)\s+(.+)\)", raw, re.I
    )
    if provenance:
        described = _parse_expression(provenance.group(1))
        origin = _parse_expression(provenance.group(2))
        if (
            described is not None
            and origin is not None
            and _expression_is_grounded(described, tree, kind)
            and _expression_is_grounded(origin, tree, kind)
            and _assignment_links(tree, described, origin)
        ):
            return described if _is_explicit_magnitude(described) else origin

    leading = _parse_expression(raw.split(" (", 1)[0])
    if (
        leading is not None
        and _is_explicit_magnitude(leading)
        and _expression_is_grounded(leading, tree, kind)
    ):
        return leading
    return None


def _expression_is_grounded(expression, tree, magnitude_kind):
    signature = ast.dump(expression, include_attributes=False)
    if any(
        isinstance(node, ast.expr)
        and ast.dump(node, include_attributes=False) == signature
        for node in ast.walk(tree)
    ):
        return True
    if isinstance(expression, ast.Name):
        return any(
            isinstance(node, ast.Name) and node.id == expression.id
            for node in ast.walk(tree)
        )
    if (
        isinstance(expression, ast.Call)
        and isinstance(expression.func, ast.Name)
        and expression.func.id == "len"
        and len(expression.args) == 1
        and magnitude_kind in {"request_size", "input_length", "element_count", "logical_size"}
    ):
        return _expression_is_grounded(expression.args[0], tree, magnitude_kind)
    return False


def _assignment_links(tree, described, origin):
    target = described.args[0] if (
        isinstance(described, ast.Call)
        and isinstance(described.func, ast.Name)
        and described.func.id == "len"
        and len(described.args) == 1
    ) else described
    if not isinstance(target, ast.Name):
        return False
    origin_signature = ast.dump(origin, include_attributes=False)
    return any(
        isinstance(node, ast.Assign)
        and any(isinstance(item, ast.Name) and item.id == target.id for item in node.targets)
        and ast.dump(node.value, include_attributes=False) == origin_signature
        for node in ast.walk(tree)
    )


def _is_explicit_magnitude(expression):
    return (
        isinstance(expression, ast.Call)
        and isinstance(expression.func, ast.Name)
        and expression.func.id == "len"
        and len(expression.args) == 1
    )


def _filter_unsupported_magnitude_flows(facts, tree):
    sources = {
        str(source.get("id")): str(source.get("expr") or "")
        for source in (facts.get("magnitude_sources") or [])
        if isinstance(source, Mapping) and source.get("id") is not None
    }
    source_records = {
        str(source.get("id")): source
        for source in (facts.get("magnitude_sources") or [])
        if isinstance(source, Mapping) and source.get("id") is not None
    }
    aliases = _simple_aliases(tree)
    for record in [
        *(facts.get("costly_ops") or []),
        *(arg for call in (facts.get("call_sites") or []) if isinstance(call, Mapping)
          for arg in (call.get("args") or [])),
    ]:
        if not isinstance(record, dict):
            continue
        argument = str(record.get("arg_expr") or record.get("expr") or "")
        record["magnitudes"] = [
            flow for flow in (record.get("magnitudes") or [])
            if not isinstance(flow, Mapping)
            or _flow_has_source_support(
                flow.get("source"), argument, sources, aliases
            )
            and _flow_has_cost_support(record, flow, source_records)
        ]


def _simple_aliases(tree):
    if tree is None:
        return {}
    aliases = {}
    for node in ast.walk(tree):
        if not isinstance(node, ast.Assign) or len(node.targets) != 1:
            continue
        target = node.targets[0]
        if isinstance(target, ast.Name) and isinstance(
            node.value, (ast.Name, ast.Attribute, ast.Subscript)
        ):
            aliases[target.id] = ast.unparse(node.value)
    return aliases


def _flow_has_source_support(reference, argument, sources, aliases):
    if not isinstance(reference, str):
        return False
    if reference.startswith("mag:"):
        expression = sources.get(reference[4:], "")
    elif reference.startswith("param:"):
        expression = reference[6:]
    else:
        return True
    identifiers = set(re.findall(r"[A-Za-z_][A-Za-z0-9_]*", expression))
    identifiers.discard("len")
    if identifiers and any(
        re.search(rf"\b{re.escape(identifier)}\b", argument)
        for identifier in identifiers
    ):
        return True
    argument_ids = set(re.findall(r"[A-Za-z_][A-Za-z0-9_]*", argument))
    return any(
        identifiers.intersection(
            re.findall(r"[A-Za-z_][A-Za-z0-9_]*", aliases.get(name, ""))
        )
        for name in argument_ids
    )


def _flow_has_cost_support(record, flow, sources):
    if record.get("op_kind") != "expensive_call":
        return True
    reference = flow.get("source")
    if not isinstance(reference, str) or not reference.startswith("mag:"):
        return True
    source = sources.get(reference[4:])
    return not (
        isinstance(source, Mapping)
        and source.get("magnitude_kind") == "numeric_param"
    )


def _parse_expression(expression):
    if not isinstance(expression, str) or not expression.strip():
        return None
    try:
        return ast.parse(expression.strip(), mode="eval").body
    except (SyntaxError, TypeError, ValueError):
        return None


def _expression_references_name(expression, name):
    parsed = _parse_expression(expression)
    return parsed is not None and any(
        isinstance(node, ast.Name) and node.id == name for node in ast.walk(parsed)
    )


def _is_precision_losing_extent(value):
    return (
        isinstance(value, ast.Call)
        and isinstance(value.func, ast.Attribute)
        and isinstance(value.func.value, ast.Name)
        and value.func.value.id == "math"
        and value.func.attr == "ceil"
        and len(value.args) == 1
        and isinstance(value.args[0], ast.BinOp)
        and isinstance(value.args[0].op, ast.Div)
    )


def iteration_magnitudes_for_call(facts, source, callee_name, occurrence):
    """Return concrete collection counts enclosing one call occurrence."""
    tree = _parse(textwrap.dedent(source or ""))
    if tree is None:
        return []
    bare = callee_name.split(".")[-1]
    calls = sorted(
        (
            node for node in ast.walk(tree)
            if isinstance(node, ast.Call) and _call_name(node.func).split(".")[-1] == bare
        ),
        key=lambda node: (getattr(node, "lineno", -1), getattr(node, "col_offset", -1)),
    )
    if occurrence >= len(calls):
        return []

    parents = {
        child: parent for parent in ast.walk(tree) for child in ast.iter_child_nodes(parent)
    }
    iterables = []
    current = parents.get(calls[occurrence])
    while current is not None:
        if isinstance(current, (ast.For, ast.AsyncFor)):
            iterables.append((current.iter, getattr(current, "lineno", 0)))
        elif isinstance(current, (ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp)):
            iterables.extend(
                (generator.iter, getattr(current, "lineno", 0))
                for generator in current.generators
            )
        current = parents.get(current)

    expanded_iterables = []
    for iterable, before_line in iterables:
        expanded_iterables.append(iterable)
        if not isinstance(iterable, ast.Name):
            continue
        expanded_iterables.extend(
            node.value
            for node in ast.walk(tree)
            if isinstance(node, ast.Assign)
            and getattr(node, "lineno", 0) < before_line
            and any(
                isinstance(target, ast.Name) and target.id == iterable.id
                for target in node.targets
            )
        )
    iterable_signatures = {
        ast.dump(iterable, include_attributes=False) for iterable in expanded_iterables
    }
    flows = []
    for magnitude in facts.get("magnitude_sources") or []:
        if not isinstance(magnitude, Mapping) or not isinstance(magnitude.get("id"), str):
            continue
        expression = _parse_expression(magnitude.get("expr"))
        compared = expression
        if (
            isinstance(expression, ast.Call)
            and isinstance(expression.func, ast.Name)
            and expression.func.id == "len"
            and len(expression.args) == 1
        ):
            compared = expression.args[0]
        if compared is None or ast.dump(compared, include_attributes=False) not in iterable_signatures:
            continue
        flows.append({
            "source": "mag:" + magnitude["id"],
            "bounds": [],
            "magnitude_kind": magnitude.get("magnitude_kind"),
        })
    return flows


def _call_name(function):
    if isinstance(function, ast.Name):
        return function.id
    if isinstance(function, ast.Attribute):
        prefix = _call_name(function.value)
        return f"{prefix}.{function.attr}" if prefix else function.attr
    return ""


def rejecting_guard_for_call(source, callee_name, occurrence):
    tree = _parse(textwrap.dedent(source or ""))
    if tree is None:
        return None
    bare = callee_name.split(".")[-1]
    calls = sorted(
        (
            node for node in ast.walk(tree)
            if isinstance(node, ast.Call) and _call_name(node.func).split(".")[-1] == bare
        ),
        key=lambda node: (getattr(node, "lineno", -1), getattr(node, "col_offset", -1)),
    )
    if occurrence >= len(calls):
        return None
    target = calls[occurrence]
    for node in ast.walk(tree):
        if not isinstance(node, ast.If) or target not in tuple(ast.walk(node.test)):
            continue
        if not isinstance(node.test, ast.UnaryOp) or not isinstance(node.test.op, ast.Not):
            continue
        if not _block_terminates(node.body):
            continue
        return {
            "line": getattr(node, "lineno", 0),
            "expr": ast.unparse(node.test),
            "args": [ast.unparse(argument) for argument in target.args],
        }
    return None


def _block_terminates(statements):
    for statement in statements:
        if isinstance(statement, (ast.Return, ast.Raise)):
            return True
        if (
            isinstance(statement, ast.If)
            and statement.orelse
            and _block_terminates(statement.body)
            and _block_terminates(statement.orelse)
        ):
            return True
    return False


def source_operation_line(source, expression, occurrence=0):
    candidate = _parse_expression(expression)
    tree = _parse(textwrap.dedent(source or ""))
    if not isinstance(candidate, ast.Call) or tree is None:
        return None
    signature = ast.dump(candidate, include_attributes=False)
    lines = [
        getattr(node, "lineno", 0)
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and ast.dump(node, include_attributes=False) == signature
    ]
    lines.sort()
    return lines[occurrence] if occurrence < len(lines) else None


def returned_parameter_bounds(source, parameters):
    tree = _parse(textwrap.dedent(source or ""))
    if tree is None:
        return set()
    returns = [node for node in ast.walk(tree) if isinstance(node, ast.Return)]
    established = set()
    for parameter in parameters:
        matched = False
        for node in returns:
            if isinstance(node.value, ast.Constant) and node.value.value is False:
                continue
            if node.value is None or not _has_positive_length_cap(node.value, parameter):
                break
            matched = True
        else:
            if matched:
                established.add(parameter)
    return established


def _has_positive_length_cap(expression, parameter):
    parents = {
        child: parent for parent in ast.walk(expression)
        for child in ast.iter_child_nodes(parent)
    }
    for node in ast.walk(expression):
        if not isinstance(node, ast.Compare):
            continue
        values = [node.left, *node.comparators]
        for index, value in enumerate(values):
            if not (
                isinstance(value, ast.Call)
                and isinstance(value.func, ast.Name)
                and value.func.id == "len"
                and len(value.args) == 1
                and isinstance(value.args[0], ast.Name)
                and value.args[0].id == parameter
            ):
                continue
            current = node
            invalid_context = False
            while current in parents:
                current = parents[current]
                if isinstance(current, ast.BoolOp) and isinstance(current.op, ast.And):
                    continue
                if isinstance(current, ast.expr):
                    invalid_context = True
                    break
            if invalid_context:
                continue
            upper_on_right = index < len(node.ops) and isinstance(
                node.ops[index], (ast.Lt, ast.LtE)
            )
            upper_on_left = index > 0 and isinstance(
                node.ops[index - 1], (ast.Gt, ast.GtE)
            )
            if upper_on_right or upper_on_left:
                return True
    return False


def _add_source_bounds(facts, source, tree):
    guards = _ast_length_guards(tree) if tree is not None else _length_guards(source)
    checked_add = _has_checked_addition(tree)
    for op in facts.get("costly_ops") or []:
        if not isinstance(op, dict) or not isinstance(op.get("id"), str):
            continue
        if checked_add and op.get("op_kind") == "logical_allocation":
            _attach_bound(facts, op, "arithmetic_limit", "logical_size", checked_add)
        operation_line = source_operation_line(source, op.get("call_expr"))
        for variable, expression, guard_line in guards:
            if operation_line is not None and guard_line > operation_line:
                continue
            if _operation_uses_variable(facts, op, variable):
                _attach_bound(facts, op, "input_length_cap", "input_length", expression)


def _length_guards(source):
    guards = []
    patterns = (
        r"if\s+not\s+\(?([^:\n]*\blen\((\w+)\)[^:\n]*)\)?\s*:",
        r"return\s+\(?([^\n]*\blen\((\w+)\)[^\n]*\band\b[^\n]*)",
    )
    for pattern in patterns:
        for match in re.finditer(pattern, source):
            expression, variable = match.group(1).strip(), match.group(2)
            line = source.count("\n", 0, match.start()) + 1
            guards.append((variable, expression, line))
    return guards


def _ast_length_guards(tree):
    if tree is None:
        return []
    guards = []
    for node in ast.walk(tree):
        if isinstance(node, ast.If) and not _block_terminates(node.body):
            continue
        expression = node.test if isinstance(node, ast.If) else (
            node.value if isinstance(node, ast.Return) else None
        )
        if expression is None:
            continue
        for call in ast.walk(expression):
            if not isinstance(call, ast.Call) or not isinstance(call.func, ast.Name):
                continue
            if call.func.id != "len" or len(call.args) != 1 or not isinstance(call.args[0], ast.Name):
                continue
            if any(isinstance(compare, ast.Compare) and call in tuple(ast.walk(compare))
                   for compare in ast.walk(expression)):
                guards.append((
                    call.args[0].id,
                    ast.unparse(expression),
                    getattr(node, "lineno", 0),
                ))
    return guards


def _has_checked_addition(tree):
    if tree is None:
        return None
    for node in ast.walk(tree):
        if not isinstance(node, ast.If) or not any(isinstance(child, ast.Raise) for child in ast.walk(node)):
            continue
        if any(isinstance(child, ast.BinOp) and isinstance(child.op, ast.Add)
               for child in ast.walk(node.test)):
            try:
                return ast.unparse(node.test)
            except AttributeError:
                return "checked addition"
    return None


def _operation_uses_variable(facts, op, variable):
    text = str(op.get("arg_expr") or "")
    if re.search(rf"\b{re.escape(variable)}\b", text):
        return True
    indexed = {
        source.get("id"): str(source.get("expr") or "")
        for source in (facts.get("magnitude_sources") or []) if isinstance(source, Mapping)
    }
    return any(
        isinstance(flow, Mapping)
        and isinstance(flow.get("source"), str)
        and flow["source"].startswith("mag:")
        and re.search(rf"\b{re.escape(variable)}\b", indexed.get(flow["source"][4:], ""))
        for flow in (op.get("magnitudes") or [])
    )


def _attach_bound(facts, op, kind, magnitude_kind, expression):
    bound_id = f"SRC_BOUND_{len(facts.get('bounds') or []) + 1}"
    bound = {
        "id": bound_id, "bound_kind": kind, "expr": expression,
        "caps": [magnitude_kind], "protects_op_ids": [op["id"]],
        "placement": "before", "enforcement": "reject",
        "limit_origin": "type_limit" if kind == "arithmetic_limit" else "constant",
        "dominates": True, "confidence": "high",
    }
    facts.setdefault("bounds", []).append(bound)
    for flow in op.get("magnitudes") or []:
        if isinstance(flow, dict):
            flow.setdefault("bounds", []).append(bound_id)
    for source in facts.get("magnitude_sources") or []:
        if isinstance(source, dict) and magnitude_kind == "input_length" and _operation_uses_variable(
            facts, op, str(source.get("expr") or "")
        ):
            source["magnitude_kind"] = magnitude_kind


def _has_cache_decorator(tree):
    if tree is None:
        return False
    functions = [node for node in tree.body if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))]
    if not functions:
        return False
    for decorator in functions[0].decorator_list:
        target = decorator.func if isinstance(decorator, ast.Call) else decorator
        name = target.id if isinstance(target, ast.Name) else (
            target.attr if isinstance(target, ast.Attribute) else ""
        )
        if "cache" in name.lower():
            return True
    return False


def bounds_by_id(facts):
    bounds = facts.get("bounds") if isinstance(facts, Mapping) else None
    if not _records(bounds):
        return {}
    return {
        bound["id"]: bound
        for bound in bounds
        if isinstance(bound, Mapping) and isinstance(bound.get("id"), str)
    }


def resolve_bound(entry, indexed_bounds):
    if isinstance(entry, str):
        return indexed_bounds.get(entry)
    if isinstance(entry, Mapping):
        bound_id = entry.get("id")
        if isinstance(bound_id, str) and bound_id in indexed_bounds:
            return indexed_bounds[bound_id]
        return entry
    return None


def accepted_bound(magnitude, op, magnitude_kind, indexed_bounds):
    """Return the first hard bound covering this exact flow and op, if any."""
    entries = magnitude.get("bounds") if isinstance(magnitude, Mapping) else None
    if not _entries(entries):
        return None
    for entry in entries:
        bound = resolve_bound(entry, indexed_bounds)
        if _accepts(bound, op, magnitude_kind):
            return bound
    return None


def _accepts(bound, op, magnitude_kind):
    if not isinstance(bound, Mapping):
        return False
    if bound.get("confidence") != "high" or bound.get("dominates") is not True:
        return False

    kind = bound.get("bound_kind")
    allowed = BOUND_CAPS.get(kind)
    if allowed is None or magnitude_kind not in allowed:
        return False
    expression = str(bound.get("expr") or "")
    if kind == "size_check" and "isinstance(" in expression and "len(" not in expression:
        return False

    placement = bound.get("placement")
    if placement is not None and placement != "before":
        return False
    enforcement = bound.get("enforcement")
    if enforcement is not None and enforcement not in HARD_ENFORCEMENTS:
        return False
    limit_origin = bound.get("limit_origin")
    if limit_origin is not None and limit_origin not in TRUSTED_LIMIT_ORIGINS:
        return False

    protected = bound.get("protects_op_ids")
    if protected is not None:
        if not _string_sequence(protected):
            return False
        op_id = op.get("id") if isinstance(op, Mapping) else None
        if not isinstance(op_id, str) or op_id not in protected:
            return False

    declared = bound.get("caps")
    if not _string_sequence(declared):
        return False
    return magnitude_kind in declared


def _records(value):
    return isinstance(value, Sequence) and not isinstance(value, (str, bytes))


def _entries(value):
    return isinstance(value, Sequence) and not isinstance(value, (str, bytes))


def _string_sequence(value):
    return (
        isinstance(value, Sequence)
        and not isinstance(value, (str, bytes))
        and all(isinstance(item, str) for item in value)
    )

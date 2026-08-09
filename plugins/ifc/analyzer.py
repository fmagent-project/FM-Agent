"""IFC analysis helpers extracted from IfcPlugin SPI methods."""

import ast
import ast
import re
import textwrap
from pathlib import Path
from typing import Dict, List, Optional

from .ifc_reasoner import HIGH, LOW, UNKNOWN, _raw_input_labels


def _arg_label(arg_expr: str, caller_raw_labels: Dict[str, str]) -> str:
    """Deterministically label a call-site argument expression in caller context.

    - string/number literal -> Low
    - bare caller-parameter name -> that parameter's label
    - anything else -> Unknown (conservative)
    """
    expr = (arg_expr or "").strip()
    if re.fullmatch(r'["\'].*["\']', expr) or re.fullmatch(r"[-+]?\d+(\.\d+)?", expr):
        return LOW
    if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", expr):
        key = f"param:{expr}"
        if key in caller_raw_labels:
            return caller_raw_labels[key]
        return UNKNOWN
    return UNKNOWN


def _called_names(source: str, language: str) -> Optional[set]:
    """AST-based extraction of call target names (Python only)."""
    if language.lower() != "python":
        return None
    try:
        tree = ast.parse(textwrap.dedent(source))
    except (SyntaxError, TypeError, ValueError):
        return None
    names = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        if isinstance(func, ast.Name):
            names.add(func.id)
        elif isinstance(func, ast.Attribute):
            names.add(func.attr)
    return names


def _is_python_method(source: str, language: str) -> bool:
    """Check if the function is a Python method (first param self/cls)."""
    if language.lower() != "python":
        return False
    try:
        tree = ast.parse(textwrap.dedent(source))
    except (SyntaxError, TypeError, ValueError):
        return False
    function = next(
        (node for node in tree.body
         if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))),
        None,
    )
    if function is None:
        return False
    args = [*function.args.posonlyargs, *function.args.args]
    return bool(args and args[0].arg in {"self", "cls"})


def _source_rel_from_extracted(rel: str) -> str:
    """Map ``path/file-py/func.py`` back to ``path/file.py``."""
    path = Path(rel)
    if len(path.parts) < 2:
        return rel
    encoded = path.parent.name
    extension = path.suffix.lstrip(".")
    suffix = "-" + extension
    if not extension or not encoded.endswith(suffix):
        return rel
    return (path.parent.parent / (encoded[:-len(suffix)] + "." + extension)).as_posix()


def summarize_for_caller(name: str, payload: dict) -> str:
    """One-line callee flow summary injected into a caller's prompt."""
    if not payload:
        return f"{name}: (no valid signature)"
    outs = (payload or {}).get("outputs", {}) or {}
    parts = []
    for ch, spec in outs.items():
        deps = (spec or {}).get("deps", [])
        sink = (spec or {}).get("sink_channel", "unknown")
        visibility = (spec or {}).get("observability", "unknown")
        parts.append(f"{ch}[{sink},{visibility}]<-{{{','.join(deps)}}}")
    return f"{name}: " + ("; ".join(parts) if parts else "(no tracked outputs)")


def _python_call_return_is_used(source: str, callee_name: str) -> Optional[bool]:
    """Return whether a Python call's return value is actually consumed.

    Returns:
        True/False when Python AST analysis succeeds.
        None when the source cannot be parsed or is not Python.
    """
    try:
        tree = ast.parse(textwrap.dedent(source))
    except (SyntaxError, TypeError, ValueError):
        return None

    parents = {}
    for parent_node in ast.walk(tree):
        for child in ast.iter_child_nodes(parent_node):
            parents[child] = parent_node

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        called = None
        if isinstance(func, ast.Name):
            called = func.id
        elif isinstance(func, ast.Attribute):
            called = func.attr
        if called != callee_name:
            continue
        parent = parents.get(node)
        if isinstance(parent, ast.Expr):
            return False
        return True
    return False


def compose_calls(
    facts: dict,
    resolved_calls: list,
    source: str,
    language: str,
) -> dict:
    """Instantiate callee signatures at call sites with caller argument labels.

    Returns a copy of *facts* with composed outputs and ``_callee_resolutions``.

    Unused callee return values are NOT propagated as caller outputs
    (e.g. ``helper(password); return \"ok\"`` does not become a leak).
    """
    if facts.get("status") != "ok" or not facts.get("payload"):
        return facts
    caller_raw = _raw_input_labels(facts["payload"])
    resolutions = []
    composed_outputs = dict(facts["payload"].get("outputs") or {})
    called = _called_names(source, language)

    for ci, rc in enumerate(resolved_calls):
        callee_name = rc.get("callee_name", "")
        if called is not None and callee_name not in called:
            continue
        callee_facts = rc.get("callee_facts", {})
        if callee_facts.get("status") != "ok" or not callee_facts.get("payload"):
            continue
        binding = {
            formal: _arg_label(expr, caller_raw)
            for formal, expr in rc.get("arg_bindings", {}).items()
        }
        from .ifc_reasoner import instantiate_callee
        resolved = instantiate_callee(callee_facts["payload"], binding)
        resolutions.append({
            "callee": callee_name,
            "arg_binding": binding,
            "resolved_outputs": resolved,
        })

        return_used = True
        if language.lower() == "python":
            parsed_usage = _python_call_return_is_used(source, callee_name)
            if parsed_usage is not None:
                return_used = parsed_usage

        for channel, output in resolved.items():
            observability = output.get("observability")
            if observability == "internal":
                continue
            if channel == "return" and not return_used:
                continue
            composed_outputs[f"callee:{callee_name}:{channel}"] = {
                "deps": [],
                "const": LOW if output.get("label") == LOW else HIGH,
                "declass": ([{"anchor": "callee", "reason": "callee declassification"}]
                            if output.get("declassified") else []),
                "sink_channel": output.get("sink_channel", "unknown"),
                "observability": observability or "caller",
            }

    if resolutions:
        facts["payload"] = dict(facts["payload"])
        facts["payload"]["outputs"] = composed_outputs
        facts["payload"]["_callee_resolutions"] = resolutions
    return facts

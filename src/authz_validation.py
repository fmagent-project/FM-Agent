"""Validate authz abstractions and derive source-decidable guard facts.

The model identifies semantic security operations. This module independently
settles three narrow facts that are visible in source syntax: whether a session
lifetime has an absolute (not merely sliding) bound, whether a framework-bound
object was resolved through its enclosing scope, and which concrete object an
inherited permission gate protects before an asynchronous dispatch.
"""

from __future__ import annotations

import ast
import copy
import hashlib
import textwrap
from pathlib import Path


_REQUIRED_CHECKS = {
    "authentication",
    "absolute_authentication_lifetime",
    "subject_object_binding",
    "object_permission",
}
VALIDATION_VERSION = "authz.validation.v1"


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


def original_source_path(unit) -> Path | None:
    if not unit.abs_path:
        return None
    extracted = Path(unit.abs_path).resolve()
    parts = extracted.parts
    try:
        marker = len(parts) - 1 - parts[::-1].index("extracted_functions")
    except ValueError:
        return None
    if marker < 2:
        return None
    stage = Path(*parts[:marker - 1])
    source = stage / source_rel_from_extracted(unit.id.rel)
    return source if source.is_file() else None


def source_digest(unit) -> str:
    digest = hashlib.sha256(unit.source.encode())
    source = original_source_path(unit)
    if source is not None:
        digest.update(b"\0" + source.read_bytes())
    return digest.hexdigest()


def _parse(text: str) -> ast.Module | None:
    try:
        return ast.parse(textwrap.dedent(text))
    except (SyntaxError, TypeError, ValueError):
        return None


def _assignment_values(tree: ast.AST | None) -> dict[str, ast.AST]:
    values: dict[str, ast.AST] = {}
    if tree is None:
        return values
    for node in ast.walk(tree):
        if isinstance(node, (ast.Assign, ast.AnnAssign)) and node.value is not None:
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            for target in targets:
                if isinstance(target, ast.Name):
                    values[target.id] = node.value
    return values


def _resolved(node: ast.AST, values: dict[str, ast.AST], seen=None) -> ast.AST:
    seen = seen or set()
    if isinstance(node, ast.Name) and node.id in values and node.id not in seen:
        return _resolved(values[node.id], values, seen | {node.id})
    return node


def _time_signals(node: ast.AST, values: dict[str, ast.AST]) -> tuple[bool, bool]:
    node = _resolved(node, values)
    text = ast.unparse(node).lower()
    current = any(token in text for token in (".now(", "time.time(", "utcnow("))
    authenticated = any(token in text for token in ("login", "auth", "issued", "created"))
    return current, authenticated


def _absolute_lifetime_evidence(tree: ast.Module | None) -> str | None:
    if tree is None:
        return None
    values = _assignment_values(tree)
    for call in (node for node in ast.walk(tree) if isinstance(node, ast.Call)):
        if not isinstance(call.func, ast.Name) or call.func.id != "min":
            continue
        args = list(call.args)
        if len(args) == 1 and isinstance(_resolved(args[0], values), (ast.List, ast.Tuple)):
            args = list(_resolved(args[0], values).elts)
        signals = [_time_signals(arg, values) for arg in args]
        if any(current for current, _ in signals) and any(auth for _, auth in signals):
            return ast.unparse(call)
    return None


def _function_node(tree: ast.Module | None, base_name: str, extracted_tree: ast.Module | None = None):
    if tree is None:
        return None, None
    target = next((node for node in ast.walk(extracted_tree) if isinstance(
        node, (ast.FunctionDef, ast.AsyncFunctionDef))), None) if extracted_tree else None
    target_dump = ast.dump(target, include_attributes=False) if target is not None else None
    fallback = None
    for parent in ast.walk(tree):
        body = parent.body if isinstance(parent, (ast.Module, ast.ClassDef)) else ()
        for node in body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == base_name:
                found = (node, parent if isinstance(parent, ast.ClassDef) else None)
                fallback = fallback or found
                if target_dump and ast.dump(node, include_attributes=False) == target_dump:
                    return found
    return fallback or (None, None)


def _params(node: ast.FunctionDef | ast.AsyncFunctionDef | None) -> list[str]:
    if node is None:
        return []
    return [arg.arg for arg in (*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs)]


def _literal_subscript(target: ast.AST) -> tuple[str, str] | None:
    if not isinstance(target, ast.Subscript) or not isinstance(target.value, ast.Name):
        return None
    key = target.slice
    if isinstance(key, ast.Constant) and isinstance(key.value, str):
        return target.value.id, key.value
    return None


def _scope_bindings(tree: ast.Module | None) -> list[tuple[str, str, str]]:
    """Return (injected object parameter, scope expression, evidence)."""
    bindings = []
    if tree is None:
        return bindings
    for fn in (node for node in ast.walk(tree) if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))):
        values = _assignment_values(fn)
        subscript_names = {}
        for name, value in values.items():
            subscript = _literal_subscript(value)
            if subscript:
                subscript_names[name] = subscript[1]
        for node in ast.walk(fn):
            if not isinstance(node, ast.Assign) or not isinstance(node.value, ast.Name):
                continue
            object_name = node.value.id
            target = next((_literal_subscript(item) for item in node.targets if _literal_subscript(item)), None)
            if not target:
                continue
            lookup = values.get(object_name)
            if not isinstance(lookup, ast.Call) or not isinstance(lookup.func, ast.Attribute) or lookup.func.attr != "get":
                continue
            lookup_root = lookup.func.value
            lookup_root = _resolved(lookup_root, values)
            lookup_text = ast.unparse(lookup_root)
            candidates = set(subscript_names.values())
            candidates.update(
                value.id for call in ast.walk(lookup_root) if isinstance(call, ast.Call)
                for value in (*call.args, *(kw.value for kw in call.keywords)) if isinstance(value, ast.Name)
            )
            scope = next((name for name in sorted(candidates) if name not in {target[1], object_name}), None)
            if scope and scope in lookup_text:
                bindings.append((target[1], scope, ast.unparse(node)))
    return bindings


def _call_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = _call_name(node.value)
        return f"{parent}.{node.attr}" if parent else node.attr
    if isinstance(node, ast.Call):
        return _call_name(node.func)
    return ""


def _source_operation(op_id: str, evidence: str, **fields) -> dict:
    operation = {
        "op_id": op_id,
        "kind": "other",
        "resource_type": "protected_resource",
        "resource_id_expr": fields.get("resource_id_expr"),
        "resource_id_origin": "param",
        "action": fields.get("action", "access"),
        "evidence": evidence,
        "required_checks": fields.get("required_checks", []),
        "_source_derived": True,
    }
    operation.update({key: value for key, value in fields.items() if key not in operation})
    return operation


def _has_session_security_reference(tree: ast.Module | None) -> bool:
    if tree is None:
        return False
    has_session = any(
        isinstance(node, ast.Name) and "session" in node.id.lower()
        or isinstance(node, ast.Attribute) and "session" in node.attr.lower()
        for node in ast.walk(tree)
    )
    if not has_session:
        return False
    for node in ast.walk(tree):
        if isinstance(node, ast.Attribute) and node.attr.lower() in {"timeout", "expires", "expiry"}:
            return True
        if isinstance(node, ast.Call) and "login" in _call_name(node.func).lower():
            return True
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and \
                node.func.attr == "get" and "session" in ast.unparse(node.func.value).lower():
            keys = " ".join(ast.unparse(arg).lower() for arg in node.args)
            if any(token in keys for token in ("auth", "login", "identity", "user")):
                return True
        if isinstance(node, ast.Subscript):
            key = ast.unparse(node.slice).lower()
            if any(token in key for token in ("auth", "login", "identity", "user")) and \
                    not any(token in key for token in ("redirect", "url")):
                return True
    return False


def _session_enrichment(payload: dict, fn_tree: ast.Module | None, source_tree: ast.Module | None) -> None:
    if not _has_session_security_reference(fn_tree):
        return
    operations = payload["sensitive_operations"]
    if not operations:
        operations.append(_source_operation(
            "source_session_lifetime", ast.unparse(fn_tree),
            resource_type="Session", resource_id_expr="session", action="authenticate",
            required_checks=["absolute_authentication_lifetime"],
        ))
    for operation in operations:
        operation["required_checks"] = ["absolute_authentication_lifetime"]
    evidence = _absolute_lifetime_evidence(source_tree)
    payload["_authz_validation"]["absolute_lifetime"] = evidence is not None
    if evidence:
        subject = (payload.get("authenticated_subject") or {}).get("expr") or "authenticated_subject"
        payload["guards"].append({
            "predicate_nl": "session lifetime is capped by an authentication-anchored deadline",
            "subject": subject,
            "resource_type": "Session",
            "resource_id_expr": "session",
            "action_scope": "any",
            "kind": "authentication",
            "source": "source_validation",
            "dominates_all_paths": True,
            "absolute_lifetime_bound": True,
            "evidence": evidence,
        })


def _binding_enrichment(
    payload: dict,
    fn: ast.AST | None,
    source_tree: ast.Module | None,
    parent: ast.ClassDef | None,
) -> None:
    if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
        return
    operations = payload["sensitive_operations"]
    params = set(_params(fn))
    bindings = [binding for binding in _scope_bindings(source_tree) if binding[0] in params]
    if bindings:
        object_name, scope, evidence = bindings[0]
        if not operations:
            operations.append(_source_operation(
                "source_bound_object", evidence, resource_id_expr=object_name,
                scope_id_expr=scope, required_checks=["subject_object_binding"],
            ))
        for operation in operations:
            operation["scope_id_expr"] = scope
            operation["required_checks"] = ["subject_object_binding"]
        payload["guards"].append({
            "predicate_nl": "object is resolved from a query constrained by the enclosing scope",
            "subject": (payload.get("authenticated_subject") or {}).get("expr") or "authenticated_subject",
            "resource_type": "scoped_object",
            "resource_id_expr": scope,
            "scope_id_expr": scope,
            "action_scope": "any",
            "kind": "tenant",
            "source": "source_validation",
            "dominates_all_paths": True,
            "evidence": evidence,
        })
        payload["_authz_validation"]["scope_binding"] = True
        return

    # A handler that obtains an object from an id-only helper while also receiving
    # an enclosing domain object has no proof that the two belong together.
    for assign in (node for node in ast.walk(fn) if isinstance(node, ast.Assign)):
        if not isinstance(assign.value, ast.Call) or not isinstance(assign.value.func, ast.Attribute):
            continue
        id_args = [arg.id for arg in assign.value.args if isinstance(arg, ast.Name) and arg.id in params]
        if not id_args:
            continue
        reserved = {"self", "request", *id_args}
        scope = next((name for name in _params(fn) if name not in reserved), None)
        if scope:
            object_name = next((target.id for target in assign.targets if isinstance(target, ast.Name)), id_args[0])
            if not operations:
                operations.append(_source_operation(
                    "source_unbound_object", ast.unparse(assign), resource_id_expr=object_name,
                    scope_id_expr=scope, required_checks=["subject_object_binding"],
                ))
            for operation in operations:
                operation["scope_id_expr"] = scope
                operation["required_checks"] = ["subject_object_binding"]
            return

    # A direct keyed lookup is object-specific. Existing authz guards may still
    # discharge it, but authentication alone cannot.
    if parent is not None and any("permission" in _call_name(base).lower() for base in parent.bases):
        return
    for call in (node for node in ast.walk(fn) if isinstance(node, ast.Call)):
        if not isinstance(call.func, ast.Attribute) or call.func.attr != "get":
            continue
        keyed = [kw.value.id for kw in call.keywords if isinstance(kw.value, ast.Name) and kw.value.id in params]
        if keyed:
            if not operations:
                operations.append(_source_operation(
                    "source_keyed_lookup", ast.unparse(call), resource_id_expr=keyed[0],
                    scope_id_expr=keyed[0], required_checks=["subject_object_binding"], action="read",
                ))
            for operation in operations:
                operation["scope_id_expr"] = keyed[0]
                operation["required_checks"] = ["subject_object_binding"]
            return


def _dispatch_enrichment(payload: dict, fn: ast.AST | None, parent: ast.ClassDef | None) -> None:
    if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
        return
    values = _assignment_values(fn)
    dispatches = []
    for call in (node for node in ast.walk(fn) if isinstance(node, ast.Call)):
        if not any(kw.arg == "func" for kw in call.keywords):
            continue
        target = None
        for kw in call.keywords:
            value = kw.value
            if isinstance(value, ast.Attribute) and isinstance(value.value, ast.Name):
                candidate = value.value.id
                if candidate in values and isinstance(values[candidate], ast.Attribute):
                    target = candidate
                    break
        dispatches.append((call, target or "dispatch_target"))
    if not dispatches:
        return
    call, target = dispatches[0]
    payload["sensitive_operations"].append(_source_operation(
        "source_dispatch", ast.unparse(call), resource_id_expr=target,
        permission_object_expr=target, required_checks=["object_permission"], action="dispatch",
    ))

    if parent is None or not any("permission" in _call_name(base).lower() for base in parent.bases):
        return
    protected_model = None
    for node in parent.body:
        if isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id == "queryset" for t in node.targets):
            name = _call_name(node.value)
            protected_model = name.split(".objects", 1)[0] if ".objects" in name else None
    protected_object = None
    if protected_model:
        for name, value in values.items():
            if protected_model in _call_name(value):
                protected_object = name
                break
    if protected_object:
        payload["guards"].append({
            "predicate_nl": "inherited object permission protects the queryset object",
            "subject": (payload.get("authenticated_subject") or {}).get("expr") or "authenticated_subject",
            "resource_type": protected_model,
            "resource_id_expr": protected_object,
            "action_scope": "dispatch",
            "kind": "permission",
            "source": "source_validation",
            "dominates_all_paths": True,
            "evidence": f"queryset = {protected_model}.objects",
        })


def _transactional_permission_enrichment(payload: dict, fn: ast.AST | None) -> None:
    """Trust effects only when a scoped object recheck gates transaction commit."""
    if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
        return
    has_scoped_lookup = any(
        isinstance(call, ast.Call) and _call_name(call.func).endswith("get_object")
        for call in ast.walk(fn)
    )
    if not has_scoped_lookup:
        return

    evidence = None
    for attempt in (node for node in ast.walk(fn) if isinstance(node, ast.Try)):
        rolls_back = any(
            handler.type is not None and "doesnotexist" in ast.unparse(handler.type).lower()
            for handler in attempt.handlers
        )
        if not rolls_back:
            continue
        for block in (node for node in ast.walk(attempt) if isinstance(node, (ast.With, ast.AsyncWith))):
            contexts = [_call_name(item.context_expr).lower() for item in block.items]
            if not any(name.endswith("atomic") or name.endswith("transaction") for name in contexts):
                continue
            saves = []
            for node in ast.walk(block):
                if not isinstance(node, ast.Assign) or not isinstance(node.value, ast.Call) or \
                        not _call_name(node.value.func).endswith(".save"):
                    continue
                saves.extend(
                    (target.id, node.lineno) for target in node.targets if isinstance(target, ast.Name)
                )
            for object_name, save_line in saves:
                recheck = next((
                    call for call in ast.walk(block)
                    if isinstance(call, ast.Call)
                    and isinstance(call.func, ast.Attribute)
                    and call.func.attr in {"get", "check_perms"}
                    and call.lineno > save_line
                    and f"{object_name}." in ast.unparse(call)
                ), None)
                if recheck is not None:
                    evidence = ast.unparse(recheck)
                    break
            if evidence:
                break
        if evidence:
            break
    if not evidence:
        return

    for operation in payload["sensitive_operations"]:
        if not operation.get("required_checks"):
            operation["_source_authorized"] = True
    payload["_authz_validation"]["transactional_permission"] = True


def validate_and_enrich(payload, unit):
    """Return validated copied facts enriched only with source-derived guards."""
    if not isinstance(payload, dict):
        return None
    enriched = copy.deepcopy(payload)
    for key in list(enriched):
        if key.startswith("_"):
            enriched.pop(key)
    for key in ("sensitive_operations", "guards", "obligations", "establishes"):
        value = enriched.get(key, [])
        if not isinstance(value, list) or any(not isinstance(item, dict) for item in value):
            return None
        enriched[key] = value
    for operation in enriched["sensitive_operations"]:
        checks = operation.get("required_checks")
        if checks is not None and not isinstance(checks, list):
            return None
        for key in list(operation):
            if key.startswith("_"):
                operation.pop(key)
        # These checks are source-decidable trust facts. The model may propose
        # them, but only the structural enrichers below are allowed to assert
        # that a function requires one or that a guard satisfies it.
        operation.pop("required_checks", None)
    # Model output cannot claim the source-validation trust marker or its fields.
    enriched["guards"] = [
        {key: value for key, value in guard.items() if not key.startswith("_")}
        for guard in enriched["guards"] if guard.get("source") != "source_validation"
    ]
    for guard in enriched["guards"]:
        guard.pop("absolute_lifetime_bound", None)

    function_tree = _parse(unit.source)
    source = original_source_path(unit)
    source_tree = _parse(source.read_text(errors="replace")) if source else function_tree
    fn, parent = _function_node(source_tree, unit.id.base_name, function_tree)
    if fn is None and function_tree:
        fn = next((node for node in ast.walk(function_tree)
                   if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))), None)
    enriched["_authz_validation"] = {
        "version": VALIDATION_VERSION,
        "absolute_lifetime": False,
        "scope_binding": False,
        "transactional_permission": False,
    }
    _session_enrichment(enriched, function_tree, source_tree)
    _binding_enrichment(enriched, fn, source_tree, parent)
    _dispatch_enrichment(enriched, fn, parent)
    _transactional_permission_enrichment(enriched, fn)
    enriched["_function_digest"] = source_digest(unit)
    return enriched

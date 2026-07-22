"""Source-backed guards for security-sensitive typestate protocol events."""

from __future__ import annotations

import ast
import copy
import re
import textwrap
from pathlib import Path


SOURCE_EVENT_KINDS = {
    "CONTENT_TYPE_CHECK",
    "JSON_PARSE",
    "SSL_CONTEXT_CREATE",
    "CERT_DEFAULT_LOAD",
    "FS_NOFOLLOW_GUARD",
    "FS_ACQUIRE",
}
SOURCE_PROTOCOL_TRIGGERS = {"JSON_PARSE", "CERT_DEFAULT_LOAD", "FS_ACQUIRE"}


def source_rel_from_extracted(rel):
    """Map ``path/file-py/function.py`` back to ``path/file.py``."""
    current = Path(rel)
    while len(current.parts) >= 2:
        extension = current.suffix.lstrip(".")
        suffix = "-" + extension
        encoded = current.parent.name
        if not extension or not encoded.endswith(suffix):
            break
        current = current.parent.parent / (encoded[:-len(suffix)] + "." + extension)
    parts = current.parts
    if "extracted_functions" in parts:
        marker = len(parts) - 1 - parts[::-1].index("extracted_functions")
        current = Path(*parts[marker + 1:])
    return current.as_posix()


def _text(node):
    try:
        return ast.unparse(node)
    except (AttributeError, ValueError):
        return ""


def _parents(tree):
    result = {}
    for parent in ast.walk(tree):
        for child in ast.iter_child_nodes(parent):
            result[child] = parent
    return result


def _ancestors(node, parents, node_type):
    found = []
    while node in parents:
        node = parents[node]
        if isinstance(node, node_type):
            found.append(node)
    return found


def _nearest_function(node, parents):
    functions = _ancestors(node, parents, (ast.FunctionDef, ast.AsyncFunctionDef))
    return functions[0] if functions else None


def _same_function(node, function, parents):
    return function is not None and _nearest_function(node, parents) is function


def _branch(node, control, parents):
    child = node
    while child in parents and parents[child] is not control:
        child = parents[child]
    if child in control.body:
        return True
    if child in control.orelse:
        return False
    return None


def _if_paths(node, parents):
    return [(control, _branch(node, control, parents)) for control in _ancestors(node, parents, ast.If)]


def _dominates_statement(candidate, target, parents):
    if candidate.lineno >= target.lineno:
        return False
    function = _nearest_function(target, parents)
    if not _same_function(candidate, function, parents):
        return False
    target_ifs = {control: branch for control, branch in _if_paths(target, parents)}
    return all(target_ifs.get(control) == branch for control, branch in _if_paths(candidate, parents))


def _aliases_before(node, parents):
    aliases = {}
    function = _nearest_function(node, parents)
    for assignment in ast.walk(function) if function else ():
        if not isinstance(assignment, (ast.Assign, ast.AnnAssign)) or assignment.lineno >= node.lineno:
            continue
        if not _dominates_statement(assignment, node, parents):
            continue
        value = assignment.value
        if not isinstance(value, (ast.Name, ast.Attribute)):
            continue
        targets = assignment.targets if isinstance(assignment, ast.Assign) else [assignment.target]
        for target in targets:
            if isinstance(target, (ast.Name, ast.Attribute)):
                aliases[_text(target)] = _text(value)
    return aliases


def _normalize_condition(node, aliases):
    value = _text(node)
    for _ in range(len(aliases) + 1):
        replaced = value
        for name, alias in aliases.items():
            replaced = re.sub(rf"\b{re.escape(name)}\b", alias, replaced)
        if replaced == value:
            break
        value = replaced
    return re.sub(r"\s+", "", value).lower()


def _condition_terms(node, parents):
    aliases = _aliases_before(node, parents)
    terms = set()

    def add(test, positive):
        if positive and isinstance(test, ast.BoolOp) and isinstance(test.op, ast.And):
            for value in test.values:
                add(value, True)
            return
        term = _normalize_condition(test, aliases)
        terms.add(term if positive else f"not({term})")

    for control, positive in _if_paths(node, parents):
        if positive is not None:
            add(control.test, positive)
    return terms


def _ordered_dominating_assignments(node, parents):
    function = _nearest_function(node, parents)
    if function is None:
        return []
    return sorted(
        (
            item for item in ast.walk(function)
            if isinstance(item, (ast.Assign, ast.AnnAssign, ast.AugAssign))
            and _dominates_statement(item, node, parents)
        ),
        key=lambda item: (item.lineno, item.col_offset),
    )


def _constant_text(node):
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value.lower()
    return None


def _is_content_type_key(node):
    return _constant_text(node) == "content-type"


def _direct_content_type_source(node, request):
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
        receiver = node.func.value
        return (
            node.func.attr == "get"
            and isinstance(receiver, ast.Attribute)
            and receiver.attr == "headers"
            and _text(receiver.value) == request
            and bool(node.args)
            and _is_content_type_key(node.args[0])
        )
    return (
        isinstance(node, ast.Subscript)
        and isinstance(node.value, ast.Attribute)
        and node.value.attr == "headers"
        and _text(node.value.value) == request
        and _is_content_type_key(node.slice)
    )


def _content_type_provenance(call, request, parents):
    values = {}
    messages = set()

    def provenance(node):
        if _direct_content_type_source(node, request):
            return ("raw", request)
        if isinstance(node, (ast.Name, ast.Attribute)):
            return values.get(_text(node))
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            receiver = _text(node.func.value)
            if receiver in messages and node.func.attr == "get_content_maintype":
                return ("main", receiver)
            if receiver in messages and node.func.attr == "get_content_subtype":
                return ("sub", receiver)
        return None

    for assignment in _ordered_dominating_assignments(call, parents):
        value = assignment.value
        targets = assignment.targets if isinstance(assignment, ast.Assign) else [assignment.target]
        for target in targets:
            if (
                isinstance(target, ast.Subscript)
                and _is_content_type_key(target.slice)
                and provenance(value) == ("raw", request)
            ):
                messages.add(_text(target.value))
                continue
            if not isinstance(target, (ast.Name, ast.Attribute)):
                continue
            name = _text(target)
            messages.discard(name)
            source = provenance(value) if not isinstance(assignment, ast.AugAssign) else None
            if source is None:
                values.pop(name, None)
            else:
                values[name] = source
    return provenance


def _json_media_literal(node):
    value = _constant_text(node)
    if value is None:
        return False
    media_type = value.split(";", 1)[0].strip()
    if "/" not in media_type:
        return False
    main, subtype = media_type.split("/", 1)
    return main == "application" and (subtype == "json" or subtype.endswith("+json"))


def _media_predicates(node, provenance):
    if isinstance(node, ast.BoolOp):
        predicates = [_media_predicates(value, provenance) for value in node.values]
        if isinstance(node.op, ast.And):
            return set().union(*predicates)
        if isinstance(node.op, ast.Or) and predicates:
            return set.intersection(*predicates)
        return set()

    if isinstance(node, ast.Compare) and len(node.ops) == len(node.comparators) == 1:
        if not isinstance(node.ops[0], ast.Eq):
            return set()
        left, right = node.left, node.comparators[0]
        left_source, right_source = provenance(left), provenance(right)
        if left_source and _constant_text(right) is not None:
            source, literal = left_source, right
        elif right_source and _constant_text(left) is not None:
            source, literal = right_source, left
        else:
            return set()
        if source[0] == "raw" and _json_media_literal(literal):
            return {"full"}
        if source[0] == "main" and _constant_text(literal) == "application":
            return {f"main:{source[1]}"}
        if source[0] == "sub" and (
            _constant_text(literal) == "json"
            or str(_constant_text(literal) or "").endswith("+json")
        ):
            return {f"sub:{source[1]}"}
        return set()

    if isinstance(node, ast.Call):
        if isinstance(node.func, ast.Attribute) and node.args:
            source = provenance(node.func.value)
            if source and node.func.attr == "startswith" and source[0] == "raw":
                if all(_json_media_literal(argument) for argument in node.args):
                    return {"full"}
            if source and node.func.attr == "endswith" and source[0] == "sub":
                if all(_constant_text(argument) == "+json" for argument in node.args):
                    return {f"sub:{source[1]}"}
    return set()


def _ensure_resource(facts, canonical, kind, origin="local", mutability="stable"):
    resources = facts.setdefault("resources", [])
    for resource in resources:
        if resource.get("canonical") == canonical:
            return resource.get("id")
    base = "src_" + "".join(char if char.isalnum() else "_" for char in canonical).strip("_")
    resource_id = base or "src_resource"
    used = {resource.get("id") for resource in resources}
    suffix = 2
    while resource_id in used:
        resource_id = f"{base}_{suffix}"
        suffix += 1
    resources.append({
        "id": resource_id,
        "kind": kind,
        "canonical": canonical,
        "origin": origin,
        "formal": canonical if origin == "param" else None,
        "mutability": mutability,
        "escapes": "none",
    })
    return resource_id


def _append_event(facts, kind, resource, node, operation, predecessors=(), **extra):
    events = facts.setdefault("events", [])
    event_id = f"_src_{kind.lower()}_{getattr(node, 'lineno', len(events) + 1)}"
    used = {event.get("id") for event in events}
    base, suffix = event_id, 2
    while event_id in used:
        event_id = f"{base}_{suffix}"
        suffix += 1
    event = {
        "id": event_id,
        "order": extra.pop("order", getattr(node, "lineno", len(events) + 1)),
        "kind": kind,
        "resource": resource,
        "operation": operation,
        "path_coverage": extra.pop("path_coverage", "must"),
        "guard_id": extra.pop("guard_id", None),
        "predecessors_must": list(predecessors),
        "control_depends_on": [],
        "atomicity": extra.pop("atomicity", "not_applicable"),
        "tls_verify": "not_applicable",
        "_source_validated": True,
        **extra,
    }
    events.append(event)
    return event_id


def _content_type_events(facts, tree, parents):
    for call in ast.walk(tree):
        if not isinstance(call, ast.Call) or not isinstance(call.func, ast.Attribute):
            continue
        if call.func.attr != "json":
            continue
        canonical = _text(call.func.value) or "request"
        resource = _ensure_resource(facts, canonical, "http_request", "param", "external_mutable")
        paths = _if_paths(call, parents)
        provenance = _content_type_provenance(call, canonical, parents)
        positive_guards = [node for node, branch in paths if branch is True]
        predicates = set().union(*(
            _media_predicates(node.test, provenance) for node in positive_guards
        ))
        parsed_messages = {
            item.split(":", 1)[1] for item in predicates if item.startswith("main:")
        } & {
            item.split(":", 1)[1] for item in predicates if item.startswith("sub:")
        }
        guarded = "full" in predicates or bool(parsed_messages)
        predecessors = []
        guard_id = None
        if guarded:
            relevant = [
                node for node in positive_guards
                if _media_predicates(node.test, provenance)
            ]
            guard_node = max(relevant, key=lambda node: node.lineno)
            guard_id = f"content_type_{call.lineno}"
            predecessors.append(_append_event(
                facts, "CONTENT_TYPE_CHECK", resource, guard_node,
                " and ".join(_text(node.test) for node in relevant),
                path_coverage="guarded", guard_id=guard_id,
            ))
        _append_event(
            facts, "JSON_PARSE", resource, call, _text(call), predecessors,
            path_coverage="guarded" if guarded else "must", guard_id=guard_id,
        )


def _ssl_context_events(facts, tree, parents):
    loads = [
        call for call in ast.walk(tree)
        if isinstance(call, ast.Call)
        and isinstance(call.func, ast.Attribute)
        and call.func.attr == "load_default_certs"
    ]
    receivers = {_text(call.func.value) or "context" for call in loads}
    creations = {canonical: [] for canonical in receivers}
    for assignment in (node for node in ast.walk(tree) if isinstance(node, (ast.Assign, ast.AnnAssign))):
        value = assignment.value
        if not isinstance(value, ast.Call):
            continue
        targets = assignment.targets if isinstance(assignment, ast.Assign) else [assignment.target]
        for target in targets:
            canonical = _text(target)
            if canonical in receivers:
                creations[canonical].append((assignment, _condition_terms(assignment, parents)))

    creation_events = {canonical: [] for canonical in receivers}
    for canonical, candidates in creations.items():
        resource = _ensure_resource(facts, canonical, "tls_context")
        for node, conditions in candidates:
            creation_events[canonical].append((
                node.lineno,
                _append_event(facts, "SSL_CONTEXT_CREATE", resource, node, _text(node), path_coverage="guarded"),
                conditions,
            ))

    for call in loads:
        canonical = _text(call.func.value) or "context"
        resource = _ensure_resource(facts, canonical, "tls_context")
        conditions = _condition_terms(call, parents)
        candidates = [
            creation for creation in creation_events.get(canonical, ())
            if creation[0] < call.lineno and creation[2] <= conditions
        ]
        creation = max(candidates, key=lambda item: item[0]) if candidates else None
        correct_state = creation is not None
        predecessors = [creation[1]] if correct_state else []
        _append_event(
            facts, "CERT_DEFAULT_LOAD", resource, call, _text(call), predecessors,
            path_coverage="guarded", guard_id=f"ssl_context_{call.lineno}" if correct_state else None,
        )


def _flag_name(node):
    if isinstance(node, ast.Attribute) and node.attr.startswith("O_"):
        return node.attr
    if isinstance(node, ast.Name) and node.id.startswith("O_"):
        return node.id
    return None


def _evaluate_flag_expression(node, current, variable=None):
    flag = _flag_name(node)
    if flag:
        return {flag}
    if isinstance(node, ast.Name) and node.id == variable:
        return set(current)
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.BitOr):
        return (
            _evaluate_flag_expression(node.left, current, variable)
            | _evaluate_flag_expression(node.right, current, variable)
        )
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.BitAnd):
        left = _evaluate_flag_expression(node.left, current, variable)
        if isinstance(node.right, ast.UnaryOp) and isinstance(node.right.op, ast.Invert):
            return left - _evaluate_flag_expression(node.right.operand, current, variable)
        right = _evaluate_flag_expression(node.right, current, variable)
        return left & right
    return set()


def _flag_expression(tree, call, parents):
    argument = call.args[1] if len(call.args) >= 2 else next(
        (keyword.value for keyword in call.keywords if keyword.arg == "flags"), None,
    )
    if argument is None:
        return set(), {}
    if not isinstance(argument, ast.Name):
        return _evaluate_flag_expression(argument, set()), {}
    name = argument.id
    state = set()
    provenance = {}
    for node in _ordered_dominating_assignments(call, parents):
        targets = node.targets if isinstance(node, ast.Assign) else [node.target]
        if not any(isinstance(target, ast.Name) and target.id == name for target in targets):
            continue
        previous = set(state)
        if isinstance(node, ast.AugAssign):
            value = _evaluate_flag_expression(node.value, state, name)
            if isinstance(node.op, ast.BitOr):
                state |= value
            elif isinstance(node.op, ast.BitAnd):
                if isinstance(node.value, ast.UnaryOp) and isinstance(node.value.op, ast.Invert):
                    state -= _evaluate_flag_expression(node.value.operand, state, name)
                else:
                    state &= value
            else:
                state = set()
        else:
            state = _evaluate_flag_expression(node.value, state, name)
        for removed in previous - state:
            provenance.pop(removed, None)
        for added in state - previous:
            provenance[added] = node
        if not isinstance(node, ast.AugAssign):
            for retained in state & previous:
                if retained not in _evaluate_flag_expression(node.value, set(), name):
                    provenance[retained] = node
    return state, provenance


def _handler_may_catch(handler, raised):
    if handler.type is None:
        return True
    raised_type = None
    if isinstance(raised.exc, ast.Call):
        raised_type = _text(raised.exc.func).rsplit(".", 1)[-1]
    elif isinstance(raised.exc, (ast.Name, ast.Attribute)):
        raised_type = _text(raised.exc).rsplit(".", 1)[-1]
    if raised_type is None:
        return True
    names = {
        _text(item).rsplit(".", 1)[-1]
        for item in (handler.type.elts if isinstance(handler.type, ast.Tuple) else [handler.type])
    }
    return raised_type in names or bool(names & {"Exception", "BaseException"})


def _block_exits(statements):
    raises = []
    can_continue = True
    for statement in statements:
        if not can_continue:
            break
        if isinstance(statement, ast.Raise):
            raises.append(statement)
            can_continue = False
        elif isinstance(statement, ast.Return):
            can_continue = False
        elif isinstance(statement, ast.If):
            body_continues, body_raises = _block_exits(statement.body)
            else_continues, else_raises = _block_exits(statement.orelse)
            raises.extend(body_raises)
            raises.extend(else_raises)
            can_continue = body_continues or else_continues
    return can_continue, raises


def _child_under(node, ancestor, parents):
    child = node
    while child in parents and parents[child] is not ancestor:
        child = parents[child]
    return child


def _raise_blocks_acquisition(raised, call, parents):
    for control in _ancestors(raised, parents, ast.Try):
        raised_child = _child_under(raised, control, parents)
        if raised_child not in control.body:
            continue
        call_child = _child_under(call, control, parents)
        if call_child in control.finalbody:
            return False
        if call_child in control.body or call_child in control.orelse:
            continue
        matching = next(
            (handler for handler in control.handlers if _handler_may_catch(handler, raised)),
            None,
        )
        if matching is None:
            continue
        if call_child is matching:
            return False
        can_continue, reraises = _block_exits(matching.body)
        if can_continue:
            return False
        if not all(_raise_blocks_acquisition(item, call, parents) for item in reraises):
            return False
        return True
    return True


def _reparse_guard(tree, call, path, parents):
    function = _nearest_function(call, parents)
    for node in ast.walk(function or tree):
        if not isinstance(node, ast.If) or not _dominates_statement(node, call, parents):
            continue
        test = _text(node.test)
        raises = [item for item in node.body if isinstance(item, ast.Raise)]
        if (
            "reparse" in test.lower()
            and path in test
            and raises
            and all(_raise_blocks_acquisition(item, call, parents) for item in raises)
        ):
            return node
    return None


def _filesystem_events(facts, tree, parents):
    for call in ast.walk(tree):
        if not isinstance(call, ast.Call) or _text(call.func) != "os.open":
            continue
        flags, flag_sources = _flag_expression(tree, call, parents)
        if "O_TRUNC" not in flags:
            continue
        path = call.args[0] if call.args else next(
            (keyword.value for keyword in call.keywords if keyword.arg == "path"), None,
        )
        if path is None:
            continue
        canonical = _text(path) or "path"
        resource = _ensure_resource(facts, canonical, "filesystem_path", "param", "external_mutable")
        guard_node = None
        if "O_NOFOLLOW" in flags:
            guard_node = flag_sources.get("O_NOFOLLOW", call)
        else:
            guard_node = _reparse_guard(tree, call, canonical, parents)
        predecessors = []
        if guard_node is not None:
            protection = "nofollow" if "O_NOFOLLOW" in flags else "reparse"
            guard_order = call.lineno - 0.1 if guard_node is call else guard_node.lineno
            predecessors.append(_append_event(
                facts, "FS_NOFOLLOW_GUARD", resource, guard_node,
                "O_NOFOLLOW" if protection == "nofollow" else _text(guard_node.test),
                protection=protection, order=guard_order,
            ))
            for event in facts.get("events", []):
                if event.get("kind") == "FS_USE" and "open" in str(event.get("operation", "")):
                    event["atomicity"] = "atomic"
        _append_event(facts, "FS_ACQUIRE", resource, call, _text(call), predecessors)


def validate_and_enrich(facts, function):
    """Replace security guard claims with events derived from function source."""
    if not isinstance(facts, dict):
        return None
    for field in (
        "resources", "ambient_contexts", "entry_states", "events",
        "exit_states", "calls", "uncertainties",
    ):
        value = facts.get(field)
        if value is not None and (
            not isinstance(value, list)
            or any(not isinstance(item, dict) for item in value)
        ):
            return None
    enriched = copy.deepcopy(facts)
    events = enriched.get("events")
    if not isinstance(events, list):
        return None
    enriched["events"] = []
    for event in events:
        if event.get("kind") in SOURCE_EVENT_KINDS:
            continue
        operation = str(event.get("operation", "")).lower()
        left = operation.split("=", 1)[0].strip()
        response_metadata = (
            event.get("kind") == "STATE_CHANGE"
            and (
                left in {"response", "raw_response"}
                or left.startswith(("response.", "raw_response."))
                or operation.startswith(("response.", "raw_response."))
            )
        )
        if not response_metadata:
            enriched["events"].append(event)
    try:
        source = textwrap.dedent(function.source)
        tree = ast.parse(source)
    except (IndentationError, SyntaxError, TypeError):
        return enriched
    parents = _parents(tree)
    _content_type_events(enriched, tree, parents)
    _ssl_context_events(enriched, tree, parents)
    _filesystem_events(enriched, tree, parents)
    if any(event.get("kind") == "JSON_PARSE" for event in enriched["events"]):
        resources = {item.get("id"): item for item in enriched.get("resources") or []}
        non_lifecycle = {
            resource_id for resource_id, resource in resources.items()
            if resource.get("kind") in {"generic_resource", "http_request", "csrf_token"}
        }
        enriched["events"] = [
            event for event in enriched["events"]
            if not (event.get("kind", "").startswith("RESOURCE_") and event.get("resource") in non_lifecycle)
        ]
        enriched["exit_states"] = [
            state for state in enriched.get("exit_states") or []
            if state.get("resource") not in non_lifecycle
        ]
    if any(event.get("kind") == "CERT_DEFAULT_LOAD" for event in enriched["events"]):
        enriched["events"] = [
            event for event in enriched["events"]
            if not (
                event.get("kind") == "NETWORK_USE"
                and event.get("tls_verify") != "disabled"
                and "wrap_socket" in str(event.get("operation", ""))
            )
        ]
    source_protocol = any(
        event.get("_source_validated")
        and event.get("kind") in {"JSON_PARSE", "CERT_DEFAULT_LOAD", "FS_ACQUIRE"}
        for event in enriched["events"]
    )
    if source_protocol:
        tls_kinds = {"TLS_VERIFY_DISABLE", "TLS_VERIFY_ENABLE", "TLS_HANDSHAKE_VERIFY", "NETWORK_USE"}
        enriched["events"] = [
            event for event in enriched["events"]
            if event.get("_source_validated") or event.get("kind") in tls_kinds
        ]
        used = {event.get("resource") for event in enriched["events"] if event.get("resource") is not None}
        enriched["resources"] = [
            resource for resource in enriched.get("resources") or [] if resource.get("id") in used
        ]
        enriched["entry_states"] = []
        enriched["exit_states"] = []
        enriched["calls"] = []
    return enriched


def source_only_facts(function):
    """Build facts only when source validation recognizes a complete protocol."""
    facts = validate_and_enrich({
        "schema_version": "typestate.v1",
        "function": function.id.name,
        "function_role": "internal_helper",
        "language": function.id.language,
        "resources": [],
        "ambient_contexts": [],
        "entry_states": [],
        "events": [],
        "exit_states": [],
        "calls": [],
        "uncertainties": [],
    }, function)
    if facts and any(
        event.get("_source_validated")
        and event.get("kind") in SOURCE_PROTOCOL_TRIGGERS
        for event in facts.get("events") or ()
    ):
        return facts
    return None

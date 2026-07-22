"""Validate IFC facts and add source-settled observability facts.

The LLM derives dependencies and domain sensitivity. This module owns the
parts source syntax can settle more reliably: whether detailed caught errors
reach a public error/exception message or only a trusted logger, and whether a
nested secret bypasses a framework's normal redaction path.
"""

from __future__ import annotations

import ast
import copy
import re
import textwrap
from collections.abc import Mapping


HIGH = "High"
LOW = "Low"
UNKNOWN = "Unknown"

OBSERVABILITIES = frozenset({"external", "caller", "internal"})
SINK_CHANNELS = frozenset({
    "return", "exception_control", "exception_message", "error_detail",
    "log", "stdout", "network", "database", "shared_state", "parameter",
    "unknown",
})
_SENSITIVE_FIELD = re.compile(
    r"(^|_)(?:pass(?:word)?|pw|secret|token|credential|private(?:_key)?|api_key|auth)(?:_|$)",
    re.IGNORECASE,
)
_ERROR_NAME = re.compile(
    r"(^|_)(?:exc|exception|error|failure|cause)(?:_|$)", re.IGNORECASE
)
_EXTERNAL_MESSAGE_NAME = re.compile(
    r"(?:message|notice|alert|flash|response|error)$", re.IGNORECASE
)
_TERMINATING_CALL = re.compile(
    r"(?:fail|abort|reject|deny|raise|exit)", re.IGNORECASE
)
_GENERIC_CONTAINER = re.compile(
    r"^(?:params|parameters|options|extra|config|settings|kwargs|arguments)$",
    re.IGNORECASE,
)
_CONVENTIONAL_LOW_FIELDS = frozenset({
    "id", "name", "url", "host", "port", "path", "timeout", "count",
    "index", "flag", "state", "value", "values",
})


def infer_sink_channel(channel: str) -> str:
    leaf = channel.rsplit(":", 1)[-1].lower()
    if channel == "return":
        return "return"
    if channel == "exception":
        return "exception_control"
    if channel.startswith("exception:"):
        return "exception_message"
    if channel.startswith("error:") or "message" in leaf:
        return "error_detail"
    if "log" in leaf:
        return "log"
    if leaf in {"stdout", "stderr", "console", "print"}:
        return "stdout"
    if leaf in {"http", "response", "network", "socket"}:
        return "network"
    if leaf in {"db", "database"}:
        return "database"
    if channel.startswith("global:"):
        return "shared_state"
    if channel.startswith("param:"):
        return "parameter"
    return "unknown"


def infer_observability(channel: str, sink_channel: str) -> str:
    if channel in {"return", "exception"} or channel.startswith("exception:"):
        return "caller"
    if sink_channel == "parameter":
        return "caller"
    # Legacy side-effect channels remain fail-closed external. New facts should
    # say "internal" explicitly for trusted telemetry.
    return "external"


def validate_and_enrich(signature, source: str, allow_composed: bool = False):
    """Return a sanitized/enriched flow signature, or ``None`` if malformed."""
    if not isinstance(signature, Mapping):
        return None
    inputs = signature.get("inputs", {})
    outputs = signature.get("outputs", {})
    if not isinstance(inputs, Mapping) or not isinstance(outputs, Mapping):
        return None

    clean = {
        key: copy.deepcopy(value)
        for key, value in signature.items()
        if isinstance(key, str)
        and (not key.startswith("_") or (allow_composed and key == "_callee_resolutions"))
    }
    clean_inputs = {}
    for name, label in inputs.items():
        if (
            not isinstance(name, str)
            or not isinstance(label, str)
            or label not in {HIGH, LOW, UNKNOWN}
        ):
            return None
        clean_inputs[name] = label

    clean_outputs = {}
    for channel, raw_spec in outputs.items():
        if not isinstance(channel, str) or not isinstance(raw_spec, Mapping):
            return None
        # Callee channels are produced only by deterministic composition. Model
        # output cannot assert pre-resolved side effects from a summary.
        if channel.startswith("callee:") and not allow_composed:
            continue
        spec = {
            key: copy.deepcopy(value)
            for key, value in raw_spec.items()
            if isinstance(key, str) and not key.startswith("_")
        }
        deps = spec.get("deps", [])
        if not isinstance(deps, list) or any(not isinstance(dep, str) for dep in deps):
            return None
        const = spec.get("const")
        if const is not None and (not isinstance(const, str) or const not in {HIGH, LOW}):
            return None
        declass = spec.get("declass", [])
        if not isinstance(declass, list):
            return None
        sink_channel = spec.get("sink_channel", infer_sink_channel(channel))
        observability = spec.get(
            "observability", infer_observability(channel, sink_channel)
        )
        if (
            not isinstance(sink_channel, str)
            or sink_channel not in SINK_CHANNELS
            or not isinstance(observability, str)
            or observability not in OBSERVABILITIES
        ):
            return None
        declared_cwe = spec.get("cwe")
        if declared_cwe is not None and not isinstance(declared_cwe, str):
            return None
        spec["deps"] = deps
        spec["sink_channel"] = sink_channel
        spec["observability"] = observability
        clean_outputs[channel] = spec

    clean["inputs"] = clean_inputs
    clean["outputs"] = clean_outputs
    _enrich_python_source(clean, source)
    return clean


def source_only_fallback(source: str):
    """Return facts only when source syntax settles an IFC boundary."""
    try:
        tree = ast.parse(textwrap.dedent(source))
    except (SyntaxError, TypeError, ValueError):
        return None
    signature = {"inputs": {}, "outputs": {}, "notes": "source-settled fallback"}
    _enrich_nested_secret_bypass(signature, tree)
    _enrich_error_channels(signature, tree)
    _enrich_internal_persistence(signature, tree)
    _enrich_constant_exception_control(signature)
    _enrich_constant_return(signature, tree)
    _ground_receiver_dependencies(signature, tree)
    if signature["outputs"]:
        return signature
    return None


def _enrich_python_source(signature: dict, source: str) -> None:
    try:
        tree = ast.parse(textwrap.dedent(source))
    except (SyntaxError, TypeError, ValueError):
        return

    _enrich_conventional_low_labels(signature)
    _enrich_called_receiver_labels(signature, tree)
    _enrich_declared_parameter_labels(signature, tree)
    _enrich_nested_secret_bypass(signature, tree)
    _enrich_error_channels(signature, tree)
    _enrich_internal_persistence(signature, tree)
    _enrich_constant_exception_control(signature)
    _enrich_constant_return(signature, tree)


def _source_text(node: ast.AST) -> str:
    try:
        return ast.unparse(node)
    except (AttributeError, ValueError):
        return ""


def _enrich_conventional_low_labels(signature: dict) -> None:
    for name, label in signature["inputs"].items():
        if label == UNKNOWN and _field_name(name).lower() in _CONVENTIONAL_LOW_FIELDS:
            signature["inputs"][name] = LOW


def _enrich_called_receiver_labels(signature: dict, tree: ast.AST) -> None:
    called = {
        node.func.attr
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and _canonical_expr(node.func.value) in {"self", "cls"}
    }
    for name, label in signature["inputs"].items():
        if (
            label == UNKNOWN
            and name.startswith("receiver.")
            and _field_name(name) in called
        ):
            signature["inputs"][name] = LOW


def _enrich_declared_parameter_labels(signature: dict, tree: ast.AST) -> None:
    declared = set()

    def collect_keywords(node: ast.AST) -> None:
        if not isinstance(node, ast.Call):
            return
        for keyword in node.keywords:
            if keyword.arg:
                declared.add(keyword.arg)
            collect_keywords(keyword.value)

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        for keyword in node.keywords:
            if keyword.arg == "argument_spec":
                collect_keywords(keyword.value)

    for name, label in signature["inputs"].items():
        field = _field_name(name)
        if label == UNKNOWN and field in declared and not _SENSITIVE_FIELD.search(field):
            signature["inputs"][name] = LOW


def _enrich_internal_persistence(signature: dict, tree: ast.AST) -> None:
    local_session_write = any(
        isinstance(node, ast.Call)
        and ".session." in f".{_call_name(node)}."
        and _call_name(node).rsplit(".", 1)[-1]
        in {"add", "merge", "delete", "commit", "rollback", "flush"}
        for node in ast.walk(tree)
    )
    if not local_session_write:
        return
    for spec in signature["outputs"].values():
        if spec.get("sink_channel") == "database":
            spec["observability"] = "internal"


def _canonical_expr(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _canonical_expr(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    if isinstance(node, ast.Subscript):
        base = _canonical_expr(node.value)
        key = node.slice
        if isinstance(key, ast.Constant) and isinstance(key.value, str):
            return f"{base}.{key.value}" if base else key.value
    return ""


def _nested_merges(tree: ast.AST) -> list[tuple[int, str, str]]:
    merges = []
    for node in ast.walk(tree):
        if isinstance(node, ast.For):
            iterator = node.iter
            if (
                isinstance(iterator, ast.Call)
                and isinstance(iterator.func, ast.Attribute)
                and iterator.func.attr == "items"
            ):
                source = _canonical_expr(iterator.func.value)
                targets = {
                    _canonical_expr(target.value)
                    for stmt in node.body
                    for part in ast.walk(stmt)
                    if isinstance(part, (ast.Assign, ast.AnnAssign))
                    for target in (part.targets if isinstance(part, ast.Assign) else [part.target])
                    if isinstance(target, ast.Subscript)
                }
                if source and _GENERIC_CONTAINER.match(_field_name(source)):
                    merges.extend(
                        (getattr(node, "lineno", 0), source, target)
                        for target in targets if target
                    )
            continue
        if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
            continue
        if node.func.attr != "update" or not node.args:
            continue
        target = _canonical_expr(node.func.value)
        source = _canonical_expr(node.args[0])
        if (
            target
            and source.startswith(target + ".")
            and _GENERIC_CONTAINER.match(_field_name(source))
        ):
            merges.append((getattr(node, "lineno", 0), source, target))
    return merges


def _mentions_expr(node: ast.AST, expression: str) -> bool:
    return any(
        (value := _canonical_expr(part))
        and (value == expression or value.startswith(expression + "."))
        for part in ast.walk(node)
    )


def _local_nested_sinks(
    tree: ast.AST, merges: list[tuple[int, str, str]]
) -> set[tuple[str, str, str]]:
    sinks = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        name = _call_name(node)
        leaf = name.rsplit(".", 1)[-1]
        is_stdout = leaf in {"print", "pprint"} or ".stdout." in f".{name}."
        receiver = (
            _canonical_expr(node.func.value)
            if isinstance(node.func, ast.Attribute) else ""
        )
        is_serialized_invocation = leaf == "exit_json"
        if not is_stdout and not is_serialized_invocation:
            continue
        line = getattr(node, "lineno", 0)
        if any(
            merge_line < line
            and (
                (is_stdout and any(_mentions_expr(arg, target) for arg in node.args))
                or (
                    is_serialized_invocation
                    and receiver
                    and target.startswith(receiver + ".")
                )
            )
            for merge_line, _, target in merges
        ):
            sinks.add(("io:stdout", "stdout", "external"))
    return sinks


def _dependency_expr(dependency: str) -> str:
    if dependency.startswith("param:"):
        dependency = dependency[len("param:"):]
    if dependency.startswith("receiver."):
        dependency = "self." + dependency[len("receiver."):]
    return re.sub(r"\[['\"]([^'\"]+)['\"]\]", r".\1", dependency)


def _model_output_tracks_merge(
    spec: Mapping, merges: list[tuple[int, str, str]]
) -> bool:
    for dependency in spec.get("deps", []):
        if any(_source_tracks_merge(dependency, merge) for merge in merges):
            return True
    return False


def _source_tracks_merge(source: str, merge: tuple[int, str, str]) -> bool:
    value = _dependency_expr(source)
    _, nested, target = merge
    return any(
        value == candidate
        or value.startswith(candidate + ".")
        or candidate.startswith(value + ".")
        for candidate in (nested, target)
    ) or value == _field_name(nested)


def _unresolved_merge_sources(
    signature: Mapping,
    merge: tuple[int, str, str],
    protected: Mapping,
) -> list[str]:
    explicit = [
        source for source, label in signature["inputs"].items()
        if label == HIGH and _source_tracks_merge(source, merge)
    ]
    concrete = [source for source in explicit if not source.endswith(".<sensitive>")]
    unresolved = [
        source for source in concrete
        if not _references_rejected_field(source, protected)
    ]
    if unresolved:
        return unresolved
    if concrete or protected:
        return []
    if explicit:
        return explicit
    return [f"param:{merge[1]}.<sensitive>"]


def _statement_terminates(statement: ast.stmt) -> bool:
    if isinstance(statement, ast.Raise):
        return True
    if (
        isinstance(statement, ast.Expr)
        and isinstance(statement.value, ast.Call)
        and _TERMINATING_CALL.search(_call_name(statement.value).rsplit(".", 1)[-1])
    ):
        return True
    if isinstance(statement, ast.If) and statement.orelse:
        return _block_terminates(statement.body) and _block_terminates(statement.orelse)
    return False


def _block_terminates(statements: list[ast.stmt]) -> bool:
    return any(_statement_terminates(statement) for statement in statements)


def _rejection_guard(statement: ast.stmt) -> tuple[str, str] | None:
    if not isinstance(statement, ast.If) or not _block_terminates(statement.body):
        return None
    test = statement.test
    if (
        not isinstance(test, ast.Compare)
        or len(test.ops) != 1
        or not isinstance(test.ops[0], ast.In)
        or len(test.comparators) != 1
        or not isinstance(test.left, ast.Constant)
        or not isinstance(test.left.value, str)
        or not _SENSITIVE_FIELD.search(test.left.value)
    ):
        return None
    container = _canonical_expr(test.comparators[0])
    if not container:
        return None
    return test.left.value, container


def _sensitive_field_overwrite(statement: ast.stmt) -> tuple[str, str] | None:
    if isinstance(statement, ast.Expr) and isinstance(statement.value, ast.Call):
        call = statement.value
        if (
            isinstance(call.func, ast.Attribute)
            and call.func.attr == "pop"
            and call.args
            and isinstance(call.args[0], ast.Constant)
            and isinstance(call.args[0].value, str)
            and _SENSITIVE_FIELD.search(call.args[0].value)
        ):
            container = _canonical_expr(call.func.value)
            if container:
                return call.args[0].value, container

    targets = []
    if isinstance(statement, ast.Delete):
        targets = statement.targets
    elif isinstance(statement, (ast.Assign, ast.AnnAssign)):
        if not isinstance(statement.value, ast.Constant):
            return None
        targets = statement.targets if isinstance(statement, ast.Assign) else [statement.target]
    for target in targets:
        expression = _canonical_expr(target)
        field = _field_name(expression)
        if expression and _SENSITIVE_FIELD.search(field) and "." in expression:
            return field, expression.rsplit(".", 1)[0]
    return None


def _child_statement_blocks(statement: ast.stmt) -> list[list[ast.stmt]]:
    blocks = []
    for field in ("body", "orelse", "finalbody"):
        value = getattr(statement, field, None)
        if isinstance(value, list) and all(isinstance(item, ast.stmt) for item in value):
            blocks.append(value)
    for handler in getattr(statement, "handlers", []):
        if isinstance(handler, ast.ExceptHandler):
            blocks.append(handler.body)
    for case in getattr(statement, "cases", []):
        body = getattr(case, "body", None)
        if isinstance(body, list) and all(isinstance(item, ast.stmt) for item in body):
            blocks.append(body)
    return blocks


def _dominating_rejected_fields(
    tree: ast.AST, merges: list[tuple[int, str, str]]
) -> dict[tuple[int, str, str], set[str]]:
    by_line = {}
    for merge in merges:
        by_line.setdefault(merge[0], []).append(merge)
    dominated = {merge: set() for merge in merges}

    def visit_block(
        statements: list[ast.stmt], active: list[tuple[str, str]]
    ) -> None:
        active = list(active)
        for statement in statements:
            for merge in by_line.get(getattr(statement, "lineno", 0), []):
                for field, container in active:
                    if container == merge[1]:
                        dominated[merge].add(field)
            for block in _child_statement_blocks(statement):
                visit_block(block, active)
            guard = _rejection_guard(statement)
            if guard is not None:
                active.append(guard)
            overwrite = _sensitive_field_overwrite(statement)
            if overwrite is not None:
                active.append(overwrite)

    body = getattr(tree, "body", [])
    if isinstance(body, list):
        visit_block(body, [])
    return dominated


def _field_name(source: str) -> str:
    source = re.sub(r"\[['\"]([^'\"]+)['\"]\]", r".\1", source)
    return source.rsplit(".", 1)[-1].rsplit(":", 1)[-1]


def _references_rejected_field(source: str, rejected: Mapping) -> bool:
    field = _field_name(source)
    return any(
        re.search(rf"(^|_){re.escape(name)}(?:_|$)", field, re.IGNORECASE)
        for name in rejected
    )


def _references_receiver_field(tree: ast.AST, dependency: str) -> bool:
    if not dependency.startswith("receiver."):
        return False
    suffix = _dependency_expr(dependency)[len("self."):]
    expected = {f"self.{suffix}", f"cls.{suffix}"}
    return any(
        (expression := _canonical_expr(node)) in expected
        or any(expression.startswith(candidate + ".") for candidate in expected)
        for node in ast.walk(tree)
        if isinstance(node, ast.Attribute)
    )


def _ground_receiver_dependencies(signature: dict, tree: ast.AST) -> None:
    """Remove model receiver facts that are not rooted at self/cls in source."""
    candidates = {
        name for name in signature["inputs"] if name.startswith("receiver.")
    }
    candidates.update(
        dependency
        for spec in signature["outputs"].values()
        for dependency in spec.get("deps", [])
        if dependency.startswith("receiver.")
    )
    unsupported = {
        dependency for dependency in candidates
        if not _references_receiver_field(tree, dependency)
    }
    for dependency in unsupported:
        signature["inputs"].pop(dependency, None)
    for spec in signature["outputs"].values():
        spec["deps"] = [
            dependency for dependency in spec.get("deps", [])
            if dependency not in unsupported
        ]


def _enrich_nested_secret_bypass(signature: dict, tree: ast.AST) -> None:
    merges = _nested_merges(tree)
    if not merges:
        return
    local_sinks = _local_nested_sinks(tree, merges)
    dominated = _dominating_rejected_fields(tree, merges)
    unresolved = {
        merge: _unresolved_merge_sources(signature, merge, dominated[merge])
        for merge in merges
    }
    unresolved_merges = [merge for merge in merges if unresolved[merge]]
    rejected = {
        field: True
        for fields in dominated.values()
        for field in fields
    }

    def is_resolved(source: str) -> bool:
        relevant = [merge for merge in merges if _source_tracks_merge(source, merge)]
        if relevant:
            return all(
                _references_rejected_field(source, dominated[merge])
                for merge in relevant
            )
        return _references_rejected_field(source, rejected)

    blocked = {
        name
        for name in signature["inputs"]
        if is_resolved(name)
    }
    if blocked:
        for name in blocked:
            signature["inputs"].pop(name, None)
        for spec in signature["outputs"].values():
            spec["deps"] = [
                dep for dep in spec.get("deps", [])
                if dep not in blocked and not is_resolved(dep)
            ]

    if not unresolved_merges:
        for spec in signature["outputs"].values():
            spec["deps"] = [
                dep for dep in spec.get("deps", [])
                if not is_resolved(dep)
            ]
            if _model_output_tracks_merge(spec, merges):
                spec["deps"] = [
                    dep for dep in spec.get("deps", [])
                    if not (
                        dep.startswith("receiver.")
                        and signature["inputs"].get(dep, UNKNOWN) == UNKNOWN
                        and not _references_receiver_field(tree, dep)
                    )
                ]
            if spec.get("sink_channel") == "error_detail":
                # Replace model guesses for this source-settled boundary. The
                # rejection text is constant; concrete caught-error flows are
                # independently rebuilt by _enrich_error_channels below.
                spec["deps"] = []
                spec["const"] = LOW
                spec["declass"] = []
        for channel, sink, observability in local_sinks:
            _set_output(
                signature, channel, [], sink, observability, replace=True
            )
        return

    evidenced = [
        (channel, spec)
        for channel, spec in signature["outputs"].items()
        if spec.get("observability") != "internal"
        and _model_output_tracks_merge(spec, unresolved_merges)
    ]
    for channel, sink, observability in _local_nested_sinks(tree, unresolved_merges):
        _set_output(signature, channel, [], sink, observability)
        evidenced.append((channel, signature["outputs"][channel]))
    if not evidenced:
        return

    # A merge establishes only its unresolved sensitive sources. A flow is
    # added only to a sink already supplied by model evidence or local AST.
    sources = list(dict.fromkeys(
        source for merge in unresolved_merges for source in unresolved[merge]
    ))
    for source in sources:
        signature["inputs"][source] = HIGH
    for _, spec in evidenced:
        spec["deps"] = list(dict.fromkeys([*spec.get("deps", []), *sources]))
        if spec.get("sink_channel") != "log":
            spec["cwe"] = "CWE-200"


def _enrich_constant_exception_control(signature: dict) -> None:
    for channel, spec in signature["outputs"].items():
        sink = spec.get("sink_channel") or infer_sink_channel(channel)
        if sink == "exception_control" and not spec.get("deps") and spec.get("const") == HIGH:
            # An unconditional exception occurrence is the same on every run;
            # without a dependency it conveys no information about High data.
            spec["const"] = LOW
            spec["declass"] = []


def _call_name(node: ast.Call) -> str:
    parts = []
    current = node.func
    while isinstance(current, ast.Attribute):
        parts.append(current.attr)
        current = current.value
    if isinstance(current, ast.Name):
        parts.append(current.id)
    return ".".join(reversed(parts))


def _target_names(target: ast.AST) -> set[str]:
    if isinstance(target, ast.Name):
        return {target.id}
    if isinstance(target, (ast.Tuple, ast.List)):
        return {name for item in target.elts for name in _target_names(item)}
    return set()


def _contains_error_detail(node: ast.AST | None, sensitive: set[str], tainted: set[str]) -> bool:
    if node is None:
        return False
    for part in ast.walk(node):
        if isinstance(part, ast.Name) and part.id in sensitive | tainted:
            return True
        if isinstance(part, ast.Call) and _call_name(part).endswith("sys.exc_info"):
            return True
    return False


def _enrich_error_channels(signature: dict, tree: ast.AST) -> None:
    sensitive = {
        node.name for node in ast.walk(tree)
        if isinstance(node, ast.ExceptHandler) and isinstance(node.name, str)
    }
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for arg in (*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs):
            if _ERROR_NAME.search(arg.arg):
                sensitive.add(arg.arg)
    if not sensitive:
        return

    tainted = set()
    changed = True
    while changed:
        changed = False
        for node in ast.walk(tree):
            targets = []
            value = None
            if isinstance(node, (ast.Assign, ast.AnnAssign)):
                targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                value = node.value
            elif isinstance(node, ast.AugAssign):
                targets, value = [node.target], node.value
            if value is not None and _contains_error_detail(value, sensitive, tainted):
                additions = {name for target in targets for name in _target_names(target)}
                if not additions <= tainted:
                    tainted.update(additions)
                    changed = True

    error_source = "caught:error_detail"
    detailed_logs = False
    detailed_messages = False
    has_message_assignment = False
    detailed_raised_message = False
    has_raised_message = False
    for node in ast.walk(tree):
        if isinstance(node, (ast.Assign, ast.AnnAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            if any(_EXTERNAL_MESSAGE_NAME.search(_source_text(target)) for target in targets):
                has_message_assignment = True
                if _contains_error_detail(node.value, sensitive, tainted):
                    detailed_messages = True
        if isinstance(node, ast.Call):
            name = _call_name(node)
            if name.rsplit(".", 1)[-1] in {"debug", "info", "warning", "error", "exception", "critical"}:
                if any(_contains_error_detail(arg, sensitive, tainted) for arg in node.args):
                    detailed_logs = True
        if isinstance(node, ast.Raise) and node.exc is not None:
            has_raised_message = True
            if _contains_error_detail(node.exc, sensitive, tainted):
                detailed_raised_message = True

    # Source-settled facts can refine dependencies, but logger syntax does not
    # establish whether the configured destination is internal or external.
    if has_message_assignment:
        for channel, spec in list(signature["outputs"].items()):
            sink = spec.get("sink_channel") or infer_sink_channel(channel)
            if (sink == "error_detail" or channel.startswith("error:")
                    or channel == "exception"
                    or channel.startswith("param:self.message")):
                signature["outputs"].pop(channel)
    if detailed_logs:
        log_specs = [
            spec for channel, spec in signature["outputs"].items()
            if (spec.get("sink_channel") or infer_sink_channel(channel)) == "log"
        ]
        if log_specs:
            signature["inputs"][error_source] = HIGH
            for spec in log_specs:
                spec["deps"] = list(dict.fromkeys([
                    *spec.get("deps", []), error_source,
                ]))
    if detailed_messages:
        signature["inputs"][error_source] = HIGH
        _set_output(
            signature, "error:self.message", [error_source], "error_detail", "external",
            replace=True,
        )
    elif has_message_assignment:
        _set_output(
            signature, "error:self.message", [], "error_detail", "external",
            replace=True,
        )
    if has_raised_message:
        signature["outputs"].pop("exception:message", None)
        if detailed_raised_message:
            signature["inputs"][error_source] = HIGH
            _set_output(
                signature, "exception:message", [error_source],
                "exception_message", "caller", replace=True, cwe="CWE-200",
            )
        else:
            _set_output(
                signature, "exception:message", [], "exception_message", "caller",
                replace=True,
            )


def _enrich_constant_return(signature: dict, tree: ast.AST) -> None:
    returns = [node for node in ast.walk(tree) if isinstance(node, ast.Return)]
    if returns and not all(
        node.value is None or isinstance(node.value, ast.Constant)
        for node in returns
    ):
        return
    return_specs = [
        spec for channel, spec in signature["outputs"].items()
        if channel == "return" or spec.get("sink_channel") == "return"
    ]
    if not returns and not return_specs:
        return
    if not return_specs:
        _set_output(signature, "return", [], "return", "caller", replace=True)
        return_specs = [signature["outputs"]["return"]]
    for spec in return_specs:
        spec["deps"] = []
        spec["const"] = LOW
        spec["declass"] = []


def _set_output(
    signature: dict,
    channel: str,
    deps: list[str],
    sink_channel: str,
    observability: str,
    replace: bool = False,
    cwe: str | None = None,
) -> None:
    old = signature["outputs"].get(channel, {})
    old_deps = [] if replace else list(old.get("deps", []))
    merged = list(dict.fromkeys([*old_deps, *deps]))
    output = {
        "deps": merged,
        "const": None,
        "declass": [] if replace else list(old.get("declass", [])),
        "sink_channel": sink_channel,
        "observability": observability,
    }
    if cwe:
        output["cwe"] = cwe
    signature["outputs"][channel] = output

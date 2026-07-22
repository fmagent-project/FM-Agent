"""Integrity-taint plugin: injection detection (SQLi/cmd/path/SSRF/XSS/deser/...).

The DUAL of the IFC plugin on the shared substrate:
  - abstraction  : taint_prompts (sources + typed sinks + typed sanitizers + flows)
  - checker      : taint_reasoner.classify (source->sink reachability, typed
                   sanitizer matching, 3-status lattice, verdict precedence)
  - composition  : BOTTOM-UP (like IFC, unlike authz). A callee's parametric sink
                   ("param:x reaches sql_query unsanitized") is instantiated at
                   the caller's call site with the caller's actual argument taint;
                   if the caller passes a tainted arg, the caller inherits the
                   finding. No top-down pass needed (Oracle: taint is discharged
                   at sink sites; unknown-param taint stays POLYMORPHIC until a
                   caller instantiates it).

Verdicts: VULNERABLE / SANITIZED / POLYMORPHIC / SAFE / ERROR.
"""

from __future__ import annotations

import ast
import re
import textwrap
from typing import Dict, List, Optional, Sequence

from config import TAINT_MODEL
from src.taint_prompts import _system_prompt, _user_prompt, _extract_taint_json
from src.taint_reasoner import (
    classify, instantiate_sink, instantiate_flows, validate,
    VULNERABLE, SANITIZED, POLYMORPHIC, SAFE, ERROR,
)
from src.taint_validation import (
    call_args_from_bindings,
    merge_call_args_with_bindings,
    source_rel_from_extracted,
    validation_guard_coverage,
    validation_guard_coverage_for_call,
)
from src.plugins.base import (
    AbstractionRequest,
    AnalysisPlugin,
    Diagnostic,
    DriverContext,
    FactEnvelope,
    Finding,
    PluginMetadata,
    ResolvedCall,
    Verdict,
)


def _summarize(payload: dict, fn_name: str) -> str:
    """Concise callee summary for caller prompts: which params reach which sinks."""
    if not payload:
        return f"{fn_name}: (no taint facts)"
    parts = []
    for k in payload.get("sinks") or []:
        srcs = ",".join((fl.get("source") or "?") for fl in (k.get("flows") or []))
        parts.append(f"{k.get('sink_kind')}({k.get('arg_context')})<-{{{srcs}}}")
    rets = payload.get("return_flows") or []
    if rets:
        rs = ",".join((fl.get("source") or "?")
                      for r in rets for fl in (r.get("flows") or []))
        if rs:
            parts.append(f"return<-{{{rs}}}")
    for guard in payload.get("validation_guards") or []:
        if not isinstance(guard, dict):
            continue
        parts.append(
            f"guard:{guard.get('guard_kind')}({guard.get('input_expr')})"
            f"[{guard.get('coverage')}/{guard.get('failure_mode')}]"
        )
    summary = f"{fn_name}: " + ("; ".join(parts) if parts else "(no sinks)")
    return summary[:4096]


def _match_call_site(caller_call_sites, callee_name):
    """Find the caller's LLM-recorded call_site facts for a callee (by name)."""
    for cs in caller_call_sites or []:
        c = (cs.get("callee") or "")
        if c == callee_name or c.endswith("." + callee_name) or c.split(".")[-1] == callee_name:
            return cs
    return None


def _python_calls(source: str) -> list:
    try:
        tree = ast.parse(textwrap.dedent(source))
    except SyntaxError:
        return []
    return [node.func for node in ast.walk(tree) if isinstance(node, ast.Call)]


def _python_function(source: str):
    try:
        tree = ast.parse(textwrap.dedent(source))
    except SyntaxError:
        return None
    return next(
        (
            node for node in ast.walk(tree)
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        ),
        None,
    )


def _source_backed_dotted_member(expr: str, source: str) -> Optional[str]:
    try:
        member = ast.parse(expr, mode="eval").body
        tree = ast.parse(textwrap.dedent(source))
    except SyntaxError:
        return None
    if not isinstance(member, ast.Attribute):
        return None
    root = member.value
    while isinstance(root, ast.Attribute):
        root = root.value
    if not isinstance(root, ast.Name):
        return None
    normalized = ast.unparse(member)
    return normalized if any(
        isinstance(node, ast.Attribute) and ast.unparse(node) == normalized
        for node in ast.walk(tree)
    ) else None


def _function_params(unit) -> list:
    if unit.id.language.lower() != "python":
        return list(unit.params)
    function = _python_function(unit.source)
    if function is None:
        return list(unit.params)
    params = [*function.args.posonlyargs, *function.args.args]
    return [arg.arg for arg in params if arg.arg not in {"self", "cls"}]


def _python_call_actuals(caller, callee, param_name: str) -> list:
    function = _python_function(callee.source)
    if function is None:
        return []
    params = [
        arg.arg for arg in [*function.args.posonlyargs, *function.args.args]
        if arg.arg not in {"self", "cls"}
    ]
    try:
        position = params.index(param_name)
        tree = ast.parse(textwrap.dedent(caller.source))
    except (SyntaxError, ValueError):
        return []
    actuals = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        name = (
            node.func.id if isinstance(node.func, ast.Name)
            else node.func.attr if isinstance(node.func, ast.Attribute)
            else None
        )
        if name != callee.id.base_name:
            continue
        keyword = next((kw.value for kw in node.keywords if kw.arg == param_name), None)
        actual = keyword if keyword is not None else (
            node.args[position] if position < len(node.args) else None
        )
        if actual is not None:
            actuals.append(ast.unparse(actual))
    return actuals


def _has_call_operation(source: str, function_name: str, language: str) -> bool:
    """Reject regex call-graph edges caused by declarations and comments."""
    if language.lower() == "python":
        return any(
            (isinstance(call, ast.Name) and call.id == function_name)
            or (isinstance(call, ast.Attribute) and call.attr == function_name)
            for call in _python_calls(source)
        )
    uncommented = re.sub(r"(?m)(#|//).*?$", "", source)
    return bool(re.search(rf"\b{re.escape(function_name)}\s*\(", uncommented))


def _has_same_name_body_call(source: str, function_name: str, language: str) -> bool:
    """Only a bare same-name call is recursion; member dispatch is ambiguous."""
    if language.lower() == "python":
        return any(
            isinstance(call, ast.Name) and call.id == function_name
            for call in _python_calls(source)
        )
    uncommented = re.sub(r"(?m)(#|//).*?$", "", source)
    return len(re.findall(rf"\b{re.escape(function_name)}\s*\(", uncommented)) > 1


def _path_escape_flows(payload: dict, sink: dict) -> list:
    """Keep flows where a tainted segment is joined beneath a distinct root."""
    sources = {
        item.get("id"): item.get("expr")
        for item in (payload.get("taint_sources") or [])
        if isinstance(item, dict)
        and isinstance(item.get("id"), str)
        and isinstance(item.get("expr"), str)
    }
    arg_expr = str(sink.get("arg_expr") or "")
    compact_arg = re.sub(r"\s+", "", arg_expr)
    kept = []
    for flow in sink.get("flows") or []:
        if not isinstance(flow, dict):
            continue
        source_ref = flow.get("source")
        source_expr = None
        if isinstance(source_ref, str) and source_ref.startswith("param:"):
            source_expr = source_ref[len("param:"):]
        elif isinstance(source_ref, str) and source_ref.startswith("source:"):
            source_expr = sources.get(source_ref[len("source:"):])
        if not isinstance(source_expr, str) or not source_expr.strip():
            continue
        compact_source = re.sub(r"\s+", "", source_expr.strip())
        position = compact_arg.find(compact_source)
        if position <= 0:
            continue
        prefix = compact_arg[:position]
        if any(marker in prefix for marker in ("/", "join(", "joinpath(", "{")):
            kept.append(flow)
    return kept


def _source_proven_sink_kinds(source: str) -> set[str]:
    """Return sink families backed by concrete operations in the function source."""
    source_lower = source.lower()
    proven = set()
    markers = {
        "sql_query": (".execute(", ".executemany(", ".raw(", " raw("),
        "shell_command": (
            "os.system(", "exec(", "eval(", "shell=true", "shell = true",
        ),
        "subprocess_argv": (
            "subprocess.run(", "subprocess.call(", "subprocess.popen(",
            "check_call(", "check_output(",
        ),
        "fs_path": (
            "open(", ".read_text(", ".write_text(", ".unlink(", "send_file(",
            "shutil.", "os.remove(", "os.rename(", "os.replace(",
        ),
        "http_url_ssrf": (
            "requests.get(", "requests.post(", "requests.request(", "httpx.get(",
            "httpx.post(", "httpx.request(", "urlopen(", "urllib.request(",
        ),
        "redirect_location": ("redirect(", "redirectresponse("),
        "html_output": (
            "render_template(", "render_template_string(", "document.write(",
            ".innerhtml", "dangerouslysetinnerhtml", "httpresponse(",
            "make_response(", "response.write(", "markup(", "mark_safe(",
        ),
        "template_source": ("render_template_string(", "template(", "from_string("),
        "deserialize": (
            "pickle.load", "torch.load(", "torch_load(", "yaml.load(",
            "scan_file_path(",
        ),
        "code_eval": ("exec(", "eval("),
        "xpath": (".xpath(", "xpath(", "findall("),
    }
    for sink_kind, operations in markers.items():
        if any(operation in source_lower for operation in operations):
            proven.add(sink_kind)
    if "search_filter" in source_lower and (
        ".search(" in source_lower or "ldap_search(" in source_lower
    ):
        proven.add("ldap")
    return proven


def _compact_expr(value) -> str:
    if isinstance(value, ast.AST):
        value = ast.unparse(value)
    return re.sub(r"\s+", "", str(value or "")).lower()


def _is_static_config_pseudosource(source_record: dict, source: str) -> bool:
    """Recognize application constants, independent of the model's source label."""
    expr = source_record.get("expr")
    if not isinstance(expr, str) or re.fullmatch(
        r"config\.[A-Za-z_][A-Za-z0-9_]*", expr.strip()
    ) is None:
        return False
    try:
        tree = ast.parse(textwrap.dedent(source))
    except SyntaxError:
        return False
    matches = [
        node for node in ast.walk(tree)
        if isinstance(node, ast.Attribute) and _compact_expr(node) == _compact_expr(expr)
    ]
    return bool(matches) and all(isinstance(node.ctx, ast.Load) for node in matches)


def _call_terminal(call: ast.Call) -> str:
    return ast.unparse(call.func).lower().rsplit(".", 1)[-1]


def _scope_nodes(scope) -> list:
    nodes = []

    def collect(node):
        if node is not scope and isinstance(
            node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda, ast.ClassDef)
        ):
            return
        nodes.append(node)
        for child in ast.iter_child_nodes(node):
            collect(child)

    collect(scope)
    return nodes


def _block_terminates(body: list) -> bool:
    if not body:
        return False
    last = body[-1]
    if isinstance(last, (ast.Raise, ast.Return)):
        return True
    return (
        isinstance(last, ast.If)
        and _block_terminates(last.body)
        and _block_terminates(last.orelse)
    )


def _scan_exception_is_fail_open(nodes: list, scan_assignment: ast.AST) -> bool:
    for node in nodes:
        if not isinstance(node, ast.Try):
            continue
        if not any(
            any(candidate is scan_assignment for candidate in ast.walk(statement))
            for statement in node.body
        ):
            continue
        if any(not _block_terminates(handler.body) for handler in node.handlers):
            return True
    return False


def _scan_guard_attributes(test: ast.AST, result_name: str) -> set[str]:
    attributes = {
        node.id.lower() for node in ast.walk(test) if isinstance(node, ast.Name)
    }
    for node in ast.walk(test):
        if not isinstance(node, ast.Attribute):
            continue
        root = node.value
        while isinstance(root, ast.Attribute):
            root = root.value
        if isinstance(root, ast.Name) and (not result_name or root.id == result_name):
            attributes.add(node.attr.lower())
    return attributes


def _default_enabled_params(scope: ast.AST) -> set[str]:
    if not isinstance(scope, (ast.FunctionDef, ast.AsyncFunctionDef)):
        return set()
    positional = [*scope.args.posonlyargs, *scope.args.args]
    defaults = [None] * (len(positional) - len(scope.args.defaults)) + list(scope.args.defaults)
    pairs = [*zip(positional, defaults), *zip(scope.args.kwonlyargs, scope.args.kw_defaults)]
    return {
        arg.arg for arg, default in pairs
        if isinstance(default, ast.Constant) and default.value is True
    }


def _boolean_param_condition(test: ast.AST) -> Optional[tuple[str, bool, bool]]:
    """Return how a simple boolean-param test evaluates for True and False."""
    if isinstance(test, ast.Name):
        return test.id, True, False
    if isinstance(test, ast.UnaryOp) and isinstance(test.op, ast.Not):
        condition = _boolean_param_condition(test.operand)
        if condition is not None:
            name, when_true, when_false = condition
            return name, not when_true, not when_false
    if (
        isinstance(test, ast.Call)
        and isinstance(test.func, ast.Name)
        and test.func.id == "bool"
        and len(test.args) == 1
        and not test.keywords
    ):
        return _boolean_param_condition(test.args[0])
    if isinstance(test, ast.Compare) and len(test.ops) == len(test.comparators) == 1:
        left, right = test.left, test.comparators[0]
        if isinstance(right, ast.Name) and isinstance(left, ast.Constant):
            left, right = right, left
        if not (
            isinstance(left, ast.Name)
            and isinstance(right, ast.Constant)
            and isinstance(right.value, bool)
        ):
            return None
        op = test.ops[0]
        if isinstance(op, (ast.Eq, ast.Is)):
            return left.id, True == right.value, False == right.value
        if isinstance(op, (ast.NotEq, ast.IsNot)):
            return left.id, True != right.value, False != right.value
    return None


def _node_parents(nodes: list) -> dict:
    node_set = set(nodes)
    return {
        child: parent
        for parent in nodes
        for child in ast.iter_child_nodes(parent)
        if child in node_set
    }


def _control_context(nodes: list, operation: ast.AST) -> dict:
    parents = _node_parents(nodes)
    context = {}
    child = operation
    while child in parents:
        parent = parents[child]
        branch = None
        if isinstance(parent, ast.If):
            branch = "body" if child in parent.body else "orelse" if child in parent.orelse else None
        elif isinstance(parent, (ast.For, ast.AsyncFor, ast.While)):
            branch = "body" if child in parent.body else "orelse" if child in parent.orelse else None
        elif isinstance(parent, ast.Try):
            if child in parent.body:
                branch = "body"
            elif child in parent.orelse:
                branch = "orelse"
            elif child in parent.finalbody:
                branch = "finalbody"
            elif child in parent.handlers:
                branch = f"handler:{parent.handlers.index(child)}"
        if branch is not None:
            context[parent] = branch
        child = parent
    return context


def _same_control_context(nodes: list, left: ast.AST, right: ast.AST) -> bool:
    return _control_context(nodes, left) == _control_context(nodes, right)


def _operation_dominates_sink(nodes: list, operation: ast.AST, sink: ast.AST) -> bool:
    operation_context = _control_context(nodes, operation)
    sink_context = _control_context(nodes, sink)
    return all(sink_context.get(parent) == branch for parent, branch in operation_context.items())


def _source_scan_coverage(
    scope: ast.AST, nodes: list, operation: ast.AST, sink: ast.AST
):
    """Prove scan coverage relative to the protected sink's control path."""
    operation_context = _control_context(nodes, operation)
    sink_context = _control_context(nodes, sink)
    default_enabled = _default_enabled_params(scope)
    bypass_param = None
    for parent, branch in operation_context.items():
        sink_branch = sink_context.get(parent)
        if sink_branch is not None:
            if sink_branch != branch:
                return None
            continue
        if isinstance(parent, ast.If):
            condition = _boolean_param_condition(parent.test)
            if condition is None:
                return None
            name, when_true, when_false = condition
            in_body = branch == "body"
            executes_when_enabled = when_true if in_body else not when_true
            executes_when_disabled = when_false if in_body else not when_false
            if (
                name not in default_enabled
                or not executes_when_enabled
                or executes_when_disabled
                or bypass_param not in (None, name)
            ):
                return None
            bypass_param = name
        else:
            return None
    if bypass_param is not None:
        return "default", bypass_param
    return "must", ""


def _source_backed_call_terminal(call_expr, tree: ast.AST) -> Optional[str]:
    if not isinstance(call_expr, str) or not call_expr.strip():
        return None
    try:
        modeled = ast.parse(call_expr.strip(), mode="eval").body
    except SyntaxError:
        return None
    if not isinstance(modeled, ast.Call):
        return None
    modeled_expr = _compact_expr(modeled)
    if not any(
        isinstance(node, ast.Call) and _compact_expr(node) == modeled_expr
        for node in ast.walk(tree)
    ):
        return None
    return _call_terminal(modeled)


def _source_backed_scan_guards(source: str, sinks: list) -> Optional[dict]:
    """Map deserialize sink ids to dominating fail-closed source scan facts."""
    try:
        tree = ast.parse(textwrap.dedent(source))
    except SyntaxError:
        return None
    scopes = [tree, *(
        node for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    )]
    guarded = {}
    observed = set()
    for sink in sinks:
        if not isinstance(sink, dict) or sink.get("sink_kind") != "deserialize":
            continue
        sink_id = sink.get("id")
        expected_arg = _compact_expr(sink.get("arg_expr"))
        expected_callee = _source_backed_call_terminal(
            sink.get("call_expr"), tree
        ) or str(sink.get("callee") or "").lower().rsplit(".", 1)[-1]
        if not isinstance(sink_id, str) or not expected_arg or "scan" in expected_callee:
            continue
        for scope in scopes:
            nodes = _scope_nodes(scope)
            sink_calls = [
                node for node in nodes
                if isinstance(node, ast.Call)
                and _call_terminal(node) == expected_callee
                and node.args
                and _compact_expr(node.args[0]) == expected_arg
            ]
            for sink_call in sink_calls:
                scan_calls = [
                    node for node in nodes
                    if isinstance(node, ast.Call)
                    and "scan" in _call_terminal(node)
                    and node.args
                    and _compact_expr(node.args[0]) == expected_arg
                ]
                if scan_calls:
                    observed.add(sink_id)
                for assignment in nodes:
                    if not isinstance(assignment, (ast.Assign, ast.AnnAssign)):
                        continue
                    value = assignment.value
                    if not isinstance(value, ast.Call) or "scan" not in _call_terminal(value):
                        continue
                    if not value.args or _compact_expr(value.args[0]) != expected_arg:
                        continue
                    targets = assignment.targets if isinstance(assignment, ast.Assign) else [assignment.target]
                    result_names = [target.id for target in targets if isinstance(target, ast.Name)]
                    if not result_names or assignment.lineno >= sink_call.lineno:
                        continue
                    if _scan_exception_is_fail_open(nodes, assignment):
                        continue
                    coverage = _source_scan_coverage(scope, nodes, assignment, sink_call)
                    if coverage is None:
                        continue
                    for guard in nodes:
                        if not isinstance(guard, ast.If):
                            continue
                        if not (assignment.lineno < guard.lineno < sink_call.lineno):
                            continue
                        attributes = _scan_guard_attributes(guard.test, result_names[0])
                        rejects_unsafe = any(
                            marker in attribute
                            for attribute in attributes
                            for marker in ("infect", "unsafe", "malicious", "threat", "virus")
                        )
                        rejects_error = any(
                            marker in attribute
                            for attribute in attributes
                            for marker in ("err", "error", "fail")
                        )
                        if (
                            rejects_unsafe
                            and rejects_error
                            and _block_terminates(guard.body)
                            and _same_control_context(nodes, assignment, guard)
                        ):
                            guarded[sink_id] = {
                                "expr": ast.unparse(value),
                                "input_expr": ast.unparse(value.args[0]),
                                "coverage": coverage[0],
                                "bypass_param": coverage[1],
                            }
                            break
                    if sink_id in guarded:
                        break
                if sink_id not in guarded:
                    for scan_call in scan_calls:
                        if scan_call.lineno >= sink_call.lineno:
                            continue
                        if _scan_exception_is_fail_open(nodes, scan_call):
                            continue
                        coverage = _source_scan_coverage(scope, nodes, scan_call, sink_call)
                        if coverage is None:
                            continue
                        for guard in nodes:
                            if not isinstance(guard, ast.If):
                                continue
                            if not (scan_call.lineno < guard.lineno < sink_call.lineno):
                                continue
                            attributes = _scan_guard_attributes(guard.test, "")
                            rejects_unsafe = any(
                                marker in attribute
                                for attribute in attributes
                                for marker in ("infect", "unsafe", "malicious", "threat", "virus")
                            )
                            rejects_error = any(
                                marker in attribute
                                for attribute in attributes
                                for marker in ("err", "error", "fail")
                            )
                            if (
                                rejects_unsafe
                                and rejects_error
                                and _block_terminates(guard.body)
                                and _same_control_context(nodes, scan_call, guard)
                            ):
                                guarded[sink_id] = {
                                    "expr": ast.unparse(scan_call),
                                    "input_expr": ast.unparse(scan_call.args[0]),
                                    "coverage": coverage[0],
                                    "bypass_param": coverage[1],
                                }
                                break
                        if sink_id in guarded:
                            break
                if sink_id in guarded:
                    break
            if sink_id in guarded:
                break
    return guarded, observed


def _source_must_scan_contracts(source: str) -> dict[str, dict]:
    """Derive unconditional fail-closed content-scan contracts from source."""
    try:
        tree = ast.parse(textwrap.dedent(source))
    except SyntaxError:
        return {}
    scopes = [tree, *(
        node for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    )]
    proven = {}
    for scope in scopes:
        nodes = _scope_nodes(scope)
        for assignment in nodes:
            if not isinstance(assignment, (ast.Assign, ast.AnnAssign)):
                continue
            value = assignment.value
            if not isinstance(value, ast.Call) or "scan" not in _call_terminal(value):
                continue
            if not value.args or _control_context(nodes, assignment):
                continue
            targets = assignment.targets if isinstance(assignment, ast.Assign) else [assignment.target]
            result_names = [target.id for target in targets if isinstance(target, ast.Name)]
            if not result_names or _scan_exception_is_fail_open(nodes, assignment):
                continue
            for guard in nodes:
                if not isinstance(guard, ast.If) or guard.lineno <= assignment.lineno:
                    continue
                if not _same_control_context(nodes, assignment, guard):
                    continue
                attributes = _scan_guard_attributes(guard.test, result_names[0])
                rejects_unsafe = any(
                    marker in attribute
                    for attribute in attributes
                    for marker in ("infect", "unsafe", "malicious", "threat", "virus")
                )
                rejects_error = any(
                    marker in attribute
                    for attribute in attributes
                    for marker in ("err", "error", "fail")
                )
                if rejects_unsafe and rejects_error and _block_terminates(guard.body):
                    input_expr = ast.unparse(value.args[0])
                    proven[_compact_expr(input_expr)] = {
                        "expr": ast.unparse(value),
                        "input_expr": input_expr,
                    }
                    break
    return proven


def _source_validated_must_scan_inputs(source: str) -> set[str]:
    return {
        contract["input_expr"]
        for contract in _source_must_scan_contracts(source).values()
    }


def _call_actual_for_param(call: ast.Call, function: ast.AST, param_name: str):
    params = [
        arg.arg for arg in [*function.args.posonlyargs, *function.args.args]
        if arg.arg not in {"self", "cls"}
    ]
    if param_name not in params:
        return None
    keyword = next((item.value for item in call.keywords if item.arg == param_name), None)
    if keyword is not None:
        return keyword
    position = params.index(param_name)
    return call.args[position] if position < len(call.args) else None


def _propagate_source_validated_callee_guard(
    caller_source: str,
    callee_source: str,
    callee_name: str,
    caller_sinks: list,
) -> None:
    validated_inputs = _source_validated_must_scan_inputs(callee_source)
    callee_function = _python_function(callee_source)
    if not validated_inputs or callee_function is None:
        return
    try:
        tree = ast.parse(textwrap.dedent(caller_source))
    except SyntaxError:
        return
    scopes = [tree, *(
        node for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    )]
    callee_terminal = callee_name.lower().rsplit(".", 1)[-1]
    for scope in scopes:
        nodes = _scope_nodes(scope)
        helper_calls = [
            node for node in nodes
            if isinstance(node, ast.Call) and _call_terminal(node) == callee_terminal
        ]
        if not helper_calls:
            continue
        for sink in caller_sinks:
            if (
                not isinstance(sink, dict)
                or sink.get("_via")
                or sink.get("sink_kind") != "deserialize"
                or not isinstance(sink.get("arg_expr"), str)
            ):
                continue
            expected_callee = str(sink.get("callee") or "").lower().rsplit(".", 1)[-1]
            sink_calls = [
                node for node in nodes
                if isinstance(node, ast.Call)
                and _call_terminal(node) == expected_callee
                and node.args
                and _compact_expr(node.args[0]) == _compact_expr(sink["arg_expr"])
            ]
            for helper_call in helper_calls:
                for input_expr in validated_inputs:
                    actual = _call_actual_for_param(helper_call, callee_function, input_expr)
                    if actual is None or _compact_expr(actual) != _compact_expr(sink["arg_expr"]):
                        continue
                    if any(
                        helper_call.lineno < sink_call.lineno
                        and _operation_dominates_sink(nodes, helper_call, sink_call)
                        for sink_call in sink_calls
                    ):
                        sink["_validation_guard_coverage"] = "must"
                        break
                if sink.get("_validation_guard_coverage") == "must":
                    break


def _normalize_source_backed_scan_guards(guards: list, sinks: list, source: str) -> None:
    analysis = _source_backed_scan_guards(source, sinks)
    if analysis is None:
        return
    guarded, observed = analysis
    unsafe_sink_ids = {
        sink.get("id") for sink in sinks
        if isinstance(sink, dict)
        and sink.get("sink_kind") == "deserialize"
        and "scan" not in str(sink.get("callee") or "").lower()
        and isinstance(sink.get("id"), str)
    }
    for guard in guards:
        if not isinstance(guard, dict) or guard.get("guard_kind") != "content_scan":
            continue
        protected = set(guard.get("protects_sink_ids") or []) & unsafe_sink_ids
        if (
            protected
            and not protected.issubset(guarded)
            and isinstance(guard.get("expr"), str)
        ):
            guard["failure_mode"] = "open"
    for sink in sinks:
        if not isinstance(sink, dict) or sink.get("id") not in guarded:
            continue
        sink_id = sink["id"]
        proof = guarded[sink_id]
        guard = next((
            candidate for candidate in guards
            if isinstance(candidate, dict)
            and candidate.get("guard_kind") == "content_scan"
            and sink_id in (candidate.get("protects_sink_ids") or [])
        ), None)
        if guard is None:
            guard = {"id": f"G_SOURCE_{sink_id}", "guard_kind": "content_scan"}
            guards.append(guard)
        protected = list(guard.get("protects_sink_ids") or [])
        if sink_id not in protected:
            protected.append(sink_id)
        guard.update({
            "expr": proof["expr"],
            "input_expr": proof["input_expr"],
            "protects_sink_ids": protected,
            "endorses": ["serialized_blob"],
            "coverage": proof["coverage"],
            "failure_mode": "closed",
            "bypass_param": proof["bypass_param"],
            "confidence": "high",
        })
        if proof["coverage"] == "must":
            sink["_validation_guard_coverage"] = "must"
        else:
            sink.pop("_validation_guard_coverage", None)


def _normalize_operation_sinks(payload: dict, source: str) -> dict:
    """Discard LLM sink guesses that have no matching operation in the source."""
    normalized = dict(payload)
    sources = payload.get("taint_sources") or []
    static_config_ids = {
        source_record.get("id")
        for source_record in sources
        if isinstance(source_record, dict)
        and _is_static_config_pseudosource(source_record, source)
        and isinstance(source_record.get("id"), str)
    }
    normalized_sources = []
    for source_record in sources:
        if not isinstance(source_record, dict):
            normalized_sources.append(source_record)
            continue
        if source_record.get("id") in static_config_ids:
            continue
        item = dict(source_record)
        if item.get("source_kind") == "fs_path":
            item["source_kind"] = "untrusted_param"
        elif item.get("source_kind") == "file_read":
            item["source_kind"] = "file"
        normalized_sources.append(item)
    normalized["taint_sources"] = normalized_sources
    guards = [
        dict(guard) if isinstance(guard, dict) else guard
        for guard in (payload.get("validation_guards") or [])
    ]
    scan_match = re.search(r"scan_file_path\(\s*([A-Za-z_][A-Za-z0-9_.]*)\s*\)", source)
    scan_input = scan_match.group(1) if scan_match else None
    if scan_input:
        source_failure_mode = "closed" if "scan_err" in source else "open"
        scan_guards = [
            guard for guard in guards
            if isinstance(guard, dict) and guard.get("guard_kind") == "content_scan"
        ]
        for guard in scan_guards:
            guard["input_expr"] = scan_input
            guard["failure_mode"] = source_failure_mode
            if source_failure_mode == "closed" and not guard.get("bypass_param"):
                guard["coverage"] = "must"
        if not scan_guards and "scan" in str(payload.get("function") or "").lower():
            guards.append({
                "id": "G_SOURCE_SCAN",
                "guard_kind": "content_scan",
                "expr": f"scan_file_path({scan_input})",
                "input_expr": scan_input,
                "protects_sink_ids": [],
                "endorses": ["serialized_blob"],
                "coverage": "must",
                "failure_mode": source_failure_mode,
                "bypass_param": "",
                "confidence": "high",
            })
    normalized["validation_guards"] = guards
    kept = []
    source_proven_kinds = _source_proven_sink_kinds(source)
    for raw_sink in payload.get("sinks") or []:
        if not isinstance(raw_sink, dict):
            kept.append(raw_sink)
            continue
        sink = dict(raw_sink)
        if sink.get("_via"):
            kept.append(sink)
            continue
        kind = sink.get("sink_kind")
        call = str(sink.get("call_expr") or sink.get("callee") or "").lower()
        source_lower = source.lower()
        if kind == "code_eval" and "exec(" in call:
            sink["sink_kind"] = "shell_command"
            sink["arg_context"] = "shell_command_text"
            kind = "shell_command"
        if kind == "code_eval" and not any(
            marker in call for marker in ("exec(", "eval(")
        ):
            continue
        if kind == "unknown_external":
            continue
        if kind not in source_proven_kinds:
            continue
        ldap_arg = str(sink.get("arg_expr") or "").lower()
        if kind == "ldap" and any(
            marker in ldap_arg for marker in ("base_dn", "search_base", "search_scope")
        ):
            continue
        if kind == "fs_path":
            sink["flows"] = _path_escape_flows(normalized, sink)
            if not sink["flows"]:
                continue
        if kind == "deserialize" and any(
            marker in call for marker in ("safetensors", "gguf")
        ):
            continue
        if kind == "deserialize":
            deserialize_markers = tuple(
                marker for marker in (
                    "pickle", "torch.load", "torch_load", "yaml.load", "scan_file_path"
                )
                if marker in call
            )
            if not deserialize_markers or not any(
                marker in source_lower for marker in deserialize_markers
            ):
                continue
        if static_config_ids:
            sink["flows"] = [
                flow for flow in (sink.get("flows") or [])
                if not isinstance(flow, dict)
                or flow.get("source") not in {
                    f"source:{source_id}" for source_id in static_config_ids
                }
            ]
        kept.append(sink)

    for compact_input, contract in _source_must_scan_contracts(source).items():
        scan_sink_ids = [
            sink["id"]
            for sink in kept
            if isinstance(sink, dict)
            and isinstance(sink.get("id"), str)
            and sink.get("sink_kind") == "deserialize"
            and "scan" in str(sink.get("callee") or "").lower()
            and _compact_expr(sink.get("arg_expr")) == compact_input
        ]
        matching_guards = [
            guard for guard in guards
            if isinstance(guard, dict)
            and guard.get("guard_kind") == "content_scan"
            and _compact_expr(guard.get("input_expr")) == compact_input
        ]
        if not matching_guards:
            matching_guards = [{
                "id": f"G_SOURCE_SCAN_{len(guards)}",
                "guard_kind": "content_scan",
            }]
            guards.extend(matching_guards)
        for guard in matching_guards:
            protected = list(guard.get("protects_sink_ids") or [])
            guard.update({
                "expr": contract["expr"],
                "input_expr": contract["input_expr"],
                "protects_sink_ids": [*protected, *(
                    sink_id for sink_id in scan_sink_ids if sink_id not in protected
                )],
                "endorses": ["serialized_blob"],
                "coverage": "must",
                "failure_mode": "closed",
                "bypass_param": "",
                "confidence": "high",
            })

    _normalize_source_backed_scan_guards(guards, kept, source)
    has_deserialize = any(
        isinstance(sink, dict) and sink.get("sink_kind") == "deserialize"
        for sink in kept
    )
    scan_guard = next((
        guard for guard in guards
        if isinstance(guard, dict)
        and guard.get("guard_kind") == "content_scan"
        and "serialized_blob" in (guard.get("endorses") or [])
        and isinstance(guard.get("input_expr"), str)
    ), None)
    function_name = str(payload.get("function") or "").lower()
    if (
        not has_deserialize
        and scan_guard is not None
        and "scan" in function_name
        and "scan_file_path(" in source
    ):
        input_expr = scan_guard["input_expr"]
        source_record = next((
            item for item in normalized["taint_sources"]
            if isinstance(item, dict)
            and item.get("expr") == input_expr
            and isinstance(item.get("id"), str)
        ), None)
        source_ref = (
            f"source:{source_record['id']}" if source_record
            else f"param:{input_expr}"
        )
        sink_id = "K_SCAN_ACCEPT"
        kept.append({
            "id": sink_id,
            "sink_kind": "deserialize",
            "callee": "scan_file_path",
            "call_expr": f"scan_file_path({input_expr})",
            "arg_position": 0,
            "arg_expr": input_expr,
            "arg_context": "serialized_blob",
            "flows": [{"source": source_ref, "sanitizers": []}],
        })
        protected = scan_guard.get("protects_sink_ids")
        scan_guard["protects_sink_ids"] = [
            *(
                protected
                if isinstance(protected, list)
                else []
            ),
            sink_id,
        ]

    by_id = {
        sink["id"]: sink
        for sink in kept
        if isinstance(sink, dict) and isinstance(sink.get("id"), str)
    }
    for guard in guards:
        if not isinstance(guard, dict) or guard.get("guard_kind") != "content_scan":
            continue
        if guard.get("confidence") != "high" or guard.get("failure_mode") != "closed":
            continue
        input_expr = guard.get("input_expr")
        if not isinstance(input_expr, str):
            continue
        scan_pos = source.find(f"scan_file_path({input_expr})")
        if scan_pos < 0:
            continue
        protected = guard.get("protects_sink_ids")
        protected_ids = list(protected) if isinstance(protected, list) else []
        for sink in kept:
            if not isinstance(sink, dict) or sink.get("sink_kind") != "deserialize":
                continue
            sink_id = sink.get("id")
            if not isinstance(sink_id, str) or sink.get("arg_expr") != input_expr:
                continue
            sink_pos = source.find(str(sink.get("call_expr") or ""))
            if sink_pos > scan_pos and sink_id not in protected_ids:
                protected_ids.append(sink_id)
        guard["protects_sink_ids"] = protected_ids
    for guard in guards:
        if not isinstance(guard, dict):
            continue
        if guard.get("confidence") != "high" or guard.get("failure_mode") != "closed":
            continue
        if guard.get("guard_kind") not in {
            "schema_validation", "deserialization_allowlist", "content_scan",
        }:
            continue
        guard_expr = guard.get("expr")
        if not isinstance(guard_expr, str) or not guard_expr:
            continue
        guard_pos = source.find(guard_expr)
        if guard_pos < 0:
            continue
        for sink_id in guard.get("protects_sink_ids") or []:
            if not isinstance(sink_id, str):
                continue
            sink = by_id.get(sink_id)
            if not sink or guard.get("input_expr") != sink.get("arg_expr"):
                continue
            if sink.get("arg_context") not in (guard.get("endorses") or []):
                continue
            sink_pos = source.find(str(sink.get("call_expr") or ""))
            if sink_pos > guard_pos:
                if guard.get("coverage") == "must":
                    sink["_validation_guard_coverage"] = "must"
                elif (
                    guard.get("coverage") == "default"
                    and sink.get("_validation_guard_coverage") != "must"
                ):
                    sink.pop("_validation_guard_coverage", None)

    normalized["sinks"] = kept
    return normalized


class TaintPlugin(AnalysisPlugin):
    """Integrity-taint / injection plugin (dual of IFC)."""

    model = TAINT_MODEL
    SCHEMA = "taint.v1"

    @property
    def metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name="taint",
            version="0.1.0",
            schema_version=self.SCHEMA,
            supported_languages=("python", "javascript", "typescript", "go",
                                 "java", "php", "ruby", "c", "cpp"),
            verdicts=(VULNERABLE, POLYMORPHIC, SANITIZED, SAFE, ERROR),
            requires_top_down_context=False,
            needs_entrypoint=True,
        )

    # -- abstraction -----------------------------------------------------------

    def build_abstraction_prompt(self, request: AbstractionRequest) -> List[Dict[str, str]]:
        unit = request.function
        numbered = "\n".join(
            f"Line {i+1}: {ln}" for i, ln in enumerate(unit.source.splitlines())
        )
        callee_summaries = None
        if request.callee_context:
            callee_summaries = "\n".join(request.callee_context.values())
        return [
            {"role": "system", "content": _system_prompt(unit.id.language)},
            {"role": "user", "content": _user_prompt(
                numbered, unit.signature_line, unit.id.language, callee_summaries)},
        ]

    def parse_abstraction_response(
        self, request: AbstractionRequest, raw_response: str
    ) -> Optional[FactEnvelope]:
        payload = _extract_taint_json(raw_response)
        if payload is None or not isinstance(payload, dict):
            return None
        payload = _normalize_operation_sinks(payload, request.function.source)
        sinks = payload.get("sinks")
        if isinstance(sinks, list):
            payload = dict(payload)
            payload["sinks"] = [
                {key: value for key, value in sink.items() if not key.startswith("_")}
                if isinstance(sink, dict) else sink
                for sink in sinks
            ]
        if validate(payload) is not None:
            return None
        return FactEnvelope(
            plugin_name="taint",
            schema_version=self.SCHEMA,
            function=request.function.id,
            status="ok",
            payload=payload,
        )

    def make_error_facts(self, request: AbstractionRequest, error: str) -> FactEnvelope:
        return FactEnvelope(
            plugin_name="taint",
            schema_version=self.SCHEMA,
            function=request.function.id,
            status="error",
            payload=None,
            confidence=0.0,
            diagnostics=[Diagnostic(level="error", message=error)],
        )

    # -- composition (bottom-up: instantiate callee sinks at the call site) ----

    def summarize_for_caller(self, facts: FactEnvelope) -> str:
        if facts.status != "ok" or not facts.payload:
            return f"{facts.function.name}: (no taint facts)"
        return _summarize(facts.payload, facts.function.name)

    def compose_calls(
        self,
        caller_facts: FactEnvelope,
        resolved_calls: Sequence[ResolvedCall],
        context: DriverContext,
    ) -> FactEnvelope:
        """Instantiate each callee's parametric sinks (and return flows) at the
        caller's call site, substituting the caller's actual-argument taint. A
        callee sink over `param:p` becomes a caller sink over whatever the caller
        passes as `p` — so a tainted argument makes the caller VULNERABLE."""
        if caller_facts.status != "ok" or not caller_facts.payload:
            return caller_facts
        payload = _normalize_operation_sinks(caller_facts.payload, context.function.source)
        caller_call_sites = payload.get("call_sites") or []
        composed_sinks = list(payload.get("sinks") or [])
        composed_sanitizers = list(payload.get("sanitizers") or [])
        composed_bindings = list(payload.get("taint_bindings") or [])
        added = []

        for rc in resolved_calls:
            cf = rc.callee_facts
            if cf.status != "ok" or not cf.payload:
                continue
            if not _has_call_operation(
                context.function.source,
                rc.call_site.callee_name,
                context.function.id.language,
            ):
                continue
            if (
                rc.call_site.callee_name == context.function.id.base_name
                and not _has_same_name_body_call(
                    context.function.source,
                    rc.call_site.callee_name,
                    context.function.id.language,
                )
            ):
                continue
            callee_unit = context.program.functions.get(cf.function)
            callee_source = callee_unit.source if callee_unit is not None else ""
            callee_payload = _normalize_operation_sinks(
                cf.payload,
                callee_source,
            )
            callee_name = rc.call_site.callee_name
            _propagate_source_validated_callee_guard(
                context.function.source,
                callee_source,
                callee_name,
                composed_sinks,
            )
            cs = _match_call_site(caller_call_sites, callee_name)
            if cs:
                call_id = cs.get("id") or callee_name
                param_to_actual = {
                    a.get("param_name"): (a.get("flows") or [])
                    for a in (cs.get("args") or []) if a.get("param_name")
                }
                for formal, actual_expr in (rc.call_site.arg_bindings or {}).items():
                    p = formal[len("param:"):] if formal.startswith("param:") else formal
                    if p not in param_to_actual:
                        param_to_actual[p] = [
                            {"source": f"unknown:{call_id}:{actual_expr}", "sanitizers": []}
                        ]
            else:
                # Fall back to the driver's regex arg bindings. We don't know the
                # actuals' taint, so fail closed: treat each as unknown-tainted.
                call_id = callee_name
                param_to_actual = {}
                for formal, actual_expr in (rc.call_site.arg_bindings or {}).items():
                    p = formal[len("param:"):] if formal.startswith("param:") else formal
                    param_to_actual[p] = [
                        {"source": f"unknown:{call_id}:{actual_expr}", "sanitizers": []}
                    ]

            sanitizer_id_map = {}
            for sanitizer in callee_payload.get("sanitizers") or []:
                if not isinstance(sanitizer, dict) or not isinstance(sanitizer.get("id"), str):
                    continue
                old_id = sanitizer["id"]
                new_id = f"{call_id}::{old_id}"
                sanitizer_id_map[old_id] = new_id
                reanchored = dict(sanitizer)
                reanchored["id"] = new_id
                composed_sanitizers.append(reanchored)

            for ksink in callee_payload.get("sinks") or []:
                inst = instantiate_sink(ksink, call_id, param_to_actual, sanitizer_id_map)
                args = (cs or {}).get("args")
                if cs and isinstance(args, (list, tuple)):
                    call_args = merge_call_args_with_bindings(args, rc.call_site.arg_bindings)
                    coverage = validation_guard_coverage_for_call(callee_payload, ksink, call_args)
                else:
                    call_args = call_args_from_bindings(rc.call_site.arg_bindings)
                    coverage = (
                        validation_guard_coverage_for_call(callee_payload, ksink, call_args)
                        if call_args else validation_guard_coverage(callee_payload, ksink)
                    )
                if coverage in {"must", "default"}:
                    inst["_validation_guard_coverage"] = coverage
                composed_sinks.append(inst)
                added.append({"callee": callee_name, "sink_id": inst["id"],
                              "sink_kind": inst.get("sink_kind")})

            ret_expr = (cs or {}).get("return_expr")
            if ret_expr:
                for rf in callee_payload.get("return_flows") or []:
                    composed_bindings.append({
                        "expr": ret_expr,
                        "flows": instantiate_flows(
                            rf.get("flows"), param_to_actual, call_id, sanitizer_id_map
                        ),
                    })

        payload["sinks"] = composed_sinks
        payload["sanitizers"] = composed_sanitizers
        payload["taint_bindings"] = composed_bindings
        if added:
            payload["_composed_sinks"] = added
        caller_facts.payload = payload
        return caller_facts

    # -- checker ---------------------------------------------------------------

    def _param_reaches_entrypoint(self, context, param_name):
        program = context.program
        entrypoints = set(program.entrypoints)
        pending = [(context.function.id, param_name)]
        seen = set()
        while pending:
            callee_id, callee_param = pending.pop()
            if (callee_id, callee_param) in seen:
                continue
            seen.add((callee_id, callee_param))
            for site in program.callers_by_callee.get(callee_id, ()):
                caller = program.functions.get(site.caller)
                callee = program.functions.get(callee_id)
                if caller is None or callee is None:
                    continue
                if not _has_call_operation(
                    caller.source, site.callee_name, caller.id.language
                ):
                    continue
                if (
                    site.callee_name == caller.id.base_name
                    and not _has_same_name_body_call(
                        caller.source, site.callee_name, caller.id.language
                    )
                ):
                    continue
                bound = site.arg_bindings.get(f"param:{callee_param}")
                actual_exprs = [bound] if isinstance(bound, str) else []
                if caller.id.language.lower() == "python":
                    actual_exprs.extend(
                        _python_call_actuals(caller, callee, callee_param)
                    )
                for actual_expr in actual_exprs:
                    caller_params = [
                        candidate for candidate in _function_params(caller)
                        if re.search(rf"\b{re.escape(candidate)}\b", actual_expr)
                    ]
                    if caller_params and caller.id in entrypoints:
                        return True
                    pending.extend((caller.id, candidate) for candidate in caller_params)
        return False

    def _seed_param_status(self, facts, context):
        """Seed parameters explicitly classified as untrusted by the abstraction.

        This does not depend on entrypoint inference: an ``untrusted_param`` fact
        is already an explicit trust-boundary assertion. Other parameters remain
        UNKNOWN_PARAM until a caller instantiates them.
        """
        status = {}
        if not facts.payload:
            return status
        for s in facts.payload.get("taint_sources") or []:
            if s.get("source_kind") == "untrusted_param":
                expr = (s.get("expr") or "").strip()
                if expr.isidentifier():
                    status[expr] = "TAINTED"
                else:
                    if (
                        s.get("confidence") == "high"
                        and context.function.id.language.lower() == "python"
                    ):
                        member = _source_backed_dotted_member(
                            expr, context.function.source
                        )
                        if member is not None:
                            status[member] = "TAINTED"
                    terminal = expr.rsplit(".", 1)[-1]
                    if terminal in (facts.payload.get("params") or []):
                        status[terminal] = "TAINTED"
        for sink in facts.payload.get("sinks") or []:
            if any(
                flow.get("source") == "param:self"
                for flow in (sink.get("flows") or [])
                if isinstance(flow, dict)
            ):
                status["self"] = "TAINTED"
        if context.is_entrypoint:
            for sink in facts.payload.get("sinks") or []:
                for flow in sink.get("flows") or []:
                    source_ref = flow.get("source")
                    if isinstance(source_ref, str) and source_ref.startswith("param:"):
                        status[source_ref[len("param:"):]] = "TAINTED"
        else:
            for sink in facts.payload.get("sinks") or []:
                for flow in sink.get("flows") or []:
                    source_ref = flow.get("source")
                    if not isinstance(source_ref, str) or not source_ref.startswith("param:"):
                        continue
                    param_name = source_ref[len("param:"):]
                    if self._param_reaches_entrypoint(context, param_name):
                        status[param_name] = "TAINTED"
        return status

    def check(
        self,
        facts: FactEnvelope,
        context: DriverContext,
        propagated_contexts: Sequence = (),
    ) -> Verdict:
        if facts.status == "error" or not facts.payload:
            return Verdict(plugin_name="taint", verdict=ERROR, status="error",
                           data={"error": "no valid taint abstraction (fail-closed)"})

        facts.payload = _normalize_operation_sinks(facts.payload, context.function.source)
        param_status = self._seed_param_status(facts, context)
        result = classify(facts.payload, param_status=param_status)
        verdict = result["verdict"]
        findings: List[Finding] = []
        for f in result.get("findings", []):
            if f["status"] == SANITIZED:
                sev = "info"
            elif f["status"] == POLYMORPHIC:
                sev = "low"
            else:
                sev = "high"
            findings.append(Finding(
                rule_id=f"taint.{f['kind'].lower()}",
                title=f["kind"],
                message=f.get("message", ""),
                severity=sev,
                function=facts.function,
                data={"status": f["status"], "cwe": f.get("cwe"),
                      "sink_kind": f.get("sink_kind"), "arg_context": f.get("arg_context"),
                      "source": f.get("source"), "sanitized_by": f.get("sanitized_by"),
                      "evidence": f.get("evidence")},
            ))
        return Verdict(
            plugin_name="taint",
            verdict=verdict,
            status="ok",
            findings=findings,
            data={"signature": facts.payload, "result_findings": result.get("findings", [])},
        )

    def render_result(self, unit, facts, verdict, context):
        result = super().render_result(unit, facts, verdict, context)
        result["rel"] = source_rel_from_extracted(unit.id.rel)
        result["function"] = unit.id.name
        return result

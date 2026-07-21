"""Deterministic validation for authentication boundary contracts.

The base authn abstraction models authentication-event dominance.  These
records cover three decisions for which mere event presence is insufficient:
password-recovery identity/delivery binding, fail-closed credential contracts,
and non-reusable session-key retirement.
"""

import ast
import copy
import re
import textwrap
from collections.abc import Mapping, Sequence
from pathlib import Path


RECOVERY_KINDS = frozenset({"select_account", "deliver_credential"})
RECOVERY_BINDINGS = frozenset({
    "canonical_equivalent",
    "exact_equivalent",
    "backend_case_insensitive",
    "stored_identity",
    "untrusted_input",
    "unknown",
})
CREDENTIAL_KINDS = frozenset({"provision", "load", "verify"})
CONTRACT_STATUSES = frozenset({"valid", "invalid", "unknown"})
FAILURE_MODES = frozenset({"closed", "open", "unknown"})
SESSION_KEY_KINDS = frozenset({"retire"})
SESSION_REPLACEMENTS = frozenset({"absent", "fresh_random", "reusable_value", "unknown"})


def normalize_authentication_facts(abstraction, unit, program):
    """Correct mechanically decidable Python facts without trusting model labels."""
    normalized = copy.deepcopy(abstraction)
    if unit.id.language.lower() != "python":
        return normalized
    tree = _parse_python(unit.source)
    if tree is None:
        return normalized

    _normalize_authentication_events(normalized, tree, program)
    _normalize_recovery_events(normalized, unit, program, tree)
    _normalize_file_contracts(normalized, unit, program)
    _normalize_verifier_contract(normalized, unit, program, tree)
    _normalize_session_key_events(normalized, tree)
    if not _has_server_session_lifecycle(tree):
        normalized["session_events"] = [
            event for event in normalized.get("session_events") or []
            if not _is_token_session_event(event)
        ]
    return normalized


def _normalize_authentication_events(abstraction, tree, program):
    delegated = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.If):
            continue
        for call in (child for child in ast.walk(node.test) if isinstance(child, ast.Call)):
            name = _terminal_name(call.func)
            if name == "authenticate" or any(
                    _defined_functions(candidate.source) & {name}
                    and _contains_authenticate_call(candidate.source)
                    for candidate in program.functions.values()):
                delegated.add(name)
    for event in abstraction.get("authentication_events") or []:
        if event.get("method") == "shared_secret":
            event["method"] = "api_key"
        evidence = str(event.get("evidence", "")).lower()
        if any(name in evidence for name in delegated):
            event["strength"] = "genuine"
        protected = event.get("protects_op_ids") or []
        operations = {
            operation.get("op_id"): operation
            for operation in abstraction.get("protected_operations") or []
        }
        if protected and all(
                op_id in operations
                and _authentication_gate_contains_operation(tree, evidence, operations[op_id])
                for op_id in protected):
            event["dominates_all_paths"] = True


def _contains_authenticate_call(source):
    tree = _parse_python(source)
    return tree is not None and any(
        isinstance(node, ast.Call) and _terminal_name(node.func) == "authenticate"
        for node in ast.walk(tree)
    )


def _authentication_gate_contains_operation(tree, event_evidence, operation):
    operation_evidence = str(operation.get("evidence", "")).lower()
    for node in ast.walk(tree):
        if not isinstance(node, ast.If):
            continue
        test = ast.unparse(node.test).lower()
        test_calls = {
            _terminal_name(child.func)
            for child in ast.walk(node.test)
            if isinstance(child, ast.Call)
        }
        gate_matches = _compact(test) in _compact(event_evidence) or any(
            name in event_evidence for name in test_calls
        )
        if not gate_matches:
            continue
        body_calls = {
            _terminal_name(child.func)
            for statement in node.body
            for child in ast.walk(statement)
            if isinstance(child, ast.Call)
        }
        body = " ".join(ast.unparse(statement).lower() for statement in node.body)
        if _compact(operation_evidence) in _compact(body) or any(
                name in operation_evidence for name in body_calls):
            return True
    return False


def _compact(value):
    return "".join(str(value).split())


def _normalize_recovery_events(abstraction, unit, program, tree):
    events = abstraction.get("recovery_events") or []
    if not _has_recovery_delivery_call(tree):
        events = [event for event in events if event.get("kind") != "deliver_credential"]
    if not _has_local_identity_selection(tree):
        events = [event for event in events if event.get("kind") != "select_account"]
    elif _uses_canonical_identity_comparator(tree, unit, program):
        for event in events:
            if event.get("kind") == "select_account":
                event["binding"] = "canonical_equivalent"
                event["failure_mode"] = "closed"
                event["confidence"] = "high"

    generated = _recovery_credential_generation(tree)
    if generated:
        operations = abstraction.get("protected_operations") or []
        delivery = _source_recovery_delivery(tree, operations, generated)
        delivery_events = [event for event in events if event.get("kind") == "deliver_credential"]
        if delivery:
            if not delivery_events:
                events.append(delivery)
            else:
                for event in delivery_events:
                    event.update(delivery)
        for event in events:
            if (event.get("kind") != "deliver_credential"
                    or event.get("binding") != "stored_identity"
                    or event.get("failure_mode") != "closed"
                    or not event.get("dominates_all_paths")
                    or event.get("confidence") != "high"):
                continue
            protected = list(event.get("protects_op_ids") or [])
            for operation in operations:
                evidence = str(operation.get("evidence", "")).lower()
                if operation.get("op_id") and any(marker in evidence for marker in generated):
                    if operation["op_id"] not in protected:
                        protected.append(operation["op_id"])
            event["protects_op_ids"] = protected
    abstraction["recovery_events"] = events


def _has_recovery_delivery_call(tree):
    return any(
        isinstance(node, ast.Call)
        and any(word in _terminal_name(node.func) for word in ("send", "mail", "deliver", "notify"))
        for node in ast.walk(tree)
    )


def _has_local_identity_selection(tree):
    identity_words = ("email", "identity", "username", "user_name", "account_name")
    for node in ast.walk(tree):
        if isinstance(node, ast.Compare) and any(isinstance(op, ast.Eq) for op in node.ops):
            expressions = [node.left, *node.comparators]
            if sum(any(word in ast.unparse(expr).lower() for word in identity_words)
                   for expr in expressions) >= 2:
                return True
        if not isinstance(node, ast.Call):
            continue
        name = ast.unparse(node.func).lower()
        if (any(word in name for word in ("compare", "equal", "casefold", "normalize"))
                and len(node.args) >= 2):
            return True
        lookup_markers = [
            child.value.lower()
            for child in ast.walk(node)
            if isinstance(child, ast.Constant) and isinstance(child.value, str)
        ]
        lookup_markers.extend(keyword.arg.lower() for keyword in node.keywords if keyword.arg)
        if any(marker.endswith("__exact") or marker.endswith("__iexact")
               for marker in lookup_markers):
            return True
    return False


def _uses_canonical_identity_comparator(tree, unit, program):
    comparator_names = {
        _terminal_name(node.func)
        for node in ast.walk(tree)
        if isinstance(node, ast.Call) and len(node.args) >= 2
        and any(word in _terminal_name(node.func) for word in ("compare", "equal"))
    }
    if not comparator_names:
        return False
    sources = [unit.source] + [
        candidate.source for candidate in program.functions.values()
        if candidate.id != unit.id and _defined_functions(candidate.source) & comparator_names
    ]
    return any(_is_canonical_comparator(source) for source in sources)


def _defined_functions(source):
    tree = _parse_python(source)
    if tree is None:
        return set()
    return {
        node.name.lower()
        for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    }


def _is_canonical_comparator(source):
    tree = _parse_python(source)
    if tree is None:
        return False
    text = source.lower()
    return "normalize" in text and "casefold" in text and any(
        isinstance(node, ast.Compare) and any(isinstance(op, ast.Eq) for op in node.ops)
        for node in ast.walk(tree)
    )


def _recovery_credential_generation(tree):
    markers = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        name = _terminal_name(node.func)
        if not any(word in name for word in ("token", "credential", "reset_code", "recovery_code")):
            continue
        markers.add(name)
        markers.add(ast.unparse(node.func).lower())
        markers.update(
            word for word in ("token", "credential", "reset_code", "recovery_code")
            if word in name
        )
        parent = next((candidate for candidate in ast.walk(tree)
                       if isinstance(candidate, (ast.Assign, ast.NamedExpr))
                       and candidate.value is node), None)
        if isinstance(parent, ast.Assign):
            markers.update(
                target.id.lower() for target in parent.targets if isinstance(target, ast.Name)
            )
        elif isinstance(parent, ast.NamedExpr) and isinstance(parent.target, ast.Name):
            markers.add(parent.target.id.lower())
    return markers


def _source_recovery_delivery(tree, operations, generated):
    loops = sorted(
        (node for node in ast.walk(tree)
         if isinstance(node, (ast.For, ast.AsyncFor)) and isinstance(node.iter, ast.Call)),
        key=lambda node: node.lineno,
    )
    for loop in loops:
        account_names = _assigned_names(loop.target)
        selection_names = set().union(*(
            _loaded_names(argument)
            for argument in (*loop.iter.args, *(kw.value for kw in loop.iter.keywords))
        ))
        requested_names = {
            name for name in selection_names if _looks_like_identity_name(name)
        } or selection_names
        if not requested_names or not account_names:
            continue

        credential_calls = [
            node for node in ast.walk(loop)
            if isinstance(node, ast.Call) and _is_recovery_credential_call(node)
        ]
        delivery_calls = sorted(
            (
                node for node in ast.walk(loop)
                if isinstance(node, ast.Call)
                and any(word in _terminal_name(node.func)
                        for word in ("send", "mail", "deliver", "notify"))
            ),
            key=lambda node: (node.lineno, node.col_offset),
        )
        for call in delivery_calls:
            preceding_credentials = [
                credential for credential in credential_calls
                if credential.lineno <= call.lineno
            ]
            if not preceding_credentials:
                continue
            generated_accounts = set().union(*(
                _loaded_names(credential) & account_names
                for credential in preceding_credentials
            ))
            identity_aliases, requested_aliases = _recovery_identity_aliases(
                loop, call, account_names, requested_names
            )
            arguments = (*call.args, *(keyword.value for keyword in call.keywords))
            delivered_accounts = set().union(*(
                _stored_identity_accounts(argument, account_names, identity_aliases)
                for argument in arguments
            ))
            requested_delivery = any(
                _loaded_names(argument) & requested_aliases for argument in arguments
            )
            if not delivered_accounts and not requested_delivery:
                continue

            same_account = (
                bool(generated_accounts)
                and delivered_accounts == generated_accounts
                and not requested_delivery
            )
            if same_account:
                binding = "stored_identity"
                failure_mode = "closed"
            elif requested_delivery:
                binding = "untrusted_input"
                failure_mode = "open"
            else:
                binding = "unknown"
                failure_mode = "open"

            identity_names = [
                name for name, accounts in identity_aliases.items()
                if accounts & delivered_accounts
            ]
            identity = (
                sorted(identity_names, key=lambda name: (
                    not _looks_like_identity_name(name), name
                ))[0] if identity_names
                else sorted(delivered_accounts or account_names)[0]
            )
            delivery_markers = {_terminal_name(call.func), ast.unparse(call.func).lower()}
            protected = []
            for operation in operations:
                op_id = operation.get("op_id")
                if not op_id:
                    continue
                evidence = str(operation.get("evidence", "")).lower()
                subject_names = {
                    name.lower() for name in re.findall(
                        r"\b[A-Za-z_][A-Za-z0-9_]*\b",
                        str(operation.get("subject_expr", "")),
                    )
                }
                if (generated_accounts & subject_names or any(
                        marker in evidence for marker in generated | delivery_markers)):
                    protected.append(op_id)
            return {
                "kind": "deliver_credential",
                "requested_identity_expr": sorted(requested_names)[0],
                "account_identity_expr": identity,
                "binding": binding,
                "dominates_all_paths": True,
                "failure_mode": failure_mode,
                "protects_op_ids": protected,
                "confidence": "high",
                "evidence": ast.unparse(call),
            }
    return None


def _is_recovery_credential_call(call):
    name = _terminal_name(call.func)
    return any(
        word in name for word in ("token", "credential", "reset_code", "recovery_code")
    )


def _recovery_identity_aliases(loop, delivery, account_names, requested_names):
    identity_aliases = {}
    requested_aliases = set(requested_names)
    assignments = sorted(
        (
            node for node in ast.walk(loop)
            if isinstance(node, (ast.Assign, ast.AnnAssign))
            and node.value is not None and node.lineno <= delivery.lineno
        ),
        key=lambda node: (node.lineno, node.col_offset),
    )
    for assignment in assignments:
        targets = assignment.targets if isinstance(assignment, ast.Assign) else [assignment.target]
        names = set().union(*(_assigned_names(target) for target in targets))
        accounts = _stored_identity_accounts(
            assignment.value, account_names, identity_aliases
        )
        if accounts:
            for name in names:
                identity_aliases[name] = accounts
        if _loaded_names(assignment.value) & requested_aliases:
            requested_aliases.update(names)
    return identity_aliases, requested_aliases


def _stored_identity_accounts(expression, account_names, aliases):
    accounts = set()
    for node in ast.walk(expression):
        if isinstance(node, ast.Name) and node.id.lower() in aliases:
            accounts.update(aliases[node.id.lower()])
        elif isinstance(node, ast.Attribute) and _looks_like_identity_expression(node):
            accounts.update(_loaded_names(node) & account_names)
        elif (isinstance(node, ast.Call) and _terminal_name(node.func) == "getattr"
              and node.args and _looks_like_identity_expression(node)):
            accounts.update(_loaded_names(node.args[0]) & account_names)
    return accounts


def _looks_like_identity_expression(node):
    return _looks_like_identity_name(ast.unparse(node))


def _looks_like_identity_name(value):
    expression = str(value).lower()
    return any(
        word in expression
        for word in ("email", "identity", "username", "user_name", "account_name",
                     "address", "phone", "contact", "recipient", "destination")
    )


def _assigned_names(node):
    return {
        child.id.lower()
        for child in ast.walk(node)
        if isinstance(child, ast.Name) and isinstance(child.ctx, ast.Store)
    }


def _loaded_names(node):
    return {
        child.id.lower()
        for child in ast.walk(node)
        if isinstance(child, ast.Name) and isinstance(child.ctx, ast.Load)
    }


def _terminal_name(node):
    if isinstance(node, ast.Name):
        return node.id.lower()
    if isinstance(node, ast.Attribute):
        return node.attr.lower()
    return ast.unparse(node).lower()


def validate_security_facts(abstraction):
    """Return a malformed-fact error, or ``None`` for a valid abstraction."""
    if not isinstance(abstraction, Mapping):
        return "authentication abstraction must be an object"

    for field in (
        "protected_operations",
        "authentication_events",
        "session_events",
        "obligations",
        "recovery_events",
        "credential_events",
        "session_key_events",
    ):
        records = abstraction.get(field, [])
        if not _records(records):
            return f"{field} must be an array of objects"

    for event in abstraction.get("recovery_events") or []:
        if event.get("kind") not in RECOVERY_KINDS:
            return f"unknown recovery event kind: {event.get('kind')}"
        if event.get("binding") not in RECOVERY_BINDINGS:
            return f"unknown recovery identity binding: {event.get('binding')}"
        error = _validate_guard(event, require_failure_mode=True)
        if error:
            return error
        error = _validate_protected_ops(event)
        if error:
            return error
        if not _non_empty(event.get("requested_identity_expr")):
            return "recovery event requires requested_identity_expr"
        if not _non_empty(event.get("account_identity_expr")):
            return "recovery event requires account_identity_expr"

    for event in abstraction.get("credential_events") or []:
        if event.get("kind") not in CREDENTIAL_KINDS:
            return f"unknown credential event kind: {event.get('kind')}"
        if event.get("contract_status") not in CONTRACT_STATUSES:
            return f"unknown credential contract status: {event.get('contract_status')}"
        error = _validate_guard(event, require_failure_mode=True)
        if error:
            return error
        error = _validate_protected_ops(event)
        if error:
            return error

    for event in abstraction.get("session_key_events") or []:
        if event.get("kind") not in SESSION_KEY_KINDS:
            return f"unknown session-key event kind: {event.get('kind')}"
        if event.get("replacement") not in SESSION_REPLACEMENTS:
            return f"unknown session-key replacement: {event.get('replacement')}"
        error = _validate_guard(event, require_failure_mode=False)
        if error:
            return error
        error = _validate_protected_ops(event)
        if error:
            return error
        if not isinstance(event.get("storage_cleared"), bool):
            return "session-key event requires boolean storage_cleared"
    return None


def authentication_contract_findings(abstraction):
    """Return deterministic findings for valid boundary-contract facts."""
    findings = []
    for event in abstraction.get("recovery_events") or []:
        kind = event["kind"]
        binding = event["binding"]
        securely_bound = (
            binding in {"canonical_equivalent", "exact_equivalent"}
            if kind == "select_account"
            else binding == "stored_identity"
        )
        if (not securely_bound or not event["dominates_all_paths"]
                or event["failure_mode"] != "closed" or event["confidence"] != "high"):
            findings.append(_finding(
                "WEAK_PASSWORD_RECOVERY",
                "CWE-640",
                event,
                "Password recovery does not bind account selection and credential delivery "
                "to the same verified identity on every path.",
            ))

    for event in abstraction.get("credential_events") or []:
        if (event["contract_status"] != "valid" or event["failure_mode"] != "closed"
                or not event["dominates_all_paths"] or event["confidence"] != "high"):
            findings.append(_finding(
                "FAIL_OPEN_AUTHENTICATION",
                "CWE-287",
                event,
                "Credential provisioning, loading, and verification do not form a valid "
                "fail-closed contract.",
            ))

    for event in abstraction.get("session_key_events") or []:
        securely_retired = (
            event["replacement"] in {"absent", "fresh_random"}
            and event["storage_cleared"]
            and event["dominates_all_paths"]
            and event["confidence"] == "high"
        )
        if not securely_retired:
            findings.append(_finding(
                "SESSION_FIXATION",
                "CWE-384",
                event,
                "Retired session state can retain or converge on a reusable session key.",
            ))
    return findings


def authentication_contract_discharges(abstraction, op_id):
    """Whether a valid recovery/credential contract protects ``op_id``."""
    for event in abstraction.get("recovery_events") or []:
        binding_valid = (
            event["binding"] in {"canonical_equivalent", "exact_equivalent"}
            if event["kind"] == "select_account"
            else event["binding"] == "stored_identity"
        )
        if (binding_valid and event["failure_mode"] == "closed"
                and event["dominates_all_paths"] and event["confidence"] == "high"
                and _protects(event, op_id)):
            return True
    for event in abstraction.get("credential_events") or []:
        if (event["contract_status"] == "valid" and event["failure_mode"] == "closed"
                and event["dominates_all_paths"] and event["confidence"] == "high"
                and _protects(event, op_id)):
            return True
    for event in abstraction.get("session_key_events") or []:
        if (event["replacement"] in {"absent", "fresh_random"}
                and event["storage_cleared"] and event["dominates_all_paths"]
                and event["confidence"] == "high" and _protects(event, op_id)):
            return True
    return False


def related_authentication_context(unit, program):
    """Return source for functions sharing a security-relevant contract symbol."""
    identifiers = _security_identifiers(unit.source)
    if not identifiers:
        return ""
    related = []
    for candidate in program.functions.values():
        if candidate.id == unit.id:
            continue
        shared = identifiers & _security_identifiers(candidate.source)
        if shared:
            related.append((
                len(shared),
                len(candidate.source),
                candidate.id.rel,
                f"Related function {candidate.id.name} (shared {', '.join(sorted(shared))}):\n"
                f"{candidate.source}",
            ))
    related.sort(key=lambda item: (-item[0], item[1], item[2]))
    return "\n\n".join(item[3] for item in related[:4])


def source_rel_from_extracted(rel):
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


def _security_identifiers(source):
    identifiers = set(re.findall(r"\b[A-Z][A-Z0-9_]{2,}\b", source or ""))
    security_names = {
        identifier for identifier in identifiers
        if any(word in identifier for word in ("SECRET", "CREDENTIAL", "SESSION", "TOKEN", "KEY"))
    }
    path_literals = {
        "path:" + value
        for _, value in re.findall(r"(['\"])(/[^'\"\r\n]{3,})\1", source or "")
    }
    names = set(re.findall(r"\b[A-Za-z_][A-Za-z0-9_]*\b", source or ""))
    semantic_names = set()
    prefixes = (
        "get_", "load_", "read_", "write_", "verify_", "check_", "set_",
        "regen_", "regenerate_", "generate_", "create_", "make_",
    )
    for name in names:
        normalized = name.lower()
        if not any(word in normalized for word in ("secret", "credential", "session", "token", "key")):
            continue
        semantic_names.add("symbol:" + normalized)
        for prefix in prefixes:
            if normalized.startswith(prefix) and len(normalized) > len(prefix):
                semantic_names.add("symbol:" + normalized[len(prefix):])
                break
    return security_names | path_literals | semantic_names


def _normalize_file_contracts(abstraction, unit, program):
    accesses = _file_accesses(unit.source)
    if not accesses:
        return
    tree = _parse_python(unit.source)
    own_kinds = {
        "provision" if access["operation"] == "write" else "load"
        for access in accesses
    }
    if tree is not None and _credential_comparisons(tree):
        own_kinds.add("verify")
    abstraction["credential_events"] = [
        event for event in abstraction.get("credential_events") or []
        if event.get("kind") in own_kinds
    ]
    all_accesses = [
        (candidate, access)
        for candidate in program.functions.values()
        for access in _file_accesses(candidate.source)
    ]
    for event in abstraction.get("credential_events") or []:
        operation = "write" if event.get("kind") == "provision" else "read"
        if event.get("kind") not in {"provision", "load"}:
            continue
        own = [access for access in accesses if access["operation"] == operation]
        if not own:
            continue
        if not event.get("protects_op_ids"):
            markers = ("write", "open") if operation == "write" else ("read", "open")
            event["protects_op_ids"] = [
                protected["op_id"]
                for protected in abstraction.get("protected_operations") or []
                if protected.get("op_id") and any(
                    marker in str(protected.get("evidence", "")).lower()
                    for marker in markers
                )
            ]
        compatible = True
        matched_peer = False
        for access in own:
            if not access["valid"]:
                compatible = False
            opposite = "read" if operation == "write" else "write"
            peers = [
                peer for candidate, peer in all_accesses
                if candidate.id != unit.id and peer["path"] == access["path"]
                and peer["operation"] == opposite
            ]
            if peers:
                matched_peer = True
                if any(not peer["valid"] or peer["binary"] != access["binary"] for peer in peers):
                    compatible = False
        if not matched_peer:
            continue
        event["contract_status"] = "valid" if compatible else "invalid"
        event["failure_mode"] = (
            "closed" if compatible and _file_contract_failures_are_rejected(own, program)
            else "open"
        )
        event["dominates_all_paths"] = True
        event["confidence"] = "high"

    source_provision = _source_file_provision_contract(
        abstraction, tree, accesses, all_accesses, program
    )
    if source_provision:
        abstraction["credential_events"] = [
            event for event in abstraction.get("credential_events") or []
            if event.get("kind") != "provision"
        ] + [source_provision]


def _normalize_verifier_contract(abstraction, unit, program, tree):
    comparisons = _credential_comparisons(tree)
    if not comparisons:
        return
    own_accesses = _file_accesses(unit.source)
    own_kinds = {
        "provision" if access["operation"] == "write" else "load"
        for access in own_accesses
    }
    abstraction["credential_events"] = [
        event for event in abstraction.get("credential_events") or []
        if event.get("kind") == "verify" or event.get("kind") in own_kinds
    ]
    authenticator_names = {
        name.lower()
        for _, expression, _ in comparisons
        for name in re.findall(r"\b[A-Za-z_][A-Za-z0-9_]*\b", expression)
        if any(word in name.lower() for word in ("secret", "credential", "api_key"))
    }
    identifiers = {"symbol:" + name for name in authenticator_names}
    related = [
        candidate for candidate in program.functions.values()
        if candidate.id != unit.id
        and identifiers & _security_identifiers(candidate.source)
        and _defines_authenticator_source(candidate.source, authenticator_names)
    ]
    sentinels = set()
    for candidate in related:
        sentinels.update(_failure_sentinels(candidate.source))
    if not sentinels:
        return

    protected = []
    for event in abstraction.get("authentication_events") or []:
        text = f"{event.get('verifies_nl', '')} {event.get('evidence', '')}".lower()
        if any(word in text for word in ("secret", "credential", "api_key", "api key")):
            protected.extend(event.get("protects_op_ids") or [])
    protected = list(dict.fromkeys(op_id for op_id in protected if isinstance(op_id, str)))
    if not protected:
        return

    closed = _rejects_sentinels_before_comparison(tree, sentinels, comparisons)
    event = {
        "kind": "verify",
        "contract_status": "valid" if closed else "invalid",
        "failure_mode": "closed" if closed else "open",
        "dominates_all_paths": True,
        "protects_op_ids": protected,
        "confidence": "high",
        "evidence": comparisons[0][2],
    }
    abstraction["credential_events"] = [
        existing for existing in abstraction.get("credential_events") or []
        if existing.get("kind") != "verify"
    ] + [event]


def _normalize_session_key_events(abstraction, tree):
    source = ast.unparse(tree).lower()
    if "session" not in source or not any(word in source for word in ("key", "id")):
        abstraction["session_key_events"] = []
        return
    assignments = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            targets, value = node.targets, node.value
        elif isinstance(node, ast.AnnAssign):
            targets, value = [node.target], node.value
        else:
            continue
        if value is None:
            continue
        for target in targets:
            if _is_session_identifier(target):
                assignments.append((node, value))
    if not assignments:
        return

    assignment, value = max(assignments, key=lambda item: item[0].lineno)
    literal = _literal_value(value)
    if literal is None:
        replacement = "absent"
    elif literal is not _NO_LITERAL:
        replacement = "reusable_value"
    elif isinstance(value, ast.Call) and any(
            word in _terminal_name(value.func) for word in ("random", "token", "uuid")):
        replacement = "fresh_random"
    else:
        replacement = "unknown"
    function = next((
        node for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and assignment in node.body
    ), None)
    clear_statement = _authoritative_session_clear(function, assignment)
    dominates = _ordered_session_retirement(function, clear_statement, assignment)
    protected = [
        operation["op_id"]
        for operation in abstraction.get("protected_operations") or []
        if operation.get("op_id") and any(
            word in str(operation.get("evidence", "")).lower()
            for word in ("session", "key", "clear", "delete", "flush")
        )
    ]
    event = {
        "kind": "retire",
        "replacement": replacement,
        "storage_cleared": clear_statement is not None,
        "dominates_all_paths": dominates,
        "protects_op_ids": protected,
        "confidence": "high",
        "evidence": "; ".join(
            ast.unparse(statement)
            for statement in (clear_statement, assignment)
            if statement is not None
        ),
    }
    abstraction["session_key_events"] = [event]
    if replacement == "absent" and clear_statement is not None and dominates:
        abstraction["session_events"] = [
            existing for existing in abstraction.get("session_events") or []
            if existing.get("kind") != "trust_client_id"
        ]


def _is_session_identifier(node):
    expression = ast.unparse(node).lower()
    return "session" in expression and any(word in expression for word in ("key", "id"))


def _authoritative_session_clear(function, assignment):
    if function is None:
        return None
    assignment_index = function.body.index(assignment)
    candidates = []
    for statement in function.body[:assignment_index]:
        if not isinstance(statement, ast.Expr):
            continue
        for call in (node for node in ast.walk(statement) if isinstance(node, ast.Call)):
            if not any(
                    word in _terminal_name(call.func)
                    for word in ("delete", "remove", "invalidate", "revoke", "purge")):
                continue
            arguments = [*call.args, *(keyword.value for keyword in call.keywords)]
            if any(_is_session_identifier(argument) for argument in arguments):
                candidates.append(statement)
    return candidates[-1] if candidates else None


def _ordered_session_retirement(function, clear_statement, assignment):
    if function is None or clear_statement is None:
        return False
    clear_index = function.body.index(clear_statement)
    assignment_index = function.body.index(assignment)
    if clear_index >= assignment_index:
        return False
    return not any(
        isinstance(node, (ast.Return, ast.Raise, ast.Break, ast.Continue))
        for statement in function.body[:assignment_index]
        for node in ast.walk(statement)
    )


def _is_direct_function_statement(tree, statement):
    return any(
        statement in node.body
        for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    )


def _file_accesses(source):
    tree = _parse_python(source)
    if tree is None:
        return []
    aliases = _constant_string_aliases(tree)
    accesses = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Name) or node.func.id != "open":
            continue
        if not node.args:
            continue
        path = _static_string(node.args[0], aliases)
        if path is None:
            continue
        mode = "r"
        if len(node.args) > 1:
            static_mode = _static_string(node.args[1], aliases)
            if static_mode is not None:
                mode = static_mode
        encoding = next((keyword.value for keyword in node.keywords if keyword.arg == "encoding"), None)
        binary = "b" in mode
        accesses.append({
            "path": path,
            "operation": "write" if any(flag in mode for flag in "wax") else "read",
            "binary": binary,
            "valid": not (binary and encoding is not None),
        })
    return accesses


def _source_file_provision_contract(abstraction, tree, accesses, all_accesses, program):
    if tree is None:
        return None
    write_accesses = [access for access in accesses if access["operation"] == "write"]
    if not write_accesses:
        return None
    write_paths = {access["path"] for access in write_accesses}
    provenance, write_evidence = _credential_write_provenance(tree, write_paths)
    proven_paths = {
        path for path, status in provenance.items()
        if status in {"fresh", "reusable"} and _has_file_credential_verifier(
            path, program
        )
    }
    if not proven_paths:
        return None

    own = [access for access in write_accesses if access["path"] in proven_paths]
    compatible = all(access["valid"] for access in own)
    for access in own:
        peers = [
            peer for candidate, peer in all_accesses
            if peer["path"] == access["path"] and peer["operation"] == "read"
        ]
        if not peers or any(
                not peer["valid"] or peer["binary"] != access["binary"]
                for peer in peers):
            compatible = False
    fresh = all(provenance[path] == "fresh" for path in proven_paths)
    valid = compatible and fresh
    closed = valid and _file_contract_failures_are_rejected(own, program)

    markers, lifecycle_evidence = _credential_file_lifecycle(tree, proven_paths)
    protected = [
        operation["op_id"]
        for operation in abstraction.get("protected_operations") or []
        if operation.get("op_id") and any(
            marker in str(operation.get("evidence", "")).lower()
            for marker in markers
        )
    ]
    evidence = "; ".join(dict.fromkeys(write_evidence + lifecycle_evidence))
    return {
        "kind": "provision",
        "contract_status": "valid" if valid else "invalid",
        "failure_mode": "closed" if closed else "open",
        "dominates_all_paths": True,
        "protects_op_ids": protected,
        "confidence": "high",
        "evidence": evidence,
    }


def _credential_write_provenance(tree, paths):
    value_provenance = {}
    for function in (
            node for node in ast.walk(tree)
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))):
        positional = [*function.args.posonlyargs, *function.args.args]
        for argument, default in zip(positional[-len(function.args.defaults):],
                                     function.args.defaults):
            if _literal_value(default) is not _NO_LITERAL:
                value_provenance[argument.arg.lower()] = "reusable"

    assignments = sorted(
        (node for node in ast.walk(tree) if isinstance(node, (ast.Assign, ast.AnnAssign))),
        key=lambda node: (node.lineno, node.col_offset),
    )
    for assignment in assignments:
        value = assignment.value
        if value is None:
            continue
        status = _credential_value_provenance(value, value_provenance)
        if status == "unknown":
            continue
        targets = assignment.targets if isinstance(assignment, ast.Assign) else [assignment.target]
        for target in targets:
            for name in _assigned_names(target):
                value_provenance[name] = status

    aliases = _constant_string_aliases(tree)
    provenance = {}
    evidence = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.With):
            continue
        for item in node.items:
            call = item.context_expr
            if (not isinstance(call, ast.Call) or _terminal_name(call.func) != "open"
                    or not call.args or item.optional_vars is None):
                continue
            path = _static_string(call.args[0], aliases)
            if path not in paths:
                continue
            handles = _assigned_names(item.optional_vars)
            for child in ast.walk(node):
                if (not isinstance(child, ast.Call) or not isinstance(child.func, ast.Attribute)
                        or child.func.attr.lower() != "write" or not child.args
                        or not (_loaded_names(child.func.value) & handles)):
                    continue
                status = _credential_value_provenance(child.args[0], value_provenance)
                if status != "unknown":
                    provenance[path] = status
                    evidence.append(ast.unparse(node))
    return provenance, evidence


def _credential_value_provenance(value, known):
    if any(
            isinstance(node, ast.Call) and _is_secure_random_call(node)
            for node in ast.walk(value)):
        return "fresh"
    if _literal_value(value) is not _NO_LITERAL:
        return "reusable"
    inputs = _value_input_names(value)
    statuses = {known[name] for name in inputs if name in known}
    if "fresh" in statuses:
        return "fresh"
    if inputs and inputs <= set(known) and statuses == {"reusable"}:
        return "reusable"
    return "unknown"


def _value_input_names(value):
    names = _loaded_names(value)
    for call in (node for node in ast.walk(value) if isinstance(node, ast.Call)):
        names.difference_update(_loaded_names(call.func))
    return names


def _is_secure_random_call(call):
    name = _terminal_name(call.func)
    return (
        name in {"urandom", "get_random_bytes", "randombytes", "generate_key"}
        or name.startswith("token_")
    )


def _has_file_credential_verifier(path, program):
    loaders = [
        candidate for candidate in program.functions.values()
        if any(access["path"] == path and access["operation"] == "read"
               for access in _file_accesses(candidate.source))
    ]
    identifiers = set().union(*(
        _security_identifiers(loader.source) for loader in loaders
    ))
    if not loaders or not identifiers:
        return False
    for candidate in program.functions.values():
        if candidate in loaders or not identifiers & _security_identifiers(candidate.source):
            continue
        candidate_tree = _parse_python(candidate.source)
        if candidate_tree is not None and _credential_comparisons(candidate_tree):
            return True
    return False


def _credential_file_lifecycle(tree, paths):
    aliases = _constant_string_aliases(tree)
    markers = {"open", "write"}
    evidence = []
    metadata_names = {"chmod", "chown", "lchown", "fchmod", "fchown"}
    for call in (node for node in ast.walk(tree) if isinstance(node, ast.Call)):
        name = _terminal_name(call.func)
        if name not in metadata_names or not call.args:
            continue
        path = _static_string(call.args[0], aliases)
        if path not in paths or not _call_is_direct_function_statement(tree, call):
            continue
        markers.add(name)
        evidence.append(ast.unparse(call))
    return markers, evidence


def _call_is_direct_function_statement(tree, call):
    return any(
        call in ast.walk(statement)
        for function in ast.walk(tree)
        if isinstance(function, (ast.FunctionDef, ast.AsyncFunctionDef))
        for statement in function.body
        if isinstance(statement, ast.Expr)
    )


def _file_contract_failures_are_rejected(own_accesses, program):
    paths = {access["path"] for access in own_accesses}
    loaders = [
        candidate for candidate in program.functions.values()
        if any(access["path"] in paths and access["operation"] == "read"
               for access in _file_accesses(candidate.source))
    ]
    sentinels = set()
    loader_identifiers = set()
    for loader in loaders:
        if _has_dynamic_failure_default(loader.source):
            return False
        sentinels.update(_failure_sentinels(loader.source))
        loader_identifiers.update(_security_identifiers(loader.source))
    if not sentinels:
        return True
    verifiers = []
    for candidate in program.functions.values():
        if not loader_identifiers & _security_identifiers(candidate.source):
            continue
        tree = _parse_python(candidate.source)
        if tree is None:
            continue
        comparisons = _credential_comparisons(tree)
        if comparisons:
            verifiers.append((tree, comparisons))
    return bool(verifiers) and all(
        _rejects_sentinels_before_comparison(tree, sentinels, comparisons)
        for tree, comparisons in verifiers
    )


def _has_dynamic_failure_default(source):
    tree = _parse_python(source)
    if tree is None:
        return True
    for node in ast.walk(tree):
        if not isinstance(node, ast.Try):
            continue
        for handler in node.handlers:
            for child in ast.walk(handler):
                if (isinstance(child, ast.Return) and child.value is not None
                        and _literal_value(child.value) is _NO_LITERAL):
                    return True
    return False


def _failure_sentinels(source):
    tree = _parse_python(source)
    if tree is None:
        return set()
    values = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Try):
            continue
        for handler in node.handlers:
            for child in ast.walk(handler):
                if isinstance(child, ast.Return) and isinstance(child.value, ast.Constant):
                    values.add(child.value.value)
                elif (isinstance(child, ast.Return) and isinstance(child.value, ast.UnaryOp)
                      and isinstance(child.value.op, ast.USub)
                      and isinstance(child.value.operand, ast.Constant)):
                    values.add(-child.value.operand.value)
    return values


def _credential_comparisons(tree):
    comparisons = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Compare) or not any(isinstance(op, ast.Eq) for op in node.ops):
            continue
        expressions = [node.left, *node.comparators]
        security = [expr for expr in expressions if _is_authenticator_expr(expr)]
        if not security:
            continue
        other = [expr for expr in expressions if expr not in security]
        if not other or all(_literal_value(expr) is not _NO_LITERAL for expr in other):
            continue
        comparisons.append((node.lineno, ast.unparse(security[0]), ast.unparse(node)))
    return comparisons


def _rejects_sentinels_before_comparison(tree, sentinels, comparisons):
    first_comparison = min(line for line, _, _ in comparisons)
    rejected = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.If) or node.lineno >= first_comparison:
            continue
        if not any(isinstance(child, (ast.Raise, ast.Return)) for child in node.body):
            continue
        for child in ast.walk(node.test):
            if not isinstance(child, ast.Compare):
                continue
            expressions = [child.left, *child.comparators]
            if not any(_is_authenticator_expr(expr) for expr in expressions):
                continue
            for expr in expressions:
                value = _literal_value(expr)
                if value is not _NO_LITERAL and value in sentinels:
                    rejected.add(value)
    return sentinels <= rejected


_NO_LITERAL = object()


def _literal_value(node):
    if isinstance(node, ast.Constant):
        return node.value
    if (isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.USub)
            and isinstance(node.operand, ast.Constant)):
        return -node.operand.value
    return _NO_LITERAL


def _is_authenticator_expr(node):
    try:
        expression = ast.unparse(node).lower()
    except (AttributeError, ValueError):
        return False
    return any(word in expression for word in ("secret", "credential", "api_key", "api key"))


def _has_server_session_lifecycle(tree):
    for node in ast.walk(tree):
        if isinstance(node, (ast.Name, ast.Attribute)) and isinstance(node.ctx, ast.Store):
            if "session" in ast.unparse(node).lower():
                return True
        if isinstance(node, ast.Call):
            name = ast.unparse(node.func).lower()
            if "session" in name and any(word in name for word in ("create", "login", "cycle", "regenerate")):
                return True
    return False


def _is_token_session_event(event):
    evidence = str(event.get("evidence", "")).lower()
    return "token" in evidence and not any(
        marker in evidence for marker in ("session id", "session_id", "session key", "session_key")
    )


def _parse_python(source):
    try:
        return ast.parse(textwrap.dedent(source))
    except SyntaxError:
        return None


def _constant_string_aliases(tree):
    stores = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store):
            stores[node.id] = stores.get(node.id, 0) + 1

    aliases = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            targets = node.targets
            value = node.value
        elif isinstance(node, ast.AnnAssign):
            targets = [node.target]
            value = node.value
        else:
            continue
        if not isinstance(value, ast.Constant) or not isinstance(value.value, str):
            continue
        for target in targets:
            if isinstance(target, ast.Name) and stores.get(target.id) == 1:
                aliases[target.id] = value.value
    return aliases


def _static_string(node, aliases):
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.Name):
        return aliases.get(node.id)
    return None


def _defines_authenticator_source(source, authenticator_names):
    tree = _parse_python(source)
    if tree is None:
        return False
    function_names = {
        node.name.lower()
        for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    }
    return bool(_file_accesses(source)) or any(
        authenticator in function_name
        for authenticator in authenticator_names
        for function_name in function_names
    )


def _validate_guard(event, require_failure_mode):
    if not isinstance(event.get("dominates_all_paths"), bool):
        return "authentication contract requires boolean dominates_all_paths"
    if event.get("confidence") not in {"high", "medium", "low"}:
        return f"unknown authentication contract confidence: {event.get('confidence')}"
    if require_failure_mode and event.get("failure_mode") not in FAILURE_MODES:
        return f"unknown authentication failure mode: {event.get('failure_mode')}"
    return None


def _validate_protected_ops(event):
    value = event.get("protects_op_ids")
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes)):
        return "authentication contract requires protects_op_ids array"
    if any(not _non_empty(op_id) for op_id in value):
        return "authentication contract protects_op_ids must contain strings"
    return None


def _records(value):
    return (
        isinstance(value, Sequence)
        and not isinstance(value, (str, bytes))
        and all(isinstance(record, Mapping) for record in value)
    )


def _non_empty(value):
    return isinstance(value, str) and bool(value.strip())


def _finding(kind, cwe, event, message):
    evidence = event.get("evidence")
    return {
        "kind": kind,
        "cwe": cwe,
        "op": {},
        "evidence": evidence,
        "message": message + (f" [{evidence}]" if evidence else ""),
    }


def _protects(event, op_id):
    protected = event.get("protects_op_ids")
    return (
        isinstance(protected, Sequence)
        and not isinstance(protected, (str, bytes))
        and op_id in protected
    )

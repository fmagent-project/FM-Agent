"""Deterministically validate LLM crypto facts against analyzed source code.

The LLM supplies purpose and higher-level intent. This module owns facts that
source syntax can settle reliably: the random generator family, explicit hash
algorithm, and signing-key provenance through local/module/imported constants or
configuration. A modern API never overrides weak material provenance.
"""

from __future__ import annotations

import ast
import copy
import textwrap
from pathlib import Path


_WEAK_HASHES = {"md2", "md4", "md5", "sha1"}
_HASHES = _WEAK_HASHES | {
    "sha224", "sha256", "sha384", "sha512", "sha3_224", "sha3_256",
    "sha3_384", "sha3_512", "blake2b", "blake2s",
}
_SECURE_RANDOM_APIS = {
    "os.urandom", "secrets.choice", "secrets.randbelow", "secrets.randbits",
    "secrets.token_bytes", "secrets.token_hex", "secrets.token_urlsafe",
    "Crypto.Random.get_random_bytes", "Cryptodome.Random.get_random_bytes",
    "uuid.uuid4",
}
_INSECURE_RANDOM_METHODS = {
    "choice", "choices", "getrandbits", "randbytes", "randint", "random",
    "randrange", "sample", "uniform",
}


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
    source_name = encoded[:-len(suffix)] + "." + extension
    return (path.parent.parent / source_name).as_posix()


def original_source_path(unit) -> Path | None:
    """Locate the original source represented by an extracted FunctionUnit."""
    if not unit.abs_path:
        return None
    extracted = Path(unit.abs_path).resolve()
    parts = extracted.parts
    try:
        marker = len(parts) - 1 - parts[::-1].index("extracted_functions")
    except ValueError:
        return None
    if marker == 0 or parts[marker - 1] != "fm_agent_crypto":
        return None
    stage = Path(*parts[:marker - 1])
    source = stage / source_rel_from_extracted(unit.id.rel)
    return source if source.is_file() else None


def _parse(text: str) -> ast.Module | None:
    try:
        return ast.parse(textwrap.dedent(text))
    except (SyntaxError, ValueError, TypeError):
        return None


def _imports(tree: ast.Module | None) -> dict[str, tuple[str, str | None]]:
    aliases: dict[str, tuple[str, str | None]] = {}
    if tree is None:
        return aliases
    for node in tree.body:
        if isinstance(node, ast.Import):
            for item in node.names:
                aliases[item.asname or item.name.split(".")[0]] = (item.name, None)
        elif isinstance(node, ast.ImportFrom) and node.module:
            for item in node.names:
                aliases[item.asname or item.name] = (node.module, item.name)
    return aliases


def _call_name(node: ast.AST, aliases: dict[str, tuple[str, str | None]]) -> str | None:
    if isinstance(node, ast.Name):
        raw = node.id
    elif isinstance(node, ast.Attribute):
        parent = _call_name(node.value, aliases)
        raw = f"{parent}.{node.attr}" if parent else node.attr
    elif isinstance(node, ast.Call):
        parent = _call_name(node.func, aliases)
        raw = f"{parent}()" if parent else None
    elif isinstance(node, ast.Subscript):
        return _call_name(_subscript_root(node), aliases)
    else:
        return None
    if not raw:
        return None
    root, dot, rest = raw.partition(".")
    imported = aliases.get(root)
    if not imported:
        return raw
    module, symbol = imported
    prefix = f"{module}.{symbol}" if symbol else module
    return prefix + (dot + rest if dot else "")


def _literal_algorithm(node: ast.AST | None) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, (ast.List, ast.Tuple)) and node.elts:
        return _literal_algorithm(node.elts[0])
    return None


def _keyword(call: ast.Call, name: str) -> ast.AST | None:
    return next((kw.value for kw in call.keywords if kw.arg == name), None)


def _subscript_root(expression: ast.Subscript) -> ast.AST:
    root = expression.value
    while isinstance(root, ast.Subscript):
        root = root.value
    return root


def _module_assignments(tree: ast.Module | None) -> dict[str, ast.AST]:
    values: dict[str, ast.AST] = {}
    if tree is None:
        return values
    for node in tree.body:
        if isinstance(node, (ast.Assign, ast.AnnAssign)):
            value = node.value
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            for target in targets:
                if isinstance(target, ast.Name) and value is not None:
                    values[target.id] = value
    return values


def _local_assignments(tree: ast.Module | None) -> dict[str, ast.AST]:
    values: dict[str, ast.AST] = {}
    if tree is None:
        return values
    for node in ast.walk(tree):
        if isinstance(node, (ast.Assign, ast.AnnAssign)):
            value = node.value
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            for target in targets:
                if isinstance(target, ast.Name) and value is not None:
                    values[target.id] = value
    return values


def _module_path(root: Path, module: str) -> Path | None:
    base = root.joinpath(*module.split("."))
    for candidate in (base.with_suffix(".py"), base / "__init__.py"):
        if candidate.is_file():
            return candidate
    return None


def _provenance(
    expression: ast.AST | None,
    aliases: dict[str, tuple[str, str | None]],
    local_values: dict[str, ast.AST],
    source_tree: ast.Module | None,
    project_root: Path | None,
    seen: set[str] | None = None,
) -> tuple[str, dict]:
    seen = seen or set()
    evidence = ast.unparse(expression) if expression is not None else None
    source = {"kind": "unknown", "expression": evidence, "visibility": "unknown"}
    if expression is None:
        return "unknown", source
    if isinstance(expression, (ast.Constant, ast.List, ast.Tuple, ast.Dict, ast.Set)):
        source.update(kind="literal", visibility="local_source")
        return "hardcoded_literal", source
    if isinstance(expression, ast.Name):
        name = expression.id
        if name in seen:
            return "unknown", source
        if name in local_values:
            return _provenance(
                local_values[name], aliases, local_values, source_tree,
                project_root, seen | {name},
            )
        module_value = _module_assignments(source_tree).get(name)
        if module_value is not None:
            provenance, resolved = _provenance(
                module_value, aliases, local_values, source_tree,
                project_root, seen | {name},
            )
            resolved["visibility"] = "project_source"
            return provenance, resolved
        imported = aliases.get(name)
        if imported and imported[1] and project_root:
            imported_path = _module_path(project_root, imported[0])
            if imported_path:
                imported_tree = _parse(imported_path.read_text(errors="replace"))
                imported_value = _module_assignments(imported_tree).get(imported[1])
                if imported_value is not None:
                    provenance, resolved = _provenance(
                        imported_value, _imports(imported_tree), {}, imported_tree,
                        project_root, seen | {name},
                    )
                    resolved.update(
                        visibility="project_source",
                        definition=f"{imported_path.relative_to(project_root)}::{imported[1]}",
                    )
                    return provenance, resolved
        return "unknown", source
    if isinstance(expression, ast.Subscript):
        root = _call_name(_subscript_root(expression), aliases) or ""
        if any(token in root.lower() for token in ("config", "settings", "environ")):
            source.update(kind="config_or_env", visibility="runtime_config")
            return "from_config_or_env", source
    if isinstance(expression, ast.Attribute):
        root = _call_name(expression, aliases) or ""
        if "config" in root.lower() or "settings" in root.lower():
            source.update(kind="config_or_env", visibility="runtime_config")
            return "from_config_or_env", source
        if source_tree is not None:
            for node in ast.walk(source_tree):
                if not isinstance(node, (ast.Assign, ast.AnnAssign)):
                    continue
                value = node.value
                targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                if any(isinstance(target, ast.Attribute) and target.attr == expression.attr for target in targets):
                    return _provenance(value, aliases, local_values, source_tree, project_root, seen)
    if isinstance(expression, ast.Call):
        name = _call_name(expression.func, aliases) or ""
        lower = name.lower()
        if isinstance(expression.func, ast.Attribute) and expression.func.attr in {"hex"}:
            return _provenance(
                expression.func.value, aliases, local_values, source_tree,
                project_root, seen,
            )
        if name in _SECURE_RANDOM_APIS or "generate_key" in lower or "randombytes" in lower:
            source.update(kind="csprng", visibility="runtime_generated")
            return "from_csprng", source
        if any(token in lower for token in ("getenv", "environ.get", "config.get", "settings.get")):
            source.update(kind="config_or_env", visibility="runtime_config")
            return "from_config_or_env", source
        if any(token in lower for token in ("pbkdf2", "scrypt", "argon2", "bcrypt", "hkdf")):
            source.update(kind="kdf", visibility="runtime_derived")
            return "from_kdf", source
    return "unknown", source


def _project_context(unit) -> tuple[Path | None, ast.Module | None, dict[str, tuple[str, str | None]]]:
    source_path = original_source_path(unit)
    if source_path is None:
        return None, None, {}
    project_root = source_path
    rel_parts = Path(source_rel_from_extracted(unit.id.rel)).parts
    for _ in rel_parts:
        project_root = project_root.parent
    source_tree = _parse(source_path.read_text(errors="replace"))
    return project_root, source_tree, _imports(source_tree)


def _detected_calls(unit):
    tree = _parse(unit.source)
    project_root, source_tree, source_aliases = _project_context(unit)
    aliases = {**source_aliases, **_imports(tree)}
    local_values = _local_assignments(tree)
    detected = []
    if tree is None:
        return detected
    for call in (node for node in ast.walk(tree) if isinstance(node, ast.Call)):
        name = _call_name(call.func, aliases)
        if not name:
            continue
        lower = name.lower()
        if name in _SECURE_RANDOM_APIS:
            detected.append({"type": "random", "source": "csprng", "api": name, "node": call})
        elif lower.startswith("random.systemrandom()"):
            detected.append({"type": "random", "source": "csprng", "api": name, "node": call})
        elif lower.startswith("random.") and name.rsplit(".", 1)[-1] in _INSECURE_RANDOM_METHODS:
            detected.append({"type": "random", "source": "insecure_prng", "api": name, "node": call})
        hash_name = name.rsplit(".", 1)[-1].lower()
        if (lower.startswith("hashlib.") or aliases.get(name, (None,))[0] == "hashlib") and hash_name in _HASHES:
            detected.append({"type": "hash", "algorithm": hash_name.upper().replace("_", "-"), "api": name, "node": call})
        if lower in {"jwt.encode", "pyjwt.encode"} or lower.endswith(".jwt.encode"):
            key_expr = call.args[1] if len(call.args) > 1 else _keyword(call, "key")
            provenance, key_source = _provenance(
                key_expr, aliases, local_values, source_tree, project_root,
            )
            detected.append({
                "type": "jwt_encode", "api": name, "node": call,
                "algorithm": _literal_algorithm(_keyword(call, "algorithm")),
                "provenance": provenance, "key_source": key_source,
            })
        if lower in {"jwt.decode", "pyjwt.decode"} or lower.endswith(".jwt.decode"):
            key_expr = call.args[1] if len(call.args) > 1 else _keyword(call, "key")
            provenance, key_source = _provenance(
                key_expr, aliases, local_values, source_tree, project_root,
            )
            detected.append({
                "type": "jwt_decode", "api": name, "node": call,
                "algorithm": _literal_algorithm(_keyword(call, "algorithms")),
                "provenance": provenance, "key_source": key_source,
            })
    return detected


def _random_purpose(unit) -> str:
    semantic_text = (unit.id.name + " " + unit.source).lower()
    if any(word in semantic_text for word in ("token", "verification", "otp", "nonce", "secret", "security code")):
        return "token_generation"
    return "unknown"


def _matching_operation(
    operations: list[dict], kinds: set[str], detection: dict, used: set[int],
) -> dict | None:
    candidates = [
        operation for operation in operations
        if operation.get("kind") in kinds and id(operation) not in used
    ]
    detected_api = str(detection.get("api") or "").lower()
    for operation in candidates:
        if str(operation.get("api") or "").lower() == detected_api:
            used.add(id(operation))
            return operation
    detected_method = detected_api.rsplit(".", 1)[-1]
    for operation in candidates:
        operation_api = str(operation.get("api") or "").lower()
        if operation_api and operation_api.rsplit(".", 1)[-1] == detected_method:
            used.add(id(operation))
            return operation
    if candidates:
        used.add(id(candidates[0]))
        return candidates[0]
    return None


def _source_decidable_operation(operation: dict) -> bool:
    """Whether Python source syntax can prove this claimed operation exists."""
    kind = operation.get("kind")
    api = str(operation.get("api") or "").lower()
    evidence = str(operation.get("evidence") or "").lower()
    if kind == "random":
        return any(token in api or token in evidence for token in (
            "random.", "secrets.", "os.urandom", "uuid.uuid4",
            "crypto.random.get_random_bytes", "cryptodome.random.get_random_bytes",
        ))
    if kind in {"hash", "password_hash"}:
        return api.startswith("hashlib.") or "hashlib." in evidence
    if kind in {"sign", "jwt_decode"}:
        return api in {"jwt.encode", "pyjwt.encode", "jwt.decode", "pyjwt.decode"}
    return False


def _drop_proxy_operations(payload: dict, operations: list[dict], detections: list[dict]) -> list[dict]:
    """Drop operations that merely restate an analyzed internal callee call."""
    callees = {
        str(call.get("callee")) for call in (payload.get("calls") or [])
        if isinstance(call, dict) and call.get("callee")
    }
    detected_apis = {str(item.get("api") or "").lower() for item in detections}
    kept = []
    for operation in operations:
        api = str(operation.get("api") or "")
        is_callee_proxy = any(
            api == callee or api.endswith("." + callee) or callee.endswith("." + api)
            for callee in callees
        )
        if is_callee_proxy and api.lower() not in detected_apis:
            continue
        kept.append(operation)
    return kept


def validate_and_enrich(payload, unit):
    """Return a copied payload with source-decidable facts corrected or added."""
    if not isinstance(payload, dict):
        return None
    enriched = copy.deepcopy(payload)
    operations = enriched.get("crypto_operations")
    if not isinstance(operations, list) or any(not isinstance(op, dict) for op in operations):
        return None
    if unit.id.language.lower() != "python":
        return enriched
    detections = _detected_calls(unit)
    operations = _drop_proxy_operations(enriched, operations, detections)
    used_operations: set[int] = set()
    next_id = len(operations) + 1
    for detection in detections:
        evidence = ast.unparse(detection["node"])
        if detection["type"] == "random":
            operation = _matching_operation(
                operations, {"random"}, detection, used_operations,
            )
            if operation is None and _random_purpose(unit) != "unknown":
                operation = {
                    "id": f"source_op_{next_id}", "kind": "random",
                    "purpose": _random_purpose(unit), "evidence": evidence,
                }
                operations.append(operation)
                used_operations.add(id(operation))
                next_id += 1
            if operation is not None:
                operation["api"] = detection["api"]
                operation["randomness"] = {
                    "source": detection["source"], "api": detection["api"],
                    "evidence": evidence,
                }
        elif detection["type"] == "hash":
            operation = _matching_operation(
                operations, {"hash", "password_hash"}, detection, used_operations,
            )
            if operation is None:
                operation = {
                    "id": f"source_op_{next_id}", "kind": "hash",
                    "purpose": "unknown", "evidence": evidence,
                }
                operations.append(operation)
                used_operations.add(id(operation))
                next_id += 1
            semantic_text = (unit.id.name + " " + unit.source).lower()
            if operation.get("purpose") == "password_storage" and not any(
                word in semantic_text for word in ("password", "passwd", "passphrase")
            ):
                operation["purpose"] = "unknown"
                operation["kind"] = "hash"
            if operation.get("purpose") == "checksum_nonsecurity" and not any(
                word in semantic_text for word in ("checksum", "etag", "dedup", "content hash")
            ):
                operation["purpose"] = "unknown"
            operation["api"] = detection["api"]
            operation["algorithm"] = detection["algorithm"]
        else:
            kind = "sign" if detection["type"] == "jwt_encode" else "jwt_decode"
            operation = _matching_operation(
                operations, {kind}, detection, used_operations,
            )
            if operation is None:
                operation = {
                    "id": f"source_op_{next_id}", "kind": kind,
                    "purpose": "security", "evidence": evidence,
                }
                operations.append(operation)
                used_operations.add(id(operation))
                next_id += 1
            operation["api"] = detection["api"]
            if detection.get("algorithm"):
                operation["algorithm"] = detection["algorithm"]
            operation["key"] = {
                "provenance": detection["provenance"],
                "source": detection["key_source"], "evidence": evidence,
            }
            if kind == "jwt_decode":
                jwt = dict(operation.get("jwt") or {})
                if detection.get("algorithm"):
                    jwt["algorithms_allowed"] = [detection["algorithm"]]
                jwt.setdefault("allows_none", False)
                jwt.setdefault("signature_verification_disabled", False)
                operation["jwt"] = jwt

    operations = [
        operation for operation in operations
        if id(operation) in used_operations or not _source_decidable_operation(operation)
    ]

    # Structured operation checks own all verdicts. LLM red flags are hints and
    # must not overrule corrected source facts (for example, CSPRNG + small OTP).
    enriched["red_flags"] = []
    has_source_verify = any(item["type"] == "jwt_decode" for item in detections)
    if not has_source_verify:
        enriched["verify_events"] = []
    enriched["crypto_operations"] = operations
    return enriched


def source_only_facts(unit) -> dict | None:
    """Derive facts only when recognized source semantics are self-sufficient."""
    facts = validate_and_enrich({
        "schema_version": "crypto_v1",
        "crypto_operations": [],
        "verify_events": [],
        "returns": [],
        "red_flags": [],
    }, unit)
    if facts and facts["crypto_operations"]:
        return facts
    return None


def source_provenance_context(unit) -> str | None:
    """Return compact, source-derived context to improve the LLM abstraction."""
    source_path = original_source_path(unit)
    if source_path is None:
        return None
    tree = _parse(source_path.read_text(errors="replace"))
    if tree is None:
        return None
    lines = []
    for node in tree.body:
        if isinstance(node, (ast.Import, ast.ImportFrom, ast.Assign, ast.AnnAssign)):
            lines.append(ast.unparse(node))
    referenced_attrs = {
        node.attr for node in ast.walk(_parse(unit.source) or ast.Module(body=[], type_ignores=[]))
        if isinstance(node, ast.Attribute)
    }
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and any(
            isinstance(child, ast.Attribute) and isinstance(child.ctx, ast.Store)
            and child.attr in referenced_attrs for child in ast.walk(node)
        ):
            lines.append(ast.unparse(node))
    return "\n".join(lines) or None

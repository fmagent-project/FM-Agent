"""Canonical primitives for hash-bound generic-validator contracts."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from enum import Enum
from typing import Any


_IDENTIFIER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


class ContractError(ValueError):
    """A frozen contract contains a value that cannot be canonicalized."""


def validate_identifier(value: object, field: str) -> str:
    if type(value) is not str or not _IDENTIFIER_RE.fullmatch(value):
        raise ContractError(
            f"{field} must be a non-empty identifier containing only "
            "letters, digits, '.', '_', ':', or '-'"
        )
    return value


def validate_sha256(value: object, field: str) -> str:
    if type(value) is not str or not _SHA256_RE.fullmatch(value):
        raise ContractError(
            f"{field} must be a lowercase 64-character SHA-256 digest"
        )
    return value


def normalize_identifiers(value: object, field: str) -> tuple[str, ...]:
    if type(value) not in (tuple, list, set, frozenset):
        raise ContractError(f"{field} must be a collection of identifiers")
    normalized = tuple(
        sorted({validate_identifier(item, field) for item in value})
    )
    if len(normalized) != len(value):
        raise ContractError(f"{field} must not contain duplicate values")
    return normalized


def _normalize_json(value: Any, path: str = "$") -> Any:
    if value is None or type(value) in (bool, str, int):
        return value
    if type(value) is float:
        raise ContractError(
            f"{path} must not contain floating-point values until a canonical "
            "numeric contract is defined"
        )
    if type(value) in (list, tuple):
        return [
            _normalize_json(item, f"{path}[{index}]")
            for index, item in enumerate(value)
        ]
    if type(value) is dict:
        normalized: dict[str, Any] = {}
        for key, item in value.items():
            if type(key) is not str:
                raise ContractError(f"{path} object keys must be strings")
            normalized[key] = _normalize_json(item, f"{path}.{key}")
        return normalized
    raise ContractError(
        f"{path} has unsupported canonical JSON type {type(value).__name__}"
    )


def canonical_json_bytes(value: Any) -> bytes:
    """Return the sole UTF-8 representation used for contract hashing."""

    normalized = _normalize_json(value)
    return json.dumps(
        normalized,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def canonical_sha256(value: Any) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


class ComponentKind(str, Enum):
    ADAPTER = "adapter"
    ORACLE_BUNDLE = "oracle_bundle"
    EXECUTION_RECIPE_SCHEMA = "execution_recipe_schema"
    TARGET_EVIDENCE_POLICY = "target_evidence_policy"
    REPAIR_POLICY = "repair_policy"
    SANITY_POLICY = "sanity_policy"
    TOOLCHAIN_POLICY = "toolchain_policy"
    COMPATIBILITY_POLICY = "compatibility_policy"
    CONTROL_POLICY = "control_policy"


@dataclass(frozen=True)
class ComponentRef:
    """Exact identity of one content-addressed, immutable component."""

    kind: ComponentKind
    component_id: str
    component_version: str
    content_sha256: str

    def __post_init__(self) -> None:
        if type(self.kind) is not ComponentKind:
            raise ContractError("kind must be a ComponentKind")
        validate_identifier(self.component_id, "component_id")
        validate_identifier(self.component_version, "component_version")
        validate_sha256(self.content_sha256, "content_sha256")

    def to_document(self) -> dict[str, object]:
        return {
            "kind": self.kind.value,
            "component_id": self.component_id,
            "component_version": self.component_version,
            "content_sha256": self.content_sha256,
        }

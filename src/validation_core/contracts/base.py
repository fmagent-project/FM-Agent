"""Canonical primitives for hash-bound generic-validator contracts."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from enum import Enum
from typing import Any, Collection


_IDENTIFIER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")
_SURROGATE_RE = re.compile(r"[\ud800-\udfff]")
_CANONICAL_DECIMAL_RE = re.compile(
    r"(?:0|-?[1-9][0-9]*|-?(?:0|[1-9][0-9]*)\.[0-9]*[1-9])\Z"
)

DEFAULT_MAX_CONTRACT_BYTES = 1_048_576
MAX_CANONICAL_JSON_DEPTH = 128


class ContractError(ValueError):
    """A frozen contract contains a value that cannot be canonicalized."""


def _validate_unicode(value: str, field: str) -> str:
    if _SURROGATE_RE.search(value):
        raise ContractError(f"{field} must not contain Unicode surrogate code points")
    return value


def validate_identifier(value: object, field: str) -> str:
    if type(value) is not str or not _IDENTIFIER_RE.fullmatch(value):
        raise ContractError(
            f"{field} must be a non-empty identifier containing only "
            "letters, digits, '.', '_', ':', or '-'"
        )
    return value


def validate_control_free_string(
    value: object,
    field: str,
    *,
    allow_empty: bool = False,
    max_length: int = 4096,
) -> str:
    """Validate inert human-readable contract text.

    This validator does not turn the value into an executable language.  Schema
    owners remain responsible for rejecting text in fields that should only
    contain closed identifiers or references.
    """

    if type(max_length) is not int or max_length < 1:
        raise ContractError("max_length must be a positive integer")
    if type(value) is not str:
        raise ContractError(f"{field} must be a string")
    _validate_unicode(value, field)
    if (not value and not allow_empty) or len(value) > max_length:
        qualifier = "a non-empty" if not allow_empty else "a"
        raise ContractError(
            f"{field} must be {qualifier} string no longer than {max_length} characters"
        )
    if _CONTROL_RE.search(value):
        raise ContractError(f"{field} must not contain control characters")
    return value


def validate_safe_relative_path(value: object, field: str) -> str:
    """Validate a canonical POSIX path without consulting the host filesystem."""

    if type(value) is not str or not value:
        raise ContractError(f"{field} must be a non-empty POSIX relative path")
    _validate_unicode(value, field)
    if (
        value.startswith("/")
        or value.endswith("/")
        or "\\" in value
        or ":" in value
        or _CONTROL_RE.search(value)
    ):
        raise ContractError(f"{field} must be a safe POSIX relative path")
    parts = value.split("/")
    if any(part in ("", ".", "..") for part in parts):
        raise ContractError(f"{field} contains an unsafe path segment")
    return value


def validate_non_negative_int(
    value: object,
    field: str,
    *,
    maximum: int | None = None,
) -> int:
    if type(value) is not int or value < 0:
        raise ContractError(f"{field} must be a non-negative integer")
    if maximum is not None:
        if type(maximum) is not int or maximum < 0:
            raise ContractError("maximum must be a non-negative integer or None")
        if value > maximum:
            raise ContractError(f"{field} must not exceed {maximum}")
    return value


def validate_positive_int(
    value: object,
    field: str,
    *,
    maximum: int | None = None,
) -> int:
    if type(value) is not int or value < 1:
        raise ContractError(f"{field} must be a positive integer")
    if maximum is not None:
        if type(maximum) is not int or maximum < 1:
            raise ContractError("maximum must be a positive integer or None")
        if value > maximum:
            raise ContractError(f"{field} must not exceed {maximum}")
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


def require_exact_keys(
    value: object,
    *,
    required: Collection[str],
    optional: Collection[str] = (),
    where: str = "$",
) -> dict[str, object]:
    """Require an object to contain exactly its schema's named fields."""

    if type(value) is not dict:
        raise ContractError(f"{where} must be an object")
    if any(type(key) is not str for key in value):
        raise ContractError(f"{where} object keys must be strings")
    if type(required) in (str, bytes) or type(optional) in (str, bytes):
        raise ContractError("schema keys must be collections of field names")
    required_keys = tuple(required)
    optional_keys = tuple(optional)
    if any(type(key) is not str for key in (*required_keys, *optional_keys)):
        raise ContractError("schema keys must be strings")
    if len(set(required_keys)) != len(required_keys):
        raise ContractError("required schema keys must not contain duplicates")
    if len(set(optional_keys)) != len(optional_keys):
        raise ContractError("optional schema keys must not contain duplicates")
    overlap = set(required_keys).intersection(optional_keys)
    if overlap:
        raise ContractError("required and optional schema keys must be disjoint")

    actual = set(value)
    missing = sorted(set(required_keys) - actual)
    unexpected = sorted(actual - set(required_keys) - set(optional_keys))
    if missing or unexpected:
        details: list[str] = []
        if missing:
            details.append(f"missing keys {missing!r}")
        if unexpected:
            details.append(f"unexpected keys {unexpected!r}")
        raise ContractError(f"{where} has " + " and ".join(details))
    return value


def _reject_duplicate_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ContractError(f"JSON object contains duplicate key {key!r}")
        result[key] = value
    return result


def _reject_json_float(value: str) -> None:
    raise ContractError(
        f"JSON floating-point value {value!r} is not a canonical contract number"
    )


def _reject_json_constant(value: str) -> None:
    raise ContractError(f"JSON constant {value!r} is not permitted")


def load_strict_json_object(
    payload: object,
    *,
    max_bytes: int = DEFAULT_MAX_CONTRACT_BYTES,
) -> dict[str, object]:
    """Decode one bounded UTF-8 JSON object using fail-closed numeric rules.

    Decimal contract values must be quoted canonical decimal strings and then
    parsed by :class:`CanonicalDecimal`.  This avoids silently accepting binary
    floats whose serialization varies across implementations.
    """

    if type(max_bytes) is not int or max_bytes < 1:
        raise ContractError("max_bytes must be a positive integer")
    if type(payload) is not bytes:
        raise ContractError("contract payload must be UTF-8 bytes")
    if not payload:
        raise ContractError("contract payload must not be empty")
    if len(payload) > max_bytes:
        raise ContractError(f"contract payload exceeds {max_bytes} bytes")
    try:
        text = payload.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise ContractError("contract payload must be valid UTF-8") from exc
    try:
        value = json.loads(
            text,
            object_pairs_hook=_reject_duplicate_object,
            parse_float=_reject_json_float,
            parse_constant=_reject_json_constant,
        )
    except ContractError:
        raise
    except (json.JSONDecodeError, RecursionError, ValueError) as exc:
        raise ContractError("contract payload must contain valid bounded JSON") from exc
    if type(value) is not dict:
        raise ContractError("contract payload root must be an object")
    # Reuse the canonical tree walk to reject escaped Unicode surrogates and
    # excessive nesting before any schema parser consumes the object.
    normalized = _normalize_json(value)
    if type(normalized) is not dict:  # defensive; the root was checked above
        raise ContractError("contract payload root must be an object")
    return normalized


def _normalize_json(value: Any, path: str = "$", depth: int = 0) -> Any:
    if depth > MAX_CANONICAL_JSON_DEPTH:
        raise ContractError(
            f"{path} exceeds the maximum canonical JSON depth "
            f"of {MAX_CANONICAL_JSON_DEPTH}"
        )
    if value is None or type(value) in (bool, int):
        return value
    if type(value) is str:
        return _validate_unicode(value, path)
    if type(value) is float:
        raise ContractError(
            f"{path} must not contain floating-point values until a canonical "
            "numeric contract is defined"
        )
    if type(value) in (list, tuple):
        return [
            _normalize_json(item, f"{path}[{index}]", depth + 1)
            for index, item in enumerate(value)
        ]
    if type(value) is dict:
        normalized: dict[str, Any] = {}
        for key, item in value.items():
            if type(key) is not str:
                raise ContractError(f"{path} object keys must be strings")
            _validate_unicode(key, f"{path} object key")
            normalized[key] = _normalize_json(item, f"{path}.{key}", depth + 1)
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


@dataclass(frozen=True)
class CanonicalDecimal:
    """A finite decimal with one unambiguous, cross-runtime representation."""

    value: str

    def __post_init__(self) -> None:
        if type(self.value) is not str or not _CANONICAL_DECIMAL_RE.fullmatch(
            self.value
        ):
            raise ContractError(
                "canonical decimal must use plain base-10 notation without "
                "exponent, leading zeros, trailing fractional zeros, or negative zero"
            )
        if len(self.value) > 256:
            raise ContractError("canonical decimal must not exceed 256 characters")

    @classmethod
    def parse(cls, value: object, field: str = "decimal") -> CanonicalDecimal:
        if type(value) is not str:
            raise ContractError(f"{field} must be a canonical decimal string")
        try:
            return cls(value)
        except ContractError as exc:
            raise ContractError(f"{field}: {exc}") from exc

    def to_document(self) -> str:
        return self.value

    def __str__(self) -> str:
        return self.value


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

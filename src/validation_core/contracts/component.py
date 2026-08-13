"""Immutable, non-executable component-description contracts."""

from __future__ import annotations

import re
from dataclasses import dataclass

from .base import (
    ComponentKind,
    ComponentRef,
    ContractError,
    canonical_sha256,
    validate_identifier,
    validate_sha256,
)


_GIT_SHA1_RE = re.compile(r"^[0-9a-f]{40}$")
_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")


def _validate_git_sha1(value: object, field: str) -> str:
    if type(value) is not str or not _GIT_SHA1_RE.fullmatch(value):
        raise ContractError(f"{field} must be a full lowercase Git SHA-1")
    return value


def _validate_relative_path(value: object) -> str:
    if type(value) is not str or not value:
        raise ContractError("relative_path must be a non-empty POSIX path")
    if (
        value.startswith("/")
        or value.endswith("/")
        or "\\" in value
        or ":" in value
        or _CONTROL_RE.search(value)
    ):
        raise ContractError("relative_path must be a safe POSIX relative path")
    parts = value.split("/")
    if any(part in ("", ".", "..") for part in parts):
        raise ContractError("relative_path contains an unsafe path segment")
    return value


def _validate_semantic_value(value: object, field: str) -> str:
    if type(value) is not str or not value or _CONTROL_RE.search(value):
        raise ContractError(f"{field} must be a non-empty control-free string")
    return value


@dataclass(frozen=True)
class ImplementationRef:
    """Source provenance only; this does not authorize code execution."""

    repository_id: str
    revision: str
    relative_path: str
    git_blob_sha1: str
    source_sha256: str
    size_bytes: int

    def __post_init__(self) -> None:
        validate_identifier(self.repository_id, "repository_id")
        _validate_git_sha1(self.revision, "revision")
        _validate_relative_path(self.relative_path)
        _validate_git_sha1(self.git_blob_sha1, "git_blob_sha1")
        validate_sha256(self.source_sha256, "source_sha256")
        if type(self.size_bytes) is not int or self.size_bytes < 1:
            raise ContractError("size_bytes must be a positive integer")

    def to_document(self) -> dict[str, object]:
        return {
            "contract_kind": "implementation_ref",
            "schema_version": 1,
            "repository_id": self.repository_id,
            "revision": self.revision,
            "relative_path": self.relative_path,
            "git_blob_sha1": self.git_blob_sha1,
            "source_sha256": self.source_sha256,
            "size_bytes": self.size_bytes,
        }


@dataclass(frozen=True)
class SemanticClause:
    """One ordered, review-only statement in immutable component content.

    Clauses are human-auditable summaries.  A Gate must never interpret these
    strings as an executable Oracle, recipe, policy, command, or permission.
    """

    clause_id: str
    values: tuple[str, ...]

    def __post_init__(self) -> None:
        validate_identifier(self.clause_id, "clause_id")
        if type(self.values) not in (tuple, list) or not self.values:
            raise ContractError("values must be a non-empty ordered collection")
        values = tuple(
            _validate_semantic_value(value, "values") for value in self.values
        )
        object.__setattr__(self, "values", values)

    def to_document(self) -> dict[str, object]:
        return {
            "clause_id": self.clause_id,
            "values": list(self.values),
        }


@dataclass(frozen=True)
class SemanticContract:
    """Hash-bound semantic summary, not an executable policy language."""

    contract_id: str
    contract_version: str
    clauses: tuple[SemanticClause, ...]

    def __post_init__(self) -> None:
        validate_identifier(self.contract_id, "contract_id")
        validate_identifier(self.contract_version, "contract_version")
        if type(self.clauses) not in (tuple, list) or not self.clauses:
            raise ContractError("clauses must be a non-empty collection")
        clauses = tuple(self.clauses)
        if any(type(clause) is not SemanticClause for clause in clauses):
            raise ContractError("clauses must contain only SemanticClause values")
        ids = tuple(clause.clause_id for clause in clauses)
        if len(ids) != len(set(ids)):
            raise ContractError("clauses must not repeat clause_id")
        object.__setattr__(
            self,
            "clauses",
            tuple(sorted(clauses, key=lambda clause: clause.clause_id)),
        )

    def to_document(self) -> dict[str, object]:
        return {
            "contract_kind": "semantic_contract",
            "schema_version": 1,
            "contract_id": self.contract_id,
            "contract_version": self.contract_version,
            "clauses": [clause.to_document() for clause in self.clauses],
        }

    @property
    def content_sha256(self) -> str:
        return canonical_sha256(self.to_document())


@dataclass(frozen=True)
class ComponentDescriptor:
    """Hash-bound component content without trust or activation state."""

    kind: ComponentKind
    component_id: str
    component_version: str
    semantic_contract: SemanticContract
    implementation_refs: tuple[ImplementationRef, ...]

    def __post_init__(self) -> None:
        if type(self.kind) is not ComponentKind:
            raise ContractError("kind must be a ComponentKind")
        validate_identifier(self.component_id, "component_id")
        validate_identifier(self.component_version, "component_version")
        if type(self.semantic_contract) is not SemanticContract:
            raise ContractError("semantic_contract must be a SemanticContract")
        if (
            type(self.implementation_refs) not in (tuple, list)
            or not self.implementation_refs
        ):
            raise ContractError(
                "implementation_refs must be a non-empty collection"
            )
        references = tuple(self.implementation_refs)
        if any(type(ref) is not ImplementationRef for ref in references):
            raise ContractError(
                "implementation_refs must contain only ImplementationRef values"
            )
        keys = tuple(
            (ref.repository_id, ref.revision, ref.relative_path)
            for ref in references
        )
        if len(keys) != len(set(keys)):
            raise ContractError("implementation_refs contain a duplicate source key")
        object.__setattr__(
            self,
            "implementation_refs",
            tuple(
                sorted(
                    references,
                    key=lambda ref: (
                        ref.repository_id,
                        ref.revision,
                        ref.relative_path,
                    ),
                )
            ),
        )

    def to_document(self) -> dict[str, object]:
        return {
            "contract_kind": "component_descriptor",
            "schema_version": 1,
            "kind": self.kind.value,
            "component_id": self.component_id,
            "component_version": self.component_version,
            "semantic_contract": self.semantic_contract.to_document(),
            "implementation_refs": [
                ref.to_document() for ref in self.implementation_refs
            ],
        }

    @property
    def content_sha256(self) -> str:
        return canonical_sha256(self.to_document())

    @property
    def ref(self) -> ComponentRef:
        return ComponentRef(
            kind=self.kind,
            component_id=self.component_id,
            component_version=self.component_version,
            content_sha256=self.content_sha256,
        )

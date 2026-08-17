"""Strong, trust-free references used by frozen validator contracts."""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum

from .base import (
    ContractError,
    require_exact_keys,
    validate_identifier,
    validate_non_negative_int,
    validate_sha256,
)


_CONTRACT_REF_KIND = "contract_ref"
_ARTIFACT_REF_KIND = "artifact_ref"
_SCHEMA_VERSION = 1
_MAX_ARTIFACT_SIZE = 9_223_372_036_854_775_807
_MEDIA_TYPE_RE = re.compile(
    r"[a-z0-9][a-z0-9!#$&^_.+-]{0,126}/"
    r"[a-z0-9][a-z0-9!#$&^_.+-]{0,126}\Z"
)


class ContractRefKind(str, Enum):
    """Closed reference roles; unknown projects cannot invent executable kinds."""

    FROZEN_PROFILE = "frozen_profile"
    CASE_PLAN = "case_plan"
    CASE_SUBMISSION = "case_submission"
    EXPERIMENT_PLAN_TEMPLATE = "experiment_plan_template"
    EXECUTION_BINDING = "execution_binding"
    BASELINE_SELECTION_RECEIPT = "baseline_selection_receipt"
    OBSERVATION = "observation"
    ORACLE_DECISION = "oracle_decision"
    CROSS_GATE_DECISION = "cross_gate_decision"
    GATE_RECEIPT = "gate_receipt"
    VALIDATION_OUTCOME = "validation_outcome"
    CERTIFICATE = "certificate"
    ORACLE_SPEC = "oracle_spec"
    ORACLE_BUNDLE = "oracle_bundle"
    EXECUTION_RECIPE = "execution_recipe"
    ENTRYPOINT = "entrypoint"
    WORKLOAD_SCHEMA = "workload_schema"
    ADAPTER = "adapter"
    INSTRUMENTATION_PROVIDER = "instrumentation_provider"
    EXECUTION_RECIPE_SCHEMA = "execution_recipe_schema"
    EXECUTION_BLOCK = "execution_block"
    TOOL = "tool"
    ARGV_TEMPLATE = "argv_template"
    COLLECTOR = "collector"
    NORMALIZER = "normalizer"
    COMPARATOR = "comparator"
    HEALTHY_RELATION_POLICY = "healthy_relation_policy"
    DECISION_POLICY = "decision_policy"
    QUALIFICATION_POLICY = "qualification_policy"
    BASELINE_POLICY = "baseline_policy"
    THRESHOLD_POLICY = "threshold_policy"
    TRANSFORM_POLICY = "transform_policy"
    INVARIANT_POLICY = "invariant_policy"
    TIMEOUT_POLICY = "timeout_policy"
    RESOURCE_POLICY = "resource_policy"
    OUTPUT_CONTRACT = "output_contract"
    ENVIRONMENT_POLICY = "environment_policy"
    TARGET_EVIDENCE_POLICY = "target_evidence_policy"
    CONTROL_POLICY = "control_policy"
    REPAIR_POLICY = "repair_policy"
    RESET_POLICY = "reset_policy"
    EXECUTION_EQUIVALENCE_POLICY = "execution_equivalence_policy"
    SNAPSHOT_POLICY = "snapshot_policy"


@dataclass(frozen=True)
class ContractRef:
    """Exact identity of one immutable contract, without admission state."""

    kind: ContractRefKind
    contract_id: str
    contract_version: str
    content_sha256: str

    def __post_init__(self) -> None:
        if type(self.kind) is not ContractRefKind:
            raise ContractError("kind must be a ContractRefKind")
        validate_identifier(self.contract_id, "contract_id")
        validate_identifier(self.contract_version, "contract_version")
        validate_sha256(self.content_sha256, "content_sha256")

    def to_document(self) -> dict[str, object]:
        return {
            "contract_kind": _CONTRACT_REF_KIND,
            "schema_version": _SCHEMA_VERSION,
            "kind": self.kind.value,
            "contract_id": self.contract_id,
            "contract_version": self.contract_version,
            "content_sha256": self.content_sha256,
        }

    @classmethod
    def from_document(cls, document: object) -> ContractRef:
        parsed = require_exact_keys(
            document,
            required=(
                "contract_kind",
                "schema_version",
                "kind",
                "contract_id",
                "contract_version",
                "content_sha256",
            ),
            where="contract_ref",
        )
        if type(parsed["contract_kind"]) is not str or parsed[
            "contract_kind"
        ] != _CONTRACT_REF_KIND:
            raise ContractError("contract_ref.contract_kind must be 'contract_ref'")
        if (
            type(parsed["schema_version"]) is not int
            or parsed["schema_version"] != _SCHEMA_VERSION
        ):
            raise ContractError("contract_ref.schema_version must be integer 1")
        raw_kind = parsed["kind"]
        if type(raw_kind) is not str:
            raise ContractError("contract_ref.kind must be a string enum value")
        try:
            kind = ContractRefKind(raw_kind)
        except ValueError as exc:
            raise ContractError(
                f"contract_ref.kind has unknown value {raw_kind!r}"
            ) from exc
        return cls(
            kind=kind,
            contract_id=validate_identifier(
                parsed["contract_id"], "contract_ref.contract_id"
            ),
            contract_version=validate_identifier(
                parsed["contract_version"], "contract_ref.contract_version"
            ),
            content_sha256=validate_sha256(
                parsed["content_sha256"], "contract_ref.content_sha256"
            ),
        )


@dataclass(frozen=True)
class ArtifactRef:
    """Content-bound artifact metadata with no host or workspace path."""

    role: str
    media_type: str
    size_bytes: int
    content_sha256: str

    def __post_init__(self) -> None:
        validate_identifier(self.role, "role")
        if type(self.media_type) is not str or not _MEDIA_TYPE_RE.fullmatch(
            self.media_type
        ):
            raise ContractError(
                "media_type must be a lowercase type/subtype without parameters"
            )
        validate_non_negative_int(
            self.size_bytes,
            "size_bytes",
            maximum=_MAX_ARTIFACT_SIZE,
        )
        validate_sha256(self.content_sha256, "content_sha256")

    def to_document(self) -> dict[str, object]:
        return {
            "contract_kind": _ARTIFACT_REF_KIND,
            "schema_version": _SCHEMA_VERSION,
            "role": self.role,
            "media_type": self.media_type,
            "size_bytes": self.size_bytes,
            "content_sha256": self.content_sha256,
        }

    @classmethod
    def from_document(cls, document: object) -> ArtifactRef:
        parsed = require_exact_keys(
            document,
            required=(
                "contract_kind",
                "schema_version",
                "role",
                "media_type",
                "size_bytes",
                "content_sha256",
            ),
            where="artifact_ref",
        )
        if type(parsed["contract_kind"]) is not str or parsed[
            "contract_kind"
        ] != _ARTIFACT_REF_KIND:
            raise ContractError("artifact_ref.contract_kind must be 'artifact_ref'")
        if (
            type(parsed["schema_version"]) is not int
            or parsed["schema_version"] != _SCHEMA_VERSION
        ):
            raise ContractError("artifact_ref.schema_version must be integer 1")
        return cls(
            role=validate_identifier(parsed["role"], "artifact_ref.role"),
            media_type=_validate_media_type(
                parsed["media_type"], "artifact_ref.media_type"
            ),
            size_bytes=validate_non_negative_int(
                parsed["size_bytes"],
                "artifact_ref.size_bytes",
                maximum=_MAX_ARTIFACT_SIZE,
            ),
            content_sha256=validate_sha256(
                parsed["content_sha256"], "artifact_ref.content_sha256"
            ),
        )


def _validate_media_type(value: object, field: str) -> str:
    if type(value) is not str or not _MEDIA_TYPE_RE.fullmatch(value):
        raise ContractError(
            f"{field} must be a lowercase type/subtype without parameters"
        )
    return value

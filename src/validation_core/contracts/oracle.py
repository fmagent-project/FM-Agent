"""Frozen, non-executable Oracle specification and bundle contracts."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import ClassVar

from .base import (
    CanonicalDecimal,
    ContractError,
    canonical_sha256,
    load_strict_json_object,
    normalize_identifiers,
    require_exact_keys,
    validate_identifier,
    validate_non_negative_int,
    validate_positive_int,
)
from .references import ArtifactRef, ContractRef, ContractRefKind


_ORACLE_SPEC_KIND = "oracle_spec"
_ORACLE_BUNDLE_KIND = "oracle_bundle"
_SCHEMA_VERSION = 1
_METHOD_VERSION = 1
_MAX_COLLECTION_ITEMS = 1024
_MAX_TIMEOUT_MS = 86_400_000


class ConsequenceDomain(str, Enum):
    CORRECTNESS = "correctness"
    RELIABILITY = "reliability"
    AVAILABILITY = "availability"
    INTEGRITY = "integrity"
    SECURITY = "security"
    PERFORMANCE = "performance"
    RESOURCE = "resource"
    COMPATIBILITY = "compatibility"
    PROTOCOL = "protocol"


class OracleOrigin(str, Enum):
    """Content provenance only; registry admission remains independent."""

    HARNESS_BUILTIN = "harness_builtin"
    MAINTAINER_PRESET = "maintainer_preset"
    SETUP_AGENT_CUSTOM = "setup_agent_custom"


class VariantRole(str, Enum):
    CANDIDATE = "candidate"
    REFERENCE = "reference"
    CONTROL = "control"
    TRANSFORMED = "transformed"


class RetryReason(str, Enum):
    BROKER_LEASE_LOST = "broker_lease_lost"
    DEVICE_LEASE_LOST = "device_lease_lost"
    ENVIRONMENT_FINGERPRINT_DRIFT = "environment_fingerprint_drift"
    COLLECTOR_TRANSPORT_INTERRUPTED = "collector_transport_interrupted"


class ReproducibilityMode(str, Enum):
    DETERMINISTIC = "deterministic"
    STATISTICAL = "statistical"


class ControlEvidenceRole(str, Enum):
    ORACLE_ONLY = "oracle_only"
    CAUSAL_ONLY = "causal_only"
    DUAL_ROLE = "dual_role"


class PrimaryCombination(str, Enum):
    ALL = "all"
    ANY = "any"
    K_OF_N = "k_of_n"


def _enum_value(enum_type: type[Enum], value: object, field: str) -> Enum:
    if type(value) is not str:
        raise ContractError(f"{field} must be a string enum value")
    try:
        return enum_type(value)
    except ValueError as exc:
        raise ContractError(f"{field} has unknown value {value!r}") from exc


def _require_list(value: object, field: str) -> list[object]:
    if type(value) is not list:
        raise ContractError(f"{field} must be an array")
    if len(value) > _MAX_COLLECTION_ITEMS:
        raise ContractError(
            f"{field} must not contain more than {_MAX_COLLECTION_ITEMS} items"
        )
    return value


def _normalize_identifier_tuple(
    value: object,
    field: str,
    *,
    allow_empty: bool = False,
) -> tuple[str, ...]:
    if type(value) not in (tuple, list, set, frozenset):
        raise ContractError(f"{field} must be a collection of identifiers")
    if len(value) > _MAX_COLLECTION_ITEMS:
        raise ContractError(
            f"{field} must not contain more than {_MAX_COLLECTION_ITEMS} items"
        )
    normalized = normalize_identifiers(value, field)
    if not allow_empty and not normalized:
        raise ContractError(f"{field} must not be empty")
    return normalized


def _require_ref_kind(
    value: object,
    expected: ContractRefKind,
    field: str,
) -> ContractRef:
    if type(value) is not ContractRef:
        raise ContractError(f"{field} must be a ContractRef")
    if value.kind is not expected:
        raise ContractError(f"{field} must reference {expected.value}")
    return value


def _parse_ref(
    value: object,
    expected: ContractRefKind,
    field: str,
) -> ContractRef:
    try:
        parsed = ContractRef.from_document(value)
    except ContractError as exc:
        raise ContractError(f"{field}: {exc}") from exc
    return _require_ref_kind(parsed, expected, field)


def _normalize_refs(
    value: object,
    expected: ContractRefKind,
    field: str,
    *,
    allow_empty: bool = False,
) -> tuple[ContractRef, ...]:
    if type(value) not in (tuple, list):
        raise ContractError(f"{field} must be a collection of ContractRef values")
    if len(value) > _MAX_COLLECTION_ITEMS:
        raise ContractError(
            f"{field} must not contain more than {_MAX_COLLECTION_ITEMS} items"
        )
    refs = tuple(_require_ref_kind(item, expected, field) for item in value)
    if not allow_empty and not refs:
        raise ContractError(f"{field} must not be empty")
    identities = tuple(
        (ref.kind, ref.contract_id, ref.contract_version) for ref in refs
    )
    if len(identities) != len(set(identities)):
        raise ContractError(f"{field} must not repeat a contract identity")
    return tuple(
        sorted(
            refs,
            key=lambda ref: (
                ref.kind.value,
                ref.contract_id,
                ref.contract_version,
                ref.content_sha256,
            ),
        )
    )


def _parse_refs(
    value: object,
    expected: ContractRefKind,
    field: str,
    *,
    allow_empty: bool = False,
) -> tuple[ContractRef, ...]:
    refs = tuple(
        _parse_ref(item, expected, f"{field}[{index}]")
        for index, item in enumerate(_require_list(value, field))
    )
    return _normalize_refs(refs, expected, field, allow_empty=allow_empty)


@dataclass(frozen=True)
class OracleVariant:
    variant_id: str
    role: VariantRole
    execution_recipe: ContractRef

    def __post_init__(self) -> None:
        validate_identifier(self.variant_id, "variant_id")
        if type(self.role) is not VariantRole:
            raise ContractError("role must be a VariantRole")
        _require_ref_kind(
            self.execution_recipe,
            ContractRefKind.EXECUTION_RECIPE,
            "execution_recipe",
        )

    def to_document(self) -> dict[str, object]:
        return {
            "variant_id": self.variant_id,
            "role": self.role.value,
            "execution_recipe": self.execution_recipe.to_document(),
        }

    @classmethod
    def from_document(cls, document: object) -> OracleVariant:
        parsed = require_exact_keys(
            document,
            required=("variant_id", "role", "execution_recipe"),
            where="oracle_variant",
        )
        return cls(
            variant_id=validate_identifier(
                parsed["variant_id"], "oracle_variant.variant_id"
            ),
            role=_enum_value(
                VariantRole, parsed["role"], "oracle_variant.role"
            ),
            execution_recipe=_parse_ref(
                parsed["execution_recipe"],
                ContractRefKind.EXECUTION_RECIPE,
                "oracle_variant.execution_recipe",
            ),
        )


@dataclass(frozen=True)
class ApplicabilitySpec:
    domain_id: str
    calibrated_domain: ArtifactRef
    required_capabilities: tuple[str, ...]
    out_of_domain_reason: str

    def __post_init__(self) -> None:
        validate_identifier(self.domain_id, "domain_id")
        if type(self.calibrated_domain) is not ArtifactRef:
            raise ContractError("calibrated_domain must be an ArtifactRef")
        if self.calibrated_domain.role != "calibrated_domain":
            raise ContractError(
                "calibrated_domain artifact role must be 'calibrated_domain'"
            )
        object.__setattr__(
            self,
            "required_capabilities",
            _normalize_identifier_tuple(
                self.required_capabilities,
                "required_capabilities",
                allow_empty=True,
            ),
        )
        validate_identifier(self.out_of_domain_reason, "out_of_domain_reason")

    def to_document(self) -> dict[str, object]:
        return {
            "domain_id": self.domain_id,
            "calibrated_domain": self.calibrated_domain.to_document(),
            "required_capabilities": list(self.required_capabilities),
            "out_of_domain_reason": self.out_of_domain_reason,
        }

    @classmethod
    def from_document(cls, document: object) -> ApplicabilitySpec:
        parsed = require_exact_keys(
            document,
            required=(
                "domain_id",
                "calibrated_domain",
                "required_capabilities",
                "out_of_domain_reason",
            ),
            where="applicability",
        )
        return cls(
            domain_id=validate_identifier(
                parsed["domain_id"], "applicability.domain_id"
            ),
            calibrated_domain=ArtifactRef.from_document(
                parsed["calibrated_domain"]
            ),
            required_capabilities=_normalize_identifier_tuple(
                _require_list(
                    parsed["required_capabilities"],
                    "applicability.required_capabilities",
                ),
                "applicability.required_capabilities",
                allow_empty=True,
            ),
            out_of_domain_reason=validate_identifier(
                parsed["out_of_domain_reason"],
                "applicability.out_of_domain_reason",
            ),
        )


@dataclass(frozen=True)
class CausalControlSpec:
    """Frozen prerequisites for treating one intervention as causal evidence."""

    control_variant_id: str
    control_policy: ContractRef
    causal_prediction: ContractRef
    correctness_guard: ContractRef
    target_association: ContractRef
    reuse_policy: ContractRef

    def __post_init__(self) -> None:
        validate_identifier(self.control_variant_id, "control_variant_id")
        _require_ref_kind(
            self.control_policy,
            ContractRefKind.CONTROL_POLICY,
            "control_policy",
        )
        _require_ref_kind(
            self.causal_prediction,
            ContractRefKind.HEALTHY_RELATION_POLICY,
            "causal_prediction",
        )
        _require_ref_kind(
            self.correctness_guard,
            ContractRefKind.ORACLE_SPEC,
            "correctness_guard",
        )
        _require_ref_kind(
            self.target_association,
            ContractRefKind.TARGET_EVIDENCE_POLICY,
            "target_association",
        )
        _require_ref_kind(
            self.reuse_policy,
            ContractRefKind.CONTROL_POLICY,
            "reuse_policy",
        )

    def to_document(self) -> dict[str, object]:
        return {
            "control_variant_id": self.control_variant_id,
            "control_policy": self.control_policy.to_document(),
            "causal_prediction": self.causal_prediction.to_document(),
            "correctness_guard": self.correctness_guard.to_document(),
            "target_association": self.target_association.to_document(),
            "reuse_policy": self.reuse_policy.to_document(),
        }

    @classmethod
    def from_document(cls, document: object) -> CausalControlSpec:
        parsed = require_exact_keys(
            document,
            required=(
                "control_variant_id",
                "control_policy",
                "causal_prediction",
                "correctness_guard",
                "target_association",
                "reuse_policy",
            ),
            where="causal_control",
        )
        return cls(
            control_variant_id=parsed["control_variant_id"],
            control_policy=_parse_ref(
                parsed["control_policy"],
                ContractRefKind.CONTROL_POLICY,
                "causal_control.control_policy",
            ),
            causal_prediction=_parse_ref(
                parsed["causal_prediction"],
                ContractRefKind.HEALTHY_RELATION_POLICY,
                "causal_control.causal_prediction",
            ),
            correctness_guard=_parse_ref(
                parsed["correctness_guard"],
                ContractRefKind.ORACLE_SPEC,
                "causal_control.correctness_guard",
            ),
            target_association=_parse_ref(
                parsed["target_association"],
                ContractRefKind.TARGET_EVIDENCE_POLICY,
                "causal_control.target_association",
            ),
            reuse_policy=_parse_ref(
                parsed["reuse_policy"],
                ContractRefKind.CONTROL_POLICY,
                "causal_control.reuse_policy",
            ),
        )

    @property
    def component_refs(self) -> tuple[ContractRef, ...]:
        return (
            self.control_policy,
            self.causal_prediction,
            self.target_association,
            self.reuse_policy,
        )


@dataclass(frozen=True)
class QuorumSpec:
    required: int
    total: int

    def __post_init__(self) -> None:
        validate_positive_int(self.required, "required", maximum=10_000)
        validate_positive_int(self.total, "total", maximum=10_000)
        if self.required > self.total:
            raise ContractError("quorum required must not exceed total")

    def to_document(self) -> dict[str, object]:
        return {"required": self.required, "total": self.total}

    @classmethod
    def from_document(cls, document: object) -> QuorumSpec:
        parsed = require_exact_keys(
            document,
            required=("required", "total"),
            where="quorum",
        )
        return cls(required=parsed["required"], total=parsed["total"])


@dataclass(frozen=True)
class ExecutionProtocol:
    """Frozen trial protocol; retry reasons are infrastructure-only.

    A retry never erases the failed attempt.  Target timeout, crash, OOM, and
    semantically invalid output are observations, not retry reasons.
    """

    warmup_runs: int
    repetitions: int
    quorum: QuorumSpec
    timeout_ms: int
    max_retries: int
    retry_reasons: tuple[RetryReason, ...]

    def __post_init__(self) -> None:
        validate_non_negative_int(self.warmup_runs, "warmup_runs", maximum=10_000)
        validate_positive_int(self.repetitions, "repetitions", maximum=10_000)
        if type(self.quorum) is not QuorumSpec:
            raise ContractError("quorum must be a QuorumSpec")
        if self.quorum.total != self.repetitions:
            raise ContractError("quorum total must equal repetitions")
        validate_positive_int(
            self.timeout_ms, "timeout_ms", maximum=_MAX_TIMEOUT_MS
        )
        validate_non_negative_int(self.max_retries, "max_retries", maximum=100)
        if type(self.retry_reasons) not in (tuple, list):
            raise ContractError("retry_reasons must be a collection")
        reasons = tuple(self.retry_reasons)
        if any(type(reason) is not RetryReason for reason in reasons):
            raise ContractError("retry_reasons must contain only RetryReason values")
        if len(reasons) != len(set(reasons)):
            raise ContractError("retry_reasons must not contain duplicates")
        if self.max_retries == 0 and reasons:
            raise ContractError("retry_reasons must be empty when max_retries is zero")
        if self.max_retries > 0 and not reasons:
            raise ContractError(
                "retry_reasons are required when max_retries is positive"
            )
        object.__setattr__(
            self, "retry_reasons", tuple(sorted(reasons, key=lambda item: item.value))
        )

    def to_document(self) -> dict[str, object]:
        return {
            "warmup_runs": self.warmup_runs,
            "repetitions": self.repetitions,
            "quorum": self.quorum.to_document(),
            "timeout_ms": self.timeout_ms,
            "max_retries": self.max_retries,
            "retry_reasons": [reason.value for reason in self.retry_reasons],
        }

    @classmethod
    def from_document(cls, document: object) -> ExecutionProtocol:
        parsed = require_exact_keys(
            document,
            required=(
                "warmup_runs",
                "repetitions",
                "quorum",
                "timeout_ms",
                "max_retries",
                "retry_reasons",
            ),
            where="execution_protocol",
        )
        reasons = tuple(
            _enum_value(
                RetryReason,
                value,
                f"execution_protocol.retry_reasons[{index}]",
            )
            for index, value in enumerate(
                _require_list(
                    parsed["retry_reasons"],
                    "execution_protocol.retry_reasons",
                )
            )
        )
        return cls(
            warmup_runs=parsed["warmup_runs"],
            repetitions=parsed["repetitions"],
            quorum=QuorumSpec.from_document(parsed["quorum"]),
            timeout_ms=parsed["timeout_ms"],
            max_retries=parsed["max_retries"],
            retry_reasons=reasons,
        )


@dataclass(frozen=True)
class ReasonVocabulary:
    violation: tuple[str, ...]
    passed: tuple[str, ...]
    inconclusive: tuple[str, ...]

    def __post_init__(self) -> None:
        groups = {
            "violation": _normalize_identifier_tuple(self.violation, "violation"),
            "passed": _normalize_identifier_tuple(self.passed, "passed"),
            "inconclusive": _normalize_identifier_tuple(
                self.inconclusive, "inconclusive"
            ),
        }
        seen: set[str] = set()
        for field, codes in groups.items():
            overlap = seen.intersection(codes)
            if overlap:
                raise ContractError(
                    "reason vocabulary assigns "
                    f"{sorted(overlap)!r} to multiple verdicts"
                )
            seen.update(codes)
            object.__setattr__(self, field, codes)

    def to_document(self) -> dict[str, object]:
        return {
            "violation": list(self.violation),
            "pass": list(self.passed),
            "inconclusive": list(self.inconclusive),
        }

    @classmethod
    def from_document(cls, document: object) -> ReasonVocabulary:
        parsed = require_exact_keys(
            document,
            required=("violation", "pass", "inconclusive"),
            where="reason_vocabulary",
        )
        return cls(
            violation=_normalize_identifier_tuple(
                _require_list(
                    parsed["violation"], "reason_vocabulary.violation"
                ),
                "reason_vocabulary.violation",
            ),
            passed=_normalize_identifier_tuple(
                _require_list(parsed["pass"], "reason_vocabulary.pass"),
                "reason_vocabulary.pass",
            ),
            inconclusive=_normalize_identifier_tuple(
                _require_list(
                    parsed["inconclusive"], "reason_vocabulary.inconclusive"
                ),
                "reason_vocabulary.inconclusive",
            ),
        )


@dataclass(frozen=True)
class CrossGateReproducibility:
    mode: ReproducibilityMode
    require_same_direction: bool
    require_normalized_equality: bool
    max_effect_delta: CanonicalDecimal | None

    def __post_init__(self) -> None:
        if type(self.mode) is not ReproducibilityMode:
            raise ContractError("mode must be a ReproducibilityMode")
        if type(self.require_same_direction) is not bool:
            raise ContractError("require_same_direction must be a boolean")
        if type(self.require_normalized_equality) is not bool:
            raise ContractError("require_normalized_equality must be a boolean")
        if self.max_effect_delta is not None and type(
            self.max_effect_delta
        ) is not CanonicalDecimal:
            raise ContractError("max_effect_delta must be a CanonicalDecimal or None")
        if (
            self.max_effect_delta is not None
            and self.max_effect_delta.value.startswith("-")
        ):
            raise ContractError("max_effect_delta must not be negative")
        if self.mode is ReproducibilityMode.DETERMINISTIC:
            if self.max_effect_delta is not None:
                raise ContractError(
                    "deterministic reproducibility cannot use max_effect_delta"
                )
        else:
            if not self.require_same_direction:
                raise ContractError(
                    "statistical reproducibility must require the same direction"
                )
            if self.require_normalized_equality:
                raise ContractError(
                    "statistical reproducibility cannot require normalized equality"
                )
            if self.max_effect_delta is None:
                raise ContractError(
                    "statistical reproducibility requires max_effect_delta"
                )

    def to_document(self) -> dict[str, object]:
        return {
            "mode": self.mode.value,
            "require_same_direction": self.require_same_direction,
            "require_normalized_equality": self.require_normalized_equality,
            "max_effect_delta": (
                None
                if self.max_effect_delta is None
                else self.max_effect_delta.to_document()
            ),
        }

    @classmethod
    def from_document(cls, document: object) -> CrossGateReproducibility:
        parsed = require_exact_keys(
            document,
            required=(
                "mode",
                "require_same_direction",
                "require_normalized_equality",
                "max_effect_delta",
            ),
            where="cross_gate_reproducibility",
        )
        raw_delta = parsed["max_effect_delta"]
        return cls(
            mode=_enum_value(
                ReproducibilityMode,
                parsed["mode"],
                "cross_gate_reproducibility.mode",
            ),
            require_same_direction=parsed["require_same_direction"],
            require_normalized_equality=parsed["require_normalized_equality"],
            max_effect_delta=(
                None
                if raw_delta is None
                else CanonicalDecimal.parse(
                    raw_delta, "cross_gate_reproducibility.max_effect_delta"
                )
            ),
        )


@dataclass(frozen=True)
class GoldenMethod:
    candidate_variant_id: str
    expected_artifact: ArtifactRef

    method_id: ClassVar[str] = "golden"
    method_version: ClassVar[int] = _METHOD_VERSION

    def __post_init__(self) -> None:
        validate_identifier(self.candidate_variant_id, "candidate_variant_id")
        if type(self.expected_artifact) is not ArtifactRef:
            raise ContractError("expected_artifact must be an ArtifactRef")
        if self.expected_artifact.role != "golden":
            raise ContractError("expected_artifact role must be 'golden'")

    def to_document(self) -> dict[str, object]:
        return {
            "method_id": self.method_id,
            "method_version": self.method_version,
            "candidate_variant_id": self.candidate_variant_id,
            "expected_artifact": self.expected_artifact.to_document(),
        }


@dataclass(frozen=True)
class DifferentialMethod:
    candidate_variant_id: str
    reference_variant_id: str

    method_id: ClassVar[str] = "differential"
    method_version: ClassVar[int] = _METHOD_VERSION

    def __post_init__(self) -> None:
        validate_identifier(self.candidate_variant_id, "candidate_variant_id")
        validate_identifier(self.reference_variant_id, "reference_variant_id")
        if self.candidate_variant_id == self.reference_variant_id:
            raise ContractError("differential variants must be distinct")

    def to_document(self) -> dict[str, object]:
        return {
            "method_id": self.method_id,
            "method_version": self.method_version,
            "candidate_variant_id": self.candidate_variant_id,
            "reference_variant_id": self.reference_variant_id,
        }


@dataclass(frozen=True)
class MetamorphicMethod:
    source_variant_id: str
    transformed_variant_id: str
    transform_policy: ContractRef

    method_id: ClassVar[str] = "metamorphic"
    method_version: ClassVar[int] = _METHOD_VERSION

    def __post_init__(self) -> None:
        validate_identifier(self.source_variant_id, "source_variant_id")
        validate_identifier(self.transformed_variant_id, "transformed_variant_id")
        if self.source_variant_id == self.transformed_variant_id:
            raise ContractError("metamorphic variants must be distinct")
        _require_ref_kind(
            self.transform_policy,
            ContractRefKind.TRANSFORM_POLICY,
            "transform_policy",
        )

    def to_document(self) -> dict[str, object]:
        return {
            "method_id": self.method_id,
            "method_version": self.method_version,
            "source_variant_id": self.source_variant_id,
            "transformed_variant_id": self.transformed_variant_id,
            "transform_policy": self.transform_policy.to_document(),
        }


@dataclass(frozen=True)
class InvariantMethod:
    variant_id: str
    invariant_policy: ContractRef

    method_id: ClassVar[str] = "invariant"
    method_version: ClassVar[int] = _METHOD_VERSION

    def __post_init__(self) -> None:
        validate_identifier(self.variant_id, "variant_id")
        _require_ref_kind(
            self.invariant_policy,
            ContractRefKind.INVARIANT_POLICY,
            "invariant_policy",
        )

    def to_document(self) -> dict[str, object]:
        return {
            "method_id": self.method_id,
            "method_version": self.method_version,
            "variant_id": self.variant_id,
            "invariant_policy": self.invariant_policy.to_document(),
        }


@dataclass(frozen=True)
class ConsensusMethod:
    candidate_variant_id: str
    reference_variant_ids: tuple[str, ...]
    minimum_reference_agreement: int

    method_id: ClassVar[str] = "consensus"
    method_version: ClassVar[int] = _METHOD_VERSION

    def __post_init__(self) -> None:
        validate_identifier(self.candidate_variant_id, "candidate_variant_id")
        references = _normalize_identifier_tuple(
            self.reference_variant_ids, "reference_variant_ids"
        )
        if len(references) < 2:
            raise ContractError("consensus requires at least two references")
        if self.candidate_variant_id in references:
            raise ContractError("candidate cannot also be a consensus reference")
        validate_positive_int(
            self.minimum_reference_agreement,
            "minimum_reference_agreement",
            maximum=len(references),
        )
        if self.minimum_reference_agreement < 2:
            raise ContractError(
                "consensus requires agreement from at least two references"
            )
        object.__setattr__(self, "reference_variant_ids", references)

    def to_document(self) -> dict[str, object]:
        return {
            "method_id": self.method_id,
            "method_version": self.method_version,
            "candidate_variant_id": self.candidate_variant_id,
            "reference_variant_ids": list(self.reference_variant_ids),
            "minimum_reference_agreement": self.minimum_reference_agreement,
        }


@dataclass(frozen=True)
class StatisticalBaselineMethod:
    candidate_variant_id: str
    baseline_variant_id: str
    metric_id: str

    method_id: ClassVar[str] = "statistical_baseline"
    method_version: ClassVar[int] = _METHOD_VERSION

    def __post_init__(self) -> None:
        validate_identifier(self.candidate_variant_id, "candidate_variant_id")
        validate_identifier(self.baseline_variant_id, "baseline_variant_id")
        validate_identifier(self.metric_id, "metric_id")
        if self.candidate_variant_id == self.baseline_variant_id:
            raise ContractError("statistical baseline variants must be distinct")

    def to_document(self) -> dict[str, object]:
        return {
            "method_id": self.method_id,
            "method_version": self.method_version,
            "candidate_variant_id": self.candidate_variant_id,
            "baseline_variant_id": self.baseline_variant_id,
            "metric_id": self.metric_id,
        }


@dataclass(frozen=True)
class ResourceGrowthMethod:
    variant_id: str
    resource_metric_id: str
    ordered_axis_id: str

    method_id: ClassVar[str] = "resource_growth"
    method_version: ClassVar[int] = _METHOD_VERSION

    def __post_init__(self) -> None:
        validate_identifier(self.variant_id, "variant_id")
        validate_identifier(self.resource_metric_id, "resource_metric_id")
        validate_identifier(self.ordered_axis_id, "ordered_axis_id")

    def to_document(self) -> dict[str, object]:
        return {
            "method_id": self.method_id,
            "method_version": self.method_version,
            "variant_id": self.variant_id,
            "resource_metric_id": self.resource_metric_id,
            "ordered_axis_id": self.ordered_axis_id,
        }


OracleMethod = (
    GoldenMethod
    | DifferentialMethod
    | MetamorphicMethod
    | InvariantMethod
    | ConsensusMethod
    | StatisticalBaselineMethod
    | ResourceGrowthMethod
)

_METHOD_TYPES = (
    GoldenMethod,
    DifferentialMethod,
    MetamorphicMethod,
    InvariantMethod,
    ConsensusMethod,
    StatisticalBaselineMethod,
    ResourceGrowthMethod,
)


def _parse_method(document: object) -> OracleMethod:
    if type(document) is not dict:
        raise ContractError("oracle method must be an object")
    raw_id = document.get("method_id")
    raw_version = document.get("method_version")
    if type(raw_id) is not str:
        raise ContractError("oracle method_id must be a string")
    if type(raw_version) is not int or raw_version != _METHOD_VERSION:
        raise ContractError("oracle method_version must be integer 1")

    if raw_id == GoldenMethod.method_id:
        parsed = require_exact_keys(
            document,
            required=(
                "method_id",
                "method_version",
                "candidate_variant_id",
                "expected_artifact",
            ),
            where="golden_method",
        )
        return GoldenMethod(
            candidate_variant_id=parsed["candidate_variant_id"],
            expected_artifact=ArtifactRef.from_document(
                parsed["expected_artifact"]
            ),
        )
    if raw_id == DifferentialMethod.method_id:
        parsed = require_exact_keys(
            document,
            required=(
                "method_id",
                "method_version",
                "candidate_variant_id",
                "reference_variant_id",
            ),
            where="differential_method",
        )
        return DifferentialMethod(
            candidate_variant_id=parsed["candidate_variant_id"],
            reference_variant_id=parsed["reference_variant_id"],
        )
    if raw_id == MetamorphicMethod.method_id:
        parsed = require_exact_keys(
            document,
            required=(
                "method_id",
                "method_version",
                "source_variant_id",
                "transformed_variant_id",
                "transform_policy",
            ),
            where="metamorphic_method",
        )
        return MetamorphicMethod(
            source_variant_id=parsed["source_variant_id"],
            transformed_variant_id=parsed["transformed_variant_id"],
            transform_policy=_parse_ref(
                parsed["transform_policy"],
                ContractRefKind.TRANSFORM_POLICY,
                "metamorphic_method.transform_policy",
            ),
        )
    if raw_id == InvariantMethod.method_id:
        parsed = require_exact_keys(
            document,
            required=(
                "method_id",
                "method_version",
                "variant_id",
                "invariant_policy",
            ),
            where="invariant_method",
        )
        return InvariantMethod(
            variant_id=parsed["variant_id"],
            invariant_policy=_parse_ref(
                parsed["invariant_policy"],
                ContractRefKind.INVARIANT_POLICY,
                "invariant_method.invariant_policy",
            ),
        )
    if raw_id == ConsensusMethod.method_id:
        parsed = require_exact_keys(
            document,
            required=(
                "method_id",
                "method_version",
                "candidate_variant_id",
                "reference_variant_ids",
                "minimum_reference_agreement",
            ),
            where="consensus_method",
        )
        return ConsensusMethod(
            candidate_variant_id=parsed["candidate_variant_id"],
            reference_variant_ids=_normalize_identifier_tuple(
                _require_list(
                    parsed["reference_variant_ids"],
                    "consensus_method.reference_variant_ids",
                ),
                "consensus_method.reference_variant_ids",
            ),
            minimum_reference_agreement=parsed[
                "minimum_reference_agreement"
            ],
        )
    if raw_id == StatisticalBaselineMethod.method_id:
        parsed = require_exact_keys(
            document,
            required=(
                "method_id",
                "method_version",
                "candidate_variant_id",
                "baseline_variant_id",
                "metric_id",
            ),
            where="statistical_baseline_method",
        )
        return StatisticalBaselineMethod(
            candidate_variant_id=parsed["candidate_variant_id"],
            baseline_variant_id=parsed["baseline_variant_id"],
            metric_id=parsed["metric_id"],
        )
    if raw_id == ResourceGrowthMethod.method_id:
        parsed = require_exact_keys(
            document,
            required=(
                "method_id",
                "method_version",
                "variant_id",
                "resource_metric_id",
                "ordered_axis_id",
            ),
            where="resource_growth_method",
        )
        return ResourceGrowthMethod(
            variant_id=parsed["variant_id"],
            resource_metric_id=parsed["resource_metric_id"],
            ordered_axis_id=parsed["ordered_axis_id"],
        )
    raise ContractError(f"oracle method_id has unknown value {raw_id!r}")


def _method_component_refs(method: OracleMethod) -> tuple[ContractRef, ...]:
    if type(method) is MetamorphicMethod:
        return (method.transform_policy,)
    if type(method) is InvariantMethod:
        return (method.invariant_policy,)
    return ()


def _method_variant_ids(method: OracleMethod) -> frozenset[str]:
    if type(method) is GoldenMethod:
        return frozenset({method.candidate_variant_id})
    if type(method) is DifferentialMethod:
        return frozenset(
            {method.candidate_variant_id, method.reference_variant_id}
        )
    if type(method) is MetamorphicMethod:
        return frozenset(
            {method.source_variant_id, method.transformed_variant_id}
        )
    if type(method) is InvariantMethod:
        return frozenset({method.variant_id})
    if type(method) is ConsensusMethod:
        return frozenset(
            (method.candidate_variant_id, *method.reference_variant_ids)
        )
    if type(method) is StatisticalBaselineMethod:
        return frozenset(
            {method.candidate_variant_id, method.baseline_variant_id}
        )
    if type(method) is ResourceGrowthMethod:
        return frozenset({method.variant_id})
    raise ContractError("method must be a supported typed Oracle method")


def _validate_method_variants(
    method: OracleMethod,
    variants: tuple[OracleVariant, ...],
) -> None:
    by_id = {variant.variant_id: variant.role for variant in variants}

    def require(variant_id: str, roles: tuple[VariantRole, ...], field: str) -> None:
        role = by_id.get(variant_id)
        if role is None:
            raise ContractError(f"{field} names an undeclared variant")
        if role not in roles:
            expected = ", ".join(item.value for item in roles)
            raise ContractError(f"{field} must have one of roles: {expected}")

    if type(method) is GoldenMethod:
        require(method.candidate_variant_id, (VariantRole.CANDIDATE,), "candidate")
    elif type(method) is DifferentialMethod:
        require(method.candidate_variant_id, (VariantRole.CANDIDATE,), "candidate")
        require(
            method.reference_variant_id,
            (VariantRole.REFERENCE, VariantRole.CONTROL),
            "reference",
        )
    elif type(method) is MetamorphicMethod:
        require(method.source_variant_id, (VariantRole.CANDIDATE,), "source")
        require(
            method.transformed_variant_id,
            (VariantRole.TRANSFORMED,),
            "transformed",
        )
    elif type(method) is InvariantMethod:
        require(method.variant_id, (VariantRole.CANDIDATE,), "variant")
    elif type(method) is ConsensusMethod:
        require(
            method.candidate_variant_id,
            (VariantRole.CANDIDATE,),
            "consensus candidate",
        )
        for variant_id in method.reference_variant_ids:
            require(
                variant_id,
                (VariantRole.REFERENCE,),
                "consensus reference",
            )
    elif type(method) is StatisticalBaselineMethod:
        require(method.candidate_variant_id, (VariantRole.CANDIDATE,), "candidate")
        require(
            method.baseline_variant_id,
            (VariantRole.REFERENCE, VariantRole.CONTROL),
            "baseline",
        )
    elif type(method) is ResourceGrowthMethod:
        require(method.variant_id, (VariantRole.CANDIDATE,), "variant")


@dataclass(frozen=True)
class OracleSpec:
    oracle_id: str
    oracle_version: str
    declared_origin: OracleOrigin
    consequence_domain: ConsequenceDomain
    method: OracleMethod
    applicability: ApplicabilitySpec
    variants: tuple[OracleVariant, ...]
    collectors: tuple[ContractRef, ...]
    normalizer: ContractRef
    comparator: ContractRef
    execution_protocol: ExecutionProtocol
    healthy_relation: ContractRef
    decision_policy: ContractRef
    qualification_policy: ContractRef
    baseline_policy: ContractRef | None
    threshold_policy: ContractRef | None
    cross_gate_reproducibility: CrossGateReproducibility
    reason_vocabulary: ReasonVocabulary
    control_evidence_role: ControlEvidenceRole
    causal_control: CausalControlSpec | None

    def __post_init__(self) -> None:
        validate_identifier(self.oracle_id, "oracle_id")
        validate_identifier(self.oracle_version, "oracle_version")
        if type(self.declared_origin) is not OracleOrigin:
            raise ContractError("declared_origin must be an OracleOrigin")
        if type(self.consequence_domain) is not ConsequenceDomain:
            raise ContractError("consequence_domain must be a ConsequenceDomain")
        if type(self.method) not in _METHOD_TYPES:
            raise ContractError("method must be a supported typed Oracle method")
        if type(self.applicability) is not ApplicabilitySpec:
            raise ContractError("applicability must be an ApplicabilitySpec")
        if type(self.variants) not in (tuple, list):
            raise ContractError("variants must be a collection")
        variants = tuple(self.variants)
        if not variants:
            raise ContractError("variants must not be empty")
        if len(variants) > _MAX_COLLECTION_ITEMS:
            raise ContractError("variants contains too many entries")
        if any(type(variant) is not OracleVariant for variant in variants):
            raise ContractError("variants must contain only OracleVariant values")
        ids = tuple(variant.variant_id for variant in variants)
        if len(ids) != len(set(ids)):
            raise ContractError("variants must not repeat variant_id")
        recipe_hashes: dict[tuple[str, str], str] = {}
        for variant in variants:
            recipe = variant.execution_recipe
            recipe_key = (recipe.contract_id, recipe.contract_version)
            prior_hash = recipe_hashes.get(recipe_key)
            if prior_hash is not None and prior_hash != recipe.content_sha256:
                raise ContractError(
                    "variants contain conflicting hashes for one recipe identity"
                )
            recipe_hashes[recipe_key] = recipe.content_sha256
        object.__setattr__(
            self,
            "variants",
            tuple(sorted(variants, key=lambda item: item.variant_id)),
        )
        _validate_method_variants(self.method, self.variants)
        object.__setattr__(
            self,
            "collectors",
            _normalize_refs(
                self.collectors, ContractRefKind.COLLECTOR, "collectors"
            ),
        )
        _require_ref_kind(
            self.normalizer, ContractRefKind.NORMALIZER, "normalizer"
        )
        _require_ref_kind(
            self.comparator, ContractRefKind.COMPARATOR, "comparator"
        )
        if type(self.execution_protocol) is not ExecutionProtocol:
            raise ContractError("execution_protocol must be an ExecutionProtocol")
        _require_ref_kind(
            self.healthy_relation,
            ContractRefKind.HEALTHY_RELATION_POLICY,
            "healthy_relation",
        )
        _require_ref_kind(
            self.decision_policy,
            ContractRefKind.DECISION_POLICY,
            "decision_policy",
        )
        _require_ref_kind(
            self.qualification_policy,
            ContractRefKind.QUALIFICATION_POLICY,
            "qualification_policy",
        )
        if self.baseline_policy is not None:
            _require_ref_kind(
                self.baseline_policy,
                ContractRefKind.BASELINE_POLICY,
                "baseline_policy",
            )
        if self.threshold_policy is not None:
            _require_ref_kind(
                self.threshold_policy,
                ContractRefKind.THRESHOLD_POLICY,
                "threshold_policy",
            )
        statistical = type(self.method) is StatisticalBaselineMethod
        resource_growth = type(self.method) is ResourceGrowthMethod
        if statistical and self.baseline_policy is None:
            raise ContractError("statistical_baseline requires baseline_policy")
        if not statistical and self.baseline_policy is not None:
            raise ContractError(
                "baseline_policy is only valid for statistical_baseline"
            )
        if (statistical or resource_growth) and self.threshold_policy is None:
            raise ContractError(
                "statistical_baseline and resource_growth require threshold_policy"
            )
        if type(self.cross_gate_reproducibility) is not CrossGateReproducibility:
            raise ContractError(
                "cross_gate_reproducibility must be a CrossGateReproducibility"
            )
        if statistical and (
            self.cross_gate_reproducibility.mode
            is not ReproducibilityMode.STATISTICAL
        ):
            raise ContractError(
                "statistical_baseline requires statistical cross-gate rules"
            )
        if type(self.reason_vocabulary) is not ReasonVocabulary:
            raise ContractError("reason_vocabulary must be a ReasonVocabulary")
        if (
            self.applicability.out_of_domain_reason
            not in self.reason_vocabulary.inconclusive
        ):
            raise ContractError(
                "applicability out_of_domain_reason must be an inconclusive reason"
            )
        if type(self.control_evidence_role) is not ControlEvidenceRole:
            raise ContractError("control_evidence_role must be a ControlEvidenceRole")
        control_variants = tuple(
            variant.variant_id
            for variant in self.variants
            if variant.role is VariantRole.CONTROL
        )
        roles_by_id = {
            variant.variant_id: variant.role for variant in self.variants
        }
        oracle_control_id: str | None = None
        if type(self.method) is DifferentialMethod:
            oracle_control_id = self.method.reference_variant_id
        elif type(self.method) is StatisticalBaselineMethod:
            oracle_control_id = self.method.baseline_variant_id
        uses_control_as_oracle = (
            oracle_control_id is not None
            and roles_by_id[oracle_control_id] is VariantRole.CONTROL
        )
        if self.causal_control is not None and type(
            self.causal_control
        ) is not CausalControlSpec:
            raise ContractError("causal_control must be a CausalControlSpec or None")
        if self.control_evidence_role is ControlEvidenceRole.ORACLE_ONLY:
            if self.causal_control is not None:
                raise ContractError(
                    "oracle_only cannot carry causal control prerequisites"
                )
        elif self.causal_control is None:
            raise ContractError(
                "causal control evidence roles require causal_control"
            )
        else:
            if control_variants != (self.causal_control.control_variant_id,):
                raise ContractError(
                    "causal_control must identify the sole control variant"
                )
            guard = self.causal_control.correctness_guard
            if (
                guard.contract_id == self.oracle_id
                and guard.contract_version == self.oracle_version
            ):
                raise ContractError("causal correctness guard cannot self-reference")
        if (
            self.control_evidence_role is ControlEvidenceRole.CAUSAL_ONLY
            and uses_control_as_oracle
        ):
            raise ContractError(
                "causal_only control cannot be used as an Oracle reference"
            )
        if (
            self.control_evidence_role is ControlEvidenceRole.DUAL_ROLE
            and not uses_control_as_oracle
        ):
            raise ContractError(
                "dual_role requires the control to be an Oracle reference"
            )
        declared_variant_ids = frozenset(ids)
        expected_variant_ids = _method_variant_ids(self.method)
        if self.causal_control is not None:
            expected_variant_ids = expected_variant_ids.union(
                {self.causal_control.control_variant_id}
            )
        if declared_variant_ids != expected_variant_ids:
            raise ContractError(
                "variants must exactly match method and causal-control inputs"
            )
        # Trigger cross-field identity conflict detection during construction,
        # rather than waiting for a profile graph consumer to access the view.
        self.component_refs

    def to_document(self) -> dict[str, object]:
        return {
            "contract_kind": _ORACLE_SPEC_KIND,
            "schema_version": _SCHEMA_VERSION,
            "oracle_id": self.oracle_id,
            "oracle_version": self.oracle_version,
            "declared_origin": self.declared_origin.value,
            "consequence_domain": self.consequence_domain.value,
            "method": self.method.to_document(),
            "applicability": self.applicability.to_document(),
            "variants": [variant.to_document() for variant in self.variants],
            "collectors": [ref.to_document() for ref in self.collectors],
            "normalizer": self.normalizer.to_document(),
            "comparator": self.comparator.to_document(),
            "execution_protocol": self.execution_protocol.to_document(),
            "healthy_relation": self.healthy_relation.to_document(),
            "decision_policy": self.decision_policy.to_document(),
            "qualification_policy": self.qualification_policy.to_document(),
            "baseline_policy": (
                None
                if self.baseline_policy is None
                else self.baseline_policy.to_document()
            ),
            "threshold_policy": (
                None
                if self.threshold_policy is None
                else self.threshold_policy.to_document()
            ),
            "cross_gate_reproducibility": (
                self.cross_gate_reproducibility.to_document()
            ),
            "reason_vocabulary": self.reason_vocabulary.to_document(),
            "control_evidence_role": self.control_evidence_role.value,
            "causal_control": (
                None
                if self.causal_control is None
                else self.causal_control.to_document()
            ),
        }

    @classmethod
    def from_document(cls, document: object) -> OracleSpec:
        required = (
            "contract_kind",
            "schema_version",
            "oracle_id",
            "oracle_version",
            "declared_origin",
            "consequence_domain",
            "method",
            "applicability",
            "variants",
            "collectors",
            "normalizer",
            "comparator",
            "execution_protocol",
            "healthy_relation",
            "decision_policy",
            "qualification_policy",
            "baseline_policy",
            "threshold_policy",
            "cross_gate_reproducibility",
            "reason_vocabulary",
            "control_evidence_role",
            "causal_control",
        )
        parsed = require_exact_keys(
            document, required=required, where="oracle_spec"
        )
        if (
            type(parsed["contract_kind"]) is not str
            or parsed["contract_kind"] != _ORACLE_SPEC_KIND
        ):
            raise ContractError("oracle_spec.contract_kind must be 'oracle_spec'")
        if (
            type(parsed["schema_version"]) is not int
            or parsed["schema_version"] != _SCHEMA_VERSION
        ):
            raise ContractError("oracle_spec.schema_version must be integer 1")
        variants = tuple(
            OracleVariant.from_document(item)
            for item in _require_list(parsed["variants"], "oracle_spec.variants")
        )
        raw_baseline = parsed["baseline_policy"]
        raw_threshold = parsed["threshold_policy"]
        return cls(
            oracle_id=parsed["oracle_id"],
            oracle_version=parsed["oracle_version"],
            declared_origin=_enum_value(
                OracleOrigin,
                parsed["declared_origin"],
                "oracle_spec.declared_origin",
            ),
            consequence_domain=_enum_value(
                ConsequenceDomain,
                parsed["consequence_domain"],
                "oracle_spec.consequence_domain",
            ),
            method=_parse_method(parsed["method"]),
            applicability=ApplicabilitySpec.from_document(
                parsed["applicability"]
            ),
            variants=variants,
            collectors=_parse_refs(
                parsed["collectors"], ContractRefKind.COLLECTOR, "collectors"
            ),
            normalizer=_parse_ref(
                parsed["normalizer"],
                ContractRefKind.NORMALIZER,
                "normalizer",
            ),
            comparator=_parse_ref(
                parsed["comparator"],
                ContractRefKind.COMPARATOR,
                "comparator",
            ),
            execution_protocol=ExecutionProtocol.from_document(
                parsed["execution_protocol"]
            ),
            healthy_relation=_parse_ref(
                parsed["healthy_relation"],
                ContractRefKind.HEALTHY_RELATION_POLICY,
                "healthy_relation",
            ),
            decision_policy=_parse_ref(
                parsed["decision_policy"],
                ContractRefKind.DECISION_POLICY,
                "decision_policy",
            ),
            qualification_policy=_parse_ref(
                parsed["qualification_policy"],
                ContractRefKind.QUALIFICATION_POLICY,
                "qualification_policy",
            ),
            baseline_policy=(
                None
                if raw_baseline is None
                else _parse_ref(
                    raw_baseline,
                    ContractRefKind.BASELINE_POLICY,
                    "baseline_policy",
                )
            ),
            threshold_policy=(
                None
                if raw_threshold is None
                else _parse_ref(
                    raw_threshold,
                    ContractRefKind.THRESHOLD_POLICY,
                    "threshold_policy",
                )
            ),
            cross_gate_reproducibility=CrossGateReproducibility.from_document(
                parsed["cross_gate_reproducibility"]
            ),
            reason_vocabulary=ReasonVocabulary.from_document(
                parsed["reason_vocabulary"]
            ),
            control_evidence_role=_enum_value(
                ControlEvidenceRole,
                parsed["control_evidence_role"],
                "oracle_spec.control_evidence_role",
            ),
            causal_control=(
                None
                if parsed["causal_control"] is None
                else CausalControlSpec.from_document(parsed["causal_control"])
            ),
        )

    @classmethod
    def from_json(cls, payload: object) -> OracleSpec:
        return cls.from_document(load_strict_json_object(payload))

    @property
    def content_sha256(self) -> str:
        return canonical_sha256(self.to_document())

    @property
    def ref(self) -> ContractRef:
        return ContractRef(
            kind=ContractRefKind.ORACLE_SPEC,
            contract_id=self.oracle_id,
            contract_version=self.oracle_version,
            content_sha256=self.content_sha256,
        )

    @property
    def component_refs(self) -> tuple[ContractRef, ...]:
        refs = (
            *self.collectors,
            self.normalizer,
            self.comparator,
            self.healthy_relation,
            self.decision_policy,
            self.qualification_policy,
            *(() if self.baseline_policy is None else (self.baseline_policy,)),
            *(() if self.threshold_policy is None else (self.threshold_policy,)),
            *_method_component_refs(self.method),
            *(
                ()
                if self.causal_control is None
                else self.causal_control.component_refs
            ),
        )
        by_identity: dict[tuple[ContractRefKind, str, str], ContractRef] = {}
        for ref in refs:
            key = (ref.kind, ref.contract_id, ref.contract_version)
            previous = by_identity.get(key)
            if previous is not None and previous.content_sha256 != ref.content_sha256:
                raise ContractError(
                    "component_refs contains conflicting hashes for one identity"
                )
            by_identity[key] = ref
        return tuple(
            sorted(
                by_identity.values(),
                key=lambda ref: (
                    ref.kind.value,
                    ref.contract_id,
                    ref.contract_version,
                    ref.content_sha256,
                ),
            )
        )

    @property
    def execution_recipe_refs(self) -> tuple[ContractRef, ...]:
        refs = {variant.execution_recipe for variant in self.variants}
        return tuple(
            sorted(
                refs,
                key=lambda ref: (
                    ref.contract_id,
                    ref.contract_version,
                    ref.content_sha256,
                ),
            )
        )

    @property
    def dependent_oracle_spec_refs(self) -> tuple[ContractRef, ...]:
        if self.causal_control is None:
            return ()
        return (self.causal_control.correctness_guard,)


@dataclass(frozen=True)
class OracleBundle:
    bundle_id: str
    bundle_version: str
    required_guards: tuple[ContractRef, ...]
    primary_oracles: tuple[ContractRef, ...]
    supporting_oracles: tuple[ContractRef, ...]
    primary_combination: PrimaryCombination
    k: int | None
    control_evidence_role: ControlEvidenceRole
    control_oracle: ContractRef | None
    primary_metric_oracle: ContractRef | None
    multiplicity_policy: ContractRef | None

    def __post_init__(self) -> None:
        validate_identifier(self.bundle_id, "bundle_id")
        validate_identifier(self.bundle_version, "bundle_version")
        object.__setattr__(
            self,
            "required_guards",
            _normalize_refs(
                self.required_guards,
                ContractRefKind.ORACLE_SPEC,
                "required_guards",
                allow_empty=True,
            ),
        )
        object.__setattr__(
            self,
            "primary_oracles",
            _normalize_refs(
                self.primary_oracles,
                ContractRefKind.ORACLE_SPEC,
                "primary_oracles",
            ),
        )
        object.__setattr__(
            self,
            "supporting_oracles",
            _normalize_refs(
                self.supporting_oracles,
                ContractRefKind.ORACLE_SPEC,
                "supporting_oracles",
                allow_empty=True,
            ),
        )
        groups = (
            self.required_guards,
            self.primary_oracles,
            self.supporting_oracles,
        )
        identities = [
            (ref.contract_id, ref.contract_version) for group in groups for ref in group
        ]
        if len(identities) != len(set(identities)):
            raise ContractError(
                "an OracleSpec identity may appear in only one bundle role"
            )
        if type(self.primary_combination) is not PrimaryCombination:
            raise ContractError("primary_combination must be a PrimaryCombination")
        if self.primary_combination is PrimaryCombination.K_OF_N:
            if self.k is None:
                raise ContractError("k_of_n requires k")
            validate_positive_int(self.k, "k", maximum=len(self.primary_oracles))
        elif self.k is not None:
            raise ContractError("k is only valid for k_of_n")
        if type(self.control_evidence_role) is not ControlEvidenceRole:
            raise ContractError("control_evidence_role must be a ControlEvidenceRole")
        all_oracles = frozenset(
            (*self.required_guards, *self.primary_oracles, *self.supporting_oracles)
        )
        if self.control_oracle is not None:
            _require_ref_kind(
                self.control_oracle,
                ContractRefKind.ORACLE_SPEC,
                "control_oracle",
            )
            if self.control_oracle not in all_oracles:
                raise ContractError("control_oracle must be a bundle member")
        if self.control_evidence_role is ControlEvidenceRole.ORACLE_ONLY:
            if self.control_oracle is not None:
                raise ContractError(
                    "oracle_only bundle must not designate causal control evidence"
                )
        elif self.control_oracle is None:
            raise ContractError(
                "causal bundle evidence requires a member control_oracle"
            )
        if self.primary_metric_oracle is not None:
            _require_ref_kind(
                self.primary_metric_oracle,
                ContractRefKind.ORACLE_SPEC,
                "primary_metric_oracle",
            )
        if self.multiplicity_policy is not None:
            _require_ref_kind(
                self.multiplicity_policy,
                ContractRefKind.DECISION_POLICY,
                "multiplicity_policy",
            )
        if len(self.primary_oracles) > 1:
            has_metric = self.primary_metric_oracle is not None
            has_policy = self.multiplicity_policy is not None
            if has_metric != has_policy:
                raise ContractError(
                    "multiple-comparison fields must be supplied together"
                )
            if has_metric and self.primary_metric_oracle not in self.primary_oracles:
                raise ContractError(
                    "primary_metric_oracle must be one of the primary oracles"
                )
        elif (
            self.primary_metric_oracle is not None
            or self.multiplicity_policy is not None
        ):
            raise ContractError(
                "single primary must not carry multiple-comparison fields"
            )

    def to_document(self) -> dict[str, object]:
        return {
            "contract_kind": _ORACLE_BUNDLE_KIND,
            "schema_version": _SCHEMA_VERSION,
            "bundle_id": self.bundle_id,
            "bundle_version": self.bundle_version,
            "required_guards": [ref.to_document() for ref in self.required_guards],
            "primary_oracles": [ref.to_document() for ref in self.primary_oracles],
            "supporting_oracles": [
                ref.to_document() for ref in self.supporting_oracles
            ],
            "primary_combination": self.primary_combination.value,
            "k": self.k,
            "control_evidence_role": self.control_evidence_role.value,
            "control_oracle": (
                None
                if self.control_oracle is None
                else self.control_oracle.to_document()
            ),
            "primary_metric_oracle": (
                None
                if self.primary_metric_oracle is None
                else self.primary_metric_oracle.to_document()
            ),
            "multiplicity_policy": (
                None
                if self.multiplicity_policy is None
                else self.multiplicity_policy.to_document()
            ),
        }

    @classmethod
    def from_document(cls, document: object) -> OracleBundle:
        parsed = require_exact_keys(
            document,
            required=(
                "contract_kind",
                "schema_version",
                "bundle_id",
                "bundle_version",
                "required_guards",
                "primary_oracles",
                "supporting_oracles",
                "primary_combination",
                "k",
                "control_evidence_role",
                "control_oracle",
                "primary_metric_oracle",
                "multiplicity_policy",
            ),
            where="oracle_bundle",
        )
        if (
            type(parsed["contract_kind"]) is not str
            or parsed["contract_kind"] != _ORACLE_BUNDLE_KIND
        ):
            raise ContractError("oracle_bundle.contract_kind must be 'oracle_bundle'")
        if (
            type(parsed["schema_version"]) is not int
            or parsed["schema_version"] != _SCHEMA_VERSION
        ):
            raise ContractError("oracle_bundle.schema_version must be integer 1")
        return cls(
            bundle_id=parsed["bundle_id"],
            bundle_version=parsed["bundle_version"],
            required_guards=_parse_refs(
                parsed["required_guards"],
                ContractRefKind.ORACLE_SPEC,
                "required_guards",
                allow_empty=True,
            ),
            primary_oracles=_parse_refs(
                parsed["primary_oracles"],
                ContractRefKind.ORACLE_SPEC,
                "primary_oracles",
            ),
            supporting_oracles=_parse_refs(
                parsed["supporting_oracles"],
                ContractRefKind.ORACLE_SPEC,
                "supporting_oracles",
                allow_empty=True,
            ),
            primary_combination=_enum_value(
                PrimaryCombination,
                parsed["primary_combination"],
                "oracle_bundle.primary_combination",
            ),
            k=parsed["k"],
            control_evidence_role=_enum_value(
                ControlEvidenceRole,
                parsed["control_evidence_role"],
                "oracle_bundle.control_evidence_role",
            ),
            control_oracle=(
                None
                if parsed["control_oracle"] is None
                else _parse_ref(
                    parsed["control_oracle"],
                    ContractRefKind.ORACLE_SPEC,
                    "oracle_bundle.control_oracle",
                )
            ),
            primary_metric_oracle=(
                None
                if parsed["primary_metric_oracle"] is None
                else _parse_ref(
                    parsed["primary_metric_oracle"],
                    ContractRefKind.ORACLE_SPEC,
                    "oracle_bundle.primary_metric_oracle",
                )
            ),
            multiplicity_policy=(
                None
                if parsed["multiplicity_policy"] is None
                else _parse_ref(
                    parsed["multiplicity_policy"],
                    ContractRefKind.DECISION_POLICY,
                    "oracle_bundle.multiplicity_policy",
                )
            ),
        )

    @classmethod
    def from_json(cls, payload: object) -> OracleBundle:
        return cls.from_document(load_strict_json_object(payload))

    @property
    def content_sha256(self) -> str:
        return canonical_sha256(self.to_document())

    @property
    def ref(self) -> ContractRef:
        return ContractRef(
            kind=ContractRefKind.ORACLE_BUNDLE,
            contract_id=self.bundle_id,
            contract_version=self.bundle_version,
            content_sha256=self.content_sha256,
        )

    @property
    def oracle_spec_refs(self) -> tuple[ContractRef, ...]:
        return (
            *self.required_guards,
            *self.primary_oracles,
            *self.supporting_oracles,
        )

    @property
    def component_refs(self) -> tuple[ContractRef, ...]:
        if self.multiplicity_policy is None:
            return ()
        return (self.multiplicity_policy,)

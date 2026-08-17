"""Deterministic, self-identifying Oracle normalizer/comparator atoms."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from decimal import Decimal, localcontext

from ..contracts import (
    ArtifactRef,
    CanonicalDecimal,
    CanonicalTypedValue,
    CanonicalValueKind,
    ConsensusMethod,
    ContractRef,
    ContractRefKind,
    DifferentialMethod,
    GoldenMethod,
    InvariantMethod,
    MetamorphicMethod,
    OracleVerdict,
    StatisticalBaselineMethod,
    canonical_json_bytes,
    load_strict_json_object,
)
from ..contracts.base import (
    ContractError,
    canonical_sha256,
    require_exact_keys,
    validate_identifier,
    validate_non_negative_int,
    validate_positive_int,
    validate_sha256,
)
from .model import AtomicDataError, AtomicRunResult, AtomicRunStatus, TrialDecision


_ATOM_VERSION = "1.0.0"


def _atom_ref(kind: ContractRefKind, atom_id: str, descriptor: object) -> ContractRef:
    return ContractRef(kind, atom_id, _ATOM_VERSION, canonical_sha256(descriptor))


def _normalized_payload_key(value: CanonicalTypedValue) -> str:
    document = value.to_document()
    if value.kind is CanonicalValueKind.ARTIFACT:
        artifact = value.value
        return canonical_sha256(
            {
                "kind": document["kind"],
                "media_type": artifact.media_type,
                "size_bytes": artifact.size_bytes,
                "content_sha256": artifact.content_sha256,
            }
        )
    return canonical_sha256({"kind": document["kind"], "value": document["value"]})


def _single_artifact(result: AtomicRunResult) -> ArtifactRef:
    if result.status is not AtomicRunStatus.COMPLETED or len(result.artifacts) != 1:
        raise AtomicDataError(
            "METRIC_INVALID",
            "a completed run with exactly one artifact is required",
        )
    return result.artifacts[0].artifact


@dataclass(frozen=True)
class Utf8ArtifactNormalizer:
    atom_id: str = "builtin.normalizer.utf8_exact"

    reason_codes = ("METRIC_INVALID",)

    def __post_init__(self) -> None:
        validate_identifier(self.atom_id, "atom_id")

    @property
    def atom_ref(self) -> ContractRef:
        return _atom_ref(
            ContractRefKind.NORMALIZER,
            self.atom_id,
            {
                "atom": "utf8_exact",
                "version": 1,
                "reason_codes": list(self.reason_codes),
            },
        )

    def __call__(self, variant_id, repetition_index, result, read_artifact):
        try:
            text = read_artifact(_single_artifact(result)).decode("utf-8")
        except UnicodeDecodeError as exc:
            raise AtomicDataError("METRIC_INVALID", "artifact is not UTF-8") from exc
        return CanonicalTypedValue(variant_id, CanonicalValueKind.TEXT, text)


@dataclass(frozen=True)
class CanonicalDecimalNormalizer:
    atom_id: str = "builtin.normalizer.canonical_decimal"

    reason_codes = ("METRIC_INVALID",)

    def __post_init__(self) -> None:
        validate_identifier(self.atom_id, "atom_id")

    @property
    def atom_ref(self) -> ContractRef:
        return _atom_ref(
            ContractRefKind.NORMALIZER,
            self.atom_id,
            {
                "atom": "canonical_decimal",
                "version": 1,
                "reason_codes": list(self.reason_codes),
            },
        )

    def __call__(self, variant_id, repetition_index, result, read_artifact):
        try:
            text = read_artifact(_single_artifact(result)).decode("ascii")
            value = CanonicalDecimal.parse(text, "runner decimal output")
        except (UnicodeDecodeError, ContractError) as exc:
            raise AtomicDataError(
                "METRIC_INVALID",
                "artifact is not a canonical decimal",
            ) from exc
        return CanonicalTypedValue(variant_id, CanonicalValueKind.DECIMAL, value)


@dataclass(frozen=True)
class ArtifactIdentityNormalizer:
    atom_id: str = "builtin.normalizer.artifact_identity"

    reason_codes = ("METRIC_INVALID",)

    def __post_init__(self) -> None:
        validate_identifier(self.atom_id, "atom_id")

    @property
    def atom_ref(self) -> ContractRef:
        return _atom_ref(
            ContractRefKind.NORMALIZER,
            self.atom_id,
            {
                "atom": "artifact_identity",
                "version": 1,
                "reason_codes": list(self.reason_codes),
            },
        )

    def __call__(self, variant_id, repetition_index, result, read_artifact):
        artifact = _single_artifact(result)
        read_artifact(artifact)
        return CanonicalTypedValue(
            variant_id,
            CanonicalValueKind.ARTIFACT,
            artifact,
        )


@dataclass(frozen=True)
class RunStatusNormalizer:
    atom_id: str = "builtin.normalizer.run_status"

    reason_codes = ()

    def __post_init__(self) -> None:
        validate_identifier(self.atom_id, "atom_id")

    @property
    def atom_ref(self) -> ContractRef:
        return _atom_ref(
            ContractRefKind.NORMALIZER,
            self.atom_id,
            {
                "atom": "run_status",
                "version": 1,
                "reason_codes": list(self.reason_codes),
            },
        )

    def __call__(self, variant_id, repetition_index, result, read_artifact):
        return CanonicalTypedValue(
            variant_id,
            CanonicalValueKind.TEXT,
            result.status.value,
        )


def _normalize_policy_refs(value: object) -> tuple[ContractRef, ...]:
    if type(value) not in (tuple, list) or any(
        type(item) is not ContractRef for item in value
    ):
        raise ContractError("policy_refs must contain ContractRef values")
    refs = tuple(value)
    if len(refs) != len(set(refs)):
        raise ContractError("policy_refs must not contain duplicates")
    return tuple(
        sorted(
            refs,
            key=lambda item: (
                item.kind.value,
                item.contract_id,
                item.contract_version,
                item.content_sha256,
            ),
        )
    )


class _ComparatorIdentity:
    atom_id: str
    policy_refs: tuple[ContractRef, ...]
    atom_name: str
    reason_codes: dict[OracleVerdict, tuple[str, ...]]
    supported_method_types: tuple[type, ...]

    @property
    def threshold_values(self) -> tuple[CanonicalTypedValue, ...]:
        return ()

    @property
    def atom_ref(self) -> ContractRef:
        descriptor = {
            "atom": self.atom_name,
            "version": 1,
            "supported_methods": [
                {
                    "method_id": method_type.method_id,
                    "method_version": method_type.method_version,
                }
                for method_type in sorted(
                    self.supported_method_types,
                    key=lambda item: (item.method_id, item.method_version),
                )
            ],
            "policy_refs": [item.to_document() for item in self.policy_refs],
            "reason_codes": {
                verdict.value: list(self.reason_codes[verdict])
                for verdict in OracleVerdict
            },
            **self._descriptor_parameters(),
        }
        return _atom_ref(ContractRefKind.COMPARATOR, self.atom_id, descriptor)

    def _descriptor_parameters(self) -> dict[str, object]:
        return {}


@dataclass(frozen=True)
class ExactEqualityComparator(_ComparatorIdentity):
    policy_refs: tuple[ContractRef, ...]
    atom_id: str = "builtin.comparator.exact_equality"

    atom_name = "exact_equality"
    supported_method_types = (DifferentialMethod, MetamorphicMethod)
    reason_codes = {
        OracleVerdict.VIOLATION: ("RELATION_VIOLATED",),
        OracleVerdict.PASS: ("RELATION_HOLDS",),
        OracleVerdict.INCONCLUSIVE: ("METRIC_INVALID",),
    }

    def __post_init__(self) -> None:
        validate_identifier(self.atom_id, "atom_id")
        object.__setattr__(self, "policy_refs", _normalize_policy_refs(self.policy_refs))

    def __call__(
        self, method, values, read_artifact=None, *, repetition_index=None
    ):
        if type(method) not in (DifferentialMethod, MetamorphicMethod) or len(values) != 2:
            return TrialDecision(OracleVerdict.INCONCLUSIVE, "METRIC_INVALID", ())
        by_id = {value.value_id: value for value in values}
        ids = (
            (method.candidate_variant_id, method.reference_variant_id)
            if type(method) is DifferentialMethod
            else (method.source_variant_id, method.transformed_variant_id)
        )
        try:
            left, right = (by_id[item] for item in ids)
        except KeyError:
            return TrialDecision(OracleVerdict.INCONCLUSIVE, "METRIC_INVALID", ())
        equal = _normalized_payload_key(left) == _normalized_payload_key(right)
        return TrialDecision(
            OracleVerdict.PASS if equal else OracleVerdict.VIOLATION,
            "RELATION_HOLDS" if equal else "RELATION_VIOLATED",
            tuple(values),
        )


@dataclass(frozen=True)
class GoldenArtifactComparator(_ComparatorIdentity):
    policy_refs: tuple[ContractRef, ...]
    atom_id: str = "builtin.comparator.golden_artifact"

    atom_name = "golden_artifact"
    supported_method_types = (GoldenMethod,)
    reason_codes = ExactEqualityComparator.reason_codes

    def __post_init__(self) -> None:
        validate_identifier(self.atom_id, "atom_id")
        object.__setattr__(self, "policy_refs", _normalize_policy_refs(self.policy_refs))

    def __call__(
        self, method, values, read_artifact=None, *, repetition_index=None
    ):
        if type(method) is not GoldenMethod or len(values) != 1:
            return TrialDecision(OracleVerdict.INCONCLUSIVE, "METRIC_INVALID", ())
        candidate = values[0]
        if (
            candidate.value_id != method.candidate_variant_id
            or candidate.kind is not CanonicalValueKind.ARTIFACT
            or type(candidate.value) is not ArtifactRef
        ):
            return TrialDecision(OracleVerdict.INCONCLUSIVE, "METRIC_INVALID", ())
        actual = candidate.value
        expected = method.expected_artifact
        equal = (
            actual.media_type,
            actual.size_bytes,
            actual.content_sha256,
        ) == (
            expected.media_type,
            expected.size_bytes,
            expected.content_sha256,
        )
        return TrialDecision(
            OracleVerdict.PASS if equal else OracleVerdict.VIOLATION,
            "RELATION_HOLDS" if equal else "RELATION_VIOLATED",
            tuple(values),
        )


@dataclass(frozen=True)
class BooleanInvariantComparator(_ComparatorIdentity):
    policy_refs: tuple[ContractRef, ...]
    atom_id: str = "builtin.comparator.boolean_invariant"

    atom_name = "boolean_invariant"
    supported_method_types = (InvariantMethod,)
    reason_codes = ExactEqualityComparator.reason_codes

    def __post_init__(self) -> None:
        validate_identifier(self.atom_id, "atom_id")
        object.__setattr__(self, "policy_refs", _normalize_policy_refs(self.policy_refs))

    def __call__(
        self, method, values, read_artifact=None, *, repetition_index=None
    ):
        if type(method) is not InvariantMethod or len(values) != 1:
            return TrialDecision(OracleVerdict.INCONCLUSIVE, "METRIC_INVALID", ())
        value = values[0]
        if value.value_id != method.variant_id or value.kind is not CanonicalValueKind.BOOLEAN:
            return TrialDecision(OracleVerdict.INCONCLUSIVE, "METRIC_INVALID", ())
        holds = value.value is True
        return TrialDecision(
            OracleVerdict.PASS if holds else OracleVerdict.VIOLATION,
            "RELATION_HOLDS" if holds else "RELATION_VIOLATED",
            tuple(values),
        )


@dataclass(frozen=True)
class ConsensusEqualityComparator(_ComparatorIdentity):
    policy_refs: tuple[ContractRef, ...]
    atom_id: str = "builtin.comparator.consensus_equality"

    atom_name = "consensus_equality"
    supported_method_types = (ConsensusMethod,)
    reason_codes = {
        OracleVerdict.VIOLATION: ("RELATION_VIOLATED",),
        OracleVerdict.PASS: ("RELATION_HOLDS",),
        OracleVerdict.INCONCLUSIVE: ("METRIC_INVALID", "REFERENCE_UNAVAILABLE"),
    }

    def __post_init__(self) -> None:
        validate_identifier(self.atom_id, "atom_id")
        object.__setattr__(self, "policy_refs", _normalize_policy_refs(self.policy_refs))

    def __call__(
        self, method, values, read_artifact=None, *, repetition_index=None
    ):
        if type(method) is not ConsensusMethod:
            return TrialDecision(OracleVerdict.INCONCLUSIVE, "METRIC_INVALID", ())
        by_id = {value.value_id: value for value in values}
        try:
            candidate = by_id[method.candidate_variant_id]
            references = tuple(by_id[item] for item in method.reference_variant_ids)
        except KeyError:
            return TrialDecision(OracleVerdict.INCONCLUSIVE, "METRIC_INVALID", ())
        counts = Counter(_normalized_payload_key(item) for item in references)
        if not counts:
            return TrialDecision(
                OracleVerdict.INCONCLUSIVE,
                "REFERENCE_UNAVAILABLE",
                (),
            )
        [(winner, count), *rest] = counts.most_common()
        if count < method.minimum_reference_agreement or (
            rest and rest[0][1] == count
        ):
            return TrialDecision(
                OracleVerdict.INCONCLUSIVE,
                "REFERENCE_UNAVAILABLE",
                tuple(values),
            )
        equal = _normalized_payload_key(candidate) == winner
        return TrialDecision(
            OracleVerdict.PASS if equal else OracleVerdict.VIOLATION,
            "RELATION_HOLDS" if equal else "RELATION_VIOLATED",
            tuple(values),
        )


@dataclass(frozen=True)
class ScalarEstimate:
    """One trial-bound output from an externally qualified estimator.

    The envelope makes replay and literal cross-trial reuse detectable.  It does
    not itself grant trust to the estimator implementation; code admission and
    qualification reports belong to the profile/adapter registry.
    """

    variant_id: str
    repetition_index: int
    pair_id: str
    metric_id: str
    estimator_id: str
    estimate: CanonicalDecimal
    lower_bound: CanonicalDecimal
    upper_bound: CanonicalDecimal
    confidence: CanonicalDecimal
    sample_count: int
    qualification_policy_sha256: str
    interval_semantics: str = "simultaneous_two_arm"

    def __post_init__(self) -> None:
        validate_identifier(self.variant_id, "variant_id")
        validate_non_negative_int(
            self.repetition_index,
            "repetition_index",
            maximum=100_000,
        )
        validate_identifier(self.pair_id, "pair_id")
        validate_identifier(self.metric_id, "metric_id")
        validate_identifier(self.estimator_id, "estimator_id")
        if self.interval_semantics != "simultaneous_two_arm":
            raise ContractError(
                "scalar estimate requires simultaneous two-arm coverage"
            )
        for field in ("estimate", "lower_bound", "upper_bound", "confidence"):
            if type(getattr(self, field)) is not CanonicalDecimal:
                raise ContractError(f"{field} must be a CanonicalDecimal")
        validate_positive_int(self.sample_count, "sample_count", maximum=10**12)
        validate_sha256(
            self.qualification_policy_sha256,
            "qualification_policy_sha256",
        )
        estimate = Decimal(self.estimate.value)
        lower = Decimal(self.lower_bound.value)
        upper = Decimal(self.upper_bound.value)
        confidence = Decimal(self.confidence.value)
        if lower < 0 or estimate < lower or estimate > upper:
            raise ContractError(
                "scalar estimate must satisfy 0 <= lower <= estimate <= upper"
            )
        if confidence <= 0 or confidence >= 1:
            raise ContractError("confidence must be strictly between zero and one")

    def to_document(self) -> dict[str, object]:
        return {
            "contract_kind": "scalar_estimate",
            "schema_version": 1,
            "variant_id": self.variant_id,
            "repetition_index": self.repetition_index,
            "pair_id": self.pair_id,
            "metric_id": self.metric_id,
            "estimator_id": self.estimator_id,
            "estimate": self.estimate.to_document(),
            "lower_bound": self.lower_bound.to_document(),
            "upper_bound": self.upper_bound.to_document(),
            "confidence": self.confidence.to_document(),
            "sample_count": self.sample_count,
            "qualification_policy_sha256": self.qualification_policy_sha256,
            "interval_semantics": self.interval_semantics,
        }

    def to_json(self) -> bytes:
        return canonical_json_bytes(self.to_document())

    @classmethod
    def from_json(cls, payload: bytes) -> "ScalarEstimate":
        parsed = require_exact_keys(
            load_strict_json_object(payload),
            required=(
                "contract_kind",
                "schema_version",
                "variant_id",
                "repetition_index",
                "pair_id",
                "metric_id",
                "estimator_id",
                "estimate",
                "lower_bound",
                "upper_bound",
                "confidence",
                "sample_count",
                "qualification_policy_sha256",
                "interval_semantics",
            ),
            where="scalar_estimate",
        )
        if parsed["contract_kind"] != "scalar_estimate":
            raise ContractError("scalar_estimate contract_kind is invalid")
        if type(parsed["schema_version"]) is not int or parsed["schema_version"] != 1:
            raise ContractError("scalar_estimate schema_version must be integer 1")
        return cls(
            variant_id=parsed["variant_id"],
            repetition_index=parsed["repetition_index"],
            pair_id=parsed["pair_id"],
            metric_id=parsed["metric_id"],
            estimator_id=parsed["estimator_id"],
            estimate=CanonicalDecimal.parse(parsed["estimate"], "estimate"),
            lower_bound=CanonicalDecimal.parse(
                parsed["lower_bound"], "lower_bound"
            ),
            upper_bound=CanonicalDecimal.parse(
                parsed["upper_bound"], "upper_bound"
            ),
            confidence=CanonicalDecimal.parse(parsed["confidence"], "confidence"),
            sample_count=parsed["sample_count"],
            qualification_policy_sha256=parsed["qualification_policy_sha256"],
            interval_semantics=parsed["interval_semantics"],
        )


@dataclass(frozen=True)
class RatioUpperBoundComparator(_ComparatorIdentity):
    """Conservative ratio decision over joint-coverage arm intervals.

    vLLM can later provide its hierarchical paired-bootstrap estimates, but the
    generic comparator never treats one unqualified scalar as statistical
    proof.  Each arm must carry a qualified estimator, minimum sample count,
    and a simultaneous two-arm interval before repetition quorum is considered.
    """

    policy_refs: tuple[ContractRef, ...]
    max_ratio: CanonicalDecimal
    estimator_id: str
    confidence: CanonicalDecimal
    min_samples_per_variant: int
    interval_semantics: str = "simultaneous_two_arm"
    atom_id: str = "builtin.comparator.ratio_upper_bound"

    atom_name = "ratio_upper_bound"
    supported_method_types = (StatisticalBaselineMethod,)
    reason_codes = {
        OracleVerdict.VIOLATION: ("RELATION_VIOLATED",),
        OracleVerdict.PASS: ("RELATION_HOLDS",),
        OracleVerdict.INCONCLUSIVE: (
            "CI_CROSSES_BOUNDARY",
            "INSUFFICIENT_SAMPLES",
            "METRIC_INVALID",
        ),
    }

    def __post_init__(self) -> None:
        validate_identifier(self.atom_id, "atom_id")
        validate_identifier(self.estimator_id, "estimator_id")
        if self.interval_semantics != "simultaneous_two_arm":
            raise ContractError(
                "ratio comparator requires simultaneous two-arm intervals"
            )
        object.__setattr__(self, "policy_refs", _normalize_policy_refs(self.policy_refs))
        for field in ("max_ratio", "confidence"):
            if type(getattr(self, field)) is not CanonicalDecimal:
                raise ContractError(f"{field} must be a CanonicalDecimal")
        ratio = Decimal(self.max_ratio.value)
        confidence = Decimal(self.confidence.value)
        if ratio <= 0:
            raise ContractError("max_ratio must be positive")
        if confidence <= 0 or confidence >= 1:
            raise ContractError("confidence must be strictly between zero and one")
        validate_positive_int(
            self.min_samples_per_variant,
            "min_samples_per_variant",
            maximum=10**12,
        )
        if (
            len(
                [
                    item
                    for item in self.policy_refs
                    if item.kind is ContractRefKind.QUALIFICATION_POLICY
                ]
            )
            != 1
        ):
            raise ContractError(
                "ratio comparator requires one qualification policy"
            )
        if not any(
            item.kind is ContractRefKind.THRESHOLD_POLICY
            for item in self.policy_refs
        ):
            raise ContractError("ratio comparator requires a threshold policy")

    @property
    def qualification_policy(self) -> ContractRef:
        return next(
            item
            for item in self.policy_refs
            if item.kind is ContractRefKind.QUALIFICATION_POLICY
        )

    @property
    def threshold_values(self) -> tuple[CanonicalTypedValue, ...]:
        return (
            CanonicalTypedValue(
                "confidence",
                CanonicalValueKind.DECIMAL,
                self.confidence,
            ),
            CanonicalTypedValue(
                "interval_semantics",
                CanonicalValueKind.TEXT,
                self.interval_semantics,
            ),
            CanonicalTypedValue(
                "max_ratio",
                CanonicalValueKind.DECIMAL,
                self.max_ratio,
            ),
            CanonicalTypedValue(
                "min_samples_per_variant",
                CanonicalValueKind.INTEGER,
                self.min_samples_per_variant,
            ),
        )

    def _descriptor_parameters(self) -> dict[str, object]:
        return {
            "max_ratio": self.max_ratio.to_document(),
            "estimator_id": self.estimator_id,
            "confidence": self.confidence.to_document(),
            "min_samples_per_variant": self.min_samples_per_variant,
            "interval_semantics": self.interval_semantics,
        }

    def _estimate(
        self,
        value,
        read_artifact,
        repetition_index,
    ) -> ScalarEstimate:
        if (
            value.kind is not CanonicalValueKind.ARTIFACT
            or type(value.value) is not ArtifactRef
            or not callable(read_artifact)
        ):
            raise ContractError("statistical values must be readable artifacts")
        estimate = ScalarEstimate.from_json(read_artifact(value.value))
        if (
            estimate.variant_id != value.value_id
            or estimate.repetition_index != repetition_index
        ):
            raise ContractError("statistical estimate trial binding is invalid")
        return estimate

    def __call__(
        self,
        method,
        values,
        read_artifact=None,
        *,
        repetition_index=None,
    ):
        if (
            type(method) is not StatisticalBaselineMethod
            or len(values) != 2
            or type(repetition_index) is not int
            or repetition_index < 0
        ):
            return TrialDecision(OracleVerdict.INCONCLUSIVE, "METRIC_INVALID", ())
        by_id = {value.value_id: value for value in values}
        try:
            candidate = self._estimate(
                by_id[method.candidate_variant_id],
                read_artifact,
                repetition_index,
            )
            baseline = self._estimate(
                by_id[method.baseline_variant_id],
                read_artifact,
                repetition_index,
            )
        except (KeyError, ContractError, UnicodeDecodeError):
            return TrialDecision(OracleVerdict.INCONCLUSIVE, "METRIC_INVALID", ())
        expected_qualification = self.qualification_policy.content_sha256
        if candidate.pair_id != baseline.pair_id:
            return TrialDecision(
                OracleVerdict.INCONCLUSIVE,
                "METRIC_INVALID",
                tuple(values),
            )
        for estimate in (candidate, baseline):
            if (
                estimate.metric_id != method.metric_id
                or estimate.estimator_id != self.estimator_id
                or estimate.confidence != self.confidence
                or estimate.qualification_policy_sha256 != expected_qualification
                or estimate.interval_semantics != self.interval_semantics
            ):
                return TrialDecision(
                    OracleVerdict.INCONCLUSIVE,
                    "METRIC_INVALID",
                    tuple(values),
                    candidate.pair_id,
                )
        if min(candidate.sample_count, baseline.sample_count) < (
            self.min_samples_per_variant
        ):
            return TrialDecision(
                OracleVerdict.INCONCLUSIVE,
                "INSUFFICIENT_SAMPLES",
                tuple(values),
                candidate.pair_id,
            )
        candidate_lower = Decimal(candidate.lower_bound.value)
        candidate_upper = Decimal(candidate.upper_bound.value)
        baseline_lower = Decimal(baseline.lower_bound.value)
        baseline_upper = Decimal(baseline.upper_bound.value)
        if baseline_lower <= 0:
            return TrialDecision(
                OracleVerdict.INCONCLUSIVE,
                "METRIC_INVALID",
                tuple(values),
                candidate.pair_id,
            )
        with localcontext() as context:
            context.prec = 600
            threshold = Decimal(self.max_ratio.value)
            violation = candidate_lower > threshold * baseline_upper
            passed = candidate_upper <= threshold * baseline_lower
        if violation:
            return TrialDecision(
                OracleVerdict.VIOLATION,
                "RELATION_VIOLATED",
                tuple(values),
                candidate.pair_id,
            )
        if passed:
            return TrialDecision(
                OracleVerdict.PASS,
                "RELATION_HOLDS",
                tuple(values),
                candidate.pair_id,
            )
        return TrialDecision(
            OracleVerdict.INCONCLUSIVE,
            "CI_CROSSES_BOUNDARY",
            tuple(values),
            candidate.pair_id,
        )

"""Frozen observations and Oracle decisions for the generic validator.

The contracts in this module describe evidence that a Harness says it
collected and a decision that a frozen Oracle says it derived.  They do not
run a collector, resolve a CAS object, establish wall-clock ordering, or grant
the producer authority.  Those are runtime and registry responsibilities.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Iterable

from .base import (
    CanonicalDecimal,
    ContractError,
    canonical_sha256,
    load_strict_json_object,
    require_exact_keys,
    validate_control_free_string,
    validate_identifier,
    validate_non_negative_int,
    validate_positive_int,
    validate_sha256,
)
from .oracle import OracleSpec
from .plan import (
    BaselineSelectionReceipt,
    ExecutionBinding,
    ExperimentPhase,
    ExperimentPlanTemplate,
    GateRole,
    validate_execution_binding,
)
from .references import ArtifactRef, ContractRef, ContractRefKind


_OBSERVATION_KIND = "observation"
_ORACLE_DECISION_KIND = "oracle_decision"
_SCHEMA_VERSION = 1
_CONTENT_REF_VERSION = "1"
_MAX_ARTIFACTS = 16_384
_MAX_OBSERVATIONS = 65_536
_MAX_VALUES = 16_384
_MAX_REASON_CODES = 1024
_MAX_REPETITIONS = 10_000
_MAX_RETRIES = 100
_MAX_SIGNED_INTEGER = 9_223_372_036_854_775_807
_UTC_TIMESTAMP_RE = re.compile(
    r"[0-9]{4}-(?:0[1-9]|1[0-2])-"
    r"(?:0[1-9]|[12][0-9]|3[01])T"
    r"(?:[01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9]Z\Z"
)


class ObservationFactKind(str, Enum):
    """Closed classes of raw facts that an approved collector may emit."""

    PROCESS_EXIT = "process_exit"
    PROCESS_STDOUT = "process_stdout"
    PROCESS_STDERR = "process_stderr"
    HTTP_RESPONSE = "http_response"
    TOKEN_IDS = "token_ids"
    TENSOR = "tensor"
    TRACE = "trace"
    COVERAGE = "coverage"
    LATENCY_SAMPLES = "latency_samples"
    GPU_MEMORY = "gpu_memory"
    FILE_CHANGES = "file_changes"
    DEVICE_LOGS = "device_logs"


class CanonicalValueKind(str, Enum):
    """Closed inline value kinds used after normalization."""

    BOOLEAN = "boolean"
    INTEGER = "integer"
    DECIMAL = "decimal"
    TEXT = "text"
    ARTIFACT = "artifact"


class OracleVerdict(str, Enum):
    PASS = "PASS"
    VIOLATION = "VIOLATION"
    INCONCLUSIVE = "INCONCLUSIVE"


def _enum_value(enum_type: type[Enum], value: object, field: str) -> Enum:
    if type(value) is not str:
        raise ContractError(f"{field} must be a string enum value")
    try:
        return enum_type(value)
    except ValueError as exc:
        raise ContractError(f"{field} has unsupported value {value!r}") from exc


def _validate_utc_timestamp(value: object, field: str) -> str:
    if type(value) is not str or not _UTC_TIMESTAMP_RE.fullmatch(value):
        raise ContractError(
            f"{field} must use UTC second-precision YYYY-MM-DDTHH:MM:SSZ"
        )
    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=timezone.utc
        )
    except ValueError as exc:
        raise ContractError(f"{field} must contain a valid UTC timestamp") from exc
    if parsed.strftime("%Y-%m-%dT%H:%M:%SZ") != value:
        raise ContractError(f"{field} must be a canonical UTC timestamp")
    return value


def _require_ref(
    value: object,
    expected_kind: ContractRefKind,
    field: str,
) -> ContractRef:
    if type(value) is not ContractRef:
        raise ContractError(f"{field} must be a ContractRef")
    if value.kind is not expected_kind:
        raise ContractError(f"{field} must reference {expected_kind.value}")
    return value


def _ref_from_document(
    value: object,
    expected_kind: ContractRefKind,
    field: str,
) -> ContractRef:
    try:
        reference = ContractRef.from_document(value)
    except ContractError as exc:
        raise ContractError(f"invalid {field}: {exc}") from exc
    return _require_ref(reference, expected_kind, field)


def _ref_sort_key(reference: ContractRef) -> tuple[str, str, str, str]:
    return (
        reference.kind.value,
        reference.contract_id,
        reference.contract_version,
        reference.content_sha256,
    )


def _normalize_observation_refs(
    values: object,
    field: str,
) -> tuple[ContractRef, ...]:
    if type(values) not in (tuple, list):
        raise ContractError(f"{field} must be a collection")
    refs = tuple(
        _require_ref(value, ContractRefKind.OBSERVATION, field)
        for value in values
    )
    if not refs:
        raise ContractError(f"{field} must not be empty")
    if len(refs) > _MAX_OBSERVATIONS:
        raise ContractError(
            f"{field} must not contain more than {_MAX_OBSERVATIONS} values"
        )
    identities = tuple(
        (reference.contract_id, reference.contract_version) for reference in refs
    )
    if len(identities) != len(set(identities)):
        raise ContractError(f"{field} must not repeat an observation identity")
    return tuple(sorted(refs, key=_ref_sort_key))


@dataclass(frozen=True)
class CapturedArtifact:
    """One content-bound raw fact and its collector provenance."""

    fact_kind: ObservationFactKind
    artifact: ArtifactRef
    output_contract: ContractRef
    collector: ContractRef
    collector_run_id: str
    capture_id: str
    captured_at: str
    provenance_sha256: str

    def __post_init__(self) -> None:
        if type(self.fact_kind) is not ObservationFactKind:
            raise ContractError("fact_kind must be an ObservationFactKind")
        if type(self.artifact) is not ArtifactRef:
            raise ContractError("artifact must be an ArtifactRef")
        _require_ref(
            self.output_contract,
            ContractRefKind.OUTPUT_CONTRACT,
            "output_contract",
        )
        _require_ref(self.collector, ContractRefKind.COLLECTOR, "collector")
        validate_identifier(self.collector_run_id, "collector_run_id")
        validate_identifier(self.capture_id, "capture_id")
        _validate_utc_timestamp(self.captured_at, "captured_at")
        validate_sha256(self.provenance_sha256, "provenance_sha256")

    def to_document(self) -> dict[str, object]:
        return {
            "fact_kind": self.fact_kind.value,
            "artifact": self.artifact.to_document(),
            "output_contract": self.output_contract.to_document(),
            "collector": self.collector.to_document(),
            "collector_run_id": self.collector_run_id,
            "capture_id": self.capture_id,
            "captured_at": self.captured_at,
            "provenance_sha256": self.provenance_sha256,
        }

    @classmethod
    def from_document(cls, value: object) -> CapturedArtifact:
        document = require_exact_keys(
            value,
            required=(
                "fact_kind",
                "artifact",
                "output_contract",
                "collector",
                "collector_run_id",
                "capture_id",
                "captured_at",
                "provenance_sha256",
            ),
            where="captured artifact",
        )
        return cls(
            fact_kind=_enum_value(
                ObservationFactKind,
                document["fact_kind"],
                "captured artifact fact_kind",
            ),
            artifact=ArtifactRef.from_document(document["artifact"]),
            output_contract=_ref_from_document(
                document["output_contract"],
                ContractRefKind.OUTPUT_CONTRACT,
                "captured artifact output_contract",
            ),
            collector=_ref_from_document(
                document["collector"],
                ContractRefKind.COLLECTOR,
                "captured artifact collector",
            ),
            collector_run_id=document["collector_run_id"],
            capture_id=document["capture_id"],
            captured_at=document["captured_at"],
            provenance_sha256=document["provenance_sha256"],
        )


@dataclass(frozen=True)
class Observation:
    """Harness-produced raw facts for one bound execution step invocation."""

    validation_instance_id: str
    attempt_id: str
    role: GateRole
    template: ContractRef
    binding: ContractRef
    step_id: str
    repetition_index: int
    retry_index: int
    started_at: str
    finished_at: str
    artifacts: tuple[CapturedArtifact, ...]

    def __post_init__(self) -> None:
        validate_sha256(self.validation_instance_id, "validation_instance_id")
        validate_identifier(self.attempt_id, "attempt_id")
        if type(self.role) is not GateRole:
            raise ContractError("role must be a GateRole")
        _require_ref(
            self.template,
            ContractRefKind.EXPERIMENT_PLAN_TEMPLATE,
            "template",
        )
        _require_ref(self.binding, ContractRefKind.EXECUTION_BINDING, "binding")
        validate_identifier(self.step_id, "step_id")
        validate_non_negative_int(
            self.repetition_index,
            "repetition_index",
            maximum=_MAX_REPETITIONS - 1,
        )
        validate_non_negative_int(
            self.retry_index,
            "retry_index",
            maximum=_MAX_RETRIES,
        )
        started_at = _validate_utc_timestamp(self.started_at, "started_at")
        finished_at = _validate_utc_timestamp(self.finished_at, "finished_at")
        if finished_at < started_at:
            raise ContractError("finished_at must not be earlier than started_at")
        if type(self.artifacts) not in (tuple, list):
            raise ContractError("artifacts must be a collection")
        artifacts = tuple(self.artifacts)
        if not artifacts:
            raise ContractError("artifacts must not be empty")
        if len(artifacts) > _MAX_ARTIFACTS:
            raise ContractError(
                f"artifacts must not contain more than {_MAX_ARTIFACTS} values"
            )
        if any(type(artifact) is not CapturedArtifact for artifact in artifacts):
            raise ContractError("artifacts must contain CapturedArtifact values")
        capture_keys = tuple(
            (
                artifact.collector,
                artifact.collector_run_id,
                artifact.capture_id,
            )
            for artifact in artifacts
        )
        if len(capture_keys) != len(set(capture_keys)):
            raise ContractError("artifacts must not repeat a collector capture")
        for artifact in artifacts:
            if not started_at <= artifact.captured_at <= finished_at:
                raise ContractError(
                    "artifact captured_at must fall within the observation interval"
                )
        object.__setattr__(
            self,
            "artifacts",
            tuple(
                sorted(
                    artifacts,
                    key=lambda item: (
                        item.fact_kind.value,
                        *_ref_sort_key(item.collector),
                        item.collector_run_id,
                        item.capture_id,
                        item.provenance_sha256,
                        item.artifact.content_sha256,
                    ),
                )
            ),
        )

    def to_document(self) -> dict[str, object]:
        return {
            "contract_kind": _OBSERVATION_KIND,
            "schema_version": _SCHEMA_VERSION,
            "validation_instance_id": self.validation_instance_id,
            "attempt_id": self.attempt_id,
            "role": self.role.value,
            "template": self.template.to_document(),
            "binding": self.binding.to_document(),
            "step_id": self.step_id,
            "repetition_index": self.repetition_index,
            "retry_index": self.retry_index,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "artifacts": [artifact.to_document() for artifact in self.artifacts],
        }

    @classmethod
    def from_document(cls, value: object) -> Observation:
        document = require_exact_keys(
            value,
            required=(
                "contract_kind",
                "schema_version",
                "validation_instance_id",
                "attempt_id",
                "role",
                "template",
                "binding",
                "step_id",
                "repetition_index",
                "retry_index",
                "started_at",
                "finished_at",
                "artifacts",
            ),
            where="observation",
        )
        if document["contract_kind"] != _OBSERVATION_KIND:
            raise ContractError(
                f"observation contract_kind must be {_OBSERVATION_KIND!r}"
            )
        if (
            type(document["schema_version"]) is not int
            or document["schema_version"] != _SCHEMA_VERSION
        ):
            raise ContractError("observation schema_version must be integer 1")
        artifact_documents = document["artifacts"]
        if type(artifact_documents) is not list:
            raise ContractError("observation artifacts must be a list")
        return cls(
            validation_instance_id=document["validation_instance_id"],
            attempt_id=document["attempt_id"],
            role=_enum_value(GateRole, document["role"], "observation role"),
            template=_ref_from_document(
                document["template"],
                ContractRefKind.EXPERIMENT_PLAN_TEMPLATE,
                "observation template",
            ),
            binding=_ref_from_document(
                document["binding"],
                ContractRefKind.EXECUTION_BINDING,
                "observation binding",
            ),
            step_id=document["step_id"],
            repetition_index=document["repetition_index"],
            retry_index=document["retry_index"],
            started_at=document["started_at"],
            finished_at=document["finished_at"],
            artifacts=tuple(
                CapturedArtifact.from_document(artifact)
                for artifact in artifact_documents
            ),
        )

    @classmethod
    def from_json(cls, payload: object) -> Observation:
        return cls.from_document(load_strict_json_object(payload))

    @property
    def content_sha256(self) -> str:
        return canonical_sha256(self.to_document())

    @property
    def ref(self) -> ContractRef:
        return ContractRef(
            kind=ContractRefKind.OBSERVATION,
            contract_id=self.content_sha256,
            contract_version=_CONTENT_REF_VERSION,
            content_sha256=self.content_sha256,
        )


@dataclass(frozen=True)
class CanonicalTypedValue:
    """A named scalar or content-bound aggregate with an exact wire type."""

    value_id: str
    kind: CanonicalValueKind
    value: bool | int | CanonicalDecimal | str | ArtifactRef

    def __post_init__(self) -> None:
        validate_identifier(self.value_id, "value_id")
        if type(self.kind) is not CanonicalValueKind:
            raise ContractError("kind must be a CanonicalValueKind")
        if self.kind is CanonicalValueKind.BOOLEAN:
            if type(self.value) is not bool:
                raise ContractError("boolean canonical value must contain a boolean")
        elif self.kind is CanonicalValueKind.INTEGER:
            if (
                type(self.value) is not int
                or self.value < -_MAX_SIGNED_INTEGER - 1
                or self.value > _MAX_SIGNED_INTEGER
            ):
                raise ContractError(
                    "integer canonical value must contain a signed 64-bit integer"
                )
        elif self.kind is CanonicalValueKind.DECIMAL:
            if type(self.value) is not CanonicalDecimal:
                raise ContractError(
                    "decimal canonical value must contain a CanonicalDecimal"
                )
        elif self.kind is CanonicalValueKind.TEXT:
            validate_control_free_string(
                self.value,
                "text canonical value",
                allow_empty=True,
                max_length=4096,
            )
        elif type(self.value) is not ArtifactRef:
            raise ContractError(
                "artifact canonical value must contain an ArtifactRef"
            )

    def to_document(self) -> dict[str, object]:
        if type(self.value) is CanonicalDecimal:
            encoded: object = self.value.to_document()
        elif type(self.value) is ArtifactRef:
            encoded = self.value.to_document()
        else:
            encoded = self.value
        return {
            "value_id": self.value_id,
            "kind": self.kind.value,
            "value": encoded,
        }

    @classmethod
    def from_document(cls, value: object) -> CanonicalTypedValue:
        document = require_exact_keys(
            value,
            required=("value_id", "kind", "value"),
            where="canonical typed value",
        )
        kind = _enum_value(
            CanonicalValueKind,
            document["kind"],
            "canonical typed value kind",
        )
        raw_value = document["value"]
        if kind is CanonicalValueKind.DECIMAL:
            parsed_value: object = CanonicalDecimal.parse(
                raw_value,
                "canonical typed decimal value",
            )
        elif kind is CanonicalValueKind.ARTIFACT:
            parsed_value = ArtifactRef.from_document(raw_value)
        else:
            parsed_value = raw_value
        return cls(
            value_id=document["value_id"],
            kind=kind,
            value=parsed_value,
        )


def _normalize_values(
    values: object,
    field: str,
    *,
    allow_empty: bool,
) -> tuple[CanonicalTypedValue, ...]:
    if type(values) not in (tuple, list):
        raise ContractError(f"{field} must be a collection")
    normalized = tuple(values)
    if not allow_empty and not normalized:
        raise ContractError(f"{field} must not be empty")
    if len(normalized) > _MAX_VALUES:
        raise ContractError(
            f"{field} must not contain more than {_MAX_VALUES} values"
        )
    if any(type(value) is not CanonicalTypedValue for value in normalized):
        raise ContractError(f"{field} must contain CanonicalTypedValue values")
    value_ids = tuple(value.value_id for value in normalized)
    if len(value_ids) != len(set(value_ids)):
        raise ContractError(f"{field} must not repeat value_id")
    return tuple(sorted(normalized, key=lambda value: value.value_id))


@dataclass(frozen=True)
class DecisionQuorum:
    """Observed terminal counts for one frozen repetition protocol."""

    required: int
    total: int
    violation_count: int
    pass_count: int
    inconclusive_count: int

    def __post_init__(self) -> None:
        validate_positive_int(
            self.required,
            "required",
            maximum=_MAX_REPETITIONS,
        )
        validate_positive_int(self.total, "total", maximum=_MAX_REPETITIONS)
        if self.required > self.total:
            raise ContractError("quorum required must not exceed total")
        for field in ("violation_count", "pass_count", "inconclusive_count"):
            validate_non_negative_int(
                getattr(self, field),
                field,
                maximum=self.total,
            )
        if (
            self.violation_count + self.pass_count + self.inconclusive_count
            != self.total
        ):
            raise ContractError("quorum terminal counts must sum to total")

    def to_document(self) -> dict[str, object]:
        return {
            "required": self.required,
            "total": self.total,
            "violation_count": self.violation_count,
            "pass_count": self.pass_count,
            "inconclusive_count": self.inconclusive_count,
        }

    @classmethod
    def from_document(cls, value: object) -> DecisionQuorum:
        document = require_exact_keys(
            value,
            required=(
                "required",
                "total",
                "violation_count",
                "pass_count",
                "inconclusive_count",
            ),
            where="decision quorum",
        )
        return cls(
            required=document["required"],
            total=document["total"],
            violation_count=document["violation_count"],
            pass_count=document["pass_count"],
            inconclusive_count=document["inconclusive_count"],
        )


@dataclass(frozen=True)
class OracleDecision:
    """Three-state mechanical decision over an exact Observation closure."""

    validation_instance_id: str
    attempt_id: str
    role: GateRole
    profile: ContractRef
    case_plan: ContractRef
    template: ContractRef
    binding: ContractRef
    oracle_spec: ContractRef
    baseline_selection: ContractRef | None
    baseline_source_id: str | None
    domain_match: bool
    observations: tuple[ContractRef, ...]
    normalizer: ContractRef
    comparator: ContractRef
    threshold_policy: ContractRef | None
    normalized_values: tuple[CanonicalTypedValue, ...]
    threshold_values: tuple[CanonicalTypedValue, ...]
    quorum: DecisionQuorum
    verdict: OracleVerdict
    reason_codes: tuple[str, ...]

    def __post_init__(self) -> None:
        validate_sha256(self.validation_instance_id, "validation_instance_id")
        validate_identifier(self.attempt_id, "attempt_id")
        if type(self.role) is not GateRole:
            raise ContractError("role must be a GateRole")
        _require_ref(self.profile, ContractRefKind.FROZEN_PROFILE, "profile")
        _require_ref(self.case_plan, ContractRefKind.CASE_PLAN, "case_plan")
        _require_ref(
            self.template,
            ContractRefKind.EXPERIMENT_PLAN_TEMPLATE,
            "template",
        )
        _require_ref(self.binding, ContractRefKind.EXECUTION_BINDING, "binding")
        _require_ref(self.oracle_spec, ContractRefKind.ORACLE_SPEC, "oracle_spec")
        if self.baseline_selection is None:
            if self.baseline_source_id is not None:
                raise ContractError(
                    "baseline_source_id requires baseline_selection"
                )
        else:
            _require_ref(
                self.baseline_selection,
                ContractRefKind.BASELINE_SELECTION_RECEIPT,
                "baseline_selection",
            )
            if self.baseline_source_id is None:
                raise ContractError(
                    "baseline_selection requires baseline_source_id"
                )
            validate_identifier(self.baseline_source_id, "baseline_source_id")
        if type(self.domain_match) is not bool:
            raise ContractError("domain_match must be a boolean")
        object.__setattr__(
            self,
            "observations",
            _normalize_observation_refs(self.observations, "observations"),
        )
        _require_ref(self.normalizer, ContractRefKind.NORMALIZER, "normalizer")
        _require_ref(self.comparator, ContractRefKind.COMPARATOR, "comparator")
        if self.threshold_policy is not None:
            _require_ref(
                self.threshold_policy,
                ContractRefKind.THRESHOLD_POLICY,
                "threshold_policy",
            )
        if type(self.verdict) is not OracleVerdict:
            raise ContractError("verdict must be an OracleVerdict")
        normalized_values = _normalize_values(
            self.normalized_values,
            "normalized_values",
            allow_empty=self.verdict is OracleVerdict.INCONCLUSIVE,
        )
        threshold_values = _normalize_values(
            self.threshold_values,
            "threshold_values",
            allow_empty=True,
        )
        if self.threshold_policy is None and threshold_values:
            raise ContractError(
                "threshold_values require a threshold_policy"
            )
        if self.threshold_policy is not None and not threshold_values:
            raise ContractError(
                "threshold_policy requires threshold_values"
            )
        object.__setattr__(self, "normalized_values", normalized_values)
        object.__setattr__(self, "threshold_values", threshold_values)
        if type(self.quorum) is not DecisionQuorum:
            raise ContractError("quorum must be a DecisionQuorum")
        if not self.domain_match and self.verdict is not OracleVerdict.INCONCLUSIVE:
            raise ContractError("a domain mismatch must be INCONCLUSIVE")
        if self.domain_match:
            violation_met = self.quorum.violation_count >= self.quorum.required
            pass_met = self.quorum.pass_count >= self.quorum.required
            expected_verdict = (
                OracleVerdict.VIOLATION
                if violation_met and not pass_met
                else OracleVerdict.PASS
                if pass_met and not violation_met
                else OracleVerdict.INCONCLUSIVE
            )
            if self.verdict is not expected_verdict:
                raise ContractError(
                    "verdict does not match the mechanical quorum result"
                )
        if type(self.reason_codes) not in (tuple, list):
            raise ContractError("reason_codes must be a collection")
        reason_codes = tuple(
            validate_identifier(reason, "reason_codes")
            for reason in self.reason_codes
        )
        if not reason_codes:
            raise ContractError("reason_codes must not be empty")
        if len(reason_codes) > _MAX_REASON_CODES:
            raise ContractError(
                "reason_codes must not contain more than "
                f"{_MAX_REASON_CODES} values"
            )
        if len(reason_codes) != len(set(reason_codes)):
            raise ContractError("reason_codes must not contain duplicates")
        object.__setattr__(self, "reason_codes", tuple(sorted(reason_codes)))

    def to_document(self) -> dict[str, object]:
        return {
            "contract_kind": _ORACLE_DECISION_KIND,
            "schema_version": _SCHEMA_VERSION,
            "validation_instance_id": self.validation_instance_id,
            "attempt_id": self.attempt_id,
            "role": self.role.value,
            "profile": self.profile.to_document(),
            "case_plan": self.case_plan.to_document(),
            "template": self.template.to_document(),
            "binding": self.binding.to_document(),
            "oracle_spec": self.oracle_spec.to_document(),
            "baseline_selection": (
                None
                if self.baseline_selection is None
                else self.baseline_selection.to_document()
            ),
            "baseline_source_id": self.baseline_source_id,
            "domain_match": self.domain_match,
            "observations": [
                observation.to_document() for observation in self.observations
            ],
            "normalizer": self.normalizer.to_document(),
            "comparator": self.comparator.to_document(),
            "threshold_policy": (
                None
                if self.threshold_policy is None
                else self.threshold_policy.to_document()
            ),
            "normalized_values": [
                value.to_document() for value in self.normalized_values
            ],
            "threshold_values": [
                value.to_document() for value in self.threshold_values
            ],
            "quorum": self.quorum.to_document(),
            "verdict": self.verdict.value,
            "reason_codes": list(self.reason_codes),
        }

    @classmethod
    def from_document(cls, value: object) -> OracleDecision:
        document = require_exact_keys(
            value,
            required=(
                "contract_kind",
                "schema_version",
                "validation_instance_id",
                "attempt_id",
                "role",
                "profile",
                "case_plan",
                "template",
                "binding",
                "oracle_spec",
                "baseline_selection",
                "baseline_source_id",
                "domain_match",
                "observations",
                "normalizer",
                "comparator",
                "threshold_policy",
                "normalized_values",
                "threshold_values",
                "quorum",
                "verdict",
                "reason_codes",
            ),
            where="oracle decision",
        )
        if document["contract_kind"] != _ORACLE_DECISION_KIND:
            raise ContractError(
                "oracle decision contract_kind must be "
                f"{_ORACLE_DECISION_KIND!r}"
            )
        if (
            type(document["schema_version"]) is not int
            or document["schema_version"] != _SCHEMA_VERSION
        ):
            raise ContractError("oracle decision schema_version must be integer 1")
        observation_documents = document["observations"]
        normalized_documents = document["normalized_values"]
        threshold_documents = document["threshold_values"]
        reason_documents = document["reason_codes"]
        if type(observation_documents) is not list:
            raise ContractError("oracle decision observations must be a list")
        if type(normalized_documents) is not list:
            raise ContractError("oracle decision normalized_values must be a list")
        if type(threshold_documents) is not list:
            raise ContractError("oracle decision threshold_values must be a list")
        if type(reason_documents) is not list:
            raise ContractError("oracle decision reason_codes must be a list")
        baseline = document["baseline_selection"]
        threshold_policy = document["threshold_policy"]
        return cls(
            validation_instance_id=document["validation_instance_id"],
            attempt_id=document["attempt_id"],
            role=_enum_value(GateRole, document["role"], "oracle decision role"),
            profile=_ref_from_document(
                document["profile"],
                ContractRefKind.FROZEN_PROFILE,
                "oracle decision profile",
            ),
            case_plan=_ref_from_document(
                document["case_plan"],
                ContractRefKind.CASE_PLAN,
                "oracle decision case_plan",
            ),
            template=_ref_from_document(
                document["template"],
                ContractRefKind.EXPERIMENT_PLAN_TEMPLATE,
                "oracle decision template",
            ),
            binding=_ref_from_document(
                document["binding"],
                ContractRefKind.EXECUTION_BINDING,
                "oracle decision binding",
            ),
            oracle_spec=_ref_from_document(
                document["oracle_spec"],
                ContractRefKind.ORACLE_SPEC,
                "oracle decision oracle_spec",
            ),
            baseline_selection=(
                None
                if baseline is None
                else _ref_from_document(
                    baseline,
                    ContractRefKind.BASELINE_SELECTION_RECEIPT,
                    "oracle decision baseline_selection",
                )
            ),
            baseline_source_id=document["baseline_source_id"],
            domain_match=document["domain_match"],
            observations=tuple(
                _ref_from_document(
                    observation,
                    ContractRefKind.OBSERVATION,
                    f"oracle decision observations[{index}]",
                )
                for index, observation in enumerate(observation_documents)
            ),
            normalizer=_ref_from_document(
                document["normalizer"],
                ContractRefKind.NORMALIZER,
                "oracle decision normalizer",
            ),
            comparator=_ref_from_document(
                document["comparator"],
                ContractRefKind.COMPARATOR,
                "oracle decision comparator",
            ),
            threshold_policy=(
                None
                if threshold_policy is None
                else _ref_from_document(
                    threshold_policy,
                    ContractRefKind.THRESHOLD_POLICY,
                    "oracle decision threshold_policy",
                )
            ),
            normalized_values=tuple(
                CanonicalTypedValue.from_document(item)
                for item in normalized_documents
            ),
            threshold_values=tuple(
                CanonicalTypedValue.from_document(item)
                for item in threshold_documents
            ),
            quorum=DecisionQuorum.from_document(document["quorum"]),
            verdict=_enum_value(
                OracleVerdict,
                document["verdict"],
                "oracle decision verdict",
            ),
            reason_codes=tuple(reason_documents),
        )

    @classmethod
    def from_json(cls, payload: object) -> OracleDecision:
        return cls.from_document(load_strict_json_object(payload))

    @property
    def content_sha256(self) -> str:
        return canonical_sha256(self.to_document())

    @property
    def ref(self) -> ContractRef:
        return ContractRef(
            kind=ContractRefKind.ORACLE_DECISION,
            contract_id=self.content_sha256,
            contract_version=_CONTENT_REF_VERSION,
            content_sha256=self.content_sha256,
        )


def validate_oracle_decision_evidence(
    decision: OracleDecision,
    *,
    template: ExperimentPlanTemplate,
    binding: ExecutionBinding,
    oracle_spec: OracleSpec,
    observations: Iterable[Observation],
    baseline_receipt: BaselineSelectionReceipt | None = None,
) -> None:
    """Validate one exact, already-frozen Decision evidence closure.

    This function only compares immutable values supplied by its caller.  It
    intentionally does not resolve artifacts, infer execution order from
    timestamps, or establish that any referenced producer was trusted.
    """

    if type(decision) is not OracleDecision:
        raise ContractError("decision must be an OracleDecision")
    if type(template) is not ExperimentPlanTemplate:
        raise ContractError("template must be an ExperimentPlanTemplate")
    if type(binding) is not ExecutionBinding:
        raise ContractError("binding must be an ExecutionBinding")
    if type(oracle_spec) is not OracleSpec:
        raise ContractError("oracle_spec must be an OracleSpec")
    observation_values = tuple(observations)
    if any(type(value) is not Observation for value in observation_values):
        raise ContractError("observations must contain Observation values")

    validate_execution_binding(template, binding)
    if decision.validation_instance_id != template.validation_instance_id:
        raise ContractError("decision validation instance does not match template")
    if decision.profile != template.profile:
        raise ContractError("decision profile does not match template")
    if decision.case_plan != template.case_plan:
        raise ContractError("decision CasePlan does not match template")
    if decision.template != template.ref:
        raise ContractError("decision template reference mismatch")
    if decision.binding != binding.ref:
        raise ContractError("decision ExecutionBinding reference mismatch")
    if decision.attempt_id != binding.attempt_id:
        raise ContractError("decision attempt does not match ExecutionBinding")
    if decision.role is not binding.role:
        raise ContractError("decision role does not match ExecutionBinding")
    if decision.oracle_spec != oracle_spec.ref:
        raise ContractError("decision OracleSpec reference mismatch")

    planned_matches = tuple(
        execution
        for execution in template.oracle_executions
        if execution.oracle_spec == oracle_spec.ref
    )
    if len(planned_matches) != 1:
        raise ContractError(
            "template must contain exactly one execution for the OracleSpec"
        )
    planned = planned_matches[0]
    if planned.collectors != oracle_spec.collectors:
        raise ContractError("planned collectors do not match OracleSpec")
    if decision.normalizer != oracle_spec.normalizer or (
        planned.normalizer != oracle_spec.normalizer
    ):
        raise ContractError("decision normalizer does not match frozen plan")
    if decision.comparator != oracle_spec.comparator or (
        planned.comparator != oracle_spec.comparator
    ):
        raise ContractError("decision comparator does not match frozen plan")
    if decision.threshold_policy != oracle_spec.threshold_policy:
        raise ContractError("decision threshold policy does not match OracleSpec")
    if (
        decision.quorum.required
        != oracle_spec.execution_protocol.quorum.required
        or decision.quorum.total
        != oracle_spec.execution_protocol.quorum.total
        or planned.protocol != oracle_spec.execution_protocol
    ):
        raise ContractError("decision quorum does not match frozen protocol")

    if planned.baseline_selection is None:
        if decision.baseline_selection is not None or baseline_receipt is not None:
            raise ContractError("OracleSpec does not permit a baseline receipt")
        if decision.baseline_source_id is not None:
            raise ContractError("OracleSpec does not permit a baseline source")
    else:
        if type(baseline_receipt) is not BaselineSelectionReceipt:
            raise ContractError("the planned baseline receipt is required")
        if decision.baseline_selection != planned.baseline_selection:
            raise ContractError("decision baseline reference does not match template")
        if baseline_receipt.ref != planned.baseline_selection:
            raise ContractError("baseline receipt does not match frozen plan")
        if baseline_receipt.validation_instance_id != decision.validation_instance_id:
            raise ContractError("baseline receipt validation instance mismatch")
        if baseline_receipt.profile != decision.profile:
            raise ContractError("baseline receipt profile mismatch")
        if baseline_receipt.case_plan != decision.case_plan:
            raise ContractError("baseline receipt CasePlan mismatch")
        if baseline_receipt.oracle_spec != decision.oracle_spec:
            raise ContractError("baseline receipt OracleSpec mismatch")
        if baseline_receipt.baseline_policy != oracle_spec.baseline_policy:
            raise ContractError("baseline receipt policy does not match OracleSpec")
        if baseline_receipt.healthy_relation != oracle_spec.healthy_relation:
            raise ContractError(
                "baseline receipt healthy relation does not match OracleSpec"
            )
        if decision.baseline_source_id != baseline_receipt.selected_source_id:
            raise ContractError("decision baseline source does not match receipt")

    actual_refs = tuple(
        sorted((observation.ref for observation in observation_values), key=_ref_sort_key)
    )
    if actual_refs != decision.observations:
        raise ContractError(
            "observations do not exactly match decision evidence membership"
        )
    step_by_id = {step.step_id: step for step in template.steps}
    invocation_keys: set[tuple[str, int, int]] = set()
    retry_indices_by_cell: dict[tuple[str, int], set[int]] = {}
    capture_keys: set[tuple[ContractRef, str, str]] = set()
    provenance_hashes: set[str] = set()
    output_contract_hashes: dict[tuple[ContractRefKind, str, str], str] = {}
    allowed_collectors = set(planned.collectors)
    observed_collectors: set[ContractRef] = set()
    observed_phases: set[ExperimentPhase] = set()
    for observation in observation_values:
        if observation.validation_instance_id != decision.validation_instance_id:
            raise ContractError("observation validation instance mismatch")
        if observation.attempt_id != decision.attempt_id:
            raise ContractError("observation attempt mismatch")
        if observation.role is not decision.role:
            raise ContractError("observation role mismatch")
        if observation.template != decision.template:
            raise ContractError("observation template mismatch")
        if observation.binding != decision.binding:
            raise ContractError("observation ExecutionBinding mismatch")
        step = step_by_id.get(observation.step_id)
        if step is None:
            raise ContractError("observation references an unknown template step")
        if step.oracle_spec != oracle_spec.ref:
            raise ContractError(
                "observation step does not belong to the decided OracleSpec"
            )
        if observation.repetition_index >= oracle_spec.execution_protocol.repetitions:
            raise ContractError("observation repetition is outside frozen protocol")
        if observation.retry_index > oracle_spec.execution_protocol.max_retries:
            raise ContractError("observation retry is outside frozen protocol")
        invocation = (
            observation.step_id,
            observation.repetition_index,
            observation.retry_index,
        )
        if invocation in invocation_keys:
            raise ContractError("observations repeat one step invocation")
        invocation_keys.add(invocation)
        retry_indices_by_cell.setdefault(
            (observation.step_id, observation.repetition_index),
            set(),
        ).add(observation.retry_index)
        observed_phases.add(step.phase)
        if any(
            artifact.collector not in allowed_collectors
            for artifact in observation.artifacts
        ):
            raise ContractError(
                "observation uses a collector outside the frozen Oracle plan"
            )
        for artifact in observation.artifacts:
            observed_collectors.add(artifact.collector)
            capture_key = (
                artifact.collector,
                artifact.collector_run_id,
                artifact.capture_id,
            )
            if capture_key in capture_keys:
                raise ContractError(
                    "decision observations must not reuse a collector capture"
                )
            if artifact.provenance_sha256 in provenance_hashes:
                raise ContractError(
                    "decision observations must not reuse capture provenance"
                )
            capture_keys.add(capture_key)
            provenance_hashes.add(artifact.provenance_sha256)

            output_identity = (
                artifact.output_contract.kind,
                artifact.output_contract.contract_id,
                artifact.output_contract.contract_version,
            )
            prior_output_hash = output_contract_hashes.setdefault(
                output_identity,
                artifact.output_contract.content_sha256,
            )
            if prior_output_hash != artifact.output_contract.content_sha256:
                raise ContractError(
                    "decision observations contain conflicting hashes for one "
                    "output contract identity"
                )

    for (step_id, repetition_index), retry_indices in retry_indices_by_cell.items():
        expected_retry_indices = set(range(max(retry_indices) + 1))
        if retry_indices != expected_retry_indices:
            raise ContractError(
                "observation retry indices must start at zero and be contiguous "
                f"for step {step_id!r} repetition {repetition_index}"
            )

    if decision.domain_match:
        original_family = frozenset(
            (ExperimentPhase.ORACLE_EXPERIMENT, ExperimentPhase.CAUSAL_CONTROL)
        )
        repair_family = frozenset((ExperimentPhase.REPAIR_ORACLE_EXPERIMENT,))
        uses_original_family = bool(observed_phases.intersection(original_family))
        uses_repair_family = bool(observed_phases.intersection(repair_family))
        if uses_original_family and uses_repair_family:
            raise ContractError(
                "one OracleDecision must not mix original and repair experiment "
                "families"
            )
        if uses_original_family:
            if ExperimentPhase.ORACLE_EXPERIMENT not in observed_phases:
                raise ContractError(
                    "an original-family OracleDecision requires an "
                    "oracle_experiment observation"
                )
            selected_family = original_family
        elif uses_repair_family:
            selected_family = repair_family
        else:  # ExperimentStep rejects other phases carrying an OracleSpec.
            raise ContractError(
                "OracleDecision observations do not select an experiment family"
            )

        expected_step_ids = {
            step.step_id
            for step in template.steps
            if step.oracle_spec == oracle_spec.ref and step.phase in selected_family
        }
        expected_cells = {
            (step_id, repetition_index)
            for step_id in expected_step_ids
            for repetition_index in range(decision.quorum.total)
        }
        observed_cells = set(retry_indices_by_cell)
        if observed_cells != expected_cells:
            raise ContractError(
                "decision evidence must cover every planned step and frozen "
                "repetition in its experiment family"
            )
        missing_collectors = allowed_collectors - observed_collectors
        if missing_collectors:
            raise ContractError(
                "decision evidence does not cover every declared collector"
            )

    vocabulary = oracle_spec.reason_vocabulary
    allowed_reasons = {
        OracleVerdict.VIOLATION: set(vocabulary.violation),
        OracleVerdict.PASS: set(vocabulary.passed),
        OracleVerdict.INCONCLUSIVE: set(vocabulary.inconclusive),
    }[decision.verdict]
    if any(reason not in allowed_reasons for reason in decision.reason_codes):
        raise ContractError(
            "decision reason_codes do not belong to the verdict vocabulary"
        )
    domain_reason = oracle_spec.applicability.out_of_domain_reason
    if not decision.domain_match and domain_reason not in decision.reason_codes:
        raise ContractError(
            "domain mismatch decision must include its frozen applicability reason"
        )
    if decision.domain_match and domain_reason in decision.reason_codes:
        raise ContractError(
            "domain-match decision cannot claim its out-of-domain reason"
        )


def validate_b1_b2_observation_independence(
    b1_observations: Iterable[Observation],
    b2_observations: Iterable[Observation],
) -> None:
    """Require role-local evidence envelopes without comparing raw content.

    Independent deterministic runs may legitimately produce byte-identical
    stdout, token, tensor, or trace artifacts.  Independence therefore rests
    on role-local Binding and collector provenance, not unequal artifact hash.
    """

    b1 = tuple(b1_observations)
    b2 = tuple(b2_observations)
    if not b1 or not b2:
        raise ContractError("B1 and B2 observation sets must not be empty")
    if any(type(value) is not Observation for value in (*b1, *b2)):
        raise ContractError("observation sets must contain Observation values")
    if any(value.role is not GateRole.B1 for value in b1):
        raise ContractError("the B1 observation set must contain only B1 evidence")
    if any(value.role is not GateRole.B2 for value in b2):
        raise ContractError("the B2 observation set must contain only B2 evidence")

    common_fields = ("validation_instance_id", "attempt_id", "template")
    anchor = b1[0]
    if any(
        getattr(value, field) != getattr(anchor, field)
        for value in (*b1, *b2)
        for field in common_fields
    ):
        raise ContractError("B1 and B2 observations bind different frozen inputs")
    b1_bindings = {value.binding for value in b1}
    b2_bindings = {value.binding for value in b2}
    if len(b1_bindings) != 1 or len(b2_bindings) != 1:
        raise ContractError("each Gate observation set must use one Binding")
    b1_binding = next(iter(b1_bindings))
    b2_binding = next(iter(b2_bindings))
    if (
        b1_binding.kind,
        b1_binding.contract_id,
        b1_binding.contract_version,
    ) == (
        b2_binding.kind,
        b2_binding.contract_id,
        b2_binding.contract_version,
    ):
        raise ContractError("B1 and B2 observations must use independent Bindings")

    if {value.ref for value in b1}.intersection(value.ref for value in b2):
        raise ContractError("a B1 Observation cannot be reused as B2 evidence")

    def provenance_keys(
        values: tuple[Observation, ...],
    ) -> tuple[set[tuple[ContractRef, str]], set[tuple[ContractRef, str, str]], set[str]]:
        run_ids: set[tuple[ContractRef, str]] = set()
        capture_ids: set[tuple[ContractRef, str, str]] = set()
        provenance: set[str] = set()
        for observation in values:
            for captured in observation.artifacts:
                run_ids.add((captured.collector, captured.collector_run_id))
                capture_ids.add(
                    (
                        captured.collector,
                        captured.collector_run_id,
                        captured.capture_id,
                    )
                )
                provenance.add(captured.provenance_sha256)
        return run_ids, capture_ids, provenance

    b1_runs, b1_captures, b1_provenance = provenance_keys(b1)
    b2_runs, b2_captures, b2_provenance = provenance_keys(b2)
    if b1_runs.intersection(b2_runs):
        raise ContractError("B1 and B2 must not reuse a collector run")
    if b1_captures.intersection(b2_captures):
        raise ContractError("B1 and B2 must not reuse a collector capture")
    if b1_provenance.intersection(b2_provenance):
        raise ContractError("B1 and B2 must not reuse capture provenance")

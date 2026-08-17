"""Closed, hash-bound values exchanged by Oracle runtime atoms.

The values in this module deliberately contain no argv, shell, cwd,
environment, or host path. Registered runners own those details and only
receive a request bound to an approved execution-recipe reference.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Callable, Protocol

from ..contracts import (
    ArtifactRef,
    CanonicalTypedValue,
    ContractRef,
    ContractRefKind,
    DecisionQuorum,
    ExecutionProtocol,
    OracleSpec,
    OracleVerdict,
    RetryReason,
)
from ..contracts.base import (
    ContractError,
    canonical_sha256,
    validate_identifier,
    validate_non_negative_int,
    validate_positive_int,
    validate_sha256,
)


_MAX_ATOMIC_ITEMS = 100_000


class AtomicRunStatus(str, Enum):
    """Closed outcomes emitted by a broker-backed runner."""

    COMPLETED = "COMPLETED"
    TARGET_TIMEOUT = "TARGET_TIMEOUT"
    TARGET_CRASH = "TARGET_CRASH"
    TARGET_OOM = "TARGET_OOM"
    BROKER_LEASE_LOST = "BROKER_LEASE_LOST"
    DEVICE_LEASE_LOST = "DEVICE_LEASE_LOST"
    ENVIRONMENT_FINGERPRINT_DRIFT = "ENVIRONMENT_FINGERPRINT_DRIFT"
    COLLECTOR_TRANSPORT_INTERRUPTED = "COLLECTOR_TRANSPORT_INTERRUPTED"


_STATUS_RETRY_REASON = {
    AtomicRunStatus.BROKER_LEASE_LOST: RetryReason.BROKER_LEASE_LOST,
    AtomicRunStatus.DEVICE_LEASE_LOST: RetryReason.DEVICE_LEASE_LOST,
    AtomicRunStatus.ENVIRONMENT_FINGERPRINT_DRIFT: (
        RetryReason.ENVIRONMENT_FINGERPRINT_DRIFT
    ),
    AtomicRunStatus.COLLECTOR_TRANSPORT_INTERRUPTED: (
        RetryReason.COLLECTOR_TRANSPORT_INTERRUPTED
    ),
}


class AtomicResultClass(str, Enum):
    """Why evaluation ended; the Oracle verdict remains strictly three-state."""

    DECIDED = "DECIDED"
    DOMAIN_MISMATCH = "DOMAIN_MISMATCH"
    ORACLE_INCONCLUSIVE = "ORACLE_INCONCLUSIVE"
    INFRA_INCONCLUSIVE = "INFRA_INCONCLUSIVE"


class AtomicDataError(ValueError):
    """A typed, expected observation-level failure, not an atom code failure."""

    def __init__(self, reason_code: str, message: str):
        self.reason_code = validate_identifier(reason_code, "reason_code")
        super().__init__(message)


@dataclass(frozen=True)
class AtomicRunRequest:
    recipe: ContractRef
    variant_id: str
    repetition_index: int
    retry_index: int
    warmup: bool
    timeout_ms: int
    inputs: tuple[ArtifactRef, ...] = ()

    def __post_init__(self) -> None:
        if (
            type(self.recipe) is not ContractRef
            or self.recipe.kind is not ContractRefKind.EXECUTION_RECIPE
        ):
            raise ContractError("recipe must be an execution_recipe ContractRef")
        validate_identifier(self.variant_id, "variant_id")
        validate_non_negative_int(
            self.repetition_index,
            "repetition_index",
            maximum=_MAX_ATOMIC_ITEMS,
        )
        validate_non_negative_int(
            self.retry_index,
            "retry_index",
            maximum=_MAX_ATOMIC_ITEMS,
        )
        if type(self.warmup) is not bool:
            raise ContractError("warmup must be a boolean")
        validate_positive_int(self.timeout_ms, "timeout_ms", maximum=86_400_000)
        if type(self.inputs) not in (tuple, list) or any(
            type(item) is not ArtifactRef for item in self.inputs
        ):
            raise ContractError("inputs must contain only ArtifactRef values")
        roles = tuple(item.role for item in self.inputs)
        if len(roles) != len(set(roles)):
            raise ContractError("inputs must not repeat artifact roles")
        object.__setattr__(
            self,
            "inputs",
            tuple(sorted(self.inputs, key=lambda item: item.role)),
        )

    def to_document(self) -> dict[str, object]:
        return {
            "recipe": self.recipe.to_document(),
            "variant_id": self.variant_id,
            "repetition_index": self.repetition_index,
            "retry_index": self.retry_index,
            "warmup": self.warmup,
            "timeout_ms": self.timeout_ms,
            "inputs": [item.to_document() for item in self.inputs],
        }

    @property
    def content_sha256(self) -> str:
        return canonical_sha256(self.to_document())


@dataclass(frozen=True)
class AtomicCapturedArtifact:
    artifact: ArtifactRef
    collector: ContractRef
    capture_id: str
    provenance_sha256: str

    def __post_init__(self) -> None:
        if type(self.artifact) is not ArtifactRef:
            raise ContractError("artifact must be an ArtifactRef")
        if (
            type(self.collector) is not ContractRef
            or self.collector.kind is not ContractRefKind.COLLECTOR
        ):
            raise ContractError("collector must be a collector ContractRef")
        validate_identifier(self.capture_id, "capture_id")
        validate_sha256(self.provenance_sha256, "provenance_sha256")

    def to_document(self) -> dict[str, object]:
        return {
            "artifact": self.artifact.to_document(),
            "collector": self.collector.to_document(),
            "capture_id": self.capture_id,
            "provenance_sha256": self.provenance_sha256,
        }


@dataclass(frozen=True)
class AtomicRunResult:
    status: AtomicRunStatus
    artifacts: tuple[AtomicCapturedArtifact, ...]
    detail_code: str

    def __post_init__(self) -> None:
        if type(self.status) is not AtomicRunStatus:
            raise ContractError("status must be an AtomicRunStatus")
        validate_identifier(self.detail_code, "detail_code")
        if type(self.artifacts) not in (tuple, list) or any(
            type(item) is not AtomicCapturedArtifact for item in self.artifacts
        ):
            raise ContractError(
                "artifacts must contain only AtomicCapturedArtifact values"
            )
        roles = tuple(item.artifact.role for item in self.artifacts)
        if len(roles) != len(set(roles)):
            raise ContractError("artifacts must not repeat artifact roles")
        object.__setattr__(
            self,
            "artifacts",
            tuple(sorted(self.artifacts, key=lambda item: item.artifact.role)),
        )

    def to_document(self) -> dict[str, object]:
        return {
            "status": self.status.value,
            "artifacts": [item.to_document() for item in self.artifacts],
            "detail_code": self.detail_code,
        }

    @property
    def content_sha256(self) -> str:
        return canonical_sha256(self.to_document())


@dataclass(frozen=True)
class AtomicRunRecord:
    """One auditable invocation; retries and warmups are never discarded."""

    request: AtomicRunRequest
    result: AtomicRunResult

    def __post_init__(self) -> None:
        if type(self.request) is not AtomicRunRequest:
            raise ContractError("request must be an AtomicRunRequest")
        if type(self.result) is not AtomicRunResult:
            raise ContractError("result must be an AtomicRunResult")

    def to_document(self) -> dict[str, object]:
        return {
            "request": self.request.to_document(),
            "request_sha256": self.request.content_sha256,
            "result": self.result.to_document(),
            "result_sha256": self.result.content_sha256,
        }

    @property
    def content_sha256(self) -> str:
        return canonical_sha256(self.to_document())


@dataclass(frozen=True)
class NormalizedValue:
    variant_id: str
    repetition_index: int
    value: CanonicalTypedValue
    source_run_sha256: str

    def __post_init__(self) -> None:
        validate_identifier(self.variant_id, "variant_id")
        validate_non_negative_int(
            self.repetition_index,
            "repetition_index",
            maximum=_MAX_ATOMIC_ITEMS,
        )
        if type(self.value) is not CanonicalTypedValue:
            raise ContractError("value must be a CanonicalTypedValue")
        if self.value.value_id != self.variant_id:
            raise ContractError("normalized value_id must equal variant_id")
        validate_sha256(self.source_run_sha256, "source_run_sha256")

    def to_document(self) -> dict[str, object]:
        return {
            "variant_id": self.variant_id,
            "repetition_index": self.repetition_index,
            "value": self.value.to_document(),
            "source_run_sha256": self.source_run_sha256,
        }

    @property
    def content_sha256(self) -> str:
        return canonical_sha256(self.to_document())


@dataclass(frozen=True)
class TrialDecision:
    verdict: OracleVerdict
    reason_code: str
    values: tuple[CanonicalTypedValue, ...]
    evidence_group_id: str | None = None

    def __post_init__(self) -> None:
        if type(self.verdict) is not OracleVerdict:
            raise ContractError("verdict must be an OracleVerdict")
        validate_identifier(self.reason_code, "reason_code")
        if self.evidence_group_id is not None:
            validate_identifier(self.evidence_group_id, "evidence_group_id")
        if type(self.values) not in (tuple, list) or any(
            type(item) is not CanonicalTypedValue for item in self.values
        ):
            raise ContractError("values must contain CanonicalTypedValue values")
        value_ids = tuple(item.value_id for item in self.values)
        if len(value_ids) != len(set(value_ids)):
            raise ContractError("values must not repeat value_id")
        object.__setattr__(
            self,
            "values",
            tuple(sorted(self.values, key=lambda item: item.value_id)),
        )

    def to_document(self) -> dict[str, object]:
        return {
            "verdict": self.verdict.value,
            "reason_code": self.reason_code,
            "values": [item.to_document() for item in self.values],
            "evidence_group_id": self.evidence_group_id,
        }


@dataclass(frozen=True)
class AtomicTrialRecord:
    repetition_index: int
    decision: TrialDecision

    def __post_init__(self) -> None:
        validate_non_negative_int(
            self.repetition_index,
            "repetition_index",
            maximum=_MAX_ATOMIC_ITEMS,
        )
        if type(self.decision) is not TrialDecision:
            raise ContractError("decision must be a TrialDecision")

    def to_document(self) -> dict[str, object]:
        return {
            "repetition_index": self.repetition_index,
            "decision": self.decision.to_document(),
        }


@dataclass(frozen=True)
class AtomicVariantBinding:
    variant_id: str
    recipe: ContractRef

    def __post_init__(self) -> None:
        validate_identifier(self.variant_id, "variant_id")
        if (
            type(self.recipe) is not ContractRef
            or self.recipe.kind is not ContractRefKind.EXECUTION_RECIPE
        ):
            raise ContractError("recipe must be an execution_recipe ContractRef")

    def to_document(self) -> dict[str, object]:
        return {
            "variant_id": self.variant_id,
            "recipe": self.recipe.to_document(),
        }


@dataclass(frozen=True)
class ApplicabilityResult:
    """Hash-bound matcher output consumed by the atomic runtime.

    Trust in the matcher implementation and its evidence is established by the
    later profile qualification/registry layer; this value cannot self-assert
    that trust.
    """

    domain_id: str
    calibrated_domain_sha256: str
    matcher: ContractRef
    matches: bool
    evidence: tuple[ArtifactRef, ...]

    def __post_init__(self) -> None:
        validate_identifier(self.domain_id, "domain_id")
        validate_sha256(
            self.calibrated_domain_sha256,
            "calibrated_domain_sha256",
        )
        if (
            type(self.matcher) is not ContractRef
            or self.matcher.kind is not ContractRefKind.QUALIFICATION_POLICY
        ):
            raise ContractError(
                "matcher must be a qualification_policy ContractRef"
            )
        if type(self.matches) is not bool:
            raise ContractError("matches must be a boolean")
        if type(self.evidence) not in (tuple, list) or any(
            type(item) is not ArtifactRef for item in self.evidence
        ):
            raise ContractError("evidence must contain ArtifactRef values")
        roles = tuple(item.role for item in self.evidence)
        if not roles:
            raise ContractError("applicability evidence must not be empty")
        if len(roles) != len(set(roles)):
            raise ContractError("evidence must not repeat artifact roles")
        object.__setattr__(
            self,
            "evidence",
            tuple(sorted(self.evidence, key=lambda item: item.role)),
        )

    def to_document(self) -> dict[str, object]:
        return {
            "domain_id": self.domain_id,
            "calibrated_domain_sha256": self.calibrated_domain_sha256,
            "matcher": self.matcher.to_document(),
            "matches": self.matches,
            "evidence": [item.to_document() for item in self.evidence],
        }

    @property
    def content_sha256(self) -> str:
        return canonical_sha256(self.to_document())


@dataclass(frozen=True)
class AtomicOracleResult:
    oracle_spec: ContractRef
    normalizer: ContractRef
    comparator: ContractRef
    protocol: ExecutionProtocol
    variants: tuple[AtomicVariantBinding, ...]
    collectors: tuple[ContractRef, ...]
    applicability: ApplicabilityResult
    inputs: tuple[ArtifactRef, ...]
    threshold_values: tuple[CanonicalTypedValue, ...]
    result_class: AtomicResultClass
    verdict: OracleVerdict
    reason_codes: tuple[str, ...]
    domain_match: bool
    trials: tuple[AtomicTrialRecord, ...]
    run_records: tuple[AtomicRunRecord, ...]
    normalized_values: tuple[NormalizedValue, ...]

    def __post_init__(self) -> None:
        for field, kind in (
            ("oracle_spec", ContractRefKind.ORACLE_SPEC),
            ("normalizer", ContractRefKind.NORMALIZER),
            ("comparator", ContractRefKind.COMPARATOR),
        ):
            reference = getattr(self, field)
            if type(reference) is not ContractRef or reference.kind is not kind:
                raise ContractError(f"{field} must be a {kind.value} ContractRef")
        if type(self.protocol) is not ExecutionProtocol:
            raise ContractError("protocol must be an ExecutionProtocol")
        if type(self.variants) not in (tuple, list) or any(
            type(item) is not AtomicVariantBinding for item in self.variants
        ):
            raise ContractError("variants must contain AtomicVariantBinding values")
        variants = tuple(sorted(self.variants, key=lambda item: item.variant_id))
        variant_ids = tuple(item.variant_id for item in variants)
        if not variants or len(variant_ids) != len(set(variant_ids)):
            raise ContractError("variants must be non-empty and unique")
        object.__setattr__(self, "variants", variants)
        if type(self.collectors) not in (tuple, list) or any(
            type(item) is not ContractRef
            or item.kind is not ContractRefKind.COLLECTOR
            for item in self.collectors
        ):
            raise ContractError("collectors must contain collector ContractRef values")
        collectors = tuple(
            sorted(
                self.collectors,
                key=lambda item: (
                    item.contract_id,
                    item.contract_version,
                    item.content_sha256,
                ),
            )
        )
        collector_identities = tuple(
            (item.contract_id, item.contract_version) for item in collectors
        )
        if not collectors or len(collector_identities) != len(
            set(collector_identities)
        ):
            raise ContractError("collectors must be non-empty and unique")
        object.__setattr__(self, "collectors", collectors)
        if type(self.applicability) is not ApplicabilityResult:
            raise ContractError("applicability must be an ApplicabilityResult")
        if type(self.inputs) not in (tuple, list) or any(
            type(item) is not ArtifactRef for item in self.inputs
        ):
            raise ContractError("inputs must contain ArtifactRef values")
        inputs = tuple(sorted(self.inputs, key=lambda item: item.role))
        if len({item.role for item in inputs}) != len(inputs):
            raise ContractError("inputs must not repeat artifact roles")
        object.__setattr__(self, "inputs", inputs)
        if type(self.threshold_values) not in (tuple, list) or any(
            type(item) is not CanonicalTypedValue for item in self.threshold_values
        ):
            raise ContractError(
                "threshold_values must contain CanonicalTypedValue values"
            )
        threshold_values = tuple(
            sorted(self.threshold_values, key=lambda item: item.value_id)
        )
        if len({item.value_id for item in threshold_values}) != len(
            threshold_values
        ):
            raise ContractError("threshold_values must not repeat value_id")
        object.__setattr__(self, "threshold_values", threshold_values)
        if type(self.result_class) is not AtomicResultClass:
            raise ContractError("result_class must be an AtomicResultClass")
        if type(self.verdict) is not OracleVerdict:
            raise ContractError("verdict must be an OracleVerdict")
        if type(self.domain_match) is not bool:
            raise ContractError("domain_match must be a boolean")
        if type(self.reason_codes) not in (tuple, list):
            raise ContractError("reason_codes must be a collection")
        reasons = tuple(
            sorted(
                validate_identifier(code, "reason_codes")
                for code in self.reason_codes
            )
        )
        if not reasons or len(reasons) != len(set(reasons)):
            raise ContractError("reason_codes must be non-empty and unique")
        object.__setattr__(self, "reason_codes", reasons)
        if type(self.trials) not in (tuple, list) or any(
            type(item) is not AtomicTrialRecord for item in self.trials
        ):
            raise ContractError("trials must contain AtomicTrialRecord values")
        trials = tuple(self.trials)
        trial_indices = tuple(item.repetition_index for item in trials)
        if len(trial_indices) != len(set(trial_indices)):
            raise ContractError("trials must not repeat repetition_index")
        if trials and trial_indices != tuple(range(len(trials))):
            raise ContractError("trial repetition indices must be contiguous from zero")
        if len(trials) > self.quorum_total:
            raise ContractError("trials must not exceed the frozen quorum total")
        evidence_groups = tuple(
            item.decision.evidence_group_id
            for item in trials
            if item.decision.evidence_group_id is not None
        )
        if len(evidence_groups) != len(set(evidence_groups)):
            raise ContractError("trials must not reuse an evidence group")
        object.__setattr__(self, "trials", trials)
        if type(self.run_records) not in (tuple, list) or any(
            type(item) is not AtomicRunRecord for item in self.run_records
        ):
            raise ContractError("run_records must contain AtomicRunRecord values")
        object.__setattr__(self, "run_records", tuple(self.run_records))
        if type(self.normalized_values) not in (tuple, list) or any(
            type(item) is not NormalizedValue for item in self.normalized_values
        ):
            raise ContractError(
                "normalized_values must contain NormalizedValue values"
            )
        normalized = tuple(
            sorted(
                self.normalized_values,
                key=lambda item: (item.repetition_index, item.variant_id),
            )
        )
        keys = tuple((item.repetition_index, item.variant_id) for item in normalized)
        if len(keys) != len(set(keys)):
            raise ContractError("normalized_values repeat a trial variant")
        object.__setattr__(self, "normalized_values", normalized)

        self._validate_evidence_closure()

        if not self.domain_match:
            if self.result_class is not AtomicResultClass.DOMAIN_MISMATCH:
                raise ContractError(
                    "domain mismatch requires DOMAIN_MISMATCH result class"
                )
            if self.verdict is not OracleVerdict.INCONCLUSIVE:
                raise ContractError("domain mismatch must be INCONCLUSIVE")
            if trials or self.run_records or normalized:
                raise ContractError(
                    "domain mismatch must not contain executed evidence"
                )
        elif self.result_class is AtomicResultClass.DOMAIN_MISMATCH:
            raise ContractError(
                "DOMAIN_MISMATCH result class requires domain_match false"
            )
        elif (
            self.result_class is not AtomicResultClass.DECIDED
            and not self.run_records
        ):
            raise ContractError(
                "an executed terminal result requires recorded run evidence"
            )

        if self.result_class is AtomicResultClass.DECIDED:
            if len(trials) != self.quorum_total:
                raise ContractError("a decided result requires every trial")
            violation_met = self.violation_count >= self.quorum_required
            pass_met = self.pass_count >= self.quorum_required
            expected = (
                OracleVerdict.VIOLATION
                if violation_met and not pass_met
                else OracleVerdict.PASS
                if pass_met and not violation_met
                else OracleVerdict.INCONCLUSIVE
            )
            if self.verdict is not expected:
                raise ContractError("verdict does not match mechanical quorum")
        elif self.verdict is not OracleVerdict.INCONCLUSIVE:
            raise ContractError("non-decided results must be INCONCLUSIVE")
        if self.domain_match is not self.applicability.matches:
            raise ContractError("domain_match must equal the applicability result")

    @property
    def violation_count(self) -> int:
        return sum(
            item.decision.verdict is OracleVerdict.VIOLATION
            for item in self.trials
        )

    @property
    def pass_count(self) -> int:
        return sum(
            item.decision.verdict is OracleVerdict.PASS for item in self.trials
        )

    @property
    def inconclusive_count(self) -> int:
        return len(self.trials) - self.violation_count - self.pass_count

    @property
    def quorum_required(self) -> int:
        return self.protocol.quorum.required

    @property
    def quorum_total(self) -> int:
        return self.protocol.repetitions

    def _validate_evidence_closure(self) -> None:
        variant_recipes = {item.variant_id: item.recipe for item in self.variants}
        allowed_collectors = frozenset(self.collectors)
        groups: dict[tuple[bool, str, int], list[AtomicRunRecord]] = {}
        seen_invocations: set[tuple[bool, str, int, int]] = set()
        seen_captures: set[tuple[ContractRef, str]] = set()
        seen_provenance: set[str] = set()
        for record in self.run_records:
            request = record.request
            recipe = variant_recipes.get(request.variant_id)
            if recipe is None or request.recipe != recipe:
                raise ContractError("run record does not match a frozen variant recipe")
            if request.timeout_ms != self.protocol.timeout_ms:
                raise ContractError("run record timeout differs from frozen protocol")
            if request.inputs != self.inputs:
                raise ContractError("run record inputs differ from atomic result inputs")
            upper_bound = (
                self.protocol.warmup_runs
                if request.warmup
                else self.protocol.repetitions
            )
            if request.repetition_index >= upper_bound:
                raise ContractError("run record index is outside the frozen protocol")
            invocation = (
                request.warmup,
                request.variant_id,
                request.repetition_index,
                request.retry_index,
            )
            if invocation in seen_invocations:
                raise ContractError("run records repeat one invocation")
            seen_invocations.add(invocation)
            groups.setdefault(invocation[:3], []).append(record)
            for captured in record.result.artifacts:
                if captured.collector not in allowed_collectors:
                    raise ContractError("run record uses an undeclared collector")
                capture = (captured.collector, captured.capture_id)
                if (
                    capture in seen_captures
                    or captured.provenance_sha256 in seen_provenance
                ):
                    raise ContractError("run records reuse collector provenance")
                seen_captures.add(capture)
                seen_provenance.add(captured.provenance_sha256)

        expected_cells = tuple(
            (True, variant.variant_id, index)
            for index in range(self.protocol.warmup_runs)
            for variant in self.variants
        ) + tuple(
            (False, variant.variant_id, index)
            for index in range(self.protocol.repetitions)
            for variant in self.variants
        )
        actual_cells = tuple(groups)
        if actual_cells != expected_cells[: len(actual_cells)]:
            raise ContractError("run records must be a canonical execution prefix")
        actual_invocations = tuple(
            (
                record.request.warmup,
                record.request.variant_id,
                record.request.repetition_index,
                record.request.retry_index,
            )
            for record in self.run_records
        )
        expected_invocations = tuple(
            invocation
            for cell in actual_cells
            for invocation in sorted(
                (
                    (
                        record.request.warmup,
                        record.request.variant_id,
                        record.request.repetition_index,
                        record.request.retry_index,
                    )
                    for record in groups[cell]
                ),
                key=lambda item: item[-1],
            )
        )
        if actual_invocations != expected_invocations:
            raise ContractError("run records are not in canonical invocation order")

        final_measurements: dict[tuple[str, int], AtomicRunRecord] = {}
        for (warmup, variant_id, repetition_index), records in groups.items():
            ordered = sorted(records, key=lambda item: item.request.retry_index)
            retry_indices = tuple(item.request.retry_index for item in ordered)
            if retry_indices != tuple(range(len(ordered))):
                raise ContractError("run retries must be contiguous from zero")
            if retry_indices[-1] > self.protocol.max_retries:
                raise ContractError("run retry exceeds the frozen protocol")
            for prior in ordered[:-1]:
                retry_reason = _STATUS_RETRY_REASON.get(prior.result.status)
                if retry_reason not in self.protocol.retry_reasons:
                    raise ContractError("run retried a non-approved result status")
            if not warmup:
                final_measurements[(variant_id, repetition_index)] = ordered[-1]

        normalized_by_cell = {
            (item.variant_id, item.repetition_index): item
            for item in self.normalized_values
        }
        for cell, value in normalized_by_cell.items():
            final = final_measurements.get(cell)
            if final is None or value.source_run_sha256 != final.content_sha256:
                raise ContractError(
                    "normalized value does not bind its final measured invocation"
                )
            if final.result.status in _STATUS_RETRY_REASON:
                raise ContractError(
                    "infrastructure failure cannot yield a normalized value"
                )

        for trial in self.trials:
            values = tuple(
                sorted(
                    (
                        item.value
                        for (variant_id, repetition), item in normalized_by_cell.items()
                        if repetition == trial.repetition_index
                    ),
                    key=lambda item: item.value_id,
                )
            )
            decision = trial.decision
            observed_variant_ids = {item.value_id for item in values}
            if decision.verdict is not OracleVerdict.INCONCLUSIVE and not values:
                raise ContractError("a decisive trial requires normalized evidence")
            if (
                decision.verdict is not OracleVerdict.INCONCLUSIVE
                and observed_variant_ids != set(variant_recipes)
            ):
                raise ContractError(
                    "a decisive trial requires every frozen variant value"
                )
            if decision.values and decision.values != values:
                raise ContractError("trial decision values differ from normalized evidence")
            if decision.verdict is not OracleVerdict.INCONCLUSIVE and (
                decision.values != values
            ):
                raise ContractError("a decisive trial must bind all normalized evidence")

        if self.result_class is AtomicResultClass.DECIDED:
            expected_warmups = {
                (True, variant.variant_id, index)
                for variant in self.variants
                for index in range(self.protocol.warmup_runs)
            }
            expected_measurements = {
                (False, variant.variant_id, index)
                for variant in self.variants
                for index in range(self.protocol.repetitions)
            }
            if set(groups) != expected_warmups.union(expected_measurements):
                raise ContractError("decided result lacks the full execution matrix")
            for key in expected_warmups:
                final = max(
                    groups[key], key=lambda item: item.request.retry_index
                )
                if final.result.status is not AtomicRunStatus.COMPLETED:
                    raise ContractError("decided result contains a failed warmup")
            if any(
                final.result.status in _STATUS_RETRY_REASON
                for final in final_measurements.values()
            ):
                raise ContractError("decided result ends on an infrastructure status")

    @property
    def decision_quorum(self) -> DecisionQuorum:
        """Project partial terminal execution onto the frozen decision shape."""

        return DecisionQuorum(
            required=self.quorum_required,
            total=self.quorum_total,
            violation_count=self.violation_count,
            pass_count=self.pass_count,
            inconclusive_count=(
                self.inconclusive_count + self.quorum_total - len(self.trials)
            ),
        )

    def to_document(self) -> dict[str, object]:
        return {
            "oracle_spec": self.oracle_spec.to_document(),
            "normalizer": self.normalizer.to_document(),
            "comparator": self.comparator.to_document(),
            "protocol": self.protocol.to_document(),
            "variants": [item.to_document() for item in self.variants],
            "collectors": [item.to_document() for item in self.collectors],
            "applicability": self.applicability.to_document(),
            "inputs": [item.to_document() for item in self.inputs],
            "threshold_values": [
                item.to_document() for item in self.threshold_values
            ],
            "result_class": self.result_class.value,
            "verdict": self.verdict.value,
            "reason_codes": list(self.reason_codes),
            "domain_match": self.domain_match,
            "quorum": self.decision_quorum.to_document(),
            "trials": [item.to_document() for item in self.trials],
            "run_records": [item.to_document() for item in self.run_records],
            "normalized_values": [
                item.to_document() for item in self.normalized_values
            ],
        }

    @property
    def content_sha256(self) -> str:
        return canonical_sha256(self.to_document())


ArtifactReader = Callable[[ArtifactRef], bytes]


class AtomicRunner(Protocol):
    recipe_ref: ContractRef
    collector_refs: tuple[ContractRef, ...]

    def __call__(self, request: AtomicRunRequest) -> AtomicRunResult: ...


class AtomicNormalizer(Protocol):
    atom_ref: ContractRef
    reason_codes: tuple[str, ...]

    def __call__(
        self,
        variant_id: str,
        repetition_index: int,
        result: AtomicRunResult,
        read_artifact: ArtifactReader,
    ) -> CanonicalTypedValue: ...


class AtomicComparator(Protocol):
    atom_ref: ContractRef
    policy_refs: tuple[ContractRef, ...]
    reason_codes: dict[OracleVerdict, tuple[str, ...]]
    threshold_values: tuple[CanonicalTypedValue, ...]
    supported_method_types: tuple[type, ...]

    def __call__(
        self,
        method: object,
        values: tuple[CanonicalTypedValue, ...],
        read_artifact: ArtifactReader,
        *,
        repetition_index: int,
    ) -> TrialDecision: ...


def validate_atomic_result_structure(
    spec: OracleSpec,
    result: AtomicOracleResult,
) -> None:
    """Bind a structurally closed result to a spec without trusting its facts.

    Runtime consumers must additionally use ``AtomicOracleEngine.validate_result``
    so the exact admitted normalizer and comparator are replayed over hash-checked
    artifacts.  Structure alone cannot establish observation authenticity.
    """

    if type(spec) is not OracleSpec or type(result) is not AtomicOracleResult:
        raise ContractError("atomic result validation requires exact contract types")
    expected_variants = tuple(
        AtomicVariantBinding(item.variant_id, item.execution_recipe)
        for item in spec.variants
    )
    if (
        result.oracle_spec != spec.ref
        or result.normalizer != spec.normalizer
        or result.comparator != spec.comparator
        or result.protocol != spec.execution_protocol
        or result.variants != expected_variants
        or result.collectors != spec.collectors
    ):
        raise ContractError("atomic result does not bind the supplied OracleSpec")
    if (
        result.applicability.domain_id != spec.applicability.domain_id
        or result.applicability.calibrated_domain_sha256
        != spec.applicability.calibrated_domain.content_sha256
        or result.applicability.matcher != spec.qualification_policy
    ):
        raise ContractError("atomic result applicability does not bind the OracleSpec")
    if spec.threshold_policy is None and result.threshold_values:
        raise ContractError("threshold values require a frozen threshold policy")
    if spec.threshold_policy is not None and not result.threshold_values:
        raise ContractError("frozen threshold policy requires threshold values")

    vocabulary = {
        OracleVerdict.VIOLATION: frozenset(spec.reason_vocabulary.violation),
        OracleVerdict.PASS: frozenset(spec.reason_vocabulary.passed),
        OracleVerdict.INCONCLUSIVE: frozenset(
            spec.reason_vocabulary.inconclusive
        ),
    }
    for trial in result.trials:
        if trial.decision.reason_code not in vocabulary[trial.decision.verdict]:
            raise ContractError("trial reason code is outside the OracleSpec vocabulary")

    if result.result_class is AtomicResultClass.DOMAIN_MISMATCH:
        expected_reasons = {spec.applicability.out_of_domain_reason}
    elif result.result_class is AtomicResultClass.INFRA_INCONCLUSIVE:
        expected_reasons = {"ENVIRONMENT_UNSTABLE"}
    elif result.result_class is AtomicResultClass.ORACLE_INCONCLUSIVE:
        expected_reasons = {"METRIC_INVALID"}
    elif result.verdict is OracleVerdict.INCONCLUSIVE:
        expected_reasons = {
            trial.decision.reason_code
            for trial in result.trials
            if trial.decision.verdict is OracleVerdict.INCONCLUSIVE
        }
        expected_reasons.add("QUORUM_NOT_MET")
    else:
        expected_reasons = {
            trial.decision.reason_code
            for trial in result.trials
            if trial.decision.verdict is result.verdict
        }
    if set(result.reason_codes) != expected_reasons:
        raise ContractError("result reason codes do not match terminal evidence")
    if not set(result.reason_codes).issubset(
        vocabulary[
            result.verdict
            if result.result_class is AtomicResultClass.DECIDED
            else OracleVerdict.INCONCLUSIVE
        ]
    ):
        raise ContractError("result reason code is outside the OracleSpec vocabulary")

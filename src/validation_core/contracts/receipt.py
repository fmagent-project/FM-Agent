"""Hash-bound B1/B2 Gate receipts for the generic validator.

Receipts record what an already-authorized Gate did.  They do not execute a
plan, resolve trust, or publish a terminal outcome.  The strict union keeps an
explicit ``not_confirmed`` identity/hash check structurally separate from a
full candidate experiment so that the fast path cannot impersonate evidence.
Pre-execution failures retain authority identity and parsed membership without
fabricating a Template, Binding, or execution evidence.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import TYPE_CHECKING, Iterable

from .base import (
    ContractError,
    canonical_sha256,
    load_strict_json_object,
    require_exact_keys,
    validate_identifier,
    validate_sha256,
)
from .plan import ExecutionBinding, ExperimentPhase, ExperimentPlanTemplate, GateRole
from .references import ArtifactRef, ContractRef, ContractRefKind
from .status import (
    CaseReasonCode,
    CaseStatus,
    GateAttemptDisposition,
    GatePhaseStatus,
    ValidationGrade,
    validate_status_reason,
)

if TYPE_CHECKING:
    from .case import (
        CasePlan,
        CaseSubmission,
        CaseSubmissionKind,
        ValidationInstanceIdentity,
    )
    from .evidence import Observation, OracleDecision
    from .oracle import OracleBundle
    from .profile import FrozenSystemProfile


_GATE_RECEIPT_CONTRACT_KIND = "gate_receipt"
_SCHEMA_VERSION = 1
_CONTENT_REF_VERSION = "1"
_MAX_EVIDENCE_REFS = 16_384
_MAX_PHASE_REASON_CODES = 256


class GateReceiptKind(str, Enum):
    FULL_CANDIDATE_GATE = "full_candidate_gate"
    PRE_EXECUTION_FAILURE = "pre_execution_failure"
    IDENTITY_HASH_FAST_PATH = "identity_hash_fast_path"


class EarlyGateStage(str, Enum):
    """Canonical Gate stages that precede an executable Template/Binding."""

    INTAKE = "intake"
    MEMBERSHIP = "membership"
    CONTEXT_INTEGRITY = "context_integrity"
    MATERIALIZE = "materialize"


class FastPathCheck(str, Enum):
    STRICT_SCHEMA = "strict_schema"
    IDENTITY = "identity"
    REASONING_HASH = "reasoning_hash"
    CONTEXT_HASH = "context_hash"
    PROFILE_HASH = "profile_hash"
    SUBMISSION_HASH = "submission_hash"


_REQUIRED_FAST_PATH_CHECKS = tuple(FastPathCheck)
_PHASE_ORDER = {phase: index for index, phase in enumerate(ExperimentPhase)}
_REPAIR_PHASES = frozenset(
    (
        ExperimentPhase.REPAIR,
        ExperimentPhase.BUILD_SANITY,
        ExperimentPhase.REPAIR_REAL_ENTRY_REPLAY,
        ExperimentPhase.REPAIR_TARGET_EVIDENCE,
        ExperimentPhase.REPAIR_ORACLE_EXPERIMENT,
        ExperimentPhase.REGRESSION,
    )
)


def _enum_value(enum_type: type[Enum], value: object, field: str) -> Enum:
    if type(value) is not str:
        raise ContractError(f"{field} must be a string enum value")
    try:
        return enum_type(value)
    except ValueError as exc:
        raise ContractError(f"{field} has unsupported value {value!r}") from exc


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


def _optional_ref_from_document(
    value: object,
    expected_kind: ContractRefKind,
    field: str,
) -> ContractRef | None:
    if value is None:
        return None
    return _ref_from_document(value, expected_kind, field)


def _ref_sort_key(reference: ContractRef) -> tuple[str, str, str, str]:
    return (
        reference.kind.value,
        reference.contract_id,
        reference.contract_version,
        reference.content_sha256,
    )


def _ref_identity(reference: ContractRef) -> tuple[ContractRefKind, str, str]:
    return (
        reference.kind,
        reference.contract_id,
        reference.contract_version,
    )


def _normalize_refs(
    value: object,
    expected_kind: ContractRefKind,
    field: str,
) -> tuple[ContractRef, ...]:
    if type(value) not in (tuple, list):
        raise ContractError(f"{field} must be a collection of ContractRef values")
    references = tuple(value)
    if len(references) > _MAX_EVIDENCE_REFS:
        raise ContractError(
            f"{field} must not contain more than {_MAX_EVIDENCE_REFS} values"
        )
    for reference in references:
        _require_ref(reference, expected_kind, field)
    identities = tuple(
        (reference.contract_id, reference.contract_version)
        for reference in references
    )
    if len(identities) != len(set(identities)):
        raise ContractError(f"{field} must not repeat or conflict on id/version")
    return tuple(sorted(references, key=_ref_sort_key))


def _refs_from_document(
    value: object,
    expected_kind: ContractRefKind,
    field: str,
) -> tuple[ContractRef, ...]:
    if type(value) is not list:
        raise ContractError(f"{field} must be a list")
    return _normalize_refs(
        tuple(
            _ref_from_document(item, expected_kind, f"{field}[{index}]")
            for index, item in enumerate(value)
        ),
        expected_kind,
        field,
    )


@dataclass(frozen=True)
class GatePhaseResult:
    """Coarse Gate phase state; raw facts remain in Observation contracts."""

    phase: ExperimentPhase
    status: GatePhaseStatus
    reason_codes: tuple[str, ...]

    def __post_init__(self) -> None:
        if type(self.phase) is not ExperimentPhase:
            raise ContractError("phase must be an ExperimentPhase")
        if type(self.status) is not GatePhaseStatus:
            raise ContractError("status must be a GatePhaseStatus")
        if type(self.reason_codes) not in (tuple, list):
            raise ContractError("reason_codes must be a collection of identifiers")
        reasons = tuple(
            validate_identifier(reason, "phase reason code")
            for reason in self.reason_codes
        )
        if len(reasons) > _MAX_PHASE_REASON_CODES:
            raise ContractError(
                "reason_codes must not contain more than "
                f"{_MAX_PHASE_REASON_CODES} values"
            )
        if len(reasons) != len(set(reasons)):
            raise ContractError("reason_codes must not contain duplicates")
        if self.status is GatePhaseStatus.SATISFIED:
            if reasons:
                raise ContractError("a satisfied phase must not have reason_codes")
        elif not reasons:
            raise ContractError(
                "a rejected, inconclusive, or skipped phase requires reason_codes"
            )
        object.__setattr__(self, "reason_codes", tuple(sorted(reasons)))

    def to_document(self) -> dict[str, object]:
        return {
            "phase": self.phase.value,
            "status": self.status.value,
            "reason_codes": list(self.reason_codes),
        }

    @classmethod
    def from_document(cls, value: object) -> GatePhaseResult:
        document = require_exact_keys(
            value,
            required=("phase", "status", "reason_codes"),
            where="gate phase result",
        )
        reason_codes = document["reason_codes"]
        if type(reason_codes) is not list:
            raise ContractError("gate phase result reason_codes must be a list")
        return cls(
            phase=_enum_value(
                ExperimentPhase,
                document["phase"],
                "gate phase result phase",
            ),
            status=_enum_value(
                GatePhaseStatus,
                document["status"],
                "gate phase result status",
            ),
            reason_codes=tuple(reason_codes),
        )


def _normalize_phase_results(value: object) -> tuple[GatePhaseResult, ...]:
    if type(value) not in (tuple, list):
        raise ContractError("phase_results must be a collection")
    results = tuple(value)
    if any(type(result) is not GatePhaseResult for result in results):
        raise ContractError("phase_results must contain GatePhaseResult values")
    phases = tuple(result.phase for result in results)
    if len(phases) != len(set(phases)):
        raise ContractError("phase_results must not repeat a phase")
    return tuple(sorted(results, key=lambda result: _PHASE_ORDER[result.phase]))


def _parse_optional_grade(value: object, field: str) -> ValidationGrade | None:
    if value is None:
        return None
    return _enum_value(ValidationGrade, value, field)


def _parse_optional_disposition(
    value: object,
    field: str,
) -> GateAttemptDisposition | None:
    if value is None:
        return None
    return _enum_value(GateAttemptDisposition, value, field)


def _parse_optional_sha256(value: object, field: str) -> str | None:
    if value is None:
        return None
    return validate_sha256(value, field)


@dataclass(frozen=True)
class CandidateGateReceipt:
    """One full candidate execution by B1 or B2."""

    validation_instance_id: str
    attempt_id: str
    role: GateRole
    submission: ContractRef
    profile: ContractRef
    case_plan: ContractRef
    template: ContractRef
    binding: ContractRef
    requested_grade: ValidationGrade
    final_grade: ValidationGrade | None
    original_l1_candidate_sha256: str | None
    patch_sha256: str | None
    observations: tuple[ContractRef, ...]
    decisions: tuple[ContractRef, ...]
    phase_results: tuple[GatePhaseResult, ...]
    disposition: GateAttemptDisposition | None
    result_status: CaseStatus
    result_reason_code: CaseReasonCode

    def __post_init__(self) -> None:
        validate_sha256(self.validation_instance_id, "validation_instance_id")
        validate_identifier(self.attempt_id, "attempt_id")
        if type(self.role) is not GateRole:
            raise ContractError("role must be a GateRole")
        _require_ref(self.submission, ContractRefKind.CASE_SUBMISSION, "submission")
        _require_ref(self.profile, ContractRefKind.FROZEN_PROFILE, "profile")
        _require_ref(self.case_plan, ContractRefKind.CASE_PLAN, "case_plan")
        _require_ref(
            self.template,
            ContractRefKind.EXPERIMENT_PLAN_TEMPLATE,
            "template",
        )
        _require_ref(
            self.binding,
            ContractRefKind.EXECUTION_BINDING,
            "binding",
        )
        if type(self.requested_grade) is not ValidationGrade:
            raise ContractError("requested_grade must be a ValidationGrade")
        if self.final_grade is not None and type(self.final_grade) is not ValidationGrade:
            raise ContractError("final_grade must be a ValidationGrade or None")
        if self.original_l1_candidate_sha256 is not None:
            validate_sha256(
                self.original_l1_candidate_sha256,
                "original_l1_candidate_sha256",
            )
        if self.patch_sha256 is not None:
            validate_sha256(self.patch_sha256, "patch_sha256")

        observations = _normalize_refs(
            self.observations,
            ContractRefKind.OBSERVATION,
            "observations",
        )
        decisions = _normalize_refs(
            self.decisions,
            ContractRefKind.ORACLE_DECISION,
            "decisions",
        )
        if decisions and not observations:
            raise ContractError("decisions require at least one observation")
        object.__setattr__(self, "observations", observations)
        object.__setattr__(self, "decisions", decisions)
        object.__setattr__(
            self,
            "phase_results",
            _normalize_phase_results(self.phase_results),
        )

        if type(self.result_status) is not CaseStatus:
            raise ContractError("result_status must be a CaseStatus")
        if type(self.result_reason_code) is not CaseReasonCode:
            raise ContractError("result_reason_code must be a CaseReasonCode")
        validate_status_reason(self.result_status, self.result_reason_code)
        if self.result_reason_code is CaseReasonCode.EXPLICIT_NOT_CONFIRMED:
            raise ContractError(
                "EXPLICIT_NOT_CONFIRMED is allowed only on the fast-path branch"
            )

        if self.requested_grade is ValidationGrade.L0:
            if (
                self.original_l1_candidate_sha256 is not None
                or self.patch_sha256 is not None
            ):
                raise ContractError(
                    "an L0 request must not carry original L1 candidate or patch hashes"
                )
            if self.final_grade is ValidationGrade.L1:
                raise ContractError("an L0 request cannot produce final L1")
        else:
            if (
                self.original_l1_candidate_sha256 is None
                or self.patch_sha256 is None
            ):
                raise ContractError(
                    "an L1 request must preserve original candidate and patch hashes"
                )

        confirmed_grade = {
            CaseStatus.CONFIRMED_L0: ValidationGrade.L0,
            CaseStatus.CONFIRMED_L1: ValidationGrade.L1,
        }.get(self.result_status)
        if confirmed_grade is not None:
            if self.final_grade is not confirmed_grade:
                raise ContractError(
                    "confirmed result_status must match final_grade exactly"
                )
            if not self.observations or not self.decisions:
                raise ContractError(
                    "a confirmed candidate receipt requires observations and decisions"
                )
        elif self.final_grade is not None:
            raise ContractError("a non-confirmed result must not contain final_grade")

        if self.role is GateRole.B1:
            if type(self.disposition) is not GateAttemptDisposition:
                raise ContractError("a B1 candidate receipt requires a disposition")
            if (
                self.disposition
                is GateAttemptDisposition.ACCEPTED_EXPLICIT_NOT_CONFIRMED
            ):
                raise ContractError(
                    "explicit not_confirmed is allowed only on the fast-path branch"
                )
            if confirmed_grade is not None:
                if (
                    self.disposition
                    is not GateAttemptDisposition.ACCEPTED_CONFIRMED_CANDIDATE
                ):
                    raise ContractError(
                        "a confirmed B1 result requires confirmed-candidate disposition"
                    )
            elif self.disposition is GateAttemptDisposition.ACCEPTED_CONFIRMED_CANDIDATE:
                raise ContractError(
                    "confirmed-candidate disposition requires a confirmed result"
                )
            elif self.disposition not in (
                GateAttemptDisposition.RETRYABLE_REJECTION,
                GateAttemptDisposition.TERMINAL_OUTCOME,
            ):
                raise ContractError("unsupported B1 candidate disposition")
            terminal_status = self.result_status in (
                CaseStatus.INCONCLUSIVE_INFRA,
                CaseStatus.NEEDS_ORACLE_SETUP,
            )
            terminal_integrity_reason = self.result_reason_code in (
                CaseReasonCode.PROFILE_ARTIFACT_INVALID,
                CaseReasonCode.BASELINE_ARTIFACT_HASH_MISMATCH,
            )
            if (
                terminal_status or terminal_integrity_reason
            ) and self.disposition is not GateAttemptDisposition.TERMINAL_OUTCOME:
                raise ContractError(
                    "infrastructure, setup, and frozen-integrity failures "
                    "require terminal B1 disposition"
                )
        elif self.disposition is not None:
            raise ContractError("a B2 receipt must not contain a B1 disposition")

    @property
    def receipt_kind(self) -> GateReceiptKind:
        return GateReceiptKind.FULL_CANDIDATE_GATE

    def to_document(self) -> dict[str, object]:
        return {
            "contract_kind": _GATE_RECEIPT_CONTRACT_KIND,
            "schema_version": _SCHEMA_VERSION,
            "receipt_kind": self.receipt_kind.value,
            "validation_instance_id": self.validation_instance_id,
            "attempt_id": self.attempt_id,
            "role": self.role.value,
            "submission": self.submission.to_document(),
            "profile": self.profile.to_document(),
            "case_plan": self.case_plan.to_document(),
            "template": self.template.to_document(),
            "binding": self.binding.to_document(),
            "requested_grade": self.requested_grade.value,
            "final_grade": (
                None if self.final_grade is None else self.final_grade.value
            ),
            "original_l1_candidate_sha256": self.original_l1_candidate_sha256,
            "patch_sha256": self.patch_sha256,
            "observations": [reference.to_document() for reference in self.observations],
            "decisions": [reference.to_document() for reference in self.decisions],
            "phase_results": [result.to_document() for result in self.phase_results],
            "disposition": (
                None if self.disposition is None else self.disposition.value
            ),
            "result_status": self.result_status.value,
            "result_reason_code": self.result_reason_code.value,
        }

    @classmethod
    def from_document(cls, value: object) -> CandidateGateReceipt:
        document = require_exact_keys(
            value,
            required=(
                "contract_kind",
                "schema_version",
                "receipt_kind",
                "validation_instance_id",
                "attempt_id",
                "role",
                "submission",
                "profile",
                "case_plan",
                "template",
                "binding",
                "requested_grade",
                "final_grade",
                "original_l1_candidate_sha256",
                "patch_sha256",
                "observations",
                "decisions",
                "phase_results",
                "disposition",
                "result_status",
                "result_reason_code",
            ),
            where="candidate gate receipt",
        )
        _validate_envelope(
            document,
            GateReceiptKind.FULL_CANDIDATE_GATE,
            "candidate gate receipt",
        )
        phase_documents = document["phase_results"]
        if type(phase_documents) is not list:
            raise ContractError("phase_results must be a list")
        return cls(
            validation_instance_id=document["validation_instance_id"],
            attempt_id=document["attempt_id"],
            role=_enum_value(GateRole, document["role"], "gate receipt role"),
            submission=_ref_from_document(
                document["submission"],
                ContractRefKind.CASE_SUBMISSION,
                "submission",
            ),
            profile=_ref_from_document(
                document["profile"],
                ContractRefKind.FROZEN_PROFILE,
                "profile",
            ),
            case_plan=_ref_from_document(
                document["case_plan"],
                ContractRefKind.CASE_PLAN,
                "case_plan",
            ),
            template=_ref_from_document(
                document["template"],
                ContractRefKind.EXPERIMENT_PLAN_TEMPLATE,
                "template",
            ),
            binding=_ref_from_document(
                document["binding"],
                ContractRefKind.EXECUTION_BINDING,
                "binding",
            ),
            requested_grade=_enum_value(
                ValidationGrade,
                document["requested_grade"],
                "requested_grade",
            ),
            final_grade=_parse_optional_grade(document["final_grade"], "final_grade"),
            original_l1_candidate_sha256=_parse_optional_sha256(
                document["original_l1_candidate_sha256"],
                "original_l1_candidate_sha256",
            ),
            patch_sha256=_parse_optional_sha256(
                document["patch_sha256"],
                "patch_sha256",
            ),
            observations=_refs_from_document(
                document["observations"],
                ContractRefKind.OBSERVATION,
                "observations",
            ),
            decisions=_refs_from_document(
                document["decisions"],
                ContractRefKind.ORACLE_DECISION,
                "decisions",
            ),
            phase_results=tuple(
                GatePhaseResult.from_document(item) for item in phase_documents
            ),
            disposition=_parse_optional_disposition(
                document["disposition"],
                "disposition",
            ),
            result_status=_enum_value(
                CaseStatus,
                document["result_status"],
                "result_status",
            ),
            result_reason_code=_enum_value(
                CaseReasonCode,
                document["result_reason_code"],
                "result_reason_code",
            ),
        )

    @classmethod
    def from_json(cls, payload: object) -> CandidateGateReceipt:
        receipt = gate_receipt_from_json(payload)
        if type(receipt) is not cls:
            raise ContractError("gate receipt is not a full candidate receipt")
        return receipt

    @property
    def content_sha256(self) -> str:
        return canonical_sha256(self.to_document())

    @property
    def ref(self) -> ContractRef:
        return ContractRef(
            kind=ContractRefKind.GATE_RECEIPT,
            contract_id=self.content_sha256,
            contract_version=_CONTENT_REF_VERSION,
            content_sha256=self.content_sha256,
        )


@dataclass(frozen=True)
class EarlyGateReceipt:
    """A failure before an executable Template and Binding exist.

    The authority-owned identity and raw submission are always retained.  At
    ``intake`` no parsed object is trusted.  Later stages bind the exact parsed
    objects that were inspected, without claiming that membership or context
    validation succeeded.
    """

    validation_instance_id: str
    attempt_id: str
    role: GateRole
    failure_stage: EarlyGateStage
    project_id: str
    case_id: str
    function_id: str
    snapshot_sha256: str
    reasoning_sha256: str
    profile_sha256: str
    context_sha256: str
    raw_submission: ArtifactRef
    parsed_submission_kind: CaseSubmissionKind | None
    parsed_submission: ContractRef | None
    parsed_profile: ContractRef | None
    parsed_case_plan: ContractRef | None
    disposition: GateAttemptDisposition | None
    result_status: CaseStatus
    result_reason_code: CaseReasonCode

    def __post_init__(self) -> None:
        from .case import CaseSubmissionKind, compute_validation_instance_id

        validate_sha256(self.validation_instance_id, "validation_instance_id")
        validate_identifier(self.attempt_id, "attempt_id")
        if type(self.role) is not GateRole:
            raise ContractError("role must be a GateRole")
        if type(self.failure_stage) is not EarlyGateStage:
            raise ContractError("failure_stage must be an EarlyGateStage")
        validate_identifier(self.project_id, "project_id")
        validate_identifier(self.case_id, "case_id")
        validate_identifier(self.function_id, "function_id")
        validate_sha256(self.snapshot_sha256, "snapshot_sha256")
        validate_sha256(self.reasoning_sha256, "reasoning_sha256")
        validate_sha256(self.profile_sha256, "profile_sha256")
        validate_sha256(self.context_sha256, "context_sha256")
        expected_instance_id = compute_validation_instance_id(
            project_id=self.project_id,
            case_id=self.case_id,
            function_id=self.function_id,
            snapshot_sha256=self.snapshot_sha256,
            reasoning_sha256=self.reasoning_sha256,
            profile_sha256=self.profile_sha256,
        )
        if self.validation_instance_id != expected_instance_id:
            raise ContractError(
                "early receipt validation instance does not match authority identity"
            )
        if type(self.raw_submission) is not ArtifactRef:
            raise ContractError("raw_submission must be an ArtifactRef")
        if self.raw_submission.role != "raw_submission":
            raise ContractError("raw_submission artifact role must be 'raw_submission'")

        parsed_values = (
            self.parsed_submission,
            self.parsed_profile,
            self.parsed_case_plan,
        )
        if self.failure_stage is EarlyGateStage.INTAKE:
            if self.parsed_submission_kind is not None or any(
                value is not None for value in parsed_values
            ):
                raise ContractError(
                    "an intake failure must not claim parsed contract references"
                )
        else:
            if type(self.parsed_submission_kind) is not CaseSubmissionKind:
                raise ContractError(
                    "a post-intake failure requires parsed_submission_kind"
                )
            if self.parsed_submission is None or self.parsed_profile is None:
                raise ContractError(
                    "a post-intake failure requires parsed submission and Profile refs"
                )
            _require_ref(
                self.parsed_submission,
                ContractRefKind.CASE_SUBMISSION,
                "parsed_submission",
            )
            _require_ref(
                self.parsed_profile,
                ContractRefKind.FROZEN_PROFILE,
                "parsed_profile",
            )
            if self.parsed_submission_kind is CaseSubmissionKind.CANDIDATE:
                _require_ref(
                    self.parsed_case_plan,
                    ContractRefKind.CASE_PLAN,
                    "parsed_case_plan",
                )
            else:
                if self.parsed_case_plan is not None:
                    raise ContractError(
                        "not_confirmed early receipt must not claim a CasePlan"
                    )
                if self.failure_stage is EarlyGateStage.MATERIALIZE:
                    raise ContractError(
                        "not_confirmed submission cannot reach materialize"
                    )

        if type(self.result_status) is not CaseStatus:
            raise ContractError("result_status must be a CaseStatus")
        if type(self.result_reason_code) is not CaseReasonCode:
            raise ContractError("result_reason_code must be a CaseReasonCode")
        validate_status_reason(self.result_status, self.result_reason_code)
        if self.result_status in (
            CaseStatus.CONFIRMED_L0,
            CaseStatus.CONFIRMED_L1,
            CaseStatus.NOT_CONFIRMED,
        ):
            raise ContractError(
                "a pre-execution failure cannot claim an experimental Case result"
            )

        if self.role is GateRole.B1:
            if self.disposition not in (
                GateAttemptDisposition.RETRYABLE_REJECTION,
                GateAttemptDisposition.TERMINAL_OUTCOME,
            ):
                raise ContractError(
                    "a B1 early receipt requires retryable or terminal disposition"
                )
            terminal_status = self.result_status in (
                CaseStatus.INCONCLUSIVE_INFRA,
                CaseStatus.NEEDS_ORACLE_SETUP,
            )
            terminal_integrity_reason = self.result_reason_code in (
                CaseReasonCode.PROFILE_ARTIFACT_INVALID,
                CaseReasonCode.BASELINE_ARTIFACT_HASH_MISMATCH,
            )
            if (
                terminal_status or terminal_integrity_reason
            ) and self.disposition is not GateAttemptDisposition.TERMINAL_OUTCOME:
                raise ContractError(
                    "infrastructure, setup, and frozen-integrity failures "
                    "require terminal B1 disposition"
                )
        elif self.disposition is not None:
            raise ContractError("a B2 early receipt must not contain a disposition")

    @property
    def receipt_kind(self) -> GateReceiptKind:
        return GateReceiptKind.PRE_EXECUTION_FAILURE

    def to_document(self) -> dict[str, object]:
        return {
            "contract_kind": _GATE_RECEIPT_CONTRACT_KIND,
            "schema_version": _SCHEMA_VERSION,
            "receipt_kind": self.receipt_kind.value,
            "validation_instance_id": self.validation_instance_id,
            "attempt_id": self.attempt_id,
            "role": self.role.value,
            "failure_stage": self.failure_stage.value,
            "project_id": self.project_id,
            "case_id": self.case_id,
            "function_id": self.function_id,
            "snapshot_sha256": self.snapshot_sha256,
            "reasoning_sha256": self.reasoning_sha256,
            "profile_sha256": self.profile_sha256,
            "context_sha256": self.context_sha256,
            "raw_submission": self.raw_submission.to_document(),
            "parsed_submission_kind": (
                None
                if self.parsed_submission_kind is None
                else self.parsed_submission_kind.value
            ),
            "parsed_submission": (
                None
                if self.parsed_submission is None
                else self.parsed_submission.to_document()
            ),
            "parsed_profile": (
                None
                if self.parsed_profile is None
                else self.parsed_profile.to_document()
            ),
            "parsed_case_plan": (
                None
                if self.parsed_case_plan is None
                else self.parsed_case_plan.to_document()
            ),
            "disposition": (
                None if self.disposition is None else self.disposition.value
            ),
            "result_status": self.result_status.value,
            "result_reason_code": self.result_reason_code.value,
        }

    @classmethod
    def from_document(cls, value: object) -> EarlyGateReceipt:
        document = require_exact_keys(
            value,
            required=(
                "contract_kind",
                "schema_version",
                "receipt_kind",
                "validation_instance_id",
                "attempt_id",
                "role",
                "failure_stage",
                "project_id",
                "case_id",
                "function_id",
                "snapshot_sha256",
                "reasoning_sha256",
                "profile_sha256",
                "context_sha256",
                "raw_submission",
                "parsed_submission_kind",
                "parsed_submission",
                "parsed_profile",
                "parsed_case_plan",
                "disposition",
                "result_status",
                "result_reason_code",
            ),
            where="early gate receipt",
        )
        _validate_envelope(
            document,
            GateReceiptKind.PRE_EXECUTION_FAILURE,
            "early gate receipt",
        )
        try:
            raw_submission = ArtifactRef.from_document(document["raw_submission"])
        except ContractError as exc:
            raise ContractError(f"invalid raw_submission: {exc}") from exc
        from .case import CaseSubmissionKind

        raw_submission_kind = document["parsed_submission_kind"]
        return cls(
            validation_instance_id=document["validation_instance_id"],
            attempt_id=document["attempt_id"],
            role=_enum_value(GateRole, document["role"], "gate receipt role"),
            failure_stage=_enum_value(
                EarlyGateStage,
                document["failure_stage"],
                "early gate failure_stage",
            ),
            project_id=document["project_id"],
            case_id=document["case_id"],
            function_id=document["function_id"],
            snapshot_sha256=document["snapshot_sha256"],
            reasoning_sha256=document["reasoning_sha256"],
            profile_sha256=document["profile_sha256"],
            context_sha256=document["context_sha256"],
            raw_submission=raw_submission,
            parsed_submission_kind=(
                None
                if raw_submission_kind is None
                else _enum_value(
                    CaseSubmissionKind,
                    raw_submission_kind,
                    "parsed_submission_kind",
                )
            ),
            parsed_submission=_optional_ref_from_document(
                document["parsed_submission"],
                ContractRefKind.CASE_SUBMISSION,
                "parsed_submission",
            ),
            parsed_profile=_optional_ref_from_document(
                document["parsed_profile"],
                ContractRefKind.FROZEN_PROFILE,
                "parsed_profile",
            ),
            parsed_case_plan=_optional_ref_from_document(
                document["parsed_case_plan"],
                ContractRefKind.CASE_PLAN,
                "parsed_case_plan",
            ),
            disposition=_parse_optional_disposition(
                document["disposition"],
                "disposition",
            ),
            result_status=_enum_value(
                CaseStatus,
                document["result_status"],
                "result_status",
            ),
            result_reason_code=_enum_value(
                CaseReasonCode,
                document["result_reason_code"],
                "result_reason_code",
            ),
        )

    @classmethod
    def from_json(cls, payload: object) -> EarlyGateReceipt:
        receipt = gate_receipt_from_json(payload)
        if type(receipt) is not cls:
            raise ContractError("gate receipt is not a pre-execution failure receipt")
        return receipt

    @property
    def content_sha256(self) -> str:
        return canonical_sha256(self.to_document())

    @property
    def ref(self) -> ContractRef:
        return ContractRef(
            kind=ContractRefKind.GATE_RECEIPT,
            contract_id=self.content_sha256,
            contract_version=_CONTENT_REF_VERSION,
            content_sha256=self.content_sha256,
        )


@dataclass(frozen=True)
class FastPathGateReceipt:
    """A no-run identity/hash receipt for explicit ``not_confirmed``."""

    validation_instance_id: str
    attempt_id: str
    role: GateRole
    project_id: str
    case_id: str
    function_id: str
    snapshot_sha256: str
    submission: ContractRef
    reasoning_sha256: str
    context_sha256: str
    profile_sha256: str
    successful_checks: tuple[FastPathCheck, ...]
    disposition: GateAttemptDisposition | None

    def __post_init__(self) -> None:
        from .case import compute_validation_instance_id

        validate_sha256(self.validation_instance_id, "validation_instance_id")
        validate_identifier(self.attempt_id, "attempt_id")
        if type(self.role) is not GateRole:
            raise ContractError("role must be a GateRole")
        validate_identifier(self.project_id, "project_id")
        validate_identifier(self.case_id, "case_id")
        validate_identifier(self.function_id, "function_id")
        validate_sha256(self.snapshot_sha256, "snapshot_sha256")
        _require_ref(self.submission, ContractRefKind.CASE_SUBMISSION, "submission")
        validate_sha256(self.reasoning_sha256, "reasoning_sha256")
        validate_sha256(self.context_sha256, "context_sha256")
        validate_sha256(self.profile_sha256, "profile_sha256")
        expected_instance_id = compute_validation_instance_id(
            project_id=self.project_id,
            case_id=self.case_id,
            function_id=self.function_id,
            snapshot_sha256=self.snapshot_sha256,
            reasoning_sha256=self.reasoning_sha256,
            profile_sha256=self.profile_sha256,
        )
        if self.validation_instance_id != expected_instance_id:
            raise ContractError(
                "fast receipt validation instance does not match authority identity"
            )

        if type(self.successful_checks) not in (tuple, list):
            raise ContractError("successful_checks must be a collection")
        checks = tuple(self.successful_checks)
        if any(type(check) is not FastPathCheck for check in checks):
            raise ContractError("successful_checks must contain FastPathCheck values")
        if len(checks) != len(set(checks)):
            raise ContractError("successful_checks must not contain duplicates")
        if set(checks) != set(_REQUIRED_FAST_PATH_CHECKS):
            raise ContractError(
                "successful_checks must contain the complete fast-path check set"
            )
        object.__setattr__(self, "successful_checks", _REQUIRED_FAST_PATH_CHECKS)

        if self.role is GateRole.B1:
            if (
                self.disposition
                is not GateAttemptDisposition.ACCEPTED_EXPLICIT_NOT_CONFIRMED
            ):
                raise ContractError(
                    "a B1 fast-path receipt requires explicit-not-confirmed disposition"
                )
        elif self.disposition is not None:
            raise ContractError("a B2 fast-path receipt must not contain a disposition")

    @property
    def receipt_kind(self) -> GateReceiptKind:
        return GateReceiptKind.IDENTITY_HASH_FAST_PATH

    def to_document(self) -> dict[str, object]:
        return {
            "contract_kind": _GATE_RECEIPT_CONTRACT_KIND,
            "schema_version": _SCHEMA_VERSION,
            "receipt_kind": self.receipt_kind.value,
            "validation_instance_id": self.validation_instance_id,
            "attempt_id": self.attempt_id,
            "role": self.role.value,
            "project_id": self.project_id,
            "case_id": self.case_id,
            "function_id": self.function_id,
            "snapshot_sha256": self.snapshot_sha256,
            "submission": self.submission.to_document(),
            "reasoning_sha256": self.reasoning_sha256,
            "context_sha256": self.context_sha256,
            "profile_sha256": self.profile_sha256,
            "successful_checks": [check.value for check in self.successful_checks],
            "disposition": (
                None if self.disposition is None else self.disposition.value
            ),
        }

    @classmethod
    def from_document(cls, value: object) -> FastPathGateReceipt:
        document = require_exact_keys(
            value,
            required=(
                "contract_kind",
                "schema_version",
                "receipt_kind",
                "validation_instance_id",
                "attempt_id",
                "role",
                "project_id",
                "case_id",
                "function_id",
                "snapshot_sha256",
                "submission",
                "reasoning_sha256",
                "context_sha256",
                "profile_sha256",
                "successful_checks",
                "disposition",
            ),
            where="fast-path gate receipt",
        )
        _validate_envelope(
            document,
            GateReceiptKind.IDENTITY_HASH_FAST_PATH,
            "fast-path gate receipt",
        )
        checks = document["successful_checks"]
        if type(checks) is not list:
            raise ContractError("successful_checks must be a list")
        return cls(
            validation_instance_id=document["validation_instance_id"],
            attempt_id=document["attempt_id"],
            role=_enum_value(GateRole, document["role"], "gate receipt role"),
            project_id=document["project_id"],
            case_id=document["case_id"],
            function_id=document["function_id"],
            snapshot_sha256=document["snapshot_sha256"],
            submission=_ref_from_document(
                document["submission"],
                ContractRefKind.CASE_SUBMISSION,
                "submission",
            ),
            reasoning_sha256=document["reasoning_sha256"],
            context_sha256=document["context_sha256"],
            profile_sha256=document["profile_sha256"],
            successful_checks=tuple(
                _enum_value(FastPathCheck, check, "successful_checks")
                for check in checks
            ),
            disposition=_parse_optional_disposition(
                document["disposition"],
                "disposition",
            ),
        )

    @classmethod
    def from_json(cls, payload: object) -> FastPathGateReceipt:
        receipt = gate_receipt_from_json(payload)
        if type(receipt) is not cls:
            raise ContractError("gate receipt is not an identity/hash fast-path receipt")
        return receipt

    @property
    def content_sha256(self) -> str:
        return canonical_sha256(self.to_document())

    @property
    def ref(self) -> ContractRef:
        return ContractRef(
            kind=ContractRefKind.GATE_RECEIPT,
            contract_id=self.content_sha256,
            contract_version=_CONTENT_REF_VERSION,
            content_sha256=self.content_sha256,
        )


GateReceipt = CandidateGateReceipt | EarlyGateReceipt | FastPathGateReceipt


def _validate_envelope(
    document: dict[str, object],
    expected_kind: GateReceiptKind,
    where: str,
) -> None:
    if document["contract_kind"] != _GATE_RECEIPT_CONTRACT_KIND:
        raise ContractError(
            f"{where} contract_kind must be {_GATE_RECEIPT_CONTRACT_KIND!r}"
        )
    if (
        type(document["schema_version"]) is not int
        or document["schema_version"] != _SCHEMA_VERSION
    ):
        raise ContractError(f"{where} schema_version must be integer 1")
    raw_kind = document["receipt_kind"]
    if type(raw_kind) is not str or raw_kind != expected_kind.value:
        raise ContractError(
            f"{where} receipt_kind must be {expected_kind.value!r}"
        )


def gate_receipt_from_document(value: object) -> GateReceipt:
    if type(value) is not dict:
        raise ContractError("gate receipt must be an object")
    raw_kind = value.get("receipt_kind")
    if type(raw_kind) is not str:
        raise ContractError("gate receipt receipt_kind must be a string enum value")
    try:
        receipt_kind = GateReceiptKind(raw_kind)
    except ValueError as exc:
        raise ContractError(
            f"gate receipt receipt_kind has unsupported value {raw_kind!r}"
        ) from exc
    if receipt_kind is GateReceiptKind.FULL_CANDIDATE_GATE:
        return CandidateGateReceipt.from_document(value)
    if receipt_kind is GateReceiptKind.PRE_EXECUTION_FAILURE:
        return EarlyGateReceipt.from_document(value)
    return FastPathGateReceipt.from_document(value)


def gate_receipt_from_json(payload: object) -> GateReceipt:
    return gate_receipt_from_document(load_strict_json_object(payload))


def _aggregate_oracle_bundle_verdict(
    oracle_bundle: OracleBundle,
    verdict_by_spec: dict[ContractRef, OracleVerdict],
) -> OracleVerdict:
    """Aggregate already-derived atomic verdicts by one frozen bundle rule."""

    from .evidence import OracleVerdict
    from .oracle import OracleBundle, PrimaryCombination

    if type(oracle_bundle) is not OracleBundle:
        raise ContractError("oracle_bundle must be an OracleBundle")
    missing = set(oracle_bundle.oracle_spec_refs) - set(verdict_by_spec)
    if missing:
        raise ContractError("OracleBundle verdict aggregation is missing a member")
    if any(
        verdict_by_spec[reference] is not OracleVerdict.PASS
        for reference in oracle_bundle.required_guards
    ):
        return OracleVerdict.INCONCLUSIVE

    primaries = tuple(
        verdict_by_spec[reference] for reference in oracle_bundle.primary_oracles
    )
    if oracle_bundle.primary_combination is PrimaryCombination.ALL:
        if all(verdict is OracleVerdict.VIOLATION for verdict in primaries):
            return OracleVerdict.VIOLATION
        if any(verdict is OracleVerdict.PASS for verdict in primaries):
            return OracleVerdict.PASS
        return OracleVerdict.INCONCLUSIVE
    if oracle_bundle.primary_combination is PrimaryCombination.ANY:
        if any(verdict is OracleVerdict.VIOLATION for verdict in primaries):
            return OracleVerdict.VIOLATION
        if all(verdict is OracleVerdict.PASS for verdict in primaries):
            return OracleVerdict.PASS
        return OracleVerdict.INCONCLUSIVE

    violation_count = sum(
        verdict is OracleVerdict.VIOLATION for verdict in primaries
    )
    inconclusive_count = sum(
        verdict is OracleVerdict.INCONCLUSIVE for verdict in primaries
    )
    if oracle_bundle.k is None:  # defensive; OracleBundle rejects this state
        raise ContractError("k_of_n OracleBundle is missing k")
    if violation_count >= oracle_bundle.k:
        return OracleVerdict.VIOLATION
    if violation_count + inconclusive_count < oracle_bundle.k:
        return OracleVerdict.PASS
    return OracleVerdict.INCONCLUSIVE


def validate_candidate_gate_receipt_membership(
    receipt: CandidateGateReceipt,
    *,
    submission: CaseSubmission,
    profile: FrozenSystemProfile,
    case_plan: CasePlan,
    oracle_bundle: OracleBundle,
    template: ExperimentPlanTemplate,
    binding: ExecutionBinding,
    observations: Iterable[Observation],
    decisions: Iterable[OracleDecision],
) -> None:
    """Validate exact frozen inputs and role-local evidence for one receipt."""

    from .case import CasePlan, CaseSubmission, CaseSubmissionKind
    from .evidence import Observation, OracleDecision
    from .oracle import ControlEvidenceRole, OracleBundle
    from .profile import FrozenSystemProfile

    if type(receipt) is not CandidateGateReceipt:
        raise ContractError("receipt must be a CandidateGateReceipt")
    if type(submission) is not CaseSubmission:
        raise ContractError("submission must be a CaseSubmission")
    if submission.submission_kind is not CaseSubmissionKind.CANDIDATE:
        raise ContractError("a candidate receipt requires a candidate submission")
    if type(profile) is not FrozenSystemProfile:
        raise ContractError("profile must be a FrozenSystemProfile")
    if type(case_plan) is not CasePlan:
        raise ContractError("case_plan must be a CasePlan")
    if type(oracle_bundle) is not OracleBundle:
        raise ContractError("oracle_bundle must be an OracleBundle")
    if type(template) is not ExperimentPlanTemplate:
        raise ContractError("template must be an ExperimentPlanTemplate")
    if type(binding) is not ExecutionBinding:
        raise ContractError("binding must be an ExecutionBinding")

    if receipt.submission != submission.ref:
        raise ContractError("receipt submission mismatch")
    if receipt.profile != profile.ref:
        raise ContractError("receipt Profile mismatch")
    if receipt.case_plan != case_plan.ref:
        raise ContractError("receipt CasePlan mismatch")
    if receipt.template != template.ref:
        raise ContractError("receipt experiment template mismatch")
    if receipt.binding != binding.ref:
        raise ContractError("receipt execution binding mismatch")
    if submission.case_plan is None or submission.case_plan.ref != case_plan.ref:
        raise ContractError("submission does not bind the supplied CasePlan")
    expected_grade = (
        ValidationGrade.L1
        if case_plan.repair is not None
        else ValidationGrade.L0
    )
    if receipt.requested_grade is not expected_grade:
        raise ContractError("receipt requested grade does not match CasePlan repair")
    if case_plan.repair is not None:
        if receipt.original_l1_candidate_sha256 != submission.content_sha256:
            raise ContractError(
                "receipt original L1 candidate hash does not match submission"
            )
        if receipt.patch_sha256 != case_plan.repair.patch.content_sha256:
            raise ContractError("receipt patch hash does not match CasePlan repair")
    if any(
        instance_id != receipt.validation_instance_id
        for instance_id in (
            submission.validation_instance_id,
            case_plan.validation_instance_id,
            template.validation_instance_id,
        )
    ):
        raise ContractError("receipt validation instance mismatch")
    if case_plan.profile != receipt.profile:
        raise ContractError("CasePlan Profile mismatch")
    if (
        oracle_bundle.ref != case_plan.oracle_bundle
        or oracle_bundle.ref != template.oracle_bundle
        or oracle_bundle.ref not in profile.oracle_bundles
    ):
        raise ContractError(
            "receipt does not exactly bind the selected OracleBundle"
        )
    if template.profile != receipt.profile or template.case_plan != receipt.case_plan:
        raise ContractError("experiment template frozen input mismatch")
    if binding.validation_instance_id != receipt.validation_instance_id:
        raise ContractError("binding validation instance mismatch")
    if binding.template != receipt.template:
        raise ContractError("binding experiment template mismatch")
    if binding.attempt_id != receipt.attempt_id:
        raise ContractError("binding attempt mismatch")
    if binding.role is not receipt.role:
        raise ContractError("binding Gate role mismatch")

    observation_values = tuple(observations)
    if any(type(observation) is not Observation for observation in observation_values):
        raise ContractError("observations must contain Observation values")
    observation_refs = _normalize_refs(
        tuple(observation.ref for observation in observation_values),
        ContractRefKind.OBSERVATION,
        "observations",
    )
    if observation_refs != receipt.observations:
        raise ContractError("observations do not exactly match receipt membership")
    step_by_id = {step.step_id: step for step in template.steps}
    observation_by_ref: dict[ContractRef, Observation] = {}
    observed_step_ids: set[str] = set()
    for observation in observation_values:
        if (
            observation.validation_instance_id != receipt.validation_instance_id
            or observation.attempt_id != receipt.attempt_id
            or observation.role is not receipt.role
            or observation.template != receipt.template
            or observation.binding != receipt.binding
        ):
            raise ContractError("observation context does not match receipt")
        step = step_by_id.get(observation.step_id)
        if step is None:
            raise ContractError(
                "receipt observation references an unknown template step"
            )
        observation_by_ref[observation.ref] = observation
        observed_step_ids.add(observation.step_id)

    decision_values = tuple(decisions)
    if any(type(decision) is not OracleDecision for decision in decision_values):
        raise ContractError("decisions must contain OracleDecision values")
    decision_refs = _normalize_refs(
        tuple(decision.ref for decision in decision_values),
        ContractRefKind.ORACLE_DECISION,
        "decisions",
    )
    if decision_refs != receipt.decisions:
        raise ContractError("decisions do not exactly match receipt membership")
    from .evidence import OracleVerdict

    allowed_observations = set(receipt.observations)
    planned_oracle_specs = set(template.oracle_spec_refs)
    if planned_oracle_specs != set(oracle_bundle.oracle_spec_refs):
        raise ContractError(
            "experiment template OracleSpec membership must exactly match the "
            "selected OracleBundle"
        )
    original_decisions: list[OracleDecision] = []
    repair_decisions: list[OracleDecision] = []
    for decision in decision_values:
        if (
            decision.validation_instance_id != receipt.validation_instance_id
            or decision.attempt_id != receipt.attempt_id
            or decision.role is not receipt.role
            or decision.profile != receipt.profile
            or decision.case_plan != receipt.case_plan
            or decision.template != receipt.template
            or decision.binding != receipt.binding
        ):
            raise ContractError("OracleDecision context does not match receipt")
        if not set(decision.observations).issubset(allowed_observations):
            raise ContractError("OracleDecision uses an observation outside receipt")
        if decision.oracle_spec not in planned_oracle_specs:
            raise ContractError(
                "OracleDecision uses an OracleSpec outside the experiment template"
            )
        decision_phases = {
            step_by_id[observation_by_ref[reference].step_id].phase
            for reference in decision.observations
        }
        if any(
            step_by_id[observation_by_ref[reference].step_id].oracle_spec
            != decision.oracle_spec
            for reference in decision.observations
        ):
            raise ContractError(
                "OracleDecision observation does not belong to its OracleSpec"
            )
        original_family = frozenset(
            (ExperimentPhase.ORACLE_EXPERIMENT, ExperimentPhase.CAUSAL_CONTROL)
        )
        if decision_phases.issubset(original_family) and (
            ExperimentPhase.ORACLE_EXPERIMENT in decision_phases
        ):
            original_decisions.append(decision)
        elif decision_phases == {ExperimentPhase.REPAIR_ORACLE_EXPERIMENT}:
            repair_decisions.append(decision)
        else:
            raise ContractError(
                "OracleDecision observations must belong to one original or repair "
                "phase family"
            )

    confirmed = receipt.result_status in (
        CaseStatus.CONFIRMED_L0,
        CaseStatus.CONFIRMED_L1,
    )
    if confirmed:
        if (
            oracle_bundle.control_evidence_role
            is ControlEvidenceRole.ORACLE_ONLY
            or case_plan.causal_control_id is None
        ):
            raise ContractError(
                "a generic confirmed receipt requires an approved causal control"
            )
        original_spec_values = tuple(
            decision.oracle_spec for decision in original_decisions
        )
        original_specs = set(original_spec_values)
        if len(original_spec_values) != len(original_specs):
            raise ContractError(
                "a confirmed receipt requires one original decision per OracleSpec"
            )
        if original_specs != planned_oracle_specs:
            raise ContractError(
                "a confirmed receipt requires original decisions for every planned "
                "OracleSpec"
            )
        original_by_spec = {
            decision.oracle_spec: decision for decision in original_decisions
        }
        original_verdict = _aggregate_oracle_bundle_verdict(
            oracle_bundle,
            {
                reference: decision.verdict
                for reference, decision in original_by_spec.items()
            },
        )
        if original_verdict is not OracleVerdict.VIOLATION:
            raise ContractError(
                "a confirmed receipt requires required guards to PASS and the "
                "original OracleBundle primary combination to be VIOLATION"
            )

        original_evidence = tuple(
            reference
            for decision in original_decisions
            for reference in decision.observations
        )
        expected_original_evidence = {
            observation.ref
            for observation in observation_values
            if step_by_id[observation.step_id].phase
            in (ExperimentPhase.ORACLE_EXPERIMENT, ExperimentPhase.CAUSAL_CONTROL)
        }
        if (
            len(original_evidence) != len(set(original_evidence))
            or set(original_evidence) != expected_original_evidence
        ):
            raise ContractError(
                "original Oracle decisions must exactly cover role-local Oracle "
                "observations without reuse"
            )
        if receipt.result_status is CaseStatus.CONFIRMED_L1:
            planned_repair_specs = {
                step.oracle_spec
                for step in template.steps
                if step.phase is ExperimentPhase.REPAIR_ORACLE_EXPERIMENT
                and step.oracle_spec is not None
            }
            repair_spec_values = tuple(
                decision.oracle_spec for decision in repair_decisions
            )
            repair_specs = set(repair_spec_values)
            if len(repair_spec_values) != len(repair_specs):
                raise ContractError(
                    "confirmed L1 requires one repair decision per OracleSpec"
                )
            if repair_specs != planned_repair_specs:
                raise ContractError(
                    "confirmed L1 requires repair decisions for every planned "
                    "repair OracleSpec"
                )
            if planned_repair_specs != set(oracle_bundle.oracle_spec_refs):
                raise ContractError(
                    "confirmed L1 requires repair steps for every OracleBundle member"
                )
            repair_by_spec = {
                decision.oracle_spec: decision for decision in repair_decisions
            }
            repair_verdict = _aggregate_oracle_bundle_verdict(
                oracle_bundle,
                {
                    reference: decision.verdict
                    for reference, decision in repair_by_spec.items()
                },
            )
            if repair_verdict is not OracleVerdict.PASS:
                raise ContractError(
                    "confirmed L1 requires repair guards to PASS and the repair "
                    "OracleBundle primary combination to be PASS"
                )
            repair_evidence = tuple(
                reference
                for decision in repair_decisions
                for reference in decision.observations
            )
            expected_repair_evidence = {
                observation.ref
                for observation in observation_values
                if step_by_id[observation.step_id].phase
                is ExperimentPhase.REPAIR_ORACLE_EXPERIMENT
            }
            if (
                len(repair_evidence) != len(set(repair_evidence))
                or set(repair_evidence) != expected_repair_evidence
            ):
                raise ContractError(
                    "repair Oracle decisions must exactly cover role-local repair "
                    "observations without reuse"
                )

        required_steps = {
            step.step_id
            for step in template.steps
            if not (
                receipt.requested_grade is ValidationGrade.L1
                and receipt.final_grade is ValidationGrade.L0
                and step.phase in _REPAIR_PHASES
            )
        }
        missing_steps = required_steps - observed_step_ids
        if missing_steps:
            raise ContractError(
                "confirmed receipt lacks observations for template steps: "
                f"{sorted(missing_steps)!r}"
            )

    validate_candidate_gate_receipt_phases(receipt, template)


def validate_candidate_gate_receipt_phases(
    receipt: CandidateGateReceipt,
    template: ExperimentPlanTemplate,
) -> None:
    """Check phase completeness and L1 downgrade evidence against a Template."""

    if type(receipt) is not CandidateGateReceipt:
        raise ContractError("receipt must be a CandidateGateReceipt")
    if type(template) is not ExperimentPlanTemplate:
        raise ContractError("template must be an ExperimentPlanTemplate")
    if receipt.template != template.ref:
        raise ContractError("receipt experiment template mismatch")
    template_phases = {step.phase for step in template.steps}
    receipt_phases = {result.phase for result in receipt.phase_results}
    if not receipt_phases.issubset(template_phases):
        raise ContractError("receipt phase_results contain a phase outside template")
    if receipt.result_status in (
        CaseStatus.CONFIRMED_L0,
        CaseStatus.CONFIRMED_L1,
    ) and receipt_phases != template_phases:
        raise ContractError(
            "a confirmed receipt must report every distinct template phase"
        )
    phase_statuses = {
        result.phase: result.status for result in receipt.phase_results
    }
    if receipt.result_status is CaseStatus.CONFIRMED_L1:
        if any(
            phase_statuses[phase] is not GatePhaseStatus.SATISFIED
            for phase in template_phases
        ):
            raise ContractError("confirmed L1 requires every template phase satisfied")
    elif receipt.result_status is CaseStatus.CONFIRMED_L0:
        if receipt.requested_grade is ValidationGrade.L0:
            if any(
                phase_statuses[phase] is not GatePhaseStatus.SATISFIED
                for phase in template_phases
            ):
                raise ContractError(
                    "requested L0 confirmed L0 requires every template phase satisfied"
                )
        else:
            non_repair_phases = template_phases - _REPAIR_PHASES
            if any(
                phase_statuses[phase] is not GatePhaseStatus.SATISFIED
                for phase in non_repair_phases
            ):
                raise ContractError(
                    "an L1-to-L0 downgrade requires all non-repair phases satisfied"
                )
            attempted_repair_phases = template_phases.intersection(_REPAIR_PHASES)
            if not attempted_repair_phases or all(
                phase_statuses[phase] is GatePhaseStatus.SATISFIED
                for phase in attempted_repair_phases
            ):
                raise ContractError(
                    "an L1-to-L0 downgrade requires a non-satisfied repair phase"
                )


def validate_early_gate_receipt_identity(
    receipt: EarlyGateReceipt,
    *,
    identity: ValidationInstanceIdentity,
    context_sha256: str,
    raw_submission: ArtifactRef,
    submission: CaseSubmission | None = None,
    profile: FrozenSystemProfile | None = None,
    case_plan: CasePlan | None = None,
) -> None:
    """Bind an early failure to authority context and the parsed objects seen.

    Parsed references prove content identity only.  They do not imply that the
    stage named by ``failure_stage`` succeeded; the receipt exists precisely
    because that stage failed.
    """

    from .case import (
        CasePlan,
        CaseSubmission,
        CaseSubmissionKind,
        ValidationInstanceIdentity,
    )
    from .profile import FrozenSystemProfile

    if type(receipt) is not EarlyGateReceipt:
        raise ContractError("receipt must be an EarlyGateReceipt")
    if type(identity) is not ValidationInstanceIdentity:
        raise ContractError("identity must be a ValidationInstanceIdentity")
    if type(raw_submission) is not ArtifactRef:
        raise ContractError("raw_submission must be an ArtifactRef")
    expected_context_sha256 = validate_sha256(context_sha256, "context_sha256")
    if receipt.validation_instance_id != identity.validation_instance_id:
        raise ContractError("early receipt validation instance mismatch")
    if (
        receipt.project_id != identity.project_id
        or receipt.case_id != identity.case_id
        or receipt.function_id != identity.function_id
        or receipt.snapshot_sha256 != identity.snapshot_sha256
        or receipt.reasoning_sha256 != identity.reasoning_sha256
        or receipt.profile_sha256 != identity.profile_sha256
    ):
        raise ContractError("early receipt authority identity mismatch")
    if receipt.context_sha256 != expected_context_sha256:
        raise ContractError("early receipt context hash mismatch")
    if receipt.raw_submission != raw_submission:
        raise ContractError("early receipt raw submission mismatch")

    supplied_parsed_values = (submission, profile, case_plan)
    if receipt.failure_stage is EarlyGateStage.INTAKE:
        if any(value is not None for value in supplied_parsed_values):
            raise ContractError(
                "an intake failure must not be validated with parsed objects"
            )
        return

    if type(submission) is not CaseSubmission:
        raise ContractError("post-intake failure requires a CaseSubmission")
    if type(profile) is not FrozenSystemProfile:
        raise ContractError("post-intake failure requires a FrozenSystemProfile")
    if receipt.parsed_submission_kind is not submission.submission_kind:
        raise ContractError("early receipt parsed submission kind mismatch")
    if receipt.parsed_submission != submission.ref:
        raise ContractError("early receipt parsed submission mismatch")
    if receipt.parsed_profile != profile.ref:
        raise ContractError("early receipt parsed Profile mismatch")
    if (
        submission.validation_instance_id != identity.validation_instance_id
        or submission.case_id != identity.case_id
        or submission.function_id != identity.function_id
        or submission.reasoning_sha256 != identity.reasoning_sha256
    ):
        raise ContractError("parsed submission authority identity mismatch")

    if submission.submission_kind is CaseSubmissionKind.NOT_CONFIRMED:
        if case_plan is not None or receipt.parsed_case_plan is not None:
            raise ContractError(
                "not_confirmed early receipt must not bind a CasePlan"
            )
        if receipt.failure_stage is EarlyGateStage.MATERIALIZE:
            raise ContractError("not_confirmed submission cannot reach materialize")
        return

    if type(case_plan) is not CasePlan:
        raise ContractError("candidate post-intake failure requires a CasePlan")
    if receipt.parsed_case_plan != case_plan.ref:
        raise ContractError("early receipt parsed CasePlan mismatch")
    if submission.case_plan is None or submission.case_plan.ref != case_plan.ref:
        raise ContractError("parsed submission does not bind the supplied CasePlan")
    if receipt.failure_stage in (
        EarlyGateStage.CONTEXT_INTEGRITY,
        EarlyGateStage.MATERIALIZE,
    ) and case_plan.profile != profile.ref:
        raise ContractError(
            "a post-membership failure must retain one parsed Profile graph"
        )
    if receipt.failure_stage is EarlyGateStage.MATERIALIZE and (
        profile.content_sha256 != identity.profile_sha256
        or profile.project.system_id != identity.project_id
        or profile.project.source_snapshot_sha256 != identity.snapshot_sha256
    ):
        raise ContractError(
            "a materialize failure requires the authority Profile context"
        )


def validate_fast_path_gate_receipt_identity(
    receipt: FastPathGateReceipt,
    *,
    identity: ValidationInstanceIdentity,
    submission: CaseSubmission,
    context_sha256: str,
) -> None:
    """Validate a fast receipt against authority-owned frozen identity."""

    from .case import CaseSubmission, CaseSubmissionKind, ValidationInstanceIdentity

    if type(receipt) is not FastPathGateReceipt:
        raise ContractError("receipt must be a FastPathGateReceipt")
    if type(identity) is not ValidationInstanceIdentity:
        raise ContractError("identity must be a ValidationInstanceIdentity")
    if type(submission) is not CaseSubmission:
        raise ContractError("submission must be a CaseSubmission")
    if submission.submission_kind is not CaseSubmissionKind.NOT_CONFIRMED:
        raise ContractError("fast path requires a not_confirmed submission")
    expected_context_sha256 = validate_sha256(context_sha256, "context_sha256")
    if receipt.validation_instance_id != identity.validation_instance_id:
        raise ContractError("fast receipt validation instance mismatch")
    if (
        receipt.project_id != identity.project_id
        or receipt.case_id != identity.case_id
        or receipt.function_id != identity.function_id
        or receipt.snapshot_sha256 != identity.snapshot_sha256
        or receipt.reasoning_sha256 != identity.reasoning_sha256
        or receipt.profile_sha256 != identity.profile_sha256
    ):
        raise ContractError("fast receipt authority identity mismatch")
    if receipt.context_sha256 != expected_context_sha256:
        raise ContractError("fast receipt context hash mismatch")
    if receipt.submission != submission.ref:
        raise ContractError("fast receipt submission mismatch")
    if (
        submission.validation_instance_id != identity.validation_instance_id
        or submission.case_id != identity.case_id
        or submission.function_id != identity.function_id
        or submission.reasoning_sha256 != identity.reasoning_sha256
    ):
        raise ContractError("not_confirmed submission identity mismatch")


def validate_b1_b2_gate_receipts(
    b1: GateReceipt,
    b2: GateReceipt,
) -> None:
    """Validate the legal ordered B1/B2 receipt pair topologies."""

    receipt_types = (CandidateGateReceipt, EarlyGateReceipt, FastPathGateReceipt)
    if type(b1) not in receipt_types:
        raise ContractError("b1 must be a GateReceipt")
    if type(b2) not in receipt_types:
        raise ContractError("b2 must be a GateReceipt")
    if b1.role is not GateRole.B1 or b2.role is not GateRole.B2:
        raise ContractError("receipt pair requires ordered B1 and B2 roles")
    if b1.validation_instance_id != b2.validation_instance_id:
        raise ContractError("B1 and B2 validation instances differ")
    if b1.attempt_id != b2.attempt_id:
        raise ContractError("B1 and B2 must belong to the same logical attempt")

    if type(b1) is FastPathGateReceipt and type(b2) is FastPathGateReceipt:
        if b1.submission != b2.submission:
            raise ContractError("B1 and B2 submission hashes differ")
        frozen_fields = (
            "project_id",
            "case_id",
            "function_id",
            "snapshot_sha256",
            "reasoning_sha256",
            "context_sha256",
            "profile_sha256",
            "successful_checks",
        )
        if any(getattr(b1, field) != getattr(b2, field) for field in frozen_fields):
            raise ContractError("B1 and B2 fast-path identity/hash inputs differ")
        return

    if type(b1) is CandidateGateReceipt and type(b2) is EarlyGateReceipt:
        from .case import CaseSubmissionKind

        if (
            b1.disposition
            is not GateAttemptDisposition.ACCEPTED_CONFIRMED_CANDIDATE
        ):
            raise ContractError(
                "an early B2 failure requires a confirmed-candidate B1 receipt"
            )
        if b2.profile_sha256 != b1.profile.content_sha256:
            raise ContractError("B1 and early B2 authority Profile hashes differ")
        if (
            b2.failure_stage is not EarlyGateStage.INTAKE
            and b2.parsed_submission_kind is not CaseSubmissionKind.CANDIDATE
        ):
            raise ContractError(
                "an early B2 recheck must retain the candidate submission branch"
            )
        comparable_refs = (
            (b2.parsed_submission, b1.submission, "submission"),
            (b2.parsed_profile, b1.profile, "Profile"),
            (b2.parsed_case_plan, b1.case_plan, "CasePlan"),
        )
        for early_ref, b1_ref, field in comparable_refs:
            if early_ref is not None and early_ref != b1_ref:
                raise ContractError(
                    f"B1 and early B2 parsed {field} inputs differ"
                )
        return

    if not (
        type(b1) is CandidateGateReceipt and type(b2) is CandidateGateReceipt
    ):
        raise ContractError("unsupported Gate receipt pair")
    if b1.submission != b2.submission:
        raise ContractError("B1 and B2 submission hashes differ")
    if (
        b1.disposition
        is not GateAttemptDisposition.ACCEPTED_CONFIRMED_CANDIDATE
    ):
        raise ContractError("full B2 requires a B1 confirmed-candidate receipt")
    frozen_fields = (
        "profile",
        "case_plan",
        "template",
        "requested_grade",
        "original_l1_candidate_sha256",
        "patch_sha256",
    )
    if any(getattr(b1, field) != getattr(b2, field) for field in frozen_fields):
        raise ContractError("B1 and B2 frozen candidate inputs differ")
    if _ref_identity(b1.binding) == _ref_identity(b2.binding):
        raise ContractError("B1 and B2 must use independent execution bindings")
    if {_ref_identity(value) for value in b1.observations}.intersection(
        _ref_identity(value) for value in b2.observations
    ):
        raise ContractError("B1 observations cannot impersonate B2 observations")
    if {_ref_identity(value) for value in b1.decisions}.intersection(
        _ref_identity(value) for value in b2.decisions
    ):
        raise ContractError("B1 decisions cannot impersonate B2 decisions")


__all__ = [
    "CandidateGateReceipt",
    "EarlyGateReceipt",
    "EarlyGateStage",
    "FastPathCheck",
    "FastPathGateReceipt",
    "GatePhaseResult",
    "GateReceipt",
    "GateReceiptKind",
    "gate_receipt_from_document",
    "gate_receipt_from_json",
    "validate_b1_b2_gate_receipts",
    "validate_candidate_gate_receipt_membership",
    "validate_candidate_gate_receipt_phases",
    "validate_early_gate_receipt_identity",
    "validate_fast_path_gate_receipt_identity",
]

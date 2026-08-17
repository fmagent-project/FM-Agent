"""Governed Project Profile Setup orchestration and Profile Gate.

This module orders qualification, result-blind review, semantic admission, and
profile publication.  Providers receive narrow, policy-bound request objects;
they never receive a current Case, current observations, or B1/B2 state.  The
Profile Gate is the sole code in this module allowed to update a mutable
profile ref.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Callable, Protocol

from ..contracts.base import (
    ContractError,
    canonical_json_bytes,
    canonical_sha256,
    load_strict_json_object,
    require_exact_keys,
    validate_identifier,
    validate_positive_int,
    validate_sha256,
)
from ..contracts.execution import ExecutionRecipe
from ..contracts.evidence import OracleVerdict
from ..contracts.oracle import OracleBundle, OracleSpec
from ..contracts.preset import RegistrationTrustTier
from ..contracts.profile import (
    FrozenSystemProfile,
    validate_frozen_profile_contracts,
)
from ..contracts.references import ArtifactRef
from ..contracts.setup import (
    ApprovalAuthorityKind,
    ApprovalDecision,
    CalibrationReport,
    DependencyInvalidationManifest,
    DependencyKind,
    ProfileAdmissionRecord,
    ProfileSetupCandidate,
    QualificationPlan,
    QualificationPolicy,
    QualificationReport,
    QualificationTrial,
    QualificationVerdict,
    RevocationEntry,
    RevocationLedger,
    RevocationTargetKind,
    ResultBlindReviewBundle,
    ReviewRecord,
    ReviewVerdict,
    SemanticApprovalRecord,
    SetupActorRole,
    SetupLifecycleRecord,
    SetupState,
    SetupStateTransition,
    make_review_subject,
    freeze_profile,
    validate_approval_graph,
    validate_approval_basis,
    validate_frozen_profile_graph,
    validate_qualification_graph,
    validate_profile_admission_graph,
    validate_invalidation_manifest_graph,
    validate_review_graph,
)
from ..storage.profile import (
    ProfileStore,
    ProfileStoreError,
    ProfileStoreErrorCode,
)
from .policy import SetupRole, SetupRolePolicy, build_setup_role_policy
from .qualification import verify_qualification_report
from .review import (
    build_result_blind_review_bundle,
    validate_result_blind_review_record,
)


_UTC_FORMAT = "%Y-%m-%dT%H:%M:%SZ"
_MAX_PROFILE_TTL_SECONDS = 31_536_000


class ProfileSetupFailureCode(str, Enum):
    """Harness failures, distinct from governed reject/revise decisions."""

    INVALID_INPUT = "INVALID_INPUT"
    INVALID_STATE_TRANSITION = "INVALID_STATE_TRANSITION"
    QUALIFICATION_PROVIDER_FAILED = "QUALIFICATION_PROVIDER_FAILED"
    QUALIFICATION_RESULT_INVALID = "QUALIFICATION_RESULT_INVALID"
    REVIEW_PROVIDER_FAILED = "REVIEW_PROVIDER_FAILED"
    REVIEW_RESULT_INVALID = "REVIEW_RESULT_INVALID"
    APPROVAL_PROVIDER_FAILED = "APPROVAL_PROVIDER_FAILED"
    APPROVAL_RESULT_INVALID = "APPROVAL_RESULT_INVALID"
    PROFILE_GATE_REJECTED = "PROFILE_GATE_REJECTED"
    PROFILE_GATE_AUTHORITY_FAILED = "PROFILE_GATE_AUTHORITY_FAILED"
    STORAGE_FAILURE = "STORAGE_FAILURE"


class ProfileSetupError(RuntimeError):
    """Typed fail-closed error outside the Setup decision vocabulary."""

    def __init__(self, code: ProfileSetupFailureCode, message: str) -> None:
        if type(code) is not ProfileSetupFailureCode:
            raise TypeError("code must be a ProfileSetupFailureCode")
        self.code = code
        super().__init__(message)


def _raise(
    code: ProfileSetupFailureCode,
    message: str,
    cause: Exception | None = None,
) -> None:
    error = ProfileSetupError(code, message)
    if cause is None:
        raise error
    raise error from cause


class _AuthorityServiceError(RuntimeError):
    """A trusted clock/verifier was unavailable, distinct from a bad proof."""


def _artifact(value: object, role: str, field: str) -> ArtifactRef:
    if type(value) is not ArtifactRef or value.role != role:
        raise ContractError(f"{field} must be the {role!r} ArtifactRef")
    return value


def _proof_document(
    value: object,
    *,
    proof_kind: str,
    fields: tuple[str, ...],
    where: str,
) -> dict[str, object]:
    document = require_exact_keys(
        value,
        required=("proof_kind", "schema_version", *fields),
        where=where,
    )
    if document["proof_kind"] != proof_kind:
        raise ContractError(f"{where} has the wrong proof_kind")
    if (
        type(document["schema_version"]) is not int
        or document["schema_version"] != 1
    ):
        raise ContractError(f"{where} schema_version must be integer 1")
    return document


@dataclass(frozen=True)
class QualificationProviderRequest:
    """Only the frozen qualification graph and worker authorization."""

    setup_session_id: str
    candidate: ProfileSetupCandidate
    policy: QualificationPolicy
    plan: QualificationPlan
    prequalification_authorization_sha256: str
    role_policy: SetupRolePolicy

    def __post_init__(self) -> None:
        validate_identifier(self.setup_session_id, "setup_session_id")
        if type(self.candidate) is not ProfileSetupCandidate:
            raise ContractError("candidate must be a ProfileSetupCandidate")
        if type(self.policy) is not QualificationPolicy:
            raise ContractError("policy must be a QualificationPolicy")
        if type(self.plan) is not QualificationPlan:
            raise ContractError("plan must be a QualificationPlan")
        if type(self.role_policy) is not SetupRolePolicy:
            raise ContractError("role_policy must be a SetupRolePolicy")
        validate_sha256(
            self.prequalification_authorization_sha256,
            "prequalification_authorization_sha256",
        )
        if (
            self.role_policy.role is not SetupRole.QUALIFICATION_WORKER
            or self.role_policy.setup_session_id != self.setup_session_id
            or self.role_policy.subject_sha256
            != self.prequalification_authorization_sha256
        ):
            raise ContractError(
                "qualification request is not bound to its worker/session/subject"
            )
        if self.candidate.qualification_policy != self.policy.ref:
            raise ContractError("candidate does not bind the qualification policy")
        if (
            self.plan.setup_subject_sha256 != self.candidate.content_sha256
            or self.plan.qualification_policy != self.policy.ref
        ):
            raise ContractError("qualification plan does not bind candidate/policy")


@dataclass(frozen=True)
class QualificationProviderResult:
    calibration: CalibrationReport
    report: QualificationReport

    def __post_init__(self) -> None:
        if type(self.calibration) is not CalibrationReport:
            raise ContractError("calibration must be a CalibrationReport")
        if type(self.report) is not QualificationReport:
            raise ContractError("report must be a QualificationReport")


@dataclass(frozen=True)
class ReviewMaterial:
    """Governance-only inputs used to build the Reviewer's sole bundle."""

    bundle_id: str
    adapter_diff: ArtifactRef
    static_scan: ArtifactRef
    healthy_relation: ArtifactRef
    qualification_design_sha256: str
    invalidation_manifest_sha256: str
    known_limitations: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        validate_identifier(self.bundle_id, "bundle_id")
        _artifact(self.adapter_diff, "adapter_diff", "adapter_diff")
        _artifact(self.static_scan, "static_scan", "static_scan")
        _artifact(self.healthy_relation, "healthy_relation", "healthy_relation")
        validate_sha256(
            self.qualification_design_sha256,
            "qualification_design_sha256",
        )
        validate_sha256(
            self.invalidation_manifest_sha256,
            "invalidation_manifest_sha256",
        )
        if type(self.known_limitations) not in (tuple, list):
            raise ContractError("known_limitations must be an ordered collection")
        limitations = tuple(self.known_limitations)
        for item in limitations:
            validate_identifier(item, "known_limitations")
        if len(limitations) != len(set(limitations)):
            raise ContractError("known_limitations must not contain duplicates")
        object.__setattr__(self, "known_limitations", tuple(sorted(limitations)))


@dataclass(frozen=True)
class ReviewProviderRequest:
    """The exact result-blind bundle and Reviewer authorization, nothing else."""

    setup_session_id: str
    bundle: ResultBlindReviewBundle
    qualification_authorization_sha256: str
    role_policy: SetupRolePolicy

    def __post_init__(self) -> None:
        validate_identifier(self.setup_session_id, "setup_session_id")
        if type(self.bundle) is not ResultBlindReviewBundle:
            raise ContractError("bundle must be a ResultBlindReviewBundle")
        if type(self.role_policy) is not SetupRolePolicy:
            raise ContractError("role_policy must be a SetupRolePolicy")
        validate_sha256(
            self.qualification_authorization_sha256,
            "qualification_authorization_sha256",
        )
        if (
            self.role_policy.role is not SetupRole.REVIEWER
            or self.role_policy.setup_session_id != self.setup_session_id
            or self.role_policy.subject_sha256
            != self.qualification_authorization_sha256
        ):
            raise ContractError(
                "review request is not bound to its reviewer/session/bundle"
            )


@dataclass(frozen=True)
class ApprovalProviderRequest:
    """External authority request without project workspace or Case material."""

    setup_session_id: str
    trust_tier: RegistrationTrustTier
    semantic_subject_sha256: str
    qualification_report_sha256: str
    review_sha256: str
    qualification_proof_sha256: tuple[str, ...]
    review_proof_sha256: str
    review_authorization_sha256: str

    def __post_init__(self) -> None:
        validate_identifier(self.setup_session_id, "setup_session_id")
        if type(self.trust_tier) is not RegistrationTrustTier:
            raise ContractError("trust_tier must be a RegistrationTrustTier")
        validate_sha256(self.semantic_subject_sha256, "semantic_subject_sha256")
        validate_sha256(
            self.qualification_report_sha256,
            "qualification_report_sha256",
        )
        validate_sha256(self.review_sha256, "review_sha256")
        proofs = _digest_collection(
            self.qualification_proof_sha256,
            "qualification_proof_sha256",
        )
        if not proofs:
            raise ContractError("qualification_proof_sha256 must not be empty")
        object.__setattr__(self, "qualification_proof_sha256", proofs)
        validate_sha256(self.review_proof_sha256, "review_proof_sha256")
        validate_sha256(
            self.review_authorization_sha256,
            "review_authorization_sha256",
        )


class QualificationProvider(Protocol):
    def __call__(
        self,
        request: QualificationProviderRequest,
    ) -> QualificationProviderResult: ...


class ReviewProvider(Protocol):
    def __call__(self, request: ReviewProviderRequest) -> ReviewRecord: ...


class ApprovalProvider(Protocol):
    def __call__(
        self,
        request: ApprovalProviderRequest,
    ) -> SemanticApprovalRecord: ...


@dataclass(frozen=True)
class ProfileSetupProviders:
    qualification: QualificationProvider
    review: ReviewProvider
    approval: ApprovalProvider

    def __post_init__(self) -> None:
        for field in ("qualification", "review", "approval"):
            if not callable(getattr(self, field)):
                raise ContractError(f"{field} provider must be callable")


ReviewBundleBuilder = Callable[
    [ProfileSetupCandidate, QualificationReport, ReviewMaterial],
    ResultBlindReviewBundle,
]


def _timestamp(value: object, field: str) -> datetime:
    if type(value) is not str:
        raise ContractError(f"{field} must be a canonical UTC timestamp")
    try:
        parsed = datetime.strptime(value, _UTC_FORMAT).replace(tzinfo=timezone.utc)
    except ValueError as exc:
        raise ContractError(f"{field} must be a canonical UTC timestamp") from exc
    if parsed.strftime(_UTC_FORMAT) != value:
        raise ContractError(f"{field} must be a canonical UTC timestamp")
    return parsed


def _identifier_collection(value: object, field: str) -> tuple[str, ...]:
    if type(value) not in (tuple, list, set, frozenset):
        raise ContractError(f"{field} must be a collection")
    result = tuple(sorted(value))
    for item in result:
        validate_identifier(item, field)
    if len(result) != len(set(result)):
        raise ContractError(f"{field} must not contain duplicates")
    return result


def _digest_collection(value: object, field: str) -> tuple[str, ...]:
    if type(value) not in (tuple, list, set, frozenset):
        raise ContractError(f"{field} must be a collection")
    result = tuple(sorted(validate_sha256(item, field) for item in value))
    if len(result) != len(set(result)):
        raise ContractError(f"{field} must not contain duplicates")
    return result


@dataclass(frozen=True)
class RevocationVerificationRequest:
    entry: RevocationEntry
    authority_policy_sha256: str

    def __post_init__(self) -> None:
        if type(self.entry) is not RevocationEntry:
            raise ContractError("entry must be a RevocationEntry")
        validate_sha256(self.authority_policy_sha256, "authority_policy_sha256")


@dataclass(frozen=True)
class RevocationVerificationProof:
    entry_sha256: str
    authority_policy_sha256: str
    verifier_id: str
    verification_receipt: ArtifactRef
    signature_valid: bool

    def __post_init__(self) -> None:
        validate_sha256(self.entry_sha256, "entry_sha256")
        validate_sha256(self.authority_policy_sha256, "authority_policy_sha256")
        validate_identifier(self.verifier_id, "verifier_id")
        _artifact(
            self.verification_receipt,
            "verification_receipt",
            "verification_receipt",
        )
        if type(self.signature_valid) is not bool:
            raise ContractError("signature_valid must be a boolean")

    def validate_request(self, request: RevocationVerificationRequest) -> None:
        if type(request) is not RevocationVerificationRequest:
            raise ContractError("revocation proof requires its exact request")
        if (
            self.entry_sha256 != request.entry.content_sha256
            or self.authority_policy_sha256 != request.authority_policy_sha256
            or not self.signature_valid
        ):
            raise ContractError("revocation signature proof is invalid or misbound")

    def to_document(self) -> dict[str, object]:
        return {
            "proof_kind": "revocation_verification_proof",
            "schema_version": 1,
            "entry_sha256": self.entry_sha256,
            "authority_policy_sha256": self.authority_policy_sha256,
            "verifier_id": self.verifier_id,
            "verification_receipt": self.verification_receipt.to_document(),
            "signature_valid": self.signature_valid,
        }

    @classmethod
    def from_document(cls, value: object) -> "RevocationVerificationProof":
        document = _proof_document(
            value,
            proof_kind="revocation_verification_proof",
            fields=(
                "entry_sha256",
                "authority_policy_sha256",
                "verifier_id",
                "verification_receipt",
                "signature_valid",
            ),
            where="revocation verification proof",
        )
        return cls(
            entry_sha256=document["entry_sha256"],
            authority_policy_sha256=document["authority_policy_sha256"],
            verifier_id=document["verifier_id"],
            verification_receipt=ArtifactRef.from_document(
                document["verification_receipt"]
            ),
            signature_valid=document["signature_valid"],
        )

    @classmethod
    def from_json(cls, payload: object) -> "RevocationVerificationProof":
        return cls.from_document(load_strict_json_object(payload))

    @property
    def content_sha256(self) -> str:
        return canonical_sha256(self.to_document())


class RevocationSignatureVerifier(Protocol):
    def __call__(
        self,
        request: RevocationVerificationRequest,
    ) -> RevocationVerificationProof: ...


@dataclass(frozen=True)
class SemanticApprovalVerificationRequest:
    approval: SemanticApprovalRecord
    semantic_subject_sha256: str
    qualification_proof_sha256: tuple[str, ...]
    review_proof_sha256: str
    review_authorization_sha256: str
    authority_policy_sha256: str

    def __post_init__(self) -> None:
        if type(self.approval) is not SemanticApprovalRecord:
            raise ContractError("approval must be a SemanticApprovalRecord")
        validate_sha256(self.semantic_subject_sha256, "semantic_subject_sha256")
        proofs = _digest_collection(
            self.qualification_proof_sha256,
            "qualification_proof_sha256",
        )
        if not proofs:
            raise ContractError("qualification_proof_sha256 must not be empty")
        object.__setattr__(self, "qualification_proof_sha256", proofs)
        validate_sha256(self.review_proof_sha256, "review_proof_sha256")
        validate_sha256(
            self.review_authorization_sha256,
            "review_authorization_sha256",
        )
        validate_sha256(self.authority_policy_sha256, "authority_policy_sha256")
        if self.approval.subject_sha256 != self.semantic_subject_sha256:
            raise ContractError("approval verifier request subject mismatch")


@dataclass(frozen=True)
class SemanticApprovalVerificationProof:
    approval_sha256: str
    semantic_subject_sha256: str
    qualification_proof_sha256: tuple[str, ...]
    review_proof_sha256: str
    review_authorization_sha256: str
    authority_policy_sha256: str
    verifier_id: str
    verification_receipt: ArtifactRef
    authority_verified: bool

    def __post_init__(self) -> None:
        for field in (
            "approval_sha256",
            "semantic_subject_sha256",
            "review_proof_sha256",
            "review_authorization_sha256",
            "authority_policy_sha256",
        ):
            validate_sha256(getattr(self, field), field)
        proofs = _digest_collection(
            self.qualification_proof_sha256,
            "qualification_proof_sha256",
        )
        if not proofs:
            raise ContractError("qualification_proof_sha256 must not be empty")
        object.__setattr__(self, "qualification_proof_sha256", proofs)
        _artifact(
            self.verification_receipt,
            "verification_receipt",
            "verification_receipt",
        )
        validate_identifier(self.verifier_id, "verifier_id")
        if type(self.authority_verified) is not bool:
            raise ContractError("authority_verified must be a boolean")

    def validate_request(self, request: SemanticApprovalVerificationRequest) -> None:
        if type(request) is not SemanticApprovalVerificationRequest:
            raise ContractError("approval proof requires its exact request")
        if (
            self.approval_sha256 != request.approval.content_sha256
            or self.semantic_subject_sha256 != request.semantic_subject_sha256
            or self.qualification_proof_sha256
            != request.qualification_proof_sha256
            or self.review_proof_sha256 != request.review_proof_sha256
            or self.review_authorization_sha256
            != request.review_authorization_sha256
            or self.authority_policy_sha256 != request.authority_policy_sha256
            or not self.authority_verified
        ):
            raise ContractError("approval authority proof is invalid or misbound")

    def to_document(self) -> dict[str, object]:
        return {
            "proof_kind": "semantic_approval_verification_proof",
            "schema_version": 1,
            "approval_sha256": self.approval_sha256,
            "semantic_subject_sha256": self.semantic_subject_sha256,
            "qualification_proof_sha256": list(
                self.qualification_proof_sha256
            ),
            "review_proof_sha256": self.review_proof_sha256,
            "review_authorization_sha256": self.review_authorization_sha256,
            "authority_policy_sha256": self.authority_policy_sha256,
            "verifier_id": self.verifier_id,
            "verification_receipt": self.verification_receipt.to_document(),
            "authority_verified": self.authority_verified,
        }

    @classmethod
    def from_document(
        cls,
        value: object,
    ) -> "SemanticApprovalVerificationProof":
        document = _proof_document(
            value,
            proof_kind="semantic_approval_verification_proof",
            fields=(
                "approval_sha256",
                "semantic_subject_sha256",
                "qualification_proof_sha256",
                "review_proof_sha256",
                "review_authorization_sha256",
                "authority_policy_sha256",
                "verifier_id",
                "verification_receipt",
                "authority_verified",
            ),
            where="semantic approval verification proof",
        )
        if type(document["qualification_proof_sha256"]) is not list:
            raise ContractError("qualification_proof_sha256 must be a list")
        return cls(
            approval_sha256=document["approval_sha256"],
            semantic_subject_sha256=document["semantic_subject_sha256"],
            qualification_proof_sha256=tuple(
                document["qualification_proof_sha256"]
            ),
            review_proof_sha256=document["review_proof_sha256"],
            review_authorization_sha256=document[
                "review_authorization_sha256"
            ],
            authority_policy_sha256=document["authority_policy_sha256"],
            verifier_id=document["verifier_id"],
            verification_receipt=ArtifactRef.from_document(
                document["verification_receipt"]
            ),
            authority_verified=document["authority_verified"],
        )

    @classmethod
    def from_json(
        cls,
        payload: object,
    ) -> "SemanticApprovalVerificationProof":
        return cls.from_document(load_strict_json_object(payload))

    @property
    def content_sha256(self) -> str:
        return canonical_sha256(self.to_document())


class SemanticApprovalVerifier(Protocol):
    def __call__(
        self,
        request: SemanticApprovalVerificationRequest,
    ) -> SemanticApprovalVerificationProof: ...


@dataclass(frozen=True)
class QualificationEvidenceVerificationRequest:
    candidate_sha256: str
    profile_environment_sha256: str
    qualification_policy_sha256: str
    qualification_plan_sha256: str
    calibration_report_sha256: str
    qualification_report_sha256: str
    broker_attestation_sha256: str
    trial: QualificationTrial
    previous_trial_sha256: str | None
    qualification_role_policy_sha256: str
    prequalification_authorization_sha256: str
    authority_policy_sha256: str

    def __post_init__(self) -> None:
        validate_sha256(self.candidate_sha256, "candidate_sha256")
        for field in (
            "qualification_policy_sha256",
            "profile_environment_sha256",
            "qualification_plan_sha256",
            "calibration_report_sha256",
            "qualification_report_sha256",
            "broker_attestation_sha256",
            "qualification_role_policy_sha256",
            "prequalification_authorization_sha256",
        ):
            validate_sha256(getattr(self, field), field)
        if type(self.trial) is not QualificationTrial:
            raise ContractError("trial must be a QualificationTrial")
        if self.previous_trial_sha256 is not None:
            validate_sha256(
                self.previous_trial_sha256,
                "previous_trial_sha256",
            )
        if (self.trial.attempt_index == 1) != (
            self.previous_trial_sha256 is None
        ):
            raise ContractError(
                "qualification retry request has a misbound predecessor"
            )
        validate_sha256(self.authority_policy_sha256, "authority_policy_sha256")


@dataclass(frozen=True)
class QualificationEvidenceVerificationProof:
    candidate_sha256: str
    profile_environment_sha256: str
    qualification_policy_sha256: str
    qualification_plan_sha256: str
    calibration_report_sha256: str
    qualification_report_sha256: str
    broker_attestation_sha256: str
    trial_id: str
    trial_sha256: str
    oracle_decision_sha256: str
    observed_verdict: OracleVerdict
    stable: bool
    previous_trial_sha256: str | None
    retry_authorization_receipt: ArtifactRef | None
    qualification_role_policy_sha256: str
    prequalification_authorization_sha256: str
    authority_policy_sha256: str
    verifier_id: str
    verification_receipt: ArtifactRef
    evidence_verified: bool

    def __post_init__(self) -> None:
        for field in (
            "candidate_sha256",
            "profile_environment_sha256",
            "qualification_policy_sha256",
            "qualification_plan_sha256",
            "calibration_report_sha256",
            "qualification_report_sha256",
            "broker_attestation_sha256",
            "trial_sha256",
            "oracle_decision_sha256",
            "qualification_role_policy_sha256",
            "prequalification_authorization_sha256",
            "authority_policy_sha256",
        ):
            validate_sha256(getattr(self, field), field)
        _artifact(
            self.verification_receipt,
            "verification_receipt",
            "verification_receipt",
        )
        validate_identifier(self.trial_id, "trial_id")
        if type(self.observed_verdict) is not OracleVerdict:
            raise ContractError("observed_verdict must be an OracleVerdict")
        if type(self.stable) is not bool:
            raise ContractError("stable must be a boolean")
        if self.previous_trial_sha256 is not None:
            validate_sha256(
                self.previous_trial_sha256,
                "previous_trial_sha256",
            )
        if self.retry_authorization_receipt is not None:
            _artifact(
                self.retry_authorization_receipt,
                "retry_authorization",
                "retry_authorization_receipt",
            )
        if (self.previous_trial_sha256 is None) != (
            self.retry_authorization_receipt is None
        ):
            raise ContractError(
                "retry proof predecessor and authorization must appear together"
            )
        validate_identifier(self.verifier_id, "verifier_id")
        if type(self.evidence_verified) is not bool:
            raise ContractError("evidence_verified must be a boolean")

    def validate_request(
        self,
        request: QualificationEvidenceVerificationRequest,
    ) -> None:
        if type(request) is not QualificationEvidenceVerificationRequest:
            raise ContractError("qualification proof requires its exact request")
        expected = (
            request.candidate_sha256,
            request.profile_environment_sha256,
            request.qualification_policy_sha256,
            request.qualification_plan_sha256,
            request.calibration_report_sha256,
            request.qualification_report_sha256,
            request.broker_attestation_sha256,
            request.trial.trial_id,
            canonical_sha256(request.trial.to_document()),
            request.trial.oracle_decision.content_sha256,
            request.trial.observed_verdict,
            request.trial.stable,
            request.previous_trial_sha256,
            request.qualification_role_policy_sha256,
            request.prequalification_authorization_sha256,
            request.authority_policy_sha256,
        )
        actual = (
            self.candidate_sha256,
            self.profile_environment_sha256,
            self.qualification_policy_sha256,
            self.qualification_plan_sha256,
            self.calibration_report_sha256,
            self.qualification_report_sha256,
            self.broker_attestation_sha256,
            self.trial_id,
            self.trial_sha256,
            self.oracle_decision_sha256,
            self.observed_verdict,
            self.stable,
            self.previous_trial_sha256,
            self.qualification_role_policy_sha256,
            self.prequalification_authorization_sha256,
            self.authority_policy_sha256,
        )
        retry_authorized = (
            request.trial.attempt_index == 1
            or self.retry_authorization_receipt is not None
        )
        if actual != expected or not self.evidence_verified or not retry_authorized:
            raise ContractError(
                "qualification evidence proof is invalid or misbound"
            )

    def to_document(self) -> dict[str, object]:
        return {
            "proof_kind": "qualification_evidence_verification_proof",
            "schema_version": 1,
            "candidate_sha256": self.candidate_sha256,
            "profile_environment_sha256": self.profile_environment_sha256,
            "qualification_policy_sha256": self.qualification_policy_sha256,
            "qualification_plan_sha256": self.qualification_plan_sha256,
            "calibration_report_sha256": self.calibration_report_sha256,
            "qualification_report_sha256": self.qualification_report_sha256,
            "broker_attestation_sha256": self.broker_attestation_sha256,
            "trial_id": self.trial_id,
            "trial_sha256": self.trial_sha256,
            "oracle_decision_sha256": self.oracle_decision_sha256,
            "observed_verdict": self.observed_verdict.value,
            "stable": self.stable,
            "previous_trial_sha256": self.previous_trial_sha256,
            "retry_authorization_receipt": (
                None
                if self.retry_authorization_receipt is None
                else self.retry_authorization_receipt.to_document()
            ),
            "qualification_role_policy_sha256": (
                self.qualification_role_policy_sha256
            ),
            "prequalification_authorization_sha256": (
                self.prequalification_authorization_sha256
            ),
            "authority_policy_sha256": self.authority_policy_sha256,
            "verifier_id": self.verifier_id,
            "verification_receipt": self.verification_receipt.to_document(),
            "evidence_verified": self.evidence_verified,
        }

    @classmethod
    def from_document(
        cls,
        value: object,
    ) -> "QualificationEvidenceVerificationProof":
        document = _proof_document(
            value,
            proof_kind="qualification_evidence_verification_proof",
            fields=(
                "candidate_sha256",
                "profile_environment_sha256",
                "qualification_policy_sha256",
                "qualification_plan_sha256",
                "calibration_report_sha256",
                "qualification_report_sha256",
                "broker_attestation_sha256",
                "trial_id",
                "trial_sha256",
                "oracle_decision_sha256",
                "observed_verdict",
                "stable",
                "previous_trial_sha256",
                "retry_authorization_receipt",
                "qualification_role_policy_sha256",
                "prequalification_authorization_sha256",
                "authority_policy_sha256",
                "verifier_id",
                "verification_receipt",
                "evidence_verified",
            ),
            where="qualification evidence verification proof",
        )
        try:
            observed_verdict = OracleVerdict(document["observed_verdict"])
        except (TypeError, ValueError) as exc:
            raise ContractError("invalid observed_verdict") from exc
        retry = document["retry_authorization_receipt"]
        return cls(
            candidate_sha256=document["candidate_sha256"],
            profile_environment_sha256=document[
                "profile_environment_sha256"
            ],
            qualification_policy_sha256=document[
                "qualification_policy_sha256"
            ],
            qualification_plan_sha256=document["qualification_plan_sha256"],
            calibration_report_sha256=document["calibration_report_sha256"],
            qualification_report_sha256=document[
                "qualification_report_sha256"
            ],
            broker_attestation_sha256=document[
                "broker_attestation_sha256"
            ],
            trial_id=document["trial_id"],
            trial_sha256=document["trial_sha256"],
            oracle_decision_sha256=document["oracle_decision_sha256"],
            observed_verdict=observed_verdict,
            stable=document["stable"],
            previous_trial_sha256=document["previous_trial_sha256"],
            retry_authorization_receipt=(
                None if retry is None else ArtifactRef.from_document(retry)
            ),
            qualification_role_policy_sha256=document[
                "qualification_role_policy_sha256"
            ],
            prequalification_authorization_sha256=document[
                "prequalification_authorization_sha256"
            ],
            authority_policy_sha256=document["authority_policy_sha256"],
            verifier_id=document["verifier_id"],
            verification_receipt=ArtifactRef.from_document(
                document["verification_receipt"]
            ),
            evidence_verified=document["evidence_verified"],
        )

    @classmethod
    def from_json(
        cls,
        payload: object,
    ) -> "QualificationEvidenceVerificationProof":
        return cls.from_document(load_strict_json_object(payload))

    @property
    def content_sha256(self) -> str:
        return canonical_sha256(self.to_document())


class QualificationEvidenceVerifier(Protocol):
    def __call__(
        self,
        request: QualificationEvidenceVerificationRequest,
    ) -> QualificationEvidenceVerificationProof: ...


@dataclass(frozen=True)
class ReviewVerificationRequest:
    review_bundle_sha256: str
    review_sha256: str
    reviewer_authority: str
    reviewer_session_id: str
    model_id: str
    prompt_sha256: str
    reviewer_role_policy_sha256: str
    excluded_setup_session_id: str
    qualification_authorization_sha256: str
    authority_policy_sha256: str

    def __post_init__(self) -> None:
        for field in (
            "review_bundle_sha256",
            "review_sha256",
            "prompt_sha256",
            "reviewer_role_policy_sha256",
            "qualification_authorization_sha256",
            "authority_policy_sha256",
        ):
            validate_sha256(getattr(self, field), field)
        for field in (
            "reviewer_authority",
            "reviewer_session_id",
            "model_id",
            "excluded_setup_session_id",
        ):
            validate_identifier(getattr(self, field), field)
        if self.reviewer_session_id == self.excluded_setup_session_id:
            raise ContractError("reviewer session is not independent from Setup")


@dataclass(frozen=True)
class ReviewVerificationProof:
    review_bundle_sha256: str
    review_sha256: str
    reviewer_authority: str
    reviewer_session_id: str
    model_id: str
    prompt_sha256: str
    reviewer_role_policy_sha256: str
    excluded_setup_session_id: str
    qualification_authorization_sha256: str
    authority_policy_sha256: str
    verifier_id: str
    isolation_attestation: ArtifactRef
    verification_receipt: ArtifactRef
    authority_verified: bool

    def __post_init__(self) -> None:
        for field in (
            "review_bundle_sha256",
            "review_sha256",
            "prompt_sha256",
            "reviewer_role_policy_sha256",
            "qualification_authorization_sha256",
            "authority_policy_sha256",
        ):
            validate_sha256(getattr(self, field), field)
        _artifact(
            self.isolation_attestation,
            "review_isolation_attestation",
            "isolation_attestation",
        )
        _artifact(
            self.verification_receipt,
            "verification_receipt",
            "verification_receipt",
        )
        for field in (
            "reviewer_authority",
            "reviewer_session_id",
            "model_id",
            "excluded_setup_session_id",
            "verifier_id",
        ):
            validate_identifier(getattr(self, field), field)
        if type(self.authority_verified) is not bool:
            raise ContractError("authority_verified must be a boolean")

    def validate_request(self, request: ReviewVerificationRequest) -> None:
        expected = (
            request.review_bundle_sha256,
            request.review_sha256,
            request.reviewer_authority,
            request.reviewer_session_id,
            request.model_id,
            request.prompt_sha256,
            request.reviewer_role_policy_sha256,
            request.excluded_setup_session_id,
            request.qualification_authorization_sha256,
            request.authority_policy_sha256,
        )
        actual = (
            self.review_bundle_sha256,
            self.review_sha256,
            self.reviewer_authority,
            self.reviewer_session_id,
            self.model_id,
            self.prompt_sha256,
            self.reviewer_role_policy_sha256,
            self.excluded_setup_session_id,
            self.qualification_authorization_sha256,
            self.authority_policy_sha256,
        )
        if type(request) is not ReviewVerificationRequest or actual != expected:
            raise ContractError("review authority proof is misbound")
        if not self.authority_verified:
            raise ContractError("review authority proof is not verified")

    def to_document(self) -> dict[str, object]:
        return {
            "proof_kind": "review_verification_proof",
            "schema_version": 1,
            "review_bundle_sha256": self.review_bundle_sha256,
            "review_sha256": self.review_sha256,
            "reviewer_authority": self.reviewer_authority,
            "reviewer_session_id": self.reviewer_session_id,
            "model_id": self.model_id,
            "prompt_sha256": self.prompt_sha256,
            "reviewer_role_policy_sha256": self.reviewer_role_policy_sha256,
            "excluded_setup_session_id": self.excluded_setup_session_id,
            "qualification_authorization_sha256": (
                self.qualification_authorization_sha256
            ),
            "authority_policy_sha256": self.authority_policy_sha256,
            "verifier_id": self.verifier_id,
            "isolation_attestation": self.isolation_attestation.to_document(),
            "verification_receipt": self.verification_receipt.to_document(),
            "authority_verified": self.authority_verified,
        }

    @classmethod
    def from_document(cls, value: object) -> "ReviewVerificationProof":
        document = _proof_document(
            value,
            proof_kind="review_verification_proof",
            fields=(
                "review_bundle_sha256",
                "review_sha256",
                "reviewer_authority",
                "reviewer_session_id",
                "model_id",
                "prompt_sha256",
                "reviewer_role_policy_sha256",
                "excluded_setup_session_id",
                "qualification_authorization_sha256",
                "authority_policy_sha256",
                "verifier_id",
                "isolation_attestation",
                "verification_receipt",
                "authority_verified",
            ),
            where="review verification proof",
        )
        return cls(
            review_bundle_sha256=document["review_bundle_sha256"],
            review_sha256=document["review_sha256"],
            reviewer_authority=document["reviewer_authority"],
            reviewer_session_id=document["reviewer_session_id"],
            model_id=document["model_id"],
            prompt_sha256=document["prompt_sha256"],
            reviewer_role_policy_sha256=document[
                "reviewer_role_policy_sha256"
            ],
            excluded_setup_session_id=document[
                "excluded_setup_session_id"
            ],
            qualification_authorization_sha256=document[
                "qualification_authorization_sha256"
            ],
            authority_policy_sha256=document["authority_policy_sha256"],
            verifier_id=document["verifier_id"],
            isolation_attestation=ArtifactRef.from_document(
                document["isolation_attestation"]
            ),
            verification_receipt=ArtifactRef.from_document(
                document["verification_receipt"]
            ),
            authority_verified=document["authority_verified"],
        )

    @classmethod
    def from_json(cls, payload: object) -> "ReviewVerificationProof":
        return cls.from_document(load_strict_json_object(payload))

    @property
    def content_sha256(self) -> str:
        return canonical_sha256(self.to_document())


class ReviewVerifier(Protocol):
    def __call__(
        self,
        request: ReviewVerificationRequest,
    ) -> ReviewVerificationProof: ...


@dataclass(frozen=True)
class StaticProfileVerificationRequest:
    candidate_sha256: str
    profile_graph_sha256: str
    entrypoint_sha256: tuple[str, ...]
    workload_schema_sha256: tuple[str, ...]
    adapter_sha256: tuple[str, ...]
    instrumentation_sha256: tuple[str, ...]
    permission_manifest_sha256: str
    sbom_sha256: str
    static_scan_sha256: str
    authority_policy_sha256: str

    def __post_init__(self) -> None:
        for field in (
            "candidate_sha256",
            "profile_graph_sha256",
            "permission_manifest_sha256",
            "sbom_sha256",
            "static_scan_sha256",
            "authority_policy_sha256",
        ):
            validate_sha256(getattr(self, field), field)
        for field in (
            "entrypoint_sha256",
            "workload_schema_sha256",
            "adapter_sha256",
            "instrumentation_sha256",
        ):
            object.__setattr__(
                self,
                field,
                _digest_collection(getattr(self, field), field),
            )


@dataclass(frozen=True)
class StaticProfileVerificationProof:
    request_sha256: str
    authority_policy_sha256: str
    verifier_id: str
    verification_receipt: ArtifactRef
    profile_verified: bool

    def __post_init__(self) -> None:
        for field in (
            "request_sha256",
            "authority_policy_sha256",
        ):
            validate_sha256(getattr(self, field), field)
        _artifact(
            self.verification_receipt,
            "verification_receipt",
            "verification_receipt",
        )
        validate_identifier(self.verifier_id, "verifier_id")
        if type(self.profile_verified) is not bool:
            raise ContractError("profile_verified must be a boolean")

    def validate_request(self, request: StaticProfileVerificationRequest) -> None:
        if type(request) is not StaticProfileVerificationRequest:
            raise ContractError("static profile proof requires its exact request")
        expected = canonical_sha256(request.__dict__)
        if (
            self.request_sha256 != expected
            or self.authority_policy_sha256 != request.authority_policy_sha256
            or not self.profile_verified
        ):
            raise ContractError("static profile proof is invalid or misbound")

    def to_document(self) -> dict[str, object]:
        return {
            "proof_kind": "static_profile_verification_proof",
            "schema_version": 1,
            "request_sha256": self.request_sha256,
            "authority_policy_sha256": self.authority_policy_sha256,
            "verifier_id": self.verifier_id,
            "verification_receipt": self.verification_receipt.to_document(),
            "profile_verified": self.profile_verified,
        }

    @classmethod
    def from_document(
        cls,
        value: object,
    ) -> "StaticProfileVerificationProof":
        document = _proof_document(
            value,
            proof_kind="static_profile_verification_proof",
            fields=(
                "request_sha256",
                "authority_policy_sha256",
                "verifier_id",
                "verification_receipt",
                "profile_verified",
            ),
            where="static profile verification proof",
        )
        return cls(
            request_sha256=document["request_sha256"],
            authority_policy_sha256=document["authority_policy_sha256"],
            verifier_id=document["verifier_id"],
            verification_receipt=ArtifactRef.from_document(
                document["verification_receipt"]
            ),
            profile_verified=document["profile_verified"],
        )

    @classmethod
    def from_json(
        cls,
        payload: object,
    ) -> "StaticProfileVerificationProof":
        return cls.from_document(load_strict_json_object(payload))

    @property
    def content_sha256(self) -> str:
        return canonical_sha256(self.to_document())


class StaticProfileVerifier(Protocol):
    def __call__(
        self,
        request: StaticProfileVerificationRequest,
    ) -> StaticProfileVerificationProof: ...


@dataclass(frozen=True)
class AuthorityReceiptValidationRequest:
    proof_kind: str
    authority_policy_sha256: str
    signed_claims_sha256: str
    verification_receipt: ArtifactRef

    def __post_init__(self) -> None:
        validate_identifier(self.proof_kind, "proof_kind")
        validate_sha256(self.authority_policy_sha256, "authority_policy_sha256")
        validate_sha256(self.signed_claims_sha256, "signed_claims_sha256")
        _artifact(
            self.verification_receipt,
            "verification_receipt",
            "verification_receipt",
        )


class AuthorityReceiptValidator(Protocol):
    """Local, no-network verifier for an authority-owned receipt artifact."""

    def __call__(
        self,
        request: AuthorityReceiptValidationRequest,
        receipt_payload: bytes,
    ) -> bool: ...


def _validate_authority_receipt(
    *,
    store: ProfileStore,
    proof: object,
    validator: AuthorityReceiptValidator,
) -> None:
    document = proof.to_document()
    proof_kind = document.get("proof_kind")
    authority_policy_sha256 = document.get("authority_policy_sha256")
    receipt_document = document.pop("verification_receipt", None)
    if type(proof_kind) is not str:
        raise ContractError("authority proof has no proof_kind")
    validate_sha256(authority_policy_sha256, "authority_policy_sha256")
    receipt = ArtifactRef.from_document(receipt_document)
    _artifact(receipt, "verification_receipt", "verification_receipt")
    payload = store.get_object(
        receipt.content_sha256,
        expected_size_bytes=receipt.size_bytes,
    )
    request = AuthorityReceiptValidationRequest(
        proof_kind=proof_kind,
        authority_policy_sha256=authority_policy_sha256,
        signed_claims_sha256=canonical_sha256(document),
        verification_receipt=receipt,
    )
    try:
        valid = validator(request, payload)
    except Exception as exc:
        raise _AuthorityServiceError(
            f"{proof_kind} receipt validator failed"
        ) from exc
    if type(valid) is not bool or not valid:
        raise ContractError(f"{proof_kind} authority receipt is invalid")
    _verify_all_references(store, (proof.to_document(),))


@dataclass(frozen=True)
class ProfileGatePolicy:
    governance_policy_sha256: str
    admission_authority_kind: ApprovalAuthorityKind
    admission_authority_id: str
    allowed_permissions: tuple[str, ...]
    supported_adapter_versions: tuple[str, ...]
    max_profile_ttl_seconds: int
    revocation_authority_policy_sha256: str
    approval_authority_policy_sha256: str
    qualification_evidence_authority_policy_sha256: str
    review_authority_policy_sha256: str
    static_profile_authority_policy_sha256: str
    allowed_reviewer_authorities: tuple[str, ...]
    allowed_reviewer_models: tuple[str, ...]
    trusted_preset_subject_sha256: tuple[str, ...] = ()
    allow_profile_custom: bool = True

    def __post_init__(self) -> None:
        validate_sha256(
            self.governance_policy_sha256,
            "governance_policy_sha256",
        )
        if (
            type(self.admission_authority_kind) is not ApprovalAuthorityKind
            or self.admission_authority_kind
            not in (ApprovalAuthorityKind.HARNESS, ApprovalAuthorityKind.MAINTAINER)
        ):
            raise ContractError(
                "Profile Gate admission authority must be harness or maintainer"
            )
        validate_identifier(self.admission_authority_id, "admission_authority_id")
        object.__setattr__(
            self,
            "allowed_permissions",
            _identifier_collection(self.allowed_permissions, "allowed_permissions"),
        )
        object.__setattr__(
            self,
            "supported_adapter_versions",
            _identifier_collection(
                self.supported_adapter_versions,
                "supported_adapter_versions",
            ),
        )
        if not self.supported_adapter_versions:
            raise ContractError("supported_adapter_versions must not be empty")
        validate_positive_int(
            self.max_profile_ttl_seconds,
            "max_profile_ttl_seconds",
            maximum=_MAX_PROFILE_TTL_SECONDS,
        )
        validate_sha256(
            self.revocation_authority_policy_sha256,
            "revocation_authority_policy_sha256",
        )
        validate_sha256(
            self.approval_authority_policy_sha256,
            "approval_authority_policy_sha256",
        )
        validate_sha256(
            self.qualification_evidence_authority_policy_sha256,
            "qualification_evidence_authority_policy_sha256",
        )
        validate_sha256(
            self.review_authority_policy_sha256,
            "review_authority_policy_sha256",
        )
        validate_sha256(
            self.static_profile_authority_policy_sha256,
            "static_profile_authority_policy_sha256",
        )
        for field in (
            "allowed_reviewer_authorities",
            "allowed_reviewer_models",
        ):
            normalized = _identifier_collection(getattr(self, field), field)
            if not normalized:
                raise ContractError(f"{field} must not be empty")
            object.__setattr__(self, field, normalized)
        object.__setattr__(
            self,
            "trusted_preset_subject_sha256",
            _digest_collection(
                self.trusted_preset_subject_sha256,
                "trusted_preset_subject_sha256",
            ),
        )
        if type(self.allow_profile_custom) is not bool:
            raise ContractError("allow_profile_custom must be a boolean")

    def to_document(self) -> dict[str, object]:
        return {
            "contract_kind": "profile_gate_policy",
            "schema_version": 1,
            "governance_policy_sha256": self.governance_policy_sha256,
            "admission_authority_kind": self.admission_authority_kind.value,
            "admission_authority_id": self.admission_authority_id,
            "allowed_permissions": list(self.allowed_permissions),
            "supported_adapter_versions": list(
                self.supported_adapter_versions
            ),
            "max_profile_ttl_seconds": self.max_profile_ttl_seconds,
            "revocation_authority_policy_sha256": (
                self.revocation_authority_policy_sha256
            ),
            "approval_authority_policy_sha256": (
                self.approval_authority_policy_sha256
            ),
            "qualification_evidence_authority_policy_sha256": (
                self.qualification_evidence_authority_policy_sha256
            ),
            "review_authority_policy_sha256": (
                self.review_authority_policy_sha256
            ),
            "static_profile_authority_policy_sha256": (
                self.static_profile_authority_policy_sha256
            ),
            "allowed_reviewer_authorities": list(
                self.allowed_reviewer_authorities
            ),
            "allowed_reviewer_models": list(self.allowed_reviewer_models),
            "trusted_preset_subject_sha256": list(
                self.trusted_preset_subject_sha256
            ),
            "allow_profile_custom": self.allow_profile_custom,
        }

    @classmethod
    def from_document(cls, value: object) -> "ProfileGatePolicy":
        fields = (
            "contract_kind",
            "schema_version",
            "governance_policy_sha256",
            "admission_authority_kind",
            "admission_authority_id",
            "allowed_permissions",
            "supported_adapter_versions",
            "max_profile_ttl_seconds",
            "revocation_authority_policy_sha256",
            "approval_authority_policy_sha256",
            "qualification_evidence_authority_policy_sha256",
            "review_authority_policy_sha256",
            "static_profile_authority_policy_sha256",
            "allowed_reviewer_authorities",
            "allowed_reviewer_models",
            "trusted_preset_subject_sha256",
            "allow_profile_custom",
        )
        document = require_exact_keys(
            value,
            required=fields,
            where="profile gate policy",
        )
        if document["contract_kind"] != "profile_gate_policy":
            raise ContractError("profile gate policy has the wrong contract_kind")
        if (
            type(document["schema_version"]) is not int
            or document["schema_version"] != 1
        ):
            raise ContractError("profile gate policy schema_version must be integer 1")
        try:
            authority_kind = ApprovalAuthorityKind(
                document["admission_authority_kind"]
            )
        except (TypeError, ValueError) as exc:
            raise ContractError("invalid admission_authority_kind") from exc
        for field in (
            "allowed_permissions",
            "supported_adapter_versions",
            "allowed_reviewer_authorities",
            "allowed_reviewer_models",
            "trusted_preset_subject_sha256",
        ):
            if type(document[field]) is not list:
                raise ContractError(f"{field} must be a list")
        return cls(
            governance_policy_sha256=document["governance_policy_sha256"],
            admission_authority_kind=authority_kind,
            admission_authority_id=document["admission_authority_id"],
            allowed_permissions=tuple(document["allowed_permissions"]),
            supported_adapter_versions=tuple(
                document["supported_adapter_versions"]
            ),
            max_profile_ttl_seconds=document["max_profile_ttl_seconds"],
            revocation_authority_policy_sha256=document[
                "revocation_authority_policy_sha256"
            ],
            approval_authority_policy_sha256=document[
                "approval_authority_policy_sha256"
            ],
            qualification_evidence_authority_policy_sha256=document[
                "qualification_evidence_authority_policy_sha256"
            ],
            review_authority_policy_sha256=document[
                "review_authority_policy_sha256"
            ],
            static_profile_authority_policy_sha256=document[
                "static_profile_authority_policy_sha256"
            ],
            allowed_reviewer_authorities=tuple(
                document["allowed_reviewer_authorities"]
            ),
            allowed_reviewer_models=tuple(
                document["allowed_reviewer_models"]
            ),
            trusted_preset_subject_sha256=tuple(
                document["trusted_preset_subject_sha256"]
            ),
            allow_profile_custom=document["allow_profile_custom"],
        )

    @classmethod
    def from_json(cls, payload: object) -> "ProfileGatePolicy":
        return cls.from_document(load_strict_json_object(payload))

    @property
    def content_sha256(self) -> str:
        return canonical_sha256(self.to_document())


@dataclass(frozen=True)
class StagedProfileGateGraph:
    """CAS addresses consumed and reparsed by the Profile Gate."""

    candidate_sha256: str
    qualification_policy_sha256: str
    qualification_plan_sha256: str
    calibration_report_sha256: str
    qualification_report_sha256: str
    review_bundle_sha256: str
    review_sha256: str
    approval_sha256: str
    invalidation_manifest_sha256: str
    lifecycle_sha256: str
    revocation_ledger_sha256: str
    revocation_storage_head_sha256: str | None
    qualification_role_policy_sha256: str
    review_role_policy_sha256: str
    prequalification_authorization_sha256: str
    qualification_authorization_sha256: str
    review_authorization_sha256: str
    basis_qualification_authorization_sha256: str
    basis_review_authorization_sha256: str
    current_qualification_proof_sha256: tuple[str, ...]
    basis_qualification_proof_sha256: tuple[str, ...]
    current_review_proof_sha256: str
    basis_review_proof_sha256: str
    approval_proof_sha256: str
    revocation_proof_sha256: tuple[str, ...]
    static_profile_proof_sha256: str

    def __post_init__(self) -> None:
        for field in (
            "candidate_sha256",
            "qualification_policy_sha256",
            "qualification_plan_sha256",
            "calibration_report_sha256",
            "qualification_report_sha256",
            "review_bundle_sha256",
            "review_sha256",
            "approval_sha256",
            "invalidation_manifest_sha256",
            "lifecycle_sha256",
            "revocation_ledger_sha256",
            "qualification_role_policy_sha256",
            "review_role_policy_sha256",
            "prequalification_authorization_sha256",
            "qualification_authorization_sha256",
            "review_authorization_sha256",
            "basis_qualification_authorization_sha256",
            "basis_review_authorization_sha256",
            "current_review_proof_sha256",
            "basis_review_proof_sha256",
            "approval_proof_sha256",
            "static_profile_proof_sha256",
        ):
            validate_sha256(getattr(self, field), field)
        if self.revocation_storage_head_sha256 is not None:
            validate_sha256(
                self.revocation_storage_head_sha256,
                "revocation_storage_head_sha256",
            )
        for field, allow_empty in (
            ("current_qualification_proof_sha256", False),
            ("basis_qualification_proof_sha256", False),
            ("revocation_proof_sha256", True),
        ):
            values = _digest_collection(getattr(self, field), field)
            if not allow_empty and not values:
                raise ContractError(f"{field} must not be empty")
            object.__setattr__(self, field, values)

    def to_document(self) -> dict[str, object]:
        return {
            "contract_kind": "staged_profile_gate_graph",
            "schema_version": 1,
            "candidate_sha256": self.candidate_sha256,
            "qualification_policy_sha256": self.qualification_policy_sha256,
            "qualification_plan_sha256": self.qualification_plan_sha256,
            "calibration_report_sha256": self.calibration_report_sha256,
            "qualification_report_sha256": self.qualification_report_sha256,
            "review_bundle_sha256": self.review_bundle_sha256,
            "review_sha256": self.review_sha256,
            "approval_sha256": self.approval_sha256,
            "invalidation_manifest_sha256": self.invalidation_manifest_sha256,
            "lifecycle_sha256": self.lifecycle_sha256,
            "revocation_ledger_sha256": self.revocation_ledger_sha256,
            "revocation_storage_head_sha256": (
                self.revocation_storage_head_sha256
            ),
            "qualification_role_policy_sha256": (
                self.qualification_role_policy_sha256
            ),
            "review_role_policy_sha256": self.review_role_policy_sha256,
            "prequalification_authorization_sha256": (
                self.prequalification_authorization_sha256
            ),
            "qualification_authorization_sha256": (
                self.qualification_authorization_sha256
            ),
            "review_authorization_sha256": self.review_authorization_sha256,
            "basis_qualification_authorization_sha256": (
                self.basis_qualification_authorization_sha256
            ),
            "basis_review_authorization_sha256": (
                self.basis_review_authorization_sha256
            ),
            "current_qualification_proof_sha256": list(
                self.current_qualification_proof_sha256
            ),
            "basis_qualification_proof_sha256": list(
                self.basis_qualification_proof_sha256
            ),
            "current_review_proof_sha256": self.current_review_proof_sha256,
            "basis_review_proof_sha256": self.basis_review_proof_sha256,
            "approval_proof_sha256": self.approval_proof_sha256,
            "revocation_proof_sha256": list(self.revocation_proof_sha256),
            "static_profile_proof_sha256": self.static_profile_proof_sha256,
        }

    @classmethod
    def from_document(cls, value: object) -> "StagedProfileGateGraph":
        fields = (
            "contract_kind",
            "schema_version",
            "candidate_sha256",
            "qualification_policy_sha256",
            "qualification_plan_sha256",
            "calibration_report_sha256",
            "qualification_report_sha256",
            "review_bundle_sha256",
            "review_sha256",
            "approval_sha256",
            "invalidation_manifest_sha256",
            "lifecycle_sha256",
            "revocation_ledger_sha256",
            "revocation_storage_head_sha256",
            "qualification_role_policy_sha256",
            "review_role_policy_sha256",
            "prequalification_authorization_sha256",
            "qualification_authorization_sha256",
            "review_authorization_sha256",
            "basis_qualification_authorization_sha256",
            "basis_review_authorization_sha256",
            "current_qualification_proof_sha256",
            "basis_qualification_proof_sha256",
            "current_review_proof_sha256",
            "basis_review_proof_sha256",
            "approval_proof_sha256",
            "revocation_proof_sha256",
            "static_profile_proof_sha256",
        )
        document = require_exact_keys(
            value,
            required=fields,
            where="staged Profile Gate graph",
        )
        if document["contract_kind"] != "staged_profile_gate_graph":
            raise ContractError("staged Profile Gate graph has wrong contract_kind")
        if (
            type(document["schema_version"]) is not int
            or document["schema_version"] != 1
        ):
            raise ContractError(
                "staged Profile Gate graph schema_version must be integer 1"
            )
        for field in (
            "current_qualification_proof_sha256",
            "basis_qualification_proof_sha256",
            "revocation_proof_sha256",
        ):
            if type(document[field]) is not list:
                raise ContractError(f"{field} must be a list")
        return cls(
            **{
                field: document[field]
                for field in fields
                if field not in ("contract_kind", "schema_version")
            }
        )

    @classmethod
    def from_json(cls, payload: object) -> "StagedProfileGateGraph":
        return cls.from_document(load_strict_json_object(payload))

    @property
    def content_sha256(self) -> str:
        return canonical_sha256(self.to_document())


@dataclass(frozen=True)
class ProfileGateRequest:
    setup_session_id: str
    staged: StagedProfileGateGraph
    role_policy: SetupRolePolicy
    effective_permissions: tuple[str, ...]
    admitted_at: str
    expected_previous_ref_sha256: str | None

    def __post_init__(self) -> None:
        validate_identifier(self.setup_session_id, "setup_session_id")
        if type(self.staged) is not StagedProfileGateGraph:
            raise ContractError("staged must be a StagedProfileGateGraph")
        if type(self.role_policy) is not SetupRolePolicy:
            raise ContractError("role_policy must be a SetupRolePolicy")
        if (
            self.role_policy.role is not SetupRole.PROFILE_GATE
            or self.role_policy.setup_session_id != self.setup_session_id
            or self.role_policy.subject_sha256 != self.staged.content_sha256
        ):
            raise ContractError("Profile Gate request has a misbound role policy")
        object.__setattr__(
            self,
            "effective_permissions",
            _identifier_collection(
                self.effective_permissions,
                "effective_permissions",
            ),
        )
        _timestamp(self.admitted_at, "admitted_at")
        if self.expected_previous_ref_sha256 is not None:
            validate_sha256(
                self.expected_previous_ref_sha256,
                "expected_previous_ref_sha256",
            )


@dataclass(frozen=True)
class GateVerificationReceipt:
    gate_policy_sha256: str
    gate_role_policy_sha256: str
    staged_graph_sha256: str
    profile_sha256: str
    admission_claims_sha256: str
    qualification_proof_sha256: tuple[str, ...]
    review_proof_sha256: tuple[str, ...]
    approval_proof_sha256: str
    revocation_proof_sha256: tuple[str, ...]
    static_profile_proof_sha256: str
    verified_at: str

    def __post_init__(self) -> None:
        for field in (
            "gate_policy_sha256",
            "gate_role_policy_sha256",
            "staged_graph_sha256",
            "profile_sha256",
            "admission_claims_sha256",
            "approval_proof_sha256",
            "static_profile_proof_sha256",
        ):
            validate_sha256(getattr(self, field), field)
        for field, allow_empty in (
            ("qualification_proof_sha256", False),
            ("review_proof_sha256", False),
            ("revocation_proof_sha256", True),
        ):
            values = _digest_collection(getattr(self, field), field)
            if not allow_empty and not values:
                raise ContractError(f"{field} must not be empty")
            object.__setattr__(self, field, values)
        _timestamp(self.verified_at, "verified_at")

    def to_document(self) -> dict[str, object]:
        return {
            "contract_kind": "gate_verification_receipt",
            "schema_version": 1,
            "gate_policy_sha256": self.gate_policy_sha256,
            "gate_role_policy_sha256": self.gate_role_policy_sha256,
            "staged_graph_sha256": self.staged_graph_sha256,
            "profile_sha256": self.profile_sha256,
            "admission_claims_sha256": self.admission_claims_sha256,
            "qualification_proof_sha256": list(
                self.qualification_proof_sha256
            ),
            "review_proof_sha256": list(self.review_proof_sha256),
            "approval_proof_sha256": self.approval_proof_sha256,
            "revocation_proof_sha256": list(
                self.revocation_proof_sha256
            ),
            "static_profile_proof_sha256": (
                self.static_profile_proof_sha256
            ),
            "verified_at": self.verified_at,
        }

    @classmethod
    def from_document(cls, value: object) -> "GateVerificationReceipt":
        fields = (
            "contract_kind",
            "schema_version",
            "gate_policy_sha256",
            "gate_role_policy_sha256",
            "staged_graph_sha256",
            "profile_sha256",
            "admission_claims_sha256",
            "qualification_proof_sha256",
            "review_proof_sha256",
            "approval_proof_sha256",
            "revocation_proof_sha256",
            "static_profile_proof_sha256",
            "verified_at",
        )
        document = require_exact_keys(
            value,
            required=fields,
            where="gate verification receipt",
        )
        if document["contract_kind"] != "gate_verification_receipt":
            raise ContractError("gate verification receipt has wrong contract_kind")
        if (
            type(document["schema_version"]) is not int
            or document["schema_version"] != 1
        ):
            raise ContractError(
                "gate verification receipt schema_version must be integer 1"
            )
        for field in (
            "qualification_proof_sha256",
            "review_proof_sha256",
            "revocation_proof_sha256",
        ):
            if type(document[field]) is not list:
                raise ContractError(f"{field} must be a list")
        return cls(
            gate_policy_sha256=document["gate_policy_sha256"],
            gate_role_policy_sha256=document["gate_role_policy_sha256"],
            staged_graph_sha256=document["staged_graph_sha256"],
            profile_sha256=document["profile_sha256"],
            admission_claims_sha256=document["admission_claims_sha256"],
            qualification_proof_sha256=tuple(
                document["qualification_proof_sha256"]
            ),
            review_proof_sha256=tuple(document["review_proof_sha256"]),
            approval_proof_sha256=document["approval_proof_sha256"],
            revocation_proof_sha256=tuple(
                document["revocation_proof_sha256"]
            ),
            static_profile_proof_sha256=document[
                "static_profile_proof_sha256"
            ],
            verified_at=document["verified_at"],
        )

    @classmethod
    def from_json(cls, payload: object) -> "GateVerificationReceipt":
        return cls.from_document(load_strict_json_object(payload))

    @property
    def content_sha256(self) -> str:
        return canonical_sha256(self.to_document())


def _admission_claims_sha256(admission: ProfileAdmissionRecord) -> str:
    if type(admission) is not ProfileAdmissionRecord:
        raise ContractError("admission claims require ProfileAdmissionRecord")
    document = admission.to_document()
    del document["gate_verification_receipt_sha256"]
    return canonical_sha256(document)


@dataclass(frozen=True)
class ProfileGateResult:
    profile: FrozenSystemProfile
    admission: ProfileAdmissionRecord
    lifecycle: SetupLifecycleRecord
    gate_verification_receipt: GateVerificationReceipt
    profile_ref_sha256: str
    approval_reused: bool

    def __post_init__(self) -> None:
        if type(self.profile) is not FrozenSystemProfile:
            raise ContractError("profile must be a FrozenSystemProfile")
        if type(self.admission) is not ProfileAdmissionRecord:
            raise ContractError("admission must be a ProfileAdmissionRecord")
        if type(self.lifecycle) is not SetupLifecycleRecord:
            raise ContractError("lifecycle must be a SetupLifecycleRecord")
        if type(self.gate_verification_receipt) is not GateVerificationReceipt:
            raise ContractError(
                "gate_verification_receipt must be a GateVerificationReceipt"
            )
        validate_sha256(self.profile_ref_sha256, "profile_ref_sha256")
        if type(self.approval_reused) is not bool:
            raise ContractError("approval_reused must be a boolean")
        if self.admission.profile != self.profile.ref:
            raise ContractError("admission does not bind the frozen profile")
        if self.admission.lifecycle_sha256 != self.lifecycle.content_sha256:
            raise ContractError("admission does not bind the final lifecycle")
        if (
            self.admission.gate_verification_receipt_sha256
            != self.gate_verification_receipt.content_sha256
        ):
            raise ContractError("admission does not bind Gate verification receipt")
        if (
            _admission_claims_sha256(self.admission)
            != self.gate_verification_receipt.admission_claims_sha256
        ):
            raise ContractError("Gate receipt does not bind admission claims")
        if (
            self.gate_verification_receipt.profile_sha256
            != self.profile.content_sha256
        ):
            raise ContractError("Gate receipt does not bind the frozen profile")
        if (
            self.gate_verification_receipt.gate_policy_sha256
            != self.admission.gate_policy_sha256
        ):
            raise ContractError("Gate receipt does not bind admission policy")
        if (
            self.gate_verification_receipt.verified_at
            != self.admission.admitted_at
        ):
            raise ContractError("Gate receipt time differs from admission time")


def _load_contract(store: ProfileStore, digest: str, contract_type):
    payload = store.get_object(digest)
    value = contract_type.from_json(payload)
    if value.content_sha256 != digest:
        raise ContractError(
            f"{contract_type.__name__} canonical content differs from its CAS address"
        )
    return value


def _all_hash_references(
    document: object,
) -> tuple[tuple[str, int | None], ...]:
    """Collect typed ContractRef/ArtifactRef hashes from a canonical document."""

    result: set[tuple[str, int | None]] = set()

    def visit(value: object) -> None:
        if type(value) is dict:
            kind = value.get("contract_kind")
            if kind in ("contract_ref", "artifact_ref"):
                digest = value.get("content_sha256")
                validate_sha256(digest, "referenced content_sha256")
                size: int | None = None
                if kind == "artifact_ref":
                    size = value.get("size_bytes")
                    if type(size) is not int or size < 0:
                        raise ContractError(
                            "referenced artifact size_bytes must be non-negative"
                        )
                result.add((digest, size))
            for child in value.values():
                visit(child)
        elif type(value) in (list, tuple):
            for child in value:
                visit(child)

    visit(document)
    return tuple(sorted(result, key=lambda item: (item[0], item[1] or -1)))


def _verify_all_references(store: ProfileStore, documents: tuple[object, ...]) -> None:
    declarations: dict[str, set[int]] = {}
    contracts: set[str] = set()
    for document in documents:
        for digest, size in _all_hash_references(document):
            if size is None:
                contracts.add(digest)
            else:
                declarations.setdefault(digest, set()).add(size)
    for digest, sizes in declarations.items():
        if len(sizes) != 1:
            raise ContractError("one artifact hash has conflicting declared sizes")
        store.get_object(digest, expected_size_bytes=next(iter(sizes)))
    for digest in sorted(contracts - declarations.keys()):
        store.get_object(digest)


def _validate_revocation_view(
    store: ProfileStore,
    expected_storage_head_sha256: str | None,
    ledger: RevocationLedger,
    verifier: RevocationSignatureVerifier,
    authority_policy_sha256: str,
) -> tuple[RevocationVerificationProof, ...]:
    if ledger.authority_policy_sha256 != authority_policy_sha256:
        raise ContractError("revocation ledger uses the wrong authority policy")
    current_head = store.revocation_head()
    current_head_sha256 = (
        None if current_head is None else current_head.content_sha256
    )
    if current_head_sha256 != expected_storage_head_sha256:
        raise ContractError("Profile Gate revocation view is not the current head")
    chain = store.revocation_chain(expected_storage_head_sha256)
    if len(chain) != len(ledger.entries):
        raise ContractError("revocation ledger differs from durable storage chain")
    proofs = []
    for storage_entry, entry in zip(chain, ledger.entries):
        payload = store.get_object(storage_entry.payload_sha256)
        expected = canonical_json_bytes(entry.to_document())
        if payload != expected or storage_entry.payload_sha256 != entry.content_sha256:
            raise ContractError("durable revocation payload differs from ledger entry")
        request = RevocationVerificationRequest(
            entry=entry,
            authority_policy_sha256=authority_policy_sha256,
        )
        try:
            proof = verifier(request)
        except Exception as exc:
            raise _AuthorityServiceError(
                "revocation signature verifier failed"
            ) from exc
        if type(proof) is not RevocationVerificationProof:
            raise ContractError(
                "revocation verifier must return RevocationVerificationProof"
            )
        proof.validate_request(request)
        proofs.append(proof)
    return tuple(proofs)


def _revoked_at(
    ledger: RevocationLedger,
    evaluated_at: str,
) -> dict[RevocationTargetKind, frozenset[str]]:
    result: dict[RevocationTargetKind, set[str]] = {}
    for entry in ledger.entries:
        if entry.effective_at <= evaluated_at:
            result.setdefault(entry.target.kind, set()).add(
                entry.target.content_sha256
            )
    return {kind: frozenset(values) for kind, values in result.items()}


def _qualification_verification_requests(
    *,
    candidate: ProfileSetupCandidate,
    policy: QualificationPolicy,
    plan: QualificationPlan,
    calibration: CalibrationReport,
    report: QualificationReport,
    role_policy: SetupRolePolicy,
    prequalification_authorization_sha256: str,
    authority_policy_sha256: str,
) -> tuple[QualificationEvidenceVerificationRequest, ...]:
    history: dict[
        tuple[object, str],
        QualificationTrial,
    ] = {}
    requests = []
    ordered_trials = sorted(
        report.trials,
        key=lambda item: (
            item.partition_kind.value,
            item.member_commitment,
            item.attempt_index,
        ),
    )
    for trial in ordered_trials:
        key = (trial.partition_kind, trial.member_commitment)
        previous = history.get(key)
        if trial.attempt_index > 1:
            if previous is None or previous.attempt_index != trial.attempt_index - 1:
                raise ContractError("qualification retry history is not contiguous")
            if (
                previous.stable
                and previous.observed_verdict is not OracleVerdict.INCONCLUSIVE
            ):
                raise ContractError(
                    "qualification cannot retry a usable prior decision"
                )
        elif previous is not None:
            raise ContractError("qualification member repeats its first attempt")
        requests.append(QualificationEvidenceVerificationRequest(
            candidate_sha256=candidate.content_sha256,
            profile_environment_sha256=canonical_sha256(
                candidate.profile_graph.environment.to_document()
            ),
            qualification_policy_sha256=policy.content_sha256,
            qualification_plan_sha256=plan.content_sha256,
            calibration_report_sha256=calibration.content_sha256,
            qualification_report_sha256=report.content_sha256,
            broker_attestation_sha256=(
                report.qualification_environment_sha256
            ),
            trial=trial,
            previous_trial_sha256=(
                None
                if previous is None
                else canonical_sha256(previous.to_document())
            ),
            qualification_role_policy_sha256=role_policy.content_sha256,
            prequalification_authorization_sha256=(
                prequalification_authorization_sha256
            ),
            authority_policy_sha256=authority_policy_sha256,
        ))
        history[key] = trial
    return tuple(requests)


def _verify_qualification_evidence(
    *,
    candidate: ProfileSetupCandidate,
    policy: QualificationPolicy,
    plan: QualificationPlan,
    calibration: CalibrationReport,
    report: QualificationReport,
    role_policy: SetupRolePolicy,
    prequalification_authorization_sha256: str,
    verifier: QualificationEvidenceVerifier,
    authority_policy_sha256: str,
) -> tuple[QualificationEvidenceVerificationProof, ...]:
    requests = _qualification_verification_requests(
        candidate=candidate,
        policy=policy,
        plan=plan,
        calibration=calibration,
        report=report,
        role_policy=role_policy,
        prequalification_authorization_sha256=(
            prequalification_authorization_sha256
        ),
        authority_policy_sha256=authority_policy_sha256,
    )
    proofs = []
    for request in requests:
        try:
            proof = verifier(request)
        except Exception as exc:
            raise _AuthorityServiceError(
                "qualification evidence verifier failed"
            ) from exc
        if type(proof) is not QualificationEvidenceVerificationProof:
            raise ContractError(
                "qualification verifier returned an unexpected proof type"
            )
        proof.validate_request(request)
        proofs.append(proof)
    return tuple(proofs)


def _verify_review(
    *,
    bundle: ResultBlindReviewBundle,
    review: ReviewRecord,
    role_policy: SetupRolePolicy,
    excluded_setup_session_id: str,
    qualification_authorization_sha256: str,
    verifier: ReviewVerifier,
    authority_policy_sha256: str,
) -> ReviewVerificationProof:
    request = ReviewVerificationRequest(
        review_bundle_sha256=bundle.content_sha256,
        review_sha256=review.content_sha256,
        reviewer_authority=review.reviewer_authority,
        reviewer_session_id=review.reviewer_session_id,
        model_id=review.model_id,
        prompt_sha256=review.prompt_sha256,
        reviewer_role_policy_sha256=role_policy.content_sha256,
        excluded_setup_session_id=excluded_setup_session_id,
        qualification_authorization_sha256=(
            qualification_authorization_sha256
        ),
        authority_policy_sha256=authority_policy_sha256,
    )
    try:
        proof = verifier(request)
    except Exception as exc:
        raise _AuthorityServiceError("review authority verifier failed") from exc
    if type(proof) is not ReviewVerificationProof:
        raise ContractError("review verifier returned an unexpected proof type")
    proof.validate_request(request)
    return proof


def _verify_static_profile(
    *,
    candidate: ProfileSetupCandidate,
    static_scan: ArtifactRef,
    verifier: StaticProfileVerifier,
    authority_policy_sha256: str,
) -> StaticProfileVerificationProof:
    graph = candidate.profile_graph
    request = StaticProfileVerificationRequest(
        candidate_sha256=candidate.content_sha256,
        profile_graph_sha256=graph.content_sha256,
        entrypoint_sha256=tuple(
            item.content_sha256 for item in graph.entrypoints
        ),
        workload_schema_sha256=tuple(
            item.content_sha256 for item in graph.workload_schemas
        ),
        adapter_sha256=tuple(item.content_sha256 for item in graph.adapters),
        instrumentation_sha256=tuple(
            item.content_sha256 for item in graph.instrumentation_providers
        ),
        permission_manifest_sha256=(
            candidate.permission_manifest.content_sha256
        ),
        sbom_sha256=candidate.sbom.content_sha256,
        static_scan_sha256=static_scan.content_sha256,
        authority_policy_sha256=authority_policy_sha256,
    )
    try:
        proof = verifier(request)
    except Exception as exc:
        raise _AuthorityServiceError("static profile verifier failed") from exc
    if type(proof) is not StaticProfileVerificationProof:
        raise ContractError(
            "static profile verifier returned an unexpected proof type"
        )
    proof.validate_request(request)
    return proof


def _prequalification_authorization_sha256(
    *,
    candidate_sha256: str,
    policy_sha256: str,
    plan_sha256: str,
    static_proof_sha256: str,
    revocation_proof_sha256: tuple[str, ...],
    revocation_storage_head_sha256: str | None,
    revocation_ledger_sha256: str,
    invalidation_manifest_sha256: str,
    gate_policy_sha256: str,
) -> str:
    return canonical_sha256(
        {
            "authorization_kind": "prequalification",
            "candidate_sha256": candidate_sha256,
            "qualification_policy_sha256": policy_sha256,
            "qualification_plan_sha256": plan_sha256,
            "static_profile_proof_sha256": static_proof_sha256,
            "revocation_proof_sha256": list(
                sorted(revocation_proof_sha256)
            ),
            "revocation_storage_head_sha256": revocation_storage_head_sha256,
            "revocation_ledger_sha256": revocation_ledger_sha256,
            "invalidation_manifest_sha256": invalidation_manifest_sha256,
            "gate_policy_sha256": gate_policy_sha256,
        }
    )


def _qualification_authorization_sha256(
    *,
    prequalification_authorization_sha256: str,
    calibration_report_sha256: str,
    qualification_report_sha256: str,
    qualification_proof_sha256: tuple[str, ...],
) -> str:
    return canonical_sha256(
        {
            "authorization_kind": "qualification",
            "prequalification_authorization_sha256": (
                prequalification_authorization_sha256
            ),
            "calibration_report_sha256": calibration_report_sha256,
            "qualification_report_sha256": qualification_report_sha256,
            "qualification_proof_sha256": list(
                sorted(qualification_proof_sha256)
            ),
        }
    )


def _review_authorization_sha256(
    *,
    qualification_authorization_sha256: str,
    review_bundle_sha256: str,
    review_sha256: str,
    review_proof_sha256: str,
) -> str:
    return canonical_sha256(
        {
            "authorization_kind": "review",
            "qualification_authorization_sha256": (
                qualification_authorization_sha256
            ),
            "review_bundle_sha256": review_bundle_sha256,
            "review_sha256": review_sha256,
            "review_proof_sha256": review_proof_sha256,
        }
    )


def _load_qualification_proof_set(
    *,
    store: ProfileStore,
    digests: tuple[str, ...],
    requests: tuple[QualificationEvidenceVerificationRequest, ...],
    receipt_validator: AuthorityReceiptValidator,
) -> tuple[QualificationEvidenceVerificationProof, ...]:
    if len(digests) != len(requests):
        raise ContractError("qualification proof count does not match trials")
    loaded = tuple(
        _load_contract(store, digest, QualificationEvidenceVerificationProof)
        for digest in digests
    )
    by_trial = {proof.trial_sha256: proof for proof in loaded}
    if len(by_trial) != len(loaded):
        raise ContractError("qualification proof set contains duplicates")
    ordered = []
    for request in requests:
        trial_sha256 = canonical_sha256(request.trial.to_document())
        proof = by_trial.get(trial_sha256)
        if proof is None:
            raise ContractError("qualification proof set omits a trial")
        proof.validate_request(request)
        _validate_authority_receipt(
            store=store,
            proof=proof,
            validator=receipt_validator,
        )
        ordered.append(proof)
    return tuple(ordered)


def _load_review_proof(
    *,
    store: ProfileStore,
    digest: str,
    request: ReviewVerificationRequest,
    receipt_validator: AuthorityReceiptValidator,
) -> ReviewVerificationProof:
    proof = _load_contract(store, digest, ReviewVerificationProof)
    proof.validate_request(request)
    _validate_authority_receipt(
        store=store,
        proof=proof,
        validator=receipt_validator,
    )
    return proof


def _load_approval_proof(
    *,
    store: ProfileStore,
    digest: str,
    request: SemanticApprovalVerificationRequest,
    receipt_validator: AuthorityReceiptValidator,
) -> SemanticApprovalVerificationProof:
    proof = _load_contract(
        store,
        digest,
        SemanticApprovalVerificationProof,
    )
    proof.validate_request(request)
    _validate_authority_receipt(
        store=store,
        proof=proof,
        validator=receipt_validator,
    )
    return proof


class ProfileGate:
    """Reparse the complete staged graph and atomically publish its profile ref."""

    def __init__(
        self,
        store: ProfileStore,
        gate_policy: ProfileGatePolicy,
        authority_receipt_validator: AuthorityReceiptValidator,
        clock: Callable[[], str],
    ) -> None:
        if type(store) is not ProfileStore:
            raise ContractError("store must be a ProfileStore")
        if type(gate_policy) is not ProfileGatePolicy:
            raise ContractError("gate_policy must be a ProfileGatePolicy")
        if not callable(authority_receipt_validator):
            raise ContractError("authority_receipt_validator must be callable")
        if not callable(clock):
            raise ContractError("clock must be callable")
        self._store = store
        self._gate_policy = gate_policy
        self._authority_receipt_validator = authority_receipt_validator
        self._clock = clock

    def freeze(
        self,
        request: ProfileGateRequest,
    ) -> ProfileGateResult:
        if type(request) is not ProfileGateRequest:
            raise ContractError("request must be a ProfileGateRequest")
        try:
            return self._freeze(request)
        except _AuthorityServiceError as exc:
            _raise(
                ProfileSetupFailureCode.PROFILE_GATE_AUTHORITY_FAILED,
                str(exc),
                exc,
            )
        except ProfileStoreError as exc:
            _raise(ProfileSetupFailureCode.STORAGE_FAILURE, str(exc), exc)
        except ContractError as exc:
            _raise(ProfileSetupFailureCode.PROFILE_GATE_REJECTED, str(exc), exc)

    def _freeze(
        self,
        request: ProfileGateRequest,
    ) -> ProfileGateResult:
        try:
            trusted_admitted_at = self._clock()
        except Exception as exc:
            raise _AuthorityServiceError(
                "Profile Gate authority clock failed"
            ) from exc
        _timestamp(trusted_admitted_at, "trusted_admitted_at")
        if (
            request.role_policy.governance_policy_sha256
            != self._gate_policy.content_sha256
        ):
            raise ContractError("Profile Gate request uses the wrong governance policy")
        stored_gate_policy = _load_contract(
            self._store,
            self._gate_policy.content_sha256,
            ProfileGatePolicy,
        )
        if stored_gate_policy != self._gate_policy:
            raise ContractError("Profile Gate policy CAS object is misbound")
        staged = request.staged
        stored_staged = _load_contract(
            self._store,
            staged.content_sha256,
            StagedProfileGateGraph,
        )
        if stored_staged != staged:
            raise ContractError("staged Profile Gate graph CAS object is misbound")
        stored_gate_role = _load_contract(
            self._store,
            request.role_policy.content_sha256,
            SetupRolePolicy,
        )
        if stored_gate_role != request.role_policy:
            raise ContractError("Profile Gate role policy CAS object is misbound")
        qualification_role = _load_contract(
            self._store,
            staged.qualification_role_policy_sha256,
            SetupRolePolicy,
        )
        review_role = _load_contract(
            self._store,
            staged.review_role_policy_sha256,
            SetupRolePolicy,
        )
        candidate = _load_contract(
            self._store, staged.candidate_sha256, ProfileSetupCandidate
        )
        policy = _load_contract(
            self._store,
            staged.qualification_policy_sha256,
            QualificationPolicy,
        )
        plan = _load_contract(
            self._store, staged.qualification_plan_sha256, QualificationPlan
        )
        calibration = _load_contract(
            self._store, staged.calibration_report_sha256, CalibrationReport
        )
        report = _load_contract(
            self._store, staged.qualification_report_sha256, QualificationReport
        )
        bundle = _load_contract(
            self._store, staged.review_bundle_sha256, ResultBlindReviewBundle
        )
        review = _load_contract(self._store, staged.review_sha256, ReviewRecord)
        approval = _load_contract(
            self._store, staged.approval_sha256, SemanticApprovalRecord
        )
        manifest = _load_contract(
            self._store,
            staged.invalidation_manifest_sha256,
            DependencyInvalidationManifest,
        )
        lifecycle = _load_contract(
            self._store, staged.lifecycle_sha256, SetupLifecycleRecord
        )
        ledger = _load_contract(
            self._store, staged.revocation_ledger_sha256, RevocationLedger
        )

        basis_review = _load_contract(
            self._store,
            approval.basis_review_sha256,
            ReviewRecord,
        )
        basis_report = _load_contract(
            self._store,
            approval.basis_qualification_report_sha256,
            QualificationReport,
        )
        basis_bundle = _load_contract(
            self._store,
            basis_review.input_bundle_sha256,
            ResultBlindReviewBundle,
        )
        basis_candidate = _load_contract(
            self._store,
            basis_bundle.candidate_sha256,
            ProfileSetupCandidate,
        )
        basis_policy = _load_contract(
            self._store,
            basis_report.qualification_policy_sha256,
            QualificationPolicy,
        )
        basis_plan = _load_contract(
            self._store,
            basis_report.qualification_plan_sha256,
            QualificationPlan,
        )
        basis_calibration = _load_contract(
            self._store,
            basis_report.calibration_report_sha256,
            CalibrationReport,
        )

        validate_qualification_graph(candidate, policy, plan, calibration, report)
        verify_qualification_report(
            policy=policy,
            plan=plan,
            calibration_report=calibration,
            report=report,
        )
        if report.verdict is not QualificationVerdict.PASS:
            raise ContractError("Profile Gate requires passing qualification")
        static_request = StaticProfileVerificationRequest(
            candidate_sha256=candidate.content_sha256,
            profile_graph_sha256=candidate.profile_graph.content_sha256,
            entrypoint_sha256=tuple(
                item.content_sha256
                for item in candidate.profile_graph.entrypoints
            ),
            workload_schema_sha256=tuple(
                item.content_sha256
                for item in candidate.profile_graph.workload_schemas
            ),
            adapter_sha256=tuple(
                item.content_sha256 for item in candidate.profile_graph.adapters
            ),
            instrumentation_sha256=tuple(
                item.content_sha256
                for item in candidate.profile_graph.instrumentation_providers
            ),
            permission_manifest_sha256=(
                candidate.permission_manifest.content_sha256
            ),
            sbom_sha256=candidate.sbom.content_sha256,
            static_scan_sha256=bundle.static_scan.content_sha256,
            authority_policy_sha256=(
                self._gate_policy.static_profile_authority_policy_sha256
            ),
        )
        static_profile_proof = _load_contract(
            self._store,
            staged.static_profile_proof_sha256,
            StaticProfileVerificationProof,
        )
        static_profile_proof.validate_request(static_request)
        _validate_authority_receipt(
            store=self._store,
            proof=static_profile_proof,
            validator=self._authority_receipt_validator,
        )

        current_head = self._store.revocation_head()
        current_head_sha256 = (
            None if current_head is None else current_head.content_sha256
        )
        if current_head_sha256 != staged.revocation_storage_head_sha256:
            raise ContractError("Profile Gate revocation view is not current")
        chain = self._store.revocation_chain(
            staged.revocation_storage_head_sha256
        )
        if len(chain) != len(ledger.entries):
            raise ContractError("revocation ledger differs from durable chain")
        if len(staged.revocation_proof_sha256) != len(ledger.entries):
            raise ContractError("revocation proof count differs from ledger")
        revocation_proofs = []
        proof_by_entry = {
            proof.entry_sha256: proof
            for proof in (
                _load_contract(
                    self._store,
                    digest,
                    RevocationVerificationProof,
                )
                for digest in staged.revocation_proof_sha256
            )
        }
        if len(proof_by_entry) != len(staged.revocation_proof_sha256):
            raise ContractError("revocation proof set contains duplicates")
        for storage_entry, entry in zip(chain, ledger.entries):
            if (
                storage_entry.payload_sha256 != entry.content_sha256
                or self._store.get_object(storage_entry.payload_sha256)
                != canonical_json_bytes(entry.to_document())
            ):
                raise ContractError("durable revocation entry is misbound")
            proof = proof_by_entry.get(entry.content_sha256)
            if proof is None:
                raise ContractError("revocation proof set omits an entry")
            revocation_request = RevocationVerificationRequest(
                entry=entry,
                authority_policy_sha256=(
                    self._gate_policy.revocation_authority_policy_sha256
                ),
            )
            proof.validate_request(revocation_request)
            _validate_authority_receipt(
                store=self._store,
                proof=proof,
                validator=self._authority_receipt_validator,
            )
            revocation_proofs.append(proof)

        expected_prequalification = _prequalification_authorization_sha256(
            candidate_sha256=candidate.content_sha256,
            policy_sha256=policy.content_sha256,
            plan_sha256=plan.content_sha256,
            static_proof_sha256=static_profile_proof.content_sha256,
            revocation_proof_sha256=tuple(
                item.content_sha256 for item in revocation_proofs
            ),
            revocation_storage_head_sha256=(
                staged.revocation_storage_head_sha256
            ),
            revocation_ledger_sha256=ledger.content_sha256,
            invalidation_manifest_sha256=manifest.content_sha256,
            gate_policy_sha256=self._gate_policy.content_sha256,
        )
        if staged.prequalification_authorization_sha256 != expected_prequalification:
            raise ContractError("prequalification authorization is misbound")
        if (
            qualification_role.role is not SetupRole.QUALIFICATION_WORKER
            or qualification_role.setup_session_id != request.setup_session_id
            or qualification_role.subject_sha256 != expected_prequalification
            or qualification_role.governance_policy_sha256
            != self._gate_policy.content_sha256
        ):
            raise ContractError("qualification role policy is misbound")
        current_qualification_requests = _qualification_verification_requests(
            candidate=candidate,
            policy=policy,
            plan=plan,
            calibration=calibration,
            report=report,
            role_policy=qualification_role,
            prequalification_authorization_sha256=expected_prequalification,
            authority_policy_sha256=(
                self._gate_policy.qualification_evidence_authority_policy_sha256
            ),
        )
        current_qualification_proofs = _load_qualification_proof_set(
            store=self._store,
            digests=staged.current_qualification_proof_sha256,
            requests=current_qualification_requests,
            receipt_validator=self._authority_receipt_validator,
        )
        expected_qualification_authorization = (
            _qualification_authorization_sha256(
                prequalification_authorization_sha256=expected_prequalification,
                calibration_report_sha256=calibration.content_sha256,
                qualification_report_sha256=report.content_sha256,
                qualification_proof_sha256=tuple(
                    item.content_sha256
                    for item in current_qualification_proofs
                ),
            )
        )
        if (
            staged.qualification_authorization_sha256
            != expected_qualification_authorization
        ):
            raise ContractError("qualification authorization is misbound")
        validate_review_graph(candidate, report, bundle, review)
        validate_result_blind_review_record(bundle, review)
        if review.verdict is not ReviewVerdict.APPROVE:
            raise ContractError("Profile Gate requires an approved review")
        if review.reviewer_session_id in (
            request.setup_session_id,
            candidate.setup_id,
        ):
            raise ContractError("review session is not independent from Setup")
        if (
            review.reviewer_authority
            not in self._gate_policy.allowed_reviewer_authorities
            or review.model_id not in self._gate_policy.allowed_reviewer_models
        ):
            raise ContractError("review authority or model is not allowlisted")
        if (
            review_role.role is not SetupRole.REVIEWER
            or review_role.setup_session_id != request.setup_session_id
            or review_role.subject_sha256
            != expected_qualification_authorization
            or review_role.governance_policy_sha256
            != self._gate_policy.content_sha256
        ):
            raise ContractError("review role policy is misbound")
        current_review_request = ReviewVerificationRequest(
            review_bundle_sha256=bundle.content_sha256,
            review_sha256=review.content_sha256,
            reviewer_authority=review.reviewer_authority,
            reviewer_session_id=review.reviewer_session_id,
            model_id=review.model_id,
            prompt_sha256=review.prompt_sha256,
            reviewer_role_policy_sha256=review_role.content_sha256,
            excluded_setup_session_id=request.setup_session_id,
            qualification_authorization_sha256=(
                expected_qualification_authorization
            ),
            authority_policy_sha256=self._gate_policy.review_authority_policy_sha256,
        )
        current_review_proof = _load_review_proof(
            store=self._store,
            digest=staged.current_review_proof_sha256,
            request=current_review_request,
            receipt_validator=self._authority_receipt_validator,
        )
        expected_review_authorization = _review_authorization_sha256(
            qualification_authorization_sha256=(
                expected_qualification_authorization
            ),
            review_bundle_sha256=bundle.content_sha256,
            review_sha256=review.content_sha256,
            review_proof_sha256=current_review_proof.content_sha256,
        )
        if staged.review_authorization_sha256 != expected_review_authorization:
            raise ContractError("review authorization is misbound")
        semantic_subject = make_review_subject(candidate)
        if candidate.trust_tier is RegistrationTrustTier.TRUSTED_PRESET:
            if (
                semantic_subject.content_sha256
                not in self._gate_policy.trusted_preset_subject_sha256
            ):
                raise ContractError(
                    "trusted_preset subject is not authority-admitted"
                )
        elif not self._gate_policy.allow_profile_custom:
            raise ContractError("profile_custom admission is disabled by authority")
        validate_approval_graph(candidate, approval)
        validate_qualification_graph(
            basis_candidate,
            basis_policy,
            basis_plan,
            basis_calibration,
            basis_report,
        )
        verify_qualification_report(
            policy=basis_policy,
            plan=basis_plan,
            calibration_report=basis_calibration,
            report=basis_report,
        )
        raw_basis_qualification_proofs = tuple(
            _load_contract(
                self._store,
                digest,
                QualificationEvidenceVerificationProof,
            )
            for digest in staged.basis_qualification_proof_sha256
        )
        if not raw_basis_qualification_proofs:
            raise ContractError("approval basis qualification proofs are empty")
        basis_role_hashes = {
            item.qualification_role_policy_sha256
            for item in raw_basis_qualification_proofs
        }
        basis_prequal_hashes = {
            item.prequalification_authorization_sha256
            for item in raw_basis_qualification_proofs
        }
        if len(basis_role_hashes) != 1 or len(basis_prequal_hashes) != 1:
            raise ContractError("approval basis qualification proofs disagree")
        basis_qualification_role = _load_contract(
            self._store,
            next(iter(basis_role_hashes)),
            SetupRolePolicy,
        )
        basis_prequalification_authorization = next(iter(basis_prequal_hashes))
        if (
            basis_qualification_role.role is not SetupRole.QUALIFICATION_WORKER
            or basis_qualification_role.subject_sha256
            != basis_prequalification_authorization
            or basis_qualification_role.governance_policy_sha256
            != self._gate_policy.content_sha256
        ):
            raise ContractError("approval basis qualification role is misbound")
        basis_qualification_requests = _qualification_verification_requests(
            candidate=basis_candidate,
            policy=basis_policy,
            plan=basis_plan,
            calibration=basis_calibration,
            report=basis_report,
            role_policy=basis_qualification_role,
            prequalification_authorization_sha256=(
                basis_prequalification_authorization
            ),
            authority_policy_sha256=(
                self._gate_policy.qualification_evidence_authority_policy_sha256
            ),
        )
        basis_qualification_proofs = _load_qualification_proof_set(
            store=self._store,
            digests=staged.basis_qualification_proof_sha256,
            requests=basis_qualification_requests,
            receipt_validator=self._authority_receipt_validator,
        )
        expected_basis_qualification_authorization = (
            _qualification_authorization_sha256(
                prequalification_authorization_sha256=(
                    basis_prequalification_authorization
                ),
                calibration_report_sha256=basis_calibration.content_sha256,
                qualification_report_sha256=basis_report.content_sha256,
                qualification_proof_sha256=tuple(
                    item.content_sha256 for item in basis_qualification_proofs
                ),
            )
        )
        if (
            staged.basis_qualification_authorization_sha256
            != expected_basis_qualification_authorization
        ):
            raise ContractError("basis qualification authorization is misbound")
        validate_review_graph(
            basis_candidate,
            basis_report,
            basis_bundle,
            basis_review,
        )
        validate_result_blind_review_record(basis_bundle, basis_review)
        if basis_review.reviewer_session_id == basis_candidate.setup_id:
            raise ContractError("approval basis review is not independent")
        if (
            basis_review.reviewer_authority
            not in self._gate_policy.allowed_reviewer_authorities
            or basis_review.model_id
            not in self._gate_policy.allowed_reviewer_models
        ):
            raise ContractError(
                "approval basis reviewer authority or model is not allowlisted"
            )
        raw_basis_review_proof = _load_contract(
            self._store,
            staged.basis_review_proof_sha256,
            ReviewVerificationProof,
        )
        basis_review_role = _load_contract(
            self._store,
            raw_basis_review_proof.reviewer_role_policy_sha256,
            SetupRolePolicy,
        )
        if (
            basis_review_role.role is not SetupRole.REVIEWER
            or basis_review_role.setup_session_id
            != raw_basis_review_proof.excluded_setup_session_id
            or basis_review_role.subject_sha256
            != expected_basis_qualification_authorization
            or basis_review_role.governance_policy_sha256
            != self._gate_policy.content_sha256
        ):
            raise ContractError("approval basis review role is misbound")
        basis_review_request = ReviewVerificationRequest(
            review_bundle_sha256=basis_bundle.content_sha256,
            review_sha256=basis_review.content_sha256,
            reviewer_authority=basis_review.reviewer_authority,
            reviewer_session_id=basis_review.reviewer_session_id,
            model_id=basis_review.model_id,
            prompt_sha256=basis_review.prompt_sha256,
            reviewer_role_policy_sha256=basis_review_role.content_sha256,
            excluded_setup_session_id=basis_review_role.setup_session_id,
            qualification_authorization_sha256=(
                expected_basis_qualification_authorization
            ),
            authority_policy_sha256=self._gate_policy.review_authority_policy_sha256,
        )
        basis_review_proof = _load_review_proof(
            store=self._store,
            digest=staged.basis_review_proof_sha256,
            request=basis_review_request,
            receipt_validator=self._authority_receipt_validator,
        )
        expected_basis_review_authorization = _review_authorization_sha256(
            qualification_authorization_sha256=(
                expected_basis_qualification_authorization
            ),
            review_bundle_sha256=basis_bundle.content_sha256,
            review_sha256=basis_review.content_sha256,
            review_proof_sha256=basis_review_proof.content_sha256,
        )
        if (
            staged.basis_review_authorization_sha256
            != expected_basis_review_authorization
        ):
            raise ContractError("basis review authorization is misbound")
        validate_approval_basis(
            approval,
            basis_bundle,
            basis_review,
            basis_report,
        )
        if (
            make_review_subject(basis_candidate).content_sha256
            != approval.subject_sha256
        ):
            raise ContractError("approval basis has a different semantic subject")
        approval_verification_request = SemanticApprovalVerificationRequest(
            approval=approval,
            semantic_subject_sha256=semantic_subject.content_sha256,
            qualification_proof_sha256=tuple(
                item.content_sha256 for item in basis_qualification_proofs
            ),
            review_proof_sha256=basis_review_proof.content_sha256,
            review_authorization_sha256=(
                expected_basis_review_authorization
            ),
            authority_policy_sha256=(
                self._gate_policy.approval_authority_policy_sha256
            ),
        )
        approval_proof = _load_approval_proof(
            store=self._store,
            digest=staged.approval_proof_sha256,
            request=approval_verification_request,
            receipt_validator=self._authority_receipt_validator,
        )
        validate_invalidation_manifest_graph(candidate, manifest)
        if bundle.invalidation_manifest_sha256 != manifest.content_sha256:
            raise ContractError("review bundle does not bind invalidation manifest")
        if (
            lifecycle.candidate_sha256 != candidate.content_sha256
            or lifecycle.trust_tier is not candidate.trust_tier
            or lifecycle.final_state is not SetupState.AWAITING_APPROVAL
            or not lifecycle.transitions
            or lifecycle.transitions[-1].evidence_sha256 != review.content_sha256
        ):
            raise ContractError(
                "Profile Gate requires the candidate's awaiting-approval lifecycle"
            )

        gate_policy = self._gate_policy
        effective = set(request.effective_permissions)
        if not effective.issubset(set(candidate.declared_permissions)):
            raise ContractError("effective permissions exceed candidate declaration")
        if not effective.issubset(set(gate_policy.allowed_permissions)):
            raise ContractError("effective permissions exceed authority allowlist")
        if any(
            adapter.contract_version not in gate_policy.supported_adapter_versions
            for adapter in candidate.profile_graph.adapters
        ):
            raise ContractError("candidate requires an unsupported Adapter API/version")

        admitted = _timestamp(trusted_admitted_at, "admitted_at")
        evidence_times = (
            _timestamp(candidate.created_at, "candidate.created_at"),
            _timestamp(calibration.completed_at, "calibration.completed_at"),
            _timestamp(report.completed_at, "report.completed_at"),
            _timestamp(review.reviewed_at, "review.reviewed_at"),
            _timestamp(approval.approved_at, "approval.approved_at"),
            _timestamp(
                basis_candidate.created_at,
                "basis_candidate.created_at",
            ),
            _timestamp(
                basis_calibration.completed_at,
                "basis_calibration.completed_at",
            ),
            _timestamp(basis_report.completed_at, "basis_report.completed_at"),
            _timestamp(basis_review.reviewed_at, "basis_review.reviewed_at"),
        )
        if any(value > admitted for value in evidence_times):
            raise ContractError("Profile Gate evidence is dated after admission")
        expires = min(
            _timestamp(calibration.expires_at, "calibration.expires_at"),
            _timestamp(report.expires_at, "report.expires_at"),
            admitted + timedelta(seconds=gate_policy.max_profile_ttl_seconds),
        )
        if approval.expires_at is not None:
            expires = min(
                expires,
                _timestamp(approval.expires_at, "approval.expires_at"),
            )
        if expires <= admitted:
            raise ContractError("Profile Gate evidence is expired")
        expires_at = expires.strftime(_UTC_FORMAT)
        if not (
            calibration.completed_at <= report.completed_at <= review.reviewed_at
            and basis_calibration.completed_at
            <= basis_report.completed_at
            <= basis_review.reviewed_at
            <= approval.approved_at
        ):
            raise ContractError("Profile Gate evidence time order is invalid")

        revoked = _revoked_at(ledger, trusted_admitted_at)
        replace_approval_sha256: str | None = None
        try:
            mapped_approval = self._store.resolve_approval(
                approval.subject_sha256
            )
        except ProfileStoreError as exc:
            if exc.code is not ProfileStoreErrorCode.APPROVAL_NOT_FOUND:
                raise
            mapped_approval = None
        if mapped_approval is None:
            approval_reused = False
        elif mapped_approval.approval_sha256 == approval.content_sha256:
            approval_reused = True
        else:
            previous_approval = _load_contract(
                self._store,
                mapped_approval.approval_sha256,
                SemanticApprovalRecord,
            )
            previous_expired = (
                previous_approval.expires_at is not None
                and previous_approval.expires_at <= trusted_admitted_at
            )
            previous_revoked = (
                previous_approval.content_sha256
                in revoked.get(RevocationTargetKind.APPROVAL, frozenset())
            )
            if not previous_expired and not previous_revoked:
                raise ContractError(
                    "semantic subject already has a current trusted approval"
                )
            replace_approval_sha256 = previous_approval.content_sha256
            approval_reused = False
        if not approval_reused:
            validate_approval_basis(approval, bundle, review, report)
        pre_profile_targets = {
            RevocationTargetKind.ADAPTER: {
                item.content_sha256 for item in candidate.profile_graph.adapters
            },
            RevocationTargetKind.APPROVAL: {approval.content_sha256},
            RevocationTargetKind.QUALIFICATION: {
                report.content_sha256,
                basis_report.content_sha256,
            },
            RevocationTargetKind.REVIEW: {
                review.content_sha256,
                basis_review.content_sha256,
            },
        }
        for kind, hashes in pre_profile_targets.items():
            if hashes.intersection(revoked.get(kind, frozenset())):
                raise ContractError(f"Profile Gate evidence is revoked: {kind.value}")

        graph = candidate.profile_graph
        profile = freeze_profile(
            candidate,
            report,
            bundle,
            review,
            approval,
            created_at=trusted_admitted_at,
            expires_at=expires_at,
            approval_basis_review=basis_review,
            approval_basis_review_bundle=basis_bundle,
            approval_basis_qualification_report=basis_report,
        )

        oracle_specs = tuple(
            _load_contract(self._store, item.content_sha256, OracleSpec)
            for item in graph.oracle_specs
        )
        oracle_bundles = tuple(
            _load_contract(self._store, item.content_sha256, OracleBundle)
            for item in graph.oracle_bundles
        )
        recipes = tuple(
            _load_contract(self._store, item.content_sha256, ExecutionRecipe)
            for item in graph.execution_recipes
        )
        validate_frozen_profile_contracts(
            profile,
            oracle_specs=oracle_specs,
            oracle_bundles=oracle_bundles,
            execution_recipes=recipes,
        )
        _verify_all_references(
            self._store,
            (
                candidate.to_document(),
                policy.to_document(),
                plan.to_document(),
                calibration.to_document(),
                report.to_document(),
                bundle.to_document(),
                basis_candidate.to_document(),
                basis_policy.to_document(),
                basis_plan.to_document(),
                basis_calibration.to_document(),
                basis_report.to_document(),
                basis_bundle.to_document(),
                ledger.to_document(),
                *(item.to_document() for item in oracle_specs),
                *(item.to_document() for item in oracle_bundles),
                *(item.to_document() for item in recipes),
            ),
        )
        if profile.content_sha256 in revoked.get(
            RevocationTargetKind.PROFILE, frozenset()
        ):
            raise ContractError("new profile is already revoked")

        expected_actor_role = {
            ApprovalAuthorityKind.HARNESS: SetupActorRole.HARNESS,
            ApprovalAuthorityKind.MAINTAINER: SetupActorRole.MAINTAINER,
        }[gate_policy.admission_authority_kind]
        final_transitions = list(lifecycle.transitions)
        _transition(
            final_transitions,
            to_state=SetupState.FROZEN,
            actor_role=expected_actor_role,
            actor_id=gate_policy.admission_authority_id,
            evidence_sha256=canonical_sha256(
                {
                    "profile_gate_subject_sha256": staged.content_sha256,
                    "approval_sha256": approval.content_sha256,
                }
            ),
            occurred_at=trusted_admitted_at,
        )
        final_lifecycle = _lifecycle(candidate, final_transitions)
        _stage_contract(self._store, final_lifecycle)

        qualification_proofs = tuple(
            {
                item.content_sha256: item
                for item in (
                    *current_qualification_proofs,
                    *basis_qualification_proofs,
                )
            }.values()
        )
        review_proofs = tuple(
            {
                item.content_sha256: item
                for item in (current_review_proof, basis_review_proof)
            }.values()
        )
        for proof in (
            *qualification_proofs,
            *review_proofs,
            approval_proof,
            *revocation_proofs,
            static_profile_proof,
        ):
            _stage_contract(self._store, proof)
        provisional_admission = ProfileAdmissionRecord(
            admission_id=f"{candidate.setup_id}.admission",
            setup_id=candidate.setup_id,
            trust_tier=candidate.trust_tier,
            candidate_sha256=candidate.content_sha256,
            profile=profile.ref,
            qualification_report_sha256=report.content_sha256,
            review_sha256=review.content_sha256,
            approval_sha256=approval.content_sha256,
            invalidation_manifest_sha256=manifest.content_sha256,
            lifecycle_sha256=final_lifecycle.content_sha256,
            gate_policy_sha256=gate_policy.content_sha256,
            gate_verification_receipt_sha256=canonical_sha256(
                {"state": "pending_gate_verification_receipt"}
            ),
            revocation_ledger_sha256=ledger.content_sha256,
            declared_permissions=candidate.declared_permissions,
            effective_permissions=request.effective_permissions,
            admission_authority_kind=gate_policy.admission_authority_kind,
            admission_authority_id=gate_policy.admission_authority_id,
            admitted_at=trusted_admitted_at,
            qualification_expires_at=report.expires_at,
            approval_expires_at=approval.expires_at,
            expires_at=expires_at,
        )
        gate_verification_receipt = GateVerificationReceipt(
            gate_policy_sha256=gate_policy.content_sha256,
            gate_role_policy_sha256=request.role_policy.content_sha256,
            staged_graph_sha256=staged.content_sha256,
            profile_sha256=profile.content_sha256,
            admission_claims_sha256=_admission_claims_sha256(
                provisional_admission
            ),
            qualification_proof_sha256=tuple(
                item.content_sha256 for item in qualification_proofs
            ),
            review_proof_sha256=tuple(
                item.content_sha256 for item in review_proofs
            ),
            approval_proof_sha256=approval_proof.content_sha256,
            revocation_proof_sha256=tuple(
                item.content_sha256 for item in revocation_proofs
            ),
            static_profile_proof_sha256=static_profile_proof.content_sha256,
            verified_at=trusted_admitted_at,
        )
        _stage_contract(self._store, gate_verification_receipt)
        admission = replace(
            provisional_admission,
            gate_verification_receipt_sha256=(
                gate_verification_receipt.content_sha256
            ),
        )
        if (
            _admission_claims_sha256(admission)
            != gate_verification_receipt.admission_claims_sha256
        ):
            raise ContractError("Gate receipt admission claims are misbound")
        if admission.content_sha256 in revoked.get(
            RevocationTargetKind.ADMISSION, frozenset()
        ):
            raise ContractError("new profile admission is already revoked")
        validate_profile_admission_graph(
            candidate,
            profile,
            report,
            bundle,
            review,
            approval,
            basis_bundle,
            basis_review,
            basis_report,
            gate_policy.content_sha256,
            gate_verification_receipt.content_sha256,
            manifest,
            final_lifecycle,
            ledger,
            admission,
        )

        publication = self._store.publish_profile_admission(
            profile_id=profile.profile_id,
            profile_payload=canonical_json_bytes(profile.to_document()),
            profile_sha256=profile.content_sha256,
            admission_payload=canonical_json_bytes(admission.to_document()),
            admission_sha256=admission.content_sha256,
            approval_payload=canonical_json_bytes(approval.to_document()),
            approval_sha256=approval.content_sha256,
            approval_subject_sha256=approval.subject_sha256,
            replace_approval_sha256=replace_approval_sha256,
            expected_previous_ref_sha256=request.expected_previous_ref_sha256,
            expected_revocation_head_sha256=(
                staged.revocation_storage_head_sha256
            ),
        )
        resolved = self._store.resolve_profile_admission(
            profile.profile_id,
            publication.profile_ref.content_sha256,
        )
        resolved_profile = FrozenSystemProfile.from_json(resolved.profile_payload)
        resolved_admission = ProfileAdmissionRecord.from_json(
            resolved.admission_payload
        )
        if resolved_profile != profile or resolved_admission != admission:
            raise ContractError(
                "published profile/admission discovery differs from Gate output"
            )
        return ProfileGateResult(
            profile=profile,
            admission=admission,
            lifecycle=final_lifecycle,
            gate_verification_receipt=gate_verification_receipt,
            profile_ref_sha256=publication.profile_ref.content_sha256,
            approval_reused=publication.approval_reused,
        )


@dataclass(frozen=True)
class ProfileSetupConfiguration:
    setup_session_id: str
    setup_agent_id: str
    qualification_worker_id: str
    effective_permissions: tuple[str, ...]
    admitted_at: str
    expected_previous_ref_sha256: str | None = None

    def __post_init__(self) -> None:
        for field in (
            "setup_session_id",
            "setup_agent_id",
            "qualification_worker_id",
        ):
            validate_identifier(getattr(self, field), field)
        object.__setattr__(
            self,
            "effective_permissions",
            _identifier_collection(
                self.effective_permissions,
                "effective_permissions",
            ),
        )
        _timestamp(self.admitted_at, "admitted_at")
        if self.expected_previous_ref_sha256 is not None:
            validate_sha256(
                self.expected_previous_ref_sha256,
                "expected_previous_ref_sha256",
            )


@dataclass(frozen=True)
class ProfileSetupRunResult:
    lifecycle: SetupLifecycleRecord
    qualification: QualificationProviderResult
    review_bundle: ResultBlindReviewBundle | None
    review: ReviewRecord | None
    approval: SemanticApprovalRecord | None
    gate_result: ProfileGateResult | None

    def __post_init__(self) -> None:
        if type(self.lifecycle) is not SetupLifecycleRecord:
            raise ContractError("lifecycle must be a SetupLifecycleRecord")
        if type(self.qualification) is not QualificationProviderResult:
            raise ContractError(
                "qualification must be a QualificationProviderResult"
            )
        optional_types = (
            (self.review_bundle, ResultBlindReviewBundle, "review_bundle"),
            (self.review, ReviewRecord, "review"),
            (self.approval, SemanticApprovalRecord, "approval"),
            (self.gate_result, ProfileGateResult, "gate_result"),
        )
        for value, expected, field in optional_types:
            if value is not None and type(value) is not expected:
                raise ContractError(f"{field} has an unexpected type")
        if self.lifecycle.final_state is SetupState.FROZEN:
            if any(
                value is None
                for value in (
                    self.review_bundle,
                    self.review,
                    self.approval,
                    self.gate_result,
                )
            ):
                raise ContractError("frozen Setup result lacks admitted evidence")
        elif self.gate_result is not None:
            raise ContractError("non-frozen Setup result cannot contain Gate result")


def _transition(
    transitions: list[SetupStateTransition],
    *,
    to_state: SetupState,
    actor_role: SetupActorRole,
    actor_id: str,
    evidence_sha256: str,
    occurred_at: str,
) -> None:
    from_state = (
        SetupState.DRAFT if not transitions else transitions[-1].to_state
    )
    transitions.append(
        SetupStateTransition(
            sequence=len(transitions) + 1,
            from_state=from_state,
            to_state=to_state,
            actor_role=actor_role,
            actor_id=actor_id,
            evidence_sha256=evidence_sha256,
            occurred_at=occurred_at,
        )
    )


def _lifecycle(
    candidate: ProfileSetupCandidate,
    transitions: list[SetupStateTransition],
) -> SetupLifecycleRecord:
    updated_at = candidate.created_at if not transitions else transitions[-1].occurred_at
    return SetupLifecycleRecord(
        candidate_sha256=candidate.content_sha256,
        trust_tier=candidate.trust_tier,
        transitions=tuple(transitions),
        final_state=(
            SetupState.DRAFT if not transitions else transitions[-1].to_state
        ),
        created_at=candidate.created_at,
        updated_at=updated_at,
    )


def _stage_contract(store: ProfileStore, value: object) -> str:
    document = value.to_document()
    digest = value.content_sha256
    stored = store.put_canonical_document(document)
    if stored.sha256 != digest:
        raise ContractError("ProfileStore changed canonical staged bytes")
    return digest


def _build_review_bundle(
    candidate: ProfileSetupCandidate,
    policy: QualificationPolicy,
    plan: QualificationPlan,
    calibration: CalibrationReport,
    report: QualificationReport,
    material: ReviewMaterial,
) -> ResultBlindReviewBundle:
    return build_result_blind_review_bundle(
        bundle_id=material.bundle_id,
        candidate=candidate,
        qualification_policy=policy,
        qualification_plan=plan,
        calibration_report=calibration,
        qualification_report=report,
        adapter_diff=material.adapter_diff,
        static_scan=material.static_scan,
        healthy_relation=material.healthy_relation,
        qualification_design_sha256=material.qualification_design_sha256,
        invalidation_manifest_sha256=material.invalidation_manifest_sha256,
        known_limitations=material.known_limitations,
    )


def _validate_setup_run_inputs(
    *,
    configuration: object,
    candidate: object,
    qualification_policy: object,
    qualification_plan: object,
    review_material: object,
    invalidation_manifest: object,
    revocation_ledger: object,
) -> None:
    expected = (
        (configuration, ProfileSetupConfiguration, "configuration"),
        (candidate, ProfileSetupCandidate, "candidate"),
        (qualification_policy, QualificationPolicy, "qualification_policy"),
        (qualification_plan, QualificationPlan, "qualification_plan"),
        (review_material, ReviewMaterial, "review_material"),
        (
            invalidation_manifest,
            DependencyInvalidationManifest,
            "invalidation_manifest",
        ),
        (revocation_ledger, RevocationLedger, "revocation_ledger"),
    )
    for value, value_type, field in expected:
        if type(value) is not value_type:
            raise ContractError(f"{field} must be {value_type.__name__}")
    if (
        review_material.invalidation_manifest_sha256
        != invalidation_manifest.content_sha256
    ):
        raise ContractError("review material does not bind invalidation manifest")
    validate_invalidation_manifest_graph(candidate, invalidation_manifest)


class ProfileSetupCoordinator:
    """One governed draft-to-freeze Setup lifecycle."""

    def __init__(
        self,
        *,
        store: ProfileStore,
        providers: ProfileSetupProviders,
        gate_policy: ProfileGatePolicy,
        revocation_verifier: RevocationSignatureVerifier,
        approval_verifier: SemanticApprovalVerifier,
        qualification_evidence_verifier: QualificationEvidenceVerifier,
        review_verifier: ReviewVerifier,
        static_profile_verifier: StaticProfileVerifier,
        authority_receipt_validator: AuthorityReceiptValidator,
        clock: Callable[[], str],
    ) -> None:
        if type(store) is not ProfileStore:
            raise ContractError("store must be a ProfileStore")
        if type(providers) is not ProfileSetupProviders:
            raise ContractError("providers must be ProfileSetupProviders")
        if type(gate_policy) is not ProfileGatePolicy:
            raise ContractError("gate_policy must be a ProfileGatePolicy")
        for verifier, field in (
            (revocation_verifier, "revocation_verifier"),
            (approval_verifier, "approval_verifier"),
            (qualification_evidence_verifier, "qualification_evidence_verifier"),
            (review_verifier, "review_verifier"),
            (static_profile_verifier, "static_profile_verifier"),
            (authority_receipt_validator, "authority_receipt_validator"),
        ):
            if not callable(verifier):
                raise ContractError(f"{field} must be callable")
        if not callable(clock):
            raise ContractError("clock must be callable")
        self._store = store
        self._providers = providers
        self._gate_policy = gate_policy
        self._revocation_verifier = revocation_verifier
        self._approval_verifier = approval_verifier
        self._qualification_evidence_verifier = qualification_evidence_verifier
        self._review_verifier = review_verifier
        self._static_profile_verifier = static_profile_verifier
        self._authority_receipt_validator = authority_receipt_validator
        self._clock = clock
        self._gate = ProfileGate(
            store,
            gate_policy,
            authority_receipt_validator,
            clock,
        )

    def run(
        self,
        *,
        configuration: ProfileSetupConfiguration,
        candidate: ProfileSetupCandidate,
        qualification_policy: QualificationPolicy,
        qualification_plan: QualificationPlan,
        review_material: ReviewMaterial,
        invalidation_manifest: DependencyInvalidationManifest,
        revocation_ledger: RevocationLedger,
    ) -> ProfileSetupRunResult:
        try:
            _validate_setup_run_inputs(
                configuration=configuration,
                candidate=candidate,
                qualification_policy=qualification_policy,
                qualification_plan=qualification_plan,
                review_material=review_material,
                invalidation_manifest=invalidation_manifest,
                revocation_ledger=revocation_ledger,
            )
        except ContractError as exc:
            _raise(ProfileSetupFailureCode.INVALID_INPUT, str(exc), exc)

        try:
            trusted_preflight_at = self._clock()
        except Exception as exc:
            _raise(
                ProfileSetupFailureCode.PROFILE_GATE_AUTHORITY_FAILED,
                "Profile Setup authority clock failed",
                exc,
            )
        try:
            _timestamp(trusted_preflight_at, "trusted_preflight_at")
            if revocation_ledger.created_at > trusted_preflight_at:
                raise ContractError("revocation ledger is dated after Setup preflight")
            for value, value_type in (
                (candidate, ProfileSetupCandidate),
                (qualification_policy, QualificationPolicy),
                (qualification_plan, QualificationPlan),
                (invalidation_manifest, DependencyInvalidationManifest),
                (revocation_ledger, RevocationLedger),
                (self._gate_policy, ProfileGatePolicy),
            ):
                _stage_contract(self._store, value)
                if _load_contract(
                    self._store,
                    value.content_sha256,
                    value_type,
                ) != value:
                    raise ContractError("staged Setup input did not round-trip")
            head = self._store.revocation_head()
            storage_head_sha256 = (
                None if head is None else head.content_sha256
            )
            revocation_proofs = _validate_revocation_view(
                self._store,
                storage_head_sha256,
                revocation_ledger,
                self._revocation_verifier,
                self._gate_policy.revocation_authority_policy_sha256,
            )
            for proof in revocation_proofs:
                _stage_contract(self._store, proof)
                _validate_authority_receipt(
                    store=self._store,
                    proof=proof,
                    validator=self._authority_receipt_validator,
                )
            static_profile_proof = _verify_static_profile(
                candidate=candidate,
                static_scan=review_material.static_scan,
                verifier=self._static_profile_verifier,
                authority_policy_sha256=(
                    self._gate_policy.static_profile_authority_policy_sha256
                ),
            )
            _stage_contract(self._store, static_profile_proof)
            _validate_authority_receipt(
                store=self._store,
                proof=static_profile_proof,
                validator=self._authority_receipt_validator,
            )
            _verify_all_references(
                self._store,
                (
                    candidate.to_document(),
                    qualification_policy.to_document(),
                    qualification_plan.to_document(),
                    review_material.static_scan.to_document(),
                ),
            )
            revoked = _revoked_at(revocation_ledger, trusted_preflight_at)
            adapter_hashes = {
                item.content_sha256 for item in candidate.profile_graph.adapters
            }
            if adapter_hashes.intersection(
                revoked.get(RevocationTargetKind.ADAPTER, frozenset())
            ):
                raise ContractError("candidate Adapter is already revoked")
        except _AuthorityServiceError as exc:
            _raise(
                ProfileSetupFailureCode.PROFILE_GATE_AUTHORITY_FAILED,
                str(exc),
                exc,
            )
        except ProfileStoreError as exc:
            _raise(ProfileSetupFailureCode.STORAGE_FAILURE, str(exc), exc)
        except ContractError as exc:
            _raise(ProfileSetupFailureCode.PROFILE_GATE_REJECTED, str(exc), exc)

        prequalification_authorization_sha256 = (
            _prequalification_authorization_sha256(
                candidate_sha256=candidate.content_sha256,
                policy_sha256=qualification_policy.content_sha256,
                plan_sha256=qualification_plan.content_sha256,
                static_proof_sha256=static_profile_proof.content_sha256,
                revocation_proof_sha256=tuple(
                    item.content_sha256 for item in revocation_proofs
                ),
                revocation_storage_head_sha256=storage_head_sha256,
                revocation_ledger_sha256=revocation_ledger.content_sha256,
                invalidation_manifest_sha256=(
                    invalidation_manifest.content_sha256
                ),
                gate_policy_sha256=self._gate_policy.content_sha256,
            )
        )

        transitions: list[SetupStateTransition] = []
        _transition(
            transitions,
            to_state=SetupState.QUALIFYING,
            actor_role=SetupActorRole.SETUP_AGENT,
            actor_id=configuration.setup_agent_id,
            evidence_sha256=candidate.content_sha256,
            occurred_at=candidate.created_at,
        )
        qualification_role = build_setup_role_policy(
            SetupRole.QUALIFICATION_WORKER,
            setup_session_id=configuration.setup_session_id,
            subject_sha256=prequalification_authorization_sha256,
            governance_policy_sha256=self._gate_policy.content_sha256,
        )
        qualification_request = QualificationProviderRequest(
            setup_session_id=configuration.setup_session_id,
            candidate=candidate,
            policy=qualification_policy,
            plan=qualification_plan,
            prequalification_authorization_sha256=(
                prequalification_authorization_sha256
            ),
            role_policy=qualification_role,
        )
        try:
            qualification = self._providers.qualification(qualification_request)
        except Exception as exc:
            _raise(
                ProfileSetupFailureCode.QUALIFICATION_PROVIDER_FAILED,
                "qualification provider failed",
                exc,
            )
        if type(qualification) is not QualificationProviderResult:
            _raise(
                ProfileSetupFailureCode.QUALIFICATION_RESULT_INVALID,
                "qualification provider returned an unexpected type",
            )
        try:
            validate_qualification_graph(
                candidate,
                qualification_policy,
                qualification_plan,
                qualification.calibration,
                qualification.report,
            )
            verify_qualification_report(
                policy=qualification_policy,
                plan=qualification_plan,
                calibration_report=qualification.calibration,
                report=qualification.report,
            )
        except ContractError as exc:
            _raise(
                ProfileSetupFailureCode.QUALIFICATION_RESULT_INVALID,
                str(exc),
                exc,
            )
        try:
            for value, value_type in (
                (qualification.calibration, CalibrationReport),
                (qualification.report, QualificationReport),
                (qualification_role, SetupRolePolicy),
            ):
                _stage_contract(self._store, value)
                if _load_contract(
                    self._store,
                    value.content_sha256,
                    value_type,
                ) != value:
                    raise ContractError(
                        "staged qualification evidence did not round-trip"
                    )
            current_qualification_proofs = _verify_qualification_evidence(
                candidate=candidate,
                policy=qualification_policy,
                plan=qualification_plan,
                calibration=qualification.calibration,
                report=qualification.report,
                role_policy=qualification_role,
                prequalification_authorization_sha256=(
                    prequalification_authorization_sha256
                ),
                verifier=self._qualification_evidence_verifier,
                authority_policy_sha256=(
                    self._gate_policy.
                    qualification_evidence_authority_policy_sha256
                ),
            )
            for proof in current_qualification_proofs:
                _stage_contract(self._store, proof)
                _validate_authority_receipt(
                    store=self._store,
                    proof=proof,
                    validator=self._authority_receipt_validator,
                )
        except _AuthorityServiceError as exc:
            _raise(
                ProfileSetupFailureCode.PROFILE_GATE_AUTHORITY_FAILED,
                str(exc),
                exc,
            )
        except ProfileStoreError as exc:
            _raise(ProfileSetupFailureCode.STORAGE_FAILURE, str(exc), exc)
        except ContractError as exc:
            _raise(
                ProfileSetupFailureCode.QUALIFICATION_RESULT_INVALID,
                str(exc),
                exc,
            )
        qualification_authorization_sha256 = (
            _qualification_authorization_sha256(
                prequalification_authorization_sha256=(
                    prequalification_authorization_sha256
                ),
                calibration_report_sha256=(
                    qualification.calibration.content_sha256
                ),
                qualification_report_sha256=(
                    qualification.report.content_sha256
                ),
                qualification_proof_sha256=tuple(
                    item.content_sha256
                    for item in current_qualification_proofs
                ),
            )
        )
        if qualification.report.verdict is QualificationVerdict.FAIL:
            _transition(
                transitions,
                to_state=SetupState.NEEDS_REVISION,
                actor_role=SetupActorRole.QUALIFICATION_WORKER,
                actor_id=configuration.qualification_worker_id,
                evidence_sha256=qualification.report.content_sha256,
                occurred_at=qualification.report.completed_at,
            )
            return ProfileSetupRunResult(
                lifecycle=_lifecycle(candidate, transitions),
                qualification=qualification,
                review_bundle=None,
                review=None,
                approval=None,
                gate_result=None,
            )

        _transition(
            transitions,
            to_state=SetupState.AWAITING_REVIEW,
            actor_role=SetupActorRole.QUALIFICATION_WORKER,
            actor_id=configuration.qualification_worker_id,
            evidence_sha256=qualification.report.content_sha256,
            occurred_at=qualification.report.completed_at,
        )
        try:
            review_bundle = _build_review_bundle(
                candidate,
                qualification_policy,
                qualification_plan,
                qualification.calibration,
                qualification.report,
                review_material,
            )
        except (ContractError, TypeError, ValueError) as exc:
            _raise(ProfileSetupFailureCode.REVIEW_RESULT_INVALID, str(exc), exc)
        review_role = build_setup_role_policy(
            SetupRole.REVIEWER,
            setup_session_id=configuration.setup_session_id,
            subject_sha256=qualification_authorization_sha256,
            governance_policy_sha256=self._gate_policy.content_sha256,
        )
        review_request = ReviewProviderRequest(
            setup_session_id=configuration.setup_session_id,
            bundle=review_bundle,
            qualification_authorization_sha256=(
                qualification_authorization_sha256
            ),
            role_policy=review_role,
        )
        try:
            for value in (review_bundle, review_role):
                _stage_contract(self._store, value)
            head = self._store.revocation_head()
            if (
                None if head is None else head.content_sha256
            ) != storage_head_sha256:
                raise ContractError("revocation head changed before review")
        except ProfileStoreError as exc:
            _raise(ProfileSetupFailureCode.STORAGE_FAILURE, str(exc), exc)
        except ContractError as exc:
            _raise(ProfileSetupFailureCode.PROFILE_GATE_REJECTED, str(exc), exc)
        try:
            review = self._providers.review(review_request)
        except Exception as exc:
            _raise(
                ProfileSetupFailureCode.REVIEW_PROVIDER_FAILED,
                "review provider failed",
                exc,
            )
        if type(review) is not ReviewRecord:
            _raise(
                ProfileSetupFailureCode.REVIEW_RESULT_INVALID,
                "review provider returned an unexpected type",
            )
        try:
            validate_review_graph(
                candidate,
                qualification.report,
                review_bundle,
                review,
            )
            validate_result_blind_review_record(review_bundle, review)
        except ContractError as exc:
            _raise(ProfileSetupFailureCode.REVIEW_RESULT_INVALID, str(exc), exc)
        try:
            _stage_contract(self._store, review)
            if _load_contract(
                self._store,
                review.content_sha256,
                ReviewRecord,
            ) != review:
                raise ContractError("staged review did not round-trip")
            if review.reviewer_session_id in (
                configuration.setup_session_id,
                candidate.setup_id,
            ):
                raise ContractError("review session is not independent from Setup")
            if (
                review.reviewer_authority
                not in self._gate_policy.allowed_reviewer_authorities
                or review.model_id
                not in self._gate_policy.allowed_reviewer_models
            ):
                raise ContractError("review authority or model is not allowlisted")
            current_review_proof = _verify_review(
                bundle=review_bundle,
                review=review,
                role_policy=review_role,
                excluded_setup_session_id=configuration.setup_session_id,
                qualification_authorization_sha256=(
                    qualification_authorization_sha256
                ),
                verifier=self._review_verifier,
                authority_policy_sha256=(
                    self._gate_policy.review_authority_policy_sha256
                ),
            )
            _stage_contract(self._store, current_review_proof)
            _validate_authority_receipt(
                store=self._store,
                proof=current_review_proof,
                validator=self._authority_receipt_validator,
            )
        except _AuthorityServiceError as exc:
            _raise(
                ProfileSetupFailureCode.PROFILE_GATE_AUTHORITY_FAILED,
                str(exc),
                exc,
            )
        except ProfileStoreError as exc:
            _raise(ProfileSetupFailureCode.STORAGE_FAILURE, str(exc), exc)
        except ContractError as exc:
            _raise(ProfileSetupFailureCode.REVIEW_RESULT_INVALID, str(exc), exc)
        review_authorization_sha256 = _review_authorization_sha256(
            qualification_authorization_sha256=(
                qualification_authorization_sha256
            ),
            review_bundle_sha256=review_bundle.content_sha256,
            review_sha256=review.content_sha256,
            review_proof_sha256=current_review_proof.content_sha256,
        )
        if review.verdict is not ReviewVerdict.APPROVE:
            _transition(
                transitions,
                to_state=SetupState.NEEDS_REVISION,
                actor_role=SetupActorRole.REVIEWER,
                actor_id=review.reviewer_authority,
                evidence_sha256=review.content_sha256,
                occurred_at=review.reviewed_at,
            )
            return ProfileSetupRunResult(
                lifecycle=_lifecycle(candidate, transitions),
                qualification=qualification,
                review_bundle=review_bundle,
                review=review,
                approval=None,
                gate_result=None,
            )

        _transition(
            transitions,
            to_state=SetupState.AWAITING_APPROVAL,
            actor_role=SetupActorRole.REVIEWER,
            actor_id=review.reviewer_authority,
            evidence_sha256=review.content_sha256,
            occurred_at=review.reviewed_at,
        )
        subject = make_review_subject(candidate)
        try:
            reuse = self._store.resolve_approval(subject.content_sha256)
        except ProfileStoreError as exc:
            if exc.code is not ProfileStoreErrorCode.APPROVAL_NOT_FOUND:
                _raise(ProfileSetupFailureCode.STORAGE_FAILURE, str(exc), exc)
            reuse = None
        if reuse is not None:
            try:
                existing_approval = _load_contract(
                    self._store,
                    reuse.approval_sha256,
                    SemanticApprovalRecord,
                )
            except (ProfileStoreError, ContractError) as exc:
                _raise(ProfileSetupFailureCode.STORAGE_FAILURE, str(exc), exc)
            revoked_approvals = _revoked_at(
                revocation_ledger,
                trusted_preflight_at,
            ).get(RevocationTargetKind.APPROVAL, frozenset())
            existing_unusable = (
                existing_approval.content_sha256 in revoked_approvals
                or (
                    existing_approval.expires_at is not None
                    and existing_approval.expires_at <= trusted_preflight_at
                )
            )
            approval = None if existing_unusable else existing_approval
        else:
            approval = None
        if approval is None:
            approval_request = ApprovalProviderRequest(
                setup_session_id=configuration.setup_session_id,
                trust_tier=candidate.trust_tier,
                semantic_subject_sha256=subject.content_sha256,
                qualification_report_sha256=qualification.report.content_sha256,
                review_sha256=review.content_sha256,
                qualification_proof_sha256=tuple(
                    item.content_sha256
                    for item in current_qualification_proofs
                ),
                review_proof_sha256=current_review_proof.content_sha256,
                review_authorization_sha256=review_authorization_sha256,
            )
            try:
                head = self._store.revocation_head()
                if (
                    None if head is None else head.content_sha256
                ) != storage_head_sha256:
                    raise ContractError("revocation head changed before approval")
            except ProfileStoreError as exc:
                _raise(ProfileSetupFailureCode.STORAGE_FAILURE, str(exc), exc)
            except ContractError as exc:
                _raise(
                    ProfileSetupFailureCode.PROFILE_GATE_REJECTED,
                    str(exc),
                    exc,
                )
            try:
                approval = self._providers.approval(approval_request)
            except Exception as exc:
                _raise(
                    ProfileSetupFailureCode.APPROVAL_PROVIDER_FAILED,
                    "approval provider failed",
                    exc,
                )
            if type(approval) is SemanticApprovalRecord:
                try:
                    validate_approval_basis(
                        approval,
                        review_bundle,
                        review,
                        qualification.report,
                    )
                except ContractError as exc:
                    _raise(
                        ProfileSetupFailureCode.APPROVAL_RESULT_INVALID,
                        str(exc),
                        exc,
                    )
        if type(approval) is not SemanticApprovalRecord:
            _raise(
                ProfileSetupFailureCode.APPROVAL_RESULT_INVALID,
                "approval provider/store returned an unexpected type",
            )
        expected_approval = (
            candidate.trust_tier,
            subject.content_sha256,
        )
        if (approval.trust_tier, approval.subject_sha256) != expected_approval:
            _raise(
                ProfileSetupFailureCode.APPROVAL_RESULT_INVALID,
                "approval does not bind the exact semantic subject",
            )
        if approval.decision is ApprovalDecision.REJECT:
            _transition(
                transitions,
                to_state=SetupState.NEEDS_REVISION,
                actor_role={
                    ApprovalAuthorityKind.HUMAN: SetupActorRole.HUMAN,
                    ApprovalAuthorityKind.HARNESS: SetupActorRole.HARNESS,
                    ApprovalAuthorityKind.MAINTAINER: SetupActorRole.MAINTAINER,
                }[approval.authority_kind],
                actor_id=approval.authority_id,
                evidence_sha256=approval.content_sha256,
                occurred_at=approval.approved_at,
            )
            return ProfileSetupRunResult(
                lifecycle=_lifecycle(candidate, transitions),
                qualification=qualification,
                review_bundle=review_bundle,
                review=review,
                approval=approval,
                gate_result=None,
            )
        try:
            validate_approval_graph(candidate, approval)
        except ContractError as exc:
            _raise(ProfileSetupFailureCode.APPROVAL_RESULT_INVALID, str(exc), exc)

        try:
            _stage_contract(self._store, approval)
            if _load_contract(
                self._store,
                approval.content_sha256,
                SemanticApprovalRecord,
            ) != approval:
                raise ContractError("staged approval did not round-trip")
            if (
                approval.basis_review_sha256 == review.content_sha256
                and approval.basis_qualification_report_sha256
                == qualification.report.content_sha256
            ):
                basis_qualification_proofs = current_qualification_proofs
                basis_review_proof = current_review_proof
                basis_qualification_authorization_sha256 = (
                    qualification_authorization_sha256
                )
                basis_review_authorization_sha256 = (
                    review_authorization_sha256
                )
            else:
                resolved_prior = self._store.resolve_profile_admission(
                    candidate.profile_graph.profile_id
                )
                prior_admission = ProfileAdmissionRecord.from_json(
                    resolved_prior.admission_payload
                )
                if prior_admission.approval_sha256 != approval.content_sha256:
                    raise ContractError(
                        "reused approval has no current admitted proof chain"
                    )
                prior_receipt = _load_contract(
                    self._store,
                    prior_admission.gate_verification_receipt_sha256,
                    GateVerificationReceipt,
                )
                prior_staged = _load_contract(
                    self._store,
                    prior_receipt.staged_graph_sha256,
                    StagedProfileGateGraph,
                )
                if (
                    prior_staged.approval_sha256
                    != approval.content_sha256
                ):
                    raise ContractError("prior staged approval is misbound")
                basis_qualification_proofs = tuple(
                    _load_contract(
                        self._store,
                        digest,
                        QualificationEvidenceVerificationProof,
                    )
                    for digest in (
                        prior_staged.current_qualification_proof_sha256
                    )
                )
                basis_review_proof = _load_contract(
                    self._store,
                    prior_staged.current_review_proof_sha256,
                    ReviewVerificationProof,
                )
                for proof in (
                    *basis_qualification_proofs,
                    basis_review_proof,
                ):
                    _validate_authority_receipt(
                        store=self._store,
                        proof=proof,
                        validator=self._authority_receipt_validator,
                    )
                if (
                    basis_review_proof.review_sha256
                    != approval.basis_review_sha256
                    or any(
                        item.qualification_report_sha256
                        != approval.basis_qualification_report_sha256
                        for item in basis_qualification_proofs
                    )
                ):
                    raise ContractError("reused approval proof chain is misbound")
                basis_qualification_authorization_sha256 = (
                    prior_staged.qualification_authorization_sha256
                )
                basis_review_authorization_sha256 = (
                    prior_staged.review_authorization_sha256
                )

            approval_verification_request = (
                SemanticApprovalVerificationRequest(
                    approval=approval,
                    semantic_subject_sha256=subject.content_sha256,
                    qualification_proof_sha256=tuple(
                        item.content_sha256
                        for item in basis_qualification_proofs
                    ),
                    review_proof_sha256=basis_review_proof.content_sha256,
                    review_authorization_sha256=(
                        basis_review_authorization_sha256
                    ),
                    authority_policy_sha256=(
                        self._gate_policy.approval_authority_policy_sha256
                    ),
                )
            )
            try:
                approval_proof = self._approval_verifier(
                    approval_verification_request
                )
            except Exception as exc:
                raise _AuthorityServiceError(
                    "semantic approval verifier failed"
                ) from exc
            if type(approval_proof) is not SemanticApprovalVerificationProof:
                raise ContractError(
                    "approval verifier returned an unexpected proof type"
                )
            approval_proof.validate_request(approval_verification_request)
            _stage_contract(self._store, approval_proof)
            _validate_authority_receipt(
                store=self._store,
                proof=approval_proof,
                validator=self._authority_receipt_validator,
            )
        except _AuthorityServiceError as exc:
            _raise(
                ProfileSetupFailureCode.PROFILE_GATE_AUTHORITY_FAILED,
                str(exc),
                exc,
            )
        except ProfileStoreError as exc:
            _raise(ProfileSetupFailureCode.STORAGE_FAILURE, str(exc), exc)
        except ContractError as exc:
            _raise(ProfileSetupFailureCode.APPROVAL_RESULT_INVALID, str(exc), exc)

        lifecycle = _lifecycle(candidate, transitions)

        try:
            for value in (
                candidate,
                qualification_policy,
                qualification_plan,
                qualification.calibration,
                qualification.report,
                review_bundle,
                review,
                approval,
                invalidation_manifest,
                lifecycle,
                revocation_ledger,
                self._gate_policy,
                qualification_role,
                review_role,
                *current_qualification_proofs,
                *basis_qualification_proofs,
                current_review_proof,
                basis_review_proof,
                approval_proof,
                *revocation_proofs,
                static_profile_proof,
            ):
                _stage_contract(self._store, value)
            head = self._store.revocation_head()
            final_storage_head_sha256 = (
                None if head is None else head.content_sha256
            )
            if final_storage_head_sha256 != storage_head_sha256:
                raise ContractError(
                    "revocation head changed during Profile Setup"
                )
        except ProfileStoreError as exc:
            _raise(ProfileSetupFailureCode.STORAGE_FAILURE, str(exc), exc)
        except ContractError as exc:
            _raise(ProfileSetupFailureCode.STORAGE_FAILURE, str(exc), exc)
        staged = StagedProfileGateGraph(
            candidate_sha256=candidate.content_sha256,
            qualification_policy_sha256=qualification_policy.content_sha256,
            qualification_plan_sha256=qualification_plan.content_sha256,
            calibration_report_sha256=qualification.calibration.content_sha256,
            qualification_report_sha256=qualification.report.content_sha256,
            review_bundle_sha256=review_bundle.content_sha256,
            review_sha256=review.content_sha256,
            approval_sha256=approval.content_sha256,
            invalidation_manifest_sha256=invalidation_manifest.content_sha256,
            lifecycle_sha256=lifecycle.content_sha256,
            revocation_ledger_sha256=revocation_ledger.content_sha256,
            revocation_storage_head_sha256=storage_head_sha256,
            qualification_role_policy_sha256=(
                qualification_role.content_sha256
            ),
            review_role_policy_sha256=review_role.content_sha256,
            prequalification_authorization_sha256=(
                prequalification_authorization_sha256
            ),
            qualification_authorization_sha256=(
                qualification_authorization_sha256
            ),
            review_authorization_sha256=review_authorization_sha256,
            basis_qualification_authorization_sha256=(
                basis_qualification_authorization_sha256
            ),
            basis_review_authorization_sha256=(
                basis_review_authorization_sha256
            ),
            current_qualification_proof_sha256=tuple(
                item.content_sha256 for item in current_qualification_proofs
            ),
            basis_qualification_proof_sha256=tuple(
                item.content_sha256 for item in basis_qualification_proofs
            ),
            current_review_proof_sha256=current_review_proof.content_sha256,
            basis_review_proof_sha256=basis_review_proof.content_sha256,
            approval_proof_sha256=approval_proof.content_sha256,
            revocation_proof_sha256=tuple(
                item.content_sha256 for item in revocation_proofs
            ),
            static_profile_proof_sha256=static_profile_proof.content_sha256,
        )
        try:
            _stage_contract(self._store, staged)
        except (ProfileStoreError, ContractError) as exc:
            _raise(ProfileSetupFailureCode.STORAGE_FAILURE, str(exc), exc)
        gate_role = build_setup_role_policy(
            SetupRole.PROFILE_GATE,
            setup_session_id=configuration.setup_session_id,
            subject_sha256=staged.content_sha256,
            governance_policy_sha256=self._gate_policy.content_sha256,
        )
        try:
            _stage_contract(self._store, gate_role)
        except (ProfileStoreError, ContractError) as exc:
            _raise(ProfileSetupFailureCode.STORAGE_FAILURE, str(exc), exc)
        gate_request = ProfileGateRequest(
            setup_session_id=configuration.setup_session_id,
            staged=staged,
            role_policy=gate_role,
            effective_permissions=configuration.effective_permissions,
            admitted_at=configuration.admitted_at,
            expected_previous_ref_sha256=(
                configuration.expected_previous_ref_sha256
            ),
        )
        gate_result = self._gate.freeze(gate_request)
        return ProfileSetupRunResult(
            lifecycle=gate_result.lifecycle,
            qualification=qualification,
            review_bundle=review_bundle,
            review=review,
            approval=approval,
            gate_result=gate_result,
        )


def run_profile_setup(
    *,
    coordinator: ProfileSetupCoordinator,
    configuration: ProfileSetupConfiguration,
    candidate: ProfileSetupCandidate,
    qualification_policy: QualificationPolicy,
    qualification_plan: QualificationPlan,
    review_material: ReviewMaterial,
    invalidation_manifest: DependencyInvalidationManifest,
    revocation_ledger: RevocationLedger,
) -> ProfileSetupRunResult:
    """Functional API for one complete governed setup lifecycle."""

    if type(coordinator) is not ProfileSetupCoordinator:
        raise ContractError("coordinator must be a ProfileSetupCoordinator")
    return coordinator.run(
        configuration=configuration,
        candidate=candidate,
        qualification_policy=qualification_policy,
        qualification_plan=qualification_plan,
        review_material=review_material,
        invalidation_manifest=invalidation_manifest,
        revocation_ledger=revocation_ledger,
    )


__all__ = [
    "ApprovalProvider",
    "ApprovalProviderRequest",
    "AuthorityReceiptValidationRequest",
    "AuthorityReceiptValidator",
    "GateVerificationReceipt",
    "ProfileGate",
    "ProfileGatePolicy",
    "ProfileGateRequest",
    "ProfileGateResult",
    "ProfileSetupConfiguration",
    "ProfileSetupCoordinator",
    "ProfileSetupError",
    "ProfileSetupFailureCode",
    "ProfileSetupProviders",
    "ProfileSetupRunResult",
    "QualificationProvider",
    "QualificationProviderRequest",
    "QualificationProviderResult",
    "QualificationEvidenceVerifier",
    "QualificationEvidenceVerificationProof",
    "QualificationEvidenceVerificationRequest",
    "ReviewMaterial",
    "ReviewProvider",
    "ReviewProviderRequest",
    "ReviewVerifier",
    "ReviewVerificationProof",
    "ReviewVerificationRequest",
    "RevocationSignatureVerifier",
    "RevocationVerificationProof",
    "RevocationVerificationRequest",
    "SemanticApprovalVerifier",
    "SemanticApprovalVerificationProof",
    "SemanticApprovalVerificationRequest",
    "StagedProfileGateGraph",
    "StaticProfileVerifier",
    "StaticProfileVerificationProof",
    "StaticProfileVerificationRequest",
    "run_profile_setup",
]

"""Host-side lifecycle coordinator for independent B1/B2 validation.

The coordinator is deliberately not a judge.  A trusted Gate provider creates
receipts and Oracle evidence; this module only freezes transport inputs,
allocates role-specific workspaces, validates the resulting contract graph,
enforces the Agent exit barrier, and orders retries.

This first runtime is intentionally single-process.  A process crash abandons
the whole lifecycle; durable journal replay and cross-process fencing belong to
the later production-wiring stage and must not be inferred from these APIs.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from enum import Enum
from threading import Lock
from typing import Callable, Protocol

from ..contracts.base import (
    ContractError,
    canonical_sha256,
    validate_identifier,
    validate_positive_int,
    validate_sha256,
)
from ..contracts.case import (
    CasePlan,
    CaseSubmission,
    CaseSubmissionKind,
    ValidationInstanceIdentity,
    validate_case_submission_membership,
)
from ..contracts.coordinator import (
    CoordinatorRequestEnvelope,
    CoordinatorResponseEnvelope,
)
from ..contracts.evidence import (
    Observation,
    OracleDecision,
    validate_b1_b2_observation_independence,
    validate_oracle_decision_evidence,
)
from ..contracts.oracle import OracleBundle, OracleSpec
from ..contracts.outcome import (
    CrossGateDecision,
    CrossGateVerdict,
    validate_cross_gate_decision,
)
from ..contracts.plan import (
    BaselineSelectionReceipt,
    ExecutionBinding,
    ExperimentPlanTemplate,
    GateRole,
    validate_b1_b2_binding_equivalence,
    validate_execution_binding,
    validate_experiment_plan_membership,
    validate_template_determinism,
)
from ..contracts.profile import FrozenSystemProfile
from ..contracts.receipt import (
    CandidateGateReceipt,
    EarlyGateReceipt,
    EarlyGateStage,
    FastPathGateReceipt,
    GateReceipt,
    validate_b1_b2_gate_receipts,
    validate_candidate_gate_receipt_membership,
    validate_early_gate_receipt_identity,
    validate_fast_path_gate_receipt_identity,
)
from ..contracts.references import ContractRef, ContractRefKind
from ..contracts.snapshot import SnapshotRef
from ..contracts.status import (
    CaseReasonCode,
    CaseStatus,
    GateAttemptDisposition,
)
from .role_policy import WorkspaceRole, build_role_policy
from .mailbox import CoordinatorMailbox, FrozenCoordinatorRequest
from .workspace import (
    WorkspaceAllocation,
    WorkspaceError,
    WorkspaceLineageRecord,
    WorkspaceManager,
    validate_workspace_lineage,
)


_MAX_LIFECYCLES = 1_000
_MAX_SUBMISSIONS_PER_SESSION = 1_000_000
_MAX_TIMEOUT_MS = 86_400_000
_MAX_DIAGNOSTICS = 16


class CoordinatorFailureCode(str, Enum):
    """Failures of orchestration or trust boundaries, never Case verdicts."""

    INVALID_CONFIGURATION = "INVALID_CONFIGURATION"
    INVALID_STATE_TRANSITION = "INVALID_STATE_TRANSITION"
    MAILBOX_FAILURE = "MAILBOX_FAILURE"
    REQUEST_IDENTITY_MISMATCH = "REQUEST_IDENTITY_MISMATCH"
    AGENT_START_FAILED = "AGENT_START_FAILED"
    AGENT_EXITED_EARLY = "AGENT_EXITED_EARLY"
    AGENT_RESPONSE_COMMIT_UNPROVEN = "AGENT_RESPONSE_COMMIT_UNPROVEN"
    AGENT_STOP_FAILED = "AGENT_STOP_FAILED"
    AGENT_TEARDOWN_UNPROVEN = "AGENT_TEARDOWN_UNPROVEN"
    WORKSPACE_ALLOCATION_FAILED = "WORKSPACE_ALLOCATION_FAILED"
    WORKSPACE_RELEASE_FAILED = "WORKSPACE_RELEASE_FAILED"
    GATE_EXECUTION_FAILED = "GATE_EXECUTION_FAILED"
    GATE_RESULT_INVALID = "GATE_RESULT_INVALID"
    EVIDENCE_NOT_PERSISTED = "EVIDENCE_NOT_PERSISTED"
    CROSS_GATE_INVALID = "CROSS_GATE_INVALID"
    CLEANUP_UNPROVEN = "CLEANUP_UNPROVEN"


class CoordinatorError(RuntimeError):
    """Typed fail-closed error outside the normative CaseStatus vocabulary."""

    def __init__(self, code: CoordinatorFailureCode, message: str) -> None:
        if type(code) is not CoordinatorFailureCode:
            raise TypeError("code must be a CoordinatorFailureCode")
        super().__init__(message)
        self.code = code


def _raise(
    code: CoordinatorFailureCode,
    message: str,
    cause: BaseException | None = None,
) -> None:
    error = CoordinatorError(code, message)
    if cause is None:
        raise error
    raise error from cause


class CoordinatorState(str, Enum):
    NEW = "NEW"
    A_RUNNING = "A_RUNNING"
    WAITING_SUBMISSION = "WAITING_SUBMISSION"
    B1_RUNNING = "B1_RUNNING"
    AGENT_EXITING = "AGENT_EXITING"
    AGENT_EXITED = "AGENT_EXITED"
    B2_RUNNING = "B2_RUNNING"
    LIFECYCLE_CLOSED = "LIFECYCLE_CLOSED"
    COMPLETE = "COMPLETE"
    FAILED = "FAILED"


_ALLOWED_TRANSITIONS: dict[CoordinatorState, frozenset[CoordinatorState]] = {
    CoordinatorState.NEW: frozenset((CoordinatorState.A_RUNNING,)),
    CoordinatorState.A_RUNNING: frozenset((CoordinatorState.WAITING_SUBMISSION,)),
    CoordinatorState.WAITING_SUBMISSION: frozenset(
        (CoordinatorState.B1_RUNNING, CoordinatorState.AGENT_EXITING)
    ),
    CoordinatorState.B1_RUNNING: frozenset(
        (CoordinatorState.WAITING_SUBMISSION, CoordinatorState.AGENT_EXITING)
    ),
    CoordinatorState.AGENT_EXITING: frozenset((CoordinatorState.AGENT_EXITED,)),
    CoordinatorState.AGENT_EXITED: frozenset(
        (
            CoordinatorState.B2_RUNNING,
            CoordinatorState.LIFECYCLE_CLOSED,
        )
    ),
    CoordinatorState.B2_RUNNING: frozenset((CoordinatorState.LIFECYCLE_CLOSED,)),
    CoordinatorState.LIFECYCLE_CLOSED: frozenset(
        (CoordinatorState.A_RUNNING, CoordinatorState.COMPLETE)
    ),
    CoordinatorState.COMPLETE: frozenset(),
    CoordinatorState.FAILED: frozenset(),
}


class GatePreflightState(str, Enum):
    INTAKE_INVALID = "INTAKE_INVALID"
    MEMBERSHIP_INVALID = "MEMBERSHIP_INVALID"
    CONTEXT_INVALID = "CONTEXT_INVALID"
    READY_FAST_PATH = "READY_FAST_PATH"
    READY_CANDIDATE = "READY_CANDIDATE"


class AgentStopReason(str, Enum):
    B1_ACCEPTED = "B1_ACCEPTED"
    B1_TERMINAL = "B1_TERMINAL"
    COORDINATOR_FAILURE = "COORDINATOR_FAILURE"


class CoordinatorCompletionKind(str, Enum):
    CONFIRMED_READY = "CONFIRMED_READY"
    EXPLICIT_NOT_CONFIRMED_READY = "EXPLICIT_NOT_CONFIRMED_READY"
    B1_TERMINAL_READY = "B1_TERMINAL_READY"
    B2_RECHECK_FAILED = "B2_RECHECK_FAILED"
    CROSS_GATE_FAILED = "CROSS_GATE_FAILED"


@dataclass(frozen=True)
class CoordinatorLimits:
    max_lifecycles: int = 1
    max_submissions_per_session: int = 8
    request_timeout_ms: int = 900_000
    poll_interval_ms: int = 50

    def __post_init__(self) -> None:
        validate_positive_int(
            self.max_lifecycles,
            "max_lifecycles",
            maximum=_MAX_LIFECYCLES,
        )
        validate_positive_int(
            self.max_submissions_per_session,
            "max_submissions_per_session",
            maximum=_MAX_SUBMISSIONS_PER_SESSION,
        )
        validate_positive_int(
            self.request_timeout_ms,
            "request_timeout_ms",
            maximum=_MAX_TIMEOUT_MS,
        )
        validate_positive_int(
            self.poll_interval_ms,
            "poll_interval_ms",
            maximum=_MAX_TIMEOUT_MS,
        )
        if self.poll_interval_ms > self.request_timeout_ms:
            raise ContractError("poll_interval_ms must not exceed request_timeout_ms")


@dataclass(frozen=True)
class AgentStartRequest:
    validation_instance_id: str
    lifecycle_id: str
    agent_session_id: str
    case_id: str
    function_id: str
    reasoning_sha256: str
    profile_sha256: str
    context_sha256: str
    submission_budget: int

    def __post_init__(self) -> None:
        validate_sha256(self.validation_instance_id, "validation_instance_id")
        validate_identifier(self.lifecycle_id, "lifecycle_id")
        validate_identifier(self.agent_session_id, "agent_session_id")
        validate_identifier(self.case_id, "case_id")
        validate_identifier(self.function_id, "function_id")
        validate_sha256(self.reasoning_sha256, "reasoning_sha256")
        validate_sha256(self.profile_sha256, "profile_sha256")
        validate_sha256(self.context_sha256, "context_sha256")
        validate_positive_int(
            self.submission_budget,
            "submission_budget",
            maximum=_MAX_SUBMISSIONS_PER_SESSION,
        )


@dataclass(frozen=True)
class AgentStartResult:
    """Trusted driver result that makes a launched Agent cleanup-addressable."""

    lifecycle_id: str
    agent_session_id: str
    authoritative_handle_id: str
    startup_receipt_sha256: str
    handle: object

    def __post_init__(self) -> None:
        validate_identifier(self.lifecycle_id, "lifecycle_id")
        validate_identifier(self.agent_session_id, "agent_session_id")
        validate_identifier(
            self.authoritative_handle_id,
            "authoritative_handle_id",
        )
        validate_sha256(self.startup_receipt_sha256, "startup_receipt_sha256")
        if self.handle is None:
            raise ContractError("Agent start result must contain an authoritative handle")

    def validate_request(self, request: AgentStartRequest) -> None:
        if type(request) is not AgentStartRequest:
            raise ContractError("Agent start result requires its exact start request")
        if (
            self.lifecycle_id != request.lifecycle_id
            or self.agent_session_id != request.agent_session_id
        ):
            raise ContractError("Agent start result identity mismatch")


@dataclass(frozen=True)
class AgentResponseCommitRequest:
    """Exact binding a driver must fence around one mailbox response commit."""

    lifecycle_id: str
    agent_session_id: str
    authoritative_handle_id: str
    nonce: int
    request_sha256: str
    response_sha256: str

    def __post_init__(self) -> None:
        validate_identifier(self.lifecycle_id, "lifecycle_id")
        validate_identifier(self.agent_session_id, "agent_session_id")
        validate_identifier(
            self.authoritative_handle_id,
            "authoritative_handle_id",
        )
        validate_positive_int(self.nonce, "nonce", maximum=_MAX_SUBMISSIONS_PER_SESSION)
        validate_sha256(self.request_sha256, "request_sha256")
        validate_sha256(self.response_sha256, "response_sha256")


@dataclass(frozen=True)
class AgentResponseCommitProof:
    """Driver attestation that commit happened before a live-handle observation."""

    lifecycle_id: str
    agent_session_id: str
    authoritative_handle_id: str
    nonce: int
    request_sha256: str
    response_sha256: str
    commit_callback_called_once: bool
    alive_observed_after_commit: bool

    def __post_init__(self) -> None:
        AgentResponseCommitRequest(
            lifecycle_id=self.lifecycle_id,
            agent_session_id=self.agent_session_id,
            authoritative_handle_id=self.authoritative_handle_id,
            nonce=self.nonce,
            request_sha256=self.request_sha256,
            response_sha256=self.response_sha256,
        )
        for field in (
            "commit_callback_called_once",
            "alive_observed_after_commit",
        ):
            if type(getattr(self, field)) is not bool:
                raise ContractError(f"{field} must be an exact boolean")

    def validate_request(self, request: AgentResponseCommitRequest) -> None:
        if type(request) is not AgentResponseCommitRequest:
            raise ContractError("response commit proof requires its exact request")
        expected = (
            request.lifecycle_id,
            request.agent_session_id,
            request.authoritative_handle_id,
            request.nonce,
            request.request_sha256,
            request.response_sha256,
        )
        actual = (
            self.lifecycle_id,
            self.agent_session_id,
            self.authoritative_handle_id,
            self.nonce,
            self.request_sha256,
            self.response_sha256,
        )
        if actual != expected:
            raise ContractError("response commit proof binding mismatch")
        if not self.commit_callback_called_once or not self.alive_observed_after_commit:
            raise ContractError(
                "response commit proof lacks the single-commit live-handle fence"
            )


@dataclass(frozen=True)
class AgentExitProof:
    """Trusted driver attestation required before A release or B2 startup."""

    lifecycle_id: str
    agent_session_id: str
    authoritative_handle_id: str
    authoritative_handle_exited: bool
    process_tree_empty: bool
    provider_endpoint_revoked: bool
    credentials_revoked: bool
    writable_handles_revoked: bool
    workspace_mount_revoked: bool
    trace_finished_once: bool
    trace_receipt_sha256: str

    def __post_init__(self) -> None:
        validate_identifier(self.lifecycle_id, "lifecycle_id")
        validate_identifier(self.agent_session_id, "agent_session_id")
        validate_identifier(
            self.authoritative_handle_id,
            "authoritative_handle_id",
        )
        for field in (
            "authoritative_handle_exited",
            "process_tree_empty",
            "provider_endpoint_revoked",
            "credentials_revoked",
            "writable_handles_revoked",
            "workspace_mount_revoked",
            "trace_finished_once",
        ):
            if type(getattr(self, field)) is not bool:
                raise ContractError(f"{field} must be an exact boolean")
        validate_sha256(self.trace_receipt_sha256, "trace_receipt_sha256")

    def validate_complete(
        self,
        *,
        lifecycle_id: str,
        agent_session_id: str,
        authoritative_handle_id: str,
    ) -> None:
        if (
            self.lifecycle_id != lifecycle_id
            or self.agent_session_id != agent_session_id
            or self.authoritative_handle_id != authoritative_handle_id
        ):
            raise ContractError("Agent exit proof identity mismatch")
        if not all(
            (
                self.authoritative_handle_exited,
                self.process_tree_empty,
                self.provider_endpoint_revoked,
                self.credentials_revoked,
                self.writable_handles_revoked,
                self.workspace_mount_revoked,
                self.trace_finished_once,
            )
        ):
            raise ContractError("Agent exit proof does not establish full teardown")


def _require_contract_ref(
    value: object,
    kind: ContractRefKind,
    field: str,
) -> ContractRef:
    if type(value) is not ContractRef or value.kind is not kind:
        raise ContractError(f"{field} must be a {kind.value} ContractRef")
    return value


def _validate_frozen_request(value: object) -> None:
    """Rebind a mailbox result without trusting protocol-shaped duck types."""

    if type(value) is not FrozenCoordinatorRequest:
        raise ContractError("frozen_request must be a FrozenCoordinatorRequest")
    value.validate_integrity()


@dataclass(frozen=True)
class GateExecutionRequest:
    """Exact input handed to one trusted Gate invocation."""

    validation_instance_id: str
    lifecycle_id: str
    agent_session_id: str | None
    attempt_id: str
    role: GateRole
    may_retry: bool
    preflight_state: GatePreflightState
    frozen_request: FrozenCoordinatorRequest
    submission: CaseSubmission | None
    oracle_bundle: OracleBundle | None
    oracle_specs: tuple[OracleSpec, ...]
    workspace: WorkspaceAllocation | None
    expected_template: ExperimentPlanTemplate | None = None
    expected_adapter: ContractRef | None = None

    def __post_init__(self) -> None:
        validate_sha256(self.validation_instance_id, "validation_instance_id")
        validate_identifier(self.lifecycle_id, "lifecycle_id")
        if self.agent_session_id is not None:
            validate_identifier(self.agent_session_id, "agent_session_id")
        validate_identifier(self.attempt_id, "attempt_id")
        if type(self.role) is not GateRole:
            raise ContractError("role must be a GateRole")
        if type(self.may_retry) is not bool:
            raise ContractError("may_retry must be an exact boolean")
        if type(self.preflight_state) is not GatePreflightState:
            raise ContractError("preflight_state must be a GatePreflightState")
        _validate_frozen_request(self.frozen_request)
        if type(self.oracle_specs) not in (tuple, list):
            raise ContractError("oracle_specs must be an ordered collection")
        specs = tuple(self.oracle_specs)
        if any(type(spec) is not OracleSpec for spec in specs):
            raise ContractError("oracle_specs must contain OracleSpec values")
        if len({spec.ref for spec in specs}) != len(specs):
            raise ContractError("oracle_specs must not contain duplicate refs")
        object.__setattr__(self, "oracle_specs", specs)

        envelope = self.frozen_request.envelope
        if envelope.validation_instance_id != self.validation_instance_id:
            raise ContractError("Gate request frozen validation instance mismatch")
        if self.role is GateRole.B1:
            if self.agent_session_id != envelope.agent_session_id:
                raise ContractError("B1 must retain the Agent session identity")
        elif self.agent_session_id is not None:
            raise ContractError("B2 must not receive an Agent session identity")
        if self.role is GateRole.B2 and self.may_retry:
            raise ContractError("B2 may never request an in-session retry")

        if self.workspace is not None:
            if type(self.workspace) is not WorkspaceAllocation:
                raise ContractError("workspace must be a WorkspaceAllocation or None")
            expected_role = {
                GateRole.B1: WorkspaceRole.B1,
                GateRole.B2: WorkspaceRole.B2,
            }[self.role]
            if self.workspace.lease.role is not expected_role:
                raise ContractError("Gate request workspace role mismatch")
            if self.workspace.lease.attempt_id != self.attempt_id:
                raise ContractError("Gate request workspace attempt mismatch")

        if self.preflight_state is GatePreflightState.INTAKE_INVALID:
            if any(
                value is not None
                for value in (
                    self.submission,
                    self.oracle_bundle,
                    self.workspace,
                    self.expected_template,
                    self.expected_adapter,
                )
            ) or specs:
                raise ContractError("intake-invalid Gate input must contain no graph")
        elif self.preflight_state in (
            GatePreflightState.MEMBERSHIP_INVALID,
            GatePreflightState.CONTEXT_INVALID,
        ):
            if type(self.submission) is not CaseSubmission:
                raise ContractError("pre-execution failure requires parsed submission")
            if any(
                value is not None
                for value in (
                    self.oracle_bundle,
                    self.workspace,
                    self.expected_template,
                    self.expected_adapter,
                )
            ) or specs:
                raise ContractError("pre-execution failure must not execute a graph")
        elif self.preflight_state is GatePreflightState.READY_FAST_PATH:
            if (
                type(self.submission) is not CaseSubmission
                or self.submission.submission_kind
                is not CaseSubmissionKind.NOT_CONFIRMED
                or self.oracle_bundle is not None
                or specs
                or self.workspace is not None
                or self.expected_template is not None
                or self.expected_adapter is not None
            ):
                raise ContractError("fast-path Gate input has an executable graph")
        else:
            if (
                type(self.submission) is not CaseSubmission
                or self.submission.submission_kind is not CaseSubmissionKind.CANDIDATE
                or type(self.oracle_bundle) is not OracleBundle
                or not specs
                or type(self.workspace) is not WorkspaceAllocation
            ):
                raise ContractError("candidate Gate input lacks its frozen graph")
            if self.role is GateRole.B1 and (
                self.expected_template is not None or self.expected_adapter is not None
            ):
                raise ContractError("B1 must not receive a prior Gate template")
            if self.role is GateRole.B2:
                if type(self.expected_template) is not ExperimentPlanTemplate:
                    raise ContractError("B2 candidate requires the frozen B1 template")
                _require_contract_ref(
                    self.expected_adapter,
                    ContractRefKind.ADAPTER,
                    "expected_adapter",
                )


@dataclass(frozen=True)
class GateEvidencePersistenceProof:
    """Trusted storage attestation bound to the complete Gate evidence graph.

    This slice does not implement the production CAS authority.  It does make
    that authority an explicit, exact provider seam: a bare digest supplied by
    the Gate result is not accepted as proof of persistence.
    """

    validation_instance_id: str
    lifecycle_id: str
    attempt_id: str
    role: GateRole
    storage_authority_id: str
    evidence_graph_sha256: str
    persistence_receipt_sha256: str
    durable_before_workspace_release: bool

    def __post_init__(self) -> None:
        validate_sha256(self.validation_instance_id, "validation_instance_id")
        validate_identifier(self.lifecycle_id, "lifecycle_id")
        validate_identifier(self.attempt_id, "attempt_id")
        if type(self.role) is not GateRole:
            raise ContractError("role must be a GateRole")
        validate_identifier(self.storage_authority_id, "storage_authority_id")
        validate_sha256(self.evidence_graph_sha256, "evidence_graph_sha256")
        validate_sha256(
            self.persistence_receipt_sha256,
            "persistence_receipt_sha256",
        )
        if type(self.durable_before_workspace_release) is not bool:
            raise ContractError(
                "durable_before_workspace_release must be an exact boolean"
            )

    @classmethod
    def for_graph(
        cls,
        *,
        lifecycle_id: str,
        storage_authority_id: str,
        persistence_receipt_sha256: str,
        durable_before_workspace_release: bool,
        receipt: GateReceipt,
        adapter: ContractRef | None,
        template: ExperimentPlanTemplate | None,
        binding: ExecutionBinding | None,
        baseline_receipts: tuple[BaselineSelectionReceipt, ...],
        observations: tuple[Observation, ...],
        decisions: tuple[OracleDecision, ...],
    ) -> GateEvidencePersistenceProof:
        if type(receipt) not in (
            CandidateGateReceipt,
            EarlyGateReceipt,
            FastPathGateReceipt,
        ):
            raise ContractError("persistence proof requires an exact Gate receipt")
        graph_sha256 = _gate_evidence_graph_sha256(
            receipt=receipt,
            adapter=adapter,
            template=template,
            binding=binding,
            baseline_receipts=baseline_receipts,
            observations=observations,
            decisions=decisions,
        )
        return cls(
            validation_instance_id=receipt.validation_instance_id,
            lifecycle_id=lifecycle_id,
            attempt_id=receipt.attempt_id,
            role=receipt.role,
            storage_authority_id=storage_authority_id,
            evidence_graph_sha256=graph_sha256,
            persistence_receipt_sha256=persistence_receipt_sha256,
            durable_before_workspace_release=durable_before_workspace_release,
        )


def _gate_evidence_graph_sha256(
    *,
    receipt: GateReceipt,
    adapter: ContractRef | None,
    template: ExperimentPlanTemplate | None,
    binding: ExecutionBinding | None,
    baseline_receipts: tuple[BaselineSelectionReceipt, ...],
    observations: tuple[Observation, ...],
    decisions: tuple[OracleDecision, ...],
) -> str:
    def optional_ref(value: object | None) -> object | None:
        if value is None:
            return None
        reference = value if type(value) is ContractRef else value.ref
        return reference.to_document()

    return canonical_sha256(
        {
            "receipt": receipt.ref.to_document(),
            "adapter": optional_ref(adapter),
            "template": optional_ref(template),
            "binding": optional_ref(binding),
            "baseline_receipts": [
                value.ref.to_document() for value in baseline_receipts
            ],
            "observations": [value.ref.to_document() for value in observations],
            "decisions": [value.ref.to_document() for value in decisions],
        }
    )


@dataclass(frozen=True)
class GateExecutionResult:
    """Gate output plus the concrete graph needed for host-side validation."""

    receipt: GateReceipt
    adapter: ContractRef | None
    template: ExperimentPlanTemplate | None
    binding: ExecutionBinding | None
    baseline_receipts: tuple[BaselineSelectionReceipt, ...]
    observations: tuple[Observation, ...]
    decisions: tuple[OracleDecision, ...]
    evidence_persistence: GateEvidencePersistenceProof
    diagnostics: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        receipt_types = (
            CandidateGateReceipt,
            EarlyGateReceipt,
            FastPathGateReceipt,
        )
        if type(self.receipt) not in receipt_types:
            raise ContractError("receipt must be a closed GateReceipt value")
        collections = (
            ("baseline_receipts", self.baseline_receipts, BaselineSelectionReceipt),
            ("observations", self.observations, Observation),
            ("decisions", self.decisions, OracleDecision),
        )
        for field, values, item_type in collections:
            if type(values) not in (tuple, list):
                raise ContractError(f"{field} must be an ordered collection")
            normalized = tuple(values)
            if any(type(item) is not item_type for item in normalized):
                raise ContractError(f"{field} contains an invalid value")
            object.__setattr__(self, field, normalized)
        if type(self.receipt) is CandidateGateReceipt:
            _require_contract_ref(self.adapter, ContractRefKind.ADAPTER, "adapter")
            if type(self.template) is not ExperimentPlanTemplate:
                raise ContractError("candidate result requires an experiment template")
            if type(self.binding) is not ExecutionBinding:
                raise ContractError("candidate result requires an execution binding")
        elif any(
            value is not None for value in (self.adapter, self.template, self.binding)
        ) or any(
            (self.baseline_receipts, self.observations, self.decisions)
        ):
            raise ContractError("early and fast results must not invent execution data")
        if type(self.evidence_persistence) is not GateEvidencePersistenceProof:
            raise ContractError(
                "evidence_persistence must be a GateEvidencePersistenceProof"
            )
        persistence = self.evidence_persistence
        if (
            persistence.validation_instance_id != self.receipt.validation_instance_id
            or persistence.attempt_id != self.receipt.attempt_id
            or persistence.role is not self.receipt.role
            or persistence.evidence_graph_sha256
            != _gate_evidence_graph_sha256(
                receipt=self.receipt,
                adapter=self.adapter,
                template=self.template,
                binding=self.binding,
                baseline_receipts=tuple(self.baseline_receipts),
                observations=tuple(self.observations),
                decisions=tuple(self.decisions),
            )
            or not persistence.durable_before_workspace_release
        ):
            raise ContractError(
                "Gate evidence persistence proof does not bind a durable graph"
            )
        if type(self.diagnostics) not in (tuple, list):
            raise ContractError("diagnostics must be an ordered collection")
        diagnostics = tuple(
            validate_identifier(value, "diagnostic") for value in self.diagnostics
        )
        if len(diagnostics) > _MAX_DIAGNOSTICS:
            raise ContractError("diagnostics exceeds the bounded response limit")
        if len(set(diagnostics)) != len(diagnostics):
            raise ContractError("diagnostics must not contain duplicates")
        allowed = {
            reason.value
            for reason in CaseReasonCode
            if reason not in (CaseReasonCode.CONFIRMED_L0, CaseReasonCode.CONFIRMED_L1)
        }
        if not set(diagnostics).issubset(allowed):
            raise ContractError("diagnostics contains a non-allowlisted identifier")
        object.__setattr__(self, "diagnostics", tuple(sorted(diagnostics)))

@dataclass(frozen=True)
class CrossGateComparisonRequest:
    validation_instance_id: str
    lifecycle_id: str
    attempt_id: str
    b1: GateExecutionResult
    b2: GateExecutionResult

    def __post_init__(self) -> None:
        validate_sha256(self.validation_instance_id, "validation_instance_id")
        validate_identifier(self.lifecycle_id, "lifecycle_id")
        validate_identifier(self.attempt_id, "attempt_id")
        if type(self.b1) is not GateExecutionResult or type(self.b2) is not GateExecutionResult:
            raise ContractError("cross-Gate request requires exact Gate results")
        if (
            type(self.b1.receipt) is not CandidateGateReceipt
            or type(self.b2.receipt) is not CandidateGateReceipt
        ):
            raise ContractError("cross-Gate request requires candidate receipts")
        if (
            self.b1.receipt.validation_instance_id != self.validation_instance_id
            or self.b2.receipt.validation_instance_id != self.validation_instance_id
            or self.b1.receipt.attempt_id != self.attempt_id
            or self.b2.receipt.attempt_id != self.attempt_id
            or self.b1.evidence_persistence.lifecycle_id != self.lifecycle_id
            or self.b2.evidence_persistence.lifecycle_id != self.lifecycle_id
        ):
            raise ContractError("cross-Gate request identity mismatch")


class CoordinatorMailboxPort(Protocol):
    @property
    def agent_endpoint(self) -> object: ...

    @property
    def request_capacity(self) -> int: ...

    def claim_next(
        self,
        *,
        expected_nonce: int,
        is_agent_alive: Callable[[], bool],
        timeout_ms: int,
        poll_interval_ms: int,
    ) -> FrozenCoordinatorRequest: ...

    def close_requests(self) -> None: ...

    def publish_response(
        self,
        response: CoordinatorResponseEnvelope,
        frozen_request: FrozenCoordinatorRequest,
    ) -> str: ...

    def assert_quiescent(self) -> None: ...

    def dispose(self) -> None: ...


@dataclass(frozen=True)
class CoordinatorProviders:
    evidence_storage_authority_id: str
    create_mailbox: Callable[[WorkspaceAllocation, str], CoordinatorMailboxPort]
    start_agent: Callable[
        [AgentStartRequest, WorkspaceAllocation, object],
        AgentStartResult,
    ]
    agent_is_alive: Callable[[object], bool]
    commit_agent_response: Callable[
        [object, AgentResponseCommitRequest, Callable[[], str]],
        AgentResponseCommitProof,
    ]
    request_agent_stop: Callable[[object, AgentStopReason], None]
    finish_agent: Callable[[object, AgentStopReason], AgentExitProof]
    evaluate_gate: Callable[[GateExecutionRequest], GateExecutionResult]
    compare_cross_gate: Callable[[CrossGateComparisonRequest], CrossGateDecision]

    def __post_init__(self) -> None:
        validate_identifier(
            self.evidence_storage_authority_id,
            "evidence_storage_authority_id",
        )
        for field in (
            "create_mailbox",
            "start_agent",
            "agent_is_alive",
            "commit_agent_response",
            "request_agent_stop",
            "finish_agent",
            "evaluate_gate",
            "compare_cross_gate",
        ):
            if not callable(getattr(self, field)):
                raise ContractError(f"Coordinator provider {field} must be callable")


def create_filesystem_mailbox(
    allocation: WorkspaceAllocation,
    agent_session_id: str,
) -> CoordinatorMailbox:
    """Create the built-in mailbox only for the exact live A allocation."""

    if type(allocation) is not WorkspaceAllocation:
        raise TypeError("allocation must be a WorkspaceAllocation")
    validate_identifier(agent_session_id, "agent_session_id")
    if (
        allocation.lease.role is not WorkspaceRole.A
        or allocation.lease.agent_session_id != agent_session_id
        or allocation.paths.case_staging is None
    ):
        raise ContractError(
            "filesystem mailbox requires the matching Agent workspace lease"
        )
    return CoordinatorMailbox(
        allocation.paths.case_staging,
        agent_session_id=agent_session_id,
    )


@dataclass(frozen=True)
class CoordinatorAttemptRecord:
    nonce: int
    request: CoordinatorRequestEnvelope
    request_sha256: str
    gate_attempt_id: str
    response: CoordinatorResponseEnvelope
    response_commit: AgentResponseCommitProof
    gate_result: GateExecutionResult
    b1_workspace: WorkspaceLineageRecord | None

    def __post_init__(self) -> None:
        validate_positive_int(self.nonce, "nonce")
        if type(self.request) is not CoordinatorRequestEnvelope:
            raise ContractError("attempt request must be a CoordinatorRequestEnvelope")
        validate_sha256(self.request_sha256, "request_sha256")
        validate_identifier(self.gate_attempt_id, "gate_attempt_id")
        if type(self.response) is not CoordinatorResponseEnvelope:
            raise ContractError("attempt response must be a CoordinatorResponseEnvelope")
        if type(self.response_commit) is not AgentResponseCommitProof:
            raise ContractError(
                "attempt response_commit must be an AgentResponseCommitProof"
            )
        if type(self.gate_result) is not GateExecutionResult:
            raise ContractError("attempt gate_result must be a GateExecutionResult")
        self.response.validate_request(self.request)
        if (
            self.nonce != self.request.nonce
            or self.request_sha256 != self.request.content_sha256
            or self.response.request_sha256 != self.request_sha256
            or self.gate_attempt_id != self.gate_result.receipt.attempt_id
            or self.response.gate_attempt_id != self.gate_attempt_id
            or self.response.b1_receipt != self.gate_result.receipt.ref
            or self.gate_result.receipt.validation_instance_id
            != self.request.validation_instance_id
            or self.gate_result.evidence_persistence.lifecycle_id
            != self.response_commit.lifecycle_id
        ):
            raise ContractError("attempt record identities do not agree")
        receipt = self.gate_result.receipt
        if (
            receipt.role is not GateRole.B1
            or type(receipt.disposition) is not GateAttemptDisposition
        ):
            raise ContractError("attempt record requires a dispositive B1 receipt")
        if type(receipt) is FastPathGateReceipt:
            expected_status = CaseStatus.NOT_CONFIRMED
            expected_reason = CaseReasonCode.EXPLICIT_NOT_CONFIRMED
        else:
            expected_status = receipt.result_status
            expected_reason = receipt.result_reason_code
        if (
            self.response.disposition is not receipt.disposition
            or self.response.result_status is not expected_status
            or self.response.result_reason_code is not expected_reason
            or self.response.diagnostics != self.gate_result.diagnostics
        ):
            raise ContractError("attempt response changed its Gate result projection")
        self.response_commit.validate_request(
            AgentResponseCommitRequest(
                lifecycle_id=self.response_commit.lifecycle_id,
                agent_session_id=self.request.agent_session_id,
                authoritative_handle_id=(
                    self.response_commit.authoritative_handle_id
                ),
                nonce=self.nonce,
                request_sha256=self.request_sha256,
                response_sha256=self.response.content_sha256,
            )
        )
        if self.b1_workspace is not None and type(self.b1_workspace) is not WorkspaceLineageRecord:
            raise ContractError("b1_workspace must be lineage metadata or None")
        workspace_required = type(receipt) is CandidateGateReceipt or (
            type(receipt) is EarlyGateReceipt
            and receipt.failure_stage is EarlyGateStage.MATERIALIZE
        )
        if (self.b1_workspace is not None) is not workspace_required:
            raise ContractError(
                "B1 workspace lineage does not match the receipt execution stage"
            )


@dataclass(frozen=True)
class CoordinatorLifecycleRecord:
    lifecycle_id: str
    agent_session_id: str
    authoritative_handle_id: str
    startup_receipt_sha256: str
    submission_budget: int
    a_workspace: WorkspaceLineageRecord
    b1_attempts: tuple[CoordinatorAttemptRecord, ...]
    agent_exit: AgentExitProof
    completion: CoordinatorCompletionKind
    b2_result: GateExecutionResult | None = None
    b2_workspace: WorkspaceLineageRecord | None = None
    cross_gate_decision: CrossGateDecision | None = None

    def __post_init__(self) -> None:
        validate_identifier(self.lifecycle_id, "lifecycle_id")
        validate_identifier(self.agent_session_id, "agent_session_id")
        validate_identifier(
            self.authoritative_handle_id,
            "authoritative_handle_id",
        )
        validate_sha256(self.startup_receipt_sha256, "startup_receipt_sha256")
        validate_positive_int(
            self.submission_budget,
            "submission_budget",
            maximum=_MAX_SUBMISSIONS_PER_SESSION,
        )
        if type(self.a_workspace) is not WorkspaceLineageRecord:
            raise ContractError("a_workspace must be WorkspaceLineageRecord")
        if (
            self.a_workspace.lease.role is not WorkspaceRole.A
            or self.a_workspace.lease.agent_session_id != self.agent_session_id
        ):
            raise ContractError("A lineage does not bind the lifecycle Agent session")
        if type(self.b1_attempts) not in (tuple, list) or not self.b1_attempts:
            raise ContractError("a lifecycle must contain at least one B1 attempt")
        attempts = tuple(self.b1_attempts)
        if any(type(item) is not CoordinatorAttemptRecord for item in attempts):
            raise ContractError("b1_attempts contains an invalid record")
        if tuple(item.nonce for item in attempts) != tuple(range(1, len(attempts) + 1)):
            raise ContractError("B1 attempt nonces must be contiguous from one")
        if len(attempts) > self.submission_budget or any(
            item.response.remaining_submission_budget
            != self.submission_budget - item.nonce
            for item in attempts
        ):
            raise ContractError("B1 history does not bind its submission budget")
        for index, item in enumerate(attempts):
            expected_previous = (
                None if index == 0 else attempts[index - 1].response.content_sha256
            )
            if item.request.previous_response_sha256 != expected_previous:
                raise ContractError(
                    "B1 retry request does not acknowledge the prior response"
                )
        object.__setattr__(self, "b1_attempts", attempts)
        if any(
            item.gate_result.receipt.disposition
            is not GateAttemptDisposition.RETRYABLE_REJECTION
            for item in attempts[:-1]
        ) or attempts[-1].gate_result.receipt.disposition is (
            GateAttemptDisposition.RETRYABLE_REJECTION
        ):
            raise ContractError("B1 history must end after zero or more retries")
        if any(
            item.request.agent_session_id != self.agent_session_id
            or item.request.validation_instance_id
            != self.a_workspace.lease.validation_instance_id
            or item.response_commit.lifecycle_id != self.lifecycle_id
            or item.response_commit.authoritative_handle_id
            != self.authoritative_handle_id
            for item in attempts
        ):
            raise ContractError("B1 history does not bind the lifecycle identities")
        if len(
            {
                item.gate_result.evidence_persistence.persistence_receipt_sha256
                for item in attempts
            }
        ) != len(attempts):
            raise ContractError("B1 attempts reused an evidence persistence receipt")
        for item in attempts:
            if item.b1_workspace is not None and (
                item.b1_workspace.lease.role is not WorkspaceRole.B1
                or item.b1_workspace.lease.attempt_id != item.gate_attempt_id
            ):
                raise ContractError("B1 lineage does not bind its Gate attempt")
        b1_lineages = tuple(
            item.b1_workspace
            for item in attempts
            if item.b1_workspace is not None
        )
        for lineage in b1_lineages:
            if (
                lineage.lease.validation_instance_id
                != self.a_workspace.lease.validation_instance_id
                or lineage.lease.snapshot != self.a_workspace.lease.snapshot
                or lineage.role_policy.profile
                != self.a_workspace.role_policy.profile
                or lineage.role_policy.resource_policy
                != self.a_workspace.role_policy.resource_policy
                or lineage.lease.workspace_equivalence_policy
                != self.a_workspace.lease.workspace_equivalence_policy
                or lineage.lease.equivalence_fingerprint_sha256
                != self.a_workspace.lease.equivalence_fingerprint_sha256
            ):
                raise ContractError("B1 retry lineage changed frozen A context")
        unique_b1_fields = (
            tuple(lineage.lease.lease_id for lineage in b1_lineages),
            tuple(lineage.lease.write_layer_sha256 for lineage in b1_lineages),
            tuple(
                lineage.lease.materialization_proof_sha256
                for lineage in b1_lineages
            ),
            tuple(
                lineage.lease.resource_fingerprint_sha256
                for lineage in b1_lineages
            ),
            tuple(
                lineage.materialization_proof.materialization_id
                for lineage in b1_lineages
            ),
        )
        if any(len(values) != len(set(values)) for values in unique_b1_fields):
            raise ContractError("B1 retries reused workspace provenance")
        if type(self.agent_exit) is not AgentExitProof:
            raise ContractError("agent_exit must be an AgentExitProof")
        self.agent_exit.validate_complete(
            lifecycle_id=self.lifecycle_id,
            agent_session_id=self.agent_session_id,
            authoritative_handle_id=self.authoritative_handle_id,
        )
        if type(self.completion) is not CoordinatorCompletionKind:
            raise ContractError("completion must be a CoordinatorCompletionKind")
        if self.b2_result is not None and type(self.b2_result) is not GateExecutionResult:
            raise ContractError("b2_result must be a GateExecutionResult or None")
        if (
            self.b2_result is not None
            and self.b2_result.evidence_persistence.lifecycle_id
            != self.lifecycle_id
        ):
            raise ContractError("B2 persistence proof changed lifecycle identity")
        if self.b2_result is not None and (
            self.b2_result.evidence_persistence.persistence_receipt_sha256
            in {
                item.gate_result.evidence_persistence.persistence_receipt_sha256
                for item in attempts
            }
        ):
            raise ContractError("B2 reused a B1 evidence persistence receipt")
        if self.b2_workspace is not None and type(self.b2_workspace) is not WorkspaceLineageRecord:
            raise ContractError("b2_workspace must be lineage metadata or None")
        if self.cross_gate_decision is not None and type(self.cross_gate_decision) is not CrossGateDecision:
            raise ContractError("cross_gate_decision has an invalid type")

        final = attempts[-1].gate_result.receipt
        if self.completion is CoordinatorCompletionKind.B1_TERMINAL_READY:
            if (
                final.disposition is not GateAttemptDisposition.TERMINAL_OUTCOME
                or self.b2_result is not None
                or self.b2_workspace is not None
                or self.cross_gate_decision is not None
            ):
                raise ContractError("B1-terminal lifecycle has an invalid topology")
        elif self.completion is CoordinatorCompletionKind.EXPLICIT_NOT_CONFIRMED_READY:
            if (
                final.disposition
                is not GateAttemptDisposition.ACCEPTED_EXPLICIT_NOT_CONFIRMED
                or type(self.b2_result) is not GateExecutionResult
                or type(self.b2_result.receipt) is not FastPathGateReceipt
                or self.b2_workspace is not None
                or self.cross_gate_decision is not None
            ):
                raise ContractError("explicit-not-confirmed lifecycle topology is invalid")
            validate_b1_b2_gate_receipts(final, self.b2_result.receipt)
        else:
            if (
                final.disposition
                is not GateAttemptDisposition.ACCEPTED_CONFIRMED_CANDIDATE
                or type(self.b2_result) is not GateExecutionResult
                or self.b2_workspace is None
            ):
                raise ContractError("candidate lifecycle lacks its accepted B1/B2 graph")
            if (
                type(final) is not CandidateGateReceipt
                or attempts[-1].b1_workspace is None
                or self.b2_workspace.lease.role is not WorkspaceRole.B2
                or self.b2_workspace.lease.attempt_id != final.attempt_id
            ):
                raise ContractError(
                    "candidate lifecycle has an invalid receipt/workspace topology"
                )
            validate_b1_b2_gate_receipts(final, self.b2_result.receipt)
            validate_workspace_lineage(
                self.a_workspace,
                attempts[-1].b1_workspace,
                self.b2_workspace,
            )
            if self.completion is CoordinatorCompletionKind.CONFIRMED_READY:
                if (
                    self.cross_gate_decision is None
                    or self.cross_gate_decision.verdict
                    is not CrossGateVerdict.REPRODUCIBLE
                ):
                    raise ContractError("confirmed-ready lifecycle lacks reproducibility")
                validate_cross_gate_decision(
                    self.cross_gate_decision,
                    final,
                    self.b2_result.receipt,
                )
            elif self.completion is CoordinatorCompletionKind.CROSS_GATE_FAILED:
                if (
                    self.cross_gate_decision is None
                    or self.cross_gate_decision.verdict
                    is not CrossGateVerdict.REPRODUCIBILITY_FAILED
                ):
                    raise ContractError("cross-Gate failure lacks its failed decision")
                validate_cross_gate_decision(
                    self.cross_gate_decision,
                    final,
                    self.b2_result.receipt,
                )
            elif (
                self.cross_gate_decision is not None
                or (
                    type(self.b2_result.receipt) is CandidateGateReceipt
                    and self.b2_result.receipt.result_status
                    in (CaseStatus.CONFIRMED_L0, CaseStatus.CONFIRMED_L1)
                )
            ):
                raise ContractError(
                    "B2 recheck failure must contain a non-confirmed B2 receipt only"
                )


@dataclass(frozen=True)
class CoordinatorRunResult:
    validation_instance_id: str
    evidence_storage_authority_id: str
    completion: CoordinatorCompletionKind
    lifecycles: tuple[CoordinatorLifecycleRecord, ...]

    def __post_init__(self) -> None:
        validate_sha256(self.validation_instance_id, "validation_instance_id")
        validate_identifier(
            self.evidence_storage_authority_id,
            "evidence_storage_authority_id",
        )
        if type(self.completion) is not CoordinatorCompletionKind:
            raise ContractError("completion must be a CoordinatorCompletionKind")
        if type(self.lifecycles) not in (tuple, list) or not self.lifecycles:
            raise ContractError("Coordinator result requires lifecycle records")
        lifecycles = tuple(self.lifecycles)
        if any(type(item) is not CoordinatorLifecycleRecord for item in lifecycles):
            raise ContractError("lifecycles contains an invalid record")
        if lifecycles[-1].completion is not self.completion:
            raise ContractError("final lifecycle completion mismatch")
        if len({item.lifecycle_id for item in lifecycles}) != len(lifecycles):
            raise ContractError("lifecycle ids must be globally unique")
        if len({item.agent_session_id for item in lifecycles}) != len(lifecycles):
            raise ContractError("Agent session ids must be globally unique")
        if len({item.authoritative_handle_id for item in lifecycles}) != len(lifecycles):
            raise ContractError("authoritative Agent handle ids must be globally unique")
        if len({item.startup_receipt_sha256 for item in lifecycles}) != len(lifecycles):
            raise ContractError("Agent startup receipts must be globally unique")
        gate_attempt_ids = tuple(
            attempt.gate_attempt_id
            for lifecycle in lifecycles
            for attempt in lifecycle.b1_attempts
        )
        if len(set(gate_attempt_ids)) != len(gate_attempt_ids):
            raise ContractError("Gate attempt ids must be globally unique")
        if any(
            item.a_workspace.lease.validation_instance_id
            != self.validation_instance_id
            for item in lifecycles
        ):
            raise ContractError(
                "lifecycle records do not bind the Coordinator validation instance"
            )
        persistence_proofs = tuple(
            proof
            for lifecycle in lifecycles
            for proof in (
                *(
                    attempt.gate_result.evidence_persistence
                    for attempt in lifecycle.b1_attempts
                ),
                *((lifecycle.b2_result.evidence_persistence,)
                  if lifecycle.b2_result is not None else ()),
            )
        )
        if any(
            proof.storage_authority_id != self.evidence_storage_authority_id
            for proof in persistence_proofs
        ):
            raise ContractError("Gate evidence changed trusted storage authority")
        if len(
            {proof.persistence_receipt_sha256 for proof in persistence_proofs}
        ) != len(persistence_proofs):
            raise ContractError("Gate attempts reused an evidence persistence receipt")
        if len(
            {item.agent_exit.trace_receipt_sha256 for item in lifecycles}
        ) != len(lifecycles):
            raise ContractError("Agent lifecycles reused a trace receipt")
        anchor = lifecycles[0].a_workspace
        if any(
            item.a_workspace.lease.snapshot != anchor.lease.snapshot
            or item.a_workspace.role_policy.profile != anchor.role_policy.profile
            or item.a_workspace.role_policy.resource_policy
            != anchor.role_policy.resource_policy
            or item.a_workspace.lease.workspace_equivalence_policy
            != anchor.lease.workspace_equivalence_policy
            or item.a_workspace.lease.equivalence_fingerprint_sha256
            != anchor.lease.equivalence_fingerprint_sha256
            for item in lifecycles[1:]
        ):
            raise ContractError("fresh lifecycles changed their frozen run context")
        restartable = {
            CoordinatorCompletionKind.B2_RECHECK_FAILED,
            CoordinatorCompletionKind.CROSS_GATE_FAILED,
        }
        if any(item.completion not in restartable for item in lifecycles[:-1]):
            raise ContractError("only failed B2 lifecycles may precede the final one")
        lineages = tuple(
            lineage
            for lifecycle in lifecycles
            for lineage in (
                lifecycle.a_workspace,
                *(
                    attempt.b1_workspace
                    for attempt in lifecycle.b1_attempts
                    if attempt.b1_workspace is not None
                ),
                *((lifecycle.b2_workspace,) if lifecycle.b2_workspace is not None else ()),
            )
        )
        unique_fields = (
            tuple(lineage.lease.lease_id for lineage in lineages),
            tuple(lineage.lease.write_layer_sha256 for lineage in lineages),
            tuple(
                lineage.lease.materialization_proof_sha256
                for lineage in lineages
            ),
            tuple(
                lineage.lease.resource_fingerprint_sha256
                for lineage in lineages
            ),
            tuple(
                lineage.materialization_proof.materialization_id
                for lineage in lineages
            ),
        )
        if any(len(values) != len(set(values)) for values in unique_fields):
            raise ContractError("separate lifecycles reused workspace provenance")
        object.__setattr__(self, "lifecycles", lifecycles)


@dataclass(frozen=True)
class _PreflightResult:
    state: GatePreflightState
    submission: CaseSubmission | None
    oracle_bundle: OracleBundle | None
    oracle_specs: tuple[OracleSpec, ...]


@dataclass(frozen=True)
class _LifecycleExecution:
    record: CoordinatorLifecycleRecord
    restartable: bool


class ValidationCoordinator:
    """One-shot, fail-closed orchestrator over trusted provider seams."""

    def __init__(
        self,
        *,
        snapshot: SnapshotRef,
        identity: ValidationInstanceIdentity,
        profile: FrozenSystemProfile,
        context_sha256: str,
        workspace_equivalence_policy: ContractRef,
        oracle_bundles: tuple[OracleBundle, ...],
        oracle_specs: tuple[OracleSpec, ...],
        workspace_manager: WorkspaceManager,
        providers: CoordinatorProviders,
        limits: CoordinatorLimits = CoordinatorLimits(),
    ) -> None:
        if type(snapshot) is not SnapshotRef:
            raise TypeError("snapshot must be a SnapshotRef")
        if type(identity) is not ValidationInstanceIdentity:
            raise TypeError("identity must be a ValidationInstanceIdentity")
        if type(profile) is not FrozenSystemProfile:
            raise TypeError("profile must be a FrozenSystemProfile")
        validate_sha256(context_sha256, "context_sha256")
        _require_contract_ref(
            workspace_equivalence_policy,
            ContractRefKind.EXECUTION_EQUIVALENCE_POLICY,
            "workspace_equivalence_policy",
        )
        if type(workspace_manager) is not WorkspaceManager:
            raise TypeError("workspace_manager must be a WorkspaceManager")
        if type(providers) is not CoordinatorProviders:
            raise TypeError("providers must be CoordinatorProviders")
        if type(limits) is not CoordinatorLimits:
            raise TypeError("limits must be CoordinatorLimits")
        if identity.snapshot_sha256 != snapshot.snapshot_sha256:
            raise ContractError("Coordinator identity does not bind SnapshotRef")
        if identity.profile_sha256 != profile.content_sha256:
            raise ContractError("Coordinator identity does not bind Frozen Profile")
        if identity.project_id != profile.project.system_id:
            raise ContractError("Coordinator identity does not bind Profile project")
        if profile.project.source_snapshot_sha256 != snapshot.snapshot_sha256:
            raise ContractError("Frozen Profile does not bind SnapshotRef")
        if workspace_equivalence_policy not in profile.components:
            raise ContractError("workspace equivalence policy is outside Profile")

        if type(oracle_bundles) not in (tuple, list):
            raise ContractError("oracle_bundles must be an ordered collection")
        bundles = tuple(oracle_bundles)
        if any(type(bundle) is not OracleBundle for bundle in bundles):
            raise ContractError("oracle_bundles contains an invalid value")
        if len({bundle.ref for bundle in bundles}) != len(bundles):
            raise ContractError("oracle_bundles must not repeat refs")
        if any(bundle.ref not in profile.oracle_bundles for bundle in bundles):
            raise ContractError("oracle_bundles contains a value outside Profile")
        if type(oracle_specs) not in (tuple, list):
            raise ContractError("oracle_specs must be an ordered collection")
        specs = tuple(oracle_specs)
        if any(type(spec) is not OracleSpec for spec in specs):
            raise ContractError("oracle_specs contains an invalid value")
        if len({spec.ref for spec in specs}) != len(specs):
            raise ContractError("oracle_specs must not repeat refs")
        if any(spec.ref not in profile.oracle_specs for spec in specs):
            raise ContractError("oracle_specs contains a value outside Profile")

        self.snapshot = snapshot
        self.identity = identity
        self.profile = profile
        self.context_sha256 = context_sha256
        self.workspace_equivalence_policy = workspace_equivalence_policy
        self.oracle_bundles = bundles
        self.oracle_specs = specs
        self.workspace_manager = workspace_manager
        self.providers = providers
        self.limits = limits
        self._state = CoordinatorState.NEW
        self._seen_ids: set[str] = set()
        self._started = False

    @property
    def state(self) -> CoordinatorState:
        return self._state

    def _transition(self, target: CoordinatorState) -> None:
        if target not in _ALLOWED_TRANSITIONS[self._state]:
            _raise(
                CoordinatorFailureCode.INVALID_STATE_TRANSITION,
                f"illegal Coordinator transition {self._state.value}->{target.value}",
            )
        self._state = target

    def _new_id(self, prefix: str) -> str:
        validate_identifier(prefix, "id prefix")
        while True:
            value = f"{prefix}-{uuid.uuid4().hex}"
            if value not in self._seen_ids:
                self._seen_ids.add(value)
                return value

    def run(self) -> CoordinatorRunResult:
        if self._started:
            _raise(
                CoordinatorFailureCode.INVALID_STATE_TRANSITION,
                "ValidationCoordinator is one-shot",
            )
        self._started = True
        lifecycles: list[CoordinatorLifecycleRecord] = []
        try:
            for lifecycle_index in range(self.limits.max_lifecycles):
                if lifecycle_index:
                    self._transition(CoordinatorState.A_RUNNING)
                execution = self._run_lifecycle(
                    lifecycle_index=lifecycle_index,
                    already_transitioned=bool(lifecycle_index),
                )
                lifecycles.append(execution.record)
                if execution.restartable and (
                    lifecycle_index + 1 < self.limits.max_lifecycles
                ):
                    continue
                self._transition(CoordinatorState.COMPLETE)
                return CoordinatorRunResult(
                    validation_instance_id=self.identity.validation_instance_id,
                    evidence_storage_authority_id=(
                        self.providers.evidence_storage_authority_id
                    ),
                    completion=execution.record.completion,
                    lifecycles=tuple(lifecycles),
                )
        except CoordinatorError:
            self._state = CoordinatorState.FAILED
            raise
        except (ContractError, WorkspaceError, OSError, RuntimeError) as exc:
            self._state = CoordinatorState.FAILED
            _raise(
                CoordinatorFailureCode.CLEANUP_UNPROVEN,
                "Coordinator failed outside a typed boundary",
                exc,
            )
        except BaseException:
            self._state = CoordinatorState.FAILED
            raise
        raise AssertionError("positive max_lifecycles makes this path unreachable")

    def _run_lifecycle(
        self,
        *,
        lifecycle_index: int,
        already_transitioned: bool,
    ) -> _LifecycleExecution:
        if not already_transitioned:
            self._transition(CoordinatorState.A_RUNNING)
        lifecycle_id = self._new_id(f"lifecycle{lifecycle_index + 1}")
        agent_session_id = self._new_id(f"agent{lifecycle_index + 1}")
        a_policy = build_role_policy(
            WorkspaceRole.A,
            self.profile,
            self.profile.environment.resource_policy,
        )
        try:
            a_allocation = self.workspace_manager.materialize(
                snapshot=self.snapshot,
                identity=self.identity,
                profile=self.profile,
                attempt_id=self._new_id("agent-view"),
                role_policy=a_policy,
                workspace_equivalence_policy=self.workspace_equivalence_policy,
                agent_session_id=agent_session_id,
            )
        except (ContractError, WorkspaceError, OSError) as exc:
            _raise(
                CoordinatorFailureCode.WORKSPACE_ALLOCATION_FAILED,
                "cannot allocate the Agent workspace",
                exc,
            )
        a_lineage = WorkspaceLineageRecord.from_allocation(a_allocation)

        mailbox: CoordinatorMailboxPort | None = None
        agent_handle: object | None = None
        start_result: AgentStartResult | None = None
        start_attempted = False
        stop_called = False
        finish_called = False
        exit_proven = False
        mailbox_disposed = False
        a_released = False
        current_b1: WorkspaceAllocation | None = None
        attempts: list[CoordinatorAttemptRecord] = []
        normal_stop_reason: AgentStopReason | None = None
        normal_exit_proof: AgentExitProof | None = None

        try:
            try:
                mailbox = self.providers.create_mailbox(
                    a_allocation,
                    agent_session_id,
                )
                capacity = mailbox.request_capacity
                if type(capacity) is not int or capacity < 1:
                    raise ContractError(
                        "mailbox request_capacity must be a positive integer"
                    )
                if self.limits.max_submissions_per_session > capacity:
                    _raise(
                        CoordinatorFailureCode.INVALID_CONFIGURATION,
                        "Coordinator submission budget exceeds mailbox capacity",
                    )
            except CoordinatorError:
                raise
            except Exception as exc:
                _raise(
                    CoordinatorFailureCode.MAILBOX_FAILURE,
                    "cannot initialize the Agent mailbox",
                    exc,
                )
            start_request = AgentStartRequest(
                validation_instance_id=self.identity.validation_instance_id,
                lifecycle_id=lifecycle_id,
                agent_session_id=agent_session_id,
                case_id=self.identity.case_id,
                function_id=self.identity.function_id,
                reasoning_sha256=self.identity.reasoning_sha256,
                profile_sha256=self.identity.profile_sha256,
                context_sha256=self.context_sha256,
                submission_budget=self.limits.max_submissions_per_session,
            )
            try:
                start_attempted = True
                candidate_start = self.providers.start_agent(
                    start_request,
                    a_allocation,
                    mailbox.agent_endpoint,
                )
                if type(candidate_start) is not AgentStartResult:
                    raise ContractError(
                        "Agent driver returned no exact AgentStartResult"
                    )
                candidate_start.validate_request(start_request)
                start_result = candidate_start
                agent_handle = candidate_start.handle
            except BaseException as exc:
                _raise(
                    CoordinatorFailureCode.AGENT_START_FAILED,
                    "trusted Agent start is not cleanup-addressable",
                    exc,
                )
            self._transition(CoordinatorState.WAITING_SUBMISSION)

            final_attempt: CoordinatorAttemptRecord | None = None
            final_frozen: FrozenCoordinatorRequest | None = None
            for nonce in range(1, self.limits.max_submissions_per_session + 1):
                try:
                    frozen = mailbox.claim_next(
                        expected_nonce=nonce,
                        is_agent_alive=lambda: self._agent_alive(agent_handle),
                        timeout_ms=self.limits.request_timeout_ms,
                        poll_interval_ms=self.limits.poll_interval_ms,
                    )
                except CoordinatorError:
                    raise
                except Exception as exc:
                    if not self._agent_alive(agent_handle):
                        _raise(
                            CoordinatorFailureCode.AGENT_EXITED_EARLY,
                            "Agent exited before a formal submission was frozen",
                            exc,
                        )
                    _raise(
                        CoordinatorFailureCode.MAILBOX_FAILURE,
                        "mailbox failed while claiming a submission",
                        exc,
                    )
                self._validate_request_authority(
                    frozen,
                    agent_session_id=agent_session_id,
                    expected_nonce=nonce,
                    expected_previous_response_sha256=(
                        None
                        if not attempts
                        else attempts[-1].response.content_sha256
                    ),
                )
                preflight = self._preflight(frozen)
                attempt_id = self._new_id("gate-attempt")
                may_retry = nonce < self.limits.max_submissions_per_session
                b1_lineage: WorkspaceLineageRecord | None = None
                if preflight.state is GatePreflightState.READY_CANDIDATE:
                    b1_policy = build_role_policy(
                        WorkspaceRole.B1,
                        self.profile,
                        self.profile.environment.resource_policy,
                    )
                    try:
                        current_b1 = self.workspace_manager.materialize(
                            snapshot=self.snapshot,
                            identity=self.identity,
                            profile=self.profile,
                            attempt_id=attempt_id,
                            role_policy=b1_policy,
                            workspace_equivalence_policy=(
                                self.workspace_equivalence_policy
                            ),
                            agent_session_id=None,
                        )
                    except (ContractError, WorkspaceError, OSError) as exc:
                        _raise(
                            CoordinatorFailureCode.WORKSPACE_ALLOCATION_FAILED,
                            "cannot allocate a fresh B1 workspace",
                            exc,
                        )
                    b1_lineage = WorkspaceLineageRecord.from_allocation(current_b1)

                self._transition(CoordinatorState.B1_RUNNING)
                gate_request = GateExecutionRequest(
                    validation_instance_id=self.identity.validation_instance_id,
                    lifecycle_id=lifecycle_id,
                    agent_session_id=agent_session_id,
                    attempt_id=attempt_id,
                    role=GateRole.B1,
                    may_retry=may_retry,
                    preflight_state=preflight.state,
                    frozen_request=frozen,
                    submission=preflight.submission,
                    oracle_bundle=preflight.oracle_bundle,
                    oracle_specs=preflight.oracle_specs,
                    workspace=current_b1,
                )
                b1_result = self._evaluate_and_validate(gate_request)
                if b1_result.receipt.disposition is (
                    GateAttemptDisposition.RETRYABLE_REJECTION
                ) and not may_retry:
                    _raise(
                        CoordinatorFailureCode.GATE_RESULT_INVALID,
                        "Gate returned retryable rejection after budget exhaustion",
                    )
                if current_b1 is not None:
                    self._release_workspace(current_b1, "B1")
                    current_b1 = None
                if not self._agent_alive(agent_handle):
                    _raise(
                        CoordinatorFailureCode.AGENT_EXITED_EARLY,
                        "Agent exited before its B1 response was committed",
                    )

                response = self._build_response(
                    frozen=frozen,
                    result=b1_result,
                    remaining_budget=(
                        self.limits.max_submissions_per_session - nonce
                    ),
                )
                disposition = b1_result.receipt.disposition
                if disposition is not GateAttemptDisposition.RETRYABLE_REJECTION:
                    try:
                        mailbox.close_requests()
                    except Exception as exc:
                        _raise(
                            CoordinatorFailureCode.MAILBOX_FAILURE,
                            "cannot close mailbox submissions before Agent exit",
                            exc,
                        )
                if start_result is None:
                    raise AssertionError("successful start must retain its result")
                response_commit = self._commit_agent_response(
                    start_result=start_result,
                    mailbox=mailbox,
                    response=response,
                    frozen=frozen,
                )
                record = CoordinatorAttemptRecord(
                    nonce=nonce,
                    request=frozen.envelope,
                    request_sha256=frozen.request_sha256,
                    gate_attempt_id=attempt_id,
                    response=response,
                    response_commit=response_commit,
                    gate_result=b1_result,
                    b1_workspace=b1_lineage,
                )
                attempts.append(record)
                if disposition is GateAttemptDisposition.RETRYABLE_REJECTION:
                    self._transition(CoordinatorState.WAITING_SUBMISSION)
                    continue
                final_attempt = record
                final_frozen = frozen
                normal_stop_reason = (
                    AgentStopReason.B1_TERMINAL
                    if disposition is GateAttemptDisposition.TERMINAL_OUTCOME
                    else AgentStopReason.B1_ACCEPTED
                )
                break

            if final_attempt is None or final_frozen is None or normal_stop_reason is None:
                _raise(
                    CoordinatorFailureCode.GATE_RESULT_INVALID,
                    "submission budget ended without a terminal B1 receipt",
                )

            self._transition(CoordinatorState.AGENT_EXITING)
            try:
                stop_called = True
                self.providers.request_agent_stop(agent_handle, normal_stop_reason)
            except Exception as exc:
                _raise(
                    CoordinatorFailureCode.AGENT_STOP_FAILED,
                    "trusted Agent driver failed to request stop",
                    exc,
                )
            try:
                finish_called = True
                normal_exit_proof = self.providers.finish_agent(
                    agent_handle,
                    normal_stop_reason,
                )
            except BaseException as exc:
                _raise(
                    CoordinatorFailureCode.AGENT_TEARDOWN_UNPROVEN,
                    "trusted Agent driver failed to finish",
                    exc,
                )
            self._validate_exit_proof(
                normal_exit_proof,
                lifecycle_id=lifecycle_id,
                agent_session_id=agent_session_id,
                authoritative_handle_id=start_result.authoritative_handle_id,
            )
            exit_proven = True
            try:
                mailbox.assert_quiescent()
            except Exception as exc:
                _raise(
                    CoordinatorFailureCode.MAILBOX_FAILURE,
                    "mailbox was not quiescent after Agent exit",
                    exc,
                )
            try:
                mailbox.dispose()
                mailbox_disposed = True
            except BaseException as exc:
                _raise(
                    CoordinatorFailureCode.MAILBOX_FAILURE,
                    "mailbox descriptors were not disposed before A release",
                    exc,
                )
            self._release_workspace(a_allocation, "A")
            a_released = True
            self._transition(CoordinatorState.AGENT_EXITED)

            disposition = final_attempt.gate_result.receipt.disposition
            if disposition is GateAttemptDisposition.TERMINAL_OUTCOME:
                self._transition(CoordinatorState.LIFECYCLE_CLOSED)
                return _LifecycleExecution(
                    record=CoordinatorLifecycleRecord(
                        lifecycle_id=lifecycle_id,
                        agent_session_id=agent_session_id,
                        authoritative_handle_id=(
                            start_result.authoritative_handle_id
                        ),
                        startup_receipt_sha256=(
                            start_result.startup_receipt_sha256
                        ),
                        submission_budget=self.limits.max_submissions_per_session,
                        a_workspace=a_lineage,
                        b1_attempts=tuple(attempts),
                        agent_exit=normal_exit_proof,
                        completion=CoordinatorCompletionKind.B1_TERMINAL_READY,
                    ),
                    restartable=False,
                )

            b2_result, b2_lineage, cross_gate = self._run_b2(
                lifecycle_id=lifecycle_id,
                frozen=final_frozen,
                b1_attempt=final_attempt,
                a_lineage=a_lineage,
            )
            if disposition is GateAttemptDisposition.ACCEPTED_EXPLICIT_NOT_CONFIRMED:
                completion = CoordinatorCompletionKind.EXPLICIT_NOT_CONFIRMED_READY
                restartable = False
            elif type(b2_result.receipt) is not CandidateGateReceipt or (
                b2_result.receipt.result_status
                not in (CaseStatus.CONFIRMED_L0, CaseStatus.CONFIRMED_L1)
            ):
                completion = CoordinatorCompletionKind.B2_RECHECK_FAILED
                restartable = True
            elif cross_gate is None:
                _raise(
                    CoordinatorFailureCode.CROSS_GATE_INVALID,
                    "confirmed Gate pair lacks a Cross-Gate decision",
                )
            elif cross_gate.verdict is CrossGateVerdict.REPRODUCIBLE:
                completion = CoordinatorCompletionKind.CONFIRMED_READY
                restartable = False
            else:
                completion = CoordinatorCompletionKind.CROSS_GATE_FAILED
                restartable = True
            self._transition(CoordinatorState.LIFECYCLE_CLOSED)
            return _LifecycleExecution(
                record=CoordinatorLifecycleRecord(
                    lifecycle_id=lifecycle_id,
                    agent_session_id=agent_session_id,
                    authoritative_handle_id=start_result.authoritative_handle_id,
                    startup_receipt_sha256=start_result.startup_receipt_sha256,
                    submission_budget=self.limits.max_submissions_per_session,
                    a_workspace=a_lineage,
                    b1_attempts=tuple(attempts),
                    agent_exit=normal_exit_proof,
                    completion=completion,
                    b2_result=b2_result,
                    b2_workspace=b2_lineage,
                    cross_gate_decision=cross_gate,
                ),
                restartable=restartable,
            )
        except BaseException as original:
            cleanup_failure: BaseException | None = None
            if current_b1 is not None:
                try:
                    self.workspace_manager.release(current_b1)
                except BaseException as exc:
                    cleanup_failure = exc
            if mailbox is not None and not mailbox_disposed:
                # A failed lifecycle publishes no record and never reaches B2.
                # Close+dispose abandons any outstanding request; A release
                # still requires a complete Agent exit proof below.  Strict
                # quiescence is reserved for the successful barrier above.
                try:
                    mailbox.close_requests()
                except BaseException as exc:
                    cleanup_failure = cleanup_failure or exc
            if agent_handle is not None and not finish_called:
                cleanup_stop_failure: BaseException | None = None
                if not stop_called:
                    stop_called = True
                    try:
                        self.providers.request_agent_stop(
                            agent_handle,
                            AgentStopReason.COORDINATOR_FAILURE,
                        )
                    except BaseException as exc:
                        # finish_agent is the authoritative teardown barrier.  A
                        # failed cooperative stop request must not prevent it.
                        cleanup_stop_failure = exc
                try:
                    finish_called = True
                    proof = self.providers.finish_agent(
                        agent_handle,
                        AgentStopReason.COORDINATOR_FAILURE,
                    )
                    self._validate_exit_proof(
                        proof,
                        lifecycle_id=lifecycle_id,
                        agent_session_id=agent_session_id,
                        authoritative_handle_id=(
                            start_result.authoritative_handle_id
                            if start_result is not None
                            else "unreachable-missing-start-result"
                        ),
                    )
                    exit_proven = True
                except BaseException as exc:
                    cleanup_failure = (
                        cleanup_failure or cleanup_stop_failure or exc
                    )
            if mailbox is not None and not mailbox_disposed:
                try:
                    mailbox.dispose()
                    mailbox_disposed = True
                except BaseException as exc:
                    cleanup_failure = cleanup_failure or exc
            if not a_released:
                safe_without_agent = not start_attempted and agent_handle is None
                if (
                    (safe_without_agent or exit_proven)
                    and (mailbox is None or mailbox_disposed)
                ):
                    try:
                        self.workspace_manager.release(a_allocation)
                        a_released = True
                    except BaseException as exc:
                        cleanup_failure = cleanup_failure or exc
            if cleanup_failure is not None:
                _raise(
                    CoordinatorFailureCode.CLEANUP_UNPROVEN,
                    "Coordinator cleanup could not be proven complete",
                    cleanup_failure,
                )
            raise original

    def _agent_alive(self, handle: object) -> bool:
        try:
            alive = self.providers.agent_is_alive(handle)
        except Exception as exc:
            _raise(
                CoordinatorFailureCode.AGENT_TEARDOWN_UNPROVEN,
                "trusted Agent liveness probe failed",
                exc,
            )
        if type(alive) is not bool:
            _raise(
                CoordinatorFailureCode.AGENT_TEARDOWN_UNPROVEN,
                "trusted Agent liveness probe returned a non-boolean",
            )
        return alive

    def _commit_agent_response(
        self,
        *,
        start_result: AgentStartResult,
        mailbox: CoordinatorMailboxPort,
        response: CoordinatorResponseEnvelope,
        frozen: FrozenCoordinatorRequest,
    ) -> AgentResponseCommitProof:
        """Publish once inside the driver's authoritative live-handle fence."""

        request = AgentResponseCommitRequest(
            lifecycle_id=start_result.lifecycle_id,
            agent_session_id=start_result.agent_session_id,
            authoritative_handle_id=start_result.authoritative_handle_id,
            nonce=response.nonce,
            request_sha256=frozen.request_sha256,
            response_sha256=response.content_sha256,
        )
        callback_calls = 0
        committed_sha256: str | None = None
        callback_open = True
        callback_lock = Lock()

        def commit() -> str:
            nonlocal callback_calls, committed_sha256
            with callback_lock:
                if not callback_open:
                    raise ContractError("response commit fence is already closed")
                callback_calls += 1
                if callback_calls != 1:
                    raise ContractError(
                        "response commit callback may be called only once"
                    )
                published_sha256 = mailbox.publish_response(response, frozen)
                if published_sha256 != response.content_sha256:
                    raise ContractError(
                        "mailbox did not return the durable response digest"
                    )
                committed_sha256 = published_sha256
                return committed_sha256

        try:
            try:
                proof = self.providers.commit_agent_response(
                    start_result.handle,
                    request,
                    commit,
                )
            finally:
                with callback_lock:
                    callback_open = False
        except BaseException as exc:
            if not self._agent_alive(start_result.handle):
                _raise(
                    CoordinatorFailureCode.AGENT_EXITED_EARLY,
                    "Agent exited before the B1 response commit fence completed",
                    exc,
                )
            _raise(
                CoordinatorFailureCode.AGENT_RESPONSE_COMMIT_UNPROVEN,
                "trusted driver could not prove the B1 response commit",
                exc,
            )
        try:
            if type(proof) is not AgentResponseCommitProof:
                raise ContractError(
                    "driver returned no exact AgentResponseCommitProof"
                )
            if callback_calls != 1 or committed_sha256 != request.response_sha256:
                raise ContractError(
                    "driver did not invoke the exact response commit once"
                )
            proof.validate_request(request)
        except ContractError as exc:
            if not self._agent_alive(start_result.handle):
                _raise(
                    CoordinatorFailureCode.AGENT_EXITED_EARLY,
                    "Agent was not alive after the B1 response was committed",
                    exc,
                )
            _raise(
                CoordinatorFailureCode.AGENT_RESPONSE_COMMIT_UNPROVEN,
                "response commit proof failed exact binding validation",
                exc,
            )
        return proof

    def _validate_exit_proof(
        self,
        proof: object,
        *,
        lifecycle_id: str,
        agent_session_id: str,
        authoritative_handle_id: str,
    ) -> None:
        if type(proof) is not AgentExitProof:
            _raise(
                CoordinatorFailureCode.AGENT_TEARDOWN_UNPROVEN,
                "Agent driver returned no exact exit proof",
            )
        try:
            proof.validate_complete(
                lifecycle_id=lifecycle_id,
                agent_session_id=agent_session_id,
                authoritative_handle_id=authoritative_handle_id,
            )
        except ContractError as exc:
            _raise(
                CoordinatorFailureCode.AGENT_TEARDOWN_UNPROVEN,
                "Agent teardown proof is incomplete",
                exc,
            )

    def _validate_request_authority(
        self,
        frozen: FrozenCoordinatorRequest,
        *,
        agent_session_id: str,
        expected_nonce: int,
        expected_previous_response_sha256: str | None,
    ) -> None:
        try:
            _validate_frozen_request(frozen)
            envelope = frozen.envelope
            authority = (
                envelope.validation_instance_id
                == self.identity.validation_instance_id
                and envelope.case_id == self.identity.case_id
                and envelope.function_id == self.identity.function_id
                and envelope.reasoning_sha256 == self.identity.reasoning_sha256
                and envelope.profile_sha256 == self.identity.profile_sha256
                and envelope.context_sha256 == self.context_sha256
                and envelope.agent_session_id == agent_session_id
                and envelope.nonce == expected_nonce
                and envelope.previous_response_sha256
                == expected_previous_response_sha256
                and frozen.request_sha256 == envelope.content_sha256
            )
        except (AttributeError, ContractError, TypeError, ValueError) as exc:
            _raise(
                CoordinatorFailureCode.REQUEST_IDENTITY_MISMATCH,
                "frozen request is not bound to authority context",
                exc,
            )
        if not authority:
            _raise(
                CoordinatorFailureCode.REQUEST_IDENTITY_MISMATCH,
                "frozen request authority identity mismatch",
            )

    def _preflight(self, frozen: FrozenCoordinatorRequest) -> _PreflightResult:
        try:
            submission = CaseSubmission.from_json(frozen.raw_submission_bytes)
        except ContractError:
            return _PreflightResult(
                GatePreflightState.INTAKE_INVALID,
                None,
                None,
                (),
            )
        if submission.submission_kind is CaseSubmissionKind.NOT_CONFIRMED:
            try:
                validate_case_submission_membership(
                    submission,
                    identity=self.identity,
                    profile=self.profile,
                )
            except ContractError:
                return _PreflightResult(
                    GatePreflightState.MEMBERSHIP_INVALID,
                    submission,
                    None,
                    (),
                )
            return _PreflightResult(
                GatePreflightState.READY_FAST_PATH,
                submission,
                None,
                (),
            )
        try:
            if submission.case_plan is None:
                raise ContractError("candidate submission is missing CasePlan")
            bundle, specs = self._resolve_oracle_graph(submission.case_plan)
            validate_case_submission_membership(
                submission,
                identity=self.identity,
                profile=self.profile,
                oracle_bundle=bundle,
                oracle_specs=specs,
            )
        except ContractError:
            return _PreflightResult(
                GatePreflightState.MEMBERSHIP_INVALID,
                submission,
                None,
                (),
            )
        try:
            self._validate_case_artifacts(submission.case_plan, frozen)
        except ContractError:
            return _PreflightResult(
                GatePreflightState.CONTEXT_INVALID,
                submission,
                None,
                (),
            )
        return _PreflightResult(
            GatePreflightState.READY_CANDIDATE,
            submission,
            bundle,
            specs,
        )

    def _resolve_oracle_graph(
        self,
        plan: CasePlan,
    ) -> tuple[OracleBundle, tuple[OracleSpec, ...]]:
        bundle_by_ref = {bundle.ref: bundle for bundle in self.oracle_bundles}
        spec_by_ref = {spec.ref: spec for spec in self.oracle_specs}
        bundle = bundle_by_ref.get(plan.oracle_bundle)
        if bundle is None:
            raise ContractError("CasePlan OracleBundle is unresolved")
        pending = list(bundle.oracle_spec_refs)
        resolved: set[ContractRef] = set()
        while pending:
            reference = pending.pop(0)
            if reference in resolved:
                continue
            spec = spec_by_ref.get(reference)
            if spec is None:
                raise ContractError("CasePlan OracleSpec closure is unresolved")
            resolved.add(reference)
            pending.extend(spec.dependent_oracle_spec_refs)
        specs = tuple(
            sorted(
                (spec_by_ref[reference] for reference in resolved),
                key=lambda value: (
                    value.ref.contract_id,
                    value.ref.contract_version,
                    value.ref.content_sha256,
                ),
            )
        )
        return bundle, specs

    @staticmethod
    def _validate_case_artifacts(
        plan: CasePlan,
        frozen: FrozenCoordinatorRequest,
    ) -> None:
        expected = (
            plan.workload.artifact,
            plan.target_evidence.expected_input,
            plan.target_evidence.predicted_buggy_output,
            *(() if plan.repair is None else (plan.repair.patch,)),
            *plan.artifacts,
        )
        actual = tuple(binding.artifact for binding in frozen.envelope.artifacts)
        sort_key = lambda artifact: (
            artifact.role,
            artifact.media_type,
            artifact.size_bytes,
            artifact.content_sha256,
        )
        if tuple(sorted(actual, key=sort_key)) != tuple(sorted(expected, key=sort_key)):
            raise ContractError(
                "staged artifacts do not exactly match CasePlan artifact refs"
            )

    def _evaluate_and_validate(
        self,
        request: GateExecutionRequest,
    ) -> GateExecutionResult:
        try:
            result = self.providers.evaluate_gate(request)
        except Exception as exc:
            _raise(
                CoordinatorFailureCode.GATE_EXECUTION_FAILED,
                "trusted Gate provider failed",
                exc,
            )
        if type(result) is not GateExecutionResult:
            _raise(
                CoordinatorFailureCode.GATE_RESULT_INVALID,
                "Gate provider returned no exact GateExecutionResult",
            )
        try:
            persistence = result.evidence_persistence
            if (
                persistence.lifecycle_id != request.lifecycle_id
                or persistence.storage_authority_id
                != self.providers.evidence_storage_authority_id
            ):
                raise ContractError(
                    "Gate persistence proof does not bind this lifecycle"
                )
        except (ContractError, AttributeError, TypeError, ValueError) as exc:
            _raise(
                CoordinatorFailureCode.EVIDENCE_NOT_PERSISTED,
                "Gate evidence lacks an exact durable persistence proof",
                exc,
            )
        try:
            self._validate_gate_result(request, result)
        except (ContractError, AttributeError, TypeError, ValueError) as exc:
            _raise(
                CoordinatorFailureCode.GATE_RESULT_INVALID,
                "Gate result failed frozen-graph validation",
                exc,
            )
        return result

    def _validate_gate_result(
        self,
        request: GateExecutionRequest,
        result: GateExecutionResult,
    ) -> None:
        receipt = result.receipt
        if (
            receipt.validation_instance_id != self.identity.validation_instance_id
            or receipt.attempt_id != request.attempt_id
            or receipt.role is not request.role
        ):
            raise ContractError("Gate receipt identity, attempt, or role mismatch")
        if type(receipt) is EarlyGateReceipt:
            if request.preflight_state is GatePreflightState.READY_FAST_PATH:
                raise ContractError("ready fast path cannot return an early receipt")
            if (
                request.preflight_state is GatePreflightState.INTAKE_INVALID
                and receipt.failure_stage is not EarlyGateStage.INTAKE
            ):
                raise ContractError(
                    "intake-invalid input requires an intake failure receipt"
                )
            if (
                request.preflight_state is GatePreflightState.MEMBERSHIP_INVALID
                and receipt.failure_stage is not EarlyGateStage.MEMBERSHIP
            ):
                raise ContractError(
                    "membership-invalid input requires a membership failure receipt"
                )
            if (
                request.preflight_state is GatePreflightState.CONTEXT_INVALID
                and receipt.failure_stage is not EarlyGateStage.CONTEXT_INTEGRITY
            ):
                raise ContractError(
                    "context-invalid input requires a context-integrity receipt"
                )
            if (
                request.preflight_state is GatePreflightState.READY_CANDIDATE
                and receipt.failure_stage is not EarlyGateStage.MATERIALIZE
            ):
                raise ContractError(
                    "a ready candidate may fail only at materialization before execution"
                )
            if receipt.failure_stage is EarlyGateStage.INTAKE:
                parsed_submission = None
                parsed_profile = None
                parsed_plan = None
            else:
                parsed_submission = request.submission
                parsed_profile = self.profile
                parsed_plan = (
                    None
                    if request.submission is None
                    else request.submission.case_plan
                )
            validate_early_gate_receipt_identity(
                receipt,
                identity=self.identity,
                context_sha256=self.context_sha256,
                raw_submission=request.frozen_request.envelope.raw_submission.artifact,
                submission=parsed_submission,
                profile=parsed_profile,
                case_plan=parsed_plan,
            )
            return

        if type(receipt) is FastPathGateReceipt:
            if request.preflight_state is not GatePreflightState.READY_FAST_PATH:
                raise ContractError("fast receipt requires a ready fast-path input")
            if request.submission is None:
                raise ContractError("fast receipt has no parsed submission")
            validate_fast_path_gate_receipt_identity(
                receipt,
                identity=self.identity,
                submission=request.submission,
                context_sha256=self.context_sha256,
            )
            return

        if request.preflight_state is not GatePreflightState.READY_CANDIDATE:
            raise ContractError("candidate receipt requires a ready candidate input")
        if (
            request.submission is None
            or request.submission.case_plan is None
            or request.oracle_bundle is None
            or request.workspace is None
            or result.adapter is None
            or result.template is None
            or result.binding is None
        ):
            raise ContractError("candidate result lacks its frozen graph")
        validate_experiment_plan_membership(
            result.template,
            profile=self.profile,
            case_plan=request.submission.case_plan,
            adapter=result.adapter,
            oracle_bundle=request.oracle_bundle,
            oracle_specs=request.oracle_specs,
            baseline_receipts=result.baseline_receipts,
        )
        validate_execution_binding(result.template, result.binding)
        if (
            result.binding.attempt_id != request.attempt_id
            or result.binding.role is not request.role
        ):
            raise ContractError("candidate ExecutionBinding context mismatch")
        workspace_resource = request.workspace.lease.to_dynamic_resource_binding(
            request.role
        )
        resources = {resource.symbol: resource for resource in result.binding.resources}
        if resources.get("workspace.project") != workspace_resource:
            raise ContractError(
                "candidate ExecutionBinding does not bind the allocated workspace"
            )
        validate_candidate_gate_receipt_membership(
            receipt,
            submission=request.submission,
            profile=self.profile,
            case_plan=request.submission.case_plan,
            oracle_bundle=request.oracle_bundle,
            template=result.template,
            binding=result.binding,
            observations=result.observations,
            decisions=result.decisions,
        )
        spec_by_ref = {spec.ref: spec for spec in request.oracle_specs}
        baseline_by_ref = {
            baseline.ref: baseline for baseline in result.baseline_receipts
        }
        observation_by_ref = {
            observation.ref: observation for observation in result.observations
        }
        planned_by_spec = {
            execution.oracle_spec: execution
            for execution in result.template.oracle_executions
        }
        for decision in result.decisions:
            planned = planned_by_spec[decision.oracle_spec]
            decision_observations = tuple(
                observation_by_ref[reference]
                for reference in decision.observations
            )
            validate_oracle_decision_evidence(
                decision,
                template=result.template,
                binding=result.binding,
                oracle_spec=spec_by_ref[decision.oracle_spec],
                observations=decision_observations,
                baseline_receipt=(
                    None
                    if planned.baseline_selection is None
                    else baseline_by_ref[planned.baseline_selection]
                ),
            )

    def _build_response(
        self,
        *,
        frozen: FrozenCoordinatorRequest,
        result: GateExecutionResult,
        remaining_budget: int,
    ) -> CoordinatorResponseEnvelope:
        receipt = result.receipt
        disposition = receipt.disposition
        if type(disposition) is not GateAttemptDisposition:
            _raise(
                CoordinatorFailureCode.GATE_RESULT_INVALID,
                "B1 receipt lacks an attempt disposition",
            )
        if type(receipt) is FastPathGateReceipt:
            status = CaseStatus.NOT_CONFIRMED
            reason = CaseReasonCode.EXPLICIT_NOT_CONFIRMED
        else:
            status = receipt.result_status
            reason = receipt.result_reason_code
        terminal = disposition is GateAttemptDisposition.TERMINAL_OUTCOME
        try:
            response = CoordinatorResponseEnvelope(
                validation_instance_id=self.identity.validation_instance_id,
                case_id=self.identity.case_id,
                function_id=self.identity.function_id,
                reasoning_sha256=self.identity.reasoning_sha256,
                profile_sha256=self.identity.profile_sha256,
                context_sha256=self.context_sha256,
                agent_session_id=frozen.envelope.agent_session_id,
                nonce=frozen.envelope.nonce,
                request_sha256=frozen.request_sha256,
                gate_attempt_id=receipt.attempt_id,
                b1_receipt=receipt.ref,
                disposition=disposition,
                result_status=status,
                result_reason_code=reason,
                remaining_submission_budget=remaining_budget,
                terminal_status=status if terminal else None,
                terminal_reason_code=reason if terminal else None,
                diagnostics=result.diagnostics,
            )
            response.validate_request(frozen.envelope)
            return response
        except ContractError as exc:
            _raise(
                CoordinatorFailureCode.GATE_RESULT_INVALID,
                "B1 result cannot form a normative response",
                exc,
            )

    def _run_b2(
        self,
        *,
        lifecycle_id: str,
        frozen: FrozenCoordinatorRequest,
        b1_attempt: CoordinatorAttemptRecord,
        a_lineage: WorkspaceLineageRecord,
    ) -> tuple[
        GateExecutionResult,
        WorkspaceLineageRecord | None,
        CrossGateDecision | None,
    ]:
        b1_result = b1_attempt.gate_result
        b1_receipt = b1_result.receipt
        disposition = b1_receipt.disposition
        if disposition not in (
            GateAttemptDisposition.ACCEPTED_CONFIRMED_CANDIDATE,
            GateAttemptDisposition.ACCEPTED_EXPLICIT_NOT_CONFIRMED,
        ):
            _raise(
                CoordinatorFailureCode.INVALID_STATE_TRANSITION,
                "B2 may start only after an accepted B1 receipt",
            )
        self._transition(CoordinatorState.B2_RUNNING)
        preflight = self._preflight(frozen)
        b2_allocation: WorkspaceAllocation | None = None
        b2_lineage: WorkspaceLineageRecord | None = None
        try:
            if disposition is GateAttemptDisposition.ACCEPTED_EXPLICIT_NOT_CONFIRMED:
                if preflight.state is not GatePreflightState.READY_FAST_PATH:
                    _raise(
                        CoordinatorFailureCode.GATE_RESULT_INVALID,
                        "accepted fast-path request changed before B2",
                    )
            else:
                if (
                    preflight.state is not GatePreflightState.READY_CANDIDATE
                    or b1_attempt.b1_workspace is None
                    or b1_result.template is None
                    or b1_result.adapter is None
                ):
                    _raise(
                        CoordinatorFailureCode.GATE_RESULT_INVALID,
                        "accepted candidate graph is unavailable for B2",
                    )
                b2_policy = build_role_policy(
                    WorkspaceRole.B2,
                    self.profile,
                    self.profile.environment.resource_policy,
                )
                try:
                    b2_allocation = self.workspace_manager.materialize(
                        snapshot=self.snapshot,
                        identity=self.identity,
                        profile=self.profile,
                        attempt_id=b1_receipt.attempt_id,
                        role_policy=b2_policy,
                        workspace_equivalence_policy=(
                            self.workspace_equivalence_policy
                        ),
                        agent_session_id=None,
                    )
                except (ContractError, WorkspaceError, OSError) as exc:
                    _raise(
                        CoordinatorFailureCode.WORKSPACE_ALLOCATION_FAILED,
                        "cannot allocate a fresh B2 workspace",
                        exc,
                    )
                b2_lineage = WorkspaceLineageRecord.from_allocation(b2_allocation)

            request = GateExecutionRequest(
                validation_instance_id=self.identity.validation_instance_id,
                lifecycle_id=lifecycle_id,
                agent_session_id=None,
                attempt_id=b1_receipt.attempt_id,
                role=GateRole.B2,
                may_retry=False,
                preflight_state=preflight.state,
                frozen_request=frozen,
                submission=preflight.submission,
                oracle_bundle=preflight.oracle_bundle,
                oracle_specs=preflight.oracle_specs,
                workspace=b2_allocation,
                expected_template=(
                    b1_result.template
                    if disposition
                    is GateAttemptDisposition.ACCEPTED_CONFIRMED_CANDIDATE
                    else None
                ),
                expected_adapter=(
                    b1_result.adapter
                    if disposition
                    is GateAttemptDisposition.ACCEPTED_CONFIRMED_CANDIDATE
                    else None
                ),
            )
            b2_result = self._evaluate_and_validate(request)
            validate_b1_b2_gate_receipts(b1_receipt, b2_result.receipt)
            if disposition is GateAttemptDisposition.ACCEPTED_EXPLICIT_NOT_CONFIRMED:
                if type(b2_result.receipt) is not FastPathGateReceipt:
                    raise ContractError("explicit not_confirmed B2 must be fast-path")
            else:
                if b2_lineage is None or b1_attempt.b1_workspace is None:
                    raise ContractError("candidate B2 lacks workspace lineage")
                validate_workspace_lineage(
                    a_lineage,
                    b1_attempt.b1_workspace,
                    b2_lineage,
                )
                if type(b2_result.receipt) is CandidateGateReceipt:
                    if (
                        b1_result.template is None
                        or b2_result.template is None
                        or b1_result.binding is None
                        or b2_result.binding is None
                    ):
                        raise ContractError("candidate pair lacks binding graph")
                    validate_template_determinism(
                        b1_result.template,
                        b2_result.template,
                    )
                    if b1_result.adapter != b2_result.adapter:
                        raise ContractError("B1/B2 selected different Adapters")
                    if b1_result.baseline_receipts != b2_result.baseline_receipts:
                        raise ContractError("B1/B2 selected different baselines")
                    validate_b1_b2_binding_equivalence(
                        b1_result.template,
                        b1_result.binding,
                        b2_result.binding,
                    )
                    validate_b1_b2_observation_independence(
                        b1_result.observations,
                        b2_result.observations,
                    )
        except CoordinatorError:
            raise
        except (ContractError, WorkspaceError, AttributeError, TypeError, ValueError) as exc:
            _raise(
                CoordinatorFailureCode.GATE_RESULT_INVALID,
                "B1/B2 pair failed independence validation",
                exc,
            )
        finally:
            if b2_allocation is not None:
                self._release_workspace(b2_allocation, "B2")

        cross_gate: CrossGateDecision | None = None
        if (
            type(b1_receipt) is CandidateGateReceipt
            and type(b2_result.receipt) is CandidateGateReceipt
            and b2_result.receipt.result_status
            in (CaseStatus.CONFIRMED_L0, CaseStatus.CONFIRMED_L1)
        ):
            comparison_request = CrossGateComparisonRequest(
                validation_instance_id=self.identity.validation_instance_id,
                lifecycle_id=lifecycle_id,
                attempt_id=b1_receipt.attempt_id,
                b1=b1_result,
                b2=b2_result,
            )
            try:
                cross_gate = self.providers.compare_cross_gate(comparison_request)
                validate_cross_gate_decision(
                    cross_gate,
                    b1_receipt,
                    b2_result.receipt,
                )
            except (ContractError, AttributeError, TypeError, ValueError) as exc:
                _raise(
                    CoordinatorFailureCode.CROSS_GATE_INVALID,
                    "Cross-Gate comparison failed exact receipt validation",
                    exc,
                )
            except Exception as exc:
                _raise(
                    CoordinatorFailureCode.CROSS_GATE_INVALID,
                    "trusted Cross-Gate provider failed",
                    exc,
                )
        return b2_result, b2_lineage, cross_gate

    def _release_workspace(
        self,
        allocation: WorkspaceAllocation,
        role: str,
    ) -> None:
        try:
            self.workspace_manager.release(allocation)
        except (WorkspaceError, OSError) as exc:
            _raise(
                CoordinatorFailureCode.WORKSPACE_RELEASE_FAILED,
                f"cannot prove complete {role} workspace release",
                exc,
            )


__all__ = [
    "AgentExitProof",
    "AgentResponseCommitProof",
    "AgentResponseCommitRequest",
    "AgentStartRequest",
    "AgentStartResult",
    "AgentStopReason",
    "CoordinatorAttemptRecord",
    "CoordinatorCompletionKind",
    "CoordinatorError",
    "CoordinatorFailureCode",
    "CoordinatorLifecycleRecord",
    "CoordinatorLimits",
    "CoordinatorMailboxPort",
    "CoordinatorProviders",
    "CoordinatorRunResult",
    "CoordinatorState",
    "CrossGateComparisonRequest",
    "GateExecutionRequest",
    "GateExecutionResult",
    "GateEvidencePersistenceProof",
    "GatePreflightState",
    "ValidationCoordinator",
    "create_filesystem_mailbox",
]

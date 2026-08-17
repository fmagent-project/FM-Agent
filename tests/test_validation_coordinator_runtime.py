import dataclasses
import hashlib
from pathlib import Path
import tempfile
import threading
import unittest
from unittest import mock

from src.validation_core.contracts.base import ContractError, canonical_json_bytes
from src.validation_core.contracts.case import (
    CaseSubmission,
    CaseSubmissionKind,
)
from src.validation_core.contracts.coordinator import (
    CoordinatorRequestEnvelope,
    StagedArtifactBinding,
)
from src.validation_core.contracts.outcome import (
    CrossGateDecision,
    CrossGateVerdict,
)
from src.validation_core.contracts.plan import ExperimentPhase, GateRole
from src.validation_core.contracts.receipt import (
    EarlyGateReceipt,
    EarlyGateStage,
    FastPathCheck,
    FastPathGateReceipt,
)
from src.validation_core.contracts.references import ArtifactRef
from src.validation_core.contracts.status import (
    CaseReasonCode,
    CaseStatus,
    GateAttemptDisposition,
    GatePhaseStatus,
    ValidationGrade,
)
from src.validation_core.execution.coordinator import (
    AgentExitProof,
    AgentResponseCommitProof,
    AgentStartResult,
    AgentStopReason,
    CoordinatorCompletionKind,
    CoordinatorError,
    CoordinatorFailureCode,
    CoordinatorAttemptRecord,
    CoordinatorLimits,
    CoordinatorProviders,
    CoordinatorRunResult,
    CoordinatorState,
    GateEvidencePersistenceProof,
    GateExecutionResult,
    GatePreflightState,
    ValidationCoordinator,
)
from src.validation_core.execution.mailbox import (
    CoordinatorMailbox,
    FrozenCoordinatorRequest,
    FrozenStagedArtifact,
)
from src.validation_core.execution.role_policy import WorkspaceRole
from src.validation_core.execution.workspace import WorkspaceManager
from src.validation_core.storage.snapshot import SnapshotStore
from tests.test_validation_case_contracts import _candidate as _case_submission
from tests.test_validation_plan_contracts import _binding, _membership_fixture
from tests.test_validation_receipt_contracts import _confirmed_proof
from tests.test_validation_snapshot_runtime import _policy


def _digest(value):
    if isinstance(value, str):
        value = value.encode("utf-8")
    return hashlib.sha256(value).hexdigest()


def _rebase_fixture(snapshot_sha256):
    fixture = _membership_fixture(causal=True, repair=True)
    profile = dataclasses.replace(
        fixture["profile"],
        project=dataclasses.replace(
            fixture["profile"].project,
            source_snapshot_sha256=snapshot_sha256,
        ),
    )
    identity = dataclasses.replace(
        fixture["identity"],
        snapshot_sha256=snapshot_sha256,
        profile_sha256=profile.content_sha256,
    )
    case_plan = dataclasses.replace(
        fixture["case_plan"],
        validation_instance_id=identity.validation_instance_id,
        profile=profile.ref,
    )
    template = dataclasses.replace(
        fixture["template"],
        validation_instance_id=identity.validation_instance_id,
        profile=profile.ref,
        case_plan=case_plan.ref,
    )
    return {
        **fixture,
        "profile": profile,
        "identity": identity,
        "case_plan": case_plan,
        "template": template,
    }


def _case_artifacts(submission):
    if submission.submission_kind is CaseSubmissionKind.NOT_CONFIRMED:
        return ()
    plan = submission.case_plan
    if plan is None:  # pragma: no cover - CaseSubmission rejects this shape
        raise AssertionError("candidate fixture has no CasePlan")
    return (
        plan.workload.artifact,
        plan.target_evidence.expected_input,
        plan.target_evidence.predicted_buggy_output,
        *(() if plan.repair is None else (plan.repair.patch,)),
        *plan.artifacts,
    )


def _frozen_request(
    submission,
    *,
    identity,
    context_sha256,
    agent_session_id,
    nonce,
    previous_response_sha256,
):
    raw_payload = canonical_json_bytes(submission.to_document())
    raw_binding = StagedArtifactBinding(
        relative_path=f"submissions/{nonce}/submission.json",
        artifact=ArtifactRef(
            role="raw_submission",
            media_type="application/json",
            size_bytes=len(raw_payload),
            content_sha256=_digest(raw_payload),
        ),
    )
    payload_by_path = {}
    bindings = []
    for artifact in _case_artifacts(submission):
        # tests.test_validation_case_contracts._artifact hashes the role text.
        payload = artifact.role.encode("utf-8")
        if (
            len(payload) != artifact.size_bytes
            or _digest(payload) != artifact.content_sha256
        ):
            raise AssertionError("fixture artifact payload no longer matches helper")
        path = f"submissions/{nonce}/artifacts/{artifact.role}.json"
        binding = StagedArtifactBinding(path, artifact)
        bindings.append(binding)
        payload_by_path[path] = payload
    envelope = CoordinatorRequestEnvelope(
        validation_instance_id=identity.validation_instance_id,
        case_id=identity.case_id,
        function_id=identity.function_id,
        reasoning_sha256=identity.reasoning_sha256,
        profile_sha256=identity.profile_sha256,
        context_sha256=context_sha256,
        agent_session_id=agent_session_id,
        nonce=nonce,
        previous_response_sha256=previous_response_sha256,
        raw_submission=raw_binding,
        artifacts=tuple(bindings),
    )
    transport = envelope.to_json()
    return FrozenCoordinatorRequest(
        envelope=envelope,
        request_sha256=envelope.content_sha256,
        transport_sha256=_digest(transport),
        transport_bytes=transport,
        raw_submission=FrozenStagedArtifact(raw_binding, raw_payload),
        artifacts=tuple(
            FrozenStagedArtifact(binding, payload_by_path[binding.relative_path])
            for binding in envelope.artifacts
        ),
    )


def _rebind_frozen_request(
    frozen,
    *,
    raw_submission=None,
    artifacts=None,
):
    raw_submission = raw_submission or frozen.raw_submission
    artifacts = frozen.artifacts if artifacts is None else tuple(artifacts)
    envelope = dataclasses.replace(
        frozen.envelope,
        raw_submission=raw_submission.binding,
        artifacts=tuple(item.binding for item in artifacts),
    )
    transport = envelope.to_json()
    return FrozenCoordinatorRequest(
        envelope=envelope,
        request_sha256=envelope.content_sha256,
        transport_sha256=_digest(transport),
        transport_bytes=transport,
        raw_submission=raw_submission,
        artifacts=artifacts,
    )


class _FakeMailbox:
    def __init__(self, harness, allocation, session_id, submissions):
        self.harness = harness
        self.allocation = allocation
        self.session_id = session_id
        self.submissions = tuple(submissions)
        self.lifecycle_id = None
        self.closed = False
        self.outstanding = None
        self.responses = []
        self.claimed = []
        self.release_before_response = []
        self.disposed = False

    @property
    def agent_endpoint(self):
        return self

    @property
    def request_capacity(self):
        return getattr(self.harness, "request_capacity", 1_000_000)

    def claim_next(
        self,
        *,
        expected_nonce,
        is_agent_alive,
        timeout_ms,
        poll_interval_ms,
    ):
        del timeout_ms, poll_interval_ms
        if self.closed:
            raise RuntimeError("claim attempted after mailbox closure")
        if self.outstanding is not None:
            raise RuntimeError("two outstanding requests")
        if type(is_agent_alive()) is not bool or not is_agent_alive():
            raise RuntimeError("Agent is not alive")
        if expected_nonce != len(self.claimed) + 1:
            raise RuntimeError("nonce is not monotonic")
        try:
            submission = self.submissions[expected_nonce - 1]
        except IndexError as exc:
            raise RuntimeError("script has no next submission") from exc
        frozen = _frozen_request(
            submission,
            identity=self.harness.fixture["identity"],
            context_sha256=self.harness.context_sha256,
            agent_session_id=self.session_id,
            nonce=expected_nonce,
            previous_response_sha256=(
                None
                if expected_nonce == 1
                else self.responses[-1].content_sha256
            ),
        )
        self.claimed.append(frozen)
        self.outstanding = frozen
        return frozen

    def close_requests(self):
        self.closed = True

    def publish_response(self, response, frozen_request):
        if frozen_request is not self.outstanding:
            raise RuntimeError("response does not bind outstanding request")
        response.validate_request(frozen_request.envelope)
        root = self.harness.b1_roots_by_attempt.get(response.gate_attempt_id)
        released = root is None or not root.exists()
        self.release_before_response.append(released)
        if not released:
            raise RuntimeError("B1 remained live while response was published")
        self.responses.append(response)
        self.outstanding = None
        return response.content_sha256

    def assert_quiescent(self):
        if not self.closed:
            raise RuntimeError("mailbox is not closed and quiescent")

    def dispose(self):
        self.disposed = True


class _PreflightMailbox(_FakeMailbox):
    def claim_next(self, **kwargs):
        frozen = super().claim_next(**kwargs)
        frozen = self.harness.mutate_frozen_request(frozen)
        self.claimed[-1] = frozen
        self.outstanding = frozen
        return frozen


class _AgentHandle:
    def __init__(self, ordinal, request, allocation, mailbox):
        self.ordinal = ordinal
        self.request = request
        self.allocation = allocation
        self.mailbox = mailbox
        self.authoritative_handle_id = (
            f"trusted-handle-{ordinal}-{request.agent_session_id}"
        )
        self.alive = True
        self.stop_reason = None
        self.finished = False


class _ProviderHarness:
    def __init__(
        self,
        fixture,
        context_sha256,
        lifecycle_submissions,
        gate_behaviors,
        *,
        incomplete_exit_ordinal=None,
    ):
        self.fixture = fixture
        self.context_sha256 = context_sha256
        self.lifecycle_submissions = tuple(
            tuple(values) for values in lifecycle_submissions
        )
        self.gate_behaviors = tuple(gate_behaviors)
        self.incomplete_exit_ordinal = incomplete_exit_ordinal
        self.mailboxes = []
        self.handles = []
        self.gate_requests = []
        self.b1_roots_by_attempt = {}
        self.b2_roots = []
        self.accepted_frozen_by_lifecycle = {}
        self.b2_barriers = []
        self.cross_gate_requests = []

    @property
    def providers(self):
        return CoordinatorProviders(
            evidence_storage_authority_id="test.coordinator.evidence",
            create_mailbox=self.create_mailbox,
            start_agent=self.start_agent,
            agent_is_alive=self.agent_is_alive,
            commit_agent_response=self.commit_agent_response,
            request_agent_stop=self.request_agent_stop,
            finish_agent=self.finish_agent,
            evaluate_gate=self.evaluate_gate,
            compare_cross_gate=self.compare_cross_gate,
        )

    def create_mailbox(self, allocation, agent_session_id):
        ordinal = len(self.mailboxes)
        mailbox = _FakeMailbox(
            self,
            allocation,
            agent_session_id,
            self.lifecycle_submissions[ordinal],
        )
        self.mailboxes.append(mailbox)
        return mailbox

    def start_agent(self, request, allocation, endpoint):
        mailbox = self.mailboxes[-1]
        if endpoint is not mailbox or request.agent_session_id != mailbox.session_id:
            raise RuntimeError("Agent received the wrong mailbox endpoint")
        mailbox.lifecycle_id = request.lifecycle_id
        handle = _AgentHandle(len(self.handles), request, allocation, mailbox)
        self.handles.append(handle)
        (allocation.paths.project / "agent-only.txt").write_text(
            request.lifecycle_id,
            encoding="utf-8",
        )
        return self._start_result(handle)

    @staticmethod
    def _start_result(handle):
        return AgentStartResult(
            lifecycle_id=handle.request.lifecycle_id,
            agent_session_id=handle.request.agent_session_id,
            authoritative_handle_id=handle.authoritative_handle_id,
            startup_receipt_sha256=_digest(
                f"startup:{handle.request.lifecycle_id}:"
                f"{handle.authoritative_handle_id}"
            ),
            handle=handle,
        )

    @staticmethod
    def agent_is_alive(handle):
        return handle.alive

    def commit_agent_response(self, handle, request, commit):
        if (
            request.lifecycle_id != handle.request.lifecycle_id
            or request.agent_session_id != handle.request.agent_session_id
            or request.authoritative_handle_id
            != handle.authoritative_handle_id
        ):
            raise RuntimeError("response commit request does not bind the Agent")
        if not self.agent_is_alive(handle):
            raise RuntimeError("Agent died before the response commit")
        committed_sha256 = commit()
        return AgentResponseCommitProof(
            lifecycle_id=request.lifecycle_id,
            agent_session_id=request.agent_session_id,
            authoritative_handle_id=request.authoritative_handle_id,
            nonce=request.nonce,
            request_sha256=request.request_sha256,
            response_sha256=committed_sha256,
            commit_callback_called_once=True,
            alive_observed_after_commit=self.agent_is_alive(handle),
        )

    @staticmethod
    def request_agent_stop(handle, reason):
        if not handle.alive or handle.stop_reason is not None:
            raise RuntimeError("Agent stop was not requested exactly once")
        handle.stop_reason = reason

    def finish_agent(self, handle, reason):
        if handle.finished or handle.stop_reason is not reason:
            raise RuntimeError("Agent finish did not bind the sole stop request")
        handle.finished = True
        handle.alive = False
        complete = handle.ordinal != self.incomplete_exit_ordinal
        return AgentExitProof(
            lifecycle_id=handle.request.lifecycle_id,
            agent_session_id=handle.request.agent_session_id,
            authoritative_handle_id=handle.authoritative_handle_id,
            authoritative_handle_exited=True,
            process_tree_empty=complete,
            provider_endpoint_revoked=True,
            credentials_revoked=True,
            writable_handles_revoked=True,
            workspace_mount_revoked=True,
            trace_finished_once=True,
            trace_receipt_sha256=_digest(
                f"trace:{handle.request.lifecycle_id}"
            ),
        )

    def _candidate_result(self, request):
        (
            _old_fixture,
            _old_submission,
            _old_binding,
            old_observations,
            old_decisions,
            old_receipt,
        ) = _confirmed_proof(
            causal=True,
            repair=True,
            role=request.role,
        )
        template = self.fixture["template"]
        binding = _binding(
            template,
            request.role,
            resources=(
                request.workspace.lease.to_dynamic_resource_binding(request.role),
            ),
            receipt=_digest(
                f"broker:{request.lifecycle_id}:{request.attempt_id}:"
                f"{request.role.value}"
            ),
            attempt_id=request.attempt_id,
        )
        observations = []
        observation_ref_map = {}
        for observation_index, old in enumerate(old_observations):
            captured = tuple(
                dataclasses.replace(
                    item,
                    collector_run_id=(
                        f"{request.role.value}.{request.attempt_id}."
                        f"run-{observation_index}-{artifact_index}"
                    ),
                    capture_id=(
                        f"{request.role.value}.{request.attempt_id}."
                        f"capture-{observation_index}-{artifact_index}"
                    ),
                    provenance_sha256=_digest(
                        f"provenance:{request.role.value}:"
                        f"{request.attempt_id}:{observation_index}:"
                        f"{artifact_index}"
                    ),
                )
                for artifact_index, item in enumerate(old.artifacts)
            )
            observation = dataclasses.replace(
                old,
                validation_instance_id=(
                    self.fixture["identity"].validation_instance_id
                ),
                attempt_id=request.attempt_id,
                template=template.ref,
                binding=binding.ref,
                artifacts=captured,
            )
            observations.append(observation)
            observation_ref_map[old.ref] = observation.ref
        decisions = tuple(
            dataclasses.replace(
                old,
                validation_instance_id=(
                    self.fixture["identity"].validation_instance_id
                ),
                attempt_id=request.attempt_id,
                profile=self.fixture["profile"].ref,
                case_plan=self.fixture["case_plan"].ref,
                template=template.ref,
                binding=binding.ref,
                observations=tuple(
                    observation_ref_map[reference]
                    for reference in old.observations
                ),
            )
            for old in old_decisions
        )
        submission = request.submission
        receipt = dataclasses.replace(
            old_receipt,
            validation_instance_id=(
                self.fixture["identity"].validation_instance_id
            ),
            attempt_id=request.attempt_id,
            submission=submission.ref,
            profile=self.fixture["profile"].ref,
            case_plan=self.fixture["case_plan"].ref,
            template=template.ref,
            binding=binding.ref,
            original_l1_candidate_sha256=submission.content_sha256,
            patch_sha256=(
                self.fixture["case_plan"].repair.patch.content_sha256
            ),
            observations=tuple(value.ref for value in observations),
            decisions=tuple(value.ref for value in decisions),
        )
        observations = tuple(observations)
        persistence = GateEvidencePersistenceProof.for_graph(
            lifecycle_id=request.lifecycle_id,
            storage_authority_id="test.coordinator.evidence",
            persistence_receipt_sha256=_digest(
                f"persisted:{request.lifecycle_id}:{request.attempt_id}:"
                f"{request.role.value}"
            ),
            durable_before_workspace_release=True,
            receipt=receipt,
            adapter=self.fixture["adapter"],
            template=template,
            binding=binding,
            baseline_receipts=self.fixture["receipts"],
            observations=observations,
            decisions=decisions,
        )
        return GateExecutionResult(
            receipt=receipt,
            adapter=self.fixture["adapter"],
            template=template,
            binding=binding,
            baseline_receipts=self.fixture["receipts"],
            observations=observations,
            decisions=decisions,
            evidence_persistence=persistence,
        )

    def _fast_result(self, request):
        identity = self.fixture["identity"]
        receipt = FastPathGateReceipt(
            validation_instance_id=identity.validation_instance_id,
            attempt_id=request.attempt_id,
            role=request.role,
            project_id=identity.project_id,
            case_id=identity.case_id,
            function_id=identity.function_id,
            snapshot_sha256=identity.snapshot_sha256,
            submission=request.submission.ref,
            reasoning_sha256=identity.reasoning_sha256,
            context_sha256=self.context_sha256,
            profile_sha256=identity.profile_sha256,
            successful_checks=tuple(FastPathCheck),
            disposition=(
                GateAttemptDisposition.ACCEPTED_EXPLICIT_NOT_CONFIRMED
                if request.role is GateRole.B1
                else None
            ),
        )
        persistence = GateEvidencePersistenceProof.for_graph(
            lifecycle_id=request.lifecycle_id,
            storage_authority_id="test.coordinator.evidence",
            persistence_receipt_sha256=_digest(
                f"fast:{request.lifecycle_id}:{request.attempt_id}:"
                f"{request.role.value}"
            ),
            durable_before_workspace_release=True,
            receipt=receipt,
            adapter=None,
            template=None,
            binding=None,
            baseline_receipts=(),
            observations=(),
            decisions=(),
        )
        return GateExecutionResult(
            receipt=receipt,
            adapter=None,
            template=None,
            binding=None,
            baseline_receipts=(),
            observations=(),
            decisions=(),
            evidence_persistence=persistence,
        )

    def _replace_gate_result(self, request, result, **changes):
        values = {
            "receipt": result.receipt,
            "adapter": result.adapter,
            "template": result.template,
            "binding": result.binding,
            "baseline_receipts": result.baseline_receipts,
            "observations": result.observations,
            "decisions": result.decisions,
            "diagnostics": result.diagnostics,
        }
        values.update(changes)
        values["evidence_persistence"] = GateEvidencePersistenceProof.for_graph(
            lifecycle_id=request.lifecycle_id,
            storage_authority_id="test.coordinator.evidence",
            persistence_receipt_sha256=_digest(
                f"rebound:{request.lifecycle_id}:{request.attempt_id}:"
                f"{values['receipt'].content_sha256}"
            ),
            durable_before_workspace_release=True,
            receipt=values["receipt"],
            adapter=values["adapter"],
            template=values["template"],
            binding=values["binding"],
            baseline_receipts=values["baseline_receipts"],
            observations=values["observations"],
            decisions=values["decisions"],
        )
        return GateExecutionResult(**values)

    def evaluate_gate(self, request):
        try:
            behavior = self.gate_behaviors[len(self.gate_requests)]
        except IndexError as exc:
            raise RuntimeError("Gate script was exhausted") from exc
        self.gate_requests.append(request)

        if request.workspace is not None:
            if not request.workspace.paths.root.exists():
                raise RuntimeError("Gate received a released workspace")
            if request.role is GateRole.B1:
                root = request.workspace.paths.root
                self.b1_roots_by_attempt[request.attempt_id] = root
                (request.workspace.paths.project / "b1-only.txt").write_text(
                    request.attempt_id,
                    encoding="utf-8",
                )
            else:
                self.b2_roots.append(request.workspace.paths.root)

        if request.role is GateRole.B2:
            handle = next(
                item
                for item in self.handles
                if item.request.lifecycle_id == request.lifecycle_id
            )
            barrier = (
                handle.finished
                and not handle.alive
                and not handle.allocation.paths.root.exists()
                and all(
                    not root.exists()
                    for attempt, root in self.b1_roots_by_attempt.items()
                    if attempt == request.attempt_id
                )
                and request.frozen_request
                is self.accepted_frozen_by_lifecycle[request.lifecycle_id]
            )
            self.b2_barriers.append(barrier)
            if not barrier:
                raise RuntimeError("B2 crossed the Agent/A/B1 exit barrier")
            if request.workspace is not None and (
                (request.workspace.paths.project / "agent-only.txt").exists()
                or (request.workspace.paths.project / "b1-only.txt").exists()
            ):
                raise RuntimeError("B2 inherited a writable A/B1 contaminant")

        if behavior == "fast":
            result = self._fast_result(request)
        else:
            result = self._candidate_result(request)
            if behavior == "retry":
                result = self._replace_gate_result(
                    request,
                    result,
                    receipt=dataclasses.replace(
                        result.receipt,
                        final_grade=None,
                        disposition=GateAttemptDisposition.RETRYABLE_REJECTION,
                        result_status=CaseStatus.NOT_CONFIRMED,
                        result_reason_code=CaseReasonCode.TARGET_NOT_REACHED,
                    ),
                    diagnostics=(CaseReasonCode.TARGET_NOT_REACHED.value,),
                )
            elif behavior == "terminal":
                result = self._replace_gate_result(
                    request,
                    result,
                    receipt=dataclasses.replace(
                        result.receipt,
                        final_grade=None,
                        disposition=GateAttemptDisposition.TERMINAL_OUTCOME,
                        result_status=CaseStatus.INCONCLUSIVE_INFRA,
                        result_reason_code=CaseReasonCode.TOOL_UNAVAILABLE,
                    ),
                    diagnostics=(CaseReasonCode.TOOL_UNAVAILABLE.value,),
                )
            elif behavior == "b2_fail":
                result = self._replace_gate_result(
                    request,
                    result,
                    receipt=dataclasses.replace(
                        result.receipt,
                        final_grade=None,
                        disposition=None,
                        result_status=CaseStatus.NOT_CONFIRMED,
                        result_reason_code=(
                            CaseReasonCode.CONSEQUENCE_NOT_REPRODUCED
                        ),
                    ),
                )
            elif behavior == "downgrade":
                phases = tuple(
                    dataclasses.replace(
                        value,
                        status=GatePhaseStatus.REJECTED,
                        reason_codes=("PATCH_BUILD_FAILED",),
                    )
                    if value.phase is ExperimentPhase.BUILD_SANITY
                    else value
                    for value in result.receipt.phase_results
                )
                result = self._replace_gate_result(
                    request,
                    result,
                    receipt=dataclasses.replace(
                        result.receipt,
                        final_grade=ValidationGrade.L0,
                        phase_results=phases,
                        result_status=CaseStatus.CONFIRMED_L0,
                        result_reason_code=CaseReasonCode.CONFIRMED_L0,
                    ),
                )
            elif behavior == "wrong_role":
                result = self._replace_gate_result(
                    request,
                    result,
                    receipt=dataclasses.replace(
                        result.receipt,
                        role=GateRole.B2,
                        disposition=None,
                    ),
                )
            elif behavior == "wrong_attempt":
                result = self._replace_gate_result(
                    request,
                    result,
                    receipt=dataclasses.replace(
                        result.receipt,
                        attempt_id="forged-gate-attempt",
                    ),
                )
            elif behavior == "wrong_binding":
                bad_resource = dataclasses.replace(
                    result.binding.resources[0],
                    allocation_id="forged-allocation",
                )
                bad_binding = dataclasses.replace(
                    result.binding,
                    resources=(bad_resource,),
                    broker_receipt_sha256=_digest("forged-broker-receipt"),
                )
                result = self._replace_gate_result(
                    request,
                    result,
                    binding=bad_binding,
                    receipt=dataclasses.replace(
                        result.receipt,
                        binding=bad_binding.ref,
                    ),
                )
            elif behavior != "accept":
                raise RuntimeError(f"unknown Gate behavior {behavior}")

        if request.role is GateRole.B1 and result.receipt.disposition in (
            GateAttemptDisposition.ACCEPTED_CONFIRMED_CANDIDATE,
            GateAttemptDisposition.ACCEPTED_EXPLICIT_NOT_CONFIRMED,
        ):
            self.accepted_frozen_by_lifecycle[request.lifecycle_id] = (
                request.frozen_request
            )
        return result

    def compare_cross_gate(self, request):
        self.cross_gate_requests.append(request)
        payload = f"comparison:{request.lifecycle_id}".encode("utf-8")
        return CrossGateDecision(
            validation_instance_id=request.validation_instance_id,
            b1_receipt=request.b1.receipt.ref,
            b2_receipt=request.b2.receipt.ref,
            b1_decisions=request.b1.receipt.decisions,
            b2_decisions=request.b2.receipt.decisions,
            comparison=ArtifactRef(
                role="cross_gate_comparison",
                media_type="application/json",
                size_bytes=len(payload),
                content_sha256=_digest(payload),
            ),
            verdict=CrossGateVerdict.REPRODUCIBLE,
        )


class _EarlyGateHarness(_ProviderHarness):
    def __init__(self, *args, preflight_state, receipt_stage, **kwargs):
        super().__init__(*args, **kwargs)
        self.preflight_state = preflight_state
        self.receipt_stage = receipt_stage

    def create_mailbox(self, allocation, agent_session_id):
        ordinal = len(self.mailboxes)
        mailbox = _PreflightMailbox(
            self,
            allocation,
            agent_session_id,
            self.lifecycle_submissions[ordinal],
        )
        self.mailboxes.append(mailbox)
        return mailbox

    def mutate_frozen_request(self, frozen):
        if self.preflight_state is GatePreflightState.INTAKE_INVALID:
            payload = b"{invalid-json"
            binding = StagedArtifactBinding(
                relative_path=frozen.raw_submission.relative_path,
                artifact=ArtifactRef(
                    role="raw_submission",
                    media_type="application/json",
                    size_bytes=len(payload),
                    content_sha256=_digest(payload),
                ),
            )
            return _rebind_frozen_request(
                frozen,
                raw_submission=FrozenStagedArtifact(binding, payload),
            )
        if self.preflight_state is GatePreflightState.CONTEXT_INVALID:
            return _rebind_frozen_request(
                frozen,
                artifacts=frozen.artifacts[:-1],
            )
        return frozen

    def evaluate_gate(self, request):
        self.gate_requests.append(request)
        identity = self.fixture["identity"]
        parsed = request.submission
        if parsed is None:
            parsed = _case_submission(self.fixture["case_plan"])
        intake = self.receipt_stage is EarlyGateStage.INTAKE
        reason_by_stage = {
            EarlyGateStage.INTAKE: CaseReasonCode.SCHEMA_INVALID,
            EarlyGateStage.MEMBERSHIP: CaseReasonCode.MEMBERSHIP_INVALID,
            EarlyGateStage.CONTEXT_INTEGRITY: (
                CaseReasonCode.PROFILE_ARTIFACT_INVALID
            ),
        }
        reason = reason_by_stage[self.receipt_stage]
        receipt = EarlyGateReceipt(
            validation_instance_id=identity.validation_instance_id,
            attempt_id=request.attempt_id,
            role=request.role,
            failure_stage=self.receipt_stage,
            project_id=identity.project_id,
            case_id=identity.case_id,
            function_id=identity.function_id,
            snapshot_sha256=identity.snapshot_sha256,
            reasoning_sha256=identity.reasoning_sha256,
            profile_sha256=identity.profile_sha256,
            context_sha256=self.context_sha256,
            raw_submission=request.frozen_request.envelope.raw_submission.artifact,
            parsed_submission_kind=None if intake else parsed.submission_kind,
            parsed_submission=None if intake else parsed.ref,
            parsed_profile=None if intake else self.fixture["profile"].ref,
            parsed_case_plan=(
                None if intake or parsed.case_plan is None else parsed.case_plan.ref
            ),
            disposition=GateAttemptDisposition.TERMINAL_OUTCOME,
            result_status=CaseStatus.INVALID_SUBMISSION,
            result_reason_code=reason,
        )
        persistence = GateEvidencePersistenceProof.for_graph(
            lifecycle_id=request.lifecycle_id,
            storage_authority_id="test.coordinator.evidence",
            persistence_receipt_sha256=_digest(
                f"early:{request.lifecycle_id}:{request.attempt_id}:"
                f"{self.receipt_stage.value}"
            ),
            durable_before_workspace_release=True,
            receipt=receipt,
            adapter=None,
            template=None,
            binding=None,
            baseline_receipts=(),
            observations=(),
            decisions=(),
        )
        return GateExecutionResult(
            receipt=receipt,
            adapter=None,
            template=None,
            binding=None,
            baseline_receipts=(),
            observations=(),
            decisions=(),
            evidence_persistence=persistence,
            diagnostics=(reason.value,),
        )


class _ThreadedMailboxHarness(_ProviderHarness):
    """Run the Agent side through the real split-permission filesystem mailbox."""

    def create_mailbox(self, allocation, agent_session_id):
        ordinal = len(self.mailboxes)
        if ordinal >= len(self.lifecycle_submissions):
            raise RuntimeError("mailbox script was exhausted")
        mailbox = CoordinatorMailbox(
            allocation.paths.case_staging,
            agent_session_id=agent_session_id,
        )
        self.mailboxes.append(mailbox)
        return mailbox

    def start_agent(self, request, allocation, endpoint):
        mailbox = self.mailboxes[-1]
        if endpoint is not mailbox.agent_endpoint:
            raise RuntimeError("Agent received the wrong real mailbox endpoint")
        handle = _AgentHandle(len(self.handles), request, allocation, mailbox)
        handle.stop_event = threading.Event()
        handle.thread_done = threading.Event()
        handle.error = None
        handle.responses = []
        handle.published_requests = []
        self.handles.append(handle)
        (allocation.paths.project / "agent-only.txt").write_text(
            request.lifecycle_id,
            encoding="utf-8",
        )

        submissions = self.lifecycle_submissions[handle.ordinal]

        def run_agent():
            try:
                previous_response_sha256 = None
                for nonce, submission in enumerate(submissions, start=1):
                    staged = _frozen_request(
                        submission,
                        identity=self.fixture["identity"],
                        context_sha256=self.context_sha256,
                        agent_session_id=request.agent_session_id,
                        nonce=nonce,
                        previous_response_sha256=previous_response_sha256,
                    )
                    payloads = {
                        item.relative_path: item.content_bytes
                        for item in staged.all_artifacts
                    }
                    endpoint.publish_request(staged.envelope, payloads)
                    handle.published_requests.append(staged.envelope)
                    response = endpoint.wait_response(
                        nonce,
                        timeout_seconds=10,
                        poll_interval_seconds=0.001,
                        request=staged.envelope,
                    )
                    handle.responses.append(response)
                    previous_response_sha256 = response.content_sha256
                    if (
                        response.disposition
                        is GateAttemptDisposition.RETRYABLE_REJECTION
                    ):
                        continue
                    break
                if not handle.stop_event.wait(timeout=10):
                    raise RuntimeError("Agent never received its stop request")
            except BaseException as exc:
                handle.error = exc
            finally:
                handle.thread_done.set()

        handle.thread = threading.Thread(
            target=run_agent,
            name=f"test-agent-{handle.ordinal}",
            daemon=True,
        )
        handle.thread.start()
        return self._start_result(handle)

    @staticmethod
    def agent_is_alive(handle):
        return handle.thread.is_alive()

    @staticmethod
    def request_agent_stop(handle, reason):
        _ProviderHarness.request_agent_stop(handle, reason)
        handle.stop_event.set()

    def finish_agent(self, handle, reason):
        handle.thread.join(timeout=10)
        if handle.thread.is_alive():
            raise RuntimeError("real-mailbox Agent thread did not exit")
        if handle.error is not None:
            raise RuntimeError("real-mailbox Agent thread failed") from handle.error
        return super().finish_agent(handle, reason)

    def dispose_mailboxes(self):
        for mailbox in self.mailboxes:
            mailbox.dispose()


class _FinishInterruptHarness(_ProviderHarness):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.finish_calls = 0

    def finish_agent(self, handle, reason):
        del handle, reason
        self.finish_calls += 1
        raise KeyboardInterrupt("simulated trusted-driver interruption")


class _GateInterruptHarness(_ProviderHarness):
    def evaluate_gate(self, request):
        del request
        raise KeyboardInterrupt("simulated Gate interruption")


class _NullStartHarness(_ProviderHarness):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.start_calls = 0
        self.start_allocations = []
        self.liveness_calls = 0
        self.stop_calls = 0
        self.finish_calls = 0

    def start_agent(self, request, allocation, endpoint):
        del request, endpoint
        self.start_calls += 1
        self.start_allocations.append(allocation)
        return None

    def agent_is_alive(self, handle):
        del handle
        self.liveness_calls += 1
        return False

    def request_agent_stop(self, handle, reason):
        del handle, reason
        self.stop_calls += 1

    def finish_agent(self, handle, reason):
        del handle, reason
        self.finish_calls += 1
        raise AssertionError("a missing Agent handle cannot be finished")


class _RetainedCommitCallbackHarness(_ProviderHarness):
    def __init__(self, *args, commit_behavior, **kwargs):
        super().__init__(*args, **kwargs)
        self.commit_behavior = commit_behavior
        self.retained_callback = None

    def commit_agent_response(self, handle, request, commit):
        del handle
        self.retained_callback = commit
        if self.commit_behavior == "raise":
            raise RuntimeError("simulated response-commit provider failure")
        if self.commit_behavior != "return":
            raise AssertionError("unknown retained-callback behavior")
        return AgentResponseCommitProof(
            lifecycle_id=request.lifecycle_id,
            agent_session_id=request.agent_session_id,
            authoritative_handle_id=request.authoritative_handle_id,
            nonce=request.nonce,
            request_sha256=request.request_sha256,
            response_sha256=request.response_sha256,
            commit_callback_called_once=True,
            alive_observed_after_commit=True,
        )


class _CapacityHarness(_ProviderHarness):
    def __init__(self, *args, request_capacity, **kwargs):
        super().__init__(*args, **kwargs)
        self.request_capacity = request_capacity
        self.start_calls = 0

    def start_agent(self, request, allocation, endpoint):
        self.start_calls += 1
        return super().start_agent(request, allocation, endpoint)


class _DeathOnCloseMailbox(_FakeMailbox):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.handle = None
        self.close_calls = 0

    def close_requests(self):
        self.close_calls += 1
        super().close_requests()
        if self.handle is not None:
            self.handle.alive = False


class _DeathOnCloseHarness(_ProviderHarness):
    def create_mailbox(self, allocation, agent_session_id):
        ordinal = len(self.mailboxes)
        mailbox = _DeathOnCloseMailbox(
            self,
            allocation,
            agent_session_id,
            self.lifecycle_submissions[ordinal],
        )
        self.mailboxes.append(mailbox)
        return mailbox

    def start_agent(self, request, allocation, endpoint):
        start_result = super().start_agent(request, allocation, endpoint)
        endpoint.handle = start_result.handle
        return start_result


class _TrackingCoordinatorMailbox(CoordinatorMailbox):
    def __init__(self, *args, **kwargs):
        self.close_request_calls = 0
        self.dispose_calls = 0
        super().__init__(*args, **kwargs)

    def close_requests(self):
        self.close_request_calls += 1
        return super().close_requests()

    def dispose(self):
        if not self._disposed:
            self.dispose_calls += 1
        return super().dispose()

    @property
    def disposed(self):
        return self._disposed


class _DisposedMailboxFailureHarness(_ThreadedMailboxHarness):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.finish_calls = 0
        self.disposed_before_b2 = []

    def create_mailbox(self, allocation, agent_session_id):
        mailbox = _TrackingCoordinatorMailbox(
            allocation.paths.case_staging,
            agent_session_id=agent_session_id,
        )
        self.mailboxes.append(mailbox)
        return mailbox

    def finish_agent(self, handle, reason):
        self.finish_calls += 1
        return super().finish_agent(handle, reason)

    def evaluate_gate(self, request):
        if request.role is GateRole.B2:
            mailbox = self.mailboxes[-1]
            self.disposed_before_b2.append(mailbox.disposed)
        return super().evaluate_gate(request)


class ValidationCoordinatorRuntimeTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(
            prefix="fmagent-coordinator-",
            dir="/tmp",
        )
        self.base = Path(self.temporary.name).resolve()
        source = self.base / "source"
        source.mkdir()
        (source / "main.txt").write_text("frozen\n", encoding="utf-8")
        self.store = SnapshotStore(self.base / "cas")
        self.snapshot = self.store.capture(source, _policy())
        self.fixture = _rebase_fixture(self.snapshot.ref.snapshot_sha256)
        self.context_sha256 = _digest("coordinator-context")
        self.manager = WorkspaceManager(
            store=self.store,
            run_root=self.base / "runs",
            broker_id="test.coordinator.workspace",
        )

    def tearDown(self):
        self.temporary.cleanup()

    def _candidate(self, attempts=1):
        return _case_submission(self.fixture["case_plan"], attempts=attempts)

    def _not_confirmed(self):
        identity = self.fixture["identity"]
        return CaseSubmission(
            submission_kind=CaseSubmissionKind.NOT_CONFIRMED,
            validation_instance_id=identity.validation_instance_id,
            case_id=identity.case_id,
            function_id=identity.function_id,
            reasoning_sha256=identity.reasoning_sha256,
            attempts=1,
            notes="no confirmed candidate",
        )

    def _coordinator(
        self,
        harness,
        *,
        max_lifecycles=1,
        max_submissions=1,
        fixture=None,
    ):
        fixture = self.fixture if fixture is None else fixture
        return ValidationCoordinator(
            snapshot=self.snapshot.ref,
            identity=fixture["identity"],
            profile=fixture["profile"],
            context_sha256=self.context_sha256,
            workspace_equivalence_policy=fixture["equivalence_policy"],
            oracle_bundles=(fixture["bundle"],),
            oracle_specs=fixture["specs"],
            workspace_manager=self.manager,
            providers=harness.providers,
            limits=CoordinatorLimits(
                max_lifecycles=max_lifecycles,
                max_submissions_per_session=max_submissions,
                request_timeout_ms=1_000,
                poll_interval_ms=1,
            ),
        )

    def test_retry_keeps_one_agent_session_and_uses_a_fresh_b1(self):
        harness = _ProviderHarness(
            self.fixture,
            self.context_sha256,
            ((self._candidate(1), self._candidate(2)),),
            ("retry", "accept", "accept"),
        )
        coordinator = self._coordinator(harness, max_submissions=2)

        result = coordinator.run()

        self.assertEqual(result.completion, CoordinatorCompletionKind.CONFIRMED_READY)
        lifecycle = result.lifecycles[0]
        self.assertEqual(len(lifecycle.b1_attempts), 2)
        self.assertEqual(len(harness.handles), 1)
        self.assertTrue(harness.handles[0].finished)
        self.assertEqual(
            [item.envelope.agent_session_id for item in harness.mailboxes[0].claimed],
            [lifecycle.agent_session_id, lifecycle.agent_session_id],
        )
        self.assertEqual(
            [item.response.disposition for item in lifecycle.b1_attempts],
            [
                GateAttemptDisposition.RETRYABLE_REJECTION,
                GateAttemptDisposition.ACCEPTED_CONFIRMED_CANDIDATE,
            ],
        )
        self.assertEqual(
            [
                item.request.previous_response_sha256
                for item in lifecycle.b1_attempts
            ],
            [None, lifecycle.b1_attempts[0].response.content_sha256],
        )
        self.assertEqual(
            [
                item.envelope.previous_response_sha256
                for item in harness.mailboxes[0].claimed
            ],
            [None, harness.mailboxes[0].responses[0].content_sha256],
        )
        self.assertNotEqual(
            lifecycle.b1_attempts[0].gate_attempt_id,
            lifecycle.b1_attempts[1].gate_attempt_id,
        )
        self.assertNotEqual(
            lifecycle.b1_attempts[0].b1_workspace.lease.lease_id,
            lifecycle.b1_attempts[1].b1_workspace.lease.lease_id,
        )
        self.assertTrue(all(harness.mailboxes[0].release_before_response))
        self.assertEqual(
            [request.role for request in harness.gate_requests],
            [GateRole.B1, GateRole.B1, GateRole.B2],
        )
        self.assertEqual(
            harness.gate_requests[-1].attempt_id,
            lifecycle.b1_attempts[-1].gate_attempt_id,
        )
        self.assertTrue(all(harness.b2_barriers))
        self.assertEqual(coordinator.state, CoordinatorState.COMPLETE)

    def test_real_mailbox_agent_thread_retries_then_accepts_and_reaches_b2(self):
        harness = _ThreadedMailboxHarness(
            self.fixture,
            self.context_sha256,
            ((self._candidate(1), self._candidate(2)),),
            ("retry", "accept", "accept"),
        )
        self.addCleanup(harness.dispose_mailboxes)
        coordinator = self._coordinator(harness, max_submissions=2)

        result = coordinator.run()

        lifecycle = result.lifecycles[0]
        handle = harness.handles[0]
        mailbox = harness.mailboxes[0]
        self.assertEqual(result.completion, CoordinatorCompletionKind.CONFIRMED_READY)
        self.assertEqual(len(harness.handles), 1)
        self.assertTrue(handle.finished)
        self.assertFalse(handle.thread.is_alive())
        self.assertIsNone(handle.error)
        self.assertEqual(
            [request.nonce for request in handle.published_requests],
            [1, 2],
        )
        self.assertEqual(
            [response.nonce for response in handle.responses],
            [1, 2],
        )
        self.assertEqual(
            [response.disposition for response in handle.responses],
            [
                GateAttemptDisposition.RETRYABLE_REJECTION,
                GateAttemptDisposition.ACCEPTED_CONFIRMED_CANDIDATE,
            ],
        )
        self.assertEqual(
            [response.request_sha256 for response in handle.responses],
            [request.content_sha256 for request in handle.published_requests],
        )
        self.assertEqual(
            [
                request.previous_response_sha256
                for request in handle.published_requests
            ],
            [None, handle.responses[0].content_sha256],
        )
        self.assertEqual(
            [request.agent_session_id for request in handle.published_requests],
            [lifecycle.agent_session_id, lifecycle.agent_session_id],
        )
        self.assertEqual(mailbox.next_nonce, 3)
        self.assertTrue(mailbox.is_closed)
        self.assertFalse(mailbox.has_outstanding_request)
        self.assertEqual(len(lifecycle.b1_attempts), 2)
        self.assertNotEqual(
            lifecycle.b1_attempts[0].b1_workspace.lease.lease_id,
            lifecycle.b1_attempts[1].b1_workspace.lease.lease_id,
        )
        self.assertTrue(all(harness.b2_barriers))
        self.assertEqual(
            [request.role for request in harness.gate_requests],
            [GateRole.B1, GateRole.B1, GateRole.B2],
        )
        self.assertFalse(handle.allocation.paths.root.exists())
        self.assertTrue(
            all(not root.exists() for root in harness.b1_roots_by_attempt.values())
        )
        self.assertTrue(all(not root.exists() for root in harness.b2_roots))

    def test_b2_starts_after_exit_and_receives_original_l1_frozen_request(self):
        candidate = self._candidate()
        harness = _ProviderHarness(
            self.fixture,
            self.context_sha256,
            ((candidate,),),
            ("downgrade", "downgrade"),
        )

        result = self._coordinator(harness).run()

        lifecycle = result.lifecycles[0]
        b1 = lifecycle.b1_attempts[0].gate_result.receipt
        b2_request = harness.gate_requests[1]
        self.assertEqual(result.completion, CoordinatorCompletionKind.CONFIRMED_READY)
        self.assertEqual(b1.requested_grade, ValidationGrade.L1)
        self.assertEqual(b1.final_grade, ValidationGrade.L0)
        self.assertEqual(b1.original_l1_candidate_sha256, candidate.content_sha256)
        self.assertEqual(
            b1.patch_sha256,
            candidate.case_plan.repair.patch.content_sha256,
        )
        self.assertIs(
            b2_request.frozen_request,
            harness.gate_requests[0].frozen_request,
        )
        reparsed = CaseSubmission.from_json(
            b2_request.frozen_request.raw_submission_bytes
        )
        self.assertEqual(reparsed, candidate)
        self.assertIsNotNone(reparsed.case_plan.repair)
        self.assertTrue(all(harness.b2_barriers))
        self.assertFalse(harness.handles[0].allocation.paths.root.exists())
        self.assertTrue(
            all(not root.exists() for root in harness.b1_roots_by_attempt.values())
        )
        self.assertTrue(all(not root.exists() for root in harness.b2_roots))

    def test_explicit_not_confirmed_uses_fast_b1_b2_without_gate_workspaces(self):
        harness = _ProviderHarness(
            self.fixture,
            self.context_sha256,
            ((self._not_confirmed(),),),
            ("fast", "fast"),
        )

        result = self._coordinator(harness).run()

        lifecycle = result.lifecycles[0]
        self.assertEqual(
            result.completion,
            CoordinatorCompletionKind.EXPLICIT_NOT_CONFIRMED_READY,
        )
        self.assertIsNone(lifecycle.b1_attempts[0].b1_workspace)
        self.assertIsNone(lifecycle.b2_workspace)
        self.assertEqual(harness.b1_roots_by_attempt, {})
        self.assertEqual(harness.b2_roots, [])
        self.assertTrue(all(request.workspace is None for request in harness.gate_requests))
        self.assertTrue(all(harness.b2_barriers))
        self.assertEqual(harness.cross_gate_requests, [])

    def test_b1_terminal_finishes_agent_without_starting_b2(self):
        harness = _ProviderHarness(
            self.fixture,
            self.context_sha256,
            ((self._candidate(),),),
            ("terminal",),
        )

        result = self._coordinator(harness).run()

        lifecycle = result.lifecycles[0]
        self.assertEqual(
            result.completion,
            CoordinatorCompletionKind.B1_TERMINAL_READY,
        )
        self.assertIsNone(lifecycle.b2_result)
        self.assertIsNone(lifecycle.b2_workspace)
        self.assertEqual([value.role for value in harness.gate_requests], [GateRole.B1])
        self.assertEqual(harness.cross_gate_requests, [])
        self.assertEqual(
            harness.handles[0].stop_reason,
            AgentStopReason.B1_TERMINAL,
        )
        self.assertFalse(harness.handles[0].allocation.paths.root.exists())

    def test_incomplete_exit_proof_fails_closed_before_b2(self):
        harness = _ProviderHarness(
            self.fixture,
            self.context_sha256,
            ((self._candidate(),),),
            ("accept",),
            incomplete_exit_ordinal=0,
        )
        coordinator = self._coordinator(harness)

        with self.assertRaises(CoordinatorError) as caught:
            coordinator.run()

        self.assertEqual(
            caught.exception.code,
            CoordinatorFailureCode.AGENT_TEARDOWN_UNPROVEN,
        )
        self.assertEqual(coordinator.state, CoordinatorState.FAILED)
        self.assertEqual([value.role for value in harness.gate_requests], [GateRole.B1])
        self.assertEqual(harness.b2_roots, [])
        self.assertEqual(harness.cross_gate_requests, [])
        self.assertTrue(harness.handles[0].finished)
        # Without a complete teardown proof, the Coordinator intentionally
        # refuses to destroy or reuse A and, most importantly, cannot start B2.
        self.assertTrue(harness.handles[0].allocation.paths.root.exists())

    def test_finish_keyboard_interrupt_is_not_retried_or_treated_as_exit_proof(self):
        harness = _FinishInterruptHarness(
            self.fixture,
            self.context_sha256,
            ((self._candidate(),),),
            ("accept",),
        )
        coordinator = self._coordinator(harness)

        with self.assertRaises(CoordinatorError) as caught:
            coordinator.run()

        self.assertEqual(
            caught.exception.code,
            CoordinatorFailureCode.AGENT_TEARDOWN_UNPROVEN,
        )
        self.assertEqual(harness.finish_calls, 1)
        self.assertEqual([request.role for request in harness.gate_requests], [GateRole.B1])
        self.assertEqual(harness.b2_roots, [])
        self.assertTrue(harness.handles[0].allocation.paths.root.exists())
        self.assertEqual(coordinator.state, CoordinatorState.FAILED)

    def test_unwrapped_gate_interrupt_still_leaves_a_terminal_failed_state(self):
        harness = _GateInterruptHarness(
            self.fixture,
            self.context_sha256,
            ((self._candidate(),),),
            (),
        )
        coordinator = self._coordinator(harness)

        with self.assertRaisesRegex(KeyboardInterrupt, "simulated Gate interruption"):
            coordinator.run()

        self.assertEqual(coordinator.state, CoordinatorState.FAILED)
        self.assertEqual(len(harness.handles), 1)
        self.assertTrue(harness.handles[0].finished)
        self.assertFalse(harness.handles[0].allocation.paths.root.exists())
        self.assertEqual(harness.b2_roots, [])

    def test_none_agent_handle_fails_start_closed_without_releasing_a(self):
        harness = _NullStartHarness(
            self.fixture,
            self.context_sha256,
            ((self._candidate(),),),
            (),
        )
        coordinator = self._coordinator(harness)

        with self.assertRaises(CoordinatorError) as caught:
            coordinator.run()

        self.assertEqual(
            caught.exception.code,
            CoordinatorFailureCode.AGENT_START_FAILED,
        )
        self.assertEqual(harness.start_calls, 1)
        self.assertEqual(harness.liveness_calls, 0)
        self.assertEqual(harness.stop_calls, 0)
        self.assertEqual(harness.finish_calls, 0)
        self.assertEqual(harness.gate_requests, [])
        self.assertEqual(len(harness.start_allocations), 1)
        self.assertTrue(harness.start_allocations[0].paths.root.exists())
        self.assertEqual(coordinator.state, CoordinatorState.FAILED)

    def test_agent_death_during_accepted_close_fails_before_response_and_b2(self):
        harness = _DeathOnCloseHarness(
            self.fixture,
            self.context_sha256,
            ((self._candidate(),),),
            ("accept",),
        )
        coordinator = self._coordinator(harness)

        with self.assertRaises(CoordinatorError):
            coordinator.run()

        mailbox = harness.mailboxes[0]
        self.assertGreaterEqual(mailbox.close_calls, 1)
        self.assertEqual(mailbox.responses, [])
        self.assertEqual([request.role for request in harness.gate_requests], [GateRole.B1])
        self.assertEqual(harness.b2_roots, [])
        self.assertEqual(harness.cross_gate_requests, [])
        self.assertEqual(coordinator.state, CoordinatorState.FAILED)

    def test_retained_response_commit_callback_expires_on_return_or_raise(self):
        for commit_behavior in ("return", "raise"):
            with self.subTest(commit_behavior=commit_behavior):
                harness = _RetainedCommitCallbackHarness(
                    self.fixture,
                    self.context_sha256,
                    ((self._candidate(),),),
                    ("accept",),
                    commit_behavior=commit_behavior,
                )
                coordinator = self._coordinator(harness)

                with self.assertRaises(CoordinatorError) as caught:
                    coordinator.run()

                self.assertEqual(
                    caught.exception.code,
                    CoordinatorFailureCode.AGENT_RESPONSE_COMMIT_UNPROVEN,
                )
                mailbox = harness.mailboxes[0]
                self.assertEqual(mailbox.responses, [])
                self.assertIsNotNone(harness.retained_callback)
                with self.assertRaisesRegex(ContractError, "fence is already closed"):
                    harness.retained_callback()
                self.assertEqual(mailbox.responses, [])
                self.assertEqual(harness.b2_roots, [])
                self.assertEqual(coordinator.state, CoordinatorState.FAILED)

    def test_submission_budget_over_mailbox_capacity_fails_before_agent_start(self):
        harness = _CapacityHarness(
            self.fixture,
            self.context_sha256,
            ((self._candidate(),),),
            (),
            request_capacity=1,
        )
        coordinator = self._coordinator(harness, max_submissions=2)

        with self.assertRaises(CoordinatorError) as caught:
            coordinator.run()

        self.assertEqual(
            caught.exception.code,
            CoordinatorFailureCode.INVALID_CONFIGURATION,
        )
        self.assertEqual(harness.start_calls, 0)
        self.assertEqual(harness.handles, [])
        self.assertEqual(harness.gate_requests, [])
        self.assertEqual(len(harness.mailboxes), 1)
        mailbox = harness.mailboxes[0]
        self.assertTrue(mailbox.closed)
        self.assertTrue(mailbox.disposed)
        self.assertFalse(mailbox.allocation.paths.root.exists())
        self.assertEqual(coordinator.state, CoordinatorState.FAILED)

    def test_disposed_real_mailbox_does_not_mask_a_later_b2_provider_failure(self):
        harness = _DisposedMailboxFailureHarness(
            self.fixture,
            self.context_sha256,
            ((self._candidate(),),),
            ("accept", "b2_error"),
        )
        self.addCleanup(harness.dispose_mailboxes)
        coordinator = self._coordinator(harness)

        with self.assertRaises(CoordinatorError) as caught:
            coordinator.run()

        mailbox = harness.mailboxes[0]
        handle = harness.handles[0]
        self.assertEqual(
            caught.exception.code,
            CoordinatorFailureCode.GATE_EXECUTION_FAILED,
        )
        self.assertEqual(harness.finish_calls, 1)
        self.assertEqual(harness.disposed_before_b2, [True])
        self.assertTrue(mailbox.disposed)
        self.assertEqual(mailbox.dispose_calls, 1)
        self.assertEqual(mailbox.close_request_calls, 1)
        self.assertTrue(handle.finished)
        self.assertFalse(handle.thread.is_alive())
        self.assertFalse(handle.allocation.paths.root.exists())
        self.assertTrue(
            all(not root.exists() for root in harness.b1_roots_by_attempt.values())
        )
        self.assertTrue(all(not root.exists() for root in harness.b2_roots))
        self.assertEqual(coordinator.state, CoordinatorState.FAILED)

    def test_prior_b1_cleanup_failure_does_not_prevent_independent_a_release(self):
        harness = _ProviderHarness(
            self.fixture,
            self.context_sha256,
            ((self._candidate(),),),
            ("accept",),
        )
        coordinator = self._coordinator(harness)
        real_release = self.manager.release
        blocked_b1 = {}

        def fail_b1_release(allocation):
            if allocation.lease.role is WorkspaceRole.B1:
                blocked_b1[allocation.lease.lease_id] = allocation
                raise OSError("simulated persistent B1 release failure")
            return real_release(allocation)

        def cleanup_blocked_b1():
            for allocation in blocked_b1.values():
                if allocation.paths.root.exists():
                    real_release(allocation)

        self.addCleanup(cleanup_blocked_b1)
        with mock.patch.object(
            self.manager,
            "release",
            side_effect=fail_b1_release,
        ):
            with self.assertRaises(CoordinatorError) as caught:
                coordinator.run()

        self.assertEqual(
            caught.exception.code,
            CoordinatorFailureCode.CLEANUP_UNPROVEN,
        )
        self.assertTrue(blocked_b1)
        self.assertEqual(len(harness.handles), 1)
        self.assertTrue(harness.handles[0].finished)
        self.assertFalse(harness.handles[0].allocation.paths.root.exists())
        self.assertTrue(harness.mailboxes[0].disposed)
        self.assertEqual(coordinator.state, CoordinatorState.FAILED)

    def test_b2_failure_restarts_with_new_agent_and_full_workspace_lifecycle(self):
        harness = _ProviderHarness(
            self.fixture,
            self.context_sha256,
            ((self._candidate(),), (self._candidate(),)),
            ("accept", "b2_fail", "accept", "accept"),
        )

        result = self._coordinator(harness, max_lifecycles=2).run()

        self.assertEqual(result.completion, CoordinatorCompletionKind.CONFIRMED_READY)
        self.assertEqual(len(result.lifecycles), 2)
        first, second = result.lifecycles
        self.assertEqual(first.completion, CoordinatorCompletionKind.B2_RECHECK_FAILED)
        self.assertEqual(second.completion, CoordinatorCompletionKind.CONFIRMED_READY)
        self.assertNotEqual(first.lifecycle_id, second.lifecycle_id)
        self.assertNotEqual(first.agent_session_id, second.agent_session_id)
        self.assertEqual(len(harness.handles), 2)
        self.assertTrue(all(handle.finished for handle in harness.handles))
        self.assertEqual(
            [request.role for request in harness.gate_requests],
            [GateRole.B1, GateRole.B2, GateRole.B1, GateRole.B2],
        )
        first_attempt = first.b1_attempts[0].gate_attempt_id
        second_attempt = second.b1_attempts[0].gate_attempt_id
        self.assertNotEqual(first_attempt, second_attempt)
        self.assertEqual(first.b2_result.receipt.attempt_id, first_attempt)
        self.assertEqual(second.b2_result.receipt.attempt_id, second_attempt)
        lease_ids = {
            first.a_workspace.lease.lease_id,
            first.b1_attempts[0].b1_workspace.lease.lease_id,
            first.b2_workspace.lease.lease_id,
            second.a_workspace.lease.lease_id,
            second.b1_attempts[0].b1_workspace.lease.lease_id,
            second.b2_workspace.lease.lease_id,
        }
        self.assertEqual(len(lease_ids), 6)
        self.assertTrue(all(harness.b2_barriers))
        self.assertTrue(
            all(not handle.allocation.paths.root.exists() for handle in harness.handles)
        )
        self.assertEqual(len(harness.cross_gate_requests), 1)

    def test_forged_gate_role_attempt_and_workspace_binding_fail_closed(self):
        for behavior in ("wrong_role", "wrong_attempt", "wrong_binding"):
            with self.subTest(behavior=behavior):
                harness = _ProviderHarness(
                    self.fixture,
                    self.context_sha256,
                    ((self._candidate(),),),
                    (behavior,),
                )
                coordinator = self._coordinator(harness)

                with self.assertRaises(CoordinatorError) as caught:
                    coordinator.run()

                self.assertEqual(
                    caught.exception.code,
                    CoordinatorFailureCode.GATE_RESULT_INVALID,
                )
                self.assertEqual(coordinator.state, CoordinatorState.FAILED)
                self.assertEqual(len(harness.gate_requests), 1)
                self.assertEqual(harness.b2_roots, [])
                self.assertEqual(harness.cross_gate_requests, [])
                self.assertTrue(harness.handles[0].finished)
                self.assertFalse(harness.handles[0].allocation.paths.root.exists())

    def test_lifecycle_rejects_foreign_b2_receipt_workspace_and_cross_gate(self):
        primary_harness = _ProviderHarness(
            self.fixture,
            self.context_sha256,
            ((self._candidate(),),),
            ("accept", "accept"),
        )
        foreign_harness = _ProviderHarness(
            self.fixture,
            self.context_sha256,
            ((self._candidate(),),),
            ("accept", "accept"),
        )
        primary = self._coordinator(primary_harness).run().lifecycles[0]
        foreign = self._coordinator(foreign_harness).run().lifecycles[0]

        for field, forged in (
            ("b2_result", foreign.b2_result),
            ("b2_workspace", foreign.b2_workspace),
            ("cross_gate_decision", foreign.cross_gate_decision),
        ):
            with self.subTest(field=field), self.assertRaises(ContractError):
                dataclasses.replace(primary, **{field: forged})

    def test_attempt_record_rejects_self_consistent_foreign_validation_graph(self):
        local_harness = _ProviderHarness(
            self.fixture,
            self.context_sha256,
            ((self._candidate(),),),
            ("accept", "accept"),
        )
        local_attempt = self._coordinator(local_harness).run().lifecycles[
            0
        ].b1_attempts[0]

        foreign_reasoning = _digest("foreign-reasoning")
        foreign_identity = dataclasses.replace(
            self.fixture["identity"],
            reasoning_sha256=foreign_reasoning,
        )
        foreign_plan = dataclasses.replace(
            self.fixture["case_plan"],
            validation_instance_id=foreign_identity.validation_instance_id,
            reasoning_sha256=foreign_reasoning,
        )
        foreign_template = dataclasses.replace(
            self.fixture["template"],
            validation_instance_id=foreign_identity.validation_instance_id,
            case_plan=foreign_plan.ref,
        )
        foreign_fixture = {
            **self.fixture,
            "identity": foreign_identity,
            "case_plan": foreign_plan,
            "template": foreign_template,
        }
        foreign_harness = _ProviderHarness(
            foreign_fixture,
            self.context_sha256,
            ((_case_submission(foreign_plan),),),
            ("accept", "accept"),
        )
        foreign_attempt = self._coordinator(
            foreign_harness,
            fixture=foreign_fixture,
        ).run().lifecycles[0].b1_attempts[0]

        foreign_gate_result = dataclasses.replace(
            foreign_attempt.gate_result,
            evidence_persistence=dataclasses.replace(
                foreign_attempt.gate_result.evidence_persistence,
                lifecycle_id=local_attempt.response_commit.lifecycle_id,
            ),
        )
        foreign_receipt = foreign_gate_result.receipt
        forged_response = dataclasses.replace(
            local_attempt.response,
            gate_attempt_id=foreign_receipt.attempt_id,
            b1_receipt=foreign_receipt.ref,
            disposition=foreign_receipt.disposition,
            result_status=foreign_receipt.result_status,
            result_reason_code=foreign_receipt.result_reason_code,
            diagnostics=foreign_gate_result.diagnostics,
        )
        forged_commit = dataclasses.replace(
            local_attempt.response_commit,
            response_sha256=forged_response.content_sha256,
        )
        self.assertEqual(
            foreign_gate_result.evidence_persistence.validation_instance_id,
            foreign_receipt.validation_instance_id,
        )
        self.assertNotEqual(
            foreign_receipt.validation_instance_id,
            local_attempt.request.validation_instance_id,
        )
        with self.assertRaisesRegex(ContractError, "identities do not agree"):
            CoordinatorAttemptRecord(
                nonce=local_attempt.nonce,
                request=local_attempt.request,
                request_sha256=local_attempt.request_sha256,
                gate_attempt_id=foreign_receipt.attempt_id,
                response=forged_response,
                response_commit=forged_commit,
                gate_result=foreign_gate_result,
                b1_workspace=foreign_attempt.b1_workspace,
            )

    def test_run_result_rejects_cross_validation_and_reused_agent_handle(self):
        harness = _ProviderHarness(
            self.fixture,
            self.context_sha256,
            ((self._candidate(),), (self._candidate(),)),
            ("accept", "b2_fail", "accept", "accept"),
        )
        result = self._coordinator(harness, max_lifecycles=2).run()

        with self.assertRaisesRegex(ContractError, "validation instance"):
            CoordinatorRunResult(
                validation_instance_id=_digest("foreign-validation"),
                evidence_storage_authority_id=(
                    result.evidence_storage_authority_id
                ),
                completion=result.completion,
                lifecycles=result.lifecycles,
            )

        first, second = result.lifecycles
        reused_handle_id = first.authoritative_handle_id
        rebound_attempts = tuple(
            dataclasses.replace(
                attempt,
                response_commit=dataclasses.replace(
                    attempt.response_commit,
                    authoritative_handle_id=reused_handle_id,
                ),
            )
            for attempt in second.b1_attempts
        )
        rebound_second = dataclasses.replace(
            second,
            authoritative_handle_id=reused_handle_id,
            b1_attempts=rebound_attempts,
            agent_exit=dataclasses.replace(
                second.agent_exit,
                authoritative_handle_id=reused_handle_id,
            ),
        )
        with self.assertRaisesRegex(ContractError, "handle ids"):
            CoordinatorRunResult(
                validation_instance_id=result.validation_instance_id,
                evidence_storage_authority_id=(
                    result.evidence_storage_authority_id
                ),
                completion=result.completion,
                lifecycles=(first, rebound_second),
            )

    def test_preflight_state_requires_its_exact_early_gate_stage(self):
        foreign_profile = dataclasses.replace(
            self.fixture["profile"].ref,
            contract_id=_digest("foreign-profile"),
            content_sha256=_digest("foreign-profile"),
        )
        membership_invalid_plan = dataclasses.replace(
            self.fixture["case_plan"],
            profile=foreign_profile,
        )
        membership_invalid_submission = dataclasses.replace(
            self._candidate(),
            case_plan=membership_invalid_plan,
        )
        stages = (
            EarlyGateStage.INTAKE,
            EarlyGateStage.MEMBERSHIP,
            EarlyGateStage.CONTEXT_INTEGRITY,
        )
        cases = (
            (
                GatePreflightState.INTAKE_INVALID,
                self._candidate(),
                EarlyGateStage.INTAKE,
            ),
            (
                GatePreflightState.MEMBERSHIP_INVALID,
                membership_invalid_submission,
                EarlyGateStage.MEMBERSHIP,
            ),
            (
                GatePreflightState.CONTEXT_INVALID,
                self._candidate(),
                EarlyGateStage.CONTEXT_INTEGRITY,
            ),
        )
        for preflight_state, submission, expected_stage in cases:
            for receipt_stage in stages:
                with self.subTest(
                    preflight_state=preflight_state,
                    receipt_stage=receipt_stage,
                ):
                    harness = _EarlyGateHarness(
                        self.fixture,
                        self.context_sha256,
                        ((submission,),),
                        (),
                        preflight_state=preflight_state,
                        receipt_stage=receipt_stage,
                    )
                    coordinator = self._coordinator(harness)
                    if receipt_stage is expected_stage:
                        result = coordinator.run()
                        self.assertEqual(
                            result.completion,
                            CoordinatorCompletionKind.B1_TERMINAL_READY,
                        )
                        receipt = result.lifecycles[0].b1_attempts[0].gate_result.receipt
                        self.assertIs(receipt.failure_stage, expected_stage)
                    else:
                        with self.assertRaises(CoordinatorError) as caught:
                            coordinator.run()
                        self.assertEqual(
                            caught.exception.code,
                            CoordinatorFailureCode.GATE_RESULT_INVALID,
                        )
                    self.assertEqual(len(harness.gate_requests), 1)
                    self.assertIs(
                        harness.gate_requests[0].preflight_state,
                        preflight_state,
                    )


if __name__ == "__main__":
    unittest.main()

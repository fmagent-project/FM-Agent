import copy
import dataclasses
import hashlib
import json
import unittest

from src.validation_core.contracts.base import ContractError
from src.validation_core.contracts.case import (
    CaseSubmission,
    CaseSubmissionKind,
    compute_validation_instance_id,
)
from src.validation_core.contracts.evidence import (
    CanonicalTypedValue,
    CanonicalValueKind,
    CapturedArtifact,
    DecisionQuorum,
    Observation,
    ObservationFactKind,
    OracleDecision,
    OracleVerdict,
)
from src.validation_core.contracts.oracle import (
    ControlEvidenceRole,
    OracleBundle,
    PrimaryCombination,
)
from src.validation_core.contracts.plan import ExperimentPhase, GateRole
from src.validation_core.contracts.receipt import (
    CandidateGateReceipt,
    EarlyGateReceipt,
    EarlyGateStage,
    FastPathCheck,
    FastPathGateReceipt,
    GatePhaseResult,
    GateReceiptKind,
    gate_receipt_from_document,
    gate_receipt_from_json,
    validate_b1_b2_gate_receipts,
    _aggregate_oracle_bundle_verdict,
    validate_candidate_gate_receipt_membership,
    validate_candidate_gate_receipt_phases,
    validate_early_gate_receipt_identity,
)
from src.validation_core.contracts.references import (
    ArtifactRef,
    ContractRef,
    ContractRefKind,
)
from src.validation_core.contracts.status import (
    CaseReasonCode,
    CaseStatus,
    GateAttemptDisposition,
    GatePhaseStatus,
    ValidationGrade,
)
from tests.test_validation_case_contracts import _candidate as _case_submission
from tests.test_validation_plan_contracts import (
    _binding,
    _membership_fixture,
    _step,
    _template,
)


def _digest(value):
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _ref(kind, name):
    return ContractRef(
        kind=kind,
        contract_id=f"example.{name}",
        contract_version="1.0.0",
        content_sha256=_digest(f"{kind.value}:{name}"),
    )


def _phase(
    phase=ExperimentPhase.ORACLE_EXPERIMENT,
    status=GatePhaseStatus.SATISFIED,
    reasons=(),
):
    return GatePhaseResult(
        phase=phase,
        status=status,
        reason_codes=reasons,
    )


def _candidate(
    role=GateRole.B1,
    *,
    template=None,
    requested=ValidationGrade.L0,
    final=ValidationGrade.L0,
    status=CaseStatus.CONFIRMED_L0,
    reason=CaseReasonCode.CONFIRMED_L0,
    disposition=None,
    binding=None,
    observations=None,
    decisions=None,
    phases=None,
    original_l1=None,
    patch=None,
):
    if template is None:
        template_ref = _ref(
            ContractRefKind.EXPERIMENT_PLAN_TEMPLATE,
            "template",
        )
    else:
        template_ref = template.ref
    if disposition is None and role is GateRole.B1:
        disposition = GateAttemptDisposition.ACCEPTED_CONFIRMED_CANDIDATE
    if observations is None:
        observations = (_ref(ContractRefKind.OBSERVATION, f"observation.{role.value}"),)
    if decisions is None:
        decisions = (_ref(ContractRefKind.ORACLE_DECISION, f"decision.{role.value}"),)
    if phases is None:
        phases = (_phase(),)
    if requested is ValidationGrade.L1:
        original_l1 = original_l1 or _digest("original-l1-candidate")
        patch = patch or _digest("patch")
    return CandidateGateReceipt(
        validation_instance_id=_digest("instance"),
        attempt_id="attempt-1",
        role=role,
        submission=_ref(ContractRefKind.CASE_SUBMISSION, "submission"),
        profile=_ref(ContractRefKind.FROZEN_PROFILE, "profile"),
        case_plan=_ref(ContractRefKind.CASE_PLAN, "case"),
        template=template_ref,
        binding=binding
        or _ref(ContractRefKind.EXECUTION_BINDING, f"binding.{role.value}"),
        requested_grade=requested,
        final_grade=final,
        original_l1_candidate_sha256=original_l1,
        patch_sha256=patch,
        observations=observations,
        decisions=decisions,
        phase_results=phases,
        disposition=disposition,
        result_status=status,
        result_reason_code=reason,
    )


def _fast(role=GateRole.B1, *, disposition=None, checks=None):
    if disposition is None and role is GateRole.B1:
        disposition = GateAttemptDisposition.ACCEPTED_EXPLICIT_NOT_CONFIRMED
    project_id = "example.project"
    case_id = "case-1"
    function_id = "function-1"
    snapshot_sha256 = _digest("snapshot")
    reasoning_sha256 = _digest("reasoning")
    profile_sha256 = _digest("profile")
    return FastPathGateReceipt(
        validation_instance_id=compute_validation_instance_id(
            project_id=project_id,
            case_id=case_id,
            function_id=function_id,
            snapshot_sha256=snapshot_sha256,
            reasoning_sha256=reasoning_sha256,
            profile_sha256=profile_sha256,
        ),
        attempt_id="attempt-1",
        role=role,
        project_id=project_id,
        case_id=case_id,
        function_id=function_id,
        snapshot_sha256=snapshot_sha256,
        submission=_ref(ContractRefKind.CASE_SUBMISSION, "submission.not-confirmed"),
        reasoning_sha256=reasoning_sha256,
        context_sha256=_digest("context"),
        profile_sha256=profile_sha256,
        successful_checks=tuple(FastPathCheck) if checks is None else checks,
        disposition=disposition,
    )


def _raw_submission(name="candidate"):
    return ArtifactRef(
        role="raw_submission",
        media_type="application/json",
        size_bytes=len(name),
        content_sha256=_digest(f"raw:{name}"),
    )


def _not_confirmed_submission(fixture):
    identity = fixture["identity"]
    return CaseSubmission(
        submission_kind=CaseSubmissionKind.NOT_CONFIRMED,
        validation_instance_id=identity.validation_instance_id,
        case_id=identity.case_id,
        function_id=identity.function_id,
        reasoning_sha256=identity.reasoning_sha256,
        attempts=1,
        notes="no valid candidate",
    )


def _early(
    fixture,
    *,
    stage=EarlyGateStage.INTAKE,
    role=GateRole.B1,
    submission=None,
    disposition=None,
    status=CaseStatus.INVALID_SUBMISSION,
    reason=CaseReasonCode.SCHEMA_INVALID,
):
    identity = fixture["identity"]
    if disposition is None and role is GateRole.B1:
        disposition = GateAttemptDisposition.RETRYABLE_REJECTION
    if stage is EarlyGateStage.INTAKE:
        parsed_kind = None
        parsed_submission = None
        parsed_profile = None
        parsed_case_plan = None
    else:
        submission = submission or _case_submission(fixture["case_plan"])
        parsed_kind = submission.submission_kind
        parsed_submission = submission.ref
        parsed_profile = fixture["profile"].ref
        parsed_case_plan = (
            None if submission.case_plan is None else submission.case_plan.ref
        )
    return EarlyGateReceipt(
        validation_instance_id=identity.validation_instance_id,
        attempt_id="attempt-1",
        role=role,
        failure_stage=stage,
        project_id=identity.project_id,
        case_id=identity.case_id,
        function_id=identity.function_id,
        snapshot_sha256=identity.snapshot_sha256,
        reasoning_sha256=identity.reasoning_sha256,
        profile_sha256=identity.profile_sha256,
        context_sha256=_digest("context"),
        raw_submission=_raw_submission(
            "unknown" if submission is None else submission.submission_kind.value
        ),
        parsed_submission_kind=parsed_kind,
        parsed_submission=parsed_submission,
        parsed_profile=parsed_profile,
        parsed_case_plan=parsed_case_plan,
        disposition=disposition,
        result_status=status,
        result_reason_code=reason,
    )


def _captured_for_step(fixture, role, index):
    collector = fixture["specs"][0].collectors[0]
    return CapturedArtifact(
        fact_kind=ObservationFactKind.PROCESS_EXIT,
        artifact=ArtifactRef(
            role=f"step_fact_{index}",
            media_type="application/json",
            size_bytes=index + 1,
            content_sha256=_digest(f"step-fact:{role.value}:{index}"),
        ),
        output_contract=_ref(
            ContractRefKind.OUTPUT_CONTRACT,
            f"step-output.{index}",
        ),
        collector=collector,
        collector_run_id=f"{role.value}.run-{index}",
        capture_id=f"{role.value}.capture-{index}",
        captured_at="2026-08-16T01:00:01Z",
        provenance_sha256=_digest(f"provenance:{role.value}:{index}"),
    )


def _observation_for_step(fixture, binding, step, index):
    template = fixture["template"]
    return Observation(
        validation_instance_id=template.validation_instance_id,
        attempt_id=binding.attempt_id,
        role=binding.role,
        template=template.ref,
        binding=binding.ref,
        step_id=step.step_id,
        repetition_index=0,
        retry_index=0,
        started_at="2026-08-16T01:00:00Z",
        finished_at="2026-08-16T01:00:02Z",
        artifacts=(_captured_for_step(fixture, binding.role, index),),
    )


def _oracle_decision(fixture, binding, spec, observations, verdict):
    if verdict is OracleVerdict.VIOLATION:
        quorum = DecisionQuorum(1, 1, 1, 0, 0)
        reason = "RELATION_VIOLATED"
        normalized_values = (
            CanonicalTypedValue(
                "relation_holds",
                CanonicalValueKind.BOOLEAN,
                False,
            ),
        )
    elif verdict is OracleVerdict.PASS:
        quorum = DecisionQuorum(1, 1, 0, 1, 0)
        reason = "RELATION_HOLDS"
        normalized_values = (
            CanonicalTypedValue(
                "relation_holds",
                CanonicalValueKind.BOOLEAN,
                True,
            ),
        )
    else:
        quorum = DecisionQuorum(1, 1, 0, 0, 1)
        reason = "INSUFFICIENT_QUORUM"
        normalized_values = ()
    return OracleDecision(
        validation_instance_id=fixture["template"].validation_instance_id,
        attempt_id=binding.attempt_id,
        role=binding.role,
        profile=fixture["template"].profile,
        case_plan=fixture["template"].case_plan,
        template=fixture["template"].ref,
        binding=binding.ref,
        oracle_spec=spec.ref,
        baseline_selection=None,
        baseline_source_id=None,
        domain_match=True,
        observations=tuple(observation.ref for observation in observations),
        normalizer=spec.normalizer,
        comparator=spec.comparator,
        threshold_policy=None,
        normalized_values=normalized_values,
        threshold_values=(),
        quorum=quorum,
        verdict=verdict,
        reason_codes=(reason,),
    )


def _decision_with_verdict(decision, verdict):
    if verdict is OracleVerdict.VIOLATION:
        quorum = DecisionQuorum(1, 1, 1, 0, 0)
        reason_codes = ("RELATION_VIOLATED",)
        normalized_values = (
            CanonicalTypedValue(
                "relation_holds",
                CanonicalValueKind.BOOLEAN,
                False,
            ),
        )
    elif verdict is OracleVerdict.PASS:
        quorum = DecisionQuorum(1, 1, 0, 1, 0)
        reason_codes = ("RELATION_HOLDS",)
        normalized_values = (
            CanonicalTypedValue(
                "relation_holds",
                CanonicalValueKind.BOOLEAN,
                True,
            ),
        )
    else:
        quorum = DecisionQuorum(1, 1, 0, 0, 1)
        reason_codes = ("INSUFFICIENT_QUORUM",)
        normalized_values = ()
    return dataclasses.replace(
        decision,
        quorum=quorum,
        normalized_values=normalized_values,
        verdict=verdict,
        reason_codes=reason_codes,
    )


def _confirmed_proof(
    *,
    repair=False,
    causal=False,
    role=GateRole.B1,
):
    fixture = _membership_fixture(causal=causal, repair=repair)
    template = fixture["template"]
    binding = _binding(template, role)
    submission = _case_submission(fixture["case_plan"])
    observations = tuple(
        _observation_for_step(fixture, binding, step, index)
        for index, step in enumerate(template.steps)
    )
    observation_by_step = {
        observation.step_id: observation for observation in observations
    }
    original_family = {
        ExperimentPhase.ORACLE_EXPERIMENT,
        ExperimentPhase.CAUSAL_CONTROL,
    }
    decisions = []
    for spec in fixture["specs"]:
        original = tuple(
            observation_by_step[step.step_id]
            for step in template.steps
            if step.oracle_spec == spec.ref and step.phase in original_family
        )
        original_verdict = (
            OracleVerdict.PASS
            if spec.ref in fixture["bundle"].required_guards
            else OracleVerdict.VIOLATION
        )
        decisions.append(
            _oracle_decision(
                fixture,
                binding,
                spec,
                original,
                original_verdict,
            )
        )
        if repair:
            repaired = tuple(
                observation_by_step[step.step_id]
                for step in template.steps
                if step.oracle_spec == spec.ref
                and step.phase is ExperimentPhase.REPAIR_ORACLE_EXPERIMENT
            )
            decisions.append(
                _oracle_decision(
                    fixture,
                    binding,
                    spec,
                    repaired,
                    OracleVerdict.PASS,
                )
            )
    requested = ValidationGrade.L1 if repair else ValidationGrade.L0
    final = requested
    receipt = CandidateGateReceipt(
        validation_instance_id=template.validation_instance_id,
        attempt_id=binding.attempt_id,
        role=role,
        submission=submission.ref,
        profile=fixture["profile"].ref,
        case_plan=fixture["case_plan"].ref,
        template=template.ref,
        binding=binding.ref,
        requested_grade=requested,
        final_grade=final,
        original_l1_candidate_sha256=(
            submission.content_sha256 if repair else None
        ),
        patch_sha256=(
            fixture["case_plan"].repair.patch.content_sha256 if repair else None
        ),
        observations=tuple(observation.ref for observation in observations),
        decisions=tuple(decision.ref for decision in decisions),
        phase_results=tuple(
            _phase(phase)
            for phase in {step.phase for step in template.steps}
        ),
        disposition=(
            GateAttemptDisposition.ACCEPTED_CONFIRMED_CANDIDATE
            if role is GateRole.B1
            else None
        ),
        result_status=(
            CaseStatus.CONFIRMED_L1 if repair else CaseStatus.CONFIRMED_L0
        ),
        result_reason_code=(
            CaseReasonCode.CONFIRMED_L1
            if repair
            else CaseReasonCode.CONFIRMED_L0
        ),
    )
    return fixture, submission, binding, observations, tuple(decisions), receipt


class CandidateGateReceiptTests(unittest.TestCase):
    def test_frozen_bundle_aggregation_honors_guards_roles_and_combinations(self):
        guard = _ref(ContractRefKind.ORACLE_SPEC, "bundle.guard")
        primary_a = _ref(ContractRefKind.ORACLE_SPEC, "bundle.primary-a")
        primary_b = _ref(ContractRefKind.ORACLE_SPEC, "bundle.primary-b")
        supporting = _ref(ContractRefKind.ORACLE_SPEC, "bundle.supporting")

        def bundle(combination, *, k=None):
            return OracleBundle(
                bundle_id=f"example.bundle.{combination.value}",
                bundle_version="1.0.0",
                required_guards=(guard,),
                primary_oracles=(primary_a, primary_b),
                supporting_oracles=(supporting,),
                primary_combination=combination,
                k=k,
                control_evidence_role=ControlEvidenceRole.DUAL_ROLE,
                control_oracle=primary_a,
                primary_metric_oracle=None,
                multiplicity_policy=None,
            )

        base = {
            guard: OracleVerdict.PASS,
            primary_a: OracleVerdict.PASS,
            primary_b: OracleVerdict.PASS,
            supporting: OracleVerdict.VIOLATION,
        }
        cases = (
            (
                "supporting-only-violation",
                bundle(PrimaryCombination.ALL),
                base,
                OracleVerdict.PASS,
            ),
            (
                "all-violate",
                bundle(PrimaryCombination.ALL),
                {
                    **base,
                    primary_a: OracleVerdict.VIOLATION,
                    primary_b: OracleVerdict.VIOLATION,
                },
                OracleVerdict.VIOLATION,
            ),
            (
                "all-mixed",
                bundle(PrimaryCombination.ALL),
                {**base, primary_a: OracleVerdict.VIOLATION},
                OracleVerdict.PASS,
            ),
            (
                "any-one-violates",
                bundle(PrimaryCombination.ANY),
                {**base, primary_a: OracleVerdict.VIOLATION},
                OracleVerdict.VIOLATION,
            ),
            (
                "any-unresolved",
                bundle(PrimaryCombination.ANY),
                {**base, primary_b: OracleVerdict.INCONCLUSIVE},
                OracleVerdict.INCONCLUSIVE,
            ),
            (
                "k-reached",
                bundle(PrimaryCombination.K_OF_N, k=2),
                {
                    **base,
                    primary_a: OracleVerdict.VIOLATION,
                    primary_b: OracleVerdict.VIOLATION,
                },
                OracleVerdict.VIOLATION,
            ),
            (
                "k-impossible",
                bundle(PrimaryCombination.K_OF_N, k=2),
                {**base, primary_a: OracleVerdict.VIOLATION},
                OracleVerdict.PASS,
            ),
            (
                "k-unresolved",
                bundle(PrimaryCombination.K_OF_N, k=2),
                {
                    **base,
                    primary_a: OracleVerdict.VIOLATION,
                    primary_b: OracleVerdict.INCONCLUSIVE,
                },
                OracleVerdict.INCONCLUSIVE,
            ),
            (
                "guard-violation",
                bundle(PrimaryCombination.ANY),
                {
                    **base,
                    guard: OracleVerdict.VIOLATION,
                    primary_a: OracleVerdict.VIOLATION,
                },
                OracleVerdict.INCONCLUSIVE,
            ),
            (
                "guard-inconclusive",
                bundle(PrimaryCombination.ANY),
                {
                    **base,
                    guard: OracleVerdict.INCONCLUSIVE,
                    primary_a: OracleVerdict.VIOLATION,
                },
                OracleVerdict.INCONCLUSIVE,
            ),
        )
        for name, selected, verdicts, expected in cases:
            with self.subTest(name=name):
                self.assertIs(
                    _aggregate_oracle_bundle_verdict(selected, verdicts),
                    expected,
                )

    def test_membership_binds_requested_l1_and_patch_to_submission(self):
        fixture = _membership_fixture(repair=True)
        plan = fixture["case_plan"]
        submission = _case_submission(plan)
        binding = _binding(fixture["template"], GateRole.B1)
        receipt = CandidateGateReceipt(
            validation_instance_id=plan.validation_instance_id,
            attempt_id=binding.attempt_id,
            role=GateRole.B1,
            submission=submission.ref,
            profile=fixture["profile"].ref,
            case_plan=plan.ref,
            template=fixture["template"].ref,
            binding=binding.ref,
            requested_grade=ValidationGrade.L1,
            final_grade=None,
            original_l1_candidate_sha256=submission.content_sha256,
            patch_sha256=plan.repair.patch.content_sha256,
            observations=(),
            decisions=(),
            phase_results=(),
            disposition=GateAttemptDisposition.RETRYABLE_REJECTION,
            result_status=CaseStatus.NOT_CONFIRMED,
            result_reason_code=CaseReasonCode.TARGET_NOT_REACHED,
        )
        kwargs = {
            "submission": submission,
            "profile": fixture["profile"],
            "case_plan": plan,
            "oracle_bundle": fixture["bundle"],
            "template": fixture["template"],
            "binding": binding,
            "observations": (),
            "decisions": (),
        }
        validate_candidate_gate_receipt_membership(receipt, **kwargs)

        for changed in (
            dataclasses.replace(
                receipt,
                original_l1_candidate_sha256=_digest("other-submission"),
            ),
            dataclasses.replace(receipt, patch_sha256=_digest("other-patch")),
            dataclasses.replace(
                receipt,
                requested_grade=ValidationGrade.L0,
                original_l1_candidate_sha256=None,
                patch_sha256=None,
            ),
        ):
            with self.subTest(changed=changed), self.assertRaises(ContractError):
                validate_candidate_gate_receipt_membership(changed, **kwargs)

    def test_round_trip_is_canonical_and_content_addressed(self):
        receipt = _candidate(
            observations=(
                _ref(ContractRefKind.OBSERVATION, "z"),
                _ref(ContractRefKind.OBSERVATION, "a"),
            ),
            decisions=(
                _ref(ContractRefKind.ORACLE_DECISION, "z"),
                _ref(ContractRefKind.ORACLE_DECISION, "a"),
            ),
            phases=(
                _phase(ExperimentPhase.ORACLE_EXPERIMENT),
                _phase(ExperimentPhase.SANDBOX_HEALTH),
            ),
        )
        parsed = gate_receipt_from_json(
            json.dumps(receipt.to_document()).encode("utf-8")
        )

        self.assertEqual(parsed, receipt)
        self.assertEqual(parsed.content_sha256, receipt.content_sha256)
        self.assertEqual(receipt.ref.kind, ContractRefKind.GATE_RECEIPT)
        self.assertEqual(receipt.ref.contract_id, receipt.content_sha256)
        self.assertEqual(
            [result.phase for result in receipt.phase_results],
            [ExperimentPhase.SANDBOX_HEALTH, ExperimentPhase.ORACLE_EXPERIMENT],
        )

    def test_union_parser_rejects_cross_branch_and_unknown_fields(self):
        candidate = _candidate().to_document()
        fast = _fast().to_document()

        cross = copy.deepcopy(fast)
        cross["template"] = candidate["template"]
        with self.assertRaises(ContractError):
            gate_receipt_from_document(cross)

        missing = copy.deepcopy(candidate)
        missing.pop("binding")
        with self.assertRaises(ContractError):
            gate_receipt_from_document(missing)

        unknown = copy.deepcopy(candidate)
        unknown["receipt_kind"] = "future_gate"
        with self.assertRaises(ContractError):
            gate_receipt_from_document(unknown)

    def test_strict_json_rejects_duplicate_keys_and_floating_values(self):
        with self.assertRaises(ContractError):
            gate_receipt_from_json(
                b'{"receipt_kind":"full_candidate_gate",'
                b'"receipt_kind":"identity_hash_fast_path"}'
            )
        with self.assertRaises(ContractError):
            gate_receipt_from_json(
                b'{"receipt_kind":"full_candidate_gate","schema_version":1.0}'
            )

    def test_requested_l1_preserves_original_candidate_and_patch_on_downgrade(self):
        receipt = _candidate(
            requested=ValidationGrade.L1,
            final=ValidationGrade.L0,
            original_l1=_digest("original"),
            patch=_digest("patch-v1"),
        )

        self.assertEqual(receipt.requested_grade, ValidationGrade.L1)
        self.assertEqual(receipt.final_grade, ValidationGrade.L0)
        self.assertEqual(receipt.original_l1_candidate_sha256, _digest("original"))
        self.assertEqual(receipt.patch_sha256, _digest("patch-v1"))
        self.assertEqual(
            gate_receipt_from_document(receipt.to_document()),
            receipt,
        )

        with self.assertRaises(ContractError):
            dataclasses.replace(receipt, original_l1_candidate_sha256=None)
        with self.assertRaises(ContractError):
            dataclasses.replace(receipt, patch_sha256=None)
        with self.assertRaises(ContractError):
            _candidate(original_l1=_digest("forbidden"))

    def test_confirmed_grade_status_and_nonconfirmed_grade_are_fail_closed(self):
        with self.assertRaises(ContractError):
            _candidate(
                final=ValidationGrade.L1,
                status=CaseStatus.CONFIRMED_L0,
                reason=CaseReasonCode.CONFIRMED_L0,
            )
        with self.assertRaises(ContractError):
            _candidate(
                final=ValidationGrade.L0,
                status=CaseStatus.NOT_CONFIRMED,
                reason=CaseReasonCode.CONSEQUENCE_NOT_REPRODUCED,
                disposition=GateAttemptDisposition.RETRYABLE_REJECTION,
            )

        retryable = _candidate(
            final=None,
            status=CaseStatus.NOT_CONFIRMED,
            reason=CaseReasonCode.CONSEQUENCE_NOT_REPRODUCED,
            disposition=GateAttemptDisposition.RETRYABLE_REJECTION,
            observations=(),
            decisions=(),
            phases=(),
        )
        terminal = dataclasses.replace(
            retryable,
            disposition=GateAttemptDisposition.TERMINAL_OUTCOME,
        )
        self.assertEqual(
            retryable.disposition,
            GateAttemptDisposition.RETRYABLE_REJECTION,
        )
        self.assertEqual(
            terminal.disposition,
            GateAttemptDisposition.TERMINAL_OUTCOME,
        )

    def test_disposition_and_role_matrix_is_strict(self):
        with self.assertRaises(ContractError):
            _candidate(disposition=GateAttemptDisposition.RETRYABLE_REJECTION)
        with self.assertRaises(ContractError):
            _candidate(
                final=None,
                status=CaseStatus.NOT_CONFIRMED,
                reason=CaseReasonCode.CONSEQUENCE_NOT_REPRODUCED,
                disposition=GateAttemptDisposition.ACCEPTED_CONFIRMED_CANDIDATE,
            )
        with self.assertRaises(ContractError):
            _candidate(
                disposition=GateAttemptDisposition.ACCEPTED_EXPLICIT_NOT_CONFIRMED
            )
        with self.assertRaises(ContractError):
            _candidate(
                GateRole.B2,
                disposition=GateAttemptDisposition.TERMINAL_OUTCOME,
            )
        with self.assertRaises(ContractError):
            _candidate(
                status=CaseStatus.NOT_CONFIRMED,
                reason=CaseReasonCode.CONFIRMED_L0,
                final=None,
                disposition=GateAttemptDisposition.RETRYABLE_REJECTION,
            )
        with self.assertRaisesRegex(ContractError, "fast-path branch"):
            _candidate(
                status=CaseStatus.NOT_CONFIRMED,
                reason=CaseReasonCode.EXPLICIT_NOT_CONFIRMED,
                final=None,
                disposition=GateAttemptDisposition.TERMINAL_OUTCOME,
                observations=(),
                decisions=(),
                phases=(),
            )
        for status, reason in (
            (CaseStatus.INCONCLUSIVE_INFRA, CaseReasonCode.TOOL_UNAVAILABLE),
            (
                CaseStatus.NEEDS_ORACLE_SETUP,
                CaseReasonCode.NO_APPLICABLE_PROFILE_CAPABILITY,
            ),
            (
                CaseStatus.INVALID_SUBMISSION,
                CaseReasonCode.PROFILE_ARTIFACT_INVALID,
            ),
        ):
            with self.subTest(status=status), self.assertRaises(ContractError):
                _candidate(
                    final=None,
                    status=status,
                    reason=reason,
                    disposition=GateAttemptDisposition.RETRYABLE_REJECTION,
                    observations=(),
                    decisions=(),
                    phases=(),
                )

    def test_phase_reasons_are_strict_and_canonical(self):
        satisfied = _phase()
        rejected = _phase(
            status=GatePhaseStatus.REJECTED,
            reasons=("PATCH_STILL_VIOLATES", "BUILD_FAILED"),
        )
        self.assertEqual(
            rejected.reason_codes,
            ("BUILD_FAILED", "PATCH_STILL_VIOLATES"),
        )
        self.assertEqual(satisfied.reason_codes, ())
        self.assertEqual(
            GatePhaseResult.from_document(rejected.to_document()),
            rejected,
        )
        with self.assertRaises(ContractError):
            _phase(status=GatePhaseStatus.REJECTED)
        with self.assertRaises(ContractError):
            _phase(reasons=("UNEXPECTED",))
        with self.assertRaises(ContractError):
            _phase(status=GatePhaseStatus.SKIPPED)
        with self.assertRaises(ContractError):
            GatePhaseResult.from_document(
                {"phase": "oracle_experiment", "status": "SATISFIED"}
            )

    def test_phase_membership_audits_confirmed_and_l1_downgrade(self):
        oracle = _step(
            step_id="oracle",
            phase=ExperimentPhase.ORACLE_EXPERIMENT,
        )
        repair = _step(
            step_id="repair",
            phase=ExperimentPhase.REPAIR,
            depends_on=("oracle",),
        )
        template = _template(steps=(oracle, repair))

        downgraded = _candidate(
            template=template,
            requested=ValidationGrade.L1,
            final=ValidationGrade.L0,
            phases=(
                _phase(ExperimentPhase.ORACLE_EXPERIMENT),
                _phase(
                    ExperimentPhase.REPAIR,
                    GatePhaseStatus.REJECTED,
                    ("PATCH_STILL_VIOLATES",),
                ),
            ),
        )
        validate_candidate_gate_receipt_phases(downgraded, template)

        with self.assertRaises(ContractError):
            validate_candidate_gate_receipt_phases(
                dataclasses.replace(
                    downgraded,
                    phase_results=(
                        _phase(ExperimentPhase.ORACLE_EXPERIMENT),
                        _phase(ExperimentPhase.REPAIR),
                    ),
                ),
                template,
            )
        with self.assertRaises(ContractError):
            validate_candidate_gate_receipt_phases(
                dataclasses.replace(
                    downgraded,
                    phase_results=(
                        _phase(
                            ExperimentPhase.ORACLE_EXPERIMENT,
                            GatePhaseStatus.INCONCLUSIVE,
                            ("ORACLE_UNSTABLE",),
                        ),
                        _phase(
                            ExperimentPhase.REPAIR,
                            GatePhaseStatus.REJECTED,
                            ("PATCH_STILL_VIOLATES",),
                        ),
                    ),
                ),
                template,
            )

        l1 = dataclasses.replace(
            downgraded,
            final_grade=ValidationGrade.L1,
            result_status=CaseStatus.CONFIRMED_L1,
            result_reason_code=CaseReasonCode.CONFIRMED_L1,
        )
        with self.assertRaises(ContractError):
            validate_candidate_gate_receipt_phases(l1, template)

    def test_confirmed_membership_requires_planned_oracles_and_verdict_phases(self):
        values = _confirmed_proof(causal=True)
        fixture, submission, binding, observations, decisions, receipt = values
        kwargs = {
            "submission": submission,
            "profile": fixture["profile"],
            "case_plan": fixture["case_plan"],
            "oracle_bundle": fixture["bundle"],
            "template": fixture["template"],
            "binding": binding,
            "observations": observations,
        }
        validate_candidate_gate_receipt_membership(
            receipt,
            decisions=decisions,
            **kwargs,
        )

        oracle_observation = next(
            observation
            for observation in observations
            if next(
                step
                for step in fixture["template"].steps
                if step.step_id == observation.step_id
            ).phase
            is ExperimentPhase.ORACLE_EXPERIMENT
        )
        original_artifact = oracle_observation.artifacts[0]
        extra_artifact = dataclasses.replace(
            original_artifact,
            artifact=dataclasses.replace(
                original_artifact.artifact,
                content_sha256=_digest("unconsumed-oracle-fact"),
            ),
            collector_run_id="extra.oracle.run",
            capture_id="extra.oracle.capture",
            provenance_sha256=_digest("extra-oracle-provenance"),
        )
        unconsumed = dataclasses.replace(
            oracle_observation,
            retry_index=1,
            artifacts=(extra_artifact,),
        )
        observations_with_extra = (*observations, unconsumed)
        with self.assertRaisesRegex(ContractError, "exactly cover"):
            validate_candidate_gate_receipt_membership(
                dataclasses.replace(
                    receipt,
                    observations=tuple(
                        observation.ref for observation in observations_with_extra
                    ),
                ),
                decisions=decisions,
                observations=observations_with_extra,
                **{
                    key: value
                    for key, value in kwargs.items()
                    if key != "observations"
                },
            )

        oracle_only = _confirmed_proof(causal=False)
        (
            oracle_fixture,
            oracle_submission,
            oracle_binding,
            oracle_observations,
            oracle_decisions,
            oracle_receipt,
        ) = oracle_only
        with self.assertRaisesRegex(ContractError, "approved causal control"):
            validate_candidate_gate_receipt_membership(
                oracle_receipt,
                submission=oracle_submission,
                profile=oracle_fixture["profile"],
                case_plan=oracle_fixture["case_plan"],
                oracle_bundle=oracle_fixture["bundle"],
                template=oracle_fixture["template"],
                binding=oracle_binding,
                observations=oracle_observations,
                decisions=oracle_decisions,
            )

        missing = decisions[:-1]
        with self.assertRaisesRegex(ContractError, "every planned OracleSpec"):
            validate_candidate_gate_receipt_membership(
                dataclasses.replace(
                    receipt,
                    decisions=tuple(decision.ref for decision in missing),
                ),
                decisions=missing,
                **kwargs,
            )

        unknown = dataclasses.replace(
            decisions[0],
            oracle_spec=_ref(ContractRefKind.ORACLE_SPEC, "unknown"),
        )
        changed = (unknown, *decisions[1:])
        with self.assertRaisesRegex(ContractError, "outside the experiment template"):
            validate_candidate_gate_receipt_membership(
                dataclasses.replace(
                    receipt,
                    decisions=tuple(decision.ref for decision in changed),
                ),
                decisions=changed,
                **kwargs,
            )

        passed = tuple(
            dataclasses.replace(
                decision,
                verdict=OracleVerdict.PASS,
                quorum=DecisionQuorum(1, 1, 0, 1, 0),
                reason_codes=("RELATION_HOLDS",),
            )
            for decision in decisions
        )
        with self.assertRaisesRegex(
            ContractError,
            "primary combination.*VIOLATION",
        ):
            validate_candidate_gate_receipt_membership(
                dataclasses.replace(
                    receipt,
                    decisions=tuple(decision.ref for decision in passed),
                ),
                decisions=passed,
                **kwargs,
            )

        guard_failed = tuple(
            _decision_with_verdict(
                decision,
                OracleVerdict.VIOLATION
                if decision.oracle_spec in fixture["bundle"].required_guards
                else OracleVerdict.PASS,
            )
            for decision in decisions
        )
        with self.assertRaisesRegex(ContractError, "required guards to PASS"):
            validate_candidate_gate_receipt_membership(
                dataclasses.replace(
                    receipt,
                    decisions=tuple(decision.ref for decision in guard_failed),
                ),
                decisions=guard_failed,
                **kwargs,
            )

        l1_values = _confirmed_proof(repair=True, causal=True)
        l1_fixture, l1_submission, l1_binding, l1_obs, l1_decisions, l1_receipt = (
            l1_values
        )
        l1_kwargs = {
            "submission": l1_submission,
            "profile": l1_fixture["profile"],
            "case_plan": l1_fixture["case_plan"],
            "oracle_bundle": l1_fixture["bundle"],
            "template": l1_fixture["template"],
            "binding": l1_binding,
            "observations": l1_obs,
        }
        validate_candidate_gate_receipt_membership(
            l1_receipt,
            decisions=l1_decisions,
            **l1_kwargs,
        )
        l1_observation_by_ref = {
            observation.ref: observation for observation in l1_obs
        }
        l1_step_by_id = {
            step.step_id: step for step in l1_fixture["template"].steps
        }

        def is_repair_decision(decision):
            return all(
                l1_step_by_id[l1_observation_by_ref[reference].step_id].phase
                is ExperimentPhase.REPAIR_ORACLE_EXPERIMENT
                for reference in decision.observations
            )

        repair_guard_failed = tuple(
            _decision_with_verdict(decision, OracleVerdict.VIOLATION)
            if is_repair_decision(decision)
            and decision.oracle_spec in l1_fixture["bundle"].required_guards
            else decision
            for decision in l1_decisions
        )
        with self.assertRaisesRegex(ContractError, "repair guards to PASS"):
            validate_candidate_gate_receipt_membership(
                dataclasses.replace(
                    l1_receipt,
                    decisions=tuple(
                        decision.ref for decision in repair_guard_failed
                    ),
                ),
                decisions=repair_guard_failed,
                **l1_kwargs,
            )

        repair_primary_failed = tuple(
            _decision_with_verdict(decision, OracleVerdict.VIOLATION)
            if is_repair_decision(decision)
            and decision.oracle_spec in l1_fixture["bundle"].primary_oracles
            else decision
            for decision in l1_decisions
        )
        with self.assertRaisesRegex(
            ContractError,
            "repair OracleBundle primary combination to be PASS",
        ):
            validate_candidate_gate_receipt_membership(
                dataclasses.replace(
                    l1_receipt,
                    decisions=tuple(
                        decision.ref for decision in repair_primary_failed
                    ),
                ),
                decisions=repair_primary_failed,
                **l1_kwargs,
            )

        original_only = tuple(
            decision
            for decision in l1_decisions
            if all(
                l1_step_by_id[l1_observation_by_ref[reference].step_id].phase
                is not ExperimentPhase.REPAIR_ORACLE_EXPERIMENT
                for reference in decision.observations
            )
        )
        with self.assertRaisesRegex(ContractError, "repair decisions"):
            validate_candidate_gate_receipt_membership(
                dataclasses.replace(
                    l1_receipt,
                    decisions=tuple(decision.ref for decision in original_only),
                ),
                decisions=original_only,
                **l1_kwargs,
            )

        original = original_only[0]
        repair_observation = next(
            observation
            for observation in l1_obs
            if next(
                step
                for step in l1_fixture["template"].steps
                if step.step_id == observation.step_id
            ).phase
            is ExperimentPhase.REPAIR_ORACLE_EXPERIMENT
        )
        mixed = dataclasses.replace(
            original,
            observations=(*original.observations, repair_observation.ref),
        )
        mixed_decisions = (mixed, *l1_decisions[1:])
        with self.assertRaisesRegex(ContractError, "phase family"):
            validate_candidate_gate_receipt_membership(
                dataclasses.replace(
                    l1_receipt,
                    decisions=tuple(
                        decision.ref for decision in mixed_decisions
                    ),
                ),
                decisions=mixed_decisions,
                **l1_kwargs,
            )

    def test_confirmed_membership_requires_every_executable_step_observed(self):
        values = _confirmed_proof(causal=True)
        fixture, submission, binding, observations, decisions, receipt = values
        kwargs = {
            "submission": submission,
            "profile": fixture["profile"],
            "case_plan": fixture["case_plan"],
            "oracle_bundle": fixture["bundle"],
            "template": fixture["template"],
            "binding": binding,
            "decisions": decisions,
        }
        missing = tuple(
            observation
            for observation in observations
            if observation.step_id != "phase.target"
        )
        with self.assertRaisesRegex(ContractError, "template steps"):
            validate_candidate_gate_receipt_membership(
                dataclasses.replace(
                    receipt,
                    observations=tuple(
                        observation.ref for observation in missing
                    ),
                ),
                observations=missing,
                **kwargs,
            )

        sandbox = next(
            observation
            for observation in observations
            if observation.step_id == "phase.health"
        )
        unknown = dataclasses.replace(sandbox, step_id="unknown.step")
        changed = tuple(
            unknown if observation is sandbox else observation
            for observation in observations
        )
        with self.assertRaisesRegex(ContractError, "unknown template step"):
            validate_candidate_gate_receipt_membership(
                dataclasses.replace(
                    receipt,
                    observations=tuple(
                        observation.ref for observation in changed
                    ),
                ),
                observations=changed,
                **kwargs,
            )

        l1_values = _confirmed_proof(repair=True, causal=True)
        l1_fixture, l1_submission, l1_binding, l1_obs, l1_decisions, l1_receipt = (
            l1_values
        )
        step_by_id = {
            step.step_id: step for step in l1_fixture["template"].steps
        }
        original_observations = tuple(
            observation
            for observation in l1_obs
            if step_by_id[observation.step_id].phase not in {
                ExperimentPhase.REPAIR,
                ExperimentPhase.BUILD_SANITY,
                ExperimentPhase.REPAIR_REAL_ENTRY_REPLAY,
                ExperimentPhase.REPAIR_TARGET_EVIDENCE,
                ExperimentPhase.REPAIR_ORACLE_EXPERIMENT,
                ExperimentPhase.REGRESSION,
            }
        )
        observation_by_ref = {
            observation.ref: observation for observation in l1_obs
        }
        original_decisions = tuple(
            decision
            for decision in l1_decisions
            if all(
                step_by_id[observation_by_ref[reference].step_id].phase
                is not ExperimentPhase.REPAIR_ORACLE_EXPERIMENT
                for reference in decision.observations
            )
        )
        downgraded_phases = tuple(
            _phase(
                phase,
                (
                    GatePhaseStatus.REJECTED
                    if phase is ExperimentPhase.REPAIR
                    else GatePhaseStatus.SATISFIED
                ),
                ("PATCH_REJECTED",)
                if phase is ExperimentPhase.REPAIR
                else (),
            )
            for phase in {step.phase for step in l1_fixture["template"].steps}
        )
        downgraded = dataclasses.replace(
            l1_receipt,
            final_grade=ValidationGrade.L0,
            result_status=CaseStatus.CONFIRMED_L0,
            result_reason_code=CaseReasonCode.CONFIRMED_L0,
            observations=tuple(
                observation.ref for observation in original_observations
            ),
            decisions=tuple(decision.ref for decision in original_decisions),
            phase_results=downgraded_phases,
        )
        downgrade_kwargs = {
            "submission": l1_submission,
            "profile": l1_fixture["profile"],
            "case_plan": l1_fixture["case_plan"],
            "oracle_bundle": l1_fixture["bundle"],
            "template": l1_fixture["template"],
            "binding": l1_binding,
            "decisions": original_decisions,
        }
        validate_candidate_gate_receipt_membership(
            downgraded,
            observations=original_observations,
            **downgrade_kwargs,
        )
        missing_original = tuple(
            observation
            for observation in original_observations
            if observation.step_id != "phase.replay"
        )
        with self.assertRaisesRegex(ContractError, "template steps"):
            validate_candidate_gate_receipt_membership(
                dataclasses.replace(
                    downgraded,
                    observations=tuple(
                        observation.ref for observation in missing_original
                    ),
                ),
                observations=missing_original,
                **downgrade_kwargs,
            )


class EarlyGateReceiptTests(unittest.TestCase):
    def test_intake_failure_round_trip_has_only_raw_authority_inputs(self):
        fixture = _membership_fixture(causal=False, repair=False)
        receipt = _early(fixture)
        parsed = gate_receipt_from_json(
            json.dumps(receipt.to_document()).encode("utf-8")
        )

        self.assertEqual(parsed, receipt)
        self.assertEqual(receipt.receipt_kind, GateReceiptKind.PRE_EXECUTION_FAILURE)
        self.assertEqual(receipt.ref.kind, ContractRefKind.GATE_RECEIPT)
        for forbidden in ("template", "binding", "observations", "decisions"):
            self.assertNotIn(forbidden, receipt.to_document())
        document_with_execution_field = receipt.to_document()
        document_with_execution_field["template"] = _ref(
            ContractRefKind.EXPERIMENT_PLAN_TEMPLATE,
            "fabricated-template",
        ).to_document()
        with self.assertRaises(ContractError):
            gate_receipt_from_document(document_with_execution_field)
        validate_early_gate_receipt_identity(
            receipt,
            identity=fixture["identity"],
            context_sha256=_digest("context"),
            raw_submission=receipt.raw_submission,
        )

        with self.assertRaises(ContractError):
            dataclasses.replace(
                receipt,
                parsed_submission_kind=CaseSubmissionKind.CANDIDATE,
                parsed_submission=_ref(
                    ContractRefKind.CASE_SUBMISSION,
                    "untrusted",
                ),
            )
        with self.assertRaises(ContractError):
            dataclasses.replace(
                receipt,
                validation_instance_id=_digest("self-reported-instance"),
            )
        with self.assertRaises(ContractError):
            dataclasses.replace(
                receipt,
                raw_submission=dataclasses.replace(
                    receipt.raw_submission,
                    role="other",
                ),
            )

    def test_post_intake_candidate_refs_are_exact_content_bindings(self):
        fixture = _membership_fixture(causal=False, repair=False)
        submission = _case_submission(fixture["case_plan"])
        receipt = _early(
            fixture,
            stage=EarlyGateStage.MEMBERSHIP,
            submission=submission,
            reason=CaseReasonCode.MEMBERSHIP_INVALID,
        )
        validate_early_gate_receipt_identity(
            receipt,
            identity=fixture["identity"],
            context_sha256=_digest("context"),
            raw_submission=receipt.raw_submission,
            submission=submission,
            profile=fixture["profile"],
            case_plan=fixture["case_plan"],
        )

        with self.assertRaisesRegex(ContractError, "parsed Profile mismatch"):
            validate_early_gate_receipt_identity(
                dataclasses.replace(
                    receipt,
                    parsed_profile=_ref(
                        ContractRefKind.FROZEN_PROFILE,
                        "other-profile",
                    ),
                ),
                identity=fixture["identity"],
                context_sha256=_digest("context"),
                raw_submission=receipt.raw_submission,
                submission=submission,
                profile=fixture["profile"],
                case_plan=fixture["case_plan"],
            )
        with self.assertRaises(ContractError):
            dataclasses.replace(
                receipt,
                parsed_case_plan=None,
            )

    def test_not_confirmed_can_record_hash_failure_but_never_materialize(self):
        fixture = _membership_fixture(causal=False, repair=False)
        submission = _not_confirmed_submission(fixture)
        receipt = _early(
            fixture,
            stage=EarlyGateStage.CONTEXT_INTEGRITY,
            submission=submission,
            disposition=GateAttemptDisposition.TERMINAL_OUTCOME,
            reason=CaseReasonCode.PROFILE_ARTIFACT_INVALID,
        )
        self.assertIsNone(receipt.parsed_case_plan)
        validate_early_gate_receipt_identity(
            receipt,
            identity=fixture["identity"],
            context_sha256=_digest("context"),
            raw_submission=receipt.raw_submission,
            submission=submission,
            profile=fixture["profile"],
            case_plan=None,
        )

        with self.assertRaises(ContractError):
            dataclasses.replace(
                receipt,
                failure_stage=EarlyGateStage.MATERIALIZE,
            )
        with self.assertRaises(ContractError):
            dataclasses.replace(
                receipt,
                parsed_case_plan=fixture["case_plan"].ref,
            )

    def test_early_role_and_disposition_matrix_is_fail_closed(self):
        fixture = _membership_fixture(causal=False, repair=False)
        with self.assertRaises(ContractError):
            _early(
                fixture,
                disposition=GateAttemptDisposition.ACCEPTED_CONFIRMED_CANDIDATE,
            )
        with self.assertRaises(ContractError):
            _early(
                fixture,
                status=CaseStatus.NOT_CONFIRMED,
                reason=CaseReasonCode.CONSEQUENCE_NOT_REPRODUCED,
            )
        b2 = _early(
            fixture,
            role=GateRole.B2,
            disposition=None,
        )
        self.assertIsNone(b2.disposition)
        with self.assertRaises(ContractError):
            dataclasses.replace(
                b2,
                disposition=GateAttemptDisposition.TERMINAL_OUTCOME,
            )


class FastPathGateReceiptTests(unittest.TestCase):
    def test_fast_path_round_trip_has_no_candidate_execution_fields(self):
        receipt = _fast()
        parsed = gate_receipt_from_document(receipt.to_document())

        self.assertEqual(parsed, receipt)
        self.assertEqual(receipt.ref.kind, ContractRefKind.GATE_RECEIPT)
        for forbidden in (
            "template",
            "binding",
            "observations",
            "decisions",
            "requested_grade",
            "final_grade",
        ):
            self.assertNotIn(forbidden, receipt.to_document())
        with self.assertRaisesRegex(ContractError, "authority identity"):
            dataclasses.replace(
                receipt,
                validation_instance_id=_digest("self-reported-fast-instance"),
            )

    def test_fast_path_requires_every_successful_check_once(self):
        with self.assertRaises(ContractError):
            _fast(checks=tuple(FastPathCheck)[:-1])
        with self.assertRaises(ContractError):
            _fast(checks=tuple(FastPathCheck) + (FastPathCheck.IDENTITY,))

        reversed_checks = _fast(checks=tuple(reversed(tuple(FastPathCheck))))
        self.assertEqual(reversed_checks.successful_checks, tuple(FastPathCheck))

    def test_fast_path_role_disposition_is_not_spoofable(self):
        with self.assertRaises(ContractError):
            _fast(disposition=GateAttemptDisposition.TERMINAL_OUTCOME)
        with self.assertRaises(ContractError):
            _fast(
                GateRole.B2,
                disposition=GateAttemptDisposition.ACCEPTED_EXPLICIT_NOT_CONFIRMED,
            )
        self.assertIsNone(_fast(GateRole.B2).disposition)


class ReceiptPairTests(unittest.TestCase):
    def test_confirmed_b1_can_pair_with_pre_execution_b2_failure_only(self):
        values = _confirmed_proof(causal=False)
        fixture, submission, _binding_value, _observations, _decisions, b1 = values
        b2 = _early(
            fixture,
            stage=EarlyGateStage.MEMBERSHIP,
            role=GateRole.B2,
            submission=submission,
            disposition=None,
            reason=CaseReasonCode.MEMBERSHIP_INVALID,
        )
        validate_b1_b2_gate_receipts(b1, b2)

        with self.assertRaises(ContractError):
            validate_b1_b2_gate_receipts(
                b1,
                dataclasses.replace(
                    b2,
                    parsed_profile=_ref(
                        ContractRefKind.FROZEN_PROFILE,
                        "other-profile",
                    ),
                ),
            )
        with self.assertRaisesRegex(ContractError, "candidate submission branch"):
            validate_b1_b2_gate_receipts(
                b1,
                dataclasses.replace(
                    b2,
                    parsed_submission_kind=CaseSubmissionKind.NOT_CONFIRMED,
                    parsed_case_plan=None,
                ),
            )
        with self.assertRaises(ContractError):
            validate_b1_b2_gate_receipts(
                _early(
                    fixture,
                    stage=EarlyGateStage.MEMBERSHIP,
                    submission=submission,
                    reason=CaseReasonCode.MEMBERSHIP_INVALID,
                ),
                b2,
            )

        rejected_b1 = dataclasses.replace(
            b1,
            final_grade=None,
            disposition=GateAttemptDisposition.TERMINAL_OUTCOME,
            result_status=CaseStatus.NOT_CONFIRMED,
            result_reason_code=CaseReasonCode.TARGET_NOT_REACHED,
        )
        with self.assertRaises(ContractError):
            validate_b1_b2_gate_receipts(rejected_b1, b2)

    def test_candidate_pair_requires_same_frozen_inputs_and_independent_evidence(self):
        b1 = _candidate()
        b2 = _candidate(GateRole.B2)
        validate_b1_b2_gate_receipts(b1, b2)

        for changed in (
            dataclasses.replace(b2, attempt_id="attempt-2"),
            dataclasses.replace(
                b2,
                submission=_ref(ContractRefKind.CASE_SUBMISSION, "other"),
            ),
            dataclasses.replace(b2, binding=b1.binding),
            dataclasses.replace(
                b2,
                binding=dataclasses.replace(
                    b1.binding,
                    content_sha256=_digest("conflicting-binding-content"),
                ),
            ),
            dataclasses.replace(b2, observations=b1.observations),
            dataclasses.replace(
                b2,
                observations=(
                    dataclasses.replace(
                        b1.observations[0],
                        content_sha256=_digest("conflicting-observation-content"),
                    ),
                ),
            ),
            dataclasses.replace(b2, decisions=b1.decisions),
            dataclasses.replace(
                b2,
                decisions=(
                    dataclasses.replace(
                        b1.decisions[0],
                        content_sha256=_digest("conflicting-decision-content"),
                    ),
                ),
            ),
        ):
            with self.subTest(changed=changed):
                with self.assertRaises(ContractError):
                    validate_b1_b2_gate_receipts(b1, changed)

    def test_pair_allows_outer_failure_and_grade_mismatch_for_outcome_audit(self):
        b1 = _candidate(
            requested=ValidationGrade.L1,
            final=ValidationGrade.L1,
            status=CaseStatus.CONFIRMED_L1,
            reason=CaseReasonCode.CONFIRMED_L1,
        )
        b2_failure = _candidate(
            GateRole.B2,
            requested=ValidationGrade.L1,
            final=None,
            status=CaseStatus.INCONCLUSIVE_ORACLE,
            reason=CaseReasonCode.REPRODUCIBILITY_FAILED,
        )
        validate_b1_b2_gate_receipts(b1, b2_failure)

        b2_downgraded = _candidate(
            GateRole.B2,
            requested=ValidationGrade.L1,
            final=ValidationGrade.L0,
            status=CaseStatus.CONFIRMED_L0,
            reason=CaseReasonCode.CONFIRMED_L0,
        )
        validate_b1_b2_gate_receipts(b1, b2_downgraded)

    def test_pair_rejects_outer_without_confirmed_b1(self):
        b1 = _candidate(
            final=None,
            status=CaseStatus.NOT_CONFIRMED,
            reason=CaseReasonCode.CONSEQUENCE_NOT_REPRODUCED,
            disposition=GateAttemptDisposition.TERMINAL_OUTCOME,
        )
        with self.assertRaises(ContractError):
            validate_b1_b2_gate_receipts(b1, _candidate(GateRole.B2))

    def test_fast_pair_requires_identical_authority_inputs(self):
        b1 = _fast()
        b2 = _fast(GateRole.B2)
        validate_b1_b2_gate_receipts(b1, b2)

        with self.assertRaises(ContractError):
            validate_b1_b2_gate_receipts(
                b1,
                dataclasses.replace(b2, context_sha256=_digest("other-context")),
            )
        with self.assertRaises(ContractError):
            validate_b1_b2_gate_receipts(
                b1,
                dataclasses.replace(b2, snapshot_sha256=_digest("other-snapshot")),
            )
        with self.assertRaises(ContractError):
            validate_b1_b2_gate_receipts(b1, _candidate(GateRole.B2))


if __name__ == "__main__":
    unittest.main()

import copy
import dataclasses
import hashlib
import json
import unittest

from src.validation_core.contracts.base import ContractError
from src.validation_core.contracts.case import (
    CaseSubmissionKind,
    compute_validation_instance_id,
)
from src.validation_core.contracts.outcome import (
    B1TerminalOutcome,
    B2RecheckFailedOutcome,
    CertificateV2,
    ConfirmedOutcome,
    CrossGateDecision,
    CrossGateFailedOutcome,
    CrossGateVerdict,
    ExplicitNotConfirmedOutcome,
    OutcomeKind,
    validate_certificate_publication,
    validate_cross_gate_decision,
    validate_outcome_publication,
    validation_outcome_from_document,
    validation_outcome_from_json,
)
from src.validation_core.contracts.plan import ExperimentPhase, GateRole
from src.validation_core.contracts.receipt import (
    CandidateGateReceipt,
    EarlyGateReceipt,
    EarlyGateStage,
    FastPathCheck,
    FastPathGateReceipt,
    GatePhaseResult,
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


def _digest(value):
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _ref(kind, name):
    return ContractRef(
        kind=kind,
        contract_id=f"example.{name}",
        contract_version="1.0.0",
        content_sha256=_digest(f"{kind.value}:{name}"),
    )


_PROFILE = _ref(ContractRefKind.FROZEN_PROFILE, "profile")
_CASE_PLAN = _ref(ContractRefKind.CASE_PLAN, "case-plan")
_TEMPLATE = _ref(ContractRefKind.EXPERIMENT_PLAN_TEMPLATE, "template")
_SUBMISSION = _ref(ContractRefKind.CASE_SUBMISSION, "submission")
_PROJECT_ID = "project"
_CASE_ID = "bug-123"
_FUNCTION_ID = "module:target"
_SNAPSHOT_SHA256 = _digest("source-snapshot")
_REASONING_SHA256 = _digest("reasoning")
_CONTEXT_SHA256 = _digest("context")
_INSTANCE = compute_validation_instance_id(
    project_id=_PROJECT_ID,
    case_id=_CASE_ID,
    function_id=_FUNCTION_ID,
    snapshot_sha256=_SNAPSHOT_SHA256,
    reasoning_sha256=_REASONING_SHA256,
    profile_sha256=_PROFILE.content_sha256,
)


def _candidate_receipt(
    role,
    *,
    attempt_id="attempt-2",
    disposition=None,
    status=CaseStatus.CONFIRMED_L0,
    reason=CaseReasonCode.CONFIRMED_L0,
    requested_grade=ValidationGrade.L0,
    final_grade=ValidationGrade.L0,
    submission=_SUBMISSION,
    profile=_PROFILE,
    case_plan=_CASE_PLAN,
    template=_TEMPLATE,
    binding=None,
    observations=None,
    decisions=None,
):
    if disposition is None and role is GateRole.B1:
        disposition = GateAttemptDisposition.ACCEPTED_CONFIRMED_CANDIDATE
    return CandidateGateReceipt(
        validation_instance_id=_INSTANCE,
        attempt_id=attempt_id,
        role=role,
        submission=submission,
        profile=profile,
        case_plan=case_plan,
        template=template,
        binding=binding
        or _ref(ContractRefKind.EXECUTION_BINDING, f"binding.{role.value}"),
        requested_grade=requested_grade,
        final_grade=final_grade,
        original_l1_candidate_sha256=(
            _digest("original-l1")
            if requested_grade is ValidationGrade.L1
            else None
        ),
        patch_sha256=(
            _digest("patch") if requested_grade is ValidationGrade.L1 else None
        ),
        observations=observations
        or (_ref(ContractRefKind.OBSERVATION, f"observation.{role.value}"),),
        decisions=decisions
        or (_ref(ContractRefKind.ORACLE_DECISION, f"decision.{role.value}"),),
        phase_results=(
            GatePhaseResult(
                phase=ExperimentPhase.ORACLE_EXPERIMENT,
                status=GatePhaseStatus.SATISFIED,
                reason_codes=(),
            ),
        ),
        disposition=disposition,
        result_status=status,
        result_reason_code=reason,
    )


def _retry_receipt(attempt_id="attempt-1"):
    return _candidate_receipt(
        GateRole.B1,
        attempt_id=attempt_id,
        disposition=GateAttemptDisposition.RETRYABLE_REJECTION,
        status=CaseStatus.NOT_CONFIRMED,
        reason=CaseReasonCode.TARGET_NOT_REACHED,
        final_grade=None,
    )


def _terminal_receipt(
    *,
    attempt_id="attempt-2",
    status=CaseStatus.INCONCLUSIVE_INFRA,
    reason=CaseReasonCode.TOOL_UNAVAILABLE,
):
    return _candidate_receipt(
        GateRole.B1,
        attempt_id=attempt_id,
        disposition=GateAttemptDisposition.TERMINAL_OUTCOME,
        status=status,
        reason=reason,
        final_grade=None,
    )


def _b2_failure_receipt(
    *,
    status=CaseStatus.NOT_CONFIRMED,
    reason=CaseReasonCode.CONSEQUENCE_NOT_REPRODUCED,
    final_grade=None,
):
    return _candidate_receipt(
        GateRole.B2,
        disposition=None,
        status=status,
        reason=reason,
        final_grade=final_grade,
    )


def _fast_receipt(
    role,
    *,
    profile_sha256=None,
    snapshot_sha256=None,
    submission=_SUBMISSION,
):
    effective_profile_sha256 = profile_sha256 or _PROFILE.content_sha256
    effective_snapshot_sha256 = snapshot_sha256 or _SNAPSHOT_SHA256
    return FastPathGateReceipt(
        validation_instance_id=compute_validation_instance_id(
            project_id=_PROJECT_ID,
            case_id=_CASE_ID,
            function_id=_FUNCTION_ID,
            snapshot_sha256=effective_snapshot_sha256,
            reasoning_sha256=_REASONING_SHA256,
            profile_sha256=effective_profile_sha256,
        ),
        attempt_id="attempt-fast",
        role=role,
        project_id=_PROJECT_ID,
        case_id=_CASE_ID,
        function_id=_FUNCTION_ID,
        submission=submission,
        reasoning_sha256=_REASONING_SHA256,
        context_sha256=_CONTEXT_SHA256,
        profile_sha256=effective_profile_sha256,
        snapshot_sha256=effective_snapshot_sha256,
        successful_checks=tuple(FastPathCheck),
        disposition=(
            GateAttemptDisposition.ACCEPTED_EXPLICIT_NOT_CONFIRMED
            if role is GateRole.B1
            else None
        ),
    )


def _early_receipt(
    role,
    *,
    attempt_id="attempt-2",
    failure_stage=EarlyGateStage.MATERIALIZE,
    disposition=None,
    status=CaseStatus.NEEDS_ORACLE_SETUP,
    reason=CaseReasonCode.NO_ELIGIBLE_BASELINE,
):
    if role is GateRole.B1 and disposition is None:
        disposition = GateAttemptDisposition.TERMINAL_OUTCOME
    intake = failure_stage is EarlyGateStage.INTAKE
    return EarlyGateReceipt(
        validation_instance_id=_INSTANCE,
        attempt_id=attempt_id,
        role=role,
        failure_stage=failure_stage,
        project_id=_PROJECT_ID,
        case_id=_CASE_ID,
        function_id=_FUNCTION_ID,
        snapshot_sha256=_SNAPSHOT_SHA256,
        reasoning_sha256=_REASONING_SHA256,
        profile_sha256=_PROFILE.content_sha256,
        context_sha256=_CONTEXT_SHA256,
        raw_submission=ArtifactRef(
            role="raw_submission",
            media_type="application/json",
            size_bytes=128,
            content_sha256=_digest("raw-submission"),
        ),
        parsed_submission_kind=(
            None if intake else CaseSubmissionKind.CANDIDATE
        ),
        parsed_submission=None if intake else _SUBMISSION,
        parsed_profile=None if intake else _PROFILE,
        parsed_case_plan=None if intake else _CASE_PLAN,
        disposition=disposition,
        result_status=status,
        result_reason_code=reason,
    )


def _cross_gate_decision(
    b1,
    b2,
    *,
    verdict=CrossGateVerdict.REPRODUCIBLE,
    comparison_salt="default",
):
    return CrossGateDecision(
        validation_instance_id=_INSTANCE,
        b1_receipt=b1.ref,
        b2_receipt=b2.ref,
        b1_decisions=b1.decisions,
        b2_decisions=b2.decisions,
        comparison=ArtifactRef(
            role="cross_gate_comparison",
            media_type="application/json",
            size_bytes=32,
            content_sha256=_digest(f"cross-gate-comparison:{comparison_salt}"),
        ),
        verdict=verdict,
    )


def _certificate(
    b1,
    b2,
    *,
    grade=ValidationGrade.L0,
    profile=_PROFILE,
    cross_gate_decision=None,
):
    cross_gate_decision = cross_gate_decision or _cross_gate_decision(b1, b2)
    return CertificateV2(
        validation_instance_id=_INSTANCE,
        profile=profile,
        case_plan=_CASE_PLAN,
        template=_TEMPLATE,
        b1_receipt=b1.ref,
        b2_receipt=b2.ref,
        cross_gate_decision=cross_gate_decision.ref,
        final_grade=grade,
    )


class CrossGateDecisionContractTests(unittest.TestCase):
    def test_round_trip_is_strict_content_addressed_evidence_envelope(self):
        b1 = _candidate_receipt(GateRole.B1)
        b2 = _candidate_receipt(GateRole.B2)
        decision = _cross_gate_decision(b1, b2)
        document = decision.to_document()

        self.assertEqual(CrossGateDecision.from_document(document), decision)
        self.assertEqual(
            CrossGateDecision.from_json(json.dumps(document).encode("utf-8")),
            decision,
        )
        self.assertEqual(
            decision.ref.kind,
            ContractRefKind.CROSS_GATE_DECISION,
        )
        self.assertEqual(decision.ref.contract_id, decision.content_sha256)
        self.assertEqual(decision.verdict, CrossGateVerdict.REPRODUCIBLE)

        with self.assertRaises(ContractError):
            CrossGateDecision.from_document({**document, "agent_claim": True})
        with self.assertRaises(ContractError):
            CrossGateDecision.from_document({**document, "verdict": "PASS"})
        with self.assertRaises(ContractError):
            dataclasses.replace(
                decision,
                comparison=dataclasses.replace(
                    decision.comparison,
                    role="oracle_decision",
                ),
            )

        changed = dataclasses.replace(
            decision,
            comparison=dataclasses.replace(
                decision.comparison,
                content_sha256=_digest("changed-cross-gate-comparison"),
            ),
        )
        self.assertNotEqual(changed.content_sha256, decision.content_sha256)

    def test_evidence_closure_exactly_binds_confirmed_receipts_and_decisions(self):
        b1 = _candidate_receipt(GateRole.B1)
        b2 = _candidate_receipt(GateRole.B2)
        decision = _cross_gate_decision(b1, b2)

        validate_cross_gate_decision(decision, b1, b2)

        for changed in (
            dataclasses.replace(
                decision,
                b1_receipt=_ref(ContractRefKind.GATE_RECEIPT, "other-b1"),
            ),
            dataclasses.replace(
                decision,
                b2_decisions=(
                    _ref(ContractRefKind.ORACLE_DECISION, "other-b2-decision"),
                ),
            ),
        ):
            with self.subTest(changed=changed), self.assertRaises(ContractError):
                validate_cross_gate_decision(changed, b1, b2)

        b2_failure = _b2_failure_receipt()
        with self.assertRaises(ContractError):
            validate_cross_gate_decision(
                _cross_gate_decision(b1, b2_failure),
                b1,
                b2_failure,
            )

    def test_reproducible_verdict_cannot_hide_grade_mismatch(self):
        b1 = _candidate_receipt(
            GateRole.B1,
            requested_grade=ValidationGrade.L1,
            final_grade=ValidationGrade.L0,
            status=CaseStatus.CONFIRMED_L0,
            reason=CaseReasonCode.CONFIRMED_L0,
        )
        b2 = _candidate_receipt(
            GateRole.B2,
            requested_grade=ValidationGrade.L1,
            final_grade=ValidationGrade.L1,
            status=CaseStatus.CONFIRMED_L1,
            reason=CaseReasonCode.CONFIRMED_L1,
        )
        with self.assertRaises(ContractError):
            validate_cross_gate_decision(
                _cross_gate_decision(b1, b2),
                b1,
                b2,
            )

        failed = _cross_gate_decision(
            b1,
            b2,
            verdict=CrossGateVerdict.REPRODUCIBILITY_FAILED,
        )
        validate_cross_gate_decision(failed, b1, b2)

    def test_reproducible_binds_unequal_non_proof_relevant_repair_history(self):
        b1 = _candidate_receipt(
            GateRole.B1,
            requested_grade=ValidationGrade.L1,
            final_grade=ValidationGrade.L0,
            status=CaseStatus.CONFIRMED_L0,
            reason=CaseReasonCode.CONFIRMED_L0,
        )
        b2 = _candidate_receipt(
            GateRole.B2,
            requested_grade=ValidationGrade.L1,
            final_grade=ValidationGrade.L0,
            status=CaseStatus.CONFIRMED_L0,
            reason=CaseReasonCode.CONFIRMED_L0,
            observations=(
                _ref(ContractRefKind.OBSERVATION, "b2.original"),
                _ref(ContractRefKind.OBSERVATION, "b2.partial-repair"),
            ),
            decisions=(
                _ref(ContractRefKind.ORACLE_DECISION, "b2.original"),
                _ref(ContractRefKind.ORACLE_DECISION, "b2.partial-repair"),
            ),
        )
        decision = _cross_gate_decision(b1, b2)

        validate_cross_gate_decision(decision, b1, b2)
        self.assertNotEqual(len(decision.b1_decisions), len(decision.b2_decisions))


class OutcomeShapeTests(unittest.TestCase):
    def test_explicit_not_confirmed_cannot_use_b1_terminal_topology(self):
        with self.assertRaisesRegex(ContractError, "fast-path topology"):
            B1TerminalOutcome(
                _INSTANCE,
                CaseStatus.NOT_CONFIRMED,
                CaseReasonCode.EXPLICIT_NOT_CONFIRMED,
                (_ref(ContractRefKind.GATE_RECEIPT, "candidate-terminal"),),
            )

    def test_conflicting_hashes_cannot_share_one_receipt_identity(self):
        first = _ref(ContractRefKind.GATE_RECEIPT, "same-receipt")
        conflicting = dataclasses.replace(
            first,
            content_sha256=_digest("conflicting-receipt-content"),
        )
        with self.assertRaises(ContractError):
            B1TerminalOutcome(
                _INSTANCE,
                CaseStatus.NOT_CONFIRMED,
                CaseReasonCode.TARGET_NOT_REACHED,
                (first, conflicting),
            )
        with self.assertRaises(ContractError):
            ExplicitNotConfirmedOutcome(
                _INSTANCE,
                CaseStatus.NOT_CONFIRMED,
                CaseReasonCode.EXPLICIT_NOT_CONFIRMED,
                (),
                first,
                conflicting,
            )

    def test_all_five_discriminated_branches_round_trip_and_hash(self):
        b1_fast = _fast_receipt(GateRole.B1)
        b2_fast = _fast_receipt(GateRole.B2)
        retry = _retry_receipt()
        terminal = _terminal_receipt()
        accepted = _candidate_receipt(GateRole.B1)
        b2_failed = _b2_failure_receipt()
        b2_confirmed = _candidate_receipt(GateRole.B2)
        reproducible = _cross_gate_decision(accepted, b2_confirmed)
        cross_failed = _cross_gate_decision(
            accepted,
            b2_confirmed,
            verdict=CrossGateVerdict.REPRODUCIBILITY_FAILED,
            comparison_salt="failed",
        )
        certificate = _certificate(
            accepted,
            b2_confirmed,
            cross_gate_decision=reproducible,
        )
        outcomes = (
            ExplicitNotConfirmedOutcome(
                validation_instance_id=_INSTANCE,
                status=CaseStatus.NOT_CONFIRMED,
                reason_code=CaseReasonCode.EXPLICIT_NOT_CONFIRMED,
                prior_b1_attempt_receipts=(),
                b1_fast_receipt=b1_fast.ref,
                b2_fast_receipt=b2_fast.ref,
            ),
            B1TerminalOutcome(
                validation_instance_id=_INSTANCE,
                status=CaseStatus.INCONCLUSIVE_INFRA,
                reason_code=CaseReasonCode.TOOL_UNAVAILABLE,
                b1_attempt_receipts=(retry.ref, terminal.ref),
            ),
            B2RecheckFailedOutcome(
                validation_instance_id=_INSTANCE,
                status=CaseStatus.INCONCLUSIVE_ORACLE,
                reason_code=CaseReasonCode.REPRODUCIBILITY_FAILED,
                b1_attempt_receipts=(accepted.ref,),
                b2_receipt=b2_failed.ref,
            ),
            CrossGateFailedOutcome(
                validation_instance_id=_INSTANCE,
                status=CaseStatus.INCONCLUSIVE_ORACLE,
                reason_code=CaseReasonCode.REPRODUCIBILITY_FAILED,
                b1_attempt_receipts=(accepted.ref,),
                b2_receipt=b2_confirmed.ref,
                cross_gate_decision=cross_failed.ref,
            ),
            ConfirmedOutcome(
                validation_instance_id=_INSTANCE,
                status=CaseStatus.CONFIRMED_L0,
                reason_code=CaseReasonCode.CONFIRMED_L0,
                b1_attempt_receipts=(accepted.ref,),
                b2_receipt=b2_confirmed.ref,
                certificate=certificate.ref,
            ),
        )

        for outcome in outcomes:
            with self.subTest(kind=outcome.outcome_kind):
                document = outcome.to_document()
                parsed = validation_outcome_from_document(document)
                self.assertEqual(parsed, outcome)
                self.assertEqual(parsed.content_sha256, outcome.content_sha256)
                self.assertEqual(
                    validation_outcome_from_json(
                        json.dumps(document).encode("utf-8")
                    ),
                    outcome,
                )
                self.assertEqual(outcome.ref.kind, ContractRefKind.VALIDATION_OUTCOME)

    def test_branch_documents_have_exact_non_optional_topology(self):
        b1 = _fast_receipt(GateRole.B1)
        b2 = _fast_receipt(GateRole.B2)
        explicit = ExplicitNotConfirmedOutcome(
            _INSTANCE,
            CaseStatus.NOT_CONFIRMED,
            CaseReasonCode.EXPLICIT_NOT_CONFIRMED,
            (),
            b1.ref,
            b2.ref,
        )
        document = explicit.to_document()
        self.assertEqual(document["outcome_kind"], "explicit_not_confirmed")
        self.assertNotIn("certificate", document)
        self.assertNotIn("template", document)
        self.assertNotIn("b1_attempt_receipts", document)
        self.assertEqual(document["prior_b1_attempt_receipts"], [])

        with self.assertRaises(ContractError):
            validation_outcome_from_document({**document, "certificate": _ref(
                ContractRefKind.CERTIFICATE, "forbidden"
            ).to_document()})
        with self.assertRaises(ContractError):
            validation_outcome_from_document({**document, "outcome_kind": "future"})

    def test_status_reason_and_topology_are_closed(self):
        receipt = _ref(ContractRefKind.GATE_RECEIPT, "one")
        other = _ref(ContractRefKind.GATE_RECEIPT, "two")
        with self.assertRaises(ContractError):
            ExplicitNotConfirmedOutcome(
                _INSTANCE,
                CaseStatus.NOT_CONFIRMED,
                CaseReasonCode.CONSEQUENCE_NOT_REPRODUCED,
                (),
                receipt,
                other,
            )
        with self.assertRaises(ContractError):
            B1TerminalOutcome(
                _INSTANCE,
                CaseStatus.CONFIRMED_L0,
                CaseReasonCode.CONFIRMED_L0,
                (receipt,),
            )
        for status, reason in (
            (CaseStatus.NOT_CONFIRMED, CaseReasonCode.TARGET_NOT_REACHED),
            (
                CaseStatus.NEEDS_ORACLE_SETUP,
                CaseReasonCode.NO_APPLICABLE_PROFILE_CAPABILITY,
            ),
        ):
            with self.subTest(status=status):
                with self.assertRaises(ContractError):
                    B2RecheckFailedOutcome(
                        _INSTANCE,
                        status,
                        reason,
                        (receipt,),
                        other,
                    )

        cross_ref = _ref(
            ContractRefKind.CROSS_GATE_DECISION,
            "cross-gate-failed",
        )
        with self.assertRaises(ContractError):
            CrossGateFailedOutcome(
                _INSTANCE,
                CaseStatus.NOT_CONFIRMED,
                CaseReasonCode.CONSEQUENCE_NOT_REPRODUCED,
                (receipt,),
                other,
                cross_ref,
            )

        cross_failed = CrossGateFailedOutcome(
            _INSTANCE,
            CaseStatus.INCONCLUSIVE_ORACLE,
            CaseReasonCode.REPRODUCIBILITY_FAILED,
            (receipt,),
            other,
            cross_ref,
        )
        self.assertNotIn("certificate", cross_failed.to_document())
        self.assertEqual(
            validation_outcome_from_document(cross_failed.to_document()),
            cross_failed,
        )

    def test_strict_json_rejects_duplicate_keys_and_float(self):
        with self.assertRaises(ContractError):
            validation_outcome_from_json(
                b'{"outcome_kind":"confirmed","outcome_kind":"confirmed"}'
            )
        with self.assertRaises(ContractError):
            validation_outcome_from_json(
                b'{"outcome_kind":"confirmed","schema_version":1.0}'
            )


class CertificateContractTests(unittest.TestCase):
    def test_certificate_rejects_conflicting_receipt_identity_hashes(self):
        first = _ref(ContractRefKind.GATE_RECEIPT, "same-certificate-receipt")
        conflicting = dataclasses.replace(
            first,
            content_sha256=_digest("conflicting-certificate-receipt"),
        )
        with self.assertRaises(ContractError):
            CertificateV2(
                _INSTANCE,
                _PROFILE,
                _CASE_PLAN,
                _TEMPLATE,
                first,
                conflicting,
                _ref(ContractRefKind.CROSS_GATE_DECISION, "cross-gate"),
                ValidationGrade.L0,
            )

    def test_certificate_v2_round_trip_is_acyclic_and_content_addressed(self):
        b1 = _candidate_receipt(GateRole.B1)
        b2 = _candidate_receipt(GateRole.B2)
        cross_gate = _cross_gate_decision(b1, b2)
        certificate = _certificate(
            b1,
            b2,
            cross_gate_decision=cross_gate,
        )
        document = certificate.to_document()

        self.assertEqual(document["schema_version"], 2)
        self.assertNotIn("outcome", document)
        self.assertNotIn("validation_outcome", document)
        self.assertEqual(
            document["cross_gate_decision"],
            cross_gate.ref.to_document(),
        )
        self.assertEqual(CertificateV2.from_document(document), certificate)
        self.assertEqual(
            CertificateV2.from_json(json.dumps(document).encode("utf-8")),
            certificate,
        )
        self.assertEqual(certificate.ref.kind, ContractRefKind.CERTIFICATE)
        self.assertEqual(certificate.ref.contract_version, "2")

        changed = dataclasses.replace(certificate, final_grade=ValidationGrade.L1)
        self.assertNotEqual(changed.content_sha256, certificate.content_sha256)

    def test_certificate_parser_rejects_wrong_version_and_extra_signature(self):
        b1 = _candidate_receipt(GateRole.B1)
        b2 = _candidate_receipt(GateRole.B2)
        document = _certificate(b1, b2).to_document()
        with self.assertRaises(ContractError):
            CertificateV2.from_document({**document, "schema_version": 1})
        with self.assertRaises(ContractError):
            CertificateV2.from_document({**document, "signature": "not-yet"})
        missing_cross_gate = copy.deepcopy(document)
        missing_cross_gate.pop("cross_gate_decision")
        with self.assertRaises(ContractError):
            CertificateV2.from_document(missing_cross_gate)

    def test_certificate_requires_full_confirmed_pair_and_matching_grade(self):
        b1 = _candidate_receipt(GateRole.B1)
        b2 = _candidate_receipt(GateRole.B2)
        cross_gate = _cross_gate_decision(b1, b2)
        certificate = _certificate(
            b1,
            b2,
            cross_gate_decision=cross_gate,
        )
        validate_certificate_publication(certificate, b1, b2, cross_gate)

        downgraded_b1 = _candidate_receipt(
            GateRole.B1,
            requested_grade=ValidationGrade.L1,
            final_grade=ValidationGrade.L0,
            status=CaseStatus.CONFIRMED_L0,
            reason=CaseReasonCode.CONFIRMED_L0,
        )
        l1_b2 = _candidate_receipt(
            GateRole.B2,
            requested_grade=ValidationGrade.L1,
            final_grade=ValidationGrade.L1,
            status=CaseStatus.CONFIRMED_L1,
            reason=CaseReasonCode.CONFIRMED_L1,
        )
        mismatch_cross_gate = _cross_gate_decision(
            downgraded_b1,
            l1_b2,
            verdict=CrossGateVerdict.REPRODUCIBILITY_FAILED,
        )
        with self.assertRaises(ContractError):
            validate_certificate_publication(
                _certificate(
                    downgraded_b1,
                    l1_b2,
                    cross_gate_decision=mismatch_cross_gate,
                ),
                downgraded_b1,
                l1_b2,
                mismatch_cross_gate,
            )

        with self.assertRaises(ContractError):
            validate_certificate_publication(
                dataclasses.replace(certificate, profile=_ref(
                    ContractRefKind.FROZEN_PROFILE, "other-profile"
                )),
                b1,
                b2,
                cross_gate,
            )
        with self.assertRaises(ContractError):
            validate_certificate_publication(
                certificate,
                _fast_receipt(GateRole.B1),
                b2,
                cross_gate,
            )

        failed_cross_gate = dataclasses.replace(
            cross_gate,
            verdict=CrossGateVerdict.REPRODUCIBILITY_FAILED,
        )
        failed_certificate = dataclasses.replace(
            certificate,
            cross_gate_decision=failed_cross_gate.ref,
        )
        with self.assertRaisesRegex(ContractError, "REPRODUCIBLE"):
            validate_certificate_publication(
                failed_certificate,
                b1,
                b2,
                failed_cross_gate,
            )

    def test_certificate_rejects_reused_binding_and_observation_provenance(self):
        b1 = _candidate_receipt(GateRole.B1)
        b2 = _candidate_receipt(GateRole.B2, binding=b1.binding)
        cross_gate = _cross_gate_decision(b1, b2)
        with self.assertRaises(ContractError):
            validate_certificate_publication(
                _certificate(b1, b2, cross_gate_decision=cross_gate),
                b1,
                b2,
                cross_gate,
            )

        b2 = _candidate_receipt(GateRole.B2, observations=b1.observations)
        cross_gate = _cross_gate_decision(b1, b2)
        with self.assertRaises(ContractError):
            validate_certificate_publication(
                _certificate(b1, b2, cross_gate_decision=cross_gate),
                b1,
                b2,
                cross_gate,
            )


class OutcomePublicationTests(unittest.TestCase):
    def test_explicit_not_confirmed_preserves_prior_b1_attempt_history(self):
        retry = _retry_receipt()
        b1 = _fast_receipt(GateRole.B1)
        b2 = _fast_receipt(GateRole.B2)
        outcome = ExplicitNotConfirmedOutcome(
            _INSTANCE,
            CaseStatus.NOT_CONFIRMED,
            CaseReasonCode.EXPLICIT_NOT_CONFIRMED,
            (retry.ref,),
            b1.ref,
            b2.ref,
        )
        validate_outcome_publication(outcome, receipts=(retry, b1, b2))

        with self.assertRaises(ContractError):
            validate_outcome_publication(outcome, receipts=(b1, b2))
        with self.assertRaises(ContractError):
            validate_outcome_publication(
                outcome,
                receipts=(retry, b1, b2),
                certificate=_certificate(
                    _candidate_receipt(GateRole.B1),
                    _candidate_receipt(GateRole.B2),
                ),
            )
        candidate_b1 = _candidate_receipt(GateRole.B1)
        candidate_b2 = _candidate_receipt(GateRole.B2)
        with self.assertRaises(ContractError):
            validate_outcome_publication(
                outcome,
                receipts=(retry, b1, b2),
                cross_gate_decision=_cross_gate_decision(
                    candidate_b1,
                    candidate_b2,
                ),
            )
        mismatched_b2 = _fast_receipt(
            GateRole.B2,
            snapshot_sha256=_digest("different-snapshot"),
        )
        mismatched = dataclasses.replace(outcome, b2_fast_receipt=mismatched_b2.ref)
        with self.assertRaises(ContractError):
            validate_outcome_publication(
                mismatched,
                receipts=(retry, b1, mismatched_b2),
            )

        repeated_attempt = _retry_receipt(attempt_id=b1.attempt_id)
        repeated_history = dataclasses.replace(
            outcome,
            prior_b1_attempt_receipts=(repeated_attempt.ref,),
        )
        with self.assertRaises(ContractError):
            validate_outcome_publication(
                repeated_history,
                receipts=(repeated_attempt, b1, b2),
            )

    def test_b1_terminal_has_only_b1_attempt_history(self):
        retry = _retry_receipt()
        terminal = _terminal_receipt()
        outcome = B1TerminalOutcome(
            _INSTANCE,
            CaseStatus.INCONCLUSIVE_INFRA,
            CaseReasonCode.TOOL_UNAVAILABLE,
            (retry.ref, terminal.ref),
        )
        validate_outcome_publication(outcome, receipts=(retry, terminal))

        with self.assertRaises(ContractError):
            validate_outcome_publication(
                outcome,
                receipts=(retry, terminal, _candidate_receipt(GateRole.B2)),
            )
        wrong_order = dataclasses.replace(
            outcome,
            b1_attempt_receipts=(terminal.ref, retry.ref),
        )
        with self.assertRaises(ContractError):
            validate_outcome_publication(wrong_order, receipts=(terminal, retry))

    def test_b1_terminal_history_accepts_honest_pre_execution_failures(self):
        retry = _early_receipt(
            GateRole.B1,
            attempt_id="attempt-early-retry",
            failure_stage=EarlyGateStage.INTAKE,
            disposition=GateAttemptDisposition.RETRYABLE_REJECTION,
            status=CaseStatus.INVALID_SUBMISSION,
            reason=CaseReasonCode.SCHEMA_INVALID,
        )
        terminal = _early_receipt(
            GateRole.B1,
            attempt_id="attempt-early-terminal",
        )
        outcome = B1TerminalOutcome(
            _INSTANCE,
            CaseStatus.NEEDS_ORACLE_SETUP,
            CaseReasonCode.NO_ELIGIBLE_BASELINE,
            (retry.ref, terminal.ref),
        )

        validate_outcome_publication(outcome, receipts=(retry, terminal))

        with self.assertRaises(ContractError):
            validate_outcome_publication(
                dataclasses.replace(
                    outcome,
                    status=CaseStatus.INVALID_SUBMISSION,
                    reason_code=CaseReasonCode.SCHEMA_INVALID,
                ),
                receipts=(retry, terminal),
            )

    def test_b2_pass_after_b1_confirmation_maps_to_reproducibility_failure(self):
        b1 = _candidate_receipt(GateRole.B1)
        for b2 in (
            _b2_failure_receipt(),
            _b2_failure_receipt(
                status=CaseStatus.NEEDS_ORACLE_SETUP,
                reason=CaseReasonCode.NO_APPLICABLE_PROFILE_CAPABILITY,
            ),
            _b2_failure_receipt(
                status=CaseStatus.INCONCLUSIVE_ORACLE,
                reason=CaseReasonCode.DOMAIN_MISMATCH,
            ),
        ):
            with self.subTest(b2_status=b2.result_status):
                outcome = B2RecheckFailedOutcome(
                    _INSTANCE,
                    CaseStatus.INCONCLUSIVE_ORACLE,
                    CaseReasonCode.REPRODUCIBILITY_FAILED,
                    (b1.ref,),
                    b2.ref,
                )
                validate_outcome_publication(outcome, receipts=(b1, b2))

                invalid_outcome = dataclasses.replace(
                    outcome,
                    reason_code=CaseReasonCode.QUORUM_NOT_MET,
                )
                with self.assertRaises(ContractError):
                    validate_outcome_publication(
                        invalid_outcome,
                        receipts=(b1, b2),
                    )

    def test_b2_explicit_infra_failure_is_preserved(self):
        b1 = _candidate_receipt(GateRole.B1)
        b2 = _b2_failure_receipt(
            status=CaseStatus.INCONCLUSIVE_INFRA,
            reason=CaseReasonCode.DEVICE_UNAVAILABLE,
        )
        outcome = B2RecheckFailedOutcome(
            _INSTANCE,
            CaseStatus.INCONCLUSIVE_INFRA,
            CaseReasonCode.DEVICE_UNAVAILABLE,
            (b1.ref,),
            b2.ref,
        )
        validate_outcome_publication(outcome, receipts=(b1, b2))

    def test_b2_pre_execution_failure_is_published_without_fake_execution(self):
        b1 = _candidate_receipt(GateRole.B1)
        b2 = _early_receipt(GateRole.B2)
        outcome = B2RecheckFailedOutcome(
            _INSTANCE,
            CaseStatus.INCONCLUSIVE_ORACLE,
            CaseReasonCode.REPRODUCIBILITY_FAILED,
            (b1.ref,),
            b2.ref,
        )

        validate_outcome_publication(outcome, receipts=(b1, b2))

        infra_b2 = _early_receipt(
            GateRole.B2,
            status=CaseStatus.INCONCLUSIVE_INFRA,
            reason=CaseReasonCode.DEVICE_UNAVAILABLE,
        )
        infra_outcome = dataclasses.replace(
            outcome,
            status=CaseStatus.INCONCLUSIVE_INFRA,
            reason_code=CaseReasonCode.DEVICE_UNAVAILABLE,
            b2_receipt=infra_b2.ref,
        )
        validate_outcome_publication(infra_outcome, receipts=(b1, infra_b2))

    def test_b2_failure_topology_cannot_hide_matching_confirmation(self):
        b1 = _candidate_receipt(GateRole.B1)
        b2 = _candidate_receipt(GateRole.B2)
        outcome = B2RecheckFailedOutcome(
            _INSTANCE,
            CaseStatus.INCONCLUSIVE_ORACLE,
            CaseReasonCode.REPRODUCIBILITY_FAILED,
            (b1.ref,),
            b2.ref,
        )
        with self.assertRaises(ContractError):
            validate_outcome_publication(outcome, receipts=(b1, b2))

    def test_grade_mismatch_uses_strict_cross_gate_failed_topology(self):
        b1 = _candidate_receipt(
            GateRole.B1,
            requested_grade=ValidationGrade.L1,
            final_grade=ValidationGrade.L0,
            status=CaseStatus.CONFIRMED_L0,
            reason=CaseReasonCode.CONFIRMED_L0,
        )
        b2 = _candidate_receipt(
            GateRole.B2,
            requested_grade=ValidationGrade.L1,
            final_grade=ValidationGrade.L1,
            status=CaseStatus.CONFIRMED_L1,
            reason=CaseReasonCode.CONFIRMED_L1,
        )
        cross_gate = _cross_gate_decision(
            b1,
            b2,
            verdict=CrossGateVerdict.REPRODUCIBILITY_FAILED,
        )
        outcome = CrossGateFailedOutcome(
            _INSTANCE,
            CaseStatus.INCONCLUSIVE_ORACLE,
            CaseReasonCode.REPRODUCIBILITY_FAILED,
            (b1.ref,),
            b2.ref,
            cross_gate.ref,
        )
        validate_outcome_publication(
            outcome,
            receipts=(b1, b2),
            cross_gate_decision=cross_gate,
        )
        with self.assertRaises(ContractError):
            validate_outcome_publication(
                B2RecheckFailedOutcome(
                    _INSTANCE,
                    CaseStatus.INCONCLUSIVE_ORACLE,
                    CaseReasonCode.REPRODUCIBILITY_FAILED,
                    (b1.ref,),
                    b2.ref,
                ),
                receipts=(b1, b2),
            )
        with self.assertRaises(ContractError):
            validate_outcome_publication(
                outcome,
                receipts=(b1, b2),
                cross_gate_decision=cross_gate,
                certificate=_certificate(
                    b1,
                    b2,
                    cross_gate_decision=dataclasses.replace(
                        cross_gate,
                        verdict=CrossGateVerdict.REPRODUCIBLE,
                    ),
                ),
            )
        with self.assertRaises(ContractError):
            validate_certificate_publication(
                _certificate(b1, b2, cross_gate_decision=cross_gate),
                b1,
                b2,
                cross_gate,
            )

        with self.assertRaises(ContractError):
            validate_outcome_publication(outcome, receipts=(b1, b2))
        with self.assertRaises(ContractError):
            validate_outcome_publication(
                outcome,
                receipts=(b1, b2),
                cross_gate_decision=dataclasses.replace(
                    cross_gate,
                    verdict=CrossGateVerdict.REPRODUCIBLE,
                ),
            )

    def test_confirmed_requires_exact_pair_and_certificate(self):
        retry = _retry_receipt()
        b1 = _candidate_receipt(GateRole.B1)
        b2 = _candidate_receipt(GateRole.B2)
        cross_gate = _cross_gate_decision(b1, b2)
        certificate = _certificate(
            b1,
            b2,
            cross_gate_decision=cross_gate,
        )
        outcome = ConfirmedOutcome(
            _INSTANCE,
            CaseStatus.CONFIRMED_L0,
            CaseReasonCode.CONFIRMED_L0,
            (retry.ref, b1.ref),
            b2.ref,
            certificate.ref,
        )
        validate_outcome_publication(
            outcome,
            receipts=(retry, b1, b2),
            certificate=certificate,
            cross_gate_decision=cross_gate,
        )

        with self.assertRaises(ContractError):
            validate_outcome_publication(
                outcome,
                receipts=(retry, b1, b2),
                cross_gate_decision=cross_gate,
            )
        with self.assertRaises(ContractError):
            validate_outcome_publication(
                outcome,
                receipts=(b1, b2),
                certificate=certificate,
                cross_gate_decision=cross_gate,
            )
        with self.assertRaises(ContractError):
            validate_outcome_publication(
                outcome,
                receipts=(retry, b1, b2),
                certificate=certificate,
            )
        with self.assertRaises(ContractError):
            validate_outcome_publication(
                outcome,
                receipts=(retry, b1, b2),
                certificate="not-a-certificate",
                cross_gate_decision=cross_gate,
            )
        with self.assertRaises(ContractError):
            validate_outcome_publication(
                outcome,
                receipts=(retry, b1, b2),
                certificate=certificate,
                cross_gate_decision="not-a-cross-gate-decision",
            )

        failed_cross_gate = dataclasses.replace(
            cross_gate,
            verdict=CrossGateVerdict.REPRODUCIBILITY_FAILED,
        )
        failed_certificate = dataclasses.replace(
            certificate,
            cross_gate_decision=failed_cross_gate.ref,
        )
        failed_claim = dataclasses.replace(
            outcome,
            certificate=failed_certificate.ref,
        )
        with self.assertRaises(ContractError):
            validate_outcome_publication(
                failed_claim,
                receipts=(retry, b1, b2),
                certificate=failed_certificate,
                cross_gate_decision=failed_cross_gate,
            )

    def test_non_certificate_terminal_origins_have_distinct_topologies(self):
        b1_fast = _fast_receipt(GateRole.B1)
        b2_fast = _fast_receipt(GateRole.B2)
        explicit = ExplicitNotConfirmedOutcome(
            _INSTANCE,
            CaseStatus.NOT_CONFIRMED,
            CaseReasonCode.EXPLICIT_NOT_CONFIRMED,
            (),
            b1_fast.ref,
            b2_fast.ref,
        )

        terminal = _terminal_receipt(
            status=CaseStatus.NOT_CONFIRMED,
            reason=CaseReasonCode.TARGET_NOT_REACHED,
        )
        b1_terminal = B1TerminalOutcome(
            _INSTANCE,
            CaseStatus.NOT_CONFIRMED,
            CaseReasonCode.TARGET_NOT_REACHED,
            (terminal.ref,),
        )

        b1 = _candidate_receipt(GateRole.B1)
        b2 = _b2_failure_receipt()
        b2_mismatch = B2RecheckFailedOutcome(
            _INSTANCE,
            CaseStatus.INCONCLUSIVE_ORACLE,
            CaseReasonCode.REPRODUCIBILITY_FAILED,
            (b1.ref,),
            b2.ref,
        )

        b2_confirmed = _candidate_receipt(GateRole.B2)
        failed_cross_gate = _cross_gate_decision(
            b1,
            b2_confirmed,
            verdict=CrossGateVerdict.REPRODUCIBILITY_FAILED,
        )
        cross_gate_failed = CrossGateFailedOutcome(
            _INSTANCE,
            CaseStatus.INCONCLUSIVE_ORACLE,
            CaseReasonCode.REPRODUCIBILITY_FAILED,
            (b1.ref,),
            b2_confirmed.ref,
            failed_cross_gate.ref,
        )

        self.assertEqual(explicit.outcome_kind, OutcomeKind.EXPLICIT_NOT_CONFIRMED)
        self.assertEqual(b1_terminal.outcome_kind, OutcomeKind.B1_TERMINAL)
        self.assertEqual(b2_mismatch.outcome_kind, OutcomeKind.B2_RECHECK_FAILED)
        self.assertEqual(
            cross_gate_failed.outcome_kind,
            OutcomeKind.CROSS_GATE_FAILED,
        )
        validate_outcome_publication(explicit, receipts=(b1_fast, b2_fast))
        validate_outcome_publication(b1_terminal, receipts=(terminal,))
        validate_outcome_publication(b2_mismatch, receipts=(b1, b2))
        validate_outcome_publication(
            cross_gate_failed,
            receipts=(b1, b2_confirmed),
            cross_gate_decision=failed_cross_gate,
        )

    def test_tampered_certificate_reference_fails_cross_object_validation(self):
        b1 = _candidate_receipt(GateRole.B1)
        b2 = _candidate_receipt(GateRole.B2)
        cross_gate = _cross_gate_decision(b1, b2)
        certificate = _certificate(
            b1,
            b2,
            cross_gate_decision=cross_gate,
        )
        document = copy.deepcopy(certificate.to_document())
        document["b1_receipt"]["content_sha256"] = _digest("tampered")
        document["b1_receipt"]["contract_id"] = _digest("tampered")
        tampered = CertificateV2.from_document(document)

        with self.assertRaises(ContractError):
            validate_certificate_publication(tampered, b1, b2, cross_gate)


if __name__ == "__main__":
    unittest.main()

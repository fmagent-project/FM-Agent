from __future__ import annotations

import dataclasses
import hashlib
import json
import unittest

from src.validation_core.contracts.base import (
    CanonicalDecimal,
    ContractError,
    canonical_json_bytes,
    canonical_sha256,
)
from src.validation_core.contracts.evidence import OracleVerdict
from src.validation_core.contracts.preset import RegistrationTrustTier
from src.validation_core.contracts.profile import EnvironmentBinding, ProjectBinding
from src.validation_core.contracts.references import (
    ArtifactRef,
    ContractRef,
    ContractRefKind,
)
from src.validation_core.contracts.setup import (
    ApprovalAuthorityKind,
    ApprovalDecision,
    CalibrationReport,
    DependencyBinding,
    DependencyInvalidationManifest,
    DependencyKind,
    FixtureVisibility,
    InvalidationAction,
    ProfileAdmissionRecord,
    ProfileGraph,
    ProfileSetupCandidate,
    QualificationMode,
    QualificationPartition,
    QualificationPartitionKind,
    QualificationPlan,
    QualificationPolicy,
    QualificationReport,
    QualificationTrial,
    QualificationUnit,
    QualificationVerdict,
    ResultBlindReviewBundle,
    ReviewRecord,
    ReviewVerdict,
    RevocationEntry,
    RevocationLedger,
    RevocationReason,
    RevocationTarget,
    RevocationTargetKind,
    SemanticApprovalRecord,
    SetupActorRole,
    SetupLifecycleRecord,
    SetupState,
    SetupStateTransition,
    StatisticalBoundMethod,
    TrustReasonCode,
    evaluate_profile_trust,
    freeze_profile,
    make_review_subject,
    validate_approval_basis,
    validate_approval_graph,
    validate_frozen_profile_graph,
    validate_invalidation_manifest_graph,
    validate_profile_admission_graph,
    validate_qualification_graph,
    validate_revocation_ledger_extension,
    validate_review_graph,
)


def _sha(label: str) -> str:
    return hashlib.sha256(label.encode("utf-8")).hexdigest()


def _ref(kind: ContractRefKind, label: str) -> ContractRef:
    return ContractRef(kind, label, "v1", _sha(label))


def _artifact(role: str, label: str | None = None) -> ArtifactRef:
    return ArtifactRef(role, "application/json", 17, _sha(label or role))


def _timestamp(second: int, hour: int = 0) -> str:
    return f"2026-01-01T{hour:02d}:00:{second:02d}Z"


class SetupFixture:
    def __init__(self) -> None:
        self.policy = QualificationPolicy(
            policy_id="policy",
            policy_version="v1",
            mode=QualificationMode.DETERMINISTIC,
            trial_unit_id="complete_decision",
            bound_method=StatisticalBoundMethod.NOT_APPLICABLE,
            confidence_level=CanonicalDecimal("1"),
            max_false_violation_rate=CanonicalDecimal("0"),
            min_detection_rate=CanonicalDecimal("1"),
            min_non_violating_groups=1,
            min_negative_groups=1,
            min_calibrated_cells=0,
            min_fault_cells=0,
            max_retries_per_trial=1,
            retryable_reasons=("broker_lease_lost",),
            qualification_ttl_seconds=43_200,
            require_ood_inconclusive=True,
        )
        self.resource = _ref(ContractRefKind.RESOURCE_POLICY, "resource")
        self.entrypoint = _ref(ContractRefKind.ENTRYPOINT, "entry")
        self.workload = _ref(ContractRefKind.WORKLOAD_SCHEMA, "workload")
        self.adapter = _ref(ContractRefKind.ADAPTER, "adapter")
        self.instrumentation = _ref(
            ContractRefKind.INSTRUMENTATION_PROVIDER, "instrumentation"
        )
        self.oracle = _ref(ContractRefKind.ORACLE_SPEC, "oracle")
        self.bundle = _ref(ContractRefKind.ORACLE_BUNDLE, "bundle")
        self.recipe = _ref(ContractRefKind.EXECUTION_RECIPE, "recipe")
        self.graph = self._graph(_sha("snapshot-1"))
        self.candidate = self._candidate(self.graph)
        self.units = {
            kind: QualificationUnit(
                _sha(f"{kind.value}-member"),
                _sha(f"{kind.value}-group"),
                _sha(f"{kind.value}-cluster"),
            )
            for kind in QualificationPartitionKind
        }
        self.partitions = tuple(
            QualificationPartition(
                kind=kind,
                fixture_manifest=_artifact(
                    f"qualification_{kind.value}_fixtures",
                    f"{kind.value}-fixtures",
                ),
                visibility=(
                    FixtureVisibility.SETUP_AGENT_VISIBLE
                    if kind is QualificationPartitionKind.CALIBRATION
                    else FixtureVisibility.HARNESS_ONLY
                ),
                units=(self.units[kind],),
            )
            for kind in QualificationPartitionKind
        )
        self.plan = QualificationPlan(
            "plan",
            "v1",
            self.candidate.content_sha256,
            self.policy.ref,
            self.partitions,
        )
        calibration_partition = next(
            item
            for item in self.plan.partitions
            if item.kind is QualificationPartitionKind.CALIBRATION
        )
        self.calibration = CalibrationReport(
            report_id="calibration",
            setup_subject_sha256=self.candidate.content_sha256,
            qualification_policy_sha256=self.policy.content_sha256,
            qualification_plan_sha256=self.plan.content_sha256,
            calibration_partition_sha256=canonical_sha256(
                calibration_partition.to_document()
            ),
            calibrated_parameters=_artifact("calibrated_parameters"),
            calibrated_domain=_artifact("calibrated_domain"),
            warmup_repetitions=1,
            decision_repetitions=2,
            unstable_group_count=0,
            verdict=QualificationVerdict.PASS,
            reason_codes=(),
            completed_at=_timestamp(2),
            expires_at=_timestamp(0, 12),
        )
        expected = {
            QualificationPartitionKind.CALIBRATION: OracleVerdict.PASS,
            QualificationPartitionKind.HOLDOUT: OracleVerdict.PASS,
            QualificationPartitionKind.NEGATIVE: OracleVerdict.VIOLATION,
            QualificationPartitionKind.OUT_OF_DOMAIN: OracleVerdict.INCONCLUSIVE,
        }
        self.trials = tuple(
            QualificationTrial(
                trial_id=f"trial-{kind.value}",
                partition_kind=kind,
                member_commitment=self.units[kind].member_commitment,
                group_commitment=self.units[kind].group_commitment,
                cluster_commitment=self.units[kind].cluster_commitment,
                workload_cell_sha256=_sha(f"cell-{kind.value}"),
                oracle_decision=_ref(
                    ContractRefKind.ORACLE_DECISION, f"decision-{kind.value}"
                ),
                expected_verdict=expected[kind],
                observed_verdict=expected[kind],
                stable=True,
                real_integration=False,
            )
            for kind in QualificationPartitionKind
        )
        self.report = QualificationReport(
            report_id="qualification",
            setup_subject_sha256=self.candidate.content_sha256,
            qualification_policy_sha256=self.policy.content_sha256,
            qualification_plan_sha256=self.plan.content_sha256,
            calibration_report_sha256=self.calibration.content_sha256,
            trials=self.trials,
            qualification_environment_sha256=_sha("qualification-environment"),
            bound_method=self.policy.bound_method,
            upper_false_violation_bound=CanonicalDecimal("0"),
            lower_detection_bound=CanonicalDecimal("1"),
            independent_non_violating_groups=1,
            independent_negative_groups=1,
            calibrated_cell_count=0,
            fault_cell_count=0,
            verdict=QualificationVerdict.PASS,
            reason_codes=(),
            completed_at=_timestamp(3),
            expires_at=_timestamp(0, 12),
        )
        self.manifest = self._manifest(self.candidate)
        self.review_bundle = ResultBlindReviewBundle(
            bundle_id="review-bundle",
            subject=make_review_subject(self.candidate),
            candidate_sha256=self.candidate.content_sha256,
            profile_graph_sha256=self.candidate.profile_graph_sha256,
            adapter_code=self.candidate.adapter_code,
            adapter_diff=_artifact("adapter_diff"),
            dependency_lock=self.candidate.dependency_lock,
            sbom=self.candidate.sbom,
            static_scan=_artifact("static_scan"),
            healthy_relation=_artifact("healthy_relation"),
            qualification_report_sha256=self.report.content_sha256,
            qualification_design_sha256=self.plan.content_sha256,
            permission_manifest=self.candidate.permission_manifest,
            invalidation_manifest_sha256=self.manifest.content_sha256,
            known_limitations=("requires_linux",),
        )
        self.review = ReviewRecord(
            review_id="review",
            subject_sha256=self.review_bundle.subject.content_sha256,
            input_bundle_sha256=self.review_bundle.content_sha256,
            verdict=ReviewVerdict.APPROVE,
            blocking_findings=(),
            non_blocking_findings=("monitor_ttl",),
            reviewer_authority="review.service",
            reviewer_session_id="review.session",
            model_id="review.model",
            prompt_sha256=_sha("review-prompt"),
            reviewed_at=_timestamp(4),
        )
        self.approval = SemanticApprovalRecord(
            approval_id="approval",
            trust_tier=RegistrationTrustTier.PROFILE_CUSTOM,
            subject_sha256=self.review_bundle.subject.content_sha256,
            basis_review_sha256=self.review.content_sha256,
            basis_qualification_report_sha256=self.report.content_sha256,
            authority_kind=ApprovalAuthorityKind.HUMAN,
            authority_id="approver",
            decision=ApprovalDecision.APPROVE,
            approved_at=_timestamp(5),
            expires_at=_timestamp(0, 12),
        )
        self.profile = freeze_profile(
            self.candidate,
            self.report,
            self.review_bundle,
            self.review,
            self.approval,
            created_at=_timestamp(6),
            expires_at=_timestamp(0, 11),
        )
        evidence = (
            self.candidate.content_sha256,
            self.report.content_sha256,
            self.review.content_sha256,
            self.approval.content_sha256,
        )
        self.lifecycle = SetupLifecycleRecord(
            candidate_sha256=self.candidate.content_sha256,
            trust_tier=self.candidate.trust_tier,
            transitions=(
                SetupStateTransition(1, SetupState.DRAFT, SetupState.QUALIFYING, SetupActorRole.SETUP_AGENT, "setup.agent", evidence[0], _timestamp(1)),
                SetupStateTransition(2, SetupState.QUALIFYING, SetupState.AWAITING_REVIEW, SetupActorRole.QUALIFICATION_WORKER, "qualification.worker", evidence[1], _timestamp(3)),
                SetupStateTransition(3, SetupState.AWAITING_REVIEW, SetupState.AWAITING_APPROVAL, SetupActorRole.REVIEWER, "reviewer", evidence[2], _timestamp(4)),
                SetupStateTransition(4, SetupState.AWAITING_APPROVAL, SetupState.FROZEN, SetupActorRole.HARNESS, "profile.gate", evidence[3], _timestamp(6)),
            ),
            final_state=SetupState.FROZEN,
            created_at=_timestamp(0),
            updated_at=_timestamp(6),
        )
        self.admission_ledger = RevocationLedger(
            ledger_id="revocations",
            ledger_version="v1",
            authority_policy_sha256=_sha("revocation-authority"),
            entries=(),
            created_at="2025-12-31T00:00:00Z",
        )
        self.gate_policy_sha256 = _sha("profile-gate-policy")
        self.gate_verification_receipt_sha256 = _sha(
            "profile-gate-verification-receipt"
        )
        self.admission = ProfileAdmissionRecord(
            admission_id="admission",
            setup_id=self.candidate.setup_id,
            trust_tier=self.candidate.trust_tier,
            candidate_sha256=self.candidate.content_sha256,
            profile=self.profile.ref,
            qualification_report_sha256=self.report.content_sha256,
            review_sha256=self.review.content_sha256,
            approval_sha256=self.approval.content_sha256,
            invalidation_manifest_sha256=self.manifest.content_sha256,
            lifecycle_sha256=self.lifecycle.content_sha256,
            gate_policy_sha256=self.gate_policy_sha256,
            gate_verification_receipt_sha256=(
                self.gate_verification_receipt_sha256
            ),
            revocation_ledger_sha256=self.admission_ledger.content_sha256,
            declared_permissions=self.candidate.declared_permissions,
            effective_permissions=("process.spawn",),
            admission_authority_kind=ApprovalAuthorityKind.HARNESS,
            admission_authority_id="profile.gate",
            admitted_at=_timestamp(7),
            qualification_expires_at=self.report.expires_at,
            approval_expires_at=self.approval.expires_at,
            expires_at=_timestamp(0, 10),
        )

    def _graph(self, snapshot_sha256: str) -> ProfileGraph:
        return ProfileGraph(
            profile_id="profile",
            profile_version="v1",
            project=ProjectBinding(
                "system", "generic", snapshot_sha256, _sha("project-dependencies")
            ),
            environment=EnvironmentBinding(
                _sha("os"), _sha("toolchain"), None, None, None, self.resource
            ),
            entrypoints=(self.entrypoint,),
            workload_schemas=(self.workload,),
            adapters=(self.adapter,),
            instrumentation_providers=(self.instrumentation,),
            oracle_specs=(self.oracle,),
            oracle_bundles=(self.bundle,),
            execution_recipes=(self.recipe,),
            components=(self.resource, self.policy.ref),
            capabilities=("process.spawn", "read.artifacts"),
        )

    def _candidate(self, graph: ProfileGraph) -> ProfileSetupCandidate:
        return ProfileSetupCandidate(
            setup_id="setup",
            candidate_version="v1",
            trust_tier=RegistrationTrustTier.PROFILE_CUSTOM,
            profile_graph=graph,
            qualification_policy=self.policy.ref,
            adapter_code=_artifact("adapter_code"),
            dependency_lock=_artifact("dependency_lock"),
            sbom=_artifact("sbom"),
            permission_manifest=_artifact("permission_manifest"),
            declared_permissions=("read.artifacts", "process.spawn"),
            created_at=_timestamp(0),
        )

    def _manifest(
        self, candidate: ProfileSetupCandidate
    ) -> DependencyInvalidationManifest:
        semantic = InvalidationAction.REQUALIFY_REVIEW_REAPPROVE
        graph = candidate.profile_graph
        expected = {
            DependencyKind.SOURCE_SNAPSHOT: {
                graph.project.source_snapshot_sha256
            },
            DependencyKind.PROFILE_GRAPH: {graph.content_sha256},
            DependencyKind.ENTRYPOINT: {
                item.content_sha256 for item in graph.entrypoints
            },
            DependencyKind.WORKLOAD_SCHEMA: {
                item.content_sha256 for item in graph.workload_schemas
            },
            DependencyKind.BASELINE: {
                item.content_sha256
                for item in graph.components
                if item.kind is ContractRefKind.BASELINE_POLICY
            },
            DependencyKind.ADAPTER: {
                item.content_sha256 for item in graph.adapters
            },
            DependencyKind.INSTRUMENTATION: {
                item.content_sha256 for item in graph.instrumentation_providers
            },
            DependencyKind.ORACLE: {
                item.content_sha256 for item in graph.oracle_specs
            },
            DependencyKind.ORACLE_BUNDLE: {
                item.content_sha256 for item in graph.oracle_bundles
            },
            DependencyKind.EXECUTION_RECIPE: {
                item.content_sha256 for item in graph.execution_recipes
            },
            DependencyKind.PROFILE_COMPONENT: {
                item.content_sha256
                for item in graph.components
                if item.kind
                not in (
                    ContractRefKind.BASELINE_POLICY,
                    ContractRefKind.RESOURCE_POLICY,
                )
            },
            DependencyKind.ADAPTER_CODE: {
                candidate.adapter_code.content_sha256
            },
            DependencyKind.DEPENDENCY_LOCK: {
                graph.project.dependency_manifest_sha256,
                candidate.dependency_lock.content_sha256,
            },
            DependencyKind.PERMISSION_MANIFEST: {
                candidate.permission_manifest.content_sha256
            },
            DependencyKind.SBOM: {candidate.sbom.content_sha256},
            DependencyKind.CAPABILITY_SET: {
                canonical_sha256({"capabilities": list(graph.capabilities)})
            },
            DependencyKind.TOOLCHAIN: {graph.environment.toolchain_sha256},
            DependencyKind.OS_IMAGE: {graph.environment.os_image_sha256},
            DependencyKind.MODEL: set(
                ()
                if graph.environment.model_sha256 is None
                else (graph.environment.model_sha256,)
            ),
            DependencyKind.HARDWARE: set(
                ()
                if graph.environment.hardware_fingerprint_sha256 is None
                else (graph.environment.hardware_fingerprint_sha256,)
            ),
            DependencyKind.DEVICE_IMAGE: set(
                ()
                if graph.environment.device_policy_sha256 is None
                else (graph.environment.device_policy_sha256,)
            ),
            DependencyKind.RESOURCE_POLICY: {
                graph.environment.resource_policy.content_sha256,
                *(
                    item.content_sha256
                    for item in graph.components
                    if item.kind is ContractRefKind.RESOURCE_POLICY
                ),
            },
        }
        semantic_kinds = {
            DependencyKind.ENTRYPOINT,
            DependencyKind.WORKLOAD_SCHEMA,
            DependencyKind.ADAPTER,
            DependencyKind.INSTRUMENTATION,
            DependencyKind.ORACLE,
            DependencyKind.ORACLE_BUNDLE,
            DependencyKind.EXECUTION_RECIPE,
            DependencyKind.PROFILE_COMPONENT,
            DependencyKind.ADAPTER_CODE,
            DependencyKind.DEPENDENCY_LOCK,
            DependencyKind.PERMISSION_MANIFEST,
            DependencyKind.SBOM,
            DependencyKind.CAPABILITY_SET,
        }
        dependencies = tuple(
            DependencyBinding(
                kind,
                f"dependency.{kind.value}.{index}",
                digest,
                semantic
                if kind in semantic_kinds
                else (
                    InvalidationAction.PROFILE_GATE
                    if kind
                    in (
                        DependencyKind.SOURCE_SNAPSHOT,
                        DependencyKind.PROFILE_GRAPH,
                    )
                    else InvalidationAction.FULL_QUALIFICATION
                ),
            )
            for kind in DependencyKind
            for index, digest in enumerate(sorted(expected.get(kind, set())))
        )
        return DependencyInvalidationManifest(
            manifest_id="invalidation",
            manifest_version="v1",
            candidate_sha256=candidate.content_sha256,
            profile_graph_sha256=candidate.profile_graph_sha256,
            dependencies=dependencies,
            unknown_change_action=InvalidationAction.FULL_QUALIFICATION,
            created_at=_timestamp(1),
        )


class ProfileSetupContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.fx = SetupFixture()

    def test_complete_graph_validates(self) -> None:
        fx = self.fx
        validate_qualification_graph(fx.candidate, fx.policy, fx.plan, fx.calibration, fx.report)
        validate_review_graph(fx.candidate, fx.report, fx.review_bundle, fx.review)
        validate_approval_graph(fx.candidate, fx.approval)
        validate_approval_basis(
            fx.approval, fx.review_bundle, fx.review, fx.report
        )
        validate_frozen_profile_graph(fx.candidate, fx.profile)
        validate_profile_admission_graph(
            fx.candidate, fx.profile, fx.report, fx.review_bundle, fx.review,
            fx.approval, fx.review_bundle, fx.review, fx.report,
            fx.gate_policy_sha256, fx.gate_verification_receipt_sha256,
            fx.manifest, fx.lifecycle,
            fx.admission_ledger, fx.admission,
        )

    def test_top_level_roundtrips_and_hashes(self) -> None:
        values = (
            self.fx.graph,
            self.fx.policy,
            self.fx.candidate,
            self.fx.plan,
            self.fx.calibration,
            self.fx.report,
            self.fx.review_bundle,
            self.fx.review,
            self.fx.approval,
            self.fx.lifecycle,
            self.fx.manifest,
            self.fx.admission,
            self.fx.admission_ledger,
        )
        for value in values:
            with self.subTest(type=type(value).__name__):
                payload = canonical_json_bytes(value.to_document())
                restored = type(value).from_json(payload)
                self.assertEqual(restored, value)
                self.assertEqual(restored.content_sha256, value.content_sha256)

    def test_strict_json_rejects_duplicate_and_unknown_keys(self) -> None:
        with self.assertRaisesRegex(ContractError, "duplicate key"):
            ProfileSetupCandidate.from_json(
                b'{"contract_kind":"profile_setup_candidate","contract_kind":"x"}'
            )
        document = self.fx.candidate.to_document()
        document["case_id"] = "forbidden"
        with self.assertRaisesRegex(ContractError, "unexpected keys"):
            ProfileSetupCandidate.from_json(json.dumps(document).encode())
        wrong_version = self.fx.candidate.to_document()
        wrong_version["schema_version"] = True
        with self.assertRaisesRegex(ContractError, "schema_version"):
            ProfileSetupCandidate.from_json(json.dumps(wrong_version).encode())

    def test_contracts_are_deeply_immutable_and_normalized(self) -> None:
        self.assertIsInstance(self.fx.candidate.declared_permissions, tuple)
        self.assertEqual(
            self.fx.candidate.declared_permissions,
            ("process.spawn", "read.artifacts"),
        )
        with self.assertRaises(dataclasses.FrozenInstanceError):
            self.fx.candidate.setup_id = "changed"  # type: ignore[misc]

    def test_partitions_reject_cross_partition_overlap_and_hidden_holdout(self) -> None:
        holdout = next(item for item in self.fx.partitions if item.kind is QualificationPartitionKind.HOLDOUT)
        with self.assertRaisesRegex(ContractError, "holdout fixtures"):
            dataclasses.replace(holdout, visibility=FixtureVisibility.SETUP_AGENT_VISIBLE)
        calibration = next(item for item in self.fx.partitions if item.kind is QualificationPartitionKind.CALIBRATION)
        with self.assertRaisesRegex(ContractError, "overlap"):
            QualificationPlan(
                "bad-plan", "v1", self.fx.candidate.content_sha256,
                self.fx.policy.ref,
                tuple(
                    dataclasses.replace(item, units=calibration.units)
                    if item.kind is QualificationPartitionKind.HOLDOUT else item
                    for item in self.fx.partitions
                ),
            )

    def test_qualification_requires_exact_lineage_coverage(self) -> None:
        missing = dataclasses.replace(self.fx.report, trials=self.fx.report.trials[:-1])
        with self.assertRaisesRegex(ContractError, "cover every frozen"):
            validate_qualification_graph(self.fx.candidate, self.fx.policy, self.fx.plan, self.fx.calibration, missing)
        bad = dataclasses.replace(
            self.fx.report.trials[0],
            group_commitment=_sha("substituted-group"),
        )
        tampered = dataclasses.replace(
            self.fx.report,
            trials=(bad, *self.fx.report.trials[1:]),
        )
        with self.assertRaisesRegex(ContractError, "cover every frozen|outside"):
            validate_qualification_graph(self.fx.candidate, self.fx.policy, self.fx.plan, self.fx.calibration, tampered)

    def test_qualification_retry_is_bounded_and_does_not_inflate_clusters(self) -> None:
        original = self.fx.report.trials[0]
        retry = dataclasses.replace(
            original,
            trial_id="trial-calibration-retry",
            oracle_decision=_ref(ContractRefKind.ORACLE_DECISION, "decision-retry"),
            attempt_index=2,
            retry_reason="broker_lease_lost",
        )
        retried = dataclasses.replace(self.fx.report, trials=(*self.fx.report.trials, retry))
        validate_qualification_graph(self.fx.candidate, self.fx.policy, self.fx.plan, self.fx.calibration, retried)
        self.assertEqual(retried.independent_non_violating_groups, 1)
        third = dataclasses.replace(
            retry,
            trial_id="trial-calibration-retry-2",
            oracle_decision=_ref(ContractRefKind.ORACLE_DECISION, "decision-retry-2"),
            attempt_index=3,
        )
        over_budget = dataclasses.replace(retried, trials=(*retried.trials, third))
        with self.assertRaisesRegex(ContractError, "retry allowance"):
            validate_qualification_graph(self.fx.candidate, self.fx.policy, self.fx.plan, self.fx.calibration, over_budget)

        non_allowlisted = dataclasses.replace(retry, retry_reason="result_disliked")
        with self.assertRaisesRegex(ContractError, "reason is not frozen"):
            validate_qualification_graph(
                self.fx.candidate,
                self.fx.policy,
                self.fx.plan,
                self.fx.calibration,
                dataclasses.replace(
                    self.fx.report,
                    trials=(*self.fx.report.trials, non_allowlisted),
                ),
            )
        skipped = dataclasses.replace(retry, attempt_index=3)
        with self.assertRaisesRegex(ContractError, "must be contiguous"):
            validate_qualification_graph(
                self.fx.candidate,
                self.fx.policy,
                self.fx.plan,
                self.fx.calibration,
                dataclasses.replace(
                    self.fx.report,
                    trials=(*self.fx.report.trials, skipped),
                ),
            )

    def test_statistical_confidence_and_ood_are_fail_closed(self) -> None:
        with self.assertRaisesRegex(ContractError, "less than 1"):
            dataclasses.replace(
                self.fx.policy,
                mode=QualificationMode.STATISTICAL,
                bound_method=StatisticalBoundMethod.CLOPPER_PEARSON,
                confidence_level=CanonicalDecimal("1"),
                max_false_violation_rate=CanonicalDecimal("0.01"),
                min_detection_rate=CanonicalDecimal("0.8"),
            )
        with self.assertRaisesRegex(ContractError, "out-of-domain"):
            dataclasses.replace(self.fx.policy, require_ood_inconclusive=False)

    def test_review_bundle_has_no_case_or_current_result_channel(self) -> None:
        forbidden = {
            "case_id", "current_observation", "predicted_result", "b1_result",
            "b2_result", "raw_holdout", "host_path",
        }
        keys: set[str] = set()
        def visit(value: object) -> None:
            if type(value) is dict:
                keys.update(value)
                for child in value.values():
                    visit(child)
            elif type(value) is list:
                for child in value:
                    visit(child)
        visit(self.fx.review_bundle.to_document())
        self.assertFalse(keys.intersection(forbidden))

    def test_semantic_approval_reuses_across_snapshot_profile_instance(self) -> None:
        graph2 = self.fx._graph(_sha("snapshot-2"))
        candidate2 = self.fx._candidate(graph2)
        self.assertNotEqual(candidate2.content_sha256, self.fx.candidate.content_sha256)
        self.assertNotEqual(candidate2.profile_graph_sha256, self.fx.candidate.profile_graph_sha256)
        self.assertEqual(make_review_subject(candidate2), make_review_subject(self.fx.candidate))
        validate_approval_graph(candidate2, self.fx.approval)
        validate_approval_basis(
            self.fx.approval,
            self.fx.review_bundle,
            self.fx.review,
            self.fx.report,
        )

    def test_approval_basis_tamper_is_rejected(self) -> None:
        altered = dataclasses.replace(self.fx.approval, basis_review_sha256=_sha("other-review"))
        with self.assertRaisesRegex(ContractError, "exact evidence basis"):
            validate_approval_basis(
                altered, self.fx.review_bundle, self.fx.review, self.fx.report
            )
        wrong_subject_review = dataclasses.replace(
            self.fx.review,
            subject_sha256=_sha("other-semantic-subject"),
        )
        approval = dataclasses.replace(
            self.fx.approval,
            basis_review_sha256=wrong_subject_review.content_sha256,
        )
        with self.assertRaisesRegex(ContractError, "different semantic subject"):
            validate_approval_basis(
                approval,
                self.fx.review_bundle,
                wrong_subject_review,
                self.fx.report,
            )

    def test_approval_cannot_predate_its_review_basis(self) -> None:
        backdated = dataclasses.replace(
            self.fx.approval,
            approved_at=_timestamp(3),
        )
        with self.assertRaisesRegex(ContractError, "chronological order"):
            validate_approval_basis(
                backdated,
                self.fx.review_bundle,
                self.fx.review,
                self.fx.report,
            )

    def test_profile_graph_projection_rejects_snapshot_tamper(self) -> None:
        graph2 = self.fx._graph(_sha("snapshot-2"))
        with self.assertRaisesRegex(ContractError, "does not exactly match"):
            validate_frozen_profile_graph(self.fx._candidate(graph2), self.fx.profile)

    def test_only_profile_gate_authority_can_freeze(self) -> None:
        transitions = list(self.fx.lifecycle.transitions)
        transitions[-1] = dataclasses.replace(
            transitions[-1], actor_role=SetupActorRole.HUMAN
        )
        with self.assertRaisesRegex(ContractError, "Profile Gate authority"):
            dataclasses.replace(self.fx.lifecycle, transitions=tuple(transitions))
        with self.assertRaisesRegex(ContractError, "illegal Setup transition"):
            SetupStateTransition(
                1, SetupState.DRAFT, SetupState.FROZEN, SetupActorRole.HARNESS,
                "profile.gate", _sha("evidence"), _timestamp(1),
            )

    def test_invalidation_manifest_fails_closed_for_semantic_change(self) -> None:
        with self.assertRaisesRegex(ContractError, "requires review or reapproval"):
            DependencyBinding(
                DependencyKind.ADAPTER_CODE,
                "adapter",
                self.fx.candidate.adapter_code.content_sha256,
                InvalidationAction.PROFILE_GATE,
            )
        with self.assertRaisesRegex(ContractError, "requires review or reapproval"):
            DependencyBinding(
                DependencyKind.ADAPTER_CODE,
                "adapter",
                self.fx.candidate.adapter_code.content_sha256,
                InvalidationAction.FULL_QUALIFICATION,
            )
        permission_role = next(
            item.role
            for item in self.fx.manifest.dependencies
            if item.kind is DependencyKind.PERMISSION_MANIFEST
        )
        incomplete = dataclasses.replace(
            self.fx.manifest,
            dependencies=tuple(
                item
                for item in self.fx.manifest.dependencies
                if item.role != permission_role
            ),
        )
        with self.assertRaisesRegex(
            ContractError,
            "exactly cover permission_manifest",
        ):
            validate_invalidation_manifest_graph(self.fx.candidate, incomplete)

    def test_each_dependency_kind_has_a_non_weakenable_change_floor(self) -> None:
        semantic_kinds = {
            DependencyKind.ENTRYPOINT,
            DependencyKind.WORKLOAD_SCHEMA,
            DependencyKind.ADAPTER,
            DependencyKind.INSTRUMENTATION,
            DependencyKind.ORACLE,
            DependencyKind.ORACLE_BUNDLE,
            DependencyKind.EXECUTION_RECIPE,
            DependencyKind.PROFILE_COMPONENT,
            DependencyKind.ADAPTER_CODE,
            DependencyKind.DEPENDENCY_LOCK,
            DependencyKind.PERMISSION_MANIFEST,
            DependencyKind.SBOM,
            DependencyKind.CAPABILITY_SET,
        }
        profile_gate_kinds = {
            DependencyKind.SOURCE_SNAPSHOT,
            DependencyKind.PROFILE_GRAPH,
        }
        qualification_kinds = set(DependencyKind) - semantic_kinds - profile_gate_kinds
        self.assertEqual(
            semantic_kinds | profile_gate_kinds | qualification_kinds,
            set(DependencyKind),
        )
        for kind in semantic_kinds:
            with self.subTest(kind=kind):
                with self.assertRaises(ContractError):
                    DependencyBinding(
                        kind,
                        f"weak.{kind.value}",
                        _sha(kind.value),
                        InvalidationAction.FULL_QUALIFICATION,
                    )
        for kind in profile_gate_kinds:
            with self.subTest(kind=kind):
                with self.assertRaises(ContractError):
                    DependencyBinding(
                        kind,
                        f"weak.{kind.value}",
                        _sha(kind.value),
                        InvalidationAction.REUSE_APPROVAL,
                    )
        for kind in qualification_kinds:
            with self.subTest(kind=kind):
                with self.assertRaises(ContractError):
                    DependencyBinding(
                        kind,
                        f"weak.{kind.value}",
                        _sha(kind.value),
                        InvalidationAction.PROFILE_GATE,
                    )

    def test_admission_rejects_permission_escalation_and_human_self_admission(self) -> None:
        with self.assertRaisesRegex(ContractError, "declared subset"):
            dataclasses.replace(
                self.fx.admission,
                effective_permissions=("network.public",),
            )
        with self.assertRaisesRegex(ContractError, "self-grant"):
            dataclasses.replace(
                self.fx.admission,
                admission_authority_kind=ApprovalAuthorityKind.HUMAN,
            )
        with self.assertRaisesRegex(ContractError, "qualification expiry"):
            dataclasses.replace(
                self.fx.admission,
                expires_at="2026-01-01T13:00:00Z",
            )

    def test_admission_binds_gate_revocation_head(self) -> None:
        tampered = dataclasses.replace(
            self.fx.admission,
            revocation_ledger_sha256=_sha("wrong-ledger"),
        )
        with self.assertRaisesRegex(ContractError, "revocation ledger"):
            validate_profile_admission_graph(
                self.fx.candidate, self.fx.profile, self.fx.report,
                self.fx.review_bundle, self.fx.review, self.fx.approval,
                self.fx.review_bundle, self.fx.review, self.fx.report,
                self.fx.gate_policy_sha256,
                self.fx.gate_verification_receipt_sha256,
                self.fx.manifest,
                self.fx.lifecycle, self.fx.admission_ledger, tampered,
            )
        with self.assertRaisesRegex(ContractError, "exact Setup graph"):
            validate_profile_admission_graph(
                self.fx.candidate, self.fx.profile, self.fx.report,
                self.fx.review_bundle, self.fx.review, self.fx.approval,
                self.fx.review_bundle, self.fx.review, self.fx.report,
                _sha("different-gate-policy"),
                self.fx.gate_verification_receipt_sha256,
                self.fx.manifest, self.fx.lifecycle,
                self.fx.admission_ledger, self.fx.admission,
            )
        with self.assertRaisesRegex(ContractError, "exact Setup graph"):
            validate_profile_admission_graph(
                self.fx.candidate, self.fx.profile, self.fx.report,
                self.fx.review_bundle, self.fx.review, self.fx.approval,
                self.fx.review_bundle, self.fx.review, self.fx.report,
                self.fx.gate_policy_sha256,
                _sha("different-gate-receipt"),
                self.fx.manifest, self.fx.lifecycle,
                self.fx.admission_ledger, self.fx.admission,
            )

    def test_revocation_is_append_only_and_changes_only_current_trust(self) -> None:
        before = evaluate_profile_trust(
            self.fx.candidate, self.fx.profile, self.fx.report,
            self.fx.review_bundle, self.fx.review, self.fx.approval,
            self.fx.review_bundle, self.fx.review, self.fx.report,
            self.fx.gate_policy_sha256,
            self.fx.gate_verification_receipt_sha256,
            self.fx.manifest, self.fx.lifecycle,
            self.fx.admission_ledger, self.fx.admission, self.fx.admission_ledger,
            issuance_at=_timestamp(8), evaluated_at=_timestamp(9),
        )
        self.assertTrue(before.valid_at_issuance)
        self.assertTrue(before.currently_trusted)
        entry = RevocationEntry(
            ledger_id=self.fx.admission_ledger.ledger_id,
            sequence=1,
            previous_entry_sha256=None,
            target=RevocationTarget(
                RevocationTargetKind.APPROVAL,
                self.fx.approval.content_sha256,
            ),
            reason=RevocationReason.MANUAL,
            authority_kind=ApprovalAuthorityKind.MAINTAINER,
            authority_id="security.maintainer",
            effective_at=_timestamp(10),
            signature=_artifact("revocation_signature"),
        )
        current = dataclasses.replace(self.fx.admission_ledger, entries=(entry,))
        validate_revocation_ledger_extension(self.fx.admission_ledger, current)
        after = evaluate_profile_trust(
            self.fx.candidate, self.fx.profile, self.fx.report,
            self.fx.review_bundle, self.fx.review, self.fx.approval,
            self.fx.review_bundle, self.fx.review, self.fx.report,
            self.fx.gate_policy_sha256,
            self.fx.gate_verification_receipt_sha256,
            self.fx.manifest, self.fx.lifecycle,
            self.fx.admission_ledger, self.fx.admission, current,
            issuance_at=_timestamp(8), evaluated_at=_timestamp(11),
        )
        self.assertTrue(after.valid_at_issuance)
        self.assertFalse(after.currently_trusted)
        self.assertIn(TrustReasonCode.APPROVAL_REVOKED, after.reason_codes)
        issued_after_revocation = evaluate_profile_trust(
            self.fx.candidate, self.fx.profile, self.fx.report,
            self.fx.review_bundle, self.fx.review, self.fx.approval,
            self.fx.review_bundle, self.fx.review, self.fx.report,
            self.fx.gate_policy_sha256,
            self.fx.gate_verification_receipt_sha256,
            self.fx.manifest, self.fx.lifecycle, self.fx.admission_ledger,
            self.fx.admission, current,
            issuance_at=_timestamp(10), evaluated_at=_timestamp(11),
        )
        self.assertFalse(issued_after_revocation.valid_at_issuance)
        self.assertFalse(issued_after_revocation.currently_trusted)
        self.assertIn(
            TrustReasonCode.INVALID_AT_ISSUANCE,
            issued_after_revocation.reason_codes,
        )
        altered_first = dataclasses.replace(
            entry, reason=RevocationReason.COMPROMISED
        )
        rewritten_second = RevocationEntry(
            ledger_id=current.ledger_id,
            sequence=2,
            previous_entry_sha256=altered_first.content_sha256,
            target=RevocationTarget(
                RevocationTargetKind.REVIEW,
                self.fx.review.content_sha256,
            ),
            reason=RevocationReason.MANUAL,
            authority_kind=ApprovalAuthorityKind.MAINTAINER,
            authority_id="security.maintainer",
            effective_at=_timestamp(11),
            signature=_artifact("revocation_signature", "second-signature"),
        )
        rewritten = dataclasses.replace(
            current,
            entries=(altered_first, rewritten_second),
        )
        with self.assertRaisesRegex(ContractError, "history was rewritten"):
            validate_revocation_ledger_extension(current, rewritten)


if __name__ == "__main__":
    unittest.main()

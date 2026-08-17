import dataclasses
import hashlib
import inspect
from decimal import Decimal
import unittest

from src.validation_core.contracts.base import (
    CanonicalDecimal,
    ContractError,
    canonical_sha256,
)
from src.validation_core.contracts.evidence import OracleVerdict
from src.validation_core.contracts.references import (
    ArtifactRef,
    ContractRef,
    ContractRefKind,
)
from src.validation_core.contracts.preset import RegistrationTrustTier
from src.validation_core.contracts.profile import EnvironmentBinding, ProjectBinding
from src.validation_core.contracts.setup import (
    CalibrationReport,
    FixtureVisibility,
    QualificationMode,
    QualificationPartition,
    QualificationPartitionKind,
    QualificationPlan,
    QualificationPolicy,
    QualificationTrial,
    QualificationUnit,
    QualificationVerdict,
    ProfileGraph,
    ProfileSetupCandidate,
    ReviewRecord,
    ReviewVerdict,
    StatisticalBoundMethod,
)
from src.validation_core.setup.qualification import (
    QualificationFailureReason,
    clopper_pearson_lower_bound,
    clopper_pearson_upper_bound,
    evaluate_qualification,
    verify_qualification_report,
)
from src.validation_core.setup.review import (
    assert_result_blind_document,
    build_result_blind_review_bundle,
    build_review_subject,
    validate_result_blind_review_record,
)


def _sha(value):
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _artifact(role, salt=None):
    return ArtifactRef(
        role=role,
        media_type="application/json",
        size_bytes=1,
        content_sha256=_sha(salt or role),
    )


def _ref(kind, name):
    return ContractRef(kind, name, "1.0.0", _sha(f"ref:{kind.value}:{name}"))


def _candidate(policy):
    dependency_lock = _artifact("dependency_lock")
    resource_policy = _ref(ContractRefKind.RESOURCE_POLICY, "resource.policy")
    graph = ProfileGraph(
        profile_id="profile.example",
        profile_version="1.0.0",
        project=ProjectBinding(
            system_id="example.system",
            project_kind="example",
            source_snapshot_sha256=_sha("source-snapshot"),
            dependency_manifest_sha256=dependency_lock.content_sha256,
        ),
        environment=EnvironmentBinding(
            os_image_sha256=_sha("os-image"),
            toolchain_sha256=_sha("toolchain"),
            hardware_fingerprint_sha256=None,
            model_sha256=None,
            device_policy_sha256=None,
            resource_policy=resource_policy,
        ),
        entrypoints=(_ref(ContractRefKind.ENTRYPOINT, "entrypoint"),),
        workload_schemas=(
            _ref(ContractRefKind.WORKLOAD_SCHEMA, "workload.schema"),
        ),
        adapters=(_ref(ContractRefKind.ADAPTER, "adapter"),),
        instrumentation_providers=(
            _ref(
                ContractRefKind.INSTRUMENTATION_PROVIDER,
                "instrumentation.provider",
            ),
        ),
        oracle_specs=(_ref(ContractRefKind.ORACLE_SPEC, "oracle.spec"),),
        oracle_bundles=(_ref(ContractRefKind.ORACLE_BUNDLE, "oracle.bundle"),),
        execution_recipes=(
            _ref(ContractRefKind.EXECUTION_RECIPE, "execution.recipe"),
        ),
        components=(resource_policy, policy.ref),
        capabilities=("generic.execution",),
    )
    return ProfileSetupCandidate(
        setup_id="setup.example",
        candidate_version="1.0.0",
        trust_tier=RegistrationTrustTier.PROFILE_CUSTOM,
        profile_graph=graph,
        qualification_policy=policy.ref,
        adapter_code=_artifact("adapter_code"),
        dependency_lock=dependency_lock,
        sbom=_artifact("sbom"),
        permission_manifest=_artifact("permission_manifest"),
        declared_permissions=("process.broker",),
        created_at="2026-08-17T00:00:00Z",
    )


def _qualification_fixture(
    *,
    bound_method=StatisticalBoundMethod.CLUSTER_AWARE,
    holdout_clusters=300,
    holdout_groups_per_cluster=1,
    negative_clusters=50,
    false_clusters=0,
    missed_negative_clusters=0,
    ood_verdict=OracleVerdict.INCONCLUSIVE,
    max_retries=1,
):
    mode = (
        QualificationMode.DETERMINISTIC
        if bound_method is StatisticalBoundMethod.NOT_APPLICABLE
        else QualificationMode.STATISTICAL
    )
    policy = QualificationPolicy(
        policy_id="qualification.policy",
        policy_version="1.0.0",
        mode=mode,
        trial_unit_id="frozen.decision.group",
        bound_method=bound_method,
        confidence_level=CanonicalDecimal("1" if mode is QualificationMode.DETERMINISTIC else "0.95"),
        max_false_violation_rate=CanonicalDecimal("0" if mode is QualificationMode.DETERMINISTIC else "0.01"),
        min_detection_rate=CanonicalDecimal("1" if mode is QualificationMode.DETERMINISTIC else "0.8"),
        min_non_violating_groups=holdout_clusters,
        min_negative_groups=negative_clusters,
        min_calibrated_cells=0,
        min_fault_cells=0,
        max_retries_per_trial=max_retries,
        retryable_reasons=("TEMPORARY_DEVICE_LOSS",),
        qualification_ttl_seconds=3600,
        require_ood_inconclusive=True,
    )

    partition_shapes = {
        QualificationPartitionKind.CALIBRATION: (1, 1),
        QualificationPartitionKind.HOLDOUT: (
            holdout_clusters,
            holdout_groups_per_cluster,
        ),
        QualificationPartitionKind.NEGATIVE: (negative_clusters, 1),
        QualificationPartitionKind.OUT_OF_DOMAIN: (1, 1),
    }
    partitions = []
    for kind, (cluster_count, groups_per_cluster) in partition_shapes.items():
        units = []
        for cluster_index in range(cluster_count):
            cluster = _sha(f"{kind.value}:cluster:{cluster_index}")
            for group_index in range(groups_per_cluster):
                group = _sha(
                    f"{kind.value}:cluster:{cluster_index}:group:{group_index}"
                )
                member = _sha(
                    f"{kind.value}:cluster:{cluster_index}:group:{group_index}:member"
                )
                units.append(QualificationUnit(member, group, cluster))
        partitions.append(
            QualificationPartition(
                kind=kind,
                fixture_manifest=_artifact(
                    f"qualification_{kind.value}_fixtures",
                    f"manifest:{kind.value}",
                ),
                visibility=(
                    FixtureVisibility.HARNESS_ONLY
                    if kind is QualificationPartitionKind.HOLDOUT
                    else FixtureVisibility.SETUP_AGENT_VISIBLE
                ),
                units=tuple(units),
            )
        )

    subject = _sha("setup-subject")
    plan = QualificationPlan(
        plan_id="qualification.plan",
        plan_version="1.0.0",
        setup_subject_sha256=subject,
        qualification_policy=policy.ref,
        partitions=tuple(partitions),
    )
    calibration_partition = next(
        item
        for item in plan.partitions
        if item.kind is QualificationPartitionKind.CALIBRATION
    )
    calibration = CalibrationReport(
        report_id="calibration.report",
        setup_subject_sha256=subject,
        qualification_policy_sha256=policy.content_sha256,
        qualification_plan_sha256=plan.content_sha256,
        calibration_partition_sha256=canonical_sha256(
            calibration_partition.to_document()
        ),
        calibrated_parameters=_artifact("calibrated_parameters"),
        calibrated_domain=_artifact("calibrated_domain"),
        warmup_repetitions=1,
        decision_repetitions=1,
        unstable_group_count=0,
        verdict=QualificationVerdict.PASS,
        reason_codes=(),
        completed_at="2026-08-17T00:00:00Z",
        expires_at="2026-08-18T00:00:00Z",
    )

    trials = []
    trial_index = 0
    expected = {
        QualificationPartitionKind.CALIBRATION: OracleVerdict.PASS,
        QualificationPartitionKind.HOLDOUT: OracleVerdict.PASS,
        QualificationPartitionKind.NEGATIVE: OracleVerdict.VIOLATION,
        QualificationPartitionKind.OUT_OF_DOMAIN: OracleVerdict.INCONCLUSIVE,
    }
    for partition in plan.partitions:
        cluster_order = {
            cluster: index
            for index, cluster in enumerate(partition.cluster_commitments)
        }
        for unit in partition.units:
            observed = expected[partition.kind]
            cluster_index = cluster_order[unit.cluster_commitment]
            if (
                partition.kind is QualificationPartitionKind.HOLDOUT
                and cluster_index < false_clusters
            ):
                observed = OracleVerdict.VIOLATION
            elif (
                partition.kind is QualificationPartitionKind.NEGATIVE
                and cluster_index < missed_negative_clusters
            ):
                observed = OracleVerdict.PASS
            elif partition.kind is QualificationPartitionKind.OUT_OF_DOMAIN:
                observed = ood_verdict
            trials.append(
                QualificationTrial(
                    trial_id=f"qualification.trial.{trial_index}",
                    partition_kind=partition.kind,
                    member_commitment=unit.member_commitment,
                    group_commitment=unit.group_commitment,
                    cluster_commitment=unit.cluster_commitment,
                    workload_cell_sha256=_sha(f"cell:{trial_index}"),
                    oracle_decision=ContractRef(
                        ContractRefKind.ORACLE_DECISION,
                        f"qualification.decision.{trial_index}",
                        "1.0.0",
                        _sha(f"decision:{trial_index}"),
                    ),
                    expected_verdict=expected[partition.kind],
                    observed_verdict=observed,
                    stable=True,
                    real_integration=False,
                )
            )
            trial_index += 1
    return policy, plan, calibration, tuple(trials)


def _evaluate(fixture):
    policy, plan, calibration, trials = fixture
    return evaluate_qualification(
        report_id="qualification.report",
        policy=policy,
        plan=plan,
        calibration_report=calibration,
        trials=trials,
        qualification_environment_sha256=_sha("qualification-environment"),
        completed_at="2026-08-17T01:00:00Z",
    )


def _review_fixture():
    policy, plan, calibration, trials = _qualification_fixture(
        bound_method=StatisticalBoundMethod.NOT_APPLICABLE,
        holdout_clusters=3,
        negative_clusters=2,
    )
    candidate = _candidate(policy)
    plan = dataclasses.replace(
        plan,
        setup_subject_sha256=candidate.content_sha256,
    )
    calibration = dataclasses.replace(
        calibration,
        setup_subject_sha256=candidate.content_sha256,
        qualification_plan_sha256=plan.content_sha256,
    )
    report = _evaluate((policy, plan, calibration, trials))
    bundle = build_result_blind_review_bundle(
        bundle_id="review.bundle",
        candidate=candidate,
        qualification_policy=policy,
        qualification_plan=plan,
        calibration_report=calibration,
        qualification_report=report,
        adapter_diff=_artifact("adapter_diff"),
        static_scan=_artifact("static_scan"),
        healthy_relation=_artifact("healthy_relation"),
        qualification_design_sha256=plan.content_sha256,
        invalidation_manifest_sha256=_sha("invalidation-manifest"),
        known_limitations=("resource.expensive",),
    )
    return candidate, policy, plan, calibration, report, bundle


class QualificationStatisticsTests(unittest.TestCase):
    def test_one_sided_false_violation_boundary(self):
        confidence = CanonicalDecimal("0.95")

        self.assertLessEqual(
            Decimal(clopper_pearson_upper_bound(0, 300, confidence).value),
            Decimal("0.01"),
        )
        self.assertGreater(
            Decimal(clopper_pearson_upper_bound(1, 300, confidence).value),
            Decimal("0.01"),
        )

    def test_one_sided_detection_boundary(self):
        confidence = CanonicalDecimal("0.95")

        self.assertGreaterEqual(
            Decimal(clopper_pearson_lower_bound(45, 50, confidence).value),
            Decimal("0.8"),
        )
        self.assertLess(
            Decimal(clopper_pearson_lower_bound(44, 50, confidence).value),
            Decimal("0.8"),
        )

    def test_bounds_are_canonical_and_conservative_at_extremes(self):
        confidence = CanonicalDecimal("0.95")

        self.assertEqual(
            clopper_pearson_upper_bound(10, 10, confidence),
            CanonicalDecimal("1"),
        )
        self.assertEqual(
            clopper_pearson_lower_bound(0, 10, confidence),
            CanonicalDecimal("0"),
        )

    def test_bounds_reject_non_exact_counts_and_probabilities(self):
        confidence = CanonicalDecimal("0.95")

        for arguments in (
            (True, 10, confidence),
            (-1, 10, confidence),
            (11, 10, confidence),
            (0, 0, confidence),
        ):
            with self.subTest(arguments=arguments):
                with self.assertRaises(ContractError):
                    clopper_pearson_upper_bound(*arguments)
        self.assertEqual(
            clopper_pearson_upper_bound(0, 10, CanonicalDecimal("1")),
            CanonicalDecimal("1"),
        )
        self.assertEqual(
            clopper_pearson_lower_bound(10, 10, CanonicalDecimal("1")),
            CanonicalDecimal("0"),
        )


class QualificationEvaluatorTests(unittest.TestCase):
    def test_cluster_aware_statistical_policy_counts_correlated_family_once(self):
        fixture = _qualification_fixture(
            holdout_groups_per_cluster=2,
            missed_negative_clusters=5,
        )

        report = _evaluate(fixture)

        self.assertIs(report.verdict, QualificationVerdict.PASS)
        self.assertEqual(report.independent_non_violating_groups, 300)
        self.assertEqual(report.independent_negative_groups, 50)
        self.assertLessEqual(
            Decimal(report.upper_false_violation_bound.value), Decimal("0.01")
        )
        self.assertGreaterEqual(
            Decimal(report.lower_detection_bound.value), Decimal("0.8")
        )
        verify_qualification_report(
            policy=fixture[0],
            plan=fixture[1],
            calibration_report=fixture[2],
            report=report,
        )

    def test_plain_clopper_pearson_rejects_correlated_groups(self):
        report = _evaluate(
            _qualification_fixture(
                bound_method=StatisticalBoundMethod.CLOPPER_PEARSON,
                holdout_groups_per_cluster=2,
            )
        )

        self.assertIs(report.verdict, QualificationVerdict.FAIL)
        self.assertIn(
            QualificationFailureReason.CORRELATED_GROUPS_REQUIRE_CLUSTER_BOUND.value,
            report.reason_codes,
        )

    def test_statistical_thresholds_fail_closed_on_false_and_missed_controls(self):
        report = _evaluate(
            _qualification_fixture(
                false_clusters=1,
                missed_negative_clusters=6,
            )
        )

        self.assertIs(report.verdict, QualificationVerdict.FAIL)
        self.assertIn(
            QualificationFailureReason.FALSE_VIOLATION_BOUND_EXCEEDED.value,
            report.reason_codes,
        )
        self.assertIn(
            QualificationFailureReason.DETECTION_BOUND_BELOW_TARGET.value,
            report.reason_codes,
        )

    def test_deterministic_policy_requires_exact_controls(self):
        report = _evaluate(
            _qualification_fixture(
                bound_method=StatisticalBoundMethod.NOT_APPLICABLE,
                holdout_clusters=2,
                negative_clusters=2,
                false_clusters=1,
                missed_negative_clusters=1,
            )
        )

        self.assertIs(report.verdict, QualificationVerdict.FAIL)
        self.assertIn(
            QualificationFailureReason.FALSE_VIOLATION.value,
            report.reason_codes,
        )
        self.assertIn(
            QualificationFailureReason.NEGATIVE_NOT_DETECTED.value,
            report.reason_codes,
        )

    def test_ood_and_instability_are_fail_closed(self):
        fixture = _qualification_fixture(
            holdout_clusters=3,
            negative_clusters=2,
            ood_verdict=OracleVerdict.PASS,
        )
        unstable_trial = dataclasses.replace(fixture[3][0], stable=False)
        fixture = (*fixture[:3], (unstable_trial, *fixture[3][1:]))

        report = _evaluate(fixture)

        self.assertIs(report.verdict, QualificationVerdict.FAIL)
        self.assertIn(
            QualificationFailureReason.OOD_NOT_INCONCLUSIVE.value,
            report.reason_codes,
        )
        self.assertIn(
            QualificationFailureReason.UNSTABLE_TRIAL.value,
            report.reason_codes,
        )

    def test_trials_must_match_frozen_lineage_and_retry_budget(self):
        fixture = _qualification_fixture(
            holdout_clusters=2,
            negative_clusters=2,
            max_retries=0,
        )
        forged = dataclasses.replace(
            fixture[3][0],
            cluster_commitment=_sha("forged-cluster"),
        )
        with self.assertRaisesRegex(ContractError, "frozen.*lineage"):
            _evaluate((*fixture[:3], (forged, *fixture[3][1:])))

        replay = dataclasses.replace(
            fixture[3][0],
            trial_id="qualification.trial.replay",
            oracle_decision=ContractRef(
                ContractRefKind.ORACLE_DECISION,
                "qualification.decision.replay",
                "1.0.0",
                _sha("decision:replay"),
            ),
            attempt_index=2,
            retry_reason="TEMPORARY_DEVICE_LOSS",
        )
        with self.assertRaisesRegex(ContractError, "retry allowance"):
            _evaluate((*fixture[:3], (*fixture[3], replay)))

    def test_retry_reason_and_attempt_sequence_are_frozen(self):
        fixture = _qualification_fixture(
            holdout_clusters=2,
            negative_clusters=2,
            max_retries=2,
        )
        first = fixture[3][0]
        retry = dataclasses.replace(
            first,
            trial_id="qualification.trial.retry",
            oracle_decision=ContractRef(
                ContractRefKind.ORACLE_DECISION,
                "qualification.decision.retry",
                "1.0.0",
                _sha("decision:retry"),
            ),
            attempt_index=2,
            retry_reason="TEMPORARY_DEVICE_LOSS",
        )
        _evaluate((*fixture[:3], (*fixture[3], retry)))

        with self.assertRaisesRegex(ContractError, "reason is not frozen"):
            _evaluate(
                (
                    *fixture[:3],
                    (*fixture[3], dataclasses.replace(retry, retry_reason="RESULT_DISLIKED")),
                )
            )
        with self.assertRaisesRegex(ContractError, "must be contiguous"):
            _evaluate(
                (
                    *fixture[:3],
                    (*fixture[3], dataclasses.replace(retry, attempt_index=3)),
                )
            )

    def test_allowlisted_retry_uses_the_final_attempt_without_hiding_history(self):
        fixture = _qualification_fixture(
            bound_method=StatisticalBoundMethod.NOT_APPLICABLE,
            holdout_clusters=2,
            negative_clusters=2,
            max_retries=1,
        )
        failed_first = dataclasses.replace(
            fixture[3][0],
            observed_verdict=OracleVerdict.INCONCLUSIVE,
            stable=False,
        )
        retry = dataclasses.replace(
            fixture[3][0],
            trial_id="qualification.trial.retry-success",
            oracle_decision=ContractRef(
                ContractRefKind.ORACLE_DECISION,
                "qualification.decision.retry-success",
                "1.0.0",
                _sha("decision:retry-success"),
            ),
            attempt_index=2,
            retry_reason="TEMPORARY_DEVICE_LOSS",
        )
        report = _evaluate(
            (
                *fixture[:3],
                (failed_first, *fixture[3][1:], retry),
            )
        )
        self.assertIs(report.verdict, QualificationVerdict.PASS)
        self.assertEqual(len(report.trials), len(fixture[3]) + 1)

    def test_gate_recomputation_rejects_self_reported_bound(self):
        fixture = _qualification_fixture()
        report = _evaluate(fixture)
        forged = dataclasses.replace(
            report,
            upper_false_violation_bound=CanonicalDecimal("0"),
        )

        with self.assertRaisesRegex(ContractError, "canonical recomputation"):
            verify_qualification_report(
                policy=fixture[0],
                plan=fixture[1],
                calibration_report=fixture[2],
                report=forged,
            )

    def test_partition_overlap_is_rejected_before_evaluation(self):
        fixture = _qualification_fixture(
            holdout_clusters=2,
            negative_clusters=2,
        )
        plan = fixture[1]
        calibration = next(
            item
            for item in plan.partitions
            if item.kind is QualificationPartitionKind.CALIBRATION
        )
        holdout_index = next(
            index
            for index, item in enumerate(plan.partitions)
            if item.kind is QualificationPartitionKind.HOLDOUT
        )
        overlapping_holdout = dataclasses.replace(
            plan.partitions[holdout_index],
            units=(calibration.units[0], *plan.partitions[holdout_index].units),
        )
        partitions = list(plan.partitions)
        partitions[holdout_index] = overlapping_holdout

        with self.assertRaisesRegex(ContractError, "overlap"):
            dataclasses.replace(plan, partitions=tuple(partitions))


class ResultBlindBoundaryTests(unittest.TestCase):
    def test_key_audit_rejects_prohibited_fields_at_any_depth(self):
        for key in (
            "case_id",
            "currentObservation",
            "predicted_result",
            "b1-verdict",
            "b2_result",
            "raw_holdout_fixture",
            "hiddenFixtures",
        ):
            with self.subTest(key=key):
                with self.assertRaises(ContractError):
                    assert_result_blind_document(
                        {"subject": {"nested": [{key: "forbidden"}]}}
                    )

    def test_key_audit_accepts_governance_only_document(self):
        assert_result_blind_document(
            {
                "subject_sha256": "a" * 64,
                "adapter_source": {"content_sha256": "b" * 64},
                "qualification_report_sha256": "c" * 64,
                "holdout_design_ids": ["holdout.design.v1"],
                "known_limitation_ids": ["resource.expensive"],
            }
        )

    def test_builder_signature_has_no_current_case_or_result_channel(self):
        parameters = set(
            inspect.signature(build_result_blind_review_bundle).parameters
        )
        self.assertTrue(
            parameters.isdisjoint(
                {
                    "case_id",
                    "current_case",
                    "current_observation",
                    "predicted_result",
                    "expected_verdict",
                    "b1_result",
                    "b2_result",
                    "raw_holdout",
                    "hidden_fixtures",
                }
            )
        )

    def test_builder_derives_subject_and_candidate_owned_artifacts(self):
        candidate, _, _, _, report, bundle = _review_fixture()

        self.assertEqual(bundle.subject, build_review_subject(candidate))
        self.assertEqual(bundle.candidate_sha256, candidate.content_sha256)
        self.assertEqual(
            bundle.profile_graph_sha256,
            candidate.profile_graph_sha256,
        )
        self.assertEqual(bundle.adapter_code, candidate.adapter_code)
        self.assertEqual(bundle.dependency_lock, candidate.dependency_lock)
        self.assertEqual(bundle.sbom, candidate.sbom)
        self.assertEqual(
            bundle.permission_manifest,
            candidate.permission_manifest,
        )
        self.assertEqual(
            bundle.qualification_report_sha256,
            report.content_sha256,
        )
        assert_result_blind_document(bundle.to_document())

    def test_builder_recomputes_qualification_before_review(self):
        candidate, policy, plan, calibration, report, _ = _review_fixture()
        forged = dataclasses.replace(
            report,
            upper_false_violation_bound=CanonicalDecimal("1"),
        )

        with self.assertRaises(ContractError):
            build_result_blind_review_bundle(
                bundle_id="review.bundle.forged",
                candidate=candidate,
                qualification_policy=policy,
                qualification_plan=plan,
                calibration_report=calibration,
                qualification_report=forged,
                adapter_diff=_artifact("adapter_diff"),
                static_scan=_artifact("static_scan"),
                healthy_relation=_artifact("healthy_relation"),
                qualification_design_sha256=plan.content_sha256,
                invalidation_manifest_sha256=_sha("invalidation-manifest"),
            )

    def test_review_record_must_bind_exact_subject_and_bundle(self):
        _, _, _, _, _, bundle = _review_fixture()
        review = ReviewRecord(
            review_id="review.record",
            subject_sha256=bundle.subject.content_sha256,
            input_bundle_sha256=bundle.content_sha256,
            verdict=ReviewVerdict.APPROVE,
            blocking_findings=(),
            non_blocking_findings=("document.limitations",),
            reviewer_authority="review.authority",
            reviewer_session_id="review.session",
            model_id="review.model",
            prompt_sha256=_sha("review-prompt"),
            reviewed_at="2026-08-17T02:00:00Z",
        )
        validate_result_blind_review_record(bundle, review)

        with self.assertRaisesRegex(ContractError, "exact input bundle"):
            validate_result_blind_review_record(
                bundle,
                dataclasses.replace(
                    review,
                    input_bundle_sha256=_sha("wrong-bundle"),
                ),
            )


if __name__ == "__main__":
    unittest.main()

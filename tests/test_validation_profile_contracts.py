import ast
import dataclasses
import hashlib
import json
from pathlib import Path
import unittest

import src.validation_core as production_root
import src.validation_core.contracts as contracts_namespace
from src.validation_core.contracts.base import ContractError
from src.validation_core.contracts.execution import (
    ExecutionInputBinding,
    ExecutionRecipe,
    ExecutionStep,
    InputBindingSource,
)
from src.validation_core.contracts.oracle import (
    ApplicabilitySpec,
    CausalControlSpec,
    ConsequenceDomain,
    ControlEvidenceRole,
    CrossGateReproducibility,
    DifferentialMethod,
    ExecutionProtocol,
    GoldenMethod,
    OracleBundle,
    OracleOrigin,
    OracleSpec,
    OracleVariant,
    PrimaryCombination,
    QuorumSpec,
    ReasonVocabulary,
    ReproducibilityMode,
    RetryReason,
    VariantRole,
)
from src.validation_core.contracts.profile import (
    EnvironmentBinding,
    FrozenSystemProfile,
    ProjectBinding,
    validate_frozen_profile_contracts,
)
from src.validation_core.contracts.references import (
    ArtifactRef,
    ContractRef,
    ContractRefKind,
)


def _digest(value):
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _ref(kind, name=None, *, salt="default"):
    contract_id = name or f"example.{kind.value}"
    return ContractRef(
        kind=kind,
        contract_id=contract_id,
        contract_version="1.0.0",
        content_sha256=_digest(f"{kind.value}:{contract_id}:{salt}"),
    )


def _recipe(*, recipe_id="example.recipe", changed_tool=None):
    resource = _ref(ContractRefKind.RESOURCE_POLICY)
    step = ExecutionStep(
        step_id="run",
        execution_block=_ref(ContractRefKind.EXECUTION_BLOCK),
        tool=changed_tool or _ref(ContractRefKind.TOOL),
        argv_template=_ref(ContractRefKind.ARGV_TEMPLATE),
        timeout_policy=_ref(ContractRefKind.TIMEOUT_POLICY),
        resource_policy=resource,
        output_contract=_ref(ContractRefKind.OUTPUT_CONTRACT),
        environment_policy=_ref(ContractRefKind.ENVIRONMENT_POLICY),
        input_bindings=(
            ExecutionInputBinding(
                name="workload",
                source=InputBindingSource.ARTIFACT_ROLE,
                symbol="case.workload",
            ),
        ),
        cwd_symbol="workspace.project",
        stdin_artifact_role=None,
    )
    return ExecutionRecipe(
        recipe_id=recipe_id,
        recipe_version="1.0.0",
        recipe_schema=_ref(ContractRefKind.EXECUTION_RECIPE_SCHEMA),
        steps=(step,),
    )


def _base_spec_values(recipe, *, oracle_id, domain, method, variants):
    return {
        "oracle_id": oracle_id,
        "oracle_version": "1.0.0",
        "declared_origin": OracleOrigin.MAINTAINER_PRESET,
        "consequence_domain": domain,
        "method": method,
        "applicability": ApplicabilitySpec(
            domain_id="example.domain",
            calibrated_domain=ArtifactRef(
                role="calibrated_domain",
                media_type="application/json",
                size_bytes=32,
                content_sha256=_digest("calibrated-domain"),
            ),
            required_capabilities=("generic.execution",),
            out_of_domain_reason="DOMAIN_MISMATCH",
        ),
        "variants": variants,
        "collectors": (_ref(ContractRefKind.COLLECTOR),),
        "normalizer": _ref(ContractRefKind.NORMALIZER),
        "comparator": _ref(ContractRefKind.COMPARATOR),
        "execution_protocol": ExecutionProtocol(
            warmup_runs=0,
            repetitions=1,
            quorum=QuorumSpec(required=1, total=1),
            timeout_ms=30_000,
            max_retries=1,
            retry_reasons=(RetryReason.ENVIRONMENT_FINGERPRINT_DRIFT,),
        ),
        "healthy_relation": _ref(ContractRefKind.HEALTHY_RELATION_POLICY),
        "decision_policy": _ref(ContractRefKind.DECISION_POLICY),
        "qualification_policy": _ref(ContractRefKind.QUALIFICATION_POLICY),
        "baseline_policy": None,
        "threshold_policy": None,
        "cross_gate_reproducibility": CrossGateReproducibility(
            mode=ReproducibilityMode.DETERMINISTIC,
            require_same_direction=False,
            require_normalized_equality=True,
            max_effect_delta=None,
        ),
        "reason_vocabulary": ReasonVocabulary(
            violation=("RELATION_VIOLATED",),
            passed=("RELATION_HOLDS",),
            inconclusive=("DOMAIN_MISMATCH", "ENVIRONMENT_UNSTABLE"),
        ),
        "control_evidence_role": ControlEvidenceRole.ORACLE_ONLY,
        "causal_control": None,
    }


def _golden_spec(
    recipe,
    *,
    oracle_id="example.correctness",
    domain=ConsequenceDomain.CORRECTNESS,
    **changes,
):
    candidate = OracleVariant(
        variant_id="candidate",
        role=VariantRole.CANDIDATE,
        execution_recipe=recipe.ref,
    )
    values = _base_spec_values(
        recipe,
        oracle_id=oracle_id,
        domain=domain,
        method=GoldenMethod(
            candidate_variant_id="candidate",
            expected_artifact=ArtifactRef(
                role="golden",
                media_type="application/json",
                size_bytes=8,
                content_sha256=_digest(f"golden:{oracle_id}"),
            ),
        ),
        variants=(candidate,),
    )
    values.update(changes)
    return OracleSpec(**values)


def _causal_spec(recipe, guard, *, oracle_id="example.causal"):
    candidate = OracleVariant(
        "candidate", VariantRole.CANDIDATE, recipe.ref
    )
    control = OracleVariant("control", VariantRole.CONTROL, recipe.ref)
    values = _base_spec_values(
        recipe,
        oracle_id=oracle_id,
        domain=ConsequenceDomain.PERFORMANCE,
        method=DifferentialMethod("candidate", "control"),
        variants=(candidate, control),
    )
    values.update(
        {
            "control_evidence_role": ControlEvidenceRole.DUAL_ROLE,
            "causal_control": CausalControlSpec(
                control_variant_id="control",
                control_policy=_ref(
                    ContractRefKind.CONTROL_POLICY,
                    "example.control.intervention",
                ),
                causal_prediction=_ref(
                    ContractRefKind.HEALTHY_RELATION_POLICY,
                    "example.control.prediction",
                ),
                correctness_guard=guard.ref,
                target_association=_ref(
                    ContractRefKind.TARGET_EVIDENCE_POLICY,
                ),
                reuse_policy=_ref(
                    ContractRefKind.CONTROL_POLICY,
                    "example.control.reuse",
                ),
            ),
        }
    )
    return OracleSpec(**values)


def _bundle(
    specs,
    *,
    bundle_id="example.bundle",
    role=ControlEvidenceRole.ORACLE_ONLY,
    control_oracle=None,
    primary_metric_oracle=None,
    multiplicity_policy=None,
):
    return OracleBundle(
        bundle_id=bundle_id,
        bundle_version="1.0.0",
        required_guards=(),
        primary_oracles=tuple(spec.ref for spec in specs),
        supporting_oracles=(),
        primary_combination=PrimaryCombination.ALL,
        k=None,
        control_evidence_role=role,
        control_oracle=control_oracle,
        primary_metric_oracle=primary_metric_oracle,
        multiplicity_policy=multiplicity_policy,
    )


def _unique_refs(*groups):
    references = [reference for group in groups for reference in group]
    by_identity = {
        (ref.kind, ref.contract_id, ref.contract_version): ref
        for ref in references
    }
    return tuple(by_identity.values())


def _profile(specs, bundles, recipes, *, components=None, capabilities=None):
    if components is None:
        components = _unique_refs(
            *(spec.component_refs for spec in specs),
            *(bundle.component_refs for bundle in bundles),
            *(recipe.component_refs for recipe in recipes),
        )
    if capabilities is None:
        capabilities = ("generic.execution",)
    resource = next(
        ref for ref in components if ref.kind is ContractRefKind.RESOURCE_POLICY
    )
    return FrozenSystemProfile(
        profile_id="example.profile",
        profile_version="1.0.0",
        project=ProjectBinding(
            system_id="example.project",
            project_kind="unknown_project",
            source_snapshot_sha256=_digest("snapshot"),
            dependency_manifest_sha256=_digest("dependencies"),
        ),
        environment=EnvironmentBinding(
            os_image_sha256=_digest("os"),
            toolchain_sha256=_digest("toolchain"),
            hardware_fingerprint_sha256=None,
            model_sha256=None,
            device_policy_sha256=None,
            resource_policy=resource,
        ),
        entrypoints=(_ref(ContractRefKind.ENTRYPOINT),),
        workload_schemas=(_ref(ContractRefKind.WORKLOAD_SCHEMA),),
        adapters=(_ref(ContractRefKind.ADAPTER),),
        instrumentation_providers=(
            _ref(ContractRefKind.INSTRUMENTATION_PROVIDER),
        ),
        oracle_specs=tuple(spec.ref for spec in specs),
        oracle_bundles=tuple(bundle.ref for bundle in bundles),
        execution_recipes=tuple(recipe.ref for recipe in recipes),
        components=components,
        capabilities=capabilities,
        qualification_report_sha256=_digest("qualification"),
        review_sha256=_digest("review"),
        approval_sha256=_digest("approval"),
        created_at="2026-08-14T00:00:00Z",
        expires_at="2027-08-14T00:00:00Z",
    )


class FrozenSystemProfileContractTests(unittest.TestCase):
    def test_new_contracts_are_public_only_in_the_contract_namespace(self):
        pre_stage_exports = {
            "ComponentKind",
            "ComponentRef",
            "ComponentDescriptor",
            "ContractError",
            "GenericAdapterKind",
            "PresetRef",
            "PresetDependency",
            "ImplementationRef",
            "RegistrationOrigin",
            "RegistrationRecord",
            "RegistrationTrustTier",
            "RoutingDecision",
            "RoutingReasonCode",
            "RoutingRequest",
            "SemanticClause",
            "SemanticContract",
            "ValidationPreset",
            "ValidationEngine",
            "ValidationRoutingError",
            "ValidationRoutingErrorCode",
            "canonical_json_bytes",
            "canonical_sha256",
        }
        stage_exports = {
            "ApplicabilitySpec",
            "ArtifactRef",
            "CanonicalDecimal",
            "CausalControlSpec",
            "ConsequenceDomain",
            "ConsensusMethod",
            "ContractRef",
            "ContractRefKind",
            "ControlEvidenceRole",
            "CrossGateReproducibility",
            "DifferentialMethod",
            "EnvironmentBinding",
            "ExecutionInputBinding",
            "ExecutionProtocol",
            "ExecutionRecipe",
            "ExecutionStep",
            "FrozenSystemProfile",
            "GoldenMethod",
            "InputBindingSource",
            "InvariantMethod",
            "MetamorphicMethod",
            "OracleBundle",
            "OracleOrigin",
            "OracleSpec",
            "OracleVariant",
            "PrimaryCombination",
            "ProjectBinding",
            "QuorumSpec",
            "ReasonVocabulary",
            "ReproducibilityMode",
            "ResourceGrowthMethod",
            "RetryReason",
            "StatisticalBaselineMethod",
            "VariantRole",
            "load_strict_json_object",
            "validate_frozen_profile_contracts",
        }
        stage_4b_exports = {
            "BaselineCandidate",
            "BaselineEligibility",
            "BaselineSelectionReceipt",
            "BaselineSourceKind",
            "CasePlan",
            "CaseSubmission",
            "CaseSubmissionKind",
            "DynamicBindingRequest",
            "DynamicResourceBinding",
            "DynamicResourceKind",
            "ExecutionBinding",
            "ExperimentPhase",
            "ExperimentPlanTemplate",
            "ExperimentStep",
            "GateRole",
            "PlannedOracleExecution",
            "RepairSelection",
            "TargetEvidenceSelection",
            "ValidationInstanceIdentity",
            "WorkloadSelection",
            "compute_validation_instance_id",
            "validate_b1_b2_binding_equivalence",
            "validate_case_plan_membership",
            "validate_case_submission_membership",
            "validate_execution_binding",
            "validate_experiment_plan_membership",
            "validate_template_baseline_selections",
            "validate_template_determinism",
        }
        stage_4c_exports = {
            "B1TerminalOutcome",
            "B2RecheckFailedOutcome",
            "CandidateGateReceipt",
            "CanonicalTypedValue",
            "CanonicalValueKind",
            "CapturedArtifact",
            "CaseReasonCode",
            "CaseStatus",
            "CertificateV2",
            "ConfirmedOutcome",
            "CrossGateDecision",
            "CrossGateFailedOutcome",
            "CrossGateVerdict",
            "DecisionQuorum",
            "EarlyGateReceipt",
            "EarlyGateStage",
            "ExplicitNotConfirmedOutcome",
            "FastPathCheck",
            "FastPathGateReceipt",
            "GateAttemptDisposition",
            "GatePhaseResult",
            "GatePhaseStatus",
            "GateReceipt",
            "GateReceiptKind",
            "Observation",
            "ObservationFactKind",
            "OracleDecision",
            "OracleVerdict",
            "OutcomeKind",
            "ValidationGrade",
            "ValidationOutcome",
            "gate_receipt_from_document",
            "gate_receipt_from_json",
            "validate_b1_b2_gate_receipts",
            "validate_b1_b2_observation_independence",
            "validate_candidate_gate_receipt_membership",
            "validate_candidate_gate_receipt_phases",
            "validate_certificate_publication",
            "validate_cross_gate_decision",
            "validate_early_gate_receipt_identity",
            "validate_fast_path_gate_receipt_identity",
            "validate_oracle_decision_evidence",
            "validate_outcome_publication",
            "validate_status_reason",
            "validation_outcome_from_document",
            "validation_outcome_from_json",
        }
        snapshot_exports = {
            "SnapshotEntryKind",
            "SnapshotManifest",
            "SnapshotManifestEntry",
            "SnapshotPolicy",
            "SnapshotRef",
            "SymlinkPolicy",
            "generic_source_snapshot_policy_v1",
        }
        coordinator_exports = {
            "CoordinatorRequestEnvelope",
            "CoordinatorResponseEnvelope",
            "StagedArtifactBinding",
        }
        stage_6_exports = {
            "ApprovalAuthorityKind",
            "ApprovalDecision",
            "CalibrationReport",
            "DependencyBinding",
            "DependencyInvalidationManifest",
            "DependencyKind",
            "FixtureVisibility",
            "InvalidationAction",
            "ProfileAdmissionRecord",
            "ProfileGraph",
            "ProfileSetupCandidate",
            "QualificationMode",
            "QualificationPartition",
            "QualificationPartitionKind",
            "QualificationPlan",
            "QualificationPolicy",
            "QualificationReport",
            "QualificationTrial",
            "QualificationUnit",
            "QualificationVerdict",
            "ResultBlindReviewBundle",
            "ReviewRecord",
            "ReviewSubject",
            "ReviewVerdict",
            "RevocationEntry",
            "RevocationLedger",
            "RevocationReason",
            "RevocationTarget",
            "RevocationTargetKind",
            "SemanticApprovalRecord",
            "SetupActorRole",
            "SetupLifecycleRecord",
            "SetupState",
            "SetupStateTransition",
            "StatisticalBoundMethod",
            "TrustEvaluation",
            "TrustReasonCode",
            "evaluate_profile_trust",
            "freeze_profile",
            "make_review_subject",
            "validate_approval_basis",
            "validate_approval_graph",
            "validate_frozen_profile_graph",
            "validate_invalidation_manifest_graph",
            "validate_profile_admission_graph",
            "validate_qualification_graph",
            "validate_revocation_ledger_extension",
            "validate_review_graph",
        }
        exports = contracts_namespace.__all__
        self.assertEqual(len(exports), len(set(exports)))
        self.assertEqual(
            set(exports),
            pre_stage_exports
            | stage_exports
            | stage_4b_exports
            | stage_4c_exports
            | snapshot_exports
            | coordinator_exports
            | stage_6_exports,
        )
        for name in exports:
            self.assertTrue(hasattr(contracts_namespace, name), name)
        for name in (
            stage_exports
            | stage_4b_exports
            | stage_4c_exports
            | snapshot_exports
            | coordinator_exports
            | stage_6_exports
        ):
            self.assertFalse(hasattr(production_root, name), name)

    def test_profile_round_trip_hash_and_deep_immutability(self):
        recipe = _recipe()
        spec = _golden_spec(recipe)
        bundle = _bundle((spec,))
        components = list(
            _unique_refs(
                spec.component_refs,
                bundle.component_refs,
                recipe.component_refs,
            )
        )
        profile = _profile((spec,), (bundle,), (recipe,), components=components)
        digest = profile.content_sha256

        restored = FrozenSystemProfile.from_document(profile.to_document())
        from_json = FrozenSystemProfile.from_json(
            json.dumps(profile.to_document()).encode("utf-8")
        )
        self.assertEqual(restored, profile)
        self.assertEqual(from_json, profile)
        self.assertEqual(profile.ref.kind, ContractRefKind.FROZEN_PROFILE)
        self.assertEqual(profile.ref.content_sha256, digest)

        components.append(_ref(ContractRefKind.RESET_POLICY))
        self.assertEqual(profile.content_sha256, digest)
        self.assertNotIn(ContractRefKind.RESET_POLICY, {r.kind for r in profile.components})
        with self.assertRaises(dataclasses.FrozenInstanceError):
            profile.profile_id = "changed"

    def test_set_like_membership_is_canonical_but_semantic_changes_rehash(self):
        recipe = _recipe()
        spec = _golden_spec(recipe)
        bundle = _bundle((spec,))
        profile = _profile((spec,), (bundle,), (recipe,))
        reordered = dataclasses.replace(
            profile,
            components=tuple(reversed(profile.components)),
        )
        changed_snapshot = dataclasses.replace(
            profile,
            project=dataclasses.replace(
                profile.project,
                source_snapshot_sha256=_digest("other snapshot"),
            ),
        )

        self.assertEqual(reordered.to_document(), profile.to_document())
        self.assertEqual(reordered.content_sha256, profile.content_sha256)
        self.assertNotEqual(changed_snapshot.content_sha256, profile.content_sha256)

    def test_profile_schema_ref_kinds_and_timestamps_fail_closed(self):
        recipe = _recipe()
        spec = _golden_spec(recipe)
        bundle = _bundle((spec,))
        profile = _profile((spec,), (bundle,), (recipe,))

        for key, value in (
            ("trusted", True),
            ("active", True),
            ("command", "bash -c true"),
            ("current_observation", {"verdict": "VIOLATION"}),
        ):
            document = profile.to_document()
            document[key] = value
            with self.subTest(key=key):
                with self.assertRaises(ContractError):
                    FrozenSystemProfile.from_document(document)

        with self.assertRaises(ContractError):
            dataclasses.replace(
                profile,
                entrypoints=(_ref(ContractRefKind.TOOL),),
            )
        with self.assertRaises(ContractError):
            dataclasses.replace(profile, created_at="2026-08-14T00:00:00+00:00")
        with self.assertRaises(ContractError):
            dataclasses.replace(profile, expires_at=profile.created_at)
        with self.assertRaises(ContractError):
            dataclasses.replace(
                profile,
                capabilities=tuple(f"capability{i}" for i in range(4097)),
            )
        with self.assertRaises(ContractError):
            dataclasses.replace(
                profile,
                entrypoints=profile.entrypoints * 4097,
            )

    def test_complete_contract_graph_accepts_exact_membership(self):
        recipe = _recipe()
        spec = _golden_spec(recipe)
        bundle = _bundle((spec,))
        profile = _profile((spec,), (bundle,), (recipe,))

        self.assertIsNone(
            validate_frozen_profile_contracts(
                profile,
                oracle_specs=(spec,),
                oracle_bundles=(bundle,),
                execution_recipes=(recipe,),
            )
        )

    def test_graph_rejects_missing_hash_conflicts_and_unapproved_dependencies(self):
        recipe = _recipe()
        spec = _golden_spec(recipe)
        bundle = _bundle((spec,))
        profile = _profile((spec,), (bundle,), (recipe,))

        invalid_calls = (
            {
                "profile": profile,
                "oracle_specs": (),
                "oracle_bundles": (bundle,),
                "execution_recipes": (recipe,),
            },
            {
                "profile": dataclasses.replace(
                    profile,
                    oracle_specs=(
                        ContractRef(
                            ContractRefKind.ORACLE_SPEC,
                            spec.oracle_id,
                            spec.oracle_version,
                            _digest("forged"),
                        ),
                    ),
                ),
                "oracle_specs": (spec,),
                "oracle_bundles": (bundle,),
                "execution_recipes": (recipe,),
            },
        )
        for call in invalid_calls:
            with self.subTest(call=call):
                with self.assertRaises(ContractError):
                    validate_frozen_profile_contracts(**call)

        changed_recipe = _recipe(
            changed_tool=_ref(ContractRefKind.TOOL, salt="unapproved")
        )
        changed_spec = _golden_spec(changed_recipe)
        changed_bundle = _bundle((changed_spec,))
        changed_profile = _profile(
            (changed_spec,),
            (changed_bundle,),
            (changed_recipe,),
            components=profile.components,
        )
        with self.assertRaises(ContractError):
            validate_frozen_profile_contracts(
                changed_profile,
                oracle_specs=(changed_spec,),
                oracle_bundles=(changed_bundle,),
                execution_recipes=(changed_recipe,),
            )

        other_recipe = _recipe(recipe_id="example.other_recipe")
        mismatched_spec = _golden_spec(other_recipe)
        mismatched_bundle = _bundle((mismatched_spec,))
        mismatched_profile = _profile(
            (mismatched_spec,),
            (mismatched_bundle,),
            (recipe,),
        )
        with self.assertRaises(ContractError):
            validate_frozen_profile_contracts(
                mismatched_profile,
                oracle_specs=(mismatched_spec,),
                oracle_bundles=(mismatched_bundle,),
                execution_recipes=(recipe,),
            )

    def test_graph_enforces_capabilities_guards_and_causal_bundle_membership(self):
        recipe = _recipe()
        guard = _golden_spec(recipe, oracle_id="example.guard")
        causal = _causal_spec(recipe, guard)
        missing_guard_bundle = _bundle(
            (causal,),
            role=ControlEvidenceRole.DUAL_ROLE,
            control_oracle=causal.ref,
        )
        missing_guard_profile = _profile(
            (guard, causal),
            (missing_guard_bundle,),
            (recipe,),
        )
        with self.assertRaisesRegex(ContractError, "required_guards"):
            validate_frozen_profile_contracts(
                missing_guard_profile,
                oracle_specs=(guard, causal),
                oracle_bundles=(missing_guard_bundle,),
                execution_recipes=(recipe,),
            )

        bundle = dataclasses.replace(
            missing_guard_bundle,
            required_guards=(guard.ref,),
        )
        profile = _profile((guard, causal), (bundle,), (recipe,))
        validate_frozen_profile_contracts(
            profile,
            oracle_specs=(guard, causal),
            oracle_bundles=(bundle,),
            execution_recipes=(recipe,),
        )

        with self.assertRaises(ContractError):
            validate_frozen_profile_contracts(
                dataclasses.replace(profile, capabilities=("other",)),
                oracle_specs=(guard, causal),
                oracle_bundles=(bundle,),
                execution_recipes=(recipe,),
            )

        wrong_domain_guard = _golden_spec(
            recipe,
            oracle_id="example.guard.performance",
            domain=ConsequenceDomain.PERFORMANCE,
        )
        wrong_causal = _causal_spec(recipe, wrong_domain_guard)
        wrong_bundle = _bundle(
            (wrong_causal,),
            bundle_id="example.wrong_bundle",
            role=ControlEvidenceRole.DUAL_ROLE,
            control_oracle=wrong_causal.ref,
        )
        wrong_profile = _profile(
            (wrong_domain_guard, wrong_causal),
            (wrong_bundle,),
            (recipe,),
        )
        with self.assertRaises(ContractError):
            validate_frozen_profile_contracts(
                wrong_profile,
                oracle_specs=(wrong_domain_guard, wrong_causal),
                oracle_bundles=(wrong_bundle,),
                execution_recipes=(recipe,),
            )

        hidden_causal_bundle = OracleBundle(
            bundle_id="example.hidden_causal",
            bundle_version="1.0.0",
            required_guards=(),
            primary_oracles=(guard.ref,),
            supporting_oracles=(causal.ref,),
            primary_combination=PrimaryCombination.ALL,
            k=None,
            control_evidence_role=ControlEvidenceRole.ORACLE_ONLY,
            control_oracle=None,
            primary_metric_oracle=None,
            multiplicity_policy=None,
        )
        hidden_profile = _profile(
            (guard, causal),
            (hidden_causal_bundle,),
            (recipe,),
        )
        with self.assertRaises(ContractError):
            validate_frozen_profile_contracts(
                hidden_profile,
                oracle_specs=(guard, causal),
                oracle_bundles=(hidden_causal_bundle,),
                execution_recipes=(recipe,),
            )

        causal_guard = dataclasses.replace(
            _causal_spec(recipe, guard, oracle_id="example.causal_guard"),
            consequence_domain=ConsequenceDomain.CORRECTNESS,
        )
        guarded_by_causal = _causal_spec(
            recipe,
            causal_guard,
            oracle_id="example.guarded_by_causal",
        )
        causal_guard_bundle = _bundle(
            (guarded_by_causal,),
            bundle_id="example.causal_guard_bundle",
            role=ControlEvidenceRole.DUAL_ROLE,
            control_oracle=guarded_by_causal.ref,
        )
        causal_guard_profile = _profile(
            (guard, causal_guard, guarded_by_causal),
            (causal_guard_bundle,),
            (recipe,),
        )
        with self.assertRaises(ContractError):
            validate_frozen_profile_contracts(
                causal_guard_profile,
                oracle_specs=(guard, causal_guard, guarded_by_causal),
                oracle_bundles=(causal_guard_bundle,),
                execution_recipes=(recipe,),
            )

    def test_hash_bound_cycle_shaped_guard_rebinding_fails_closed(self):
        recipe = _recipe()
        leaf = _golden_spec(recipe, oracle_id="example.leaf")
        first = _causal_spec(recipe, leaf, oracle_id="example.first")
        second = _causal_spec(recipe, first, oracle_id="example.second")
        rebound_control = dataclasses.replace(
            first.causal_control,
            correctness_guard=second.ref,
        )
        rebound_first = dataclasses.replace(
            first,
            causal_control=rebound_control,
        )
        bundle = _bundle(
            (rebound_first,),
            bundle_id="example.cycle_attempt",
            role=ControlEvidenceRole.DUAL_ROLE,
            control_oracle=rebound_first.ref,
        )
        profile = _profile(
            (leaf, rebound_first, second),
            (bundle,),
            (recipe,),
        )
        with self.assertRaises(ContractError):
            validate_frozen_profile_contracts(
                profile,
                oracle_specs=(leaf, rebound_first, second),
                oracle_bundles=(bundle,),
                execution_recipes=(recipe,),
            )

    def test_graph_requires_performance_multiplicity_and_allowlisted_policy(self):
        recipe = _recipe()
        first = _golden_spec(
            recipe,
            oracle_id="example.performance.first",
            domain=ConsequenceDomain.PERFORMANCE,
        )
        second = _golden_spec(
            recipe,
            oracle_id="example.performance.second",
            domain=ConsequenceDomain.RESOURCE,
        )
        missing_policy = _bundle(
            (first, second),
            bundle_id="example.performance.bundle",
        )
        missing_profile = _profile(
            (first, second),
            (missing_policy,),
            (recipe,),
        )
        with self.assertRaises(ContractError):
            validate_frozen_profile_contracts(
                missing_profile,
                oracle_specs=(first, second),
                oracle_bundles=(missing_policy,),
                execution_recipes=(recipe,),
            )

        multiplicity = _ref(
            ContractRefKind.DECISION_POLICY,
            "example.multiplicity",
        )
        valid_bundle = _bundle(
            (first, second),
            bundle_id="example.performance.bundle.approved",
            primary_metric_oracle=first.ref,
            multiplicity_policy=multiplicity,
        )
        profile_without_policy = _profile(
            (first, second),
            (valid_bundle,),
            (recipe,),
            components=_unique_refs(
                first.component_refs,
                second.component_refs,
                recipe.component_refs,
            ),
        )
        with self.assertRaises(ContractError):
            validate_frozen_profile_contracts(
                profile_without_policy,
                oracle_specs=(first, second),
                oracle_bundles=(valid_bundle,),
                execution_recipes=(recipe,),
            )

        valid_profile = _profile(
            (first, second),
            (valid_bundle,),
            (recipe,),
        )
        validate_frozen_profile_contracts(
            valid_profile,
            oracle_specs=(first, second),
            oracle_bundles=(valid_bundle,),
            execution_recipes=(recipe,),
        )

    def test_all_new_contract_modules_have_only_pure_imports_and_no_eval(self):
        allowed_absolute_roots = {
            "__future__",
            "dataclasses",
            "datetime",
            "enum",
            "hashlib",
            "json",
            "re",
            "typing",
            "unicodedata",
        }
        allowed_contract_siblings = {
            "base",
            "case",
            "execution",
            "evidence",
            "oracle",
            "outcome",
            "plan",
            "profile",
            "receipt",
            "references",
            "status",
            "snapshot",
        }
        for relative_path in (
            "src/validation_core/contracts/base.py",
            "src/validation_core/contracts/references.py",
            "src/validation_core/contracts/execution.py",
            "src/validation_core/contracts/oracle.py",
            "src/validation_core/contracts/profile.py",
            "src/validation_core/contracts/case.py",
            "src/validation_core/contracts/plan.py",
            "src/validation_core/contracts/status.py",
            "src/validation_core/contracts/evidence.py",
            "src/validation_core/contracts/receipt.py",
            "src/validation_core/contracts/outcome.py",
            "src/validation_core/contracts/snapshot.py",
        ):
            with self.subTest(relative_path=relative_path):
                tree = ast.parse(Path(relative_path).read_text(encoding="utf-8"))
                for node in ast.walk(tree):
                    if isinstance(node, ast.Import):
                        for alias in node.names:
                            self.assertIn(
                                alias.name.split(".", 1)[0],
                                allowed_absolute_roots,
                            )
                    elif isinstance(node, ast.ImportFrom):
                        if node.level == 0:
                            self.assertIn(
                                (node.module or "").split(".", 1)[0],
                                allowed_absolute_roots,
                            )
                        else:
                            self.assertEqual(node.level, 1)
                            self.assertIn(
                                node.module,
                                allowed_contract_siblings,
                            )
                    elif (
                        isinstance(node, ast.Call)
                        and isinstance(node.func, ast.Name)
                    ):
                        self.assertNotIn(
                            node.func.id,
                            {"eval", "exec", "compile", "__import__"},
                        )

    def test_every_top_level_parser_rejects_duplicate_json_keys(self):
        recipe = _recipe()
        spec = _golden_spec(recipe)
        bundle = _bundle((spec,))
        profile = _profile((spec,), (bundle,), (recipe,))
        parsers_and_documents = (
            (ExecutionRecipe.from_json, recipe.to_document()),
            (OracleSpec.from_json, spec.to_document()),
            (OracleBundle.from_json, bundle.to_document()),
            (FrozenSystemProfile.from_json, profile.to_document()),
        )
        for parser, document in parsers_and_documents:
            encoded = json.dumps(document, separators=(",", ":"))
            duplicate = (
                '{"contract_kind":"forged",' + encoded.lstrip("{")
            ).encode("utf-8")
            with self.subTest(parser=parser.__qualname__):
                with self.assertRaises(ContractError):
                    parser(duplicate)


if __name__ == "__main__":
    unittest.main()

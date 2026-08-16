import copy
import dataclasses
import hashlib
import json
import unittest

from src.validation_core.contracts.base import ContractError
from src.validation_core.contracts.case import (
    CasePlan,
    CaseSubmission,
    CaseSubmissionKind,
    RepairSelection,
    TargetEvidenceSelection,
    ValidationInstanceIdentity,
    WorkloadSelection,
    compute_validation_instance_id,
    validate_case_plan_membership,
    validate_case_submission_membership,
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
)
from src.validation_core.contracts.references import (
    ArtifactRef,
    ContractRef,
    ContractRefKind,
)


def _digest(value):
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _ref(kind, name, *, salt="default"):
    return ContractRef(
        kind=kind,
        contract_id=f"example.{name}",
        contract_version="1.0.0",
        content_sha256=_digest(f"{kind.value}:{name}:{salt}"),
    )


def _artifact(role, *, salt=None):
    value = salt or role
    return ArtifactRef(
        role=role,
        media_type="application/json",
        size_bytes=len(value),
        content_sha256=_digest(value),
    )


def _base_spec_values(*, oracle_id, method, variants, role, causal_control):
    return {
        "oracle_id": oracle_id,
        "oracle_version": "1.0.0",
        "declared_origin": OracleOrigin.MAINTAINER_PRESET,
        "consequence_domain": ConsequenceDomain.CORRECTNESS,
        "method": method,
        "applicability": ApplicabilitySpec(
            domain_id="example.domain",
            calibrated_domain=_artifact(
                "calibrated_domain",
                salt=f"domain.{oracle_id}",
            ),
            required_capabilities=("generic.execution",),
            out_of_domain_reason="DOMAIN_MISMATCH",
        ),
        "variants": variants,
        "collectors": (_ref(ContractRefKind.COLLECTOR, "collector"),),
        "normalizer": _ref(ContractRefKind.NORMALIZER, "normalizer"),
        "comparator": _ref(ContractRefKind.COMPARATOR, "comparator"),
        "execution_protocol": ExecutionProtocol(
            warmup_runs=0,
            repetitions=1,
            quorum=QuorumSpec(required=1, total=1),
            timeout_ms=10_000,
            max_retries=1,
            retry_reasons=(RetryReason.ENVIRONMENT_FINGERPRINT_DRIFT,),
        ),
        "healthy_relation": _ref(
            ContractRefKind.HEALTHY_RELATION_POLICY,
            "healthy",
        ),
        "decision_policy": _ref(
            ContractRefKind.DECISION_POLICY,
            "decision",
        ),
        "qualification_policy": _ref(
            ContractRefKind.QUALIFICATION_POLICY,
            "qualification",
        ),
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
        "control_evidence_role": role,
        "causal_control": causal_control,
    }


def _golden_spec(recipe, *, oracle_id="example.guard"):
    candidate = OracleVariant(
        variant_id="candidate",
        role=VariantRole.CANDIDATE,
        execution_recipe=recipe,
    )
    return OracleSpec(
        **_base_spec_values(
            oracle_id=oracle_id,
            method=GoldenMethod(
                candidate_variant_id="candidate",
                expected_artifact=_artifact(
                    "golden",
                    salt=f"golden.{oracle_id}",
                ),
            ),
            variants=(candidate,),
            role=ControlEvidenceRole.ORACLE_ONLY,
            causal_control=None,
        )
    )


def _causal_spec(candidate_recipe, control_recipe, guard, target_policy):
    candidate = OracleVariant(
        variant_id="candidate",
        role=VariantRole.CANDIDATE,
        execution_recipe=candidate_recipe,
    )
    control = OracleVariant(
        variant_id="control",
        role=VariantRole.CONTROL,
        execution_recipe=control_recipe,
    )
    causal_control = CausalControlSpec(
        control_variant_id="control",
        control_policy=_ref(ContractRefKind.CONTROL_POLICY, "control"),
        causal_prediction=_ref(
            ContractRefKind.HEALTHY_RELATION_POLICY,
            "causal-prediction",
        ),
        correctness_guard=guard.ref,
        target_association=target_policy,
        reuse_policy=_ref(ContractRefKind.CONTROL_POLICY, "reuse"),
    )
    return OracleSpec(
        **_base_spec_values(
            oracle_id="example.causal",
            method=DifferentialMethod(
                candidate_variant_id="candidate",
                reference_variant_id="control",
            ),
            variants=(candidate, control),
            role=ControlEvidenceRole.DUAL_ROLE,
            causal_control=causal_control,
        )
    )


def _graph(*, causal=False):
    primary_recipe = _ref(ContractRefKind.EXECUTION_RECIPE, "recipe.primary")
    control_recipe = _ref(ContractRefKind.EXECUTION_RECIPE, "recipe.control")
    guard_recipe = _ref(ContractRefKind.EXECUTION_RECIPE, "recipe.guard")
    unused_recipe = _ref(ContractRefKind.EXECUTION_RECIPE, "recipe.unused")
    target_policy = _ref(
        ContractRefKind.TARGET_EVIDENCE_POLICY,
        "target",
    )
    alternate_target_policy = _ref(
        ContractRefKind.TARGET_EVIDENCE_POLICY,
        "target.alternate",
    )
    repair_policy = _ref(ContractRefKind.REPAIR_POLICY, "repair")
    resource_policy = _ref(ContractRefKind.RESOURCE_POLICY, "resource")
    guard = _golden_spec(guard_recipe if causal else primary_recipe)
    if causal:
        primary = _causal_spec(
            primary_recipe,
            control_recipe,
            guard,
            target_policy,
        )
        specs = (guard, primary)
        bundle = OracleBundle(
            bundle_id="example.bundle.causal",
            bundle_version="1.0.0",
            required_guards=(guard.ref,),
            primary_oracles=(primary.ref,),
            supporting_oracles=(),
            primary_combination=PrimaryCombination.ALL,
            k=None,
            control_evidence_role=ControlEvidenceRole.DUAL_ROLE,
            control_oracle=primary.ref,
            primary_metric_oracle=None,
            multiplicity_policy=None,
        )
    else:
        specs = (guard,)
        bundle = OracleBundle(
            bundle_id="example.bundle.oracle-only",
            bundle_version="1.0.0",
            required_guards=(),
            primary_oracles=(guard.ref,),
            supporting_oracles=(),
            primary_combination=PrimaryCombination.ALL,
            k=None,
            control_evidence_role=ControlEvidenceRole.ORACLE_ONLY,
            control_oracle=None,
            primary_metric_oracle=None,
            multiplicity_policy=None,
        )

    component_values = (
        resource_policy,
        target_policy,
        alternate_target_policy,
        repair_policy,
        *(ref for spec in specs for ref in spec.component_refs),
        *bundle.component_refs,
    )
    components = {
        (ref.kind, ref.contract_id, ref.contract_version): ref
        for ref in component_values
    }
    profile = FrozenSystemProfile(
        profile_id="example.profile",
        profile_version="1.0.0",
        project=ProjectBinding(
            system_id="example.project",
            project_kind="example",
            source_snapshot_sha256=_digest("snapshot"),
            dependency_manifest_sha256=_digest("dependencies"),
        ),
        environment=EnvironmentBinding(
            os_image_sha256=_digest("os"),
            toolchain_sha256=_digest("toolchain"),
            hardware_fingerprint_sha256=None,
            model_sha256=None,
            device_policy_sha256=None,
            resource_policy=resource_policy,
        ),
        entrypoints=(_ref(ContractRefKind.ENTRYPOINT, "entry"),),
        workload_schemas=(
            _ref(ContractRefKind.WORKLOAD_SCHEMA, "workload"),
        ),
        adapters=(_ref(ContractRefKind.ADAPTER, "adapter"),),
        instrumentation_providers=(
            _ref(
                ContractRefKind.INSTRUMENTATION_PROVIDER,
                "instrumentation",
            ),
        ),
        oracle_specs=tuple(spec.ref for spec in specs),
        oracle_bundles=(bundle.ref,),
        execution_recipes=(
            primary_recipe,
            control_recipe,
            guard_recipe,
            unused_recipe,
        ),
        components=tuple(components.values()),
        capabilities=("generic.execution",),
        qualification_report_sha256=_digest("qualification-report"),
        review_sha256=_digest("review"),
        approval_sha256=_digest("approval"),
        created_at="2026-08-14T00:00:00Z",
        expires_at=None,
    )
    identity = ValidationInstanceIdentity(
        project_id=profile.project.system_id,
        case_id="bug-123",
        function_id="scheduler::choose_block",
        snapshot_sha256=profile.project.source_snapshot_sha256,
        reasoning_sha256=_digest("reasoning"),
        profile_sha256=profile.content_sha256,
    )
    return {
        "profile": profile,
        "identity": identity,
        "specs": specs,
        "bundle": bundle,
        "primary_recipe": primary_recipe,
        "control_recipe": control_recipe,
        "guard_recipe": guard_recipe,
        "unused_recipe": unused_recipe,
        "target_policy": target_policy,
        "alternate_target_policy": alternate_target_policy,
        "repair_policy": repair_policy,
    }


def _plan(graph, *, repair=True, causal_control_id=None, changes=None):
    workload = _artifact("workload")
    expected_input = _artifact("expected_input")
    predicted_output = _artifact("predicted_buggy_output")
    patch = _artifact("patch")
    values = {
        "validation_instance_id": graph["identity"].validation_instance_id,
        "case_id": graph["identity"].case_id,
        "function_id": graph["identity"].function_id,
        "reasoning_sha256": graph["identity"].reasoning_sha256,
        "profile": graph["profile"].ref,
        "entrypoint": graph["profile"].entrypoints[0],
        "primary_execution_recipe": graph["primary_recipe"],
        "workload": WorkloadSelection(
            schema=graph["profile"].workload_schemas[0],
            artifact=workload,
        ),
        "target_evidence": TargetEvidenceSelection(
            policy=graph["target_policy"],
            expected_input=expected_input,
            predicted_buggy_output=predicted_output,
        ),
        "oracle_bundle": graph["bundle"].ref,
        "causal_control_id": causal_control_id,
        "repair": (
            RepairSelection(policy=graph["repair_policy"], patch=patch)
            if repair
            else None
        ),
        "artifacts": (_artifact("request_trace"),),
        "notes": "bash -c appears only as inert explanatory text",
    }
    if changes:
        values.update(changes)
    return CasePlan(**values)


def _candidate(plan, *, attempts=1):
    return CaseSubmission(
        submission_kind=CaseSubmissionKind.CANDIDATE,
        validation_instance_id=plan.validation_instance_id,
        case_id=plan.case_id,
        function_id=plan.function_id,
        reasoning_sha256=plan.reasoning_sha256,
        attempts=attempts,
        notes=plan.notes,
        case_plan=plan,
    )


class ValidationCaseContractTests(unittest.TestCase):
    def test_validation_instance_id_uses_the_exact_authority_preimage(self):
        values = {
            "project_id": "project.example",
            "case_id": "bug-123",
            "function_id": "scheduler::choose_block",
            "snapshot_sha256": "1" * 64,
            "reasoning_sha256": "2" * 64,
            "profile_sha256": "3" * 64,
        }
        identity = ValidationInstanceIdentity(**values)

        self.assertEqual(
            identity.validation_instance_id,
            "9088c2651dace3b8fdb67921a9c0539ea816a59fc9fbd277715cfb5f3e796401",
        )
        self.assertEqual(
            compute_validation_instance_id(**values),
            identity.validation_instance_id,
        )
        for field in values:
            changed = dict(values)
            changed[field] = (
                f"changed.{field}"
                if field in {"project_id", "case_id", "function_id"}
                else "4" * 64
            )
            with self.subTest(field=field):
                self.assertNotEqual(
                    compute_validation_instance_id(**changed),
                    identity.validation_instance_id,
                )

    def test_candidate_and_not_confirmed_round_trip_as_strict_v4_union(self):
        graph = _graph()
        plan = _plan(graph)
        candidate = _candidate(plan)
        not_confirmed = CaseSubmission(
            submission_kind=CaseSubmissionKind.NOT_CONFIRMED,
            validation_instance_id=graph["identity"].validation_instance_id,
            case_id=graph["identity"].case_id,
            function_id=graph["identity"].function_id,
            reasoning_sha256=graph["identity"].reasoning_sha256,
            attempts=2,
            notes="no reproducible case",
        )

        for submission in (candidate, not_confirmed):
            with self.subTest(kind=submission.submission_kind.value):
                rebuilt = CaseSubmission.from_json(
                    json.dumps(submission.to_document()).encode("utf-8")
                )
                self.assertEqual(rebuilt, submission)
                self.assertEqual(rebuilt.content_sha256, submission.content_sha256)
                self.assertEqual(rebuilt.ref.kind, ContractRefKind.CASE_SUBMISSION)
                self.assertEqual(rebuilt.ref.contract_id, submission.content_sha256)
                self.assertEqual(rebuilt.ref.contract_version, "4")
        self.assertIn("case_plan", candidate.to_document())
        self.assertNotIn("case_plan", not_confirmed.to_document())

    def test_case_plan_is_frozen_canonical_and_content_addressed(self):
        graph = _graph()
        additional = [_artifact("z_extra"), _artifact("a_extra")]
        plan = _plan(graph, changes={"artifacts": additional})
        digest = plan.content_sha256
        additional.append(_artifact("late"))

        self.assertEqual(
            [artifact.role for artifact in plan.artifacts],
            ["a_extra", "z_extra"],
        )
        self.assertEqual(plan.content_sha256, digest)
        self.assertEqual(CasePlan.from_document(plan.to_document()), plan)
        self.assertIn("primary_execution_recipe", plan.to_document())
        self.assertNotIn("execution_recipe", plan.to_document())
        self.assertEqual(plan.ref.kind, ContractRefKind.CASE_PLAN)
        self.assertEqual(plan.ref.contract_id, digest)
        self.assertEqual(plan.ref.contract_version, "1")
        self.assertEqual(plan.ref.content_sha256, digest)
        with self.assertRaises(dataclasses.FrozenInstanceError):
            plan.notes = "changed"

        reordered = _plan(
            graph,
            changes={"artifacts": tuple(reversed(plan.artifacts))},
        )
        self.assertEqual(reordered.content_sha256, digest)
        changed = dataclasses.replace(plan, notes="different")
        self.assertNotEqual(changed.ref, plan.ref)

    def test_core_and_additional_artifact_roles_are_globally_unique(self):
        graph = _graph()
        plan = _plan(graph)
        self.assertEqual([item.role for item in plan.artifacts], ["request_trace"])

        duplicate_core = _artifact("workload", salt="additional-copy")
        with self.assertRaisesRegex(ContractError, "globally unique"):
            _plan(graph, changes={"artifacts": (duplicate_core,)})
        duplicate_additional = _artifact("extra")
        with self.assertRaisesRegex(ContractError, "globally unique"):
            _plan(
                graph,
                changes={"artifacts": (duplicate_additional, duplicate_additional)},
            )
        with self.assertRaisesRegex(ContractError, "globally unique"):
            _plan(
                graph,
                changes={
                    "target_evidence": TargetEvidenceSelection(
                        policy=graph["target_policy"],
                        expected_input=_artifact("workload", salt="input"),
                        predicted_buggy_output=_artifact("predicted"),
                    )
                },
            )

    def test_authority_recomputes_claimed_id_and_matches_all_frozen_identity(self):
        graph = _graph()
        plan = _plan(graph)
        submission = _candidate(plan)
        kwargs = {
            "identity": graph["identity"],
            "profile": graph["profile"],
            "oracle_bundle": graph["bundle"],
            "oracle_specs": graph["specs"],
        }
        validate_case_plan_membership(plan, **kwargs)
        validate_case_submission_membership(submission, **kwargs)

        identity = graph["identity"]
        replacements = {
            "project_id": "different.project",
            "case_id": "bug-999",
            "function_id": "different::function",
            "snapshot_sha256": _digest("different-snapshot"),
            "reasoning_sha256": _digest("different-reasoning"),
            "profile_sha256": _digest("different-profile"),
        }
        for field, value in replacements.items():
            with self.subTest(field=field), self.assertRaises(ContractError):
                validate_case_plan_membership(
                    plan,
                    **{**kwargs, "identity": dataclasses.replace(identity, **{field: value})},
                )

        forged = dataclasses.replace(plan, validation_instance_id="f" * 64)
        with self.assertRaisesRegex(ContractError, "authoritative context"):
            validate_case_plan_membership(forged, **kwargs)

    def test_not_confirmed_authority_check_never_requires_a_plan_graph(self):
        graph = _graph()
        submission = CaseSubmission(
            submission_kind=CaseSubmissionKind.NOT_CONFIRMED,
            validation_instance_id=graph["identity"].validation_instance_id,
            case_id=graph["identity"].case_id,
            function_id=graph["identity"].function_id,
            reasoning_sha256=graph["identity"].reasoning_sha256,
            attempts=1,
            notes="none",
        )
        validate_case_submission_membership(
            submission,
            identity=graph["identity"],
            profile=graph["profile"],
        )
        with self.assertRaisesRegex(ContractError, "authoritative context"):
            validate_case_submission_membership(
                dataclasses.replace(submission, validation_instance_id="f" * 64),
                identity=graph["identity"],
                profile=graph["profile"],
            )

    def test_profile_and_oracle_graph_membership_is_exact(self):
        graph = _graph()
        plan = _plan(graph)
        kwargs = {
            "identity": graph["identity"],
            "profile": graph["profile"],
            "oracle_bundle": graph["bundle"],
            "oracle_specs": graph["specs"],
        }
        invalid_plans = (
            dataclasses.replace(
                plan,
                entrypoint=_ref(ContractRefKind.ENTRYPOINT, "unauthorized"),
            ),
            dataclasses.replace(
                plan,
                primary_execution_recipe=_ref(
                    ContractRefKind.EXECUTION_RECIPE,
                    "unauthorized",
                ),
            ),
            dataclasses.replace(
                plan,
                workload=dataclasses.replace(
                    plan.workload,
                    schema=_ref(
                        ContractRefKind.WORKLOAD_SCHEMA,
                        "unauthorized",
                    ),
                ),
            ),
            dataclasses.replace(
                plan,
                oracle_bundle=_ref(
                    ContractRefKind.ORACLE_BUNDLE,
                    "unauthorized",
                ),
            ),
            dataclasses.replace(
                plan,
                target_evidence=dataclasses.replace(
                    plan.target_evidence,
                    policy=_ref(
                        ContractRefKind.TARGET_EVIDENCE_POLICY,
                        "unauthorized",
                    ),
                ),
            ),
            dataclasses.replace(
                plan,
                repair=dataclasses.replace(
                    plan.repair,
                    policy=_ref(ContractRefKind.REPAIR_POLICY, "unauthorized"),
                ),
            ),
        )
        for invalid in invalid_plans:
            with self.subTest(field=invalid), self.assertRaises(ContractError):
                validate_case_plan_membership(invalid, **kwargs)

        with self.assertRaisesRegex(ContractError, "candidate recipe"):
            validate_case_plan_membership(
                dataclasses.replace(
                    plan,
                    primary_execution_recipe=graph["unused_recipe"],
                ),
                **kwargs,
            )
        with self.assertRaisesRegex(ContractError, "unresolved"):
            validate_case_plan_membership(
                plan,
                **{**kwargs, "oracle_specs": ()},
            )

        extra_spec = _golden_spec(
            graph["primary_recipe"],
            oracle_id="example.extra-approved-but-unselected",
        )
        expanded_profile = dataclasses.replace(
            graph["profile"],
            oracle_specs=graph["profile"].oracle_specs + (extra_spec.ref,),
        )
        expanded_identity = dataclasses.replace(
            graph["identity"],
            profile_sha256=expanded_profile.content_sha256,
        )
        expanded_plan = dataclasses.replace(
            plan,
            validation_instance_id=expanded_identity.validation_instance_id,
            profile=expanded_profile.ref,
        )
        with self.assertRaisesRegex(ContractError, "exactly equal"):
            validate_case_plan_membership(
                expanded_plan,
                identity=expanded_identity,
                profile=expanded_profile,
                oracle_bundle=graph["bundle"],
                oracle_specs=graph["specs"] + (extra_spec,),
            )

    def test_oracle_only_and_causal_control_selection_are_unambiguous(self):
        oracle_graph = _graph()
        oracle_plan = _plan(oracle_graph)
        oracle_kwargs = {
            "identity": oracle_graph["identity"],
            "profile": oracle_graph["profile"],
            "oracle_bundle": oracle_graph["bundle"],
            "oracle_specs": oracle_graph["specs"],
        }
        validate_case_plan_membership(oracle_plan, **oracle_kwargs)
        with self.assertRaisesRegex(ContractError, "requires causal_control_id"):
            validate_case_plan_membership(
                dataclasses.replace(oracle_plan, causal_control_id="control"),
                **oracle_kwargs,
            )

        causal_graph = _graph(causal=True)
        causal_plan = _plan(causal_graph, causal_control_id="control")
        causal_kwargs = {
            "identity": causal_graph["identity"],
            "profile": causal_graph["profile"],
            "oracle_bundle": causal_graph["bundle"],
            "oracle_specs": causal_graph["specs"],
        }
        validate_case_plan_membership(causal_plan, **causal_kwargs)
        for recipe_name in ("control_recipe", "guard_recipe"):
            with self.subTest(recipe=recipe_name), self.assertRaisesRegex(
                ContractError,
                "candidate recipe",
            ):
                validate_case_plan_membership(
                    dataclasses.replace(
                        causal_plan,
                        primary_execution_recipe=causal_graph[recipe_name],
                    ),
                    **causal_kwargs,
                )
        with self.assertRaisesRegex(ContractError, "sole control"):
            validate_case_plan_membership(
                dataclasses.replace(causal_plan, causal_control_id="other"),
                **causal_kwargs,
            )
        wrong_target = dataclasses.replace(
            causal_plan,
            target_evidence=dataclasses.replace(
                causal_plan.target_evidence,
                policy=causal_graph["alternate_target_policy"],
            ),
        )
        with self.assertRaisesRegex(ContractError, "control association"):
            validate_case_plan_membership(wrong_target, **causal_kwargs)

    def test_union_and_nested_schemas_are_exact_and_fail_closed(self):
        graph = _graph()
        plan = _plan(graph)
        candidate_document = _candidate(plan).to_document()
        not_confirmed_document = copy.deepcopy(candidate_document)
        not_confirmed_document["submission_kind"] = "not_confirmed"
        not_confirmed_document.pop("case_plan")

        invalid_documents = []
        value = copy.deepcopy(not_confirmed_document)
        value["case_plan"] = plan.to_document()
        invalid_documents.append(value)
        value = copy.deepcopy(candidate_document)
        value.pop("case_plan")
        invalid_documents.append(value)
        value = copy.deepcopy(candidate_document)
        value["verdict"] = "VIOLATION"
        invalid_documents.append(value)
        value = copy.deepcopy(candidate_document)
        value["schema_version"] = True
        invalid_documents.append(value)
        value = copy.deepcopy(candidate_document)
        value["attempts"] = True
        invalid_documents.append(value)
        value = copy.deepcopy(candidate_document)
        value["case_plan"]["target_evidence"]["threshold"] = "0.1"
        invalid_documents.append(value)
        value = copy.deepcopy(candidate_document)
        value["case_plan"]["command"] = "bash -c whoami"
        invalid_documents.append(value)
        value = copy.deepcopy(candidate_document)
        value["case_plan"]["execution_recipe"] = value["case_plan"].pop(
            "primary_execution_recipe"
        )
        invalid_documents.append(value)

        for index, document in enumerate(invalid_documents):
            with self.subTest(index=index), self.assertRaises(ContractError):
                CaseSubmission.from_document(document)
        with self.assertRaises(ContractError):
            CaseSubmission.from_json(
                b'{"submission_kind":"not_confirmed",'
                b'"submission_kind":"candidate"}'
            )
        encoded_plan = json.dumps(
            plan.to_document(), separators=(",", ":")
        )
        with self.assertRaises(ContractError):
            CasePlan.from_json(
                ('{"contract_kind":"forged",' + encoded_plan.lstrip("{")).encode(
                    "utf-8"
                )
            )
        with self.assertRaises(ContractError):
            CaseSubmission.from_json(
                json.dumps(not_confirmed_document)
                .replace('"attempts": 1', '"attempts": 1.5')
                .encode("utf-8")
            )

    def test_case_plan_has_no_agent_supplied_execution_or_decision_fields(self):
        field_names = {field.name for field in dataclasses.fields(CasePlan)}
        forbidden = {
            "verdict",
            "observation",
            "threshold",
            "normalizer",
            "comparator",
            "matcher",
            "command",
            "argv",
            "env",
            "permissions",
            "workspace",
            "path",
        }
        self.assertTrue(forbidden.isdisjoint(field_names))
        # Human notes may mention executable syntax, but remain inert data.
        self.assertIn("bash -c", _plan(_graph()).notes)


if __name__ == "__main__":
    unittest.main()

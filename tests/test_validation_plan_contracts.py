import ast
import copy
import dataclasses
import hashlib
import json
from pathlib import Path
import unittest

import src.validation_core as production_root
from src.validation_core.contracts.base import CanonicalDecimal, ContractError
from src.validation_core.contracts.case import validate_case_plan_membership
from src.validation_core.contracts.oracle import (
    ControlEvidenceRole,
    DifferentialMethod,
    ExecutionProtocol,
    ConsequenceDomain,
    CrossGateReproducibility,
    OracleSpec,
    OracleVariant,
    QuorumSpec,
    ReproducibilityMode,
    RetryReason,
    StatisticalBaselineMethod,
    VariantRole,
)
from src.validation_core.contracts.plan import (
    BaselineCandidate,
    BaselineEligibility,
    BaselineSelectionReceipt,
    BaselineSourceKind,
    DynamicBindingRequest,
    DynamicResourceBinding,
    DynamicResourceKind,
    ExecutionBinding,
    ExperimentPhase,
    ExperimentPlanTemplate,
    ExperimentStep,
    GateRole,
    PlannedOracleExecution,
    validate_b1_b2_binding_equivalence,
    validate_execution_binding,
    validate_experiment_plan_membership,
    validate_template_baseline_selections,
    validate_template_determinism,
)
from src.validation_core.contracts.references import ContractRef, ContractRefKind
from tests.test_validation_case_contracts import (
    _base_spec_values as _case_spec_values,
    _graph as _case_graph,
    _plan as _case_plan,
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


def _baseline_candidate(
    source_id="history",
    *,
    eligibility=BaselineEligibility.ELIGIBLE,
    kind=BaselineSourceKind.MATCHED_TREND,
):
    return BaselineCandidate(
        source_id=source_id,
        source_kind=kind,
        source_sha256=_digest(f"source:{source_id}"),
        eligibility=eligibility,
        static_eligibility_facts_sha256=_digest(f"eligibility:{source_id}"),
    )


def _receipt(
    *,
    oracle=None,
    profile=None,
    case_plan=None,
    instance=None,
    candidates=None,
    selected_source_id="history",
    baseline_policy=None,
    healthy_relation=None,
):
    return BaselineSelectionReceipt(
        validation_instance_id=instance or _digest("instance-1"),
        profile=profile or _ref(ContractRefKind.FROZEN_PROFILE, "profile"),
        case_plan=case_plan or _ref(ContractRefKind.CASE_PLAN, "case"),
        oracle_spec=oracle or _ref(ContractRefKind.ORACLE_SPEC, "oracle"),
        baseline_policy=baseline_policy
        or _ref(ContractRefKind.BASELINE_POLICY, "baseline"),
        healthy_relation=healthy_relation
        or _ref(ContractRefKind.HEALTHY_RELATION_POLICY, "healthy"),
        static_selection_inputs_sha256=_digest("selection-inputs"),
        candidates=(
            (_baseline_candidate(),) if candidates is None else candidates
        ),
        selected_source_id=selected_source_id,
    )


def _protocol(*, repetitions=3, timeout_ms=30_000):
    return ExecutionProtocol(
        warmup_runs=1,
        repetitions=repetitions,
        quorum=QuorumSpec(required=2 if repetitions >= 2 else 1, total=repetitions),
        timeout_ms=timeout_ms,
        max_retries=1,
        retry_reasons=(RetryReason.BROKER_LEASE_LOST,),
    )


def _planned_oracle(name="oracle", *, baseline=None, seed=41, protocol=None):
    return PlannedOracleExecution(
        oracle_spec=_ref(ContractRefKind.ORACLE_SPEC, name),
        collectors=(
            _ref(ContractRefKind.COLLECTOR, f"{name}.trace"),
            _ref(ContractRefKind.COLLECTOR, f"{name}.process"),
        ),
        normalizer=_ref(ContractRefKind.NORMALIZER, f"{name}.normalizer"),
        comparator=_ref(ContractRefKind.COMPARATOR, f"{name}.comparator"),
        protocol=protocol or _protocol(),
        fixed_seed=seed,
        reset_policy=_ref(ContractRefKind.RESET_POLICY, f"{name}.reset"),
        baseline_selection=None if baseline is None else baseline.ref,
    )


def _step(
    step_id="run",
    *,
    oracle=None,
    phase=ExperimentPhase.ORACLE_EXPERIMENT,
    depends_on=(),
    variant_role=VariantRole.CANDIDATE,
):
    oracle_ref = oracle or _ref(ContractRefKind.ORACLE_SPEC, "oracle")
    return ExperimentStep(
        step_id=step_id,
        phase=phase,
        execution_recipe=_ref(ContractRefKind.EXECUTION_RECIPE, "recipe"),
        variant_id=(
            "candidate"
            if phase
            in (
                ExperimentPhase.ORACLE_EXPERIMENT,
                ExperimentPhase.CAUSAL_CONTROL,
                ExperimentPhase.REPAIR_ORACLE_EXPERIMENT,
            )
            else None
        ),
        variant_role=(
            variant_role
            if phase
            in (
                ExperimentPhase.ORACLE_EXPERIMENT,
                ExperimentPhase.CAUSAL_CONTROL,
                ExperimentPhase.REPAIR_ORACLE_EXPERIMENT,
            )
            else None
        ),
        oracle_spec=(
            oracle_ref
            if phase
            in (
                ExperimentPhase.ORACLE_EXPERIMENT,
                ExperimentPhase.CAUSAL_CONTROL,
                ExperimentPhase.REPAIR_ORACLE_EXPERIMENT,
            )
            else None
        ),
        depends_on=depends_on,
    )


def _request(symbol="workspace.project", kind=DynamicResourceKind.WORKSPACE):
    return DynamicBindingRequest(
        symbol=symbol,
        resource_kind=kind,
        equivalence_policy=_ref(
            ContractRefKind.EXECUTION_EQUIVALENCE_POLICY,
            f"equivalence.{kind.value}",
        ),
    )


def _template(
    *,
    oracle_executions=None,
    steps=None,
    requests=None,
    profile=None,
    case_plan=None,
    instance=None,
):
    if oracle_executions is None:
        oracle_executions = (_planned_oracle(),)
    if steps is None:
        steps = (_step(oracle=oracle_executions[0].oracle_spec),)
    if requests is None:
        requests = (
            _request(),
            _request("network.api", DynamicResourceKind.LOOPBACK_PORT),
        )
    return ExperimentPlanTemplate(
        validation_instance_id=instance or _digest("instance-1"),
        profile=profile or _ref(ContractRefKind.FROZEN_PROFILE, "profile"),
        case_plan=case_plan or _ref(ContractRefKind.CASE_PLAN, "case"),
        adapter=_ref(ContractRefKind.ADAPTER, "adapter"),
        oracle_bundle=_ref(ContractRefKind.ORACLE_BUNDLE, "bundle"),
        oracle_executions=oracle_executions,
        steps=steps,
        dynamic_requests=requests,
    )


def _resource(
    request,
    role,
    *,
    allocation_id=None,
    equivalence_fingerprint=None,
    port=None,
):
    if port is None and request.resource_kind is DynamicResourceKind.LOOPBACK_PORT:
        port = 31_000 if role is GateRole.B1 else 31_001
    return DynamicResourceBinding(
        symbol=request.symbol,
        resource_kind=request.resource_kind,
        broker_id="broker.primary",
        allocation_id=allocation_id or f"{role.value}.{request.symbol}",
        resource_fingerprint_sha256=_digest(
            f"resource:{role.value}:{request.symbol}"
        ),
        equivalence_policy=request.equivalence_policy,
        equivalence_fingerprint_sha256=(
            equivalence_fingerprint or _digest(f"equivalent:{request.symbol}")
        ),
        loopback_port=port,
    )


def _binding(
    template,
    role,
    *,
    resources=None,
    receipt=None,
    attempt_id="attempt-1",
):
    if resources is None:
        resources = tuple(
            _resource(request, role) for request in template.dynamic_requests
        )
    return ExecutionBinding(
        validation_instance_id=template.validation_instance_id,
        attempt_id=attempt_id,
        role=role,
        template=template.ref,
        resources=resources,
        broker_receipt_sha256=receipt or _digest(f"broker-receipt:{role.value}"),
    )


def _membership_fixture(
    *, causal=True, with_baseline=False, repair=False, causal_only=False
):
    graph = _case_graph(causal=causal)
    specs = graph["specs"]
    bundle = graph["bundle"]
    if causal_only:
        if not causal:
            raise AssertionError("causal_only requires the causal fixture")
        guard = specs[0]
        original = specs[-1]
        candidate = next(
            variant
            for variant in original.variants
            if variant.role is VariantRole.CANDIDATE
        )
        control = next(
            variant
            for variant in original.variants
            if variant.role is VariantRole.CONTROL
        )
        reference = OracleVariant(
            variant_id="reference",
            role=VariantRole.REFERENCE,
            execution_recipe=graph["guard_recipe"],
        )
        causal_only_spec = OracleSpec(
            **_case_spec_values(
                oracle_id="example.causal-only",
                method=DifferentialMethod(
                    candidate_variant_id=candidate.variant_id,
                    reference_variant_id=reference.variant_id,
                ),
                variants=(candidate, reference, control),
                role=ControlEvidenceRole.CAUSAL_ONLY,
                causal_control=original.causal_control,
            )
        )
        specs = (guard, causal_only_spec)
        bundle = dataclasses.replace(
            bundle,
            primary_oracles=(causal_only_spec.ref,),
            control_evidence_role=ControlEvidenceRole.CAUSAL_ONLY,
            control_oracle=causal_only_spec.ref,
        )
    baseline_policy = None
    if with_baseline:
        if causal:
            raise AssertionError("baseline fixture uses the one-Oracle graph")
        baseline_policy = _ref(ContractRefKind.BASELINE_POLICY, "selected-baseline")
        threshold_policy = _ref(
            ContractRefKind.THRESHOLD_POLICY,
            "selected-threshold",
        )
        selected = dataclasses.replace(
            specs[0],
            consequence_domain=ConsequenceDomain.PERFORMANCE,
            method=StatisticalBaselineMethod(
                candidate_variant_id="candidate",
                baseline_variant_id="baseline",
                metric_id="latency.p99",
            ),
            variants=(
                OracleVariant(
                    "candidate",
                    VariantRole.CANDIDATE,
                    graph["primary_recipe"],
                ),
                OracleVariant(
                    "baseline",
                    VariantRole.REFERENCE,
                    graph["control_recipe"],
                ),
            ),
            baseline_policy=baseline_policy,
            threshold_policy=threshold_policy,
            cross_gate_reproducibility=CrossGateReproducibility(
                mode=ReproducibilityMode.STATISTICAL,
                require_same_direction=True,
                require_normalized_equality=False,
                max_effect_delta=CanonicalDecimal("0.1"),
            ),
        )
        specs = (selected,)
        bundle = dataclasses.replace(bundle, primary_oracles=(selected.ref,))

    reset_policy = _ref(ContractRefKind.RESET_POLICY, "experiment-reset")
    equivalence_policy = _ref(
        ContractRefKind.EXECUTION_EQUIVALENCE_POLICY,
        "workspace-equivalence",
    )
    component_values = (
        *graph["profile"].components,
        reset_policy,
        equivalence_policy,
        *(component for spec in specs for component in spec.component_refs),
        *bundle.component_refs,
    )
    components = {
        (reference.kind, reference.contract_id, reference.contract_version): reference
        for reference in component_values
    }
    profile = dataclasses.replace(
        graph["profile"],
        oracle_specs=tuple(spec.ref for spec in specs),
        oracle_bundles=(bundle.ref,),
        components=tuple(components.values()),
    )
    identity = dataclasses.replace(
        graph["identity"],
        profile_sha256=profile.content_sha256,
    )
    plan = _case_plan(
        graph,
        repair=repair,
        causal_control_id="control" if causal else None,
    )
    plan = dataclasses.replace(
        plan,
        validation_instance_id=identity.validation_instance_id,
        profile=profile.ref,
        oracle_bundle=bundle.ref,
    )

    receipts = []
    executions = []
    health_step = ExperimentStep(
        step_id="phase.health",
        phase=ExperimentPhase.SANDBOX_HEALTH,
        execution_recipe=plan.primary_execution_recipe,
        variant_id=None,
        variant_role=None,
        oracle_spec=None,
    )
    replay_step = ExperimentStep(
        step_id="phase.replay",
        phase=ExperimentPhase.REAL_ENTRY_REPLAY,
        execution_recipe=plan.primary_execution_recipe,
        variant_id=None,
        variant_role=None,
        oracle_spec=None,
        depends_on=(health_step.step_id,),
    )
    target_step = ExperimentStep(
        step_id="phase.target",
        phase=ExperimentPhase.TARGET_EVIDENCE,
        execution_recipe=plan.primary_execution_recipe,
        variant_id=None,
        variant_role=None,
        oracle_spec=None,
        depends_on=(replay_step.step_id,),
    )
    steps = [health_step, replay_step, target_step]
    for spec_index, spec in enumerate(specs):
        receipt = None
        if spec.baseline_policy is not None:
            receipt = _receipt(
                oracle=spec.ref,
                profile=profile.ref,
                case_plan=plan.ref,
                instance=plan.validation_instance_id,
                baseline_policy=spec.baseline_policy,
                healthy_relation=spec.healthy_relation,
            )
            receipts.append(receipt)
        executions.append(
            PlannedOracleExecution(
                oracle_spec=spec.ref,
                collectors=spec.collectors,
                normalizer=spec.normalizer,
                comparator=spec.comparator,
                protocol=spec.execution_protocol,
                fixed_seed=100 + spec_index,
                reset_policy=reset_policy,
                baseline_selection=None if receipt is None else receipt.ref,
            )
        )
        for variant in spec.variants:
            steps.append(
                ExperimentStep(
                    step_id=f"step.{spec_index}.{variant.variant_id}",
                    phase=(
                        ExperimentPhase.CAUSAL_CONTROL
                        if variant.role is VariantRole.CONTROL
                        else ExperimentPhase.ORACLE_EXPERIMENT
                    ),
                    execution_recipe=variant.execution_recipe,
                    variant_id=variant.variant_id,
                    variant_role=variant.role,
                    oracle_spec=spec.ref,
                    depends_on=(target_step.step_id,),
                )
            )
    if repair:
        variant_step_ids = tuple(
            step.step_id
            for step in steps
            if step.oracle_spec is not None
        )
        repair_step = ExperimentStep(
            step_id="phase.repair",
            phase=ExperimentPhase.REPAIR,
            execution_recipe=plan.primary_execution_recipe,
            variant_id=None,
            variant_role=None,
            oracle_spec=None,
            depends_on=variant_step_ids,
        )
        build_step = ExperimentStep(
            step_id="phase.build-sanity",
            phase=ExperimentPhase.BUILD_SANITY,
            execution_recipe=plan.primary_execution_recipe,
            variant_id=None,
            variant_role=None,
            oracle_spec=None,
            depends_on=(repair_step.step_id,),
        )
        repair_replay_step = ExperimentStep(
            step_id="phase.repair-replay",
            phase=ExperimentPhase.REPAIR_REAL_ENTRY_REPLAY,
            execution_recipe=plan.primary_execution_recipe,
            variant_id=None,
            variant_role=None,
            oracle_spec=None,
            depends_on=(build_step.step_id,),
        )
        repair_target_step = ExperimentStep(
            step_id="phase.repair-target",
            phase=ExperimentPhase.REPAIR_TARGET_EVIDENCE,
            execution_recipe=plan.primary_execution_recipe,
            variant_id=None,
            variant_role=None,
            oracle_spec=None,
            depends_on=(repair_replay_step.step_id,),
        )
        repair_oracle_steps = []
        for spec_index, spec in enumerate(specs):
            for variant in spec.variants:
                if (
                    spec.control_evidence_role is ControlEvidenceRole.CAUSAL_ONLY
                    and spec.causal_control is not None
                    and variant.variant_id
                    == spec.causal_control.control_variant_id
                ):
                    continue
                repair_oracle_steps.append(
                    ExperimentStep(
                        step_id=f"repair.{spec_index}.{variant.variant_id}",
                        phase=ExperimentPhase.REPAIR_ORACLE_EXPERIMENT,
                        execution_recipe=variant.execution_recipe,
                        variant_id=variant.variant_id,
                        variant_role=variant.role,
                        oracle_spec=spec.ref,
                        depends_on=(repair_target_step.step_id,),
                    )
                )
        regression_step = ExperimentStep(
            step_id="phase.regression",
            phase=ExperimentPhase.REGRESSION,
            execution_recipe=plan.primary_execution_recipe,
            variant_id=None,
            variant_role=None,
            oracle_spec=None,
            depends_on=tuple(step.step_id for step in repair_oracle_steps),
        )
        steps.extend(
            (
                repair_step,
                build_step,
                repair_replay_step,
                repair_target_step,
                *repair_oracle_steps,
                regression_step,
            )
        )
    request = DynamicBindingRequest(
        symbol="workspace.project",
        resource_kind=DynamicResourceKind.WORKSPACE,
        equivalence_policy=equivalence_policy,
    )
    template = ExperimentPlanTemplate(
        validation_instance_id=plan.validation_instance_id,
        profile=profile.ref,
        case_plan=plan.ref,
        adapter=profile.adapters[0],
        oracle_bundle=bundle.ref,
        oracle_executions=tuple(executions),
        steps=tuple(steps),
        dynamic_requests=(request,),
    )
    return {
        "profile": profile,
        "identity": identity,
        "case_plan": plan,
        "adapter": profile.adapters[0],
        "bundle": bundle,
        "specs": specs,
        "receipts": tuple(receipts),
        "template": template,
        "reset_policy": reset_policy,
        "equivalence_policy": equivalence_policy,
        "baseline_policy": baseline_policy,
    }


class BaselineSelectionReceiptTests(unittest.TestCase):
    def test_source_kinds_are_the_four_frozen_anchor_classes(self):
        self.assertEqual(
            {kind.name: kind.value for kind in BaselineSourceKind},
            {
                "ABSOLUTE": "absolute",
                "PAIRED_CONTROL": "paired_control",
                "MATCHED_TREND": "matched_trend",
                "EXTERNAL_REFERENCE": "external_reference",
            },
        )
        for kind in BaselineSourceKind:
            candidate = _baseline_candidate(kind=kind)
            with self.subTest(kind=kind):
                self.assertEqual(
                    BaselineCandidate.from_document(candidate.to_document()),
                    candidate,
                )

    def test_round_trip_is_content_addressed_and_has_no_hash_cycle(self):
        receipt = _receipt()
        restored = BaselineSelectionReceipt.from_document(receipt.to_document())
        from_json = BaselineSelectionReceipt.from_json(
            json.dumps(receipt.to_document()).encode("utf-8")
        )

        self.assertEqual(restored, receipt)
        self.assertEqual(from_json, receipt)
        self.assertEqual(
            receipt.ref.kind,
            ContractRefKind.BASELINE_SELECTION_RECEIPT,
        )
        self.assertEqual(receipt.ref.contract_id, receipt.content_sha256)
        self.assertEqual(receipt.ref.content_sha256, receipt.content_sha256)
        rendered = repr(receipt.to_document()).lower()
        self.assertNotIn("observation", rendered)
        self.assertNotIn("template", rendered)

    def test_fallback_path_is_ordered_and_selects_first_eligible_source(self):
        rejected = _baseline_candidate(
            "preferred",
            eligibility=BaselineEligibility.INELIGIBLE,
        )
        selected = _baseline_candidate("history")
        deferred = _baseline_candidate(
            "external",
            eligibility=BaselineEligibility.NOT_EVALUATED,
            kind=BaselineSourceKind.EXTERNAL_REFERENCE,
        )
        receipt = _receipt(
            candidates=(rejected, selected, deferred),
            selected_source_id="history",
        )
        self.assertEqual(
            [candidate.source_id for candidate in receipt.candidates],
            ["preferred", "history", "external"],
        )

        invalid_paths = (
            ((), "history"),
            ((selected, rejected), "preferred"),
            ((deferred, selected), "history"),
            ((selected,), "missing"),
            ((selected, selected), "history"),
        )
        for candidates, selected_id in invalid_paths:
            with self.subTest(selected_id=selected_id), self.assertRaises(ContractError):
                _receipt(
                    candidates=candidates,
                    selected_source_id=selected_id,
                )

    def test_receipt_deep_freezes_candidates_and_rehashes_semantic_changes(self):
        candidates = [_baseline_candidate()]
        receipt = _receipt(candidates=candidates)
        digest = receipt.content_sha256
        candidates.append(_baseline_candidate("late"))
        self.assertEqual(len(receipt.candidates), 1)
        self.assertEqual(receipt.content_sha256, digest)
        changed = dataclasses.replace(
            receipt,
            static_selection_inputs_sha256=_digest("different inputs"),
        )
        self.assertNotEqual(changed.content_sha256, digest)

    def test_receipt_strict_json_and_reference_kinds_fail_closed(self):
        receipt = _receipt()
        document = receipt.to_document()
        for field, value in (
            ("schema_version", True),
            ("schema_version", 2),
            ("contract_kind", "observation"),
        ):
            mutated = copy.deepcopy(document)
            mutated[field] = value
            with self.subTest(field=field, value=value), self.assertRaises(ContractError):
                BaselineSelectionReceipt.from_document(mutated)

        unknown = copy.deepcopy(document)
        unknown["observation_ids"] = []
        with self.assertRaises(ContractError):
            BaselineSelectionReceipt.from_document(unknown)
        with self.assertRaises(ContractError):
            BaselineSelectionReceipt.from_json(
                b'{"schema_version":1,"schema_version":1}'
            )
        with self.assertRaises(ContractError):
            dataclasses.replace(
                receipt,
                profile=_ref(ContractRefKind.ADAPTER, "wrong"),
            )


class ExperimentPlanTemplateTests(unittest.TestCase):
    def test_round_trip_embeds_complete_oracle_execution_protocol(self):
        template = _template()
        restored = ExperimentPlanTemplate.from_document(template.to_document())
        from_json = ExperimentPlanTemplate.from_json(
            json.dumps(template.to_document()).encode("utf-8")
        )

        self.assertEqual(restored, template)
        self.assertEqual(from_json, template)
        planned = template.oracle_executions[0]
        self.assertEqual(planned.fixed_seed, 41)
        self.assertEqual(planned.protocol.warmup_runs, 1)
        self.assertEqual(planned.protocol.repetitions, 3)
        self.assertEqual(planned.protocol.quorum, QuorumSpec(2, 3))
        self.assertEqual(planned.protocol.timeout_ms, 30_000)
        self.assertEqual(planned.reset_policy.kind, ContractRefKind.RESET_POLICY)
        self.assertEqual(
            {reference.kind for reference in planned.collectors},
            {ContractRefKind.COLLECTOR},
        )
        self.assertEqual(planned.normalizer.kind, ContractRefKind.NORMALIZER)
        self.assertEqual(planned.comparator.kind, ContractRefKind.COMPARATOR)
        self.assertEqual(
            template.ref.kind,
            ContractRefKind.EXPERIMENT_PLAN_TEMPLATE,
        )
        self.assertEqual(template.ref.contract_id, template.content_sha256)

    def test_oracle_and_dynamic_membership_are_canonical_but_steps_are_ordered(self):
        alpha = _planned_oracle("alpha")
        beta = _planned_oracle("beta")
        requests = (
            _request("workspace.project", DynamicResourceKind.WORKSPACE),
            _request("network.api", DynamicResourceKind.LOOPBACK_PORT),
        )
        prepare = _step(
            "prepare",
            phase=ExperimentPhase.SANDBOX_HEALTH,
        )
        execute = _step(
            "execute",
            oracle=alpha.oracle_spec,
        )
        forward = _template(
            oracle_executions=(alpha, beta),
            steps=(prepare, execute),
            requests=requests,
        )
        reordered_members = _template(
            oracle_executions=(beta, alpha),
            steps=(prepare, execute),
            requests=tuple(reversed(requests)),
        )
        reversed_steps = _template(
            oracle_executions=(alpha, beta),
            steps=(execute, prepare),
            requests=requests,
        )
        self.assertEqual(forward.content_sha256, reordered_members.content_sha256)
        self.assertNotEqual(forward.content_sha256, reversed_steps.content_sha256)

    def test_steps_require_unique_ids_prior_dependencies_and_planned_oracles(self):
        planned = _planned_oracle()
        prepare = _step("prepare", phase=ExperimentPhase.SANDBOX_HEALTH)
        execute = _step(
            "execute",
            oracle=planned.oracle_spec,
            depends_on=("prepare",),
        )
        self.assertEqual(
            _template(
                oracle_executions=(planned,),
                steps=(prepare, execute),
            ).steps,
            (prepare, execute),
        )

        invalid_steps = (
            (execute, prepare),
            (prepare, prepare),
            (_step(oracle=_ref(ContractRefKind.ORACLE_SPEC, "outside")),),
        )
        for steps in invalid_steps:
            with self.subTest(steps=steps), self.assertRaises(ContractError):
                _template(oracle_executions=(planned,), steps=steps)
        with self.assertRaises(ContractError):
            ExperimentStep(
                step_id="run",
                phase=ExperimentPhase.ORACLE_EXPERIMENT,
                execution_recipe=_ref(
                    ContractRefKind.EXECUTION_RECIPE,
                    "recipe",
                ),
                variant_id=None,
                variant_role=VariantRole.CANDIDATE,
                oracle_spec=planned.oracle_spec,
            )

    def test_non_oracle_phases_reject_variants_and_causal_phase_requires_control(self):
        oracle = _ref(ContractRefKind.ORACLE_SPEC, "oracle")
        recipe = _ref(ContractRefKind.EXECUTION_RECIPE, "recipe")
        for phase in (
            ExperimentPhase.TARGET_EVIDENCE,
            ExperimentPhase.BUILD_SANITY,
        ):
            with self.subTest(phase=phase), self.assertRaisesRegex(
                ContractError,
                "must not carry",
            ):
                ExperimentStep(
                    step_id=f"bad.{phase.value}",
                    phase=phase,
                    execution_recipe=recipe,
                    variant_id="candidate",
                    variant_role=VariantRole.CANDIDATE,
                    oracle_spec=oracle,
                )
        with self.assertRaisesRegex(ContractError, "control variant role"):
            ExperimentStep(
                step_id="bad.causal",
                phase=ExperimentPhase.CAUSAL_CONTROL,
                execution_recipe=recipe,
                variant_id="candidate",
                variant_role=VariantRole.CANDIDATE,
                oracle_spec=oracle,
            )

    def test_template_contains_only_symbolic_dynamic_requests(self):
        template = _template()
        document = template.to_document()
        rendered = repr(document).lower()
        for forbidden in (
            "workspace_path",
            "gpu_uuid",
            "device_lease",
            "temporary_directory_path",
            "shell",
            "command",
            "observation",
            "verdict",
        ):
            self.assertNotIn(forbidden, rendered)
            mutated = copy.deepcopy(document)
            mutated[forbidden] = "injected"
            with self.assertRaises(ContractError):
                ExperimentPlanTemplate.from_document(mutated)

    def test_template_requires_one_canonical_project_workspace(self):
        invalid_requests = (
            ((), "exactly one workspace request"),
            (
                (_request("network.api", DynamicResourceKind.LOOPBACK_PORT),),
                "exactly one workspace request",
            ),
            (
                (_request("workspace.other", DynamicResourceKind.WORKSPACE),),
                "workspace.project",
            ),
            (
                (
                    _request("workspace.project", DynamicResourceKind.WORKSPACE),
                    _request("workspace.other", DynamicResourceKind.WORKSPACE),
                ),
                "exactly one workspace request",
            ),
        )
        for requests, error in invalid_requests:
            with self.subTest(requests=requests), self.assertRaisesRegex(
                ContractError, error
            ):
                _template(requests=requests)

    def test_zero_or_multiple_baseline_receipts_bind_without_cycles(self):
        without_baseline = _template()
        validate_template_baseline_selections(without_baseline, ())

        profile = _ref(ContractRefKind.FROZEN_PROFILE, "profile")
        case_plan = _ref(ContractRefKind.CASE_PLAN, "case")
        first_oracle = _ref(ContractRefKind.ORACLE_SPEC, "alpha")
        second_oracle = _ref(ContractRefKind.ORACLE_SPEC, "beta")
        first_receipt = _receipt(
            oracle=first_oracle,
            profile=profile,
            case_plan=case_plan,
        )
        second_receipt = _receipt(
            oracle=second_oracle,
            profile=profile,
            case_plan=case_plan,
            candidates=(_baseline_candidate("external"),),
            selected_source_id="external",
        )
        first_plan = dataclasses.replace(
            _planned_oracle("alpha"),
            oracle_spec=first_oracle,
            baseline_selection=first_receipt.ref,
        )
        second_plan = dataclasses.replace(
            _planned_oracle("beta"),
            oracle_spec=second_oracle,
            baseline_selection=second_receipt.ref,
        )
        template = _template(
            profile=profile,
            case_plan=case_plan,
            oracle_executions=(first_plan, second_plan),
            steps=(
                _step("alpha", oracle=first_oracle),
                _step("beta", oracle=second_oracle),
            ),
        )
        validate_template_baseline_selections(
            template,
            (second_receipt, first_receipt),
        )

        with self.assertRaises(ContractError):
            validate_template_baseline_selections(template, (first_receipt,))
        mismatched = dataclasses.replace(
            second_receipt,
            validation_instance_id=_digest("other-instance"),
        )
        mismatched_plan = dataclasses.replace(
            second_plan,
            baseline_selection=mismatched.ref,
        )
        mismatched_template = _template(
            profile=profile,
            case_plan=case_plan,
            oracle_executions=(first_plan, mismatched_plan),
            steps=(
                _step("alpha", oracle=first_oracle),
                _step("beta", oracle=second_oracle),
            ),
        )
        with self.assertRaisesRegex(ContractError, "validation instance"):
            validate_template_baseline_selections(
                mismatched_template,
                (first_receipt, mismatched),
            )

    def test_determinism_requires_same_frozen_inputs_and_exact_template_hash(self):
        first = _template()
        validate_template_determinism(first, ExperimentPlanTemplate.from_document(
            first.to_document()
        ))

        changed_protocol = dataclasses.replace(
            first.oracle_executions[0],
            protocol=_protocol(timeout_ms=30_001),
        )
        non_deterministic = dataclasses.replace(
            first,
            oracle_executions=(changed_protocol,),
        )
        with self.assertRaisesRegex(ContractError, "non-deterministic"):
            validate_template_determinism(first, non_deterministic)
        changed_input = dataclasses.replace(
            first,
            case_plan=_ref(ContractRefKind.CASE_PLAN, "other-case"),
        )
        with self.assertRaisesRegex(ContractError, "frozen inputs"):
            validate_template_determinism(first, changed_input)

    def test_constructor_freezes_lists_and_strict_parser_rejects_float_and_unknown(self):
        planned = [_planned_oracle()]
        steps = [_step(oracle=planned[0].oracle_spec)]
        requests = [_request()]
        template = _template(
            oracle_executions=planned,
            steps=steps,
            requests=requests,
        )
        digest = template.content_sha256
        planned.append(_planned_oracle("late"))
        steps.append(_step("late", oracle=planned[-1].oracle_spec))
        requests.append(_request("temp", DynamicResourceKind.TEMPORARY_DIRECTORY))
        self.assertEqual(len(template.oracle_executions), 1)
        self.assertEqual(len(template.steps), 1)
        self.assertEqual(len(template.dynamic_requests), 1)
        self.assertEqual(template.content_sha256, digest)

        with self.assertRaises(ContractError):
            ExperimentPlanTemplate.from_json(
                json.dumps(template.to_document()).replace(
                    '"schema_version": 1',
                    '"schema_version": 1.0',
                ).encode("utf-8")
            )
        mutated = template.to_document()
        mutated["extra"] = True
        with self.assertRaises(ContractError):
            ExperimentPlanTemplate.from_document(mutated)
        encoded = json.dumps(template.to_document(), separators=(",", ":"))
        with self.assertRaises(ContractError):
            ExperimentPlanTemplate.from_json(
                ('{"contract_kind":"forged",' + encoded.lstrip("{")).encode(
                    "utf-8"
                )
            )


class ExperimentPlanMembershipTests(unittest.TestCase):
    @staticmethod
    def _validate(fixture):
        validate_experiment_plan_membership(
            fixture["template"],
            profile=fixture["profile"],
            case_plan=fixture["case_plan"],
            adapter=fixture["adapter"],
            oracle_bundle=fixture["bundle"],
            oracle_specs=fixture["specs"],
            baseline_receipts=fixture["receipts"],
        )

    def test_exact_bundle_guard_closure_and_every_variant_pass(self):
        fixture = _membership_fixture(causal=True)
        validate_case_plan_membership(
            fixture["case_plan"],
            identity=fixture["identity"],
            profile=fixture["profile"],
            oracle_bundle=fixture["bundle"],
            oracle_specs=fixture["specs"],
        )
        self._validate(fixture)
        expected_variants = sum(len(spec.variants) for spec in fixture["specs"])
        self.assertEqual(
            sum(
                step.oracle_spec is not None
                for step in fixture["template"].steps
            ),
            expected_variants,
        )

        primary = fixture["specs"][-1]
        incomplete_executions = tuple(
            execution
            for execution in fixture["template"].oracle_executions
            if execution.oracle_spec == primary.ref
        )
        incomplete_steps = tuple(
            step
            for step in fixture["template"].steps
            if step.oracle_spec is None or step.oracle_spec == primary.ref
        )
        incomplete = dataclasses.replace(
            fixture["template"],
            oracle_executions=incomplete_executions,
            steps=incomplete_steps,
        )
        with self.assertRaisesRegex(ContractError, "exactly cover"):
            validate_experiment_plan_membership(
                incomplete,
                profile=fixture["profile"],
                case_plan=fixture["case_plan"],
                adapter=fixture["adapter"],
                oracle_bundle=fixture["bundle"],
                oracle_specs=fixture["specs"],
                baseline_receipts=(),
            )

    def test_phase_grammar_requires_l0_evidence_and_matches_repair_presence(self):
        fixture = _membership_fixture(causal=False)
        self._validate(fixture)
        for required_phase in (
            ExperimentPhase.SANDBOX_HEALTH,
            ExperimentPhase.REAL_ENTRY_REPLAY,
            ExperimentPhase.TARGET_EVIDENCE,
        ):
            missing = dataclasses.replace(
                fixture["template"],
                steps=tuple(
                    dataclasses.replace(step, depends_on=())
                    for step in fixture["template"].steps
                    if step.phase is not required_phase
                ),
            )
            with self.subTest(missing=required_phase), self.assertRaisesRegex(
                ContractError,
                "phase grammar",
            ):
                self._validate({**fixture, "template": missing})

        injected_repair = ExperimentStep(
            step_id="injected.repair",
            phase=ExperimentPhase.REPAIR,
            execution_recipe=fixture["case_plan"].primary_execution_recipe,
            variant_id=None,
            variant_role=None,
            oracle_spec=None,
        )
        injected = dataclasses.replace(
            fixture["template"],
            steps=fixture["template"].steps + (injected_repair,),
        )
        with self.assertRaisesRegex(ContractError, "phase grammar"):
            self._validate({**fixture, "template": injected})

        repair_fixture = _membership_fixture(causal=False, repair=True)
        self._validate(repair_fixture)
        for repair_phase in (
            ExperimentPhase.REPAIR,
            ExperimentPhase.BUILD_SANITY,
            ExperimentPhase.REPAIR_REAL_ENTRY_REPLAY,
            ExperimentPhase.REPAIR_TARGET_EVIDENCE,
            ExperimentPhase.REGRESSION,
        ):
            missing = dataclasses.replace(
                repair_fixture["template"],
                steps=tuple(
                    dataclasses.replace(step, depends_on=())
                    for step in repair_fixture["template"].steps
                    if step.phase is not repair_phase
                ),
            )
            with self.subTest(missing=repair_phase), self.assertRaisesRegex(
                ContractError,
                "phase grammar",
            ):
                self._validate({**repair_fixture, "template": missing})

    def test_l0_rejects_every_repair_only_phase(self):
        fixture = _membership_fixture(causal=False)
        for phase in (
            ExperimentPhase.REPAIR,
            ExperimentPhase.BUILD_SANITY,
            ExperimentPhase.REPAIR_REAL_ENTRY_REPLAY,
            ExperimentPhase.REPAIR_TARGET_EVIDENCE,
            ExperimentPhase.REGRESSION,
        ):
            injected = ExperimentStep(
                step_id=f"injected.{phase.value}",
                phase=phase,
                execution_recipe=fixture["case_plan"].primary_execution_recipe,
                variant_id=None,
                variant_role=None,
                oracle_spec=None,
            )
            template = dataclasses.replace(
                fixture["template"],
                steps=fixture["template"].steps + (injected,),
            )
            with self.subTest(phase=phase), self.assertRaisesRegex(
                ContractError, "phase grammar"
            ):
                self._validate({**fixture, "template": template})

        spec = fixture["specs"][0]
        variant = spec.variants[0]
        repair_oracle = ExperimentStep(
            step_id="injected.repair-oracle",
            phase=ExperimentPhase.REPAIR_ORACLE_EXPERIMENT,
            execution_recipe=variant.execution_recipe,
            variant_id=variant.variant_id,
            variant_role=variant.role,
            oracle_spec=spec.ref,
        )
        template = dataclasses.replace(
            fixture["template"],
            steps=fixture["template"].steps + (repair_oracle,),
        )
        with self.assertRaisesRegex(ContractError, "invents an Oracle variant"):
            self._validate({**fixture, "template": template})

    def test_phase_grammar_rejects_duplicate_counts_and_wrong_region_order(self):
        for fixture in (
            _membership_fixture(causal=False),
            _membership_fixture(causal=False, repair=True),
        ):
            counted_phases = [
                ExperimentPhase.SANDBOX_HEALTH,
                ExperimentPhase.REAL_ENTRY_REPLAY,
                ExperimentPhase.TARGET_EVIDENCE,
            ]
            if fixture["case_plan"].repair is not None:
                counted_phases.extend(
                    (
                        ExperimentPhase.REPAIR,
                        ExperimentPhase.BUILD_SANITY,
                        ExperimentPhase.REPAIR_REAL_ENTRY_REPLAY,
                        ExperimentPhase.REPAIR_TARGET_EVIDENCE,
                        ExperimentPhase.REGRESSION,
                    )
                )
            for phase in counted_phases:
                steps = list(fixture["template"].steps)
                index = next(i for i, step in enumerate(steps) if step.phase is phase)
                duplicate = dataclasses.replace(
                    steps[index],
                    step_id=f"{steps[index].step_id}.duplicate",
                    depends_on=(),
                )
                steps.insert(index + 1, duplicate)
                template = dataclasses.replace(
                    fixture["template"], steps=tuple(steps)
                )
                with self.subTest(
                    repair=fixture["case_plan"].repair is not None,
                    duplicate=phase,
                ), self.assertRaisesRegex(ContractError, "phase grammar"):
                    self._validate({**fixture, "template": template})

        repair_fixture = _membership_fixture(causal=False, repair=True)
        ordered = [
            dataclasses.replace(step, depends_on=())
            for step in repair_fixture["template"].steps
        ]
        wrong_pairs = (
            (ExperimentPhase.SANDBOX_HEALTH, ExperimentPhase.REAL_ENTRY_REPLAY),
            (ExperimentPhase.REAL_ENTRY_REPLAY, ExperimentPhase.TARGET_EVIDENCE),
            (ExperimentPhase.REPAIR, ExperimentPhase.BUILD_SANITY),
            (ExperimentPhase.BUILD_SANITY, ExperimentPhase.REPAIR_REAL_ENTRY_REPLAY),
            (
                ExperimentPhase.REPAIR_REAL_ENTRY_REPLAY,
                ExperimentPhase.REPAIR_TARGET_EVIDENCE,
            ),
            (
                ExperimentPhase.REPAIR_TARGET_EVIDENCE,
                ExperimentPhase.REPAIR_ORACLE_EXPERIMENT,
            ),
            (ExperimentPhase.REPAIR_ORACLE_EXPERIMENT, ExperimentPhase.REGRESSION),
        )
        for earlier, later in wrong_pairs:
            reordered = list(ordered)
            left = next(i for i, step in enumerate(reordered) if step.phase is earlier)
            right = next(i for i, step in enumerate(reordered) if step.phase is later)
            reordered[left], reordered[right] = reordered[right], reordered[left]
            template = dataclasses.replace(
                repair_fixture["template"], steps=tuple(reordered)
            )
            with self.subTest(earlier=earlier, later=later), self.assertRaisesRegex(
                ContractError, "out of order"
            ):
                self._validate({**repair_fixture, "template": template})

    def test_l1_replays_exact_method_inputs_for_dual_and_causal_only_controls(self):
        for causal_only in (False, True):
            fixture = _membership_fixture(
                causal=True,
                repair=True,
                causal_only=causal_only,
            )
            self._validate(fixture)
            repair_steps = tuple(
                step
                for step in fixture["template"].steps
                if step.phase is ExperimentPhase.REPAIR_ORACLE_EXPERIMENT
            )
            actual = {(step.oracle_spec, step.variant_id) for step in repair_steps}
            expected = {
                (spec.ref, variant.variant_id)
                for spec in fixture["specs"]
                for variant in spec.variants
                if not (
                    spec.control_evidence_role is ControlEvidenceRole.CAUSAL_ONLY
                    and spec.causal_control is not None
                    and variant.variant_id == spec.causal_control.control_variant_id
                )
            }
            self.assertEqual(actual, expected)
            primary = fixture["specs"][-1]
            control_key = (
                primary.ref,
                primary.causal_control.control_variant_id,
            )
            self.assertEqual(control_key in actual, not causal_only)
            if causal_only:
                control = next(
                    variant
                    for variant in primary.variants
                    if variant.variant_id
                    == primary.causal_control.control_variant_id
                )
                forbidden = ExperimentStep(
                    step_id="repair.forbidden-causal-control",
                    phase=ExperimentPhase.REPAIR_ORACLE_EXPERIMENT,
                    execution_recipe=control.execution_recipe,
                    variant_id=control.variant_id,
                    variant_role=control.role,
                    oracle_spec=primary.ref,
                    depends_on=("phase.repair-target",),
                )
                regression_index = next(
                    index
                    for index, step in enumerate(fixture["template"].steps)
                    if step.phase is ExperimentPhase.REGRESSION
                )
                invalid_steps = (
                    fixture["template"].steps[:regression_index]
                    + (forbidden,)
                    + fixture["template"].steps[regression_index:]
                )
                with self.assertRaisesRegex(
                    ContractError, "invents an Oracle variant"
                ):
                    self._validate(
                        {
                            **fixture,
                            "template": dataclasses.replace(
                                fixture["template"], steps=invalid_steps
                            ),
                        }
                    )

        fixture = _membership_fixture(causal=True, repair=True)
        removed = next(
            step
            for step in fixture["template"].steps
            if step.phase is ExperimentPhase.REPAIR_ORACLE_EXPERIMENT
        )
        remaining_ids = tuple(
            step.step_id
            for step in fixture["template"].steps
            if step.phase is ExperimentPhase.REPAIR_ORACLE_EXPERIMENT
            and step.step_id != removed.step_id
        )
        incomplete_steps = tuple(
            dataclasses.replace(step, depends_on=remaining_ids)
            if step.phase is ExperimentPhase.REGRESSION
            else step
            for step in fixture["template"].steps
            if step.step_id != removed.step_id
        )
        incomplete = dataclasses.replace(
            fixture["template"], steps=incomplete_steps
        )
        with self.assertRaisesRegex(ContractError, "repair experiment steps"):
            self._validate({**fixture, "template": incomplete})

    def test_experiment_region_preserves_control_before_candidate_order(self):
        fixture = _membership_fixture(causal=True)
        prelude = tuple(
            step
            for step in fixture["template"].steps
            if step.phase
            in (
                ExperimentPhase.SANDBOX_HEALTH,
                ExperimentPhase.REAL_ENTRY_REPLAY,
                ExperimentPhase.TARGET_EVIDENCE,
            )
        )
        experiment = tuple(
            step
            for step in fixture["template"].steps
            if step.phase
            in (
                ExperimentPhase.ORACLE_EXPERIMENT,
                ExperimentPhase.CAUSAL_CONTROL,
            )
        )
        control = next(
            step
            for step in experiment
            if step.phase is ExperimentPhase.CAUSAL_CONTROL
        )
        reordered = dataclasses.replace(
            fixture["template"],
            steps=prelude
            + (control,)
            + tuple(step for step in experiment if step is not control),
        )
        self._validate({**fixture, "template": reordered})
        self.assertLess(
            reordered.steps.index(control),
            next(
                index
                for index, step in enumerate(reordered.steps)
                if step.oracle_spec == control.oracle_spec
                and step.variant_role is VariantRole.CANDIDATE
            ),
        )

    def test_oracle_protocol_components_and_variant_mapping_are_exact(self):
        fixture = _membership_fixture(causal=True)
        template = fixture["template"]
        first_execution = template.oracle_executions[0]
        mismatched_execution = dataclasses.replace(
            first_execution,
            protocol=_protocol(timeout_ms=99_999),
        )
        changed = dataclasses.replace(
            template,
            oracle_executions=(mismatched_execution,)
            + template.oracle_executions[1:],
        )
        with self.assertRaisesRegex(ContractError, "planned protocol"):
            self._validate({**fixture, "template": changed})

        control_step = next(
            step
            for step in template.steps
            if step.phase is ExperimentPhase.CAUSAL_CONTROL
        )
        wrong_phase = dataclasses.replace(
            control_step,
            phase=ExperimentPhase.ORACLE_EXPERIMENT,
        )
        changed = dataclasses.replace(
            template,
            steps=tuple(
                wrong_phase if step.step_id == wrong_phase.step_id else step
                for step in template.steps
            ),
        )
        with self.assertRaisesRegex(ContractError, "wrong Oracle variant phase"):
            self._validate({**fixture, "template": changed})

        candidate_step = next(
            step
            for step in template.steps
            if step.variant_role is VariantRole.CANDIDATE
        )
        wrong_role = dataclasses.replace(
            candidate_step,
            variant_role=VariantRole.REFERENCE,
        )
        changed = dataclasses.replace(
            template,
            steps=tuple(
                wrong_role if step.step_id == wrong_role.step_id else step
                for step in template.steps
            ),
        )
        with self.assertRaisesRegex(ContractError, "wrong Oracle variant role"):
            self._validate({**fixture, "template": changed})

        wrong_recipe = dataclasses.replace(
            candidate_step,
            execution_recipe=fixture["profile"].execution_recipes[-1],
        )
        changed = dataclasses.replace(
            template,
            steps=tuple(
                wrong_recipe if step.step_id == wrong_recipe.step_id else step
                for step in template.steps
            ),
        )
        with self.assertRaisesRegex(ContractError, "wrong Oracle variant recipe"):
            self._validate({**fixture, "template": changed})

    def test_baseline_presence_policy_and_identity_are_exact(self):
        fixture = _membership_fixture(causal=False, with_baseline=True)
        self._validate(fixture)

        planned = fixture["template"].oracle_executions[0]
        missing = dataclasses.replace(planned, baseline_selection=None)
        missing_template = dataclasses.replace(
            fixture["template"],
            oracle_executions=(missing,),
        )
        with self.assertRaisesRegex(ContractError, "requires a baseline"):
            self._validate(
                {**fixture, "template": missing_template, "receipts": ()}
            )

        receipt = fixture["receipts"][0]
        wrong_receipt = dataclasses.replace(
            receipt,
            baseline_policy=_ref(ContractRefKind.BASELINE_POLICY, "wrong"),
        )
        wrong_planned = dataclasses.replace(
            planned,
            baseline_selection=wrong_receipt.ref,
        )
        wrong_template = dataclasses.replace(
            fixture["template"],
            oracle_executions=(wrong_planned,),
        )
        with self.assertRaisesRegex(ContractError, "baseline policy"):
            self._validate(
                {
                    **fixture,
                    "template": wrong_template,
                    "receipts": (wrong_receipt,),
                }
            )

        tampered_bindings = (
            (
                "profile",
                _ref(ContractRefKind.FROZEN_PROFILE, "wrong-profile"),
                "profile mismatch",
            ),
            (
                "case_plan",
                _ref(ContractRefKind.CASE_PLAN, "wrong-case"),
                "CasePlan mismatch",
            ),
            (
                "oracle_spec",
                _ref(ContractRefKind.ORACLE_SPEC, "wrong-oracle"),
                "OracleSpec mismatch",
            ),
            (
                "healthy_relation",
                _ref(ContractRefKind.HEALTHY_RELATION_POLICY, "wrong-healthy"),
                "baseline healthy relation",
            ),
        )
        for field, value, error in tampered_bindings:
            tampered_receipt = dataclasses.replace(receipt, **{field: value})
            tampered_planned = dataclasses.replace(
                planned,
                baseline_selection=tampered_receipt.ref,
            )
            tampered_template = dataclasses.replace(
                fixture["template"],
                oracle_executions=(tampered_planned,),
            )
            with self.subTest(field=field), self.assertRaisesRegex(
                ContractError, error
            ):
                self._validate(
                    {
                        **fixture,
                        "template": tampered_template,
                        "receipts": (tampered_receipt,),
                    }
                )

    def test_adapter_reset_equivalence_and_recipe_must_be_profile_members(self):
        fixture = _membership_fixture(causal=False)
        template = fixture["template"]
        with self.assertRaisesRegex(ContractError, "Adapter"):
            validate_experiment_plan_membership(
                template,
                profile=fixture["profile"],
                case_plan=fixture["case_plan"],
                adapter=_ref(ContractRefKind.ADAPTER, "outside"),
                oracle_bundle=fixture["bundle"],
                oracle_specs=fixture["specs"],
                baseline_receipts=fixture["receipts"],
            )

        planned = dataclasses.replace(
            template.oracle_executions[0],
            reset_policy=_ref(ContractRefKind.RESET_POLICY, "outside"),
        )
        with self.assertRaisesRegex(ContractError, "components outside Profile"):
            self._validate(
                {
                    **fixture,
                    "template": dataclasses.replace(
                        template,
                        oracle_executions=(planned,),
                    ),
                }
            )

        request = dataclasses.replace(
            template.dynamic_requests[0],
            equivalence_policy=_ref(
                ContractRefKind.EXECUTION_EQUIVALENCE_POLICY,
                "outside",
            ),
        )
        with self.assertRaisesRegex(ContractError, "policy outside Profile"):
            self._validate(
                {
                    **fixture,
                    "template": dataclasses.replace(
                        template,
                        dynamic_requests=(request,),
                    ),
                }
            )


class ExecutionBindingTests(unittest.TestCase):
    def test_round_trip_and_content_addressed_ref(self):
        template = _template()
        binding = _binding(template, GateRole.B1)
        restored = ExecutionBinding.from_document(binding.to_document())
        from_json = ExecutionBinding.from_json(
            json.dumps(binding.to_document()).encode("utf-8")
        )
        self.assertEqual(restored, binding)
        self.assertEqual(from_json, binding)
        self.assertEqual(binding.ref.kind, ContractRefKind.EXECUTION_BINDING)
        self.assertEqual(binding.ref.contract_id, binding.content_sha256)
        self.assertEqual(binding.ref.content_sha256, binding.content_sha256)
        validate_execution_binding(template, binding)
        encoded = json.dumps(binding.to_document(), separators=(",", ":"))
        with self.assertRaises(ContractError):
            ExecutionBinding.from_json(
                ('{"contract_kind":"forged",' + encoded.lstrip("{")).encode(
                    "utf-8"
                )
            )

    def test_resource_union_enforces_kind_specific_loopback_value(self):
        workspace = _request()
        port = _request("network.api", DynamicResourceKind.LOOPBACK_PORT)
        _resource(workspace, GateRole.B1)
        _resource(port, GateRole.B1, port=31_111)
        with self.assertRaises(ContractError):
            _resource(workspace, GateRole.B1, port=31_111)
        with self.assertRaises(ContractError):
            _resource(port, GateRole.B1, port=True)
        with self.assertRaises(ContractError):
            _resource(port, GateRole.B1, port=0)
        mutated = _resource(port, GateRole.B1).to_document()
        mutated["device_uuid"] = "arbitrary"
        with self.assertRaises(ContractError):
            DynamicResourceBinding.from_document(mutated)

        second_port = _request(
            "network.metrics", DynamicResourceKind.LOOPBACK_PORT
        )
        template = _template(requests=(workspace, port, second_port))
        colliding = (
            _resource(workspace, GateRole.B1),
            _resource(port, GateRole.B1, port=31_111),
            _resource(second_port, GateRole.B1, port=31_111),
        )
        with self.assertRaisesRegex(ContractError, "repeat a loopback_port"):
            _binding(template, GateRole.B1, resources=colliding)

    def test_binding_requires_exact_request_symbols_kinds_policies_and_template(self):
        template = _template()
        valid = _binding(template, GateRole.B1)
        validate_execution_binding(template, valid)

        with self.assertRaisesRegex(ContractError, "exactly match"):
            validate_execution_binding(
                template,
                dataclasses.replace(valid, resources=valid.resources[:-1]),
            )
        request = template.dynamic_requests[0]
        wrong_kind = dataclasses.replace(
            valid.resources[0],
            resource_kind=DynamicResourceKind.GPU_LEASE,
            loopback_port=None,
        )
        resources = (wrong_kind,) + valid.resources[1:]
        with self.assertRaisesRegex(ContractError, "kind mismatch"):
            validate_execution_binding(
                template,
                dataclasses.replace(valid, resources=resources),
            )
        wrong_policy = dataclasses.replace(
            valid.resources[0],
            equivalence_policy=_ref(
                ContractRefKind.EXECUTION_EQUIVALENCE_POLICY,
                "wrong",
            ),
        )
        with self.assertRaisesRegex(ContractError, "policy mismatch"):
            validate_execution_binding(
                template,
                dataclasses.replace(
                    valid,
                    resources=(wrong_policy,) + valid.resources[1:],
                ),
            )
        with self.assertRaisesRegex(ContractError, "template mismatch"):
            validate_execution_binding(
                template,
                dataclasses.replace(
                    valid,
                    template=_ref(
                        ContractRefKind.EXPERIMENT_PLAN_TEMPLATE,
                        "other-template",
                    ),
                ),
            )
        self.assertEqual(request.symbol, valid.resources[0].symbol)

    def test_b1_b2_may_have_different_allocations_but_must_be_equivalent(self):
        template = _template()
        b1 = _binding(template, GateRole.B1)
        b2 = _binding(template, GateRole.B2)
        validate_b1_b2_binding_equivalence(template, b1, b2)
        self.assertNotEqual(b1.content_sha256, b2.content_sha256)
        ports = {
            binding.role: next(
                resource.loopback_port
                for resource in binding.resources
                if resource.resource_kind is DynamicResourceKind.LOOPBACK_PORT
            )
            for binding in (b1, b2)
        }
        self.assertNotEqual(ports[GateRole.B1], ports[GateRole.B2])

    def test_b1_b2_reject_fingerprint_drift_reuse_and_wrong_roles(self):
        template = _template()
        b1 = _binding(template, GateRole.B1)
        b2 = _binding(template, GateRole.B2)
        workspace = next(
            resource
            for resource in b2.resources
            if resource.resource_kind is DynamicResourceKind.WORKSPACE
        )

        drifted = dataclasses.replace(
            workspace,
            equivalence_fingerprint_sha256=_digest("drifted"),
        )
        with self.assertRaisesRegex(ContractError, "outside equivalence"):
            validate_b1_b2_binding_equivalence(
                template,
                b1,
                dataclasses.replace(
                    b2,
                    resources=tuple(
                        drifted if resource.symbol == drifted.symbol else resource
                        for resource in b2.resources
                    ),
                ),
            )

        b1_by_symbol = {resource.symbol: resource for resource in b1.resources}
        for b2_resource in b2.resources:
            reused = dataclasses.replace(
                b2_resource,
                allocation_id=b1_by_symbol[b2_resource.symbol].allocation_id,
            )
            with self.subTest(reused=b2_resource.resource_kind), self.assertRaisesRegex(
                ContractError,
                "reuse allocation",
            ):
                validate_b1_b2_binding_equivalence(
                    template,
                    b1,
                    dataclasses.replace(
                        b2,
                        resources=tuple(
                            reused
                            if resource.symbol == reused.symbol
                            else resource
                            for resource in b2.resources
                        ),
                    ),
                )
        with self.assertRaisesRegex(ContractError, "same attempt"):
            validate_b1_b2_binding_equivalence(
                template,
                b1,
                dataclasses.replace(b2, attempt_id="attempt-2"),
            )
        cross_reused = dataclasses.replace(
            b2.resources[0],
            allocation_id=b1.resources[-1].allocation_id,
        )
        with self.assertRaisesRegex(ContractError, "reuse allocation"):
            validate_b1_b2_binding_equivalence(
                template,
                b1,
                dataclasses.replace(
                    b2,
                    resources=(cross_reused,) + b2.resources[1:],
                ),
            )
        with self.assertRaisesRegex(ContractError, "independent broker"):
            validate_b1_b2_binding_equivalence(
                template,
                b1,
                dataclasses.replace(
                    b2,
                    broker_receipt_sha256=b1.broker_receipt_sha256,
                ),
            )
        with self.assertRaisesRegex(ContractError, "ordered B1 and B2"):
            validate_b1_b2_binding_equivalence(template, b2, b1)

    def test_b1_b2_require_independent_workspaces_but_allow_new_gpu_leases(self):
        workspace_request = _request(
            "workspace.project", DynamicResourceKind.WORKSPACE
        )
        gpu_request = _request("gpu.primary", DynamicResourceKind.GPU_LEASE)
        template = _template(requests=(workspace_request, gpu_request))
        b1 = _binding(template, GateRole.B1)
        b2 = _binding(template, GateRole.B2)
        b1_by_symbol = {resource.symbol: resource for resource in b1.resources}

        b2_workspace = next(
            resource
            for resource in b2.resources
            if resource.resource_kind is DynamicResourceKind.WORKSPACE
        )
        reused_workspace = dataclasses.replace(
            b2_workspace,
            resource_fingerprint_sha256=b1_by_symbol[
                b2_workspace.symbol
            ].resource_fingerprint_sha256,
        )
        with self.assertRaisesRegex(ContractError, "independent resource fingerprints"):
            validate_b1_b2_binding_equivalence(
                template,
                b1,
                dataclasses.replace(
                    b2,
                    resources=tuple(
                        reused_workspace
                        if resource.symbol == reused_workspace.symbol
                        else resource
                        for resource in b2.resources
                    ),
                ),
            )

        b2_gpu = next(
            resource
            for resource in b2.resources
            if resource.resource_kind is DynamicResourceKind.GPU_LEASE
        )
        same_physical_gpu = dataclasses.replace(
            b2_gpu,
            resource_fingerprint_sha256=b1_by_symbol[
                b2_gpu.symbol
            ].resource_fingerprint_sha256,
        )
        equivalent_b2 = dataclasses.replace(
            b2,
            resources=tuple(
                same_physical_gpu
                if resource.symbol == same_physical_gpu.symbol
                else resource
                for resource in b2.resources
            ),
        )
        validate_b1_b2_binding_equivalence(template, b1, equivalent_b2)
        self.assertNotEqual(
            b1_by_symbol[b2_gpu.symbol].allocation_id,
            same_physical_gpu.allocation_id,
        )

    def test_binding_is_deeply_frozen_and_rejects_runtime_authority_fields(self):
        template = _template()
        resources = [
            _resource(request, GateRole.B1)
            for request in template.dynamic_requests
        ]
        binding = _binding(template, GateRole.B1, resources=resources)
        digest = binding.content_sha256
        resources.clear()
        self.assertEqual(len(binding.resources), len(template.dynamic_requests))
        self.assertEqual(binding.content_sha256, digest)
        for field in (
            "trusted",
            "approved",
            "observation_ids",
            "verdict",
            "command",
        ):
            mutated = binding.to_document()
            mutated[field] = True
            with self.subTest(field=field), self.assertRaises(ContractError):
                ExecutionBinding.from_document(mutated)


class PlanImportBoundaryTests(unittest.TestCase):
    def test_plan_contract_has_no_runtime_or_production_imports(self):
        source_path = (
            Path(__file__).parents[1]
            / "src"
            / "validation_core"
            / "contracts"
            / "plan.py"
        )
        tree = ast.parse(source_path.read_text(encoding="utf-8"))
        imported = set()
        called = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.update(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom):
                imported.add(node.module or "")
            elif isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                called.add(node.func.id)
        for forbidden in (
            "os",
            "pathlib",
            "subprocess",
            "socket",
            "importlib",
            "src.validation_core.registry",
            "src.validation_core.routing",
            "src.validation_core.outcome_loader",
        ):
            self.assertNotIn(forbidden, imported)
        self.assertTrue(called.isdisjoint({"eval", "exec", "compile", "__import__"}))

    def test_plan_types_are_not_exported_from_production_root(self):
        for name in (
            "BaselineSelectionReceipt",
            "ExperimentPlanTemplate",
            "ExecutionBinding",
            "validate_b1_b2_binding_equivalence",
        ):
            with self.subTest(name=name):
                self.assertFalse(hasattr(production_root, name))


if __name__ == "__main__":
    unittest.main()

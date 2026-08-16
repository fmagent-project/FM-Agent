import dataclasses
import hashlib
import json
import unittest

from src.validation_core.contracts.base import CanonicalDecimal, ContractError
from src.validation_core.contracts.evidence import (
    CanonicalTypedValue,
    CanonicalValueKind,
    CapturedArtifact,
    DecisionQuorum,
    Observation,
    ObservationFactKind,
    OracleDecision,
    OracleVerdict,
    validate_b1_b2_observation_independence,
    validate_oracle_decision_evidence,
)
from src.validation_core.contracts.oracle import StatisticalBaselineMethod, VariantRole
from src.validation_core.contracts.plan import (
    ExperimentPhase,
    GateRole,
    PlannedOracleExecution,
)
from src.validation_core.contracts.references import (
    ArtifactRef,
    ContractRefKind,
)
from tests.test_validation_oracle_contracts import (
    _method_cases,
    _spec,
)
from tests.test_validation_plan_contracts import (
    _binding,
    _receipt,
    _ref,
    _step,
    _template,
)


def _digest(value):
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _artifact(fill="d"):
    return ArtifactRef(
        role="process_exit",
        media_type="application/json",
        size_bytes=17,
        content_sha256=fill * 64,
    )


def _planned(spec, *, baseline=None):
    return PlannedOracleExecution(
        oracle_spec=spec.ref,
        collectors=spec.collectors,
        normalizer=spec.normalizer,
        comparator=spec.comparator,
        protocol=spec.execution_protocol,
        fixed_seed=41,
        reset_policy=_ref(ContractRefKind.RESET_POLICY, "evidence.reset"),
        baseline_selection=None if baseline is None else baseline.ref,
    )


def _graph(*, role=GateRole.B1, spec=None, baseline=None):
    spec = spec or _spec()
    planned = _planned(spec, baseline=baseline)
    template = _template(
        oracle_executions=(planned,),
        steps=(_step("oracle.candidate", oracle=spec.ref),),
    )
    binding = _binding(template, role)
    return spec, template, binding


def _captured(
    spec,
    *,
    role=GateRole.B1,
    index=0,
    artifact=None,
    collector=None,
    provenance=None,
):
    return CapturedArtifact(
        fact_kind=ObservationFactKind.PROCESS_EXIT,
        artifact=artifact or _artifact(),
        output_contract=_ref(
            ContractRefKind.OUTPUT_CONTRACT,
            "evidence.process-exit",
        ),
        collector=collector or spec.collectors[0],
        collector_run_id=f"{role.value}.collector-run-{index}",
        capture_id=f"{role.value}.capture-{index}",
        captured_at="2026-08-16T01:00:01Z",
        provenance_sha256=provenance
        or _digest(f"provenance:{role.value}:{index}"),
    )


def _observation(
    spec,
    template,
    binding,
    *,
    index=0,
    capture_index=None,
    artifact=None,
    captured=None,
):
    capture_index = index if capture_index is None else capture_index
    return Observation(
        validation_instance_id=template.validation_instance_id,
        attempt_id=binding.attempt_id,
        role=binding.role,
        template=template.ref,
        binding=binding.ref,
        step_id="oracle.candidate",
        repetition_index=index,
        retry_index=0,
        started_at="2026-08-16T01:00:00Z",
        finished_at="2026-08-16T01:00:02Z",
        artifacts=(
            (captured,)
            if captured is not None
            else tuple(
                _captured(
                    spec,
                    role=binding.role,
                    index=capture_index,
                    artifact=artifact,
                    collector=collector,
                    provenance=_digest(
                        "provenance:"
                        f"{binding.role.value}:{capture_index}:"
                        f"{collector.content_sha256}"
                    ),
                )
                for collector in spec.collectors
            )
        ),
    )


def _observations(spec, template, binding, *, artifact=None):
    return tuple(
        _observation(
            spec,
            template,
            binding,
            index=index,
            artifact=artifact,
        )
        for index in range(spec.execution_protocol.repetitions)
    )


def _observations_for_steps(spec, template, binding, steps):
    return tuple(
        dataclasses.replace(
            _observation(
                spec,
                template,
                binding,
                index=repetition_index,
                capture_index=(step_index + 1) * 100 + repetition_index,
            ),
            step_id=step.step_id,
        )
        for step_index, step in enumerate(steps)
        for repetition_index in range(spec.execution_protocol.repetitions)
    )


def _decision(
    spec,
    template,
    binding,
    observations,
    *,
    baseline=None,
    verdict=OracleVerdict.VIOLATION,
    reason_codes=("RELATION_VIOLATED",),
    domain_match=True,
    quorum=None,
):
    if quorum is None:
        if verdict is OracleVerdict.VIOLATION:
            quorum = DecisionQuorum(4, 5, 4, 1, 0)
        elif verdict is OracleVerdict.PASS:
            quorum = DecisionQuorum(4, 5, 1, 4, 0)
        else:
            quorum = DecisionQuorum(4, 5, 2, 2, 1)
    threshold_values = (
        (
            CanonicalTypedValue(
                "approved.threshold",
                CanonicalValueKind.DECIMAL,
                CanonicalDecimal("1.25"),
            ),
        )
        if spec.threshold_policy is not None
        else ()
    )
    return OracleDecision(
        validation_instance_id=template.validation_instance_id,
        attempt_id=binding.attempt_id,
        role=binding.role,
        profile=template.profile,
        case_plan=template.case_plan,
        template=template.ref,
        binding=binding.ref,
        oracle_spec=spec.ref,
        baseline_selection=None if baseline is None else baseline.ref,
        baseline_source_id=(
            None if baseline is None else baseline.selected_source_id
        ),
        domain_match=domain_match,
        observations=tuple(item.ref for item in observations),
        normalizer=spec.normalizer,
        comparator=spec.comparator,
        threshold_policy=spec.threshold_policy,
        normalized_values=(
            CanonicalTypedValue(
                "effect.delta",
                CanonicalValueKind.DECIMAL,
                CanonicalDecimal("2.5"),
            ),
        ),
        threshold_values=threshold_values,
        quorum=quorum,
        verdict=verdict,
        reason_codes=reason_codes,
    )


class ObservationContractTests(unittest.TestCase):
    def test_round_trip_hash_reference_and_deep_freeze(self):
        spec, template, binding = _graph()
        observation = _observation(spec, template, binding)
        payload = json.dumps(observation.to_document()).encode("utf-8")

        parsed = Observation.from_json(payload)

        self.assertEqual(parsed, observation)
        self.assertEqual(parsed.content_sha256, observation.content_sha256)
        self.assertEqual(parsed.ref.kind, ContractRefKind.OBSERVATION)
        self.assertEqual(parsed.ref.contract_id, parsed.content_sha256)
        self.assertIsInstance(parsed.artifacts, tuple)
        with self.assertRaises(dataclasses.FrozenInstanceError):
            parsed.step_id = "other"

    def test_strict_json_exact_keys_numeric_types_and_timestamps(self):
        spec, template, binding = _graph()
        document = _observation(spec, template, binding).to_document()
        document["unexpected"] = True
        with self.assertRaises(ContractError):
            Observation.from_json(json.dumps(document).encode("utf-8"))

        document.pop("unexpected")
        document["repetition_index"] = 0.0
        with self.assertRaises(ContractError):
            Observation.from_json(json.dumps(document).encode("utf-8"))

        with self.assertRaises(ContractError):
            Observation.from_json(
                b'{"contract_kind":"observation","contract_kind":"observation"}'
            )
        with self.assertRaises(ContractError):
            dataclasses.replace(
                _observation(spec, template, binding),
                started_at="2026-08-16T01:00:00+00:00",
            )

    def test_captured_artifact_requires_closed_fact_and_output_contract(self):
        spec, _, _ = _graph()
        captured = _captured(spec)
        with self.assertRaises(ContractError):
            dataclasses.replace(captured, fact_kind="process_exit")
        with self.assertRaises(ContractError):
            dataclasses.replace(
                captured,
                output_contract=_ref(ContractRefKind.COLLECTOR, "wrong"),
            )
        _, template, binding = _graph(spec=spec)
        with self.assertRaises(ContractError):
            dataclasses.replace(
                _observation(spec, template, binding),
                artifacts=(
                    dataclasses.replace(
                        captured,
                        captured_at="2026-08-16T01:00:03Z",
                    ),
                ),
            )

    def test_typed_values_reject_bool_as_integer_and_noncanonical_decimal(self):
        with self.assertRaises(ContractError):
            CanonicalTypedValue(
                "count",
                CanonicalValueKind.INTEGER,
                True,
            )
        with self.assertRaises(ContractError):
            CanonicalTypedValue(
                "effect",
                CanonicalValueKind.DECIMAL,
                "1.0",
            )
        with self.assertRaises(ContractError):
            CanonicalDecimal("1.0")


class OracleDecisionContractTests(unittest.TestCase):
    def test_quorum_requires_all_repetitions_and_unique_capture_provenance(self):
        spec, template, binding = _graph()
        first = _observation(spec, template, binding, index=0)
        incomplete = (first,)
        decision = _decision(spec, template, binding, incomplete)
        with self.assertRaisesRegex(
            ContractError,
            "every planned step.*frozen repetition",
        ):
            validate_oracle_decision_evidence(
                decision,
                template=template,
                binding=binding,
                oracle_spec=spec,
                observations=incomplete,
            )

        reused = tuple(
            dataclasses.replace(
                first,
                repetition_index=index,
                started_at="2026-08-16T01:00:00Z",
                finished_at="2026-08-16T01:00:02Z",
            )
            for index in range(spec.execution_protocol.repetitions)
        )
        decision = _decision(spec, template, binding, reused)
        with self.assertRaisesRegex(ContractError, "reuse a collector capture"):
            validate_oracle_decision_evidence(
                decision,
                template=template,
                binding=binding,
                oracle_spec=spec,
                observations=reused,
            )

    def test_decision_requires_every_step_repetition_and_declared_collector(self):
        spec = _spec()
        candidate = _step("oracle.candidate", oracle=spec.ref)
        control = dataclasses.replace(
            _step(
                "oracle.control",
                oracle=spec.ref,
                phase=ExperimentPhase.CAUSAL_CONTROL,
                variant_role=VariantRole.CONTROL,
            ),
            variant_id="control",
        )
        template = _template(
            oracle_executions=(_planned(spec),),
            steps=(candidate, control),
        )
        binding = _binding(template, GateRole.B1)

        candidate_only = _observations_for_steps(
            spec,
            template,
            binding,
            (candidate,),
        )
        decision = _decision(spec, template, binding, candidate_only)
        with self.assertRaisesRegex(
            ContractError,
            "every planned step.*frozen repetition",
        ):
            validate_oracle_decision_evidence(
                decision,
                template=template,
                binding=binding,
                oracle_spec=spec,
                observations=candidate_only,
            )

        complete = _observations_for_steps(
            spec,
            template,
            binding,
            (candidate, control),
        )
        decision = _decision(spec, template, binding, complete)
        validate_oracle_decision_evidence(
            decision,
            template=template,
            binding=binding,
            oracle_spec=spec,
            observations=complete,
        )

        one_collector = tuple(
            dataclasses.replace(observation, artifacts=(observation.artifacts[0],))
            for observation in complete
        )
        decision = _decision(spec, template, binding, one_collector)
        with self.assertRaisesRegex(ContractError, "every declared collector"):
            validate_oracle_decision_evidence(
                decision,
                template=template,
                binding=binding,
                oracle_spec=spec,
                observations=one_collector,
            )

    def test_original_and_repair_families_cannot_mix(self):
        spec = _spec()
        original = _step("oracle.candidate", oracle=spec.ref)
        repair = _step(
            "repair.candidate",
            oracle=spec.ref,
            phase=ExperimentPhase.REPAIR_ORACLE_EXPERIMENT,
        )
        template = _template(
            oracle_executions=(_planned(spec),),
            steps=(original, repair),
        )
        binding = _binding(template, GateRole.B1)
        repair_only = _observations_for_steps(
            spec,
            template,
            binding,
            (repair,),
        )
        decision = _decision(spec, template, binding, repair_only)
        validate_oracle_decision_evidence(
            decision,
            template=template,
            binding=binding,
            oracle_spec=spec,
            observations=repair_only,
        )

        mixed = (
            dataclasses.replace(repair_only[0], step_id=original.step_id),
            *repair_only[1:],
        )
        decision = _decision(spec, template, binding, mixed)
        with self.assertRaisesRegex(ContractError, "mix original and repair"):
            validate_oracle_decision_evidence(
                decision,
                template=template,
                binding=binding,
                oracle_spec=spec,
                observations=mixed,
            )

    def test_retry_history_is_contiguous_even_for_domain_mismatch(self):
        spec, template, binding = _graph()
        observations = tuple(
            dataclasses.replace(observation, retry_index=1)
            for observation in _observations(spec, template, binding)
        )
        decision = _decision(spec, template, binding, observations)
        with self.assertRaisesRegex(ContractError, "start at zero.*contiguous"):
            validate_oracle_decision_evidence(
                decision,
                template=template,
                binding=binding,
                oracle_spec=spec,
                observations=observations,
            )

        early_observation = (_observation(spec, template, binding),)
        early_decision = _decision(
            spec,
            template,
            binding,
            early_observation,
            domain_match=False,
            verdict=OracleVerdict.INCONCLUSIVE,
            reason_codes=(spec.applicability.out_of_domain_reason,),
        )
        validate_oracle_decision_evidence(
            early_decision,
            template=template,
            binding=binding,
            oracle_spec=spec,
            observations=early_observation,
        )

        skipped_initial_retry = (
            dataclasses.replace(early_observation[0], retry_index=1),
        )
        skipped_decision = dataclasses.replace(
            early_decision,
            observations=tuple(item.ref for item in skipped_initial_retry),
        )
        with self.assertRaisesRegex(ContractError, "start at zero.*contiguous"):
            validate_oracle_decision_evidence(
                skipped_decision,
                template=template,
                binding=binding,
                oracle_spec=spec,
                observations=skipped_initial_retry,
            )

    def test_conflicting_output_contract_identity_is_rejected(self):
        spec, template, binding = _graph()
        observations = list(_observations(spec, template, binding))
        first = observations[0]
        captured = first.artifacts[0]
        conflicting_output = dataclasses.replace(
            captured.output_contract,
            content_sha256=_digest("conflicting-output-contract"),
        )
        observations[0] = dataclasses.replace(
            first,
            artifacts=(
                dataclasses.replace(
                    captured,
                    output_contract=conflicting_output,
                ),
                *first.artifacts[1:],
            ),
        )
        observations = tuple(observations)
        decision = _decision(spec, template, binding, observations)
        with self.assertRaisesRegex(ContractError, "conflicting hashes"):
            validate_oracle_decision_evidence(
                decision,
                template=template,
                binding=binding,
                oracle_spec=spec,
                observations=observations,
            )

    def test_round_trip_hash_and_exact_typed_values(self):
        spec, template, binding = _graph()
        observations = _observations(spec, template, binding)
        decision = _decision(spec, template, binding, observations)

        parsed = OracleDecision.from_json(
            json.dumps(decision.to_document()).encode("utf-8")
        )

        self.assertEqual(parsed, decision)
        self.assertEqual(parsed.ref.kind, ContractRefKind.ORACLE_DECISION)
        self.assertEqual(parsed.ref.content_sha256, decision.content_sha256)
        self.assertIsInstance(parsed.observations, tuple)
        self.assertIsInstance(parsed.normalized_values, tuple)

    def test_verdict_must_mechanically_match_quorum(self):
        spec, template, binding = _graph()
        observations = _observations(spec, template, binding)
        with self.assertRaisesRegex(ContractError, "mechanical quorum"):
            _decision(
                spec,
                template,
                binding,
                observations,
                verdict=OracleVerdict.VIOLATION,
                quorum=DecisionQuorum(4, 5, 1, 4, 0),
            )
        inconclusive = _decision(
            spec,
            template,
            binding,
            observations,
            verdict=OracleVerdict.INCONCLUSIVE,
            reason_codes=("INSUFFICIENT_SAMPLES",),
            quorum=DecisionQuorum(2, 5, 2, 2, 1),
        )
        self.assertIs(inconclusive.verdict, OracleVerdict.INCONCLUSIVE)

    def test_schema_rejects_unknown_verdict_float_and_extra_key(self):
        spec, template, binding = _graph()
        observations = _observations(spec, template, binding)
        document = _decision(
            spec, template, binding, observations
        ).to_document()
        document["verdict"] = "FAIL"
        with self.assertRaises(ContractError):
            OracleDecision.from_json(json.dumps(document).encode("utf-8"))

        document["verdict"] = "VIOLATION"
        document["normalized_values"][0]["value"] = 2.5
        with self.assertRaises(ContractError):
            OracleDecision.from_json(json.dumps(document).encode("utf-8"))

        document["normalized_values"][0]["value"] = "2.5"
        document["agent_claim"] = "confirmed"
        with self.assertRaises(ContractError):
            OracleDecision.from_json(json.dumps(document).encode("utf-8"))

    def test_cross_validator_accepts_exact_frozen_closure(self):
        spec, template, binding = _graph()
        observations = _observations(spec, template, binding)
        decision = _decision(spec, template, binding, observations)

        validate_oracle_decision_evidence(
            decision,
            template=template,
            binding=binding,
            oracle_spec=spec,
            observations=observations,
        )

    def test_cross_validator_rejects_missing_extra_or_wrong_gate_evidence(self):
        spec, template, binding = _graph()
        observations = _observations(spec, template, binding)
        decision = _decision(spec, template, binding, observations)
        with self.assertRaisesRegex(ContractError, "exactly match"):
            validate_oracle_decision_evidence(
                decision,
                template=template,
                binding=binding,
                oracle_spec=spec,
                observations=observations[:-1],
            )

        wrong_role = dataclasses.replace(observations[0], role=GateRole.B2)
        wrong_refs = (wrong_role, *observations[1:])
        wrong_decision = dataclasses.replace(
            decision,
            observations=tuple(item.ref for item in wrong_refs),
        )
        with self.assertRaisesRegex(ContractError, "role mismatch"):
            validate_oracle_decision_evidence(
                wrong_decision,
                template=template,
                binding=binding,
                oracle_spec=spec,
                observations=wrong_refs,
            )

    def test_cross_validator_rejects_unknown_step_and_collector(self):
        spec, template, binding = _graph()
        observations = _observations(spec, template, binding)
        unknown_step = dataclasses.replace(observations[0], step_id="other.step")
        changed = (unknown_step, *observations[1:])
        decision = _decision(spec, template, binding, changed)
        with self.assertRaisesRegex(ContractError, "unknown template step"):
            validate_oracle_decision_evidence(
                decision,
                template=template,
                binding=binding,
                oracle_spec=spec,
                observations=changed,
            )

        foreign_capture = dataclasses.replace(
            observations[0].artifacts[0],
            collector=_ref(ContractRefKind.COLLECTOR, "foreign.collector"),
        )
        foreign = dataclasses.replace(observations[0], artifacts=(foreign_capture,))
        changed = (foreign, *observations[1:])
        decision = _decision(spec, template, binding, changed)
        with self.assertRaisesRegex(ContractError, "outside the frozen"):
            validate_oracle_decision_evidence(
                decision,
                template=template,
                binding=binding,
                oracle_spec=spec,
                observations=changed,
            )

    def test_reason_vocabulary_and_domain_relation_fail_closed(self):
        spec, template, binding = _graph()
        observations = _observations(spec, template, binding)
        wrong_reason = _decision(
            spec,
            template,
            binding,
            observations,
            reason_codes=("RELATION_HOLDS",),
        )
        with self.assertRaisesRegex(ContractError, "verdict vocabulary"):
            validate_oracle_decision_evidence(
                wrong_reason,
                template=template,
                binding=binding,
                oracle_spec=spec,
                observations=observations,
            )

        out_of_domain = _decision(
            spec,
            template,
            binding,
            observations,
            domain_match=False,
            verdict=OracleVerdict.INCONCLUSIVE,
            reason_codes=("INSUFFICIENT_SAMPLES",),
        )
        with self.assertRaisesRegex(ContractError, "applicability reason"):
            validate_oracle_decision_evidence(
                out_of_domain,
                template=template,
                binding=binding,
                oracle_spec=spec,
                observations=observations,
            )

    def test_baseline_reference_and_source_are_exact(self):
        method, variants = next(
            (method, variants)
            for method, variants in _method_cases()
            if type(method) is StatisticalBaselineMethod
        )
        spec = _spec(method, variants)
        preliminary_template = _template(
            oracle_executions=(_planned(spec),),
            steps=(_step("oracle.candidate", oracle=spec.ref),),
        )
        baseline = _receipt(
            oracle=spec.ref,
            profile=preliminary_template.profile,
            case_plan=preliminary_template.case_plan,
            instance=preliminary_template.validation_instance_id,
            baseline_policy=spec.baseline_policy,
            healthy_relation=spec.healthy_relation,
        )
        spec, template, binding = _graph(spec=spec, baseline=baseline)
        observations = _observations(spec, template, binding)
        decision = _decision(
            spec,
            template,
            binding,
            observations,
            baseline=baseline,
        )
        validate_oracle_decision_evidence(
            decision,
            template=template,
            binding=binding,
            oracle_spec=spec,
            observations=observations,
            baseline_receipt=baseline,
        )

        wrong_source = dataclasses.replace(
            decision,
            baseline_source_id="different-source",
        )
        with self.assertRaisesRegex(ContractError, "baseline source"):
            validate_oracle_decision_evidence(
                wrong_source,
                template=template,
                binding=binding,
                oracle_spec=spec,
                observations=observations,
                baseline_receipt=baseline,
            )


class CrossGateObservationTests(unittest.TestCase):
    def test_same_raw_hash_is_valid_with_independent_envelopes(self):
        spec, template, b1_binding = _graph(role=GateRole.B1)
        b2_binding = _binding(template, GateRole.B2)
        shared_raw = _artifact("e")
        b1 = _observations(spec, template, b1_binding, artifact=shared_raw)
        b2 = _observations(spec, template, b2_binding, artifact=shared_raw)

        validate_b1_b2_observation_independence(b1, b2)

        self.assertEqual(
            {item.artifacts[0].artifact.content_sha256 for item in b1},
            {item.artifacts[0].artifact.content_sha256 for item in b2},
        )
        self.assertTrue({item.ref for item in b1}.isdisjoint(item.ref for item in b2))

    def test_reused_binding_or_provenance_is_rejected(self):
        spec, template, b1_binding = _graph(role=GateRole.B1)
        b2_binding = _binding(template, GateRole.B2)
        b1 = _observations(spec, template, b1_binding)
        b2 = _observations(spec, template, b2_binding)

        reused_binding = tuple(
            dataclasses.replace(item, binding=b1_binding.ref) for item in b2
        )
        with self.assertRaisesRegex(ContractError, "independent Bindings"):
            validate_b1_b2_observation_independence(b1, reused_binding)

        conflicting_binding_ref = dataclasses.replace(
            b1_binding.ref,
            content_sha256=_digest("conflicting-binding-content"),
        )
        conflicting_binding = tuple(
            dataclasses.replace(item, binding=conflicting_binding_ref)
            for item in b2
        )
        with self.assertRaisesRegex(ContractError, "independent Bindings"):
            validate_b1_b2_observation_independence(b1, conflicting_binding)

        reused_capture = dataclasses.replace(
            b2[0].artifacts[0],
            collector_run_id=b1[0].artifacts[0].collector_run_id,
            capture_id=b1[0].artifacts[0].capture_id,
            provenance_sha256=b1[0].artifacts[0].provenance_sha256,
        )
        reused_provenance = (
            dataclasses.replace(b2[0], artifacts=(reused_capture,)),
            *b2[1:],
        )
        with self.assertRaisesRegex(ContractError, "collector run|provenance"):
            validate_b1_b2_observation_independence(b1, reused_provenance)

    def test_attempt_id_is_shared_but_role_must_be_exact(self):
        spec, template, b1_binding = _graph(role=GateRole.B1)
        b2_binding = _binding(template, GateRole.B2)
        b1 = _observations(spec, template, b1_binding)
        b2 = _observations(spec, template, b2_binding)
        self.assertEqual(b1[0].attempt_id, b2[0].attempt_id)
        validate_b1_b2_observation_independence(b1, b2)

        wrong_role = (dataclasses.replace(b2[0], role=GateRole.B1), *b2[1:])
        with self.assertRaisesRegex(ContractError, "only B2 evidence"):
            validate_b1_b2_observation_independence(b1, wrong_role)


if __name__ == "__main__":
    unittest.main()

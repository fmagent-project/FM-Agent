import ast
import dataclasses
import json
from pathlib import Path
import unittest

from src.validation_core.contracts.base import CanonicalDecimal, ContractError
from src.validation_core.contracts.oracle import (
    ApplicabilitySpec,
    CausalControlSpec,
    ConsequenceDomain,
    ConsensusMethod,
    ControlEvidenceRole,
    CrossGateReproducibility,
    DifferentialMethod,
    ExecutionProtocol,
    GoldenMethod,
    InvariantMethod,
    MetamorphicMethod,
    OracleBundle,
    OracleOrigin,
    OracleSpec,
    OracleVariant,
    PrimaryCombination,
    QuorumSpec,
    ReasonVocabulary,
    ReproducibilityMode,
    ResourceGrowthMethod,
    RetryReason,
    StatisticalBaselineMethod,
    VariantRole,
)
from src.validation_core.contracts.references import (
    ArtifactRef,
    ContractRef,
    ContractRefKind,
)


def _ref(kind, name=None, fill="1"):
    return ContractRef(
        kind=kind,
        contract_id=name or f"example.{kind.value}",
        contract_version="1.0.0",
        content_sha256=fill * 64,
    )


def _artifact(role="calibrated_domain", fill="2"):
    return ArtifactRef(
        role=role,
        media_type="application/json",
        size_bytes=42,
        content_sha256=fill * 64,
    )


def _causal_control(control_variant_id="control"):
    return CausalControlSpec(
        control_variant_id=control_variant_id,
        control_policy=_ref(
            ContractRefKind.CONTROL_POLICY, "example.control.intervention", "1"
        ),
        causal_prediction=_ref(
            ContractRefKind.HEALTHY_RELATION_POLICY,
            "example.control.prediction",
            "2",
        ),
        correctness_guard=_ref(
            ContractRefKind.ORACLE_SPEC, "example.control.correctness", "3"
        ),
        target_association=_ref(
            ContractRefKind.TARGET_EVIDENCE_POLICY,
            "example.control.target",
            "4",
        ),
        reuse_policy=_ref(
            ContractRefKind.CONTROL_POLICY, "example.control.reuse", "5"
        ),
    )


def _variants(*items):
    return tuple(
        OracleVariant(
            name,
            role,
            _ref(
                ContractRefKind.EXECUTION_RECIPE,
                f"example.recipe.{name}",
                "0",
            ),
        )
        for name, role in items
    )


def _method_cases():
    return (
        (
            GoldenMethod("candidate", _artifact("golden", "3")),
            _variants(("candidate", VariantRole.CANDIDATE)),
        ),
        (
            DifferentialMethod("candidate", "reference"),
            _variants(
                ("candidate", VariantRole.CANDIDATE),
                ("reference", VariantRole.REFERENCE),
            ),
        ),
        (
            MetamorphicMethod(
                "candidate",
                "transformed",
                _ref(ContractRefKind.TRANSFORM_POLICY),
            ),
            _variants(
                ("candidate", VariantRole.CANDIDATE),
                ("transformed", VariantRole.TRANSFORMED),
            ),
        ),
        (
            InvariantMethod(
                "candidate", _ref(ContractRefKind.INVARIANT_POLICY)
            ),
            _variants(("candidate", VariantRole.CANDIDATE)),
        ),
        (
            ConsensusMethod("candidate", ("reference.a", "reference.b"), 2),
            _variants(
                ("candidate", VariantRole.CANDIDATE),
                ("reference.a", VariantRole.REFERENCE),
                ("reference.b", VariantRole.REFERENCE),
            ),
        ),
        (
            StatisticalBaselineMethod("candidate", "control", "latency.p99"),
            _variants(
                ("candidate", VariantRole.CANDIDATE),
                ("control", VariantRole.CONTROL),
            ),
        ),
        (
            ResourceGrowthMethod("candidate", "gpu_memory", "request_count"),
            _variants(("candidate", VariantRole.CANDIDATE)),
        ),
    )


def _spec(method=None, variants=None, **changes):
    if method is None:
        method, variants = _method_cases()[1]
    statistical = type(method) is StatisticalBaselineMethod
    resource_growth = type(method) is ResourceGrowthMethod
    values = {
        "oracle_id": f"example.{method.method_id}",
        "oracle_version": "1.0.0",
        "declared_origin": OracleOrigin.MAINTAINER_PRESET,
        "consequence_domain": (
            ConsequenceDomain.PERFORMANCE
            if statistical or resource_growth
            else ConsequenceDomain.CORRECTNESS
        ),
        "method": method,
        "applicability": ApplicabilitySpec(
            domain_id="example.domain",
            calibrated_domain=_artifact(),
            required_capabilities=("linux", "repeatable"),
            out_of_domain_reason="DOMAIN_MISMATCH",
        ),
        "variants": variants,
        "collectors": (
            _ref(ContractRefKind.COLLECTOR, "example.collector.a", "4"),
            _ref(ContractRefKind.COLLECTOR, "example.collector.b", "5"),
        ),
        "normalizer": _ref(ContractRefKind.NORMALIZER, fill="6"),
        "comparator": _ref(ContractRefKind.COMPARATOR, fill="7"),
        "execution_protocol": ExecutionProtocol(
            warmup_runs=1,
            repetitions=5,
            quorum=QuorumSpec(4, 5),
            timeout_ms=30_000,
            max_retries=1,
            retry_reasons=(RetryReason.BROKER_LEASE_LOST,),
        ),
        "healthy_relation": _ref(
            ContractRefKind.HEALTHY_RELATION_POLICY, fill="8"
        ),
        "decision_policy": _ref(ContractRefKind.DECISION_POLICY, fill="9"),
        "qualification_policy": _ref(
            ContractRefKind.QUALIFICATION_POLICY, fill="a"
        ),
        "baseline_policy": (
            _ref(ContractRefKind.BASELINE_POLICY, fill="b")
            if statistical
            else None
        ),
        "threshold_policy": (
            _ref(ContractRefKind.THRESHOLD_POLICY, fill="c")
            if statistical or resource_growth
            else None
        ),
        "cross_gate_reproducibility": CrossGateReproducibility(
            mode=(
                ReproducibilityMode.STATISTICAL
                if statistical
                else ReproducibilityMode.DETERMINISTIC
            ),
            require_same_direction=statistical,
            require_normalized_equality=not statistical,
            max_effect_delta=(
                CanonicalDecimal.parse("0.05") if statistical else None
            ),
        ),
        "reason_vocabulary": ReasonVocabulary(
            violation=("RELATION_VIOLATED",),
            passed=("RELATION_HOLDS",),
            inconclusive=(
                "DOMAIN_MISMATCH",
                "INSUFFICIENT_SAMPLES",
                "REFERENCE_UNAVAILABLE",
            ),
        ),
        "control_evidence_role": ControlEvidenceRole.ORACLE_ONLY,
        "causal_control": None,
    }
    values.update(changes)
    return OracleSpec(**values)


def _bundle(**changes):
    values = {
        "bundle_id": "example.bundle",
        "bundle_version": "1.0.0",
        "required_guards": (
            _ref(ContractRefKind.ORACLE_SPEC, "example.guard", "d"),
        ),
        "primary_oracles": (
            _ref(ContractRefKind.ORACLE_SPEC, "example.primary", "e"),
        ),
        "supporting_oracles": (
            _ref(ContractRefKind.ORACLE_SPEC, "example.support", "f"),
        ),
        "primary_combination": PrimaryCombination.ALL,
        "k": None,
        "control_evidence_role": ControlEvidenceRole.ORACLE_ONLY,
        "control_oracle": None,
        "primary_metric_oracle": None,
        "multiplicity_policy": None,
    }
    values.update(changes)
    return OracleBundle(**values)


class OracleSpecContractTests(unittest.TestCase):
    def test_all_typed_methods_round_trip_with_stable_content_identity(self):
        expected_ids = {
            "golden",
            "differential",
            "metamorphic",
            "invariant",
            "consensus",
            "statistical_baseline",
            "resource_growth",
        }
        observed = set()
        for method, variants in _method_cases():
            with self.subTest(method=method.method_id):
                original = _spec(method, variants)
                restored = OracleSpec.from_document(original.to_document())
                from_json = OracleSpec.from_json(
                    json.dumps(original.to_document()).encode("utf-8")
                )
                self.assertEqual(restored, original)
                self.assertEqual(from_json, original)
                self.assertEqual(restored.content_sha256, original.content_sha256)
                self.assertEqual(restored.ref.kind, ContractRefKind.ORACLE_SPEC)
                self.assertEqual(restored.ref.content_sha256, original.content_sha256)
                observed.add(method.method_id)
        self.assertEqual(observed, expected_ids)
        self.assertEqual(
            _spec().content_sha256,
            "e585860f25d3b66613cdafe2f85f09105e59b89661e2e1005fdb6bbe1fc9a17a",
        )

    def test_method_union_rejects_unknown_version_fields_and_role_mismatch(self):
        baseline = _spec()
        variants = (
            ("method_id", "invented"),
            ("method_version", 2),
            ("command", "sh -c true"),
        )
        for key, value in variants:
            document = baseline.to_document()
            document["method"][key] = value
            with self.subTest(key=key):
                with self.assertRaises(ContractError):
                    OracleSpec.from_document(document)

        with self.assertRaises(ContractError):
            _spec(
                DifferentialMethod("candidate", "reference"),
                _variants(
                    ("candidate", VariantRole.CANDIDATE),
                    ("reference", VariantRole.CANDIDATE),
                ),
            )
        with self.assertRaises(ContractError):
            _spec(
                InvariantMethod(
                    "missing", _ref(ContractRefKind.INVARIANT_POLICY)
                ),
                _variants(("candidate", VariantRole.CANDIDATE)),
            )

    def test_method_specific_policy_kinds_and_baseline_rules_fail_closed(self):
        with self.assertRaises(ContractError):
            MetamorphicMethod(
                "candidate",
                "transformed",
                _ref(ContractRefKind.COMPARATOR),
            )
        with self.assertRaises(ContractError):
            InvariantMethod(
                "candidate", _ref(ContractRefKind.DECISION_POLICY)
            )

        statistical, variants = _method_cases()[5]
        with self.assertRaises(ContractError):
            _spec(statistical, variants, baseline_policy=None)
        with self.assertRaises(ContractError):
            _spec(statistical, variants, threshold_policy=None)
        with self.assertRaises(ContractError):
            _spec(baseline_policy=_ref(ContractRefKind.BASELINE_POLICY))
        floating_correctness = _spec(
            threshold_policy=_ref(ContractRefKind.THRESHOLD_POLICY)
        )
        self.assertIn(
            ContractRefKind.THRESHOLD_POLICY,
            {ref.kind for ref in floating_correctness.component_refs},
        )
        growth, growth_variants = _method_cases()[6]
        with self.assertRaises(ContractError):
            _spec(growth, growth_variants, threshold_policy=None)

    def test_each_method_rejects_ambiguous_parameters(self):
        invalid_factories = (
            lambda: GoldenMethod("candidate", object()),
            lambda: GoldenMethod("candidate", _artifact("not_golden")),
            lambda: DifferentialMethod("same", "same"),
            lambda: MetamorphicMethod(
                "same",
                "same",
                _ref(ContractRefKind.TRANSFORM_POLICY),
            ),
            lambda: InvariantMethod(
                "candidate", _ref(ContractRefKind.TRANSFORM_POLICY)
            ),
            lambda: ConsensusMethod("candidate", ("only",), 1),
            lambda: ConsensusMethod("candidate", ("a", "b"), 1),
            lambda: ConsensusMethod("candidate", ("a", "b"), True),
            lambda: ConsensusMethod("candidate", ("a", "b"), 3),
            lambda: ConsensusMethod("candidate", ("candidate", "b"), 2),
            lambda: StatisticalBaselineMethod("same", "same", "latency"),
            lambda: ResourceGrowthMethod("candidate", "bad metric", "axis"),
            lambda: OracleVariant(
                "candidate",
                "candidate",
                _ref(ContractRefKind.EXECUTION_RECIPE),
            ),
            lambda: OracleVariant(
                "candidate",
                VariantRole.CANDIDATE,
                _ref(ContractRefKind.EXECUTION_BLOCK),
            ),
        )
        for index, factory in enumerate(invalid_factories):
            with self.subTest(index=index):
                with self.assertRaises(ContractError):
                    factory()

    def test_execution_protocol_is_closed_and_boolean_safe(self):
        invalid = (
            {"warmup_runs": True},
            {"repetitions": 0},
            {"quorum": QuorumSpec(1, 1)},
            {"timeout_ms": 0},
            {"max_retries": True},
            {
                "max_retries": 0,
                "retry_reasons": (RetryReason.BROKER_LEASE_LOST,),
            },
            {"max_retries": 1, "retry_reasons": ()},
            {
                "max_retries": 1,
                "retry_reasons": (
                    RetryReason.BROKER_LEASE_LOST,
                    RetryReason.BROKER_LEASE_LOST,
                ),
            },
        )
        base = {
            "warmup_runs": 0,
            "repetitions": 2,
            "quorum": QuorumSpec(1, 2),
            "timeout_ms": 100,
            "max_retries": 0,
            "retry_reasons": (),
        }
        for changes in invalid:
            with self.subTest(changes=changes):
                values = dict(base)
                values.update(changes)
                with self.assertRaises(ContractError):
                    ExecutionProtocol(**values)

        document = _spec().to_document()
        document["execution_protocol"]["retry_reasons"] = ["result_looks_bad"]
        with self.assertRaises(ContractError):
            OracleSpec.from_document(document)

    def test_reason_vocabulary_and_applicability_are_three_state_and_closed(self):
        with self.assertRaises(ContractError):
            ReasonVocabulary(
                violation=("SAME",),
                passed=("SAME",),
                inconclusive=("UNKNOWN",),
            )
        with self.assertRaises(ContractError):
            ReasonVocabulary(
                violation=("$(run)",),
                passed=("PASS",),
                inconclusive=("UNKNOWN",),
            )
        with self.assertRaises(ContractError):
            _spec(
                applicability=ApplicabilitySpec(
                    "example.domain",
                    _artifact(),
                    (),
                    "NOT_DECLARED",
                )
            )
        with self.assertRaises(ContractError):
            ApplicabilitySpec(
                "example.domain",
                _artifact("not_calibrated_domain"),
                (),
                "DOMAIN_MISMATCH",
            )

    def test_control_evidence_role_does_not_double_count_oracle_evidence(self):
        method, reference_variants = _method_cases()[1]
        control_variants = _variants(
            ("candidate", VariantRole.CANDIDATE),
            ("reference", VariantRole.CONTROL),
        )
        self.assertEqual(
            _spec(
                method,
                control_variants,
                control_evidence_role=ControlEvidenceRole.DUAL_ROLE,
                causal_control=_causal_control("reference"),
            ).control_evidence_role,
            ControlEvidenceRole.DUAL_ROLE,
        )
        with self.assertRaises(ContractError):
            _spec(
                method,
                control_variants,
                control_evidence_role=ControlEvidenceRole.CAUSAL_ONLY,
                causal_control=_causal_control("reference"),
            )
        with self.assertRaises(ContractError):
            _spec(
                method,
                reference_variants,
                control_evidence_role=ControlEvidenceRole.DUAL_ROLE,
                causal_control=_causal_control("reference"),
            )

    def test_cross_gate_reproducibility_separates_deterministic_and_statistics(self):
        invalid = (
            {
                "mode": ReproducibilityMode.DETERMINISTIC,
                "require_same_direction": False,
                "require_normalized_equality": True,
                "max_effect_delta": CanonicalDecimal.parse("0.1"),
            },
            {
                "mode": ReproducibilityMode.STATISTICAL,
                "require_same_direction": False,
                "require_normalized_equality": False,
                "max_effect_delta": CanonicalDecimal.parse("0.1"),
            },
            {
                "mode": ReproducibilityMode.STATISTICAL,
                "require_same_direction": True,
                "require_normalized_equality": True,
                "max_effect_delta": CanonicalDecimal.parse("0.1"),
            },
            {
                "mode": ReproducibilityMode.STATISTICAL,
                "require_same_direction": True,
                "require_normalized_equality": False,
                "max_effect_delta": None,
            },
            {
                "mode": ReproducibilityMode.STATISTICAL,
                "require_same_direction": True,
                "require_normalized_equality": False,
                "max_effect_delta": CanonicalDecimal.parse("-0.1"),
            },
        )
        for values in invalid:
            with self.subTest(values=values):
                with self.assertRaises(ContractError):
                    CrossGateReproducibility(**values)

        document = _spec(*_method_cases()[5]).to_document()
        document["cross_gate_reproducibility"]["max_effect_delta"] = 0.1
        with self.assertRaises(ContractError):
            OracleSpec.from_document(document)

    def test_refs_are_exactly_typed_and_component_refs_are_complete(self):
        method, variants = _method_cases()[2]
        spec = _spec(method, variants)
        kinds = tuple(ref.kind for ref in spec.component_refs)
        self.assertEqual(
            set(kinds),
            {
                ContractRefKind.COLLECTOR,
                ContractRefKind.NORMALIZER,
                ContractRefKind.COMPARATOR,
                ContractRefKind.HEALTHY_RELATION_POLICY,
                ContractRefKind.DECISION_POLICY,
                ContractRefKind.QUALIFICATION_POLICY,
                ContractRefKind.TRANSFORM_POLICY,
            },
        )
        self.assertEqual(kinds, tuple(sorted(kinds, key=lambda item: item.value)))
        self.assertEqual(
            {ref.kind for ref in spec.execution_recipe_refs},
            {ContractRefKind.EXECUTION_RECIPE},
        )
        self.assertTrue(
            set(spec.execution_recipe_refs).isdisjoint(spec.component_refs)
        )
        with self.assertRaises(ContractError):
            _spec(normalizer=_ref(ContractRefKind.COLLECTOR))
        with self.assertRaises(ContractError):
            _spec(
                collectors=(
                    _ref(ContractRefKind.COLLECTOR),
                    _ref(ContractRefKind.COLLECTOR, fill="2"),
                )
            )
        method = DifferentialMethod("candidate", "reference")
        conflicting_variants = list(
            _variants(
                ("candidate", VariantRole.CANDIDATE),
                ("reference", VariantRole.REFERENCE),
            )
        )
        conflicting_variants[1] = dataclasses.replace(
            conflicting_variants[1],
            execution_recipe=dataclasses.replace(
                conflicting_variants[0].execution_recipe,
                content_sha256="f" * 64,
            ),
        )
        with self.assertRaises(ContractError):
            _spec(method, tuple(conflicting_variants))

    def test_declared_origin_is_hash_bound_provenance_not_admission(self):
        specs = tuple(_spec(declared_origin=origin) for origin in OracleOrigin)
        self.assertEqual(len({spec.content_sha256 for spec in specs}), len(specs))
        for spec in specs:
            document = spec.to_document()
            self.assertEqual(document["declared_origin"], spec.declared_origin.value)
            rendered = repr(document)
            self.assertNotIn("trust_tier", rendered)
            self.assertNotIn("approved", rendered)
            self.assertNotIn("active", rendered)
        document = specs[0].to_document()
        document["declared_origin"] = "self_asserted_trusted"
        with self.assertRaises(ContractError):
            OracleSpec.from_document(document)

    def test_causal_control_freezes_every_prerequisite_and_exact_variant_set(self):
        method = GoldenMethod("candidate", _artifact("golden"))
        variants = _variants(
            ("candidate", VariantRole.CANDIDATE),
            ("control", VariantRole.CONTROL),
        )
        causal = _causal_control()
        spec = _spec(
            method,
            variants,
            control_evidence_role=ControlEvidenceRole.CAUSAL_ONLY,
            causal_control=causal,
        )
        self.assertEqual(spec.dependent_oracle_spec_refs, (causal.correctness_guard,))
        self.assertTrue(set(causal.component_refs).issubset(spec.component_refs))
        self.assertEqual(OracleSpec.from_document(spec.to_document()), spec)

        with self.assertRaises(ContractError):
            _spec(
                method,
                variants,
                control_evidence_role=ControlEvidenceRole.CAUSAL_ONLY,
                causal_control=None,
            )
        with self.assertRaises(ContractError):
            _spec(
                method,
                variants,
                control_evidence_role=ControlEvidenceRole.ORACLE_ONLY,
                causal_control=causal,
            )
        with self.assertRaises(ContractError):
            _spec(
                method,
                (*variants, *_variants(("unused", VariantRole.REFERENCE))),
                control_evidence_role=ControlEvidenceRole.CAUSAL_ONLY,
                causal_control=causal,
            )
        with self.assertRaises(ContractError):
            _spec(
                method,
                (*variants, *_variants(("other", VariantRole.CONTROL))),
                control_evidence_role=ControlEvidenceRole.CAUSAL_ONLY,
                causal_control=causal,
            )

    def test_causal_control_policy_kinds_and_self_guard_fail_closed(self):
        causal = _causal_control()
        fields = {
            "control_policy": ContractRefKind.DECISION_POLICY,
            "causal_prediction": ContractRefKind.CONTROL_POLICY,
            "correctness_guard": ContractRefKind.INVARIANT_POLICY,
            "target_association": ContractRefKind.CONTROL_POLICY,
            "reuse_policy": ContractRefKind.RESET_POLICY,
        }
        for field, wrong_kind in fields.items():
            with self.subTest(field=field):
                with self.assertRaises(ContractError):
                    dataclasses.replace(causal, **{field: _ref(wrong_kind)})

        method = GoldenMethod("candidate", _artifact("golden"))
        variants = _variants(
            ("candidate", VariantRole.CANDIDATE),
            ("control", VariantRole.CONTROL),
        )
        self_guard = dataclasses.replace(
            causal,
            correctness_guard=_ref(
                ContractRefKind.ORACLE_SPEC, "example.golden"
            ),
        )
        with self.assertRaises(ContractError):
            _spec(
                method,
                variants,
                control_evidence_role=ControlEvidenceRole.CAUSAL_ONLY,
                causal_control=self_guard,
            )

        document = causal.to_document()
        for key in tuple(document):
            missing = dict(document)
            missing.pop(key)
            with self.subTest(missing=key):
                with self.assertRaises(ContractError):
                    CausalControlSpec.from_document(missing)

    def test_contracts_deep_freeze_inputs_and_hash_semantic_changes(self):
        collectors = [
            _ref(ContractRefKind.COLLECTOR, "example.collector.a", "1")
        ]
        variants = [
            OracleVariant(
                "candidate",
                VariantRole.CANDIDATE,
                _ref(
                    ContractRefKind.EXECUTION_RECIPE,
                    "example.recipe.candidate",
                    "0",
                ),
            )
        ]
        spec = _spec(
            GoldenMethod("candidate", _artifact("golden")),
            variants,
            collectors=collectors,
        )
        collectors.append(_ref(ContractRefKind.COLLECTOR, "injected", "2"))
        variants.extend(
            _variants(("injected", VariantRole.REFERENCE))
        )
        self.assertEqual(len(spec.collectors), 1)
        self.assertEqual(len(spec.variants), 1)
        with self.assertRaises(dataclasses.FrozenInstanceError):
            spec.oracle_id = "changed"

        changed = _spec(
            GoldenMethod("candidate", _artifact("golden", "9")),
            _variants(("candidate", VariantRole.CANDIDATE)),
        )
        self.assertNotEqual(spec.content_sha256, changed.content_sha256)

    def test_external_parser_rejects_duplicate_keys_and_result_driven_fields(self):
        document = _spec().to_document()
        payload = json.dumps(document, separators=(",", ":")).encode("utf-8")
        duplicate = payload.replace(
            b'"oracle_id":',
            b'"oracle_id":"shadow","oracle_id":',
            1,
        )
        with self.assertRaises(ContractError):
            OracleSpec.from_json(duplicate)

        for forbidden in (
            "trusted",
            "approved",
            "active",
            "current_observation",
            "shell",
            "url",
            "threshold",
        ):
            mutated = dict(document)
            mutated[forbidden] = "injected"
            with self.subTest(forbidden=forbidden):
                with self.assertRaises(ContractError):
                    OracleSpec.from_document(mutated)

        for field, value in (
            ("contract_kind", "not_oracle_spec"),
            ("contract_kind", True),
            ("schema_version", 2),
            ("schema_version", True),
        ):
            mutated = dict(document)
            mutated[field] = value
            with self.subTest(field=field, value=value):
                with self.assertRaises(ContractError):
                    OracleSpec.from_document(mutated)
        missing = dict(document)
        missing.pop("qualification_policy")
        with self.assertRaises(ContractError):
            OracleSpec.from_document(missing)


class OracleBundleContractTests(unittest.TestCase):
    def test_bundle_round_trip_hash_and_oracle_ref_projection(self):
        original = _bundle()
        restored = OracleBundle.from_document(original.to_document())
        from_json = OracleBundle.from_json(
            json.dumps(original.to_document()).encode("utf-8")
        )
        self.assertEqual(restored, original)
        self.assertEqual(from_json, original)
        self.assertEqual(original.ref.kind, ContractRefKind.ORACLE_BUNDLE)
        self.assertEqual(original.ref.content_sha256, original.content_sha256)
        self.assertEqual(
            original.content_sha256,
            "a7382d7c877895d13047d3fa3d9fe611e1bc46d19dcca56dff9b3a35fbcad808",
        )
        self.assertEqual(
            set(original.oracle_spec_refs),
            set(
                original.required_guards
                + original.primary_oracles
                + original.supporting_oracles
            ),
        )

    def test_all_any_and_k_of_n_are_frozen_before_observations(self):
        primary = (
            _ref(ContractRefKind.ORACLE_SPEC, "primary.a", "1"),
            _ref(ContractRefKind.ORACLE_SPEC, "primary.b", "2"),
            _ref(ContractRefKind.ORACLE_SPEC, "primary.c", "3"),
        )
        for mode, k in (
            (PrimaryCombination.ALL, None),
            (PrimaryCombination.ANY, None),
            (PrimaryCombination.K_OF_N, 2),
        ):
            with self.subTest(mode=mode):
                value = _bundle(
                    primary_oracles=primary,
                    primary_combination=mode,
                    k=k,
                    primary_metric_oracle=primary[0],
                    multiplicity_policy=_ref(
                        ContractRefKind.DECISION_POLICY,
                        "example.multiple_comparison",
                    ),
                )
                self.assertEqual(
                    OracleBundle.from_document(value.to_document()), value
                )

        invalid = (
            (PrimaryCombination.ALL, 1),
            (PrimaryCombination.ANY, 1),
            (PrimaryCombination.K_OF_N, None),
            (PrimaryCombination.K_OF_N, 0),
            (PrimaryCombination.K_OF_N, 4),
            (PrimaryCombination.K_OF_N, True),
        )
        for mode, k in invalid:
            with self.subTest(mode=mode, k=k):
                with self.assertRaises(ContractError):
                    _bundle(
                        primary_oracles=primary,
                        primary_combination=mode,
                        k=k,
                        primary_metric_oracle=primary[0],
                        multiplicity_policy=_ref(
                            ContractRefKind.DECISION_POLICY,
                            "example.multiple_comparison",
                        ),
                    )

        correctness_bundle = _bundle(
            primary_oracles=primary,
            primary_combination=PrimaryCombination.ALL,
            k=None,
        )
        self.assertIsNone(correctness_bundle.multiplicity_policy)
        with self.assertRaises(ContractError):
            _bundle(
                primary_oracles=primary,
                primary_metric_oracle=primary[0],
                multiplicity_policy=None,
            )
        with self.assertRaises(ContractError):
            _bundle(
                primary_oracles=primary,
                primary_metric_oracle=_ref(
                    ContractRefKind.ORACLE_SPEC, "outside.primary"
                ),
                multiplicity_policy=_ref(
                    ContractRefKind.DECISION_POLICY,
                    "example.multiple_comparison",
                ),
            )

    def test_bundle_roles_are_disjoint_support_cannot_be_the_only_primary(self):
        shared = _ref(ContractRefKind.ORACLE_SPEC, "shared", "1")
        with self.assertRaises(ContractError):
            _bundle(required_guards=(shared,), primary_oracles=(shared,))
        with self.assertRaises(ContractError):
            _bundle(primary_oracles=())
        with self.assertRaises(ContractError):
            _bundle(primary_oracles=(_ref(ContractRefKind.COMPARATOR),))

    def test_bundle_causal_role_is_anchored_to_an_exact_member_spec(self):
        control = _ref(ContractRefKind.ORACLE_SPEC, "example.control", "1")
        bundle = _bundle(
            supporting_oracles=(control,),
            control_evidence_role=ControlEvidenceRole.CAUSAL_ONLY,
            control_oracle=control,
        )
        self.assertEqual(bundle.control_oracle, control)
        self.assertEqual(OracleBundle.from_document(bundle.to_document()), bundle)
        with self.assertRaises(ContractError):
            _bundle(
                control_evidence_role=ControlEvidenceRole.CAUSAL_ONLY,
                control_oracle=None,
            )
        with self.assertRaises(ContractError):
            _bundle(
                control_evidence_role=ControlEvidenceRole.DUAL_ROLE,
                control_oracle=_ref(
                    ContractRefKind.ORACLE_SPEC, "outside.control"
                ),
            )
        with self.assertRaises(ContractError):
            _bundle(
                control_evidence_role=ControlEvidenceRole.ORACLE_ONLY,
                control_oracle=_bundle().primary_oracles[0],
            )

    def test_bundle_has_no_self_asserted_authority_or_runtime_selection(self):
        document = _bundle().to_document()
        rendered = repr(document)
        for forbidden in (
            "trust",
            "approved",
            "active",
            "observation",
            "verdict",
            "command",
        ):
            self.assertNotIn(forbidden, rendered)
            mutated = dict(document)
            mutated[forbidden] = True
            with self.assertRaises(ContractError):
                OracleBundle.from_document(mutated)

        for field, value in (
            ("contract_kind", "not_oracle_bundle"),
            ("contract_kind", True),
            ("schema_version", 2),
            ("schema_version", True),
        ):
            mutated = dict(document)
            mutated[field] = value
            with self.subTest(field=field, value=value):
                with self.assertRaises(ContractError):
                    OracleBundle.from_document(mutated)
        missing = dict(document)
        missing.pop("primary_combination")
        with self.assertRaises(ContractError):
            OracleBundle.from_document(missing)


class OracleImportBoundaryTests(unittest.TestCase):
    def test_contract_module_has_no_execution_or_production_imports(self):
        source_path = (
            Path(__file__).parents[1]
            / "src"
            / "validation_core"
            / "contracts"
            / "oracle.py"
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
            "subprocess",
            "shlex",
            "importlib",
            "pathlib",
            "socket",
            "src.check_submission",
            "src.validation_core.routing",
            "src.validation_core.registry",
        ):
            self.assertNotIn(forbidden, imported)
        self.assertTrue(called.isdisjoint({"eval", "exec", "compile", "__import__"}))


if __name__ == "__main__":
    unittest.main()

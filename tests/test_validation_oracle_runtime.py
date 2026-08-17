import dataclasses
import hashlib
import ast
from pathlib import Path
import unittest

from src.validation_core.contracts import (
    ArtifactRef,
    CanonicalDecimal,
    CanonicalTypedValue,
    CanonicalValueKind,
    ControlEvidenceRole,
    ContractError,
    ContractRef,
    ContractRefKind,
    DifferentialMethod,
    ExecutionProtocol,
    OracleVerdict,
    QuorumSpec,
    ReasonVocabulary,
    RetryReason,
    VariantRole,
)
from src.validation_core.oracle import (
    ApplicabilityResult,
    ArtifactIdentityNormalizer,
    ArtifactIntegrityError,
    AtomicCapturedArtifact,
    AtomicDataError,
    AtomicOracleCatalog,
    AtomicOracleEngine,
    AtomicOracleError,
    AtomicOracleErrorCode,
    AtomicResultClass,
    AtomicRunRequest,
    AtomicRunResult,
    AtomicRunStatus,
    BooleanInvariantComparator,
    CatalogError,
    ConsensusEqualityComparator,
    ExactEqualityComparator,
    GoldenArtifactComparator,
    RatioUpperBoundComparator,
    RunStatusNormalizer,
    ScalarEstimate,
    TrialDecision,
    Utf8ArtifactNormalizer,
)
from tests.test_validation_oracle_contracts import (
    _causal_control,
    _method_cases,
    _spec,
    _variants,
)


def _digest(payload):
    return hashlib.sha256(payload).hexdigest()


def _artifact(role, payload, *, size=None, digest=None, media_type="text/plain"):
    return ArtifactRef(
        role=role,
        media_type=media_type,
        size_bytes=len(payload) if size is None else size,
        content_sha256=_digest(payload) if digest is None else digest,
    )


def _protocol(*, warmup=0, repetitions=3, required=2, retries=0, reasons=()):
    return ExecutionProtocol(
        warmup_runs=warmup,
        repetitions=repetitions,
        quorum=QuorumSpec(required, repetitions),
        timeout_ms=500,
        max_retries=retries,
        retry_reasons=reasons,
    )


def _reason_vocabulary():
    return ReasonVocabulary(
        violation=("RELATION_VIOLATED",),
        passed=("RELATION_HOLDS",),
        inconclusive=(
            "DOMAIN_MISMATCH",
            "ENVIRONMENT_UNSTABLE",
            "CI_CROSSES_BOUNDARY",
            "INSUFFICIENT_SAMPLES",
            "METRIC_INVALID",
            "QUORUM_NOT_MET",
            "REFERENCE_UNAVAILABLE",
        ),
    )


def _policy_refs(spec):
    refs = [spec.healthy_relation, spec.decision_policy, spec.qualification_policy]
    if spec.baseline_policy is not None:
        refs.append(spec.baseline_policy)
    if spec.threshold_policy is not None:
        refs.append(spec.threshold_policy)
    for field in ("transform_policy", "invariant_policy"):
        reference = getattr(spec.method, field, None)
        if reference is not None:
            refs.append(reference)
    return tuple(
        sorted(
            refs,
            key=lambda item: (
                item.kind.value,
                item.contract_id,
                item.contract_version,
                item.content_sha256,
            ),
        )
    )


def _runtime_spec(*, protocol=None, statistical=False, normalizer=None, comparator=None):
    method, variants = _method_cases()[5 if statistical else 1]
    collector = ContractRef(
        ContractRefKind.COLLECTOR,
        "runtime.collector",
        "1.0.0",
        "d" * 64,
    )
    base = _spec(
        method,
        variants,
        collectors=(collector,),
        execution_protocol=protocol or _protocol(),
        reason_vocabulary=_reason_vocabulary(),
    )
    normalizer = normalizer or (
        ArtifactIdentityNormalizer() if statistical else Utf8ArtifactNormalizer()
    )
    comparator = comparator or (
        RatioUpperBoundComparator(
            _policy_refs(base),
            CanonicalDecimal.parse("1.2"),
            "paired_bootstrap",
            CanonicalDecimal.parse("0.95"),
            100,
        )
        if statistical
        else ExactEqualityComparator(_policy_refs(base))
    )
    return (
        dataclasses.replace(
            base,
            normalizer=normalizer.atom_ref,
            comparator=comparator.atom_ref,
        ),
        normalizer,
        comparator,
        collector,
    )


class ScriptedRunner:
    def __init__(self, recipe_ref, collector, action):
        self.recipe_ref = recipe_ref
        self.collector_refs = (collector,)
        self._collector = collector
        self._action = action
        self.calls = []

    def __call__(self, request):
        self.calls.append(request)
        status, artifact = self._action(request)
        captured = ()
        if artifact is not None:
            invocation = request.content_sha256
            captured = (
                AtomicCapturedArtifact(
                    artifact=artifact,
                    collector=self._collector,
                    capture_id=f"capture.{invocation}",
                    provenance_sha256=_digest(
                        f"provenance:{invocation}".encode("ascii")
                    ),
                ),
            )
        return AtomicRunResult(status, captured, status.value)


class BoundNormalizer:
    def __init__(self, atom_ref, callback):
        self.atom_ref = atom_ref
        self.reason_codes = ("METRIC_INVALID",)
        self._callback = callback

    def __call__(self, variant_id, repetition_index, result, read_artifact):
        return self._callback(
            variant_id,
            repetition_index,
            result,
            read_artifact,
        )


class BoundComparator:
    def __init__(self, atom_ref, policy_refs, callback):
        self.atom_ref = atom_ref
        self.policy_refs = policy_refs
        self.reason_codes = {
            OracleVerdict.VIOLATION: ("RELATION_VIOLATED",),
            OracleVerdict.PASS: ("RELATION_HOLDS",),
            OracleVerdict.INCONCLUSIVE: ("METRIC_INVALID",),
        }
        self.supported_method_types = (DifferentialMethod,)
        self.threshold_values = ()
        self._callback = callback

    def __call__(
        self,
        method,
        values,
        read_artifact,
        *,
        repetition_index,
    ):
        return self._callback(method, values)


def _build(spec, normalizer, comparator, collector, actions, store):
    catalog = AtomicOracleCatalog()
    runners = {}
    for variant in spec.variants:
        action = actions[variant.variant_id]
        runner = ScriptedRunner(variant.execution_recipe, collector, action)
        runners[variant.variant_id] = runner
        catalog.register_runner(variant.execution_recipe, runner)
    catalog.register_normalizer(normalizer.atom_ref, normalizer)
    catalog.register_comparator(comparator.atom_ref, comparator)
    engine = AtomicOracleEngine(catalog, store)
    applicability = ApplicabilityResult(
        spec.applicability.domain_id,
        spec.applicability.calibrated_domain.content_sha256,
        spec.qualification_policy,
        True,
        (spec.applicability.calibrated_domain,),
    )
    return engine, applicability, runners, catalog


def _base_store(spec, *payloads):
    domain_payload = b"{" + b" " * 40 + b"}"
    assert len(domain_payload) == spec.applicability.calibrated_domain.size_bytes
    # The contract fixture uses a synthetic digest; runtime tests bind it to
    # actual bytes so integrity checks exercise the real path.
    domain = _artifact(
        "calibrated_domain",
        domain_payload,
        media_type="application/json",
    )
    spec = dataclasses.replace(
        spec,
        applicability=dataclasses.replace(
            spec.applicability,
            calibrated_domain=domain,
        ),
    )
    store = {domain.content_sha256: domain_payload}
    for payload in payloads:
        store[_digest(payload)] = payload
    return spec, store


def _estimate_payload(
    spec,
    variant_id,
    repetition_index,
    estimate,
    lower,
    upper,
    *,
    samples=100,
    estimator="paired_bootstrap",
    confidence="0.95",
    qualification_sha256=None,
    pair_id=None,
):
    return ScalarEstimate(
        variant_id=variant_id,
        repetition_index=repetition_index,
        pair_id=pair_id or f"pair.{repetition_index}",
        metric_id=spec.method.metric_id,
        estimator_id=estimator,
        estimate=CanonicalDecimal.parse(str(estimate)),
        lower_bound=CanonicalDecimal.parse(str(lower)),
        upper_bound=CanonicalDecimal.parse(str(upper)),
        confidence=CanonicalDecimal.parse(confidence),
        sample_count=samples,
        qualification_policy_sha256=(
            qualification_sha256 or spec.qualification_policy.content_sha256
        ),
    ).to_json()


class CatalogAndBindingTests(unittest.TestCase):
    def test_causal_control_requires_the_later_coordinator_executor(self):
        method, _ = _method_cases()[0]
        spec = _spec(
            method,
            _variants(
                ("candidate", VariantRole.CANDIDATE),
                ("control", VariantRole.CONTROL),
            ),
            control_evidence_role=ControlEvidenceRole.CAUSAL_ONLY,
            causal_control=_causal_control(),
        )
        applicability = ApplicabilityResult(
            spec.applicability.domain_id,
            spec.applicability.calibrated_domain.content_sha256,
            spec.qualification_policy,
            True,
            (spec.applicability.calibrated_domain,),
        )
        engine = AtomicOracleEngine(AtomicOracleCatalog(), {})
        with self.assertRaises(AtomicOracleError) as raised:
            engine.execute(spec, applicability=applicability)
        self.assertEqual(
            raised.exception.code,
            AtomicOracleErrorCode.CAUSAL_CONTROL_NOT_COMPILED,
        )

    def test_catalog_requires_self_bound_atoms_and_seals_on_engine_creation(self):
        spec, normalizer, comparator, collector = _runtime_spec()
        spec, store = _base_store(spec)
        catalog = AtomicOracleCatalog()
        with self.assertRaises(CatalogError):
            catalog.register_normalizer(spec.normalizer, lambda *args: None)
        catalog.register_normalizer(normalizer.atom_ref, normalizer)
        catalog.register_comparator(comparator.atom_ref, comparator)
        for variant in spec.variants:
            runner = ScriptedRunner(
                variant.execution_recipe,
                collector,
                lambda request: (AtomicRunStatus.COMPLETED, None),
            )
            catalog.register_runner(variant.execution_recipe, runner)
        AtomicOracleEngine(catalog, store)
        self.assertTrue(catalog.sealed)
        with self.assertRaises(CatalogError):
            catalog.register_normalizer(normalizer.atom_ref, normalizer)

    def test_same_identity_and_version_cannot_register_two_hashes(self):
        catalog = AtomicOracleCatalog()
        first = Utf8ArtifactNormalizer("normalizer.identity")
        second_ref = dataclasses.replace(first.atom_ref, content_sha256="e" * 64)
        second = BoundNormalizer(second_ref, lambda *args: None)
        catalog.register_normalizer(first.atom_ref, first)
        with self.assertRaisesRegex(CatalogError, "multiple content hashes"):
            catalog.register_normalizer(second_ref, second)

    def test_comparator_hash_binds_supported_method_capabilities(self):
        spec, _, _, _ = _runtime_spec()
        broad = ExactEqualityComparator(_policy_refs(spec))

        class DifferentialOnlyComparator(ExactEqualityComparator):
            supported_method_types = (DifferentialMethod,)

        narrow = DifferentialOnlyComparator(_policy_refs(spec))
        self.assertEqual(broad.atom_ref.contract_id, narrow.atom_ref.contract_id)
        self.assertEqual(
            broad.atom_ref.contract_version,
            narrow.atom_ref.contract_version,
        )
        self.assertNotEqual(
            broad.atom_ref.content_sha256,
            narrow.atom_ref.content_sha256,
        )

    def test_comparator_policy_refs_must_exactly_match_spec(self):
        base, normalizer, _, collector = _runtime_spec(statistical=True)
        wrong_policy = ContractRef(
            ContractRefKind.THRESHOLD_POLICY,
            "runtime.wrong-threshold",
            "1.0.0",
            "f" * 64,
        )
        comparator = RatioUpperBoundComparator(
            (*_policy_refs(base), wrong_policy),
            CanonicalDecimal.parse("1.2"),
            "paired_bootstrap",
            CanonicalDecimal.parse("0.95"),
            100,
        )
        spec = dataclasses.replace(base, comparator=comparator.atom_ref)
        spec, store = _base_store(spec, b"1")
        actions = {
            variant.variant_id: (
                lambda request: (
                    AtomicRunStatus.COMPLETED,
                    _artifact("metric", b"1"),
                )
            )
            for variant in spec.variants
        }
        engine, applicability, _, _ = _build(
            spec, normalizer, comparator, collector, actions, store
        )
        with self.assertRaises(AtomicOracleError) as raised:
            engine.execute(spec, applicability=applicability)
        self.assertEqual(
            raised.exception.code,
            AtomicOracleErrorCode.ATOM_POLICY_BINDING_INVALID,
        )

    def test_unregistered_hash_mismatch_fails_even_when_out_of_domain(self):
        spec, normalizer, comparator, collector = _runtime_spec()
        spec, store = _base_store(spec)
        catalog = AtomicOracleCatalog()
        catalog.register_normalizer(normalizer.atom_ref, normalizer)
        catalog.register_comparator(comparator.atom_ref, comparator)
        first = spec.variants[0]
        runner = ScriptedRunner(
            first.execution_recipe,
            collector,
            lambda request: (AtomicRunStatus.COMPLETED, None),
        )
        catalog.register_runner(first.execution_recipe, runner)
        engine = AtomicOracleEngine(catalog, store)
        applicability = ApplicabilityResult(
            spec.applicability.domain_id,
            spec.applicability.calibrated_domain.content_sha256,
            spec.qualification_policy,
            False,
            (spec.applicability.calibrated_domain,),
        )
        with self.assertRaises(CatalogError):
            engine.execute(spec, applicability=applicability)

    def test_runtime_reason_vocabulary_is_checked_before_execution(self):
        spec, normalizer, comparator, collector = _runtime_spec()
        spec = dataclasses.replace(
            spec,
            reason_vocabulary=ReasonVocabulary(
                violation=("RELATION_VIOLATED",),
                passed=("RELATION_HOLDS",),
                inconclusive=("DOMAIN_MISMATCH", "METRIC_INVALID"),
            ),
        )
        spec, store = _base_store(spec)
        actions = {
            variant.variant_id: lambda request: (
                AtomicRunStatus.COMPLETED,
                None,
            )
            for variant in spec.variants
        }
        engine, applicability, runners, _ = _build(
            spec, normalizer, comparator, collector, actions, store
        )
        with self.assertRaises(AtomicOracleError) as raised:
            engine.execute(spec, applicability=applicability)
        self.assertEqual(
            raised.exception.code,
            AtomicOracleErrorCode.ATOM_REASON_VOCABULARY_INVALID,
        )
        self.assertTrue(all(not runner.calls for runner in runners.values()))

    def test_artifact_thresholds_are_verified_during_preflight(self):
        for present_but_wrong, expected_code in (
            (False, AtomicOracleErrorCode.ARTIFACT_UNAVAILABLE),
            (True, AtomicOracleErrorCode.ARTIFACT_HASH_MISMATCH),
        ):
            with self.subTest(present_but_wrong=present_but_wrong):
                spec, normalizer, comparator, collector = _runtime_spec(
                    statistical=True,
                    protocol=_protocol(repetitions=1, required=1),
                )
                payload = b"good"
                artifact = _artifact("threshold", payload)

                class ArtifactThresholdComparator:
                    atom_ref = ContractRef(
                        ContractRefKind.COMPARATOR,
                        "test.comparator.artifact_threshold",
                        "1.0.0",
                        "e" * 64,
                    )
                    policy_refs = comparator.policy_refs
                    reason_codes = comparator.reason_codes
                    supported_method_types = comparator.supported_method_types
                    threshold_values = (
                        CanonicalTypedValue(
                            "threshold",
                            CanonicalValueKind.ARTIFACT,
                            artifact,
                        ),
                    )

                    def __call__(self, *args, **kwargs):
                        return comparator(*args, **kwargs)

                bound = ArtifactThresholdComparator()
                spec = dataclasses.replace(spec, comparator=bound.atom_ref)
                spec, store = _base_store(spec)
                if present_but_wrong:
                    store[artifact.content_sha256] = b"evil"
                actions = {
                    variant.variant_id: lambda request: (
                        AtomicRunStatus.COMPLETED,
                        None,
                    )
                    for variant in spec.variants
                }
                engine, applicability, runners, _ = _build(
                    spec,
                    normalizer,
                    bound,
                    collector,
                    actions,
                    store,
                )
                with self.assertRaises(ArtifactIntegrityError) as raised:
                    engine.execute(spec, applicability=applicability)
                self.assertEqual(raised.exception.code, expected_code)
                self.assertTrue(all(not runner.calls for runner in runners.values()))

    def test_applicability_is_bound_to_matcher_and_hash_stored_evidence(self):
        spec, normalizer, comparator, collector = _runtime_spec()
        spec, store = _base_store(spec)
        actions = {
            variant.variant_id: lambda request: (
                AtomicRunStatus.COMPLETED,
                None,
            )
            for variant in spec.variants
        }
        engine, applicability, runners, _ = _build(
            spec, normalizer, comparator, collector, actions, store
        )
        wrong_matcher = ContractRef(
            ContractRefKind.QUALIFICATION_POLICY,
            "runtime.other-matcher",
            "1.0.0",
            "e" * 64,
        )
        with self.assertRaises(AtomicOracleError) as raised:
            engine.execute(
                spec,
                applicability=dataclasses.replace(
                    applicability,
                    matcher=wrong_matcher,
                ),
            )
        self.assertEqual(
            raised.exception.code,
            AtomicOracleErrorCode.APPLICABILITY_BINDING_INVALID,
        )
        self.assertTrue(all(not runner.calls for runner in runners.values()))
        with self.assertRaises(ContractError):
            ApplicabilityResult(
                spec.applicability.domain_id,
                spec.applicability.calibrated_domain.content_sha256,
                spec.qualification_policy,
                True,
                (),
            )

    def test_comparator_method_compatibility_is_checked_before_execution(self):
        spec, normalizer, comparator, collector = _runtime_spec()
        incompatible = BoundComparator(
            comparator.atom_ref,
            _policy_refs(spec),
            lambda method, values: TrialDecision(
                OracleVerdict.PASS,
                "RELATION_HOLDS",
                values,
            ),
        )
        incompatible.supported_method_types = (str,)
        spec, store = _base_store(spec)
        actions = {
            variant.variant_id: lambda request: (
                AtomicRunStatus.COMPLETED,
                None,
            )
            for variant in spec.variants
        }
        engine, applicability, runners, _ = _build(
            spec, normalizer, incompatible, collector, actions, store
        )
        with self.assertRaises(AtomicOracleError) as raised:
            engine.execute(spec, applicability=applicability)
        self.assertEqual(
            raised.exception.code,
            AtomicOracleErrorCode.ATOM_METHOD_INCOMPATIBLE,
        )
        self.assertTrue(all(not runner.calls for runner in runners.values()))


class ArtifactAndInvocationTests(unittest.TestCase):
    def test_normalized_artifact_must_be_captured_by_its_source_run(self):
        for artifact_is_stored in (False, True):
            with self.subTest(artifact_is_stored=artifact_is_stored):
                spec, normalizer, comparator, collector = _runtime_spec(
                    protocol=_protocol(repetitions=1, required=1)
                )
                payload = b"synthetic"
                synthetic = _artifact("synthetic", payload)
                fabricated = BoundNormalizer(
                    normalizer.atom_ref,
                    lambda variant_id, *args: CanonicalTypedValue(
                        variant_id,
                        CanonicalValueKind.ARTIFACT,
                        synthetic,
                    ),
                )
                if artifact_is_stored:
                    spec, store = _base_store(spec, payload)
                else:
                    spec, store = _base_store(spec)
                actions = {
                    variant.variant_id: lambda request: (
                        AtomicRunStatus.COMPLETED,
                        None,
                    )
                    for variant in spec.variants
                }
                engine, applicability, _, _ = _build(
                    spec,
                    fabricated,
                    comparator,
                    collector,
                    actions,
                    store,
                )
                with self.assertRaises(AtomicOracleError) as raised:
                    engine.execute(spec, applicability=applicability)
                self.assertEqual(
                    raised.exception.code,
                    AtomicOracleErrorCode.ATOM_EXECUTION_FAILED,
                )

    def test_requests_and_normalized_values_bind_the_exact_invocation(self):
        protocol = _protocol(warmup=1, repetitions=2, required=2)
        spec, normalizer, comparator, collector = _runtime_spec(protocol=protocol)
        output = b"same"
        spec, store = _base_store(spec, output)
        ref = _artifact("stdout", output)
        actions = {
            variant.variant_id: lambda request, ref=ref: (
                AtomicRunStatus.COMPLETED,
                ref,
            )
            for variant in spec.variants
        }
        engine, applicability, runners, _ = _build(
            spec, normalizer, comparator, collector, actions, store
        )
        result = engine.execute(spec, applicability=applicability)
        self.assertEqual(result.verdict, OracleVerdict.PASS)
        self.assertEqual(len(result.run_records), 6)
        self.assertEqual(len({item.content_sha256 for item in result.run_records}), 6)
        self.assertEqual(
            [call.warmup for call in runners["candidate"].calls],
            [True, False, False],
        )
        measured = {
            (record.request.variant_id, record.request.repetition_index): record
            for record in result.run_records
            if not record.request.warmup
        }
        for value in result.normalized_values:
            self.assertEqual(
                value.source_run_sha256,
                measured[(value.variant_id, value.repetition_index)].content_sha256,
            )

    def test_request_hash_changes_for_recipe_retry_warmup_timeout_and_input(self):
        recipe = _method_cases()[1][1][0].execution_recipe
        payload = b"input"
        artifact = _artifact("input", payload)
        base = AtomicRunRequest(recipe, "candidate", 0, 0, False, 100, (artifact,))
        variants = (
            dataclasses.replace(base, recipe=dataclasses.replace(recipe, content_sha256="f" * 64)),
            dataclasses.replace(base, retry_index=1),
            dataclasses.replace(base, warmup=True),
            dataclasses.replace(base, timeout_ms=101),
            dataclasses.replace(base, inputs=()),
        )
        self.assertEqual(len({base.content_sha256, *(item.content_sha256 for item in variants)}), 6)

    def test_missing_input_is_hard_failure_before_any_runner_call(self):
        spec, normalizer, comparator, collector = _runtime_spec()
        spec, store = _base_store(spec, b"same")
        output = _artifact("stdout", b"same")
        actions = {
            variant.variant_id: lambda request: (
                AtomicRunStatus.COMPLETED,
                output,
            )
            for variant in spec.variants
        }
        engine, applicability, runners, _ = _build(
            spec, normalizer, comparator, collector, actions, store
        )
        missing = _artifact("input", b"missing")
        with self.assertRaises(ArtifactIntegrityError) as raised:
            engine.execute(spec, applicability=applicability, inputs=(missing,))
        self.assertEqual(
            raised.exception.code,
            AtomicOracleErrorCode.ARTIFACT_UNAVAILABLE,
        )
        self.assertTrue(all(not runner.calls for runner in runners.values()))

    def test_all_output_artifacts_are_verified_even_if_normalizer_ignores_them(self):
        status_normalizer = RunStatusNormalizer()
        spec, _, _, collector = _runtime_spec(normalizer=status_normalizer)
        comparator = ExactEqualityComparator(_policy_refs(spec))
        spec = dataclasses.replace(
            spec,
            normalizer=status_normalizer.atom_ref,
            comparator=comparator.atom_ref,
        )
        spec, store = _base_store(spec)
        bad = _artifact("ignored", b"payload")
        actions = {
            variant.variant_id: lambda request: (
                AtomicRunStatus.COMPLETED,
                bad,
            )
            for variant in spec.variants
        }
        engine, applicability, _, _ = _build(
            spec, status_normalizer, comparator, collector, actions, store
        )
        with self.assertRaises(ArtifactIntegrityError):
            engine.execute(spec, applicability=applicability)

    def test_size_and_hash_mismatch_are_distinct_hard_failures(self):
        for expected_code, bad_ref, stored_payload in (
            (
                AtomicOracleErrorCode.ARTIFACT_SIZE_MISMATCH,
                _artifact("stdout", b"actual", size=99),
                b"actual",
            ),
            (
                AtomicOracleErrorCode.ARTIFACT_HASH_MISMATCH,
                _artifact("stdout", b"expected"),
                b"tampered",
            ),
        ):
            with self.subTest(code=expected_code):
                spec, normalizer, comparator, collector = _runtime_spec()
                spec, store = _base_store(spec)
                store[bad_ref.content_sha256] = stored_payload
                actions = {
                    variant.variant_id: lambda request, ref=bad_ref: (
                        AtomicRunStatus.COMPLETED,
                        ref,
                    )
                    for variant in spec.variants
                }
                engine, applicability, _, _ = _build(
                    spec, normalizer, comparator, collector, actions, store
                )
                with self.assertRaises(ArtifactIntegrityError) as raised:
                    engine.execute(spec, applicability=applicability)
                self.assertEqual(raised.exception.code, expected_code)


class RetryWarmupAndFailureTests(unittest.TestCase):
    def test_only_frozen_infra_reason_retries_and_all_attempts_remain(self):
        protocol = _protocol(
            repetitions=1,
            required=1,
            retries=1,
            reasons=(RetryReason.BROKER_LEASE_LOST,),
        )
        spec, normalizer, comparator, collector = _runtime_spec(protocol=protocol)
        payload = b"same"
        spec, store = _base_store(spec, payload)
        output = _artifact("stdout", payload)

        def action(request):
            if request.variant_id == "candidate" and request.retry_index == 0:
                return AtomicRunStatus.BROKER_LEASE_LOST, None
            return AtomicRunStatus.COMPLETED, output

        actions = {variant.variant_id: action for variant in spec.variants}
        engine, applicability, _, _ = _build(
            spec, normalizer, comparator, collector, actions, store
        )
        result = engine.execute(spec, applicability=applicability)
        self.assertEqual(result.verdict, OracleVerdict.PASS)
        candidate_records = [
            item for item in result.run_records if item.request.variant_id == "candidate"
        ]
        self.assertEqual(
            [item.request.retry_index for item in candidate_records],
            [0, 1],
        )
        self.assertEqual(
            candidate_records[0].result.status,
            AtomicRunStatus.BROKER_LEASE_LOST,
        )
        premature = dataclasses.replace(
            result,
            result_class=AtomicResultClass.INFRA_INCONCLUSIVE,
            verdict=OracleVerdict.INCONCLUSIVE,
            reason_codes=("ENVIRONMENT_UNSTABLE",),
            trials=(),
            run_records=(candidate_records[0],),
            normalized_values=(),
        )
        with self.assertRaises(AtomicOracleError) as raised:
            engine.validate_result(spec, premature)
        self.assertEqual(
            raised.exception.code,
            AtomicOracleErrorCode.RESULT_REPLAY_MISMATCH,
        )

    def test_disallowed_or_exhausted_infra_status_is_inconclusive(self):
        protocol = _protocol(repetitions=1, required=1)
        spec, normalizer, comparator, collector = _runtime_spec(protocol=protocol)
        spec, store = _base_store(spec)
        actions = {
            variant.variant_id: lambda request: (
                AtomicRunStatus.DEVICE_LEASE_LOST,
                None,
            )
            for variant in spec.variants
        }
        engine, applicability, _, _ = _build(
            spec, normalizer, comparator, collector, actions, store
        )
        result = engine.execute(spec, applicability=applicability)
        self.assertEqual(result.result_class, AtomicResultClass.INFRA_INCONCLUSIVE)
        self.assertEqual(result.verdict, OracleVerdict.INCONCLUSIVE)
        self.assertEqual(result.reason_codes, ("ENVIRONMENT_UNSTABLE",))
        self.assertEqual(len(result.run_records), 1)

    def test_infra_terminal_requires_exact_partial_normalization_evidence(self):
        spec, normalizer, comparator, collector = _runtime_spec(
            protocol=_protocol(repetitions=1, required=1)
        )
        payload = b"same"
        spec, store = _base_store(spec, payload)
        output = _artifact("stdout", payload)
        actions = {
            "candidate": lambda request: (AtomicRunStatus.COMPLETED, output),
            "reference": lambda request: (
                AtomicRunStatus.DEVICE_LEASE_LOST,
                None,
            ),
        }
        engine, applicability, _, _ = _build(
            spec, normalizer, comparator, collector, actions, store
        )
        result = engine.execute(spec, applicability=applicability)
        self.assertEqual(result.result_class, AtomicResultClass.INFRA_INCONCLUSIVE)
        self.assertEqual(len(result.normalized_values), 1)
        forged = dataclasses.replace(result, normalized_values=())
        with self.assertRaises(AtomicOracleError) as raised:
            engine.validate_result(spec, forged)
        self.assertEqual(
            raised.exception.code,
            AtomicOracleErrorCode.RESULT_REPLAY_MISMATCH,
        )

    def test_warmup_target_failure_cannot_be_silently_discarded(self):
        protocol = _protocol(warmup=1, repetitions=1, required=1)
        spec, normalizer, comparator, collector = _runtime_spec(protocol=protocol)
        spec, store = _base_store(spec)
        actions = {
            variant.variant_id: lambda request: (
                AtomicRunStatus.TARGET_CRASH,
                None,
            )
            for variant in spec.variants
        }
        engine, applicability, runners, _ = _build(
            spec, normalizer, comparator, collector, actions, store
        )
        result = engine.execute(spec, applicability=applicability)
        self.assertEqual(result.result_class, AtomicResultClass.ORACLE_INCONCLUSIVE)
        self.assertEqual(result.reason_codes, ("METRIC_INVALID",))
        self.assertTrue(all(len(runner.calls) <= 1 for runner in runners.values()))
        self.assertTrue(all(item.request.warmup for item in result.run_records))

    def test_target_status_is_oracle_data_not_an_infrastructure_retry(self):
        normalizer = RunStatusNormalizer()
        spec, _, comparator, collector = _runtime_spec(
            protocol=_protocol(repetitions=1, required=1),
            normalizer=normalizer,
        )
        spec, store = _base_store(spec)
        actions = {
            "candidate": lambda request: (AtomicRunStatus.TARGET_CRASH, None),
            "reference": lambda request: (AtomicRunStatus.COMPLETED, None),
        }
        engine, applicability, runners, _ = _build(
            spec, normalizer, comparator, collector, actions, store
        )
        result = engine.execute(spec, applicability=applicability)
        self.assertEqual(result.result_class, AtomicResultClass.DECIDED)
        self.assertEqual(result.verdict, OracleVerdict.VIOLATION)
        self.assertEqual(len(runners["candidate"].calls), 1)

    def test_runner_exception_and_untyped_return_are_hard_stops(self):
        for expected, action in (
            (
                AtomicOracleErrorCode.RUNNER_RAISED,
                lambda request: (_ for _ in ()).throw(RuntimeError("boom")),
            ),
            (AtomicOracleErrorCode.RUNNER_RESULT_INVALID, lambda request: object()),
        ):
            with self.subTest(code=expected):
                spec, normalizer, comparator, collector = _runtime_spec(
                    protocol=_protocol(repetitions=1, required=1)
                )
                spec, store = _base_store(spec)
                catalog = AtomicOracleCatalog()
                for variant in spec.variants:
                    runner = ScriptedRunner(variant.execution_recipe, collector, action)
                    # Bypass ScriptedRunner's tuple unpacking for the untyped case.
                    if expected is AtomicOracleErrorCode.RUNNER_RESULT_INVALID:
                        runner.__class__ = type(
                            "UntypedRunner",
                            (),
                            {
                                "recipe_ref": variant.execution_recipe,
                                "collector_refs": (collector,),
                                "__call__": staticmethod(action),
                            },
                        )
                    catalog.register_runner(variant.execution_recipe, runner)
                catalog.register_normalizer(normalizer.atom_ref, normalizer)
                catalog.register_comparator(comparator.atom_ref, comparator)
                engine = AtomicOracleEngine(catalog, store)
                applicability = ApplicabilityResult(
                    spec.applicability.domain_id,
                    spec.applicability.calibrated_domain.content_sha256,
                    spec.qualification_policy,
                    True,
                    (spec.applicability.calibrated_domain,),
                )
                with self.assertRaises(AtomicOracleError) as raised:
                    engine.execute(spec, applicability=applicability)
                self.assertEqual(raised.exception.code, expected)


class NormalizationComparatorAndQuorumTests(unittest.TestCase):
    def test_invalid_utf8_and_statistical_payload_are_metric_invalid(self):
        cases = (
            (False, b"\xff"),
            (True, b"not-json"),
            (True, b"{}"),
        )
        for statistical, payload in cases:
            with self.subTest(statistical=statistical, payload=payload):
                spec, normalizer, comparator, collector = _runtime_spec(
                    statistical=statistical,
                    protocol=_protocol(repetitions=1, required=1),
                )
                spec, store = _base_store(spec, payload)
                output = _artifact("metric", payload)
                actions = {
                    variant.variant_id: lambda request, ref=output: (
                        AtomicRunStatus.COMPLETED,
                        ref,
                    )
                    for variant in spec.variants
                }
                engine, applicability, _, _ = _build(
                    spec, normalizer, comparator, collector, actions, store
                )
                result = engine.execute(spec, applicability=applicability)
                self.assertEqual(result.verdict, OracleVerdict.INCONCLUSIVE)
                self.assertIn("METRIC_INVALID", result.reason_codes)
                self.assertEqual(len(result.run_records), 2)

    def test_undeclared_atom_data_reason_is_a_hard_failure(self):
        for broken_role in ("normalizer", "comparator"):
            with self.subTest(broken_role=broken_role):
                spec, normalizer, comparator, collector = _runtime_spec(
                    protocol=_protocol(repetitions=1, required=1)
                )

                def undeclared(*args):
                    raise AtomicDataError(
                        "REFERENCE_UNAVAILABLE",
                        "reason is in the spec but not declared by this atom",
                    )

                if broken_role == "normalizer":
                    normalizer = BoundNormalizer(normalizer.atom_ref, undeclared)
                else:
                    comparator = BoundComparator(
                        comparator.atom_ref,
                        _policy_refs(spec),
                        undeclared,
                    )
                payload = b"same"
                spec, store = _base_store(spec, payload)
                output = _artifact("stdout", payload)
                actions = {
                    variant.variant_id: lambda request: (
                        AtomicRunStatus.COMPLETED,
                        output,
                    )
                    for variant in spec.variants
                }
                engine, applicability, _, _ = _build(
                    spec, normalizer, comparator, collector, actions, store
                )
                with self.assertRaises(AtomicOracleError) as raised:
                    engine.execute(spec, applicability=applicability)
                self.assertEqual(
                    raised.exception.code,
                    AtomicOracleErrorCode.ATOM_EXECUTION_FAILED,
                )

    def test_normalizer_wrong_value_identity_is_a_hard_atom_failure(self):
        spec, normalizer, comparator, collector = _runtime_spec(
            protocol=_protocol(repetitions=1, required=1)
        )
        wrong = BoundNormalizer(
            normalizer.atom_ref,
            lambda *args: CanonicalTypedValue(
                "other",
                CanonicalValueKind.TEXT,
                "same",
            ),
        )
        spec, store = _base_store(spec)
        actions = {
            variant.variant_id: lambda request: (
                AtomicRunStatus.COMPLETED,
                None,
            )
            for variant in spec.variants
        }
        engine, applicability, _, _ = _build(
            spec, wrong, comparator, collector, actions, store
        )
        with self.assertRaises(AtomicOracleError) as raised:
            engine.execute(spec, applicability=applicability)
        self.assertEqual(
            raised.exception.code,
            AtomicOracleErrorCode.ATOM_EXECUTION_FAILED,
        )

    def test_comparator_cannot_replace_normalized_evidence(self):
        spec, normalizer, comparator, collector = _runtime_spec(
            protocol=_protocol(repetitions=1, required=1)
        )
        dishonest = BoundComparator(
            comparator.atom_ref,
            _policy_refs(spec),
            lambda method, values: TrialDecision(
                OracleVerdict.PASS,
                "RELATION_HOLDS",
                (
                    CanonicalTypedValue(
                        "candidate",
                        CanonicalValueKind.TEXT,
                        "fabricated",
                    ),
                    values[1],
                ),
            ),
        )
        payload = b"same"
        spec, store = _base_store(spec, payload)
        output = _artifact("stdout", payload)
        actions = {
            variant.variant_id: lambda request: (
                AtomicRunStatus.COMPLETED,
                output,
            )
            for variant in spec.variants
        }
        engine, applicability, _, _ = _build(
            spec, normalizer, dishonest, collector, actions, store
        )
        with self.assertRaises(AtomicOracleError) as raised:
            engine.execute(spec, applicability=applicability)
        self.assertEqual(
            raised.exception.code,
            AtomicOracleErrorCode.ATOM_EXECUTION_FAILED,
        )

    def test_comparator_cannot_decide_without_normalized_evidence(self):
        spec, normalizer, comparator, collector = _runtime_spec(
            protocol=_protocol(repetitions=1, required=1)
        )
        dishonest = BoundComparator(
            comparator.atom_ref,
            _policy_refs(spec),
            lambda method, values: TrialDecision(
                OracleVerdict.VIOLATION,
                "RELATION_VIOLATED",
                (),
            ),
        )
        payload = b"different"
        spec, store = _base_store(spec, payload)
        output = _artifact("stdout", payload)
        actions = {
            variant.variant_id: lambda request: (
                AtomicRunStatus.COMPLETED,
                output,
            )
            for variant in spec.variants
        }
        engine, applicability, _, _ = _build(
            spec, normalizer, dishonest, collector, actions, store
        )
        with self.assertRaises(AtomicOracleError) as raised:
            engine.execute(spec, applicability=applicability)
        self.assertEqual(
            raised.exception.code,
            AtomicOracleErrorCode.ATOM_EXECUTION_FAILED,
        )

    def test_atom_exception_is_a_hard_failure_and_cannot_be_outvoted(self):
        spec, normalizer, comparator, collector = _runtime_spec(
            protocol=_protocol(repetitions=3, required=2)
        )

        def normalize(variant_id, repetition_index, result, read_artifact):
            if repetition_index == 1:
                raise RuntimeError("atom defect")
            return normalizer(
                variant_id,
                repetition_index,
                result,
                read_artifact,
            )

        broken = BoundNormalizer(normalizer.atom_ref, normalize)
        payload = b"same"
        spec, store = _base_store(spec, payload)
        output = _artifact("stdout", payload)
        actions = {
            variant.variant_id: lambda request: (
                AtomicRunStatus.COMPLETED,
                output,
            )
            for variant in spec.variants
        }
        engine, applicability, _, _ = _build(
            spec, broken, comparator, collector, actions, store
        )
        with self.assertRaises(AtomicOracleError) as raised:
            engine.execute(spec, applicability=applicability)
        self.assertEqual(
            raised.exception.code,
            AtomicOracleErrorCode.ATOM_EXECUTION_FAILED,
        )

    def test_comparator_exception_is_a_hard_failure_and_cannot_be_outvoted(self):
        spec, normalizer, comparator, collector = _runtime_spec(
            protocol=_protocol(repetitions=3, required=2)
        )
        calls = []

        def compare(method, values):
            calls.append(values)
            if len(calls) == 2:
                raise RuntimeError("atom defect")
            return comparator(method, values)

        broken = BoundComparator(comparator.atom_ref, _policy_refs(spec), compare)
        payload = b"same"
        spec, store = _base_store(spec, payload)
        output = _artifact("stdout", payload)
        actions = {
            variant.variant_id: lambda request: (
                AtomicRunStatus.COMPLETED,
                output,
            )
            for variant in spec.variants
        }
        engine, applicability, _, _ = _build(
            spec, normalizer, broken, collector, actions, store
        )
        with self.assertRaises(AtomicOracleError) as raised:
            engine.execute(spec, applicability=applicability)
        self.assertEqual(
            raised.exception.code,
            AtomicOracleErrorCode.ATOM_EXECUTION_FAILED,
        )

    def test_artifact_equality_ignores_pipeline_role(self):
        normalizer = ArtifactIdentityNormalizer()
        spec, _, _, collector = _runtime_spec(
            protocol=_protocol(repetitions=1, required=1),
            normalizer=normalizer,
        )
        comparator = ExactEqualityComparator(_policy_refs(spec))
        spec = dataclasses.replace(
            spec,
            normalizer=normalizer.atom_ref,
            comparator=comparator.atom_ref,
        )
        payload = b"same bytes"
        spec, store = _base_store(spec, payload)
        actions = {
            "candidate": lambda request: (
                AtomicRunStatus.COMPLETED,
                _artifact("candidate_output", payload),
            ),
            "reference": lambda request: (
                AtomicRunStatus.COMPLETED,
                _artifact("reference_output", payload),
            ),
        }
        engine, applicability, _, _ = _build(
            spec, normalizer, comparator, collector, actions, store
        )
        result = engine.execute(spec, applicability=applicability)
        self.assertEqual(result.verdict, OracleVerdict.PASS)

    def test_quorum_pure_and_mixed_results_match_decision_contract(self):
        scenarios = (
            ((b"bad", b"bad", b"bad", b"same"), 3, OracleVerdict.VIOLATION),
            ((b"same", b"same", b"same", b"bad"), 3, OracleVerdict.PASS),
            ((b"bad", b"bad", b"same", b"same"), 2, OracleVerdict.INCONCLUSIVE),
        )
        for candidate_values, required, expected in scenarios:
            with self.subTest(expected=expected):
                protocol = _protocol(repetitions=4, required=required)
                spec, normalizer, comparator, collector = _runtime_spec(
                    protocol=protocol
                )
                payloads = (*candidate_values, b"same")
                spec, store = _base_store(spec, *payloads)

                def candidate(request):
                    value = candidate_values[request.repetition_index]
                    return AtomicRunStatus.COMPLETED, _artifact("stdout", value)

                actions = {
                    "candidate": candidate,
                    "reference": lambda request: (
                        AtomicRunStatus.COMPLETED,
                        _artifact("stdout", b"same"),
                    ),
                }
                engine, applicability, _, _ = _build(
                    spec, normalizer, comparator, collector, actions, store
                )
                result = engine.execute(spec, applicability=applicability)
                self.assertEqual(result.verdict, expected)
                self.assertEqual(
                    result.violation_count + result.pass_count + result.inconclusive_count,
                    4,
                )
                if expected is OracleVerdict.INCONCLUSIVE:
                    self.assertEqual(result.reason_codes, ("QUORUM_NOT_MET",))
                elif expected is OracleVerdict.VIOLATION:
                    self.assertEqual(result.reason_codes, ("RELATION_VIOLATED",))
                else:
                    self.assertEqual(result.reason_codes, ("RELATION_HOLDS",))

    def test_domain_mismatch_has_no_runs_but_keeps_frozen_quorum(self):
        spec, normalizer, comparator, collector = _runtime_spec()
        spec, store = _base_store(spec)
        actions = {
            variant.variant_id: lambda request: (
                AtomicRunStatus.COMPLETED,
                None,
            )
            for variant in spec.variants
        }
        engine, applicability, runners, _ = _build(
            spec, normalizer, comparator, collector, actions, store
        )
        result = engine.execute(
            spec,
            applicability=dataclasses.replace(applicability, matches=False),
        )
        self.assertEqual(result.result_class, AtomicResultClass.DOMAIN_MISMATCH)
        self.assertEqual(result.reason_codes, ("DOMAIN_MISMATCH",))
        self.assertEqual(result.quorum_total, 3)
        self.assertEqual(result.decision_quorum.inconclusive_count, 3)
        self.assertEqual(result.to_document()["quorum"]["inconclusive_count"], 3)
        self.assertFalse(result.run_records)
        self.assertTrue(all(not runner.calls for runner in runners.values()))


class BuiltinComparatorTests(unittest.TestCase):
    @staticmethod
    def _text(value_id, value):
        return CanonicalTypedValue(value_id, CanonicalValueKind.TEXT, value)

    def test_golden_metamorphic_invariant_and_consensus_atoms(self):
        golden_method, golden_variants = _method_cases()[0]
        golden_spec = _spec(golden_method, golden_variants)
        golden = GoldenArtifactComparator(_policy_refs(golden_spec))
        candidate_artifact = dataclasses.replace(
            golden_method.expected_artifact,
            role="candidate_output",
        )
        golden_decision = golden(
            golden_method,
            (
                CanonicalTypedValue(
                    "candidate",
                    CanonicalValueKind.ARTIFACT,
                    candidate_artifact,
                ),
            ),
        )
        self.assertEqual(golden_decision.verdict, OracleVerdict.PASS)

        metamorphic_method, metamorphic_variants = _method_cases()[2]
        metamorphic_spec = _spec(metamorphic_method, metamorphic_variants)
        equality = ExactEqualityComparator(_policy_refs(metamorphic_spec))
        metamorphic_decision = equality(
            metamorphic_method,
            (
                self._text("candidate", "same"),
                self._text("transformed", "same"),
            ),
        )
        self.assertEqual(metamorphic_decision.verdict, OracleVerdict.PASS)

        invariant_method, invariant_variants = _method_cases()[3]
        invariant_spec = _spec(invariant_method, invariant_variants)
        invariant = BooleanInvariantComparator(_policy_refs(invariant_spec))
        self.assertEqual(
            invariant(
                invariant_method,
                (
                    CanonicalTypedValue(
                        "candidate",
                        CanonicalValueKind.BOOLEAN,
                        False,
                    ),
                ),
            ).verdict,
            OracleVerdict.VIOLATION,
        )

        consensus_method, consensus_variants = _method_cases()[4]
        consensus_spec = _spec(consensus_method, consensus_variants)
        consensus = ConsensusEqualityComparator(_policy_refs(consensus_spec))
        agreed = consensus(
            consensus_method,
            (
                self._text("candidate", "answer"),
                self._text("reference.a", "answer"),
                self._text("reference.b", "answer"),
            ),
        )
        unavailable = consensus(
            consensus_method,
            (
                self._text("candidate", "answer"),
                self._text("reference.a", "left"),
                self._text("reference.b", "right"),
            ),
        )
        self.assertEqual(agreed.verdict, OracleVerdict.PASS)
        self.assertEqual(unavailable.verdict, OracleVerdict.INCONCLUSIVE)
        self.assertEqual(unavailable.reason_code, "REFERENCE_UNAVAILABLE")

class StatisticalThresholdTests(unittest.TestCase):
    def test_ratio_uses_conservative_confidence_interval_boundaries(self):
        scenarios = (
            (("80", "75", "85"), ("100", "95", "105"), OracleVerdict.PASS, "RELATION_HOLDS"),
            (("112", "110", "114"), ("100", "95", "105"), OracleVerdict.PASS, "RELATION_HOLDS"),
            (
                ("130", "127", "133"),
                ("100", "95", "105"),
                OracleVerdict.VIOLATION,
                "RELATION_VIOLATED",
            ),
            (
                ("120", "115", "125"),
                ("100", "95", "105"),
                OracleVerdict.INCONCLUSIVE,
                "CI_CROSSES_BOUNDARY",
            ),
        )
        for candidate, baseline, expected, reason in scenarios:
            with self.subTest(candidate=candidate, baseline=baseline):
                spec, normalizer, comparator, collector = _runtime_spec(
                    statistical=True,
                    protocol=_protocol(repetitions=1, required=1),
                )
                candidate_payload = _estimate_payload(
                    spec, "candidate", 0, *candidate
                )
                baseline_payload = _estimate_payload(
                    spec, "control", 0, *baseline
                )
                spec, store = _base_store(
                    spec,
                    candidate_payload,
                    baseline_payload,
                )
                actions = {
                    "candidate": lambda request, value=candidate_payload: (
                        AtomicRunStatus.COMPLETED,
                        _artifact("candidate_metric", value, media_type="application/json"),
                    ),
                    "control": lambda request, value=baseline_payload: (
                        AtomicRunStatus.COMPLETED,
                        _artifact("control_metric", value, media_type="application/json"),
                    ),
                }
                engine, applicability, _, _ = _build(
                    spec, normalizer, comparator, collector, actions, store
                )
                result = engine.execute(spec, applicability=applicability)
                self.assertEqual(result.verdict, expected)
                self.assertIn(reason, result.reason_codes)
                self.assertEqual(
                    {item.value_id for item in result.threshold_values},
                    {
                        "confidence",
                        "interval_semantics",
                        "max_ratio",
                        "min_samples_per_variant",
                    },
                )

    def test_ratio_rejects_unqualified_or_undersampled_estimates(self):
        cases = (
            ({"samples": 99}, "INSUFFICIENT_SAMPLES"),
            ({"qualification_sha256": "0" * 64}, "METRIC_INVALID"),
            ({"estimator": "unapproved_estimator"}, "METRIC_INVALID"),
        )
        for overrides, expected_reason in cases:
            with self.subTest(overrides=overrides):
                spec, normalizer, comparator, collector = _runtime_spec(
                    statistical=True,
                    protocol=_protocol(repetitions=1, required=1),
                )
                candidate = _estimate_payload(
                    spec,
                    "candidate",
                    0,
                    "130",
                    "127",
                    "133",
                    **overrides,
                )
                baseline = _estimate_payload(
                    spec, "control", 0, "100", "95", "105"
                )
                spec, store = _base_store(spec, candidate, baseline)
                actions = {
                    "candidate": lambda request: (
                        AtomicRunStatus.COMPLETED,
                        _artifact("candidate_metric", candidate, media_type="application/json"),
                    ),
                    "control": lambda request: (
                        AtomicRunStatus.COMPLETED,
                        _artifact("control_metric", baseline, media_type="application/json"),
                    ),
                }
                engine, applicability, _, _ = _build(
                    spec, normalizer, comparator, collector, actions, store
                )
                result = engine.execute(spec, applicability=applicability)
                self.assertEqual(result.verdict, OracleVerdict.INCONCLUSIVE)
                self.assertIn(expected_reason, result.reason_codes)

    def test_replay_rejects_threshold_audit_rebinding(self):
        spec, normalizer, comparator, collector = _runtime_spec(
            statistical=True,
            protocol=_protocol(repetitions=1, required=1),
        )
        candidate = _estimate_payload(
            spec, "candidate", 0, "80", "75", "85"
        )
        baseline = _estimate_payload(
            spec, "control", 0, "100", "95", "105"
        )
        spec, store = _base_store(spec, candidate, baseline)
        actions = {
            "candidate": lambda request: (
                AtomicRunStatus.COMPLETED,
                _artifact("candidate_metric", candidate, media_type="application/json"),
            ),
            "control": lambda request: (
                AtomicRunStatus.COMPLETED,
                _artifact("control_metric", baseline, media_type="application/json"),
            ),
        }
        engine, applicability, _, _ = _build(
            spec, normalizer, comparator, collector, actions, store
        )
        result = engine.execute(spec, applicability=applicability)
        rebound_thresholds = tuple(
            CanonicalTypedValue(
                "max_ratio",
                CanonicalValueKind.DECIMAL,
                CanonicalDecimal.parse("999"),
            )
            if item.value_id == "max_ratio"
            else item
            for item in result.threshold_values
        )
        rebound = dataclasses.replace(
            result,
            threshold_values=rebound_thresholds,
        )
        with self.assertRaises(AtomicOracleError) as raised:
            engine.validate_result(spec, rebound)
        self.assertEqual(
            raised.exception.code,
            AtomicOracleErrorCode.RESULT_REPLAY_MISMATCH,
        )

    def test_ratio_threshold_and_policy_change_comparator_hash(self):
        spec, _, _, _ = _runtime_spec(statistical=True)
        first = RatioUpperBoundComparator(
            _policy_refs(spec),
            CanonicalDecimal.parse("1.2"),
            "paired_bootstrap",
            CanonicalDecimal.parse("0.95"),
            100,
        )
        changed_threshold = RatioUpperBoundComparator(
            _policy_refs(spec),
            CanonicalDecimal.parse("1.21"),
            "paired_bootstrap",
            CanonicalDecimal.parse("0.95"),
            100,
        )
        changed_policy = RatioUpperBoundComparator(
            (
                *(_policy_refs(spec)[:-1]),
                dataclasses.replace(_policy_refs(spec)[-1], content_sha256="0" * 64),
            ),
            CanonicalDecimal.parse("1.2"),
            "paired_bootstrap",
            CanonicalDecimal.parse("0.95"),
            100,
        )
        self.assertEqual(
            len(
                {
                    first.atom_ref.content_sha256,
                    changed_threshold.atom_ref.content_sha256,
                    changed_policy.atom_ref.content_sha256,
                }
            ),
            3,
        )

    def test_repeated_ratio_trials_use_frozen_quorum(self):
        spec, normalizer, comparator, collector = _runtime_spec(
            statistical=True,
            protocol=_protocol(repetitions=5, required=4),
        )
        intervals = (
            ("130", "128", "132"),
            ("129", "127", "131"),
            ("128", "127", "129"),
            ("110", "108", "112"),
            ("100", "98", "102"),
        )
        values = tuple(
            _estimate_payload(spec, "candidate", index, *item)
            for index, item in enumerate(intervals)
        )
        baselines = tuple(
            _estimate_payload(spec, "control", index, "100", "95", "105")
            for index in range(len(intervals))
        )
        spec, store = _base_store(spec, *values, *baselines)

        def candidate(request):
            value = values[request.repetition_index]
            return AtomicRunStatus.COMPLETED, _artifact(
                "candidate_metric",
                value,
                media_type="application/json",
            )

        actions = {
            "candidate": candidate,
            "control": lambda request: (
                AtomicRunStatus.COMPLETED,
                _artifact(
                    "control_metric",
                    baselines[request.repetition_index],
                    media_type="application/json",
                ),
            ),
        }
        engine, applicability, _, _ = _build(
            spec, normalizer, comparator, collector, actions, store
        )
        result = engine.execute(spec, applicability=applicability)
        self.assertEqual(result.verdict, OracleVerdict.INCONCLUSIVE)
        self.assertEqual(result.violation_count, 3)
        self.assertEqual(result.pass_count, 2)
        self.assertEqual(result.reason_codes, ("QUORUM_NOT_MET",))

    def test_one_statistical_envelope_cannot_be_replayed_as_two_trials(self):
        spec, normalizer, comparator, collector = _runtime_spec(
            statistical=True,
            protocol=_protocol(repetitions=2, required=2),
        )
        candidate = _estimate_payload(
            spec, "candidate", 0, "130", "127", "133"
        )
        baseline = _estimate_payload(
            spec, "control", 0, "100", "95", "105"
        )
        spec, store = _base_store(spec, candidate, baseline)
        actions = {
            "candidate": lambda request: (
                AtomicRunStatus.COMPLETED,
                _artifact("candidate_metric", candidate, media_type="application/json"),
            ),
            "control": lambda request: (
                AtomicRunStatus.COMPLETED,
                _artifact("control_metric", baseline, media_type="application/json"),
            ),
        }
        engine, applicability, _, _ = _build(
            spec, normalizer, comparator, collector, actions, store
        )
        result = engine.execute(spec, applicability=applicability)
        self.assertEqual(result.verdict, OracleVerdict.INCONCLUSIVE)
        self.assertEqual(result.violation_count, 1)
        self.assertEqual(result.inconclusive_count, 1)
        self.assertIn("METRIC_INVALID", result.reason_codes)

    def test_one_pair_identity_cannot_be_rewrapped_as_two_trials(self):
        spec, normalizer, comparator, collector = _runtime_spec(
            statistical=True,
            protocol=_protocol(repetitions=2, required=2),
        )
        candidates = tuple(
            _estimate_payload(
                spec,
                "candidate",
                index,
                "130",
                "127",
                "133",
                pair_id="pair.same",
            )
            for index in range(2)
        )
        baselines = tuple(
            _estimate_payload(
                spec,
                "control",
                index,
                "100",
                "95",
                "105",
                pair_id="pair.same",
            )
            for index in range(2)
        )
        spec, store = _base_store(spec, *candidates, *baselines)
        actions = {
            "candidate": lambda request: (
                AtomicRunStatus.COMPLETED,
                _artifact(
                    "candidate_metric",
                    candidates[request.repetition_index],
                    media_type="application/json",
                ),
            ),
            "control": lambda request: (
                AtomicRunStatus.COMPLETED,
                _artifact(
                    "control_metric",
                    baselines[request.repetition_index],
                    media_type="application/json",
                ),
            ),
        }
        engine, applicability, _, _ = _build(
            spec, normalizer, comparator, collector, actions, store
        )
        result = engine.execute(spec, applicability=applicability)
        self.assertEqual(result.result_class, AtomicResultClass.ORACLE_INCONCLUSIVE)
        self.assertEqual(result.verdict, OracleVerdict.INCONCLUSIVE)
        self.assertEqual(result.violation_count, 1)
        self.assertEqual(result.reason_codes, ("METRIC_INVALID",))
        forged = dataclasses.replace(
            result,
            normalized_values=result.normalized_values[:-1],
        )
        with self.assertRaises(AtomicOracleError) as raised:
            engine.validate_result(spec, forged)
        self.assertEqual(
            raised.exception.code,
            AtomicOracleErrorCode.RESULT_REPLAY_MISMATCH,
        )


class RuntimeModelTests(unittest.TestCase):
    def test_result_hash_is_stable_and_every_invocation_field_is_bound(self):
        spec, normalizer, comparator, collector = _runtime_spec(
            protocol=_protocol(repetitions=1, required=1)
        )
        payload = b"same"
        spec, store = _base_store(spec, payload)
        output = _artifact("stdout", payload)
        actions = {
            variant.variant_id: lambda request: (
                AtomicRunStatus.COMPLETED,
                output,
            )
            for variant in spec.variants
        }
        engine, applicability, _, _ = _build(
            spec, normalizer, comparator, collector, actions, store
        )
        result = engine.execute(spec, applicability=applicability)
        second_engine, second_applicability, _, _ = _build(
            spec, normalizer, comparator, collector, actions, store
        )
        repeated = second_engine.execute(
            spec,
            applicability=second_applicability,
        )
        self.assertEqual(result.to_document(), repeated.to_document())
        self.assertEqual(result.content_sha256, repeated.content_sha256)
        self.assertEqual(result.oracle_spec, spec.ref)
        self.assertEqual(result.normalizer, spec.normalizer)
        self.assertEqual(result.comparator, spec.comparator)
        self.assertEqual(result.decision_quorum.total, 1)
        self.assertEqual(result.decision_quorum.pass_count, 1)
        record = result.run_records[0]
        changed = dataclasses.replace(
            record.request,
            timeout_ms=record.request.timeout_ms + 1,
        )
        self.assertNotEqual(record.request.content_sha256, changed.content_sha256)
        self.assertNotEqual(
            record.content_sha256,
            dataclasses.replace(record, request=changed).content_sha256,
        )

    def test_decided_result_cannot_be_forged_without_execution_evidence(self):
        spec, normalizer, comparator, collector = _runtime_spec(
            protocol=_protocol(repetitions=1, required=1)
        )
        payload = b"same"
        spec, store = _base_store(spec, payload)
        output = _artifact("stdout", payload)
        actions = {
            variant.variant_id: lambda request: (
                AtomicRunStatus.COMPLETED,
                output,
            )
            for variant in spec.variants
        }
        engine, applicability, _, _ = _build(
            spec, normalizer, comparator, collector, actions, store
        )
        result = engine.execute(spec, applicability=applicability)
        with self.assertRaises(ContractError):
            dataclasses.replace(
                result,
                run_records=(),
                normalized_values=(),
            )
        with self.assertRaises(ContractError):
            dataclasses.replace(
                result,
                run_records=tuple(reversed(result.run_records)),
            )
        with self.assertRaises(ContractError):
            dataclasses.replace(result, verdict=OracleVerdict.VIOLATION)

    def test_terminal_result_requires_a_replayable_execution_witness(self):
        spec, normalizer, comparator, collector = _runtime_spec(
            protocol=_protocol(repetitions=1, required=1)
        )
        payload = b"same"
        spec, store = _base_store(spec, payload)
        output = _artifact("stdout", payload)
        actions = {
            variant.variant_id: lambda request: (
                AtomicRunStatus.COMPLETED,
                output,
            )
            for variant in spec.variants
        }
        engine, applicability, _, _ = _build(
            spec, normalizer, comparator, collector, actions, store
        )
        result = engine.execute(spec, applicability=applicability)

        with self.assertRaises(ContractError):
            dataclasses.replace(
                result,
                result_class=AtomicResultClass.ORACLE_INCONCLUSIVE,
                verdict=OracleVerdict.INCONCLUSIVE,
                reason_codes=("METRIC_INVALID",),
                trials=(),
                run_records=(),
                normalized_values=(),
            )

        completed_prefix = dataclasses.replace(
            result,
            result_class=AtomicResultClass.INFRA_INCONCLUSIVE,
            verdict=OracleVerdict.INCONCLUSIVE,
            reason_codes=("ENVIRONMENT_UNSTABLE",),
            trials=(),
            run_records=(result.run_records[0],),
            normalized_values=(),
        )
        with self.assertRaises(AtomicOracleError) as raised:
            engine.validate_result(spec, completed_prefix)
        self.assertEqual(
            raised.exception.code,
            AtomicOracleErrorCode.RESULT_REPLAY_MISMATCH,
        )

        completed_matrix = dataclasses.replace(
            result,
            result_class=AtomicResultClass.ORACLE_INCONCLUSIVE,
            verdict=OracleVerdict.INCONCLUSIVE,
            reason_codes=("METRIC_INVALID",),
            trials=(),
        )
        with self.assertRaises(AtomicOracleError) as raised:
            engine.validate_result(spec, completed_matrix)
        self.assertEqual(
            raised.exception.code,
            AtomicOracleErrorCode.RESULT_REPLAY_MISMATCH,
        )

    def test_result_validator_rejects_cross_spec_and_reason_rebinding(self):
        spec, normalizer, comparator, collector = _runtime_spec(
            protocol=_protocol(repetitions=1, required=1)
        )
        payload = b"same"
        spec, store = _base_store(spec, payload)
        output = _artifact("stdout", payload)
        actions = {
            variant.variant_id: lambda request: (
                AtomicRunStatus.COMPLETED,
                output,
            )
            for variant in spec.variants
        }
        engine, applicability, _, _ = _build(
            spec, normalizer, comparator, collector, actions, store
        )
        result = engine.execute(spec, applicability=applicability)
        other_spec = dataclasses.replace(spec, oracle_version="1.0.1")
        with self.assertRaises(ContractError):
            engine.validate_result(other_spec, result)
        rebound = dataclasses.replace(result, reason_codes=("OTHER_REASON",))
        with self.assertRaises(ContractError):
            engine.validate_result(spec, rebound)

    def test_replay_enforces_the_comparator_reason_declaration(self):
        spec, normalizer, comparator, collector = _runtime_spec(
            protocol=_protocol(repetitions=1, required=1)
        )
        spec = dataclasses.replace(
            spec,
            reason_vocabulary=dataclasses.replace(
                spec.reason_vocabulary,
                passed=("ALTERNATE_PASS", "RELATION_HOLDS"),
            ),
        )
        state = {"alternate": False}

        def compare(method, values):
            if state["alternate"]:
                return TrialDecision(
                    OracleVerdict.PASS,
                    "ALTERNATE_PASS",
                    values,
                )
            return comparator(method, values)

        stateful = BoundComparator(
            comparator.atom_ref,
            _policy_refs(spec),
            compare,
        )
        payload = b"same"
        spec, store = _base_store(spec, payload)
        output = _artifact("stdout", payload)
        actions = {
            variant.variant_id: lambda request: (
                AtomicRunStatus.COMPLETED,
                output,
            )
            for variant in spec.variants
        }
        engine, applicability, _, _ = _build(
            spec, normalizer, stateful, collector, actions, store
        )
        result = engine.execute(spec, applicability=applicability)
        state["alternate"] = True
        forged_trial = dataclasses.replace(
            result.trials[0],
            decision=TrialDecision(
                OracleVerdict.PASS,
                "ALTERNATE_PASS",
                result.trials[0].decision.values,
            ),
        )
        forged = dataclasses.replace(
            result,
            reason_codes=("ALTERNATE_PASS",),
            trials=(forged_trial,),
        )
        with self.assertRaises(AtomicOracleError) as raised:
            engine.validate_result(spec, forged)
        self.assertEqual(
            raised.exception.code,
            AtomicOracleErrorCode.RESULT_REPLAY_MISMATCH,
        )

    def test_replay_rejects_coordinated_normalization_and_verdict_forgery(self):
        spec, normalizer, comparator, collector = _runtime_spec(
            protocol=_protocol(repetitions=1, required=1)
        )
        payload = b"same"
        spec, store = _base_store(spec, payload)
        output = _artifact("stdout", payload)
        actions = {
            variant.variant_id: lambda request: (
                AtomicRunStatus.COMPLETED,
                output,
            )
            for variant in spec.variants
        }
        engine, applicability, _, _ = _build(
            spec, normalizer, comparator, collector, actions, store
        )
        result = engine.execute(spec, applicability=applicability)
        forged_normalized = tuple(
            dataclasses.replace(
                item,
                value=CanonicalTypedValue(
                    "candidate",
                    CanonicalValueKind.TEXT,
                    "fabricated",
                ),
            )
            if item.variant_id == "candidate"
            else item
            for item in result.normalized_values
        )
        forged_values = tuple(item.value for item in forged_normalized)
        forged_trial = dataclasses.replace(
            result.trials[0],
            decision=TrialDecision(
                OracleVerdict.VIOLATION,
                "RELATION_VIOLATED",
                forged_values,
            ),
        )
        forged = dataclasses.replace(
            result,
            verdict=OracleVerdict.VIOLATION,
            reason_codes=("RELATION_VIOLATED",),
            trials=(forged_trial,),
            normalized_values=forged_normalized,
        )
        with self.assertRaises(AtomicOracleError) as raised:
            engine.validate_result(spec, forged)
        self.assertEqual(
            raised.exception.code,
            AtomicOracleErrorCode.RESULT_REPLAY_MISMATCH,
        )

    def test_runtime_values_reject_invalid_counts_ids_and_duplicate_roles(self):
        recipe = _method_cases()[1][1][0].execution_recipe
        with self.assertRaises(ContractError):
            AtomicRunRequest(recipe, "candidate", -1, 0, False, 10)
        payload = b"x"
        artifact = _artifact("same", payload)
        collector = ContractRef(
            ContractRefKind.COLLECTOR,
            "runtime.collector",
            "1.0.0",
            "d" * 64,
        )
        captured = AtomicCapturedArtifact(
            artifact,
            collector,
            "capture.one",
            _digest(b"capture.one"),
        )
        with self.assertRaises(ContractError):
            AtomicRunResult(
                AtomicRunStatus.COMPLETED,
                (captured, dataclasses.replace(captured, capture_id="capture.two")),
                "COMPLETED",
            )

    def test_runtime_modules_do_not_directly_own_shell_or_network(self):
        # Runner capability confinement is enforced by the later broker/adapter
        # layer; this smoke test covers only the atomic runtime package itself.
        root = Path("src/validation_core/oracle")
        forbidden_imports = {"os", "shlex", "socket", "subprocess"}
        forbidden_calls = {"eval", "exec", "compile", "__import__"}
        for path in sorted(root.glob("*.py")):
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            imports = {
                alias.name.split(".", 1)[0]
                for node in ast.walk(tree)
                if isinstance(node, (ast.Import, ast.ImportFrom))
                for alias in node.names
                if isinstance(node, ast.Import)
            }
            imports.update(
                node.module.split(".", 1)[0]
                for node in ast.walk(tree)
                if isinstance(node, ast.ImportFrom) and node.module
            )
            calls = {
                node.func.id
                for node in ast.walk(tree)
                if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
            }
            with self.subTest(path=path.name):
                self.assertFalse(imports.intersection(forbidden_imports))
                self.assertFalse(calls.intersection(forbidden_calls))


if __name__ == "__main__":
    unittest.main()

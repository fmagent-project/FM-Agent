"""Mechanical Oracle execution over frozen specs and exact catalog entries."""

from __future__ import annotations

import hashlib
from enum import Enum

from ..contracts import (
    ArtifactRef,
    CanonicalTypedValue,
    CanonicalValueKind,
    ContractRef,
    ContractRefKind,
    GoldenMethod,
    InvariantMethod,
    MetamorphicMethod,
    OracleSpec,
    OracleVerdict,
    RetryReason,
)
from ..contracts.base import ContractError, validate_sha256
from .catalog import AtomicOracleCatalog, CatalogError
from .model import (
    ApplicabilityResult,
    AtomicDataError,
    AtomicOracleResult,
    AtomicResultClass,
    AtomicRunRecord,
    AtomicRunRequest,
    AtomicRunResult,
    AtomicRunStatus,
    AtomicTrialRecord,
    AtomicVariantBinding,
    NormalizedValue,
    TrialDecision,
    validate_atomic_result_structure,
)


class AtomicOracleErrorCode(str, Enum):
    ARTIFACT_UNAVAILABLE = "ARTIFACT_UNAVAILABLE"
    ARTIFACT_SIZE_MISMATCH = "ARTIFACT_SIZE_MISMATCH"
    ARTIFACT_HASH_MISMATCH = "ARTIFACT_HASH_MISMATCH"
    APPLICABILITY_BINDING_INVALID = "APPLICABILITY_BINDING_INVALID"
    ATOM_POLICY_BINDING_INVALID = "ATOM_POLICY_BINDING_INVALID"
    ATOM_REASON_VOCABULARY_INVALID = "ATOM_REASON_VOCABULARY_INVALID"
    ATOM_METHOD_INCOMPATIBLE = "ATOM_METHOD_INCOMPATIBLE"
    CAUSAL_CONTROL_NOT_COMPILED = "CAUSAL_CONTROL_NOT_COMPILED"
    THRESHOLD_BINDING_INVALID = "THRESHOLD_BINDING_INVALID"
    COLLECTOR_BINDING_INVALID = "COLLECTOR_BINDING_INVALID"
    COLLECTOR_PROVENANCE_REUSED = "COLLECTOR_PROVENANCE_REUSED"
    RUNNER_RAISED = "RUNNER_RAISED"
    RUNNER_RESULT_INVALID = "RUNNER_RESULT_INVALID"
    ATOM_EXECUTION_FAILED = "ATOM_EXECUTION_FAILED"
    RESULT_REPLAY_MISMATCH = "RESULT_REPLAY_MISMATCH"


class AtomicOracleError(RuntimeError):
    """Typed hard stop; callers must never reinterpret it as PASS."""

    def __init__(self, code: AtomicOracleErrorCode, message: str):
        self.code = code
        super().__init__(f"{code.value}: {message}")


class ArtifactIntegrityError(AtomicOracleError):
    """Hard integrity failure that maps to invalid_submission at Gate level."""


_RETRY_STATUS = {
    AtomicRunStatus.BROKER_LEASE_LOST: RetryReason.BROKER_LEASE_LOST,
    AtomicRunStatus.DEVICE_LEASE_LOST: RetryReason.DEVICE_LEASE_LOST,
    AtomicRunStatus.ENVIRONMENT_FINGERPRINT_DRIFT: (
        RetryReason.ENVIRONMENT_FINGERPRINT_DRIFT
    ),
    AtomicRunStatus.COLLECTOR_TRANSPORT_INTERRUPTED: (
        RetryReason.COLLECTOR_TRANSPORT_INTERRUPTED
    ),
}

_SYSTEM_INCONCLUSIVE_REASONS = frozenset(
    ("METRIC_INVALID", "QUORUM_NOT_MET", "ENVIRONMENT_UNSTABLE")
)


def _ref_sort_key(reference: ContractRef) -> tuple[str, str, str, str]:
    return (
        reference.kind.value,
        reference.contract_id,
        reference.contract_version,
        reference.content_sha256,
    )


def _runtime_policy_refs(spec: OracleSpec) -> tuple[ContractRef, ...]:
    refs = [spec.healthy_relation, spec.decision_policy, spec.qualification_policy]
    if spec.baseline_policy is not None:
        refs.append(spec.baseline_policy)
    if spec.threshold_policy is not None:
        refs.append(spec.threshold_policy)
    if type(spec.method) is MetamorphicMethod:
        refs.append(spec.method.transform_policy)
    if type(spec.method) is InvariantMethod:
        refs.append(spec.method.invariant_policy)
    return tuple(sorted(set(refs), key=_ref_sort_key))


class AtomicOracleEngine:
    """Execute one OracleSpec without exposing a general command surface."""

    def __init__(
        self,
        catalog: AtomicOracleCatalog,
        artifacts: dict[str, bytes],
    ):
        if type(catalog) is not AtomicOracleCatalog:
            raise CatalogError("catalog must be an AtomicOracleCatalog")
        if type(artifacts) is not dict:
            raise ContractError("artifacts must be a digest-to-bytes dictionary")
        copied: dict[str, bytes] = {}
        for digest, payload in artifacts.items():
            validate_sha256(digest, "artifact store key")
            if type(payload) is not bytes:
                raise ContractError("artifact store values must be bytes")
            copied[digest] = payload
        self._catalog = catalog
        self._artifacts = copied
        self._catalog.seal()

    def _read_artifact(self, reference: ArtifactRef) -> bytes:
        if type(reference) is not ArtifactRef:
            raise ContractError("artifact reader requires an ArtifactRef")
        payload = self._artifacts.get(reference.content_sha256)
        if payload is None:
            raise ArtifactIntegrityError(
                AtomicOracleErrorCode.ARTIFACT_UNAVAILABLE,
                f"artifact role {reference.role!r} is unavailable",
            )
        if len(payload) != reference.size_bytes:
            raise ArtifactIntegrityError(
                AtomicOracleErrorCode.ARTIFACT_SIZE_MISMATCH,
                f"artifact role {reference.role!r} has an unexpected size",
            )
        if hashlib.sha256(payload).hexdigest() != reference.content_sha256:
            raise ArtifactIntegrityError(
                AtomicOracleErrorCode.ARTIFACT_HASH_MISMATCH,
                f"artifact role {reference.role!r} failed SHA-256 verification",
            )
        return payload

    @staticmethod
    def _validate_component_reason_codes(spec: OracleSpec, comparator) -> None:
        declared = {
            OracleVerdict.VIOLATION: frozenset(spec.reason_vocabulary.violation),
            OracleVerdict.PASS: frozenset(spec.reason_vocabulary.passed),
            OracleVerdict.INCONCLUSIVE: frozenset(
                spec.reason_vocabulary.inconclusive
            ),
        }
        reason_codes = getattr(comparator, "reason_codes", None)
        if type(reason_codes) is not dict or set(reason_codes) != set(OracleVerdict):
            raise AtomicOracleError(
                AtomicOracleErrorCode.ATOM_REASON_VOCABULARY_INVALID,
                "comparator must declare possible codes for all three verdicts",
            )
        for verdict, values in reason_codes.items():
            if type(values) not in (tuple, list) or not values:
                raise AtomicOracleError(
                    AtomicOracleErrorCode.ATOM_REASON_VOCABULARY_INVALID,
                    "comparator reason-code groups must be non-empty",
                )
            if any(type(value) is not str for value in values) or not set(
                values
            ).issubset(declared[verdict]):
                raise AtomicOracleError(
                    AtomicOracleErrorCode.ATOM_REASON_VOCABULARY_INVALID,
                    "comparator reason codes are outside the frozen vocabulary",
                )
        if not _SYSTEM_INCONCLUSIVE_REASONS.issubset(
            declared[OracleVerdict.INCONCLUSIVE]
        ):
            raise AtomicOracleError(
                AtomicOracleErrorCode.ATOM_REASON_VOCABULARY_INVALID,
                "OracleSpec must freeze generic runtime inconclusive reasons",
            )

    def _preflight(self, spec: OracleSpec, applicability: ApplicabilityResult):
        if type(spec) is not OracleSpec:
            raise ContractError("execute requires an OracleSpec")
        if type(applicability) is not ApplicabilityResult:
            raise ContractError("applicability must be an ApplicabilityResult")
        if (
            applicability.domain_id != spec.applicability.domain_id
            or applicability.calibrated_domain_sha256
            != spec.applicability.calibrated_domain.content_sha256
            or applicability.matcher != spec.qualification_policy
        ):
            raise AtomicOracleError(
                AtomicOracleErrorCode.APPLICABILITY_BINDING_INVALID,
                "applicability result does not bind the frozen calibrated domain",
            )
        if spec.causal_control is not None:
            raise AtomicOracleError(
                AtomicOracleErrorCode.CAUSAL_CONTROL_NOT_COMPILED,
                "causal control requires guard and bundle orchestration before "
                "atomic execution",
            )

        # Resolve every executable component before observing domain or run data.
        normalizer = self._catalog.normalizer(spec.normalizer)
        comparator = self._catalog.comparator(spec.comparator)
        runners = {
            variant.variant_id: self._catalog.runner(variant.execution_recipe)
            for variant in spec.variants
        }
        policy_refs = getattr(comparator, "policy_refs", None)
        if type(policy_refs) not in (tuple, list) or tuple(policy_refs) != (
            _runtime_policy_refs(spec)
        ):
            raise AtomicOracleError(
                AtomicOracleErrorCode.ATOM_POLICY_BINDING_INVALID,
                "comparator policies do not exactly match the frozen OracleSpec",
            )
        normalizer_reasons = getattr(normalizer, "reason_codes", None)
        if (
            type(normalizer_reasons) is not tuple
            or len(normalizer_reasons) != len(set(normalizer_reasons))
            or any(type(item) is not str for item in normalizer_reasons)
            or not set(normalizer_reasons).issubset(
                spec.reason_vocabulary.inconclusive
            )
        ):
            raise AtomicOracleError(
                AtomicOracleErrorCode.ATOM_REASON_VOCABULARY_INVALID,
                "normalizer reasons are outside the frozen vocabulary",
            )
        self._validate_component_reason_codes(spec, comparator)
        supported_methods = getattr(comparator, "supported_method_types", None)
        if (
            type(supported_methods) is not tuple
            or not supported_methods
            or type(spec.method) not in supported_methods
        ):
            raise AtomicOracleError(
                AtomicOracleErrorCode.ATOM_METHOD_INCOMPATIBLE,
                "comparator does not support the frozen Oracle method",
            )
        threshold_values = getattr(comparator, "threshold_values", None)
        if type(threshold_values) not in (tuple, list) or any(
            type(item) is not CanonicalTypedValue for item in threshold_values
        ):
            raise AtomicOracleError(
                AtomicOracleErrorCode.THRESHOLD_BINDING_INVALID,
                "comparator threshold values are not typed",
            )
        threshold_values = tuple(
            sorted(threshold_values, key=lambda item: item.value_id)
        )
        if len({item.value_id for item in threshold_values}) != len(
            threshold_values
        ):
            raise AtomicOracleError(
                AtomicOracleErrorCode.THRESHOLD_BINDING_INVALID,
                "comparator threshold values repeat an identity",
            )
        if (spec.threshold_policy is None) != (not threshold_values):
            raise AtomicOracleError(
                AtomicOracleErrorCode.THRESHOLD_BINDING_INVALID,
                "comparator threshold values do not match the frozen policy",
            )
        for threshold in threshold_values:
            if threshold.kind is CanonicalValueKind.ARTIFACT:
                self._read_artifact(threshold.value)
        for runner in runners.values():
            collector_refs = getattr(runner, "collector_refs", None)
            if type(collector_refs) not in (tuple, list) or tuple(
                sorted(collector_refs, key=_ref_sort_key)
            ) != tuple(spec.collectors):
                raise AtomicOracleError(
                    AtomicOracleErrorCode.COLLECTOR_BINDING_INVALID,
                    "runner collectors do not exactly match the frozen OracleSpec",
                )
        return normalizer, comparator, runners, threshold_values

    def _validate_captured_artifacts(
        self,
        result: AtomicRunResult,
        allowed_collectors: frozenset[ContractRef],
        seen_captures: set[tuple[ContractRef, str]],
        seen_provenance: set[str],
    ) -> None:
        for captured in result.artifacts:
            if captured.collector not in allowed_collectors:
                raise AtomicOracleError(
                    AtomicOracleErrorCode.COLLECTOR_BINDING_INVALID,
                    "runner returned an artifact from an undeclared collector",
                )
            capture_key = (captured.collector, captured.capture_id)
            if (
                capture_key in seen_captures
                or captured.provenance_sha256 in seen_provenance
            ):
                raise AtomicOracleError(
                    AtomicOracleErrorCode.COLLECTOR_PROVENANCE_REUSED,
                    "collector capture/provenance was reused across invocations",
                )
            self._read_artifact(captured.artifact)
            seen_captures.add(capture_key)
            seen_provenance.add(captured.provenance_sha256)

    def _run_once(
        self,
        *,
        runner,
        recipe: ContractRef,
        variant_id: str,
        repetition_index: int,
        warmup: bool,
        inputs: tuple[ArtifactRef, ...],
        spec: OracleSpec,
        seen_captures: set[tuple[ContractRef, str]],
        seen_provenance: set[str],
    ) -> tuple[AtomicRunRecord, tuple[AtomicRunRecord, ...], bool]:
        protocol = spec.execution_protocol
        allowed_retries = frozenset(protocol.retry_reasons)
        records: list[AtomicRunRecord] = []
        for retry_index in range(protocol.max_retries + 1):
            request = AtomicRunRequest(
                recipe=recipe,
                variant_id=variant_id,
                repetition_index=repetition_index,
                retry_index=retry_index,
                warmup=warmup,
                timeout_ms=protocol.timeout_ms,
                inputs=inputs,
            )
            try:
                result = runner(request)
            except Exception as exc:
                raise AtomicOracleError(
                    AtomicOracleErrorCode.RUNNER_RAISED,
                    "runner raised outside its typed result contract",
                ) from exc
            if type(result) is not AtomicRunResult:
                raise AtomicOracleError(
                    AtomicOracleErrorCode.RUNNER_RESULT_INVALID,
                    "runner returned an untyped result",
                )
            self._validate_captured_artifacts(
                result,
                frozenset(spec.collectors),
                seen_captures,
                seen_provenance,
            )
            record = AtomicRunRecord(request, result)
            records.append(record)
            retry_reason = _RETRY_STATUS.get(result.status)
            may_retry = (
                retry_reason in allowed_retries
                and retry_index < protocol.max_retries
            )
            if may_retry:
                continue
            return record, tuple(records), retry_reason is not None
        raise AssertionError("bounded retry loop did not return")

    def _terminal_result(
        self,
        spec: OracleSpec,
        applicability: ApplicabilityResult,
        inputs: tuple[ArtifactRef, ...],
        threshold_values: tuple[CanonicalTypedValue, ...],
        result_class: AtomicResultClass,
        reason: str,
        run_records: list[AtomicRunRecord],
        trials: list[AtomicTrialRecord],
        normalized: list[NormalizedValue],
    ) -> AtomicOracleResult:
        result = AtomicOracleResult(
            oracle_spec=spec.ref,
            normalizer=spec.normalizer,
            comparator=spec.comparator,
            protocol=spec.execution_protocol,
            variants=tuple(
                AtomicVariantBinding(item.variant_id, item.execution_recipe)
                for item in spec.variants
            ),
            collectors=spec.collectors,
            applicability=applicability,
            inputs=inputs,
            threshold_values=threshold_values,
            result_class=result_class,
            verdict=OracleVerdict.INCONCLUSIVE,
            reason_codes=(reason,),
            domain_match=True,
            trials=tuple(trials),
            run_records=tuple(run_records),
            normalized_values=tuple(normalized),
        )
        self.validate_result(spec, result)
        return result

    def _replay_normalizer(
        self,
        normalizer,
        final: AtomicRunRecord,
    ) -> tuple[NormalizedValue | None, str | None]:
        request = final.request
        try:
            value = normalizer(
                request.variant_id,
                request.repetition_index,
                final.result,
                self._read_artifact,
            )
        except ArtifactIntegrityError:
            raise
        except AtomicDataError as exc:
            return None, exc.reason_code
        except Exception as exc:
            raise AtomicOracleError(
                AtomicOracleErrorCode.RESULT_REPLAY_MISMATCH,
                "normalizer could not replay recorded evidence",
            ) from exc
        return (
            self._bind_normalized_value(
                value,
                final,
                error_code=AtomicOracleErrorCode.RESULT_REPLAY_MISMATCH,
                context="normalizer replay",
            ),
            None,
        )

    def _bind_normalized_value(
        self,
        candidate,
        final: AtomicRunRecord,
        *,
        error_code: AtomicOracleErrorCode,
        context: str,
    ) -> NormalizedValue:
        """Bind a normalizer value to the exact run evidence it derives from."""

        request = final.request
        if (
            type(candidate) is not CanonicalTypedValue
            or candidate.value_id != request.variant_id
        ):
            raise AtomicOracleError(
                error_code,
                f"{context} returned an invalid canonical value",
            )
        if candidate.kind is CanonicalValueKind.ARTIFACT:
            captured = tuple(item.artifact for item in final.result.artifacts)
            if candidate.value not in captured:
                raise AtomicOracleError(
                    error_code,
                    f"{context} returned an artifact not captured by its run",
                )
            # Captures are checked on ingestion too.  Rechecking here makes the
            # normalized-value boundary independently fail closed.
            self._read_artifact(candidate.value)
        return NormalizedValue(
            variant_id=request.variant_id,
            repetition_index=request.repetition_index,
            value=candidate,
            source_run_sha256=final.content_sha256,
        )

    def _require_valid_comparator_decision(
        self,
        comparator,
        candidate,
        expected_values: tuple[CanonicalTypedValue, ...],
        *,
        error_code: AtomicOracleErrorCode,
        context: str,
    ) -> TrialDecision:
        """Apply the same declared-reason and evidence rules on every path."""

        if type(candidate) is not TrialDecision:
            raise AtomicOracleError(error_code, f"{context} returned an invalid type")
        allowed_reasons = getattr(comparator, "reason_codes", {}).get(
            candidate.verdict,
            (),
        )
        valid_values = (
            candidate.values in ((), expected_values)
            if candidate.verdict is OracleVerdict.INCONCLUSIVE
            else bool(expected_values) and candidate.values == expected_values
        )
        if candidate.reason_code not in allowed_reasons or not valid_values:
            raise AtomicOracleError(
                error_code,
                f"{context} violated its declared reason or evidence contract",
            )
        return candidate

    def validate_result(
        self,
        spec: OracleSpec,
        result: AtomicOracleResult,
    ) -> None:
        """Replay admitted pure atoms over recorded, hash-checked evidence."""

        validate_atomic_result_structure(spec, result)
        normalizer, comparator, _, threshold_values = self._preflight(
            spec,
            result.applicability,
        )
        if result.threshold_values != threshold_values:
            raise AtomicOracleError(
                AtomicOracleErrorCode.RESULT_REPLAY_MISMATCH,
                "recorded thresholds differ from the admitted comparator",
            )

        self._read_artifact(spec.applicability.calibrated_domain)
        for reference in (*result.applicability.evidence, *result.inputs):
            self._read_artifact(reference)
        if type(spec.method) is GoldenMethod:
            self._read_artifact(spec.method.expected_artifact)
        for record in result.run_records:
            for captured in record.result.artifacts:
                self._read_artifact(captured.artifact)
        if not result.domain_match:
            return

        final_measurements: dict[tuple[str, int], AtomicRunRecord] = {}
        for record in result.run_records:
            request = record.request
            if request.warmup:
                continue
            cell = (request.variant_id, request.repetition_index)
            previous = final_measurements.get(cell)
            if (
                previous is None
                or previous.request.retry_index < request.retry_index
            ):
                final_measurements[cell] = record

        provided = {
            (item.variant_id, item.repetition_index): item
            for item in result.normalized_values
        }
        replayed: dict[tuple[str, int], NormalizedValue] = {}
        for trial in result.trials:
            data_reasons: set[str] = set()
            for variant in spec.variants:
                cell = (variant.variant_id, trial.repetition_index)
                final = final_measurements.get(cell)
                if final is None:
                    raise AtomicOracleError(
                        AtomicOracleErrorCode.RESULT_REPLAY_MISMATCH,
                        "a trial has no final recorded invocation",
                    )
                value, data_reason = self._replay_normalizer(normalizer, final)
                if data_reason is not None:
                    if data_reason not in getattr(normalizer, "reason_codes", ()):
                        raise AtomicOracleError(
                            AtomicOracleErrorCode.RESULT_REPLAY_MISMATCH,
                            "normalizer replay emitted an undeclared reason",
                        )
                    data_reasons.add(data_reason)
                else:
                    assert value is not None
                    replayed[cell] = value

            expected_normalized = tuple(
                sorted(
                    (
                        item
                        for (variant_id, repetition_index), item in replayed.items()
                        if repetition_index == trial.repetition_index
                    ),
                    key=lambda item: item.variant_id,
                )
            )
            provided_normalized = tuple(
                sorted(
                    (
                        item
                        for (variant_id, repetition_index), item in provided.items()
                        if repetition_index == trial.repetition_index
                    ),
                    key=lambda item: item.variant_id,
                )
            )
            if provided_normalized != expected_normalized:
                raise AtomicOracleError(
                    AtomicOracleErrorCode.RESULT_REPLAY_MISMATCH,
                    "recorded normalized values differ from atom replay",
                )
            values = tuple(item.value for item in expected_normalized)
            if data_reasons:
                expected_decision = TrialDecision(
                    OracleVerdict.INCONCLUSIVE,
                    sorted(data_reasons)[0],
                    values,
                )
            else:
                try:
                    expected_decision = comparator(
                        spec.method,
                        values,
                        self._read_artifact,
                        repetition_index=trial.repetition_index,
                    )
                except ArtifactIntegrityError:
                    raise
                except AtomicDataError as exc:
                    if exc.reason_code not in getattr(
                        comparator,
                        "reason_codes",
                        {},
                    ).get(OracleVerdict.INCONCLUSIVE, ()):
                        raise AtomicOracleError(
                            AtomicOracleErrorCode.RESULT_REPLAY_MISMATCH,
                            "comparator replay emitted an undeclared reason",
                        ) from exc
                    expected_decision = TrialDecision(
                        OracleVerdict.INCONCLUSIVE,
                        exc.reason_code,
                        values,
                    )
                except Exception as exc:
                    raise AtomicOracleError(
                        AtomicOracleErrorCode.RESULT_REPLAY_MISMATCH,
                        "comparator could not replay recorded evidence",
                    ) from exc
                expected_decision = self._require_valid_comparator_decision(
                    comparator,
                    expected_decision,
                    values,
                    error_code=AtomicOracleErrorCode.RESULT_REPLAY_MISMATCH,
                    context="comparator replay",
                )
            if trial.decision != expected_decision:
                raise AtomicOracleError(
                    AtomicOracleErrorCode.RESULT_REPLAY_MISMATCH,
                    "recorded trial decision differs from atom replay",
                )

        self._validate_terminal_witness(
            spec,
            result,
            normalizer,
            comparator,
            final_measurements,
            provided,
        )

    def _validate_terminal_witness(
        self,
        spec: OracleSpec,
        result: AtomicOracleResult,
        normalizer,
        comparator,
        final_measurements: dict[tuple[str, int], AtomicRunRecord],
        provided: dict[tuple[str, int], NormalizedValue],
    ) -> None:
        """Derive a non-decided terminal class from its execution prefix."""

        if result.result_class is AtomicResultClass.DECIDED:
            return
        if not result.run_records:
            raise AtomicOracleError(
                AtomicOracleErrorCode.RESULT_REPLAY_MISMATCH,
                "executed terminal result has no run witness",
            )

        finals: dict[tuple[bool, str, int], AtomicRunRecord] = {}
        for record in result.run_records:
            request = record.request
            finals[(request.warmup, request.variant_id, request.repetition_index)] = (
                record
            )
        ordered_finals = tuple(finals.values())
        last = result.run_records[-1]
        if ordered_finals[-1] != last:
            raise AtomicOracleError(
                AtomicOracleErrorCode.RESULT_REPLAY_MISMATCH,
                "terminal witness is not the final invocation of its cell",
            )

        # The executor cannot advance beyond a failed warmup or infrastructure
        # status.  Checking this here prevents a fabricated later prefix from
        # laundering the earlier stop condition.
        for prior in ordered_finals[:-1]:
            if prior.request.warmup:
                valid = prior.result.status is AtomicRunStatus.COMPLETED
            else:
                valid = prior.result.status not in _RETRY_STATUS
            if not valid:
                raise AtomicOracleError(
                    AtomicOracleErrorCode.RESULT_REPLAY_MISMATCH,
                    "execution continued after a terminal run status",
                )

        trailing_repetition = len(result.trials)
        trailing_provided = {
            cell: value
            for cell, value in provided.items()
            if cell[1] >= trailing_repetition
        }

        def replay_cells(
            records: tuple[AtomicRunRecord, ...],
        ) -> tuple[
            dict[tuple[str, int], NormalizedValue],
            frozenset[str],
        ]:
            expected: dict[tuple[str, int], NormalizedValue] = {}
            data_reasons: set[str] = set()
            for record in records:
                value, data_reason = self._replay_normalizer(normalizer, record)
                if data_reason is not None:
                    if data_reason not in getattr(normalizer, "reason_codes", ()):
                        raise AtomicOracleError(
                            AtomicOracleErrorCode.RESULT_REPLAY_MISMATCH,
                            "terminal normalizer replay emitted an undeclared reason",
                        )
                    data_reasons.add(data_reason)
                    continue
                assert value is not None
                expected[(value.variant_id, value.repetition_index)] = value
            return expected, frozenset(data_reasons)

        def require_legal_infra_stop() -> None:
            retry_reason = _RETRY_STATUS.get(last.result.status)
            retry_exhausted = (
                last.request.retry_index >= result.protocol.max_retries
            )
            retry_disallowed = retry_reason not in result.protocol.retry_reasons
            if retry_reason is None or not (retry_exhausted or retry_disallowed):
                raise AtomicOracleError(
                    AtomicOracleErrorCode.RESULT_REPLAY_MISMATCH,
                    "infrastructure terminal does not exhaust or forbid its retry",
                )

        if last.request.warmup:
            if result.trials or result.normalized_values:
                raise AtomicOracleError(
                    AtomicOracleErrorCode.RESULT_REPLAY_MISMATCH,
                    "warmup terminal contains measurement evidence",
                )
            if result.result_class is AtomicResultClass.INFRA_INCONCLUSIVE:
                require_legal_infra_stop()
                return
            if (
                result.result_class is AtomicResultClass.ORACLE_INCONCLUSIVE
                and last.result.status
                in {
                    AtomicRunStatus.TARGET_TIMEOUT,
                    AtomicRunStatus.TARGET_CRASH,
                    AtomicRunStatus.TARGET_OOM,
                }
            ):
                return
            raise AtomicOracleError(
                AtomicOracleErrorCode.RESULT_REPLAY_MISMATCH,
                "warmup prefix does not witness the recorded terminal class",
            )

        if last.request.repetition_index != trailing_repetition:
            raise AtomicOracleError(
                AtomicOracleErrorCode.RESULT_REPLAY_MISMATCH,
                "terminal measurement is not the next unrecorded trial",
            )

        variant_ids = tuple(variant.variant_id for variant in spec.variants)
        try:
            last_variant_index = variant_ids.index(last.request.variant_id)
        except ValueError as exc:  # Defensive: structural validation also binds it.
            raise AtomicOracleError(
                AtomicOracleErrorCode.RESULT_REPLAY_MISMATCH,
                "terminal measurement uses an unknown variant",
            ) from exc
        current_records = tuple(
            final_measurements[(variant_id, trailing_repetition)]
            for variant_id in variant_ids[: last_variant_index + 1]
            if (variant_id, trailing_repetition) in final_measurements
        )
        if tuple(record.request.variant_id for record in current_records) != (
            variant_ids[: last_variant_index + 1]
        ):
            raise AtomicOracleError(
                AtomicOracleErrorCode.RESULT_REPLAY_MISMATCH,
                "terminal measurement prefix skips a frozen variant",
            )

        if result.result_class is AtomicResultClass.INFRA_INCONCLUSIVE:
            require_legal_infra_stop()
            expected, _ = replay_cells(current_records[:-1])
            if trailing_provided != expected:
                raise AtomicOracleError(
                    AtomicOracleErrorCode.RESULT_REPLAY_MISMATCH,
                    "infrastructure terminal normalized evidence is incomplete",
                )
            return

        if result.result_class is not AtomicResultClass.ORACLE_INCONCLUSIVE:
            raise AtomicOracleError(
                AtomicOracleErrorCode.RESULT_REPLAY_MISMATCH,
                "execution prefix has no supported terminal class",
            )
        if last_variant_index != len(variant_ids) - 1:
            raise AtomicOracleError(
                AtomicOracleErrorCode.RESULT_REPLAY_MISMATCH,
                "oracle terminal does not contain a complete trailing trial",
            )
        expected, data_reasons = replay_cells(current_records)
        if data_reasons or trailing_provided != expected:
            raise AtomicOracleError(
                AtomicOracleErrorCode.RESULT_REPLAY_MISMATCH,
                "oracle terminal normalized evidence is not replayable",
            )
        values = tuple(
            expected[(variant_id, trailing_repetition)].value
            for variant_id in variant_ids
        )
        try:
            decision = comparator(
                spec.method,
                values,
                self._read_artifact,
                repetition_index=trailing_repetition,
            )
        except ArtifactIntegrityError:
            raise
        except Exception as exc:
            raise AtomicOracleError(
                AtomicOracleErrorCode.RESULT_REPLAY_MISMATCH,
                "terminal comparator evidence could not be replayed",
            ) from exc
        decision = self._require_valid_comparator_decision(
            comparator,
            decision,
            values,
            error_code=AtomicOracleErrorCode.RESULT_REPLAY_MISMATCH,
            context="terminal comparator replay",
        )
        prior_groups = {
            trial.decision.evidence_group_id
            for trial in result.trials
            if trial.decision.evidence_group_id is not None
        }
        if (
            decision.evidence_group_id is None
            or decision.evidence_group_id not in prior_groups
        ):
            raise AtomicOracleError(
                AtomicOracleErrorCode.RESULT_REPLAY_MISMATCH,
                "oracle terminal is not witnessed by a repeated evidence group",
            )

    def execute(
        self,
        spec: OracleSpec,
        *,
        applicability: ApplicabilityResult,
        inputs: tuple[ArtifactRef, ...] = (),
    ) -> AtomicOracleResult:
        normalizer, comparator, runners, threshold_values = self._preflight(
            spec, applicability
        )
        if type(inputs) not in (tuple, list) or any(
            type(item) is not ArtifactRef for item in inputs
        ):
            raise ContractError("inputs must contain ArtifactRef values")
        inputs = tuple(sorted(inputs, key=lambda item: item.role))
        if len({item.role for item in inputs}) != len(inputs):
            raise ContractError("inputs must not repeat artifact roles")

        # Integrity is checked before domain branching or the first runner call.
        self._read_artifact(spec.applicability.calibrated_domain)
        for reference in (*applicability.evidence, *inputs):
            self._read_artifact(reference)
        if type(spec.method) is GoldenMethod:
            self._read_artifact(spec.method.expected_artifact)

        protocol = spec.execution_protocol
        if not applicability.matches:
            result = AtomicOracleResult(
                oracle_spec=spec.ref,
                normalizer=spec.normalizer,
                comparator=spec.comparator,
                protocol=spec.execution_protocol,
                variants=tuple(
                    AtomicVariantBinding(item.variant_id, item.execution_recipe)
                    for item in spec.variants
                ),
                collectors=spec.collectors,
                applicability=applicability,
                inputs=inputs,
                threshold_values=threshold_values,
                result_class=AtomicResultClass.DOMAIN_MISMATCH,
                verdict=OracleVerdict.INCONCLUSIVE,
                reason_codes=(spec.applicability.out_of_domain_reason,),
                domain_match=False,
                trials=(),
                run_records=(),
                normalized_values=(),
            )
            self.validate_result(spec, result)
            return result

        all_runs: list[AtomicRunRecord] = []
        trials: list[AtomicTrialRecord] = []
        normalized: list[NormalizedValue] = []
        evidence_groups: set[str] = set()
        seen_captures: set[tuple[ContractRef, str]] = set()
        seen_provenance: set[str] = set()

        for warmup_index in range(protocol.warmup_runs):
            for variant in spec.variants:
                final, records, infra_failure = self._run_once(
                    runner=runners[variant.variant_id],
                    recipe=variant.execution_recipe,
                    variant_id=variant.variant_id,
                    repetition_index=warmup_index,
                    warmup=True,
                    inputs=inputs,
                    spec=spec,
                    seen_captures=seen_captures,
                    seen_provenance=seen_provenance,
                )
                all_runs.extend(records)
                if infra_failure:
                    return self._terminal_result(
                        spec,
                        applicability,
                        inputs,
                        threshold_values,
                        AtomicResultClass.INFRA_INCONCLUSIVE,
                        "ENVIRONMENT_UNSTABLE",
                        all_runs,
                        trials,
                        normalized,
                    )
                if final.result.status is not AtomicRunStatus.COMPLETED:
                    return self._terminal_result(
                        spec,
                        applicability,
                        inputs,
                        threshold_values,
                        AtomicResultClass.ORACLE_INCONCLUSIVE,
                        "METRIC_INVALID",
                        all_runs,
                        trials,
                        normalized,
                    )

        for repetition_index in range(protocol.repetitions):
            trial_values: list[CanonicalTypedValue] = []
            trial_normalized: list[NormalizedValue] = []
            data_error_reasons: set[str] = set()
            for variant in spec.variants:
                final, records, infra_failure = self._run_once(
                    runner=runners[variant.variant_id],
                    recipe=variant.execution_recipe,
                    variant_id=variant.variant_id,
                    repetition_index=repetition_index,
                    warmup=False,
                    inputs=inputs,
                    spec=spec,
                    seen_captures=seen_captures,
                    seen_provenance=seen_provenance,
                )
                all_runs.extend(records)
                if infra_failure:
                    normalized.extend(trial_normalized)
                    return self._terminal_result(
                        spec,
                        applicability,
                        inputs,
                        threshold_values,
                        AtomicResultClass.INFRA_INCONCLUSIVE,
                        "ENVIRONMENT_UNSTABLE",
                        all_runs,
                        trials,
                        normalized,
                    )
                try:
                    value = normalizer(
                        variant.variant_id,
                        repetition_index,
                        final.result,
                        self._read_artifact,
                    )
                except ArtifactIntegrityError:
                    raise
                except AtomicDataError as exc:
                    if exc.reason_code not in getattr(
                        normalizer,
                        "reason_codes",
                        (),
                    ):
                        raise AtomicOracleError(
                            AtomicOracleErrorCode.ATOM_EXECUTION_FAILED,
                            "normalizer emitted an undeclared data reason",
                        ) from exc
                    data_error_reasons.add(exc.reason_code)
                    continue
                except Exception as exc:
                    raise AtomicOracleError(
                        AtomicOracleErrorCode.ATOM_EXECUTION_FAILED,
                        "normalizer raised outside its typed data contract",
                    ) from exc
                bound_value = self._bind_normalized_value(
                    value,
                    final,
                    error_code=AtomicOracleErrorCode.ATOM_EXECUTION_FAILED,
                    context="normalizer",
                )
                trial_values.append(bound_value.value)
                trial_normalized.append(bound_value)

            expected_values = tuple(
                sorted(trial_values, key=lambda item: item.value_id)
            )
            normalized.extend(trial_normalized)
            if data_error_reasons:
                decision = TrialDecision(
                    OracleVerdict.INCONCLUSIVE,
                    sorted(data_error_reasons)[0],
                    expected_values,
                )
            else:
                try:
                    candidate = comparator(
                        spec.method,
                        expected_values,
                        self._read_artifact,
                        repetition_index=repetition_index,
                    )
                except ArtifactIntegrityError:
                    raise
                except AtomicDataError as exc:
                    allowed = getattr(comparator, "reason_codes", {}).get(
                        OracleVerdict.INCONCLUSIVE,
                        (),
                    )
                    if exc.reason_code not in allowed:
                        raise AtomicOracleError(
                            AtomicOracleErrorCode.ATOM_EXECUTION_FAILED,
                            "comparator emitted an undeclared data reason",
                        ) from exc
                    candidate = TrialDecision(
                        OracleVerdict.INCONCLUSIVE,
                        exc.reason_code,
                        expected_values,
                    )
                except Exception as exc:
                    raise AtomicOracleError(
                        AtomicOracleErrorCode.ATOM_EXECUTION_FAILED,
                        "comparator raised outside its typed data contract",
                    ) from exc
                decision = self._require_valid_comparator_decision(
                    comparator,
                    candidate,
                    expected_values,
                    error_code=AtomicOracleErrorCode.ATOM_EXECUTION_FAILED,
                    context="comparator",
                )
            if decision.evidence_group_id is not None:
                if decision.evidence_group_id in evidence_groups:
                    return self._terminal_result(
                        spec,
                        applicability,
                        inputs,
                        threshold_values,
                        AtomicResultClass.ORACLE_INCONCLUSIVE,
                        "METRIC_INVALID",
                        all_runs,
                        trials,
                        normalized,
                    )
                evidence_groups.add(decision.evidence_group_id)
            trials.append(AtomicTrialRecord(repetition_index, decision))

        violation_count = sum(
            item.decision.verdict is OracleVerdict.VIOLATION for item in trials
        )
        pass_count = sum(
            item.decision.verdict is OracleVerdict.PASS for item in trials
        )
        required = protocol.quorum.required
        violation_met = violation_count >= required
        pass_met = pass_count >= required
        verdict = (
            OracleVerdict.VIOLATION
            if violation_met and not pass_met
            else OracleVerdict.PASS
            if pass_met and not violation_met
            else OracleVerdict.INCONCLUSIVE
        )
        if verdict is OracleVerdict.INCONCLUSIVE:
            reasons = {
                item.decision.reason_code
                for item in trials
                if item.decision.verdict is OracleVerdict.INCONCLUSIVE
            }
            reasons.add("QUORUM_NOT_MET")
        else:
            reasons = {
                item.decision.reason_code
                for item in trials
                if item.decision.verdict is verdict
            }
        result = AtomicOracleResult(
            oracle_spec=spec.ref,
            normalizer=spec.normalizer,
            comparator=spec.comparator,
            protocol=spec.execution_protocol,
            variants=tuple(
                AtomicVariantBinding(item.variant_id, item.execution_recipe)
                for item in spec.variants
            ),
            collectors=spec.collectors,
            applicability=applicability,
            inputs=inputs,
            threshold_values=threshold_values,
            result_class=AtomicResultClass.DECIDED,
            verdict=verdict,
            reason_codes=tuple(sorted(reasons)),
            domain_match=True,
            trials=tuple(trials),
            run_records=tuple(all_runs),
            normalized_values=tuple(normalized),
        )
        self.validate_result(spec, result)
        return result

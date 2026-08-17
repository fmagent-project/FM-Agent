"""Fail-closed statistical evaluation for profile qualification.

This module contains no execution surface.  It consumes already frozen setup
contracts and Oracle decisions produced by a qualification worker, then emits
an auditable qualification report.  In particular, it never grants profile
trust or creates an approval.
"""

from __future__ import annotations

from decimal import Decimal, ROUND_CEILING, ROUND_FLOOR, localcontext
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from enum import Enum

from ..contracts.base import (
    CanonicalDecimal,
    ContractError,
    canonical_sha256,
    validate_sha256,
)
from ..contracts.evidence import OracleVerdict
from ..contracts.setup import (
    CalibrationReport,
    QualificationMode,
    QualificationPartitionKind,
    QualificationPlan,
    QualificationPolicy,
    QualificationReport,
    QualificationTrial,
    QualificationVerdict,
    StatisticalBoundMethod,
)


_BOUND_PRECISION = 192
_BOUND_DIGITS = 48
_BISECTION_STEPS = 640
_MAX_BOUND_TRIALS = 1_000_000


class QualificationFailureReason(str, Enum):
    CALIBRATION_FAILED = "CALIBRATION_FAILED"
    CALIBRATION_EXPIRED = "CALIBRATION_EXPIRED"
    UNSTABLE_TRIAL = "UNSTABLE_TRIAL"
    CALIBRATION_EXPECTATION_MISMATCH = "CALIBRATION_EXPECTATION_MISMATCH"
    HOLDOUT_INCONCLUSIVE = "HOLDOUT_INCONCLUSIVE"
    FALSE_VIOLATION = "FALSE_VIOLATION"
    NEGATIVE_INCONCLUSIVE = "NEGATIVE_INCONCLUSIVE"
    NEGATIVE_NOT_DETECTED = "NEGATIVE_NOT_DETECTED"
    OOD_POLICY_NOT_FAIL_CLOSED = "OOD_POLICY_NOT_FAIL_CLOSED"
    OOD_NOT_INCONCLUSIVE = "OOD_NOT_INCONCLUSIVE"
    INSUFFICIENT_NON_VIOLATING_GROUPS = "INSUFFICIENT_NON_VIOLATING_GROUPS"
    INSUFFICIENT_NEGATIVE_GROUPS = "INSUFFICIENT_NEGATIVE_GROUPS"
    INSUFFICIENT_CALIBRATED_CELLS = "INSUFFICIENT_CALIBRATED_CELLS"
    INSUFFICIENT_FAULT_CELLS = "INSUFFICIENT_FAULT_CELLS"
    CORRELATED_GROUPS_REQUIRE_CLUSTER_BOUND = (
        "CORRELATED_GROUPS_REQUIRE_CLUSTER_BOUND"
    )
    FALSE_VIOLATION_BOUND_EXCEEDED = "FALSE_VIOLATION_BOUND_EXCEEDED"
    DETECTION_BOUND_BELOW_TARGET = "DETECTION_BOUND_BELOW_TARGET"


@dataclass(frozen=True)
class _GroupOutcome:
    partition_kind: QualificationPartitionKind
    group_commitment: str
    cluster_commitment: str
    observed_verdicts: frozenset[OracleVerdict]
    stable: bool


def _probability(value: CanonicalDecimal, field: str) -> Decimal:
    if type(value) is not CanonicalDecimal:
        raise ContractError(f"{field} must be a CanonicalDecimal")
    result = Decimal(value.value)
    if result <= 0 or result > 1:
        raise ContractError(f"{field} must be greater than zero and at most one")
    return result


def _counts(events: object, trials: object) -> tuple[int, int]:
    if type(events) is not int or type(trials) is not int:
        raise ContractError("events and trials must be integers")
    if trials < 1 or trials > _MAX_BOUND_TRIALS:
        raise ContractError(
            f"trials must be between 1 and {_MAX_BOUND_TRIALS}"
        )
    if events < 0 or events > trials:
        raise ContractError("events must be between zero and trials")
    return events, trials


def _binomial_range_probability(
    trials: int,
    first: int,
    last: int,
    probability: Decimal,
) -> Decimal:
    """Return an inclusive binomial probability using fixed Decimal rules."""

    if first > last:
        return Decimal(0)
    complement = Decimal(1) - probability
    if probability == 0:
        return Decimal(1) if first == 0 else Decimal(0)
    if probability == 1:
        return Decimal(1) if last == trials else Decimal(0)

    # Qualification uses low false-event tails and high detection tails.  A
    # recurrence avoids enormous binomial coefficients and gives bounded work
    # proportional to the tail being evaluated.
    term = complement**trials
    total = term if first == 0 else Decimal(0)
    odds = probability / complement
    for count in range(0, last):
        term *= (
            Decimal(trials - count) / Decimal(count + 1)
        ) * odds
        if count + 1 >= first:
            total += term
    return total


def _canonical_bound(value: Decimal, *, upper: bool) -> CanonicalDecimal:
    quantum = Decimal(1).scaleb(-_BOUND_DIGITS)
    rounding = ROUND_CEILING if upper else ROUND_FLOOR
    bounded = min(Decimal(1), max(Decimal(0), value))
    rendered = format(bounded.quantize(quantum, rounding=rounding), "f")
    if "." in rendered:
        rendered = rendered.rstrip("0").rstrip(".")
    return CanonicalDecimal(rendered or "0")


def clopper_pearson_upper_bound(
    events: int,
    trials: int,
    confidence: CanonicalDecimal,
) -> CanonicalDecimal:
    """Conservative one-sided exact upper bound for a Bernoulli event rate.

    The returned decimal is rounded *up*, so serialization cannot turn a
    failing governance comparison into a pass.
    """

    events, trials = _counts(events, trials)
    confidence_value = _probability(confidence, "confidence")
    if confidence_value == 1:
        return CanonicalDecimal("1")
    if events == trials:
        return CanonicalDecimal("1")

    with localcontext() as context:
        context.prec = _BOUND_PRECISION
        target = Decimal(1) - confidence_value
        low = Decimal(0)
        high = Decimal(1)
        for _ in range(_BISECTION_STEPS):
            midpoint = (low + high) / 2
            cumulative = _binomial_range_probability(
                trials,
                0,
                events,
                midpoint,
            )
            if cumulative > target:
                low = midpoint
            else:
                high = midpoint
        return _canonical_bound(high, upper=True)


def clopper_pearson_lower_bound(
    successes: int,
    trials: int,
    confidence: CanonicalDecimal,
) -> CanonicalDecimal:
    """Conservative one-sided exact lower bound for a Bernoulli success rate.

    The returned decimal is rounded *down*, preserving fail-closed threshold
    comparisons after canonical serialization.
    """

    successes, trials = _counts(successes, trials)
    confidence_value = _probability(confidence, "confidence")
    if confidence_value == 1:
        return CanonicalDecimal("0")
    if successes == 0:
        return CanonicalDecimal("0")

    with localcontext() as context:
        context.prec = _BOUND_PRECISION
        target = Decimal(1) - confidence_value
        low = Decimal(0)
        high = Decimal(1)
        for _ in range(_BISECTION_STEPS):
            midpoint = (low + high) / 2
            # P[X >= successes | p] equals the lower tail for the number of
            # failures under probability (1-p).  This keeps work small for the
            # intended high-detection qualification boundary.
            upper_tail = _binomial_range_probability(
                trials,
                0,
                trials - successes,
                Decimal(1) - midpoint,
            )
            if upper_tail < target:
                low = midpoint
            else:
                high = midpoint
        return _canonical_bound(low, upper=False)


def _parse_timestamp(value: str, field: str) -> datetime:
    if type(value) is not str:
        raise ContractError(f"{field} must be a UTC timestamp")
    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=timezone.utc
        )
    except ValueError as exc:
        raise ContractError(f"{field} must be a canonical UTC timestamp") from exc
    if parsed.strftime("%Y-%m-%dT%H:%M:%SZ") != value:
        raise ContractError(f"{field} must be a canonical UTC timestamp")
    return parsed


def _representative_verdict(
    partition: QualificationPartitionKind,
    verdicts: frozenset[OracleVerdict],
) -> OracleVerdict:
    if partition in (
        QualificationPartitionKind.CALIBRATION,
        QualificationPartitionKind.HOLDOUT,
    ):
        if OracleVerdict.VIOLATION in verdicts:
            return OracleVerdict.VIOLATION
        if OracleVerdict.INCONCLUSIVE in verdicts:
            return OracleVerdict.INCONCLUSIVE
        return OracleVerdict.PASS
    if partition is QualificationPartitionKind.NEGATIVE:
        if verdicts == frozenset({OracleVerdict.VIOLATION}):
            return OracleVerdict.VIOLATION
        if OracleVerdict.INCONCLUSIVE in verdicts:
            return OracleVerdict.INCONCLUSIVE
        return OracleVerdict.PASS
    if verdicts == frozenset({OracleVerdict.INCONCLUSIVE}):
        return OracleVerdict.INCONCLUSIVE
    if OracleVerdict.VIOLATION in verdicts:
        return OracleVerdict.VIOLATION
    return OracleVerdict.PASS


def _validate_and_group_trials(
    plan: QualificationPlan,
    trials: object,
    max_retries_per_trial: int,
    retryable_reasons: tuple[str, ...],
) -> tuple[tuple[QualificationTrial, ...], tuple[_GroupOutcome, ...]]:
    if type(trials) not in (tuple, list):
        raise ContractError("trials must be a collection of QualificationTrial values")
    normalized = tuple(trials)
    if not normalized or any(type(item) is not QualificationTrial for item in normalized):
        raise ContractError("trials must be a non-empty QualificationTrial collection")

    ids = tuple(item.trial_id for item in normalized)
    decisions = tuple(item.oracle_decision for item in normalized)
    if len(ids) != len(set(ids)) or len(decisions) != len(set(decisions)):
        raise ContractError("qualification trials must have unique ids and decisions")

    partitions = {item.kind: item for item in plan.partitions}
    expected_units = {
        kind: {
            unit.member_commitment: (
                unit.group_commitment,
                unit.cluster_commitment,
            )
            for unit in partition.units
        }
        for kind, partition in partitions.items()
    }
    observed_members = {kind: set() for kind in QualificationPartitionKind}
    by_group: dict[
        tuple[QualificationPartitionKind, str], list[QualificationTrial]
    ] = {}
    member_bindings: dict[
        tuple[QualificationPartitionKind, str], tuple[str, str, str, bool]
    ] = {}
    member_attempts: dict[
        tuple[QualificationPartitionKind, str], set[int]
    ] = {}
    allowed_retry_reasons = frozenset(retryable_reasons)

    for trial in normalized:
        unit = expected_units[trial.partition_kind].get(trial.member_commitment)
        if unit != (trial.group_commitment, trial.cluster_commitment):
            raise ContractError(
                "qualification trial is outside its frozen member/group/cluster lineage"
            )
        observed_members[trial.partition_kind].add(trial.member_commitment)
        member_key = (trial.partition_kind, trial.member_commitment)
        attempts = member_attempts.setdefault(member_key, set())
        if trial.attempt_index in attempts:
            raise ContractError("qualification member repeats an attempt_index")
        attempts.add(trial.attempt_index)
        if len(attempts) > 1 + max_retries_per_trial:
            raise ContractError(
                "qualification member exceeds the frozen retry allowance"
            )
        if (
            trial.attempt_index > 1
            and trial.retry_reason not in allowed_retry_reasons
        ):
            raise ContractError(
                "qualification retry reason is not frozen by policy"
            )
        binding = (
            trial.group_commitment,
            trial.cluster_commitment,
            trial.workload_cell_sha256,
            trial.real_integration,
        )
        previous = member_bindings.setdefault(member_key, binding)
        if previous != binding:
            raise ContractError("replays changed a frozen qualification member binding")
    for attempts in member_attempts.values():
        if attempts != set(range(1, len(attempts) + 1)):
            raise ContractError(
                "qualification attempt_index values must be contiguous"
            )

    final_by_member: dict[
        tuple[QualificationPartitionKind, str], QualificationTrial
    ] = {}
    for trial in normalized:
        key = (trial.partition_kind, trial.member_commitment)
        previous = final_by_member.get(key)
        if previous is None or trial.attempt_index > previous.attempt_index:
            final_by_member[key] = trial
    for trial in final_by_member.values():
        by_group.setdefault(
            (trial.partition_kind, trial.group_commitment), []
        ).append(trial)

    for kind in QualificationPartitionKind:
        if observed_members[kind] != set(expected_units[kind]):
            raise ContractError(
                f"qualification trials do not exactly cover {kind.value} members"
            )

    outcomes: list[_GroupOutcome] = []
    for (kind, group), grouped in by_group.items():
        clusters = {item.cluster_commitment for item in grouped}
        if len(clusters) != 1:
            raise ContractError("one frozen group cannot span multiple clusters")
        verdicts = frozenset(item.observed_verdict for item in grouped)
        outcomes.append(
            _GroupOutcome(
                partition_kind=kind,
                group_commitment=group,
                cluster_commitment=next(iter(clusters)),
                observed_verdicts=verdicts,
                stable=all(item.stable for item in grouped) and len(verdicts) == 1,
            )
        )
    return (
        tuple(sorted(normalized, key=lambda item: item.trial_id)),
        tuple(
            sorted(
                outcomes,
                key=lambda item: (
                    item.partition_kind.value,
                    item.cluster_commitment,
                    item.group_commitment,
                ),
            )
        ),
    )


def evaluate_qualification(
    *,
    report_id: str,
    policy: QualificationPolicy,
    plan: QualificationPlan,
    calibration_report: CalibrationReport,
    trials: tuple[QualificationTrial, ...],
    qualification_environment_sha256: str,
    completed_at: str,
) -> QualificationReport:
    """Evaluate frozen qualification evidence without granting profile trust."""

    if type(policy) is not QualificationPolicy:
        raise ContractError("policy must be a QualificationPolicy")
    if type(plan) is not QualificationPlan:
        raise ContractError("plan must be a QualificationPlan")
    if type(calibration_report) is not CalibrationReport:
        raise ContractError("calibration_report must be a CalibrationReport")
    validate_sha256(
        qualification_environment_sha256,
        "qualification_environment_sha256",
    )
    if plan.qualification_policy != policy.ref:
        raise ContractError("qualification plan does not bind the supplied policy")

    calibration_partition = next(
        item
        for item in plan.partitions
        if item.kind is QualificationPartitionKind.CALIBRATION
    )
    expected_calibration_binding = (
        plan.setup_subject_sha256,
        policy.content_sha256,
        plan.content_sha256,
        canonical_sha256(calibration_partition.to_document()),
    )
    actual_calibration_binding = (
        calibration_report.setup_subject_sha256,
        calibration_report.qualification_policy_sha256,
        calibration_report.qualification_plan_sha256,
        calibration_report.calibration_partition_sha256,
    )
    if actual_calibration_binding != expected_calibration_binding:
        raise ContractError("calibration report does not bind the qualification graph")

    normalized_trials, groups = _validate_and_group_trials(
        plan,
        trials,
        policy.max_retries_per_trial,
        policy.retryable_reasons,
    )
    completed = _parse_timestamp(completed_at, "completed_at")
    calibration_completed = _parse_timestamp(
        calibration_report.completed_at,
        "calibration_report.completed_at",
    )
    calibration_expires = _parse_timestamp(
        calibration_report.expires_at,
        "calibration_report.expires_at",
    )
    if calibration_completed > completed:
        raise ContractError("calibration report cannot be completed in the future")
    policy_expires = completed + timedelta(seconds=policy.qualification_ttl_seconds)

    reasons: set[QualificationFailureReason] = set()
    if calibration_report.verdict is not QualificationVerdict.PASS:
        reasons.add(QualificationFailureReason.CALIBRATION_FAILED)
    if calibration_expires <= completed:
        reasons.add(QualificationFailureReason.CALIBRATION_EXPIRED)
        expires = policy_expires
    else:
        expires = min(policy_expires, calibration_expires)

    grouped_by_partition = {
        kind: tuple(item for item in groups if item.partition_kind is kind)
        for kind in QualificationPartitionKind
    }
    if any(not item.stable for item in groups):
        reasons.add(QualificationFailureReason.UNSTABLE_TRIAL)

    calibration_groups = grouped_by_partition[QualificationPartitionKind.CALIBRATION]
    if any(
        _representative_verdict(item.partition_kind, item.observed_verdicts)
        is not OracleVerdict.PASS
        for item in calibration_groups
    ):
        reasons.add(QualificationFailureReason.CALIBRATION_EXPECTATION_MISMATCH)

    holdout_groups = grouped_by_partition[QualificationPartitionKind.HOLDOUT]
    negative_groups = grouped_by_partition[QualificationPartitionKind.NEGATIVE]
    ood_groups = grouped_by_partition[QualificationPartitionKind.OUT_OF_DOMAIN]

    holdout_by_cluster: dict[str, list[_GroupOutcome]] = {}
    negative_by_cluster: dict[str, list[_GroupOutcome]] = {}
    for item in holdout_groups:
        holdout_by_cluster.setdefault(item.cluster_commitment, []).append(item)
    for item in negative_groups:
        negative_by_cluster.setdefault(item.cluster_commitment, []).append(item)

    false_events = 0
    for cluster_groups in holdout_by_cluster.values():
        verdicts = tuple(
            _representative_verdict(item.partition_kind, item.observed_verdicts)
            for item in cluster_groups
        )
        if OracleVerdict.INCONCLUSIVE in verdicts:
            reasons.add(QualificationFailureReason.HOLDOUT_INCONCLUSIVE)
        if any(item is not OracleVerdict.PASS for item in verdicts):
            false_events += 1

    detections = 0
    for cluster_groups in negative_by_cluster.values():
        verdicts = tuple(
            _representative_verdict(item.partition_kind, item.observed_verdicts)
            for item in cluster_groups
        )
        if OracleVerdict.INCONCLUSIVE in verdicts:
            reasons.add(QualificationFailureReason.NEGATIVE_INCONCLUSIVE)
        if all(item is OracleVerdict.VIOLATION for item in verdicts):
            detections += 1

    if not policy.require_ood_inconclusive:
        reasons.add(QualificationFailureReason.OOD_POLICY_NOT_FAIL_CLOSED)
    if any(
        _representative_verdict(item.partition_kind, item.observed_verdicts)
        is not OracleVerdict.INCONCLUSIVE
        for item in ood_groups
    ):
        reasons.add(QualificationFailureReason.OOD_NOT_INCONCLUSIVE)

    non_violating_count = len(holdout_by_cluster)
    negative_count = len(negative_by_cluster)
    calibrated_cells = {
        item.workload_cell_sha256
        for item in normalized_trials
        if item.real_integration
        and item.partition_kind
        in (
            QualificationPartitionKind.CALIBRATION,
            QualificationPartitionKind.HOLDOUT,
        )
    }
    fault_cells = {
        item.workload_cell_sha256
        for item in normalized_trials
        if item.real_integration
        and item.partition_kind is QualificationPartitionKind.NEGATIVE
    }

    if non_violating_count < policy.min_non_violating_groups:
        reasons.add(QualificationFailureReason.INSUFFICIENT_NON_VIOLATING_GROUPS)
    if negative_count < policy.min_negative_groups:
        reasons.add(QualificationFailureReason.INSUFFICIENT_NEGATIVE_GROUPS)
    if len(calibrated_cells) < policy.min_calibrated_cells:
        reasons.add(QualificationFailureReason.INSUFFICIENT_CALIBRATED_CELLS)
    if len(fault_cells) < policy.min_fault_cells:
        reasons.add(QualificationFailureReason.INSUFFICIENT_FAULT_CELLS)

    if policy.mode is QualificationMode.DETERMINISTIC:
        upper_bound = CanonicalDecimal("0")
        lower_bound = CanonicalDecimal("1")
        if false_events:
            reasons.add(QualificationFailureReason.FALSE_VIOLATION)
        if detections != negative_count:
            reasons.add(QualificationFailureReason.NEGATIVE_NOT_DETECTED)
    else:
        if policy.bound_method is StatisticalBoundMethod.CLOPPER_PEARSON:
            if any(len(items) != 1 for items in holdout_by_cluster.values()) or any(
                len(items) != 1 for items in negative_by_cluster.values()
            ):
                reasons.add(
                    QualificationFailureReason.CORRELATED_GROUPS_REQUIRE_CLUSTER_BOUND
                )
        upper_bound = clopper_pearson_upper_bound(
            false_events,
            non_violating_count,
            policy.confidence_level,
        )
        lower_bound = clopper_pearson_lower_bound(
            detections,
            negative_count,
            policy.confidence_level,
        )
        if Decimal(upper_bound.value) > Decimal(
            policy.max_false_violation_rate.value
        ):
            reasons.add(QualificationFailureReason.FALSE_VIOLATION_BOUND_EXCEEDED)
        if Decimal(lower_bound.value) < Decimal(policy.min_detection_rate.value):
            reasons.add(QualificationFailureReason.DETECTION_BOUND_BELOW_TARGET)

    verdict = (
        QualificationVerdict.FAIL if reasons else QualificationVerdict.PASS
    )
    return QualificationReport(
        report_id=report_id,
        setup_subject_sha256=plan.setup_subject_sha256,
        qualification_policy_sha256=policy.content_sha256,
        qualification_plan_sha256=plan.content_sha256,
        calibration_report_sha256=calibration_report.content_sha256,
        trials=normalized_trials,
        qualification_environment_sha256=qualification_environment_sha256,
        bound_method=policy.bound_method,
        upper_false_violation_bound=upper_bound,
        lower_detection_bound=lower_bound,
        independent_non_violating_groups=non_violating_count,
        independent_negative_groups=negative_count,
        calibrated_cell_count=len(calibrated_cells),
        fault_cell_count=len(fault_cells),
        verdict=verdict,
        reason_codes=tuple(sorted(item.value for item in reasons)),
        completed_at=completed.strftime("%Y-%m-%dT%H:%M:%SZ"),
        expires_at=expires.strftime("%Y-%m-%dT%H:%M:%SZ"),
    )


def verify_qualification_report(
    *,
    policy: QualificationPolicy,
    plan: QualificationPlan,
    calibration_report: CalibrationReport,
    report: QualificationReport,
) -> None:
    """Recompute every aggregate and reject a self-reported qualification."""

    if type(report) is not QualificationReport:
        raise ContractError("report must be a QualificationReport")
    recomputed = evaluate_qualification(
        report_id=report.report_id,
        policy=policy,
        plan=plan,
        calibration_report=calibration_report,
        trials=report.trials,
        qualification_environment_sha256=report.qualification_environment_sha256,
        completed_at=report.completed_at,
    )
    if recomputed != report:
        raise ContractError(
            "qualification report does not equal its canonical recomputation"
        )

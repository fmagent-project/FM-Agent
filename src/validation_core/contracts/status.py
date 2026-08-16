"""Closed validation status vocabulary shared by receipts and outcomes."""

from __future__ import annotations

from enum import Enum

from .base import ContractError


class ValidationGrade(str, Enum):
    L0 = "L0"
    L1 = "L1"


class GateAttemptDisposition(str, Enum):
    RETRYABLE_REJECTION = "RETRYABLE_REJECTION"
    ACCEPTED_CONFIRMED_CANDIDATE = "ACCEPTED_CONFIRMED_CANDIDATE"
    ACCEPTED_EXPLICIT_NOT_CONFIRMED = "ACCEPTED_EXPLICIT_NOT_CONFIRMED"
    TERMINAL_OUTCOME = "TERMINAL_OUTCOME"


class GatePhaseStatus(str, Enum):
    SATISFIED = "SATISFIED"
    REJECTED = "REJECTED"
    INCONCLUSIVE = "INCONCLUSIVE"
    SKIPPED = "SKIPPED"


class CaseStatus(str, Enum):
    CONFIRMED_L0 = "confirmed_l0"
    CONFIRMED_L1 = "confirmed_l1"
    NOT_CONFIRMED = "not_confirmed"
    INCONCLUSIVE_INFRA = "inconclusive_infra"
    INCONCLUSIVE_ORACLE = "inconclusive_oracle"
    NEEDS_ORACLE_SETUP = "needs_oracle_setup"
    INVALID_SUBMISSION = "invalid_submission"


class CaseReasonCode(str, Enum):
    NO_APPLICABLE_PROFILE_CAPABILITY = "NO_APPLICABLE_PROFILE_CAPABILITY"
    NO_ELIGIBLE_BASELINE = "NO_ELIGIBLE_BASELINE"

    SCHEMA_INVALID = "SCHEMA_INVALID"
    PROFILE_ARTIFACT_INVALID = "PROFILE_ARTIFACT_INVALID"
    BASELINE_ARTIFACT_HASH_MISMATCH = "BASELINE_ARTIFACT_HASH_MISMATCH"
    MEMBERSHIP_INVALID = "MEMBERSHIP_INVALID"

    TOOL_UNAVAILABLE = "TOOL_UNAVAILABLE"
    DEVICE_UNAVAILABLE = "DEVICE_UNAVAILABLE"
    ENVIRONMENT_UNSTABLE = "ENVIRONMENT_UNSTABLE"

    DOMAIN_MISMATCH = "DOMAIN_MISMATCH"
    QUALIFICATION_EXPIRED = "QUALIFICATION_EXPIRED"
    WORKLOAD_OR_TRACE_MISMATCH = "WORKLOAD_OR_TRACE_MISMATCH"
    INSUFFICIENT_SAMPLES = "INSUFFICIENT_SAMPLES"
    INSUFFICIENT_TAIL_SAMPLES = "INSUFFICIENT_TAIL_SAMPLES"
    CI_CROSSES_BOUNDARY = "CI_CROSSES_BOUNDARY"
    QUORUM_NOT_MET = "QUORUM_NOT_MET"
    MEASUREMENT_NOISE_TOO_HIGH = "MEASUREMENT_NOISE_TOO_HIGH"
    CONTROL_DRIFT_TOO_HIGH = "CONTROL_DRIFT_TOO_HIGH"
    METRIC_INVALID = "METRIC_INVALID"
    TIMEOUT_POLICY_UNDEFINED = "TIMEOUT_POLICY_UNDEFINED"
    ORACLE_GUARD_FAILED = "ORACLE_GUARD_FAILED"
    CONTROL_NOT_SEMANTICALLY_EQUIVALENT = (
        "CONTROL_NOT_SEMANTICALLY_EQUIVALENT"
    )
    REPRODUCIBILITY_FAILED = "REPRODUCIBILITY_FAILED"

    CONSEQUENCE_NOT_REPRODUCED = "CONSEQUENCE_NOT_REPRODUCED"
    EXPLICIT_NOT_CONFIRMED = "EXPLICIT_NOT_CONFIRMED"
    TARGET_NOT_REACHED = "TARGET_NOT_REACHED"
    TARGET_INPUT_MISMATCH = "TARGET_INPUT_MISMATCH"
    PREDICTED_Z_NOT_REPRODUCED = "PREDICTED_Z_NOT_REPRODUCED"
    CAUSAL_CONTROL_NO_EFFECT = "CAUSAL_CONTROL_NO_EFFECT"

    CONFIRMED_L0 = "CONFIRMED_L0"
    CONFIRMED_L1 = "CONFIRMED_L1"


_REASONS_BY_STATUS: dict[CaseStatus, frozenset[CaseReasonCode]] = {
    CaseStatus.CONFIRMED_L0: frozenset((CaseReasonCode.CONFIRMED_L0,)),
    CaseStatus.CONFIRMED_L1: frozenset((CaseReasonCode.CONFIRMED_L1,)),
    CaseStatus.NOT_CONFIRMED: frozenset(
        (
            CaseReasonCode.CONSEQUENCE_NOT_REPRODUCED,
            CaseReasonCode.EXPLICIT_NOT_CONFIRMED,
            CaseReasonCode.TARGET_NOT_REACHED,
            CaseReasonCode.TARGET_INPUT_MISMATCH,
            CaseReasonCode.PREDICTED_Z_NOT_REPRODUCED,
            CaseReasonCode.CAUSAL_CONTROL_NO_EFFECT,
        )
    ),
    CaseStatus.INCONCLUSIVE_INFRA: frozenset(
        (
            CaseReasonCode.TOOL_UNAVAILABLE,
            CaseReasonCode.DEVICE_UNAVAILABLE,
            CaseReasonCode.ENVIRONMENT_UNSTABLE,
        )
    ),
    CaseStatus.INCONCLUSIVE_ORACLE: frozenset(
        (
            CaseReasonCode.DOMAIN_MISMATCH,
            CaseReasonCode.QUALIFICATION_EXPIRED,
            CaseReasonCode.WORKLOAD_OR_TRACE_MISMATCH,
            CaseReasonCode.INSUFFICIENT_SAMPLES,
            CaseReasonCode.INSUFFICIENT_TAIL_SAMPLES,
            CaseReasonCode.CI_CROSSES_BOUNDARY,
            CaseReasonCode.QUORUM_NOT_MET,
            CaseReasonCode.MEASUREMENT_NOISE_TOO_HIGH,
            CaseReasonCode.CONTROL_DRIFT_TOO_HIGH,
            CaseReasonCode.METRIC_INVALID,
            CaseReasonCode.TIMEOUT_POLICY_UNDEFINED,
            CaseReasonCode.ORACLE_GUARD_FAILED,
            CaseReasonCode.CONTROL_NOT_SEMANTICALLY_EQUIVALENT,
            CaseReasonCode.REPRODUCIBILITY_FAILED,
        )
    ),
    CaseStatus.NEEDS_ORACLE_SETUP: frozenset(
        (
            CaseReasonCode.NO_APPLICABLE_PROFILE_CAPABILITY,
            CaseReasonCode.NO_ELIGIBLE_BASELINE,
        )
    ),
    CaseStatus.INVALID_SUBMISSION: frozenset(
        (
            CaseReasonCode.SCHEMA_INVALID,
            CaseReasonCode.PROFILE_ARTIFACT_INVALID,
            CaseReasonCode.BASELINE_ARTIFACT_HASH_MISMATCH,
            CaseReasonCode.MEMBERSHIP_INVALID,
        )
    ),
}


def validate_status_reason(
    status: CaseStatus,
    reason_code: CaseReasonCode,
) -> None:
    """Reject status/reason combinations outside the normative mapping."""

    if type(status) is not CaseStatus:
        raise ContractError("status must be a CaseStatus")
    if type(reason_code) is not CaseReasonCode:
        raise ContractError("reason_code must be a CaseReasonCode")
    if reason_code not in _REASONS_BY_STATUS[status]:
        raise ContractError(
            f"reason code {reason_code.value!r} is not valid for "
            f"status {status.value!r}"
        )

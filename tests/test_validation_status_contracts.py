import unittest

import src.validation_core as production_root
from src.validation_core.contracts.base import ContractError
from src.validation_core.contracts.status import (
    CaseReasonCode,
    CaseStatus,
    GateAttemptDisposition,
    GatePhaseStatus,
    ValidationGrade,
    validate_status_reason,
)


class ValidationStatusContractTests(unittest.TestCase):
    def test_normative_status_reason_pairs_are_accepted(self):
        pairs = (
            (CaseStatus.CONFIRMED_L0, CaseReasonCode.CONFIRMED_L0),
            (CaseStatus.CONFIRMED_L1, CaseReasonCode.CONFIRMED_L1),
            (
                CaseStatus.NOT_CONFIRMED,
                CaseReasonCode.CONSEQUENCE_NOT_REPRODUCED,
            ),
            (
                CaseStatus.INCONCLUSIVE_INFRA,
                CaseReasonCode.ENVIRONMENT_UNSTABLE,
            ),
            (
                CaseStatus.INCONCLUSIVE_ORACLE,
                CaseReasonCode.REPRODUCIBILITY_FAILED,
            ),
            (
                CaseStatus.NEEDS_ORACLE_SETUP,
                CaseReasonCode.NO_ELIGIBLE_BASELINE,
            ),
            (
                CaseStatus.INVALID_SUBMISSION,
                CaseReasonCode.PROFILE_ARTIFACT_INVALID,
            ),
        )
        for status, reason in pairs:
            with self.subTest(status=status.value, reason=reason.value):
                self.assertIsNone(validate_status_reason(status, reason))

    def test_cross_status_reason_is_rejected(self):
        with self.assertRaises(ContractError):
            validate_status_reason(
                CaseStatus.CONFIRMED_L0,
                CaseReasonCode.CONSEQUENCE_NOT_REPRODUCED,
            )

    def test_raw_strings_cannot_impersonate_closed_enums(self):
        with self.assertRaises(ContractError):
            validate_status_reason("confirmed_l0", CaseReasonCode.CONFIRMED_L0)
        with self.assertRaises(ContractError):
            validate_status_reason(CaseStatus.CONFIRMED_L0, "CONFIRMED_L0")

    def test_status_axes_remain_separate_closed_enums(self):
        self.assertEqual(ValidationGrade.L1.value, "L1")
        self.assertEqual(
            GateAttemptDisposition.RETRYABLE_REJECTION.value,
            "RETRYABLE_REJECTION",
        )
        self.assertEqual(GatePhaseStatus.SKIPPED.value, "SKIPPED")
        with self.assertRaises(ValueError):
            CaseStatus("failed")

    def test_stage4c_contracts_are_not_exported_from_production_root(self):
        for name in (
            "Observation",
            "OracleDecision",
            "CandidateGateReceipt",
            "FastPathGateReceipt",
            "ValidationOutcome",
            "CertificateV2",
            "CaseStatus",
        ):
            with self.subTest(name=name):
                self.assertFalse(hasattr(production_root, name))


if __name__ == "__main__":
    unittest.main()

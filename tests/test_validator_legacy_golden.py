import json
import unittest

from tests.validator_legacy_golden import (
    CORPUS_PATH,
    canonical_json_bytes,
    corpus_sha256,
    load_corpus,
)


EXPECTED_CORPUS_SHA256 = (
    "a6708bf3b5e9b0e6066cdd8c8f512c17bcf7897ff4eabfcaee2d0317ecae2131"
)


class ValidatorLegacyGoldenTests(unittest.TestCase):
    def test_corpus_is_strictly_valid_and_bound_to_multirun(self):
        corpus = load_corpus()

        self.assertEqual(
            corpus["baseline"],
            {
                "repository_ref": "private/multirun",
                "git_commit": "29eb099c01e6b6ef2f8e68ebc41608184b9f13d4",
                "submission_schema_version": 3,
                "result_schema_version": 3,
                "sidecar_schema_version": 5,
                "gate_version": "boundary-witness-v6",
                "toolchain_descriptor_version": 2,
            },
        )
        self.assertEqual(corpus_sha256(corpus), EXPECTED_CORPUS_SHA256)

    def test_canonical_capture_is_repeatable(self):
        first = load_corpus()
        second = load_corpus()

        self.assertEqual(canonical_json_bytes(first), canonical_json_bytes(second))
        self.assertEqual(
            json.loads(canonical_json_bytes(first).decode("utf-8")),
            first,
        )

    def test_all_required_semantic_cells_are_present(self):
        corpus = load_corpus()
        case_ids = {case["case_id"] for case in corpus["cases"]}

        self.assertEqual(len(case_ids), 32)
        self.assertTrue(
            {
                "gate.not_confirmed_fast_path",
                "gate.schema_v2_pre_execution_reject",
                "gate.exact_boundary_l1_accept",
                "gate.coverage_count_mismatch",
                "gate.direct_l0_hard_reject_after_evidence",
                "gate.l1_behavior_failure_downgrades_l0",
                "gate.l1_attempt_invalid_hard_reject",
                "flow.inner_reject_then_fix_same_session",
                "flow.inner_downgrade_preserves_outer_l1",
                "flow.outer_reject_starts_fresh_attempt_on_budget",
                "phenomenon.preprocess_normalized_text_diff",
                "phenomenon.syntax_accept_reject",
                "phenomenon.asm_success_output_ignored",
                "phenomenon.object_success_output_ignored",
                "phenomenon.run_build_accept_reject",
                "phenomenon.run_exit_diff",
                "phenomenon.run_stdout_diff",
                "trace.interleaved_span_pairing",
                "trace.missing_return_fails_closed",
                "l1.non_building_patch_hard_reject",
                "l1.patch_still_differs_downgrade_eligible",
                "l1.sanity_output_change_downgrade_eligible",
                "artifact.bound_inputs_fail_closed_on_tamper",
                "consumer.current_verified_artifact_skips",
                "consumer.raw_or_tampered_artifact_reruns",
            }.issubset(case_ids)
        )

    def test_known_legacy_gaps_are_not_mislabelled_as_target_behavior(self):
        corpus = load_corpus()
        policies = {
            case["case_id"]: case["parity_policy"] for case in corpus["cases"]
        }

        self.assertEqual(
            policies["gate.condition_a_not_mechanical"],
            "legacy_known_gap",
        )
        self.assertEqual(
            policies["flow.direct_scratch_candidate_bypasses_submit"],
            "intentional_cutover_delta",
        )

    def test_gate_order_and_original_l1_outer_candidate_are_pinned(self):
        corpus = load_corpus()
        cases = {case["case_id"]: case for case in corpus["cases"]}

        direct_l0 = cases["gate.direct_l0_hard_reject_after_evidence"]
        self.assertEqual(
            direct_l0["expected"]["external_calls"],
            ["replay", "coverage", "phenomenon"],
        )
        self.assertEqual(
            direct_l0["expected"]["decision"]["check"],
            "L1-attempt",
        )

        downgraded = cases["flow.inner_downgrade_preserves_outer_l1"]
        self.assertEqual(
            downgraded["expected"]["flow"]["requested_grade"], "L1"
        )
        self.assertEqual(
            downgraded["expected"]["flow"]["inner_final_grade"], "L0"
        )
        self.assertEqual(
            downgraded["expected"]["flow"]["outer_candidate"],
            "original_submission",
        )
        self.assertEqual(downgraded["expected"]["flow"]["outer_calls"], 1)

    def test_fixture_is_committed_at_the_documented_location(self):
        self.assertTrue(CORPUS_PATH.is_file())
        self.assertEqual(
            CORPUS_PATH.as_posix().split("/")[-4:],
            ["fixtures", "validator_legacy_golden", "v1", "corpus.json"],
        )


if __name__ == "__main__":
    unittest.main()

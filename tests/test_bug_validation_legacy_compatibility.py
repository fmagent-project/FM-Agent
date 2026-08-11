import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import src.entry_reasoning_pipeline as entry_pipeline
import src.incremental_reasoner as incremental
import src.verification as verification
from src.file_utils import (
    _get_incomplete_verification_files,
    _terminal_validation_record_is_valid,
)


_GAP_FIELDS = {
    "spec_claim": "the proposed contract",
    "actual_behavior": "the observed behavior",
    "code_evidence": "the relevant branch",
    "trigger_condition": "a supported input",
}


def _write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value), encoding="utf-8")


def _terminal_record(bug_id: str, status: str = "confirmed") -> dict:
    return {
        "id": bug_id,
        "source_file": "pkg/target.py",
        "function_name": "target",
        "confirmation_status": status,
        "attempts": 1,
        "probe_script": "probe.py",
        "detail_file": "detail.md",
        "probe_stdout": "observed",
        "trigger_summary": "supported input",
    }


def _write_all_bugs_reasoning(results_dir: Path, bug_count: int = 2) -> str:
    rel = "pkg/target.py"
    primary = results_dir / "pkg" / "target.json"
    _write_json(
        primary,
        {
            "function": "pkg/target.py",
            "verdict": "MISMATCH",
            "all_bugs": True,
            "reasoning_complete": True,
            "bug_count": bug_count,
        },
    )
    for index in range(1, bug_count + 1):
        _write_json(
            results_dir / "pkg" / f"target.bug-{index:03d}.json",
            {
                "function": "pkg/target.py",
                "verdict": "MISMATCH",
                "gaps": dict(_GAP_FIELDS),
            },
        )
    return rel


class PrivateMainLegacyValidationTests(unittest.TestCase):
    def test_default_resume_accepts_any_parseable_legacy_result(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            work = root / "fm_agent"
            results = work / "logic_verification_results"
            rel = "pkg/target.py"
            _write_json(results / "pkg" / "target.json", {"verdict": "MISMATCH"})
            validation = work / "bug_validation" / "pkg--target.result.json"
            _write_json(validation, {"legacy": "parseable but unverified"})

            complete = _get_incomplete_verification_files(
                [rel],
                str(work / "extracted_functions"),
                str(results),
                str(work),
            )
            self.assertEqual(complete, [])

            validation.write_text("{broken", encoding="utf-8")
            incomplete = _get_incomplete_verification_files(
                [rel],
                str(work / "extracted_functions"),
                str(results),
                str(work),
            )
            self.assertEqual(incomplete, [rel])

    def test_all_bugs_resume_requires_every_candidate_terminal(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            work = root / "fm_agent"
            results = work / "logic_verification_results"
            rel = _write_all_bugs_reasoning(results)
            validations = work / "bug_validation"
            _write_json(
                validations / "pkg--target.bug-001.result.json",
                _terminal_record("pkg--target.bug-001", "confirmed"),
            )

            incomplete = _get_incomplete_verification_files(
                [rel],
                str(work / "extracted_functions"),
                str(results),
                str(work),
                all_bugs=True,
            )
            self.assertEqual(incomplete, [rel])

            _write_json(
                validations / "pkg--target.bug-002.result.json",
                _terminal_record("pkg--target.bug-002", "error"),
            )
            complete = _get_incomplete_verification_files(
                [rel],
                str(work / "extracted_functions"),
                str(results),
                str(work),
                all_bugs=True,
            )
            self.assertEqual(complete, [])

            wrong_identity = _terminal_record("wrong", "not_confirmed")
            _write_json(
                validations / "pkg--target.bug-002.result.json",
                wrong_identity,
            )
            incomplete = _get_incomplete_verification_files(
                [rel],
                str(work / "extracted_functions"),
                str(results),
                str(work),
                all_bugs=True,
            )
            self.assertEqual(incomplete, [rel])

    def test_all_bugs_terminal_schema_keeps_three_legacy_statuses(self):
        for status in ("confirmed", "not_confirmed", "error"):
            with self.subTest(status=status):
                self.assertTrue(
                    _terminal_validation_record_is_valid(
                        _terminal_record("bug-001", status),
                        "bug-001",
                    )
                )

        bool_attempt = _terminal_record("bug-001")
        bool_attempt["attempts"] = True
        self.assertFalse(
            _terminal_validation_record_is_valid(bool_attempt, "bug-001")
        )
        self.assertFalse(
            _terminal_validation_record_is_valid(
                _terminal_record("other"),
                "bug-001",
            )
        )

    def test_all_bugs_summary_marks_missing_pending_and_ignores_orphans(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            work = Path(temp_dir) / "fm_agent"
            results = work / "logic_verification_results"
            _write_all_bugs_reasoning(results)
            validations = work / "bug_validation"
            _write_json(
                validations / "pkg--target.bug-001.result.json",
                _terminal_record("pkg--target.bug-001", "confirmed"),
            )
            _write_json(
                validations / "stale--orphan.result.json",
                _terminal_record("stale--orphan", "confirmed"),
            )

            with patch.object(
                verification.config, "BUG_VALIDATION_MAX_RETRIES", 1
            ):
                verification._generate_all_bugs_validation_summary(str(work))

            summary = json.loads(
                (validations / "summary.json").read_text(encoding="utf-8")
            )
            self.assertEqual(summary["total_reported"], 2)
            self.assertEqual(summary["total_confirmed"], 1)
            self.assertEqual(summary["total_pending"], 1)
            self.assertEqual(
                {record["id"] for record in summary["bugs"]},
                {"pkg--target.bug-001", "pkg--target.bug-002"},
            )
            pending = next(
                record
                for record in summary["bugs"]
                if record["confirmation_status"] == "pending"
            )
            self.assertEqual(pending["validation_error"], "missing_or_invalid_result")

    def test_candidate_keeps_distinct_bug_and_function_identities(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            project = Path(temp_dir)
            work = project / "fm_agent"
            custom = project / "validator.md"
            custom.write_text("CUSTOM CANDIDATE VALIDATOR", encoding="utf-8")
            captured = {}

            def build_command(**kwargs):
                prompt_path = Path(kwargs["files"][0])
                captured["prompt"] = prompt_path.read_text(encoding="utf-8")
                return ["opencode"]

            def run_validation(**kwargs):
                captured["function_ids"] = kwargs["function_ids"]
                result_path = (
                    work
                    / "bug_validation"
                    / "pkg--target.bug-001.result.json"
                )
                _write_json(
                    result_path,
                    _terminal_record("pkg--target.bug-001", "not_confirmed"),
                )

            with (
                patch.object(
                    verification,
                    "build_llm_cli_command",
                    side_effect=build_command,
                ),
                patch.object(
                    verification,
                    "run_opencode_traced",
                    side_effect=run_validation,
                ),
                patch.object(
                    verification.config, "BUG_VALIDATION_MAX_RETRIES", 1
                ),
            ):
                verification._validate_single_bug(
                    "fm_agent/logic_verification_results/pkg/target.bug-001.json",
                    str(project),
                    str(work),
                    bug_validator_path=str(custom),
                )

            self.assertEqual(captured["function_ids"], ["pkg::target"])
            self.assertIn("CUSTOM CANDIDATE VALIDATOR", captured["prompt"])
            self.assertIn("Mandatory FM-Agent Candidate Result Contract", captured["prompt"])
            self.assertIn("pkg--target.bug-001", captured["prompt"])
            self.assertNotIn("operating in **single-file mode**", captured["prompt"])

    def test_incremental_validation_forwards_custom_validator_and_result_shape(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            project = Path(temp_dir)
            work = project / "fm_agent"
            extracted = work / "extracted_functions" / "module" / "func.py"
            extracted.parent.mkdir(parents=True)
            extracted.write_text("def func():\n    return 1\n", encoding="utf-8")
            calls = []

            def validate(result_rel, proj_dir, work_dir, *, bug_validator_path=None):
                calls.append((result_rel, proj_dir, work_dir, bug_validator_path))
                _write_json(
                    work / "bug_validation" / "module--func.result.json",
                    {"confirmation_status": "confirmed"},
                )

            with (
                patch.object(
                    incremental,
                    "_verify_single_file",
                    return_value=(str(extracted), "MISMATCH"),
                ),
                patch.object(
                    incremental,
                    "_validate_single_bug",
                    side_effect=validate,
                ),
                patch.object(incremental, "MAX_WORKERS", 1),
            ):
                result = incremental._verify_incremental_functions(
                    str(project),
                    str(work),
                    {},
                    ["module/func.py"],
                    bug_validator_path="custom-validator.md",
                )

            self.assertEqual(result, ["module/func.py"])
            self.assertEqual(len(calls), 1)
            self.assertEqual(
                calls[0][0].replace(os.sep, "/"),
                "fm_agent/logic_verification_results/module/func.json",
            )
            self.assertEqual(calls[0][3], "custom-validator.md")

    def test_entry_mode_disables_validation_but_preserves_reporting_options(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            captured = {}

            def run_inner(*args, **kwargs):
                captured["retries"] = entry_pipeline.config.BUG_VALIDATION_MAX_RETRIES
                captured["bug_validator_path"] = kwargs["bug_validator_path"]
                captured["all_bugs"] = kwargs["all_bugs"]

            with (
                patch.object(
                    entry_pipeline,
                    "_run_entry_pipeline_inner",
                    side_effect=run_inner,
                ),
                patch.object(
                    entry_pipeline.config, "BUG_VALIDATION_MAX_RETRIES", 3
                ),
            ):
                entry_pipeline.run_entry_pipeline(
                    temp_dir,
                    entry_func="main-py::main",
                    bug_validator_path="custom-validator.md",
                    all_bugs=True,
                )

            self.assertEqual(captured["retries"], 0)
            self.assertEqual(captured["bug_validator_path"], "custom-validator.md")
            self.assertTrue(captured["all_bugs"])


if __name__ == "__main__":
    unittest.main()

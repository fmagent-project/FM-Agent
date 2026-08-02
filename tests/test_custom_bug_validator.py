import inspect
import json
import os
import contextlib
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import main
from main import _resolve_bug_validator_path
from src.incremental_reasoner import (
    _verify_incremental_functions,
    run_incremental_pipeline,
)
from src.verification import _validate_single_bug, streaming_reasoner


class CustomBugValidatorPromptTests(unittest.TestCase):
    def _capture_prompt(self, custom_content=None, with_knowledge=False):
        with tempfile.TemporaryDirectory() as temp_dir:
            proj_dir = Path(temp_dir)
            work_dir = proj_dir / "fm_agent"
            result_rel = "fm_agent/logic_verification_results/sample.json"
            result_path = proj_dir / result_rel
            result_path.parent.mkdir(parents=True, exist_ok=True)
            result_path.write_text("{}", encoding="utf-8")

            if with_knowledge:
                knowledge_dir = (
                    work_dir
                    / "spec_prompts"
                    / "domain_context"
                    / "user_knowledge"
                )
                knowledge_dir.mkdir(parents=True, exist_ok=True)
                (knowledge_dir / "rules.md").write_text(
                    "project-specific rules", encoding="utf-8"
                )

            validator_path = None
            if custom_content is not None:
                validator_path = proj_dir / "custom_bug_validator.md"
                validator_path.write_text(custom_content, encoding="utf-8")

            captured = {}

            def build_command(**kwargs):
                prompt_path = Path(kwargs["files"][0])
                captured["content"] = prompt_path.read_text(encoding="utf-8")
                return ["opencode"]

            def run_validation(**_kwargs):
                result_file = work_dir / "bug_validation" / "sample.result.json"
                result_file.write_text(
                    json.dumps({"confirmation_status": "not_confirmed"}),
                    encoding="utf-8",
                )

            with (
                patch("src.verification.build_llm_cli_command", side_effect=build_command),
                patch("src.verification.run_opencode_traced", side_effect=run_validation),
                patch("src.verification.config.BUG_VALIDATION_MAX_RETRIES", 1),
            ):
                _validate_single_bug(
                    result_rel,
                    str(proj_dir),
                    str(work_dir),
                    bug_validator_path=(
                        str(validator_path) if validator_path is not None else None
                    ),
                )

            return captured["content"]

    def test_custom_validator_replaces_builtin_content(self):
        marker = "CUSTOM VALIDATOR INSTRUCTIONS"

        prompt = self._capture_prompt(marker, with_knowledge=True)

        self.assertIn(marker, prompt)
        self.assertNotIn("operating in **single-file mode**", prompt)
        self.assertIn("**Bug ID:** `sample`", prompt)
        self.assertIn(
            "fm_agent/spec_prompts/domain_context/user_knowledge/rules.md",
            prompt,
        )

    def test_default_validator_is_used_when_custom_path_is_absent(self):
        prompt = self._capture_prompt()

        self.assertIn("operating in **single-file mode**", prompt)

    def test_parameter_is_exposed_across_pipeline_layers(self):
        functions = [
            main.run_pipeline,
            streaming_reasoner,
            _validate_single_bug,
            run_incremental_pipeline,
            _verify_incremental_functions,
        ]

        for function in functions:
            with self.subTest(function=function.__name__):
                parameter = inspect.signature(function).parameters[
                    "bug_validator_path"
                ]
                self.assertIsNone(parameter.default)

    def test_cli_rejects_missing_validator_file(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            missing = Path(temp_dir) / "missing.md"
            result = subprocess.run(
                [
                    sys.executable,
                    str(Path(main.__file__).resolve()),
                    temp_dir,
                    "--bug-validator",
                    str(missing),
                ],
                cwd=temp_dir,
                capture_output=True,
                text=True,
                env=os.environ.copy(),
            )

        self.assertEqual(result.returncode, 2)
        self.assertIn("--bug-validator must point to a file", result.stderr)

    def test_cli_accepts_launch_relative_validator(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            proj_dir = root / "project"
            caller_dir = root / "caller"
            validator = caller_dir / "prompts" / "validator.md"
            validator.parent.mkdir(parents=True)
            (proj_dir / "src").mkdir(parents=True)
            validator.write_text("launch validator", encoding="utf-8")

            result = subprocess.run(
                [
                    sys.executable,
                    str(Path(main.__file__).resolve()),
                    str(proj_dir),
                    "--bug-validator",
                    "prompts/validator.md",
                    "--submodule",
                    "src",
                    "--entry-func",
                    "main-py::fake",
                ],
                cwd=caller_dir,
                capture_output=True,
                text=True,
                env=os.environ.copy(),
            )

        self.assertEqual(result.returncode, 2)
        self.assertNotIn(
            "--bug-validator must point to a file",
            result.stderr,
        )
        self.assertIn(
            "--submodule cannot be combined with --entry-func",
            result.stderr,
        )

    def test_relative_validator_uses_launch_directory(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            proj_dir = root / "project"
            cwd = root / "caller"
            project_validator = proj_dir / "prompts" / "validator.md"
            cwd_validator = cwd / "prompts" / "validator.md"

            project_validator.parent.mkdir(parents=True)
            cwd_validator.parent.mkdir(parents=True)
            project_validator.write_text("project", encoding="utf-8")
            cwd_validator.write_text("cwd", encoding="utf-8")

            with contextlib.chdir(cwd):
                resolved = _resolve_bug_validator_path(
                    "prompts/validator.md"
                )

            self.assertEqual(resolved, str(cwd_validator.resolve()))

    def test_relative_validator_does_not_use_project_directory(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            proj_dir = root / "project"
            cwd = root / "caller"
            project_validator = proj_dir / "prompts" / "validator.md"

            project_validator.parent.mkdir(parents=True)
            cwd.mkdir()
            project_validator.write_text("project", encoding="utf-8")

            with contextlib.chdir(cwd):
                with self.assertRaisesRegex(
                    ValueError,
                    "--bug-validator must point to a file",
                ):
                    _resolve_bug_validator_path(
                        "prompts/validator.md"
                    )

    def test_absolute_validator_path_is_unchanged(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            validator = Path(temp_dir) / "validator.md"
            validator.write_text("absolute", encoding="utf-8")

            resolved = _resolve_bug_validator_path(str(validator))

            self.assertEqual(resolved, str(validator.resolve()))

    def test_missing_relative_validator_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)

            with self.assertRaisesRegex(
                ValueError,
                "--bug-validator must point to a file",
            ):
                _resolve_bug_validator_path(
                    str(root / "prompts" / "missing.md")
                )


if __name__ == "__main__":
    unittest.main()

from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import main
from src.generate_batch_prompts import build_prompt, callee_expectation
from src.spec_storage import metadata_paths, write_info, write_spec


class StructuredBatchPromptTests(unittest.TestCase):
    def setUp(self):
        self.tmp = TemporaryDirectory()
        self.work_dir = Path(self.tmp.name) / "fm_agent"
        function_dir = (
            self.work_dir / "extracted_functions" / "src" / "module-py"
        )
        function_dir.mkdir(parents=True)
        self.caller_path = function_dir / "caller.py"
        self.callee_path = function_dir / "callee.py"
        self.caller_path.write_text(
            "def caller():\n    return callee()\n",
            encoding="utf-8",
        )
        self.callee_path.write_text(
            "def callee():\n    return 1\n",
            encoding="utf-8",
        )
        write_spec(
            self.caller_path,
            {
                "schema_version": 1,
                "function": "src::module-py::caller",
                "unit": "src/module.py",
                "signature": "caller() -> int",
                "preconditions": [],
                "postconditions": ["returns the callee result"],
            },
        )
        write_info(
            self.caller_path,
            {
                "schema_version": 1,
                "function": "src::module-py::caller",
                "callees": [
                    {
                        "function": "src::module-py::callee",
                        "signature": "callee() -> int",
                        "preconditions": [],
                        "postconditions": ["returns a positive integer"],
                    }
                ],
            },
        )
        self.caller = {
            "name": "src::module-py::caller",
            "file": "extracted_functions/src/module-py/caller.py",
            "phase1_callers": [],
        }
        self.callee = {
            "name": "src::module-py::callee",
            "file": "extracted_functions/src/module-py/callee.py",
            "phase1_callers": ["src::module-py::caller"],
        }

    def tearDown(self):
        self.tmp.cleanup()

    def test_callee_expectation_matches_full_fqn_only(self):
        info = {
            "callees": [
                {
                    "function": "src::one::parse",
                    "signature": "parse() -> int",
                    "preconditions": [],
                    "postconditions": ["returns one"],
                },
                {
                    "function": "src::two::parse",
                    "signature": "parse() -> int",
                    "preconditions": [],
                    "postconditions": ["returns two"],
                },
            ]
        }

        matched = callee_expectation(info, "src::two::parse")

        self.assertEqual(matched["postconditions"], ["returns two"])
        self.assertIsNone(callee_expectation(info, "parse"))

    def test_prompt_writes_two_json_files_and_preserves_implementation(self):
        prompt = build_prompt(
            phase=1,
            layer_idx=1,
            is_cycle=False,
            functions=[self.callee],
            func_to_layer={
                "src::module-py::caller": 0,
                "src::module-py::callee": 1,
            },
            all_funcs={
                "src::module-py::caller": self.caller,
                "src::module-py::callee": self.callee,
            },
            work_dir=self.work_dir,
            fm_agent_prefix="fm_agent/",
            ext_to_lang={"py": "python"},
        )

        self.assertIn("callee.spec.json", prompt)
        self.assertIn("callee.info.json", prompt)
        self.assertIn("returns the callee result", prompt)
        self.assertIn("returns a positive integer", prompt)
        self.assertIn("src::module-py::callee", prompt)
        self.assertIn("implementation file is immutable", prompt.lower())
        self.assertNotIn("prepend", prompt.lower())
        self.assertNotIn("overwriting the original", prompt.lower())
        self.assertNotIn("save the complete file", prompt.lower())


class BatchIntegrityTests(unittest.TestCase):
    def setUp(self):
        self.tmp = TemporaryDirectory()
        self.project = Path(self.tmp.name)
        self.work_dir = self.project / "fm_agent"
        self.function = (
            self.work_dir
            / "extracted_functions"
            / "src"
            / "module-py"
            / "load_data.py"
        )
        self.function.parent.mkdir(parents=True)
        self.original = b"def load_data():\n    return 1\n"
        self.function.write_bytes(self.original)
        (self.work_dir / "workflow_spec_step4_batch.md").write_text(
            "structured workflow\n",
            encoding="utf-8",
        )
        self.function_rel = self.function.relative_to(self.project).as_posix()
        self.batch = {
            "file": "batch_000_layer0_extracted_b0.txt",
            "functions": [self.function_rel],
        }

    def tearDown(self):
        self.tmp.cleanup()

    def _write_generated_metadata(self):
        write_spec(
            self.function,
            {
                "schema_version": 1,
                "function": "src::module-py::load_data",
                "unit": "src/module.py",
                "signature": "load_data() -> int",
                "preconditions": [],
                "postconditions": ["returns one"],
            },
        )
        write_info(
            self.function,
            {
                "schema_version": 1,
                "function": "src::module-py::load_data",
                "callees": [],
            },
        )

    def test_batch_restores_modified_implementation_and_rejects_outputs(self):
        def fake_run(**kwargs):
            self.function.write_text(
                "# generated header\ndef load_data():\n    return 1\n",
                encoding="utf-8",
            )
            self._write_generated_metadata()
            return SimpleNamespace(returncode=0)

        with (
            patch.object(main, "is_cli_backend_enabled", return_value=False),
            patch.object(main, "run_opencode_traced", side_effect=fake_run),
        ):
            return_code = main._run_spec_generation_batch(
                str(self.project),
                str(self.work_dir),
                1,
                1,
                0,
                "fm_agent/spec_prompts/batches",
                self.batch,
            )

        self.assertEqual(return_code, 1)
        self.assertEqual(self.function.read_bytes(), self.original)
        for metadata_path in metadata_paths(self.function):
            self.assertFalse(metadata_path.exists())

    def test_trace_declares_metadata_as_outputs(self):
        captured = {}

        def fake_run(**kwargs):
            captured.update(kwargs)
            self._write_generated_metadata()
            return SimpleNamespace(returncode=0)

        with (
            patch.object(main, "is_cli_backend_enabled", return_value=False),
            patch.object(main, "run_opencode_traced", side_effect=fake_run),
        ):
            return_code = main._run_spec_generation_batch(
                str(self.project),
                str(self.work_dir),
                1,
                1,
                0,
                "fm_agent/spec_prompts/batches",
                self.batch,
            )

        spec_path, info_path = metadata_paths(Path(self.function_rel))
        self.assertEqual(return_code, 0)
        self.assertEqual(
            captured["output_files"],
            [spec_path.as_posix(), info_path.as_posix()],
        )
        self.assertIn(self.function_rel, captured["input_files"])


if __name__ == "__main__":
    unittest.main()

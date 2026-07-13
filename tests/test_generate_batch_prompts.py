from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from src.generate_batch_prompts import build_prompt, callee_expectation
from src.spec_storage import write_info, write_spec


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


if __name__ == "__main__":
    unittest.main()

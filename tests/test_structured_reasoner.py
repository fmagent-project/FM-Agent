import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from src.prompts import _knowledge_text
from src.reasoner import reasoner
from src.verification import _verify_single_file


class StructuredReasonerTests(unittest.TestCase):
    def setUp(self):
        self.spec = {
            "schema_version": 1,
            "function": "module-py::calculate",
            "unit": "module.py",
            "signature": "calculate(value) -> int",
            "preconditions": [
                "value is an integer",
                "value is non-negative",
            ],
            "postconditions": [
                "returns an integer",
                "the result is non-negative",
            ],
        }
        self.info = {
            "schema_version": 1,
            "function": "module-py::calculate",
            "callees": [],
        }

    @patch("src.reasoner._check_post_implies_spec")
    @patch("src.reasoner._generate_block_post_condition")
    def test_reasoner_passes_deterministic_condition_text_and_structured_info(
        self, generate_post, check_spec
    ):
        generate_post.return_value = "- returns value + 1"
        check_spec.return_value = (True, None, None, None)

        result = reasoner(
            "Line 1: return value + 1",
            self.spec,
            self.info,
            "python",
        )

        self.assertIn("passes the verification", result)
        generate_args = generate_post.call_args.args
        self.assertEqual(
            generate_args[1],
            "- value is an integer\n- value is non-negative",
        )
        self.assertIs(generate_args[2], self.info)
        check_args = check_spec.call_args.args
        self.assertEqual(
            check_args[2],
            "- returns an integer\n- the result is non-negative",
        )
        self.assertIs(check_args[3], self.info)

    @patch("src.reasoner._check_post_implies_spec")
    @patch("src.reasoner._generate_block_post_condition")
    def test_reasoner_accepts_empty_preconditions(
        self, generate_post, check_spec
    ):
        self.spec["preconditions"] = []
        generate_post.return_value = "- returns zero"
        check_spec.return_value = (True, None, None, None)

        result = reasoner(
            "Line 1: return 0",
            self.spec,
            self.info,
            "python",
        )

        self.assertIn("passes the verification", result)
        self.assertEqual(generate_post.call_args.args[1], "- (none)")

    def test_knowledge_text_is_deterministic_json(self):
        info = {
            "schema_version": 1,
            "function": "module-py::calculate",
            "callees": [
                {
                    "function": "module-py::helper",
                    "signature": "helper() -> int",
                    "preconditions": [],
                    "postconditions": ["返回一"],
                }
            ],
        }

        rendered = _knowledge_text(info)

        self.assertEqual(
            rendered,
            json.dumps(info, indent=2, ensure_ascii=False, sort_keys=True),
        )
        self.assertEqual(_knowledge_text({"callees": []}), "")

    @patch("src.verification.load_staged_domain_knowledge_text")
    @patch("src.verification.reasoner")
    @patch("src.verification.parse_input_function")
    def test_verification_keeps_domain_knowledge_structured_and_in_memory(
        self, parse_input, run_reasoner, load_domain
    ):
        parse_input.return_value = (
            "Line 1: return 1",
            self.spec,
            self.info,
        )
        run_reasoner.return_value = "The function passes the verification."
        load_domain.return_value = "The result is measured in widgets."

        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            input_dir = root / "extracted_functions"
            output_dir = root / "results"
            function = input_dir / "calculate.py"
            function.parent.mkdir(parents=True)
            function.write_text("return 1\n", encoding="utf-8")

            _, verdict = _verify_single_file(
                str(function),
                str(input_dir),
                str(output_dir),
                "python",
                work_dir=str(root),
            )

        self.assertEqual(verdict, "MATCH")
        passed_info = run_reasoner.call_args.args[2]
        self.assertEqual(passed_info["callees"], [])
        self.assertEqual(
            passed_info["domain_knowledge"],
            "The result is measured in widgets.",
        )
        self.assertNotIn("domain_knowledge", self.info)


if __name__ == "__main__":
    unittest.main()

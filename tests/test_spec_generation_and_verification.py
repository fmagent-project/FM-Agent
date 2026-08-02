import json
import os
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from src.generate_batch_prompts import build_prompt
from src.spec_generation_and_verification import (
    _get_pending_batches,
    _run_spec_generation_batch,
)


class SpecGenerationRetryTests(unittest.TestCase):
    def test_batch_prompt_preserves_function_extension_in_sidecar_names(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            prompt = build_prompt(
                phase=1,
                layer_idx=0,
                is_cycle=False,
                functions=[{"file": "function.py", "name": "function"}],
                func_to_layer={"function": 0},
                all_funcs={"function": {"file": "function.py"}},
                work_dir=Path(temp_dir),
                fm_agent_prefix="fm_agent/",
                ext_to_lang={"py": "python"},
            )

        self.assertIn("`foo.py.spec.json`", prompt)
        self.assertIn("`foo.py.info.json`", prompt)

    def _capture_prompt(self, attempt):
        with tempfile.TemporaryDirectory() as temp_dir:
            with (
                patch(
                    "src.spec_generation_and_verification.build_llm_cli_command",
                    return_value=["opencode"],
                ) as build_command,
                patch(
                    "src.spec_generation_and_verification.run_opencode_traced",
                    return_value=SimpleNamespace(returncode=0),
                ),
                patch(
                    "src.spec_generation_and_verification."
                    "list_staged_domain_knowledge_relpaths",
                    return_value=[],
                ),
            ):
                result = _run_spec_generation_batch(
                    temp_dir,
                    temp_dir,
                    attempt,
                    1,
                    0,
                    "fm_agent/spec_prompts/batches",
                    {"file": "batch.txt", "functions": ["function.py"]},
                )
        self.assertEqual(result, 0)
        return build_command.call_args.kwargs["prompt"]

    def test_retry_prompt_requires_valid_sidecars(self):
        prompt = self._capture_prompt(attempt=2)

        self.assertIn("Skip it only when both", prompt)
        self.assertIn("valid JSON", prompt)
        self.assertIn("missing, malformed, or schema-invalid", prompt)
        self.assertIn(
            "rewrite the complete .spec.json and .info.json files", prompt
        )
        self.assertNotIn(
            "do not have both .spec.json and .info.json files yet", prompt
        )

    def test_first_attempt_prompt_is_unchanged(self):
        prompt = self._capture_prompt(attempt=1)

        self.assertIn("generate behavioral specs for each function listed", prompt)
        self.assertIn(
            "write the .spec.json and .info.json files for each function", prompt
        )
        self.assertNotIn("Skip it only when both", prompt)


class PendingBatchTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.project_dir = Path(self.temp_dir.name)
        self.function_path = self.project_dir / "function.py"
        self.function_path.write_text("def function():\n    pass\n", encoding="utf-8")
        self.batch = {
            "file": "batch.txt",
            "functions": [os.fspath(self.function_path.relative_to(self.project_dir))],
        }

    def tearDown(self):
        self.temp_dir.cleanup()

    def _write_sidecars(self, spec, info):
        Path(f"{self.function_path}.spec.json").write_text(
            spec if isinstance(spec, str) else json.dumps(spec), encoding="utf-8"
        )
        Path(f"{self.function_path}.info.json").write_text(
            info if isinstance(info, str) else json.dumps(info), encoding="utf-8"
        )

    def test_valid_sidecars_are_not_pending(self):
        self._write_sidecars(
            {
                "signature": "function()",
                "pre_condition": "true",
                "post_condition": "returns normally",
            },
            {"callees": []},
        )

        self.assertEqual(_get_pending_batches([self.batch], self.project_dir), [])

    def test_malformed_sidecars_remain_pending(self):
        self._write_sidecars("{malformed", {"callees": []})

        self.assertEqual(
            _get_pending_batches([self.batch], self.project_dir), [self.batch]
        )

    def test_schema_invalid_sidecars_remain_pending(self):
        self._write_sidecars(
            {"unit": "function.py"},
            {"callees": []},
        )

        self.assertEqual(
            _get_pending_batches([self.batch], self.project_dir), [self.batch]
        )


if __name__ == "__main__":
    unittest.main()

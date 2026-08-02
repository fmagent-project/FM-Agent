import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from src.pipeline_setup import (
    _deduplicate_phases,
    _phase_plan_complete,
    _phase_plan_schema_errors,
    _run_generate_phases,
)


class PhasePlanSchemaTests(unittest.TestCase):
    def _write_phases(self, work_dir, phases):
        work_dir.mkdir(parents=True, exist_ok=True)
        (work_dir / "phases.json").write_text(
            json.dumps({"phases": phases}), encoding="utf-8"
        )

    def _valid_phases(self):
        return [
            {
                "phase": 1,
                "name": "phase",
                "modules": [
                    {
                        "name": "module",
                        "description": "valid module",
                        "source_files": ["src/main.py"],
                    }
                ],
            }
        ]

    def test_valid_phase_plan_is_complete(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            work_dir = Path(temp_dir)
            self._write_phases(work_dir, self._valid_phases())

            self.assertEqual(
                _phase_plan_schema_errors(work_dir / "phases.json"), []
            )
            self.assertTrue(_phase_plan_complete(work_dir))

    def test_invalid_source_files_schema_reports_actionable_errors(self):
        invalid_values = [
            ({"name": "missing"}, "source_files is missing"),
            ({"name": "null", "source_files": None}, "must be an array"),
            ({"name": "string", "source_files": "src/main.py"}, "must be an array"),
            ({"name": "object", "source_files": {"path": "src/main.py"}}, "must be an array"),
            ({"name": "item", "source_files": [123]}, "source_files[0] must be a string"),
        ]

        for module, expected_error in invalid_values:
            with self.subTest(module=module["name"]):
                with tempfile.TemporaryDirectory() as temp_dir:
                    work_dir = Path(temp_dir)
                    self._write_phases(
                        work_dir,
                        [{"phase": 1, "name": "phase", "modules": [module]}],
                    )

                    errors = _phase_plan_schema_errors(work_dir / "phases.json")

                    self.assertTrue(any(expected_error in error for error in errors))
                    self.assertFalse(_phase_plan_complete(work_dir))

    def test_deduplicate_phases_preserves_valid_behavior(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            work_dir = Path(temp_dir)
            phases = self._valid_phases()
            phases[0]["modules"].append(
                {
                    "name": "duplicate",
                    "source_files": ["src/main.py", "src/other.py"],
                }
            )
            self._write_phases(work_dir, phases)

            _deduplicate_phases(work_dir)

            data = json.loads(
                (work_dir / "phases.json").read_text(encoding="utf-8")
            )
            self.assertEqual(
                data["phases"][0]["modules"][1]["source_files"],
                ["src/other.py"],
            )


class PhasePlanRepairTests(unittest.TestCase):
    script_dir = Path(__file__).resolve().parents[1]

    def _write_plan(self, work_dir, modules):
        work_dir.mkdir(parents=True, exist_ok=True)
        (work_dir / "phases.json").write_text(
            json.dumps(
                {
                    "phases": [
                        {"phase": 1, "name": "phase", "modules": modules}
                    ]
                }
            ),
            encoding="utf-8",
        )

    def _valid_module(self):
        return {"name": "module", "source_files": ["src/main.py"]}

    @patch("src.pipeline_setup.time.sleep")
    @patch("src.pipeline_setup.build_llm_cli_command", return_value=["opencode"])
    @patch("src.pipeline_setup.run_opencode_traced")
    def test_resume_generates_phase_plan_when_file_is_missing(
        self, run_opencode, build_command, _sleep
    ):
        with tempfile.TemporaryDirectory() as temp_dir:
            proj_dir = Path(temp_dir)
            work_dir = proj_dir / "fm_agent"
            work_dir.mkdir(parents=True, exist_ok=True)

            run_opencode.side_effect = lambda **_kwargs: self._write_plan(
                work_dir, [self._valid_module()]
            )

            _run_generate_phases(
                str(proj_dir),
                str(work_dir),
                str(self.script_dir),
                resume=True,
            )

            run_opencode.assert_called_once()
            self.assertNotIn(
                "does not match the required schema",
                build_command.call_args.kwargs["prompt"],
            )
            self.assertTrue(_phase_plan_complete(work_dir))

    @patch("src.pipeline_setup.time.sleep")
    @patch("src.pipeline_setup.build_llm_cli_command", return_value=["opencode"])
    @patch("src.pipeline_setup.run_opencode_traced")
    def test_agent_retries_and_repairs_invalid_phase_plan(
        self, run_opencode, build_command, _sleep
    ):
        with tempfile.TemporaryDirectory() as temp_dir:
            proj_dir = Path(temp_dir)
            work_dir = proj_dir / "fm_agent"
            work_dir.mkdir(parents=True, exist_ok=True)

            def generate_plan(**_kwargs):
                if run_opencode.call_count == 1:
                    self._write_plan(work_dir, [{"name": "module"}])
                else:
                    self._write_plan(work_dir, [self._valid_module()])

            run_opencode.side_effect = generate_plan

            _run_generate_phases(
                str(proj_dir), str(work_dir), str(self.script_dir)
            )

            self.assertEqual(run_opencode.call_count, 2)
            retry_prompt = build_command.call_args_list[1].kwargs["prompt"]
            self.assertIn("source_files is missing", retry_prompt)
            self.assertTrue(_phase_plan_complete(work_dir))

    @patch("src.pipeline_setup.time.sleep")
    @patch("src.pipeline_setup.build_llm_cli_command", return_value=["opencode"])
    @patch("src.pipeline_setup.run_opencode_traced")
    def test_resume_repairs_invalid_plan_instead_of_skipping(
        self, run_opencode, build_command, _sleep
    ):
        with tempfile.TemporaryDirectory() as temp_dir:
            proj_dir = Path(temp_dir)
            work_dir = proj_dir / "fm_agent"
            self._write_plan(work_dir, [{"name": "module"}])

            run_opencode.side_effect = lambda **_kwargs: self._write_plan(
                work_dir, [self._valid_module()]
            )

            _run_generate_phases(
                str(proj_dir),
                str(work_dir),
                str(self.script_dir),
                resume=True,
            )

            run_opencode.assert_called_once()
            self.assertIn(
                "source_files is missing",
                build_command.call_args.kwargs["prompt"],
            )
            self.assertTrue(_phase_plan_complete(work_dir))

    @patch("src.pipeline_setup.OPENCODE_MAX_RETRIES", 2)
    @patch("src.pipeline_setup.time.sleep")
    @patch("src.pipeline_setup.build_llm_cli_command", return_value=["opencode"])
    @patch("src.pipeline_setup.run_opencode_traced")
    def test_invalid_plan_exits_after_retry_limit(
        self, run_opencode, _build_command, _sleep
    ):
        with tempfile.TemporaryDirectory() as temp_dir:
            proj_dir = Path(temp_dir)
            work_dir = proj_dir / "fm_agent"
            work_dir.mkdir(parents=True, exist_ok=True)
            run_opencode.side_effect = lambda **_kwargs: self._write_plan(
                work_dir, [{"name": "module", "source_files": "src/main.py"}]
            )

            with self.assertRaisesRegex(SystemExit, "1"):
                _run_generate_phases(
                    str(proj_dir), str(work_dir), str(self.script_dir)
                )

            self.assertEqual(run_opencode.call_count, 2)


if __name__ == "__main__":
    unittest.main()

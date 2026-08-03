import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from rich.console import Console

import main as main_module
from dashboard import State, _locate_workdir, render_preflight
from src.run_estimate import (
    ANALYSIS_STAGES,
    build_scope_inventory,
    estimate_from_history,
    read_history,
    record_completed_run,
    summarize_completed_run,
    write_preflight_estimate,
)


class ScopeInventoryTests(unittest.TestCase):
    def test_inventory_reports_included_excluded_files_dirs_and_functions(self):
        with tempfile.TemporaryDirectory() as tmp:
            project = Path(tmp)
            (project / "src").mkdir()
            (project / "tests").mkdir()
            (project / "examples").mkdir()
            (project / "node_modules").mkdir()
            (project / "app.py").write_text("def root():\n    return 1\n")
            (project / "src" / "worker.py").write_text(
                "def first():\n    return 1\n\n"
                "def second():\n    return 2\n"
            )
            (project / "tests" / "test_worker.py").write_text(
                "def test_worker():\n    assert True\n"
            )
            (project / "examples" / "demo.py").write_text(
                "def demo():\n    return 3\n"
            )
            (project / "node_modules" / "dependency.js").write_text(
                "function ignored() {}\n"
            )

            scope = build_scope_inventory(str(project), submodules=["src"])

            self.assertEqual(scope["included_files"], ["src/worker.py"])
            self.assertEqual(scope["included_directories"], ["src"])
            self.assertEqual(scope["included_file_count"], 1)
            self.assertEqual(scope["excluded_file_count"], 3)
            self.assertEqual(scope["function_count"], 2)
            reasons = {
                (item["path"], item["reason"])
                for item in scope["excluded_directories"]
            }
            self.assertIn(("node_modules", "scanner ignored directory"), reasons)
            self.assertIn((".", "outside selected submodule"), reasons)
            self.assertIn(("tests", "outside selected submodule"), reasons)

    def test_root_sources_do_not_hide_nested_included_directories(self):
        with tempfile.TemporaryDirectory() as tmp:
            project = Path(tmp)
            (project / "src").mkdir()
            (project / "app.py").write_text("def root():\n    pass\n")
            (project / "src" / "worker.py").write_text("def work():\n    pass\n")

            scope = build_scope_inventory(str(project))

            self.assertEqual(scope["included_directories"], [".", "src"])


class HistoricalEstimateTests(unittest.TestCase):
    def test_ranges_scale_completed_runs_by_function_count(self):
        scope = {"function_count": 20, "included_file_count": 4}
        samples = [
            {
                "function_count": 10,
                "included_file_count": 2,
                "duration_seconds": 100,
                "llm_calls": 10,
                "tokens": 1_000,
                "cost_usd": 1.0,
            },
            {
                "function_count": 20,
                "included_file_count": 4,
                "duration_seconds": 300,
                "llm_calls": 30,
                "tokens": 3_000,
                "cost_usd": 3.0,
            },
        ]

        estimate = estimate_from_history(scope, samples)

        self.assertEqual(estimate["based_on_runs"], 2)
        self.assertEqual(estimate["duration_seconds"], {"low": 180.0, "high": 330.0})
        self.assertEqual(estimate["llm_calls"], {"low": 18, "high": 33})
        self.assertEqual(estimate["tokens"], {"low": 1800, "high": 3300})
        self.assertEqual(estimate["cost_usd"], {"low": 1.8, "high": 3.3})

    def test_single_sample_has_explicit_uncertainty_band(self):
        estimate = estimate_from_history(
            {"function_count": 10},
            [
                {
                    "function_count": 10,
                    "duration_seconds": 100,
                    "llm_calls": 20,
                    "tokens": 1_000,
                    "cost_usd": 2,
                }
            ],
        )
        self.assertEqual(estimate["duration_seconds"], {"low": 75.0, "high": 125.0})
        self.assertEqual(estimate["llm_calls"], {"low": 15, "high": 25})


class RunHistoryTests(unittest.TestCase):
    def test_completed_trace_is_summarized_and_persisted(self):
        with tempfile.TemporaryDirectory() as tmp:
            work_dir = Path(tmp)
            trace_dir = work_dir / "trace"
            opencode_dir = trace_dir / "opencode"
            opencode_dir.mkdir(parents=True)
            (work_dir / "version.log").write_text("abc123\n")
            (work_dir / "estimate.json").write_text(
                json.dumps(
                    {
                        "scope": {
                            "included_file_count": 2,
                            "function_count": 4,
                        }
                    }
                )
            )
            events = [
                {
                    "type": "llm_call",
                    "start_time": "2026-01-01T00:00:00Z",
                    "end_time": "2026-01-01T00:00:10Z",
                    "metadata": {
                        "model": "test-model",
                        "usage": {"input_tokens": 100, "output_tokens": 20},
                    },
                },
                {
                    "type": "opencode_call",
                    "start_time": "2026-01-01T00:00:10Z",
                    "end_time": "2026-01-01T00:00:20Z",
                    "metadata": {},
                },
            ]
            (trace_dir / "events.jsonl").write_text(
                "".join(json.dumps(event) + "\n" for event in events)
            )
            records = [
                {
                    "_kind": "request",
                    "_id": "call-1",
                    "model": "test-model",
                },
                {
                    "_kind": "response",
                    "_id": "call-1",
                    "usage": {"input_tokens": 50, "output_tokens": 10},
                },
            ]
            (opencode_dir / "one.jsonl").write_text(
                "".join(json.dumps(record) + "\n" for record in records)
            )
            price = {
                "input_cost_per_token": 0.001,
                "output_cost_per_token": 0.002,
            }

            with patch.dict("src.run_estimate._MODEL_COST", {"test-model": price}):
                summary = summarize_completed_run(work_dir)
                persisted = record_completed_run(work_dir, duration_seconds=42)

            self.assertEqual(summary["included_file_count"], 2)
            self.assertEqual(summary["function_count"], 4)
            self.assertEqual(summary["duration_seconds"], 20)
            self.assertEqual(summary["llm_calls"], 2)
            self.assertEqual(summary["tokens"], 180)
            self.assertAlmostEqual(summary["cost_usd"], 0.21)
            self.assertEqual(persisted["run_id"], summary["run_id"])
            self.assertEqual(persisted["duration_seconds"], 42)
            self.assertEqual(len(read_history(work_dir)), 1)

    def test_incomplete_workspace_is_not_used_as_history(self):
        with tempfile.TemporaryDirectory() as tmp:
            work_dir = Path(tmp)
            (work_dir / "trace").mkdir()
            (work_dir / "trace" / "events.jsonl").write_text("")
            self.assertIsNone(summarize_completed_run(work_dir))


class DashboardEstimateTests(unittest.TestCase):
    def test_project_namesake_estimate_json_does_not_override_live_workdir(self):
        with tempfile.TemporaryDirectory() as tmp:
            project = Path(tmp)
            (project / "estimate.json").write_text(
                json.dumps({"duration_seconds": 30}),
                encoding="utf-8",
            )

            self.assertEqual(
                _locate_workdir(project),
                (project / "fm_agent").resolve(),
            )

    def test_preflight_manifest_identifies_direct_estimate_workspace(self):
        with tempfile.TemporaryDirectory() as tmp:
            project = Path(tmp) / "project"
            project.mkdir()
            (project / "app.py").write_text("def main():\n    return 0\n")
            work_dir = Path(tmp) / "saved-estimate"
            write_preflight_estimate(project, work_dir)

            self.assertEqual(_locate_workdir(work_dir), work_dir.resolve())

    def test_one_shot_manifest_renders_scope_stages_and_estimate_label(self):
        with tempfile.TemporaryDirectory() as tmp:
            project = Path(tmp) / "project"
            project.mkdir()
            (project / "src").mkdir()
            (project / "src" / "app.py").write_text("def main():\n    return 0\n")
            work_dir = project / "fm_agent_estimate"
            estimate = write_preflight_estimate(project, work_dir)
            estimate["estimate"] = {
                "label": "estimate",
                "based_on_runs": 2,
                "duration_seconds": {"low": 60, "high": 120},
                "llm_calls": {"low": 4, "high": 8},
                "tokens": {"low": 1_000, "high": 2_000},
                "cost_usd": {"low": 1.0, "high": 2.0},
            }
            (work_dir / "estimate.json").write_text(json.dumps(estimate))

            state = State(project, workdir=work_dir)
            console = Console(record=True, width=180)
            console.print(render_preflight(state))
            rendered = console.export_text()

            self.assertIn("Pre-run Scope & ESTIMATE", rendered)
            self.assertIn("included dirs", rendered)
            self.assertIn("excluded dirs", rendered)
            self.assertIn("functions", rendered)
            self.assertIn("analysis stages", rendered)
            self.assertIn("LLM calls", rendered)
            self.assertIn("2 completed historical run(s)", rendered)
            self.assertEqual(len(ANALYSIS_STAGES), 6)


class MainEstimateCliTests(unittest.TestCase):
    def test_estimate_mode_needs_neither_git_nor_llm_credentials(self):
        repository = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory() as tmp:
            project = Path(tmp)
            (project / "app.py").write_text("def main():\n    return 0\n")
            (project / "fm_agent").mkdir()
            (project / "fm_agent" / "history.jsonl").write_text(
                json.dumps(
                    {
                        "run_id": "previous",
                        "function_count": 1,
                        "included_file_count": 1,
                        "duration_seconds": 60,
                        "llm_calls": 4,
                        "tokens": 1_000,
                        "cost_usd": 1.0,
                    }
                )
                + "\n"
            )
            env = os.environ.copy()
            env.pop("LLM_API_KEY", None)

            result = subprocess.run(
                [sys.executable, str(repository / "main.py"), str(project), "--estimate"],
                cwd=repository,
                env=env,
                text=True,
                capture_output=True,
                timeout=30,
                check=False,
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("ESTIMATE — no LLM calls were made", result.stdout)
            self.assertIn("1 included source file(s)", result.stdout)
            self.assertIn("Historical samples: 1", result.stdout)
            self.assertIn("time (ESTIMATE): 45s – 1m 15s", result.stdout)
            self.assertIn("cost (ESTIMATE): $0.750 – $1.250", result.stdout)
            self.assertTrue((project / "fm_agent_estimate" / "estimate.json").is_file())


class NormalPipelinePreflightTests(unittest.TestCase):
    def test_fresh_run_preserves_history_and_writes_estimate_before_first_llm_stage(self):
        with tempfile.TemporaryDirectory() as tmp:
            project = Path(tmp)
            (project / "app.py").write_text("def main():\n    return 0\n")
            work_dir = project / "fm_agent"
            work_dir.mkdir()
            (work_dir / "stale.txt").write_text("old run")
            (work_dir / "history.jsonl").write_text(
                json.dumps(
                    {
                        "run_id": "previous",
                        "function_count": 1,
                        "included_file_count": 1,
                        "duration_seconds": 60,
                        "llm_calls": 4,
                        "tokens": 1_000,
                        "cost_usd": 1.0,
                    }
                )
                + "\n"
            )

            with patch.object(
                main_module,
                "_run_generate_phases",
                side_effect=RuntimeError("stop after preflight"),
            ):
                with self.assertRaisesRegex(RuntimeError, "stop after preflight"):
                    main_module.run_pipeline(str(project))

            estimate = json.loads((work_dir / "estimate.json").read_text())
            self.assertFalse((work_dir / "stale.txt").exists())
            self.assertTrue((work_dir / "history.jsonl").is_file())
            self.assertEqual(estimate["estimate"]["based_on_runs"], 1)
            self.assertEqual(estimate["scope"]["function_count"], 1)


if __name__ == "__main__":
    unittest.main()

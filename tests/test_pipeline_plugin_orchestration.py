import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import main
from src.plugin import PluginConfig, PluginStageConfig


STAGES = {
    "generate_phase_plan": "phase",
    "generate_domain_context": "context",
    "extract_functions": "extract",
    "collect_file_list": "files",
    "generate_topdown_layers": "topdown",
    "generate_specs_and_verification": "spec",
}


class PipelinePluginOrchestrationTests(unittest.TestCase):
    def _project(self):
        temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(temp_dir.cleanup)
        project = Path(temp_dir.name) / "project"
        work = project / "fm_agent"
        extracted = work / "extracted_functions" / "main-py"
        extracted.mkdir(parents=True)
        (project / "main.py").write_text("def main():\n    pass\n", encoding="utf-8")
        (extracted / "main.py").write_text("def main():\n    pass\n", encoding="utf-8")
        (work / "phases.json").write_text(
            json.dumps(
                {
                    "project": "project",
                    "phases": [
                        {
                            "phase": 1,
                            "name": "Main",
                            "modules": [
                                {"name": "Main", "source_files": ["main.py"]}
                            ],
                        }
                    ],
                }
            ),
            encoding="utf-8",
        )
        (work / "fm_agent_file_list.json").write_text(
            json.dumps(["main-py/main.py"]), encoding="utf-8"
        )
        return project

    def _config(self, stage_name, mode, events):
        def before(proj_dir: str) -> None:
            events.append(("input", proj_dir))

        def replace(proj_dir: str) -> None:
            events.append(("replace", proj_dir))

        def after(proj_dir: str) -> None:
            events.append(("output", proj_dir))

        stage = PluginStageConfig(type=mode)
        if mode == "replace":
            stage.replace_function = "replace"
            stage.replace_hook = replace
        elif mode == "modify":
            stage.input_function = "before"
            stage.input_hook = before
            stage.output_function = "after"
            stage.output_hook = after
        return PluginConfig(
            name="test",
            version="V1.0",
            root=Path("/plugin"),
            stages={stage_name: stage},
        )

    def _run(self, stage_name=None, mode=None, resume=False):
        project = self._project()
        work = project / "fm_agent"
        events = []
        config = (
            self._config(stage_name, mode, events)
            if stage_name is not None
            else None
        )

        def record(name):
            def side_effect(*_args, **_kwargs):
                events.append((name, str(project)))
            return side_effect

        def collect(_input_dir, output_path):
            events.append(("files", str(project)))
            Path(output_path).write_text(
                json.dumps(["main-py/main.py"]), encoding="utf-8"
            )
            return ["main-py/main.py"]

        with (
            patch.object(main, "_has_source_code", return_value=True),
            patch.object(main, "_clean_previous_run"),
            patch.object(main, "stage_domain_knowledge_files", return_value=[]),
            patch.object(main, "load_call_edges", return_value=[]),
            patch.object(main, "_run_generate_phases", side_effect=record("phase")),
            patch.object(main, "_post_process_phases", return_value=False),
            patch.object(main, "_run_generate_domain_context", side_effect=record("context")),
            patch.object(main, "try_codegraph_init", side_effect=record("codegraph")),
            patch.object(main, "run_extraction", side_effect=record("extract")) as extraction,
            patch.object(main.shutil, "copy2"),
            patch.object(main, "collect_file_names", side_effect=collect),
            patch.object(main, "generate_topdown_layers", side_effect=record("topdown")) as topdown,
            patch.object(
                main,
                "run_spec_generation_and_verification",
                side_effect=record("spec"),
            ) as spec,
        ):
            main.run_pipeline(
                str(project),
                resume=resume,
                plugin_config=config,
                plugin_context={},
            )

        return str(project), events, extraction, topdown, spec, work

    def test_all_stages_support_pass_replace_and_modify(self):
        for stage_name, builtin in STAGES.items():
            for mode in ("pass", "replace", "modify"):
                with self.subTest(stage=stage_name, mode=mode):
                    project, events, *_rest = self._run(stage_name, mode)
                    relevant = [
                        event
                        for event in events
                        if event[0] in {"input", "replace", "output", builtin}
                    ]
                    if mode == "pass":
                        self.assertEqual(relevant, [])
                    elif mode == "replace":
                        self.assertEqual(relevant, [("replace", project)])
                    else:
                        self.assertEqual(
                            relevant,
                            [
                                ("input", project),
                                (builtin, project),
                                ("output", project),
                            ],
                        )

    def test_no_plugin_uses_original_stage_calls(self):
        project, events, extraction, topdown, spec, _work = self._run()

        for builtin in STAGES.values():
            self.assertIn((builtin, project), events)
        extraction.assert_called_once_with(
            project,
            work_dir=str(Path(project) / "fm_agent"),
            force=True,
            verbose=True,
        )
        topdown.assert_called_once()
        spec.assert_called_once()

    def test_resume_still_runs_modify_hooks(self):
        project, events, *_rest = self._run(
            "generate_phase_plan", "modify", resume=True
        )

        relevant = [event for event in events if event[0] in {"input", "phase", "output"}]
        self.assertEqual(
            relevant,
            [("input", project), ("phase", project), ("output", project)],
        )

    def test_stage4_output_hook_controls_downstream_file_list(self):
        project = self._project()
        work = project / "fm_agent"
        observed = {}

        def output_hook(proj_dir: str) -> None:
            path = Path(proj_dir) / "fm_agent" / "fm_agent_file_list.json"
            path.write_text(json.dumps(["selected.py"]), encoding="utf-8")

        stage = PluginStageConfig(
            type="modify",
            output_function="output_hook",
            output_hook=output_hook,
        )
        config = PluginConfig(
            name="test",
            version="V1.0",
            root=Path("/plugin"),
            stages={"collect_file_list": stage},
        )

        def spec(*_args, **_kwargs):
            observed["file_list"] = json.loads(
                (work / "fm_agent_file_list.json").read_text(encoding="utf-8")
            )

        with (
            patch.object(main, "_has_source_code", return_value=True),
            patch.object(main, "_clean_previous_run"),
            patch.object(main, "stage_domain_knowledge_files", return_value=[]),
            patch.object(main, "load_call_edges", return_value=[]),
            patch.object(main, "_run_generate_phases"),
            patch.object(main, "_post_process_phases", return_value=False),
            patch.object(main, "_run_generate_domain_context"),
            patch.object(main, "try_codegraph_init"),
            patch.object(main, "run_extraction"),
            patch.object(main.shutil, "copy2"),
            patch.object(
                main,
                "collect_file_names",
                side_effect=lambda _i, path: (
                    Path(path).write_text(json.dumps(["all.py"]), encoding="utf-8")
                    or ["all.py"]
                ),
            ),
            patch.object(main, "generate_topdown_layers"),
            patch.object(main, "run_spec_generation_and_verification", side_effect=spec),
        ):
            main.run_pipeline(str(project), plugin_config=config)

        self.assertEqual(observed["file_list"], ["selected.py"])


if __name__ == "__main__":
    unittest.main()

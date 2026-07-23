import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import main
from src.entry_reasoning_pipeline import (
    _run_entry_pipeline_inner,
    _select_functions_by_source,
)
from src.incremental_reasoner import run_incremental_pipeline
from src.plugin import PluginConfig, PluginStageConfig


class StopAfterPropagation(Exception):
    pass


def plugin_config(root):
    stage = PluginStageConfig(type="pass")
    return PluginConfig(
        name="sample",
        version="V1.0",
        root=root,
        stages={"extract_functions": stage},
    ), stage


class FullPipelinePropagationTests(unittest.TestCase):
    def _project(self, root):
        project = root / "project"
        project.mkdir()
        (project / "sample.py").write_text(
            "def sample():\n    pass\n", encoding="utf-8"
        )
        return project

    def _run_until_extraction(self, project, config, resume):
        work_dir = project / "fm_agent"
        if resume:
            work_dir.mkdir()

        with (
            patch("main._has_source_code", return_value=True),
            patch("main._clean_previous_run"),
            patch("main.stage_domain_knowledge_files", return_value=[]),
            patch("main._run_generate_phases"),
            patch("main._post_process_phases", return_value=False),
            patch("main._run_generate_domain_context"),
            patch("main.try_codegraph_init"),
            patch(
                "main.run_extraction",
                side_effect=StopAfterPropagation,
            ) as extraction,
        ):
            with self.assertRaises(StopAfterPropagation):
                main.run_pipeline(
                    project,
                    resume=resume,
                    plugin_config=config,
                )
        return extraction

    def test_full_pipeline_passes_stage3_plugin(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            project = self._project(Path(temp_dir))
            config, stage = plugin_config(project)

            extraction = self._run_until_extraction(
                project, config, resume=False
            )

            self.assertIs(extraction.call_args.kwargs["plugin_stage"], stage)
            self.assertTrue(extraction.call_args.kwargs["force"])

    def test_resume_passes_stage3_plugin_without_forcing(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            project = self._project(Path(temp_dir))
            config, stage = plugin_config(project)

            extraction = self._run_until_extraction(
                project, config, resume=True
            )

            self.assertIs(extraction.call_args.kwargs["plugin_stage"], stage)
            self.assertFalse(extraction.call_args.kwargs["force"])

    def test_full_pipeline_without_plugin_passes_none(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            project = self._project(Path(temp_dir))

            extraction = self._run_until_extraction(
                project, None, resume=False
            )

            self.assertIsNone(extraction.call_args.kwargs["plugin_stage"])


class EntryPipelinePropagationTests(unittest.TestCase):
    def test_selection_passes_stage3_plugin(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            project = Path(temp_dir) / "project"
            project.mkdir()
            (project / "sample.py").write_text(
                "def sample():\n    pass\n", encoding="utf-8"
            )
            stage = PluginStageConfig(type="pass")

            with (
                patch("src.entry_reasoning_pipeline.try_codegraph_init"),
                patch(
                    "src.entry_reasoning_pipeline.run_extraction",
                    side_effect=StopAfterPropagation,
                ) as extraction,
            ):
                with self.assertRaises(StopAfterPropagation):
                    _select_functions_by_source(
                        str(project),
                        "sample-py::sample",
                        None,
                        plugin_stage=stage,
                    )

            self.assertIs(extraction.call_args.kwargs["plugin_stage"], stage)
            self.assertTrue(extraction.call_args.kwargs["force"])

    def test_entry_inner_resolves_plugin_before_selection(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            project = Path(temp_dir) / "project"
            project.mkdir()
            config, stage = plugin_config(project)

            with (
                patch(
                    "src.entry_reasoning_pipeline.load_call_edges",
                    return_value={},
                ),
                patch(
                    "src.entry_reasoning_pipeline._select_functions_by_source",
                    side_effect=StopAfterPropagation,
                ) as selection,
            ):
                with self.assertRaises(StopAfterPropagation):
                    _run_entry_pipeline_inner(
                        project,
                        project / "fm_agent",
                        "sample-py::sample",
                        None,
                        False,
                        plugin_config=config,
                    )

            self.assertIs(selection.call_args.kwargs["plugin_stage"], stage)


class IncrementalPipelinePropagationTests(unittest.TestCase):
    def _project(self, root):
        project = root / "project"
        work_dir = project / "fm_agent"
        work_dir.mkdir(parents=True)
        intent = project / "intent.md"
        intent.write_text("change sample", encoding="utf-8")
        return project, intent

    def test_incremental_reextraction_passes_stage3_plugin(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            project, intent = self._project(Path(temp_dir))
            config, stage = plugin_config(project)

            with (
                patch(
                    "src.incremental_reasoner._setup_incremental_logging"
                ),
                patch(
                    "src.incremental_reasoner.stage_domain_knowledge_files",
                    return_value=[],
                ),
                patch(
                    "src.incremental_reasoner.check_last_run_existence",
                    return_value=True,
                ),
                patch("main._run_setup_extract"),
                patch(
                    "src.incremental_reasoner.extract_existing_specs",
                    return_value={},
                ),
                patch("src.incremental_reasoner.try_codegraph_init"),
                patch(
                    "src.incremental_reasoner.run_extraction",
                    side_effect=StopAfterPropagation,
                ) as extraction,
            ):
                with self.assertRaises(StopAfterPropagation):
                    run_incremental_pipeline(
                        project,
                        intent,
                        "old-commit",
                        plugin_config=config,
                    )

            self.assertIs(extraction.call_args.kwargs["plugin_stage"], stage)
            self.assertTrue(extraction.call_args.kwargs["force"])

    def test_incremental_fallback_preserves_plugin_config(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            project, intent = self._project(Path(temp_dir))
            config, _ = plugin_config(project)

            with (
                patch(
                    "src.incremental_reasoner._setup_incremental_logging"
                ),
                patch(
                    "src.incremental_reasoner.stage_domain_knowledge_files",
                    return_value=[],
                ),
                patch(
                    "src.incremental_reasoner.check_last_run_existence",
                    return_value=False,
                ),
                patch("main.run_pipeline") as full_pipeline,
            ):
                run_incremental_pipeline(
                    project,
                    intent,
                    "old-commit",
                    plugin_config=config,
                )

            self.assertIs(
                full_pipeline.call_args.kwargs["plugin_config"], config
            )


if __name__ == "__main__":
    unittest.main()

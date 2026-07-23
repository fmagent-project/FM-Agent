import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from src.extract import run_extraction
from src.plugin import PluginStageConfig


class Stage3PluginExecutionTests(unittest.TestCase):
    def _project(self, root, source="def original():\n    return 1\n"):
        project = root / "project"
        source_dir = project / "src"
        work_dir = project / "fm_agent"
        source_dir.mkdir(parents=True)
        work_dir.mkdir()
        source_path = source_dir / "sample.py"
        source_path.write_text(source, encoding="utf-8")
        (work_dir / "phases.json").write_text(
            json.dumps(
                {
                    "phases": [
                        {
                            "phase": 1,
                            "modules": [
                                {
                                    "name": "sample",
                                    "source_files": ["src/sample.py"],
                                }
                            ],
                        }
                    ]
                }
            ),
            encoding="utf-8",
        )
        return project, work_dir, source_path

    def _output(self, work_dir, function_name="original"):
        return work_dir / "extracted_functions" / "src" / "sample-py" / f"{function_name}.py"

    @patch("src.extract.batch_extract_all", return_value=({}, set()))
    def test_no_plugin_keeps_builtin_extraction(self, _batch_extract):
        with tempfile.TemporaryDirectory() as temp_dir:
            project, work_dir, _ = self._project(Path(temp_dir))

            written, skipped = run_extraction(project, work_dir=work_dir)

            self.assertEqual((written, skipped), (1, 0))
            self.assertTrue(self._output(work_dir).is_file())

    def test_pass_uses_existing_outputs(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            project, work_dir, _ = self._project(Path(temp_dir))
            output = self._output(work_dir)
            output.parent.mkdir(parents=True)
            output.write_text("def original():\n    return 1\n", encoding="utf-8")
            stage = PluginStageConfig(type="pass")

            written, skipped = run_extraction(
                project, work_dir=work_dir, plugin_stage=stage
            )

            self.assertEqual((written, skipped), (0, 1))

    def test_pass_requires_existing_outputs(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            project, work_dir, _ = self._project(Path(temp_dir))
            stage = PluginStageConfig(type="pass")

            with self.assertRaisesRegex(RuntimeError, "requires existing"):
                run_extraction(project, work_dir=work_dir, plugin_stage=stage)

    @patch("src.extract.try_codegraph_init")
    @patch("src.extract.batch_extract_all", return_value=({}, set()))
    def test_input_hook_uses_temporary_project(self, _batch_extract, _codegraph):
        with tempfile.TemporaryDirectory() as temp_dir:
            project, work_dir, source_path = self._project(Path(temp_dir))
            original_source = source_path.read_text(encoding="utf-8")

            def prepare_source(path):
                Path(path).write_text(
                    "def modified():\n    return 2\n", encoding="utf-8"
                )

            stage = PluginStageConfig(
                type="modify",
                input_function="prepare_source",
                input_hook=prepare_source,
            )

            run_extraction(project, work_dir=work_dir, plugin_stage=stage)

            self.assertEqual(source_path.read_text(encoding="utf-8"), original_source)
            self.assertTrue(self._output(work_dir, "modified").is_file())
            self.assertFalse(self._output(work_dir).exists())
            _codegraph.assert_called_once()

    @patch("src.extract.try_codegraph_init")
    def test_input_hook_runtime_contract_is_enforced(self, _codegraph):
        invalid_hooks = (
            (lambda path: "wrong", "must return None"),
            (lambda path: os.remove(path), "removed or replaced"),
        )
        for hook, expected in invalid_hooks:
            with self.subTest(expected=expected):
                with tempfile.TemporaryDirectory() as temp_dir:
                    project, work_dir, _ = self._project(Path(temp_dir))
                    stage = PluginStageConfig(
                        type="modify",
                        input_function="prepare_source",
                        input_hook=hook,
                    )

                    with self.assertRaisesRegex(RuntimeError, expected):
                        run_extraction(project, work_dir=work_dir, plugin_stage=stage)

    @patch("src.extract.batch_extract_all", return_value=({}, set()))
    def test_output_hook_modifies_written_file(self, _batch_extract):
        with tempfile.TemporaryDirectory() as temp_dir:
            project, work_dir, _ = self._project(Path(temp_dir))

            def normalize_output(path):
                output = Path(path)
                output.write_text(
                    output.read_text(encoding="utf-8") + "# plugin\n",
                    encoding="utf-8",
                )

            stage = PluginStageConfig(
                type="modify",
                output_function="normalize_output",
                output_hook=normalize_output,
            )

            run_extraction(project, work_dir=work_dir, plugin_stage=stage)

            self.assertTrue(
                self._output(work_dir).read_text(encoding="utf-8").endswith("# plugin\n")
            )

    @patch("src.extract.batch_extract_all", return_value=({}, set()))
    def test_output_hook_runtime_contract_is_enforced(self, _batch_extract):
        invalid_hooks = (
            (lambda path: "wrong", "must return None"),
            (lambda path: os.remove(path), "removed or replaced"),
        )
        for hook, expected in invalid_hooks:
            with self.subTest(expected=expected):
                with tempfile.TemporaryDirectory() as temp_dir:
                    project, work_dir, _ = self._project(Path(temp_dir))
                    stage = PluginStageConfig(
                        type="modify",
                        output_function="normalize_output",
                        output_hook=hook,
                    )

                    with self.assertRaisesRegex(RuntimeError, expected):
                        run_extraction(project, work_dir=work_dir, plugin_stage=stage)

    @patch("src.extract.batch_extract_all", return_value=({}, set()))
    def test_resume_does_not_run_output_hook_for_ready_file(self, _batch_extract):
        with tempfile.TemporaryDirectory() as temp_dir:
            project, work_dir, _ = self._project(Path(temp_dir))
            output = self._output(work_dir)
            output.parent.mkdir(parents=True)
            output.write_text(
                "# [SPEC]\n# existing\n# [SPEC]\n"
                "# [INFO]\n# existing\n# [INFO]\n"
                "def original():\n    return 1\n",
                encoding="utf-8",
            )
            calls = []

            def normalize_output(path):
                calls.append(path)

            stage = PluginStageConfig(
                type="modify",
                output_function="normalize_output",
                output_hook=normalize_output,
            )

            written, skipped = run_extraction(
                project,
                work_dir=work_dir,
                force=False,
                plugin_stage=stage,
            )

            self.assertEqual((written, skipped), (0, 1))
            self.assertEqual(calls, [])

    def test_replace_writes_returned_files(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            project, work_dir, source_path = self._project(Path(temp_dir))
            received = {}

            def replace_sources(source_paths, output_dir):
                received["source_paths"] = source_paths
                received["output_dir"] = output_dir
                output = Path(output_dir) / "src" / "sample-py" / "replacement.py"
                output.parent.mkdir(parents=True)
                output.write_text("def replacement():\n    return 3\n", encoding="utf-8")
                return [str(output)]

            stage = PluginStageConfig(
                type="replace",
                replace_function="replace_sources",
                replace_hook=replace_sources,
            )

            written, skipped = run_extraction(
                project, work_dir=work_dir, plugin_stage=stage
            )

            self.assertEqual((written, skipped), (1, 0))
            self.assertEqual(received["source_paths"], [str(source_path.resolve())])
            self.assertTrue(self._output(work_dir, "replacement").is_file())

    def test_replace_preserves_ready_output_when_not_forced(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            project, work_dir, _ = self._project(Path(temp_dir))
            output = self._output(work_dir, "replacement")
            output.parent.mkdir(parents=True)
            existing = (
                "# [SPEC]\n# existing\n# [SPEC]\n"
                "# [INFO]\n# existing\n# [INFO]\n"
                "def replacement():\n    return 1\n"
            )
            output.write_text(existing, encoding="utf-8")

            def replace_sources(source_paths, output_dir):
                replacement = (
                    Path(output_dir) / "src" / "sample-py" / "replacement.py"
                )
                replacement.parent.mkdir(parents=True)
                replacement.write_text(
                    "def replacement():\n    return 2\n", encoding="utf-8"
                )
                return [str(replacement)]

            stage = PluginStageConfig(
                type="replace",
                replace_function="replace_sources",
                replace_hook=replace_sources,
            )

            written, skipped = run_extraction(
                project,
                work_dir=work_dir,
                force=False,
                plugin_stage=stage,
            )

            self.assertEqual((written, skipped), (0, 1))
            self.assertEqual(output.read_text(encoding="utf-8"), existing)

    def test_replace_runtime_contract_is_enforced(self):
        def outside_output(source_paths, output_dir):
            outside = Path(output_dir).parent / "outside.py"
            outside.write_text("def outside():\n    pass\n", encoding="utf-8")
            return [str(outside)]

        invalid_hooks = (
            (lambda source_paths, output_dir: "wrong", "must return list"),
            (lambda source_paths, output_dir: [], "at least one"),
            (lambda source_paths, output_dir: [1], "only string"),
            (lambda source_paths, output_dir: [str(Path(output_dir) / "missing.py")], "does not exist"),
            (outside_output, "must remain under"),
        )
        for hook, expected in invalid_hooks:
            with self.subTest(expected=expected):
                with tempfile.TemporaryDirectory() as temp_dir:
                    project, work_dir, _ = self._project(Path(temp_dir))
                    stage = PluginStageConfig(
                        type="replace",
                        replace_function="replace_sources",
                        replace_hook=hook,
                    )

                    with self.assertRaisesRegex(RuntimeError, expected):
                        run_extraction(project, work_dir=work_dir, plugin_stage=stage)

    def test_replace_rejects_duplicate_paths(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            project, work_dir, _ = self._project(Path(temp_dir))

            def duplicate_output(source_paths, output_dir):
                output = Path(output_dir) / "duplicate.py"
                output.write_text("def duplicate():\n    pass\n", encoding="utf-8")
                return [str(output), str(output)]

            stage = PluginStageConfig(
                type="replace",
                replace_function="duplicate_output",
                replace_hook=duplicate_output,
            )

            with self.assertRaisesRegex(RuntimeError, "duplicate output path"):
                run_extraction(project, work_dir=work_dir, plugin_stage=stage)


if __name__ == "__main__":
    unittest.main()

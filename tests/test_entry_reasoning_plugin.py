import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from plugins.entry_reasoning import plugin
from src.file_utils import clear_test_file_exemptions
from src.plugin import validate_plugin


class EntryReasoningPluginTests(unittest.TestCase):
    def setUp(self):
        clear_test_file_exemptions()
        plugin._project_dir = None
        plugin._entry_func = None
        plugin._end_funcs = []
        plugin._extra_edge = None
        plugin._selected_fqns = set()
        plugin._selected_sources = []

    def tearDown(self):
        clear_test_file_exemptions()

    def _project(self):
        temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(temp_dir.cleanup)
        project = Path(temp_dir.name) / "project"
        work = project / "fm_agent"
        work.mkdir(parents=True)
        (project / "main.py").write_text(
            "def main():\n    return helper()\n\n"
            "def unused():\n    return 2\n",
            encoding="utf-8",
        )
        (project / "service.py").write_text(
            "def helper():\n    return 1\n",
            encoding="utf-8",
        )
        (project / "unrelated.py").write_text(
            "def unrelated():\n    return 3\n",
            encoding="utf-8",
        )
        return project

    def _configure(self, project, entry="main-py::main", end_funcs=None):
        context = {
            "entry_func": entry,
            "end_funcs": end_funcs or [],
            "extra_edge": None,
        }
        (project / "fm_agent" / "plugin_context.json").write_text(
            json.dumps(context), encoding="utf-8"
        )
        plugin.configure(str(project))

    def _select(self, project, end_funcs=None):
        self._configure(project, end_funcs=end_funcs)
        phase_files = [
            ("main", "module"),
            ("helper", "module"),
            ("unused", "module"),
            ("unrelated", "module"),
        ]
        fqns = {
            "main": "main-py::main",
            "helper": "service-py::helper",
            "unused": "main-py::unused",
            "unrelated": "unrelated-py::unrelated",
        }
        with (
            patch.object(
                plugin,
                "_iter_project_source_files",
                return_value=iter(["main.py", "service.py", "unrelated.py"]),
            ),
            patch.object(plugin, "try_codegraph_init"),
            patch.object(plugin, "_make_codegraph_available"),
            patch.object(plugin, "run_extraction"),
            patch.object(plugin, "_collect_phase_files", return_value=phase_files),
            patch.object(
                plugin,
                "_build_call_graph",
                return_value=(
                    {
                        "main-py::main": {"service-py::helper"},
                        "service-py::helper": set(),
                        "main-py::unused": set(),
                        "unrelated-py::unrelated": set(),
                    },
                    {},
                    set(),
                    {},
                    {},
                    {},
                ),
            ),
            patch.object(plugin, "_file_to_fqn", side_effect=lambda path, _root: fqns[path]),
        ):
            plugin.select_entry_call_chain(str(project))

    def test_manifest_and_hooks_use_unified_contract(self):
        plugin_dir = Path(__file__).resolve().parents[1] / "plugins" / "entry_reasoning"

        config = validate_plugin(plugin_dir)

        self.assertIsNotNone(config)
        self.assertTrue(callable(config.configure_hook))
        phase = config.get_stage("generate_phase_plan")
        files = config.get_stage("collect_file_list")
        self.assertTrue(callable(phase.input_hook))
        self.assertTrue(callable(phase.output_hook))
        self.assertTrue(callable(files.output_hook))

    def test_configure_requires_valid_context(self):
        project = self._project()
        context_path = project / "fm_agent" / "plugin_context.json"
        context_path.write_text(json.dumps({"entry_func": None}), encoding="utf-8")

        with self.assertRaisesRegex(ValueError, "non-empty --entry-func"):
            plugin.configure(str(project))

    def test_selects_reachable_sources_and_writes_standard_artifacts(self):
        project = self._project()
        self._select(project)
        phases_path = project / "fm_agent" / "phases.json"
        phases_path.write_text(
            json.dumps({"project": "demo", "phases": []}), encoding="utf-8"
        )

        plugin.write_entry_phase_plan(str(project))

        phases = json.loads(phases_path.read_text(encoding="utf-8"))
        sources = phases["phases"][0]["modules"][0]["source_files"]
        self.assertEqual(sources, ["main.py", "service.py"])

        file_list = project / "fm_agent" / "fm_agent_file_list.json"
        file_list.write_text(
            json.dumps(
                [
                    "main-py/main.py",
                    "main-py/unused.py",
                    "service-py/helper.py",
                    "unrelated-py/unrelated.py",
                ]
            ),
            encoding="utf-8",
        )
        plugin.filter_entry_file_list(str(project))

        self.assertEqual(
            json.loads(file_list.read_text(encoding="utf-8")),
            ["main-py/main.py", "service-py/helper.py"],
        )
        self.assertIn("def unused", (project / "main.py").read_text(encoding="utf-8"))

    def test_end_function_is_terminal(self):
        project = self._project()
        self._select(project, end_funcs=["main-py::main"])

        self.assertEqual(plugin._selected_fqns, {"main-py::main"})
        self.assertEqual(plugin._selected_sources, ["main.py"])

    def test_hooks_reject_a_different_project_directory(self):
        project = self._project()
        self._configure(project)

        with self.assertRaisesRegex(RuntimeError, "different proj_dir"):
            plugin.select_entry_call_chain(str(project.parent / "other"))


if __name__ == "__main__":
    unittest.main()

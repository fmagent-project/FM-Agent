import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from main import _existing_required_source_files
from plugins.entry_reasoning import plugin
from plugins.entry_reasoning.plugin import (
    _normalize_entry_funcs,
    _reachable_call_graph,
    _restrict_to_chains,
    _validate_entry_funcs,
)


class EntryReasoningPluginTests(unittest.TestCase):
    def test_normalize_entries_accepts_strings_and_deduplicates_lists(self):
        self.assertEqual(_normalize_entry_funcs("main-py::entry"), ["main-py::entry"])
        self.assertEqual(
            _normalize_entry_funcs(["a-py::entry", "b-py::entry", "a-py::entry"]),
            ["a-py::entry", "b-py::entry"],
        )

    def test_normalize_entries_rejects_empty_or_invalid_values(self):
        for value in (None, [], ["a-py::entry", ""], ["a-py::entry", 1]):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    _normalize_entry_funcs(value)

    def test_reachable_graph_is_the_union_from_all_entries(self):
        graph = _reachable_call_graph(
            {
                "a": {"shared", "a_only"},
                "b": {"shared", "b_only"},
                "shared": {"leaf"},
            },
            ["a", "b", "a"],
        )
        self.assertEqual(
            graph,
            {
                "a": ["a_only", "shared"],
                "b": ["b_only", "shared"],
                "a_only": [],
                "shared": ["leaf"],
                "b_only": [],
                "leaf": [],
            },
        )

    def test_end_pruning_keeps_all_entry_to_end_chains_and_makes_end_terminal(self):
        graph = {
            "a": ["shared", "off_a"],
            "b": ["shared", "off_b"],
            "shared": ["end"],
            "end": ["after_end"],
            "off_a": [],
            "off_b": [],
            "after_end": [],
        }
        self.assertEqual(
            _restrict_to_chains(graph, ["end"]),
            {
                "a": ["shared"],
                "b": ["shared"],
                "shared": ["end"],
                "end": [],
            },
        )

    def test_missing_entries_are_reported_together(self):
        with self.assertRaisesRegex(ValueError, r"\['missing_a', 'missing_b'\]"):
            _validate_entry_funcs(["present", "missing_a", "missing_b"], {"present"})

    def test_required_sources_exclude_files_removed_by_scope_selection(self):
        with tempfile.TemporaryDirectory() as temporary_dir:
            project_dir = Path(temporary_dir)
            (project_dir / "survives.py").touch()
            self.assertEqual(
                _existing_required_source_files(
                    project_dir, ["survives.py", "pruned.py"]
                ),
                ["survives.py"],
            )

    def test_configure_exempts_every_entry_source_file(self):
        with tempfile.TemporaryDirectory() as temporary_dir:
            root = Path(temporary_dir)
            original = root / "project"
            run_dir = root / "project.fm-entry-run"
            context_dir = run_dir / "fm_agent"
            context_dir.mkdir(parents=True)
            (context_dir / "plugin_context.json").write_text(
                json.dumps(
                    {
                        "original_proj_dir": str(original),
                        "entry_run_dir": str(run_dir),
                        "entry_funcs": [
                            "tests::entry_one-py::start",
                            "tests::entry_two-py::start",
                        ],
                        "end_funcs": [],
                        "extra_edge": None,
                        "all_bugs": False,
                    }
                ),
                encoding="utf-8",
            )
            with patch.object(plugin, "add_test_file_exemption") as exempt:
                plugin.configure(str(run_dir))

            self.assertEqual(
                [call.args[0] for call in exempt.call_args_list],
                ["tests/entry_one.py", "tests/entry_two.py"],
            )
            plugin.clear_test_file_exemptions()


if __name__ == "__main__":
    unittest.main()

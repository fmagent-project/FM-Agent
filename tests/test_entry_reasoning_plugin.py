import unittest

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


if __name__ == "__main__":
    unittest.main()

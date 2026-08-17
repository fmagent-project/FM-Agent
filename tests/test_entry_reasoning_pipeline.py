"""Tests for src.entry_reasoning_pipeline._restrict_to_chains."""

from src.entry_reasoning_pipeline import _restrict_to_chains


def test_no_end_funcs_returns_graph_unchanged():
    graph = {"A": ["B"], "B": []}
    assert _restrict_to_chains(graph, []) is graph
    assert _restrict_to_chains(graph, None) is graph


def test_keeps_only_nodes_that_reach_an_end_func():
    # Diamond: both B and C can reach D, so the whole graph stays.
    graph = {"A": ["B", "C"], "B": ["D"], "C": ["D"], "D": []}
    assert _restrict_to_chains(graph, ["D"]) == graph


def test_off_chain_branches_are_pruned():
    graph = {"A": ["B", "X"], "B": [], "X": ["Y"], "Y": []}
    assert _restrict_to_chains(graph, ["B"]) == {"A": ["B"], "B": []}


def test_end_funcs_are_terminal():
    # C is reachable from B but B is an end func: its outgoing edges are
    # dropped and C (not on any chain ending at B) is removed.
    graph = {"A": ["B"], "B": ["C"], "C": []}
    assert _restrict_to_chains(graph, ["B"]) == {"A": ["B"], "B": []}


def test_unknown_end_func_yields_empty_graph():
    graph = {"A": ["B"], "B": []}
    assert _restrict_to_chains(graph, ["ZZZ"]) == {}


def test_multiple_end_funcs():
    graph = {"A": ["B", "C"], "B": [], "C": []}
    assert _restrict_to_chains(graph, ["B", "C"]) == {
        "A": ["B", "C"],
        "B": [],
        "C": [],
    }


def test_cycle_on_chain_is_retained():
    graph = {"A": ["B"], "B": ["A", "C"], "C": []}
    result = _restrict_to_chains(graph, ["C"])
    assert result == {"A": ["B"], "B": ["A", "C"], "C": []}

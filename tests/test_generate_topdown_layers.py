"""Tests for the pure graph helpers in src.generate_topdown_layers."""

from src.generate_topdown_layers import _compute_layers, _tarjan_scc


class TestTarjanScc:
    def test_empty_graph(self):
        assert _tarjan_scc([], {}) == []

    def test_single_node_no_edges(self):
        assert _tarjan_scc(["a"], {"a": set()}) == [{"a"}]

    def test_self_loop_is_one_scc(self):
        assert _tarjan_scc(["a"], {"a": {"a"}}) == [{"a"}]

    def test_cycle_and_sink_reverse_topological_order(self):
        # a <-> b form an SCC; c is a sink reachable from b. SCCs come back in
        # reverse topological order: the sink SCC first.
        sccs = _tarjan_scc(["a", "b", "c"], {"a": {"b"}, "b": {"a", "c"}, "c": set()})
        assert sccs == [{"c"}, {"a", "b"}]

    def test_plain_chain(self):
        sccs = _tarjan_scc(["a", "b"], {"a": {"b"}, "b": set()})
        assert sccs == [{"b"}, {"a"}]

    def test_edges_may_omit_sink_nodes(self):
        # edges.get(node, set()) tolerates nodes missing from the edges dict.
        sccs = _tarjan_scc(["a", "b"], {"a": {"b"}})
        assert [set(s) for s in sccs] == [{"b"}, {"a"}]


class TestComputeLayers:
    def test_empty_phase(self):
        assert _compute_layers(set(), {}, {}) == []

    def test_independent_functions_single_layer(self):
        layers = _compute_layers({"a", "b"}, {}, {})
        assert layers == [
            {"layer": 0, "functions": ["a", "b"], "cycle_resolution": False}
        ]

    def test_linear_chain_callers_first(self):
        # a calls b, b calls c. A function becomes ready once all its in-phase
        # callers are assigned, so callers land in earlier layers.
        callees = {"a": {"b"}, "b": {"c"}, "c": set()}
        callers = {"b": {"a"}, "c": {"b"}}
        layers = _compute_layers({"a", "b", "c"}, callees, callers)
        assert layers == [
            {"layer": 0, "functions": ["a"], "cycle_resolution": False},
            {"layer": 1, "functions": ["b"], "cycle_resolution": False},
            {"layer": 2, "functions": ["c"], "cycle_resolution": False},
        ]

    def test_diamond(self):
        # top calls left and right; both call bottom.
        callees = {"top": {"left", "right"}, "left": {"bottom"}, "right": {"bottom"}, "bottom": set()}
        callers = {"left": {"top"}, "right": {"top"}, "bottom": {"left", "right"}}
        layers = _compute_layers({"top", "left", "right", "bottom"}, callees, callers)
        assert [l["functions"] for l in layers] == [["top"], ["left", "right"], ["bottom"]]
        assert all(l["cycle_resolution"] is False for l in layers)

    def test_mutual_recursion_marks_cycle_resolution(self):
        # x <-> y are mutually recursive; y also calls z (a non-cycle tail).
        callees = {"x": {"y"}, "y": {"x", "z"}, "z": set()}
        callers = {"x": {"y"}, "y": {"x"}, "z": {"y"}}
        layers = _compute_layers({"x", "y", "z"}, callees, callers)
        assert layers == [
            {"layer": 0, "functions": ["x", "y"], "cycle_resolution": True},
            {"layer": 1, "functions": ["z"], "cycle_resolution": False},
        ]

    def test_self_loop_resolved_as_single_node_scc(self):
        # A one-node SCC (self-recursive function) is not flagged as a cycle
        # layer by the current implementation (is_cycle requires len(scc) > 1).
        layers = _compute_layers({"a"}, {"a": {"a"}}, {"a": {"a"}})
        assert layers == [
            {"layer": 0, "functions": ["a"], "cycle_resolution": False}
        ]

    def test_callers_outside_phase_are_ignored(self):
        # External callers (not in phase_fqns) must not delay readiness.
        callees = {"a": set()}
        callers = {"a": {"external"}}
        layers = _compute_layers({"a"}, callees, callers)
        assert layers == [
            {"layer": 0, "functions": ["a"], "cycle_resolution": False}
        ]

"""
Unit tests for WP (Weakest Precondition) reasoning components.

Tests cover:
1. _parse_wp_json() — WP JSON response validation
2. _compute_bottomup_layers() — leaf-first topological layering + cycle handling
3. _collect_callee_wps() / _format_callee_wps() — callee WP propagation
4. _parse_spec_conditions() — spec pre/post condition parsing (shared with SP)
5. Result format handling — both SP and WP verdict strings

These tests do NOT make LLM calls — they test the pure-logic helper functions.
Run with: python -m pytest tests/test_wp_reasoner.py -v
"""

import sys
import os
import json

# Ensure the project root is on the path
_proj_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _proj_root not in sys.path:
    sys.path.insert(0, _proj_root)

import pytest
from src.reasoner import (
    _parse_spec_conditions,
    _collect_callee_wps,
    _format_callee_wps,
)
from src.prompts import _parse_wp_json
from src.generate_topdown_layers import (
    _compute_layers,
    _compute_bottomup_layers,
    _tarjan_scc,
)


# ---------------------------------------------------------------------------
# 1. _parse_wp_json — WP JSON response validation
# ---------------------------------------------------------------------------

class TestParseWpJson:
    """Test _parse_wp_json() validates WP LLM responses correctly."""

    def test_valid_json(self):
        data = {"pre_condition": "x > 0 and y != None"}
        result = _parse_wp_json(data)
        assert result == "x > 0 and y != None"

    def test_strips_whitespace(self):
        data = {"pre_condition": "  x > 0  "}
        result = _parse_wp_json(data)
        assert result == "x > 0"

    def test_empty_string_raises(self):
        with pytest.raises(ValueError, match="non-empty"):
            _parse_wp_json({"pre_condition": ""})

    def test_whitespace_only_raises(self):
        with pytest.raises(ValueError, match="non-empty"):
            _parse_wp_json({"pre_condition": "   "})

    def test_missing_field_raises(self):
        with pytest.raises(ValueError, match="pre_condition"):
            _parse_wp_json({"post_condition": "x > 0"})

    def test_non_string_raises(self):
        with pytest.raises(ValueError, match="non-empty"):
            _parse_wp_json({"pre_condition": 123})

    def test_non_dict_raises(self):
        with pytest.raises(ValueError, match="object"):
            _parse_wp_json("not a dict")

    def test_none_raises(self):
        with pytest.raises(ValueError, match="object"):
            _parse_wp_json(None)

    def test_complex_condition(self):
        wp = ("For all elements e in array: e.field != NULL. "
              "Array length > 0. Mutex m is locked.")
        data = {"pre_condition": wp}
        result = _parse_wp_json(data)
        assert result == wp


# ---------------------------------------------------------------------------
# 2. _compute_bottomup_layers — leaf-first topological layering
# ---------------------------------------------------------------------------

class TestComputeBottomupLayers:
    """Test _compute_bottomup_layers() produces correct leaf-first ordering."""

    def test_simple_chain(self):
        """entry -> helper -> leaf: bottom-up should be [leaf], [helper], [entry]."""
        # callees_map: who each function calls
        callees_map = {
            "entry": {"helper"},
            "helper": {"leaf"},
            "leaf": set(),
        }
        callers_map = {
            "entry": set(),
            "helper": {"entry"},
            "leaf": {"helper"},
        }
        phase_fqns = {"entry", "helper", "leaf"}

        layers = _compute_bottomup_layers(phase_fqns, callees_map, callers_map)
        assert len(layers) == 3
        # Layer 0: leaf (no callees)
        assert layers[0]["functions"] == ["leaf"]
        assert not layers[0]["cycle_resolution"]
        # Layer 1: helper (callees = {leaf}, already assigned)
        assert layers[1]["functions"] == ["helper"]
        # Layer 2: entry (callees = {helper}, already assigned)
        assert layers[2]["functions"] == ["entry"]

    def test_diamond(self):
        """entry -> {a, b} -> leaf: bottom-up should be [leaf], [a, b], [entry]."""
        callees_map = {
            "entry": {"a", "b"},
            "a": {"leaf"},
            "b": {"leaf"},
            "leaf": set(),
        }
        callers_map = {
            "entry": set(),
            "a": {"entry"},
            "b": {"entry"},
            "leaf": {"a", "b"},
        }
        phase_fqns = {"entry", "a", "b", "leaf"}

        layers = _compute_bottomup_layers(phase_fqns, callees_map, callers_map)
        assert len(layers) == 3
        assert layers[0]["functions"] == ["leaf"]
        # a and b should be in the same layer (both depend only on leaf)
        assert set(layers[1]["functions"]) == {"a", "b"}
        assert layers[2]["functions"] == ["entry"]

    def test_isolated_functions(self):
        """Functions with no callees and no callers go first."""
        callees_map = {
            "f1": set(),
            "f2": set(),
            "f3": set(),
        }
        callers_map = {
            "f1": set(),
            "f2": set(),
            "f3": set(),
        }
        phase_fqns = {"f1", "f2", "f3"}

        layers = _compute_bottomup_layers(phase_fqns, callees_map, callers_map)
        assert len(layers) == 1
        assert set(layers[0]["functions"]) == {"f1", "f2", "f3"}

    def test_cycle_mutual_recursion(self):
        """a <-> b (mutual recursion): both should be in the same cycle layer."""
        callees_map = {
            "a": {"b"},
            "b": {"a"},
        }
        callers_map = {
            "a": {"b"},
            "b": {"a"},
        }
        phase_fqns = {"a", "b"}

        layers = _compute_bottomup_layers(phase_fqns, callees_map, callers_map)
        # Both should end up in a single layer (cycle resolution)
        assert len(layers) >= 1
        all_fns = set()
        for layer in layers:
            all_fns.update(layer["functions"])
        assert all_fns == {"a", "b"}
        # At least one layer should mark cycle_resolution
        assert any(l.get("cycle_resolution") for l in layers)

    def test_cycle_with_entry(self):
        """entry -> {a, b} where a <-> b: leaf-first, cycle layer, then entry."""
        callees_map = {
            "entry": {"a", "b"},
            "a": {"b"},
            "b": {"a"},
        }
        callers_map = {
            "entry": set(),
            "a": {"entry", "b"},
            "b": {"entry", "a"},
        }
        phase_fqns = {"entry", "a", "b"}

        layers = _compute_bottomup_layers(phase_fqns, callees_map, callers_map)
        # a and b form a cycle, entry depends on both
        # Layer 0: {a, b} (cycle, all callees within cycle)
        # Layer 1: {entry}
        assert len(layers) == 2
        assert set(layers[0]["functions"]) == {"a", "b"}
        assert layers[0].get("cycle_resolution") is True
        assert layers[1]["functions"] == ["entry"]

    def test_topdown_vs_bottomup_reversed(self):
        """Bottom-up layers should be the reverse of top-down for a simple chain."""
        callees_map = {
            "entry": {"mid"},
            "mid": {"leaf"},
            "leaf": set(),
        }
        callers_map = {
            "entry": set(),
            "mid": {"entry"},
            "leaf": {"mid"},
        }
        phase_fqns = {"entry", "mid", "leaf"}

        td_layers = _compute_layers(phase_fqns, callees_map, callers_map)
        bu_layers = _compute_bottomup_layers(phase_fqns, callees_map, callers_map)

        # Top-down: entry, mid, leaf
        td_order = [f for l in td_layers for f in l["functions"]]
        # Bottom-up: leaf, mid, entry
        bu_order = [f for l in bu_layers for f in l["functions"]]
        assert td_order == ["entry", "mid", "leaf"]
        assert bu_order == ["leaf", "mid", "entry"]
        assert bu_order == list(reversed(td_order))

    def test_empty_input(self):
        """Empty phase should produce empty layers."""
        layers = _compute_bottomup_layers(set(), {}, {})
        assert layers == []

    def test_cross_phase_callees_ignored(self):
        """Only same-phase callees affect readiness."""
        callees_map = {
            "f1": {"f2", "external_func"},  # external_func not in phase
            "f2": set(),
        }
        callers_map = {
            "f1": set(),
            "f2": {"f1"},
        }
        phase_fqns = {"f1", "f2"}

        layers = _compute_bottomup_layers(phase_fqns, callees_map, callers_map)
        # f2 has no same-phase callees -> layer 0
        # f1's only same-phase callee is f2 -> layer 1
        assert len(layers) == 2
        assert layers[0]["functions"] == ["f2"]
        assert layers[1]["functions"] == ["f1"]


# ---------------------------------------------------------------------------
# 3. _collect_callee_wps / _format_callee_wps — WP propagation
# ---------------------------------------------------------------------------

class TestCalleeWpPropagation:
    """Test callee WP collection and formatting for upward propagation."""

    def test_collect_simple(self):
        callees_map = {
            "caller": {"callee_a", "callee_b"},
        }
        phase_fqns = {"caller", "callee_a", "callee_b"}
        wp_cache = {
            "callee_a": "x > 0",
            "callee_b": "list is non-empty",
        }
        result = _collect_callee_wps("caller", phase_fqns, wp_cache, callees_map)
        assert result == {"callee_a": "x > 0", "callee_b": "list is non-empty"}

    def test_collect_filters_uncached(self):
        """Callees not yet in wp_cache are skipped."""
        callees_map = {
            "caller": {"callee_a", "callee_b", "callee_c"},
        }
        phase_fqns = {"caller", "callee_a", "callee_b", "callee_c"}
        wp_cache = {
            "callee_a": "x > 0",
            # callee_b not cached yet
            "callee_c": "y != NULL",
        }
        result = _collect_callee_wps("caller", phase_fqns, wp_cache, callees_map)
        assert "callee_a" in result
        assert "callee_b" not in result
        assert "callee_c" in result

    def test_collect_filters_out_of_phase(self):
        """Callees not in phase_fqns are excluded."""
        callees_map = {
            "caller": {"in_phase", "out_of_phase"},
        }
        phase_fqns = {"caller", "in_phase"}
        wp_cache = {
            "in_phase": "x > 0",
            "out_of_phase": "should be ignored",
        }
        result = _collect_callee_wps("caller", phase_fqns, wp_cache, callees_map)
        assert "in_phase" in result
        assert "out_of_phase" not in result

    def test_collect_no_callees(self):
        """Function with no callees returns empty dict."""
        callees_map = {"lonely": set()}
        phase_fqns = {"lonely"}
        wp_cache = {}
        result = _collect_callee_wps("lonely", phase_fqns, wp_cache, callees_map)
        assert result == {}

    def test_collect_empty_cache(self):
        """Empty wp_cache returns empty dict."""
        callees_map = {"caller": {"callee"}}
        phase_fqns = {"caller", "callee"}
        wp_cache = {}
        result = _collect_callee_wps("caller", phase_fqns, wp_cache, callees_map)
        assert result == {}

    def test_format_simple(self):
        callee_wps = {
            "module::callee_a": "x > 0",
            "module::callee_b": "list is non-empty",
        }
        result = _format_callee_wps(callee_wps)
        assert "Callee pre-condition requirements" in result
        assert "callee_a requires: x > 0" in result
        assert "callee_b requires: list is non-empty" in result

    def test_format_truncates_long_wp(self):
        long_wp = "A" * 250
        callee_wps = {"mod::func": long_wp}
        result = _format_callee_wps(callee_wps)
        # Should be truncated to 200 chars + "..."
        assert "..." in result
        assert "AAAA" in result  # Still contains the content

    def test_format_empty(self):
        result = _format_callee_wps({})
        assert result == ""

    def test_format_short_name(self):
        """FQN should be shortened to last component."""
        callee_wps = {"a::b::c::deep_func": "x > 0"}
        result = _format_callee_wps(callee_wps)
        assert "deep_func requires:" in result
        assert "a::b::c::deep_func requires:" not in result


# ---------------------------------------------------------------------------
# 4. _parse_spec_conditions — spec parsing (shared with SP)
# ---------------------------------------------------------------------------

class TestParseSpecConditions:
    """Test spec pre/post condition parsing — critical for both SP and WP."""

    def test_standard_format(self):
        spec = """Pre-condition:
x >= 0 and x < MAX_SIZE

Post-condition:
result == factorial(x) and result >= 1"""
        pre, post = _parse_spec_conditions(spec)
        assert pre is not None
        assert "x >= 0" in pre
        assert "x < MAX_SIZE" in pre
        assert post is not None
        assert "factorial(x)" in post

    def test_missing_post_condition(self):
        spec = """Pre-condition:
x >= 0"""
        pre, post = _parse_spec_conditions(spec)
        assert pre is not None
        assert post is None

    def test_missing_pre_condition(self):
        spec = """Post-condition:
result == 0"""
        pre, post = _parse_spec_conditions(spec)
        assert pre is None
        assert post is not None

    def test_empty_spec(self):
        pre, post = _parse_spec_conditions("")
        assert pre is None
        assert post is None

    def test_multiline_conditions(self):
        spec = """Pre-condition:
- x must be a non-negative integer
- buffer must have at least x bytes allocated
- mutex must be held

Post-condition:
- buffer is filled with x bytes of data
- return value is 0 on success, -1 on error"""
        pre, post = _parse_spec_conditions(spec)
        assert "non-negative" in pre
        assert "mutex" in pre
        assert "buffer is filled" in post
        assert "return value is 0" in post


# ---------------------------------------------------------------------------
# 5. Result format handling — SP vs WP verdict strings
# ---------------------------------------------------------------------------

class TestResultFormatHandling:
    """Test that the verification result regex handles both SP and WP formats.

    This mirrors the regex logic in verification._verify_single_file().
    """

    def test_sp_success_string(self):
        """SP success message should be detected as 'passes'."""
        result = "The function passes the verification. All code blocks satisfy the specification's post-condition."
        assert "passes" in result and "verification" in result

    def test_wp_success_string(self):
        """WP success message should be detected as 'passes'."""
        result = ("The function passes the WP verification. "
                  "The specification's pre-condition is sufficient to guarantee "
                  "the post-condition across all code paths.")
        assert "passes" in result and "verification" in result

    def test_sp_failure_format(self):
        """SP failure uses 'Post-condition:' label."""
        import re
        result = """Verification FAILED.
Statements triggering the violation:
Line 5: if (x == 0) return -1;

Post-condition:
result >= 0

Reason for violation:
The code can return -1 when x == 0, violating the post-condition that result >= 0."""

        stmts_match = re.search(
            r"Statements triggering the violation:\n(.*?)\n\n(?:Post-condition|Weakest pre-condition):",
            result, re.DOTALL
        )
        assert stmts_match is not None
        assert "Line 5" in stmts_match.group(1)

        cond_match = re.search(
            r"(?:Post-condition|Weakest pre-condition):\n(.*?)\n\nReason for violation:",
            result, re.DOTALL
        )
        assert cond_match is not None
        assert "result >= 0" in cond_match.group(1)

    def test_wp_failure_format(self):
        """WP failure uses 'Weakest pre-condition:' label."""
        import re
        result = """Verification FAILED (WP).
Statements triggering the violation:
Line 3: int result = array[index];

Weakest pre-condition:
index < array_length and index >= 0

Reason for violation:
The spec pre-condition only guarantees 'index is non-negative' but the code
requires 'index < array_length' to avoid out-of-bounds access."""

        stmts_match = re.search(
            r"Statements triggering the violation:\n(.*?)\n\n(?:Post-condition|Weakest pre-condition):",
            result, re.DOTALL
        )
        assert stmts_match is not None
        assert "Line 3" in stmts_match.group(1)

        cond_match = re.search(
            r"(?:Post-condition|Weakest pre-condition):\n(.*?)\n\nReason for violation:",
            result, re.DOTALL
        )
        assert cond_match is not None
        assert "index < array_length" in cond_match.group(1)

    def test_reason_extraction_both_formats(self):
        """Reason for violation should be extractable from both SP and WP results."""
        import re

        sp_result = """Verification FAILED.
Statements triggering the violation:
Line 5: return -1;

Post-condition:
result >= 0

Reason for violation:
Returns negative value."""

        wp_result = """Verification FAILED (WP).
Statements triggering the violation:
Line 3: x = 1 / y;

Weakest pre-condition:
y != 0

Reason for violation:
Division by zero when y == 0."""

        for result in [sp_result, wp_result]:
            reason_match = re.search(r"Reason for violation:\n(.*)", result, re.DOTALL)
            assert reason_match is not None
            assert len(reason_match.group(1).strip()) > 0


# ---------------------------------------------------------------------------
# 6. Integration: bottom-up layering simulates real call graphs
# ---------------------------------------------------------------------------

class TestBottomupLayeringIntegration:
    """Integration tests with realistic call graph structures."""

    def test_multi_phase_realistic(self):
        """Simulate a realistic module with 6 functions and mixed dependencies."""
        # f1 (entry) calls f2, f3
        # f2 calls f4
        # f3 calls f4, f5
        # f4 calls f6 (leaf)
        # f5 calls f6 (leaf)
        # f6 is a leaf (no callees)
        callees_map = {
            "f1": {"f2", "f3"},
            "f2": {"f4"},
            "f3": {"f4", "f5"},
            "f4": {"f6"},
            "f5": {"f6"},
            "f6": set(),
        }
        callers_map = {
            "f1": set(),
            "f2": {"f1"},
            "f3": {"f1"},
            "f4": {"f2", "f3"},
            "f5": {"f3"},
            "f6": {"f4", "f5"},
        }
        phase_fqns = set(callees_map.keys())

        layers = _compute_bottomup_layers(phase_fqns, callees_map, callers_map)

        # Verify leaf-first ordering
        assigned_order = []
        for layer in layers:
            assigned_order.extend(layer["functions"])

        # f6 must come before f4 and f5
        assert assigned_order.index("f6") < assigned_order.index("f4")
        assert assigned_order.index("f6") < assigned_order.index("f5")
        # f4 and f5 must come before f2 and f3
        assert assigned_order.index("f4") < assigned_order.index("f2")
        assert assigned_order.index("f4") < assigned_order.index("f3")
        assert assigned_order.index("f5") < assigned_order.index("f3")
        # f2 and f3 must come before f1
        assert assigned_order.index("f2") < assigned_order.index("f1")
        assert assigned_order.index("f3") < assigned_order.index("f1")

    def test_wp_propagation_simulation(self):
        """Simulate the WP propagation flow: leaf WPs flow up to entry."""
        callees_map = {
            "entry": {"helper"},
            "helper": {"leaf"},
            "leaf": set(),
        }
        phase_fqns = {"entry", "helper", "leaf"}

        # Simulate bottom-up processing
        layers = _compute_bottomup_layers(phase_fqns, callees_map, {})
        wp_cache = {}

        for layer in layers:
            for fqn in layer["functions"]:
                # Simulate WP computation
                if fqn == "leaf":
                    wp_cache[fqn] = "input > 0"
                elif fqn == "helper":
                    # Collect callee WP
                    callee_wps = _collect_callee_wps(fqn, phase_fqns, wp_cache, callees_map)
                    assert "leaf" in callee_wps
                    assert callee_wps["leaf"] == "input > 0"
                    wp_cache[fqn] = "input > 0 (propagated from leaf)"
                elif fqn == "entry":
                    callee_wps = _collect_callee_wps(fqn, phase_fqns, wp_cache, callees_map)
                    assert "helper" in callee_wps
                    assert "propagated from leaf" in callee_wps["helper"]
                    wp_cache[fqn] = "input > 0 (propagated through helper)"

        assert "entry" in wp_cache
        assert "helper" in wp_cache
        assert "leaf" in wp_cache


class TestWpReasonerReturnOrder:
    """Regression test: verify _check_pre_implies_wp return values are correctly
    mapped to the error message fields in wp_reasoner().

    Bug: the return order (passed, stmts, wp, reason) was unpacked as
    (passed, stmts, reason, wp_cond), swapping wp and reason in the output.
    """

    def test_violation_fields_not_swapped(self):
        """Ensure 'Weakest pre-condition' shows the WP, not the reason, and vice versa."""
        from unittest.mock import patch, MagicMock
        from src.reasoner import wp_reasoner

        spec = "[SPEC]\nPre: input >= 0\nPost: result >= 0"
        func_body = "int x = input + 1; return x;"

        with patch("src.reasoner._parse_spec_conditions", return_value=("spec_pre", "spec_post")), \
             patch("src.reasoner._split_into_blocks_braced", return_value=[func_body]), \
             patch("src.reasoner._generate_block_wp", return_value="WP_AT_ENTRY"), \
             patch("src.reasoner._has_terminating_statement", return_value=False), \
             patch("src.reasoner._check_pre_implies_wp",
                   return_value=(False, "OFFENDING_LINE_42", "WP_AT_ENTRY", "CALLER_GUARANTEE_INSUFFICIENT")):
            result, entry_wp = wp_reasoner(func_body, spec, "", "C")

        # entry_wp should be the WP computed at block 0
        assert entry_wp == "WP_AT_ENTRY"

        # The error message must map fields correctly (NOT swapped):
        # - "Statements triggering" → OFFENDING_LINE_42
        # - "Weakest pre-condition" → WP_AT_ENTRY
        # - "Reason for violation" → CALLER_GUARANTEE_INSUFFICIENT
        assert "OFFENDING_LINE_42" in result
        assert "Weakest pre-condition:\nWP_AT_ENTRY" in result
        assert "Reason for violation:\nCALLER_GUARANTEE_INSUFFICIENT" in result

        # Negative assertions: the values must NOT appear in the wrong sections
        assert "Weakest pre-condition:\nCALLER_GUARANTEE_INSUFFICIENT" not in result
        assert "Reason for violation:\nWP_AT_ENTRY" not in result

    def test_success_returns_entry_wp(self):
        """On success, wp_reasoner returns (message, entry_wp) where entry_wp is the WP at block 0."""
        from unittest.mock import patch
        from src.reasoner import wp_reasoner

        spec = "[SPEC]\nPre: input >= 0\nPost: result >= 0"
        func_body = "int x = input + 1; return x;"

        with patch("src.reasoner._parse_spec_conditions", return_value=("spec_pre", "spec_post")), \
             patch("src.reasoner._split_into_blocks_braced", return_value=[func_body]), \
             patch("src.reasoner._generate_block_wp", return_value="THE_WP_VALUE"), \
             patch("src.reasoner._has_terminating_statement", return_value=False), \
             patch("src.reasoner._check_pre_implies_wp",
                   return_value=(True, None, None, None)):
            result, entry_wp = wp_reasoner(func_body, spec, "", "C")

        assert "passes the WP verification" in result
        assert entry_wp == "THE_WP_VALUE"

    def test_parse_failure_returns_none_wp(self):
        """On spec parse failure, wp_reasoner returns (error_msg, None)."""
        from unittest.mock import patch
        from src.reasoner import wp_reasoner

        with patch("src.reasoner._parse_spec_conditions", return_value=(None, None)):
            result, entry_wp = wp_reasoner("func body", "bad spec", "", "C")

        assert "Failed to parse" in result
        assert entry_wp is None


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

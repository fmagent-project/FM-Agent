"""Tests for the pure helpers in src.reasoner.

GRANULARITY is a module-level constant imported from config; tests monkeypatch
it to a small value so fixtures stay readable.
"""

import pytest

from src import reasoner
from src.parser import format_spec_for_reasoner
from src.reasoner import (
    _compute_brace_depth_per_line,
    _has_terminating_statement,
    _parse_spec_conditions,
    _split_into_blocks,
    _split_into_blocks_braced,
)


@pytest.fixture(autouse=True)
def small_granularity(monkeypatch):
    monkeypatch.setattr(reasoner, "GRANULARITY", 5)


def _numbered_lines(prefix, count):
    return "\n".join(f"{prefix}{i}" for i in range(count))


class TestSplitIntoBlocks:
    def test_short_function_returned_whole(self):
        func = "int f() {\n  return 1;\n}"
        assert _split_into_blocks(func) == [func]

    def test_strips_surrounding_whitespace(self):
        assert _split_into_blocks("  one\ntwo  \n") == ["one\ntwo"]

    def test_exactly_granularity_lines_is_single_block(self):
        func = _numbered_lines("line", 5)
        assert _split_into_blocks(func) == [func]

    def test_up_to_double_granularity_is_single_block(self):
        # remaining <= GRANULARITY * 2 -> appended whole, no split.
        func = _numbered_lines("line", 10)
        assert _split_into_blocks(func) == [func]

    def test_long_function_splits_at_granularity(self):
        func = _numbered_lines("line", 12)
        blocks = _split_into_blocks(func)
        assert [len(b.split("\n")) for b in blocks] == [5, 7]
        assert "\n".join(blocks) == func

    def test_very_long_function_multiple_granularity_blocks(self):
        func = _numbered_lines("line", 23)
        blocks = _split_into_blocks(func)
        # 5, 5, then remaining 13 > 10 -> 5, then remaining 8 <= 10.
        assert [len(b.split("\n")) for b in blocks] == [5, 5, 5, 8]
        assert "\n".join(blocks) == func


class TestComputeBraceDepthPerLine:
    def test_simple_braces(self):
        depths = _compute_brace_depth_per_line(["void f() {", "  x();", "}"])
        assert depths == [1, 1, 0]

    def test_braces_in_strings_and_comments_are_ignored(self):
        lines = [
            "void f() {",
            '  char *s = "{";',
            "  // }",
            "  /* { */",
            "  char c = '}';",
            "  return;",
            "}",
        ]
        assert _compute_brace_depth_per_line(lines) == [1, 1, 1, 1, 1, 1, 0]

    def test_unterminated_block_comment_spans_lines(self):
        lines = ["/* {", "still comment { } */", "x();"]
        assert _compute_brace_depth_per_line(lines) == [0, 0, 0]


class TestSplitIntoBlocksBraced:
    def test_short_function_returned_whole(self):
        func = "void f() {\n  return;\n}"
        assert _split_into_blocks_braced(func, "go") == [func]

    def test_python_uses_line_based_splitter(self):
        func = _numbered_lines("stmt", 12)
        blocks = _split_into_blocks_braced(func, "python")
        assert [len(b.split("\n")) for b in blocks] == [5, 7]

    def test_no_braces_falls_back_to_line_splitter(self):
        # entry depth stays 0 -> safe fallback.
        func = _numbered_lines("stmt", 12)
        blocks = _split_into_blocks_braced(func, "go")
        assert [len(b.split("\n")) for b in blocks] == [5, 7]

    def test_splits_only_at_entry_depth(self):
        lines = ["func f() {"]  # entry depth 1
        for i in range(6):
            lines += [f"\tif c{i} {{", f"\t\tx{i}()", "\t}"]
        lines += ["\tlast()", "}"]
        func = "\n".join(lines)
        depths = _compute_brace_depth_per_line(lines)

        blocks = _split_into_blocks_braced(func, "go")
        assert len(blocks) > 1
        assert "\n".join(blocks) == func
        # Every block except the last ends on a line back at entry depth.
        offset = 0
        for block in blocks[:-1]:
            offset += len(block.split("\n"))
            assert depths[offset - 1] == 1

    def test_line_prefixes_are_normalized_for_depth_but_kept_in_output(self):
        lines = ["func f() {"]
        for i in range(6):
            lines += [f"\tif c{i} {{", f"\t\tx{i}()", "\t}"]
        lines += ["\tlast()", "}"]
        func = "\n".join(lines)
        prefixed = "\n".join(f"Line {i + 1}: {line}" for i, line in enumerate(lines))
        blocks = _split_into_blocks_braced(prefixed, "go")
        assert "\n".join(blocks) == prefixed


class TestParseSpecConditions:
    def test_parses_pre_and_post(self):
        spec = (
            "header\n"
            "Pre-condition:\n"
            "  x > 0\n"
            "  y != null\n"
            "Post-condition:\n"
            "  result >= x\n"
        )
        pre, post, invariants = _parse_spec_conditions(spec)
        assert pre == "x > 0\n  y != null"
        assert post == "result >= x"
        assert invariants is None

    def test_missing_markers_return_none(self):
        assert _parse_spec_conditions("no markers here") == (None, None, None)

    def test_post_without_pre(self):
        pre, post, invariants = _parse_spec_conditions("Post-condition:\n  done")
        assert pre is None
        assert post == "done"
        assert invariants is None

    def test_pre_runs_to_end_without_post(self):
        pre, post, invariants = _parse_spec_conditions("Pre-condition:\n  x > 0")
        assert pre == "x > 0"
        assert post is None
        assert invariants is None

    def test_parses_invariants_section(self):
        spec = (
            "header\n"
            "Pre-condition:\n"
            "  running\n"
            "Post-condition:\n"
            "  never returns\n"
            "Invariants:\n"
            "  queue size <= capacity\n"
            "  no partial messages visible\n"
        )
        pre, post, invariants = _parse_spec_conditions(spec)
        assert pre == "running"
        assert post == "never returns"
        assert invariants == "queue size <= capacity\n  no partial messages visible"

    def test_post_condition_stops_at_invariants(self):
        spec = (
            "Pre-condition:\n"
            "  pre\n"
            "Post-condition:\n"
            "  post\n"
            "Invariants:\n"
            "  inv\n"
        )
        _, post, invariants = _parse_spec_conditions(spec)
        assert post == "post"
        assert invariants == "inv"


class TestHasTerminatingStatement:
    def test_c_return(self):
        assert _has_terminating_statement("return 1;", "c") is True

    def test_c_plain_statement(self):
        assert _has_terminating_statement("x = 1;", "c") is False

    def test_c_abort(self):
        assert _has_terminating_statement("abort();", "c") is True

    def test_python_raise(self):
        assert _has_terminating_statement("raise ValueError()", "python") is True

    def test_unknown_language_falls_back_to_generic_pattern(self):
        assert _has_terminating_statement("return", "cobol") is True
        assert _has_terminating_statement("foo();", "cobol") is False

    def test_language_matched_case_insensitively(self):
        assert _has_terminating_statement("exit(0);", "C") is True


_SPEC_WITH_INVARIANTS = (
    "serve(req)\n\n"
    "Pre-condition:\n"
    "  server socket is bound\n\n"
    "Post-condition:\n"
    "  returns only on shutdown\n\n"
    "Invariants:\n"
    "  queue size <= capacity"
)

_SPEC_WITHOUT_INVARIANTS = (
    "add(a, b)\n\n"
    "Pre-condition:\n"
    "  a and b are ints\n\n"
    "Post-condition:\n"
    "  returns a + b"
)


def _patch_reasoner_llm_calls(monkeypatch, invariant_result=(True, None, None)):
    """Replace the LLM-backed helpers inside src.reasoner with fakes."""
    post_conditions = iter(["post after block 0", "post after block 1", "post after block 2"])
    generated = []

    def fake_generate(block, pre, info, language, trace_dir=None, trace_meta=None):
        generated.append(pre)
        return next(post_conditions, generated[-1])

    def fake_post_check(block, post_condition, spec_post_condition, info, language,
                        trace_dir=None, trace_meta=None):
        return True, None, None, None

    invariant_calls = []

    def fake_invariant_check(block, pre_condition, invariants, info, language,
                             trace_dir=None, trace_meta=None):
        invariant_calls.append({"block": block, "pre_condition": pre_condition,
                                "invariants": invariants})
        return invariant_result

    monkeypatch.setattr(reasoner, "_generate_block_post_condition", fake_generate)
    monkeypatch.setattr(reasoner, "_check_post_implies_spec", fake_post_check)
    monkeypatch.setattr(reasoner, "_check_block_preserves_invariants", fake_invariant_check)
    return generated, invariant_calls


class TestFormatSpecForReasoner:
    def test_without_invariants_unchanged(self):
        spec = {
            "signature": "add(a, b)",
            "pre_condition": "a and b are ints",
            "post_condition": "returns a + b",
        }
        assert format_spec_for_reasoner(spec) == (
            "add(a, b)\n\n"
            "Pre-condition:\na and b are ints\n\n"
            "Post-condition:\nreturns a + b"
        )

    def test_invariants_appended(self):
        spec = {
            "signature": "serve(req)",
            "pre_condition": "bound",
            "post_condition": "never returns",
            "invariants": "queue size <= capacity",
        }
        assert format_spec_for_reasoner(spec) == (
            "serve(req)\n\n"
            "Pre-condition:\nbound\n\n"
            "Post-condition:\nnever returns\n\n"
            "Invariants:\nqueue size <= capacity"
        )

    def test_empty_invariants_omitted(self):
        spec = {
            "signature": "add(a, b)",
            "pre_condition": "a and b are ints",
            "post_condition": "returns a + b",
            "invariants": "",
        }
        assert "Invariants:" not in format_spec_for_reasoner(spec)


class TestReasonerInvariants:
    def test_every_block_checked_when_invariants_present(self, monkeypatch):
        _, invariant_calls = _patch_reasoner_llm_calls(monkeypatch)
        func = _numbered_lines("stmt", 12)  # two blocks at GRANULARITY=5
        result = reasoner.reasoner(func, _SPEC_WITH_INVARIANTS, None, "python",
                                   all_bugs=True)
        assert result["status"] == "MATCH"
        assert result["violations"] == []
        assert len(invariant_calls) == 2
        assert invariant_calls[0]["pre_condition"] == "server socket is bound"
        assert invariant_calls[1]["pre_condition"] == "post after block 0"
        assert all(call["invariants"] == "queue size <= capacity"
                   for call in invariant_calls)

    def test_no_invariant_check_without_invariants(self, monkeypatch):
        _, invariant_calls = _patch_reasoner_llm_calls(monkeypatch)
        func = _numbered_lines("stmt", 12)
        result = reasoner.reasoner(func, _SPEC_WITHOUT_INVARIANTS, None, "python",
                                   all_bugs=True)
        assert result["status"] == "MATCH"
        assert invariant_calls == []

    def test_all_bugs_violation_carries_invariant_kind(self, monkeypatch):
        _patch_reasoner_llm_calls(
            monkeypatch,
            invariant_result=(False, "Line 3: q.append(x)", "queue may overflow"),
        )
        func = _numbered_lines("stmt", 6)  # single block
        result = reasoner.reasoner(func, _SPEC_WITH_INVARIANTS, None, "python",
                                   all_bugs=True)
        assert result["status"] == "MISMATCH"
        assert len(result["violations"]) == 1
        violation = result["violations"][0]
        assert violation["kind"] == "invariant"
        assert violation["statements"] == "Line 3: q.append(x)"
        assert violation["reason"] == "queue may overflow"

    def test_all_bugs_post_violation_carries_post_condition_kind(self, monkeypatch):
        _patch_reasoner_llm_calls(monkeypatch)
        monkeypatch.setattr(
            reasoner, "_check_post_implies_spec",
            lambda *args, **kwargs: (False, "Line 1: stmt", "post text", "why"),
        )
        func = "stmt0\nstmt1\nstmt2\nstmt3\nreturn None"
        result = reasoner.reasoner(func, _SPEC_WITHOUT_INVARIANTS, None, "python",
                                   all_bugs=True)
        assert result["status"] == "MISMATCH"
        assert result["violations"][0]["kind"] == "post_condition"

    def test_non_all_bugs_invariant_violation_returns_failure_string(self, monkeypatch):
        _patch_reasoner_llm_calls(
            monkeypatch,
            invariant_result=(False, "Line 3: q.append(x)", "queue may overflow"),
        )
        func = _numbered_lines("stmt", 6)
        result = reasoner.reasoner(func, _SPEC_WITH_INVARIANTS, None, "python",
                                   all_bugs=False)
        assert isinstance(result, str)
        assert result.startswith("Verification FAILED.")
        assert "invariant" in result
        assert "queue may overflow" in result

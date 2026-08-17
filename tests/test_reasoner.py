"""Tests for the pure helpers in src.reasoner.

GRANULARITY is a module-level constant imported from config; tests monkeypatch
it to a small value so fixtures stay readable.
"""

import pytest

from src import reasoner
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
        pre, post = _parse_spec_conditions(spec)
        assert pre == "x > 0\n  y != null"
        assert post == "result >= x"

    def test_missing_markers_return_none(self):
        assert _parse_spec_conditions("no markers here") == (None, None)

    def test_post_without_pre(self):
        pre, post = _parse_spec_conditions("Post-condition:\n  done")
        assert pre is None
        assert post == "done"

    def test_pre_runs_to_end_without_post(self):
        pre, post = _parse_spec_conditions("Pre-condition:\n  x > 0")
        assert pre == "x > 0"
        assert post is None


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

import re

from src.languages.codegraph import CodeGraphExtractor


_LINE_PREFIX = re.compile(r"^Line \d+: ?")


def _line_end(node) -> int:
    """Return the inclusive source line containing ``node``'s end."""
    row, column = node.end_point
    return row - 1 if column == 0 and row > node.start_point[0] else row


def _function_block_nodes(root):
    """Return safe top-level C block boundaries for one function."""
    stack = list(reversed(root.named_children))
    while stack:
        node = stack.pop()
        if node.type == "function_definition":
            body = node.child_by_field_name("body")
            if body is None or body.type != "compound_statement":
                return None
            return [child for child in body.named_children if child.type != "comment"]
        stack.extend(reversed(node.named_children))
    return None


def split_blocks(func: str, granularity: int) -> list[str] | None:
    """Split a C function at complete top-level syntax nodes.

    ``func`` may carry the ``Line N:`` prefixes added by ``parser.py``. They are
    removed only for parsing; returned chunks retain the original prompt text.
    Returning ``None`` asks the caller to use its regex/brace-depth fallback.
    """
    try:
        import tree_sitter_c as ts_c
        from tree_sitter import Language, Parser
    except (ImportError, OSError):
        return None

    prompt_lines = func.strip().split("\n")
    if len(prompt_lines) <= granularity:
        return [func.strip()]

    source = "\n".join(_LINE_PREFIX.sub("", line) for line in prompt_lines)
    try:
        parser = Parser(Language(ts_c.language()))
        tree = parser.parse(source.encode("utf-8"))
    except (TypeError, UnicodeError, ValueError):
        return None

    if tree.root_node.has_error:
        return None

    block_nodes = _function_block_nodes(tree.root_node)
    if not block_nodes:
        return None

    boundaries = sorted({_line_end(node) for node in block_nodes})
    blocks = []
    start = 0
    total = len(prompt_lines)
    while start < total:
        if total - start <= granularity * 2:
            blocks.append("\n".join(prompt_lines[start:]))
            break

        split_at = next((end for end in boundaries if end >= start + granularity), None)
        if split_at is None or split_at >= total - 1:
            blocks.append("\n".join(prompt_lines[start:]))
            break

        blocks.append("\n".join(prompt_lines[start : split_at + 1]))
        start = split_at + 1

    return blocks


def remove_comments(code: str) -> str | None:
    """Remove C comments using Tree-sitter syntax nodes."""
    # C11 translates trigraphs before line splicing and comment recognition;
    # Tree-sitter receives physical source text and does not perform that phase.
    if "??/" in code:
        return None
    try:
        import tree_sitter_c as ts_c
        from tree_sitter import Language, Parser
    except (ImportError, OSError):
        return None

    try:
        source = code.encode("utf-8")
        parser = Parser(Language(ts_c.language()))
        tree = parser.parse(source)
    except (TypeError, UnicodeError, ValueError):
        return None

    if tree.root_node.has_error:
        return None

    cleaned = bytearray(source)
    nodes = [tree.root_node]
    while nodes:
        node = nodes.pop()
        if node.type == "comment":
            for index in range(node.start_byte, node.end_byte):
                if cleaned[index] not in (ord("\n"), ord("\r")):
                    cleaned[index] = ord(" ")
            continue
        nodes.extend(node.children)

    return cleaned.decode("utf-8")


def batch_extract(proj_dir: str) -> dict:
    """Return {abs_filepath: [(func_name, body)]} for all C files."""
    cg = CodeGraphExtractor.from_proj_dir(proj_dir)
    return cg.get_functions_by_file("c", proj_dir) if cg else {}


def call_edges(proj_dir: str) -> dict:
    """Return {(caller_stem, caller_module): {callee_stems}} for C."""
    cg = CodeGraphExtractor.from_proj_dir(proj_dir)
    return cg.get_call_edges("c") if cg else None


def function_spans(proj_dir: str, filepath: str):
    """Return [(name, start_idx, end_idx)] for one C file, or None.

    Line indices are 0-indexed and inclusive. None means codegraph is
    unavailable or does not index the file, so the caller falls back to the
    regex extractor.
    """
    cg = CodeGraphExtractor.from_proj_dir(proj_dir)
    return cg.get_function_spans("c", filepath) if cg else None

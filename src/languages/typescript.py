import re

from src.languages.codegraph import CodeGraphExtractor


_LINE_PREFIX = re.compile(r"^Line \d+: ?")
_FUNCTION_TYPES = {
    "function_declaration",
    "generator_function_declaration",
    "function_expression",
    "generator_function",
    "arrow_function",
    "method_definition",
}


def _line_end(node) -> int:
    """Return the inclusive source line containing ``node``'s end."""
    row, column = node.end_point
    return row - 1 if column == 0 and row > node.start_point[0] else row


def _function_block_nodes(root):
    """Return safe top-level TypeScript block boundaries for one callable."""
    stack = list(reversed(root.named_children))
    while stack:
        node = stack.pop()
        if node.type in _FUNCTION_TYPES:
            body = node.child_by_field_name("body")
            if body is None or body.type != "statement_block":
                return None
            return [child for child in body.named_children if child.type != "comment"]
        stack.extend(reversed(node.named_children))
    return None


def _parse_callable(source: str, typescript, tsx, parser_type):
    """Parse TypeScript or TSX source, adding class context for methods."""
    for language in (typescript, tsx):
        parser = parser_type(language)
        tree = parser.parse(source.encode("utf-8"))
        if not tree.root_node.has_error:
            return tree, 0

    for language in (typescript, tsx):
        parser = parser_type(language)
        tree = parser.parse(f"class _ {{\n{source}\n}}".encode("utf-8"))
        if not tree.root_node.has_error:
            return tree, 1

    return None


def split_blocks(func: str, granularity: int) -> list[str] | None:
    """Split a TypeScript callable at complete top-level syntax nodes.

    The TypeScript parser is preferred; TSX is retried for JSX-bearing source.
    ``func`` may carry the ``Line N:`` prefixes added by ``parser.py``. They are
    removed only for parsing; returned chunks retain the original prompt text.
    Returning ``None`` asks the caller to use its regex/brace-depth fallback.
    """
    try:
        import tree_sitter_typescript as ts_typescript
        from tree_sitter import Language, Parser
    except (ImportError, OSError):
        return None

    prompt_lines = func.strip().split("\n")
    if len(prompt_lines) <= granularity:
        return [func.strip()]

    source = "\n".join(_LINE_PREFIX.sub("", line) for line in prompt_lines)
    try:
        parsed = _parse_callable(
            source,
            Language(ts_typescript.language_typescript()),
            Language(ts_typescript.language_tsx()),
            Parser,
        )
    except (TypeError, UnicodeError, ValueError):
        return None

    if parsed is None:
        return None
    tree, line_offset = parsed

    block_nodes = _function_block_nodes(tree.root_node)
    if not block_nodes:
        return None

    boundaries = sorted({_line_end(node) - line_offset for node in block_nodes})
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


def batch_extract(proj_dir: str) -> dict:
    """Return {abs_filepath: [(func_name, body)]} for all TypeScript files."""
    cg = CodeGraphExtractor.from_proj_dir(proj_dir)
    return cg.get_functions_by_file("typescript", proj_dir) if cg else {}


def call_edges(proj_dir: str) -> dict:
    """Return {(caller_stem, caller_module): {callee_stems}} for TypeScript."""
    cg = CodeGraphExtractor.from_proj_dir(proj_dir)
    return cg.get_call_edges("typescript") if cg else None


def function_spans(proj_dir: str, filepath: str):
    """Return [(name, start_idx, end_idx)] for one TypeScript file, or None.

    Line indices are 0-indexed and inclusive. None means codegraph is
    unavailable or does not index the file, so the caller falls back to the
    regex extractor.
    """
    cg = CodeGraphExtractor.from_proj_dir(proj_dir)
    return cg.get_function_spans("typescript", filepath) if cg else None

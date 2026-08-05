import re

from src.languages.codegraph import CodeGraphExtractor


_COMMENT_TYPES = {"block_comment", "line_comment"}
_UNICODE_ESCAPE = re.compile(r"\\u+[0-9a-fA-F]{4}")


def remove_comments(code: str) -> str | None:
    """Remove Java comments using Tree-sitter syntax nodes."""
    # JLS 3.3 translates Unicode escapes before comment recognition, while
    # Tree-sitter receives the physical source text. Fall back rather than
    # misclassifying code exposed by an escaped line terminator or delimiter.
    if _UNICODE_ESCAPE.search(code):
        return None
    try:
        import tree_sitter_java as ts_java
        from tree_sitter import Language, Parser
    except (ImportError, OSError):
        return None

    try:
        source = code.encode("utf-8")
        parser = Parser(Language(ts_java.language()))
        tree = parser.parse(source)
    except (TypeError, UnicodeError, ValueError):
        return None

    source_start = 0
    source_end = len(source)
    if tree.root_node.has_error:
        prefix = "class __FM_AGENT_COMMENT_WRAPPER__ {\n".encode("utf-8")
        suffix = "\n}".encode("utf-8")
        try:
            source = prefix + source + suffix
            tree = parser.parse(source)
        except UnicodeError:
            return None
        if tree.root_node.has_error:
            return None
        source_start = len(prefix)
        source_end = source_start + source_end

    cleaned = bytearray(source)
    nodes = [tree.root_node]
    while nodes:
        node = nodes.pop()
        if node.type in _COMMENT_TYPES:
            for index in range(node.start_byte, node.end_byte):
                if cleaned[index] not in (ord("\n"), ord("\r")):
                    cleaned[index] = ord(" ")
            continue
        nodes.extend(node.children)

    return cleaned[source_start:source_end].decode("utf-8")


def batch_extract(proj_dir: str) -> dict:
    """Return {abs_filepath: [(func_name, body)]} for all Java files."""
    cg = CodeGraphExtractor.from_proj_dir(proj_dir)
    return cg.get_functions_by_file("java", proj_dir) if cg else {}


def call_edges(proj_dir: str) -> dict:
    """Return {(caller_stem, caller_module): {callee_stems}} for Java."""
    cg = CodeGraphExtractor.from_proj_dir(proj_dir)
    return cg.get_call_edges("java") if cg else None


def function_spans(proj_dir: str, filepath: str):
    """Return [(name, start_idx, end_idx)] for one Java file, or None.

    Line indices are 0-indexed and inclusive. None means codegraph is
    unavailable or does not index the file, so the caller falls back to the
    regex extractor.
    """
    cg = CodeGraphExtractor.from_proj_dir(proj_dir)
    return cg.get_function_spans("java", filepath) if cg else None

"""CodeGraph-backed extraction helpers for ArkTS."""

from src.languages.codegraph import CodeGraphExtractor


_COMMENT_TYPES = {"comment", "html_comment"}


def remove_comments(code: str) -> str | None:
    """Remove ArkTS comments using the pinned ArkTS Tree-sitter grammar."""
    try:
        import tree_sitter_arkts as ts_arkts
        from tree_sitter import Language, Parser
    except (ImportError, OSError):
        return None

    try:
        source = code.encode("utf-8")
        parser = Parser(Language(ts_arkts.language()))
        tree = parser.parse(source)
    except (TypeError, UnicodeError, ValueError):
        return None

    source_start = 0
    source_end = len(source)
    if tree.root_node.has_error:
        tree = None
        for prefix in (
            b"class __FM_AGENT_COMMENT_WRAPPER__ {\n",
            b"struct __FM_AGENT_COMMENT_WRAPPER__ {\n",
        ):
            wrapped_source = prefix + source + b"\n}"
            try:
                candidate = parser.parse(wrapped_source)
            except (TypeError, UnicodeError, ValueError):
                return None
            if not candidate.root_node.has_error:
                source = wrapped_source
                tree = candidate
                source_start = len(prefix)
                source_end += source_start
                break
        if tree is None:
            return None

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
    """Return {abs_filepath: [(func_name, body)]} for all ArkTS files."""
    cg = CodeGraphExtractor.from_proj_dir(proj_dir)
    return cg.get_functions_by_file("arkts", proj_dir) if cg else {}


def call_edges(proj_dir: str) -> dict:
    """Return CodeGraph call edges for ArkTS."""
    cg = CodeGraphExtractor.from_proj_dir(proj_dir)
    return cg.get_call_edges("arkts") if cg else None


def function_spans(proj_dir: str, filepath: str):
    """Return ArkTS function spans, or None when CodeGraph is unavailable."""
    cg = CodeGraphExtractor.from_proj_dir(proj_dir)
    return cg.get_function_spans("arkts", filepath) if cg else None

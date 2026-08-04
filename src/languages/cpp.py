from src.languages.codegraph import CodeGraphExtractor


def remove_comments(code: str) -> str | None:
    """Remove C++ comments using syntax nodes while preserving line structure.

    Comments are replaced with spaces instead of deleted so tokens separated by
    a comment, such as ``int/**/value``, remain separate after cleaning.
    ``None`` asks the shared parser to use its legacy fallback.
    """
    try:
        import tree_sitter_cpp as ts_cpp
        from tree_sitter import Language, Parser
    except (ImportError, OSError):
        return None

    try:
        source = code.encode("utf-8")
        parser = Parser(Language(ts_cpp.language()))
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
    """Return {abs_filepath: [(func_name, body)]} for all C++ files."""
    cg = CodeGraphExtractor.from_proj_dir(proj_dir)
    return cg.get_functions_by_file("cpp", proj_dir) if cg else {}


def call_edges(proj_dir: str) -> dict:
    """Return {(caller_stem, caller_module): {callee_stems}} for C++."""
    cg = CodeGraphExtractor.from_proj_dir(proj_dir)
    return cg.get_call_edges("cpp") if cg else None


def function_spans(proj_dir: str, filepath: str):
    """Return [(name, start_idx, end_idx)] for one C++ file, or None.

    Line indices are 0-indexed and inclusive. None means codegraph is
    unavailable or does not index the file, so the caller falls back to the
    regex extractor.
    """
    cg = CodeGraphExtractor.from_proj_dir(proj_dir)
    return cg.get_function_spans("cpp", filepath) if cg else None

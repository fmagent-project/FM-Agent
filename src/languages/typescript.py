from src.languages.codegraph import CodeGraphExtractor


_COMMENT_TYPES = {"comment", "html_comment"}


def remove_comments(code: str) -> str | None:
    """Remove TypeScript and TSX comments using Tree-sitter syntax nodes."""
    try:
        import tree_sitter_typescript as ts_typescript
        from tree_sitter import Language, Parser
    except (ImportError, OSError):
        return None

    try:
        source = code.encode("utf-8")
        # The parser receives a language name rather than a .ts/.tsx suffix.
        # Prefer TypeScript, then accept TSX only when TypeScript rejects it.
        grammars = (ts_typescript.language_typescript, ts_typescript.language_tsx)
    except (AttributeError, UnicodeError):
        return None

    tree = None
    try:
        for grammar in grammars:
            parser = Parser(Language(grammar()))
            candidate = parser.parse(source)
            if not candidate.root_node.has_error:
                tree = candidate
                break
    except (TypeError, UnicodeError, ValueError):
        return None

    source_start = 0
    source_end = len(source)
    if tree is None:
        prefix = b"class __FM_AGENT_COMMENT_WRAPPER__ {\n"
        suffix = b"\n}"
        source = prefix + source + suffix
        try:
            for grammar in grammars:
                parser = Parser(Language(grammar()))
                candidate = parser.parse(source)
                if not candidate.root_node.has_error:
                    tree = candidate
                    break
        except (TypeError, UnicodeError, ValueError):
            return None
        if tree is None:
            return None
        source_start = len(prefix)
        source_end += source_start

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

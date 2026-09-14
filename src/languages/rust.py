from collections import defaultdict
import json
import math
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
from urllib.parse import unquote, urlparse

from src.languages.codegraph import CodeGraphExtractor, _node_fqn_map


_RUST_ANALYZER_CACHE = {}


def _rust_analyzer_command() -> list[str] | None:
    """Return the configured rust-analyzer command when it is available."""
    configured = os.environ.get("RUST_ANALYZER_COMMAND", "rust-analyzer").strip()
    if not configured:
        return None
    try:
        command = shlex.split(configured)
    except ValueError:
        return None
    if not command or shutil.which(command[0]) is None:
        return None
    return command


def _run_rust_analyzer_lsif(root: Path) -> str | None:
    """Run rust-analyzer's batch LSIF export, or request codegraph fallback."""
    command = _rust_analyzer_command()
    if command is None:
        return None
    try:
        timeout = float(os.environ.get("RUST_ANALYZER_TIMEOUT_SECONDS", "300"))
    except (TypeError, ValueError, OverflowError):
        timeout = 300.0
    if not math.isfinite(timeout) or timeout <= 0:
        timeout = 300.0
    try:
        result = subprocess.run(
            [*command, "lsif", "."],
            cwd=root,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except (OSError, UnicodeError, subprocess.SubprocessError):
        return None
    if result.returncode != 0 or not result.stdout.strip():
        return None
    return result.stdout


def _parse_rust_lsif(text: str):
    """Parse LSIF JSONL while ignoring diagnostic text on stdout."""
    vertices = {}
    edges = []
    parsed = False
    for line in text.splitlines():
        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(entry, dict) or "id" not in entry:
            continue
        parsed = True
        key = str(entry["id"])
        if entry.get("type") == "vertex":
            vertices[key] = entry
        elif entry.get("type") == "edge":
            edges.append(entry)
    return (vertices, edges) if parsed else None


def _rust_lsif_file_path(uri, root: Path) -> str | None:
    """Convert a file URI to a project-relative POSIX path."""
    if not isinstance(uri, str):
        return None
    try:
        parsed = urlparse(uri)
        if parsed.scheme != "file":
            return None
        return Path(unquote(parsed.path)).resolve().relative_to(root).as_posix()
    except (OSError, ValueError):
        return None


def _rust_function_fqns(extractor, root: Path):
    """Map indexed Rust function ranges to the FQNs used by extraction."""
    import sqlite3

    try:
        connection = sqlite3.connect(extractor._db)
        cursor = connection.cursor()
        fqn_of = _node_fqn_map(cursor, ["rust"])
        rows = cursor.execute(
            """
            SELECT id, file_path, start_line, end_line, start_column, end_column
            FROM nodes
            WHERE kind IN ('function', 'method') AND language = 'rust'
            ORDER BY file_path, start_line
            """
        ).fetchall()
        connection.close()
    except (OSError, sqlite3.Error):
        return None
    functions = defaultdict(list)
    for node_id, file_path, start_line, end_line, start_column, end_column in rows:
        fqn = fqn_of.get(node_id)
        if fqn:
            functions[file_path].append(
                (
                    int(start_line),
                    int(end_line),
                    int(start_column),
                    int(end_column),
                    fqn,
                )
            )
    for file_path, entries in list(functions.items()):
        try:
            canonical = os.path.relpath(os.path.realpath(root / file_path), root)
        except (OSError, ValueError):
            continue
        canonical = canonical.replace(os.sep, "/")
        if canonical != ".." and not canonical.startswith("../"):
            functions.setdefault(canonical, entries)
    return functions


def _rust_function_at(functions, line: int, column: int | None = None, exact_start: bool = False):
    candidates = [item for item in functions if item[0] <= line <= item[1]]
    if column is not None:
        positioned = [
            item
            for item in candidates
            if item[0] != line or item[2] <= column <= item[3]
        ]
        if positioned:
            candidates = positioned
    if exact_start:
        exact = [item for item in candidates if item[0] == line]
        if exact:
            candidates = exact
    return (
        min(candidates, key=lambda item: (item[1] - item[0], item[0], item[2]))
        if candidates
        else None
    )


def _rust_utf16_index(text: str, units: int) -> int:
    consumed = 0
    for index, character in enumerate(text):
        if consumed >= units:
            return index
        consumed += 2 if ord(character) > 0xFFFF else 1
    return len(text)


def _rust_turbofish_is_call(suffix: str) -> bool:
    """Require a call delimiter immediately after balanced generic arguments."""
    stripped = suffix.lstrip()
    if stripped.startswith("::<"):
        generic_start = 2
    elif stripped.startswith("<"):
        generic_start = 0
    else:
        return False

    angle_depth = 0
    delimiters = []
    matching = {")": "(", "]": "[", "}": "{"}
    quote = None
    escaped = False
    index = generic_start
    while index < len(stripped):
        character = stripped[index]
        if quote is not None:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == quote:
                quote = None
            index += 1
            continue
        if character == '"':
            quote = character
        elif character == "'" and index + 2 < len(stripped):
            if stripped[index + 1] == "\\":
                char_end = index + 3
            else:
                char_end = index + 2
            if char_end < len(stripped) and stripped[char_end] == "'":
                quote = character
        elif character in "([{":
            delimiters.append(character)
        elif character in ")]}":
            if delimiters and matching[character] == delimiters[-1]:
                delimiters.pop()
        elif not delimiters and character == "<":
            angle_depth += 1
        elif (
            not delimiters
            and character == ">"
            and (index == 0 or stripped[index - 1] != "-")
        ):
            angle_depth -= 1
            if angle_depth == 0:
                return stripped[index + 1 :].lstrip().startswith("(")
            if angle_depth < 0:
                return False
        index += 1
    return False


def _rust_is_call(source_lines, range_node) -> bool:
    """Check that an LSIF reference token is used as a call, not a value."""
    if not isinstance(range_node, dict):
        return False
    try:
        end = range_node.get("end", {})
        line = int(end.get("line", -1))
        column = int(end.get("character", -1))
    except (TypeError, ValueError):
        return False
    if line < 0 or column < 0 or line >= len(source_lines):
        return False
    suffix = source_lines[line][_rust_utf16_index(source_lines[line], column):]
    if suffix.lstrip().startswith("("):
        return True
    return _rust_turbofish_is_call(suffix)


def _rust_analyzer_cache_key(root: Path, extractor):
    """Return a stable key that changes when the indexed project changes."""
    try:
        stat = os.stat(extractor._db)
        return (str(root), stat.st_mtime_ns, stat.st_size)
    except OSError:
        return None


def _rust_edges_from_lsif(text: str, root: Path, extractor):
    parsed = _parse_rust_lsif(text)
    functions = _rust_function_fqns(extractor, root)
    if parsed is None or functions is None:
        return None
    vertices, edges = parsed
    documents = {
        key: _rust_lsif_file_path(vertex.get("uri"), root)
        for key, vertex in vertices.items()
        if vertex.get("label") == "document"
    }
    ranges = {
        key: vertex
        for key, vertex in vertices.items()
        if vertex.get("label") == "range"
    }
    range_files = {}
    definition_items = defaultdict(set)
    reference_items = defaultdict(set)
    definition_results = defaultdict(set)
    reference_results = defaultdict(set)
    for edge in edges:
        label = edge.get("label")
        if label == "contains":
            range_ids = edge.get("inVs", [])
            if isinstance(range_ids, (list, tuple)):
                for range_id in range_ids:
                    range_files[str(range_id)] = documents.get(str(edge.get("outV")))
        elif label == "item" and edge.get("property") in {None, "definitions", "references"}:
            range_ids = edge.get("inVs", [])
            if not isinstance(range_ids, (list, tuple)):
                continue
            target = (
                definition_items
                if edge.get("property") in {None, "definitions"}
                else reference_items
            )
            target[str(edge.get("outV"))].update(str(value) for value in range_ids)
        elif label == "textDocument/definition":
            definition_results[str(edge.get("outV"))].add(str(edge.get("inV")))
        elif label == "textDocument/references":
            reference_results[str(edge.get("outV"))].add(str(edge.get("inV")))

    result_definitions = defaultdict(set)
    result_references = defaultdict(set)
    for result_set, result_ids in definition_results.items():
        for result_id in result_ids:
            result_definitions[result_set].update(definition_items[result_id])
    for result_set, result_ids in reference_results.items():
        for result_id in result_ids:
            result_references[result_set].update(reference_items[result_id])

    source_cache = {}
    output = []
    seen = set()
    for result_set, reference_ids in result_references.items():
        for reference_id in reference_ids:
            reference = ranges.get(reference_id)
            source_file = range_files.get(reference_id)
            definition_ids = result_definitions.get(result_set, ())
            if reference is None or source_file is None or not definition_ids:
                continue
            if source_file not in source_cache:
                try:
                    source_cache[source_file] = (root / source_file).read_text(
                        encoding="utf-8"
                    ).splitlines()
                except (OSError, UnicodeError):
                    source_cache[source_file] = []
            source_lines = source_cache[source_file]
            if not _rust_is_call(source_lines, reference):
                continue
            try:
                start = reference.get("start", {})
                call_line = int(start.get("line", -1)) + 1
                call_column = int(start.get("character", 0))
            except (TypeError, ValueError):
                continue
            caller = _rust_function_at(
                functions.get(source_file, ()), call_line, call_column
            )
            if caller is None:
                continue
            callee = None
            for definition_id in definition_ids:
                definition = ranges.get(definition_id)
                definition_file = range_files.get(definition_id)
                if definition is None or definition_file is None:
                    continue
                try:
                    definition_line = int(
                        definition.get("start", {}).get("line", -1)
                    ) + 1
                    definition_column = int(
                        definition.get("start", {}).get("character", 0)
                    )
                except (TypeError, ValueError):
                    continue
                target = _rust_function_at(
                    functions.get(definition_file, ()),
                    definition_line,
                    definition_column,
                    exact_start=True,
                )
                if target is not None:
                    callee = target[4]
                    break
            if callee is None or callee == caller[4]:
                continue
            edge = {
                "caller": caller[4],
                "callee": callee,
                "kind": "call",
                "span": {
                    "file": source_file,
                    "start_line": call_line,
                    "start_column": call_column,
                },
            }
            key = (edge["caller"], edge["callee"], source_file, call_line, call_column)
            if key not in seen:
                seen.add(key)
                output.append(edge)
    output.sort(key=lambda edge: (
        edge["span"]["file"], edge["span"]["start_line"], edge["span"]["start_column"]
    ))
    return output


_LINE_PREFIX = re.compile(r"^Line \d+: ?")
_COMMENT_TYPES = {"block_comment", "line_comment"}


def _line_end(node) -> int:
    """Return the inclusive source line containing ``node``'s end."""
    row, column = node.end_point
    return row - 1 if column == 0 and row > node.start_point[0] else row


def _function_block_nodes(root):
    """Return safe top-level Rust block boundaries for one function."""
    stack = list(reversed(root.named_children))
    while stack:
        node = stack.pop()
        if node.type == "function_item":
            body = node.child_by_field_name("body")
            if body is None or body.type != "block":
                return None
            return [child for child in body.named_children if child.type != "comment"]
        stack.extend(reversed(node.named_children))
    return None


def split_blocks(func: str, granularity: int) -> list[str] | None:
    """Split a Rust function at complete top-level syntax nodes.

    ``func`` may carry the ``Line N:`` prefixes added by ``parser.py``. They are
    removed only for parsing; returned chunks retain the original prompt text.
    Returning ``None`` asks the caller to use its regex/brace-depth fallback.
    """
    try:
        import tree_sitter_rust as ts_rust
        from tree_sitter import Language, Parser
    except (ImportError, OSError):
        return None

    prompt_lines = func.strip().split("\n")
    if len(prompt_lines) <= granularity:
        return [func.strip()]

    source = "\n".join(_LINE_PREFIX.sub("", line) for line in prompt_lines)
    try:
        parser = Parser(Language(ts_rust.language()))
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
    """Remove Rust comments using Tree-sitter syntax nodes."""
    try:
        import tree_sitter_rust as ts_rust
        from tree_sitter import Language, Parser
    except (ImportError, OSError):
        return None

    try:
        source = code.encode("utf-8")
        parser = Parser(Language(ts_rust.language()))
        tree = parser.parse(source)
    except (TypeError, UnicodeError, ValueError):
        return None

    if tree.root_node.has_error:
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

    return cleaned.decode("utf-8")


def batch_extract(proj_dir: str) -> dict:
    """Return {abs_filepath: [(func_name, body)]} for all Rust files."""
    cg = CodeGraphExtractor.from_proj_dir(proj_dir)
    return cg.get_functions_by_file("rust", proj_dir) if cg else {}


def call_edges(proj_dir: str) -> dict:
    """Return {(caller_stem, caller_module): {callee_stems}} for Rust."""
    cg = CodeGraphExtractor.from_proj_dir(proj_dir)
    if cg is None:
        return None
    root = Path(cg._db).resolve().parent.parent
    cache_key = _rust_analyzer_cache_key(root, cg)
    if cache_key is not None and cache_key in _RUST_ANALYZER_CACHE:
        cached = _RUST_ANALYZER_CACHE[cache_key]
    elif cache_key is not None:
        semantic_text = _run_rust_analyzer_lsif(root)
        semantic_edges = (
            _rust_edges_from_lsif(semantic_text, root, cg)
            if semantic_text is not None
            else None
        )
        for old_key in list(_RUST_ANALYZER_CACHE):
            if old_key[0] == cache_key[0] and old_key != cache_key:
                del _RUST_ANALYZER_CACHE[old_key]
        _RUST_ANALYZER_CACHE[cache_key] = semantic_edges
        cached = semantic_edges
    else:
        cached = None
    if cached is not None:
        return cached
    return cg.get_call_edges("rust")


def function_spans(proj_dir: str, filepath: str):
    """Return [(name, start_idx, end_idx)] for one Rust file, or None.

    Line indices are 0-indexed and inclusive. None means codegraph is
    unavailable or does not index the file, so the caller falls back to the
    regex extractor.
    """
    cg = CodeGraphExtractor.from_proj_dir(proj_dir)
    return cg.get_function_spans("rust", filepath) if cg else None

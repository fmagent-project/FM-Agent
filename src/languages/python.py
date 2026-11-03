import ast
from collections import defaultdict
import json
import logging
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile

from src.file_utils import _is_test_file
from src.languages.codegraph import CodeGraphExtractor, _node_fqn_map


_PYREFLY_VERSION = "1.4.0"
_CACHE = {}
_LOGGER = logging.getLogger(__name__)


def _function_index(extractor, root):
    with sqlite3.connect(extractor._db) as connection:
        fqns = _node_fqn_map(connection.cursor(), ["python"])
        rows = connection.execute(
            "SELECT id, file_path, start_line, end_line FROM nodes "
            "WHERE language = 'python' AND kind IN ('function', 'method')"
        ).fetchall()
    functions = defaultdict(list)
    for node_id, file, start, end in rows:
        path = (root / file).resolve()
        if node_id in fqns and path.is_relative_to(root) and path.suffix == ".py":
            functions[path].append((start, end, fqns[node_id]))
    return functions


def _position(location):
    start, end = location.split("|", 1)[0].split("-")
    line, column = map(int, start.split(":"))
    end_line, end_column = map(int, end.split(":"))
    return line, column, end_line, end_column


def _source_labels(path):
    source = path.read_text(encoding="utf-8")
    labels = {}
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return labels
    for node in ast.walk(tree):
        if isinstance(node, (ast.Call, ast.Attribute)):
            expression = node.func if isinstance(node, ast.Call) else node
            label = ast.unparse(expression)
            if label:
                labels[(node.lineno, node.col_offset + 1,
                        node.end_lineno, node.end_col_offset + 1)] = label
    return labels


def _report_edges(directory, root, functions):
    identities = {}
    definitions = {}
    classes = {}
    overrides = defaultdict(set)
    modules = {}
    for path in sorted((directory / "definitions").glob("*.json")):
        data = json.loads(path.read_text(encoding="utf-8"))
        if data["format_version"] != 1:
            raise ValueError("Unsupported Pysa report format")
        source = data["source_path"].get("FileSystem")
        if source is None:
            continue
        source = (root / source).resolve()
        if source not in functions:
            continue
        module_id = data["module_id"]
        modules[module_id] = (path.name, source)
        for class_id, definition in data["class_definitions"].items():
            classes[module_id, int(class_id)] = definition
        for function_id, definition in data["function_definitions"].items():
            identity = (module_id, function_id)
            definitions[identity] = {name: definition[name] for name in ("name", "defining_class")
                                     if name in definition}
            if definition.get("name_location"):
                line, *_ = _position(definition["name_location"])
                candidates = [item for item in functions[source] if item[0] <= line <= item[1]]
                if candidates:
                    identities[identity] = min(candidates, key=lambda item: item[1] - item[0])[2]
            base = definition.get("overridden_base_method")
            if base:
                overrides[base["module_id"], base["function_id"]].add(identity)

    def targets(target):
        reference = target["target"]
        expanded = "Overrides" in reference
        reference = reference.get("Overrides", reference.get("Function"))
        if reference is None:
            return (), ()
        identity = (reference["module_id"], reference["function_id"])
        pending = [identity]
        resolved = set()
        receiver = target.get("receiver_class")
        receiver_key = (receiver["module_id"], receiver["class_id"]) if receiver else None
        while pending:
            candidate = pending.pop()
            if candidate in resolved:
                continue
            resolved.add(candidate)
            if expanded:
                pending.extend(overrides.get(candidate, ()))
        if expanded and receiver_key in classes:
            compatible = set()
            for candidate in resolved:
                owner = definitions.get(candidate, {}).get("defining_class")
                if owner is None:
                    compatible.add(candidate)
                    continue
                owner_key = (owner["module_id"], owner["class_id"])
                ancestry = classes.get(owner_key, {}).get("mro", {}).get("Resolved", [])
                receiver_mro = classes[receiver_key].get("mro", {}).get("Resolved", [])
                if (owner_key == receiver_key
                        or any((base["module_id"], base["class_id"]) == receiver_key for base in ancestry)
                        or any((base["module_id"], base["class_id"]) == owner_key for base in receiver_mro)):
                    compatible.add(candidate)
            resolved = compatible
        definition = definitions.get(identity, {})
        owner = definition.get("defining_class")
        aliases = [reference["function_name"]]
        if owner:
            aliases.append(f"{owner['class_name']}.{definition['name']}")
        return resolved, aliases

    output = {}
    covered = set()
    for module_id, (filename, source) in modules.items():
        path = directory / "call_graphs" / filename
        data = json.loads(path.read_text(encoding="utf-8"))
        if data["format_version"] != 1:
            raise ValueError("Unsupported Pysa call graph format")
        labels = _source_labels(source)
        for function_id, sites in data["call_graphs"].items():
            caller = identities.get((module_id, function_id))
            if caller is None:
                continue
            covered.add(caller)
            for location, site in sites.items():
                if "|" in location:
                    continue
                position = _position(location)
                call = site.get("Call", {})
                attribute = site.get("AttributeAccess", {})
                for kind, entries in (
                    ("call", call.get("call_targets", [])),
                    ("constructor", call.get("init_targets", []) + call.get("new_targets", [])),
                    ("call", attribute.get("property_getters", []) + attribute.get("property_setters", [])),
                ):
                    for target in entries:
                        resolved, aliases = targets(target)
                        for identity in sorted(resolved):
                            callee = identities.get(identity)
                            if callee is None:
                                continue
                            key = (caller, callee, kind, source, position)
                            edge = output.setdefault(key, {
                                "caller": caller, "callee": callee, "kind": kind,
                                "info_names": [],
                                "span": {"file": source.relative_to(root).as_posix(),
                                         "start_line": position[0], "start_column": position[1] - 1},
                            })
                            edge["info_names"] = sorted((set(edge["info_names"]) | set(aliases)
                                                         | {labels.get(position, "")}) - {""})
    return list(output.values()), covered


def _pyrefly_edges(extractor):
    root = Path(extractor._db).parent.parent.resolve()
    try:
        functions = _function_index(extractor, root)
        if not functions:
            return None
        files = sorted(path for path in functions if not _is_test_file(path.relative_to(root).as_posix()))
        if not files:
            return None
        paths = {Path(extractor._db), *functions}
        for source in functions:
            for parent in source.parents:
                if not parent.is_relative_to(root):
                    break
                paths.update(path for name in ("pyrefly.toml", "pyproject.toml", "mypy.ini", "pyrightconfig.json")
                             if (path := parent / name).is_file())
        signature = tuple(sorted((str(path), path.stat().st_mtime_ns, path.stat().st_size) for path in paths))
        key = (str(root), sys.executable, signature, tuple(files))
        if key in _CACHE:
            return _CACHE[key]
        version = subprocess.run([sys.executable, "-m", "pyrefly", "--version"],
                                 capture_output=True, text=True, timeout=30, check=False)
        if version.returncode or version.stdout.strip() != f"pyrefly {_PYREFLY_VERSION}":
            raise RuntimeError(f"pyrefly {_PYREFLY_VERSION} is required for Python call edges")
        with tempfile.TemporaryDirectory(prefix="fm-agent-pyrefly-") as temporary:
            report = Path(temporary) / "report"
            result = subprocess.run(
                [sys.executable, "-m", "pyrefly", "check", "--check-unannotated-defs=true",
                 "--infer-return-types", "checked", "--report-pysa", str(report),
                 "--report-pysa-format", "json", "--output-format", "omit-errors", *map(str, files)],
                cwd=root, capture_output=True, text=True, timeout=300, check=False,
            )
            if result.returncode not in (0, 1) or not (report / "definitions").is_dir():
                raise RuntimeError(result.stderr.strip()[-2000:] or "Pysa report was not generated")
            edges = _report_edges(report, root, functions)
        for old_key in list(_CACHE):
            if old_key[0] == str(root):
                del _CACHE[old_key]
        _CACHE[key] = edges
        return edges
    except (OSError, ValueError, KeyError, TypeError, sqlite3.Error, RuntimeError,
            subprocess.SubprocessError) as error:
        _LOGGER.warning("Pyrefly unavailable; using codegraph for Python: %s", error)
        return None


def remove_comments(code: str) -> str | None:
    """Remove Python comments using Tree-sitter syntax nodes."""
    try:
        import tree_sitter_python as ts_python
        from tree_sitter import Language, Parser
    except (ImportError, OSError):
        return None

    try:
        source = code.encode("utf-8")
        parser = Parser(Language(ts_python.language()))
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
    """Return {abs_filepath: [(func_name, body)]} for all Python files."""
    cg = CodeGraphExtractor.from_proj_dir(proj_dir)
    return cg.get_functions_by_file("python", proj_dir) if cg else {}


def call_edges(proj_dir: str) -> list | None:
    """Return type-aware Python calls, with codegraph fallback for uncovered functions."""
    cg = CodeGraphExtractor.from_proj_dir(proj_dir)
    if cg is None:
        return None
    root = Path(cg._db).parent.parent.resolve()
    if (root / "fm_agent" / ".entry_scope_ready").is_file():
        try:
            context = json.loads((root / "fm_agent" / "plugin_context.json").read_text())
            edges = context.get("python_call_edges")
            if (Path(context.get("entry_run_dir", "")).resolve() == root
                    and isinstance(edges, list)):
                return edges
        except (OSError, ValueError, TypeError):
            pass
    analysis = _pyrefly_edges(cg)
    if analysis is None:
        return cg.get_call_edges("python")
    edges, covered = analysis
    combined = [edge for edge in cg.get_call_edges("python")
                if edge["caller"] not in covered or edge["callee"] not in covered] + edges
    return sorted(combined, key=lambda edge: (
        edge.get("span", {}).get("file") or "", edge.get("span", {}).get("start_line") or 0,
        edge.get("span", {}).get("start_column") or 0, edge["caller"], edge["callee"],
    ))


def function_spans(proj_dir: str, filepath: str):
    """Return [(name, start_idx, end_idx)] for one Python file, or None.

    Line indices are 0-indexed and inclusive. None means codegraph is
    unavailable or does not index the file, so the caller falls back to the
    regex extractor.
    """
    cg = CodeGraphExtractor.from_proj_dir(proj_dir)
    return cg.get_function_spans("python", filepath) if cg else None

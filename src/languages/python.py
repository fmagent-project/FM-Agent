from collections import defaultdict
import json
import logging
import os
from pathlib import Path
import shlex
import shutil
import sqlite3
import subprocess
import sys
import tempfile

from src.languages.codegraph import CodeGraphExtractor, _node_fqn_map


_CACHE = {}
_LOGGER = logging.getLogger(__name__)
# Pyrefly's report also records what would run if a value were called
# (Identifier, Define, AttributeAccess if_called); only these are calls.
_PROPERTY_TARGETS = {"property_getters", "property_setters"}


def _pyrefly_command():
    configured = os.environ.get("PYREFLY_COMMAND")
    if configured is not None:
        try:
            command = shlex.split(configured)
        except ValueError:
            return None
        return command if command and shutil.which(command[0]) else None
    bundled = Path(sys.executable).parent / ("pyrefly.exe" if os.name == "nt" else "pyrefly")
    if bundled.is_file():
        return [str(bundled)]
    found = shutil.which("pyrefly")
    return [found] if found else None


def _run_pyrefly(command, root, report_dir):
    environment = {name: value for name, value in os.environ.items() if name != "VIRTUAL_ENV"}
    completed = subprocess.run(
        [*command, "check", "--check-unannotated-defs=true", "--infer-return-types", "checked",
         "--project-excludes", "**/fm_agent/**", "--report-pysa", str(report_dir),
         "--report-pysa-format", "json", "."],
        cwd=root, env=environment, capture_output=True, text=True, encoding="utf-8",
        errors="replace", timeout=600, check=False,
    )
    # Exit status 1 only means pyrefly found type errors.
    if completed.returncode not in (0, 1) or not (report_dir / "pyrefly.pysa.json").is_file():
        raise RuntimeError(completed.stderr.strip()[-2000:] or f"exit status {completed.returncode}")


def _functions(extractor, root):
    with sqlite3.connect(extractor._db) as connection:
        fqns = _node_fqn_map(connection.cursor(), ["python"])
        rows = connection.execute(
            "SELECT id, file_path, start_line, start_column FROM nodes "
            "WHERE language = 'python' AND kind IN ('function', 'method')"
        ).fetchall()
    functions = defaultdict(lambda: defaultdict(list))
    for node_id, file, line, column in rows:
        if node_id in fqns:
            functions[str((root / file).resolve())][line].append((column or 0, fqns[node_id]))
    return functions


def _position(location):
    line, column = location.split("|")[0].split("-")[0].split(":")
    return int(line), int(column)


def _targets(value, path=()):
    if isinstance(value, dict):
        target = value.get("target")
        if isinstance(target, dict):
            for kind in ("Function", "Overrides"):
                if kind in target:
                    yield path, kind, target[kind]
        for key, item in value.items():
            yield from _targets(item, path + (key,))
    elif isinstance(value, list):
        for item in value:
            yield from _targets(item, path)


def _is_call(path):
    if path[:1] == ("Call",):
        return "higher_order_parameters" not in path
    return path[:1] == ("AttributeAccess",) and bool(_PROPERTY_TARGETS.intersection(path))


def _pyrefly_edges(report_dir, root, extractor):
    """Return (edges, covered FQNs, stub call sites) from a pyrefly --report-pysa json report."""
    report = json.loads((report_dir / "pyrefly.pysa.json").read_text(encoding="utf-8"))
    if report.get("format_version") != 1:
        raise ValueError(f"unsupported pyrefly report format {report.get('format_version')!r}")
    functions = _functions(extractor, root)
    # A file can appear twice, as a project module and as the module an import
    # resolves to (`src.pkg` and `pkg`); keep every module of an indexed file.
    files, info, stubs = {}, {}, set()
    for module in report["modules"].values():
        source = (module.get("source_path") or {}).get("FileSystem")
        if not source:
            continue
        file = (root / source).resolve()
        if file.suffix == ".pyi" and file.is_relative_to(root):
            stubs.add(module["module_id"])
        # Callers of a module with a stub resolve into the .pyi, which codegraph
        # does not index; leave such modules to codegraph.
        elif str(file) in functions and not file.with_suffix(".pyi").exists():
            files[module["module_id"]] = file
            info[module["module_id"]] = module["info_filename"]

    # Pyrefly names a function by its name; codegraph starts it at `def`, same line.
    def fqn_at(file, location):
        line, column = _position(location)
        candidates = [item for item in functions.get(str(file), {}).get(line, ()) if item[0] < column]
        return max(candidates)[1] if candidates else None

    fqn_of, owner_of, methods, mro = {}, {}, defaultdict(dict), {}
    for module_id, file in files.items():
        path = report_dir / "definitions" / info[module_id]
        if path.is_file():
            data = json.loads(path.read_text(encoding="utf-8"))
            for function_id, definition in data["function_definitions"].items():
                fqn = fqn_at(file, definition["name_location"]) if "name_location" in definition else None
                if fqn is None:
                    continue
                fqn_of[(module_id, function_id)] = fqn
                owner = definition.get("defining_class")
                if owner:
                    owner_key = (owner["module_id"], owner["class_id"])
                    owner_of[(module_id, function_id)] = owner_key
                    methods[owner_key][definition["name"]] = (module_id, function_id)
            for class_id, definition in data.get("class_definitions", {}).items():
                resolved = (definition.get("mro") or {}).get("Resolved") or []
                mro[(module_id, int(class_id))] = [(base["module_id"], base["class_id"]) for base in resolved]
    subclasses = defaultdict(set)
    for cls, bases in mro.items():
        for base in bases:
            subclasses[base].add(cls)
    resolved_callees = {}

    def callees_of(kind, key, name):
        # An Overrides target may dispatch to any project override of it.
        if (kind, key) not in resolved_callees:
            callees = [fqn_of[key]] if key in fqn_of else []
            if kind == "Overrides" and key in owner_of:
                for subclass in subclasses.get(owner_of[key], ()):
                    override = methods.get(subclass, {}).get(name)
                    if override in fqn_of:
                        callees.append(fqn_of[override])
            resolved_callees[(kind, key)] = callees
        return resolved_callees[(kind, key)]

    edges, covered, stub_sites = {}, set(), set()
    for module_id, file in files.items():
        relative = file.relative_to(root).as_posix()
        path = report_dir / "call_graphs" / info[module_id]
        if path.is_file():
            covered.update(fqn for entries in functions.get(str(file), {}).values() for _column, fqn in entries)
            for function_id, sites in json.loads(path.read_text(encoding="utf-8"))["call_graphs"].items():
                caller = fqn_of.get((module_id, function_id))
                if caller is None:
                    continue
                for site, value in sites.items():
                    line, column = _position(site)
                    for target_path, kind, target in _targets(value):
                        if not _is_call(target_path):
                            continue
                        if target["module_id"] in stubs:
                            stub_sites.add((relative, line, column - 1))
                        key = (target["module_id"], target["function_id"])
                        for callee in callees_of(kind, key, target["function_name"]):
                            span = {"file": relative, "start_line": line, "start_column": column - 1}
                            edges.setdefault((caller, callee, relative, line, column - 1),
                                             {"caller": caller, "callee": callee, "kind": "call", "span": span})
    return list(edges.values()), covered, stub_sites


def _edge_key(edge):
    span = edge.get("span", {})
    return (edge["caller"], edge["callee"], span.get("file"),
            span.get("start_line"), span.get("start_column"))


def _semantic_call_edges(extractor):
    """Replace covered edges with pyrefly's, keeping codegraph where either endpoint is uncovered."""
    fallback = extractor.get_call_edges("python")
    root = Path(extractor._db).parent.parent.resolve()
    try:
        stat = os.stat(extractor._db)
    except OSError:
        return fallback
    key = (str(root), stat.st_mtime_ns, stat.st_size, os.environ.get("PYREFLY_COMMAND"))
    if key not in _CACHE:
        result = None
        command = _pyrefly_command()
        if command is None and os.environ.get("PYREFLY_COMMAND", "x").strip():
            _LOGGER.warning("pyrefly unavailable; using codegraph: pyrefly not found")
        elif command is not None:
            try:
                with tempfile.TemporaryDirectory(prefix="fm-agent-pyrefly-") as directory:
                    report_dir = Path(directory) / "report"
                    _run_pyrefly(command, root, report_dir)
                    result = _pyrefly_edges(report_dir, root, extractor)
            except Exception as error:  # noqa: BLE001 - any failure falls back to codegraph
                _LOGGER.warning("pyrefly unavailable; using codegraph: %s", error)
        for old_key in list(_CACHE):
            if old_key[0] == key[0]:
                del _CACHE[old_key]
        _CACHE[key] = result
    if _CACHE[key] is None or not _CACHE[key][1]:
        return fallback
    semantic, covered, stub_sites = _CACHE[key]
    # Calls pyrefly resolved into a project stub (.pyi) keep codegraph's edge.
    edges = [edge for edge in fallback
             if edge["caller"] not in covered or edge["callee"] not in covered
             or (edge.get("span", {}).get("file"), edge.get("span", {}).get("start_line"),
                 edge.get("span", {}).get("start_column")) in stub_sites]
    unique = {}
    for edge in edges + semantic:
        unique.setdefault(_edge_key(edge), edge)
    return sorted(unique.values(), key=lambda edge: (
        edge.get("span", {}).get("file") or "", edge.get("span", {}).get("start_line") or 0,
        edge.get("span", {}).get("start_column") or 0, edge["caller"], edge["callee"],
    ))


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
    """Return pyrefly call edges, falling back to codegraph where pyrefly cannot help."""
    cg = CodeGraphExtractor.from_proj_dir(proj_dir)
    return _semantic_call_edges(cg) if cg else None


def function_spans(proj_dir: str, filepath: str):
    """Return [(name, start_idx, end_idx)] for one Python file, or None.

    Line indices are 0-indexed and inclusive. None means codegraph is
    unavailable or does not index the file, so the caller falls back to the
    regex extractor.
    """
    cg = CodeGraphExtractor.from_proj_dir(proj_dir)
    return cg.get_function_spans("python", filepath) if cg else None

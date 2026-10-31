from collections import defaultdict
import hashlib
import json
import logging
import os
from pathlib import Path
import shutil
import sqlite3
import subprocess

from src.languages.codegraph import CodeGraphExtractor, _node_fqn_map
from src.file_utils import _is_test_file


_CACHE = {}
_TOOL = Path(__file__).resolve().parents[2] / "tools" / "go-vta"
_LOGGER = logging.getLogger(__name__)


def _run(command, cwd, env=None):
    completed = subprocess.run(
        command, cwd=cwd, capture_output=True, text=True,
        encoding="utf-8", errors="replace", timeout=300, check=False, env=env,
    )
    if completed.returncode:
        raise RuntimeError(completed.stderr.strip()[-2000:])
    return completed.stdout


def _binary(go):
    host_os, host_arch = _run([go, "env", "GOHOSTOS", "GOHOSTARCH"], _TOOL).split()
    build_env = {**os.environ, "GOOS": host_os, "GOARCH": host_arch, "CGO_ENABLED": "0"}
    digest = hashlib.sha256()
    digest.update(_run([go, "version"], _TOOL).encode())
    digest.update(f"{host_os}/{host_arch}".encode())
    for filename in ("main.go", "go.mod", "go.sum"):
        digest.update((_TOOL / filename).read_bytes())
    directory = Path(os.environ.get("XDG_CACHE_HOME", Path.home() / ".cache")) / "fm-agent" / "go-vta"
    directory.mkdir(parents=True, exist_ok=True)
    binary = directory / (digest.hexdigest()[:20] + (".exe" if os.name == "nt" else ""))
    if not binary.exists():
        temporary = binary.with_name(binary.name + f".{os.getpid()}.tmp")
        try:
            _run([go, "build", "-mod=readonly", "-o", str(temporary), "."], _TOOL, env=build_env)
            temporary.replace(binary)
        finally:
            temporary.unlink(missing_ok=True)
    return str(binary)


def _index(extractor, root):
    with sqlite3.connect(extractor._db) as connection:
        fqns = _node_fqn_map(connection.cursor(), ["go"])
        rows = connection.execute(
            "SELECT id, file_path, start_line, end_line, start_column, end_column "
            "FROM nodes WHERE language = 'go' AND kind IN ('function', 'method')"
        ).fetchall()
    functions = defaultdict(list)
    for node_id, file, start, end, column, end_column in rows:
        if node_id in fqns:
            functions[str((root / file).resolve())].append(
                (start, end, column, end_column, fqns[node_id])
            )
    return functions


def _function_at(functions, position):
    candidates = [
        item for item in functions.get(str(Path(position["file"]).resolve()), ())
        if item[0] <= position["line"] <= item[1]
        and (item[0] != position["line"] or position["column"] >= (item[2] or 0))
        and (item[1] != position["line"] or position["column"] <= (item[3] or 10**9))
    ]
    if not candidates:
        return None
    return min(candidates, key=lambda item: (item[1] - item[0], -item[0], -(item[2] or 0)))[-1]


def _module(file, root):
    for directory in Path(file).parents:
        if directory != root and root not in directory.parents:
            break
        if (directory / "go.mod").is_file():
            return directory
    return None


def _edge_key(edge):
    span = edge.get("span", {})
    return (edge["caller"], edge["callee"], span.get("file"),
            span.get("start_line"), span.get("start_column"))


def _analyze(extractor):
    root = Path(extractor._db).parent.parent.resolve()
    go = shutil.which("go")
    if go is None:
        return None
    try:
        functions = _index(extractor, root)
        test_files = tuple(sorted(file for file in functions if file.endswith("_test.go")
                                  and not _is_test_file(Path(file).relative_to(root).as_posix())))
        modules = sorted({module for file in functions if (module := _module(file, root))})
        if not modules:
            return None
        signature = []
        source_paths = [Path(extractor._db)]
        for directory, dirs, files in os.walk(root):
            dirs[:] = [name for name in dirs if name not in {".git", ".codegraph", "fm_agent"}]
            source_paths.extend(Path(directory) / name for name in files
                                if name.endswith(".go") or name in {"go.mod", "go.sum", "go.work", "go.work.sum"})
        for path in source_paths:
            stat = path.stat()
            signature.append((str(path), stat.st_mtime_ns, stat.st_size))
        environment = tuple((name, os.environ.get(name)) for name in (
            "GOFLAGS", "GOOS", "GOARCH", "CGO_ENABLED", "GOWORK", "GOTOOLCHAIN", "GOPROXY",
        ))
        key = (str(root), go, environment, tuple(sorted(signature)), test_files)
        if key in _CACHE:
            return _CACHE[key]
        binary = _binary(go)
        covered = set()
        owners = {}
        edges = {}
        for module in modules:
            try:
                packages = sorted({"./" + Path(file).parent.relative_to(module).as_posix()
                                   for file in functions if _module(file, root) == module})
                tests = [file for file in test_files if _module(file, root) == module]
                options = ["-test-files", json.dumps(tests)] if tests else []
                data = json.loads(_run([binary, *options, str(module), str(root), *packages], module))
                loaded_files = {str(Path(file).resolve()) for file in data["files"]}
                identities = {}
                module_owners = {}
                module_edges = {}
                for function in data["functions"]:
                    owner = _function_at(functions, function["owner"])
                    if owner is None:
                        continue
                    identity = owner
                    if function["closure"]:
                        at = function["at"]
                        identity = f"{owner}::$closure@{at['line']}:{at['column']}"
                        module_owners[identity] = owner
                    identities[function["id"]] = identity
                for edge in data["edges"]:
                    caller = identities.get(edge["caller"])
                    callee = identities.get(edge["callee"])
                    if caller is None or callee is None:
                        continue
                    at = edge["at"]
                    resolved = {
                        "caller": caller, "callee": callee, "kind": "call",
                        "info_names": edge["labels"],
                        "span": {"file": Path(at["file"]).relative_to(root).as_posix(),
                                 "start_line": at["line"], "start_column": at["column"]},
                    }
                    module_edges.setdefault(_edge_key(resolved), resolved)
                for edge_key, resolved in module_edges.items():
                    edges.setdefault(edge_key, resolved)
                owners.update(module_owners)
                covered.update(fqn for file, entries in functions.items() if file in loaded_files
                               for *_span, fqn in entries)
                del data, identities, module_edges
            except (OSError, ValueError, KeyError, TypeError, RuntimeError, subprocess.SubprocessError) as error:
                _LOGGER.warning("Go VTA unavailable for %s; using codegraph: %s", module, error)
        result = (list(edges.values()), owners, covered)
        for old_key in list(_CACHE):
            if old_key[0] == str(root):
                del _CACHE[old_key]
        _CACHE[key] = result
        return result
    except (OSError, ValueError, sqlite3.Error, RuntimeError, subprocess.SubprocessError) as error:
        _LOGGER.warning("Go VTA unavailable; using codegraph: %s", error)
        return None


def _vta_call_edges(extractor, separate_closures=False):
    """Replace covered edges, preserving codegraph when either endpoint is uncovered."""
    analysis = _analyze(extractor)
    if analysis is None:
        return extractor.get_call_edges("go"), {}
    semantic, owners, covered = analysis
    if not covered:
        return extractor.get_call_edges("go"), {}
    edges = [edge for edge in extractor.get_call_edges("go")
             if edge["caller"] not in covered or edge["callee"] not in covered]
    for edge in semantic:
        if separate_closures:
            edges.append(edge)
        else:
            edges.append({**edge, "caller": owners.get(edge["caller"], edge["caller"]),
                          "callee": owners.get(edge["callee"], edge["callee"])})
    unique = {}
    for edge in edges:
        unique.setdefault(_edge_key(edge), edge)
    return sorted(unique.values(), key=lambda edge: (
        edge.get("span", {}).get("file") or "", edge.get("span", {}).get("start_line") or 0,
        edge.get("span", {}).get("start_column") or 0, edge["caller"], edge["callee"],
    )), owners


def remove_comments(code: str) -> str | None:
    """Remove Go comments using Tree-sitter syntax nodes."""
    try:
        import tree_sitter_go as ts_go
        from tree_sitter import Language, Parser
    except (ImportError, OSError):
        return None

    try:
        source = code.encode("utf-8")
        parser = Parser(Language(ts_go.language()))
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
    """Return {abs_filepath: [(func_name, body)]} for all Go files."""
    cg = CodeGraphExtractor.from_proj_dir(proj_dir)
    return cg.get_functions_by_file("go", proj_dir) if cg else {}


def call_edges(proj_dir: str) -> list | None:
    """Return VTA call edges, falling back to codegraph when Go cannot load."""
    cg = CodeGraphExtractor.from_proj_dir(proj_dir)
    if cg is None:
        return None
    root = Path(cg._db).parent.parent.resolve()
    if (root / "fm_agent" / ".entry_scope_ready").is_file():
        try:
            context = json.loads((root / "fm_agent" / "plugin_context.json").read_text())
            edges = context.get("go_call_edges")
            if (Path(context.get("entry_run_dir", "")).resolve() == root
                    and isinstance(edges, list)):
                return edges
        except (OSError, ValueError, TypeError):
            pass
    return _vta_call_edges(cg)[0]


def scope_call_edges(proj_dir: str):
    """Return edges with separate closure nodes and their extracted owners."""
    cg = CodeGraphExtractor.from_proj_dir(proj_dir)
    if cg is None:
        return None, {}
    return _vta_call_edges(cg, separate_closures=True)


def function_spans(proj_dir: str, filepath: str):
    """Return [(name, start_idx, end_idx)] for one Go file, or None.

    Line indices are 0-indexed and inclusive. None means codegraph is
    unavailable or does not index the file, so the caller falls back to the
    regex extractor.
    """
    cg = CodeGraphExtractor.from_proj_dir(proj_dir)
    return cg.get_function_spans("go", filepath) if cg else None

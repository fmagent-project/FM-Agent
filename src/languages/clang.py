"""Clang-backed call edges for C and C++ with codegraph-compatible FQNs."""

import json
import math
import os
import shlex
import shutil
import sqlite3
import subprocess
from collections import defaultdict
from pathlib import Path

from src.languages.codegraph import _node_fqn_map

_CLANG_CACHE = {}
_FUNCTION_KINDS = {
    "FunctionDecl",
    "CXXMethodDecl",
    "CXXConstructorDecl",
    "CXXDestructorDecl",
    "CXXConversionDecl",
}
_CALL_KINDS = {
    "CallExpr",
    "CXXMemberCallExpr",
    "CXXOperatorCallExpr",
    "CUDAKernelCallExpr",
    "UserDefinedLiteral",
}
_CONSTRUCT_KINDS = {"CXXConstructExpr", "CXXTemporaryObjectExpr"}
_C_EXTENSIONS = {".c"}
_CPP_EXTENSIONS = {".cc", ".cp", ".cpp", ".cxx", ".c++", ".C"}
_SOURCE_EXTENSIONS = (
    _C_EXTENSIONS
    | _CPP_EXTENSIONS
    | {
        ".h",
        ".hh",
        ".hpp",
        ".hxx",
        ".h++",
    }
)


def _clang_command(language: str) -> list[str] | None:
    """Return the configured Clang driver, or request codegraph fallback."""
    default = "clang" if language == "c" else "clang++"
    configured = os.environ.get("CLANG_COMMAND", default).strip()
    if not configured:
        return None
    try:
        command = shlex.split(configured)
    except ValueError:
        return None
    if not command or shutil.which(command[0]) is None:
        return None
    return command


def _clang_timeout() -> float:
    try:
        timeout = float(os.environ.get("CLANG_TIMEOUT_SECONDS", "120"))
    except (TypeError, ValueError, OverflowError):
        return 120.0
    return timeout if math.isfinite(timeout) and timeout > 0 else 120.0


def _canonical_relative(path, root: Path, directory: Path | None = None) -> str | None:
    if not isinstance(path, (str, os.PathLike)) or not str(path):
        return None
    try:
        candidate = Path(path)
        if not candidate.is_absolute():
            candidate = (directory or root) / candidate
        return candidate.resolve().relative_to(root).as_posix()
    except (OSError, ValueError):
        return None


def _clang_function_fqns(extractor, root: Path, language: str):
    """Map indexed function ranges to the FQNs used by extraction."""
    connection = None
    try:
        connection = sqlite3.connect(extractor._db)
        cursor = connection.cursor()
        fqn_of = _node_fqn_map(cursor, [language])
        rows = cursor.execute(
            """
            SELECT id, file_path, start_line, end_line, start_column, end_column
            FROM nodes
            WHERE kind IN ('function', 'method') AND language = ?
            ORDER BY file_path, start_line, start_column
            """,
            (language,),
        ).fetchall()
    except (OSError, sqlite3.Error):
        return None
    finally:
        if connection is not None:
            connection.close()

    functions = defaultdict(list)
    all_fqns = set()
    indexed_files = set()
    for node_id, file_path, start_line, end_line, start_column, end_column in rows:
        fqn = fqn_of.get(node_id)
        if not fqn:
            continue
        entry = (
            int(start_line),
            int(end_line),
            int(start_column or 0),
            int(end_column or 0),
            fqn,
        )
        logical = str(file_path).replace("\\", "/")
        functions[logical].append(entry)
        canonical = _canonical_relative(root / file_path, root)
        if canonical:
            functions.setdefault(canonical, functions[logical])
            indexed_files.add(canonical)
        else:
            indexed_files.add(logical)
        all_fqns.add(fqn)
    return functions, all_fqns, indexed_files


def _function_at(entries, line: int, column: int | None = None):
    candidates = [entry for entry in entries if entry[0] <= line <= entry[1]]
    if column is not None:
        positioned = [
            entry
            for entry in candidates
            if (entry[0] != line or entry[2] == 0 or entry[2] <= column)
            and (entry[1] != line or entry[3] == 0 or column <= entry[3])
        ]
        if positioned:
            candidates = positioned
    return (
        min(candidates, key=lambda entry: (entry[1] - entry[0], entry[0], entry[2]))
        if candidates
        else None
    )


def _compile_database_path(root: Path) -> Path | None:
    configured = os.environ.get("CLANG_COMPILE_COMMANDS", "").strip()
    if configured:
        candidate = Path(configured).expanduser()
        if candidate.is_dir():
            candidate /= "compile_commands.json"
        return candidate.resolve() if candidate.is_file() else None
    for candidate in (
        root / "compile_commands.json",
        root / "build" / "compile_commands.json",
    ):
        if candidate.is_file():
            return candidate.resolve()
    return None


def _read_compile_database(path: Path | None):
    if path is None:
        return []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return None
    return data if isinstance(data, list) else None


def _entry_arguments(entry) -> list[str] | None:
    arguments = entry.get("arguments")
    if isinstance(arguments, list) and all(
        isinstance(value, str) for value in arguments
    ):
        return list(arguments)
    command = entry.get("command")
    if not isinstance(command, str):
        return None
    try:
        return shlex.split(command, posix=os.name != "nt")
    except ValueError:
        return None


def _entry_language(path: Path, arguments: list[str]) -> str | None:
    for index, argument in enumerate(arguments):
        if argument == "-x":
            if index + 1 >= len(arguments):
                break
            value = arguments[index + 1].lower()
        elif argument.startswith("-x") and len(argument) > 2:
            value = argument[2:].lower()
        else:
            continue
        if value.startswith("c++"):
            return "cpp"
        if value.startswith("c"):
            return "c"
    if path.suffix in _C_EXTENSIONS:
        return "c"
    if path.suffix in _CPP_EXTENSIONS:
        return "cpp"
    return None


def _clang_tasks(root: Path, language: str, functions, database_path: Path | None):
    database = _read_compile_database(database_path)
    if database is None:
        return None

    tasks = []
    seen = set()
    for entry in database:
        if not isinstance(entry, dict) or not isinstance(entry.get("file"), str):
            continue
        directory = Path(entry.get("directory") or database_path.parent)
        if not directory.is_absolute():
            directory = database_path.parent / directory
        source = Path(entry["file"])
        if not source.is_absolute():
            source = directory / source
        arguments = _entry_arguments(entry)
        if arguments is None or _entry_language(source, arguments) != language:
            continue
        try:
            source = source.resolve()
        except OSError:
            continue
        relative = _canonical_relative(source, root)
        if relative is None or source in seen:
            continue
        seen.add(source)
        tasks.append((source, directory.resolve(), arguments))

    if tasks:
        return tasks

    for relative in functions:
        source = root / relative
        if source.suffix not in _SOURCE_EXTENSIONS:
            continue
        try:
            source = source.resolve()
        except OSError:
            continue
        if source in seen or not source.is_file():
            continue
        seen.add(source)
        tasks.append((source, root, []))
    return tasks


def _same_path(argument: str, source: Path, directory: Path) -> bool:
    try:
        candidate = Path(argument)
        if not candidate.is_absolute():
            candidate = directory / candidate
        return candidate.resolve() == source
    except (OSError, ValueError):
        return False


def _clang_arguments(
    arguments: list[str], source: Path, directory: Path, language: str
):
    """Keep compilation flags while removing output-producing driver arguments."""
    result = []
    skip_next = False
    drop_with_value = {"-o", "-MF", "-MT", "-MQ", "-MJ", "--serialize-diagnostics"}
    drop_exact = {"-c", "-S", "-E", "-M", "-MM", "-MD", "-MMD", "-emit-llvm"}
    wrappers = {"ccache", "sccache", "distcc"}
    start = 1
    if arguments and Path(arguments[0]).stem.lower() in wrappers:
        start = 2
    for argument in arguments[start:]:
        if skip_next:
            skip_next = False
            continue
        if argument in drop_with_value:
            skip_next = True
            continue
        if argument in drop_exact or _same_path(argument, source, directory):
            continue
        if any(argument.startswith(prefix) for prefix in ("-MF", "-MT", "-MQ", "-MJ")):
            continue
        result.append(argument)

    if not any(argument == "-x" or argument.startswith("-x") for argument in result):
        result.extend(["-x", "c" if language == "c" else "c++"])
    result.extend(
        ["-Wno-error", "-fsyntax-only", "-Xclang", "-ast-dump=json", str(source)]
    )
    return result


def _run_clang_ast(command, task, language: str, timeout: float):
    source, directory, arguments = task
    argv = [*command, *_clang_arguments(arguments, source, directory, language)]
    try:
        result = subprocess.run(
            argv,
            cwd=directory,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if result.returncode != 0 or not result.stdout.strip():
        return None
    try:
        ast = json.loads(result.stdout)
    except json.JSONDecodeError:
        return None
    return ast if isinstance(ast, dict) else None


def _location_part(location):
    if not isinstance(location, dict):
        return {}
    expansion = location.get("expansionLoc")
    if isinstance(expansion, dict):
        return expansion
    spelling = location.get("spellingLoc")
    if isinstance(spelling, dict):
        return spelling
    return location


def _location_file(location, root: Path, directory: Path, inherited: str | None):
    part = _location_part(location)
    explicit = part.get("file")
    return _canonical_relative(explicit, root, directory) if explicit else inherited


def _line_from_offset(root: Path, relative: str | None, offset, cache) -> int | None:
    if relative is None:
        return None
    try:
        offset = int(offset)
    except (TypeError, ValueError):
        return None
    if relative not in cache:
        try:
            cache[relative] = (root / relative).read_bytes()
        except OSError:
            cache[relative] = b""
    return cache[relative].count(b"\n", 0, offset) + 1


def _location_position(location, root: Path, relative: str | None, source_cache):
    part = _location_part(location)
    try:
        line = int(part["line"])
    except (KeyError, TypeError, ValueError):
        line = _line_from_offset(root, relative, part.get("offset"), source_cache)
    try:
        column = int(part.get("col", 0))
    except (TypeError, ValueError):
        column = 0
    return line, column


def _symbol_key(node, relative: str | None):
    symbol = node.get("mangledName")
    if not isinstance(symbol, str) or not symbol:
        name = node.get("name")
        function_type = node.get("type", {}).get("qualType")
        if not isinstance(name, str) or not name:
            return None
        symbol = f"{name}\0{function_type or ''}"
    internal = node.get("storageClass") == "static" or "_GLOBAL__N_" in symbol
    return symbol, relative if internal else None


def _call_target_id(node) -> str | None:
    inner = node.get("inner")
    if not isinstance(inner, list) or not inner:
        return None
    stack = [inner[0]]
    while stack:
        current = stack.pop()
        if not isinstance(current, dict):
            continue
        referenced = current.get("referencedDecl")
        if isinstance(referenced, dict) and referenced.get("kind") in _FUNCTION_KINDS:
            identifier = referenced.get("id")
            return str(identifier) if identifier is not None else None
        member = current.get("referencedMemberDecl")
        if member is not None:
            return str(member)
        children = current.get("inner")
        if isinstance(children, list):
            stack.extend(reversed(children))
    return None


def _constructor_key(node):
    constructed = node.get("type", {}).get("qualType")
    signature = node.get("ctorType", node.get("type", {})).get("qualType")
    if not isinstance(constructed, str) or not isinstance(signature, str):
        return None
    constructed = constructed.removeprefix("struct ").removeprefix("class ").strip()
    base_name = constructed.rsplit("::", 1)[-1].split("<", 1)[0].strip()
    return (base_name, signature), constructed


def _constructor_declaration_key(node):
    name = node.get("name")
    signature = node.get("type", {}).get("qualType")
    if not isinstance(name, str) or not isinstance(signature, str):
        return None
    return name.split("<", 1)[0].strip(), signature


def _clang_edges_from_asts(asts, root: Path, functions, all_fqns, indexed_files):
    declaration_symbols = {}
    declaration_fqns = {}
    symbol_fqns = defaultdict(set)
    constructor_fqns = defaultdict(set)
    calls = []
    covered_fqns = set()
    covered_files = set()
    source_cache = {}

    def walk(node, task_index, directory, inherited_file, caller_fqn):
        if not isinstance(node, dict):
            return inherited_file
        kind = node.get("kind")
        location = node.get("loc", {})
        node_file = _location_file(location, root, directory, inherited_file)
        active_caller = caller_fqn
        is_function = kind in _FUNCTION_KINDS

        if is_function:
            line, column = _location_position(location, root, node_file, source_cache)
            match = (
                _function_at(functions.get(node_file, ()), line, column)
                if line is not None
                else None
            )
            identifier = node.get("id")
            key = (task_index, str(identifier)) if identifier is not None else None
            symbol = _symbol_key(node, node_file)
            if key is not None and symbol is not None:
                declaration_symbols[key] = symbol
            if match is not None:
                active_caller = match[4]
                covered_fqns.add(match[4])
                if node_file is not None:
                    covered_files.add(node_file)
                if key is not None:
                    declaration_fqns[key] = match[4]
                if symbol is not None:
                    symbol_fqns[symbol].add(match[4])
                if kind == "CXXConstructorDecl":
                    constructor_key = _constructor_declaration_key(node)
                    if constructor_key is not None:
                        constructor_fqns[constructor_key].add(match[4])

        if kind in _CALL_KINDS and active_caller:
            target = _call_target_id(node)
            if target is not None:
                begin = node.get("range", {}).get("begin", {})
                call_file = _location_file(begin, root, directory, node_file)
                line, column = _location_position(begin, root, call_file, source_cache)
                calls.append(
                    (task_index, active_caller, "call", target, call_file, line, column)
                )
        elif kind in _CONSTRUCT_KINDS and active_caller:
            constructor = _constructor_key(node)
            if constructor is not None:
                begin = node.get("range", {}).get("begin", {})
                call_file = _location_file(begin, root, directory, node_file)
                line, column = _location_position(begin, root, call_file, source_cache)
                calls.append(
                    (
                        task_index,
                        active_caller,
                        "constructor",
                        constructor,
                        call_file,
                        line,
                        column,
                    )
                )

        sibling_file = node_file
        children = node.get("inner")
        if isinstance(children, list):
            for child in children:
                sibling_file = walk(
                    child,
                    task_index,
                    directory,
                    sibling_file,
                    active_caller,
                )
        return node_file if is_function else sibling_file

    for task_index, (ast, source, directory) in enumerate(asts):
        relative = _canonical_relative(source, root)
        walk(ast, task_index, directory, relative, None)

    if all_fqns and (not covered_fqns or not indexed_files <= covered_files):
        return None

    output = []
    seen = set()
    for task_index, caller, kind, target, call_file, line, column in calls:
        if kind == "constructor":
            constructor_key, constructed = target
            candidates = constructor_fqns.get(constructor_key, ())
            if len(candidates) > 1 and "::" in constructed:
                suffix = f"::{constructed}::{constructor_key[0]}"
                candidates = [
                    candidate for candidate in candidates if suffix in candidate
                ]
            callee = next(iter(candidates)) if len(candidates) == 1 else None
        else:
            target_key = (task_index, target)
            callee = declaration_fqns.get(target_key)
            if callee is None:
                symbol = declaration_symbols.get(target_key)
                candidates = symbol_fqns.get(symbol, ())
                if len(candidates) == 1:
                    callee = next(iter(candidates))
        if callee is None or callee == caller:
            continue
        edge = {
            "caller": caller,
            "callee": callee,
            "kind": kind,
            "span": {
                "file": call_file,
                "start_line": line,
                "start_column": column,
            },
        }
        dedup = (caller, callee, call_file, line, column)
        if dedup not in seen:
            seen.add(dedup)
            output.append(edge)
    output.sort(
        key=lambda edge: (
            edge["span"]["file"] or "",
            edge["span"]["start_line"] or 0,
            edge["span"]["start_column"] or 0,
        )
    )
    return output


def _cache_key(root: Path, extractor, language: str, command, database_path):
    try:
        database_stat = os.stat(extractor._db)
        compile_stat = os.stat(database_path) if database_path else None
    except OSError:
        return None
    return (
        language,
        str(root),
        database_stat.st_mtime_ns,
        database_stat.st_size,
        compile_stat.st_mtime_ns if compile_stat else None,
        compile_stat.st_size if compile_stat else None,
        str(database_path) if database_path else None,
        tuple(command),
    )


def call_edges(proj_dir: str, language: str, extractor):
    """Return Clang-resolved edges, or ``None`` to use codegraph."""
    root = Path(extractor._db).resolve().parent.parent
    command = _clang_command(language)
    if command is None:
        return None
    database_path = _compile_database_path(root)
    cache_key = _cache_key(root, extractor, language, command, database_path)
    if cache_key is not None and cache_key in _CLANG_CACHE:
        return _CLANG_CACHE[cache_key]

    indexed = _clang_function_fqns(extractor, root, language)
    if indexed is None:
        result = None
    else:
        functions, all_fqns, indexed_files = indexed
        tasks = _clang_tasks(root, language, functions, database_path)
        if tasks is None or (all_fqns and not tasks):
            result = None
        elif not all_fqns:
            result = []
        else:
            asts = []
            timeout = _clang_timeout()
            for task in tasks:
                ast = _run_clang_ast(command, task, language, timeout)
                if ast is None:
                    asts = None
                    break
                asts.append((ast, task[0], task[1]))
            result = (
                _clang_edges_from_asts(asts, root, functions, all_fqns, indexed_files)
                if asts is not None
                else None
            )

    if cache_key is not None:
        for old_key in list(_CLANG_CACHE):
            if old_key[:2] == cache_key[:2] and old_key != cache_key:
                del _CLANG_CACHE[old_key]
        _CLANG_CACHE[cache_key] = result
    return result

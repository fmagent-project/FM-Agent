"""Clang-backed call edges for C and C++ with codegraph-compatible FQNs."""

import hashlib
import json
import logging
import math
import os
import shlex
import shutil
import sqlite3
import subprocess
import threading
from collections import defaultdict
from pathlib import Path

from src.languages.codegraph import _node_fqn_map

logger = logging.getLogger(__name__)

_CLANG_CACHE = {}
_COMPILE_DATABASE_CACHE = {}
_COMPILE_DATABASE_LOCK = threading.Lock()
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


def _compile_database_timeout() -> float:
    try:
        timeout = float(
            os.environ.get("CLANG_COMPILE_COMMANDS_TIMEOUT_SECONDS", "300")
        )
    except (TypeError, ValueError, OverflowError):
        return 300.0
    return timeout if math.isfinite(timeout) and timeout > 0 else 300.0


def _auto_compile_database_enabled() -> bool:
    value = os.environ.get("CLANG_GENERATE_COMPILE_COMMANDS", "0")
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _bear_build_command(root: Path) -> list[str] | None:
    configured = os.environ.get("CLANG_BEAR_BUILD_COMMAND", "").strip()
    if configured:
        try:
            command = shlex.split(configured)
        except ValueError:
            return None
        return command or None
    if any((root / name).is_file() for name in ("GNUmakefile", "Makefile", "makefile")):
        make = shutil.which("make")
        return [make, "-B"] if make is not None else None
    return None


def _analysis_environment() -> dict[str, str]:
    """Return a build environment without FM-Agent's LLM credentials."""
    environment = os.environ.copy()
    for key in (
        "LLM_API_KEY",
        "OPENAI_API_KEY",
        "ANTHROPIC_API_KEY",
        "OPENROUTER_API_KEY",
    ):
        environment.pop(key, None)
    return environment


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
        all_fqns.add(fqn)
    return functions, all_fqns


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


def _configured_compile_database(root: Path) -> tuple[Path | None, bool]:
    configured = os.environ.get("CLANG_COMPILE_COMMANDS", "").strip()
    if configured:
        candidate = Path(configured).expanduser()
        if candidate.is_dir():
            candidate /= "compile_commands.json"
        return (candidate.resolve() if candidate.is_file() else None), True
    for candidate in (
        root / "compile_commands.json",
        root / "build" / "compile_commands.json",
    ):
        if candidate.is_file():
            return candidate.resolve(), False
    return None, False


def _generate_cmake_compile_database(root: Path) -> Path | None:
    """Configure a CMake project and return its generated compilation database."""
    cmake_file = root / "CMakeLists.txt"
    if not cmake_file.is_file() or not _auto_compile_database_enabled():
        return None
    cmake = shutil.which("cmake")
    ninja = shutil.which("ninja")
    if cmake is None or ninja is None:
        logger.info(
            "Cannot generate compile_commands.json: cmake or ninja is unavailable"
        )
        return None

    try:
        stat = cmake_file.stat()
    except OSError:
        return None
    cache_key = ("cmake", str(root), stat.st_mtime_ns, stat.st_size, cmake, ninja)
    with _COMPILE_DATABASE_LOCK:
        if cache_key in _COMPILE_DATABASE_CACHE:
            return _COMPILE_DATABASE_CACHE[cache_key]

        root_id = hashlib.sha256(str(root).encode("utf-8")).hexdigest()[:12]
        build_dir = root / "fm_agent" / "clang_build" / root_id
        database_path = build_dir / "compile_commands.json"
        try:
            build_dir.mkdir(parents=True, exist_ok=True)
            database_path.unlink(missing_ok=True)
            result = subprocess.run(
                [
                    cmake,
                    "-S",
                    str(root),
                    "-B",
                    str(build_dir),
                    "-G",
                    "Ninja",
                    "-DCMAKE_EXPORT_COMPILE_COMMANDS=ON",
                ],
                cwd=root,
                env=_analysis_environment(),
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=_compile_database_timeout(),
                check=False,
            )
        except (OSError, subprocess.SubprocessError):
            result = None

        generated = (
            database_path.resolve()
            if result is not None
            and result.returncode == 0
            and database_path.is_file()
            else None
        )
        if generated is None:
            detail = ""
            if result is not None:
                lines = [
                    line.strip()
                    for line in (result.stderr or result.stdout).splitlines()
                    if line.strip()
                ]
                detail = f": {' | '.join(lines[-3:])}" if lines else ""
            logger.info("CMake compilation database generation failed%s", detail)
        else:
            print(f"[Clang] Generated compilation database at {generated}")

        for old_key in list(_COMPILE_DATABASE_CACHE):
            if old_key[1] == str(root) and old_key != cache_key:
                del _COMPILE_DATABASE_CACHE[old_key]
        _COMPILE_DATABASE_CACHE[cache_key] = generated
        return generated


def _generate_bear_compile_database(root: Path) -> Path | None:
    """Run a detected or configured build through Bear and return its database."""
    build_command = _bear_build_command(root)
    if build_command is None or not _auto_compile_database_enabled():
        return None
    bear = shutil.which("bear")
    if bear is None:
        logger.info("Cannot generate compile_commands.json: bear is unavailable")
        return None

    cache_key = ("bear", str(root), bear, tuple(build_command))
    with _COMPILE_DATABASE_LOCK:
        if cache_key in _COMPILE_DATABASE_CACHE:
            return _COMPILE_DATABASE_CACHE[cache_key]

        root_id = hashlib.sha256(str(root).encode("utf-8")).hexdigest()[:12]
        build_dir = root / "fm_agent" / "clang_build" / root_id
        database_path = build_dir / "compile_commands.json"
        try:
            build_dir.mkdir(parents=True, exist_ok=True)
            database_path.unlink(missing_ok=True)
            result = subprocess.run(
                [bear, "--output", str(database_path), "--", *build_command],
                cwd=root,
                env=_analysis_environment(),
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=_compile_database_timeout(),
                check=False,
            )
        except (OSError, subprocess.SubprocessError):
            result = None

        generated = (
            database_path.resolve()
            if result is not None
            and result.returncode == 0
            and database_path.is_file()
            else None
        )
        if generated is None:
            detail = ""
            if result is not None:
                lines = [
                    line.strip()
                    for line in (result.stderr or result.stdout).splitlines()
                    if line.strip()
                ]
                detail = f": {' | '.join(lines[-3:])}" if lines else ""
            logger.info("Bear compilation database generation failed%s", detail)
        else:
            print(f"[Clang] Generated compilation database with Bear at {generated}")

        for old_key in list(_COMPILE_DATABASE_CACHE):
            if old_key[1] == str(root) and old_key != cache_key:
                del _COMPILE_DATABASE_CACHE[old_key]
        _COMPILE_DATABASE_CACHE[cache_key] = generated
        return generated


def _compile_database_path(root: Path) -> Path | None:
    existing, explicitly_configured = _configured_compile_database(root)
    if existing is not None:
        return existing
    if explicitly_configured:
        logger.info("Configured CLANG_COMPILE_COMMANDS path does not exist")
        return None
    if not _auto_compile_database_enabled():
        return None
    if (root / "CMakeLists.txt").is_file():
        return _generate_cmake_compile_database(root)
    return _generate_bear_compile_database(root)


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
    if database_path is None:
        return None
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


def _clang_edges_from_asts(asts, root: Path, functions):
    declaration_symbols = {}
    declaration_fqns = {}
    symbol_fqns = defaultdict(set)
    constructor_fqns = defaultdict(set)
    calls = []
    covered_fqns = set()
    source_cache = {}

    def walk(node, task_index, directory, inherited_file, caller_fqn):
        if not isinstance(node, dict):
            return inherited_file
        kind = node.get("kind")
        location = node.get("loc", {})
        node_file = _location_file(location, root, directory, inherited_file)
        active_caller = caller_fqn
        is_function = kind in _FUNCTION_KINDS
        is_mappable_function = is_function and not node.get("isImplicit", False)

        if is_mappable_function:
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
        del ast

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
    return output, covered_fqns


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
    """Return a pure Clang call graph, or request codegraph fallback."""
    root = Path(extractor._db).resolve().parent.parent
    command = _clang_command(language)
    if command is None:
        logger.info("Clang unavailable for %s; using codegraph", language)
        return None
    database_path = _compile_database_path(root)
    cache_key = _cache_key(root, extractor, language, command, database_path)
    if cache_key is not None and cache_key in _CLANG_CACHE:
        return _CLANG_CACHE[cache_key]

    indexed = _clang_function_fqns(extractor, root, language)
    if indexed is None:
        logger.info("Cannot read indexed %s functions; using codegraph", language)
        result = None
    else:
        functions, all_fqns = indexed
        tasks = _clang_tasks(root, language, functions, database_path)
        if tasks is None or (all_fqns and not tasks):
            logger.info("Cannot prepare Clang %s tasks; using codegraph", language)
            result = None
        elif not all_fqns:
            result = []
        else:
            timeout = _clang_timeout()
            task_stats = {"succeeded": 0, "failed": 0}

            def parsed_asts():
                for task in tasks:
                    ast = _run_clang_ast(command, task, language, timeout)
                    if ast is None:
                        task_stats["failed"] += 1
                        logger.debug("Clang failed to parse %s", task[0])
                        continue
                    task_stats["succeeded"] += 1
                    yield ast, task[0], task[1]
                    del ast

            clang_edges, covered_fqns = _clang_edges_from_asts(
                parsed_asts(), root, functions
            )
            successful = (
                task_stats["succeeded"] == len(tasks)
                and covered_fqns == all_fqns
            )
            result = clang_edges if successful else None
            backend = "using Clang only" if successful else "using codegraph only"
            print(
                f"[Clang] {language}: covered {len(covered_fqns)}/"
                f"{len(all_fqns)} functions from {task_stats['succeeded']}/"
                f"{len(tasks)} translation units; {backend}."
            )

    if cache_key is not None:
        for old_key in list(_CLANG_CACHE):
            if old_key[:2] == cache_key[:2] and old_key != cache_key:
                del _CLANG_CACHE[old_key]
        _CLANG_CACHE[cache_key] = result
    return result

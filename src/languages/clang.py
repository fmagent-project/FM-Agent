"""Clang-backed call edges for C and C++ with codegraph-compatible FQNs."""

import functools
import hashlib
import json
import logging
import math
import os
import re
import shlex
import shutil
import signal
import sqlite3
import subprocess
import threading
from collections import defaultdict
from pathlib import Path

from src.languages.codegraph import CodeGraphExtractor, _node_fqn_map, canonicalize

logger = logging.getLogger(__name__)

_LLVM_CACHE = {}
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
_SOURCE_EXTENSIONS_LOWER = {extension.lower() for extension in _C_EXTENSIONS | _CPP_EXTENSIONS}
_CLANG_EXTRACTED_EXTENSIONS = _C_EXTENSIONS | _CPP_EXTENSIONS | {".h", ".hpp"}
_HEADER_EXTENSIONS = {".h", ".hh", ".hpp", ".hxx", ".inc", ".inl", ".ipp", ".tpp"}


@functools.cache
def _homebrew_llvm_bin() -> Path | None:
    brew = shutil.which("brew")
    if brew is None:
        return None
    try:
        result = subprocess.run(
            [brew, "--prefix", "llvm"],
            check=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=10,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if result.returncode != 0 or not result.stdout.strip():
        return None
    llvm_bin = Path(result.stdout.strip()) / "bin"
    return llvm_bin if llvm_bin.is_dir() else None


def _default_llvm_tool(name: str) -> str:
    """Prefer LLVM 15, including Homebrew's keg-only LLVM installation."""
    homebrew_bin = _homebrew_llvm_bin()
    candidates = [f"{name}-15"]
    if homebrew_bin is not None:
        candidates.append(str(homebrew_bin / name))
    candidates.extend(
        [
            f"/opt/homebrew/opt/llvm/bin/{name}",
            f"/usr/local/opt/llvm/bin/{name}",
            name,
        ]
    )
    return next((candidate for candidate in candidates if shutil.which(candidate)), name)


def _configured_tool(name: str, default: str) -> list[str] | None:
    configured = os.environ.get(name, default).strip()
    if not configured:
        return None
    try:
        command = shlex.split(configured)
    except ValueError:
        return None
    if not command or shutil.which(command[0]) is None:
        return None
    return command


def _llvm_link_command() -> list[str] | None:
    return _configured_tool("LLVM_LINK_COMMAND", _default_llvm_tool("llvm-link"))


def _llvm_dis_command() -> list[str] | None:
    return _configured_tool("LLVM_DIS_COMMAND", _default_llvm_tool("llvm-dis"))


def _phasar_command() -> list[str] | None:
    return _configured_tool("PHASAR_CALL_GRAPH_COMMAND", "phasar-cli")


def _clang_command(language: str) -> list[str] | None:
    """Return the configured Clang driver, or request codegraph fallback."""
    default = _default_llvm_tool("clang" if language == "c" else "clang++")
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


def _run_generation_command(
    argv: list[str], root: Path
) -> subprocess.CompletedProcess[str] | None:
    """Run one generator in its own process group and stop the group on timeout."""
    try:
        process = subprocess.Popen(
            argv,
            cwd=root,
            env=_analysis_environment(),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            start_new_session=os.name != "nt",
        )
    except OSError:
        return None

    try:
        stdout, stderr = process.communicate(timeout=_compile_database_timeout())
    except subprocess.TimeoutExpired:
        try:
            if os.name != "nt":
                os.killpg(process.pid, signal.SIGKILL)
            else:
                process.kill()
        except OSError:
            pass
        process.wait()
        if process.stdout is not None:
            process.stdout.close()
        if process.stderr is not None:
            process.stderr.close()
        return None

    return subprocess.CompletedProcess(
        argv,
        process.returncode,
        stdout,
        stderr,
    )


def _run_tool(
    argv: list[str],
    *,
    cwd: Path | None = None,
    timeout: float,
) -> subprocess.CompletedProcess[str] | None:
    """Run an analysis tool and terminate its process tree on timeout."""
    try:
        process = subprocess.Popen(
            argv,
            cwd=cwd,
            env=_analysis_environment(),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            start_new_session=os.name != "nt",
        )
    except OSError:
        return None
    try:
        stdout, stderr = process.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        try:
            if os.name != "nt":
                os.killpg(process.pid, signal.SIGKILL)
            else:
                process.kill()
        except OSError:
            pass
        process.wait()
        return None
    return subprocess.CompletedProcess(argv, process.returncode, stdout, stderr)


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


def _is_owned_analysis_path(path, root: Path, directory: Path) -> bool:
    """Return whether the logical path belongs to FM-Agent's workspace tree."""
    try:
        candidate = Path(path)
        if not candidate.is_absolute():
            candidate = directory / candidate
        relative = Path(os.path.abspath(candidate)).relative_to(root)
    except (OSError, ValueError):
        return False
    return bool(relative.parts) and relative.parts[0] == "fm_agent"


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


def _read_compile_database(path: Path | None):
    if path is None:
        return []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return None
    return data if isinstance(data, list) else None


def _compile_database_artifacts(root: Path) -> tuple[Path, Path]:
    root_id = hashlib.sha256(str(root).encode("utf-8")).hexdigest()[:12]
    build_dir = root / "fm_agent" / "clang_build" / root_id
    return build_dir / "compile_commands.json", build_dir / "generation.json"


def _build_configuration_fingerprint(root: Path, generator: str) -> str:
    """Fingerprint inputs that determine an automatically generated database."""
    fingerprint = hashlib.sha256(generator.encode("ascii"))
    for key in ("CC", "CXX", "CFLAGS", "CXXFLAGS", "CPPFLAGS", "LDFLAGS"):
        fingerprint.update(f"\0{key}={os.environ.get(key, '')}".encode())
    if generator == "bear":
        build_command = _bear_build_command(root) or []
        fingerprint.update(b"\0build-command\0")
        fingerprint.update("\0".join(build_command).encode())
    build_names = {"CMakeLists.txt", "CMakePresets.json"}
    make_names = {"GNUmakefile", "Makefile", "makefile"}
    errors = []
    for directory, subdirectories, filenames in os.walk(root, onerror=errors.append):
        relative_directory = Path(directory).relative_to(root)
        if not relative_directory.parts:
            subdirectories[:] = [
                name
                for name in subdirectories
                if name not in {".git", ".codegraph", "fm_agent"}
            ]
        subdirectories.sort()
        for filename in sorted(filenames):
            path = Path(directory) / filename
            suffix = path.suffix.lower()
            is_source = suffix in _SOURCE_EXTENSIONS_LOWER
            is_build_input = (
                generator == "cmake"
                and (filename in build_names or suffix == ".cmake")
            ) or (
                generator == "bear"
                and (filename in make_names or suffix == ".mk")
            )
            if not is_source and not is_build_input:
                continue
            relative = path.relative_to(root).as_posix()
            fingerprint.update(relative.encode("utf-8", errors="surrogateescape"))
            if is_build_input:
                try:
                    fingerprint.update(path.read_bytes())
                except OSError:
                    fingerprint.update(b"\0unreadable\0")
    for error in errors:
        fingerprint.update(str(error).encode("utf-8", errors="replace"))
    return fingerprint.hexdigest()


def _write_generation_metadata(root: Path, generator: str) -> bool:
    _database_path, metadata_path = _compile_database_artifacts(root)
    metadata = {
        "generator": generator,
        "fingerprint": _build_configuration_fingerprint(root, generator),
    }
    try:
        metadata_path.write_text(json.dumps(metadata, sort_keys=True), encoding="utf-8")
    except OSError:
        return False
    return True


def _generated_compile_database(root: Path) -> Path | None:
    """Return a readable generated database whose build inputs are unchanged."""
    database_path, metadata_path = _compile_database_artifacts(root)
    if not database_path.is_file() or _read_compile_database(database_path) is None:
        return None
    try:
        metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return None
    generator = metadata.get("generator") if isinstance(metadata, dict) else None
    if generator not in {"cmake", "bear"}:
        return None
    expected = _build_configuration_fingerprint(root, generator)
    return (
        database_path.resolve()
        if metadata.get("fingerprint") == expected
        else None
    )


def _has_extracted_clang_sources(root: Path) -> bool:
    """Return whether extraction already emitted files a native build may consume."""
    extracted = root / "fm_agent" / "extracted_functions"
    if not extracted.exists():
        return False
    if not extracted.is_dir():
        return True
    scan_errors = []
    for _directory, _subdirectories, filenames in os.walk(
        extracted, onerror=scan_errors.append
    ):
        if any(
            Path(filename).suffix in _CLANG_EXTRACTED_EXTENSIONS
            for filename in filenames
        ):
            return True
    return bool(scan_errors)


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
    configuration_fingerprint = _build_configuration_fingerprint(root, "cmake")
    cache_key = (
        "cmake",
        str(root),
        stat.st_mtime_ns,
        stat.st_size,
        configuration_fingerprint,
        cmake,
        ninja,
    )
    with _COMPILE_DATABASE_LOCK:
        if cache_key in _COMPILE_DATABASE_CACHE:
            return _COMPILE_DATABASE_CACHE[cache_key]

        database_path, metadata_path = _compile_database_artifacts(root)
        build_dir = database_path.parent
        try:
            build_dir.mkdir(parents=True, exist_ok=True)
            database_path.unlink(missing_ok=True)
            metadata_path.unlink(missing_ok=True)
            (build_dir / "CMakeCache.txt").unlink(missing_ok=True)
            shutil.rmtree(build_dir / "CMakeFiles", ignore_errors=True)
            result = _run_generation_command(
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
                root,
            )
        except OSError:
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
            _write_generation_metadata(root, "cmake")
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
    existing = _generated_compile_database(root)
    if existing is not None:
        return existing
    if _has_extracted_clang_sources(root):
        logger.info(
            "Skipping Bear compilation database generation after function "
            "extraction; using codegraph"
        )
        return None
    bear = shutil.which("bear")
    if bear is None:
        logger.info("Cannot generate compile_commands.json: bear is unavailable")
        return None

    configuration_fingerprint = _build_configuration_fingerprint(root, "bear")
    cache_key = (
        "bear",
        str(root),
        configuration_fingerprint,
        bear,
        tuple(build_command),
    )
    with _COMPILE_DATABASE_LOCK:
        if cache_key in _COMPILE_DATABASE_CACHE:
            return _COMPILE_DATABASE_CACHE[cache_key]

        database_path, metadata_path = _compile_database_artifacts(root)
        build_dir = database_path.parent
        try:
            build_dir.mkdir(parents=True, exist_ok=True)
            database_path.unlink(missing_ok=True)
            metadata_path.unlink(missing_ok=True)
            result = _run_generation_command(
                [bear, "--output", str(database_path), "--", *build_command],
                root,
            )
        except OSError:
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
            _write_generation_metadata(root, "bear")
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
    generated = _generated_compile_database(root)
    if generated is not None:
        return generated
    if (root / "CMakeLists.txt").is_file():
        return _generate_cmake_compile_database(root)
    return _generate_bear_compile_database(root)


def _has_indexed_clang_functions(proj_dir: str) -> bool:
    """Return whether Clang can contribute to the current codegraph index."""
    extractor = CodeGraphExtractor.from_proj_dir(proj_dir)
    if extractor is None:
        return False
    try:
        expected_database = (Path(proj_dir) / ".codegraph" / "codegraph.db").resolve()
        if Path(extractor._db).resolve() != expected_database:
            return False
    except OSError:
        return False
    connection = None
    try:
        connection = sqlite3.connect(extractor._db)
        return (
            connection.execute(
                """
                SELECT 1 FROM nodes
                WHERE kind IN ('function', 'method')
                  AND language IN ('c', 'cpp')
                LIMIT 1
                """
            ).fetchone()
            is not None
        )
    except sqlite3.Error:
        return False
    finally:
        if connection is not None:
            connection.close()


def _project_source_state(root: Path) -> bytes:
    """Fingerprint source paths and stats while excluding FM-Agent artifacts."""
    fingerprint = hashlib.sha256()
    errors = []
    for directory, subdirectories, filenames in os.walk(root, onerror=errors.append):
        relative_directory = Path(directory).relative_to(root)
        if not relative_directory.parts:
            subdirectories[:] = [
                name
                for name in subdirectories
                if name not in {".git", ".codegraph", "fm_agent"}
            ]
        subdirectories.sort()
        for filename in sorted(filenames):
            path = Path(directory) / filename
            if path.suffix.lower() not in _SOURCE_EXTENSIONS_LOWER:
                continue
            try:
                stat = path.stat()
                relative = path.relative_to(root).as_posix()
                fingerprint.update(relative.encode("utf-8", errors="surrogateescape"))
                fingerprint.update(
                    f"\0{stat.st_mtime_ns}:{stat.st_size}\0".encode("ascii")
                )
            except (OSError, ValueError):
                fingerprint.update(str(path).encode("utf-8", errors="surrogateescape"))
                fingerprint.update(b"\0unreadable\0")
    for error in errors:
        fingerprint.update(str(error).encode("utf-8", errors="replace"))
    return fingerprint.digest()


def prepare_compile_database(
    proj_dir: str, languages: tuple[str, ...] | None = None
) -> bool:
    """Prepare an opted-in database and report whether project sources changed."""
    if not _auto_compile_database_enabled():
        return False
    if languages is not None and {"c", "cpp"}.isdisjoint(languages):
        return False
    if not _has_indexed_clang_functions(proj_dir):
        return False
    root = Path(proj_dir).resolve()
    before = _project_source_state(root)
    _compile_database_path(root)
    return before != _project_source_state(root)


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
        if _is_owned_analysis_path(source, root, directory):
            continue
        try:
            source = source.resolve()
        except OSError:
            continue
        relative = _canonical_relative(source, root)
        if (
            relative is None
            or relative == "fm_agent"
            or relative.startswith("fm_agent/")
            or source in seen
        ):
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


def _llvm_arguments(
    arguments: list[str],
    source: Path,
    directory: Path,
    language: str,
    output: Path,
):
    """Turn one compilation-database command into a relocatable LLVM build."""
    result = []
    skip_next = False
    drop_with_value = {
        "-o",
        "-MF",
        "-MT",
        "-MQ",
        "-MJ",
        "--serialize-diagnostics",
    }
    drop_exact = {
        "-c",
        "-S",
        "-E",
        "-M",
        "-MM",
        "-MD",
        "-MMD",
        "-emit-llvm",
    }
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
        [
            "-Wno-error",
            "-O0",
            "-g",
            "-emit-llvm",
            "-c",
            "-o",
            str(output),
            str(source),
        ]
    )
    return result


def _tool_major(command: list[str], version_arg: str = "--version") -> int | None:
    result = _run_tool(command + [version_arg], timeout=10.0)
    if result is None or result.returncode != 0:
        return None
    match = re.search(r"(?:version|LLVM version|clang version)\s+(\d+)", result.stdout)
    return int(match.group(1)) if match else None


def _phasar_llvm_major() -> int | None:
    value = os.environ.get("PHASAR_LLVM_VERSION", "15").strip()
    try:
        major = int(value)
    except ValueError:
        return None
    return major if major > 0 else None


def _project_header_fingerprint(root: Path) -> bytes:
    """Fingerprint project and generated headers that can affect LLVM modules."""
    fingerprint = hashlib.sha256()
    errors = []
    for directory, subdirectories, filenames in os.walk(root, onerror=errors.append):
        relative_directory = Path(directory).relative_to(root)
        if not relative_directory.parts:
            subdirectories[:] = [
                name
                for name in subdirectories
                if name not in {".git", ".codegraph"}
            ]
        elif relative_directory.parts == ("fm_agent",):
            subdirectories[:] = [
                name for name in subdirectories if name == "clang_build"
            ]
        subdirectories.sort()
        for filename in sorted(filenames):
            path = Path(directory) / filename
            if path.suffix.lower() not in _HEADER_EXTENSIONS:
                continue
            try:
                stat = path.stat()
                relative = path.relative_to(root).as_posix()
                fingerprint.update(relative.encode("utf-8", errors="surrogateescape"))
                fingerprint.update(
                    f"\0{stat.st_mtime_ns}:{stat.st_size}\0".encode("ascii")
                )
                with path.open("rb") as stream:
                    while chunk := stream.read(1024 * 1024):
                        fingerprint.update(chunk)
            except (OSError, ValueError):
                fingerprint.update(str(path).encode("utf-8", errors="surrogateescape"))
                fingerprint.update(b"\0unreadable\0")
    for error in errors:
        fingerprint.update(str(error).encode("utf-8", errors="replace"))
    return fingerprint.digest()


def _llvm_cache_directory(
    root: Path,
    database_path: Path,
    language: str,
    tasks,
    commands: list[list[str]],
) -> Path:
    root_id = hashlib.sha256(str(root).encode("utf-8")).hexdigest()[:12]
    fingerprint = hashlib.sha256()
    fingerprint.update(str(database_path).encode("utf-8"))
    try:
        fingerprint.update(str(database_path.stat().st_mtime_ns).encode("ascii"))
    except OSError:
        return root / "fm_agent" / "clang_build" / root_id / "llvm" / "invalid"
    fingerprint.update(_project_header_fingerprint(root))
    for source, _directory, arguments in tasks:
        fingerprint.update(str(source).encode("utf-8"))
        fingerprint.update("\0".join(arguments).encode("utf-8"))
        try:
            stat = source.stat()
            fingerprint.update(f"{stat.st_mtime_ns}:{stat.st_size}".encode("ascii"))
        except OSError:
            fingerprint.update(b"missing")
    for command in commands:
        fingerprint.update("\0".join(command).encode("utf-8"))
    database_id = fingerprint.hexdigest()[:16]
    return root / "fm_agent" / "clang_build" / root_id / "llvm" / language / database_id


def _run_llvm_compile(command, task, language: str, output: Path, timeout: float):
    source, directory, arguments = task
    argv = [
        *command,
        *_llvm_arguments(arguments, source, directory, language, output),
    ]
    result = _run_tool(argv, cwd=directory, timeout=timeout)
    if result is None:
        return False
    if result.returncode != 0 or not output.is_file():
        logger.debug("LLVM IR generation failed for %s: %s", source, result.stderr)
        return False
    return True


def _run_phasar(command, module: Path, output: Path, timeout: float):
    output_dir = output.with_suffix(".phasar")
    try:
        if output_dir.exists():
            for child in output_dir.iterdir():
                if child.is_dir():
                    shutil.rmtree(child)
                else:
                    child.unlink()
        output_dir.mkdir(parents=True, exist_ok=True)
        output.unlink(missing_ok=True)
    except OSError:
        return False
    argv = [
        *command,
        "--silent",
        "--module",
        str(module),
        "--entry-points",
        "__ALL__",
        "--call-graph-analysis",
        "otf",
        "--alias-analysis",
        "cflanders",
        "--emit-cg-as-dot",
        "--out",
        str(output_dir),
    ]
    result = _run_tool(argv, timeout=timeout)
    if result is None:
        return False
    candidates = list(output_dir.rglob("psr-cg.txt"))
    if result.returncode != 0 or not candidates:
        logger.debug("PhASAR call graph failed: %s", result.stderr)
        return False
    try:
        shutil.copyfile(max(candidates, key=lambda path: path.stat().st_mtime_ns), output)
    except OSError:
        return False
    return True


def _parse_phasar_dot(path: Path):
    """Read PhASAR's stable DOT call-graph representation."""
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError):
        return None
    if not re.search(r"\bdigraph\s+CallGraph\s*\{", text):
        return None
    nodes = {}
    for match in re.finditer(
        r'(?m)^\s*(\d+)\s*\[label="((?:\\.|[^"\\])*)"\]\s*;', text
    ):
        label = match.group(2).replace(r'\"', '"').replace(r'\\', '\\')
        nodes[match.group(1)] = label
    if not nodes:
        return None
    edges = []
    for match in re.finditer(
        r"(?m)^\s*(\d+)\s*->\s*(\d+)\s*\[label=", text
    ):
        caller = nodes.get(match.group(1))
        callee = nodes.get(match.group(2))
        if caller and callee:
            edges.append((caller, callee))
    return edges


def _llvm_unescape(value: str) -> str:
    return re.sub(
        r"\\([0-9A-Fa-f]{2})",
        lambda match: bytes([int(match.group(1), 16)]).decode("latin-1"),
        value,
    ).replace(r"\\", "\\").replace(r'\"', '"')


def _metadata_string(record: str, field: str) -> str | None:
    match = re.search(rf'\b{re.escape(field)}:\s*"((?:\\.|[^"\\])*)"', record)
    return _llvm_unescape(match.group(1)) if match else None


def _fqn_matches_debug_name(fqn: str, name: str) -> bool:
    """Match an LLVM source name to an extracted FQN's optional dedup suffix."""
    tail = fqn.rsplit("::", 1)[-1]
    expected = canonicalize(name)
    if tail == expected:
        return True
    prefix = f"{expected}_"
    return tail.startswith(prefix) and tail[len(prefix) :].isdigit()


def _llvm_symbol_fqns(disassembler, module: Path, root: Path, functions, timeout):
    """Map defined LLVM symbols to extracted FQNs through debug locations."""
    result = _run_tool([*disassembler, str(module), "-o", "-"], timeout=timeout)
    if result is None or result.returncode != 0:
        return None
    text = result.stdout
    files = {}
    for match in re.finditer(r"(?m)^!(\d+) = !DIFile\((.*)\)$", text):
        filename = _metadata_string(match.group(2), "filename")
        directory = _metadata_string(match.group(2), "directory") or ""
        if filename:
            files[match.group(1)] = _canonical_relative(
                filename, root, Path(directory) if directory else root
            )
    subprograms = {}
    for match in re.finditer(
        r"(?m)^!(\d+) = (?:distinct )?!DISubprogram\((.*)\)$", text
    ):
        record = match.group(2)
        file_match = re.search(r"\bfile:\s*!(\d+)", record)
        line_match = re.search(r"\bline:\s*(\d+)", record)
        name = _metadata_string(record, "name")
        if file_match and line_match:
            subprograms[match.group(1)] = (
                files.get(file_match.group(1)),
                int(line_match.group(1)),
                name,
            )
    symbols = defaultdict(set)
    defined_symbols = set()
    definition = re.compile(
        r'(?m)^define\b.*?@((?:"(?:\\.|[^"\\])*")|[-$._A-Za-z0-9]+)\s*\(.*?!dbg !(\d+)\s*\{'
    )
    for match in definition.finditer(text):
        symbol = match.group(1)
        if symbol.startswith('"'):
            symbol = _llvm_unescape(symbol[1:-1])
        relative, line, name = subprograms.get(match.group(2), (None, None, None))
        if relative is None or line is None:
            continue
        candidates = functions.get(relative, ())
        if name:
            named = [
                entry
                for entry in candidates
                if _fqn_matches_debug_name(entry[4], name)
            ]
            candidates = named or candidates
        function = _function_at(candidates, line)
        if function is not None:
            symbols[symbol].add(function[4])
            defined_symbols.add(symbol)
    return symbols, defined_symbols


def _phasar_module_edges(
    phasar,
    module: Path,
    local_symbols,
    local_definitions,
    global_symbols,
    global_definitions,
    timeout: float,
):
    """Analyze one translation unit when project-wide linking is impossible."""
    dot = module.with_suffix(".phasar.dot")
    if not dot.is_file() and not _run_phasar(phasar, module, dot, timeout):
        return None
    pairs = _parse_phasar_dot(dot)
    if pairs is None:
        return None
    edges = []
    seen = set()
    for caller_symbol, callee_symbol in pairs:
        callers = local_symbols.get(caller_symbol, ())
        if len(callers) != 1:
            if caller_symbol in local_definitions:
                return None
            continue
        callees = local_symbols.get(callee_symbol, ())
        if not callees:
            callees = global_symbols.get(callee_symbol, ())
        if len(callees) != 1:
            if callee_symbol in global_definitions:
                return None
            continue
        caller = next(iter(callers))
        callee = next(iter(callees))
        if caller == callee or (caller, callee) in seen:
            continue
        seen.add((caller, callee))
        edges.append({"caller": caller, "callee": callee, "kind": "call"})
    return edges


def _ast_symbol_fqns(asts, root: Path, functions):
    """Collect Clang symbol identities as a fallback for sparse debug metadata."""
    symbols = defaultdict(set)

    def walk(node, directory, inherited_file):
        if not isinstance(node, dict):
            return inherited_file
        location = node.get("loc", {})
        node_file = _location_file(location, root, directory, inherited_file)
        if node.get("kind") in _FUNCTION_KINDS and not node.get("isImplicit", False):
            line, column = _location_position(location, root, node_file, {})
            match = (
                _function_at(functions.get(node_file, ()), line, column)
                if line is not None
                else None
            )
            symbol = _symbol_key(node, node_file)
            if match is not None and symbol is not None:
                symbols[symbol[0]].add(match[4])
        child_file = node_file
        children = node.get("inner")
        if isinstance(children, list):
            for child in children:
                child_file = walk(child, directory, child_file)
        return node_file if node.get("kind") in _FUNCTION_KINDS else child_file

    for ast, _source, directory in asts:
        walk(ast, directory, None)
        del ast
    return symbols


def _llvm_call_edges(root: Path, language: str, extractor):
    """Build a whole-language call graph with LLVM IR and PhASAR only."""
    compiler = _clang_command(language)
    linker = _llvm_link_command()
    disassembler = _llvm_dis_command()
    phasar = _phasar_command()
    if compiler is None or linker is None or disassembler is None or phasar is None:
        return None
    compiler_major = _tool_major(compiler)
    linker_major = _tool_major(linker)
    disassembler_major = _tool_major(disassembler)
    expected_phasar_major = _phasar_llvm_major()
    if (
        compiler_major is None
        or linker_major is None
        or disassembler_major is None
        or compiler_major != linker_major
        or compiler_major != disassembler_major
        or expected_phasar_major != compiler_major
    ):
        logger.info(
            "LLVM toolchain mismatch for %s "
            "(clang=%s llvm-link=%s llvm-dis=%s phasar=%s)",
            language,
            compiler_major,
            linker_major,
            disassembler_major,
            expected_phasar_major,
        )
        return None
    database_path = _compile_database_path(root)
    indexed = _clang_function_fqns(extractor, root, language)
    if indexed is None:
        return None
    functions, all_fqns = indexed
    tasks = _clang_tasks(root, language, functions, database_path)
    if not all_fqns or not tasks:
        return None
    work_dir = _llvm_cache_directory(
        root,
        database_path,
        language,
        tasks,
        [compiler, linker, disassembler, phasar],
    )
    try:
        work_dir.mkdir(parents=True, exist_ok=True)
    except OSError:
        return None
    cache_key = (
        language,
        str(root),
        str(work_dir),
        tuple(compiler),
        tuple(linker),
        tuple(disassembler),
        tuple(phasar),
    )
    if cache_key in _LLVM_CACHE:
        return _LLVM_CACHE[cache_key]
    modules = []
    for index, task in enumerate(tasks):
        task_id = hashlib.sha256(
            (str(task[0]) + "\0" + "\0".join(task[2])).encode("utf-8")
        ).hexdigest()[:16]
        module = work_dir / f"tu-{index}-{task_id}.bc"
        if not module.is_file() and not _run_llvm_compile(
            compiler, task, language, module, _clang_timeout()
        ):
            result = None
            break
        modules.append(module)
    else:
        linked = work_dir / "project.bc"
        if not linked.is_file():
            link = _run_tool(
                [*linker, *map(str, modules), "-o", str(linked)],
                timeout=_clang_timeout(),
            )
            if link is None or link.returncode != 0 or not linked.is_file():
                per_module_edges = []
                per_module_failed = False
                module_symbol_data = []
                global_symbols = defaultdict(set)
                global_definitions = set()
                for module in modules:
                    symbol_data = _llvm_symbol_fqns(
                        disassembler, module, root, functions, _clang_timeout()
                    )
                    if symbol_data is None:
                        per_module_failed = True
                        break
                    local_symbols, local_definitions = symbol_data
                    module_symbol_data.append((local_symbols, local_definitions))
                    global_definitions.update(local_definitions)
                    for symbol, fqns in local_symbols.items():
                        global_symbols[symbol].update(fqns)
                for module, symbol_data in zip(modules, module_symbol_data):
                    if per_module_failed:
                        break
                    local_symbols, local_definitions = symbol_data
                    module_edges = _phasar_module_edges(
                        phasar,
                        module,
                        local_symbols,
                        local_definitions,
                        global_symbols,
                        global_definitions,
                        _clang_timeout(),
                    )
                    if module_edges is None:
                        per_module_failed = True
                        break
                    per_module_edges.extend(module_edges)
                if per_module_failed or not per_module_edges:
                    result = None
                else:
                    result = {}
                    seen = set()
                    for edge in per_module_edges:
                        key = (edge["caller"], edge["callee"])
                        if key not in seen:
                            seen.add(key)
                            result.setdefault("edges", []).append(edge)
                    result = result.get("edges", [])
            else:
                result = True
        else:
            result = True
        if result is True:
            dot = work_dir / "phasar-callgraph.dot"
            if not dot.is_file() and not _run_phasar(
                phasar, linked, dot, _clang_timeout()
            ):
                result = None
        if result is True:
            pairs = _parse_phasar_dot(dot)
            symbol_data = _llvm_symbol_fqns(
                disassembler, linked, root, functions, _clang_timeout()
            )
            if pairs is None or symbol_data is None:
                result = None
            else:
                symbol_fqns, defined_symbols = symbol_data
                edges = []
                seen = set()
                for caller_symbol, callee_symbol in pairs:
                    caller_candidates = symbol_fqns.get(caller_symbol, ())
                    callee_candidates = symbol_fqns.get(callee_symbol, ())
                    if len(caller_candidates) != 1 or len(callee_candidates) != 1:
                        if (
                            caller_symbol in defined_symbols
                            or callee_symbol in defined_symbols
                        ):
                            result = None
                            break
                        continue
                    caller = next(iter(caller_candidates))
                    callee = next(iter(callee_candidates))
                    if caller == callee:
                        continue
                    edge = {"caller": caller, "callee": callee, "kind": "call"}
                    key = (caller, callee)
                    if key not in seen:
                        seen.add(key)
                        edges.append(edge)
                else:
                    mapped = set().union(*symbol_fqns.values()) if symbol_fqns else set()
                    result = edges if mapped.intersection(all_fqns) else None
                if result is not None:
                    print(
                        f"[Clang] {language}: PhASAR mapped {len(mapped & all_fqns)}/"
                        f"{len(all_fqns)} indexed functions from {len(tasks)} "
                        "translation units."
                    )
    if cache_key is not None:
        _LLVM_CACHE[cache_key] = result
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
                    (
                        task_index,
                        active_caller,
                        "call",
                        target,
                        call_file,
                        line,
                        column,
                    )
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
    """Return a pure LLVM/PhASAR call graph, or request CodeGraph fallback."""
    root = Path(extractor._db).resolve().parent.parent
    result = _llvm_call_edges(root, language, extractor)
    if result is None:
        logger.info("LLVM/PhASAR unavailable for %s; using codegraph", language)
    else:
        print(f"[Clang] {language}: using LLVM/PhASAR call graph only.")
    return result

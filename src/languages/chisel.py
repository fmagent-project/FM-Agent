"""Chisel language service with direct CIRCT and source fallback backends.

Chisel is embedded in Scala, but FM-Agent analysis units are hardware modules,
not arbitrary Scala declarations. This handler owns Scala-aware declaration
scanning, module classification, source spans, and module-instantiation edges.
When configured with elaborated FIRRTL, a direct CIRCT pass provides the
authoritative module graph. Source scanning remains available as a conservative
fallback when the optional toolchain cannot run.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import shlex
import shutil
import subprocess
import tempfile
import threading
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path

from src.file_utils import _is_test_file
from src.languages.codegraph import canonicalize
from src.languages.hardware import (
    CHISEL_EXTENSIONS,
    is_excluded_source_directory,
)


_MODULE_ROOTS = frozenset({
    "Module",
    "RawModule",
    "BlackBox",
    "ExtModule",
    "MultiIOModule",
})
_MODIFIER = (
    r"(?:"
    r"(?:private|protected)(?:\[[\w.]+\])?"
    r"|final|sealed|abstract|implicit|lazy|override|case"
    r")"
)
_DECLARATION_RE = re.compile(
    r"^(?:" + _MODIFIER + r"\s+)*"
    r"(?P<kind>class|object|trait|def)\s+"
    r"(?P<name>[A-Za-z_$][\w$]*)"
)
_LOCAL_DECLARATION_RE = re.compile(
    r"\b(?:class|object|trait)\s+([A-Za-z_$][\w$]*)"
)
_NEW_MODULE_RE = re.compile(
    r"\bnew\s+"
    r"(?P<name>[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*)"
)
_DYNAMIC_MODULE_RE = re.compile(r"\bModule\s*\((?!\s*new\b)")
_PACKAGE_RE = re.compile(
    r"^\s*package\s+([A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*)"
    r"\s*(?:\{)?\s*$",
    re.MULTILINE,
)

_CIRCT_INPUT_ENV = "FM_AGENT_CHISEL_CIRCT_INPUT"
_CIRCT_COMMAND_ENV = "FM_AGENT_CHISEL_CIRCT_COMMAND"
_CIRCT_PLUGIN_ENV = "FM_AGENT_CHISEL_CIRCT_PLUGIN"
_CIRCT_TIMEOUT_ENV = "FM_AGENT_CHISEL_CIRCT_TIMEOUT_SECONDS"
_CIRCT_GRAPH_FILENAME = "chisel_circt_module_graph.json"
_CIRCT_SCHEMA_VERSION = 1
_DEFAULT_CIRCT_TIMEOUT_SECONDS = 180
_PLUGIN_FILENAMES = (
    "libFMAgentChiselCirctPlugin.so",
    "FMAgentChiselCirctPlugin.so",
    "libFMAgentChiselCirctPlugin.dylib",
    "FMAgentChiselCirctPlugin.dylib",
)

_CIRCT_CACHE: dict[tuple[str, str], "CirctGraph | None"] = {}
_CIRCT_DIAGNOSTICS: set[tuple[str, str]] = set()
_CIRCT_CACHE_LOCK = threading.Lock()


@dataclass(frozen=True)
class ChiselUnit:
    """One top-level Scala declaration and its source metadata."""

    abs_path: str
    rel_path: str
    source: str
    kind: str
    name: str
    parent: str | None
    span: tuple[int, int] | None
    package: str | None = None
    fqn: str | None = None


@dataclass(frozen=True)
class CirctModule:
    """One module record emitted directly by the CIRCT pass."""

    name: str
    symbol: str
    kind: str
    location_file: str | None = None
    location_line: int | None = None
    location_column: int | None = None


@dataclass(frozen=True)
class CirctGraph:
    """Validated direct-pass module graph."""

    top: str | None
    modules: tuple[CirctModule, ...]
    edges: dict[str, tuple[str, ...]]
    source: str = "direct-pass"


@dataclass(frozen=True)
class ChiselAnalysis:
    """One project scan, including handled-empty files."""

    files: tuple[str, ...]
    declarations: tuple[ChiselUnit, ...]
    modules: tuple[ChiselUnit, ...]
    circt_graph: CirctGraph | None = None
    circt_units_by_symbol: dict[str, tuple[ChiselUnit, ...]] | None = None


def _project_root(proj_dir: str | Path) -> Path:
    root = Path(os.path.abspath(proj_dir))
    return root.parent if root.name == "fm_agent" else root


def _work_dir(proj_dir: str | Path) -> Path:
    root = Path(os.path.abspath(proj_dir))
    return root if root.name == "fm_agent" else root / "fm_agent"


def _circt_timeout_seconds() -> int:
    raw = os.environ.get(
        _CIRCT_TIMEOUT_ENV,
        str(_DEFAULT_CIRCT_TIMEOUT_SECONDS),
    )
    try:
        return max(1, int(raw))
    except ValueError:
        logging.warning(
            "Invalid %s=%r; using %d seconds",
            _CIRCT_TIMEOUT_ENV,
            raw,
            _DEFAULT_CIRCT_TIMEOUT_SECONDS,
        )
        return _DEFAULT_CIRCT_TIMEOUT_SECONDS


def _circt_command() -> list[str]:
    raw = os.environ.get(_CIRCT_COMMAND_ENV, "firtool").strip() or "firtool"
    command = shlex.split(raw, posix=os.name != "nt")
    return command or ["firtool"]


def _input_format(path: Path) -> str:
    lowered = path.name.lower()
    if lowered.endswith(".fir"):
        return "fir"
    if lowered.endswith(".mlir"):
        return "mlir"
    raise RuntimeError(
        f"unsupported CIRCT input format for {path}; expected .fir or .mlir"
    )


def _escape_pass_option(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"')


def _graph_pipeline(output_path: Path) -> str:
    escaped = _escape_pass_option(str(output_path))
    return (
        "firrtl.circuit("
        f'fm-agent-emit-chisel-module-graph{{output-file="{escaped}"}}'
        ")"
    )


def _normalize_circt_graph(data: object) -> CirctGraph | None:
    if not isinstance(data, dict):
        return None
    if data.get("schema_version") != _CIRCT_SCHEMA_VERSION:
        return None
    modules_data = data.get("modules")
    edges_data = data.get("edges")
    if not isinstance(modules_data, list) or not isinstance(edges_data, dict):
        return None

    modules = []
    symbols = set()
    for item in modules_data:
        if not isinstance(item, dict):
            return None
        name = item.get("name")
        symbol = item.get("symbol", name)
        kind = item.get("kind", "module")
        if not all(
            isinstance(value, str) and value
            for value in (name, symbol, kind)
        ):
            return None
        if symbol in symbols:
            return None
        symbols.add(symbol)
        location = item.get("location")
        if location is not None and not isinstance(location, dict):
            return None
        location = location or {}
        location_file = location.get("file")
        location_line = location.get("line")
        location_column = location.get("column")
        if location_file is not None and not isinstance(location_file, str):
            return None
        for value in (location_line, location_column):
            if value is not None and (type(value) is not int or value < 0):
                return None
        modules.append(
            CirctModule(
                name=name,
                symbol=symbol,
                kind=kind,
                location_file=location_file,
                location_line=location_line,
                location_column=location_column,
            )
        )
    if not modules:
        return None

    edges = {}
    for caller, callees in edges_data.items():
        if not isinstance(caller, str) or not isinstance(callees, list):
            return None
        if not all(isinstance(callee, str) for callee in callees):
            return None
        edges[caller] = tuple(sorted(set(callees)))

    top = data.get("top")
    source = data.get("source", "direct-pass")
    if top is not None and not isinstance(top, str):
        return None
    if not isinstance(source, str):
        return None
    return CirctGraph(
        top=top,
        modules=tuple(modules),
        edges=edges,
        source=source,
    )


def _circt_graph_data(graph: CirctGraph) -> dict[str, object]:
    return {
        "schema_version": _CIRCT_SCHEMA_VERSION,
        "top": graph.top,
        "modules": [
            {
                "name": module.name,
                "symbol": module.symbol,
                "kind": module.kind,
                "location": (
                    {
                        "file": module.location_file,
                        "line": module.location_line,
                        "column": module.location_column,
                    }
                    if module.location_file is not None
                    else None
                ),
            }
            for module in graph.modules
        ],
        "edges": {
            caller: list(callees)
            for caller, callees in sorted(graph.edges.items())
        },
        "source": graph.source,
    }


class _CirctBackend:
    """Discover and invoke firtool with the direct module-graph pass."""

    def __init__(self, proj_dir: str | Path, source_files: tuple[str, ...]):
        self.project = _project_root(proj_dir)
        self.work_dir = _work_dir(proj_dir)
        self.source_files = source_files

    @property
    def input_path(self) -> Path | None:
        raw = os.environ.get(_CIRCT_INPUT_ENV, "").strip()
        if not raw:
            return None
        path = Path(raw)
        if not path.is_absolute():
            path = self.project / path
        return Path(os.path.abspath(path))

    @property
    def graph_path(self) -> Path:
        return self.work_dir / _CIRCT_GRAPH_FILENAME

    def _plugin_candidates(self):
        raw = os.environ.get(_CIRCT_PLUGIN_ENV, "").strip()
        if raw:
            configured = Path(raw)
            if not configured.is_absolute():
                configured = self.project / configured
            yield configured

        repository = Path(__file__).resolve().parents[2]
        tool_root = repository / "tools" / "chisel-circt" / "build"
        for directory in (tool_root / "lib", tool_root / "plugin", tool_root):
            for filename in _PLUGIN_FILENAMES:
                yield directory / filename
        local_lib = Path.home() / ".local" / "lib"
        for filename in _PLUGIN_FILENAMES:
            yield local_lib / filename

    @property
    def plugin_path(self) -> Path | None:
        configured = os.environ.get(_CIRCT_PLUGIN_ENV, "").strip()
        if configured:
            path = Path(configured)
            if not path.is_absolute():
                path = self.project / path
            path = Path(os.path.abspath(path))
            return path if path.is_file() else None
        return next(
            (Path(os.path.abspath(path)) for path in self._plugin_candidates() if path.is_file()),
            None,
        )

    def _fingerprint(self, input_path: Path, plugin_path: Path) -> str:
        def record(path: Path) -> tuple[str, int, int]:
            stat = path.stat()
            return (str(path), stat.st_size, stat.st_mtime_ns)

        payload = {
            "command": _circt_command(),
            "input": record(input_path),
            "plugin": record(plugin_path),
            "sources": [record(Path(path)) for path in self.source_files],
        }
        encoded = json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()

    def _load_persisted(self, fingerprint: str) -> CirctGraph | None:
        try:
            with self.graph_path.open("r", encoding="utf-8") as file:
                data = json.load(file)
        except (OSError, UnicodeDecodeError, json.JSONDecodeError):
            return None
        if not isinstance(data, dict) or data.get("project_fingerprint") != fingerprint:
            return None
        return _normalize_circt_graph(data)

    def _persist(self, graph: CirctGraph, fingerprint: str) -> None:
        self.work_dir.mkdir(parents=True, exist_ok=True)
        document = {
            **_circt_graph_data(graph),
            "status": "success",
            "backend": "llvm/circt",
            "circt_command": _circt_command(),
            "circt_plugin": str(self.plugin_path),
            "project_fingerprint": fingerprint,
        }
        temporary = self.graph_path.with_suffix(".json.tmp")
        try:
            with temporary.open("w", encoding="utf-8") as file:
                json.dump(document, file, indent=2, ensure_ascii=False)
                file.write("\n")
            temporary.replace(self.graph_path)
        except OSError:
            temporary.unlink(missing_ok=True)
            raise

    def _run(self, input_path: Path, plugin_path: Path) -> CirctGraph:
        command = _circt_command()
        executable = command[0]
        if shutil.which(executable) is None and not Path(executable).is_file():
            raise RuntimeError(f"CIRCT command was not found: {executable}")

        self.work_dir.mkdir(parents=True, exist_ok=True)
        descriptor, output_name = tempfile.mkstemp(
            prefix=".chisel_circt_graph.",
            suffix=".json",
            dir=self.work_dir,
        )
        os.close(descriptor)
        output_path = Path(output_name)
        output_path.unlink(missing_ok=True)
        argv = [
            *command,
            str(input_path),
            f"--format={_input_format(input_path)}",
            "--disable-output",
            f"--load-pass-plugin={plugin_path}",
            f"--high-firrtl-pass-plugin={_graph_pipeline(output_path)}",
        ]
        try:
            completed = subprocess.run(
                argv,
                cwd=self.project,
                check=True,
                capture_output=True,
                text=True,
                timeout=_circt_timeout_seconds(),
            )
            del completed
            try:
                with output_path.open("r", encoding="utf-8") as file:
                    data = json.load(file)
            except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise RuntimeError(
                    "CIRCT pass did not produce a valid JSON graph"
                ) from exc
            graph = _normalize_circt_graph(data)
            if graph is None:
                raise RuntimeError("CIRCT pass produced an unsupported graph schema")
            return graph
        except subprocess.TimeoutExpired as exc:
            raise RuntimeError(
                f"CIRCT graph command timed out after {_circt_timeout_seconds()}s"
            ) from exc
        except subprocess.CalledProcessError as exc:
            stderr = (exc.stderr or "").strip()
            detail = f": {stderr}" if stderr else ""
            raise RuntimeError(f"CIRCT graph command failed{detail}") from exc
        finally:
            output_path.unlink(missing_ok=True)

    def graph_or_none(self) -> CirctGraph | None:
        input_path = self.input_path
        if input_path is None:
            return None
        cache_key: tuple[str, str] | None = None
        try:
            if not input_path.is_file():
                raise RuntimeError(f"CIRCT input path does not exist: {input_path}")
            plugin_path = self.plugin_path
            if plugin_path is None:
                raise RuntimeError(
                    "FM-Agent Chisel CIRCT plugin was not found; set "
                    f"{_CIRCT_PLUGIN_ENV}"
                )
            fingerprint = self._fingerprint(input_path, plugin_path)
            cache_key = (str(self.project), fingerprint)
            with _CIRCT_CACHE_LOCK:
                if cache_key in _CIRCT_CACHE:
                    return _CIRCT_CACHE[cache_key]

            graph = self._load_persisted(fingerprint)
            if graph is None:
                graph = self._run(input_path, plugin_path)
                try:
                    self._persist(graph, fingerprint)
                except OSError as exc:
                    logging.warning(
                        "Unable to persist the direct CIRCT Chisel graph: %s",
                        exc,
                    )
            with _CIRCT_CACHE_LOCK:
                _CIRCT_CACHE[cache_key] = graph
            return graph
        except Exception as exc:
            if cache_key is not None:
                with _CIRCT_CACHE_LOCK:
                    _CIRCT_CACHE[cache_key] = None
            diagnostic_key = (str(self.project), str(exc))
            with _CIRCT_CACHE_LOCK:
                first_report = diagnostic_key not in _CIRCT_DIAGNOSTICS
                _CIRCT_DIAGNOSTICS.add(diagnostic_key)
            if first_report:
                logging.warning(
                    "Direct CIRCT Chisel analysis unavailable; using source "
                    "fallback: %s",
                    exc,
                )
            return None


def _clear_circt_cache_for_tests() -> None:
    with _CIRCT_CACHE_LOCK:
        _CIRCT_CACHE.clear()
        _CIRCT_DIAGNOSTICS.clear()


def _iter_chisel_files(proj_dir: str | Path):
    project = _project_root(proj_dir)
    if not project.is_dir():
        return
    for current_root, dirnames, filenames in os.walk(project):
        dirnames[:] = sorted(
            name
            for name in dirnames
            if not is_excluded_source_directory(name)
        )
        root = Path(current_root)
        for filename in sorted(filenames):
            path = root / filename
            if path.suffix.lower() not in CHISEL_EXTENSIONS:
                continue
            rel_path = path.relative_to(project).as_posix()
            if _is_test_file(rel_path):
                continue
            yield path, rel_path


def _skip_quoted(text: str, index: int, quote: str) -> int:
    index += 1
    while index < len(text):
        if text[index] == "\n":
            return index
        if text[index] == "\\":
            index += 2
            continue
        if text[index] == quote:
            return index + 1
        index += 1
    return index


def _skip_character(text: str, index: int) -> int:
    """Skip a Scala character literal without consuming legacy symbols."""
    if (
        index + 3 < len(text)
        and text[index + 1] == "\\"
        and text[index + 3] == "'"
    ):
        return index + 4
    if index + 2 < len(text) and text[index + 2] == "'":
        return index + 3
    return index + 1


def mask_non_code(text: str) -> str:
    """Mask Scala comments and string/character literals, preserving layout."""
    masked = list(text)
    index = 0
    block_depth = 0
    in_triple = False

    while index < len(text):
        char = text[index]
        following = text[index + 1] if index + 1 < len(text) else ""

        if in_triple:
            if text[index:index + 3] == '\"\"\"':
                masked[index:index + 3] = "   "
                in_triple = False
                index += 3
            else:
                if char != "\n":
                    masked[index] = " "
                index += 1
            continue

        if block_depth:
            if char == "/" and following == "*":
                masked[index:index + 2] = "  "
                block_depth += 1
                index += 2
            elif char == "*" and following == "/":
                masked[index:index + 2] = "  "
                block_depth -= 1
                index += 2
            else:
                if char != "\n":
                    masked[index] = " "
                index += 1
            continue

        if char == "/" and following == "/":
            while index < len(text) and text[index] != "\n":
                masked[index] = " "
                index += 1
            continue
        if char == "/" and following == "*":
            masked[index:index + 2] = "  "
            block_depth += 1
            index += 2
            continue
        if text[index:index + 3] == '\"\"\"':
            masked[index:index + 3] = "   "
            in_triple = True
            index += 3
            continue
        if char == '"':
            end = _skip_quoted(text, index, char)
            for position in range(index, min(end, len(text))):
                if masked[position] != "\n":
                    masked[position] = " "
            index = end
            continue
        if char == "'":
            end = _skip_character(text, index)
            for position in range(index, min(end, len(text))):
                if masked[position] != "\n":
                    masked[position] = " "
            index = end
            continue
        index += 1

    return "".join(masked)


def _line_depths(masked_lines: list[str]) -> list[int]:
    depths = []
    depth = 0
    for line in masked_lines:
        depths.append(depth)
        depth += line.count("{") - line.count("}")
    return depths


def _matching_block_end(
    masked_lines: list[str],
    start_line: int,
) -> int:
    depth = 0
    opened = False
    for line_index in range(start_line, len(masked_lines)):
        for char in masked_lines[line_index]:
            if char == "{":
                depth += 1
                opened = True
            elif char == "}":
                depth -= 1
                if opened and depth == 0:
                    return line_index
    return len(masked_lines) - 1


def _package_block_line(line: str) -> bool:
    stripped = line.strip()
    return stripped.startswith("package ") and stripped.endswith("{")


def _signature_end(masked_lines: list[str], start_line: int) -> int:
    parens = 0
    brackets = 0
    saw_extends = False
    for line_index in range(start_line, len(masked_lines)):
        stripped = masked_lines[line_index].strip()
        if not stripped and line_index > start_line:
            continue
        parens += stripped.count("(") - stripped.count(")")
        brackets += stripped.count("[") - stripped.count("]")
        saw_extends = saw_extends or "extends" in stripped
        if "{" in stripped and parens <= 0 and brackets <= 0:
            return line_index
        if parens > 0 or brackets > 0:
            continue
        if stripped.endswith(("extends", "with", ",")):
            continue
        next_line = next(
            (
                masked_lines[index].strip()
                for index in range(line_index + 1, len(masked_lines))
                if masked_lines[index].strip()
            ),
            "",
        )
        if next_line.startswith(("(", "extends ", "with ")):
            continue
        if next_line == "{":
            return line_index + 1
        if saw_extends or line_index == start_line:
            return line_index
    return len(masked_lines) - 1


def _declaration_end(masked_lines: list[str], start_line: int) -> int:
    signature_end = _signature_end(masked_lines, start_line)
    signature = " ".join(masked_lines[start_line:signature_end + 1])
    if "{" not in signature:
        return signature_end
    return _matching_block_end(masked_lines, start_line)


def _parent_from_signature(signature: str) -> str | None:
    match = re.search(
        r"\bextends\s+([A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*)",
        signature,
    )
    return match.group(1).rsplit(".", 1)[-1] if match else None


def _package_name(masked_text: str) -> str | None:
    packages = _PACKAGE_RE.findall(masked_text)
    return ".".join(packages) if packages else None


def _declarations(path: Path, rel_path: str) -> list[ChiselUnit]:
    text = path.read_text(encoding="utf-8", errors="replace")
    source_lines = text.splitlines()
    masked_text = mask_non_code(text)
    masked_lines = masked_text.splitlines()
    depths = _line_depths(masked_lines)
    package_blocks: list[tuple[int, int]] = []
    units = []
    line_index = 0

    while line_index < len(masked_lines):
        package_blocks = [
            block for block in package_blocks if line_index <= block[1]
        ]
        in_package_top = any(
            depths[line_index] == depth and line_index <= end
            for depth, end in package_blocks
        )
        if depths[line_index] != 0 and not in_package_top:
            line_index += 1
            continue

        stripped = masked_lines[line_index].lstrip()
        if _package_block_line(masked_lines[line_index]):
            package_blocks.append(
                (
                    depths[line_index] + 1,
                    _matching_block_end(masked_lines, line_index),
                )
            )
            line_index += 1
            continue
        if stripped.startswith(("package ", "import ")):
            line_index += 1
            continue

        match = _DECLARATION_RE.match(stripped)
        if match is None:
            line_index += 1
            continue

        end_line = _declaration_end(masked_lines, line_index)
        signature_end = _signature_end(masked_lines, line_index)
        signature = " ".join(
            masked_lines[line_index:signature_end + 1]
        )
        units.append(
            ChiselUnit(
                abs_path=os.path.abspath(path),
                rel_path=rel_path,
                source="\n".join(source_lines[line_index:end_line + 1]) + "\n",
                kind=match.group("kind"),
                name=match.group("name"),
                parent=_parent_from_signature(signature),
                span=(line_index, end_line),
                package=_package_name(masked_text),
            )
        )
        line_index = end_line + 1

    return units


def _module_units(units: list[ChiselUnit]) -> tuple[ChiselUnit, ...]:
    declarations_by_name: dict[str, list[int]] = defaultdict(list)
    for index, unit in enumerate(units):
        if unit.kind == "class":
            declarations_by_name[unit.name].append(index)

    resolved: dict[int, bool] = {}
    visiting: set[int] = set()

    def is_module(index: int) -> bool:
        if index in resolved:
            return resolved[index]
        if index in visiting:
            return False
        visiting.add(index)
        unit = units[index]
        result = unit.kind == "class" and unit.parent in _MODULE_ROOTS
        if unit.kind == "class" and unit.parent and not result:
            result = any(
                is_module(parent_index)
                for parent_index in declarations_by_name.get(unit.parent, ())
            )
        visiting.remove(index)
        resolved[index] = result
        return result

    return tuple(
        unit for index, unit in enumerate(units) if is_module(index)
    )


def _analyze_sources(proj_dir: str | Path) -> ChiselAnalysis:
    files = []
    declarations = []
    for path, rel_path in _iter_chisel_files(proj_dir):
        files.append(os.path.abspath(path))
        try:
            declarations.extend(_declarations(path, rel_path))
        except OSError as exc:
            logging.warning("Unable to read Chisel source %s: %s", path, exc)
    return ChiselAnalysis(
        files=tuple(files),
        declarations=tuple(declarations),
        modules=_module_units(declarations),
    )


def _resolve_circt_location(
    project: Path,
    location_file: str | None,
    source_files: tuple[str, ...],
) -> str | None:
    if not location_file:
        return None
    location = Path(location_file)
    candidates = []
    if location.is_absolute():
        candidates.append(Path(os.path.abspath(location)))
    else:
        candidates.extend([
            Path(os.path.abspath(project / location)),
            Path(os.path.abspath(project / str(location).lstrip("./"))),
        ])
    source_set = set(source_files)
    for candidate in candidates:
        if str(candidate) in source_set:
            return str(candidate)

    basename_matches = [
        path for path in source_files if Path(path).name == location.name
    ]
    return basename_matches[0] if len(basename_matches) == 1 else None


def _match_circt_module(
    project: Path,
    module: CirctModule,
    analysis: ChiselAnalysis,
) -> ChiselUnit | None:
    declarations = [
        unit for unit in analysis.declarations if unit.kind == "class"
    ]
    resolved_file = _resolve_circt_location(
        project,
        module.location_file,
        analysis.files,
    )
    if resolved_file is not None:
        same_file = [
            unit for unit in declarations if unit.abs_path == resolved_file
        ]
        exact_name = [unit for unit in same_file if unit.name == module.name]
        if len(exact_name) == 1:
            return exact_name[0]
        if module.location_line is not None:
            target = max(0, module.location_line - 1)
            containing = [
                unit
                for unit in same_file
                if unit.span is not None
                and unit.span[0] <= target <= unit.span[1]
            ]
            if len(containing) == 1:
                return containing[0]
            if same_file:
                return min(
                    same_file,
                    key=lambda unit: abs((unit.span or (0, 0))[0] - target),
                )

    exact_name = [unit for unit in declarations if unit.name == module.name]
    return exact_name[0] if len(exact_name) == 1 else None


def _apply_circt_graph(
    proj_dir: str | Path,
    analysis: ChiselAnalysis,
    graph: CirctGraph,
) -> ChiselAnalysis:
    project = _project_root(proj_dir)
    by_symbol: dict[str, list[ChiselUnit]] = defaultdict(list)
    matched_units = set()
    unmatched = []
    for module in graph.modules:
        unit = _match_circt_module(project, module, analysis)
        if unit is None:
            unmatched.append(module.symbol)
            continue
        matched_units.add(unit)
        by_symbol[module.symbol].append(unit)
        if module.name != module.symbol:
            by_symbol[module.name].append(unit)

    if not matched_units:
        logging.warning(
            "Direct CIRCT graph contained %d module(s), but none mapped to "
            "Chisel source declarations; using source fallback",
            len(graph.modules),
        )
        return analysis

    if unmatched:
        logging.warning(
            "Direct CIRCT graph has %d generated or unmapped module(s); "
            "they will not become specification units: %s",
            len(unmatched),
            ", ".join(sorted(unmatched)[:5]),
        )

    selected = tuple(
        unit for unit in analysis.declarations if unit in matched_units
    )
    return ChiselAnalysis(
        files=analysis.files,
        declarations=analysis.declarations,
        modules=selected,
        circt_graph=graph,
        circt_units_by_symbol={
            symbol: tuple(dict.fromkeys(units))
            for symbol, units in by_symbol.items()
        },
    )


def _analyze(proj_dir: str | Path) -> ChiselAnalysis:
    analysis = _analyze_sources(proj_dir)
    if not analysis.files:
        return analysis
    graph = _CirctBackend(proj_dir, analysis.files).graph_or_none()
    if graph is None:
        return analysis
    return _apply_circt_graph(proj_dir, analysis, graph)


def _deduped_records(
    analysis: ChiselAnalysis,
    *,
    spans: bool,
) -> dict[str, list[tuple]]:
    grouped: dict[str, list[tuple]] = {
        path: [] for path in analysis.files
    }
    counts: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    for unit in analysis.modules:
        name = canonicalize(unit.name)
        count = counts[unit.abs_path][name]
        counts[unit.abs_path][name] += 1
        deduped = name if count == 0 else f"{name}_{count}"
        if spans:
            if unit.span is not None:
                grouped[unit.abs_path].append(
                    (deduped, unit.span[0], unit.span[1])
                )
        else:
            grouped[unit.abs_path].append((deduped, unit.source))
    return grouped


def batch_extract(proj_dir: str) -> dict[str, list[tuple[str, str]]]:
    """Return module units, retaining empty lists for handled Chisel files."""
    return _deduped_records(_analyze(proj_dir), spans=False)


def function_spans(proj_dir: str, filepath: str):
    """Return module spans; Chisel files with no modules are handled-empty."""
    path = Path(os.path.abspath(filepath))
    if path.suffix.lower() not in CHISEL_EXTENSIONS or not path.is_file():
        return None
    analysis = _analyze(proj_dir)
    records = _deduped_records(analysis, spans=True)
    return records.get(str(path), [])


def _source_unit_fqn(unit: ChiselUnit, extracted_name: str | None = None) -> str:
    source_path = Path(unit.rel_path)
    dashed = f"{source_path.stem}-{source_path.suffix.lstrip('.')}"
    parts = [
        *source_path.parent.parts,
        dashed,
        canonicalize(extracted_name or unit.name),
    ]
    return "::".join(part for part in parts if part not in {"", "."})


def _source_units_with_fqns(
    modules: tuple[ChiselUnit, ...],
) -> list[tuple[str, ChiselUnit]]:
    counts: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    result = []
    for unit in modules:
        name = canonicalize(unit.name)
        count = counts[unit.abs_path][name]
        counts[unit.abs_path][name] += 1
        extracted_name = name if count == 0 else f"{name}_{count}"
        result.append((_source_unit_fqn(unit, extracted_name), unit))
    return result


def _extracted_unit_fqn(relative_path: Path) -> str:
    return "::".join(relative_path.with_suffix("").parts)


def _extracted_modules(proj_dir: str | Path) -> tuple[ChiselUnit, ...]:
    extracted_root = _work_dir(proj_dir) / "extracted_functions"
    if not extracted_root.is_dir():
        return ()
    units = []
    for path in sorted(extracted_root.rglob("*")):
        if not path.is_file() or path.suffix.lower() not in CHISEL_EXTENSIONS:
            continue
        relative_path = path.relative_to(extracted_root)
        declarations = _declarations(path, relative_path.as_posix())
        for unit in declarations:
            if unit.kind != "class":
                continue
            units.append(
                ChiselUnit(
                    abs_path=unit.abs_path,
                    rel_path=unit.rel_path,
                    source=unit.source,
                    kind=unit.kind,
                    name=unit.name,
                    parent=unit.parent,
                    span=unit.span,
                    package=unit.package,
                    fqn=_extracted_unit_fqn(relative_path),
                )
            )
    return tuple(units)


def _local_declaration_names(source: str, own_name: str) -> set[str]:
    names = set(_LOCAL_DECLARATION_RE.findall(mask_non_code(source)))
    names.discard(own_name)
    return names


def _instantiated_names(source: str) -> set[str]:
    return {
        match.group("name")
        for match in _NEW_MODULE_RE.finditer(mask_non_code(source))
    }


def _resolve_target(
    reference: str,
    candidates: list[tuple[str, ChiselUnit]],
) -> list[str]:
    if len(candidates) <= 1:
        return [fqn for fqn, _unit in candidates]
    qualifier, separator, _name = reference.rpartition(".")
    if separator:
        qualified = [
            fqn
            for fqn, unit in candidates
            if unit.package == qualifier
            or (unit.package and unit.package.endswith("." + qualifier))
        ]
        if len(qualified) == 1:
            return qualified
    logging.warning(
        "Skipping ambiguous Chisel module reference %s; candidates: %s",
        reference,
        ", ".join(sorted(fqn for fqn, _unit in candidates)),
    )
    return []


def _direct_circt_edges(analysis: ChiselAnalysis) -> dict[str, set[str]]:
    graph = analysis.circt_graph
    units_by_symbol = analysis.circt_units_by_symbol or {}
    if graph is None:
        return {}

    fqn_by_unit = {
        unit: fqn for fqn, unit in _source_units_with_fqns(analysis.modules)
    }
    edges: dict[str, set[str]] = defaultdict(set)
    unmapped_edges = 0
    for caller_symbol, callee_symbols in graph.edges.items():
        callers = units_by_symbol.get(caller_symbol, ())
        for callee_symbol in callee_symbols:
            callees = units_by_symbol.get(callee_symbol, ())
            if not callers or not callees:
                unmapped_edges += 1
                continue
            for caller in callers:
                for callee in callees:
                    caller_fqn = fqn_by_unit.get(caller)
                    callee_fqn = fqn_by_unit.get(callee)
                    if (
                        caller_fqn is not None
                        and callee_fqn is not None
                        and caller_fqn != callee_fqn
                    ):
                        edges[caller_fqn].add(callee_fqn)
    if unmapped_edges:
        logging.warning(
            "Ignored %d direct CIRCT edge(s) whose source specification unit "
            "could not be mapped",
            unmapped_edges,
        )
    return dict(edges)


def call_edges(proj_dir: str) -> dict[str, set[str]]:
    """Return conservative module-instantiation edges for Chisel units."""
    analysis = _analyze(proj_dir)
    if analysis.circt_graph is not None:
        return _direct_circt_edges(analysis)

    extracted = _extracted_modules(proj_dir)
    if extracted:
        units_with_fqns = [
            (unit.fqn or _extracted_unit_fqn(Path(unit.rel_path)), unit)
            for unit in extracted
        ]
    else:
        units_with_fqns = _source_units_with_fqns(
            analysis.modules
        )

    by_name: dict[str, list[tuple[str, ChiselUnit]]] = defaultdict(list)
    for fqn, unit in units_with_fqns:
        by_name[unit.name].append((fqn, unit))

    edges: dict[str, set[str]] = defaultdict(set)
    for caller_fqn, caller in units_with_fqns:
        shadowed = _local_declaration_names(caller.source, caller.name)
        if _DYNAMIC_MODULE_RE.search(mask_non_code(caller.source)):
            logging.warning(
                "Chisel source fallback could not resolve one or more dynamic "
                "Module(...) constructions in %s",
                caller_fqn,
            )
        for reference in _instantiated_names(caller.source):
            simple_name = reference.rsplit(".", 1)[-1]
            if simple_name in shadowed:
                continue
            for callee_fqn in _resolve_target(
                reference,
                by_name.get(simple_name, []),
            ):
                if callee_fqn != caller_fqn:
                    edges[caller_fqn].add(callee_fqn)
    return dict(edges)

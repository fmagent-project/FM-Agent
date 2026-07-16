"""Chisel extraction and module-graph backend.

This backend keeps Chisel support inside the normal FM-Agent language registry:

  * ``batch_extract(proj_dir)`` returns extracted hardware-module units
  * ``call_edges(proj_dir)`` returns the module-instantiation graph
  * ``function_spans(proj_dir, filepath)`` returns extracted unit spans

Chisel is Scala-based, but the analysis unit here is intentionally conservative:
only hardware modules are extracted as standalone units. Bundles and other
supporting declarations remain source context inside extracted modules.

When CIRCT inputs are provided, this backend invokes a CIRCT-backed helper
tool that runs a real FIRRTL pass and emits an authoritative module graph.
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

from src.file_utils import _is_test_file
from src.languages.codegraph import canonicalize


_MODULE_ROOTS = {"Module", "RawModule", "ExtModule", "BlackBox", "MultiIOModule"}
_MODULE_PARENT_SUFFIXES = ("Module", "ModuleImp", "RawModule", "Shell")
_NON_MODULE_PARENT_SUFFIXES = (
    "Backend",
    "Binder",
    "IOBinder",
    "Overlay",
    "PlacedOverlay",
    "Placer",
    "ShellPlacer",
    "Params",
    "TypeParams",
    "Config",
    "Field",
)
_SOURCE_EXTS = (".scala", ".sc")
_LOCAL_DECL_RE = re.compile(r"\b(?:class|object|trait)\s+([A-Za-z_$][\w$]*)")
_MOD = (
    r'(?:'
    r'(?:private|protected)(?:\[[\w.]+\])?'
    r'|final|sealed|abstract|implicit|lazy|override|case'
    r')'
)
_DECL_RE = re.compile(
    r'^(?:' + _MOD + r'\s+)*'
    r'(?P<kind>class|object|trait|def)\s+'
    r'(?P<name>[A-Za-z_$][\w$]*)'
)
_CIRCT_INPUT_ENV = "FM_AGENT_CHISEL_CIRCT_INPUT"
_CIRCT_COMMAND_ENV = "FM_AGENT_CHISEL_CIRCT_COMMAND"
_CIRCT_PLUGIN_ENV = "FM_AGENT_CHISEL_CIRCT_PLUGIN"
_CIRCT_TIMEOUT_ENV = "FM_AGENT_CHISEL_CIRCT_TIMEOUT_SECONDS"
_LANG_KEY = "chisel"
_DEFAULT_TIMEOUT_SECONDS = 180
_GRAPH_FILENAME = "chisel_module_graph.json"
_LEGACY_GRAPH_FILENAME = "chisel_circt_module_graph.json"
_SKIP_DIRS = {
    ".git",
    ".codegraph",
    "node_modules",
    "__pycache__",
    "venv",
    ".venv",
    "fm_agent",
    "extracted_functions",
    "spec_prompts",
}

_GRAPH_CACHE: dict[str, tuple[tuple, "CirctGraph | None"]] = {}
_ANALYSIS_CACHE: dict[str, tuple[tuple, "ChiselAnalysis"]] = {}
_CACHE_LOCK = threading.Lock()

@dataclass(frozen=True)
class ChiselUnit:
    """One top-level Scala declaration plus the metadata FM-Agent needs."""

    abs_path: str
    rel_path: str
    source: str
    kind: str | None
    name: str
    parent: str | None = None
    span: tuple[int, int] | None = None
    fqn: str | None = None


@dataclass(frozen=True)
class CirctGraph:
    """Authoritative module set and instantiation edges from CIRCT."""

    top: str | None
    modules: tuple["CirctModule", ...]
    edges: dict[str, tuple[str, ...]]
    source: str = "unknown"

    @property
    def module_names(self) -> tuple[str, ...]:
        return tuple(module.name for module in self.modules)


@dataclass(frozen=True)
class CirctModule:
    name: str
    kind: str
    symbol: str
    location_file: str | None = None
    location_line: int | None = None
    location_column: int | None = None
    location_end_line: int | None = None
    location_end_column: int | None = None


@dataclass
class ChiselAnalysis:
    functions: dict[str, list[tuple[str, str]]]
    spans: dict[str, list[tuple[str, int, int]]]
    graph: CirctGraph | None = None


@dataclass(frozen=True)
class _CollectedUnits:
    units: list[ChiselUnit]
    use_extracted_fqns: bool = False


@dataclass(frozen=True)
class _EdgeContext:
    fqns_by_name: dict[str, set[str]]
    texts_by_fqn: dict[str, str]
    local_names_by_fqn: dict[str, set[str]]


class _CirctBackend:
    """Small stateful adapter for CIRCT graph loading and execution."""

    def __init__(self, proj_dir: str):
        self.proj_dir = _project_root(proj_dir)

    @property
    def graph_output_dir(self) -> str:
        return os.path.join(self.proj_dir, ".codegraph")

    @property
    def graph_path(self) -> str:
        return os.path.join(self.graph_output_dir, _GRAPH_FILENAME)

    @property
    def input_path(self) -> str:
        raw = os.environ.get(_CIRCT_INPUT_ENV, "").strip()
        if not raw:
            return ""
        return raw if os.path.isabs(raw) else os.path.join(self.proj_dir, raw)

    @property
    def plugin_path(self) -> str | None:
        for candidate in self._candidate_plugin_paths():
            if os.path.isfile(candidate):
                return candidate
        return None

    def graph_candidate_paths(self) -> list[str]:
        paths = [self.graph_path]
        for work_dir in _candidate_work_dirs(self.proj_dir):
            paths.append(os.path.join(work_dir, _LEGACY_GRAPH_FILENAME))
        return paths

    def fingerprint(self) -> tuple:
        records = []
        if self.input_path and os.path.exists(self.input_path):
            stat = os.stat(self.input_path)
            records.append(
                (
                    os.path.relpath(self.input_path, self.proj_dir),
                    stat.st_size,
                    stat.st_mtime_ns,
                )
            )

        plugin_record = None
        if self.plugin_path and os.path.exists(self.plugin_path):
            stat = os.stat(self.plugin_path)
            plugin_record = (self.plugin_path, stat.st_size, stat.st_mtime_ns)

        return (tuple(_circt_argv()), self.input_path, plugin_record, tuple(records))

    def load_graph(self) -> CirctGraph | None:
        expected_fingerprint = _fingerprint_digest(self.fingerprint())
        for path in self.graph_candidate_paths():
            try:
                with open(path, "r") as handle:
                    data = json.load(handle)
            except OSError:
                continue
            except json.JSONDecodeError:
                logging.warning("Ignoring corrupt CIRCT graph file: %s", path)
                continue
            stored_fingerprint = data.get("project_fingerprint")
            if stored_fingerprint and stored_fingerprint != expected_fingerprint:
                logging.info("Ignoring stale CIRCT graph file with mismatched fingerprint: %s", path)
                continue
            graph = _normalize_graph_payload(data)
            if graph is None:
                logging.warning("Ignoring malformed CIRCT graph file: %s", path)
                continue
            return graph
        return None

    def build_graph(self) -> CirctGraph | None:
        fingerprint = self.fingerprint()
        with _CACHE_LOCK:
            cached = _GRAPH_CACHE.get(self.proj_dir)
            if cached and cached[0] == fingerprint:
                return cached[1]

        graph = self._run_graph_pass()
        if graph is not None:
            try:
                self.persist_graph(fingerprint, graph)
            except OSError as exc:
                logging.warning(
                    "Unable to persist CIRCT Chisel module graph for %s: %s",
                    self.proj_dir,
                    exc,
                )
        with _CACHE_LOCK:
            _GRAPH_CACHE[self.proj_dir] = (fingerprint, graph)
        return graph

    def graph_or_none(self, allow_build: bool) -> CirctGraph | None:
        try:
            graph = self.load_graph()
            if graph is not None or not allow_build:
                return graph
            return self.build_graph()
        except Exception as exc:
            logging.warning("CIRCT Chisel analysis unavailable for %s: %s", self.proj_dir, exc)
            return None

    def persist_graph(self, fingerprint: tuple, graph: CirctGraph):
        document = {
            "schema_version": 1,
            "status": "success",
            "backend": "llvm/circt",
            "circt_command": list(_circt_argv()),
            "circt_plugin": self.plugin_path,
            "project_fingerprint": _fingerprint_digest(fingerprint),
            **_graph_to_json(graph),
        }

        os.makedirs(self.graph_output_dir, exist_ok=True)
        temp_path = None
        try:
            with tempfile.NamedTemporaryFile(
                mode="w",
                encoding="utf-8",
                dir=self.graph_output_dir,
                prefix=".chisel_module_graph.",
                suffix=".tmp",
                delete=False,
            ) as stream:
                temp_path = stream.name
                json.dump(document, stream, indent=2, ensure_ascii=False)
                stream.write("\n")
            os.replace(temp_path, self.graph_path)
        finally:
            if temp_path and os.path.exists(temp_path):
                try:
                    os.unlink(temp_path)
                except OSError:
                    pass

    def _candidate_plugin_paths(self) -> list[str]:
        env_path = os.environ.get(_CIRCT_PLUGIN_ENV, "").strip()
        candidates = []
        if env_path:
            candidates.append(
                env_path if os.path.isabs(env_path) else os.path.join(self.proj_dir, env_path)
            )

        local_names = (
            "libFMAgentChiselCirctPlugin.so",
            "FMAgentChiselCirctPlugin.so",
            "libFMAgentChiselCirctPlugin.dylib",
            "FMAgentChiselCirctPlugin.dylib",
        )
        for base in (
            os.path.join(self.proj_dir, "tools", "chisel-circt", "build", "lib"),
            os.path.join(os.path.expanduser("~"), ".local", "lib"),
        ):
            for name in local_names:
                candidates.append(os.path.join(base, name))
        return candidates

    def _run_graph_pass(self) -> CirctGraph | None:
        if not self.input_path:
            return None
        if not os.path.exists(self.input_path):
            raise RuntimeError(f"CIRCT input path does not exist: {self.input_path}")
        if not self.plugin_path:
            raise RuntimeError(
                "Unable to find the FM-Agent Chisel CIRCT plugin; set "
                f"{_CIRCT_PLUGIN_ENV} or install the plugin into ~/.local/lib"
            )

        firtool = _circt_argv()
        if shutil.which(firtool[0]) is None:
            raise RuntimeError(f"CIRCT command was not found: {firtool[0]}")

        os.makedirs(self.graph_output_dir, exist_ok=True)
        command = [
            *firtool,
            self.input_path,
            f"--format={_input_format(self.input_path)}",
            "--disable-output",
            f"--load-pass-plugin={self.plugin_path}",
            f"--high-firrtl-pass-plugin={_graph_pipeline(self.graph_path)}",
        ]
        try:
            subprocess.run(
                command,
                cwd=self.proj_dir,
                check=True,
                capture_output=True,
                text=True,
                timeout=_timeout_seconds(),
            )
        except subprocess.TimeoutExpired as exc:
            raise RuntimeError(
                f"CIRCT graph command timed out after {_timeout_seconds()}s: {' '.join(command)}"
            ) from exc
        except subprocess.CalledProcessError as exc:
            raise RuntimeError(
                "CIRCT graph command failed while building the Chisel module graph:\n"
                f"command: {' '.join(command)}\n"
                f"stdout:\n{exc.stdout}\n"
                f"stderr:\n{exc.stderr}"
            ) from exc

        graph = self.load_graph()
        if graph is None:
            raise RuntimeError(
                f"CIRCT graph command did not produce a valid graph file: {self.graph_path}"
            )
        return graph


class _SourceScanner:
    """Collect Chisel source units and extracted units for one project root."""

    def __init__(self, proj_dir: str):
        self.proj_dir = _project_root(proj_dir)

    def iter_source_files(self):
        for root, dirs, files in os.walk(self.proj_dir):
            dirs[:] = [
                directory for directory in dirs
                if not directory.startswith(".") and directory not in _SKIP_DIRS
            ]
            for fname in files:
                if not fname.endswith(_SOURCE_EXTS):
                    continue
                abs_path = os.path.join(root, fname)
                rel_path = os.path.relpath(abs_path, self.proj_dir).replace(os.sep, "/")
                if _is_test_file(rel_path):
                    continue
                yield abs_path, rel_path

    def existing_extracted_root(self) -> str | None:
        for work_dir in _candidate_work_dirs(self.proj_dir):
            extracted_root = _extracted_root(work_dir)
            if os.path.isdir(extracted_root):
                return extracted_root
        return None

    def collect_source_units(self) -> list[ChiselUnit]:
        units = []
        for abs_path, rel_path in self.iter_source_files():
            lines = _read_lines(abs_path)
            for name, start_idx, end_idx in extract_chisel_functions(lines, _LANG_KEY, None):
                units.append(_source_unit(abs_path, rel_path, lines, name, start_idx, end_idx))
        return units

    def collect_extracted_units(self, work_dir: str) -> list[ChiselUnit]:
        extracted_root = _extracted_root(work_dir)
        if not os.path.isdir(extracted_root):
            return []

        units = []
        for root, _, files in os.walk(extracted_root):
            for fname in files:
                if not fname.endswith(_SOURCE_EXTS):
                    continue
                abs_path = os.path.join(root, fname)
                rel_path = os.path.relpath(abs_path, extracted_root).replace(os.sep, "/")
                try:
                    source = _read_text(abs_path)
                except OSError:
                    continue
                unit = _extracted_unit(abs_path, rel_path, source)
                if unit is not None:
                    units.append(unit)
        return units

    def source_units_for_project(self, graph: CirctGraph | None) -> list[ChiselUnit]:
        if graph is not None:
            units = self._graph_backed_units(graph)
            if units:
                return units
            return _graph_module_fallback(self.collect_source_units(), graph)
        return _fallback_hardware_units(self.collect_source_units())

    def units_for_edges(self) -> _CollectedUnits:
        extracted_root = self.existing_extracted_root()
        if extracted_root is not None:
            graph = _graph_or_none(self.proj_dir, allow_build=False)
            return _CollectedUnits(
                units=_graph_module_fallback(
                    self.collect_extracted_units(os.path.dirname(extracted_root)),
                    graph,
                ) if graph is not None else self.collect_extracted_units(os.path.dirname(extracted_root)),
                use_extracted_fqns=True,
            )

        graph = _CirctBackend(self.proj_dir).graph_or_none(allow_build=True)
        return _CollectedUnits(
            units=self.source_units_for_project(graph),
            use_extracted_fqns=False,
        )

    def _graph_backed_units(self, graph: CirctGraph) -> list[ChiselUnit]:
        modules_by_file = defaultdict(list)
        for module in graph.modules:
            if module.location_file and module.kind in {"module", "extmodule"}:
                resolved = self._resolve_graph_file(module.location_file)
                if resolved is not None:
                    modules_by_file[resolved].append(module)

        units = []
        for abs_path, modules in modules_by_file.items():
            rel_path = os.path.relpath(abs_path, self.proj_dir).replace(os.sep, "/")
            lines = _read_lines(abs_path)
            declarations = extract_chisel_functions(lines, _LANG_KEY, None)
            for module in modules:
                match = self._match_graph_declaration(lines, declarations, module)
                if match is None:
                    continue
                name, start_idx, end_idx = match
                units.append(_source_unit(abs_path, rel_path, lines, name, start_idx, end_idx))
        return units

    def _resolve_graph_file(self, location_file: str) -> str | None:
        candidates = []
        if os.path.isabs(location_file):
            candidates.append(location_file)
        else:
            candidates.append(os.path.join(self.proj_dir, location_file))
            candidates.append(os.path.join(self.proj_dir, location_file.lstrip("./")))
        for candidate in candidates:
            normalized = os.path.abspath(candidate)
            if os.path.isfile(normalized):
                return normalized
        return None

    def _match_graph_declaration(self, lines: list[str], declarations, module: CirctModule):
        candidates = [item for item in declarations if item[0] == module.name]
        if not candidates:
            return None
        if module.location_line is None:
            return candidates[0]
        target_line = max(0, module.location_line - 1)
        return min(candidates, key=lambda item: abs(item[1] - target_line))


class _ChiselProject:
    """Project-level Chisel analysis, mirroring Erlang's backend shape."""

    def __init__(self, proj_dir: str):
        self.root = _project_root(proj_dir)
        self.circt = _CirctBackend(self.root)
        self.scanner = _SourceScanner(self.root)

    def graph_or_none(self, allow_build: bool) -> CirctGraph | None:
        return self.circt.graph_or_none(allow_build)

    def fingerprint(self) -> tuple:
        fingerprint = list(self.circt.fingerprint())
        records = list(fingerprint[-1])
        for abs_path, rel_path in self.scanner.iter_source_files():
            stat = os.stat(abs_path)
            records.append((rel_path, stat.st_size, stat.st_mtime_ns))
        fingerprint[-1] = tuple(sorted(records))
        return tuple(fingerprint)

    def analyze_uncached(self) -> ChiselAnalysis:
        graph = self.graph_or_none(allow_build=True)
        units = self.scanner.source_units_for_project(graph)
        return ChiselAnalysis(
            functions=_group_functions(units),
            spans=_group_spans(units),
            graph=graph,
        )

    def analyze(self) -> ChiselAnalysis:
        fingerprint = self.fingerprint()
        with _CACHE_LOCK:
            cached = _ANALYSIS_CACHE.get(self.root)
            if cached and cached[0] == fingerprint:
                return cached[1]

        analysis = self.analyze_uncached()
        with _CACHE_LOCK:
            _ANALYSIS_CACHE[self.root] = (fingerprint, analysis)
        return analysis

    def analysis_or_empty(self) -> ChiselAnalysis:
        try:
            return self.analyze()
        except Exception as exc:
            logging.warning("Chisel analysis unavailable for %s: %s", self.root, exc)
            return ChiselAnalysis(functions={}, spans={})

    def build_circt_module_graph(self, work_dir: str | None = None) -> dict | None:
        graph = self.graph_or_none(allow_build=True)
        if work_dir is not None:
            graph = _CirctBackend(work_dir).load_graph() or graph
        return _graph_to_json(graph) if graph else None

    def call_edges(self) -> dict[str, set[str]]:
        collected = self.scanner.units_for_edges()
        if not collected.units:
            return {}
        context = self._edge_context(collected)
        graph = self.graph_or_none(allow_build=not collected.use_extracted_fqns)
        if graph:
            return self._circt_call_edges(graph, context)
        return self._source_call_edges(context)

    def _edge_context(self, collected: _CollectedUnits) -> _EdgeContext:
        fqns_by_name = defaultdict(set)
        texts_by_fqn = {}
        local_names_by_fqn = {}
        for unit in collected.units:
            fqn = self._unit_fqn(unit, collected.use_extracted_fqns)
            fqns_by_name[unit.name].add(fqn)
            texts_by_fqn[fqn] = unit.source
            local_names = _local_declared_names(unit.source)
            local_names.discard(unit.name)
            local_names_by_fqn[fqn] = local_names
        return _EdgeContext(
            fqns_by_name=dict(fqns_by_name),
            texts_by_fqn=texts_by_fqn,
            local_names_by_fqn=local_names_by_fqn,
        )

    def _unit_fqn(self, unit: ChiselUnit, use_extracted_fqns: bool) -> str:
        if use_extracted_fqns:
            return unit.fqn or _extracted_unit_fqn(unit.rel_path)
        return _source_unit_fqn(unit.rel_path, unit.name)

    def _circt_call_edges(self, graph: CirctGraph, context: _EdgeContext) -> dict[str, set[str]]:
        edges = defaultdict(set)
        for caller_name, callee_names in graph.edges.items():
            for caller_fqn in context.fqns_by_name.get(caller_name, ()):
                for callee_name in callee_names:
                    for callee_fqn in context.fqns_by_name.get(callee_name, ()):
                        if callee_fqn != caller_fqn:
                            edges[caller_fqn].add(callee_fqn)
        return dict(edges)

    def _source_call_edges(self, context: _EdgeContext) -> dict[str, set[str]]:
        edges = defaultdict(set)
        known_names = set(context.fqns_by_name)
        for caller_fqn, text in context.texts_by_fqn.items():
            shadowed = context.local_names_by_fqn.get(caller_fqn, set())
            for callee_name in _instantiated_module_names(text, known_names):
                if callee_name in shadowed:
                    continue
                for callee_fqn in context.fqns_by_name.get(callee_name, ()):
                    if callee_fqn != caller_fqn:
                        edges[caller_fqn].add(callee_fqn)
        return dict(edges)


def _timeout_seconds() -> int:
    value = os.environ.get(_CIRCT_TIMEOUT_ENV, str(_DEFAULT_TIMEOUT_SECONDS))
    try:
        return max(1, int(value))
    except ValueError:
        logging.warning(
            "Invalid %s=%r; using %d",
            _CIRCT_TIMEOUT_ENV,
            value,
            _DEFAULT_TIMEOUT_SECONDS,
        )
        return _DEFAULT_TIMEOUT_SECONDS


def _circt_argv() -> list[str]:
    command = os.environ.get(_CIRCT_COMMAND_ENV, "firtool").strip() or "firtool"
    argv = shlex.split(command, posix=os.name != "nt")
    if not argv:
        argv = ["firtool"]
    return argv


def _skip_string(line: str, idx: int) -> int:
    idx += 1
    while idx < len(line):
        if line[idx] == "\\":
            idx += 2
            continue
        if line[idx] == '"':
            return idx + 1
        idx += 1
    return idx


def _skip_char(line: str, idx: int) -> int:
    idx += 1
    while idx < len(line):
        if line[idx] == "\\":
            idx += 2
            continue
        if line[idx] == "'":
            return idx + 1
        idx += 1
    return idx


def strip_comments(text: str) -> str:
    """Mask Scala/Chisel comments and string literals with spaces."""
    out = list(text)
    n = len(text)
    idx = 0
    block_depth = 0
    in_triple = False

    while idx < n:
        ch = text[idx]
        nxt = text[idx + 1] if idx + 1 < n else ""

        if in_triple:
            if text[idx:idx + 3] == '"""':
                out[idx] = out[idx + 1] = out[idx + 2] = " "
                in_triple = False
                idx += 3
                continue
            if out[idx] != "\n":
                out[idx] = " "
            idx += 1
            continue

        if block_depth:
            if ch == "/" and nxt == "*":
                out[idx] = out[idx + 1] = " "
                block_depth += 1
                idx += 2
                continue
            if ch == "*" and nxt == "/":
                out[idx] = out[idx + 1] = " "
                block_depth -= 1
                idx += 2
                continue
            if out[idx] != "\n":
                out[idx] = " "
            idx += 1
            continue

        if ch == "/" and nxt == "/":
            while idx < n and text[idx] != "\n":
                out[idx] = " "
                idx += 1
            continue
        if ch == "/" and nxt == "*":
            out[idx] = out[idx + 1] = " "
            block_depth += 1
            idx += 2
            continue
        if text[idx:idx + 3] == '"""':
            out[idx] = out[idx + 1] = out[idx + 2] = " "
            in_triple = True
            idx += 3
            continue
        if ch == '"':
            end = _skip_string(text, idx)
            for k in range(idx, min(end, n)):
                if out[k] != "\n":
                    out[k] = " "
            idx = end
            continue
        if ch == "'":
            end = _skip_char(text, idx)
            for k in range(idx, min(end, n)):
                if out[k] != "\n":
                    out[k] = " "
            idx = end
            continue
        idx += 1

    return "".join(out)


def _scan_line_states(lines):
    depth_start = [0] * len(lines)
    clean_start = [True] * len(lines)

    depth = 0
    block_depth = 0
    in_triple = False

    for idx, line in enumerate(lines):
        depth_start[idx] = depth
        clean_start[idx] = block_depth == 0 and not in_triple

        cursor = 0
        while cursor < len(line):
            ch = line[cursor]
            nxt = line[cursor + 1] if cursor + 1 < len(line) else ""

            if in_triple:
                if line[cursor:cursor + 3] == '"""':
                    in_triple = False
                    cursor += 3
                    continue
                cursor += 1
                continue

            if block_depth:
                if ch == "/" and nxt == "*":
                    block_depth += 1
                    cursor += 2
                    continue
                if ch == "*" and nxt == "/":
                    block_depth -= 1
                    cursor += 2
                    continue
                cursor += 1
                continue

            if ch == "/" and nxt == "/":
                break
            if ch == "/" and nxt == "*":
                block_depth += 1
                cursor += 2
                continue
            if line[cursor:cursor + 3] == '"""':
                in_triple = True
                cursor += 3
                continue
            if ch == '"':
                cursor = _skip_string(line, cursor)
                continue
            if ch == "'":
                cursor = _skip_char(line, cursor)
                continue
            if ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
            cursor += 1

    return depth_start, clean_start


def _package_block_line(line: str) -> bool:
    stripped = line.strip()
    return stripped.startswith("package ") and stripped.endswith("{")


def _find_block_end(lines, start_idx: int) -> int:
    depth = 0
    opened = False
    masked = strip_comments("\n".join(lines)).splitlines()
    for idx in range(start_idx, len(masked)):
        for ch in masked[idx]:
            if ch == "{":
                depth += 1
                opened = True
            elif ch == "}":
                depth -= 1
                if opened and depth == 0:
                    return idx
    return len(lines) - 1


def _signature_text(lines, start_idx: int) -> str:
    """Return the full declaration signature, tolerating Scala newlines."""
    masked = strip_comments("\n".join(lines)).splitlines()
    parts = []
    paren_depth = 0
    bracket_depth = 0
    brace_depth = 0
    saw_extends = False

    for idx in range(start_idx, len(masked)):
        stripped = masked[idx].strip()
        if not stripped:
            if parts:
                continue
            break
        parts.append(stripped)
        for ch in stripped:
            if ch == "(":
                paren_depth += 1
            elif ch == ")":
                paren_depth = max(0, paren_depth - 1)
            elif ch == "[":
                bracket_depth += 1
            elif ch == "]":
                bracket_depth = max(0, bracket_depth - 1)
            elif ch == "{":
                brace_depth += 1
            elif ch == "}":
                brace_depth = max(0, brace_depth - 1)
        if "extends" in stripped:
            saw_extends = True
        if "{" in stripped and paren_depth == 0 and bracket_depth == 0:
            break
        if paren_depth == 0 and bracket_depth == 0 and not stripped.endswith(("extends", "with", ",")):
            next_nonempty = None
            for follow in range(idx + 1, len(masked)):
                candidate = masked[follow].strip()
                if candidate:
                    next_nonempty = candidate
                    break
            if next_nonempty and (
                next_nonempty == "{"
                or next_nonempty.startswith("(")
                or next_nonempty.startswith("extends ")
                or next_nonempty.startswith("with ")
            ):
                if next_nonempty == "{":
                    parts.append("{")
                continue
            if not saw_extends and "{" not in stripped:
                break
            if next_nonempty == "{":
                parts.append("{")
            break
    return " ".join(parts)


def _extract_extends_expr(signature_text: str) -> str | None:
    match = re.search(r"\bextends\b(.+?)(?:\{|\bwith\b|$)", signature_text)
    if not match:
        return None
    expr = match.group(1).strip()
    while expr and expr[-1] in ",=:":
        expr = expr[:-1].rstrip()
    return expr or None


def _normalize_parent_name(expr: str) -> str | None:
    expr = expr.strip()
    if not expr:
        return None
    for token in ("(", "[", "{"):
        pos = expr.find(token)
        if pos != -1:
            expr = expr[:pos].rstrip()
    if not expr:
        return None
    if "." in expr:
        _, _, expr = expr.rpartition(".")
    return expr or None


def declaration_info(text: str) -> tuple[str | None, str | None, str | None]:
    """Return ``(kind, name, parent)`` for the first declaration."""
    lines = strip_comments(text).splitlines()
    for idx, raw in enumerate(lines):
        match = _DECL_RE.match(raw.strip())
        if match:
            extends_expr = _extract_extends_expr(_signature_text(lines, idx))
            if extends_expr:
                parent = _normalize_parent_name(extends_expr)
            else:
                parent = None
            return match.group("kind"), match.group("name"), parent
    return None, None, None


def _unit_end(lines, start_idx: int, masked_lines) -> int:
    depth = 0
    opened = False
    line_idx = start_idx

    while line_idx < len(masked_lines):
        line = masked_lines[line_idx]
        for ch in line:
            if ch == "{":
                depth += 1
                opened = True
            elif ch == "}":
                depth -= 1
                if opened and depth == 0:
                    return line_idx
        if opened:
            line_idx += 1
            continue

        signature = _signature_text(lines, start_idx)
        if "{" in signature:
            opened = True
            continue

        follow = line_idx + 1
        while follow < len(masked_lines) and not masked_lines[follow].strip():
            follow += 1
        if follow < len(masked_lines) and masked_lines[follow].strip() == "{":
            line_idx = follow
            continue
        return start_idx

    return len(lines) - 1


def extract_chisel_functions(lines, _lang_key, _lang_cfg):
    """Extract top-level Chisel/Scala declarations from one source file."""
    depth_start, clean_start = _scan_line_states(lines)
    masked_lines = strip_comments("\n".join(lines)).splitlines()
    units = []
    package_blocks = []
    idx = 0

    while idx < len(lines):
        package_blocks = [block for block in package_blocks if idx <= block[1]]
        in_package_top = any(depth_start[idx] == depth and idx <= end for depth, end in package_blocks)
        at_extractable_top = depth_start[idx] == 0 or in_package_top

        if not clean_start[idx] or not at_extractable_top:
            idx += 1
            continue

        stripped = lines[idx].lstrip()
        if not stripped or stripped.startswith(("//", "/*", "*")):
            idx += 1
            continue
        if _package_block_line(lines[idx]):
            package_blocks.append((depth_start[idx] + 1, _find_block_end(lines, idx)))
            idx += 1
            continue
        if stripped.startswith("package ") or stripped.startswith("import "):
            idx += 1
            continue

        match = _DECL_RE.match(stripped)
        if not match:
            idx += 1
            continue

        end_idx = _unit_end(lines, idx, masked_lines)
        units.append((match.group("name"), idx, end_idx))
        idx = end_idx + 1

    return units


def _read_lines(path: str) -> list[str]:
    with open(path, "r", errors="replace") as handle:
        return [line.rstrip("\n").rstrip("\r") for line in handle.readlines()]


def _read_text(path: str) -> str:
    with open(path, "r", errors="replace") as handle:
        return handle.read()


def _extracted_root(root: str) -> str:
    return os.path.join(root, "extracted_functions")


def _existing_extracted_root(root: str) -> str | None:
    return _SourceScanner(root).existing_extracted_root()


def _fallback_module_names(units: list[ChiselUnit]) -> set[str]:
    name_to_units = defaultdict(list)
    for idx, unit in enumerate(units):
        if unit.kind == "class" and unit.name:
            name_to_units[unit.name].append(idx)

    cache = {}
    visiting = set()

    def is_module(idx: int) -> bool:
        if idx in cache:
            return cache[idx]
        if idx in visiting:
            return True
        visiting.add(idx)
        unit = units[idx]
        result = False
        if unit.kind == "class":
            parent = unit.parent
            if parent in _MODULE_ROOTS:
                result = True
            elif parent:
                parent_indices = name_to_units.get(parent, ())
                if parent_indices:
                    result = any(is_module(parent_idx) for parent_idx in parent_indices)
        visiting.remove(idx)
        cache[idx] = result
        return result

    return {
        units[idx].name
        for idx in range(len(units))
        if units[idx].name and is_module(idx)
    }


def _source_unit_fqn(rel_path: str, unit_name: str) -> str:
    base = os.path.basename(rel_path)
    last_dot = base.rfind(".")
    dashed = base[:last_dot] + "-" + base[last_dot + 1:] if last_dot > 0 else base
    dir_part = os.path.dirname(rel_path).replace(os.sep, "/")
    parts = [part for part in dir_part.split("/") if part] + [dashed, unit_name.replace("/", "_")]
    return "::".join(parts)


def _extracted_unit_fqn(rel_path: str) -> str:
    stem, _ = os.path.splitext(rel_path.replace(os.sep, "/"))
    return "::".join(part for part in stem.split("/") if part)


def _source_unit(abs_path: str, rel_path: str, lines: list[str], name: str, start_idx: int, end_idx: int):
    source = "\n".join(lines[start_idx:end_idx + 1]) + "\n"
    kind, declared, parent = declaration_info(source)
    return ChiselUnit(
        abs_path=abs_path,
        rel_path=rel_path,
        source=source,
        kind=kind,
        name=declared or name,
        parent=parent,
        span=(start_idx, end_idx),
    )


def _extracted_unit(abs_path: str, rel_path: str, source: str):
    kind, declared, parent = declaration_info(source)
    if not declared:
        return None
    return ChiselUnit(
        abs_path=abs_path,
        rel_path=rel_path,
        source=source,
        kind=kind,
        name=declared,
        parent=parent,
        fqn=_extracted_unit_fqn(rel_path),
    )


def _graph_module_fallback(units: list[ChiselUnit], graph: CirctGraph) -> list[ChiselUnit]:
    module_names = set(graph.module_names)
    return [
        unit for unit in units
        if unit.kind == "class" and unit.name in module_names
    ]


def _fallback_hardware_units(units: list[ChiselUnit]) -> list[ChiselUnit]:
    module_names = _fallback_module_names(units)
    return [
        unit for unit in units
        if unit.kind == "class" and unit.name in module_names
    ]


def _candidate_work_dirs(root: str):
    root = os.path.abspath(root)
    if os.path.basename(root) == "fm_agent":
        return [root, os.path.dirname(root)]
    return [os.path.join(root, "fm_agent"), root]


def _project_root(proj_dir: str) -> str:
    root = os.path.abspath(proj_dir)
    if os.path.basename(root) == "fm_agent":
        return os.path.dirname(root)
    return root


def _normalize_graph_payload(data: dict) -> CirctGraph | None:
    modules = data.get("modules")
    edges = data.get("edges")
    if not isinstance(modules, list) or not isinstance(edges, dict):
        return None
    normalized_modules = []
    for module in modules:
        if isinstance(module, str):
            normalized_modules.append(CirctModule(name=module, kind="module", symbol=module))
        elif isinstance(module, dict) and isinstance(module.get("name"), str):
            location = module.get("location") if isinstance(module.get("location"), dict) else {}
            normalized_modules.append(
                CirctModule(
                    name=module["name"],
                    kind=module.get("kind", "module") if isinstance(module.get("kind"), str) else "module",
                    symbol=module.get("symbol", module["name"]) if isinstance(module.get("symbol"), str) else module["name"],
                    location_file=location.get("file") if isinstance(location.get("file"), str) else None,
                    location_line=int(location["line"]) if isinstance(location.get("line"), int) else None,
                    location_column=int(location["column"]) if isinstance(location.get("column"), int) else None,
                    location_end_line=int(location["end_line"]) if isinstance(location.get("end_line"), int) else None,
                    location_end_column=int(location["end_column"]) if isinstance(location.get("end_column"), int) else None,
                )
            )
    normalized_edges = {}
    for caller, callees in edges.items():
        if not isinstance(caller, str) or not isinstance(callees, list):
            continue
        normalized_edges[caller] = tuple(callee for callee in callees if isinstance(callee, str))
    return CirctGraph(
        top=data.get("top") if isinstance(data.get("top"), str) else None,
        modules=tuple(normalized_modules),
        edges=normalized_edges,
        source=data.get("source", "unknown"),
    )


def _graph_to_json(graph: CirctGraph) -> dict:
    return {
        "top": graph.top,
        "modules": [
            {
                "name": module.name,
                "kind": module.kind,
                "symbol": module.symbol,
                "location": (
                    {
                        "file": module.location_file,
                        "line": module.location_line,
                        "column": module.location_column,
                        "end_line": module.location_end_line,
                        "end_column": module.location_end_column,
                    }
                    if module.location_file is not None
                    else None
                ),
            }
            for module in graph.modules
        ],
        "edges": {caller: list(callees) for caller, callees in graph.edges.items()},
        "source": graph.source,
    }

def _fingerprint_digest(fingerprint: tuple) -> str:
    payload = json.dumps(fingerprint, ensure_ascii=False, separators=(",", ":"))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _escape_pass_option(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"')


def _input_format(input_path: str) -> str:
    lowered = input_path.lower()
    if lowered.endswith(".fir"):
        return "fir"
    if lowered.endswith(".mlir"):
        return "mlir"
    raise RuntimeError(f"Unsupported CIRCT input format for {input_path}")


def _graph_pipeline(output_path: str) -> str:
    escaped = _escape_pass_option(output_path)
    return (
        "firrtl.circuit("
        f'fm-agent-emit-chisel-module-graph{{output-file="{escaped}"}}'
        ")"
    )


def _graph_or_none(proj_dir: str, allow_build: bool) -> CirctGraph | None:
    return _CirctBackend(proj_dir).graph_or_none(allow_build)


def _group_functions(units: list[ChiselUnit]) -> dict[str, list[tuple[str, str]]]:
    return _group_unit_records(units, lambda unit, deduped: (deduped, unit.source))


def _group_spans(units: list[ChiselUnit]) -> dict[str, list[tuple[str, int, int]]]:
    return _group_unit_records(
        units,
        lambda unit, deduped: None if unit.span is None else (deduped, unit.span[0], unit.span[1]),
    )


def _group_unit_records(units: list[ChiselUnit], build_record):
    grouped = defaultdict(list)
    name_counts = defaultdict(lambda: defaultdict(int))
    for unit in units:
        cname = canonicalize(unit.name)
        count = name_counts[unit.abs_path][cname]
        name_counts[unit.abs_path][cname] += 1
        deduped = cname if count == 0 else f"{cname}_{count}"
        record = build_record(unit, deduped)
        if record is not None:
            grouped[unit.abs_path].append(record)
    return dict(grouped)


def build_circt_module_graph(proj_dir: str, work_dir: str | None = None) -> dict | None:
    """Build or load the CIRCT-backed authoritative module graph."""
    return _ChiselProject(proj_dir).build_circt_module_graph(work_dir)


def batch_extract(proj_dir: str) -> dict:
    """Return ``{abs_filepath: [(unit_name, body)]}`` for Chisel module units."""
    return _ChiselProject(proj_dir).analysis_or_empty().functions


def function_spans(proj_dir: str, filepath: str):
    """Return source ranges for extracted Chisel module units."""
    abs_path = os.path.abspath(filepath)
    return _ChiselProject(proj_dir).analysis_or_empty().spans.get(abs_path)


def _instantiated_module_names(text: str, known_names: set[str]) -> set[str]:
    cleaned = strip_comments(text)
    found = set()
    for raw_line in cleaned.splitlines():
        line = raw_line.strip()
        if "new " not in line:
            continue
        parts = line.replace("(", " ").replace(")", " ").replace("{", " ").split()
        for idx, token in enumerate(parts[:-1]):
            if token == "new":
                name = _normalize_instantiated_name(parts[idx + 1])
                if name in known_names:
                    found.add(name)
    return found


def _normalize_instantiated_name(name: str) -> str:
    candidate = name.strip().rstrip(",")
    for token in ("[", "(", "{"):
        pos = candidate.find(token)
        if pos != -1:
            candidate = candidate[:pos].rstrip()
    if "." in candidate:
        candidate = candidate.rsplit(".", 1)[-1]
    return candidate


def _local_declared_names(text: str) -> set[str]:
    names = set()
    for name in _LOCAL_DECL_RE.findall(strip_comments(text)):
        names.add(name)
    return names


def call_edges(proj_dir: str) -> dict | None:
    return _ChiselProject(proj_dir).call_edges()

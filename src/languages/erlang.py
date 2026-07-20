"""Erlang extraction and call-graph backend powered by ELP over LSP."""

from __future__ import annotations

import hashlib
import json
import logging
import os
import queue
import shlex
import subprocess
import tempfile
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import BinaryIO
from urllib.parse import unquote, urlparse

from config import settings


_FUNCTION_KIND = 12
_CONTENT_MODIFIED_ERROR = -32801
_MAX_CONTENT_MODIFIED_RETRIES = 5
_SKIP_DIRS = {
    ".git",
    ".codegraph",
    ".venv",
    "_build",
    "deps",
    "fm_agent",
    "test",
    "tests",
}
_PROJECT_CONFIG_FILES = ("elp.toml", "rebar.config", "rebar.lock")


@dataclass
class ErlangAnalysis:
    functions: dict[str, list[tuple[str, str]]]
    edges: dict[tuple[str, str], set[str]]
    spans: dict[str, list[tuple[str, int, int]]] = field(default_factory=dict)
    server_info: dict | None = None


_CACHE: dict[str, tuple[tuple, ErlangAnalysis]] = {}
_CACHE_LOCK = threading.Lock()


def _timeout_seconds() -> int:
    # ELP_TIMEOUT_SECONDS -> erlang.timeout_s is validated at config load (a
    # non-integer value fails fast at startup), so it is always an int here.
    return max(1, settings.erlang.timeout_s)


def _elp_argv() -> list[str]:
    command = settings.erlang.command.strip() or "elp"
    argv = shlex.split(command, posix=os.name != "nt")
    if not argv:
        argv = ["elp"]
    return [*argv, "server"]


class _JsonRpcReader(threading.Thread):
    def __init__(self, stream: BinaryIO, messages: queue.Queue):
        super().__init__(name="fm-agent-elp-reader", daemon=True)
        self._stream = stream
        self._messages = messages

    def run(self):
        try:
            while True:
                headers = {}
                while True:
                    line = self._stream.readline()
                    if not line:
                        raise EOFError("ELP closed its stdout")
                    if line in (b"\r\n", b"\n"):
                        break
                    name, separator, value = line.decode("ascii", "replace").partition(":")
                    if separator:
                        headers[name.strip().lower()] = value.strip()
                length = int(headers["content-length"])
                payload = self._stream.read(length)
                if len(payload) != length:
                    raise EOFError("ELP returned a truncated JSON-RPC payload")
                self._messages.put(json.loads(payload.decode("utf-8")))
        except BaseException as exc:
            self._messages.put(exc)


class _ContentModifiedError(RuntimeError):
    def __init__(self, error: dict):
        super().__init__(str(error))
        self.error = error


class ElpClient:
    """Minimal synchronous LSP client for an ``elp server`` subprocess."""

    def __init__(self, proj_dir: str):
        self.proj_dir = os.path.abspath(proj_dir)
        self.root_uri = Path(self.proj_dir).as_uri()
        self.timeout = _timeout_seconds()
        self._messages: queue.Queue = queue.Queue()
        self._next_id = 1
        self._status = None
        self._write_lock = threading.Lock()
        self._proc = None
        self._reader = None

    def __enter__(self):
        self._proc = subprocess.Popen(
            _elp_argv(),
            cwd=self.proj_dir,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        )
        self._reader = _JsonRpcReader(self._proc.stdout, self._messages)
        self._reader.start()
        return self

    def __exit__(self, exc_type, exc, tb):
        self.close()
        return False

    def _send(self, message: dict):
        if self._proc is None or self._proc.stdin is None:
            raise RuntimeError("ELP client is not running")
        payload = json.dumps(message, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        frame = f"Content-Length: {len(payload)}\r\n\r\n".encode("ascii") + payload
        with self._write_lock:
            self._proc.stdin.write(frame)
            self._proc.stdin.flush()

    def notify(self, method: str, params: dict | list | None = None):
        actual_params = {} if params is None else params
        self._send({"jsonrpc": "2.0", "method": method, "params": actual_params})

    def request(self, method: str, params: dict | list | None = None):
        actual_params = {} if params is None else params
        deadline = time.monotonic() + self.timeout
        for attempt in range(_MAX_CONTENT_MODIFIED_RETRIES):
            request_id = self._next_id
            self._next_id += 1
            self._send(
                {
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "method": method,
                    "params": actual_params,
                }
            )
            try:
                return self._wait_for_response(request_id, deadline)
            except _ContentModifiedError as exc:
                if attempt + 1 == _MAX_CONTENT_MODIFIED_RETRIES:
                    raise RuntimeError(
                        f"ELP request {method} repeatedly failed: {exc.error}"
                    ) from exc
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError(f"timed out retrying ELP request {method}") from exc
                time.sleep(min(0.5 * (2**attempt), 5.0, remaining))
        raise AssertionError("unreachable")

    def _next_message(self, deadline: float):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("timed out waiting for ELP")
        try:
            message = self._messages.get(timeout=remaining)
        except queue.Empty as exc:
            raise TimeoutError("timed out waiting for ELP") from exc
        if isinstance(message, BaseException):
            raise RuntimeError(str(message)) from message
        return message

    def _wait_for_response(self, request_id: int, deadline: float):
        while True:
            message = self._next_message(deadline)
            if message.get("id") == request_id and "method" not in message:
                error = message.get("error")
                if error:
                    if isinstance(error, dict) and error.get("code") == _CONTENT_MODIFIED_ERROR:
                        raise _ContentModifiedError(error)
                    raise RuntimeError(f"ELP request failed: {error}")
                return message.get("result")
            self._handle_server_message(message)

    def _handle_server_message(self, message: dict):
        method = message.get("method")
        params = message.get("params")
        if params is None:
            params = {}
        if method == "elp/status":
            self._status = params.get("status")
        if "id" not in message or not method:
            return

        if method == "workspace/configuration":
            result = [None for _ in params.get("items", [])]
        elif method == "workspace/workspaceFolders":
            result = [{"uri": self.root_uri, "name": os.path.basename(self.proj_dir)}]
        elif method == "workspace/applyEdit":
            result = {"applied": False}
        else:
            result = None
        self._send({"jsonrpc": "2.0", "id": message["id"], "result": result})

    def initialize(self, bootstrap_path: str, bootstrap_source: str | None = None):
        result = self.request(
            "initialize",
            {
                "processId": os.getpid(),
                "clientInfo": {"name": "fm-agent", "version": "0.1.0"},
                "rootUri": self.root_uri,
                "workspaceFolders": [
                    {"uri": self.root_uri, "name": os.path.basename(self.proj_dir)}
                ],
                "capabilities": {
                    "experimental": {"serverStatusNotification": True},
                    "workspace": {"configuration": True, "workspaceFolders": True},
                    "textDocument": {
                        "documentSymbol": {
                            "dynamicRegistration": False,
                            "hierarchicalDocumentSymbolSupport": True,
                        }
                    },
                },
            },
        )
        server_info = (result or {}).get("serverInfo") if isinstance(result, dict) else None
        self.notify("initialized")
        self.open_document(bootstrap_path, bootstrap_source)

        deadline = time.monotonic() + self.timeout
        while str(self._status).lower() != "running":
            self._handle_server_message(self._next_message(deadline))
        return server_info

    def open_document(self, path: str, source: str | None = None):
        document = Path(path).resolve()
        if source is None:
            source = document.read_text(encoding="utf-8", errors="replace")
        self.notify(
            "textDocument/didOpen",
            {
                "textDocument": {
                    "uri": document.as_uri(),
                    "languageId": "erlang",
                    "version": 1,
                    "text": source,
                }
            },
        )

    def close(self):
        proc = self._proc
        if proc is None:
            return
        try:
            if proc.poll() is None:
                try:
                    self.request("shutdown")
                except Exception:
                    pass
                try:
                    self.notify("exit")
                except Exception:
                    pass
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    proc.terminate()
                    try:
                        proc.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        proc.kill()
        finally:
            for stream in (proc.stdin, proc.stdout):
                if stream:
                    try:
                        stream.close()
                    except OSError:
                        pass
            self._proc = None


def _escape_component(value: str) -> str:
    result = []
    for char in value:
        if char.isascii() and (char.isalnum() or char == "_"):
            result.append(char)
        else:
            result.append(f"_{ord(char):02x}")
    return "".join(result)


def _module_from_uri(uri: str) -> str:
    path = unquote(urlparse(uri).path)
    return PurePosixPath(path.replace("\\", "/")).stem


def _function_id(uri: str, label: str) -> str:
    try:
        name, arity = label.rsplit("/", 1)
        int(arity)
    except (ValueError, TypeError) as exc:
        raise ValueError(f"ELP function label has no valid arity: {label!r}") from exc
    if ":" in name and not name.startswith("'"):
        name = name.rsplit(":", 1)[1]
    module = _module_from_uri(uri)
    return f"{_escape_component(module)}__{_escape_component(name)}__{arity}"


@dataclass
class _SourceIndex:
    source: str
    lines: list[str]
    line_offsets: list[int]

    @classmethod
    def build(cls, source: str) -> _SourceIndex:
        lines = source.splitlines(keepends=True)
        line_offsets = []
        offset = 0
        for line in lines:
            line_offsets.append(offset)
            offset += len(line)
        return cls(source=source, lines=lines, line_offsets=line_offsets)

    def position_to_offset(self, position: dict) -> int:
        line_number = max(0, int(position.get("line", 0)))
        utf16_target = max(0, int(position.get("character", 0)))
        if line_number >= len(self.lines):
            return len(self.source)
        base = self.line_offsets[line_number]
        line = self.lines[line_number]
        units = 0
        index = 0
        while index < len(line) and units < utf16_target:
            char_units = 2 if ord(line[index]) > 0xFFFF else 1
            if units + char_units > utf16_target:
                break
            units += char_units
            index += 1
        return base + index

    def source_for_range(self, lsp_range: dict) -> str:
        start = self.position_to_offset(lsp_range["start"])
        end = self.position_to_offset(lsp_range["end"])
        return self.source[start:end]


def _position_to_offset(source: str, position: dict) -> int:
    """Compatibility wrapper for callers that do not reuse a source index."""
    return _SourceIndex.build(source).position_to_offset(position)


def _source_for_range(source: str, lsp_range: dict) -> str:
    """Compatibility wrapper for callers that do not reuse a source index."""
    return _SourceIndex.build(source).source_for_range(lsp_range)


def _caller_module(path: str) -> str:
    base = os.path.basename(path)
    dot = base.rfind(".")
    return base[:dot] + "-" + base[dot + 1 :] if dot > 0 else base


def _iter_project_files(proj_dir: str, suffixes: set[str]):
    for root, dirs, files in os.walk(proj_dir):
        dirs[:] = [directory for directory in dirs if directory.lower() not in _SKIP_DIRS]
        for filename in files:
            if Path(filename).suffix.lower() in suffixes:
                yield os.path.abspath(os.path.join(root, filename))


def _erlang_files(proj_dir: str) -> list[str]:
    return sorted(_iter_project_files(proj_dir, {".erl"}))


def _project_fingerprint(proj_dir: str) -> tuple:
    root = os.path.abspath(proj_dir)
    paths = list(_iter_project_files(root, {".erl", ".hrl"}))
    paths.extend(
        os.path.join(root, name)
        for name in _PROJECT_CONFIG_FILES
        if os.path.isfile(os.path.join(root, name))
    )
    records = []
    for path in sorted(set(paths)):
        stat = os.stat(path)
        records.append((os.path.relpath(path, root), stat.st_size, stat.st_mtime_ns))
    return (tuple(_elp_argv()), tuple(records))


def _fingerprint_digest(fingerprint: tuple) -> str:
    payload = json.dumps(fingerprint, ensure_ascii=False, separators=(",", ":"))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _persist_analysis(proj_dir: str, fingerprint: tuple, analysis: ErlangAnalysis):
    """Persist successful ELP output for diagnostics and reproducible inspection."""
    root = os.path.abspath(proj_dir)
    output_dir = os.path.join(root, ".codegraph")
    output_path = os.path.join(output_dir, "erlang_callgraph.json")

    functions = []
    caller_files = {}
    for path, file_functions in sorted(analysis.functions.items()):
        rel_path = os.path.relpath(path, root).replace(os.sep, "/")
        caller_module = _caller_module(path)
        for function_id, _source in file_functions:
            functions.append({"id": function_id, "file": rel_path})
            caller_files[(function_id, caller_module)] = rel_path

    edges = [
        {
            "caller": caller,
            "caller_module": caller_module,
            "caller_file": caller_files.get((caller, caller_module)),
            "callee": callee,
        }
        for (caller, caller_module), callees in sorted(analysis.edges.items())
        for callee in sorted(callees)
    ]
    document = {
        "schema_version": 1,
        "status": "success",
        "backend": "elp",
        "server_info": analysis.server_info,
        "elp_command": list(_elp_argv()),
        "project_fingerprint": _fingerprint_digest(fingerprint),
        "functions": functions,
        "edges": edges,
    }

    os.makedirs(output_dir, exist_ok=True)
    temp_path = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=output_dir,
            prefix=".erlang_callgraph.",
            suffix=".tmp",
            delete=False,
        ) as stream:
            temp_path = stream.name
            json.dump(document, stream, indent=2, ensure_ascii=False)
            stream.write("\n")
        os.replace(temp_path, output_path)
    finally:
        if temp_path and os.path.exists(temp_path):
            try:
                os.unlink(temp_path)
            except OSError:
                pass


def _symbol_range(symbol: dict):
    if "range" in symbol:
        return symbol["range"]
    return (symbol.get("location") or {}).get("range")


def _symbol_uri(symbol: dict, fallback: str):
    return symbol.get("uri") or (symbol.get("location") or {}).get("uri") or fallback


def _symbol_line_span(symbol_range: dict) -> tuple[int, int]:
    """Convert an LSP half-open range to a 0-based inclusive line span."""
    start = max(0, int(symbol_range["start"].get("line", 0)))
    end_position = symbol_range["end"]
    end = max(start, int(end_position.get("line", start)))
    if end > start and int(end_position.get("character", 0)) == 0:
        end -= 1
    return start, end


def _analyze_project_uncached(proj_dir: str) -> ErlangAnalysis:
    proj_dir = os.path.abspath(proj_dir)
    files = _erlang_files(proj_dir)
    if not files:
        return ErlangAnalysis(functions={}, edges={})

    functions: dict[str, list[tuple[str, str]]] = {}
    edges: dict[tuple[str, str], set[str]] = {}
    spans: dict[str, list[tuple[str, int, int]]] = {}
    sources = {
        path: Path(path).read_text(encoding="utf-8", errors="replace")
        for path in files
    }

    with ElpClient(proj_dir) as client:
        server_info = client.initialize(files[0], sources[files[0]])
        for path in files[1:]:
            client.open_document(path, sources[path])
        for path in files:
            source = sources[path]
            source_index = _SourceIndex.build(source)
            caller_module = _caller_module(path)
            uri = Path(path).as_uri()
            symbols = client.request(
                "textDocument/documentSymbol", {"textDocument": {"uri": uri}}
            ) or []
            file_functions = []
            file_spans = []
            seen = set()
            for symbol in symbols:
                if symbol.get("kind") != _FUNCTION_KIND:
                    continue
                symbol_range = _symbol_range(symbol)
                if not symbol_range:
                    continue
                symbol_uri = _symbol_uri(symbol, uri)
                try:
                    function_id = _function_id(symbol_uri, symbol.get("name", ""))
                except ValueError:
                    logging.warning("Ignoring malformed ELP function symbol: %r", symbol)
                    continue
                if function_id in seen:
                    continue
                seen.add(function_id)
                file_functions.append((function_id, source_index.source_for_range(symbol_range)))
                start_line, end_line = _symbol_line_span(symbol_range)
                file_spans.append((function_id, start_line, end_line))

                caller_key = (function_id, caller_module)
                edges.setdefault(caller_key, set())
                selection = symbol.get("selectionRange") or symbol_range
                prepared = client.request(
                    "textDocument/prepareCallHierarchy",
                    {
                        "textDocument": {"uri": symbol_uri},
                        "position": selection["start"],
                    },
                ) or []
                if not prepared:
                    continue
                item = None
                for candidate in prepared:
                    if not isinstance(candidate, dict):
                        continue
                    try:
                        candidate_id = _function_id(
                            candidate.get("uri", symbol_uri),
                            candidate.get("name", ""),
                        )
                    except (TypeError, ValueError):
                        continue
                    if candidate_id == function_id:
                        item = candidate
                        break
                if item is None:
                    continue
                outgoing = client.request(
                    "callHierarchy/outgoingCalls", {"item": item}
                ) or []
                for call in outgoing:
                    target = call.get("to") or {}
                    try:
                        target_id = _function_id(
                            target.get("uri", symbol_uri), target.get("name", "")
                        )
                    except ValueError:
                        continue
                    edges[caller_key].add(target_id)

            if file_functions:
                functions[path] = file_functions
                spans[path] = file_spans

    return ErlangAnalysis(
        functions=functions,
        edges=edges,
        spans=spans,
        server_info=server_info,
    )


def _analyze_project(proj_dir: str) -> ErlangAnalysis:
    root = os.path.abspath(proj_dir)
    fingerprint = _project_fingerprint(root)
    with _CACHE_LOCK:
        cached = _CACHE.get(root)
        if cached and cached[0] == fingerprint:
            return cached[1]

    analysis = _analyze_project_uncached(root)
    try:
        _persist_analysis(root, fingerprint, analysis)
    except OSError as exc:
        logging.warning("Unable to persist ELP Erlang call graph for %s: %s", root, exc)
    with _CACHE_LOCK:
        _CACHE[root] = (fingerprint, analysis)
    return analysis


def _analysis_or_empty(proj_dir: str) -> ErlangAnalysis:
    try:
        return _analyze_project(proj_dir)
    except Exception as exc:
        logging.warning("ELP Erlang analysis unavailable for %s: %s", proj_dir, exc)
        return ErlangAnalysis(functions={}, edges={})


def batch_extract(proj_dir: str) -> dict:
    """Return ``{abs_filepath: [(function_id, body)]}`` for Erlang files."""
    return _analysis_or_empty(proj_dir).functions


def function_spans(proj_dir: str, filepath: str):
    """Return ELP function ranges as 0-based inclusive source-line spans."""
    path = os.path.abspath(filepath)
    return _analysis_or_empty(proj_dir).spans.get(path)


def _callgraph_project_root(proj_dir: str) -> str:
    """Resolve a pipeline workspace back to the original source-project root."""
    root = os.path.abspath(proj_dir)
    if not os.path.isdir(os.path.join(root, "extracted_functions")):
        return root

    parent = os.path.dirname(root)
    if parent == root:
        return root

    # The parent scan ignores fm_agent via _SKIP_DIRS, so only original project
    # sources qualify; extracted function files cannot trigger this redirect.
    if next(_iter_project_files(parent, {".erl"}), None) is not None:
        return parent
    return root


def call_edges(proj_dir: str) -> dict:
    """Return module-qualified Erlang call edges in registry format."""
    return _analysis_or_empty(_callgraph_project_root(proj_dir)).edges

from dataclasses import dataclass
from typing import Callable

import logging

from src.languages import python as _python
from src.languages import go as _go
from src.languages import c as _c
from src.languages import cpp as _cpp
from src.languages import java as _java
from src.languages import rust as _rust
from src.languages import javascript as _javascript
from src.languages import typescript as _typescript
from src.languages import erlang as _erlang

from src.languages.base import BackendUnavailableError as _BackendUnavailableError

@dataclass
class LanguageHandler:
    """Extraction and call-graph backend for one language.

    batch_extract(proj_dir)             -> {abs_filepath: [(func_name, body)]} | None
    call_edges(proj_dir)                -> {caller_fqn: {callee_fqns}}
    function_spans(proj_dir, filepath)  -> [(func_name, start_idx, end_idx)] | None
    incremental_source_extract(proj_dir, sources)
        -> {abs_filepath: [(func_name, body)]} | None

    Each function handles its own backend (e.g. codegraph) internally.
    batch_extract returns ``None`` when a semantic backend cannot safely
    extract its sources, distinct from a successful empty dict. call_edges
    returns an empty dict when its backend is unavailable; function_spans
    returns None so the caller can fall back to the regex extractor for that
    file, or raises BackendUnavailableError for languages where a regex
    fallback is unsafe (e.g. Erlang/ELP) — callers that are about to delete
    extracted-function artifacts should catch it and skip the file instead of
    trusting an empty regex result.

    To add a new language:
      1. Create src/languages/<lang>.py implementing batch_extract, call_edges,
         function_spans, and optionally incremental_source_extract
      2. Import it here and add one entry to REGISTRY
    No other files need to change.
    """
    batch_extract: Callable
    call_edges: Callable
    function_spans: Callable
    incremental_source_extract: Callable | None = None

BackendUnavailableError = _BackendUnavailableError

REGISTRY: dict = {
    "python":     LanguageHandler(batch_extract=_python.batch_extract,     call_edges=_python.call_edges,     function_spans=_python.function_spans),
    "go":         LanguageHandler(batch_extract=_go.batch_extract,         call_edges=_go.call_edges,         function_spans=_go.function_spans),
    "c":          LanguageHandler(batch_extract=_c.batch_extract,          call_edges=_c.call_edges,          function_spans=_c.function_spans),
    "cpp":        LanguageHandler(batch_extract=_cpp.batch_extract,        call_edges=_cpp.call_edges,        function_spans=_cpp.function_spans),
    "java":       LanguageHandler(batch_extract=_java.batch_extract,       call_edges=_java.call_edges,       function_spans=_java.function_spans),
    "rust":       LanguageHandler(batch_extract=_rust.batch_extract,       call_edges=_rust.call_edges,       function_spans=_rust.function_spans),
    "javascript": LanguageHandler(batch_extract=_javascript.batch_extract, call_edges=_javascript.call_edges, function_spans=_javascript.function_spans),
    "typescript": LanguageHandler(batch_extract=_typescript.batch_extract, call_edges=_typescript.call_edges, function_spans=_typescript.function_spans),
    "erlang":     LanguageHandler(batch_extract=_erlang.batch_extract,     call_edges=_erlang.call_edges,     function_spans=_erlang.function_spans, incremental_source_extract=_erlang.extract_functions_from_sources),
}


def batch_extract_all(proj_dir: str, include_unavailable: bool = False) -> tuple:
    """Call batch_extract for every registered language and merge results.

    Returns (funcs, langs) where funcs is {abs_filepath: [(func_name, body)]}
    and langs is the set of language keys that returned data. When
    ``include_unavailable`` is true, appends the set of languages whose
    semantic extraction backend failed.
    """
    funcs = {}
    langs = set()
    unavailable = set()
    for lang, handler in REGISTRY.items():
        result = handler.batch_extract(proj_dir)
        if result is None:
            unavailable.add(lang)
            continue
        if result:
            funcs.update(result)
            langs.add(lang)
    if include_unavailable:
        return funcs, langs, unavailable
    return funcs, langs


def function_spans_for_file(proj_dir: str, filepath: str, lang_key: str):
    """Return codegraph function spans for one file, or None to fall back.

    Delegates to the registered language handler's function_spans backend.
    Returns [(func_name, start_idx, end_idx)] (0-indexed, inclusive) when
    codegraph indexes the file, or None when the language is unregistered,
    codegraph does not support it, or the file is not in the index — in every
    such case the caller should fall back to the regex extractor. May raise
    BackendUnavailableError for languages where the backend is required
    and cannot be consulted (e.g. Erlang/ELP).
    """
    handler = REGISTRY.get(lang_key)
    if handler is None:
        return None
    return handler.function_spans(proj_dir, filepath)


def supports_incremental_source_extraction(lang_key: str) -> bool:
    """Return whether a language supplies semantic extraction for source snapshots."""
    handler = REGISTRY.get(lang_key)
    return handler is not None and handler.incremental_source_extract is not None


def extract_incremental_sources(proj_dir: str, lang_key: str, sources: dict):
    """Dispatch source-snapshot extraction to a language's registered backend.

    The backend returns ``None`` when it is unavailable or fails, distinct from
    a successful extraction whose individual source files contain no functions.
    """
    handler = REGISTRY.get(lang_key)
    if handler is None or handler.incremental_source_extract is None:
        raise ValueError(
            f"Language {lang_key!r} has no incremental source extraction backend"
        )
    return handler.incremental_source_extract(proj_dir, sources)


_logger = logging.getLogger(__name__)

# 允许透传的 edge 字段（内部缓存字段如 _internal_cache 会被过滤）
_ALLOWED_EDGE_FIELDS = {
    "caller", "callee", "kind", "language",
    "span", "arg_bindings", "order_index",
}

# span 内部的标准字段名（不同后端可能叫 file/path/source_file，统一到 file）
_SPAN_FIELD_ALIASES = {
    "file": ("file", "path", "source_file", "filename"),
    "start_line": ("start_line", "line"),
    "start_column": ("start_column", "col", "column"),
}


def _normalize_span(span) -> dict:
    """Unify span field names: {file, start_line, start_column}."""
    if not isinstance(span, dict):
        return span
    out = {}
    for canonical, aliases in _SPAN_FIELD_ALIASES.items():
        for a in aliases:
            if a in span and span[a] is not None:
                out[canonical] = span[a]
                break
    # 保留未识别字段（向后兼容）
    for k, v in span.items():
        if k not in {x for aliases in _SPAN_FIELD_ALIASES.values() for x in aliases}:
            out[k] = v
    return out


def _edge_dedup_key(d: dict) -> tuple:
    """Dedup key at call-site granularity (mirrors codegraph.py).

    Includes language so edges from different backends (e.g. C and C++)
    with the same caller/callee/span are not merged away.
    """
    span = d.get("span") if isinstance(d.get("span"), dict) else {}
    return (
        d.get("language"),
        d.get("caller"),
        d.get("callee"),
        d.get("kind", "call"),
        span.get("file"),
        span.get("start_line"),
        span.get("start_column"),
    )


def normalize_call_edges(edges, language=None) -> list:
    """Normalize language-backend call edges into FM-Agent standard format.

    Accepts:
      - dict form:      {caller: {callee, ...}} / {caller: "callee_str"}
      - list form:      [{"caller": ..., "callee": ..., "kind": ...}]
      - custom objects: 可转换为 dict 的 edge object（保留额外字段）

    Returns a list of normalized edge dicts. Malformed edges are skipped with
    a warning (never silently dropped — this is shared infrastructure).
    Dedup is applied at call-site granularity so the function is idempotent.
    """
    if edges is None:
        return []

    out = []
    seen = set()

    def _append(d: dict) -> None:
        # span 字段名统一
        if "span" in d and isinstance(d["span"], dict):
            d["span"] = _normalize_span(d["span"])
        # language 空字符串规范化：非空 language 参数覆盖空值
        if not d.get("language") and language:
            d["language"] = language
        key = _edge_dedup_key(d)
        if key in seen:
            return
        seen.add(key)
        out.append(d)

    # dict form: {caller: {callee, ...}} / {caller: "callee_str"}
    if isinstance(edges, dict):
        for caller, callees in edges.items():
            if isinstance(callees, str):
                callees = [callees]          # 兼容 {caller: "callee_str"}
            elif not isinstance(callees, (list, set, tuple)):
                _logger.warning("Skipping malformed call edge (unknown container): %r", callees)
                continue
            for callee in callees:
                _append({
                    "caller": caller,
                    "callee": callee,
                    "kind": "call",
                    "language": language,
                })
        return out

    # list form: normalized dicts or edge objects
    if isinstance(edges, list):
        for e in edges:
            if isinstance(e, dict):
                d = dict(e)
                # schema 校验：缺 caller/callee 跳过（不静默——基础设施层要留日志）
                if "caller" not in d or "callee" not in d:
                    _logger.warning("Skipping malformed call edge: %s", d)
                    continue
                d.setdefault("kind", "call")
                _append(d)
            else:
                # custom object: 统一走 getattr（兼容 __dict__ / __slots__ / @property）
                d = {}
                for key in _ALLOWED_EDGE_FIELDS:
                    if hasattr(e, key):
                        val = getattr(e, key, None)
                        if val is not None:
                            d[key] = val
                if "caller" in d and "callee" in d:
                    d.setdefault("kind", "call")
                    _append(d)
        return out

    return []


def call_edges_all(proj_dir: str, lang_keys) -> tuple:
    """Call call_edges for each language in lang_keys and merge results.

    Returns (edges, langs) where edges is a list of normalized edge dicts and
    langs is the set of language keys codegraph handled. Edges are deduped
    across language backends at call-site granularity.
    """
    edges = []
    langs = set()
    seen = set()
    for lang in lang_keys:
        if lang not in REGISTRY:
            continue
        result = REGISTRY[lang].call_edges(proj_dir)
        if result is None:
            continue
        langs.add(lang)
        for edge in normalize_call_edges(result, language=lang):
            key = _edge_dedup_key(edge)
            if key in seen:
                continue
            seen.add(key)
            edges.append(edge)
    return edges, langs

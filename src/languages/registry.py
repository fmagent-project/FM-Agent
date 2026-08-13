from dataclasses import dataclass
from typing import Callable

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
    split_blocks(func, granularity)      -> [chunk, ...] | None

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
         function_spans, and optionally incremental_source_extract / split_blocks
      2. Import it here and add one entry to REGISTRY
    No other files need to change.
    """
    batch_extract: Callable
    call_edges: Callable
    function_spans: Callable
    incremental_source_extract: Callable | None = None
    split_blocks: Callable | None = None

BackendUnavailableError = _BackendUnavailableError

REGISTRY: dict = {
    "python":     LanguageHandler(batch_extract=_python.batch_extract,     call_edges=_python.call_edges,     function_spans=_python.function_spans),
    "go":         LanguageHandler(batch_extract=_go.batch_extract,         call_edges=_go.call_edges,         function_spans=_go.function_spans),
    "c":          LanguageHandler(batch_extract=_c.batch_extract,          call_edges=_c.call_edges,          function_spans=_c.function_spans, split_blocks=_c.split_blocks),
    "cpp":        LanguageHandler(batch_extract=_cpp.batch_extract,        call_edges=_cpp.call_edges,        function_spans=_cpp.function_spans, split_blocks=_cpp.split_blocks),
    "java":       LanguageHandler(batch_extract=_java.batch_extract,       call_edges=_java.call_edges,       function_spans=_java.function_spans, split_blocks=_java.split_blocks),
    "rust":       LanguageHandler(batch_extract=_rust.batch_extract,       call_edges=_rust.call_edges,       function_spans=_rust.function_spans, split_blocks=_rust.split_blocks),
    "javascript": LanguageHandler(batch_extract=_javascript.batch_extract, call_edges=_javascript.call_edges, function_spans=_javascript.function_spans, split_blocks=_javascript.split_blocks),
    "typescript": LanguageHandler(batch_extract=_typescript.batch_extract, call_edges=_typescript.call_edges, function_spans=_typescript.function_spans, split_blocks=_typescript.split_blocks),
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


def split_blocks_for_function(func: str, lang_key: str, granularity: int):
    """Return syntax-aware blocks for ``lang_key``, or ``None`` for fallback."""
    normalized_key = {"c++": "cpp"}.get(lang_key.lower(), lang_key.lower())
    handler = REGISTRY.get(normalized_key)
    if handler is None or handler.split_blocks is None:
        return None
    return handler.split_blocks(func, granularity)


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


def call_edges_all(proj_dir: str, lang_keys) -> tuple:
    """Call call_edges for each language in lang_keys and merge results.

    Returns (edges, langs) where edges is {caller_fqn: {callee_fqns}} and langs is
    the set of language keys codegraph handled (it returned a dict, even if empty
    — None means the backend was unavailable and the caller should use regex).
    """
    edges = {}
    langs = set()
    for lang in lang_keys:
        if lang not in REGISTRY:
            continue
        result = REGISTRY[lang].call_edges(proj_dir)
        # A handler returns None when its backend (codegraph) is unavailable, and
        # a dict (possibly empty) when it handled the language. Treat "handled but
        # no edges" as codegraph-authoritative — add the language to `langs` so the
        # caller uses the codegraph path — instead of falling back to regex, which
        # would otherwise invent edges (e.g. match a function's own signature) for
        # a genuinely call-free project.
        if result is not None:
            langs.add(lang)
            for key, callees in result.items():
                edges.setdefault(key, set()).update(callees)
    return edges, langs

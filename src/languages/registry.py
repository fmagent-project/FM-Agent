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


@dataclass
class LanguageHandler:
    """Extraction and call-graph backend for one language.

    batch_extract(proj_dir)             -> {abs_filepath: [(func_name, body)]}
    call_edges(proj_dir)                -> {caller_fqn: {callee_fqns}}
    function_spans(proj_dir, filepath)  -> [(func_name, start_idx, end_idx)] | None

    Each function handles its own backend (e.g. codegraph) internally.
    batch_extract / call_edges return an empty dict when the backend is
    unavailable; function_spans returns None so the caller can fall back to the
    regex extractor for that file.

    To add a new language:
      1. Create src/languages/<lang>.py implementing batch_extract, call_edges,
         and function_spans
      2. Import it here and add one entry to REGISTRY
    No other files need to change.
    """
    batch_extract: Callable
    call_edges: Callable
    function_spans: Callable


REGISTRY: dict = {
    "python":     LanguageHandler(batch_extract=_python.batch_extract,     call_edges=_python.call_edges,     function_spans=_python.function_spans),
    "go":         LanguageHandler(batch_extract=_go.batch_extract,         call_edges=_go.call_edges,         function_spans=_go.function_spans),
    "c":          LanguageHandler(batch_extract=_c.batch_extract,          call_edges=_c.call_edges,          function_spans=_c.function_spans),
    "cpp":        LanguageHandler(batch_extract=_cpp.batch_extract,        call_edges=_cpp.call_edges,        function_spans=_cpp.function_spans),
    "java":       LanguageHandler(batch_extract=_java.batch_extract,       call_edges=_java.call_edges,       function_spans=_java.function_spans),
    "rust":       LanguageHandler(batch_extract=_rust.batch_extract,       call_edges=_rust.call_edges,       function_spans=_rust.function_spans),
    "javascript": LanguageHandler(batch_extract=_javascript.batch_extract, call_edges=_javascript.call_edges, function_spans=_javascript.function_spans),
    "typescript": LanguageHandler(batch_extract=_typescript.batch_extract, call_edges=_typescript.call_edges, function_spans=_typescript.function_spans),
}


def batch_extract_all(proj_dir: str) -> tuple:
    """Call batch_extract for every registered language and merge results.

    Returns (funcs, langs) where funcs is {abs_filepath: [(func_name, body)]}
    and langs is the set of language keys that returned data.
    """
    funcs = {}
    langs = set()
    for lang, handler in REGISTRY.items():
        result = handler.batch_extract(proj_dir)
        if result:
            funcs.update(result)
            langs.add(lang)
    return funcs, langs


def function_spans_for_file(proj_dir: str, filepath: str, lang_key: str):
    """Return codegraph function spans for one file, or None to fall back.

    Delegates to the registered language handler's function_spans backend.
    Returns [(func_name, start_idx, end_idx)] (0-indexed, inclusive) when
    codegraph indexes the file, or None when the language is unregistered,
    codegraph does not support it, or the file is not in the index — in every
    such case the caller should fall back to the regex extractor.
    """
    handler = REGISTRY.get(lang_key)
    if handler is None:
        return None
    return handler.function_spans(proj_dir, filepath)


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

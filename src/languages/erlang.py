"""CodeGraph-backed extraction helpers for Erlang."""

from src.languages.base import BackendUnavailableError
from src.languages.codegraph import CodeGraphExtractor


def _extractor(proj_dir: str) -> CodeGraphExtractor:
    """Return the project index or preserve the semantic-backend failure state."""
    cg = CodeGraphExtractor.from_proj_dir(proj_dir)
    if cg is None:
        raise BackendUnavailableError(
            f"CodeGraph index is unavailable for Erlang project {proj_dir}"
        )
    return cg


def batch_extract(proj_dir: str) -> dict | None:
    """Return Erlang functions, or None when CodeGraph cannot be consulted."""
    try:
        cg = _extractor(proj_dir)
    except BackendUnavailableError:
        return None
    return cg.get_functions_by_file("erlang", proj_dir)


def call_edges(proj_dir: str) -> list | None:
    """Return CodeGraph call edges for Erlang, or None when unavailable."""
    try:
        cg = _extractor(proj_dir)
    except BackendUnavailableError:
        return None
    return cg.get_call_edges("erlang")


def function_spans(proj_dir: str, filepath: str):
    """Return Erlang function spans, preserving CodeGraph failure semantics."""
    return _extractor(proj_dir).get_function_spans("erlang", filepath)

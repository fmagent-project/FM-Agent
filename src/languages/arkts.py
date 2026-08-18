"""CodeGraph-backed extraction helpers for ArkTS."""

from src.languages.codegraph import CodeGraphExtractor


def batch_extract(proj_dir: str) -> dict:
    """Return {abs_filepath: [(func_name, body)]} for all ArkTS files."""
    cg = CodeGraphExtractor.from_proj_dir(proj_dir)
    return cg.get_functions_by_file("arkts", proj_dir) if cg else {}


def call_edges(proj_dir: str) -> dict:
    """Return CodeGraph call edges for ArkTS."""
    cg = CodeGraphExtractor.from_proj_dir(proj_dir)
    return cg.get_call_edges("arkts") if cg else None


def function_spans(proj_dir: str, filepath: str):
    """Return ArkTS function spans, or None when CodeGraph is unavailable."""
    cg = CodeGraphExtractor.from_proj_dir(proj_dir)
    return cg.get_function_spans("arkts", filepath) if cg else None

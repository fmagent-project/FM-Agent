"""Shared source-discovery rules for hardware language handlers and plugins."""

from __future__ import annotations


CHISEL_EXTENSIONS = frozenset({".scala", ".sc"})
VERILOG_EXTENSIONS = frozenset({".v", ".sv", ".svh"})

SOURCE_SCAN_EXCLUDED_DIRECTORY_NAMES = frozenset({
    ".git",
    ".hg",
    ".svn",
    ".idea",
    ".vscode",
    ".venv",
    "__pycache__",
    "node_modules",
    "venv",
    "fm_agent",
    "target",
    "build",
    "out",
    "dist",
})


def is_excluded_source_directory(name: str) -> bool:
    """Return whether a nested directory is outside hardware source scans."""
    return (
        name.startswith(".")
        or name in SOURCE_SCAN_EXCLUDED_DIRECTORY_NAMES
    )

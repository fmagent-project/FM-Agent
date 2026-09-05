"""Run-scoped Chisel/Verilog dialect detection.

The public Pipeline writes invocation metadata to ``fm_agent/plugin_context.json``
before it invokes a plugin configure hook.  This module consumes only that
metadata for scope selection and performs one source scan to choose the chip
dialect.  The selected context remains in memory for the duration of the
configure call; no persisted dialect context is required between runs.
"""

from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from src.file_utils import _is_test_file
from src.languages.hardware import (
    CHISEL_EXTENSIONS,
    SOURCE_SCAN_EXCLUDED_DIRECTORY_NAMES,
    VERILOG_EXTENSIONS,
    is_excluded_source_directory,
)


Dialect = Literal["chisel", "verilog"]
PLUGIN_CONTEXT_RELATIVE_PATH = Path("fm_agent") / "plugin_context.json"
SAMPLE_LIMIT = 5
EXCLUDED_DIRECTORY_NAMES = SOURCE_SCAN_EXCLUDED_DIRECTORY_NAMES


class ChipContextError(ValueError):
    """Raised when chip scope or dialect detection input is invalid."""


def is_excluded_directory(name: str) -> bool:
    """Return whether *name* is excluded from hardware source discovery."""
    return is_excluded_source_directory(name)


@dataclass(frozen=True)
class DialectEvidence:
    """Deterministic source evidence retained for diagnostics."""

    chisel_count: int
    verilog_count: int
    chisel_samples: tuple[str, ...]
    verilog_samples: tuple[str, ...]

    def to_dict(self) -> dict[str, object]:
        return {
            "chisel_count": self.chisel_count,
            "verilog_count": self.verilog_count,
            "chisel_samples": list(self.chisel_samples),
            "verilog_samples": list(self.verilog_samples),
        }


@dataclass(frozen=True)
class ChipContext:
    """The in-memory routing fact used by one chip configure invocation."""

    dialect: Dialect
    evidence: DialectEvidence
    submodules: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, object]:
        """Return a diagnostic representation without making it persistent."""
        return {
            "dialect": self.dialect,
            "scope": {"submodules": list(self.submodules)},
            "evidence": self.evidence.to_dict(),
        }


def _normalize_scope(project: Path, submodules: object) -> tuple[str, ...]:
    """Validate and canonicalize a plugin scope relative to *project*."""
    if submodules is None:
        return ()
    if not isinstance(submodules, (list, tuple)):
        raise ChipContextError(
            "plugin scope 'submodules' must be a list of strings"
        )

    project_root = project.resolve()
    normalized: list[str] = []
    seen: set[str] = set()
    for raw in submodules:
        if not isinstance(raw, str) or not raw.strip():
            raise ChipContextError(
                "plugin scope 'submodules' must contain non-empty strings"
            )
        candidate = Path(raw.strip())
        if not candidate.is_absolute():
            candidate = project_root / candidate
        candidate = candidate.resolve()
        try:
            inside = candidate.is_relative_to(project_root)
        except AttributeError:  # pragma: no cover - Python < 3.9 fallback
            inside = os.path.commonpath(
                [str(project_root), str(candidate)]
            ) == str(project_root)
        if not inside or candidate == project_root or not candidate.is_dir():
            raise ChipContextError(
                "plugin scope submodule must name a directory inside project: "
                f"{raw!r}"
            )
        relative = candidate.relative_to(project_root).as_posix()
        if relative not in seen:
            normalized.append(relative)
            seen.add(relative)

    collapsed: list[str] = []
    for relative in sorted(normalized, key=lambda path: (path.count("/"), path)):
        if not any(
            relative == parent or relative.startswith(parent + "/")
            for parent in collapsed
        ):
            collapsed.append(relative)
    return tuple(collapsed)


def read_plugin_context(proj_dir: str | Path) -> dict[str, object]:
    """Read the public invocation context, or return an empty context."""
    project = Path(proj_dir).resolve()
    context_path = project / PLUGIN_CONTEXT_RELATIVE_PATH
    if not context_path.is_file():
        return {}
    try:
        with context_path.open("r", encoding="utf-8") as file:
            data = json.load(file)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ChipContextError(
            f"missing or invalid plugin context at {context_path}: {exc}"
        ) from exc
    if not isinstance(data, dict):
        raise ChipContextError("plugin context must be a JSON object")
    return data


def read_plugin_submodules(proj_dir: str | Path) -> tuple[str, ...]:
    """Read the invocation scope written by the public Pipeline.

    Older callers may omit ``submodules`` entirely.  That means the whole
    project is in scope; it is not a reason to rescan or to fail the configure
    hook.  Malformed JSON and malformed explicit scope values remain errors.
    """
    project = Path(proj_dir).resolve()
    data = read_plugin_context(project)
    return _normalize_scope(project, data.get("submodules", ()))


def _relative_samples(
    project: Path,
    submodules: tuple[str, ...] = (),
) -> tuple[list[str], list[str]]:
    """Return sorted Chisel and Verilog files in the selected project scope."""
    chisel_files: list[str] = []
    verilog_files: list[str] = []
    roots = [project / relative for relative in submodules] if submodules else [project]
    seen: set[str] = set()

    for scan_root in roots:
        for current_root, dirnames, filenames in os.walk(scan_root):
            dirnames[:] = sorted(
                name for name in dirnames if not is_excluded_directory(name)
            )
            root = Path(current_root)
            for filename in sorted(filenames):
                path = root / filename
                suffix = path.suffix.lower()
                if suffix not in CHISEL_EXTENSIONS | VERILOG_EXTENSIONS:
                    continue
                relative_path = path.relative_to(project).as_posix()
                if relative_path in seen or _is_test_file(relative_path):
                    continue
                seen.add(relative_path)
                if suffix in CHISEL_EXTENSIONS:
                    chisel_files.append(relative_path)
                else:
                    verilog_files.append(relative_path)

    return sorted(chisel_files), sorted(verilog_files)


def detect_chip_context(
    proj_dir: str | Path,
    submodules: object = (),
) -> ChipContext:
    """Choose one hardware dialect from the selected source scope.

    Chisel wins when both dialects are present.  This deterministic policy keeps
    mixed repositories usable while the Profile language filter ensures the
    selected run only processes the chosen backend.
    """
    project = Path(proj_dir).resolve()
    if not project.is_dir():
        raise ChipContextError(f"project directory does not exist: {project}")

    normalized_scope = _normalize_scope(project, submodules)
    chisel_files, verilog_files = _relative_samples(project, normalized_scope)
    evidence = DialectEvidence(
        chisel_count=len(chisel_files),
        verilog_count=len(verilog_files),
        chisel_samples=tuple(chisel_files[:SAMPLE_LIMIT]),
        verilog_samples=tuple(verilog_files[:SAMPLE_LIMIT]),
    )

    if chisel_files:
        dialect: Dialect = "chisel"
        if verilog_files:
            logging.warning(
                "Chip dialect detection found both Chisel (%d file(s), e.g. %s) "
                "and Verilog (%d file(s), e.g. %s); selecting Chisel for this run.",
                len(chisel_files), ", ".join(evidence.chisel_samples),
                len(verilog_files), ", ".join(evidence.verilog_samples),
            )
    elif verilog_files:
        dialect = "verilog"
    else:
        supported = ", ".join(sorted(CHISEL_EXTENSIONS | VERILOG_EXTENSIONS))
        scope = (
            f" (selected submodules: {', '.join(normalized_scope)})"
            if normalized_scope else ""
        )
        raise ChipContextError(
            "chip plugin found no Chisel or Verilog source files under "
            f"{project}{scope}; expected one of: {supported}"
        )

    return ChipContext(
        dialect=dialect,
        evidence=evidence,
        submodules=normalized_scope,
    )


def detect_dialect(
    proj_dir: str | Path,
    submodules: object = (),
) -> Dialect:
    """Return only the selected dialect for callers that need no evidence."""
    return detect_chip_context(proj_dir, submodules=submodules).dialect

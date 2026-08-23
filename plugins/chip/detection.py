"""Run-scoped Chisel/Verilog dialect detection and context persistence."""

from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Literal

from src.languages.hardware import (
    CHISEL_EXTENSIONS,
    SOURCE_SCAN_EXCLUDED_DIRECTORY_NAMES,
    VERILOG_EXTENSIONS,
    is_excluded_source_directory,
)

Dialect = Literal["chisel", "verilog"]
SCHEMA_VERSION = 2
CONTEXT_RELATIVE_PATH = Path("fm_agent") / "chip_context.json"
PLUGIN_CONTEXT_RELATIVE_PATH = Path("fm_agent") / "plugin_context.json"
SAMPLE_LIMIT = 5
EXCLUDED_DIRECTORY_NAMES = SOURCE_SCAN_EXCLUDED_DIRECTORY_NAMES


class ChipContextError(ValueError):
    """Raised when dialect detection or its persisted context is invalid."""


def is_excluded_directory(name: str) -> bool:
    return is_excluded_source_directory(name)


@dataclass(frozen=True)
class DialectEvidence:
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
    """The routing fact used throughout one chip-plugin run."""

    dialect: Dialect
    evidence: DialectEvidence
    submodules: tuple[str, ...] = ()
    schema_version: int = SCHEMA_VERSION

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "dialect": self.dialect,
            "scope": {"submodules": list(self.submodules)},
            "evidence": self.evidence.to_dict(),
        }


def _normalize_scope(project: Path, submodules: object) -> tuple[str, ...]:
    """Validate and canonicalize a plugin scope relative to *project*."""
    if submodules is None:
        return ()
    if not isinstance(submodules, (list, tuple)):
        raise ChipContextError("plugin scope 'submodules' must be a list of strings")

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
        except AttributeError:  # pragma: no cover
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


def read_plugin_submodules(proj_dir: str | Path) -> tuple[str, ...]:
    """Read the normalized run scope persisted by the public pipeline."""
    project = Path(proj_dir).resolve()
    context_path = project / PLUGIN_CONTEXT_RELATIVE_PATH
    if not context_path.is_file():
        return ()
    try:
        with context_path.open("r", encoding="utf-8") as file:
            data = json.load(file)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ChipContextError(
            f"missing or invalid plugin context at {context_path}: {exc}"
        ) from exc
    if not isinstance(data, dict):
        raise ChipContextError("plugin context must be a JSON object")
    if "submodules" not in data:
        raise ChipContextError("plugin context is missing 'submodules'")
    return _normalize_scope(project, data["submodules"])


def _relative_samples(
    proj_dir: Path,
    submodules: tuple[str, ...] = (),
) -> tuple[list[str], list[str]]:
    chisel_files: list[str] = []
    verilog_files: list[str] = []
    roots = [proj_dir / relative for relative in submodules] if submodules else [proj_dir]
    seen: set[str] = set()
    for scan_root in roots:
        for current_root, dirnames, filenames in os.walk(scan_root):
            dirnames[:] = sorted(
                name for name in dirnames if not is_excluded_directory(name)
            )
            root = Path(current_root)
            for filename in sorted(filenames):
                suffix = Path(filename).suffix.lower()
                if suffix not in CHISEL_EXTENSIONS | VERILOG_EXTENSIONS:
                    continue
                relative_path = (root / filename).relative_to(proj_dir).as_posix()
                if relative_path in seen:
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
    """Scan the selected target scope and choose one hardware dialect."""
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
    return ChipContext(dialect=dialect, evidence=evidence, submodules=normalized_scope)


def _require_non_negative_int(value: object, field: str) -> int:
    if type(value) is not int or value < 0:
        raise ChipContextError(
            f"chip context field '{field}' must be a non-negative integer"
        )
    return value


def _require_string_list(value: object, field: str) -> tuple[str, ...]:
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise ChipContextError(
            f"chip context field '{field}' must be a list of strings"
        )
    if len(value) > SAMPLE_LIMIT:
        raise ChipContextError(
            f"chip context field '{field}' contains more than {SAMPLE_LIMIT} samples"
        )
    return tuple(value)


def parse_chip_context(data: object) -> ChipContext:
    """Validate and parse the persisted chip context schema."""
    if not isinstance(data, dict):
        raise ChipContextError("chip context must be a JSON object")
    if set(data) != {"schema_version", "dialect", "scope", "evidence"}:
        raise ChipContextError("chip context has missing or unsupported top-level fields")
    if data["schema_version"] != SCHEMA_VERSION:
        raise ChipContextError(
            "unsupported chip context schema_version: "
            f"{data['schema_version']!r}; expected {SCHEMA_VERSION}"
        )
    dialect = data["dialect"]
    if dialect not in {"chisel", "verilog"}:
        raise ChipContextError(f"unsupported chip dialect: {dialect!r}")

    scope_data = data["scope"]
    if not isinstance(scope_data, dict) or set(scope_data) != {"submodules"}:
        raise ChipContextError("chip context scope has missing or unsupported fields")
    raw_scope = scope_data["submodules"]
    if not isinstance(raw_scope, list) or not all(
        isinstance(item, str) and item for item in raw_scope
    ):
        raise ChipContextError("chip context scope.submodules must be a list of strings")
    normalized_scope = tuple(str(PurePosixPath(item)) for item in raw_scope)
    if list(normalized_scope) != raw_scope:
        raise ChipContextError(
            "chip context scope.submodules must contain normalized project-relative paths"
        )
    if any(
        PurePosixPath(item).is_absolute()
        or ".." in PurePosixPath(item).parts
        or item in {"", "."}
        for item in normalized_scope
    ):
        raise ChipContextError(
            "chip context scope.submodules must contain safe relative paths"
        )
    if len(set(normalized_scope)) != len(normalized_scope):
        raise ChipContextError("chip context scope.submodules must not contain duplicates")

    evidence_data = data["evidence"]
    expected_evidence_fields = {
        "chisel_count", "verilog_count", "chisel_samples", "verilog_samples",
    }
    if not isinstance(evidence_data, dict) or set(evidence_data) != expected_evidence_fields:
        raise ChipContextError("chip context evidence has missing or unsupported fields")
    evidence = DialectEvidence(
        chisel_count=_require_non_negative_int(
            evidence_data["chisel_count"], "evidence.chisel_count"
        ),
        verilog_count=_require_non_negative_int(
            evidence_data["verilog_count"], "evidence.verilog_count"
        ),
        chisel_samples=_require_string_list(
            evidence_data["chisel_samples"], "evidence.chisel_samples"
        ),
        verilog_samples=_require_string_list(
            evidence_data["verilog_samples"], "evidence.verilog_samples"
        ),
    )
    if len(evidence.chisel_samples) > evidence.chisel_count:
        raise ChipContextError("Chisel sample count exceeds detected file count")
    if len(evidence.verilog_samples) > evidence.verilog_count:
        raise ChipContextError("Verilog sample count exceeds detected file count")
    if dialect == "chisel" and evidence.chisel_count == 0:
        raise ChipContextError("Chisel dialect requires at least one Chisel evidence file")
    if dialect == "verilog" and (
        evidence.verilog_count == 0 or evidence.chisel_count != 0
    ):
        raise ChipContextError(
            "Verilog dialect requires Verilog evidence and no Chisel evidence"
        )
    return ChipContext(
        dialect=dialect,
        evidence=evidence,
        submodules=normalized_scope,
    )


def write_chip_context(proj_dir: str | Path, context: ChipContext) -> Path:
    """Atomically persist a validated run-scoped dialect context."""
    project = Path(proj_dir).resolve()
    parsed = parse_chip_context(context.to_dict())
    context_path = project / CONTEXT_RELATIVE_PATH
    context_path.parent.mkdir(parents=True, exist_ok=True)
    temporary_path = context_path.with_suffix(".json.tmp")
    try:
        with temporary_path.open("w", encoding="utf-8") as file:
            json.dump(parsed.to_dict(), file, indent=2)
            file.write("\n")
        temporary_path.replace(context_path)
    except OSError:
        temporary_path.unlink(missing_ok=True)
        raise
    return context_path


def read_chip_context(proj_dir: str | Path) -> ChipContext:
    """Read the persisted routing fact without falling back to a rescan."""
    context_path = Path(proj_dir).resolve() / CONTEXT_RELATIVE_PATH
    try:
        with context_path.open("r", encoding="utf-8") as file:
            data = json.load(file)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ChipContextError(
            f"missing or invalid chip context at {context_path}: {exc}"
        ) from exc
    return parse_chip_context(data)


def validate_context_dialect(context: ChipContext, expected: Dialect) -> None:
    """Fail fast if a configured strategy disagrees with the run context."""
    if context.dialect != expected:
        raise ChipContextError(
            f"chip context dialect {context.dialect!r} does not match "
            f"configured dialect {expected!r}"
        )

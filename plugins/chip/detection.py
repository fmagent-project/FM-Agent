"""Run-scoped Chisel/Verilog dialect detection and context persistence."""

from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Literal


Dialect = Literal["chisel", "verilog"]

SCHEMA_VERSION = 1
CONTEXT_RELATIVE_PATH = Path("fm_agent") / "chip_context.json"
SAMPLE_LIMIT = 5

CHISEL_EXTENSIONS = frozenset({".scala", ".sc"})
VERILOG_EXTENSIONS = frozenset({".v", ".sv", ".svh"})

# This list is shared by dialect detection now and is intended to be reused by
# the Stage 1/2 strategies and language handlers as they are added.
EXCLUDED_DIRECTORY_NAMES = frozenset({
    ".git",
    ".hg",
    ".svn",
    ".idea",
    ".vscode",
    ".venv",
    "node_modules",
    "fm_agent",
    "target",
    "build",
    "out",
    "dist",
})


class ChipContextError(ValueError):
    """Raised when dialect detection or its persisted context is invalid."""


def is_excluded_directory(name: str) -> bool:
    """Return whether a nested directory is outside chip source discovery."""
    return name.startswith(".") or name in EXCLUDED_DIRECTORY_NAMES


@dataclass(frozen=True)
class DialectEvidence:
    """Deterministic evidence collected while selecting a hardware dialect."""

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
    """The single routing fact used throughout one chip-plugin run."""

    dialect: Dialect
    evidence: DialectEvidence
    schema_version: int = SCHEMA_VERSION

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "dialect": self.dialect,
            "evidence": self.evidence.to_dict(),
        }


def _relative_samples(proj_dir: Path) -> tuple[list[str], list[str]]:
    chisel_files: list[str] = []
    verilog_files: list[str] = []

    for current_root, dirnames, filenames in os.walk(proj_dir):
        dirnames[:] = sorted(
            name
            for name in dirnames
            if not is_excluded_directory(name)
        )
        root = Path(current_root)
        for filename in sorted(filenames):
            suffix = Path(filename).suffix.lower()
            if suffix not in CHISEL_EXTENSIONS | VERILOG_EXTENSIONS:
                continue
            relative_path = (root / filename).relative_to(proj_dir).as_posix()
            if suffix in CHISEL_EXTENSIONS:
                chisel_files.append(relative_path)
            else:
                verilog_files.append(relative_path)

    # os.walk is ordered above, but sorting the final paths also makes the
    # evidence independent of platform traversal details.
    return sorted(chisel_files), sorted(verilog_files)


def detect_chip_context(proj_dir: str | Path) -> ChipContext:
    """Scan *proj_dir* once and deterministically select one hardware dialect."""
    project = Path(proj_dir).resolve()
    if not project.is_dir():
        raise ChipContextError(f"project directory does not exist: {project}")

    chisel_files, verilog_files = _relative_samples(project)
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
                len(chisel_files),
                ", ".join(evidence.chisel_samples),
                len(verilog_files),
                ", ".join(evidence.verilog_samples),
            )
    elif verilog_files:
        dialect = "verilog"
    else:
        supported = ", ".join(sorted(CHISEL_EXTENSIONS | VERILOG_EXTENSIONS))
        raise ChipContextError(
            "chip plugin found no Chisel or Verilog source files under "
            f"{project}; expected one of: {supported}"
        )

    return ChipContext(dialect=dialect, evidence=evidence)


def _require_non_negative_int(value: object, field: str) -> int:
    if type(value) is not int or value < 0:
        raise ChipContextError(
            f"chip context field '{field}' must be a non-negative integer"
        )
    return value


def _require_string_list(value: object, field: str) -> tuple[str, ...]:
    if not isinstance(value, list) or not all(
        isinstance(item, str) for item in value
    ):
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
    if set(data) != {"schema_version", "dialect", "evidence"}:
        raise ChipContextError("chip context has missing or unsupported top-level fields")
    if data["schema_version"] != SCHEMA_VERSION:
        raise ChipContextError(
            "unsupported chip context schema_version: "
            f"{data['schema_version']!r}; expected {SCHEMA_VERSION}"
        )

    dialect = data["dialect"]
    if dialect not in {"chisel", "verilog"}:
        raise ChipContextError(f"unsupported chip dialect: {dialect!r}")

    evidence_data = data["evidence"]
    expected_evidence_fields = {
        "chisel_count",
        "verilog_count",
        "chisel_samples",
        "verilog_samples",
    }
    if (
        not isinstance(evidence_data, dict)
        or set(evidence_data) != expected_evidence_fields
    ):
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

    return ChipContext(dialect=dialect, evidence=evidence)


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

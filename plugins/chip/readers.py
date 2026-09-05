"""Markdown readers used by the chip Profile batch-prompt builder."""

from __future__ import annotations

from pathlib import Path
from typing import Sequence

from .validation import find_dependency_section


def _self_spec_path(unit_file: Path) -> Path:
    unit_file = Path(unit_file)
    return unit_file.with_name(f"{unit_file.stem}_spec.md")


def _dependency_info_path(unit_file: Path) -> Path:
    unit_file = Path(unit_file)
    return unit_file.with_name(f"{unit_file.stem}_info.md")


def read_self_spec(unit_file: Path) -> str | None:
    """Read the complete self-spec when it is present and non-empty."""
    try:
        text = _self_spec_path(unit_file).read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return None
    return text if text.strip() else None


def read_dependency_expectation(
    caller_file: Path,
    callee_fqn: str,
    aliases: Sequence[str] = (),
) -> str | None:
    """Read only the matching caller dependency section, if one exists."""
    try:
        text = _dependency_info_path(caller_file).read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return None
    if not text.strip():
        return None
    return find_dependency_section(text, callee_fqn, aliases)


HARDWARE_SELF_SPEC_READER = read_self_spec
HARDWARE_DEPENDENCY_READER = read_dependency_expectation

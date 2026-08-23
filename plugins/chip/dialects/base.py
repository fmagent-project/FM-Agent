"""Shared Stage 1/2 routing contract for hardware dialects."""

from __future__ import annotations

import json
import os
from collections import Counter
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from src.file_utils import _is_test_file, _is_under_submodules
from src.languages.hardware import is_excluded_source_directory


_PROMPTS_ROOT = Path(__file__).resolve().parents[1] / "prompts"


@dataclass(frozen=True)
class DialectStrategy:
    """Static resources and phase-plan rules for one selected dialect."""

    dialect: str
    language: str
    extensions: tuple[str, ...]

    @property
    def spec_form_id(self) -> str:
        return f"chip-{self.dialect}"

    @property
    def phase_plan_workflow(self) -> Path:
        return (
            _PROMPTS_ROOT
            / self.dialect
            / "workflow_generate_phases.md"
        )

    @property
    def domain_context_workflow(self) -> Path:
        return (
            _PROMPTS_ROOT
            / self.dialect
            / "workflow_generate_domain_context.md"
        )

    def required_resources(self) -> tuple[Path, ...]:
        return (
            self.phase_plan_workflow,
            self.domain_context_workflow,
        )

    def validate_phase_plan(
        self,
        phases_path: str | Path,
        *,
        submodules: tuple[str, ...] | list[str] = (),
    ) -> list[str]:
        """Return dialect-specific errors for an otherwise valid phase plan."""
        path = Path(phases_path)
        with path.open("r", encoding="utf-8") as file:
            data = json.load(file)

        errors: list[str] = []
        if data.get("languages") != [self.language]:
            errors.append(
                "languages must be exactly "
                f"[{self.language!r}] for the selected {self.dialect} dialect"
            )

        raw_extensions = data.get("file_extensions")
        expected_extensions = list(self.extensions)
        if raw_extensions != expected_extensions:
            errors.append(
                "file_extensions must be exactly "
                f"{expected_extensions!r} for the selected {self.dialect} dialect"
            )

        source_count = 0
        listed_sources: list[str] = []
        project_root = path.resolve().parent.parent
        for phase_index, phase in enumerate(data.get("phases", [])):
            for module_index, module in enumerate(phase.get("modules", [])):
                for source_index, raw_source in enumerate(
                    module.get("source_files", [])
                ):
                    if not isinstance(raw_source, str):
                        continue
                    source_count += 1
                    listed_sources.append(raw_source.replace("\\", "/"))
                    location = (
                        f"phases[{phase_index}].modules[{module_index}]"
                        f".source_files[{source_index}]"
                    )
                    errors.extend(
                        self._validate_source_path(
                            raw_source,
                            location,
                            project_root,
                            submodules=submodules,
                        )
                    )

        if source_count == 0:
            errors.append(
                f"phases.json must list at least one {self.dialect} source file"
            )
        duplicates = sorted(
            source
            for source, count in Counter(listed_sources).items()
            if count > 1
        )
        if duplicates:
            errors.append(
                "source files must be listed at most once; duplicates: "
                + ", ".join(duplicates)
            )

        expected_sources = self._discover_source_files(
            project_root,
            submodules=submodules,
        )
        missing_sources = sorted(expected_sources - set(listed_sources))
        if missing_sources:
            sample = ", ".join(missing_sources[:10])
            remainder = len(missing_sources) - 10
            suffix = f" (and {remainder} more)" if remainder > 0 else ""
            errors.append(
                f"phases.json omits {len(missing_sources)} non-test "
                f"{self.dialect} source file(s): {sample}{suffix}"
            )
        return errors

    def _discover_source_files(
        self,
        project_root: Path,
        *,
        submodules: tuple[str, ...] | list[str] = (),
    ) -> set[str]:
        """Return the complete in-scope source set for this dialect."""
        sources: set[str] = set()
        roots = (
            [project_root / submodule for submodule in submodules]
            if submodules else [project_root]
        )
        for scan_root in roots:
            for current_root, dirnames, filenames in os.walk(scan_root):
                dirnames[:] = sorted(
                    name
                    for name in dirnames
                    if not is_excluded_source_directory(name)
                )
                root = Path(current_root)
                for filename in sorted(filenames):
                    path = root / filename
                    suffix = path.suffix.lower().lstrip(".")
                    if suffix not in self.extensions:
                        continue
                    relative = path.relative_to(project_root).as_posix()
                    if not _is_test_file(relative):
                        sources.add(relative)
        return sources

    def _validate_source_path(
        self,
        raw_source: str,
        location: str,
        project_root: Path,
        *,
        submodules: tuple[str, ...] | list[str] = (),
    ) -> list[str]:
        normalized = raw_source.replace("\\", "/")
        pure_path = PurePosixPath(normalized)
        errors: list[str] = []

        if pure_path.is_absolute() or ".." in pure_path.parts:
            return [f"{location} must be a project-relative path: {raw_source!r}"]
        if not pure_path.parts or normalized in {"", "."}:
            return [f"{location} must not be empty"]

        suffix = pure_path.suffix.lower().lstrip(".")
        if submodules and not _is_under_submodules(normalized, submodules):
            errors.append(
                f"{location} {raw_source!r} is outside the selected submodule scope"
            )
        if suffix not in self.extensions:
            errors.append(
                f"{location} {raw_source!r} is not a {self.dialect} source; "
                f"expected one of {list(self.extensions)!r}"
            )
        if any(
            is_excluded_source_directory(part)
            for part in pure_path.parts[:-1]
        ):
            errors.append(
                f"{location} {raw_source!r} is under an excluded source directory"
            )
        if _is_test_file(normalized):
            errors.append(
                f"{location} {raw_source!r} is a test/testbench source and must be excluded"
            )
        if not (project_root / Path(*pure_path.parts)).is_file():
            errors.append(
                f"{location} does not exist in the project: {raw_source!r}"
            )
        return errors


def get_dialect_strategy(dialect: str) -> DialectStrategy:
    """Return the immutable strategy for *dialect* or fail explicitly."""
    if dialect == "chisel":
        from .chisel import CHISEL_STRATEGY

        return CHISEL_STRATEGY
    if dialect == "verilog":
        from .verilog import VERILOG_STRATEGY

        return VERILOG_STRATEGY
    raise ValueError(f"unsupported chip dialect strategy: {dialect!r}")

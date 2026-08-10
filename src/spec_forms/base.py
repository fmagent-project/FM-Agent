"""Base contract for one specification artifact form."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from pathlib import Path
from typing import Sequence


@dataclass(frozen=True)
class SpecArtifactPaths:
    """The self-spec and dependency-info artifacts for one analysis unit."""

    self_spec: Path
    dependency_info: Path


@dataclass(frozen=True)
class SpecValidationResult:
    """Side-effect-free result of checking one unit's spec artifacts."""

    ready: bool
    errors: tuple[str, ...] = ()


class SpecForm(ABC):
    """Describe the artifacts produced by one specification form.

    Project analysis, unit extraction, dependency discovery, orchestration,
    reasoning, and candidate validation deliberately remain outside this
    contract.
    """

    id: str
    schema_version: str

    @abstractmethod
    def artifact_paths(self, unit_file: Path) -> SpecArtifactPaths:
        """Return the specification artifacts adjacent to ``unit_file``."""

    @abstractmethod
    def validate(
        self,
        unit_file: Path,
        expected_dependencies: Sequence[str] = (),
    ) -> SpecValidationResult:
        """Check artifact completeness without modifying the artifacts."""

    @abstractmethod
    def read_self_spec(self, unit_file: Path) -> str | None:
        """Return caller-facing self-spec context, or ``None`` if unreadable."""

    @abstractmethod
    def read_dependency_expectation(
        self,
        caller_file: Path,
        callee_fqn: str,
        aliases: Sequence[str] = (),
    ) -> str | None:
        """Return one caller's expectation for a callee, if recorded."""

    @abstractmethod
    def batch_intro(self, language: str) -> str:
        """Render the form-specific introduction for a batch prompt."""

    @abstractmethod
    def output_contract_prompt(self) -> str:
        """Render the form-specific output contract for a batch prompt."""

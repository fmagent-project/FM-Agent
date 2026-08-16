"""C0 bootstrap contract for hardware specification forms."""

from __future__ import annotations

from pathlib import Path
from typing import NoReturn, Sequence

from src.spec_forms import SpecArtifactPaths, SpecForm, SpecValidationResult


class BootstrapHardwareSpecForm(SpecForm):
    """Carry dialect identity until the complete C4 artifact form is added.

    C0 needs a real SpecForm so configuration can finish before Stage 1. It does
    not define the Stage 6 artifact contract early; any attempted generation
    fails explicitly instead of silently using the software form.
    """

    schema_version = "V1"
    dialect: str

    @staticmethod
    def _not_implemented() -> NoReturn:
        raise RuntimeError(
            "chip hardware specification generation is not available in the C0 "
            "plugin skeleton; complete the C4 SpecForm implementation first"
        )

    def artifact_paths(self, unit_file: Path) -> SpecArtifactPaths:
        del unit_file
        self._not_implemented()

    def is_artifact_path(self, path: Path) -> bool:
        del path
        self._not_implemented()

    def validate(
        self,
        unit_file: Path,
        expected_dependencies: Sequence[str] = (),
    ) -> SpecValidationResult:
        del unit_file, expected_dependencies
        self._not_implemented()

    def read_self_spec(self, unit_file: Path) -> str | None:
        del unit_file
        self._not_implemented()

    def read_dependency_expectation(
        self,
        caller_file: Path,
        callee_fqn: str,
        aliases: Sequence[str] = (),
    ) -> str | None:
        del caller_file, callee_fqn, aliases
        self._not_implemented()

    def batch_intro(self, language: str) -> str:
        del language
        self._not_implemented()

    def output_contract_prompt(self) -> str:
        self._not_implemented()

    def system_prompt_path(self, script_dir: Path) -> Path:
        del script_dir
        self._not_implemented()

    def workflow_prompt_path(self, script_dir: Path) -> Path:
        del script_dir
        self._not_implemented()

    def generation_instruction(self, batch_prompt_rel: str, attempt: int) -> str:
        del batch_prompt_rel, attempt
        self._not_implemented()

    def trace_outputs(self, unit_files: Sequence[Path]) -> list[str]:
        del unit_files
        self._not_implemented()

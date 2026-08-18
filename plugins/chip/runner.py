"""Shared Stage 1/2 runner for the unified chip plugin."""

from __future__ import annotations

from pathlib import Path

from plugins.chip.detection import (
    read_chip_context,
    validate_context_dialect,
)
from plugins.chip.dialects import DialectStrategy, get_dialect_strategy
from src.pipeline_setup import (
    _run_generate_domain_context,
    _run_generate_phases,
)


_REPOSITORY_ROOT = Path(__file__).resolve().parents[2]


class ChipRunnerError(RuntimeError):
    """Raised when the persisted routing fact cannot drive Stage 1/2."""


def _load_strategy(
    proj_dir: str | Path,
    expected_dialect: str,
) -> DialectStrategy:
    context = read_chip_context(proj_dir)
    validate_context_dialect(context, expected_dialect)
    strategy = get_dialect_strategy(context.dialect)
    missing = [path for path in strategy.required_resources() if not path.is_file()]
    if missing:
        rendered = ", ".join(str(path) for path in missing)
        raise ChipRunnerError(
            f"chip {context.dialect} Stage 1/2 resources are missing: {rendered}"
        )
    return strategy


def generate_phase_plan(
    proj_dir: str,
    *,
    expected_dialect: str,
) -> None:
    """Generate and dialect-check the standard ``fm_agent/phases.json``."""
    project = Path(proj_dir).resolve()
    strategy = _load_strategy(project, expected_dialect)
    work_dir = project / "fm_agent"
    _run_generate_phases(
        str(project),
        str(work_dir),
        str(_REPOSITORY_ROOT),
        workflow_source=strategy.phase_plan_workflow,
        phase_plan_validator=strategy.validate_phase_plan,
    )


def generate_domain_context(
    proj_dir: str,
    *,
    expected_dialect: str,
) -> None:
    """Generate standard domain-context files for the persisted dialect."""
    project = Path(proj_dir).resolve()
    strategy = _load_strategy(project, expected_dialect)
    phases_path = project / "fm_agent" / "phases.json"
    if not phases_path.is_file():
        raise ChipRunnerError(
            f"chip Stage 2 requires Stage 1 output at {phases_path}"
        )
    phase_errors = strategy.validate_phase_plan(phases_path)
    if phase_errors:
        raise ChipRunnerError(
            "chip Stage 2 refused a phase plan that does not match the "
            f"persisted {strategy.dialect} dialect: {'; '.join(phase_errors)}"
        )
    _run_generate_domain_context(
        str(project),
        str(project / "fm_agent"),
        str(_REPOSITORY_ROOT),
        workflow_source=strategy.domain_context_workflow,
    )

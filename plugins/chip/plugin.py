"""Standard configure entry point for the unified chip plugin."""

from plugins.chip.detection import (
    detect_chip_context,
    read_plugin_submodules,
    read_chip_context,
    validate_context_dialect,
    write_chip_context,
)
from plugins.chip.forms import ChiselSpecForm, VerilogSpecForm
from plugins.chip.runner import (
    generate_domain_context as run_generate_domain_context,
    generate_phase_plan as run_generate_phase_plan,
)
from src.spec_forms import configure_current_spec_generation


_configured_dialect: str | None = None


def configure(proj_dir: str) -> None:
    """Select one dialect once and configure its run-scoped SpecForm."""
    global _configured_dialect
    _configured_dialect = None
    submodules = read_plugin_submodules(proj_dir)
    detected = detect_chip_context(proj_dir, submodules)
    write_chip_context(proj_dir, detected)

    # Consume the persisted routing fact for configuration. Later stages must
    # use this same reader rather than independently scanning the project.
    context = read_chip_context(proj_dir)
    spec_form = (
        ChiselSpecForm()
        if context.dialect == "chisel"
        else VerilogSpecForm()
    )
    validate_context_dialect(context, spec_form.dialect)
    configure_current_spec_generation(
        spec_form=spec_form,
        enable_reasoning=False,
    )
    _configured_dialect = context.dialect


def _require_configured_dialect() -> str:
    if _configured_dialect is None:
        raise RuntimeError(
            "chip Stage 1/2 runner was invoked before configure() established "
            "the run dialect"
        )
    return _configured_dialect


def generate_phase_plan(proj_dir: str) -> None:
    """Run Stage 1 with the dialect selected during configure()."""
    run_generate_phase_plan(
        proj_dir,
        expected_dialect=_require_configured_dialect(),
    )


def generate_domain_context(proj_dir: str) -> None:
    """Run Stage 2 with the dialect selected during configure()."""
    run_generate_domain_context(
        proj_dir,
        expected_dialect=_require_configured_dialect(),
    )

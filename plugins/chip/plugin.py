"""Standard configure entry point for the unified chip plugin."""

from plugins.chip.detection import (
    detect_chip_context,
    read_chip_context,
    validate_context_dialect,
    write_chip_context,
)
from plugins.chip.forms import ChiselSpecForm, VerilogSpecForm
from src.spec_forms import configure_current_spec_generation


def configure(proj_dir: str) -> None:
    """Select one dialect once and configure its run-scoped SpecForm."""
    detected = detect_chip_context(proj_dir)
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

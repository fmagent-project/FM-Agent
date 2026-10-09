"""Configure the public Pipeline with the detected chip Profile."""

from src.specification import configure_specification

from plugins.chip.detection import detect_chip_context, read_plugin_submodules
from plugins.chip.design_document import (
    generate_design_document as _generate_design_document,
)
from plugins.chip.eligibility import prepare_spec_generation
from plugins.chip.profiles import PROFILES


def configure(proj_dir: str) -> None:
    """Detect the invocation's hardware dialect and register its Profile."""
    submodules = read_plugin_submodules(proj_dir)
    context = detect_chip_context(proj_dir, submodules=submodules)
    configure_specification(PROFILES[context.dialect])


def generate_design_document(proj_dir: str) -> None:
    """Generate the chip run's Chinese design document after specs are ready."""
    _generate_design_document(proj_dir)

"""Configure the public Pipeline with the detected chip Profile."""

from src.specification import configure_specification

from plugins.chip.detection import detect_chip_context, read_plugin_submodules
from plugins.chip.profiles import PROFILES


def configure(proj_dir: str) -> None:
    """Detect the invocation's hardware dialect and register its Profile."""
    submodules = read_plugin_submodules(proj_dir)
    context = detect_chip_context(proj_dir, submodules=submodules)
    configure_specification(PROFILES[context.dialect])

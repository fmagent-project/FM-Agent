"""Specification artifact contracts used by the pipeline."""

from .base import SpecArtifactPaths, SpecForm, SpecValidationResult
from .config import (
    SpecGenerationConfig,
    configure_current_spec_generation,
)
from .software import SOFTWARE_SPEC_FORM, SoftwareSpecForm

__all__ = [
    "SOFTWARE_SPEC_FORM",
    "SoftwareSpecForm",
    "SpecArtifactPaths",
    "SpecForm",
    "SpecGenerationConfig",
    "SpecValidationResult",
    "configure_current_spec_generation",
]

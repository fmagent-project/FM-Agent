"""Specification artifact contracts used by the pipeline."""

from .base import SpecArtifactPaths, SpecForm, SpecValidationResult
from .software import SOFTWARE_SPEC_FORM, SoftwareSpecForm

__all__ = [
    "SOFTWARE_SPEC_FORM",
    "SoftwareSpecForm",
    "SpecArtifactPaths",
    "SpecForm",
    "SpecValidationResult",
]

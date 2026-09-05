"""Specification profile primitives for the common Pipeline."""

from .profile import (
    ArtifactPair,
    ArtifactPaths,
    ArtifactValidationInput,
    ArtifactValidationResult,
    ArtifactValidator,
    BatchPromptContext,
    DependencyReader,
    GenerationPromptContext,
    PromptContract,
    PromptBundle,
    JSON_PROMPT_CONTRACT,
    SelfSpecReader,
    SOFTWARE_PROFILE,
    SpecificationProfile,
)
from .session import (
    SpecificationProfileSession,
    bind_profile_session,
    configure_specification,
)

__all__ = [
    "ArtifactPair",
    "ArtifactPaths",
    "ArtifactValidationInput",
    "ArtifactValidationResult",
    "ArtifactValidator",
    "BatchPromptContext",
    "DependencyReader",
    "GenerationPromptContext",
    "PromptContract",
    "PromptBundle",
    "JSON_PROMPT_CONTRACT",
    "SelfSpecReader",
    "SOFTWARE_PROFILE",
    "SpecificationProfile",
    "SpecificationProfileSession",
    "bind_profile_session",
    "configure_specification",
]

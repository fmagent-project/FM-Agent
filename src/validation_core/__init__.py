"""Shared, versioned contracts for the bug-validator harness."""

from .outcome_loader import (
    ArchivedLegacyCCCCertificate,
    ArtifactFamily,
    LegacyBindingCheck,
    LegacyBindingState,
    LegacyCompletionPolicy,
    LegacyPromptCompletion,
    LegacyPromptTerminal,
    OutcomeLoadError,
    OutcomeLoadErrorCode,
    TrustClass,
    legacy_all_bugs_record_is_valid,
    load_archived_legacy_certificate,
    load_legacy_compatibility_outcome,
)

__all__ = [
    "ArchivedLegacyCCCCertificate",
    "ArtifactFamily",
    "LegacyBindingCheck",
    "LegacyBindingState",
    "LegacyCompletionPolicy",
    "LegacyPromptCompletion",
    "LegacyPromptTerminal",
    "OutcomeLoadError",
    "OutcomeLoadErrorCode",
    "TrustClass",
    "legacy_all_bugs_record_is_valid",
    "load_archived_legacy_certificate",
    "load_legacy_compatibility_outcome",
]

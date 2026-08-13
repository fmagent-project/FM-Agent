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
from .routing import AdapterResolver, ValidationRouter
from .registry import (
    PresetRegistry,
    PresetRegistryError,
    PresetRegistryErrorCode,
)
from .contracts.base import ComponentKind, ComponentRef, ContractError
from .contracts.component import (
    ComponentDescriptor,
    ImplementationRef,
    SemanticClause,
    SemanticContract,
)
from .contracts.preset import (
    PresetDependency,
    RegistrationOrigin,
    RegistrationRecord,
    RegistrationTrustTier,
    ValidationPreset,
)
from .contracts.routing import (
    GenericAdapterKind,
    PresetRef,
    RoutingDecision,
    RoutingReasonCode,
    RoutingRequest,
    ValidationEngine,
    ValidationRoutingError,
    ValidationRoutingErrorCode,
)

__all__ = [
    "ArchivedLegacyCCCCertificate",
    "AdapterResolver",
    "ArtifactFamily",
    "ComponentKind",
    "ComponentRef",
    "ComponentDescriptor",
    "ContractError",
    "GenericAdapterKind",
    "PresetRef",
    "PresetDependency",
    "PresetRegistry",
    "PresetRegistryError",
    "PresetRegistryErrorCode",
    "RegistrationOrigin",
    "RegistrationRecord",
    "RegistrationTrustTier",
    "ImplementationRef",
    "LegacyBindingCheck",
    "LegacyBindingState",
    "LegacyCompletionPolicy",
    "LegacyPromptCompletion",
    "LegacyPromptTerminal",
    "OutcomeLoadError",
    "OutcomeLoadErrorCode",
    "RoutingDecision",
    "RoutingReasonCode",
    "RoutingRequest",
    "SemanticClause",
    "SemanticContract",
    "TrustClass",
    "ValidationEngine",
    "ValidationPreset",
    "ValidationRouter",
    "ValidationRoutingError",
    "ValidationRoutingErrorCode",
    "legacy_all_bugs_record_is_valid",
    "load_archived_legacy_certificate",
    "load_legacy_compatibility_outcome",
]

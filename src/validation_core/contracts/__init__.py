"""Stable data contracts shared by the generic validator harness."""

from .base import (
    ComponentKind,
    ComponentRef,
    ContractError,
    canonical_json_bytes,
    canonical_sha256,
)
from .component import (
    ComponentDescriptor,
    ImplementationRef,
    SemanticClause,
    SemanticContract,
)
from .routing import (
    GenericAdapterKind,
    PresetRef,
    RoutingDecision,
    RoutingReasonCode,
    RoutingRequest,
    ValidationEngine,
    ValidationRoutingError,
    ValidationRoutingErrorCode,
)
from .preset import (
    PresetDependency,
    RegistrationOrigin,
    RegistrationRecord,
    RegistrationTrustTier,
    ValidationPreset,
)

__all__ = [
    "ComponentKind",
    "ComponentRef",
    "ComponentDescriptor",
    "ContractError",
    "GenericAdapterKind",
    "PresetRef",
    "PresetDependency",
    "ImplementationRef",
    "RegistrationOrigin",
    "RegistrationRecord",
    "RegistrationTrustTier",
    "RoutingDecision",
    "RoutingReasonCode",
    "RoutingRequest",
    "SemanticClause",
    "SemanticContract",
    "ValidationPreset",
    "ValidationEngine",
    "ValidationRoutingError",
    "ValidationRoutingErrorCode",
    "canonical_json_bytes",
    "canonical_sha256",
]

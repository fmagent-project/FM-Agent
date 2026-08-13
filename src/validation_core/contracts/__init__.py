"""Stable data contracts shared by the generic validator harness."""

from .base import (
    ComponentKind,
    ComponentRef,
    ContractError,
    canonical_json_bytes,
    canonical_sha256,
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
    "ContractError",
    "GenericAdapterKind",
    "PresetRef",
    "PresetDependency",
    "RegistrationOrigin",
    "RegistrationRecord",
    "RegistrationTrustTier",
    "RoutingDecision",
    "RoutingReasonCode",
    "RoutingRequest",
    "ValidationPreset",
    "ValidationEngine",
    "ValidationRoutingError",
    "ValidationRoutingErrorCode",
    "canonical_json_bytes",
    "canonical_sha256",
]

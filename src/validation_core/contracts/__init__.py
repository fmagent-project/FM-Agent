"""Stable data contracts shared by the generic validator harness."""

from .routing import (
    GenericAdapterKind,
    PresetRef,
    RoutingDecision,
    RoutingReasonCode,
    RoutingRequest,
    TrustedPresetRecord,
    ValidationEngine,
    ValidationRoutingError,
    ValidationRoutingErrorCode,
)

__all__ = [
    "GenericAdapterKind",
    "PresetRef",
    "RoutingDecision",
    "RoutingReasonCode",
    "RoutingRequest",
    "TrustedPresetRecord",
    "ValidationEngine",
    "ValidationRoutingError",
    "ValidationRoutingErrorCode",
]

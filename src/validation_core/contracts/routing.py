"""Immutable contracts for selecting a bug-validation execution route.

These contracts describe a decision only.  They do not load configuration,
inspect a project, execute an adapter, or invoke the validator Agent.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum


_IDENTIFIER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


class ValidationEngine(str, Enum):
    """Top-level validator implementation selected for a case."""

    LEGACY_PROMPT = "legacy_prompt"
    GENERIC_HARNESS = "generic_harness"


class GenericAdapterKind(str, Enum):
    """Planner/executor selected inside the generic harness."""

    TRUSTED_SYSTEM_PRESET = "trusted_system_preset"
    GENERIC_AGENT = "generic_agent"


class RoutingReasonCode(str, Enum):
    """Stable reason for a successful routing decision."""

    LEGACY_PROMPT_SELECTED = "LEGACY_PROMPT_SELECTED"
    EXPLICIT_TRUSTED_PRESET = "EXPLICIT_TRUSTED_PRESET"
    AUTO_TRUSTED_PRESET = "AUTO_TRUSTED_PRESET"
    NO_MATCHING_TRUSTED_PRESET = "NO_MATCHING_TRUSTED_PRESET"


class ValidationRoutingErrorCode(str, Enum):
    """Stable failure categories emitted before any validation runs."""

    INVALID_CONTRACT = "INVALID_CONTRACT"
    DUPLICATE_PRESET_REF = "DUPLICATE_PRESET_REF"
    CONFLICTING_PRESET_HASH = "CONFLICTING_PRESET_HASH"
    PRESET_NOT_FOUND = "PRESET_NOT_FOUND"
    PRESET_NOT_REGISTERED = "PRESET_NOT_REGISTERED"
    PRESET_SYSTEM_MISMATCH = "PRESET_SYSTEM_MISMATCH"
    PRESET_CAPABILITY_MISMATCH = "PRESET_CAPABILITY_MISMATCH"
    AMBIGUOUS_PRESET = "AMBIGUOUS_PRESET"


class ValidationRoutingError(ValueError):
    """Fail-closed routing error with a machine-readable code."""

    def __init__(self, code: ValidationRoutingErrorCode, message: str):
        self.code = code
        super().__init__(message)


def _contract_error(message: str) -> ValidationRoutingError:
    return ValidationRoutingError(
        ValidationRoutingErrorCode.INVALID_CONTRACT,
        message,
    )


def _validate_identifier(value: object, field: str) -> str:
    if type(value) is not str or not _IDENTIFIER_RE.fullmatch(value):
        raise _contract_error(
            f"{field} must be a non-empty identifier containing only "
            "letters, digits, '.', '_', ':', or '-'"
        )
    return value


def _normalize_capabilities(value: object, field: str) -> tuple[str, ...]:
    if type(value) not in (tuple, list, set, frozenset):
        raise _contract_error(f"{field} must be a collection of identifiers")
    normalized = tuple(sorted({_validate_identifier(item, field) for item in value}))
    if len(normalized) != len(value):
        raise _contract_error(f"{field} must not contain duplicate values")
    return normalized


@dataclass(frozen=True)
class PresetRef:
    """Exact content reference; an id alone never selects executable policy."""

    preset_id: str
    preset_version: str
    content_sha256: str

    def __post_init__(self) -> None:
        _validate_identifier(self.preset_id, "preset_id")
        _validate_identifier(self.preset_version, "preset_version")
        if type(self.content_sha256) is not str or not _SHA256_RE.fullmatch(
            self.content_sha256
        ):
            raise _contract_error(
                "content_sha256 must be a lowercase 64-character SHA-256 digest"
            )


@dataclass(frozen=True)
class RoutingRequest:
    """Inputs frozen by the Orchestrator before observations are collected.

    The requested engine is rollout policy, not an Agent/CasePlan choice.
    """

    system_id: str
    requested_engine: ValidationEngine = ValidationEngine.LEGACY_PROMPT
    requested_preset: PresetRef | None = None
    required_capabilities: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        _validate_identifier(self.system_id, "system_id")
        if type(self.requested_engine) is not ValidationEngine:
            raise _contract_error("requested_engine must be a ValidationEngine")
        if (
            self.requested_preset is not None
            and type(self.requested_preset) is not PresetRef
        ):
            raise _contract_error("requested_preset must be a PresetRef")
        capabilities = _normalize_capabilities(
            self.required_capabilities,
            "required_capabilities",
        )
        object.__setattr__(self, "required_capabilities", capabilities)
        if (
            self.requested_engine is ValidationEngine.LEGACY_PROMPT
            and (self.requested_preset is not None or self.required_capabilities)
        ):
            raise _contract_error(
                "legacy_prompt cannot carry generic preset or capability fields"
            )


@dataclass(frozen=True)
class RoutingDecision:
    """Complete, immutable route selected before validation execution."""

    engine: ValidationEngine
    system_id: str
    reason_code: RoutingReasonCode
    adapter_kind: GenericAdapterKind | None = None
    preset: PresetRef | None = None
    registration_sha256: str | None = None

    def __post_init__(self) -> None:
        if type(self.engine) is not ValidationEngine:
            raise _contract_error("engine must be a ValidationEngine")
        if type(self.reason_code) is not RoutingReasonCode:
            raise _contract_error("reason_code must be a RoutingReasonCode")
        _validate_identifier(self.system_id, "system_id")

        if self.engine is ValidationEngine.LEGACY_PROMPT:
            if (
                self.adapter_kind is not None
                or self.preset is not None
                or self.registration_sha256 is not None
            ):
                raise _contract_error(
                    "legacy_prompt decisions cannot contain adapter or preset fields"
                )
            if self.reason_code is not RoutingReasonCode.LEGACY_PROMPT_SELECTED:
                raise _contract_error(
                    "legacy_prompt decisions require LEGACY_PROMPT_SELECTED"
                )
            return

        if type(self.adapter_kind) is not GenericAdapterKind:
            raise _contract_error(
                "generic_harness decisions require a GenericAdapterKind"
            )
        if self.adapter_kind is GenericAdapterKind.GENERIC_AGENT:
            if self.preset is not None or self.registration_sha256 is not None:
                raise _contract_error(
                    "generic_agent decisions cannot contain preset fields"
                )
            if self.reason_code is not RoutingReasonCode.NO_MATCHING_TRUSTED_PRESET:
                raise _contract_error(
                    "generic_agent requires NO_MATCHING_TRUSTED_PRESET"
                )
            return

        if type(self.preset) is not PresetRef:
            raise _contract_error(
                "trusted_system_preset decisions require an exact PresetRef"
            )
        if (
            type(self.registration_sha256) is not str
            or not _SHA256_RE.fullmatch(self.registration_sha256)
        ):
            raise _contract_error(
                "trusted_system_preset decisions require registration_sha256"
            )
        if self.reason_code not in (
            RoutingReasonCode.EXPLICIT_TRUSTED_PRESET,
            RoutingReasonCode.AUTO_TRUSTED_PRESET,
        ):
            raise _contract_error(
                "trusted_system_preset requires an explicit or automatic preset reason"
            )

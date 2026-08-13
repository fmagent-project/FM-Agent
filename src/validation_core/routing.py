"""Deterministic, side-effect-free selection of bug-validation routes."""

from __future__ import annotations

from .contracts.routing import (
    GenericAdapterKind,
    RoutingDecision,
    RoutingReasonCode,
    RoutingRequest,
    ValidationEngine,
    ValidationRoutingError,
    ValidationRoutingErrorCode,
)
from .registry import PresetRegistry, RegisteredPreset


class AdapterResolver:
    """Resolve the generic harness to one trusted preset or its agent planner."""

    def __init__(self, registry: PresetRegistry | None = None):
        if registry is not None and type(registry) is not PresetRegistry:
            raise ValidationRoutingError(
                ValidationRoutingErrorCode.INVALID_CONTRACT,
                "registry must be a PresetRegistry",
            )
        self._registry = registry or PresetRegistry()

    @staticmethod
    def _supports(
        record: RegisteredPreset,
        required_capabilities: tuple[str, ...],
    ) -> bool:
        return set(required_capabilities).issubset(
            record.registration.effective_capabilities
        )

    @staticmethod
    def _preset_decision(
        request: RoutingRequest,
        record: RegisteredPreset,
        reason_code: RoutingReasonCode,
    ) -> RoutingDecision:
        return RoutingDecision(
            engine=ValidationEngine.GENERIC_HARNESS,
            system_id=request.system_id,
            reason_code=reason_code,
            adapter_kind=GenericAdapterKind.TRUSTED_SYSTEM_PRESET,
            preset=record.preset.ref,
            registration_sha256=record.registration.registration_sha256,
        )

    def resolve(self, request: RoutingRequest) -> RoutingDecision:
        if type(request) is not RoutingRequest:
            raise ValidationRoutingError(
                ValidationRoutingErrorCode.INVALID_CONTRACT,
                "request must be a RoutingRequest",
            )
        if request.requested_engine is not ValidationEngine.GENERIC_HARNESS:
            raise ValidationRoutingError(
                ValidationRoutingErrorCode.INVALID_CONTRACT,
                "AdapterResolver only resolves generic_harness requests",
            )

        if request.requested_preset is not None:
            record = self._registry.registered_preset(request.requested_preset)
            if record is None:
                existing = self._registry.known_preset_ref(
                    request.requested_preset.preset_id,
                    request.requested_preset.preset_version,
                )
                if existing is not None and existing != request.requested_preset:
                    raise ValidationRoutingError(
                        ValidationRoutingErrorCode.CONFLICTING_PRESET_HASH,
                        f"trusted preset {existing.preset_id} version "
                        f"{existing.preset_version} is registered with another hash",
                    )
                if existing is not None:
                    raise ValidationRoutingError(
                        ValidationRoutingErrorCode.PRESET_NOT_REGISTERED,
                        f"preset is not registered: {existing.preset_id} "
                        f"{existing.preset_version}",
                    )
                raise ValidationRoutingError(
                    ValidationRoutingErrorCode.PRESET_NOT_FOUND,
                    f"trusted preset not found: {request.requested_preset.preset_id} "
                    f"{request.requested_preset.preset_version}",
                )
            if record.preset.system_id != request.system_id:
                raise ValidationRoutingError(
                    ValidationRoutingErrorCode.PRESET_SYSTEM_MISMATCH,
                    f"preset {record.preset.preset_id} is registered for "
                    f"{record.preset.system_id}, not {request.system_id}",
                )
            if not self._supports(record, request.required_capabilities):
                raise ValidationRoutingError(
                    ValidationRoutingErrorCode.PRESET_CAPABILITY_MISMATCH,
                    f"preset {record.preset.preset_id} does not satisfy all "
                    "required capabilities",
                )
            return self._preset_decision(
                request,
                record,
                RoutingReasonCode.EXPLICIT_TRUSTED_PRESET,
            )

        system_records = self._registry.registered_presets_for_system(
            request.system_id
        )
        if not system_records:
            if self._registry.has_system(request.system_id):
                raise ValidationRoutingError(
                    ValidationRoutingErrorCode.PRESET_NOT_REGISTERED,
                    f"presets exist for {request.system_id}, but none are registered",
                )
            return RoutingDecision(
                engine=ValidationEngine.GENERIC_HARNESS,
                system_id=request.system_id,
                reason_code=RoutingReasonCode.NO_MATCHING_TRUSTED_PRESET,
                adapter_kind=GenericAdapterKind.GENERIC_AGENT,
            )

        eligible = tuple(
            record
            for record in system_records
            if self._supports(record, request.required_capabilities)
        )
        if not eligible:
            raise ValidationRoutingError(
                ValidationRoutingErrorCode.PRESET_CAPABILITY_MISMATCH,
                f"trusted presets exist for {request.system_id}, but none satisfy "
                "all required capabilities",
            )
        if len(eligible) > 1:
            preset_ids = ", ".join(
                sorted(
                    f"{record.preset.preset_id}@{record.preset.preset_version}"
                    for record in eligible
                )
            )
            raise ValidationRoutingError(
                ValidationRoutingErrorCode.AMBIGUOUS_PRESET,
                f"multiple trusted presets match {request.system_id}: {preset_ids}",
            )
        return self._preset_decision(
            request,
            eligible[0],
            RoutingReasonCode.AUTO_TRUSTED_PRESET,
        )


class ValidationRouter:
    """Select the legacy engine or delegate generic selection to its resolver."""

    def __init__(self, adapter_resolver: AdapterResolver | None = None):
        if (
            adapter_resolver is not None
            and type(adapter_resolver) is not AdapterResolver
        ):
            raise ValidationRoutingError(
                ValidationRoutingErrorCode.INVALID_CONTRACT,
                "adapter_resolver must be an AdapterResolver",
            )
        self._adapter_resolver = adapter_resolver or AdapterResolver()

    def route(self, request: RoutingRequest) -> RoutingDecision:
        if type(request) is not RoutingRequest:
            raise ValidationRoutingError(
                ValidationRoutingErrorCode.INVALID_CONTRACT,
                "request must be a RoutingRequest",
            )
        if request.requested_engine is ValidationEngine.LEGACY_PROMPT:
            return RoutingDecision(
                engine=ValidationEngine.LEGACY_PROMPT,
                system_id=request.system_id,
                reason_code=RoutingReasonCode.LEGACY_PROMPT_SELECTED,
            )
        return self._adapter_resolver.resolve(request)

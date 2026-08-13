"""Static, fail-closed registry for admitted validation presets."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from enum import Enum

from .contracts.base import ComponentRef
from .contracts.preset import RegistrationRecord, ValidationPreset
from .contracts.routing import PresetRef


class PresetRegistryErrorCode(str, Enum):
    INVALID_RECORD = "INVALID_RECORD"
    DUPLICATE_PRESET_REF = "DUPLICATE_PRESET_REF"
    CONFLICTING_PRESET_HASH = "CONFLICTING_PRESET_HASH"
    DUPLICATE_REGISTRATION = "DUPLICATE_REGISTRATION"
    UNREGISTERED_PRESET = "UNREGISTERED_PRESET"
    REGISTRATION_HASH_MISMATCH = "REGISTRATION_HASH_MISMATCH"
    CAPABILITY_ESCALATION = "CAPABILITY_ESCALATION"
    COMPONENT_HASH_CONFLICT = "COMPONENT_HASH_CONFLICT"


class PresetRegistryError(ValueError):
    def __init__(self, code: PresetRegistryErrorCode, message: str):
        self.code = code
        super().__init__(message)


@dataclass(frozen=True)
class RegisteredPreset:
    """A preset paired with the exact registration that admitted it."""

    preset: ValidationPreset
    registration: RegistrationRecord


class PresetRegistry:
    """Validate preset dependency closures before exposing admitted entries.

    This in-memory registry proves metadata consistency, not signer authenticity.
    The later Profile Gate is responsible for loading registration bytes from the
    approved content-addressed store and checking its admission authority.
    """

    def __init__(
        self,
        presets: Iterable[ValidationPreset] = (),
        registrations: Iterable[RegistrationRecord] = (),
    ):
        preset_values = tuple(presets)
        registration_values = tuple(registrations)

        presets_by_ref: dict[PresetRef, ValidationPreset] = {}
        refs_by_id_version: dict[tuple[str, str], PresetRef] = {}
        for preset in preset_values:
            if type(preset) is not ValidationPreset:
                raise PresetRegistryError(
                    PresetRegistryErrorCode.INVALID_RECORD,
                    "presets must contain only ValidationPreset values",
                )
            ref = preset.ref
            if ref in presets_by_ref:
                raise PresetRegistryError(
                    PresetRegistryErrorCode.DUPLICATE_PRESET_REF,
                    f"duplicate preset reference: {ref.preset_id} "
                    f"{ref.preset_version}",
                )
            id_version = (ref.preset_id, ref.preset_version)
            existing = refs_by_id_version.get(id_version)
            if existing is not None and existing != ref:
                raise PresetRegistryError(
                    PresetRegistryErrorCode.CONFLICTING_PRESET_HASH,
                    f"preset {ref.preset_id} version {ref.preset_version} "
                    "has conflicting content hashes",
                )
            presets_by_ref[ref] = preset
            refs_by_id_version[id_version] = ref

        registrations_by_ref: dict[PresetRef, RegistrationRecord] = {}
        for registration in registration_values:
            if type(registration) is not RegistrationRecord:
                raise PresetRegistryError(
                    PresetRegistryErrorCode.INVALID_RECORD,
                    "registrations must contain only RegistrationRecord values",
                )
            preset = presets_by_ref.get(registration.preset)
            if preset is None:
                id_version = (
                    registration.preset.preset_id,
                    registration.preset.preset_version,
                )
                existing = refs_by_id_version.get(id_version)
                code = (
                    PresetRegistryErrorCode.REGISTRATION_HASH_MISMATCH
                    if existing is not None
                    else PresetRegistryErrorCode.UNREGISTERED_PRESET
                )
                raise PresetRegistryError(
                    code,
                    f"registration does not reference an exact preset: "
                    f"{registration.preset.preset_id} "
                    f"{registration.preset.preset_version}",
                )
            if registration.preset in registrations_by_ref:
                raise PresetRegistryError(
                    PresetRegistryErrorCode.DUPLICATE_REGISTRATION,
                    f"duplicate registration for {registration.preset.preset_id} "
                    f"{registration.preset.preset_version}",
                )
            if not set(registration.effective_capabilities).issubset(
                preset.capabilities
            ):
                raise PresetRegistryError(
                    PresetRegistryErrorCode.CAPABILITY_ESCALATION,
                    f"registration for {registration.preset.preset_id} grants "
                    "capabilities not declared by the preset",
                )
            registrations_by_ref[registration.preset] = registration

        component_refs: dict[tuple[str, str, str], ComponentRef] = {}
        for preset_ref in registrations_by_ref:
            preset = presets_by_ref[preset_ref]
            for component in preset.component_refs:
                key = (
                    component.kind.value,
                    component.component_id,
                    component.component_version,
                )
                existing = component_refs.get(key)
                if existing is not None and existing != component:
                    raise PresetRegistryError(
                        PresetRegistryErrorCode.COMPONENT_HASH_CONFLICT,
                        f"component {component.kind.value}:"
                        f"{component.component_id}@{component.component_version} "
                        "has conflicting hashes across admitted presets",
                    )
                component_refs[key] = component

        self._presets_by_ref = presets_by_ref
        self._refs_by_id_version = refs_by_id_version
        self._registrations_by_ref = registrations_by_ref
        self._referenced_component_refs = tuple(
            sorted(
                component_refs.values(),
                key=lambda ref: (
                    ref.kind.value,
                    ref.component_id,
                    ref.component_version,
                    ref.content_sha256,
                ),
            )
        )

    def registered_presets(self) -> tuple[RegisteredPreset, ...]:
        records: list[RegisteredPreset] = []
        for preset_ref, registration in self._registrations_by_ref.items():
            preset = self._presets_by_ref[preset_ref]
            records.append(
                RegisteredPreset(
                    preset=preset,
                    registration=registration,
                )
            )
        return tuple(
            sorted(
                records,
                key=lambda record: (
                    record.preset.system_id,
                    record.preset.preset_id,
                    record.preset.preset_version,
                    record.preset.content_sha256,
                ),
            )
        )

    def registered_presets_for_system(
        self,
        system_id: str,
    ) -> tuple[RegisteredPreset, ...]:
        return tuple(
            record
            for record in self.registered_presets()
            if record.preset.system_id == system_id
        )

    def registered_preset(self, preset: PresetRef) -> RegisteredPreset | None:
        registration = self._registrations_by_ref.get(preset)
        if registration is None:
            return None
        return RegisteredPreset(
            preset=self._presets_by_ref[preset],
            registration=registration,
        )

    def known_preset_ref(
        self,
        preset_id: str,
        preset_version: str,
    ) -> PresetRef | None:
        return self._refs_by_id_version.get((preset_id, preset_version))

    def has_system(self, system_id: str) -> bool:
        return any(
            preset.system_id == system_id
            for preset in self._presets_by_ref.values()
        )

    def referenced_component_refs(self) -> tuple[ComponentRef, ...]:
        """Return components named by registered presets.

        This does not claim that every component has an independent component
        registration.  The preset registration admits the exact aggregate
        preset hash; component-level registration belongs to a later phase.
        """

        return self._referenced_component_refs

    def require_registered_preset(self, preset: PresetRef) -> RegisteredPreset:
        if type(preset) is not PresetRef:
            raise PresetRegistryError(
                PresetRegistryErrorCode.INVALID_RECORD,
                "preset must be a PresetRef",
            )
        if preset not in self._registrations_by_ref:
            raise PresetRegistryError(
                PresetRegistryErrorCode.UNREGISTERED_PRESET,
                f"preset is not admitted: {preset.preset_id} {preset.preset_version}",
            )
        return RegisteredPreset(
            preset=self._presets_by_ref[preset],
            registration=self._registrations_by_ref[preset],
        )

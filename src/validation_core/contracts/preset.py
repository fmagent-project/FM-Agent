"""Hash-bound validation-preset content and independent trust registration."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from .base import ComponentKind, ComponentRef, ContractError, canonical_sha256
from .base import normalize_identifiers, validate_identifier, validate_sha256
from .routing import PresetRef


_PRESET_CONTRACT_KIND = "validation_preset"
_PRESET_SCHEMA_VERSION = 1
_REGISTRATION_CONTRACT_KIND = "preset_registration"
_REGISTRATION_SCHEMA_VERSION = 1


_REQUIRED_DEPENDENCIES = {
    "adapter.primary": ComponentKind.ADAPTER,
    "oracle.bundle": ComponentKind.ORACLE_BUNDLE,
    "recipe.schema": ComponentKind.EXECUTION_RECIPE_SCHEMA,
    "target_evidence.policy": ComponentKind.TARGET_EVIDENCE_POLICY,
}


@dataclass(frozen=True)
class PresetDependency:
    """A named role bound to one exact component version and hash."""

    role: str
    component: ComponentRef

    def __post_init__(self) -> None:
        validate_identifier(self.role, "role")
        if type(self.component) is not ComponentRef:
            raise ContractError("component must be a ComponentRef")

    def to_document(self) -> dict[str, object]:
        return {
            "role": self.role,
            "component": self.component.to_document(),
        }


@dataclass(frozen=True)
class ValidationPreset:
    """A trust-free, hash-bound composition of validation components.

    A preset names component schemas and policies.  A concrete CasePlan still
    supplies the per-bug ExecutionRecipe, workload, inputs, and thresholds.
    """

    preset_id: str
    preset_version: str
    system_id: str
    dependencies: tuple[PresetDependency, ...]
    capabilities: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        validate_identifier(self.preset_id, "preset_id")
        validate_identifier(self.preset_version, "preset_version")
        validate_identifier(self.system_id, "system_id")
        if type(self.dependencies) not in (tuple, list):
            raise ContractError("dependencies must be a collection")
        dependencies = tuple(self.dependencies)
        if any(type(item) is not PresetDependency for item in dependencies):
            raise ContractError("dependencies must contain only PresetDependency values")
        by_role: dict[str, PresetDependency] = {}
        for dependency in dependencies:
            if dependency.role in by_role:
                raise ContractError(
                    f"dependencies must not repeat role {dependency.role}"
                )
            by_role[dependency.role] = dependency
        for role, expected_kind in _REQUIRED_DEPENDENCIES.items():
            dependency = by_role.get(role)
            if dependency is None:
                raise ContractError(f"dependencies must include required role {role}")
            if dependency.component.kind is not expected_kind:
                raise ContractError(
                    f"dependency {role} must reference a {expected_kind.value} component"
                )
        object.__setattr__(
            self,
            "dependencies",
            tuple(sorted(dependencies, key=lambda item: item.role)),
        )
        capabilities = normalize_identifiers(self.capabilities, "capabilities")
        object.__setattr__(self, "capabilities", capabilities)

    @property
    def component_refs(self) -> tuple[ComponentRef, ...]:
        return tuple(dependency.component for dependency in self.dependencies)

    def to_document(self) -> dict[str, object]:
        return {
            "contract_kind": _PRESET_CONTRACT_KIND,
            "schema_version": _PRESET_SCHEMA_VERSION,
            "preset_id": self.preset_id,
            "preset_version": self.preset_version,
            "system_id": self.system_id,
            "dependencies": [item.to_document() for item in self.dependencies],
            "capabilities": list(self.capabilities),
        }

    @property
    def content_sha256(self) -> str:
        return canonical_sha256(self.to_document())

    @property
    def ref(self) -> PresetRef:
        return PresetRef(
            preset_id=self.preset_id,
            preset_version=self.preset_version,
            content_sha256=self.content_sha256,
        )


class RegistrationTrustTier(str, Enum):
    TRUSTED_PRESET = "trusted_preset"
    PROFILE_CUSTOM = "profile_custom"


class RegistrationOrigin(str, Enum):
    HARNESS = "harness"
    MAINTAINER = "maintainer"
    SETUP_AGENT = "setup_agent"


@dataclass(frozen=True)
class RegistrationRecord:
    """Registry-owned admission record; preset content cannot grant trust."""

    preset: PresetRef
    origin: RegistrationOrigin
    trust_tier: RegistrationTrustTier
    admission_authority: str
    effective_capabilities: tuple[str, ...]
    review_sha256: str | None = None
    approval_sha256: str | None = None
    qualification_sha256: str | None = None

    def __post_init__(self) -> None:
        if type(self.preset) is not PresetRef:
            raise ContractError("preset must be a PresetRef")
        if type(self.origin) is not RegistrationOrigin:
            raise ContractError("origin must be a RegistrationOrigin")
        if type(self.trust_tier) is not RegistrationTrustTier:
            raise ContractError("trust_tier must be a RegistrationTrustTier")
        validate_identifier(self.admission_authority, "admission_authority")
        capabilities = normalize_identifiers(
            self.effective_capabilities,
            "effective_capabilities",
        )
        object.__setattr__(self, "effective_capabilities", capabilities)
        for field in (
            "review_sha256",
            "approval_sha256",
            "qualification_sha256",
        ):
            value = getattr(self, field)
            if value is not None:
                validate_sha256(value, field)
        if self.trust_tier is RegistrationTrustTier.TRUSTED_PRESET:
            if self.review_sha256 is None or self.qualification_sha256 is None:
                raise ContractError(
                    "trusted_preset requires review and qualification hashes"
                )
            if (
                self.origin is RegistrationOrigin.SETUP_AGENT
                and self.approval_sha256 is None
            ):
                raise ContractError(
                    "setup_agent promotion to trusted_preset requires approval_sha256"
                )
        elif self.trust_tier is RegistrationTrustTier.PROFILE_CUSTOM:
            if self.origin is not RegistrationOrigin.SETUP_AGENT:
                raise ContractError("profile_custom must preserve setup_agent origin")
            if any(
                value is None
                for value in (
                    self.review_sha256,
                    self.approval_sha256,
                    self.qualification_sha256,
                )
            ):
                raise ContractError(
                    "profile_custom requires review, approval, and qualification hashes"
                )

    def to_document(self) -> dict[str, object]:
        return {
            "contract_kind": _REGISTRATION_CONTRACT_KIND,
            "schema_version": _REGISTRATION_SCHEMA_VERSION,
            "preset": {
                "preset_id": self.preset.preset_id,
                "preset_version": self.preset.preset_version,
                "content_sha256": self.preset.content_sha256,
            },
            "origin": self.origin.value,
            "trust_tier": self.trust_tier.value,
            "admission_authority": self.admission_authority,
            "effective_capabilities": list(self.effective_capabilities),
            "review_sha256": self.review_sha256,
            "approval_sha256": self.approval_sha256,
            "qualification_sha256": self.qualification_sha256,
        }

    @property
    def registration_sha256(self) -> str:
        return canonical_sha256(self.to_document())

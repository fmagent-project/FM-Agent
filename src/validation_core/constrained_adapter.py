"""Trust-free exact-reference planner for the Generic Agent demo path.

The planner deliberately has no command, path, environment, import, network,
or process fields.  It can only select immutable building blocks that an
authority-owned profile has already admitted.  Execution remains a Broker
responsibility and is outside this module.

This module is dormant: it is not exported from :mod:`src.validation_core`
and no production entry imports it.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from .contracts import ArtifactRef, ContractRef, ContractRefKind
from .contracts.base import (
    ContractError,
    canonical_sha256,
    normalize_identifiers,
    validate_identifier,
    validate_sha256,
)


_MAX_REFS = 4096


class ConstrainedAdapterErrorCode(str, Enum):
    """Stable failures emitted before any Broker or target can run."""

    INVALID_REQUEST = "INVALID_REQUEST"
    SYSTEM_MISMATCH = "SYSTEM_MISMATCH"
    ADAPTER_NOT_APPROVED = "ADAPTER_NOT_APPROVED"
    RECIPE_NOT_APPROVED = "RECIPE_NOT_APPROVED"
    ORACLE_NOT_APPROVED = "ORACLE_NOT_APPROVED"
    COLLECTOR_NOT_APPROVED = "COLLECTOR_NOT_APPROVED"
    CAPABILITY_NOT_APPROVED = "CAPABILITY_NOT_APPROVED"


class ConstrainedAdapterError(ValueError):
    """A fail-closed, machine-readable Generic Agent planning error."""

    def __init__(self, code: ConstrainedAdapterErrorCode, message: str) -> None:
        if type(code) is not ConstrainedAdapterErrorCode:
            raise TypeError("code must be a ConstrainedAdapterErrorCode")
        self.code = code
        super().__init__(message)


def _error(code: ConstrainedAdapterErrorCode, message: str) -> None:
    raise ConstrainedAdapterError(code, message)


def _ref_key(reference: ContractRef) -> tuple[str, str, str, str]:
    return (
        reference.kind.value,
        reference.contract_id,
        reference.contract_version,
        reference.content_sha256,
    )


def _refs(
    value: object,
    *,
    field: str,
    kind: ContractRefKind,
    allow_empty: bool = False,
) -> tuple[ContractRef, ...]:
    if type(value) not in (tuple, list):
        raise ContractError(f"{field} must be an ordered collection")
    items = tuple(value)
    if (not allow_empty and not items) or len(items) > _MAX_REFS:
        qualifier = "one or more" if not allow_empty else "at most"
        raise ContractError(f"{field} must contain {qualifier} {_MAX_REFS} refs")
    if any(type(item) is not ContractRef or item.kind is not kind for item in items):
        raise ContractError(f"{field} must contain only {kind.value} ContractRefs")
    if len(items) != len(set(items)):
        raise ContractError(f"{field} must not contain duplicate refs")
    identities: dict[tuple[str, str, str], str] = {}
    for item in items:
        identity = (item.kind.value, item.contract_id, item.contract_version)
        previous = identities.get(identity)
        if previous is not None and previous != item.content_sha256:
            raise ContractError(f"{field} contains conflicting hashes for one identity")
        identities[identity] = item.content_sha256
    return tuple(sorted(items, key=_ref_key))


def _artifacts(value: object, field: str) -> tuple[ArtifactRef, ...]:
    if type(value) not in (tuple, list):
        raise ContractError(f"{field} must be an ordered collection")
    items = tuple(value)
    if len(items) > _MAX_REFS or any(type(item) is not ArtifactRef for item in items):
        raise ContractError(
            f"{field} must contain at most {_MAX_REFS} ArtifactRefs"
        )
    roles = tuple(item.role for item in items)
    if len(roles) != len(set(roles)):
        raise ContractError(f"{field} must not repeat artifact roles")
    return tuple(sorted(items, key=lambda item: item.role))


def _adapter_ref(value: object, field: str) -> ContractRef:
    if type(value) is not ContractRef or value.kind is not ContractRefKind.ADAPTER:
        raise ContractError(f"{field} must be an adapter ContractRef")
    return value


@dataclass(frozen=True)
class ApprovedAdapterProfile:
    """Authority-provided exact membership visible to the planner.

    This value describes already-approved membership; it does not authenticate
    approval by itself.  The caller must obtain it from a pinned Profile Gate
    result before using a plan outside this non-admissible demo.
    """

    system_id: str
    profile_sha256: str
    adapter: ContractRef
    execution_recipes: tuple[ContractRef, ...]
    oracle_specs: tuple[ContractRef, ...]
    collectors: tuple[ContractRef, ...]
    effective_capabilities: tuple[str, ...]

    def __post_init__(self) -> None:
        validate_identifier(self.system_id, "system_id")
        validate_sha256(self.profile_sha256, "profile_sha256")
        _adapter_ref(self.adapter, "adapter")
        object.__setattr__(
            self,
            "execution_recipes",
            _refs(
                self.execution_recipes,
                field="execution_recipes",
                kind=ContractRefKind.EXECUTION_RECIPE,
            ),
        )
        object.__setattr__(
            self,
            "oracle_specs",
            _refs(
                self.oracle_specs,
                field="oracle_specs",
                kind=ContractRefKind.ORACLE_SPEC,
            ),
        )
        object.__setattr__(
            self,
            "collectors",
            _refs(
                self.collectors,
                field="collectors",
                kind=ContractRefKind.COLLECTOR,
            ),
        )
        object.__setattr__(
            self,
            "effective_capabilities",
            normalize_identifiers(
                self.effective_capabilities,
                "effective_capabilities",
            ),
        )

    def to_document(self) -> dict[str, object]:
        return {
            "contract_kind": "approved_adapter_profile_demo",
            "schema_version": 1,
            "system_id": self.system_id,
            "profile_sha256": self.profile_sha256,
            "adapter": self.adapter.to_document(),
            "execution_recipes": [item.to_document() for item in self.execution_recipes],
            "oracle_specs": [item.to_document() for item in self.oracle_specs],
            "collectors": [item.to_document() for item in self.collectors],
            "effective_capabilities": list(self.effective_capabilities),
        }

    @property
    def content_sha256(self) -> str:
        return canonical_sha256(self.to_document())


@dataclass(frozen=True)
class ConstrainedPlanRequest:
    """Agent-selectable values; every executable choice is an exact ref."""

    system_id: str
    adapter: ContractRef
    execution_recipe: ContractRef
    oracle_specs: tuple[ContractRef, ...]
    collectors: tuple[ContractRef, ...]
    required_capabilities: tuple[str, ...] = ()
    input_artifacts: tuple[ArtifactRef, ...] = ()

    def __post_init__(self) -> None:
        validate_identifier(self.system_id, "system_id")
        _adapter_ref(self.adapter, "adapter")
        if (
            type(self.execution_recipe) is not ContractRef
            or self.execution_recipe.kind is not ContractRefKind.EXECUTION_RECIPE
        ):
            raise ContractError(
                "execution_recipe must be an execution_recipe ContractRef"
            )
        object.__setattr__(
            self,
            "oracle_specs",
            _refs(
                self.oracle_specs,
                field="oracle_specs",
                kind=ContractRefKind.ORACLE_SPEC,
            ),
        )
        object.__setattr__(
            self,
            "collectors",
            _refs(
                self.collectors,
                field="collectors",
                kind=ContractRefKind.COLLECTOR,
            ),
        )
        object.__setattr__(
            self,
            "required_capabilities",
            normalize_identifiers(
                self.required_capabilities,
                "required_capabilities",
            ),
        )
        object.__setattr__(
            self,
            "input_artifacts",
            _artifacts(self.input_artifacts, "input_artifacts"),
        )

    def to_document(self) -> dict[str, object]:
        return {
            "contract_kind": "constrained_plan_request_demo",
            "schema_version": 1,
            "system_id": self.system_id,
            "adapter": self.adapter.to_document(),
            "execution_recipe": self.execution_recipe.to_document(),
            "oracle_specs": [item.to_document() for item in self.oracle_specs],
            "collectors": [item.to_document() for item in self.collectors],
            "required_capabilities": list(self.required_capabilities),
            "input_artifacts": [item.to_document() for item in self.input_artifacts],
        }

    @property
    def content_sha256(self) -> str:
        return canonical_sha256(self.to_document())


@dataclass(frozen=True)
class ConstrainedExecutionPlan:
    """A non-executable selection receipt for approved building blocks."""

    system_id: str
    approved_profile_sha256: str
    approved_profile_contract_sha256: str
    request_sha256: str
    adapter: ContractRef
    execution_recipe: ContractRef
    oracle_specs: tuple[ContractRef, ...]
    collectors: tuple[ContractRef, ...]
    input_artifacts: tuple[ArtifactRef, ...]

    def __post_init__(self) -> None:
        validate_identifier(self.system_id, "system_id")
        validate_sha256(self.approved_profile_sha256, "approved_profile_sha256")
        validate_sha256(
            self.approved_profile_contract_sha256,
            "approved_profile_contract_sha256",
        )
        validate_sha256(self.request_sha256, "request_sha256")
        _adapter_ref(self.adapter, "adapter")
        if (
            type(self.execution_recipe) is not ContractRef
            or self.execution_recipe.kind is not ContractRefKind.EXECUTION_RECIPE
        ):
            raise ContractError(
                "execution_recipe must be an execution_recipe ContractRef"
            )
        object.__setattr__(
            self,
            "oracle_specs",
            _refs(
                self.oracle_specs,
                field="oracle_specs",
                kind=ContractRefKind.ORACLE_SPEC,
            ),
        )
        object.__setattr__(
            self,
            "collectors",
            _refs(
                self.collectors,
                field="collectors",
                kind=ContractRefKind.COLLECTOR,
            ),
        )
        object.__setattr__(
            self,
            "input_artifacts",
            _artifacts(self.input_artifacts, "input_artifacts"),
        )

    def to_document(self) -> dict[str, object]:
        return {
            "contract_kind": "constrained_execution_plan_demo",
            "schema_version": 1,
            "system_id": self.system_id,
            "approved_profile_sha256": self.approved_profile_sha256,
            "approved_profile_contract_sha256": (
                self.approved_profile_contract_sha256
            ),
            "request_sha256": self.request_sha256,
            "adapter": self.adapter.to_document(),
            "execution_recipe": self.execution_recipe.to_document(),
            "oracle_specs": [item.to_document() for item in self.oracle_specs],
            "collectors": [item.to_document() for item in self.collectors],
            "input_artifacts": [item.to_document() for item in self.input_artifacts],
        }

    @property
    def content_sha256(self) -> str:
        return canonical_sha256(self.to_document())


class ConstrainedExactRefPlanner:
    """Select only exact, profile-admitted refs; never execute them."""

    def __init__(self, approved_profile: ApprovedAdapterProfile) -> None:
        if type(approved_profile) is not ApprovedAdapterProfile:
            _error(
                ConstrainedAdapterErrorCode.INVALID_REQUEST,
                "approved_profile must be an ApprovedAdapterProfile",
            )
        self._approved = approved_profile

    @property
    def approved_profile(self) -> ApprovedAdapterProfile:
        return self._approved

    def plan(self, request: ConstrainedPlanRequest) -> ConstrainedExecutionPlan:
        if type(request) is not ConstrainedPlanRequest:
            _error(
                ConstrainedAdapterErrorCode.INVALID_REQUEST,
                "request must be a ConstrainedPlanRequest",
            )
        approved = self._approved
        if request.system_id != approved.system_id:
            _error(
                ConstrainedAdapterErrorCode.SYSTEM_MISMATCH,
                "request system does not match the approved profile",
            )
        if request.adapter != approved.adapter:
            _error(
                ConstrainedAdapterErrorCode.ADAPTER_NOT_APPROVED,
                "adapter is not the exact profile-admitted ref",
            )
        if request.execution_recipe not in approved.execution_recipes:
            _error(
                ConstrainedAdapterErrorCode.RECIPE_NOT_APPROVED,
                "execution recipe is not an exact approved ref",
            )
        unapproved_oracles = tuple(
            item for item in request.oracle_specs if item not in approved.oracle_specs
        )
        if unapproved_oracles:
            _error(
                ConstrainedAdapterErrorCode.ORACLE_NOT_APPROVED,
                "one or more OracleSpecs are not exact approved refs",
            )
        unapproved_collectors = tuple(
            item for item in request.collectors if item not in approved.collectors
        )
        if unapproved_collectors:
            _error(
                ConstrainedAdapterErrorCode.COLLECTOR_NOT_APPROVED,
                "one or more collectors are not exact approved refs",
            )
        if not set(request.required_capabilities).issubset(
            approved.effective_capabilities
        ):
            _error(
                ConstrainedAdapterErrorCode.CAPABILITY_NOT_APPROVED,
                "request requires a capability not granted by the profile",
            )
        return ConstrainedExecutionPlan(
            system_id=request.system_id,
            approved_profile_sha256=approved.profile_sha256,
            approved_profile_contract_sha256=approved.content_sha256,
            request_sha256=request.content_sha256,
            adapter=request.adapter,
            execution_recipe=request.execution_recipe,
            oracle_specs=request.oracle_specs,
            collectors=request.collectors,
            input_artifacts=request.input_artifacts,
        )


__all__ = (
    "ApprovedAdapterProfile",
    "ConstrainedAdapterError",
    "ConstrainedAdapterErrorCode",
    "ConstrainedExactRefPlanner",
    "ConstrainedExecutionPlan",
    "ConstrainedPlanRequest",
)

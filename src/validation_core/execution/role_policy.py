"""Frozen authorization descriptions for validation workspaces.

Role policies describe which logical namespaces and broker capabilities a
workspace role is authorized to receive.  They do not implement an OS sandbox,
mount policy, credential scrubber, or network filter; those enforcement layers
belong to the later broker/sandbox runtime and must verify this hash-bound
description before granting access.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from ..contracts.base import (
    ContractError,
    canonical_json_bytes,
    canonical_sha256,
    load_strict_json_object,
    require_exact_keys,
)
from ..contracts.profile import FrozenSystemProfile
from ..contracts.references import ContractRef, ContractRefKind


_ROLE_POLICY_CONTRACT_KIND = "workspace_role_policy"
_ROLE_POLICY_SCHEMA_VERSION = 1


class WorkspaceRole(str, Enum):
    """Closed post-Profile roles with independent project views.

    Setup S intentionally is not a v1 workspace role: it runs before a Frozen
    System Profile exists, so granting it a policy that pretends to bind that
    Profile would be unsound.  Setup authority is introduced with the later
    Project Profile Setup and approval lifecycle.
    """

    A = "A"
    B1 = "B1"
    B2 = "B2"


class RoleCapability(str, Enum):
    """Closed broker-level powers represented by a role policy."""

    AGENT_SESSION = "agent_session"
    MASKED_MODEL_PROVIDER = "masked_model_provider"
    EXPLORATION_BROKER = "exploration_broker"
    CASE_STAGING = "case_staging"
    APPROVED_ADAPTER = "approved_adapter"
    EXECUTION_BROKER = "execution_broker"
    FORMAL_EVIDENCE = "formal_evidence"
    RECEIPT_WRITE = "receipt_write"


class WorkspaceNamespace(str, Enum):
    """Closed logical mounts; write scopes are role-specific by construction."""

    FROZEN_INPUTS_READ_ONLY = "frozen_inputs_read_only"
    A_PROJECT_READ_WRITE = "a_project_read_write"
    A_CASE_STAGING_WRITE = "a_case_staging_write"
    A_SCRATCH_READ_WRITE = "a_scratch_read_write"
    B1_PROJECT_READ_WRITE = "b1_project_read_write"
    B1_VARIANTS_READ_WRITE = "b1_variants_read_write"
    B1_ARTIFACTS_WRITE = "b1_artifacts_write"
    B1_SCRATCH_READ_WRITE = "b1_scratch_read_write"
    B1_LOGS_WRITE = "b1_logs_write"
    B1_RECEIPT_WRITE = "b1_receipt_write"
    B2_PROJECT_READ_WRITE = "b2_project_read_write"
    B2_VARIANTS_READ_WRITE = "b2_variants_read_write"
    B2_ARTIFACTS_WRITE = "b2_artifacts_write"
    B2_SCRATCH_READ_WRITE = "b2_scratch_read_write"
    B2_LOGS_WRITE = "b2_logs_write"
    B2_RECEIPT_WRITE = "b2_receipt_write"


class NetworkPolicy(str, Enum):
    """Closed network exposure classes; neither grants direct public access."""

    MASKED_PROVIDER_AND_EXPLORATION_BROKER = (
        "masked_provider_and_exploration_broker"
    )
    PROFILE_INTERNAL_BROKER_ONLY = "profile_internal_broker_only"


class CredentialPolicy(str, Enum):
    """Closed credential views; Gate roles receive no credentials."""

    MASKED_PROVIDER_SCOPED = "masked_provider_scoped"
    NONE = "none"


_ROLE_CAPABILITIES: dict[WorkspaceRole, frozenset[RoleCapability]] = {
    WorkspaceRole.A: frozenset(
        {
            RoleCapability.AGENT_SESSION,
            RoleCapability.MASKED_MODEL_PROVIDER,
            RoleCapability.EXPLORATION_BROKER,
            RoleCapability.CASE_STAGING,
        }
    ),
    WorkspaceRole.B1: frozenset(
        {
            RoleCapability.APPROVED_ADAPTER,
            RoleCapability.EXECUTION_BROKER,
            RoleCapability.FORMAL_EVIDENCE,
            RoleCapability.RECEIPT_WRITE,
        }
    ),
    WorkspaceRole.B2: frozenset(
        {
            RoleCapability.APPROVED_ADAPTER,
            RoleCapability.EXECUTION_BROKER,
            RoleCapability.FORMAL_EVIDENCE,
            RoleCapability.RECEIPT_WRITE,
        }
    ),
}

_ROLE_NAMESPACES: dict[WorkspaceRole, frozenset[WorkspaceNamespace]] = {
    WorkspaceRole.A: frozenset(
        {
            WorkspaceNamespace.FROZEN_INPUTS_READ_ONLY,
            WorkspaceNamespace.A_PROJECT_READ_WRITE,
            WorkspaceNamespace.A_CASE_STAGING_WRITE,
            WorkspaceNamespace.A_SCRATCH_READ_WRITE,
        }
    ),
    WorkspaceRole.B1: frozenset(
        {
            WorkspaceNamespace.FROZEN_INPUTS_READ_ONLY,
            WorkspaceNamespace.B1_PROJECT_READ_WRITE,
            WorkspaceNamespace.B1_VARIANTS_READ_WRITE,
            WorkspaceNamespace.B1_ARTIFACTS_WRITE,
            WorkspaceNamespace.B1_SCRATCH_READ_WRITE,
            WorkspaceNamespace.B1_LOGS_WRITE,
            WorkspaceNamespace.B1_RECEIPT_WRITE,
        }
    ),
    WorkspaceRole.B2: frozenset(
        {
            WorkspaceNamespace.FROZEN_INPUTS_READ_ONLY,
            WorkspaceNamespace.B2_PROJECT_READ_WRITE,
            WorkspaceNamespace.B2_VARIANTS_READ_WRITE,
            WorkspaceNamespace.B2_ARTIFACTS_WRITE,
            WorkspaceNamespace.B2_SCRATCH_READ_WRITE,
            WorkspaceNamespace.B2_LOGS_WRITE,
            WorkspaceNamespace.B2_RECEIPT_WRITE,
        }
    ),
}

_ROLE_NETWORK_POLICY = {
    WorkspaceRole.A: NetworkPolicy.MASKED_PROVIDER_AND_EXPLORATION_BROKER,
    WorkspaceRole.B1: NetworkPolicy.PROFILE_INTERNAL_BROKER_ONLY,
    WorkspaceRole.B2: NetworkPolicy.PROFILE_INTERNAL_BROKER_ONLY,
}

_ROLE_CREDENTIAL_POLICY = {
    WorkspaceRole.A: CredentialPolicy.MASKED_PROVIDER_SCOPED,
    WorkspaceRole.B1: CredentialPolicy.NONE,
    WorkspaceRole.B2: CredentialPolicy.NONE,
}


def _require_ref(
    value: object,
    expected_kind: ContractRefKind,
    field: str,
) -> ContractRef:
    if type(value) is not ContractRef:
        raise ContractError(f"{field} must be a ContractRef")
    if value.kind is not expected_kind:
        raise ContractError(f"{field} must reference {expected_kind.value}")
    return value


def _ref_from_document(
    value: object,
    expected_kind: ContractRefKind,
    field: str,
) -> ContractRef:
    try:
        reference = ContractRef.from_document(value)
    except ContractError as exc:
        raise ContractError(f"invalid {field}: {exc}") from exc
    return _require_ref(reference, expected_kind, field)


def _enum_from_document(
    enum_type: type[Enum],
    value: object,
    field: str,
) -> Enum:
    if type(value) is not str:
        raise ContractError(f"{field} must be a string enum value")
    try:
        return enum_type(value)
    except ValueError as exc:
        raise ContractError(f"{field} has unsupported value {value!r}") from exc


def _normalize_exact_enum_members(
    value: object,
    *,
    enum_type: type[Enum],
    expected: frozenset[Enum],
    field: str,
) -> tuple[Enum, ...]:
    if type(value) not in (tuple, list):
        raise ContractError(f"{field} must be an ordered collection")
    members = tuple(value)
    if any(type(member) is not enum_type for member in members):
        raise ContractError(f"{field} must contain only {enum_type.__name__} values")
    if len(set(members)) != len(members):
        raise ContractError(f"{field} must not contain duplicate values")
    if frozenset(members) != expected:
        raise ContractError(f"{field} does not exactly match the built-in role")
    return tuple(sorted(members, key=lambda member: member.value))


def _enum_list_from_document(
    value: object,
    *,
    enum_type: type[Enum],
    field: str,
) -> tuple[Enum, ...]:
    if type(value) is not list:
        raise ContractError(f"{field} must be a list")
    return tuple(
        _enum_from_document(enum_type, member, f"{field}[{index}]")
        for index, member in enumerate(value)
    )


@dataclass(frozen=True)
class RolePolicy:
    """One hash-bound, built-in authorization description for A, B1, or B2.

    Construction is intentionally closed: callers cannot subtract protective
    scopes or add a model, Agent, shell, network, credential, evidence, or
    receipt power.  Runtime sandbox and broker layers still must enforce this
    description; possessing a :class:`RolePolicy` grants no OS capability.
    """

    role: WorkspaceRole
    profile: ContractRef
    resource_policy: ContractRef
    capabilities: tuple[RoleCapability, ...]
    namespaces: tuple[WorkspaceNamespace, ...]
    network_policy: NetworkPolicy
    credential_policy: CredentialPolicy

    def __post_init__(self) -> None:
        if type(self.role) is not WorkspaceRole:
            raise ContractError("role must be a WorkspaceRole")
        _require_ref(self.profile, ContractRefKind.FROZEN_PROFILE, "profile")
        _require_ref(
            self.resource_policy,
            ContractRefKind.RESOURCE_POLICY,
            "resource_policy",
        )
        capabilities = _normalize_exact_enum_members(
            self.capabilities,
            enum_type=RoleCapability,
            expected=_ROLE_CAPABILITIES[self.role],
            field="capabilities",
        )
        namespaces = _normalize_exact_enum_members(
            self.namespaces,
            enum_type=WorkspaceNamespace,
            expected=_ROLE_NAMESPACES[self.role],
            field="namespaces",
        )
        if type(self.network_policy) is not NetworkPolicy:
            raise ContractError("network_policy must be a NetworkPolicy")
        if self.network_policy is not _ROLE_NETWORK_POLICY[self.role]:
            raise ContractError(
                "network_policy does not exactly match the built-in role"
            )
        if type(self.credential_policy) is not CredentialPolicy:
            raise ContractError("credential_policy must be a CredentialPolicy")
        if self.credential_policy is not _ROLE_CREDENTIAL_POLICY[self.role]:
            raise ContractError(
                "credential_policy does not exactly match the built-in role"
            )
        object.__setattr__(self, "capabilities", capabilities)
        object.__setattr__(self, "namespaces", namespaces)

    def to_document(self) -> dict[str, object]:
        return {
            "contract_kind": _ROLE_POLICY_CONTRACT_KIND,
            "schema_version": _ROLE_POLICY_SCHEMA_VERSION,
            "role": self.role.value,
            "profile": self.profile.to_document(),
            "resource_policy": self.resource_policy.to_document(),
            "capabilities": [value.value for value in self.capabilities],
            "namespaces": [value.value for value in self.namespaces],
            "network_policy": self.network_policy.value,
            "credential_policy": self.credential_policy.value,
        }

    @classmethod
    def from_document(cls, value: object) -> RolePolicy:
        document = require_exact_keys(
            value,
            required=(
                "contract_kind",
                "schema_version",
                "role",
                "profile",
                "resource_policy",
                "capabilities",
                "namespaces",
                "network_policy",
                "credential_policy",
            ),
            where="workspace role policy",
        )
        if document["contract_kind"] != _ROLE_POLICY_CONTRACT_KIND:
            raise ContractError(
                "workspace role policy contract_kind must be "
                f"{_ROLE_POLICY_CONTRACT_KIND!r}"
            )
        if (
            type(document["schema_version"]) is not int
            or document["schema_version"] != _ROLE_POLICY_SCHEMA_VERSION
        ):
            raise ContractError(
                "workspace role policy schema_version must be the integer 1"
            )
        role = _enum_from_document(
            WorkspaceRole,
            document["role"],
            "workspace role policy role",
        )
        return cls(
            role=role,
            profile=_ref_from_document(
                document["profile"],
                ContractRefKind.FROZEN_PROFILE,
                "profile",
            ),
            resource_policy=_ref_from_document(
                document["resource_policy"],
                ContractRefKind.RESOURCE_POLICY,
                "resource_policy",
            ),
            capabilities=_enum_list_from_document(
                document["capabilities"],
                enum_type=RoleCapability,
                field="workspace role policy capabilities",
            ),
            namespaces=_enum_list_from_document(
                document["namespaces"],
                enum_type=WorkspaceNamespace,
                field="workspace role policy namespaces",
            ),
            network_policy=_enum_from_document(
                NetworkPolicy,
                document["network_policy"],
                "workspace role policy network_policy",
            ),
            credential_policy=_enum_from_document(
                CredentialPolicy,
                document["credential_policy"],
                "workspace role policy credential_policy",
            ),
        )

    @classmethod
    def from_json(cls, payload: object) -> RolePolicy:
        return cls.from_document(load_strict_json_object(payload))

    def to_json(self) -> bytes:
        return canonical_json_bytes(self.to_document())

    @property
    def content_sha256(self) -> str:
        return canonical_sha256(self.to_document())


def build_role_policy(
    role: WorkspaceRole,
    profile: FrozenSystemProfile,
    resource_policy: ContractRef,
) -> RolePolicy:
    """Build the sole v1 policy shape for a role and exact frozen inputs."""

    if type(role) is not WorkspaceRole:
        raise ContractError("role must be a WorkspaceRole")
    if type(profile) is not FrozenSystemProfile:
        raise ContractError("profile must be a FrozenSystemProfile")
    _require_ref(
        resource_policy,
        ContractRefKind.RESOURCE_POLICY,
        "resource_policy",
    )
    if resource_policy != profile.environment.resource_policy:
        raise ContractError(
            "resource_policy must exactly match the Frozen Profile environment"
        )
    return RolePolicy(
        role=role,
        profile=profile.ref,
        resource_policy=resource_policy,
        capabilities=tuple(_ROLE_CAPABILITIES[role]),
        namespaces=tuple(_ROLE_NAMESPACES[role]),
        network_policy=_ROLE_NETWORK_POLICY[role],
        credential_policy=_ROLE_CREDENTIAL_POLICY[role],
    )

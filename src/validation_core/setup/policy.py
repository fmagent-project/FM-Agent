"""Closed logical authorization contracts for pre-Profile Setup roles.

These values describe the only namespaces and broker powers a Setup runtime
may grant.  They are not an operating-system sandbox by themselves.  A later
broker must enforce the exact hash-bound policy before mounting data or
exposing a provider endpoint.

Setup policies intentionally do not reference :class:`FrozenSystemProfile`:
all four roles run before, or at, the Profile admission boundary.  Their
``subject_sha256`` instead binds the immutable object visible to that role
(source snapshot, qualification plan, review bundle, or admission graph).
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
    validate_identifier,
    validate_sha256,
)


_CONTRACT_KIND = "profile_setup_role_policy"
_SCHEMA_VERSION = 1


class SetupRole(str, Enum):
    SETUP_AGENT = "setup_agent"
    QUALIFICATION_WORKER = "qualification_worker"
    REVIEWER = "reviewer"
    PROFILE_GATE = "profile_gate"


class SetupCapability(str, Enum):
    DISCOVERY_BROKER = "discovery_broker"
    CANDIDATE_STAGING = "candidate_staging"
    MASKED_MODEL_PROVIDER = "masked_model_provider"
    CANDIDATE_ADAPTER_WORKER = "candidate_adapter_worker"
    QUALIFICATION_BROKER = "qualification_broker"
    HIDDEN_FIXTURE_ACCESS = "hidden_fixture_access"
    AGGREGATE_REPORT_WRITE = "aggregate_report_write"
    REVIEW_PROVIDER = "review_provider"
    REVIEW_RECORD_WRITE = "review_record_write"
    ADMISSION_VERIFY = "admission_verify"
    PROFILE_REGISTRY_WRITE = "profile_registry_write"
    REVOCATION_LEDGER_READ = "revocation_ledger_read"


class SetupNamespace(str, Enum):
    EXISTING_REGISTRY_READ_ONLY = "existing_registry_read_only"
    SETUP_PROJECT_READ_WRITE = "setup_project_read_write"
    CANDIDATE_STAGING_READ_WRITE = "candidate_staging_read_write"
    CANDIDATE_STAGING_READ_ONLY = "candidate_staging_read_only"
    CALIBRATION_INPUTS_READ_ONLY = "calibration_inputs_read_only"
    HIDDEN_QUALIFICATION_READ_ONLY = "hidden_qualification_read_only"
    QUALIFICATION_SCRATCH_READ_WRITE = "qualification_scratch_read_write"
    QUALIFICATION_REPORT_WRITE = "qualification_report_write"
    REVIEW_BUNDLE_READ_ONLY = "review_bundle_read_only"
    REVIEW_RECORD_WRITE = "review_record_write"
    ADMISSION_GRAPH_READ_ONLY = "admission_graph_read_only"
    PROFILE_REGISTRY_WRITE = "profile_registry_write"


class SetupNetworkPolicy(str, Enum):
    ALLOWLIST_DISCOVERY_BROKER = "allowlist_discovery_broker"
    INTERNAL_QUALIFICATION_BROKERS_ONLY = (
        "internal_qualification_brokers_only"
    )
    MASKED_REVIEW_PROVIDER_ONLY = "masked_review_provider_only"
    NONE = "none"


class SetupCredentialPolicy(str, Enum):
    SETUP_SCOPED = "setup_scoped"
    REVIEW_PROVIDER_SCOPED = "review_provider_scoped"
    NONE = "none"


_CAPABILITIES: dict[SetupRole, frozenset[SetupCapability]] = {
    SetupRole.SETUP_AGENT: frozenset(
        {
            SetupCapability.DISCOVERY_BROKER,
            SetupCapability.CANDIDATE_STAGING,
            SetupCapability.MASKED_MODEL_PROVIDER,
        }
    ),
    SetupRole.QUALIFICATION_WORKER: frozenset(
        {
            SetupCapability.CANDIDATE_ADAPTER_WORKER,
            SetupCapability.QUALIFICATION_BROKER,
            SetupCapability.HIDDEN_FIXTURE_ACCESS,
            SetupCapability.AGGREGATE_REPORT_WRITE,
        }
    ),
    SetupRole.REVIEWER: frozenset(
        {
            SetupCapability.REVIEW_PROVIDER,
            SetupCapability.REVIEW_RECORD_WRITE,
        }
    ),
    SetupRole.PROFILE_GATE: frozenset(
        {
            SetupCapability.ADMISSION_VERIFY,
            SetupCapability.PROFILE_REGISTRY_WRITE,
            SetupCapability.REVOCATION_LEDGER_READ,
        }
    ),
}


_NAMESPACES: dict[SetupRole, frozenset[SetupNamespace]] = {
    SetupRole.SETUP_AGENT: frozenset(
        {
            SetupNamespace.EXISTING_REGISTRY_READ_ONLY,
            SetupNamespace.SETUP_PROJECT_READ_WRITE,
            SetupNamespace.CANDIDATE_STAGING_READ_WRITE,
            SetupNamespace.CALIBRATION_INPUTS_READ_ONLY,
        }
    ),
    SetupRole.QUALIFICATION_WORKER: frozenset(
        {
            SetupNamespace.EXISTING_REGISTRY_READ_ONLY,
            SetupNamespace.CANDIDATE_STAGING_READ_ONLY,
            SetupNamespace.CALIBRATION_INPUTS_READ_ONLY,
            SetupNamespace.HIDDEN_QUALIFICATION_READ_ONLY,
            SetupNamespace.QUALIFICATION_SCRATCH_READ_WRITE,
            SetupNamespace.QUALIFICATION_REPORT_WRITE,
        }
    ),
    SetupRole.REVIEWER: frozenset(
        {
            SetupNamespace.REVIEW_BUNDLE_READ_ONLY,
            SetupNamespace.REVIEW_RECORD_WRITE,
        }
    ),
    SetupRole.PROFILE_GATE: frozenset(
        {
            SetupNamespace.EXISTING_REGISTRY_READ_ONLY,
            SetupNamespace.ADMISSION_GRAPH_READ_ONLY,
            SetupNamespace.PROFILE_REGISTRY_WRITE,
        }
    ),
}


_NETWORK = {
    SetupRole.SETUP_AGENT: SetupNetworkPolicy.ALLOWLIST_DISCOVERY_BROKER,
    SetupRole.QUALIFICATION_WORKER: (
        SetupNetworkPolicy.INTERNAL_QUALIFICATION_BROKERS_ONLY
    ),
    SetupRole.REVIEWER: SetupNetworkPolicy.MASKED_REVIEW_PROVIDER_ONLY,
    SetupRole.PROFILE_GATE: SetupNetworkPolicy.NONE,
}


_CREDENTIALS = {
    SetupRole.SETUP_AGENT: SetupCredentialPolicy.SETUP_SCOPED,
    SetupRole.QUALIFICATION_WORKER: SetupCredentialPolicy.NONE,
    SetupRole.REVIEWER: SetupCredentialPolicy.REVIEW_PROVIDER_SCOPED,
    SetupRole.PROFILE_GATE: SetupCredentialPolicy.NONE,
}


def _enum(enum_type: type[Enum], value: object, field: str) -> Enum:
    if type(value) is not str:
        raise ContractError(f"{field} must be a string enum value")
    try:
        return enum_type(value)
    except ValueError as exc:
        raise ContractError(f"{field} has unsupported value {value!r}") from exc


def _enum_members(
    enum_type: type[Enum],
    values: object,
    field: str,
) -> tuple[Enum, ...]:
    if type(values) is not list:
        raise ContractError(f"{field} must be a list")
    return tuple(
        _enum(enum_type, value, f"{field}[{index}]")
        for index, value in enumerate(values)
    )


@dataclass(frozen=True)
class SetupRolePolicy:
    role: SetupRole
    setup_session_id: str
    subject_sha256: str
    governance_policy_sha256: str
    capabilities: tuple[SetupCapability, ...]
    namespaces: tuple[SetupNamespace, ...]
    network_policy: SetupNetworkPolicy
    credential_policy: SetupCredentialPolicy

    def __post_init__(self) -> None:
        if type(self.role) is not SetupRole:
            raise ContractError("role must be a SetupRole")
        validate_identifier(self.setup_session_id, "setup_session_id")
        validate_sha256(self.subject_sha256, "subject_sha256")
        validate_sha256(
            self.governance_policy_sha256,
            "governance_policy_sha256",
        )
        capabilities = self._normalize_exact(
            self.capabilities,
            SetupCapability,
            _CAPABILITIES[self.role],
            "capabilities",
        )
        namespaces = self._normalize_exact(
            self.namespaces,
            SetupNamespace,
            _NAMESPACES[self.role],
            "namespaces",
        )
        if (
            type(self.network_policy) is not SetupNetworkPolicy
            or self.network_policy is not _NETWORK[self.role]
        ):
            raise ContractError(
                "network_policy does not exactly match the built-in Setup role"
            )
        if (
            type(self.credential_policy) is not SetupCredentialPolicy
            or self.credential_policy is not _CREDENTIALS[self.role]
        ):
            raise ContractError(
                "credential_policy does not exactly match the built-in Setup role"
            )
        object.__setattr__(self, "capabilities", capabilities)
        object.__setattr__(self, "namespaces", namespaces)

    @staticmethod
    def _normalize_exact(
        values: object,
        enum_type: type[Enum],
        expected: frozenset[Enum],
        field: str,
    ) -> tuple:
        if type(values) not in (tuple, list):
            raise ContractError(f"{field} must be an ordered collection")
        normalized = tuple(values)
        if any(type(value) is not enum_type for value in normalized):
            raise ContractError(
                f"{field} must contain only {enum_type.__name__} values"
            )
        if len(normalized) != len(set(normalized)):
            raise ContractError(f"{field} must not contain duplicates")
        if frozenset(normalized) != expected:
            raise ContractError(
                f"{field} does not exactly match the built-in Setup role"
            )
        return tuple(sorted(normalized, key=lambda value: value.value))

    def to_document(self) -> dict[str, object]:
        return {
            "contract_kind": _CONTRACT_KIND,
            "schema_version": _SCHEMA_VERSION,
            "role": self.role.value,
            "setup_session_id": self.setup_session_id,
            "subject_sha256": self.subject_sha256,
            "governance_policy_sha256": self.governance_policy_sha256,
            "capabilities": [value.value for value in self.capabilities],
            "namespaces": [value.value for value in self.namespaces],
            "network_policy": self.network_policy.value,
            "credential_policy": self.credential_policy.value,
        }

    @classmethod
    def from_document(cls, value: object) -> "SetupRolePolicy":
        document = require_exact_keys(
            value,
            required=(
                "contract_kind",
                "schema_version",
                "role",
                "setup_session_id",
                "subject_sha256",
                "governance_policy_sha256",
                "capabilities",
                "namespaces",
                "network_policy",
                "credential_policy",
            ),
            where="profile setup role policy",
        )
        if document["contract_kind"] != _CONTRACT_KIND:
            raise ContractError(
                f"profile setup role policy contract_kind must be {_CONTRACT_KIND!r}"
            )
        if (
            type(document["schema_version"]) is not int
            or document["schema_version"] != _SCHEMA_VERSION
        ):
            raise ContractError(
                "profile setup role policy schema_version must be integer 1"
            )
        return cls(
            role=_enum(SetupRole, document["role"], "role"),
            setup_session_id=document["setup_session_id"],
            subject_sha256=document["subject_sha256"],
            governance_policy_sha256=document["governance_policy_sha256"],
            capabilities=_enum_members(
                SetupCapability,
                document["capabilities"],
                "capabilities",
            ),
            namespaces=_enum_members(
                SetupNamespace,
                document["namespaces"],
                "namespaces",
            ),
            network_policy=_enum(
                SetupNetworkPolicy,
                document["network_policy"],
                "network_policy",
            ),
            credential_policy=_enum(
                SetupCredentialPolicy,
                document["credential_policy"],
                "credential_policy",
            ),
        )

    @classmethod
    def from_json(cls, payload: object) -> "SetupRolePolicy":
        return cls.from_document(load_strict_json_object(payload))

    def to_json(self) -> bytes:
        return canonical_json_bytes(self.to_document())

    @property
    def content_sha256(self) -> str:
        return canonical_sha256(self.to_document())


def build_setup_role_policy(
    role: SetupRole,
    *,
    setup_session_id: str,
    subject_sha256: str,
    governance_policy_sha256: str,
) -> SetupRolePolicy:
    if type(role) is not SetupRole:
        raise ContractError("role must be a SetupRole")
    return SetupRolePolicy(
        role=role,
        setup_session_id=setup_session_id,
        subject_sha256=subject_sha256,
        governance_policy_sha256=governance_policy_sha256,
        capabilities=tuple(_CAPABILITIES[role]),
        namespaces=tuple(_NAMESPACES[role]),
        network_policy=_NETWORK[role],
        credential_policy=_CREDENTIALS[role],
    )


__all__ = [
    "SetupCapability",
    "SetupCredentialPolicy",
    "SetupNamespace",
    "SetupNetworkPolicy",
    "SetupRole",
    "SetupRolePolicy",
    "build_setup_role_policy",
]

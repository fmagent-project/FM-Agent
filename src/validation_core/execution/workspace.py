"""Independent A/B1/B2 workspaces materialized from one immutable snapshot.

This module owns host paths and turns them into opaque, hash-bound leases.  A
lease is an input to the later process/resource broker; it is not itself an OS
sandbox.  Host absolute paths are intentionally absent from serialized lease
documents and from :class:`DynamicResourceBinding`.
"""

from __future__ import annotations

import hashlib
import os
import shutil
import stat
import threading
import uuid
from dataclasses import dataclass
from enum import Enum
from pathlib import Path

from ..contracts.base import (
    ContractError,
    canonical_json_bytes,
    canonical_sha256,
    load_strict_json_object,
    require_exact_keys,
    validate_identifier,
    validate_sha256,
)
from ..contracts.case import ValidationInstanceIdentity
from ..contracts.plan import DynamicResourceBinding, DynamicResourceKind, GateRole
from ..contracts.profile import FrozenSystemProfile
from ..contracts.references import ContractRef, ContractRefKind
from ..contracts.snapshot import SnapshotRef
from ..storage.snapshot import (
    MaterializedSnapshot,
    SnapshotMaterializationProof,
    SnapshotStore,
    SnapshotStoreError,
    _mount_id,
    _parent_protects_directory_entry,
    _require_single_mount_tree,
)
from .role_policy import RolePolicy, WorkspaceNamespace, WorkspaceRole


_LEASE_CONTRACT_KIND = "workspace_lease"
_LEASE_SCHEMA_VERSION = 1
_LINEAGE_CONTRACT_KIND = "workspace_lineage_record"
_LINEAGE_SCHEMA_VERSION = 1
_BROKER_VERSION = "snapshot-workspace-broker-v1"


class WorkspaceErrorCode(str, Enum):
    INVALID_RUN_ROOT = "INVALID_RUN_ROOT"
    INVALID_REQUEST = "INVALID_REQUEST"
    SNAPSHOT_MISMATCH = "SNAPSHOT_MISMATCH"
    ROLE_POLICY_MISMATCH = "ROLE_POLICY_MISMATCH"
    ALLOCATION_FAILED = "ALLOCATION_FAILED"
    WORKSPACE_INTEGRITY_FAILURE = "WORKSPACE_INTEGRITY_FAILURE"
    ACCESS_DENIED = "ACCESS_DENIED"
    UNKNOWN_LEASE = "UNKNOWN_LEASE"
    RELEASE_FAILED = "RELEASE_FAILED"


class WorkspaceError(RuntimeError):
    """A typed workspace allocation or integrity failure."""

    def __init__(self, code: WorkspaceErrorCode, message: str) -> None:
        if type(code) is not WorkspaceErrorCode:
            raise TypeError("code must be a WorkspaceErrorCode")
        super().__init__(message)
        self.code = code


def _raise(code: WorkspaceErrorCode, message: str, cause: BaseException | None = None):
    error = WorkspaceError(code, message)
    if cause is None:
        raise error
    raise error from cause


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


def _workspace_role(value: object, field: str) -> WorkspaceRole:
    if type(value) is not str:
        raise ContractError(f"{field} must be a string enum value")
    try:
        return WorkspaceRole(value)
    except ValueError as exc:
        raise ContractError(f"{field} has unsupported value {value!r}") from exc


def _equivalence_fingerprint(
    snapshot: SnapshotRef,
    equivalence_policy: ContractRef,
) -> str:
    return canonical_sha256({
        "domain": "fmagent.workspace.equivalence/v1",
        "snapshot": snapshot.to_document(),
        "equivalence_policy": equivalence_policy.to_document(),
        "materializer_version": _BROKER_VERSION,
    })


def _resource_fingerprint_document(
    *,
    lease_id: str,
    broker_id: str,
    validation_instance_id: str,
    attempt_id: str,
    agent_session_id: str | None,
    role: WorkspaceRole,
    snapshot: SnapshotRef,
    role_policy_sha256: str,
    workspace_equivalence_policy: ContractRef,
    write_layer_sha256: str,
    materialization_proof_sha256: str,
    equivalence_fingerprint_sha256: str,
) -> dict[str, object]:
    return {
        "domain": "fmagent.workspace.resource/v1",
        "lease_id": lease_id,
        "broker_id": broker_id,
        "validation_instance_id": validation_instance_id,
        "attempt_id": attempt_id,
        "agent_session_id": agent_session_id,
        "role": role.value,
        "snapshot": snapshot.to_document(),
        "role_policy_sha256": role_policy_sha256,
        "workspace_equivalence_policy": workspace_equivalence_policy.to_document(),
        "write_layer_sha256": write_layer_sha256,
        "materialization_proof_sha256": materialization_proof_sha256,
        "equivalence_fingerprint_sha256": equivalence_fingerprint_sha256,
        "broker_version": _BROKER_VERSION,
    }


@dataclass(frozen=True)
class WorkspaceLease:
    """Opaque identity and integrity binding for one writable project view."""

    lease_id: str
    broker_id: str
    validation_instance_id: str
    attempt_id: str
    agent_session_id: str | None
    role: WorkspaceRole
    snapshot: SnapshotRef
    role_policy_sha256: str
    workspace_equivalence_policy: ContractRef
    write_layer_sha256: str
    materialization_proof_sha256: str
    resource_fingerprint_sha256: str
    equivalence_fingerprint_sha256: str

    def __post_init__(self) -> None:
        validate_identifier(self.lease_id, "lease_id")
        validate_identifier(self.broker_id, "broker_id")
        validate_sha256(self.validation_instance_id, "validation_instance_id")
        validate_identifier(self.attempt_id, "attempt_id")
        if type(self.role) is not WorkspaceRole:
            raise ContractError("role must be a WorkspaceRole")
        if self.role is WorkspaceRole.A:
            validate_identifier(self.agent_session_id, "agent_session_id")
        elif self.agent_session_id is not None:
            raise ContractError("B1/B2 leases must not expose an Agent session")
        if type(self.snapshot) is not SnapshotRef:
            raise ContractError("snapshot must be a SnapshotRef")
        validate_sha256(self.role_policy_sha256, "role_policy_sha256")
        _require_ref(
            self.workspace_equivalence_policy,
            ContractRefKind.EXECUTION_EQUIVALENCE_POLICY,
            "workspace_equivalence_policy",
        )
        validate_sha256(self.write_layer_sha256, "write_layer_sha256")
        validate_sha256(
            self.materialization_proof_sha256,
            "materialization_proof_sha256",
        )
        validate_sha256(
            self.resource_fingerprint_sha256,
            "resource_fingerprint_sha256",
        )
        validate_sha256(
            self.equivalence_fingerprint_sha256,
            "equivalence_fingerprint_sha256",
        )
        expected_equivalence = _equivalence_fingerprint(
            self.snapshot,
            self.workspace_equivalence_policy,
        )
        if self.equivalence_fingerprint_sha256 != expected_equivalence:
            raise ContractError(
                "equivalence_fingerprint_sha256 does not bind snapshot and policy"
            )
        expected_resource = canonical_sha256(_resource_fingerprint_document(
            lease_id=self.lease_id,
            broker_id=self.broker_id,
            validation_instance_id=self.validation_instance_id,
            attempt_id=self.attempt_id,
            agent_session_id=self.agent_session_id,
            role=self.role,
            snapshot=self.snapshot,
            role_policy_sha256=self.role_policy_sha256,
            workspace_equivalence_policy=self.workspace_equivalence_policy,
            write_layer_sha256=self.write_layer_sha256,
            materialization_proof_sha256=self.materialization_proof_sha256,
            equivalence_fingerprint_sha256=self.equivalence_fingerprint_sha256,
        ))
        if self.resource_fingerprint_sha256 != expected_resource:
            raise ContractError(
                "resource_fingerprint_sha256 does not bind the workspace lease"
            )

    @classmethod
    def create(
        cls,
        *,
        lease_id: str,
        broker_id: str,
        identity: ValidationInstanceIdentity,
        profile: FrozenSystemProfile,
        attempt_id: str,
        agent_session_id: str | None,
        role: WorkspaceRole,
        snapshot: SnapshotRef,
        role_policy: RolePolicy,
        workspace_equivalence_policy: ContractRef,
        write_layer_sha256: str,
        materialization_proof_sha256: str,
    ) -> WorkspaceLease:
        if type(identity) is not ValidationInstanceIdentity:
            raise ContractError("identity must be a ValidationInstanceIdentity")
        if type(profile) is not FrozenSystemProfile:
            raise ContractError("profile must be a FrozenSystemProfile")
        if identity.snapshot_sha256 != snapshot.snapshot_sha256:
            raise ContractError("identity does not bind the supplied snapshot")
        if identity.profile_sha256 != profile.content_sha256:
            raise ContractError("identity does not bind the supplied Profile")
        if identity.project_id != profile.project.system_id:
            raise ContractError("identity project does not match the supplied Profile")
        if profile.project.source_snapshot_sha256 != snapshot.snapshot_sha256:
            raise ContractError("Profile does not bind the supplied snapshot")
        if type(role_policy) is not RolePolicy or role_policy.role is not role:
            raise ContractError("role_policy does not match the requested role")
        if role_policy.profile != profile.ref:
            raise ContractError("role_policy does not bind the supplied Profile")
        if role_policy.resource_policy != profile.environment.resource_policy:
            raise ContractError(
                "role_policy resource policy does not match the supplied Profile"
            )
        _require_ref(
            workspace_equivalence_policy,
            ContractRefKind.EXECUTION_EQUIVALENCE_POLICY,
            "workspace_equivalence_policy",
        )
        if workspace_equivalence_policy not in profile.components:
            raise ContractError(
                "workspace equivalence policy is not frozen in the supplied Profile"
            )
        equivalence = _equivalence_fingerprint(
            snapshot,
            workspace_equivalence_policy,
        )
        resource = canonical_sha256(_resource_fingerprint_document(
            lease_id=lease_id,
            broker_id=broker_id,
            validation_instance_id=identity.validation_instance_id,
            attempt_id=attempt_id,
            agent_session_id=agent_session_id,
            role=role,
            snapshot=snapshot,
            role_policy_sha256=role_policy.content_sha256,
            workspace_equivalence_policy=workspace_equivalence_policy,
            write_layer_sha256=write_layer_sha256,
            materialization_proof_sha256=materialization_proof_sha256,
            equivalence_fingerprint_sha256=equivalence,
        ))
        return cls(
            lease_id=lease_id,
            broker_id=broker_id,
            validation_instance_id=identity.validation_instance_id,
            attempt_id=attempt_id,
            agent_session_id=agent_session_id,
            role=role,
            snapshot=snapshot,
            role_policy_sha256=role_policy.content_sha256,
            workspace_equivalence_policy=workspace_equivalence_policy,
            write_layer_sha256=write_layer_sha256,
            materialization_proof_sha256=materialization_proof_sha256,
            resource_fingerprint_sha256=resource,
            equivalence_fingerprint_sha256=equivalence,
        )

    def to_document(self) -> dict[str, object]:
        return {
            "contract_kind": _LEASE_CONTRACT_KIND,
            "schema_version": _LEASE_SCHEMA_VERSION,
            "lease_id": self.lease_id,
            "broker_id": self.broker_id,
            "validation_instance_id": self.validation_instance_id,
            "attempt_id": self.attempt_id,
            "agent_session_id": self.agent_session_id,
            "role": self.role.value,
            "snapshot": self.snapshot.to_document(),
            "role_policy_sha256": self.role_policy_sha256,
            "workspace_equivalence_policy": (
                self.workspace_equivalence_policy.to_document()
            ),
            "write_layer_sha256": self.write_layer_sha256,
            "materialization_proof_sha256": self.materialization_proof_sha256,
            "resource_fingerprint_sha256": self.resource_fingerprint_sha256,
            "equivalence_fingerprint_sha256": (
                self.equivalence_fingerprint_sha256
            ),
        }

    @classmethod
    def from_document(cls, value: object) -> WorkspaceLease:
        document = require_exact_keys(
            value,
            required=(
                "contract_kind",
                "schema_version",
                "lease_id",
                "broker_id",
                "validation_instance_id",
                "attempt_id",
                "agent_session_id",
                "role",
                "snapshot",
                "role_policy_sha256",
                "workspace_equivalence_policy",
                "write_layer_sha256",
                "materialization_proof_sha256",
                "resource_fingerprint_sha256",
                "equivalence_fingerprint_sha256",
            ),
            where="workspace lease",
        )
        if document["contract_kind"] != _LEASE_CONTRACT_KIND:
            raise ContractError(
                f"workspace lease contract_kind must be {_LEASE_CONTRACT_KIND!r}"
            )
        if (
            type(document["schema_version"]) is not int
            or document["schema_version"] != _LEASE_SCHEMA_VERSION
        ):
            raise ContractError("workspace lease schema_version must be integer 1")
        session = document["agent_session_id"]
        if session is not None and type(session) is not str:
            raise ContractError("agent_session_id must be a string or null")
        try:
            snapshot = SnapshotRef.from_document(document["snapshot"])
        except ContractError as exc:
            raise ContractError(f"invalid workspace lease snapshot: {exc}") from exc
        return cls(
            lease_id=document["lease_id"],
            broker_id=document["broker_id"],
            validation_instance_id=document["validation_instance_id"],
            attempt_id=document["attempt_id"],
            agent_session_id=session,
            role=_workspace_role(document["role"], "workspace lease role"),
            snapshot=snapshot,
            role_policy_sha256=document["role_policy_sha256"],
            workspace_equivalence_policy=_ref_from_document(
                document["workspace_equivalence_policy"],
                ContractRefKind.EXECUTION_EQUIVALENCE_POLICY,
                "workspace_equivalence_policy",
            ),
            write_layer_sha256=document["write_layer_sha256"],
            materialization_proof_sha256=document[
                "materialization_proof_sha256"
            ],
            resource_fingerprint_sha256=document[
                "resource_fingerprint_sha256"
            ],
            equivalence_fingerprint_sha256=document[
                "equivalence_fingerprint_sha256"
            ],
        )

    @classmethod
    def from_json(cls, payload: object) -> WorkspaceLease:
        return cls.from_document(load_strict_json_object(payload))

    @property
    def content_sha256(self) -> str:
        return canonical_sha256(self.to_document())

    def to_dynamic_resource_binding(
        self,
        expected_gate_role: GateRole,
    ) -> DynamicResourceBinding:
        """Project a Gate lease only after checking its in-process provenance.

        DynamicResourceBinding does not itself carry workspace-role authority;
        the later broker receipt must preserve that provenance across a process
        boundary.  This helper therefore cannot convert A and cannot relabel a
        B1 lease as B2 (or vice versa).
        """

        if type(expected_gate_role) is not GateRole:
            raise ContractError("expected_gate_role must be a GateRole")
        expected_workspace_role = {
            GateRole.B1: WorkspaceRole.B1,
            GateRole.B2: WorkspaceRole.B2,
        }[expected_gate_role]
        if self.role is not expected_workspace_role:
            raise ContractError(
                "workspace lease role does not match the requested Gate role"
            )
        return DynamicResourceBinding(
            symbol="workspace.project",
            resource_kind=DynamicResourceKind.WORKSPACE,
            broker_id=self.broker_id,
            allocation_id=self.lease_id,
            resource_fingerprint_sha256=self.resource_fingerprint_sha256,
            equivalence_policy=self.workspace_equivalence_policy,
            equivalence_fingerprint_sha256=self.equivalence_fingerprint_sha256,
            loopback_port=None,
        )


@dataclass(frozen=True)
class WorkspacePaths:
    """Host-only paths for a materialized lease; never serialize this value."""

    root: Path
    project: Path
    variants: Path | None
    artifacts: Path | None
    scratch: Path
    logs: Path | None
    receipts: Path | None
    case_staging: Path | None

    def __post_init__(self) -> None:
        if not isinstance(self.root, Path) or not self.root.is_absolute():
            raise TypeError("root must be an absolute pathlib.Path")
        for field in (
            "project",
            "variants",
            "artifacts",
            "scratch",
            "logs",
            "receipts",
            "case_staging",
        ):
            path = getattr(self, field)
            if path is not None and (
                not isinstance(path, Path) or not path.is_absolute()
            ):
                raise TypeError(f"{field} must be an absolute pathlib.Path or None")


@dataclass(frozen=True)
class WorkspaceAllocation:
    """One in-process broker handle combining an opaque lease and host paths."""

    lease: WorkspaceLease
    role_policy: RolePolicy
    paths: WorkspacePaths
    materialization: MaterializedSnapshot

    def __post_init__(self) -> None:
        if type(self.lease) is not WorkspaceLease:
            raise TypeError("lease must be a WorkspaceLease")
        if type(self.role_policy) is not RolePolicy:
            raise TypeError("role_policy must be a RolePolicy")
        if type(self.paths) is not WorkspacePaths:
            raise TypeError("paths must be WorkspacePaths")
        if type(self.materialization) is not MaterializedSnapshot:
            raise TypeError("materialization must be a MaterializedSnapshot")
        if self.lease.role is not self.role_policy.role:
            raise ValueError("lease and role_policy roles differ")
        if self.lease.role_policy_sha256 != self.role_policy.content_sha256:
            raise ValueError("lease does not bind its role_policy")
        if self.lease.snapshot.snapshot_sha256 != (
            self.materialization.proof.snapshot_sha256
        ):
            raise ValueError("lease does not bind its materialized snapshot")
        if self.lease.materialization_proof_sha256 != (
            self.materialization.proof.content_sha256
        ):
            raise ValueError("lease does not bind its materialization proof")
        if self.materialization.proof.policy_sha256 != (
            self.lease.snapshot.policy.content_sha256
        ):
            raise ValueError("materialization proof does not bind lease policy")
        if self.materialization.proof.manifest_sha256 != (
            self.lease.snapshot.manifest.content_sha256
        ):
            raise ValueError("materialization proof does not bind lease manifest")
        if self.materialization.destination != self.paths.project:
            raise ValueError("materialization destination must be the project path")
        root = self.paths.root.resolve(strict=True)
        expected: dict[str, Path | None]
        if self.lease.role is WorkspaceRole.A:
            expected = {
                "project": root / "project",
                "variants": None,
                "artifacts": None,
                "scratch": root / "scratch",
                "logs": None,
                "receipts": None,
                "case_staging": root / "case-staging",
            }
        else:
            expected = {
                "project": root / "project",
                "variants": root / "variants",
                "artifacts": root / "artifacts",
                "scratch": root / "scratch",
                "logs": root / "logs",
                "receipts": root / "receipt",
                "case_staging": None,
            }
        for field, wanted in expected.items():
            actual = getattr(self.paths, field)
            if actual != wanted:
                raise ValueError(f"workspace {field} path has a noncanonical layout")
            if actual is not None:
                metadata = actual.lstat()
                if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
                    raise ValueError(f"workspace {field} path must be a real directory")
                if actual.resolve(strict=True) != actual:
                    raise ValueError(f"workspace {field} path must be canonical")

    def path_for_namespace(self, namespace: WorkspaceNamespace) -> Path:
        if type(namespace) is not WorkspaceNamespace:
            raise WorkspaceError(
                WorkspaceErrorCode.ACCESS_DENIED,
                "namespace must be a WorkspaceNamespace",
            )
        if namespace not in self.role_policy.namespaces:
            raise WorkspaceError(
                WorkspaceErrorCode.ACCESS_DENIED,
                f"role {self.lease.role.value} cannot access {namespace.value}",
            )
        mappings: dict[WorkspaceNamespace, Path | None] = {
            WorkspaceNamespace.A_PROJECT_READ_WRITE: self.paths.project,
            WorkspaceNamespace.A_CASE_STAGING_WRITE: self.paths.case_staging,
            WorkspaceNamespace.A_SCRATCH_READ_WRITE: self.paths.scratch,
            WorkspaceNamespace.B1_PROJECT_READ_WRITE: self.paths.project,
            WorkspaceNamespace.B1_VARIANTS_READ_WRITE: self.paths.variants,
            WorkspaceNamespace.B1_ARTIFACTS_WRITE: self.paths.artifacts,
            WorkspaceNamespace.B1_SCRATCH_READ_WRITE: self.paths.scratch,
            WorkspaceNamespace.B1_LOGS_WRITE: self.paths.logs,
            WorkspaceNamespace.B1_RECEIPT_WRITE: self.paths.receipts,
            WorkspaceNamespace.B2_PROJECT_READ_WRITE: self.paths.project,
            WorkspaceNamespace.B2_VARIANTS_READ_WRITE: self.paths.variants,
            WorkspaceNamespace.B2_ARTIFACTS_WRITE: self.paths.artifacts,
            WorkspaceNamespace.B2_SCRATCH_READ_WRITE: self.paths.scratch,
            WorkspaceNamespace.B2_LOGS_WRITE: self.paths.logs,
            WorkspaceNamespace.B2_RECEIPT_WRITE: self.paths.receipts,
            # This namespace represents broker-mounted Profile/CAS inputs and
            # intentionally has no writable host path in this allocation.
            WorkspaceNamespace.FROZEN_INPUTS_READ_ONLY: None,
        }
        root = mappings[namespace]
        if root is None:
            raise WorkspaceError(
                WorkspaceErrorCode.ACCESS_DENIED,
                f"namespace {namespace.value} is read-only or broker-provided",
            )
        return root

    def authorize_write(self, namespace: WorkspaceNamespace, candidate: Path | str) -> Path:
        """Policy-check a contained path; this return value is not a safe I/O handle.

        The later OS broker must reopen the relative path via trusted dirfds and
        openat-style no-follow operations at the actual point of use.
        """

        root = self.path_for_namespace(namespace)
        path = Path(candidate)
        if not path.is_absolute() or ".." in path.parts:
            raise WorkspaceError(
                WorkspaceErrorCode.ACCESS_DENIED,
                "write path must be absolute and lexically traversal-free",
            )
        try:
            canonical_root = root.resolve(strict=True)
            canonical_path = path.resolve(strict=False)
            relative = canonical_path.relative_to(canonical_root)
            current = canonical_root
            # Reject aliases at this policy boundary.  A later broker still
            # performs race-safe I/O through a trusted namespace dirfd.
            original_relative = path.relative_to(root)
            for component in original_relative.parts:
                current = current / component
                try:
                    metadata = current.lstat()
                except FileNotFoundError:
                    break
                if stat.S_ISLNK(metadata.st_mode):
                    raise ValueError("write path contains a symlink component")
        except (OSError, RuntimeError, ValueError) as exc:
            raise WorkspaceError(
                WorkspaceErrorCode.ACCESS_DENIED,
                "write path escapes its authorized namespace",
            ) from exc
        return canonical_path


@dataclass(frozen=True)
class WorkspaceLineageRecord:
    """Path-free evidence for one workspace materialization.

    The record retains only strict, content-bound contracts needed to compare
    an A/B1/B2 lifecycle after its physical workspaces have been released.  It
    deliberately contains no host path and grants no authority to reopen a
    released allocation.
    """

    lease: WorkspaceLease
    role_policy: RolePolicy
    materialization_proof: SnapshotMaterializationProof

    def __post_init__(self) -> None:
        if type(self.lease) is not WorkspaceLease:
            raise ContractError("lineage lease must be a WorkspaceLease")
        if type(self.role_policy) is not RolePolicy:
            raise ContractError("lineage role_policy must be a RolePolicy")
        if type(self.materialization_proof) is not SnapshotMaterializationProof:
            raise ContractError(
                "lineage materialization_proof must be a "
                "SnapshotMaterializationProof"
            )

        # Reconstruct every nested contract so even a corrupted in-process
        # dataclass cannot bypass its own content-binding invariants.
        try:
            parsed_lease = WorkspaceLease.from_document(self.lease.to_document())
            parsed_policy = RolePolicy.from_document(
                self.role_policy.to_document()
            )
            parsed_proof = SnapshotMaterializationProof.from_document(
                self.materialization_proof.to_document()
            )
        except (AttributeError, ContractError, TypeError, ValueError) as exc:
            raise ContractError(
                f"workspace lineage contains an invalid nested contract: {exc}"
            ) from exc
        if (
            parsed_lease != self.lease
            or parsed_policy != self.role_policy
            or parsed_proof != self.materialization_proof
        ):
            raise ContractError(
                "workspace lineage nested contracts are not canonical"
            )

        if self.lease.role is not self.role_policy.role:
            raise ContractError("lineage lease and role_policy roles differ")
        if self.lease.role_policy_sha256 != self.role_policy.content_sha256:
            raise ContractError("lineage lease does not bind its role_policy")
        proof = self.materialization_proof
        if self.lease.materialization_proof_sha256 != proof.content_sha256:
            raise ContractError(
                "lineage lease does not bind its materialization proof"
            )
        if self.lease.snapshot.snapshot_sha256 != proof.snapshot_sha256:
            raise ContractError(
                "lineage proof does not bind the lease snapshot"
            )
        if self.lease.snapshot.policy.content_sha256 != proof.policy_sha256:
            raise ContractError(
                "lineage proof does not bind the lease snapshot policy"
            )
        if self.lease.snapshot.manifest.content_sha256 != proof.manifest_sha256:
            raise ContractError(
                "lineage proof does not bind the lease snapshot manifest"
            )

    @classmethod
    def from_allocation(
        cls,
        allocation: WorkspaceAllocation,
    ) -> WorkspaceLineageRecord:
        """Freeze path-free lineage while an allocation handle is available."""

        if type(allocation) is not WorkspaceAllocation:
            raise TypeError("allocation must be a WorkspaceAllocation")
        return cls(
            lease=allocation.lease,
            role_policy=allocation.role_policy,
            materialization_proof=allocation.materialization.proof,
        )

    def to_document(self) -> dict[str, object]:
        return {
            "contract_kind": _LINEAGE_CONTRACT_KIND,
            "schema_version": _LINEAGE_SCHEMA_VERSION,
            "lease": self.lease.to_document(),
            "role_policy": self.role_policy.to_document(),
            "materialization_proof": self.materialization_proof.to_document(),
        }

    @classmethod
    def from_document(cls, value: object) -> WorkspaceLineageRecord:
        document = require_exact_keys(
            value,
            required=(
                "contract_kind",
                "schema_version",
                "lease",
                "role_policy",
                "materialization_proof",
            ),
            where="workspace lineage record",
        )
        if document["contract_kind"] != _LINEAGE_CONTRACT_KIND:
            raise ContractError(
                "workspace lineage record contract_kind must be "
                f"{_LINEAGE_CONTRACT_KIND!r}"
            )
        if (
            type(document["schema_version"]) is not int
            or document["schema_version"] != _LINEAGE_SCHEMA_VERSION
        ):
            raise ContractError(
                "workspace lineage record schema_version must be integer 1"
            )
        try:
            return cls(
                lease=WorkspaceLease.from_document(document["lease"]),
                role_policy=RolePolicy.from_document(document["role_policy"]),
                materialization_proof=(
                    SnapshotMaterializationProof.from_document(
                        document["materialization_proof"]
                    )
                ),
            )
        except ContractError as exc:
            raise ContractError(
                f"invalid workspace lineage record: {exc}"
            ) from exc

    @classmethod
    def from_json(cls, payload: object) -> WorkspaceLineageRecord:
        return cls.from_document(load_strict_json_object(payload))

    def to_json(self) -> bytes:
        return canonical_json_bytes(self.to_document())

    @property
    def content_sha256(self) -> str:
        return canonical_sha256(self.to_document())


def _paths_overlap(left: Path, right: Path) -> bool:
    try:
        left.relative_to(right)
        return True
    except ValueError:
        pass
    try:
        right.relative_to(left)
        return True
    except ValueError:
        return False


def _managed_directory_identity(path: Path) -> tuple[int, int, int]:
    """Return a stable owner-controlled directory inode and mount identity."""

    parent_metadata = os.lstat(path.parent)
    if (
        path.parent.resolve(strict=True) != path.parent
        or stat.S_ISLNK(parent_metadata.st_mode)
        or not _parent_protects_directory_entry(parent_metadata)
    ):
        raise OSError(f"directory parent no longer protects its entry: {path}")
    metadata = os.lstat(path)
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or stat.S_IMODE(metadata.st_mode) & 0o022
        or path.resolve(strict=True) != path
    ):
        raise OSError(f"managed directory is no longer owner-controlled: {path}")
    descriptor = -1
    try:
        descriptor = os.open(
            path,
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_NOFOLLOW", 0),
        )
        current = os.fstat(descriptor)
        if (
            not stat.S_ISDIR(current.st_mode)
            or (current.st_dev, current.st_ino) != (metadata.st_dev, metadata.st_ino)
            or current.st_uid != os.geteuid()
            or stat.S_IMODE(current.st_mode) & 0o022
        ):
            raise OSError(f"managed directory changed while opening: {path}")
        return current.st_dev, current.st_ino, _mount_id(descriptor, os.fspath(path))
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _regular_inodes(root: Path) -> set[tuple[int, int]]:
    inodes: set[tuple[int, int]] = set()
    for path in (root, *sorted(root.rglob("*"))):
        metadata = path.lstat()
        if stat.S_ISREG(metadata.st_mode):
            if metadata.st_nlink != 1:
                raise WorkspaceError(
                    WorkspaceErrorCode.WORKSPACE_INTEGRITY_FAILURE,
                    f"workspace contains a hard-linked file: {path}",
                )
            inodes.add((metadata.st_dev, metadata.st_ino))
        elif not (stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode)):
            raise WorkspaceError(
                WorkspaceErrorCode.WORKSPACE_INTEGRITY_FAILURE,
                f"workspace contains a special entry: {path}",
            )
    return inodes


def validate_workspace_lineage(
    a: WorkspaceLineageRecord,
    b1: WorkspaceLineageRecord,
    b2: WorkspaceLineageRecord,
) -> None:
    """Validate path-free A/B1/B2 provenance, including after release."""

    records = (a, b1, b2)
    if any(type(item) is not WorkspaceLineageRecord for item in records):
        raise WorkspaceError(
            WorkspaceErrorCode.WORKSPACE_INTEGRITY_FAILURE,
            "lineage validation requires WorkspaceLineageRecord values",
        )
    try:
        reparsed = tuple(
            WorkspaceLineageRecord.from_document(item.to_document())
            for item in records
        )
    except (AttributeError, ContractError, TypeError, ValueError) as exc:
        _raise(
            WorkspaceErrorCode.WORKSPACE_INTEGRITY_FAILURE,
            f"workspace lineage contains invalid bound metadata: {exc}",
            exc,
        )
    if reparsed != records:
        raise WorkspaceError(
            WorkspaceErrorCode.WORKSPACE_INTEGRITY_FAILURE,
            "workspace lineage metadata is not canonical",
        )

    if tuple(item.lease.role for item in records) != (
        WorkspaceRole.A,
        WorkspaceRole.B1,
        WorkspaceRole.B2,
    ):
        raise WorkspaceError(
            WorkspaceErrorCode.WORKSPACE_INTEGRITY_FAILURE,
            "lineage validation requires ordered A, B1, and B2 records",
        )
    if len({item.lease.validation_instance_id for item in records}) != 1:
        raise WorkspaceError(
            WorkspaceErrorCode.WORKSPACE_INTEGRITY_FAILURE,
            "workspace lineages belong to different validation instances",
        )
    if any(item.lease.snapshot != a.lease.snapshot for item in records[1:]):
        raise WorkspaceError(
            WorkspaceErrorCode.WORKSPACE_INTEGRITY_FAILURE,
            "workspace lineages do not share one exact frozen snapshot",
        )
    if len({item.role_policy.profile for item in records}) != 1:
        raise WorkspaceError(
            WorkspaceErrorCode.WORKSPACE_INTEGRITY_FAILURE,
            "workspace lineages bind different Frozen Profiles",
        )
    if len({item.role_policy.resource_policy for item in records}) != 1:
        raise WorkspaceError(
            WorkspaceErrorCode.WORKSPACE_INTEGRITY_FAILURE,
            "workspace lineages bind different resource policies",
        )
    if b1.lease.attempt_id != b2.lease.attempt_id:
        raise WorkspaceError(
            WorkspaceErrorCode.WORKSPACE_INTEGRITY_FAILURE,
            "B1 and B2 workspace lineages belong to different attempts",
        )
    if len({item.lease.workspace_equivalence_policy for item in records}) != 1:
        raise WorkspaceError(
            WorkspaceErrorCode.WORKSPACE_INTEGRITY_FAILURE,
            "workspace lineages use different equivalence policies",
        )
    if len({item.lease.equivalence_fingerprint_sha256 for item in records}) != 1:
        raise WorkspaceError(
            WorkspaceErrorCode.WORKSPACE_INTEGRITY_FAILURE,
            "workspace lineages have different equivalence fingerprints",
        )

    unique_values = (
        ("lease_id", tuple(item.lease.lease_id for item in records)),
        (
            "write_layer_sha256",
            tuple(item.lease.write_layer_sha256 for item in records),
        ),
        (
            "materialization_proof_sha256",
            tuple(
                item.lease.materialization_proof_sha256 for item in records
            ),
        ),
        (
            "resource_fingerprint_sha256",
            tuple(item.lease.resource_fingerprint_sha256 for item in records),
        ),
        (
            "materialization_id",
            tuple(
                item.materialization_proof.materialization_id
                for item in records
            ),
        ),
    )
    for field, values in unique_values:
        if len(set(values)) != len(records):
            raise WorkspaceError(
                WorkspaceErrorCode.WORKSPACE_INTEGRITY_FAILURE,
                f"workspace lineages reuse {field}",
            )


def validate_workspace_independence(
    a: WorkspaceAllocation,
    b1: WorkspaceAllocation,
    b2: WorkspaceAllocation,
) -> None:
    """Require same frozen input with three non-overlapping writable views."""

    allocations = (a, b1, b2)
    if any(type(item) is not WorkspaceAllocation for item in allocations):
        raise WorkspaceError(
            WorkspaceErrorCode.WORKSPACE_INTEGRITY_FAILURE,
            "independence requires WorkspaceAllocation values",
        )
    try:
        lineage = tuple(
            WorkspaceLineageRecord.from_allocation(item)
            for item in allocations
        )
    except (AttributeError, ContractError, TypeError, ValueError) as exc:
        _raise(
            WorkspaceErrorCode.WORKSPACE_INTEGRITY_FAILURE,
            f"workspace allocation lineage is invalid: {exc}",
            exc,
        )
    validate_workspace_lineage(*lineage)

    roots = tuple(item.paths.root.resolve(strict=True) for item in allocations)
    for index, left in enumerate(roots):
        for right in roots[index + 1:]:
            if _paths_overlap(left, right):
                raise WorkspaceError(
                    WorkspaceErrorCode.WORKSPACE_INTEGRITY_FAILURE,
                    "role workspace roots overlap",
                )
    try:
        inode_sets = tuple(
            _regular_inodes(item.paths.project) for item in allocations
        )
    except WorkspaceError:
        raise
    except (OSError, RecursionError, RuntimeError) as exc:
        _raise(
            WorkspaceErrorCode.WORKSPACE_INTEGRITY_FAILURE,
            "cannot safely inspect role workspace inode independence",
            exc,
        )
    for index, left in enumerate(inode_sets):
        for right in inode_sets[index + 1:]:
            if left.intersection(right):
                raise WorkspaceError(
                    WorkspaceErrorCode.WORKSPACE_INTEGRITY_FAILURE,
                    "role workspaces share writable regular-file inodes",
                )


def validate_workspace_lease_context(
    lease: WorkspaceLease,
    *,
    identity: ValidationInstanceIdentity,
    profile: FrozenSystemProfile,
    role_policy: RolePolicy,
) -> None:
    """Bind a parsed lease back to all authority-owned frozen inputs."""

    if type(lease) is not WorkspaceLease:
        raise ContractError("lease must be a WorkspaceLease")
    if type(identity) is not ValidationInstanceIdentity:
        raise ContractError("identity must be a ValidationInstanceIdentity")
    if type(profile) is not FrozenSystemProfile:
        raise ContractError("profile must be a FrozenSystemProfile")
    if type(role_policy) is not RolePolicy:
        raise ContractError("role_policy must be a RolePolicy")
    if lease.validation_instance_id != identity.validation_instance_id:
        raise ContractError("lease validation instance does not match identity")
    if lease.snapshot.snapshot_sha256 != identity.snapshot_sha256:
        raise ContractError("lease snapshot does not match identity")
    if profile.content_sha256 != identity.profile_sha256:
        raise ContractError("Profile does not match identity")
    if profile.project.system_id != identity.project_id:
        raise ContractError("Profile project does not match identity")
    if profile.project.source_snapshot_sha256 != identity.snapshot_sha256:
        raise ContractError("Profile snapshot does not match identity")
    if role_policy.profile != profile.ref:
        raise ContractError("role policy does not match Profile")
    if role_policy.resource_policy != profile.environment.resource_policy:
        raise ContractError("role resource policy does not match Profile")
    if lease.workspace_equivalence_policy not in profile.components:
        raise ContractError("lease equivalence policy is not frozen in Profile")
    if lease.role is not role_policy.role:
        raise ContractError("lease role does not match role policy")
    if lease.role_policy_sha256 != role_policy.content_sha256:
        raise ContractError("lease does not hash-bind role policy")


class WorkspaceManager:
    """Host-side allocator for independently copied role workspaces."""

    def __init__(
        self,
        *,
        store: SnapshotStore,
        run_root: Path | str,
        broker_id: str = "snapshot.workspace",
    ) -> None:
        if type(store) is not SnapshotStore:
            raise TypeError("store must be a SnapshotStore")
        validate_identifier(broker_id, "broker_id")
        candidate = Path(run_root)
        if not candidate.is_absolute():
            _raise(WorkspaceErrorCode.INVALID_RUN_ROOT, "run_root must be absolute")
        try:
            if candidate.parent == candidate:
                _raise(
                    WorkspaceErrorCode.INVALID_RUN_ROOT,
                    "run_root must not be a filesystem root",
                )
            parent = candidate.parent.resolve(strict=True)
            parent_metadata = os.lstat(candidate.parent)
            if (
                parent != candidate.parent
                or stat.S_ISLNK(parent_metadata.st_mode)
                or not _parent_protects_directory_entry(parent_metadata)
            ):
                _raise(
                    WorkspaceErrorCode.INVALID_RUN_ROOT,
                    "run_root parent must protect child entries by owner-only "
                    "or trusted sticky-directory semantics",
                )
            # Reject lexical containment before creating anything.  In
            # particular, an invalid ``store.root / 'runs'`` request must not
            # leave even an empty directory inside the immutable CAS tree.
            if _paths_overlap(candidate, store.root):
                _raise(
                    WorkspaceErrorCode.INVALID_RUN_ROOT,
                    "run_root must not overlap the immutable snapshot store",
                )
            if candidate.exists() or candidate.is_symlink():
                metadata = os.lstat(candidate)
                if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
                    _raise(
                        WorkspaceErrorCode.INVALID_RUN_ROOT,
                        "run_root must be a real directory",
                    )
                if metadata.st_uid != os.geteuid() or stat.S_IMODE(metadata.st_mode) & 0o022:
                    _raise(
                        WorkspaceErrorCode.INVALID_RUN_ROOT,
                        "run_root must be owner-controlled and not group/world writable",
                    )
                if candidate.resolve(strict=True) != candidate:
                    _raise(
                        WorkspaceErrorCode.INVALID_RUN_ROOT,
                        "run_root must be canonical",
                    )
            else:
                candidate.mkdir(mode=0o700)
            leases = candidate / "leases"
            if leases.exists() or leases.is_symlink():
                metadata = os.lstat(leases)
                if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
                    _raise(
                        WorkspaceErrorCode.INVALID_RUN_ROOT,
                        "leases root must be a real directory",
                    )
                if metadata.st_uid != os.geteuid() or stat.S_IMODE(metadata.st_mode) & 0o022:
                    _raise(
                        WorkspaceErrorCode.INVALID_RUN_ROOT,
                        "leases root must be owner-controlled and not group/world writable",
                    )
                if leases.resolve(strict=True) != leases:
                    _raise(
                        WorkspaceErrorCode.INVALID_RUN_ROOT,
                        "leases root must be canonical",
                    )
            else:
                leases.mkdir(mode=0o700)
        except WorkspaceError:
            raise
        except OSError as exc:
            _raise(
                WorkspaceErrorCode.INVALID_RUN_ROOT,
                f"cannot initialize workspace run root: {exc}",
                exc,
            )
        self.store = store
        self.run_root = candidate
        self.leases_root = leases
        self.broker_id = broker_id
        self._lock = threading.RLock()
        self._active: dict[str, tuple[WorkspaceAllocation, tuple[int, int]]] = {}
        try:
            self._run_root_identity = _managed_directory_identity(self.run_root)
            self._leases_root_identity = _managed_directory_identity(self.leases_root)
            if self._run_root_identity[2] != self._leases_root_identity[2]:
                _raise(
                    WorkspaceErrorCode.INVALID_RUN_ROOT,
                    "leases root crosses the workspace run-root mount boundary",
                )
        except WorkspaceError:
            raise
        except (OSError, SnapshotStoreError) as exc:
            _raise(
                WorkspaceErrorCode.INVALID_RUN_ROOT,
                "cannot pin workspace manager directory identities",
                exc,
            )

    def _validate_manager_roots(self, error_code: WorkspaceErrorCode) -> None:
        try:
            if _managed_directory_identity(self.run_root) != self._run_root_identity:
                raise OSError("workspace run-root identity changed")
            if (
                _managed_directory_identity(self.leases_root)
                != self._leases_root_identity
            ):
                raise OSError("workspace leases-root identity changed")
        except (OSError, SnapshotStoreError) as exc:
            _raise(error_code, "workspace manager roots failed revalidation", exc)

    def materialize(
        self,
        *,
        snapshot: SnapshotRef,
        identity: ValidationInstanceIdentity,
        profile: FrozenSystemProfile,
        attempt_id: str,
        role_policy: RolePolicy,
        workspace_equivalence_policy: ContractRef,
        agent_session_id: str | None = None,
    ) -> WorkspaceAllocation:
        """Allocate a fresh role view directly from the immutable CAS snapshot."""

        if type(snapshot) is not SnapshotRef:
            raise TypeError("snapshot must be a SnapshotRef")
        if type(identity) is not ValidationInstanceIdentity:
            raise TypeError("identity must be a ValidationInstanceIdentity")
        if type(profile) is not FrozenSystemProfile:
            raise TypeError("profile must be a FrozenSystemProfile")
        validate_identifier(attempt_id, "attempt_id")
        if type(role_policy) is not RolePolicy:
            raise TypeError("role_policy must be a RolePolicy")
        _require_ref(
            workspace_equivalence_policy,
            ContractRefKind.EXECUTION_EQUIVALENCE_POLICY,
            "workspace_equivalence_policy",
        )
        if identity.snapshot_sha256 != snapshot.snapshot_sha256:
            _raise(
                WorkspaceErrorCode.SNAPSHOT_MISMATCH,
                "validation identity does not bind the requested snapshot",
            )
        if profile.content_sha256 != identity.profile_sha256:
            _raise(
                WorkspaceErrorCode.ROLE_POLICY_MISMATCH,
                "Frozen Profile does not bind the validation identity",
            )
        if profile.project.system_id != identity.project_id:
            _raise(
                WorkspaceErrorCode.ROLE_POLICY_MISMATCH,
                "Frozen Profile project does not bind the validation identity",
            )
        if profile.project.source_snapshot_sha256 != snapshot.snapshot_sha256:
            _raise(
                WorkspaceErrorCode.SNAPSHOT_MISMATCH,
                "Frozen Profile does not bind the requested snapshot",
            )
        if role_policy.profile != profile.ref:
            _raise(
                WorkspaceErrorCode.ROLE_POLICY_MISMATCH,
                "role policy Profile does not bind the validation identity",
            )
        if role_policy.resource_policy != profile.environment.resource_policy:
            _raise(
                WorkspaceErrorCode.ROLE_POLICY_MISMATCH,
                "role policy resource policy does not match the Frozen Profile",
            )
        if workspace_equivalence_policy not in profile.components:
            _raise(
                WorkspaceErrorCode.ROLE_POLICY_MISMATCH,
                "workspace equivalence policy is not frozen in the Profile",
            )
        role = role_policy.role
        if role is WorkspaceRole.A:
            try:
                validate_identifier(agent_session_id, "agent_session_id")
            except ContractError as exc:
                _raise(
                    WorkspaceErrorCode.INVALID_REQUEST,
                    "A allocation requires one safe Agent session id",
                    exc,
                )
        elif agent_session_id is not None:
            _raise(
                WorkspaceErrorCode.INVALID_REQUEST,
                "B1/B2 allocation must not expose an Agent session",
            )

        with self._lock:
            self._validate_manager_roots(WorkspaceErrorCode.INVALID_RUN_ROOT)
            lease_id = f"ws-{uuid.uuid4().hex}"
            root = self.leases_root / lease_id
            root_identity: tuple[int, int] | None = None
            try:
                os.mkdir(root, mode=0o700)
                metadata = os.lstat(root)
                root_identity = (metadata.st_dev, metadata.st_ino)
                project = root / "project"
                materialization = self.store.materialize(snapshot, project)
                scratch = root / "scratch"
                scratch.mkdir(mode=0o700)
                if role is WorkspaceRole.A:
                    case_staging = root / "case-staging"
                    case_staging.mkdir(mode=0o700)
                    variants = artifacts = logs = receipts = None
                else:
                    variants = root / "variants"
                    artifacts = root / "artifacts"
                    logs = root / "logs"
                    receipts = root / "receipt"
                    for directory in (variants, artifacts, logs, receipts):
                        directory.mkdir(mode=0o700)
                    case_staging = None
                paths = WorkspacePaths(
                    root=root,
                    project=project,
                    variants=variants,
                    artifacts=artifacts,
                    scratch=scratch,
                    logs=logs,
                    receipts=receipts,
                    case_staging=case_staging,
                )
                write_layer_sha256 = hashlib.sha256(os.urandom(32)).hexdigest()
                lease = WorkspaceLease.create(
                    lease_id=lease_id,
                    broker_id=self.broker_id,
                    identity=identity,
                    profile=profile,
                    attempt_id=attempt_id,
                    agent_session_id=agent_session_id,
                    role=role,
                    snapshot=snapshot,
                    role_policy=role_policy,
                    workspace_equivalence_policy=workspace_equivalence_policy,
                    write_layer_sha256=write_layer_sha256,
                    materialization_proof_sha256=(
                        materialization.proof.content_sha256
                    ),
                )
                allocation = WorkspaceAllocation(
                    lease=lease,
                    role_policy=role_policy,
                    paths=paths,
                    materialization=materialization,
                )
                validate_workspace_lease_context(
                    lease,
                    identity=identity,
                    profile=profile,
                    role_policy=role_policy,
                )
                self._active[lease_id] = (allocation, root_identity)
                return allocation
            except WorkspaceError:
                self._cleanup_failed_root(root, root_identity)
                raise
            except (ContractError, SnapshotStoreError, OSError, ValueError) as exc:
                cleanup_detail = self._cleanup_failed_root(
                    root, root_identity, suppress=True,
                )
                suffix = f"; cleanup failed: {cleanup_detail}" if cleanup_detail else ""
                _raise(
                    WorkspaceErrorCode.ALLOCATION_FAILED,
                    f"workspace allocation failed closed: {exc}{suffix}",
                    exc,
                )

    def release(self, allocation: WorkspaceAllocation) -> None:
        """Destroy exactly one manager-owned lease or fail without broad deletion."""

        if type(allocation) is not WorkspaceAllocation:
            raise TypeError("allocation must be a WorkspaceAllocation")
        with self._lock:
            self._validate_manager_roots(WorkspaceErrorCode.RELEASE_FAILED)
            registered = self._active.get(allocation.lease.lease_id)
            if registered is None or registered[0] is not allocation:
                _raise(
                    WorkspaceErrorCode.UNKNOWN_LEASE,
                    "workspace lease is unknown or is not the active handle",
                )
            root = allocation.paths.root
            identity = registered[1]
            try:
                relative = root.relative_to(self.leases_root)
                if len(relative.parts) != 1 or relative.name != allocation.lease.lease_id:
                    _raise(
                        WorkspaceErrorCode.RELEASE_FAILED,
                        "workspace root is outside its broker namespace",
                    )
                metadata = os.lstat(root)
                if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
                    _raise(
                        WorkspaceErrorCode.RELEASE_FAILED,
                        "workspace root was replaced by a non-directory",
                    )
                if (metadata.st_dev, metadata.st_ino) != identity:
                    _raise(
                        WorkspaceErrorCode.RELEASE_FAILED,
                        "workspace root identity changed before release",
                    )
                _require_single_mount_tree(root)
                shutil.rmtree(root)
                if root.exists() or root.is_symlink():
                    _raise(
                        WorkspaceErrorCode.RELEASE_FAILED,
                        "workspace root still exists after release",
                    )
                del self._active[allocation.lease.lease_id]
            except WorkspaceError:
                raise
            except OSError as exc:
                _raise(
                    WorkspaceErrorCode.RELEASE_FAILED,
                    f"cannot safely release workspace: {exc}",
                    exc,
                )

    def _cleanup_failed_root(
        self,
        root: Path,
        identity: tuple[int, int] | None,
        *,
        suppress: bool = False,
    ) -> str | None:
        if identity is None:
            return None
        try:
            metadata = os.lstat(root)
            if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
                raise OSError("failed workspace root was replaced")
            if (metadata.st_dev, metadata.st_ino) != identity:
                raise OSError("failed workspace root identity changed")
            _require_single_mount_tree(root)
            shutil.rmtree(root)
            return None
        except FileNotFoundError:
            return None
        except OSError as exc:
            if suppress:
                return str(exc)
            _raise(
                WorkspaceErrorCode.RELEASE_FAILED,
                f"cannot clean failed workspace root: {exc}",
                exc,
            )


__all__ = [
    "WorkspaceAllocation",
    "WorkspaceError",
    "WorkspaceErrorCode",
    "WorkspaceLease",
    "WorkspaceLineageRecord",
    "WorkspaceManager",
    "WorkspacePaths",
    "validate_workspace_lease_context",
    "validate_workspace_independence",
    "validate_workspace_lineage",
]

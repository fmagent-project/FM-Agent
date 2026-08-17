"""Frozen contracts for content-addressed source snapshots.

The contracts in this module are deliberately filesystem-independent.  They
describe which paths may enter a snapshot, the canonical manifest that was
captured, and the exact policy/manifest pair that defines the snapshot root.
Filesystem traversal, race resistance, CAS writes, and materialization belong
to :mod:`validation_core.storage.snapshot`.
"""

from __future__ import annotations

import hashlib
import re
import unicodedata
from dataclasses import dataclass
from enum import Enum

from .base import (
    ContractError,
    canonical_json_bytes,
    canonical_sha256,
    load_strict_json_object,
    require_exact_keys,
    validate_identifier,
    validate_non_negative_int,
    validate_positive_int,
    validate_safe_relative_path,
    validate_sha256,
)
from .references import ArtifactRef, ContractRef, ContractRefKind


_SNAPSHOT_POLICY_CONTRACT_KIND = "snapshot_policy"
_SNAPSHOT_MANIFEST_CONTRACT_KIND = "source_snapshot_manifest"
_SNAPSHOT_REF_CONTRACT_KIND = "source_snapshot"
_SCHEMA_VERSION = 1
_SNAPSHOT_ROOT_HASH_DOMAIN = "fmagent.source_snapshot.root/v1"
_MANIFEST_ROLE = "source_snapshot_manifest"
_MANIFEST_MEDIA_TYPE = "application/json"
_MAX_POLICY_PATHS = 4_096
_MAX_MANIFEST_ENTRIES = 1_000_000
_MAX_BYTE_COUNT = 9_223_372_036_854_775_807
_MAX_PATH_BYTES = 4_096
_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")
_EMPTY_CONTENT_SHA256 = hashlib.sha256(b"").hexdigest()

# These are the producer/consumer bounds for persisted snapshot metadata.
# SnapshotStore imports these exact values so it cannot publish a contract
# that the public strict parsers are guaranteed to reject.
MAX_SNAPSHOT_POLICY_BYTES = 4 * 1024 * 1024
MAX_SNAPSHOT_MANIFEST_BYTES = 256 * 1024 * 1024
MAX_SNAPSHOT_REFERENCE_BYTES = 64 * 1024
MAX_SNAPSHOT_PATH_COMPONENTS = 256


class SnapshotEntryKind(str, Enum):
    """Closed set of stable filesystem node types admitted to a snapshot."""

    FILE = "file"
    DIRECTORY = "directory"
    SYMLINK = "symlink"


class SymlinkPolicy(str, Enum):
    """Closed symlink behavior; special files are never represented."""

    REJECT_ALL = "reject_all"
    SAFE_RELATIVE = "safe_relative"


def _validate_nfc_safe_path(value: object, field: str) -> str:
    path = validate_safe_relative_path(value, field)
    if len(path.split("/")) > MAX_SNAPSHOT_PATH_COMPONENTS:
        raise ContractError(
            f"{field} must not exceed {MAX_SNAPSHOT_PATH_COMPONENTS} path components"
        )
    if unicodedata.normalize("NFC", path) != path:
        raise ContractError(f"{field} must use Unicode NFC normalization")
    # UTF-8 encoding is part of canonical ordering and must therefore be
    # representable without surrogate replacement.
    try:
        encoded = path.encode("utf-8", errors="strict")
    except UnicodeEncodeError as exc:  # defensive; base rejects surrogates
        raise ContractError(f"{field} must be valid UTF-8 text") from exc
    if len(encoded) > _MAX_PATH_BYTES:
        raise ContractError(
            f"{field} must not exceed {_MAX_PATH_BYTES} UTF-8 bytes"
        )
    return path


def _validate_single_segment(value: object, field: str) -> str:
    segment = _validate_nfc_safe_path(value, field)
    if "/" in segment:
        raise ContractError(f"{field} must be one path segment")
    return segment


def _normalize_paths(value: object, field: str) -> tuple[str, ...]:
    if type(value) not in (tuple, list):
        raise ContractError(f"{field} must be a collection of relative paths")
    paths = tuple(
        _validate_nfc_safe_path(item, f"{field}[{index}]")
        for index, item in enumerate(value)
    )
    if len(paths) > _MAX_POLICY_PATHS:
        raise ContractError(
            f"{field} must not contain more than {_MAX_POLICY_PATHS} paths"
        )
    if len(paths) != len(set(paths)):
        raise ContractError(f"{field} must not contain duplicate paths")
    return tuple(sorted(paths, key=lambda item: item.encode("utf-8")))


def _normalize_segments(value: object, field: str) -> tuple[str, ...]:
    if type(value) not in (tuple, list):
        raise ContractError(f"{field} must be a collection of path segments")
    segments = tuple(
        _validate_single_segment(item, f"{field}[{index}]")
        for index, item in enumerate(value)
    )
    if len(segments) > _MAX_POLICY_PATHS:
        raise ContractError(
            f"{field} must not contain more than {_MAX_POLICY_PATHS} values"
        )
    if len(segments) != len(set(segments)):
        raise ContractError(f"{field} must not contain duplicate values")
    return tuple(sorted(segments, key=lambda item: item.encode("utf-8")))


def _enum_value(enum_type: type[Enum], value: object, field: str) -> Enum:
    if type(value) is not str:
        raise ContractError(f"{field} must be a string enum value")
    try:
        return enum_type(value)
    except ValueError as exc:
        raise ContractError(f"{field} has unknown value {value!r}") from exc


def _is_path_prefix(prefix: str, path: str) -> bool:
    return path == prefix or path.startswith(prefix + "/")


@dataclass(frozen=True)
class SnapshotPolicy:
    """Hash-bound, deterministic include/exclude policy for one source tree."""

    policy_id: str
    policy_version: str
    include_paths: tuple[str, ...]
    exclude_paths: tuple[str, ...]
    excluded_names: tuple[str, ...]
    excluded_name_prefixes: tuple[str, ...]
    excluded_top_level_prefixes: tuple[str, ...]
    symlink_policy: SymlinkPolicy
    max_entries: int
    max_file_bytes: int
    max_total_bytes: int

    def __post_init__(self) -> None:
        validate_identifier(self.policy_id, "policy_id")
        validate_identifier(self.policy_version, "policy_version")
        object.__setattr__(
            self,
            "include_paths",
            _normalize_paths(self.include_paths, "include_paths"),
        )
        object.__setattr__(
            self,
            "exclude_paths",
            _normalize_paths(self.exclude_paths, "exclude_paths"),
        )
        object.__setattr__(
            self,
            "excluded_names",
            _normalize_segments(self.excluded_names, "excluded_names"),
        )
        object.__setattr__(
            self,
            "excluded_name_prefixes",
            _normalize_segments(
                self.excluded_name_prefixes,
                "excluded_name_prefixes",
            ),
        )
        object.__setattr__(
            self,
            "excluded_top_level_prefixes",
            _normalize_segments(
                self.excluded_top_level_prefixes,
                "excluded_top_level_prefixes",
            ),
        )
        if type(self.symlink_policy) is not SymlinkPolicy:
            raise ContractError("symlink_policy must be a SymlinkPolicy")
        validate_positive_int(
            self.max_entries,
            "max_entries",
            maximum=_MAX_MANIFEST_ENTRIES,
        )
        validate_non_negative_int(
            self.max_file_bytes,
            "max_file_bytes",
            maximum=_MAX_BYTE_COUNT,
        )
        validate_non_negative_int(
            self.max_total_bytes,
            "max_total_bytes",
            maximum=_MAX_BYTE_COUNT,
        )
        if self.max_file_bytes > self.max_total_bytes:
            raise ContractError("max_file_bytes must not exceed max_total_bytes")

    def includes(self, relative_path: object) -> bool:
        """Return whether a canonical path may occur in this snapshot.

        Ancestors of an explicit include are admitted so manifests can carry
        the directory nodes required to reach the selected subtree.  Excludes
        always win and use whole path-segment prefix semantics.
        """

        path = _validate_nfc_safe_path(relative_path, "relative_path")
        parts = path.split("/")
        if any(name in self.excluded_names for name in parts):
            return False
        if any(
            name.startswith(prefix)
            for name in parts
            for prefix in self.excluded_name_prefixes
        ):
            return False
        top_level = parts[0]
        if any(
            top_level.startswith(prefix)
            for prefix in self.excluded_top_level_prefixes
        ):
            return False
        if any(_is_path_prefix(prefix, path) for prefix in self.exclude_paths):
            return False
        if not self.include_paths:
            return True
        return any(
            _is_path_prefix(prefix, path) or _is_path_prefix(path, prefix)
            for prefix in self.include_paths
        )

    def validate_manifest(self, manifest: SnapshotManifest) -> None:
        """Validate policy selection and byte budgets for a manifest."""

        if type(manifest) is not SnapshotManifest:
            raise ContractError("manifest must be a SnapshotManifest")
        if len(manifest.entries) > self.max_entries:
            raise ContractError("manifest exceeds snapshot policy max_entries")
        total_bytes = 0
        for entry in manifest.entries:
            if not self.includes(entry.relative_path):
                raise ContractError(
                    "manifest contains a path excluded by snapshot policy: "
                    f"{entry.relative_path}"
                )
            if entry.kind is SnapshotEntryKind.FILE:
                if entry.size_bytes > self.max_file_bytes:
                    raise ContractError(
                        "manifest file exceeds snapshot policy max_file_bytes: "
                        f"{entry.relative_path}"
                    )
                total_bytes += entry.size_bytes
            elif entry.kind is SnapshotEntryKind.SYMLINK:
                if self.symlink_policy is SymlinkPolicy.REJECT_ALL:
                    raise ContractError(
                        "manifest contains a symlink forbidden by snapshot policy: "
                        f"{entry.relative_path}"
                    )
                # A target is persisted and hash-bound content too.  Counting
                # it closes an otherwise unbounded max_total_bytes bypass.
                total_bytes += entry.size_bytes
            if total_bytes > self.max_total_bytes:
                raise ContractError("manifest exceeds snapshot policy max_total_bytes")

    def to_document(self) -> dict[str, object]:
        return {
            "contract_kind": _SNAPSHOT_POLICY_CONTRACT_KIND,
            "schema_version": _SCHEMA_VERSION,
            "policy_id": self.policy_id,
            "policy_version": self.policy_version,
            "include_paths": list(self.include_paths),
            "exclude_paths": list(self.exclude_paths),
            "excluded_names": list(self.excluded_names),
            "excluded_name_prefixes": list(self.excluded_name_prefixes),
            "excluded_top_level_prefixes": list(
                self.excluded_top_level_prefixes
            ),
            "symlink_policy": self.symlink_policy.value,
            "max_entries": self.max_entries,
            "max_file_bytes": self.max_file_bytes,
            "max_total_bytes": self.max_total_bytes,
        }

    @classmethod
    def from_document(cls, value: object) -> SnapshotPolicy:
        document = require_exact_keys(
            value,
            required=(
                "contract_kind",
                "schema_version",
                "policy_id",
                "policy_version",
                "include_paths",
                "exclude_paths",
                "excluded_names",
                "excluded_name_prefixes",
                "excluded_top_level_prefixes",
                "symlink_policy",
                "max_entries",
                "max_file_bytes",
                "max_total_bytes",
            ),
            where="snapshot_policy",
        )
        if (
            type(document["contract_kind"]) is not str
            or document["contract_kind"] != _SNAPSHOT_POLICY_CONTRACT_KIND
        ):
            raise ContractError(
                "snapshot_policy.contract_kind must be 'snapshot_policy'"
            )
        if (
            type(document["schema_version"]) is not int
            or document["schema_version"] != _SCHEMA_VERSION
        ):
            raise ContractError("snapshot_policy.schema_version must be integer 1")
        for field in (
            "include_paths",
            "exclude_paths",
            "excluded_names",
            "excluded_name_prefixes",
            "excluded_top_level_prefixes",
        ):
            if type(document[field]) is not list:
                raise ContractError(f"snapshot_policy.{field} must be a list")
        return cls(
            policy_id=document["policy_id"],
            policy_version=document["policy_version"],
            include_paths=tuple(document["include_paths"]),
            exclude_paths=tuple(document["exclude_paths"]),
            excluded_names=tuple(document["excluded_names"]),
            excluded_name_prefixes=tuple(document["excluded_name_prefixes"]),
            excluded_top_level_prefixes=tuple(
                document["excluded_top_level_prefixes"]
            ),
            symlink_policy=_enum_value(
                SymlinkPolicy,
                document["symlink_policy"],
                "snapshot_policy.symlink_policy",
            ),
            max_entries=document["max_entries"],
            max_file_bytes=document["max_file_bytes"],
            max_total_bytes=document["max_total_bytes"],
        )

    @classmethod
    def from_json(cls, payload: object) -> SnapshotPolicy:
        return cls.from_document(load_strict_json_object(
            payload,
            max_bytes=MAX_SNAPSHOT_POLICY_BYTES,
        ))

    @property
    def content_sha256(self) -> str:
        return canonical_sha256(self.to_document())

    @property
    def ref(self) -> ContractRef:
        return ContractRef(
            kind=ContractRefKind.SNAPSHOT_POLICY,
            contract_id=self.policy_id,
            contract_version=self.policy_version,
            content_sha256=self.content_sha256,
        )


def _validate_symlink_target(value: object, field: str) -> str:
    if type(value) is not str or not value:
        raise ContractError(f"{field} must be a non-empty relative POSIX path")
    if unicodedata.normalize("NFC", value) != value:
        raise ContractError(f"{field} must use Unicode NFC normalization")
    if (
        value.startswith("/")
        or "\\" in value
        or ":" in value
        or _CONTROL_RE.search(value)
    ):
        raise ContractError(f"{field} must be a safe relative POSIX path")
    try:
        encoded = value.encode("utf-8", errors="strict")
    except UnicodeEncodeError as exc:
        raise ContractError(f"{field} must be valid UTF-8 text") from exc
    if len(encoded) > _MAX_PATH_BYTES:
        raise ContractError(
            f"{field} must not exceed {_MAX_PATH_BYTES} UTF-8 bytes"
        )
    return value


@dataclass(frozen=True)
class SnapshotManifestEntry:
    """One canonical regular file, directory, or safe relative symlink."""

    relative_path: str
    kind: SnapshotEntryKind
    mode: int
    size_bytes: int
    content_sha256: str
    symlink_target: str | None

    def __post_init__(self) -> None:
        _validate_nfc_safe_path(self.relative_path, "relative_path")
        if type(self.kind) is not SnapshotEntryKind:
            raise ContractError("kind must be a SnapshotEntryKind")
        if type(self.mode) is not int or not 0 <= self.mode <= 0o777:
            raise ContractError(
                "mode must be an integer from 0 through 0777 without privilege bits"
            )
        validate_non_negative_int(
            self.size_bytes,
            "size_bytes",
            maximum=_MAX_BYTE_COUNT,
        )
        if self.kind is SnapshotEntryKind.FILE:
            validate_sha256(self.content_sha256, "content_sha256")
            if self.symlink_target is not None:
                raise ContractError("file entry symlink_target must be null")
            return
        if self.kind is SnapshotEntryKind.DIRECTORY:
            if self.size_bytes != 0:
                raise ContractError("directory entry size_bytes must be zero")
            if self.content_sha256 != _EMPTY_CONTENT_SHA256:
                raise ContractError(
                    "directory entry content_sha256 must hash empty content"
                )
            if self.symlink_target is not None:
                raise ContractError("directory entry symlink_target must be null")
            return

        target = _validate_symlink_target(
            self.symlink_target,
            "symlink_target",
        )
        if self.mode != 0o777:
            raise ContractError("symlink entry mode must be canonical 0777")
        target_bytes = target.encode("utf-8")
        if self.size_bytes != len(target_bytes):
            raise ContractError(
                "symlink entry size_bytes must equal its UTF-8 target length"
            )
        expected_hash = hashlib.sha256(target_bytes).hexdigest()
        validate_sha256(self.content_sha256, "content_sha256")
        if self.content_sha256 != expected_hash:
            raise ContractError(
                "symlink entry content_sha256 must hash its UTF-8 target"
            )

    def to_document(self) -> dict[str, object]:
        return {
            "relative_path": self.relative_path,
            "kind": self.kind.value,
            "mode": self.mode,
            "size_bytes": self.size_bytes,
            "content_sha256": self.content_sha256,
            "symlink_target": self.symlink_target,
        }

    @classmethod
    def from_document(cls, value: object) -> SnapshotManifestEntry:
        document = require_exact_keys(
            value,
            required=(
                "relative_path",
                "kind",
                "mode",
                "size_bytes",
                "content_sha256",
                "symlink_target",
            ),
            where="snapshot_manifest_entry",
        )
        return cls(
            relative_path=document["relative_path"],
            kind=_enum_value(
                SnapshotEntryKind,
                document["kind"],
                "snapshot_manifest_entry.kind",
            ),
            mode=document["mode"],
            size_bytes=document["size_bytes"],
            content_sha256=document["content_sha256"],
            symlink_target=document["symlink_target"],
        )


def _parent_paths(path: str) -> tuple[str, ...]:
    parts = path.split("/")
    return tuple("/".join(parts[:index]) for index in range(1, len(parts)))


def _collapse_rooted_parts(parts: list[str], link_path: str) -> list[str]:
    collapsed: list[str] = []
    for part in parts:
        if part in ("", "."):
            continue
        if part == "..":
            if not collapsed:
                raise ContractError(
                    f"symlink target escapes snapshot root: {link_path}"
                )
            collapsed.pop()
        else:
            collapsed.append(part)
    return collapsed


def _validate_symlink_within_root(link: SnapshotManifestEntry) -> None:
    """Reject only lexical root escape; never dereference a snapshot link.

    Dangling links, links to excluded/generated paths, and cycles are valid
    source bytes in many real projects.  They remain inert during capture and
    are recreated verbatim during materialization.
    """

    target = link.symlink_target
    if target is None:  # unreachable after entry validation
        raise ContractError(f"symlink has no target: {link.relative_path}")
    parent = link.relative_path.split("/")[:-1]
    _collapse_rooted_parts(parent + target.split("/"), link.relative_path)


@dataclass(frozen=True)
class SnapshotManifest:
    """Canonical, UTF-8-byte-ordered snapshot manifest."""

    entries: tuple[SnapshotManifestEntry, ...]

    def __post_init__(self) -> None:
        if type(self.entries) not in (tuple, list):
            raise ContractError("entries must be a collection")
        entries = tuple(self.entries)
        if len(entries) > _MAX_MANIFEST_ENTRIES:
            raise ContractError(
                f"entries must not contain more than {_MAX_MANIFEST_ENTRIES} values"
            )
        if any(type(entry) is not SnapshotManifestEntry for entry in entries):
            raise ContractError(
                "entries must contain only SnapshotManifestEntry values"
            )
        paths = tuple(entry.relative_path for entry in entries)
        if len(paths) != len(set(paths)):
            raise ContractError("entries must not repeat relative_path")
        ordered = tuple(
            sorted(entries, key=lambda entry: entry.relative_path.encode("utf-8"))
        )
        object.__setattr__(self, "entries", ordered)

        by_path = {entry.relative_path: entry for entry in ordered}
        for entry in ordered:
            for parent in _parent_paths(entry.relative_path):
                ancestor = by_path.get(parent)
                if ancestor is None:
                    raise ContractError(
                        "manifest must contain every directory parent: "
                        f"{parent}"
                    )
                if ancestor.kind is not SnapshotEntryKind.DIRECTORY:
                    raise ContractError(
                        "manifest path has a non-directory ancestor: "
                        f"{parent}"
                    )
        for entry in ordered:
            if entry.kind is SnapshotEntryKind.SYMLINK:
                _validate_symlink_within_root(entry)

    def to_document(self) -> dict[str, object]:
        return {
            "contract_kind": _SNAPSHOT_MANIFEST_CONTRACT_KIND,
            "schema_version": _SCHEMA_VERSION,
            "entries": [entry.to_document() for entry in self.entries],
        }

    @classmethod
    def from_document(cls, value: object) -> SnapshotManifest:
        document = require_exact_keys(
            value,
            required=("contract_kind", "schema_version", "entries"),
            where="snapshot_manifest",
        )
        if (
            type(document["contract_kind"]) is not str
            or document["contract_kind"] != _SNAPSHOT_MANIFEST_CONTRACT_KIND
        ):
            raise ContractError(
                "snapshot_manifest.contract_kind must be "
                "'source_snapshot_manifest'"
            )
        if (
            type(document["schema_version"]) is not int
            or document["schema_version"] != _SCHEMA_VERSION
        ):
            raise ContractError(
                "snapshot_manifest.schema_version must be integer 1"
            )
        raw_entries = document["entries"]
        if type(raw_entries) is not list:
            raise ContractError("snapshot_manifest.entries must be a list")
        return cls(
            entries=tuple(
                SnapshotManifestEntry.from_document(entry)
                for entry in raw_entries
            )
        )

    @classmethod
    def from_json(cls, payload: object) -> SnapshotManifest:
        return cls.from_document(load_strict_json_object(
            payload,
            max_bytes=MAX_SNAPSHOT_MANIFEST_BYTES,
        ))

    @property
    def canonical_bytes(self) -> bytes:
        return canonical_json_bytes(self.to_document())

    @property
    def content_sha256(self) -> str:
        return hashlib.sha256(self.canonical_bytes).hexdigest()

    @property
    def artifact_ref(self) -> ArtifactRef:
        return ArtifactRef(
            role=_MANIFEST_ROLE,
            media_type=_MANIFEST_MEDIA_TYPE,
            size_bytes=len(self.canonical_bytes),
            content_sha256=self.content_sha256,
        )


def _compute_snapshot_sha256(
    policy: ContractRef,
    manifest: ArtifactRef,
) -> str:
    return canonical_sha256(
        {
            "domain": _SNAPSHOT_ROOT_HASH_DOMAIN,
            "policy": policy.to_document(),
            "manifest": manifest.to_document(),
        }
    )


@dataclass(frozen=True)
class SnapshotRef:
    """Exact policy/manifest binding and domain-separated snapshot root."""

    policy: ContractRef
    manifest: ArtifactRef
    snapshot_sha256: str

    def __post_init__(self) -> None:
        if type(self.policy) is not ContractRef:
            raise ContractError("policy must be a ContractRef")
        if self.policy.kind is not ContractRefKind.SNAPSHOT_POLICY:
            raise ContractError("policy must reference snapshot_policy")
        if type(self.manifest) is not ArtifactRef:
            raise ContractError("manifest must be an ArtifactRef")
        if self.manifest.role != _MANIFEST_ROLE:
            raise ContractError(
                "manifest role must be 'source_snapshot_manifest'"
            )
        if self.manifest.media_type != _MANIFEST_MEDIA_TYPE:
            raise ContractError("manifest media_type must be 'application/json'")
        validate_sha256(self.snapshot_sha256, "snapshot_sha256")
        expected = _compute_snapshot_sha256(self.policy, self.manifest)
        if self.snapshot_sha256 != expected:
            raise ContractError(
                "snapshot_sha256 does not match the bound policy and manifest"
            )

    @classmethod
    def create(
        cls,
        policy_ref: ContractRef,
        manifest_ref: ArtifactRef,
    ) -> SnapshotRef:
        if type(policy_ref) is not ContractRef:
            raise ContractError("policy_ref must be a ContractRef")
        if policy_ref.kind is not ContractRefKind.SNAPSHOT_POLICY:
            raise ContractError("policy_ref must reference snapshot_policy")
        if type(manifest_ref) is not ArtifactRef:
            raise ContractError("manifest_ref must be an ArtifactRef")
        if manifest_ref.role != _MANIFEST_ROLE:
            raise ContractError(
                "manifest_ref role must be 'source_snapshot_manifest'"
            )
        if manifest_ref.media_type != _MANIFEST_MEDIA_TYPE:
            raise ContractError(
                "manifest_ref media_type must be 'application/json'"
            )
        return cls(
            policy=policy_ref,
            manifest=manifest_ref,
            snapshot_sha256=_compute_snapshot_sha256(policy_ref, manifest_ref),
        )

    def to_document(self) -> dict[str, object]:
        return {
            "contract_kind": _SNAPSHOT_REF_CONTRACT_KIND,
            "schema_version": _SCHEMA_VERSION,
            "policy": self.policy.to_document(),
            "manifest": self.manifest.to_document(),
            "snapshot_sha256": self.snapshot_sha256,
        }

    @classmethod
    def from_document(cls, value: object) -> SnapshotRef:
        document = require_exact_keys(
            value,
            required=(
                "contract_kind",
                "schema_version",
                "policy",
                "manifest",
                "snapshot_sha256",
            ),
            where="source_snapshot",
        )
        if (
            type(document["contract_kind"]) is not str
            or document["contract_kind"] != _SNAPSHOT_REF_CONTRACT_KIND
        ):
            raise ContractError(
                "source_snapshot.contract_kind must be 'source_snapshot'"
            )
        if (
            type(document["schema_version"]) is not int
            or document["schema_version"] != _SCHEMA_VERSION
        ):
            raise ContractError("source_snapshot.schema_version must be integer 1")
        try:
            policy = ContractRef.from_document(document["policy"])
        except ContractError as exc:
            raise ContractError(f"source_snapshot.policy: {exc}") from exc
        try:
            manifest = ArtifactRef.from_document(document["manifest"])
        except ContractError as exc:
            raise ContractError(f"source_snapshot.manifest: {exc}") from exc
        return cls(
            policy=policy,
            manifest=manifest,
            snapshot_sha256=document["snapshot_sha256"],
        )

    @classmethod
    def from_json(cls, payload: object) -> SnapshotRef:
        return cls.from_document(load_strict_json_object(
            payload,
            max_bytes=MAX_SNAPSHOT_REFERENCE_BYTES,
        ))


def generic_source_snapshot_policy_v1() -> SnapshotPolicy:
    """Return the harness-owned generic source policy described by the design."""

    return SnapshotPolicy(
        policy_id="fmagent.generic_source_snapshot",
        policy_version="1",
        include_paths=(),
        exclude_paths=(
            ".fm-validator-runtime",
            ".validation_runs",
            ".venv",
            "bug_validation",
            "build",
            "dist",
            "fm_agent",
            "log",
            "logs",
            "out",
            "target",
            "validation_runs",
            "venv",
        ),
        excluded_names=(
            ".aws",
            ".cache",
            ".credentials",
            ".env",
            ".git",
            ".hg",
            ".mypy_cache",
            ".omo",
            ".pytest_cache",
            ".ruff_cache",
            ".secrets",
            ".ssh",
            ".svn",
            "__pycache__",
            "cache",
            "credentials",
            "node_modules",
            "secrets",
        ),
        excluded_name_prefixes=(".env",),
        excluded_top_level_prefixes=(),
        symlink_policy=SymlinkPolicy.SAFE_RELATIVE,
        max_entries=250_000,
        max_file_bytes=1_073_741_824,
        max_total_bytes=17_179_869_184,
    )

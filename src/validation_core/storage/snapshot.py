"""Fail-closed immutable source snapshots backed by a local SHA-256 CAS.

The store is an authority-owned filesystem component.  It captures a live
project exactly once under a frozen :class:`SnapshotPolicy`, then all later
consumers resolve files through the content-addressed snapshot.  It never
uses Git metadata as a substitute for dirty source bytes and never follows a
source-tree symlink while collecting content.

The implementation deliberately uses byte copies for writable views.  A
future broker may substitute a *verified* copy-on-write primitive, but a
hardlink is never an acceptable materialization because it would let one role
mutate the CAS or another role's project.
"""

from __future__ import annotations

import errno
import ctypes
import fcntl
import hashlib
import os
import shutil
import stat
import tempfile
import threading
import unicodedata
import uuid
from contextlib import contextmanager
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import BinaryIO, Callable, Iterator

from ..contracts.base import (
    ContractError,
    canonical_json_bytes,
    canonical_sha256,
    load_strict_json_object,
    require_exact_keys,
    validate_sha256,
)
from ..contracts.snapshot import (
    MAX_SNAPSHOT_MANIFEST_BYTES,
    MAX_SNAPSHOT_PATH_COMPONENTS,
    MAX_SNAPSHOT_POLICY_BYTES,
    MAX_SNAPSHOT_REFERENCE_BYTES,
    SnapshotEntryKind,
    SnapshotManifest,
    SnapshotManifestEntry,
    SnapshotPolicy,
    SnapshotRef,
    SymlinkPolicy,
)


_CHUNK_SIZE = 1024 * 1024
_MAX_POLICY_BYTES = MAX_SNAPSHOT_POLICY_BYTES
_MAX_MANIFEST_BYTES = MAX_SNAPSHOT_MANIFEST_BYTES
_MAX_REFERENCE_BYTES = MAX_SNAPSHOT_REFERENCE_BYTES
_EMPTY_SHA256 = hashlib.sha256(b"").hexdigest()
_MATERIALIZER_VERSION = "copy-v1"
# Role workspaces wrap the project below a small fixed namespace layout.
_MAX_CLEANUP_DEPTH = MAX_SNAPSHOT_PATH_COMPONENTS + 8

_O_CLOEXEC = getattr(os, "O_CLOEXEC", 0)
_O_DIRECTORY = getattr(os, "O_DIRECTORY", 0)
_O_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
_O_PATH = getattr(os, "O_PATH", 0)
_O_NONBLOCK = getattr(os, "O_NONBLOCK", 0)
if not _O_DIRECTORY or not _O_NOFOLLOW or not _O_PATH:  # pragma: no cover
    raise RuntimeError("SnapshotStore requires Linux O_PATH/O_DIRECTORY/O_NOFOLLOW")

try:  # Linux baseline: publish without ever replacing an addressed object.
    _RENAMEAT2 = ctypes.CDLL(None, use_errno=True).renameat2
except AttributeError as exc:  # pragma: no cover - unsupported libc
    raise RuntimeError("SnapshotStore requires Linux renameat2") from exc
_RENAMEAT2.argtypes = (
    ctypes.c_int,
    ctypes.c_char_p,
    ctypes.c_int,
    ctypes.c_char_p,
    ctypes.c_uint,
)
_RENAMEAT2.restype = ctypes.c_int
_RENAME_NOREPLACE = 1


class SnapshotErrorCode(str, Enum):
    INVALID_STORE = "INVALID_STORE"
    INVALID_SOURCE = "INVALID_SOURCE"
    UNSAFE_SOURCE_ENTRY = "UNSAFE_SOURCE_ENTRY"
    SOURCE_CHANGED = "SOURCE_CHANGED"
    POLICY_LIMIT_EXCEEDED = "POLICY_LIMIT_EXCEEDED"
    SNAPSHOT_NOT_FOUND = "SNAPSHOT_NOT_FOUND"
    CAS_OBJECT_CONFLICT = "CAS_OBJECT_CONFLICT"
    INTEGRITY_FAILURE = "INTEGRITY_FAILURE"
    INVALID_DESTINATION = "INVALID_DESTINATION"
    MATERIALIZATION_FAILED = "MATERIALIZATION_FAILED"
    CLEANUP_FAILED = "CLEANUP_FAILED"


class SnapshotStoreError(RuntimeError):
    """A typed, fail-closed snapshot storage failure."""

    def __init__(self, code: SnapshotErrorCode, message: str) -> None:
        if type(code) is not SnapshotErrorCode:
            raise TypeError("code must be a SnapshotErrorCode")
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class StoredSnapshot:
    """One fully resolved immutable source snapshot."""

    ref: SnapshotRef
    policy: SnapshotPolicy
    manifest: SnapshotManifest

    def __post_init__(self) -> None:
        if type(self.ref) is not SnapshotRef:
            raise TypeError("ref must be a SnapshotRef")
        if type(self.policy) is not SnapshotPolicy:
            raise TypeError("policy must be a SnapshotPolicy")
        if type(self.manifest) is not SnapshotManifest:
            raise TypeError("manifest must be a SnapshotManifest")
        if self.ref.policy != self.policy.ref:
            raise ValueError("snapshot policy does not match its reference")
        if self.ref.manifest != self.manifest.artifact_ref:
            raise ValueError("snapshot manifest does not match its reference")
        try:
            self.policy.validate_manifest(self.manifest)
        except ContractError as exc:
            raise ValueError(
                f"snapshot manifest violates its frozen policy: {exc}"
            ) from exc


@dataclass(frozen=True)
class SnapshotMaterializationProof:
    """Path-free proof that one fresh tree was copied and fully rechecked."""

    materialization_id: str
    snapshot_sha256: str
    policy_sha256: str
    manifest_sha256: str
    entry_count: int
    total_file_bytes: int
    materializer_version: str = _MATERIALIZER_VERSION

    def __post_init__(self) -> None:
        if (
            type(self.materialization_id) is not str
            or len(self.materialization_id) != 32
            or any(char not in "0123456789abcdef" for char in self.materialization_id)
        ):
            raise ValueError("materialization_id must be 32 lowercase hex characters")
        validate_sha256(self.snapshot_sha256, "snapshot_sha256")
        validate_sha256(self.policy_sha256, "policy_sha256")
        validate_sha256(self.manifest_sha256, "manifest_sha256")
        if type(self.entry_count) is not int or self.entry_count < 0:
            raise ValueError("entry_count must be a non-negative integer")
        if type(self.total_file_bytes) is not int or self.total_file_bytes < 0:
            raise ValueError("total_file_bytes must be a non-negative integer")
        if self.materializer_version != _MATERIALIZER_VERSION:
            raise ValueError("unsupported materializer_version")

    def to_document(self) -> dict[str, object]:
        return {
            "contract_kind": "snapshot_materialization_proof",
            "schema_version": 1,
            "materialization_id": self.materialization_id,
            "snapshot_sha256": self.snapshot_sha256,
            "policy_sha256": self.policy_sha256,
            "manifest_sha256": self.manifest_sha256,
            "entry_count": self.entry_count,
            "total_file_bytes": self.total_file_bytes,
            "materializer_version": self.materializer_version,
        }

    @classmethod
    def from_document(cls, value: object) -> SnapshotMaterializationProof:
        document = require_exact_keys(
            value,
            required=(
                "contract_kind",
                "schema_version",
                "materialization_id",
                "snapshot_sha256",
                "policy_sha256",
                "manifest_sha256",
                "entry_count",
                "total_file_bytes",
                "materializer_version",
            ),
            where="snapshot materialization proof",
        )
        if document["contract_kind"] != "snapshot_materialization_proof":
            raise ContractError(
                "snapshot materialization proof contract_kind must be "
                "'snapshot_materialization_proof'"
            )
        if (
            type(document["schema_version"]) is not int
            or document["schema_version"] != 1
        ):
            raise ContractError(
                "snapshot materialization proof schema_version must be integer 1"
            )
        try:
            return cls(
                materialization_id=document["materialization_id"],
                snapshot_sha256=document["snapshot_sha256"],
                policy_sha256=document["policy_sha256"],
                manifest_sha256=document["manifest_sha256"],
                entry_count=document["entry_count"],
                total_file_bytes=document["total_file_bytes"],
                materializer_version=document["materializer_version"],
            )
        except (ContractError, TypeError, ValueError) as exc:
            raise ContractError(
                f"invalid snapshot materialization proof: {exc}"
            ) from exc

    @classmethod
    def from_json(cls, payload: object) -> SnapshotMaterializationProof:
        return cls.from_document(load_strict_json_object(
            payload,
            max_bytes=MAX_SNAPSHOT_REFERENCE_BYTES,
        ))

    @property
    def content_sha256(self) -> str:
        return canonical_sha256(self.to_document())


@dataclass(frozen=True)
class MaterializedSnapshot:
    """Host-local path paired with its path-free integrity proof."""

    destination: Path
    proof: SnapshotMaterializationProof

    def __post_init__(self) -> None:
        if not isinstance(self.destination, Path) or not self.destination.is_absolute():
            raise TypeError("destination must be an absolute pathlib.Path")
        if type(self.proof) is not SnapshotMaterializationProof:
            raise TypeError("proof must be a SnapshotMaterializationProof")


@dataclass
class _CapturedTree:
    entries: tuple[SnapshotManifestEntry, ...]
    staged_blobs: dict[str, Path]
    total_file_bytes: int


_THREAD_LOCKS_GUARD = threading.Lock()
_THREAD_LOCKS: dict[str, threading.RLock] = {}


def _thread_lock_for(root: Path) -> threading.RLock:
    key = os.fspath(root)
    with _THREAD_LOCKS_GUARD:
        return _THREAD_LOCKS.setdefault(key, threading.RLock())


def _raise(code: SnapshotErrorCode, message: str, cause: BaseException | None = None):
    error = SnapshotStoreError(code, message)
    if cause is None:
        raise error
    raise error from cause


def _mode(metadata: os.stat_result) -> int:
    return stat.S_IMODE(metadata.st_mode)


def _metadata_signature(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_nlink,
        metadata.st_uid,
        metadata.st_gid,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _parent_protects_directory_entry(metadata: os.stat_result) -> bool:
    """Return whether mode/ownership prevents another uid replacing a child."""

    if not stat.S_ISDIR(metadata.st_mode):
        return False
    mode = _mode(metadata)
    if metadata.st_uid == os.geteuid() and not mode & 0o022:
        return True
    return bool(
        mode & stat.S_ISVTX
        and metadata.st_uid in (0, os.geteuid())
    )


def _mount_id(descriptor: int, relative_path: str) -> int:
    """Return Linux's mount identity for an already-open filesystem object."""

    fdinfo = Path("/proc/self/fdinfo") / str(descriptor)
    try:
        payload = fdinfo.read_text(encoding="ascii")
    except (OSError, UnicodeError) as exc:
        _raise(
            SnapshotErrorCode.UNSAFE_SOURCE_ENTRY,
            f"cannot establish mount identity for {relative_path}",
            exc,
        )
    for line in payload.splitlines():
        if line.startswith("mnt_id:"):
            value = line.partition(":")[2].strip()
            try:
                mount_id = int(value, 10)
            except ValueError as exc:
                _raise(
                    SnapshotErrorCode.UNSAFE_SOURCE_ENTRY,
                    f"invalid mount identity for {relative_path}",
                    exc,
                )
            if mount_id < 1:
                _raise(
                    SnapshotErrorCode.UNSAFE_SOURCE_ENTRY,
                    f"invalid mount identity for {relative_path}",
                )
            return mount_id
    _raise(
        SnapshotErrorCode.UNSAFE_SOURCE_ENTRY,
        f"mount identity is unavailable for {relative_path}",
    )


def _require_single_mount_tree(root: Path) -> None:
    """Preflight a private tree before recursive deletion.

    ``shutil.rmtree`` is symlink-safe on the supported Linux runtime, but it
    will recurse through a directory mount.  Workspaces are owner-only and a
    later OS broker must deny mount mutations; this no-follow fd walk adds the
    fail-closed cleanup boundary for any mount already present.
    """

    descriptor = parent_descriptor = path_descriptor = -1
    try:
        parent_descriptor = os.open(
            root.parent,
            os.O_RDONLY | _O_CLOEXEC | _O_DIRECTORY | _O_NOFOLLOW,
        )
        parent_metadata = os.fstat(parent_descriptor)
        parent_mount_id = _mount_id(parent_descriptor, "..")
        path_descriptor = os.open(
            root,
            _O_PATH | _O_CLOEXEC | _O_DIRECTORY | _O_NOFOLLOW,
        )
        root_metadata = os.fstat(path_descriptor)
        root_identity = (root_metadata.st_dev, root_metadata.st_ino)
        root_mount_id = _mount_id(path_descriptor, ".")
        if (
            root_metadata.st_dev != parent_metadata.st_dev
            or root_mount_id != parent_mount_id
        ):
            raise OSError("cleanup root crosses its parent mount boundary")
        if root_metadata.st_uid != os.geteuid():
            raise OSError("cleanup root is not owned by the current authority")
        if _mode(root_metadata) & 0o700 != 0o700:
            os.chmod(root, _mode(root_metadata) | 0o700, follow_symlinks=False)
            current = os.fstat(path_descriptor)
            if (current.st_dev, current.st_ino) != root_identity:
                raise OSError("cleanup root changed while restoring permissions")
        descriptor = os.open(
            root,
            os.O_RDONLY | _O_CLOEXEC | _O_DIRECTORY | _O_NOFOLLOW,
        )
        current_root = os.fstat(descriptor)
        if (
            (current_root.st_dev, current_root.st_ino) != root_identity
            or _mount_id(descriptor, ".") != root_mount_id
        ):
            raise OSError("cleanup root changed before traversal")
        os.close(path_descriptor)
        path_descriptor = -1
        os.close(parent_descriptor)
        parent_descriptor = -1

        def visit(current_fd: int, relative: str, depth: int) -> None:
            if depth > _MAX_CLEANUP_DEPTH:
                raise OSError("cleanup tree exceeds the safe directory depth")
            before = os.fstat(current_fd)
            with os.scandir(current_fd) as entries:
                for item in entries:
                    metadata = os.stat(
                        item.name,
                        dir_fd=current_fd,
                        follow_symlinks=False,
                    )
                    if not stat.S_ISDIR(metadata.st_mode):
                        continue
                    child_fd = child_path_fd = -1
                    child_relative = (
                        item.name if relative == "." else f"{relative}/{item.name}"
                    )
                    try:
                        child_path_fd = os.open(
                            item.name,
                            _O_PATH | _O_CLOEXEC | _O_DIRECTORY | _O_NOFOLLOW,
                            dir_fd=current_fd,
                        )
                        current = os.fstat(child_path_fd)
                        if _metadata_signature(metadata) != _metadata_signature(current):
                            raise OSError(
                                f"cleanup tree changed at {child_relative}"
                            )
                        if (
                            current.st_dev != root_metadata.st_dev
                            or _mount_id(child_path_fd, child_relative)
                            != root_mount_id
                        ):
                            raise OSError(
                                f"cleanup refuses nested mount at {child_relative}"
                            )
                        if current.st_uid != os.geteuid():
                            raise OSError(
                                "cleanup directory is not authority-owned: "
                                f"{child_relative}"
                            )
                        child_identity = (current.st_dev, current.st_ino)
                        if _mode(current) & 0o700 != 0o700:
                            os.chmod(
                                item.name,
                                _mode(current) | 0o700,
                                dir_fd=current_fd,
                                follow_symlinks=False,
                            )
                            current = os.fstat(child_path_fd)
                            if (current.st_dev, current.st_ino) != child_identity:
                                raise OSError(
                                    "cleanup directory changed while restoring "
                                    f"permissions: {child_relative}"
                                )
                        child_fd = os.open(
                            item.name,
                            os.O_RDONLY
                            | _O_CLOEXEC
                            | _O_DIRECTORY
                            | _O_NOFOLLOW,
                            dir_fd=current_fd,
                        )
                        opened = os.fstat(child_fd)
                        if (
                            (opened.st_dev, opened.st_ino) != child_identity
                            or _mount_id(child_fd, child_relative) != root_mount_id
                        ):
                            raise OSError(
                                "cleanup directory changed before traversal: "
                                f"{child_relative}"
                            )
                        os.close(child_path_fd)
                        child_path_fd = -1
                        visit(child_fd, child_relative, depth + 1)
                    finally:
                        if child_fd >= 0:
                            os.close(child_fd)
                        if child_path_fd >= 0:
                            os.close(child_path_fd)
            after = os.fstat(current_fd)
            if _metadata_signature(before) != _metadata_signature(after):
                raise OSError(f"cleanup tree changed at {relative}")

        visit(descriptor, ".", 0)
    except SnapshotStoreError as exc:
        raise OSError(f"cannot establish cleanup mount boundary: {exc}") from exc
    except RecursionError as exc:
        raise OSError("cleanup tree exceeds the safe recursion depth") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if path_descriptor >= 0:
            os.close(path_descriptor)
        if parent_descriptor >= 0:
            os.close(parent_descriptor)


def _require_stable(
    before: os.stat_result,
    after: os.stat_result,
    relative_path: str,
) -> None:
    if _metadata_signature(before) != _metadata_signature(after):
        _raise(
            SnapshotErrorCode.SOURCE_CHANGED,
            f"source entry changed while snapshotting: {relative_path}",
        )


def _validate_name(name: str, parent: tuple[str, ...]) -> str:
    relative = "/".join((*parent, name))
    if len(parent) + 1 > MAX_SNAPSHOT_PATH_COMPONENTS:
        _raise(
            SnapshotErrorCode.UNSAFE_SOURCE_ENTRY,
            "source tree exceeds the safe directory depth",
        )
    if (
        not name
        or name in (".", "..")
        or "/" in name
        or "\\" in name
        or ":" in name
        or unicodedata.normalize("NFC", name) != name
    ):
        _raise(
            SnapshotErrorCode.UNSAFE_SOURCE_ENTRY,
            f"source contains a non-canonical path: {relative!r}",
        )
    try:
        encoded = relative.encode("utf-8", errors="strict")
    except UnicodeEncodeError as exc:
        _raise(
            SnapshotErrorCode.UNSAFE_SOURCE_ENTRY,
            f"source path is not canonical UTF-8: {relative!r}",
            exc,
        )
    if len(encoded) > 4096 or any(ord(char) < 32 or ord(char) == 127 for char in name):
        _raise(
            SnapshotErrorCode.UNSAFE_SOURCE_ENTRY,
            f"source path is unsafe or too long: {relative!r}",
        )
    return relative


def _is_path_prefix(prefix: str, path: str) -> bool:
    return path == prefix or path.startswith(prefix + "/")


def _policy_selection(
    policy: SnapshotPolicy | None,
    relative_path: str,
) -> tuple[bool, bool]:
    """Return ``(capture, may_descend)`` under deterministic prefix rules."""

    if policy is None:
        return True, True
    parts = relative_path.split("/")
    if any(name in policy.excluded_names for name in parts):
        return False, False
    if any(
        name.startswith(prefix)
        for name in parts
        for prefix in policy.excluded_name_prefixes
    ):
        return False, False
    if any(parts[0].startswith(prefix) for prefix in policy.excluded_top_level_prefixes):
        return False, False
    if any(_is_path_prefix(excluded, relative_path) for excluded in policy.exclude_paths):
        return False, False
    if not policy.include_paths:
        return True, True
    capture = any(
        _is_path_prefix(included, relative_path)
        or _is_path_prefix(relative_path, included)
        for included in policy.include_paths
    )
    descend = any(
        _is_path_prefix(included, relative_path)
        or _is_path_prefix(relative_path, included)
        for included in policy.include_paths
    )
    return capture, descend


def _open_source_root(source: Path) -> tuple[int, os.stat_result]:
    descriptor = -1
    try:
        path_metadata = os.lstat(source)
        if stat.S_ISLNK(path_metadata.st_mode) or not stat.S_ISDIR(path_metadata.st_mode):
            _raise(
                SnapshotErrorCode.INVALID_SOURCE,
                "source root must be a real directory, not a symlink",
            )
        resolved = source.resolve(strict=True)
        if resolved != source:
            _raise(
                SnapshotErrorCode.INVALID_SOURCE,
                "source root must be an absolute canonical path",
            )
        descriptor = os.open(
            source,
            os.O_RDONLY | _O_CLOEXEC | _O_DIRECTORY | _O_NOFOLLOW,
        )
        descriptor_metadata = os.fstat(descriptor)
        _require_stable(path_metadata, descriptor_metadata, ".")
        result = descriptor
        descriptor = -1
        return result, descriptor_metadata
    except SnapshotStoreError:
        raise
    except OSError as exc:
        _raise(
            SnapshotErrorCode.INVALID_SOURCE,
            f"cannot safely open source root {source}: {exc}",
            exc,
        )
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _open_child_directory(
    parent_fd: int,
    name: str,
    expected: os.stat_result,
    relative_path: str,
    root_device: int,
    root_mount_id: int,
) -> int:
    descriptor = -1
    try:
        descriptor = os.open(
            name,
            os.O_RDONLY | _O_CLOEXEC | _O_DIRECTORY | _O_NOFOLLOW,
            dir_fd=parent_fd,
        )
        current = os.fstat(descriptor)
        _require_stable(expected, current, relative_path)
        if current.st_dev != root_device:
            _raise(
                SnapshotErrorCode.UNSAFE_SOURCE_ENTRY,
                f"source entry crosses a mount boundary: {relative_path}",
            )
        if _mount_id(descriptor, relative_path) != root_mount_id:
            _raise(
                SnapshotErrorCode.UNSAFE_SOURCE_ENTRY,
                f"source entry crosses a bind-mount boundary: {relative_path}",
            )
        result = descriptor
        descriptor = -1
        return result
    except SnapshotStoreError:
        raise
    except OSError as exc:
        _raise(
            SnapshotErrorCode.SOURCE_CHANGED,
            f"source directory became unsafe while snapshotting: {relative_path}",
            exc,
        )
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _hash_open_file(
    descriptor: int,
    *,
    expected: os.stat_result,
    relative_path: str,
    maximum: int,
    output: BinaryIO | None,
) -> tuple[int, str]:
    digest = hashlib.sha256()
    size = 0
    try:
        initial = os.fstat(descriptor)
        _require_stable(expected, initial, relative_path)
        while True:
            chunk = os.read(descriptor, _CHUNK_SIZE)
            if not chunk:
                break
            size += len(chunk)
            if size > maximum:
                _raise(
                    SnapshotErrorCode.POLICY_LIMIT_EXCEEDED,
                    f"source file exceeds policy size limit: {relative_path}",
                )
            digest.update(chunk)
            if output is not None:
                output.write(chunk)
        final = os.fstat(descriptor)
        _require_stable(initial, final, relative_path)
        if size != initial.st_size:
            _raise(
                SnapshotErrorCode.SOURCE_CHANGED,
                f"source file size changed while snapshotting: {relative_path}",
            )
        return size, digest.hexdigest()
    except SnapshotStoreError:
        raise
    except OSError as exc:
        _raise(
            SnapshotErrorCode.SOURCE_CHANGED,
            f"source file changed while snapshotting: {relative_path}",
            exc,
        )


def _capture_regular_file(
    *,
    parent_fd: int,
    name: str,
    expected: os.stat_result,
    relative_path: str,
    maximum: int,
    staging_directory: Path | None,
    root_mount_id: int,
) -> tuple[int, str, Path | None]:
    descriptor = -1
    temporary_path: Path | None = None
    output: BinaryIO | None = None
    try:
        descriptor = os.open(
            name,
            os.O_RDONLY | _O_CLOEXEC | _O_NOFOLLOW | _O_NONBLOCK,
            dir_fd=parent_fd,
        )
        if _mount_id(descriptor, relative_path) != root_mount_id:
            _raise(
                SnapshotErrorCode.UNSAFE_SOURCE_ENTRY,
                f"source file crosses a bind-mount boundary: {relative_path}",
            )
        if staging_directory is not None:
            temporary_path = staging_directory / f"blob-{uuid.uuid4().hex}.tmp"
            output = open(temporary_path, "xb", buffering=0)
        size, digest = _hash_open_file(
            descriptor,
            expected=expected,
            relative_path=relative_path,
            maximum=maximum,
            output=output,
        )
        if output is not None:
            output.flush()
            os.fsync(output.fileno())
        return size, digest, temporary_path
    except SnapshotStoreError:
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)
        raise
    except OSError as exc:
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)
        _raise(
            SnapshotErrorCode.SOURCE_CHANGED,
            f"source file became unsafe while snapshotting: {relative_path}",
            exc,
        )
    finally:
        if output is not None:
            output.close()
        if descriptor >= 0:
            os.close(descriptor)


def _read_symlink(
    parent_fd: int,
    name: str,
    expected: os.stat_result,
    relative_path: str,
) -> tuple[int, str, str]:
    try:
        target = os.readlink(name, dir_fd=parent_fd)
        current = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        _require_stable(expected, current, relative_path)
        if type(target) is not str or unicodedata.normalize("NFC", target) != target:
            _raise(
                SnapshotErrorCode.UNSAFE_SOURCE_ENTRY,
                f"symlink target is not canonical Unicode: {relative_path}",
            )
        encoded = target.encode("utf-8", errors="strict")
        return len(encoded), hashlib.sha256(encoded).hexdigest(), target
    except SnapshotStoreError:
        raise
    except (OSError, UnicodeError) as exc:
        _raise(
            SnapshotErrorCode.SOURCE_CHANGED,
            f"symlink changed while snapshotting: {relative_path}",
            exc,
        )


def _scan_tree(
    *,
    root_fd: int,
    root_metadata: os.stat_result,
    policy: SnapshotPolicy | None,
    staging_directory: Path | None,
    reject_hardlinks: bool,
) -> _CapturedTree:
    entries: list[SnapshotManifestEntry] = []
    staged: dict[str, Path] = {}
    total_file_bytes = 0
    total_payload_bytes = 0
    maximum_file_bytes = policy.max_file_bytes if policy is not None else 2**63 - 1
    maximum_total_bytes = policy.max_total_bytes if policy is not None else 2**63 - 1
    maximum_entries = policy.max_entries if policy is not None else 1_000_000
    root_mount_id = _mount_id(root_fd, ".")
    source_hardlinks: dict[tuple[int, int], tuple[int, int, str]] = {}
    scanned_entries = 0

    def append(entry: SnapshotManifestEntry) -> None:
        if len(entries) >= maximum_entries:
            _raise(
                SnapshotErrorCode.POLICY_LIMIT_EXCEEDED,
                f"source tree exceeds the policy limit of {maximum_entries} entries",
            )
        entries.append(entry)

    def walk(directory_fd: int, parent: tuple[str, ...]) -> None:
        nonlocal scanned_entries, total_file_bytes, total_payload_bytes
        before = os.fstat(directory_fd)
        try:
            directory_entries = []
            with os.scandir(directory_fd) as iterator:
                for item in iterator:
                    scanned_entries += 1
                    if scanned_entries > maximum_entries:
                        _raise(
                            SnapshotErrorCode.POLICY_LIMIT_EXCEEDED,
                            "source traversal exceeds snapshot policy max_entries "
                            "including excluded entries",
                        )
                    directory_entries.append(item)
        except OSError as exc:
            _raise(
                SnapshotErrorCode.SOURCE_CHANGED,
                f"source directory is not stable: {'/'.join(parent) or '.'}",
                exc,
            )
        directory_entries.sort(key=lambda item: item.name.encode("utf-8", "surrogatepass"))
        seen_names: set[str] = set()
        for item in directory_entries:
            name = item.name
            relative_path = _validate_name(name, parent)
            if name in seen_names:
                _raise(
                    SnapshotErrorCode.UNSAFE_SOURCE_ENTRY,
                    f"source contains duplicate canonical name: {relative_path}",
                )
            seen_names.add(name)
            capture, may_descend = _policy_selection(policy, relative_path)
            if not capture and not may_descend:
                continue
            try:
                metadata = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
            except OSError as exc:
                _raise(
                    SnapshotErrorCode.SOURCE_CHANGED,
                    f"source entry disappeared while snapshotting: {relative_path}",
                    exc,
                )
            mode = _mode(metadata)
            if mode & 0o7000:
                _raise(
                    SnapshotErrorCode.UNSAFE_SOURCE_ENTRY,
                    f"source entry has privileged mode bits: {relative_path}",
                )
            if stat.S_ISDIR(metadata.st_mode):
                descriptor = _open_child_directory(
                    directory_fd,
                    name,
                    metadata,
                    relative_path,
                    root_metadata.st_dev,
                    root_mount_id,
                )
                try:
                    if capture:
                        append(SnapshotManifestEntry(
                            relative_path=relative_path,
                            kind=SnapshotEntryKind.DIRECTORY,
                            mode=mode,
                            size_bytes=0,
                            content_sha256=_EMPTY_SHA256,
                            symlink_target=None,
                        ))
                    if may_descend:
                        walk(descriptor, (*parent, name))
                    _require_stable(metadata, os.fstat(descriptor), relative_path)
                finally:
                    os.close(descriptor)
            elif stat.S_ISREG(metadata.st_mode):
                if not capture:
                    continue
                if metadata.st_dev != root_metadata.st_dev:
                    _raise(
                        SnapshotErrorCode.UNSAFE_SOURCE_ENTRY,
                        f"source file crosses a mount boundary: {relative_path}",
                    )
                if reject_hardlinks and metadata.st_nlink != 1:
                    _raise(
                        SnapshotErrorCode.INTEGRITY_FAILURE,
                        f"materialized file is hard-linked: {relative_path}",
                    )
                if not reject_hardlinks:
                    inode = (metadata.st_dev, metadata.st_ino)
                    previous = source_hardlinks.get(inode)
                    if previous is None:
                        source_hardlinks[inode] = (
                            metadata.st_nlink,
                            1,
                            relative_path,
                        )
                    else:
                        expected_links, count, first_path = previous
                        if expected_links != metadata.st_nlink:
                            _raise(
                                SnapshotErrorCode.SOURCE_CHANGED,
                                f"hardlink count changed while snapshotting: {relative_path}",
                            )
                        source_hardlinks[inode] = (
                            expected_links,
                            count + 1,
                            first_path,
                        )
                size, digest, temporary = _capture_regular_file(
                    parent_fd=directory_fd,
                    name=name,
                    expected=metadata,
                    relative_path=relative_path,
                    maximum=maximum_file_bytes,
                    staging_directory=staging_directory,
                    root_mount_id=root_mount_id,
                )
                total_file_bytes += size
                total_payload_bytes += size
                if total_payload_bytes > maximum_total_bytes:
                    if temporary is not None:
                        temporary.unlink(missing_ok=True)
                    _raise(
                        SnapshotErrorCode.POLICY_LIMIT_EXCEEDED,
                        "source tree exceeds the policy total-byte limit",
                    )
                if temporary is not None:
                    previous = staged.get(digest)
                    if previous is None:
                        staged[digest] = temporary
                    else:
                        temporary.unlink(missing_ok=True)
                append(SnapshotManifestEntry(
                    relative_path=relative_path,
                    kind=SnapshotEntryKind.FILE,
                    mode=mode,
                    size_bytes=size,
                    content_sha256=digest,
                    symlink_target=None,
                ))
            elif stat.S_ISLNK(metadata.st_mode):
                if not capture:
                    continue
                if policy is not None and policy.symlink_policy is SymlinkPolicy.REJECT_ALL:
                    _raise(
                        SnapshotErrorCode.UNSAFE_SOURCE_ENTRY,
                        f"snapshot policy rejects symlinks: {relative_path}",
                    )
                size, digest, target = _read_symlink(
                    directory_fd, name, metadata, relative_path,
                )
                total_payload_bytes += size
                if total_payload_bytes > maximum_total_bytes:
                    _raise(
                        SnapshotErrorCode.POLICY_LIMIT_EXCEEDED,
                        "source tree exceeds the policy total-byte limit",
                    )
                append(SnapshotManifestEntry(
                    relative_path=relative_path,
                    kind=SnapshotEntryKind.SYMLINK,
                    mode=mode,
                    size_bytes=size,
                    content_sha256=digest,
                    symlink_target=target,
                ))
            else:
                _raise(
                    SnapshotErrorCode.UNSAFE_SOURCE_ENTRY,
                    f"source contains a socket, device, FIFO, or special entry: {relative_path}",
                )
        _require_stable(before, os.fstat(directory_fd), "/".join(parent) or ".")

    try:
        walk(root_fd, ())
    except RecursionError as exc:
        _raise(
            SnapshotErrorCode.UNSAFE_SOURCE_ENTRY,
            "source tree nesting exceeds the safe traversal depth",
            exc,
        )
    _require_stable(root_metadata, os.fstat(root_fd), ".")
    if not reject_hardlinks:
        for expected_links, captured_links, first_path in source_hardlinks.values():
            if expected_links != captured_links:
                _raise(
                    SnapshotErrorCode.UNSAFE_SOURCE_ENTRY,
                    "source hardlink escapes or enters an excluded path: "
                    f"{first_path}",
                )
    entries.sort(key=lambda entry: entry.relative_path.encode("utf-8"))
    try:
        manifest = SnapshotManifest(entries=tuple(entries))
    except (ContractError, ValueError) as exc:
        _raise(
            SnapshotErrorCode.UNSAFE_SOURCE_ENTRY,
            f"source tree cannot form a safe canonical manifest: {exc}",
            exc,
        )
    return _CapturedTree(manifest.entries, staged, total_file_bytes)


def _write_staged_payload(directory: Path, prefix: str, payload: bytes) -> Path:
    path = directory / f"{prefix}-{uuid.uuid4().hex}.tmp"
    descriptor = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | _O_CLOEXEC | _O_NOFOLLOW,
        0o600,
    )
    try:
        view = memoryview(payload)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:  # defensive; os.write should raise instead
                raise OSError("short write while staging CAS payload")
            view = view[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    return path


def _hash_file_descriptor(descriptor: int, maximum: int) -> tuple[int, str]:
    digest = hashlib.sha256()
    size = 0
    while True:
        chunk = os.read(descriptor, _CHUNK_SIZE)
        if not chunk:
            break
        size += len(chunk)
        if size > maximum:
            _raise(
                SnapshotErrorCode.INTEGRITY_FAILURE,
                "CAS object exceeds its declared size bound",
            )
        digest.update(chunk)
    return size, digest.hexdigest()


def _freeze_staged_payload(
    path: Path,
    *,
    expected_sha256: str,
    expected_size: int,
) -> tuple[int, int]:
    """Verify, chmod, and durably freeze one private staged regular file."""

    descriptor = -1
    try:
        descriptor = os.open(
            path,
            os.O_RDONLY | _O_CLOEXEC | _O_NOFOLLOW | _O_NONBLOCK,
        )
        initial = os.fstat(descriptor)
        if (
            not stat.S_ISREG(initial.st_mode)
            or initial.st_nlink != 1
            or initial.st_uid != os.geteuid()
        ):
            _raise(
                SnapshotErrorCode.CAS_OBJECT_CONFLICT,
                "staged CAS content is not a private regular file",
            )
        actual_size, actual_digest = _hash_file_descriptor(
            descriptor,
            expected_size,
        )
        before_freeze = os.fstat(descriptor)
        if _metadata_signature(initial) != _metadata_signature(before_freeze):
            _raise(
                SnapshotErrorCode.CAS_OBJECT_CONFLICT,
                "staged CAS content changed while being verified",
            )
        if actual_size != expected_size or actual_digest != expected_sha256:
            _raise(
                SnapshotErrorCode.CAS_OBJECT_CONFLICT,
                "staged CAS content does not match its address",
            )
        os.fchmod(descriptor, 0o444)
        os.fsync(descriptor)
        frozen = os.fstat(descriptor)
        if (
            not stat.S_ISREG(frozen.st_mode)
            or frozen.st_nlink != 1
            or frozen.st_uid != os.geteuid()
            or _mode(frozen) != 0o444
            or (frozen.st_dev, frozen.st_ino) != (initial.st_dev, initial.st_ino)
        ):
            _raise(
                SnapshotErrorCode.CAS_OBJECT_CONFLICT,
                "staged CAS content could not be frozen safely",
            )
        return frozen.st_dev, frozen.st_ino
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | _O_CLOEXEC | _O_DIRECTORY | _O_NOFOLLOW)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _rename_noreplace(source: Path, destination: Path) -> None:
    """Atomically publish one direct child without clobbering an incumbent.

    Native Linux filesystems use ``renameat2(RENAME_NOREPLACE)``.  Filesystems
    such as WSL drvfs may reject that flag; there we use link-at-no-replace and
    durably unlink the staging alias.  If a producer dies in that short window,
    lock-held stale-staging recovery removes the alias before any CAS read.
    """

    source_directory_fd = destination_directory_fd = -1
    try:
        source_directory_fd = os.open(
            source.parent,
            os.O_RDONLY | _O_CLOEXEC | _O_DIRECTORY | _O_NOFOLLOW,
        )
        destination_directory_fd = os.open(
            destination.parent,
            os.O_RDONLY | _O_CLOEXEC | _O_DIRECTORY | _O_NOFOLLOW,
        )
        ctypes.set_errno(0)
        result = _RENAMEAT2(
            source_directory_fd,
            os.fsencode(source.name),
            destination_directory_fd,
            os.fsencode(destination.name),
            _RENAME_NOREPLACE,
        )
        if result == 0:
            return
        error_number = ctypes.get_errno()
        unsupported = {
            errno.EINVAL,
            errno.ENOSYS,
            getattr(errno, "EOPNOTSUPP", errno.EINVAL),
            getattr(errno, "ENOTSUP", errno.EINVAL),
        }
        if error_number not in unsupported:
            raise OSError(error_number, os.strerror(error_number))
        os.link(
            source.name,
            destination.name,
            src_dir_fd=source_directory_fd,
            dst_dir_fd=destination_directory_fd,
            follow_symlinks=False,
        )
        os.fsync(destination_directory_fd)
        os.unlink(source.name, dir_fd=source_directory_fd)
        os.fsync(source_directory_fd)
    finally:
        if destination_directory_fd >= 0:
            os.close(destination_directory_fd)
        if source_directory_fd >= 0:
            os.close(source_directory_fd)


class SnapshotStore:
    """A process-safe, tamper-evident local source snapshot store."""

    def __init__(self, root: Path | str) -> None:
        candidate = Path(root)
        if not candidate.is_absolute():
            _raise(SnapshotErrorCode.INVALID_STORE, "store root must be absolute")
        try:
            if candidate.parent == candidate:
                _raise(
                    SnapshotErrorCode.INVALID_STORE,
                    "store root must not be a filesystem root",
                )
            parent = candidate.parent.resolve(strict=True)
            parent_metadata = os.lstat(candidate.parent)
            if (
                parent != candidate.parent
                or stat.S_ISLNK(parent_metadata.st_mode)
                or not _parent_protects_directory_entry(parent_metadata)
            ):
                _raise(
                    SnapshotErrorCode.INVALID_STORE,
                    "store parent must be canonical and protect child entries "
                    "by owner-only or trusted sticky-directory semantics",
                )
            try:
                candidate.mkdir(mode=0o700)
            except FileExistsError:
                pass
            metadata = os.lstat(candidate)
            if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
                _raise(
                    SnapshotErrorCode.INVALID_STORE,
                    "store root must be a real directory",
                )
            if metadata.st_uid != os.geteuid() or _mode(metadata) & 0o022:
                _raise(
                    SnapshotErrorCode.INVALID_STORE,
                    "store root must be owner-controlled and not group/world writable",
                )
            if candidate.resolve(strict=True) != candidate:
                _raise(
                    SnapshotErrorCode.INVALID_STORE,
                    "store root must be canonical",
                )
        except SnapshotStoreError:
            raise
        except OSError as exc:
            _raise(SnapshotErrorCode.INVALID_STORE, "store root is unsafe", exc)
        self.root = candidate
        self._objects = candidate / "objects" / "sha256"
        self._snapshots = candidate / "snapshots" / "sha256"
        self._temporary = candidate / "tmp"
        self._lock_path = candidate / ".snapshot-store.lock"
        self._thread_lock = _thread_lock_for(candidate)
        with self._store_lock():
            self._ensure_layout()
            self._recover_stale_staging()

    def _ensure_layout(self) -> None:
        root_fd = -1
        try:
            parent_metadata = os.lstat(self.root.parent)
            if (
                self.root.parent.resolve(strict=True) != self.root.parent
                or stat.S_ISLNK(parent_metadata.st_mode)
                or not _parent_protects_directory_entry(parent_metadata)
            ):
                _raise(
                    SnapshotErrorCode.INVALID_STORE,
                    "store parent no longer protects the root directory entry",
                )
            root_metadata = os.lstat(self.root)
            if (
                stat.S_ISLNK(root_metadata.st_mode)
                or not stat.S_ISDIR(root_metadata.st_mode)
                or root_metadata.st_uid != os.geteuid()
                or _mode(root_metadata) & 0o022
                or self.root.resolve(strict=True) != self.root
            ):
                _raise(
                    SnapshotErrorCode.INVALID_STORE,
                    "store root is no longer an owner-controlled canonical directory",
                )
            root_fd = os.open(
                self.root,
                os.O_RDONLY | _O_CLOEXEC | _O_DIRECTORY | _O_NOFOLLOW,
            )
            opened_root = os.fstat(root_fd)
            if (
                not stat.S_ISDIR(opened_root.st_mode)
                or (root_metadata.st_dev, root_metadata.st_ino)
                != (opened_root.st_dev, opened_root.st_ino)
                or opened_root.st_uid != os.geteuid()
                or _mode(opened_root) & 0o022
            ):
                _raise(SnapshotErrorCode.INVALID_STORE, "store root changed during validation")
            root_mount_id = _mount_id(root_fd, ".")
            for directory in (
                self.root / "objects",
                self._objects,
                self.root / "snapshots",
                self._snapshots,
                self._temporary,
            ):
                if directory.exists() or directory.is_symlink():
                    metadata = os.lstat(directory)
                    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
                        _raise(
                            SnapshotErrorCode.INVALID_STORE,
                            f"store layout entry is unsafe: {directory}",
                        )
                    if metadata.st_uid != os.geteuid() or _mode(metadata) & 0o022:
                        _raise(
                            SnapshotErrorCode.INVALID_STORE,
                            f"store layout entry is not owner-controlled: {directory}",
                        )
                    if directory.resolve(strict=True) != directory:
                        _raise(
                            SnapshotErrorCode.INVALID_STORE,
                            f"store layout entry is non-canonical: {directory}",
                        )
                else:
                    directory.mkdir(mode=0o700)
                    metadata = os.lstat(directory)
                directory_fd = -1
                try:
                    directory_fd = os.open(
                        directory,
                        os.O_RDONLY | _O_CLOEXEC | _O_DIRECTORY | _O_NOFOLLOW,
                    )
                    directory_metadata = os.fstat(directory_fd)
                    if (
                        (directory_metadata.st_dev, directory_metadata.st_ino)
                        != (metadata.st_dev, metadata.st_ino)
                        or directory_metadata.st_dev != opened_root.st_dev
                        or directory_metadata.st_uid != os.geteuid()
                        or _mode(directory_metadata) & 0o022
                        or _mount_id(directory_fd, os.fspath(directory))
                        != root_mount_id
                    ):
                        _raise(
                            SnapshotErrorCode.INVALID_STORE,
                            f"store layout crosses a mount boundary: {directory}",
                        )
                finally:
                    if directory_fd >= 0:
                        os.close(directory_fd)
        except SnapshotStoreError:
            raise
        except OSError as exc:
            _raise(SnapshotErrorCode.INVALID_STORE, "cannot initialize store layout", exc)
        finally:
            if root_fd >= 0:
                os.close(root_fd)

    @contextmanager
    def _store_lock(self) -> Iterator[None]:
        with self._thread_lock:
            descriptor = -1
            try:
                descriptor = os.open(
                    self._lock_path,
                    os.O_RDWR | os.O_CREAT | _O_CLOEXEC | _O_NOFOLLOW,
                    0o600,
                )
                metadata = os.fstat(descriptor)
                if (
                    not stat.S_ISREG(metadata.st_mode)
                    or metadata.st_nlink != 1
                    or metadata.st_uid != os.geteuid()
                    or _mode(metadata) != 0o600
                ):
                    _raise(
                        SnapshotErrorCode.INVALID_STORE,
                        "store lock must be a single regular file",
                )
                fcntl.flock(descriptor, fcntl.LOCK_EX)
                yield
            except SnapshotStoreError:
                raise
            except OSError as exc:
                _raise(SnapshotErrorCode.INVALID_STORE, "cannot lock snapshot store", exc)
            finally:
                if descriptor >= 0:
                    try:
                        fcntl.flock(descriptor, fcntl.LOCK_UN)
                    finally:
                        os.close(descriptor)

    @contextmanager
    def _locked(self) -> Iterator[None]:
        with self._store_lock():
            self._ensure_layout()
            self._recover_stale_staging()
            yield

    def _recover_stale_staging(self) -> None:
        """Remove capture directories left by a producer that lost the lock."""

        try:
            found = False
            with os.scandir(self._temporary) as entries:
                for entry in entries:
                    found = True
                    if not entry.name.startswith("capture-"):
                        _raise(
                            SnapshotErrorCode.INVALID_STORE,
                            f"unknown entry in snapshot staging area: {entry.name}",
                        )
                    path = self._temporary / entry.name
                    metadata = os.lstat(path)
                    if stat.S_ISLNK(metadata.st_mode):
                        path.unlink()
                        continue
                    if (
                        not stat.S_ISDIR(metadata.st_mode)
                        or metadata.st_uid != os.geteuid()
                    ):
                        _raise(
                            SnapshotErrorCode.INVALID_STORE,
                            f"unsafe stale snapshot staging entry: {entry.name}",
                        )
                    _require_single_mount_tree(path)
                    shutil.rmtree(path)
            if found:
                _fsync_directory(self._temporary)
        except SnapshotStoreError:
            raise
        except OSError as exc:
            _raise(
                SnapshotErrorCode.CLEANUP_FAILED,
                "cannot recover stale snapshot staging state",
                exc,
            )

    def _validate_immutable_file(
        self,
        directory: Path,
        name: str,
        *,
        expected_sha256: str,
        expected_size: int | None,
        maximum: int,
        return_payload: bool,
    ) -> bytes | None:
        validate_sha256(expected_sha256, "expected_sha256")
        directory_fd = descriptor = -1
        chunks: list[bytes] | None = [] if return_payload else None
        try:
            directory_fd = os.open(
                directory,
                os.O_RDONLY | _O_CLOEXEC | _O_DIRECTORY | _O_NOFOLLOW,
            )
            descriptor = os.open(
                name,
                os.O_RDONLY | _O_CLOEXEC | _O_NOFOLLOW | _O_NONBLOCK,
                dir_fd=directory_fd,
            )
            initial = os.fstat(descriptor)
            if (
                not stat.S_ISREG(initial.st_mode)
                or initial.st_nlink != 1
                or _mode(initial) != 0o444
            ):
                _raise(
                    SnapshotErrorCode.INTEGRITY_FAILURE,
                    f"CAS object is not immutable regular content: {name}",
                )
            digest = hashlib.sha256()
            size = 0
            while True:
                chunk = os.read(descriptor, _CHUNK_SIZE)
                if not chunk:
                    break
                size += len(chunk)
                if size > maximum:
                    _raise(
                        SnapshotErrorCode.INTEGRITY_FAILURE,
                        f"CAS object exceeds its bound: {name}",
                    )
                digest.update(chunk)
                if chunks is not None:
                    chunks.append(chunk)
            final = os.fstat(descriptor)
            if _metadata_signature(initial) != _metadata_signature(final):
                _raise(
                    SnapshotErrorCode.INTEGRITY_FAILURE,
                    f"CAS object changed while reading: {name}",
                )
            if expected_size is not None and size != expected_size:
                _raise(
                    SnapshotErrorCode.INTEGRITY_FAILURE,
                    f"CAS object size mismatch: {name}",
                )
            if digest.hexdigest() != expected_sha256:
                _raise(
                    SnapshotErrorCode.INTEGRITY_FAILURE,
                    f"CAS object hash mismatch: {name}",
                )
            return b"".join(chunks) if chunks is not None else None
        except FileNotFoundError as exc:
            _raise(
                SnapshotErrorCode.INTEGRITY_FAILURE,
                f"CAS object is missing: {name}",
                exc,
            )
        except SnapshotStoreError:
            raise
        except OSError as exc:
            _raise(
                SnapshotErrorCode.INTEGRITY_FAILURE,
                f"cannot safely read CAS object {name}: {exc}",
                exc,
            )
        finally:
            if descriptor >= 0:
                os.close(descriptor)
            if directory_fd >= 0:
                os.close(directory_fd)

    def _publish_object(self, staged: Path, digest: str, size: int) -> None:
        destination = self._objects / digest
        if destination.exists() or destination.is_symlink():
            self._validate_immutable_file(
                self._objects,
                digest,
                expected_sha256=digest,
                expected_size=size,
                maximum=size,
                return_payload=False,
            )
            staged.unlink(missing_ok=True)
            return
        try:
            staged_identity = _freeze_staged_payload(
                staged,
                expected_sha256=digest,
                expected_size=size,
            )
            current = os.lstat(staged)
            if (current.st_dev, current.st_ino) != staged_identity:
                _raise(
                    SnapshotErrorCode.CAS_OBJECT_CONFLICT,
                    "staged CAS content changed before publication",
                )
            # Every cooperating producer holds the cross-process store lock.
            # A cross-directory rename on the verified single mount publishes
            # one link atomically, avoiding the link/unlink crash window that
            # could otherwise leave a permanently aliased CAS object.
            try:
                _rename_noreplace(staged, destination)
            except FileExistsError:
                self._validate_immutable_file(
                    self._objects,
                    digest,
                    expected_sha256=digest,
                    expected_size=size,
                    maximum=size,
                    return_payload=False,
                )
                staged.unlink(missing_ok=True)
            _fsync_directory(self._objects)
            _fsync_directory(staged.parent)
            self._validate_immutable_file(
                self._objects,
                digest,
                expected_sha256=digest,
                expected_size=size,
                maximum=size,
                return_payload=False,
            )
        except SnapshotStoreError:
            raise
        except OSError as exc:
            _raise(
                SnapshotErrorCode.CAS_OBJECT_CONFLICT,
                f"cannot atomically publish CAS object {digest}: {exc}",
                exc,
            )

    def _publish_snapshot_ref(self, staged: Path, reference: SnapshotRef) -> None:
        name = f"{reference.snapshot_sha256}.json"
        payload = canonical_json_bytes(reference.to_document())
        digest = hashlib.sha256(payload).hexdigest()
        destination = self._snapshots / name
        if destination.exists() or destination.is_symlink():
            existing = self._validate_immutable_file(
                self._snapshots,
                name,
                expected_sha256=digest,
                expected_size=len(payload),
                maximum=_MAX_REFERENCE_BYTES,
                return_payload=True,
            )
            if existing != payload:
                _raise(
                    SnapshotErrorCode.CAS_OBJECT_CONFLICT,
                    "snapshot reference address is already occupied",
                )
            staged.unlink(missing_ok=True)
            return
        try:
            staged_identity = _freeze_staged_payload(
                staged,
                expected_sha256=digest,
                expected_size=len(payload),
            )
            current = os.lstat(staged)
            if (current.st_dev, current.st_ino) != staged_identity:
                _raise(
                    SnapshotErrorCode.CAS_OBJECT_CONFLICT,
                    "staged snapshot reference changed before publication",
                )
            try:
                _rename_noreplace(staged, destination)
            except FileExistsError:
                existing = self._validate_immutable_file(
                    self._snapshots,
                    name,
                    expected_sha256=digest,
                    expected_size=len(payload),
                    maximum=_MAX_REFERENCE_BYTES,
                    return_payload=True,
                )
                if existing != payload:
                    _raise(
                        SnapshotErrorCode.CAS_OBJECT_CONFLICT,
                        "snapshot reference address is already occupied",
                    )
                staged.unlink(missing_ok=True)
            _fsync_directory(self._snapshots)
            _fsync_directory(staged.parent)
            published = self._validate_immutable_file(
                self._snapshots,
                name,
                expected_sha256=digest,
                expected_size=len(payload),
                maximum=_MAX_REFERENCE_BYTES,
                return_payload=True,
            )
            if published != payload:
                _raise(
                    SnapshotErrorCode.CAS_OBJECT_CONFLICT,
                    "published snapshot reference differs from staged content",
                )
        except SnapshotStoreError:
            raise
        except OSError as exc:
            _raise(
                SnapshotErrorCode.CAS_OBJECT_CONFLICT,
                "cannot atomically publish snapshot reference",
                exc,
            )

    def capture(self, source: Path | str, policy: SnapshotPolicy) -> StoredSnapshot:
        """Freeze one stable view of ``source`` and publish its ref last."""

        if type(policy) is not SnapshotPolicy:
            raise TypeError("policy must be a SnapshotPolicy")
        source_path = Path(source)
        if not source_path.is_absolute():
            _raise(SnapshotErrorCode.INVALID_SOURCE, "source root must be absolute")
        try:
            source_canonical = source_path.resolve(strict=True)
        except OSError as exc:
            _raise(
                SnapshotErrorCode.INVALID_SOURCE,
                "source root is missing or unsafe",
                exc,
            )
        try:
            source_canonical.relative_to(self.root)
            source_inside_store = True
        except ValueError:
            source_inside_store = False
        try:
            self.root.relative_to(source_canonical)
            store_inside_source = True
        except ValueError:
            store_inside_source = False
        if source_inside_store or store_inside_source:
            _raise(
                SnapshotErrorCode.INVALID_SOURCE,
                "source root must not overlap the snapshot store",
            )
        with self._locked():
            staging = Path(tempfile.mkdtemp(prefix="capture-", dir=self._temporary))
            os.chmod(staging, 0o700)
            root_fd = -1
            try:
                root_fd, root_metadata = _open_source_root(source_path)
                first = _scan_tree(
                    root_fd=root_fd,
                    root_metadata=root_metadata,
                    policy=policy,
                    staging_directory=staging,
                    reject_hardlinks=False,
                )
                first_manifest = SnapshotManifest(entries=first.entries)
                policy.validate_manifest(first_manifest)
                second = _scan_tree(
                    root_fd=root_fd,
                    root_metadata=root_metadata,
                    policy=policy,
                    staging_directory=None,
                    reject_hardlinks=False,
                )
                if (
                    second.entries != first.entries
                    or second.total_file_bytes != first.total_file_bytes
                ):
                    _raise(
                        SnapshotErrorCode.SOURCE_CHANGED,
                        "source tree changed between capture and stability verification",
                    )
                try:
                    current_path = os.lstat(source_path)
                except OSError as exc:
                    _raise(
                        SnapshotErrorCode.SOURCE_CHANGED,
                        "source root changed during capture",
                        exc,
                    )
                _require_stable(root_metadata, current_path, ".")

                policy_payload = canonical_json_bytes(policy.to_document())
                manifest_payload = first_manifest.canonical_bytes
                if len(policy_payload) > _MAX_POLICY_BYTES:
                    _raise(
                        SnapshotErrorCode.POLICY_LIMIT_EXCEEDED,
                        "snapshot policy exceeds the CAS metadata size bound",
                    )
                if len(manifest_payload) > _MAX_MANIFEST_BYTES:
                    _raise(
                        SnapshotErrorCode.POLICY_LIMIT_EXCEEDED,
                        "snapshot manifest exceeds the CAS metadata size bound",
                    )
                policy_staged = _write_staged_payload(staging, "policy", policy_payload)
                manifest_staged = _write_staged_payload(
                    staging, "manifest", manifest_payload,
                )
                first.staged_blobs[policy.content_sha256] = policy_staged
                first.staged_blobs[first_manifest.content_sha256] = manifest_staged
                sizes = {
                    entry.content_sha256: entry.size_bytes
                    for entry in first.entries
                    if entry.kind is SnapshotEntryKind.FILE
                }
                sizes[policy.content_sha256] = len(policy_payload)
                sizes[first_manifest.content_sha256] = len(manifest_payload)
                for digest in sorted(first.staged_blobs):
                    self._publish_object(
                        first.staged_blobs[digest], digest, sizes[digest],
                    )
                reference = SnapshotRef.create(policy.ref, first_manifest.artifact_ref)
                reference_payload = canonical_json_bytes(reference.to_document())
                if len(reference_payload) > _MAX_REFERENCE_BYTES:
                    _raise(
                        SnapshotErrorCode.POLICY_LIMIT_EXCEEDED,
                        "snapshot reference exceeds the CAS metadata size bound",
                    )
                reference_staged = _write_staged_payload(
                    staging, "reference", reference_payload,
                )
                self._publish_snapshot_ref(reference_staged, reference)
                stored = StoredSnapshot(reference, policy, first_manifest)
                # We still hold the store's process lock here.  Verify every
                # published file directly instead of recursively acquiring a
                # second flock through ``verify()``.
                self._verify_file_objects(stored)
                return stored
            except SnapshotStoreError:
                raise
            except (ContractError, OSError, ValueError) as exc:
                _raise(
                    SnapshotErrorCode.INTEGRITY_FAILURE,
                    f"snapshot capture failed closed: {exc}",
                    exc,
                )
            finally:
                if root_fd >= 0:
                    os.close(root_fd)
                self._cleanup_staging(staging)

    def _read_reference(self, digest: str) -> SnapshotRef:
        validate_sha256(digest, "snapshot_sha256")
        name = f"{digest}.json"
        directory_fd = descriptor = -1
        try:
            directory_fd = os.open(
                self._snapshots,
                os.O_RDONLY | _O_CLOEXEC | _O_DIRECTORY | _O_NOFOLLOW,
            )
            descriptor = os.open(
                name,
                os.O_RDONLY | _O_CLOEXEC | _O_NOFOLLOW | _O_NONBLOCK,
                dir_fd=directory_fd,
            )
            initial = os.fstat(descriptor)
            if (
                not stat.S_ISREG(initial.st_mode)
                or initial.st_nlink != 1
                or _mode(initial) != 0o444
            ):
                _raise(
                    SnapshotErrorCode.INTEGRITY_FAILURE,
                    "snapshot reference is not immutable regular content",
                )
            chunks: list[bytes] = []
            size = 0
            while True:
                chunk = os.read(descriptor, _CHUNK_SIZE)
                if not chunk:
                    break
                size += len(chunk)
                if size > _MAX_REFERENCE_BYTES:
                    _raise(
                        SnapshotErrorCode.INTEGRITY_FAILURE,
                        "snapshot reference exceeds its size bound",
                    )
                chunks.append(chunk)
            if _metadata_signature(initial) != _metadata_signature(os.fstat(descriptor)):
                _raise(
                    SnapshotErrorCode.INTEGRITY_FAILURE,
                    "snapshot reference changed while reading",
                )
            payload = b"".join(chunks)
            document = load_strict_json_object(payload, max_bytes=_MAX_REFERENCE_BYTES)
            reference = SnapshotRef.from_document(document)
            if reference.snapshot_sha256 != digest:
                _raise(
                    SnapshotErrorCode.INTEGRITY_FAILURE,
                    "snapshot reference does not match its addressed root digest",
                )
            if canonical_json_bytes(reference.to_document()) != payload:
                _raise(
                    SnapshotErrorCode.INTEGRITY_FAILURE,
                    "snapshot reference payload is not canonical",
                )
            return reference
        except FileNotFoundError as exc:
            _raise(
                SnapshotErrorCode.SNAPSHOT_NOT_FOUND,
                f"snapshot reference is missing: {digest}",
                exc,
            )
        except SnapshotStoreError:
            raise
        except (ContractError, OSError, ValueError) as exc:
            _raise(
                SnapshotErrorCode.INTEGRITY_FAILURE,
                f"snapshot reference is invalid: {exc}",
                exc,
            )
        finally:
            if descriptor >= 0:
                os.close(descriptor)
            if directory_fd >= 0:
                os.close(directory_fd)

    def load(
        self,
        snapshot: SnapshotRef | str,
        *,
        verify_file_objects: bool = False,
    ) -> StoredSnapshot:
        """Resolve and validate a frozen snapshot without trusting caller data."""

        expected = snapshot if type(snapshot) is SnapshotRef else None
        digest = expected.snapshot_sha256 if expected is not None else snapshot
        validate_sha256(digest, "snapshot_sha256")
        with self._locked():
            reference = self._read_reference(digest)
            if expected is not None and reference != expected:
                _raise(
                    SnapshotErrorCode.INTEGRITY_FAILURE,
                    "stored snapshot reference differs from the supplied exact reference",
                )
            policy_payload = self._validate_immutable_file(
                self._objects,
                reference.policy.content_sha256,
                expected_sha256=reference.policy.content_sha256,
                expected_size=None,
                maximum=_MAX_POLICY_BYTES,
                return_payload=True,
            )
            manifest_payload = self._validate_immutable_file(
                self._objects,
                reference.manifest.content_sha256,
                expected_sha256=reference.manifest.content_sha256,
                expected_size=reference.manifest.size_bytes,
                maximum=_MAX_MANIFEST_BYTES,
                return_payload=True,
            )
            if policy_payload is None or manifest_payload is None:
                _raise(
                    SnapshotErrorCode.INTEGRITY_FAILURE,
                    "snapshot metadata objects were not returned for parsing",
                )
            try:
                policy = SnapshotPolicy.from_document(load_strict_json_object(
                    policy_payload, max_bytes=_MAX_POLICY_BYTES,
                ))
                manifest = SnapshotManifest.from_document(load_strict_json_object(
                    manifest_payload, max_bytes=_MAX_MANIFEST_BYTES,
                ))
            except ContractError as exc:
                _raise(
                    SnapshotErrorCode.INTEGRITY_FAILURE,
                    f"snapshot metadata contract is invalid: {exc}",
                    exc,
                )
            if canonical_json_bytes(policy.to_document()) != policy_payload:
                _raise(
                    SnapshotErrorCode.INTEGRITY_FAILURE,
                    "snapshot policy payload is not canonical",
                )
            if manifest.canonical_bytes != manifest_payload:
                _raise(
                    SnapshotErrorCode.INTEGRITY_FAILURE,
                    "snapshot manifest payload is not canonical",
                )
            if policy.ref != reference.policy or manifest.artifact_ref != reference.manifest:
                _raise(
                    SnapshotErrorCode.INTEGRITY_FAILURE,
                    "snapshot metadata does not match the root reference",
                )
            try:
                policy.validate_manifest(manifest)
            except ContractError as exc:
                _raise(
                    SnapshotErrorCode.INTEGRITY_FAILURE,
                    f"snapshot manifest violates its frozen policy: {exc}",
                    exc,
                )
            stored = StoredSnapshot(reference, policy, manifest)
            if verify_file_objects:
                self._verify_file_objects(stored)
            return stored

    def _verify_file_objects(self, snapshot: StoredSnapshot) -> None:
        for entry in snapshot.manifest.entries:
            if entry.kind is not SnapshotEntryKind.FILE:
                continue
            if entry.content_sha256 is None:
                _raise(
                    SnapshotErrorCode.INTEGRITY_FAILURE,
                    f"file manifest entry has no content hash: {entry.relative_path}",
                )
            self._validate_immutable_file(
                self._objects,
                entry.content_sha256,
                expected_sha256=entry.content_sha256,
                expected_size=entry.size_bytes,
                maximum=entry.size_bytes,
                return_payload=False,
            )

    def verify(self, snapshot: SnapshotRef | str) -> StoredSnapshot:
        """Fully verify policy, manifest, root binding, and every file object."""

        return self.load(snapshot, verify_file_objects=True)

    def _copy_object_to_file(self, entry: SnapshotManifestEntry, destination: Path) -> None:
        if entry.content_sha256 is None:
            _raise(
                SnapshotErrorCode.INTEGRITY_FAILURE,
                f"file manifest entry has no content hash: {entry.relative_path}",
            )
        source_fd = destination_fd = -1
        try:
            source_fd = os.open(
                self._objects / entry.content_sha256,
                os.O_RDONLY | _O_CLOEXEC | _O_NOFOLLOW | _O_NONBLOCK,
            )
            source_initial = os.fstat(source_fd)
            if (
                not stat.S_ISREG(source_initial.st_mode)
                or source_initial.st_nlink != 1
                or _mode(source_initial) != 0o444
            ):
                _raise(
                    SnapshotErrorCode.INTEGRITY_FAILURE,
                    f"CAS object is unsafe: {entry.content_sha256}",
                )
            destination_fd = os.open(
                destination,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | _O_CLOEXEC | _O_NOFOLLOW,
                0o600,
            )
            digest = hashlib.sha256()
            size = 0
            while True:
                chunk = os.read(source_fd, _CHUNK_SIZE)
                if not chunk:
                    break
                size += len(chunk)
                if size > entry.size_bytes:
                    _raise(
                        SnapshotErrorCode.INTEGRITY_FAILURE,
                        f"CAS object exceeds manifest size: {entry.relative_path}",
                    )
                digest.update(chunk)
                view = memoryview(chunk)
                while view:
                    written = os.write(destination_fd, view)
                    if written <= 0:
                        raise OSError("short materialization write")
                    view = view[written:]
            source_final = os.fstat(source_fd)
            if _metadata_signature(source_initial) != _metadata_signature(source_final):
                _raise(
                    SnapshotErrorCode.INTEGRITY_FAILURE,
                    f"CAS object changed during materialization: {entry.relative_path}",
                )
            if size != entry.size_bytes or digest.hexdigest() != entry.content_sha256:
                _raise(
                    SnapshotErrorCode.INTEGRITY_FAILURE,
                    f"CAS object does not match manifest: {entry.relative_path}",
                )
            os.fsync(destination_fd)
            os.fchmod(destination_fd, entry.mode)
            materialized = os.fstat(destination_fd)
            if materialized.st_nlink != 1:
                _raise(
                    SnapshotErrorCode.INTEGRITY_FAILURE,
                    f"materialized file has a writable alias: {entry.relative_path}",
                )
            if (materialized.st_dev, materialized.st_ino) == (
                source_initial.st_dev,
                source_initial.st_ino,
            ):
                _raise(
                    SnapshotErrorCode.INTEGRITY_FAILURE,
                    f"materialized file aliases the CAS: {entry.relative_path}",
                )
        except SnapshotStoreError:
            raise
        except OSError as exc:
            _raise(
                SnapshotErrorCode.MATERIALIZATION_FAILED,
                f"cannot materialize {entry.relative_path}: {exc}",
                exc,
            )
        finally:
            if destination_fd >= 0:
                os.close(destination_fd)
            if source_fd >= 0:
                os.close(source_fd)

    def materialize(
        self,
        snapshot: SnapshotRef | str,
        destination: Path | str,
    ) -> MaterializedSnapshot:
        """Copy one snapshot into a new destination and fully verify it.

        ``destination`` must not exist.  It is host-owned and is not returned
        to a validator process until this method succeeds.  On failure only
        the exact directory inode created by this call is cleaned up.
        """

        destination_path = Path(destination)
        if not destination_path.is_absolute():
            _raise(
                SnapshotErrorCode.INVALID_DESTINATION,
                "materialization destination must be absolute",
            )
        try:
            parent = destination_path.parent.resolve(strict=True)
            parent_metadata = os.lstat(destination_path.parent)
            if (
                parent != destination_path.parent
                or stat.S_ISLNK(parent_metadata.st_mode)
                or not stat.S_ISDIR(parent_metadata.st_mode)
            ):
                _raise(
                    SnapshotErrorCode.INVALID_DESTINATION,
                    "materialization parent must be canonical and non-symlinked",
                )
            if not _parent_protects_directory_entry(parent_metadata):
                _raise(
                    SnapshotErrorCode.INVALID_DESTINATION,
                    "materialization parent must protect child entries by "
                    "owner-only or trusted sticky-directory semantics",
                )
            if destination_path.exists() or destination_path.is_symlink():
                _raise(
                    SnapshotErrorCode.INVALID_DESTINATION,
                    "materialization destination already exists",
                )
            try:
                destination_path.relative_to(self.root)
                inside_store = True
            except ValueError:
                inside_store = False
            try:
                self.root.relative_to(destination_path)
                contains_store = True
            except ValueError:
                contains_store = False
            if inside_store or contains_store:
                _raise(
                    SnapshotErrorCode.INVALID_DESTINATION,
                    "materialization destination must not overlap the snapshot store",
                )
        except SnapshotStoreError:
            raise
        except OSError as exc:
            _raise(
                SnapshotErrorCode.INVALID_DESTINATION,
                "materialization destination parent is unsafe",
                exc,
            )

        stored = self.load(snapshot, verify_file_objects=False)
        created_identity: tuple[int, int] | None = None
        try:
            os.mkdir(destination_path, mode=0o700)
            root_metadata = os.lstat(destination_path)
            created_identity = (root_metadata.st_dev, root_metadata.st_ino)
            directories = [
                entry for entry in stored.manifest.entries
                if entry.kind is SnapshotEntryKind.DIRECTORY
            ]
            files = [
                entry for entry in stored.manifest.entries
                if entry.kind is SnapshotEntryKind.FILE
            ]
            symlinks = [
                entry for entry in stored.manifest.entries
                if entry.kind is SnapshotEntryKind.SYMLINK
            ]
            for entry in sorted(
                directories,
                key=lambda item: (item.relative_path.count("/"), item.relative_path),
            ):
                os.mkdir(destination_path / entry.relative_path, mode=0o700)
            for entry in files:
                self._copy_object_to_file(entry, destination_path / entry.relative_path)
            for entry in symlinks:
                if entry.symlink_target is None:
                    _raise(
                        SnapshotErrorCode.INTEGRITY_FAILURE,
                        f"symlink manifest entry has no target: {entry.relative_path}",
                    )
                os.symlink(entry.symlink_target, destination_path / entry.relative_path)
            for entry in sorted(
                directories,
                key=lambda item: (-item.relative_path.count("/"), item.relative_path),
            ):
                os.chmod(
                    destination_path / entry.relative_path,
                    entry.mode,
                    follow_symlinks=False,
                )

            root_fd, root_metadata = _open_source_root(destination_path)
            try:
                verified = _scan_tree(
                    root_fd=root_fd,
                    root_metadata=root_metadata,
                    policy=None,
                    staging_directory=None,
                    reject_hardlinks=True,
                )
            finally:
                os.close(root_fd)
            if verified.entries != stored.manifest.entries:
                _raise(
                    SnapshotErrorCode.INTEGRITY_FAILURE,
                    "materialized tree differs from the frozen manifest",
                )
            proof = SnapshotMaterializationProof(
                materialization_id=uuid.uuid4().hex,
                snapshot_sha256=stored.ref.snapshot_sha256,
                policy_sha256=stored.policy.content_sha256,
                manifest_sha256=stored.manifest.content_sha256,
                entry_count=len(stored.manifest.entries),
                total_file_bytes=verified.total_file_bytes,
            )
            return MaterializedSnapshot(destination_path, proof)
        except SnapshotStoreError:
            self._cleanup_materialization(destination_path, created_identity)
            raise
        except (OSError, ContractError, ValueError) as exc:
            cleanup_error = self._cleanup_materialization(
                destination_path, created_identity, suppress=True,
            )
            suffix = f"; cleanup failed: {cleanup_error}" if cleanup_error else ""
            _raise(
                SnapshotErrorCode.MATERIALIZATION_FAILED,
                f"snapshot materialization failed: {exc}{suffix}",
                exc,
            )

    def _cleanup_staging(self, path: Path) -> None:
        try:
            relative = path.relative_to(self._temporary)
            if len(relative.parts) != 1 or not relative.name.startswith("capture-"):
                _raise(
                    SnapshotErrorCode.CLEANUP_FAILED,
                    "refusing to clean an unowned snapshot staging path",
                )
            if path.is_symlink():
                path.unlink()
            elif path.exists():
                _require_single_mount_tree(path)
                shutil.rmtree(path)
        except SnapshotStoreError:
            raise
        except OSError as exc:
            _raise(
                SnapshotErrorCode.CLEANUP_FAILED,
                f"cannot clean snapshot staging directory {path}",
                exc,
            )

    def _cleanup_materialization(
        self,
        path: Path,
        identity: tuple[int, int] | None,
        *,
        suppress: bool = False,
    ) -> str | None:
        if identity is None:
            return None
        try:
            metadata = os.lstat(path)
            if stat.S_ISLNK(metadata.st_mode):
                raise OSError("materialization root was replaced by a symlink")
            if not stat.S_ISDIR(metadata.st_mode) or (
                metadata.st_dev,
                metadata.st_ino,
            ) != identity:
                raise OSError("materialization root identity changed")
            _require_single_mount_tree(path)
            shutil.rmtree(path)
            return None
        except FileNotFoundError:
            return None
        except OSError as exc:
            if suppress:
                return str(exc)
            _raise(
                SnapshotErrorCode.CLEANUP_FAILED,
                f"cannot safely clean failed materialization {path}: {exc}",
                exc,
            )


__all__ = [
    "MaterializedSnapshot",
    "SnapshotErrorCode",
    "SnapshotMaterializationProof",
    "SnapshotStore",
    "SnapshotStoreError",
    "StoredSnapshot",
]

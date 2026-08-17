"""Owner-controlled immutable storage for governed validator profiles.

The store deliberately separates immutable, content-addressed evidence from
the few mutable names used to discover the current profile or revocation
ledger head.  Immutable bytes are published with no-clobber semantics.  A
mutable pointer is changed only while holding the authority's process lock,
after its new append-only history record is durable.

This module stores canonical bytes and hashes rather than importing the setup
contracts.  That keeps storage below the contract/setup layers and lets a
future Profile Gate reparse every object through the exact schema it expects.
"""

from __future__ import annotations

import fcntl
import hashlib
import os
import stat
import threading
import uuid
from contextlib import contextmanager
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Iterator

from ..contracts.base import (
    ContractError,
    canonical_json_bytes,
    load_strict_json_object,
    require_exact_keys,
    validate_identifier,
    validate_sha256,
)


_CHUNK_SIZE = 1024 * 1024
_MAX_OBJECT_BYTES = 64 * 1024 * 1024
_MAX_METADATA_BYTES = 64 * 1024
_MAX_REF_HISTORY = 1_000_000
_O_CLOEXEC = getattr(os, "O_CLOEXEC", 0)
_O_DIRECTORY = getattr(os, "O_DIRECTORY", 0)
_O_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
_O_NONBLOCK = getattr(os, "O_NONBLOCK", 0)

if not _O_DIRECTORY or not _O_NOFOLLOW:  # pragma: no cover - Linux baseline
    raise RuntimeError("ProfileStore requires O_DIRECTORY and O_NOFOLLOW")


class ProfileStoreErrorCode(str, Enum):
    INVALID_STORE = "INVALID_STORE"
    INVALID_ARGUMENT = "INVALID_ARGUMENT"
    OBJECT_NOT_FOUND = "OBJECT_NOT_FOUND"
    INTEGRITY_FAILURE = "INTEGRITY_FAILURE"
    HASH_MISMATCH = "HASH_MISMATCH"
    REF_NOT_FOUND = "REF_NOT_FOUND"
    STALE_REF = "STALE_REF"
    REF_CONFLICT = "REF_CONFLICT"
    APPROVAL_NOT_FOUND = "APPROVAL_NOT_FOUND"
    APPROVAL_SUBJECT_MISMATCH = "APPROVAL_SUBJECT_MISMATCH"
    APPROVAL_CONFLICT = "APPROVAL_CONFLICT"
    STALE_LEDGER_HEAD = "STALE_LEDGER_HEAD"
    LEDGER_CONFLICT = "LEDGER_CONFLICT"


class ProfileStoreError(RuntimeError):
    """A typed, fail-closed profile storage error."""

    def __init__(self, code: ProfileStoreErrorCode, message: str) -> None:
        if type(code) is not ProfileStoreErrorCode:
            raise TypeError("code must be a ProfileStoreErrorCode")
        self.code = code
        super().__init__(message)


def _raise(
    code: ProfileStoreErrorCode,
    message: str,
    cause: BaseException | None = None,
):
    error = ProfileStoreError(code, message)
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


def _parent_protects_entry(metadata: os.stat_result) -> bool:
    if not stat.S_ISDIR(metadata.st_mode):
        return False
    mode = _mode(metadata)
    if metadata.st_uid == os.geteuid() and not mode & 0o022:
        return True
    return bool(mode & stat.S_ISVTX and metadata.st_uid in (0, os.geteuid()))


def _validate_digest(value: object, field: str) -> str:
    try:
        return validate_sha256(value, field)
    except ContractError as exc:
        _raise(ProfileStoreErrorCode.INVALID_ARGUMENT, str(exc), exc)


def _validate_profile_id(value: object) -> str:
    try:
        identifier = validate_identifier(value, "profile_id")
    except ContractError as exc:
        _raise(ProfileStoreErrorCode.INVALID_ARGUMENT, str(exc), exc)
    # A profile id becomes exactly one directory component.
    if identifier in (".", "..") or "/" in identifier or "\\" in identifier:
        _raise(
            ProfileStoreErrorCode.INVALID_ARGUMENT,
            "profile_id must be one safe path component",
        )
    return identifier


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(
        path,
        os.O_RDONLY | _O_CLOEXEC | _O_DIRECTORY | _O_NOFOLLOW,
    )
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


@dataclass(frozen=True)
class StoredProfileObject:
    """Path-free receipt for one immutable CAS object."""

    sha256: str
    size_bytes: int

    def __post_init__(self) -> None:
        validate_sha256(self.sha256, "sha256")
        if type(self.size_bytes) is not int or self.size_bytes < 0:
            raise ValueError("size_bytes must be a non-negative integer")


@dataclass(frozen=True)
class ProfileRefRecord:
    """One immutable profile+admission link in the append-only ref history."""

    profile_id: str
    object_sha256: str
    admission_sha256: str
    previous_ref_sha256: str | None
    sequence: int

    def __post_init__(self) -> None:
        validate_identifier(self.profile_id, "profile_id")
        validate_sha256(self.object_sha256, "object_sha256")
        validate_sha256(self.admission_sha256, "admission_sha256")
        if self.previous_ref_sha256 is not None:
            validate_sha256(self.previous_ref_sha256, "previous_ref_sha256")
        if type(self.sequence) is not int or not 1 <= self.sequence <= _MAX_REF_HISTORY:
            raise ValueError("sequence must be within the supported ref history bound")
        if self.sequence == 1 and self.previous_ref_sha256 is not None:
            raise ValueError("the first profile ref must not name a previous ref")
        if self.sequence > 1 and self.previous_ref_sha256 is None:
            raise ValueError("later profile refs must name their previous ref")

    def to_document(self) -> dict[str, object]:
        return {
            "contract_kind": "profile_ref_record",
            "schema_version": 2,
            "profile_id": self.profile_id,
            "object_sha256": self.object_sha256,
            "admission_sha256": self.admission_sha256,
            "previous_ref_sha256": self.previous_ref_sha256,
            "sequence": self.sequence,
        }

    @property
    def content_sha256(self) -> str:
        return hashlib.sha256(canonical_json_bytes(self.to_document())).hexdigest()

    @classmethod
    def from_document(cls, value: object) -> "ProfileRefRecord":
        document = require_exact_keys(
            value,
            required=(
                "contract_kind",
                "schema_version",
                "profile_id",
                "object_sha256",
                "admission_sha256",
                "previous_ref_sha256",
                "sequence",
            ),
            where="profile ref record",
        )
        if document["contract_kind"] != "profile_ref_record":
            raise ContractError("profile ref record has the wrong contract_kind")
        if type(document["schema_version"]) is not int or document["schema_version"] != 2:
            raise ContractError("profile ref record schema_version must be integer 2")
        try:
            return cls(
                profile_id=document["profile_id"],
                object_sha256=document["object_sha256"],
                admission_sha256=document["admission_sha256"],
                previous_ref_sha256=document["previous_ref_sha256"],
                sequence=document["sequence"],
            )
        except (ContractError, TypeError, ValueError) as exc:
            raise ContractError(f"invalid profile ref record: {exc}") from exc


@dataclass(frozen=True)
class ApprovalReuseRecord:
    """Exact subject-to-approval mapping; it never performs fuzzy reuse."""

    subject_sha256: str
    approval_sha256: str

    def __post_init__(self) -> None:
        validate_sha256(self.subject_sha256, "subject_sha256")
        validate_sha256(self.approval_sha256, "approval_sha256")

    def to_document(self) -> dict[str, object]:
        return {
            "contract_kind": "approval_reuse_record",
            "schema_version": 1,
            "subject_sha256": self.subject_sha256,
            "approval_sha256": self.approval_sha256,
        }

    @classmethod
    def from_document(cls, value: object) -> "ApprovalReuseRecord":
        document = require_exact_keys(
            value,
            required=(
                "contract_kind",
                "schema_version",
                "subject_sha256",
                "approval_sha256",
            ),
            where="approval reuse record",
        )
        if document["contract_kind"] != "approval_reuse_record":
            raise ContractError("approval reuse record has the wrong contract_kind")
        if type(document["schema_version"]) is not int or document["schema_version"] != 1:
            raise ContractError("approval reuse record schema_version must be integer 1")
        try:
            return cls(
                subject_sha256=document["subject_sha256"],
                approval_sha256=document["approval_sha256"],
            )
        except (ContractError, TypeError, ValueError) as exc:
            raise ContractError(f"invalid approval reuse record: {exc}") from exc


@dataclass(frozen=True)
class ProfileAdmissionPublishReceipt:
    """Atomic Profile Gate publication receipt with no host paths."""

    profile_object: StoredProfileObject
    admission_object: StoredProfileObject
    approval_object: StoredProfileObject
    profile_ref: ProfileRefRecord
    approval_reused: bool
    revocation_head_sha256: str | None

    def __post_init__(self) -> None:
        if type(self.profile_object) is not StoredProfileObject:
            raise ValueError("profile_object must be a StoredProfileObject")
        if type(self.admission_object) is not StoredProfileObject:
            raise ValueError("admission_object must be a StoredProfileObject")
        if type(self.approval_object) is not StoredProfileObject:
            raise ValueError("approval_object must be a StoredProfileObject")
        if type(self.profile_ref) is not ProfileRefRecord:
            raise ValueError("profile_ref must be a ProfileRefRecord")
        if type(self.approval_reused) is not bool:
            raise ValueError("approval_reused must be a boolean")
        if self.revocation_head_sha256 is not None:
            validate_sha256(
                self.revocation_head_sha256,
                "revocation_head_sha256",
            )
        if self.profile_ref.object_sha256 != self.profile_object.sha256:
            raise ValueError("profile ref must point to the frozen profile object")
        if self.profile_ref.admission_sha256 != self.admission_object.sha256:
            raise ValueError("profile ref must bind the admission object")


@dataclass(frozen=True)
class ResolvedProfileAdmission:
    """Independently verified discovery result for admission and profile bytes."""

    profile_ref: ProfileRefRecord
    profile_payload: bytes
    admission_payload: bytes

    def __post_init__(self) -> None:
        if type(self.profile_ref) is not ProfileRefRecord:
            raise ValueError("profile_ref must be a ProfileRefRecord")
        if type(self.profile_payload) is not bytes:
            raise ValueError("profile_payload must be bytes")
        if type(self.admission_payload) is not bytes:
            raise ValueError("admission_payload must be bytes")
        if (
            hashlib.sha256(self.profile_payload).hexdigest()
            != self.profile_ref.object_sha256
            or hashlib.sha256(self.admission_payload).hexdigest()
            != self.profile_ref.admission_sha256
        ):
            raise ValueError("resolved profile/admission bytes are misbound")


@dataclass(frozen=True)
class RevocationLedgerEntry:
    """One immutable entry in the content-addressed revocation chain."""

    sequence: int
    previous_head_sha256: str | None
    payload_sha256: str

    def __post_init__(self) -> None:
        if type(self.sequence) is not int or not 1 <= self.sequence <= _MAX_REF_HISTORY:
            raise ValueError("sequence must be within the supported ledger bound")
        if self.previous_head_sha256 is not None:
            validate_sha256(self.previous_head_sha256, "previous_head_sha256")
        validate_sha256(self.payload_sha256, "payload_sha256")
        if self.sequence == 1 and self.previous_head_sha256 is not None:
            raise ValueError("the first ledger entry must not name a previous head")
        if self.sequence > 1 and self.previous_head_sha256 is None:
            raise ValueError("later ledger entries must name their previous head")

    def to_document(self) -> dict[str, object]:
        return {
            "contract_kind": "revocation_ledger_entry",
            "schema_version": 1,
            "sequence": self.sequence,
            "previous_head_sha256": self.previous_head_sha256,
            "payload_sha256": self.payload_sha256,
        }

    @property
    def content_sha256(self) -> str:
        return hashlib.sha256(canonical_json_bytes(self.to_document())).hexdigest()

    @classmethod
    def from_document(cls, value: object) -> "RevocationLedgerEntry":
        document = require_exact_keys(
            value,
            required=(
                "contract_kind",
                "schema_version",
                "sequence",
                "previous_head_sha256",
                "payload_sha256",
            ),
            where="revocation ledger entry",
        )
        if document["contract_kind"] != "revocation_ledger_entry":
            raise ContractError("revocation ledger entry has the wrong contract_kind")
        if type(document["schema_version"]) is not int or document["schema_version"] != 1:
            raise ContractError("revocation ledger entry schema_version must be integer 1")
        try:
            return cls(
                sequence=document["sequence"],
                previous_head_sha256=document["previous_head_sha256"],
                payload_sha256=document["payload_sha256"],
            )
        except (ContractError, TypeError, ValueError) as exc:
            raise ContractError(f"invalid revocation ledger entry: {exc}") from exc


_THREAD_LOCKS_GUARD = threading.Lock()
_THREAD_LOCKS: dict[str, threading.RLock] = {}


def _thread_lock_for(root: Path) -> threading.RLock:
    key = os.fspath(root)
    with _THREAD_LOCKS_GUARD:
        return _THREAD_LOCKS.setdefault(key, threading.RLock())


class ProfileStore:
    """Process-safe CAS and append-only indexes for frozen profile evidence.

    ``create=True`` accepts only a new path.  The default opens an already
    initialized store and never silently blesses an arbitrary existing
    directory as authority-owned storage.
    """

    def __init__(self, root: Path | str, *, create: bool = False) -> None:
        if type(create) is not bool:
            raise TypeError("create must be a bool")
        candidate = Path(root)
        if not candidate.is_absolute() or candidate.parent == candidate:
            _raise(
                ProfileStoreErrorCode.INVALID_STORE,
                "profile store root must be an absolute non-root path",
            )
        self._root = candidate
        self._objects = candidate / "objects" / "sha256"
        self._profiles = candidate / "refs" / "profiles"
        self._approvals = candidate / "approvals" / "by-subject"
        self._revocations = candidate / "revocation-ledger"
        self._revocation_entries = self._revocations / "entries" / "sha256"
        self._revocation_history = self._revocations / "head-history"
        self._temporary = candidate / "tmp"
        self._lock_path = candidate / ".profile-store.lock"
        self._thread_lock = _thread_lock_for(candidate)
        if create:
            self._create_fresh()
        else:
            self._validate_layout()
        with self._locked():
            pass

    @classmethod
    def create(cls, root: Path | str) -> "ProfileStore":
        return cls(root, create=True)

    @classmethod
    def open(cls, root: Path | str) -> "ProfileStore":
        return cls(root, create=False)

    def _create_fresh(self) -> None:
        try:
            parent = self._root.parent.resolve(strict=True)
            parent_metadata = os.lstat(self._root.parent)
            if (
                parent != self._root.parent
                or stat.S_ISLNK(parent_metadata.st_mode)
                or not _parent_protects_entry(parent_metadata)
            ):
                _raise(
                    ProfileStoreErrorCode.INVALID_STORE,
                    "store parent must be canonical and protect its child entries",
                )
            os.mkdir(self._root, 0o700)
            directories = (
                self._root / "objects",
                self._objects,
                self._root / "refs",
                self._profiles,
                self._root / "approvals",
                self._approvals,
                self._revocations,
                self._revocations / "entries",
                self._revocation_entries,
                self._revocation_history,
                self._temporary,
            )
            for directory in directories:
                os.mkdir(directory, 0o700)
                _fsync_directory(directory.parent)
            descriptor = os.open(
                self._lock_path,
                os.O_RDWR | os.O_CREAT | os.O_EXCL | _O_CLOEXEC | _O_NOFOLLOW,
                0o600,
            )
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
            _fsync_directory(self._root)
            self._validate_layout()
        except FileExistsError as exc:
            _raise(
                ProfileStoreErrorCode.INVALID_STORE,
                "create requires a fresh, previously absent store root",
                exc,
            )
        except ProfileStoreError:
            raise
        except OSError as exc:
            _raise(
                ProfileStoreErrorCode.INVALID_STORE,
                "cannot create a safe profile store",
                exc,
            )

    def _validate_directory(
        self,
        path: Path,
        *,
        root_device: int | None = None,
    ) -> os.stat_result:
        metadata = os.lstat(path)
        if (
            stat.S_ISLNK(metadata.st_mode)
            or not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or _mode(metadata) != 0o700
            or path.resolve(strict=True) != path
            or (root_device is not None and metadata.st_dev != root_device)
        ):
            _raise(
                ProfileStoreErrorCode.INVALID_STORE,
                f"unsafe profile store directory: {path}",
            )
        descriptor = os.open(
            path,
            os.O_RDONLY | _O_CLOEXEC | _O_DIRECTORY | _O_NOFOLLOW,
        )
        try:
            opened = os.fstat(descriptor)
            if (
                (opened.st_dev, opened.st_ino) != (metadata.st_dev, metadata.st_ino)
                or opened.st_uid != os.geteuid()
                or _mode(opened) != 0o700
            ):
                _raise(
                    ProfileStoreErrorCode.INVALID_STORE,
                    f"profile store directory changed while opening: {path}",
                )
        finally:
            os.close(descriptor)
        return metadata

    def _validate_layout(self) -> None:
        try:
            parent_metadata = os.lstat(self._root.parent)
            if (
                self._root.parent.resolve(strict=True) != self._root.parent
                or stat.S_ISLNK(parent_metadata.st_mode)
                or not _parent_protects_entry(parent_metadata)
            ):
                _raise(
                    ProfileStoreErrorCode.INVALID_STORE,
                    "store parent no longer protects its child entries",
                )
            root_metadata = self._validate_directory(self._root)
            for directory in (
                self._root / "objects",
                self._objects,
                self._root / "refs",
                self._profiles,
                self._root / "approvals",
                self._approvals,
                self._revocations,
                self._revocations / "entries",
                self._revocation_entries,
                self._revocation_history,
                self._temporary,
            ):
                self._validate_directory(directory, root_device=root_metadata.st_dev)
            lock_metadata = os.lstat(self._lock_path)
            if (
                stat.S_ISLNK(lock_metadata.st_mode)
                or not stat.S_ISREG(lock_metadata.st_mode)
                or lock_metadata.st_nlink != 1
                or lock_metadata.st_uid != os.geteuid()
                or _mode(lock_metadata) != 0o600
                or lock_metadata.st_dev != root_metadata.st_dev
            ):
                _raise(
                    ProfileStoreErrorCode.INVALID_STORE,
                    "profile store lock is unsafe",
                )
        except ProfileStoreError:
            raise
        except OSError as exc:
            _raise(
                ProfileStoreErrorCode.INVALID_STORE,
                "profile store layout is missing or unsafe",
                exc,
            )

    @contextmanager
    def _store_lock(self) -> Iterator[None]:
        with self._thread_lock:
            descriptor = -1
            try:
                descriptor = os.open(
                    self._lock_path,
                    os.O_RDWR | _O_CLOEXEC | _O_NOFOLLOW,
                )
                metadata = os.fstat(descriptor)
                if (
                    not stat.S_ISREG(metadata.st_mode)
                    or metadata.st_nlink != 1
                    or metadata.st_uid != os.geteuid()
                    or _mode(metadata) != 0o600
                ):
                    _raise(
                        ProfileStoreErrorCode.INVALID_STORE,
                        "profile store lock is unsafe",
                    )
                fcntl.flock(descriptor, fcntl.LOCK_EX)
                yield
            except ProfileStoreError:
                raise
            except OSError as exc:
                _raise(
                    ProfileStoreErrorCode.INVALID_STORE,
                    "cannot lock profile store",
                    exc,
                )
            finally:
                if descriptor >= 0:
                    try:
                        fcntl.flock(descriptor, fcntl.LOCK_UN)
                    finally:
                        os.close(descriptor)

    @contextmanager
    def _locked(self) -> Iterator[None]:
        with self._store_lock():
            self._validate_layout()
            self._recover_staging_locked()
            yield

    def _recover_staging_locked(self) -> None:
        directory_fd = -1
        try:
            changed = False
            directory_fd = os.open(
                self._temporary,
                os.O_RDONLY | _O_CLOEXEC | _O_DIRECTORY | _O_NOFOLLOW,
            )
            with os.scandir(directory_fd) as entries:
                for entry in entries:
                    if not entry.name.startswith(".stage-"):
                        _raise(
                            ProfileStoreErrorCode.INVALID_STORE,
                            f"unknown entry in profile store staging: {entry.name}",
                        )
                    metadata = os.stat(
                        entry.name,
                        dir_fd=directory_fd,
                        follow_symlinks=False,
                    )
                    if (
                        not stat.S_ISREG(metadata.st_mode)
                        or metadata.st_uid != os.geteuid()
                        or metadata.st_nlink not in (1, 2)
                    ):
                        _raise(
                            ProfileStoreErrorCode.INVALID_STORE,
                            f"unsafe stale staging entry: {entry.name}",
                        )
                    os.unlink(entry.name, dir_fd=directory_fd)
                    changed = True
            if changed:
                _fsync_directory(self._temporary)
        except ProfileStoreError:
            raise
        except OSError as exc:
            _raise(
                ProfileStoreErrorCode.INVALID_STORE,
                "cannot recover profile store staging",
                exc,
            )
        finally:
            if directory_fd >= 0:
                os.close(directory_fd)

    def _stage_bytes_locked(self, payload: bytes) -> Path:
        path = self._temporary / f".stage-{uuid.uuid4().hex}"
        descriptor = -1
        try:
            descriptor = os.open(
                path,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | _O_CLOEXEC | _O_NOFOLLOW,
                0o600,
            )
            view = memoryview(payload)
            written = 0
            while written < len(view):
                count = os.write(descriptor, view[written:])
                if count <= 0:
                    raise OSError("short write while staging profile content")
                written += count
            os.fsync(descriptor)
            os.fchmod(descriptor, 0o400)
            os.fsync(descriptor)
            metadata = os.fstat(descriptor)
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_nlink != 1
                or metadata.st_uid != os.geteuid()
                or _mode(metadata) != 0o400
                or metadata.st_size != len(payload)
            ):
                _raise(
                    ProfileStoreErrorCode.INTEGRITY_FAILURE,
                    "staged profile content could not be frozen",
                )
            _fsync_directory(self._temporary)
            return path
        except ProfileStoreError:
            path.unlink(missing_ok=True)
            raise
        except OSError as exc:
            path.unlink(missing_ok=True)
            _raise(
                ProfileStoreErrorCode.INTEGRITY_FAILURE,
                "cannot durably stage profile content",
                exc,
            )
        finally:
            if descriptor >= 0:
                os.close(descriptor)

    def _read_frozen_file_locked(
        self,
        directory: Path,
        name: str,
        *,
        expected_sha256: str | None,
        maximum: int,
        missing_code: ProfileStoreErrorCode,
    ) -> tuple[bytes, str]:
        directory_fd = descriptor = -1
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
                or initial.st_uid != os.geteuid()
                or _mode(initial) != 0o400
            ):
                _raise(
                    ProfileStoreErrorCode.INTEGRITY_FAILURE,
                    f"stored content is not an immutable regular file: {name}",
                )
            chunks: list[bytes] = []
            digest = hashlib.sha256()
            size = 0
            while True:
                chunk = os.read(descriptor, _CHUNK_SIZE)
                if not chunk:
                    break
                size += len(chunk)
                if size > maximum:
                    _raise(
                        ProfileStoreErrorCode.INTEGRITY_FAILURE,
                        f"stored content exceeds its read bound: {name}",
                    )
                digest.update(chunk)
                chunks.append(chunk)
            final = os.fstat(descriptor)
            if _metadata_signature(initial) != _metadata_signature(final):
                _raise(
                    ProfileStoreErrorCode.INTEGRITY_FAILURE,
                    f"stored content changed while reading: {name}",
                )
            actual = digest.hexdigest()
            if expected_sha256 is not None and actual != expected_sha256:
                _raise(
                    ProfileStoreErrorCode.INTEGRITY_FAILURE,
                    f"stored content hash does not match its address: {name}",
                )
            return b"".join(chunks), actual
        except FileNotFoundError as exc:
            _raise(missing_code, f"stored content is missing: {name}", exc)
        except ProfileStoreError:
            raise
        except OSError as exc:
            _raise(
                ProfileStoreErrorCode.INTEGRITY_FAILURE,
                f"cannot safely read stored content: {name}",
                exc,
            )
        finally:
            if descriptor >= 0:
                os.close(descriptor)
            if directory_fd >= 0:
                os.close(directory_fd)

    def _publish_noclobber_locked(
        self,
        directory: Path,
        name: str,
        payload: bytes,
        *,
        expected_sha256: str,
        missing_code: ProfileStoreErrorCode = ProfileStoreErrorCode.OBJECT_NOT_FOUND,
    ) -> None:
        staged = self._stage_bytes_locked(payload)
        try:
            try:
                os.link(staged, directory / name, follow_symlinks=False)
                _fsync_directory(directory)
                staged.unlink()
                _fsync_directory(self._temporary)
            except FileExistsError:
                staged.unlink(missing_ok=True)
                existing, actual = self._read_frozen_file_locked(
                    directory,
                    name,
                    expected_sha256=expected_sha256,
                    maximum=max(len(payload), _MAX_METADATA_BYTES),
                    missing_code=missing_code,
                )
                if actual != expected_sha256 or existing != payload:
                    _raise(
                        ProfileStoreErrorCode.INTEGRITY_FAILURE,
                        f"existing no-clobber destination conflicts: {name}",
                    )
            published, actual = self._read_frozen_file_locked(
                directory,
                name,
                expected_sha256=expected_sha256,
                maximum=max(len(payload), _MAX_METADATA_BYTES),
                missing_code=missing_code,
            )
            if actual != expected_sha256 or published != payload:
                _raise(
                    ProfileStoreErrorCode.INTEGRITY_FAILURE,
                    f"published bytes differ from staged bytes: {name}",
                )
        except ProfileStoreError:
            staged.unlink(missing_ok=True)
            raise
        except OSError as exc:
            staged.unlink(missing_ok=True)
            _raise(
                ProfileStoreErrorCode.INTEGRITY_FAILURE,
                f"cannot publish immutable content without clobbering: {name}",
                exc,
            )

    def _atomic_replace_locked(self, destination: Path, payload: bytes) -> None:
        staged = self._stage_bytes_locked(payload)
        try:
            os.replace(staged, destination)
            _fsync_directory(destination.parent)
            _fsync_directory(self._temporary)
        except OSError as exc:
            staged.unlink(missing_ok=True)
            _raise(
                ProfileStoreErrorCode.INTEGRITY_FAILURE,
                f"cannot atomically update pointer: {destination.name}",
                exc,
            )

    def _put_object_locked(
        self,
        payload: bytes,
        expected_sha256: str | None,
    ) -> StoredProfileObject:
        digest = hashlib.sha256(payload).hexdigest()
        if expected_sha256 is not None and digest != expected_sha256:
            _raise(
                ProfileStoreErrorCode.HASH_MISMATCH,
                "profile object does not match expected_sha256",
            )
        self._publish_noclobber_locked(
            self._objects,
            digest,
            payload,
            expected_sha256=digest,
        )
        return StoredProfileObject(sha256=digest, size_bytes=len(payload))

    def put_object(
        self,
        payload: bytes,
        *,
        expected_sha256: str | None = None,
    ) -> StoredProfileObject:
        """Publish canonical bytes once and return a path-free receipt."""

        if type(payload) is not bytes or len(payload) > _MAX_OBJECT_BYTES:
            _raise(
                ProfileStoreErrorCode.INVALID_ARGUMENT,
                f"payload must be bytes no larger than {_MAX_OBJECT_BYTES}",
            )
        if expected_sha256 is not None:
            _validate_digest(expected_sha256, "expected_sha256")
        with self._locked():
            return self._put_object_locked(payload, expected_sha256)

    def put_canonical_document(self, document: object) -> StoredProfileObject:
        try:
            payload = canonical_json_bytes(document)
        except ContractError as exc:
            _raise(ProfileStoreErrorCode.INVALID_ARGUMENT, str(exc), exc)
        return self.put_object(payload)

    def _get_object_locked(
        self,
        digest: str,
        expected_size_bytes: int | None = None,
    ) -> bytes:
        payload, _ = self._read_frozen_file_locked(
            self._objects,
            digest,
            expected_sha256=digest,
            maximum=_MAX_OBJECT_BYTES,
            missing_code=ProfileStoreErrorCode.OBJECT_NOT_FOUND,
        )
        if expected_size_bytes is not None and len(payload) != expected_size_bytes:
            _raise(
                ProfileStoreErrorCode.INTEGRITY_FAILURE,
                "stored profile object size does not match its expected size",
            )
        return payload

    def get_object(
        self,
        sha256: str,
        *,
        expected_size_bytes: int | None = None,
    ) -> bytes:
        """Return an immutable byte value after rechecking mode, size and hash."""

        digest = _validate_digest(sha256, "sha256")
        if (
            expected_size_bytes is not None
            and (
                type(expected_size_bytes) is not int
                or not 0 <= expected_size_bytes <= _MAX_OBJECT_BYTES
            )
        ):
            _raise(
                ProfileStoreErrorCode.INVALID_ARGUMENT,
                "expected_size_bytes must be a non-negative supported size",
            )
        with self._locked():
            return self._get_object_locked(digest, expected_size_bytes)

    def _ensure_profile_directories_locked(self, profile_id: str) -> tuple[Path, Path]:
        profile_directory = self._profiles / profile_id
        history = profile_directory / "history"
        try:
            if not profile_directory.exists():
                os.mkdir(profile_directory, 0o700)
                _fsync_directory(self._profiles)
                os.mkdir(history, 0o700)
                _fsync_directory(profile_directory)
            root_device = os.lstat(self._root).st_dev
            self._validate_directory(profile_directory, root_device=root_device)
            self._validate_directory(history, root_device=root_device)
            return profile_directory, history
        except ProfileStoreError:
            raise
        except OSError as exc:
            _raise(
                ProfileStoreErrorCode.INVALID_STORE,
                f"cannot establish profile ref directory: {profile_id}",
                exc,
            )

    def _parse_ref_payload(
        self,
        payload: bytes,
        *,
        expected_profile_id: str,
        expected_ref_sha256: str | None,
    ) -> ProfileRefRecord:
        try:
            document = load_strict_json_object(payload, max_bytes=_MAX_METADATA_BYTES)
            if canonical_json_bytes(document) != payload:
                raise ContractError("profile ref bytes are not canonical")
            record = ProfileRefRecord.from_document(document)
        except (ContractError, TypeError, ValueError) as exc:
            _raise(ProfileStoreErrorCode.INTEGRITY_FAILURE, str(exc), exc)
        if record.profile_id != expected_profile_id:
            _raise(
                ProfileStoreErrorCode.INTEGRITY_FAILURE,
                "profile ref is stored under a different profile id",
            )
        if expected_ref_sha256 is not None and record.content_sha256 != expected_ref_sha256:
            _raise(
                ProfileStoreErrorCode.INTEGRITY_FAILURE,
                "profile ref content hash does not match its history address",
            )
        return record

    def _current_profile_ref_locked(
        self,
        profile_id: str,
        *,
        required: bool,
    ) -> ProfileRefRecord | None:
        profile_directory = self._profiles / profile_id
        if not profile_directory.exists():
            if required:
                _raise(
                    ProfileStoreErrorCode.REF_NOT_FOUND,
                    f"profile ref does not exist: {profile_id}",
                )
            return None
        profile_directory, history = self._ensure_profile_directories_locked(profile_id)
        try:
            payload, _ = self._read_frozen_file_locked(
                profile_directory,
                "current.json",
                expected_sha256=None,
                maximum=_MAX_METADATA_BYTES,
                missing_code=ProfileStoreErrorCode.REF_NOT_FOUND,
            )
        except ProfileStoreError as exc:
            if not required and exc.code is ProfileStoreErrorCode.REF_NOT_FOUND:
                return None
            raise
        record = self._parse_ref_payload(
            payload,
            expected_profile_id=profile_id,
            expected_ref_sha256=None,
        )
        history_payload, _ = self._read_frozen_file_locked(
            history,
            f"{record.content_sha256}.json",
            expected_sha256=record.content_sha256,
            maximum=_MAX_METADATA_BYTES,
            missing_code=ProfileStoreErrorCode.INTEGRITY_FAILURE,
        )
        if history_payload != payload:
            _raise(
                ProfileStoreErrorCode.INTEGRITY_FAILURE,
                "current profile ref differs from append-only history",
            )
        self._get_object_locked(record.object_sha256)
        self._get_object_locked(record.admission_sha256)
        return record

    def update_profile_ref(
        self,
        profile_id: str,
        object_sha256: str,
        admission_sha256: str,
        *,
        expected_previous_ref_sha256: str | None,
    ) -> ProfileRefRecord:
        """CAS-update a profile name after appending its immutable history."""

        identity = _validate_profile_id(profile_id)
        object_digest = _validate_digest(object_sha256, "object_sha256")
        admission_digest = _validate_digest(
            admission_sha256,
            "admission_sha256",
        )
        if expected_previous_ref_sha256 is not None:
            expected_previous_ref_sha256 = _validate_digest(
                expected_previous_ref_sha256,
                "expected_previous_ref_sha256",
            )
        with self._locked():
            return self._update_profile_ref_locked(
                identity,
                object_digest,
                admission_digest,
                expected_previous_ref_sha256,
            )

    def _update_profile_ref_locked(
        self,
        identity: str,
        object_digest: str,
        admission_digest: str,
        expected_previous_ref_sha256: str | None,
    ) -> ProfileRefRecord:
        self._get_object_locked(object_digest)
        self._get_object_locked(admission_digest)
        profile_directory, history = self._ensure_profile_directories_locked(identity)
        current = self._current_profile_ref_locked(identity, required=False)
        actual_previous = current.content_sha256 if current is not None else None
        if (
            current is not None
            and current.object_sha256 == object_digest
            and current.admission_sha256 == admission_digest
            and expected_previous_ref_sha256
            in (current.content_sha256, current.previous_ref_sha256)
        ):
            return current
        if actual_previous != expected_previous_ref_sha256:
            _raise(
                ProfileStoreErrorCode.STALE_REF,
                "profile ref compare-and-swap observed a stale previous ref",
            )
        record = ProfileRefRecord(
            profile_id=identity,
            object_sha256=object_digest,
            admission_sha256=admission_digest,
            previous_ref_sha256=actual_previous,
            sequence=1 if current is None else current.sequence + 1,
        )
        payload = canonical_json_bytes(record.to_document())
        self._publish_noclobber_locked(
            history,
            f"{record.content_sha256}.json",
            payload,
            expected_sha256=record.content_sha256,
            missing_code=ProfileStoreErrorCode.INTEGRITY_FAILURE,
        )
        self._atomic_replace_locked(profile_directory / "current.json", payload)
        resolved = self._current_profile_ref_locked(identity, required=True)
        if resolved != record:
            _raise(
                ProfileStoreErrorCode.REF_CONFLICT,
                "published profile ref did not resolve to the requested record",
            )
        return record

    def resolve_profile_ref(self, profile_id: str) -> ProfileRefRecord:
        identity = _validate_profile_id(profile_id)
        with self._locked():
            record = self._current_profile_ref_locked(identity, required=True)
            if record is None:  # pragma: no cover - guarded by required=True
                _raise(ProfileStoreErrorCode.REF_NOT_FOUND, "profile ref is missing")
            return record

    def resolve_profile_admission(
        self,
        profile_id: str,
        profile_ref_sha256: str | None = None,
    ) -> ResolvedProfileAdmission:
        """Resolve and hash-check a pinned or current profile/admission pair."""

        identity = _validate_profile_id(profile_id)
        if profile_ref_sha256 is not None:
            profile_ref_sha256 = _validate_digest(
                profile_ref_sha256,
                "profile_ref_sha256",
            )
        with self._locked():
            if profile_ref_sha256 is None:
                profile_ref = self._current_profile_ref_locked(
                    identity,
                    required=True,
                )
                if profile_ref is None:  # pragma: no cover - required=True
                    _raise(
                        ProfileStoreErrorCode.REF_NOT_FOUND,
                        "profile ref is missing",
                    )
            else:
                current = self._current_profile_ref_locked(
                    identity,
                    required=True,
                )
                if current is None:  # pragma: no cover - required=True
                    _raise(
                        ProfileStoreErrorCode.REF_NOT_FOUND,
                        "profile ref is missing",
                    )
                _, history = self._ensure_profile_directories_locked(identity)
                profile_ref = current
                visited: set[str] = set()
                while profile_ref.content_sha256 != profile_ref_sha256:
                    digest = profile_ref.content_sha256
                    if digest in visited or len(visited) >= _MAX_REF_HISTORY:
                        _raise(
                            ProfileStoreErrorCode.INTEGRITY_FAILURE,
                            "profile ref history contains a cycle or exceeds its bound",
                        )
                    visited.add(digest)
                    previous = profile_ref.previous_ref_sha256
                    if previous is None:
                        _raise(
                            ProfileStoreErrorCode.REF_NOT_FOUND,
                            "profile ref is not committed in the current history",
                        )
                    payload, _ = self._read_frozen_file_locked(
                        history,
                        f"{previous}.json",
                        expected_sha256=previous,
                        maximum=_MAX_METADATA_BYTES,
                        missing_code=ProfileStoreErrorCode.INTEGRITY_FAILURE,
                    )
                    prior = self._parse_ref_payload(
                        payload,
                        expected_profile_id=identity,
                        expected_ref_sha256=previous,
                    )
                    if prior.sequence != profile_ref.sequence - 1:
                        _raise(
                            ProfileStoreErrorCode.INTEGRITY_FAILURE,
                            "profile ref sequence is not contiguous",
                        )
                    profile_ref = prior
            profile_payload = self._get_object_locked(profile_ref.object_sha256)
            admission_payload = self._get_object_locked(
                profile_ref.admission_sha256
            )
            return ResolvedProfileAdmission(
                profile_ref=profile_ref,
                profile_payload=profile_payload,
                admission_payload=admission_payload,
            )

    def profile_ref_history(self, profile_id: str) -> tuple[ProfileRefRecord, ...]:
        """Return the verified reachable history, oldest first."""

        identity = _validate_profile_id(profile_id)
        with self._locked():
            current = self._current_profile_ref_locked(identity, required=True)
            if current is None:  # pragma: no cover
                _raise(ProfileStoreErrorCode.REF_NOT_FOUND, "profile ref is missing")
            _, history = self._ensure_profile_directories_locked(identity)
            records: list[ProfileRefRecord] = []
            seen: set[str] = set()
            record = current
            while True:
                digest = record.content_sha256
                if digest in seen or len(records) >= _MAX_REF_HISTORY:
                    _raise(
                        ProfileStoreErrorCode.INTEGRITY_FAILURE,
                        "profile ref history contains a cycle or exceeds its bound",
                    )
                seen.add(digest)
                records.append(record)
                previous = record.previous_ref_sha256
                if previous is None:
                    if record.sequence != 1:
                        _raise(
                            ProfileStoreErrorCode.INTEGRITY_FAILURE,
                            "profile ref history terminates at the wrong sequence",
                        )
                    break
                payload, _ = self._read_frozen_file_locked(
                    history,
                    f"{previous}.json",
                    expected_sha256=previous,
                    maximum=_MAX_METADATA_BYTES,
                    missing_code=ProfileStoreErrorCode.INTEGRITY_FAILURE,
                )
                prior = self._parse_ref_payload(
                    payload,
                    expected_profile_id=identity,
                    expected_ref_sha256=previous,
                )
                if prior.sequence != record.sequence - 1:
                    _raise(
                        ProfileStoreErrorCode.INTEGRITY_FAILURE,
                        "profile ref sequence is not contiguous",
                    )
                self._get_object_locked(prior.object_sha256)
                self._get_object_locked(prior.admission_sha256)
                record = prior
            return tuple(reversed(records))

    def index_approval(
        self,
        *,
        subject_sha256: str,
        approval_sha256: str,
        approval_subject_sha256: str,
    ) -> ApprovalReuseRecord:
        """Publish one exact subject mapping after validating its approval object."""

        subject = _validate_digest(subject_sha256, "subject_sha256")
        approval = _validate_digest(approval_sha256, "approval_sha256")
        claimed_subject = _validate_digest(
            approval_subject_sha256,
            "approval_subject_sha256",
        )
        if claimed_subject != subject:
            _raise(
                ProfileStoreErrorCode.APPROVAL_SUBJECT_MISMATCH,
                "approval subject does not exactly match the reuse key",
            )
        with self._locked():
            record, _ = self._index_approval_locked(subject, approval)
            return record

    def _index_approval_locked(
        self,
        subject: str,
        approval: str,
        replace_approval_sha256: str | None = None,
    ) -> tuple[ApprovalReuseRecord, bool]:
        record = ApprovalReuseRecord(
            subject_sha256=subject,
            approval_sha256=approval,
        )
        payload = canonical_json_bytes(record.to_document())
        digest = hashlib.sha256(payload).hexdigest()
        self._get_object_locked(approval)
        path = self._approvals / f"{subject}.json"
        if path.exists() or path.is_symlink():
            existing = self._resolve_approval_locked(subject)
            if existing == record and replace_approval_sha256 is not None:
                self._preflight_approval_index_locked(
                    subject,
                    approval,
                    replace_approval_sha256,
                )
                return existing, False
            if existing != record:
                if (
                    replace_approval_sha256 is None
                    or existing.approval_sha256 != replace_approval_sha256
                ):
                    _raise(
                        ProfileStoreErrorCode.APPROVAL_CONFLICT,
                        "subject already maps to a different approval",
                    )
                for historical in (existing, record):
                    historical_payload = canonical_json_bytes(
                        historical.to_document()
                    )
                    historical_digest = hashlib.sha256(
                        historical_payload
                    ).hexdigest()
                    self._publish_noclobber_locked(
                        self._approvals,
                        f"{subject}.{historical.approval_sha256}.json",
                        historical_payload,
                        expected_sha256=historical_digest,
                        missing_code=ProfileStoreErrorCode.APPROVAL_NOT_FOUND,
                    )
                self._atomic_replace_locked(path, payload)
                return self._resolve_approval_locked(subject), False
            return existing, True
        self._publish_noclobber_locked(
            self._approvals,
            path.name,
            payload,
            expected_sha256=digest,
            missing_code=ProfileStoreErrorCode.APPROVAL_NOT_FOUND,
        )
        return self._resolve_approval_locked(subject), False

    def _preflight_approval_index_locked(
        self,
        subject: str,
        approval: str,
        replace_approval_sha256: str | None,
    ) -> bool:
        """Validate the exact approval mapping without changing durable state."""

        path = self._approvals / f"{subject}.json"
        if not path.exists() and not path.is_symlink():
            if replace_approval_sha256 is not None:
                _raise(
                    ProfileStoreErrorCode.APPROVAL_CONFLICT,
                    "expected approval mapping to replace is missing",
                )
            return False
        existing = self._resolve_approval_locked(subject)
        if existing.approval_sha256 == approval:
            if replace_approval_sha256 is None:
                return True
            historical = ApprovalReuseRecord(
                subject_sha256=subject,
                approval_sha256=replace_approval_sha256,
            )
            historical_payload = canonical_json_bytes(historical.to_document())
            historical_digest = hashlib.sha256(historical_payload).hexdigest()
            stored, _ = self._read_frozen_file_locked(
                self._approvals,
                f"{subject}.{replace_approval_sha256}.json",
                expected_sha256=historical_digest,
                maximum=_MAX_METADATA_BYTES,
                missing_code=ProfileStoreErrorCode.APPROVAL_CONFLICT,
            )
            if stored != historical_payload:
                _raise(
                    ProfileStoreErrorCode.APPROVAL_CONFLICT,
                    "approval replacement history is misbound",
                )
            self._get_object_locked(replace_approval_sha256)
            return False
        if (
            replace_approval_sha256 is None
            or existing.approval_sha256 != replace_approval_sha256
        ):
            _raise(
                ProfileStoreErrorCode.APPROVAL_CONFLICT,
                "subject already maps to a different approval",
            )
        return False

    def publish_profile_admission(
        self,
        *,
        profile_id: str,
        profile_payload: bytes,
        profile_sha256: str,
        admission_payload: bytes,
        admission_sha256: str,
        approval_payload: bytes,
        approval_sha256: str,
        approval_subject_sha256: str,
        replace_approval_sha256: str | None,
        expected_previous_ref_sha256: str | None,
        expected_revocation_head_sha256: str | None,
    ) -> ProfileAdmissionPublishReceipt:
        """Fence revocation, approval reuse, and profile discovery.

        Immutable CAS publication and approval admission are independently
        valid, idempotent transactions.  A failure after approval admission may
        expose that verified approval mapping without advancing the profile
        ref; retrying the exact replacement recovers safely.  The mutable
        profile ref advances only after every supplied digest, approval mapping,
        previous profile ref, and revocation head is verified under one lock.
        The profile ref itself binds both the frozen profile and admission;
        changing either produces a new append-only ref record.
        """

        identity = _validate_profile_id(profile_id)
        payloads = (
            (profile_payload, "profile_payload"),
            (admission_payload, "admission_payload"),
            (approval_payload, "approval_payload"),
        )
        for payload, field in payloads:
            if type(payload) is not bytes or len(payload) > _MAX_OBJECT_BYTES:
                _raise(
                    ProfileStoreErrorCode.INVALID_ARGUMENT,
                    f"{field} must be bytes no larger than {_MAX_OBJECT_BYTES}",
                )
        profile_digest = _validate_digest(profile_sha256, "profile_sha256")
        admission_digest = _validate_digest(
            admission_sha256,
            "admission_sha256",
        )
        approval_digest = _validate_digest(approval_sha256, "approval_sha256")
        approval_subject = _validate_digest(
            approval_subject_sha256,
            "approval_subject_sha256",
        )
        if replace_approval_sha256 is not None:
            replace_approval_sha256 = _validate_digest(
                replace_approval_sha256,
                "replace_approval_sha256",
            )
        if expected_previous_ref_sha256 is not None:
            expected_previous_ref_sha256 = _validate_digest(
                expected_previous_ref_sha256,
                "expected_previous_ref_sha256",
            )
        if expected_revocation_head_sha256 is not None:
            expected_revocation_head_sha256 = _validate_digest(
                expected_revocation_head_sha256,
                "expected_revocation_head_sha256",
            )

        for payload, digest in (
            (profile_payload, profile_digest),
            (admission_payload, admission_digest),
            (approval_payload, approval_digest),
        ):
            if hashlib.sha256(payload).hexdigest() != digest:
                _raise(
                    ProfileStoreErrorCode.HASH_MISMATCH,
                    "publication payload does not match its declared digest",
                )

        with self._locked():
            current_ref = self._current_profile_ref_locked(identity, required=False)
            actual_previous = (
                None if current_ref is None else current_ref.content_sha256
            )
            committed_retry = (
                current_ref is not None
                and current_ref.object_sha256 == profile_digest
                and current_ref.admission_sha256 == admission_digest
                and current_ref.previous_ref_sha256
                == expected_previous_ref_sha256
            )
            current_head = self._current_ledger_head_locked()
            actual_head = (
                None if current_head is None else current_head.content_sha256
            )
            if (
                actual_head != expected_revocation_head_sha256
                and not committed_retry
            ):
                _raise(
                    ProfileStoreErrorCode.STALE_LEDGER_HEAD,
                    "profile publication observed a stale revocation head",
                )
            if (
                actual_previous != expected_previous_ref_sha256
                and not committed_retry
            ):
                _raise(
                    ProfileStoreErrorCode.STALE_REF,
                    "profile ref compare-and-swap observed a stale previous ref",
                )
            expected_approval_reused = self._preflight_approval_index_locked(
                approval_subject,
                approval_digest,
                replace_approval_sha256,
            )
            if (
                current_ref is not None
                and current_ref.object_sha256 == profile_digest
                and current_ref.admission_sha256 == admission_digest
            ):
                predicted_ref = current_ref
            else:
                predicted_ref = ProfileRefRecord(
                    profile_id=identity,
                    object_sha256=profile_digest,
                    admission_sha256=admission_digest,
                    previous_ref_sha256=actual_previous,
                    sequence=1 if current_ref is None else current_ref.sequence + 1,
                )

            approval_object = self._put_object_locked(
                approval_payload,
                approval_digest,
            )
            profile_object = self._put_object_locked(
                profile_payload,
                profile_digest,
            )
            admission_object = self._put_object_locked(
                admission_payload,
                admission_digest,
            )
            _, approval_reused = self._index_approval_locked(
                approval_subject,
                approval_digest,
                replace_approval_sha256,
            )
            if approval_reused is not expected_approval_reused:
                _raise(
                    ProfileStoreErrorCode.APPROVAL_CONFLICT,
                    "approval mapping changed after publication preflight",
                )
            profile_ref = self._update_profile_ref_locked(
                identity,
                profile_digest,
                admission_digest,
                expected_previous_ref_sha256,
            )
            if profile_ref != predicted_ref:
                _raise(
                    ProfileStoreErrorCode.REF_CONFLICT,
                    "published profile ref differs from admission sidecar",
                )
            return ProfileAdmissionPublishReceipt(
                profile_object=profile_object,
                admission_object=admission_object,
                approval_object=approval_object,
                profile_ref=profile_ref,
                approval_reused=approval_reused,
                revocation_head_sha256=actual_head,
            )

    def _resolve_approval_locked(self, subject: str) -> ApprovalReuseRecord:
        payload, _ = self._read_frozen_file_locked(
            self._approvals,
            f"{subject}.json",
            expected_sha256=None,
            maximum=_MAX_METADATA_BYTES,
            missing_code=ProfileStoreErrorCode.APPROVAL_NOT_FOUND,
        )
        try:
            document = load_strict_json_object(payload, max_bytes=_MAX_METADATA_BYTES)
            if canonical_json_bytes(document) != payload:
                raise ContractError("approval reuse bytes are not canonical")
            record = ApprovalReuseRecord.from_document(document)
        except (ContractError, TypeError, ValueError) as exc:
            _raise(ProfileStoreErrorCode.INTEGRITY_FAILURE, str(exc), exc)
        if record.subject_sha256 != subject:
            _raise(
                ProfileStoreErrorCode.APPROVAL_SUBJECT_MISMATCH,
                "approval reuse record is stored under a different subject",
            )
        self._get_object_locked(record.approval_sha256)
        return record

    def resolve_approval(self, subject_sha256: str) -> ApprovalReuseRecord:
        subject = _validate_digest(subject_sha256, "subject_sha256")
        with self._locked():
            return self._resolve_approval_locked(subject)

    def _parse_ledger_entry_payload(
        self,
        payload: bytes,
        *,
        expected_sha256: str,
    ) -> RevocationLedgerEntry:
        try:
            document = load_strict_json_object(payload, max_bytes=_MAX_METADATA_BYTES)
            if canonical_json_bytes(document) != payload:
                raise ContractError("revocation ledger bytes are not canonical")
            entry = RevocationLedgerEntry.from_document(document)
        except (ContractError, TypeError, ValueError) as exc:
            _raise(ProfileStoreErrorCode.INTEGRITY_FAILURE, str(exc), exc)
        if entry.content_sha256 != expected_sha256:
            _raise(
                ProfileStoreErrorCode.INTEGRITY_FAILURE,
                "revocation entry does not match its address",
            )
        return entry

    def _read_ledger_entry_locked(self, digest: str) -> RevocationLedgerEntry:
        payload, _ = self._read_frozen_file_locked(
            self._revocation_entries,
            f"{digest}.json",
            expected_sha256=digest,
            maximum=_MAX_METADATA_BYTES,
            missing_code=ProfileStoreErrorCode.INTEGRITY_FAILURE,
        )
        entry = self._parse_ledger_entry_payload(payload, expected_sha256=digest)
        self._get_object_locked(entry.payload_sha256)
        return entry

    def _current_ledger_head_locked(self) -> RevocationLedgerEntry | None:
        head_path = self._revocations / "head.json"
        if not head_path.exists() and not head_path.is_symlink():
            return None
        payload, _ = self._read_frozen_file_locked(
            self._revocations,
            "head.json",
            expected_sha256=None,
            maximum=_MAX_METADATA_BYTES,
            missing_code=ProfileStoreErrorCode.INTEGRITY_FAILURE,
        )
        try:
            document = require_exact_keys(
                load_strict_json_object(payload, max_bytes=_MAX_METADATA_BYTES),
                required=("entry_sha256",),
                where="revocation ledger head",
            )
            if canonical_json_bytes(document) != payload:
                raise ContractError("revocation ledger head bytes are not canonical")
            digest = validate_sha256(document["entry_sha256"], "entry_sha256")
        except ContractError as exc:
            _raise(ProfileStoreErrorCode.INTEGRITY_FAILURE, str(exc), exc)
        history_payload, _ = self._read_frozen_file_locked(
            self._revocation_history,
            f"{digest}.json",
            expected_sha256=hashlib.sha256(payload).hexdigest(),
            maximum=_MAX_METADATA_BYTES,
            missing_code=ProfileStoreErrorCode.INTEGRITY_FAILURE,
        )
        if history_payload != payload:
            _raise(
                ProfileStoreErrorCode.INTEGRITY_FAILURE,
                "revocation head differs from append-only head history",
            )
        return self._read_ledger_entry_locked(digest)

    def append_revocation(
        self,
        payload: bytes,
        *,
        expected_previous_head: str | None,
    ) -> RevocationLedgerEntry:
        """Append under an exact previous-head CAS; old entries are untouched."""

        if type(payload) is not bytes or len(payload) > _MAX_OBJECT_BYTES:
            _raise(
                ProfileStoreErrorCode.INVALID_ARGUMENT,
                f"payload must be bytes no larger than {_MAX_OBJECT_BYTES}",
            )
        if expected_previous_head is not None:
            expected_previous_head = _validate_digest(
                expected_previous_head,
                "expected_previous_head",
            )
        with self._locked():
            current = self._current_ledger_head_locked()
            actual_previous = current.content_sha256 if current is not None else None
            if actual_previous != expected_previous_head:
                _raise(
                    ProfileStoreErrorCode.STALE_LEDGER_HEAD,
                    "revocation append observed a stale ledger head",
                )
            stored_payload = self._put_object_locked(payload, None)
            entry = RevocationLedgerEntry(
                sequence=1 if current is None else current.sequence + 1,
                previous_head_sha256=actual_previous,
                payload_sha256=stored_payload.sha256,
            )
            entry_payload = canonical_json_bytes(entry.to_document())
            self._publish_noclobber_locked(
                self._revocation_entries,
                f"{entry.content_sha256}.json",
                entry_payload,
                expected_sha256=entry.content_sha256,
                missing_code=ProfileStoreErrorCode.INTEGRITY_FAILURE,
            )
            head_payload = canonical_json_bytes({"entry_sha256": entry.content_sha256})
            head_payload_sha = hashlib.sha256(head_payload).hexdigest()
            self._publish_noclobber_locked(
                self._revocation_history,
                f"{entry.content_sha256}.json",
                head_payload,
                expected_sha256=head_payload_sha,
                missing_code=ProfileStoreErrorCode.INTEGRITY_FAILURE,
            )
            self._atomic_replace_locked(self._revocations / "head.json", head_payload)
            resolved = self._current_ledger_head_locked()
            if resolved != entry:
                _raise(
                    ProfileStoreErrorCode.LEDGER_CONFLICT,
                    "published revocation head did not resolve to the appended entry",
                )
            return entry

    def revocation_head(self) -> RevocationLedgerEntry | None:
        with self._locked():
            return self._current_ledger_head_locked()

    def revocation_chain(
        self,
        head_sha256: str | None = None,
    ) -> tuple[RevocationLedgerEntry, ...]:
        """Verify a current or explicitly pinned historical chain, oldest first."""

        if head_sha256 is not None:
            head_sha256 = _validate_digest(head_sha256, "head_sha256")
        with self._locked():
            if head_sha256 is None:
                current = self._current_ledger_head_locked()
                if current is None:
                    return ()
                entry = current
            else:
                current = self._current_ledger_head_locked()
                if current is None:
                    _raise(
                        ProfileStoreErrorCode.INTEGRITY_FAILURE,
                        "explicit revocation head is not committed",
                    )
                entry = current
                reachable_seen: set[str] = set()
                while entry.content_sha256 != head_sha256:
                    digest = entry.content_sha256
                    if (
                        digest in reachable_seen
                        or len(reachable_seen) >= _MAX_REF_HISTORY
                    ):
                        _raise(
                            ProfileStoreErrorCode.INTEGRITY_FAILURE,
                            "revocation ledger contains a cycle or exceeds its bound",
                        )
                    reachable_seen.add(digest)
                    previous = entry.previous_head_sha256
                    if previous is None:
                        _raise(
                            ProfileStoreErrorCode.INTEGRITY_FAILURE,
                            "explicit revocation head is not committed",
                        )
                    prior = self._read_ledger_entry_locked(previous)
                    if prior.sequence != entry.sequence - 1:
                        _raise(
                            ProfileStoreErrorCode.INTEGRITY_FAILURE,
                            "revocation sequence is not contiguous",
                        )
                    entry = prior
            records: list[RevocationLedgerEntry] = []
            seen: set[str] = set()
            while True:
                digest = entry.content_sha256
                if digest in seen or len(records) >= _MAX_REF_HISTORY:
                    _raise(
                        ProfileStoreErrorCode.INTEGRITY_FAILURE,
                        "revocation ledger contains a cycle or exceeds its bound",
                    )
                seen.add(digest)
                records.append(entry)
                previous = entry.previous_head_sha256
                if previous is None:
                    if entry.sequence != 1:
                        _raise(
                            ProfileStoreErrorCode.INTEGRITY_FAILURE,
                            "revocation chain terminates at the wrong sequence",
                        )
                    break
                prior = self._read_ledger_entry_locked(previous)
                if prior.sequence != entry.sequence - 1:
                    _raise(
                        ProfileStoreErrorCode.INTEGRITY_FAILURE,
                        "revocation sequence is not contiguous",
                    )
                entry = prior
            return tuple(reversed(records))

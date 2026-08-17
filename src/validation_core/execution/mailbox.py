"""Fail-closed filesystem mailbox for one validation Agent lifecycle.

The mailbox is deliberately a *single-process* Coordinator primitive.  A
fresh instance owns one fresh ``case-staging/coordinator`` directory and one
non-blocking process lock.  If the process crashes, the whole lifecycle must
be abandoned; this module does not claim durable resume or recovery from an
existing mailbox.

The logical access model is:

* ``inbox`` and ``submissions`` are written by the Agent and read by the host;
* ``outbox`` is written by the host and read by the Agent; and
* ``state`` is host-only.

Directory modes are defence in depth, not an OS sandbox.  The later process
broker must enforce those logical views with separate mount/credential
authority.  In particular, same-uid processes are not isolated by chmod.

An Agent inode is never treated as frozen evidence.  The host opens every
request and staged payload through pinned directory descriptors with
``O_NOFOLLOW | O_NONBLOCK``, rejects hard links and special files, checks
metadata before and after the bounded read, verifies the declared bytes, and
copies them to a new host-state inode.  Gate callers receive immutable
``bytes`` and path-free bindings and must never reopen the Agent path.
"""

from __future__ import annotations

import ctypes
import errno
import fcntl
import hashlib
import math
import os
import re
import stat
import time
import uuid
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from enum import Enum
from pathlib import Path

from ..contracts.base import (
    ContractError,
    canonical_json_bytes,
    validate_identifier,
)
from ..contracts.coordinator import (
    CoordinatorRequestEnvelope,
    CoordinatorResponseEnvelope,
    StagedArtifactBinding,
)


_MAILBOX_DIRECTORY = "coordinator"
_REQUEST_NAME_RE = re.compile(r"([1-9][0-9]{0,6})\.request\.json\Z")
_RESPONSE_NAME_RE = re.compile(r"([1-9][0-9]{0,6})\.response\.json\Z")
_NONCE_DIRECTORY_RE = re.compile(r"([1-9][0-9]{0,6})\Z")
_CHUNK_SIZE = 1024 * 1024
_AGENT_WRITABLE_SCAN_ATTEMPTS = 4

_O_CLOEXEC = getattr(os, "O_CLOEXEC", 0)
_O_DIRECTORY = getattr(os, "O_DIRECTORY", 0)
_O_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
_O_NONBLOCK = getattr(os, "O_NONBLOCK", 0)
if not _O_DIRECTORY or not _O_NOFOLLOW:  # pragma: no cover - Linux baseline
    raise RuntimeError("CoordinatorMailbox requires O_DIRECTORY and O_NOFOLLOW")

try:  # Linux baseline; the link/unlink fallback is only for regular files.
    _RENAMEAT2 = ctypes.CDLL(None, use_errno=True).renameat2
except AttributeError:  # pragma: no cover - unusual libc
    _RENAMEAT2 = None
else:
    _RENAMEAT2.argtypes = (
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_uint,
    )
    _RENAMEAT2.restype = ctypes.c_int
_RENAME_NOREPLACE = 1


class MailboxErrorCode(str, Enum):
    """Closed failure vocabulary for Coordinator mailbox handling."""

    INVALID_ROOT = "INVALID_ROOT"
    ROOT_CHANGED = "ROOT_CHANGED"
    STATE_CONFLICT = "STATE_CONFLICT"
    OUTBOX_CONFLICT = "OUTBOX_CONFLICT"
    CLOSED = "CLOSED"
    LATE_REQUEST = "LATE_REQUEST"
    AGENT_EXITED = "AGENT_EXITED"
    LIVENESS_CHECK_FAILED = "LIVENESS_CHECK_FAILED"
    TIMEOUT = "TIMEOUT"
    INVALID_NONCE = "INVALID_NONCE"
    NONCE_REPLAY = "NONCE_REPLAY"
    NONCE_GAP = "NONCE_GAP"
    MULTIPLE_REQUESTS = "MULTIPLE_REQUESTS"
    OUTSTANDING_REQUEST = "OUTSTANDING_REQUEST"
    STRAY_ENTRY = "STRAY_ENTRY"
    UNSAFE_ENTRY = "UNSAFE_ENTRY"
    SOURCE_CHANGED = "SOURCE_CHANGED"
    REQUEST_TOO_LARGE = "REQUEST_TOO_LARGE"
    RESPONSE_TOO_LARGE = "RESPONSE_TOO_LARGE"
    PAYLOAD_LIMIT_EXCEEDED = "PAYLOAD_LIMIT_EXCEEDED"
    INVALID_REQUEST = "INVALID_REQUEST"
    SESSION_MISMATCH = "SESSION_MISMATCH"
    PAYLOAD_MISMATCH = "PAYLOAD_MISMATCH"
    RESPONSE_MISMATCH = "RESPONSE_MISMATCH"
    RESPONSE_NOT_READY = "RESPONSE_NOT_READY"
    IO_FAILURE = "IO_FAILURE"


class MailboxError(RuntimeError):
    """A typed mailbox integrity, protocol, or availability failure."""

    def __init__(self, code: MailboxErrorCode, message: str) -> None:
        if type(code) is not MailboxErrorCode:
            raise TypeError("code must be a MailboxErrorCode")
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class MailboxLimits:
    """Host-enforced bounds, independent of the envelope schema maxima."""

    max_request_bytes: int = 1_048_576
    max_response_bytes: int = 262_144
    max_artifacts: int = 4096
    max_single_payload_bytes: int = 1_073_741_824
    max_total_payload_bytes: int = 1_073_741_824
    max_staged_entries: int = 65_536
    max_requests: int = 4096
    max_lifecycle_payload_bytes: int = 4_294_967_296
    max_lifecycle_staged_entries: int = 262_144
    max_lifecycle_request_bytes: int = 67_108_864
    max_lifecycle_response_bytes: int = 67_108_864

    def __post_init__(self) -> None:
        for field in (
            "max_request_bytes",
            "max_response_bytes",
            "max_artifacts",
            "max_single_payload_bytes",
            "max_total_payload_bytes",
            "max_staged_entries",
            "max_requests",
            "max_lifecycle_payload_bytes",
            "max_lifecycle_staged_entries",
            "max_lifecycle_request_bytes",
            "max_lifecycle_response_bytes",
        ):
            value = getattr(self, field)
            if type(value) is not int or value < 1:
                raise ValueError(f"{field} must be a positive integer")
        if self.max_single_payload_bytes > self.max_total_payload_bytes:
            raise ValueError(
                "max_single_payload_bytes must not exceed max_total_payload_bytes"
            )
        for per_request, lifecycle in (
            (self.max_total_payload_bytes, self.max_lifecycle_payload_bytes),
            (self.max_staged_entries, self.max_lifecycle_staged_entries),
            (self.max_request_bytes, self.max_lifecycle_request_bytes),
            (self.max_response_bytes, self.max_lifecycle_response_bytes),
        ):
            if per_request > lifecycle:
                raise ValueError(
                    "each per-request bound must not exceed its lifecycle bound"
                )


@dataclass(frozen=True)
class FrozenStagedArtifact:
    """One path-free artifact binding paired with copied immutable bytes."""

    binding: StagedArtifactBinding
    content: bytes

    def __post_init__(self) -> None:
        if type(self.binding) is not StagedArtifactBinding:
            raise TypeError("binding must be a StagedArtifactBinding")
        if type(self.content) is not bytes:
            raise TypeError("content must be immutable bytes")
        artifact = self.binding.artifact
        if len(self.content) != artifact.size_bytes:
            raise ValueError("frozen artifact bytes do not match declared size")
        if hashlib.sha256(self.content).hexdigest() != artifact.content_sha256:
            raise ValueError("frozen artifact bytes do not match declared hash")

    @property
    def relative_path(self) -> str:
        return self.binding.relative_path

    @property
    def artifact(self):
        return self.binding.artifact

    @property
    def content_bytes(self) -> bytes:
        return self.content


@dataclass(frozen=True)
class FrozenCoordinatorRequest:
    """Exact request bytes accepted at the Agent-to-host freeze boundary."""

    envelope: CoordinatorRequestEnvelope
    request_sha256: str
    transport_sha256: str
    transport_bytes: bytes
    raw_submission: FrozenStagedArtifact
    artifacts: tuple[FrozenStagedArtifact, ...]

    def __post_init__(self) -> None:
        if type(self.envelope) is not CoordinatorRequestEnvelope:
            raise TypeError("envelope must be a CoordinatorRequestEnvelope")
        if self.request_sha256 != self.envelope.content_sha256:
            raise ValueError("request_sha256 does not bind the request envelope")
        _validate_digest(self.transport_sha256, "transport_sha256")
        if type(self.transport_bytes) is not bytes:
            raise TypeError("transport_bytes must be immutable bytes")
        if hashlib.sha256(self.transport_bytes).hexdigest() != self.transport_sha256:
            raise ValueError("transport_sha256 does not bind the request transport")
        if type(self.raw_submission) is not FrozenStagedArtifact:
            raise TypeError("raw_submission must be a FrozenStagedArtifact")
        if self.raw_submission.binding != self.envelope.raw_submission:
            raise ValueError("frozen raw submission does not bind the envelope")
        if type(self.artifacts) not in (tuple, list):
            raise TypeError("artifacts must be an ordered collection")
        artifacts = tuple(self.artifacts)
        if any(type(item) is not FrozenStagedArtifact for item in artifacts):
            raise TypeError("artifacts must contain FrozenStagedArtifact values")
        if tuple(item.binding for item in artifacts) != self.envelope.artifacts:
            raise ValueError("frozen artifacts do not bind the request envelope")
        object.__setattr__(self, "artifacts", artifacts)
        self.validate_integrity()

    @property
    def raw_submission_bytes(self) -> bytes:
        return self.raw_submission.content

    @property
    def all_artifacts(self) -> tuple[FrozenStagedArtifact, ...]:
        return (self.raw_submission, *self.artifacts)

    def validate_integrity(self) -> None:
        """Rebuild every untrusted contract and recheck every byte binding."""

        if type(self.envelope) is not CoordinatorRequestEnvelope:
            raise ValueError("frozen request envelope has the wrong runtime type")
        if type(self.request_sha256) is not str:
            raise ValueError("frozen request content hash has the wrong runtime type")
        if type(self.transport_sha256) is not str:
            raise ValueError("frozen request transport hash has the wrong runtime type")
        if type(self.transport_bytes) is not bytes:
            raise ValueError("frozen request transport is not immutable bytes")
        if type(self.raw_submission) is not FrozenStagedArtifact:
            raise ValueError("frozen raw submission has the wrong runtime type")
        if type(self.artifacts) is not tuple:
            raise ValueError("frozen request artifacts are not an immutable tuple")
        try:
            canonical = CoordinatorRequestEnvelope.from_json(self.envelope.to_json())
            transported = CoordinatorRequestEnvelope.from_json(self.transport_bytes)
        except (AttributeError, ContractError, TypeError, ValueError) as exc:
            raise ValueError(f"frozen request contains an invalid envelope: {exc}") from exc
        if canonical != self.envelope or transported != self.envelope:
            raise ValueError("frozen request envelope is not canonical or transport-bound")
        if self.request_sha256 != canonical.content_sha256:
            raise ValueError("frozen request content hash changed")
        if hashlib.sha256(self.transport_bytes).hexdigest() != self.transport_sha256:
            raise ValueError("frozen request transport hash changed")
        expected = (canonical.raw_submission, *canonical.artifacts)
        actual = (self.raw_submission, *tuple(self.artifacts))
        if len(actual) != len(expected):
            raise ValueError("frozen request artifact cardinality changed")
        for item, binding in zip(actual, expected, strict=True):
            if (
                type(item) is not FrozenStagedArtifact
                or type(item.binding) is not StagedArtifactBinding
                or item.binding != binding
            ):
                raise ValueError("frozen request artifact binding changed")
            if type(item.content) is not bytes:
                raise ValueError("frozen request artifact content is not immutable bytes")
            reference = binding.artifact
            if (
                len(item.content) != reference.size_bytes
                or hashlib.sha256(item.content).hexdigest()
                != reference.content_sha256
            ):
                raise ValueError("frozen request artifact bytes changed")


@dataclass(frozen=True)
class _SubmissionTreeBinding:
    entry_count: int
    metadata_sha256: str

    def __post_init__(self) -> None:
        if type(self.entry_count) is not int or self.entry_count < 0:
            raise ValueError("submission tree entry_count must be non-negative")
        _validate_digest(self.metadata_sha256, "submission tree metadata_sha256")


@dataclass(frozen=True)
class _ConsumedRequestBinding:
    nonce: int
    agent_session_id: str
    request_sha256: str
    transport_sha256: str
    frozen_manifest_sha256: str
    response_sha256: str
    declared_payload_bytes: int
    transport_size_bytes: int
    artifact_count: int
    submission_tree: _SubmissionTreeBinding

    def __post_init__(self) -> None:
        if type(self.nonce) is not int or self.nonce < 1:
            raise ValueError("consumed request nonce must be positive")
        validate_identifier(self.agent_session_id, "agent_session_id")
        for field in (
            "request_sha256",
            "transport_sha256",
            "frozen_manifest_sha256",
            "response_sha256",
        ):
            _validate_digest(getattr(self, field), field)
        for field in (
            "declared_payload_bytes",
            "transport_size_bytes",
            "artifact_count",
        ):
            value = getattr(self, field)
            if type(value) is not int or value < 0:
                raise ValueError(f"{field} must be a non-negative integer")
        if type(self.submission_tree) is not _SubmissionTreeBinding:
            raise TypeError("submission_tree must be a _SubmissionTreeBinding")

    def to_bytes(self) -> bytes:
        return canonical_json_bytes(
            {
                "contract_kind": "coordinator_consumed_request_binding",
                "schema_version": 1,
                "nonce": self.nonce,
                "agent_session_id": self.agent_session_id,
                "request_sha256": self.request_sha256,
                "transport_sha256": self.transport_sha256,
                "frozen_manifest_sha256": self.frozen_manifest_sha256,
                "response_sha256": self.response_sha256,
                "declared_payload_bytes": self.declared_payload_bytes,
                "transport_size_bytes": self.transport_size_bytes,
                "artifact_count": self.artifact_count,
                "submission_entry_count": self.submission_tree.entry_count,
                "submission_metadata_sha256": (
                    self.submission_tree.metadata_sha256
                ),
            }
        )


@dataclass(frozen=True)
class _PublishedResponseBinding:
    size_bytes: int
    content_sha256: str
    request_sha256: str

    def __post_init__(self) -> None:
        if type(self.size_bytes) is not int or self.size_bytes < 1:
            raise ValueError("published response size_bytes must be positive")
        _validate_digest(self.content_sha256, "response content_sha256")
        _validate_digest(self.request_sha256, "response request_sha256")

    @classmethod
    def create(
        cls,
        payload: bytes,
        *,
        request_sha256: str,
    ) -> _PublishedResponseBinding:
        if type(payload) is not bytes:
            raise TypeError("published response payload must be bytes")
        return cls(
            size_bytes=len(payload),
            content_sha256=hashlib.sha256(payload).hexdigest(),
            request_sha256=request_sha256,
        )

    def matches(self, payload: bytes) -> bool:
        return (
            type(payload) is bytes
            and len(payload) == self.size_bytes
            and hashlib.sha256(payload).hexdigest() == self.content_sha256
        )


def _validate_digest(value: object, field: str) -> str:
    if (
        type(value) is not str
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise ValueError(f"{field} must be a lowercase SHA-256 digest")
    return value


def _request_name(nonce: int) -> str:
    return f"{nonce}.request.json"


def _response_name(nonce: int) -> str:
    return f"{nonce}.response.json"


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


def _directory_identity(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        stat.S_IMODE(metadata.st_mode),
        metadata.st_uid,
        metadata.st_gid,
    )


def _mount_id(descriptor: int) -> int:
    try:
        with open(f"/proc/self/fdinfo/{descriptor}", "r", encoding="ascii") as stream:
            for line in stream:
                if line.startswith("mnt_id:"):
                    value = int(line.partition(":")[2].strip(), 10)
                    if value > 0:
                        return value
    except (OSError, ValueError) as exc:
        raise OSError("mailbox mount identity is unavailable") from exc
    raise OSError("mailbox mount identity is unavailable")


def _seconds(value: object, field: str, *, allow_zero: bool) -> float:
    if type(value) not in (int, float) or not math.isfinite(value):
        raise ValueError(f"{field} must be a finite number")
    if value < 0 or (not allow_zero and value == 0):
        qualifier = "non-negative" if allow_zero else "positive"
        raise ValueError(f"{field} must be {qualifier}")
    return float(value)


def _write_all(descriptor: int, payload: bytes) -> None:
    view = memoryview(payload)
    while view:
        written = os.write(descriptor, view)
        if written <= 0:  # pragma: no cover - os.write raises in practice
            raise OSError("short write")
        view = view[written:]


def _write_new_file_at(
    directory_fd: int,
    name: str,
    payload: bytes,
    *,
    final_mode: int,
) -> tuple[int, ...]:
    descriptor = os.open(
        name,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | _O_CLOEXEC | _O_NOFOLLOW,
        0o600,
        dir_fd=directory_fd,
    )
    try:
        _write_all(descriptor, payload)
        os.fsync(descriptor)
        os.fchmod(descriptor, final_mode)
        os.fsync(descriptor)
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or stat.S_IMODE(metadata.st_mode) != final_mode
        ):
            raise OSError("new mailbox file could not be frozen safely")
        return _metadata_signature(metadata)
    finally:
        os.close(descriptor)


def _rename_noreplace_at(
    source_directory_fd: int,
    source_name: str,
    destination_directory_fd: int,
    destination_name: str,
) -> None:
    unsupported = {
        errno.EINVAL,
        errno.ENOSYS,
        getattr(errno, "EOPNOTSUPP", errno.EINVAL),
        getattr(errno, "ENOTSUP", errno.EINVAL),
    }
    if _RENAMEAT2 is not None:
        ctypes.set_errno(0)
        result = _RENAMEAT2(
            source_directory_fd,
            os.fsencode(source_name),
            destination_directory_fd,
            os.fsencode(destination_name),
            _RENAME_NOREPLACE,
        )
        if result == 0:
            return
        error_number = ctypes.get_errno()
        if error_number not in unsupported:
            raise OSError(error_number, os.strerror(error_number))

    # Both objects are regular files.  link() is atomic/no-clobber; the source
    # alias is removed and both directories are synced before returning.
    os.link(
        source_name,
        destination_name,
        src_dir_fd=source_directory_fd,
        dst_dir_fd=destination_directory_fd,
        follow_symlinks=False,
    )
    os.fsync(destination_directory_fd)
    os.unlink(source_name, dir_fd=source_directory_fd)
    os.fsync(source_directory_fd)


def _read_regular_at(
    directory_fd: int,
    name: str,
    *,
    maximum: int,
    expected_size: int | None = None,
    expected_mount_id: int | None = None,
    require_owner: bool = False,
    require_mode: int | None = None,
) -> tuple[bytes, tuple[int, ...]]:
    """Read one stable, single-link regular file through a directory fd."""

    descriptor = -1
    try:
        before_path = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        if not stat.S_ISREG(before_path.st_mode) or before_path.st_nlink != 1:
            raise MailboxError(
                MailboxErrorCode.UNSAFE_ENTRY,
                f"mailbox entry is not a private regular file: {name}",
            )
        if before_path.st_size > maximum:
            raise MailboxError(
                MailboxErrorCode.PAYLOAD_LIMIT_EXCEEDED,
                f"mailbox entry exceeds its byte bound: {name}",
            )
        descriptor = os.open(
            name,
            os.O_RDONLY | _O_CLOEXEC | _O_NOFOLLOW | _O_NONBLOCK,
            dir_fd=directory_fd,
        )
        before = os.fstat(descriptor)
        if _metadata_signature(before_path) != _metadata_signature(before):
            raise MailboxError(
                MailboxErrorCode.SOURCE_CHANGED,
                f"mailbox entry changed while being opened: {name}",
            )
        if expected_mount_id is not None and _mount_id(descriptor) != expected_mount_id:
            raise MailboxError(
                MailboxErrorCode.UNSAFE_ENTRY,
                f"mailbox entry crosses a mount boundary: {name}",
            )
        if require_owner and before.st_uid != os.geteuid():
            raise MailboxError(
                MailboxErrorCode.UNSAFE_ENTRY,
                f"host-state entry is not authority-owned: {name}",
            )
        if require_mode is not None and stat.S_IMODE(before.st_mode) != require_mode:
            raise MailboxError(
                MailboxErrorCode.UNSAFE_ENTRY,
                f"host-state entry has an unsafe mode: {name}",
            )
        chunks: list[bytes] = []
        size = 0
        while True:
            chunk = os.read(descriptor, min(_CHUNK_SIZE, maximum - size + 1))
            if not chunk:
                break
            chunks.append(chunk)
            size += len(chunk)
            if size > maximum:
                raise MailboxError(
                    MailboxErrorCode.PAYLOAD_LIMIT_EXCEEDED,
                    f"mailbox entry exceeds its byte bound: {name}",
                )
        after = os.fstat(descriptor)
        after_path = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        if (
            _metadata_signature(before) != _metadata_signature(after)
            or _metadata_signature(after) != _metadata_signature(after_path)
        ):
            raise MailboxError(
                MailboxErrorCode.SOURCE_CHANGED,
                f"mailbox entry changed while being read: {name}",
            )
        if expected_size is not None and size != expected_size:
            raise MailboxError(
                MailboxErrorCode.PAYLOAD_MISMATCH,
                f"mailbox entry size does not match its binding: {name}",
            )
        return b"".join(chunks), _metadata_signature(after)
    except MailboxError:
        raise
    except (OSError, UnicodeError) as exc:
        raise MailboxError(
            MailboxErrorCode.UNSAFE_ENTRY,
            f"cannot safely read mailbox entry: {name}",
        ) from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)


class _DirectorySet:
    """Pinned host descriptors for one fresh mailbox tree."""

    def __init__(self, root: Path) -> None:
        self.root = root
        self.root_fd = -1
        self.inbox_fd = -1
        self.outbox_fd = -1
        self.state_fd = -1
        self.submissions_fd = -1
        self.requests_fd = -1
        self.responses_fd = -1
        self.outgoing_fd = -1
        self.lock_fd = -1
        self.lock_signature: tuple[int, ...] | None = None
        self._identities: dict[str, tuple[int, ...]] = {}
        self.mount_id = -1

    def close(self) -> None:
        for field in (
            "lock_fd",
            "outgoing_fd",
            "responses_fd",
            "requests_fd",
            "submissions_fd",
            "state_fd",
            "outbox_fd",
            "inbox_fd",
            "root_fd",
        ):
            descriptor = getattr(self, field)
            if descriptor >= 0:
                try:
                    os.close(descriptor)
                except OSError:
                    pass
                setattr(self, field, -1)


class AgentMailboxClient:
    """Untrusted-side convenience API; host validation never trusts its checks."""

    def __init__(self, root: Path, *, agent_session_id: str) -> None:
        if not isinstance(root, Path) or not root.is_absolute():
            raise ValueError("mailbox root must be an absolute pathlib.Path")
        validate_identifier(agent_session_id, "agent_session_id")
        self.root = root
        self.agent_session_id = agent_session_id
        self.inbox = root / "inbox"
        self.outbox = root / "outbox"
        self.submissions = root / "submissions"
        self._next_nonce = 1
        self._previous_response_sha256: str | None = None
        self._outstanding: dict[int, CoordinatorRequestEnvelope] = {}

    def _validate_payloads(
        self,
        request: CoordinatorRequestEnvelope,
        payloads: Mapping[str, bytes],
    ) -> dict[str, bytes]:
        if type(request) is not CoordinatorRequestEnvelope:
            raise TypeError("request must be a CoordinatorRequestEnvelope")
        if request.agent_session_id != self.agent_session_id:
            raise MailboxError(
                MailboxErrorCode.SESSION_MISMATCH,
                "request does not belong to this Agent session",
            )
        if request.nonce != self._next_nonce:
            raise MailboxError(
                MailboxErrorCode.INVALID_NONCE,
                "Agent client request nonce is not strictly next",
            )
        if request.previous_response_sha256 != self._previous_response_sha256:
            raise MailboxError(
                MailboxErrorCode.RESPONSE_MISMATCH,
                "Agent request does not acknowledge the previous response",
            )
        if self._outstanding:
            raise MailboxError(
                MailboxErrorCode.OUTSTANDING_REQUEST,
                "Agent client already has an outstanding request",
            )
        if not isinstance(payloads, Mapping):
            raise TypeError("payloads must be a mapping from path to immutable bytes")
        normalized = dict(payloads)
        bindings = (request.raw_submission, *request.artifacts)
        expected_paths = {binding.relative_path for binding in bindings}
        if set(normalized) != expected_paths or any(
            type(path) is not str or type(payload) is not bytes
            for path, payload in normalized.items()
        ):
            raise MailboxError(
                MailboxErrorCode.PAYLOAD_MISMATCH,
                "payload mapping must contain exact request paths and immutable bytes",
            )
        for binding in bindings:
            payload = normalized[binding.relative_path]
            artifact = binding.artifact
            if (
                len(payload) != artifact.size_bytes
                or hashlib.sha256(payload).hexdigest() != artifact.content_sha256
            ):
                raise MailboxError(
                    MailboxErrorCode.PAYLOAD_MISMATCH,
                    f"payload does not match its artifact binding: {binding.relative_path}",
                )
        return normalized

    def publish_request(
        self,
        request: CoordinatorRequestEnvelope,
        payloads: Mapping[str, bytes],
    ) -> str:
        """Stage all bound bytes, then atomically publish one request."""

        normalized = self._validate_payloads(request, payloads)
        namespace = self.submissions / str(request.nonce)
        try:
            namespace.mkdir(mode=0o700)
            for binding in (request.raw_submission, *request.artifacts):
                relative = Path(binding.relative_path)
                local_parts = relative.parts[2:]
                destination = namespace.joinpath(*local_parts)
                destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                descriptor = os.open(
                    destination,
                    os.O_WRONLY
                    | os.O_CREAT
                    | os.O_EXCL
                    | _O_CLOEXEC
                    | _O_NOFOLLOW,
                    0o600,
                )
                try:
                    _write_all(descriptor, normalized[binding.relative_path])
                    os.fsync(descriptor)
                finally:
                    os.close(descriptor)

            payload = request.to_json()
            temporary_name = f".request-{request.nonce}-{uuid.uuid4().hex}.tmp"
            namespace_fd = inbox_fd = -1
            try:
                namespace_fd = os.open(
                    namespace,
                    os.O_RDONLY | _O_CLOEXEC | _O_DIRECTORY | _O_NOFOLLOW,
                )
                inbox_fd = os.open(
                    self.inbox,
                    os.O_RDONLY | _O_CLOEXEC | _O_DIRECTORY | _O_NOFOLLOW,
                )
                _write_new_file_at(
                    namespace_fd,
                    temporary_name,
                    payload,
                    final_mode=0o600,
                )
                _rename_noreplace_at(
                    namespace_fd,
                    temporary_name,
                    inbox_fd,
                    _request_name(request.nonce),
                )
                os.fsync(inbox_fd)
            finally:
                try:
                    if inbox_fd >= 0:
                        os.close(inbox_fd)
                finally:
                    if namespace_fd >= 0:
                        os.close(namespace_fd)
        except MailboxError:
            raise
        except FileExistsError as exc:
            raise MailboxError(
                MailboxErrorCode.STATE_CONFLICT,
                "Agent request staging would overwrite an existing entry",
            ) from exc
        except OSError as exc:
            raise MailboxError(
                MailboxErrorCode.IO_FAILURE,
                "Agent could not publish the mailbox request",
            ) from exc
        self._outstanding[request.nonce] = request
        return request.content_sha256

    def read_response(
        self,
        nonce: int,
        *,
        request: CoordinatorRequestEnvelope | None = None,
    ) -> CoordinatorResponseEnvelope:
        """Read one already-published response without deleting it."""

        if type(nonce) is not int or nonce < 1:
            raise ValueError("nonce must be a positive integer")
        expected = request or self._outstanding.get(nonce)
        outbox_fd = -1
        try:
            outbox_fd = os.open(
                self.outbox,
                os.O_RDONLY | _O_CLOEXEC | _O_DIRECTORY | _O_NOFOLLOW,
            )
            try:
                payload, _ = _read_regular_at(
                    outbox_fd,
                    _response_name(nonce),
                    maximum=262_144,
                )
            except MailboxError as exc:
                if isinstance(exc.__cause__, FileNotFoundError):
                    raise MailboxError(
                        MailboxErrorCode.RESPONSE_NOT_READY,
                        "Coordinator response has not been published",
                    ) from exc
                raise
            response = CoordinatorResponseEnvelope.from_json(payload)
            if (
                response.agent_session_id != self.agent_session_id
                or response.nonce != nonce
            ):
                raise MailboxError(
                    MailboxErrorCode.RESPONSE_MISMATCH,
                    "Coordinator response session or nonce mismatch",
                )
            if expected is None:
                raise MailboxError(
                    MailboxErrorCode.RESPONSE_MISMATCH,
                    "Coordinator response has no exact request binding",
                )
            response.validate_request(expected)
        except MailboxError:
            raise
        except FileNotFoundError as exc:
            raise MailboxError(
                MailboxErrorCode.RESPONSE_NOT_READY,
                "Coordinator response has not been published",
            ) from exc
        except (ContractError, OSError) as exc:
            raise MailboxError(
                MailboxErrorCode.RESPONSE_MISMATCH,
                "Coordinator response is invalid",
            ) from exc
        finally:
            if outbox_fd >= 0:
                os.close(outbox_fd)
        self._outstanding.pop(nonce, None)
        if nonce == self._next_nonce:
            self._previous_response_sha256 = response.content_sha256
            self._next_nonce += 1
        return response

    def wait_response(
        self,
        nonce: int,
        *,
        timeout_seconds: int | float,
        poll_interval_seconds: int | float = 0.01,
        request: CoordinatorRequestEnvelope | None = None,
    ) -> CoordinatorResponseEnvelope:
        timeout = _seconds(timeout_seconds, "timeout_seconds", allow_zero=True)
        interval = _seconds(
            poll_interval_seconds,
            "poll_interval_seconds",
            allow_zero=False,
        )
        deadline = time.monotonic() + timeout
        while True:
            try:
                return self.read_response(nonce, request=request)
            except MailboxError as exc:
                if exc.code is not MailboxErrorCode.RESPONSE_NOT_READY:
                    raise
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise MailboxError(
                    MailboxErrorCode.TIMEOUT,
                    "timed out waiting for Coordinator response",
                )
            time.sleep(min(interval, remaining))


class CoordinatorMailbox:
    """One-writer host authority for a single Agent session mailbox."""

    def __init__(
        self,
        case_staging: Path,
        *,
        agent_session_id: str,
        limits: MailboxLimits | None = None,
    ) -> None:
        if not isinstance(case_staging, Path) or not case_staging.is_absolute():
            raise ValueError("case_staging must be an absolute pathlib.Path")
        validate_identifier(agent_session_id, "agent_session_id")
        if limits is None:
            limits = MailboxLimits()
        if type(limits) is not MailboxLimits:
            raise TypeError("limits must be a MailboxLimits value")
        self.case_staging = case_staging
        self.root = case_staging / _MAILBOX_DIRECTORY
        self.agent_session_id = agent_session_id
        self.limits = limits
        self._directories = _DirectorySet(self.root)
        self._next_nonce = 1
        self._outstanding: FrozenCoordinatorRequest | None = None
        self._closed = False
        self._closed_marker: bytes | None = None
        self._failed: MailboxError | None = None
        self._disposed = False
        self._claimed: dict[
            int,
            FrozenCoordinatorRequest | _ConsumedRequestBinding,
        ] = {}
        self._responses: dict[int, _PublishedResponseBinding] = {}
        self._submission_bindings: dict[int, _SubmissionTreeBinding] = {}
        self._lifecycle_payload_bytes = 0
        self._lifecycle_staged_entries = 0
        self._lifecycle_request_bytes = 0
        self._lifecycle_response_bytes = 0
        self._submissions_directory_signature: tuple[int, ...] | None = None
        self._known_submission_nonces: frozenset[int] = frozenset()
        self._submission_validation_context: tuple[int, int | None, bool] | None = (
            None
        )
        try:
            self._initialize_fresh_tree()
            self.agent_client = AgentMailboxClient(
                self.root,
                agent_session_id=agent_session_id,
            )
        except BaseException:
            self._directories.close()
            raise

    def _initialize_fresh_tree(self) -> None:
        descriptors = self._directories
        case_fd = -1
        try:
            metadata = os.lstat(self.case_staging)
            if (
                not stat.S_ISDIR(metadata.st_mode)
                or stat.S_ISLNK(metadata.st_mode)
                or metadata.st_uid != os.geteuid()
                or stat.S_IMODE(metadata.st_mode) & 0o022
            ):
                raise OSError("case staging is not an owner-controlled directory")
            case_fd = os.open(
                self.case_staging,
                os.O_RDONLY | _O_CLOEXEC | _O_DIRECTORY | _O_NOFOLLOW,
            )
            current = os.fstat(case_fd)
            if _metadata_signature(metadata) != _metadata_signature(current):
                raise OSError("case staging changed while being opened")
            os.mkdir(_MAILBOX_DIRECTORY, 0o700, dir_fd=case_fd)
            os.chmod(
                _MAILBOX_DIRECTORY,
                0o700,
                dir_fd=case_fd,
                follow_symlinks=False,
            )
            descriptors.root_fd = os.open(
                _MAILBOX_DIRECTORY,
                os.O_RDONLY | _O_CLOEXEC | _O_DIRECTORY | _O_NOFOLLOW,
                dir_fd=case_fd,
            )
            descriptors.mount_id = _mount_id(descriptors.root_fd)
            for name in ("inbox", "outbox", "state", "submissions"):
                os.mkdir(name, 0o700, dir_fd=descriptors.root_fd)
                os.chmod(
                    name,
                    0o700,
                    dir_fd=descriptors.root_fd,
                    follow_symlinks=False,
                )
            descriptors.inbox_fd = self._open_child_directory(
                descriptors.root_fd, "inbox"
            )
            descriptors.outbox_fd = self._open_child_directory(
                descriptors.root_fd, "outbox"
            )
            descriptors.state_fd = self._open_child_directory(
                descriptors.root_fd, "state"
            )
            descriptors.submissions_fd = self._open_child_directory(
                descriptors.root_fd, "submissions"
            )
            for name in ("requests", "responses", "outgoing"):
                os.mkdir(name, 0o700, dir_fd=descriptors.state_fd)
                os.chmod(
                    name,
                    0o700,
                    dir_fd=descriptors.state_fd,
                    follow_symlinks=False,
                )
            descriptors.requests_fd = self._open_child_directory(
                descriptors.state_fd, "requests"
            )
            descriptors.responses_fd = self._open_child_directory(
                descriptors.state_fd, "responses"
            )
            descriptors.outgoing_fd = self._open_child_directory(
                descriptors.state_fd, "outgoing"
            )
            descriptors.lock_fd = os.open(
                "lock",
                os.O_RDWR | os.O_CREAT | os.O_EXCL | _O_CLOEXEC | _O_NOFOLLOW,
                0o600,
                dir_fd=descriptors.state_fd,
            )
            fcntl.flock(descriptors.lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            os.fsync(descriptors.lock_fd)
            descriptors.lock_signature = _metadata_signature(
                os.fstat(descriptors.lock_fd)
            )
            for name, descriptor in (
                ("root", descriptors.root_fd),
                ("inbox", descriptors.inbox_fd),
                ("outbox", descriptors.outbox_fd),
                ("state", descriptors.state_fd),
                ("submissions", descriptors.submissions_fd),
                ("requests", descriptors.requests_fd),
                ("responses", descriptors.responses_fd),
                ("outgoing", descriptors.outgoing_fd),
            ):
                descriptors._identities[name] = _directory_identity(
                    os.fstat(descriptor)
                )
            os.fsync(descriptors.state_fd)
            os.fsync(descriptors.root_fd)
            os.fsync(case_fd)
        except FileExistsError as exc:
            raise MailboxError(
                MailboxErrorCode.INVALID_ROOT,
                "mailbox root must be fresh; existing state is never resumed",
            ) from exc
        except MailboxError:
            raise
        except (BlockingIOError, OSError) as exc:
            raise MailboxError(
                MailboxErrorCode.INVALID_ROOT,
                "cannot create and exclusively own a fresh mailbox tree",
            ) from exc
        finally:
            if case_fd >= 0:
                os.close(case_fd)

    def _open_child_directory(self, parent_fd: int, name: str) -> int:
        descriptor = -1
        try:
            descriptor = os.open(
                name,
                os.O_RDONLY | _O_CLOEXEC | _O_DIRECTORY | _O_NOFOLLOW,
                dir_fd=parent_fd,
            )
            metadata = os.fstat(descriptor)
            if (
                not stat.S_ISDIR(metadata.st_mode)
                or metadata.st_uid != os.geteuid()
                or stat.S_IMODE(metadata.st_mode) & 0o077
                or _mount_id(descriptor) != self._directories.mount_id
            ):
                raise OSError(f"unsafe mailbox directory: {name}")
            result = descriptor
            descriptor = -1
            return result
        finally:
            if descriptor >= 0:
                os.close(descriptor)

    def _raise(
        self,
        code: MailboxErrorCode,
        message: str,
        cause: BaseException | None = None,
    ):
        error = MailboxError(code, message)
        if self._failed is None:
            self._failed = error
        if cause is None:
            raise error
        raise error from cause

    def _require_available(self, *, allow_closed: bool = False) -> None:
        if self._disposed:
            raise MailboxError(
                MailboxErrorCode.CLOSED,
                "mailbox descriptors have been disposed",
            )
        if self._failed is not None:
            raise MailboxError(
                self._failed.code,
                f"mailbox lifecycle is poisoned: {self._failed}",
            ) from self._failed
        if self._closed and not allow_closed:
            raise MailboxError(MailboxErrorCode.CLOSED, "mailbox is closed")

    def _verify_pinned_tree(self) -> None:
        descriptors = self._directories
        try:
            current_path = os.lstat(self.root)
            if (
                not stat.S_ISDIR(current_path.st_mode)
                or _directory_identity(current_path)
                != descriptors._identities["root"]
            ):
                self._raise(
                    MailboxErrorCode.ROOT_CHANGED,
                    "mailbox root path no longer names its pinned directory",
                )
            for name, descriptor in (
                ("root", descriptors.root_fd),
                ("inbox", descriptors.inbox_fd),
                ("outbox", descriptors.outbox_fd),
                ("state", descriptors.state_fd),
                ("submissions", descriptors.submissions_fd),
                ("requests", descriptors.requests_fd),
                ("responses", descriptors.responses_fd),
                ("outgoing", descriptors.outgoing_fd),
            ):
                metadata = os.fstat(descriptor)
                if (
                    _directory_identity(metadata) != descriptors._identities[name]
                    or _mount_id(descriptor) != descriptors.mount_id
                ):
                    self._raise(
                        MailboxErrorCode.ROOT_CHANGED,
                        f"pinned mailbox directory changed: {name}",
                    )
            for name, descriptor in (
                ("inbox", descriptors.inbox_fd),
                ("outbox", descriptors.outbox_fd),
                ("state", descriptors.state_fd),
                ("submissions", descriptors.submissions_fd),
            ):
                entry = os.stat(
                    name,
                    dir_fd=descriptors.root_fd,
                    follow_symlinks=False,
                )
                if _directory_identity(entry) != descriptors._identities[name]:
                    self._raise(
                        MailboxErrorCode.ROOT_CHANGED,
                        f"mailbox child path no longer names pinned {name}",
                    )
            for name, descriptor in (
                ("requests", descriptors.requests_fd),
                ("responses", descriptors.responses_fd),
                ("outgoing", descriptors.outgoing_fd),
            ):
                entry = os.stat(
                    name,
                    dir_fd=descriptors.state_fd,
                    follow_symlinks=False,
                )
                if _directory_identity(entry) != descriptors._identities[name]:
                    self._raise(
                        MailboxErrorCode.ROOT_CHANGED,
                        f"state child path no longer names pinned {name}",
                    )
            lock_path = os.stat(
                "lock",
                dir_fd=descriptors.state_fd,
                follow_symlinks=False,
            )
            lock_fd = os.fstat(descriptors.lock_fd)
            if (
                descriptors.lock_signature is None
                or _metadata_signature(lock_path) != descriptors.lock_signature
                or _metadata_signature(lock_fd) != descriptors.lock_signature
                or not stat.S_ISREG(lock_fd.st_mode)
                or lock_fd.st_nlink != 1
                or lock_fd.st_uid != os.geteuid()
                or stat.S_IMODE(lock_fd.st_mode) != 0o600
            ):
                self._raise(
                    MailboxErrorCode.STATE_CONFLICT,
                    "mailbox ownership lock changed",
                )
            if set(
                self._scan_names(
                    descriptors.root_fd,
                    "mailbox root",
                    maximum=5,
                )
            ) != {
                "inbox",
                "outbox",
                "state",
                "submissions",
            }:
                self._raise(
                    MailboxErrorCode.STRAY_ENTRY,
                    "mailbox root contains an unexpected entry",
                )
        except MailboxError:
            raise
        except OSError as exc:
            self._raise(
                MailboxErrorCode.ROOT_CHANGED,
                "cannot verify the pinned mailbox tree",
                exc,
            )

    def _scan_names(
        self,
        directory_fd: int,
        label: str,
        *,
        maximum: int | None = None,
        allow_concurrent_publication: bool = False,
    ) -> tuple[str, ...]:
        try:
            if maximum is None:
                maximum = self.limits.max_staged_entries
            if type(maximum) is not int or maximum < 0:
                raise ValueError("directory scan maximum must be non-negative")
            if type(allow_concurrent_publication) is not bool:
                raise ValueError(
                    "allow_concurrent_publication must be an exact boolean"
                )
            attempts = (
                _AGENT_WRITABLE_SCAN_ATTEMPTS
                if allow_concurrent_publication
                else 1
            )
            for _ in range(attempts):
                before = os.fstat(directory_fd)
                with os.scandir(directory_fd) as iterator:
                    collected: list[str] = []
                    for entry in iterator:
                        collected.append(entry.name)
                        if len(collected) > maximum:
                            self._raise(
                                MailboxErrorCode.PAYLOAD_LIMIT_EXCEEDED,
                                f"{label} exceeds its entry-count bound",
                            )
                    names = tuple(
                        sorted(
                            collected,
                            key=lambda value: value.encode(
                                "utf-8",
                                "surrogatepass",
                            ),
                        )
                    )
                after = os.fstat(directory_fd)
                if _metadata_signature(before) == _metadata_signature(after):
                    return names
            self._raise(
                MailboxErrorCode.SOURCE_CHANGED,
                f"{label} changed while being scanned",
            )
        except MailboxError:
            raise
        except (OSError, UnicodeError) as exc:
            self._raise(
                MailboxErrorCode.SOURCE_CHANGED,
                f"cannot stably scan {label}",
                exc,
            )

    def _assert_state_shape(self, *, verify_history: bool = False) -> None:
        descriptors = self._directories
        state_names = set(
            self._scan_names(descriptors.state_fd, "host state", maximum=5)
        )
        expected_state = {"lock", "requests", "responses", "outgoing"}
        if self._closed:
            expected_state.add("closed.json")
        if state_names != expected_state:
            self._raise(
                MailboxErrorCode.STATE_CONFLICT,
                "host-only state contains a missing or unexpected entry",
            )
        if self._scan_names(
            descriptors.outgoing_fd,
            "outgoing state",
            maximum=1,
        ):
            self._raise(
                MailboxErrorCode.STATE_CONFLICT,
                "outgoing state contains an abandoned publication",
            )
        if not verify_history:
            self._verify_close_marker_if_needed()
            return
        request_names = self._scan_names(
            descriptors.requests_fd,
            "request state",
            maximum=self.limits.max_requests,
        )
        expected_requests = {str(nonce) for nonce in self._claimed}
        if set(request_names) != expected_requests or any(
            _NONCE_DIRECTORY_RE.fullmatch(name) is None for name in request_names
        ):
            self._raise(
                MailboxErrorCode.STATE_CONFLICT,
                "request state does not exactly match consumed nonces",
            )
        response_names = self._scan_names(
            descriptors.responses_fd,
            "response state",
            maximum=self.limits.max_requests,
        )
        expected_responses = {_response_name(nonce) for nonce in self._responses}
        if set(response_names) != expected_responses:
            self._raise(
                MailboxErrorCode.STATE_CONFLICT,
                "response state does not exactly match published nonces",
            )
        for nonce, expected in self._responses.items():
            payload, _ = _read_regular_at(
                descriptors.responses_fd,
                _response_name(nonce),
                maximum=self.limits.max_response_bytes,
                expected_mount_id=descriptors.mount_id,
                require_owner=True,
                require_mode=0o400,
            )
            if not expected.matches(payload):
                self._raise(
                    MailboxErrorCode.STATE_CONFLICT,
                    "persisted response state changed",
                )
            claimed = self._claimed.get(nonce)
            if (
                type(claimed) is not _ConsumedRequestBinding
                or claimed.response_sha256 != expected.content_sha256
                or claimed.request_sha256 != expected.request_sha256
            ):
                self._raise(
                    MailboxErrorCode.STATE_CONFLICT,
                    "response state is not bound to its consumed request",
                )
        for nonce, claimed in self._claimed.items():
            if type(claimed) is _ConsumedRequestBinding:
                self._verify_consumed_state(nonce, claimed)
        self._verify_close_marker_if_needed()

    def _verify_close_marker_if_needed(self) -> None:
        if not self._closed:
            return
        if self._closed_marker is None:
            self._raise(
                MailboxErrorCode.STATE_CONFLICT,
                "closed mailbox has no bound close marker",
            )
        marker, _ = _read_regular_at(
            self._directories.state_fd,
            "closed.json",
            maximum=self.limits.max_response_bytes,
            expected_mount_id=self._directories.mount_id,
            require_owner=True,
            require_mode=0o400,
        )
        if marker != self._closed_marker:
            self._raise(
                MailboxErrorCode.STATE_CONFLICT,
                "mailbox close marker changed",
            )

    def _assert_outbox_shape(self) -> None:
        names = self._scan_names(
            self._directories.outbox_fd,
            "outbox",
            maximum=self.limits.max_requests,
        )
        expected = {_response_name(nonce) for nonce in self._responses}
        if set(names) != expected:
            self._raise(
                MailboxErrorCode.OUTBOX_CONFLICT,
                "outbox does not exactly match published responses",
            )

    def _scan_request_nonces(self) -> tuple[int, ...]:
        names = self._scan_names(
            self._directories.inbox_fd,
            "inbox",
            maximum=2,
            allow_concurrent_publication=True,
        )
        nonces: list[int] = []
        for name in names:
            match = _REQUEST_NAME_RE.fullmatch(name)
            if match is None:
                self._raise(
                    MailboxErrorCode.STRAY_ENTRY,
                    f"inbox contains an unexpected entry: {name!r}",
                )
            nonces.append(int(match.group(1), 10))
        return tuple(nonces)

    def _scan_submission_nonces(
        self,
        *,
        expected_nonce: int | None,
        force_rescan: bool = False,
    ) -> None:
        descriptor = self._directories.submissions_fd
        try:
            before = _metadata_signature(os.fstat(descriptor))
        except OSError as exc:
            self._raise(
                MailboxErrorCode.SOURCE_CHANGED,
                "cannot inspect the submissions namespace",
                exc,
            )
        context = (len(self._claimed), expected_nonce, self._closed)
        if (
            not force_rescan
            and before == self._submissions_directory_signature
            and context == self._submission_validation_context
        ):
            return
        if (
            not force_rescan
            and before == self._submissions_directory_signature
        ):
            nonces = self._known_submission_nonces
        else:
            for _ in range(_AGENT_WRITABLE_SCAN_ATTEMPTS):
                try:
                    before = _metadata_signature(os.fstat(descriptor))
                    names = self._scan_names(
                        descriptor,
                        "submissions",
                        maximum=self.limits.max_requests + 1,
                        allow_concurrent_publication=True,
                    )
                    after = _metadata_signature(os.fstat(descriptor))
                except OSError as exc:
                    self._raise(
                        MailboxErrorCode.SOURCE_CHANGED,
                        "cannot stably inspect the submissions namespace",
                        exc,
                    )
                if before == after:
                    break
            else:
                self._raise(
                    MailboxErrorCode.SOURCE_CHANGED,
                    "submissions changed while its nonce set was inspected",
                )
            parsed: set[int] = set()
            for name in names:
                match = _NONCE_DIRECTORY_RE.fullmatch(name)
                if match is None:
                    self._raise(
                        MailboxErrorCode.STRAY_ENTRY,
                        f"submissions contains an unexpected entry: {name!r}",
                    )
                parsed.add(int(match.group(1), 10))
            nonces = frozenset(parsed)

        for nonce in self._claimed:
            if nonce not in nonces:
                self._raise(
                    MailboxErrorCode.LATE_REQUEST,
                    f"submission namespace {nonce} disappeared after its freeze boundary",
                )
        allowed = set(self._claimed)
        if expected_nonce is not None:
            allowed.add(expected_nonce)
        for nonce in nonces:
            if nonce not in allowed:
                code = MailboxErrorCode.LATE_REQUEST if self._closed else (
                    MailboxErrorCode.NONCE_REPLAY
                    if nonce < self._next_nonce
                    else MailboxErrorCode.NONCE_GAP
                )
                self._raise(code, f"unexpected submission namespace nonce {nonce}")
        self._submissions_directory_signature = before
        self._known_submission_nonces = nonces
        self._submission_validation_context = context

    def _preflight(
        self,
        *,
        expected_nonce: int | None,
        verify_history: bool = False,
    ) -> None:
        self._verify_pinned_tree()
        self._assert_state_shape(verify_history=verify_history)
        if verify_history:
            self._assert_outbox_shape()
        self._scan_submission_nonces(
            expected_nonce=expected_nonce,
            force_rescan=verify_history,
        )

    def _require_claim_lifecycle_capacity(
        self,
        *,
        transport_bytes: int,
        payload_bytes: int,
        staged_entries: int,
    ) -> None:
        checks = (
            (
                self._lifecycle_request_bytes,
                transport_bytes,
                self.limits.max_lifecycle_request_bytes,
                "request bytes",
            ),
            (
                self._lifecycle_payload_bytes,
                payload_bytes,
                self.limits.max_lifecycle_payload_bytes,
                "payload bytes",
            ),
            (
                self._lifecycle_staged_entries,
                staged_entries,
                self.limits.max_lifecycle_staged_entries,
                "staged entries",
            ),
        )
        for consumed, requested, maximum, label in checks:
            if consumed + requested > maximum:
                self._raise(
                    MailboxErrorCode.PAYLOAD_LIMIT_EXCEEDED,
                    f"mailbox lifecycle exceeds its aggregate {label} bound",
                )

    def _open_relative_parent(
        self,
        relative_path: str,
    ) -> tuple[int, str, list[tuple[int, tuple[int, ...]]]]:
        parts = relative_path.split("/")
        descriptor = -1
        opened: list[tuple[int, tuple[int, ...]]] = []
        try:
            descriptor = os.dup(self._directories.root_fd)
            opened.append((descriptor, ()))
            opened[0] = (
                descriptor,
                _metadata_signature(os.fstat(descriptor)),
            )
            for component in parts[:-1]:
                expected = os.stat(
                    component,
                    dir_fd=descriptor,
                    follow_symlinks=False,
                )
                if not stat.S_ISDIR(expected.st_mode):
                    raise MailboxError(
                        MailboxErrorCode.UNSAFE_ENTRY,
                        f"staged path component is not a directory: {component}",
                    )
                child = os.open(
                    component,
                    os.O_RDONLY | _O_CLOEXEC | _O_DIRECTORY | _O_NOFOLLOW,
                    dir_fd=descriptor,
                )
                # Register the descriptor before any fstat/mount check so the
                # common exception cleanup owns every successfully opened fd.
                opened.append((child, ()))
                current = os.fstat(child)
                if (
                    _metadata_signature(expected) != _metadata_signature(current)
                    or _mount_id(child) != self._directories.mount_id
                ):
                    raise MailboxError(
                        MailboxErrorCode.SOURCE_CHANGED,
                        f"staged directory changed while opening: {component}",
                )
                descriptor = child
                opened[-1] = (descriptor, _metadata_signature(current))
            return descriptor, parts[-1], opened
        except BaseException:
            for item, _ in reversed(opened):
                try:
                    os.close(item)
                except OSError:
                    pass
            raise

    def _read_staged_artifact(
        self,
        binding: StagedArtifactBinding,
    ) -> FrozenStagedArtifact:
        artifact = binding.artifact
        if artifact.size_bytes > self.limits.max_single_payload_bytes:
            self._raise(
                MailboxErrorCode.PAYLOAD_LIMIT_EXCEEDED,
                f"artifact exceeds per-file mailbox bound: {binding.relative_path}",
            )
        opened: list[tuple[int, tuple[int, ...]]] = []
        try:
            parent_fd, name, opened = self._open_relative_parent(
                binding.relative_path
            )
            payload, _ = _read_regular_at(
                parent_fd,
                name,
                maximum=self.limits.max_single_payload_bytes,
                expected_size=artifact.size_bytes,
                expected_mount_id=self._directories.mount_id,
            )
            for descriptor, signature in opened:
                if _metadata_signature(os.fstat(descriptor)) != signature:
                    self._raise(
                        MailboxErrorCode.SOURCE_CHANGED,
                        f"staged path changed while reading: {binding.relative_path}",
                    )
            if hashlib.sha256(payload).hexdigest() != artifact.content_sha256:
                self._raise(
                    MailboxErrorCode.PAYLOAD_MISMATCH,
                    f"artifact hash does not match binding: {binding.relative_path}",
                )
            return FrozenStagedArtifact(binding=binding, content=payload)
        except MailboxError as exc:
            if self._failed is None:
                self._failed = exc
            raise
        except OSError as exc:
            self._raise(
                MailboxErrorCode.UNSAFE_ENTRY,
                f"cannot open staged artifact: {binding.relative_path}",
                exc,
            )
        finally:
            for descriptor, _ in reversed(opened):
                try:
                    os.close(descriptor)
                except OSError:
                    pass

    def _scan_submission_tree(
        self,
        request: CoordinatorRequestEnvelope,
    ) -> _SubmissionTreeBinding:
        expected_files = {
            binding.relative_path
            for binding in (request.raw_submission, *request.artifacts)
        }
        expected_directories: set[str] = set()
        for path in expected_files:
            parts = path.split("/")
            for end in range(3, len(parts)):
                expected_directories.add("/".join(parts[:end]))
                if (
                    len(expected_directories) + len(expected_files)
                    > self.limits.max_staged_entries
                ):
                    self._raise(
                        MailboxErrorCode.PAYLOAD_LIMIT_EXCEEDED,
                        "declared staged tree exceeds the entry-count bound",
                    )
        return self._scan_submission_namespace(
            request.nonce,
            expected_files=expected_files,
            expected_directories=expected_directories,
        )

    def _scan_submission_namespace(
        self,
        nonce: int,
        *,
        expected_files: set[str] | None,
        expected_directories: set[str] | None,
    ) -> _SubmissionTreeBinding:
        namespace_name = str(nonce)
        namespace_fd = -1
        observed_files: set[str] = set()
        count = 0
        fingerprint = hashlib.sha256()

        def bind_metadata(path: str, metadata: os.stat_result) -> None:
            encoded_path = path.encode("utf-8", "surrogatepass")
            encoded_metadata = repr(_metadata_signature(metadata)).encode("ascii")
            fingerprint.update(len(encoded_path).to_bytes(8, "big"))
            fingerprint.update(encoded_path)
            fingerprint.update(len(encoded_metadata).to_bytes(8, "big"))
            fingerprint.update(encoded_metadata)

        try:
            namespace_fd = self._open_child_untrusted_directory(
                self._directories.submissions_fd,
                namespace_name,
            )

            def visit(directory_fd: int, relative: str) -> None:
                nonlocal count
                before = os.fstat(directory_fd)
                bind_metadata(relative, before)
                names = self._scan_names(
                    directory_fd,
                    f"staged tree {relative}",
                    maximum=self.limits.max_staged_entries - count,
                )
                for name in names:
                    count += 1
                    if count > self.limits.max_staged_entries:
                        self._raise(
                            MailboxErrorCode.PAYLOAD_LIMIT_EXCEEDED,
                            "staged tree exceeds the entry-count bound",
                        )
                    path = f"{relative}/{name}"
                    metadata = os.stat(
                        name,
                        dir_fd=directory_fd,
                        follow_symlinks=False,
                    )
                    if stat.S_ISDIR(metadata.st_mode):
                        if (
                            expected_directories is not None
                            and path not in expected_directories
                        ):
                            self._raise(
                                MailboxErrorCode.STRAY_ENTRY,
                                f"staged tree contains an undeclared directory: {path}",
                            )
                        child = self._open_child_untrusted_directory(directory_fd, name)
                        try:
                            visit(child, path)
                        finally:
                            os.close(child)
                    elif stat.S_ISREG(metadata.st_mode):
                        if metadata.st_nlink != 1:
                            self._raise(
                                MailboxErrorCode.UNSAFE_ENTRY,
                                f"staged tree contains a hard-linked file: {path}",
                            )
                        if expected_files is not None and path not in expected_files:
                            self._raise(
                                MailboxErrorCode.STRAY_ENTRY,
                                f"staged tree contains an undeclared file: {path}",
                            )
                        observed_files.add(path)
                        bind_metadata(path, metadata)
                    else:
                        self._raise(
                            MailboxErrorCode.UNSAFE_ENTRY,
                            f"staged tree contains a symlink or special entry: {path}",
                        )
                if _metadata_signature(os.fstat(directory_fd)) != _metadata_signature(
                    before
                ):
                    self._raise(
                        MailboxErrorCode.SOURCE_CHANGED,
                        f"staged directory changed while scanning: {relative}",
                    )

            visit(namespace_fd, f"submissions/{nonce}")
            if expected_files is not None and observed_files != expected_files:
                self._raise(
                    MailboxErrorCode.PAYLOAD_MISMATCH,
                    "staged tree does not contain every bound artifact exactly once",
                )
            return _SubmissionTreeBinding(
                entry_count=count,
                metadata_sha256=fingerprint.hexdigest(),
            )
        except MailboxError:
            raise
        except (OSError, RecursionError) as exc:
            self._raise(
                MailboxErrorCode.UNSAFE_ENTRY,
                "cannot safely scan the staged submission tree",
                exc,
            )
        finally:
            if namespace_fd >= 0:
                os.close(namespace_fd)

    def _open_child_untrusted_directory(self, parent_fd: int, name: str) -> int:
        before = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        if not stat.S_ISDIR(before.st_mode):
            raise MailboxError(
                MailboxErrorCode.UNSAFE_ENTRY,
                f"staged entry is not a directory: {name}",
            )
        descriptor = -1
        try:
            descriptor = os.open(
                name,
                os.O_RDONLY | _O_CLOEXEC | _O_DIRECTORY | _O_NOFOLLOW,
                dir_fd=parent_fd,
            )
            after = os.fstat(descriptor)
            if (
                _metadata_signature(before) != _metadata_signature(after)
                or _mount_id(descriptor) != self._directories.mount_id
            ):
                raise MailboxError(
                    MailboxErrorCode.SOURCE_CHANGED,
                    f"staged directory changed while opening: {name}",
                )
            result = descriptor
            descriptor = -1
            return result
        finally:
            if descriptor >= 0:
                os.close(descriptor)

    def _persist_frozen_request(
        self,
        frozen: FrozenCoordinatorRequest,
        transport_payload: bytes,
    ) -> None:
        nonce_name = str(frozen.envelope.nonce)
        descriptor = -1
        try:
            os.mkdir(nonce_name, 0o700, dir_fd=self._directories.requests_fd)
            os.chmod(
                nonce_name,
                0o700,
                dir_fd=self._directories.requests_fd,
                follow_symlinks=False,
            )
            descriptor = self._open_child_directory(
                self._directories.requests_fd,
                nonce_name,
            )
            manifest = self._frozen_manifest_bytes(frozen)
            _write_new_file_at(
                descriptor,
                "envelope.json",
                frozen.envelope.to_json(),
                final_mode=0o400,
            )
            _write_new_file_at(
                descriptor,
                "transport.json",
                transport_payload,
                final_mode=0o400,
            )
            _write_new_file_at(
                descriptor,
                "manifest.json",
                manifest,
                final_mode=0o400,
            )
            for index, item in enumerate(frozen.all_artifacts):
                _write_new_file_at(
                    descriptor,
                    f"payload-{index:04d}.bin",
                    item.content,
                    final_mode=0o400,
                )
            os.fsync(descriptor)
            os.fchmod(descriptor, 0o500)
            os.fsync(descriptor)
            os.fsync(self._directories.requests_fd)
        except FileExistsError as exc:
            self._raise(
                MailboxErrorCode.STATE_CONFLICT,
                f"request state for nonce {nonce_name} was precreated",
                exc,
            )
        except MailboxError:
            raise
        except OSError as exc:
            self._raise(
                MailboxErrorCode.IO_FAILURE,
                "cannot persist frozen request into host-only state",
                exc,
            )
        finally:
            if descriptor >= 0:
                os.close(descriptor)

    def _verify_frozen_state(self, frozen: FrozenCoordinatorRequest) -> None:
        descriptor = -1
        try:
            descriptor = self._open_child_directory(
                self._directories.requests_fd,
                str(frozen.envelope.nonce),
            )
            expected_names = self._frozen_state_names(frozen)
            if set(
                self._scan_names(
                    descriptor,
                    "frozen request state",
                    maximum=self.limits.max_artifacts + 4,
                )
            ) != expected_names:
                self._raise(
                    MailboxErrorCode.STATE_CONFLICT,
                    "frozen request state contains an unexpected entry",
                )
            envelope_payload, _ = _read_regular_at(
                descriptor,
                "envelope.json",
                maximum=self.limits.max_request_bytes,
                expected_mount_id=self._directories.mount_id,
                require_owner=True,
                require_mode=0o400,
            )
            if envelope_payload != frozen.envelope.to_json():
                self._raise(
                    MailboxErrorCode.STATE_CONFLICT,
                    "persisted request envelope changed",
                )
            transport_payload, _ = _read_regular_at(
                descriptor,
                "transport.json",
                maximum=self.limits.max_request_bytes,
                expected_mount_id=self._directories.mount_id,
                require_owner=True,
                require_mode=0o400,
            )
            if (
                transport_payload != frozen.transport_bytes
                or hashlib.sha256(transport_payload).hexdigest()
                != frozen.transport_sha256
            ):
                self._raise(
                    MailboxErrorCode.STATE_CONFLICT,
                    "persisted request transport changed",
                )
            manifest_payload, _ = _read_regular_at(
                descriptor,
                "manifest.json",
                maximum=self.limits.max_request_bytes,
                expected_mount_id=self._directories.mount_id,
                require_owner=True,
                require_mode=0o400,
            )
            if manifest_payload != self._frozen_manifest_bytes(frozen):
                self._raise(
                    MailboxErrorCode.STATE_CONFLICT,
                    "persisted request manifest changed",
                )
            for index, item in enumerate(frozen.all_artifacts):
                payload, _ = _read_regular_at(
                    descriptor,
                    f"payload-{index:04d}.bin",
                    maximum=self.limits.max_single_payload_bytes,
                    expected_size=len(item.content),
                    expected_mount_id=self._directories.mount_id,
                    require_owner=True,
                    require_mode=0o400,
                )
                if payload != item.content:
                    self._raise(
                        MailboxErrorCode.STATE_CONFLICT,
                        "persisted frozen artifact changed",
                    )
        except MailboxError:
            raise
        except OSError as exc:
            self._raise(
                MailboxErrorCode.STATE_CONFLICT,
                "cannot verify persisted frozen request",
                exc,
            )
        finally:
            if descriptor >= 0:
                os.close(descriptor)

    @staticmethod
    def _frozen_state_names(frozen: FrozenCoordinatorRequest) -> set[str]:
        return {
            "envelope.json",
            "transport.json",
            "manifest.json",
            *(
                f"payload-{index:04d}.bin"
                for index in range(len(frozen.all_artifacts))
            ),
        }

    def _compact_frozen_state(
        self,
        frozen: FrozenCoordinatorRequest,
        *,
        response_sha256: str,
    ) -> _ConsumedRequestBinding:
        """Replace large transient host copies with one hash-only binding."""

        nonce = frozen.envelope.nonce
        tree = self._submission_bindings[nonce]
        binding = _ConsumedRequestBinding(
            nonce=nonce,
            agent_session_id=self.agent_session_id,
            request_sha256=frozen.request_sha256,
            transport_sha256=frozen.transport_sha256,
            frozen_manifest_sha256=hashlib.sha256(
                self._frozen_manifest_bytes(frozen)
            ).hexdigest(),
            response_sha256=response_sha256,
            declared_payload_bytes=frozen.envelope.declared_size_bytes,
            transport_size_bytes=len(frozen.transport_bytes),
            artifact_count=len(frozen.all_artifacts),
            submission_tree=tree,
        )
        descriptor = -1
        temporary_name = f".binding-{uuid.uuid4().hex}.tmp"
        try:
            descriptor = self._open_child_directory(
                self._directories.requests_fd,
                str(nonce),
            )
            os.fchmod(descriptor, 0o700)
            _write_new_file_at(
                descriptor,
                temporary_name,
                binding.to_bytes(),
                final_mode=0o400,
            )
            for name in sorted(self._frozen_state_names(frozen)):
                os.unlink(name, dir_fd=descriptor)
            _rename_noreplace_at(
                descriptor,
                temporary_name,
                descriptor,
                "binding.json",
            )
            os.fsync(descriptor)
            os.fchmod(descriptor, 0o500)
            os.fsync(descriptor)
            os.fsync(self._directories.requests_fd)
            return binding
        except MailboxError:
            raise
        except OSError as exc:
            self._raise(
                MailboxErrorCode.STATE_CONFLICT,
                "cannot compact consumed request state",
                exc,
            )
        finally:
            if descriptor >= 0:
                os.close(descriptor)

    def _verify_consumed_state(
        self,
        nonce: int,
        binding: _ConsumedRequestBinding,
    ) -> None:
        descriptor = -1
        try:
            descriptor = self._open_child_directory(
                self._directories.requests_fd,
                str(nonce),
            )
            if self._scan_names(
                descriptor,
                "consumed request state",
                maximum=2,
            ) != ("binding.json",):
                self._raise(
                    MailboxErrorCode.STATE_CONFLICT,
                    "consumed request state is not compact and exact",
                )
            payload, _ = _read_regular_at(
                descriptor,
                "binding.json",
                maximum=self.limits.max_request_bytes,
                expected_size=len(binding.to_bytes()),
                expected_mount_id=self._directories.mount_id,
                require_owner=True,
                require_mode=0o400,
            )
            if payload != binding.to_bytes():
                self._raise(
                    MailboxErrorCode.STATE_CONFLICT,
                    "consumed request binding changed",
                )
        except MailboxError:
            raise
        except OSError as exc:
            self._raise(
                MailboxErrorCode.STATE_CONFLICT,
                "cannot verify consumed request binding",
                exc,
            )
        finally:
            if descriptor >= 0:
                os.close(descriptor)

    def _verify_published_response(
        self,
        directory_fd: int,
        nonce: int,
        binding: _PublishedResponseBinding,
        *,
        require_owner: bool,
    ) -> None:
        payload, _ = _read_regular_at(
            directory_fd,
            _response_name(nonce),
            maximum=self.limits.max_response_bytes,
            expected_size=binding.size_bytes,
            expected_mount_id=self._directories.mount_id,
            require_owner=require_owner,
            require_mode=0o400 if require_owner else None,
        )
        if not binding.matches(payload):
            code = (
                MailboxErrorCode.STATE_CONFLICT
                if directory_fd == self._directories.responses_fd
                else MailboxErrorCode.OUTBOX_CONFLICT
            )
            self._raise(code, "published response changed after publication")

    @staticmethod
    def _frozen_manifest_bytes(frozen: FrozenCoordinatorRequest) -> bytes:
        return canonical_json_bytes(
            {
                "request_sha256": frozen.request_sha256,
                "transport_sha256": frozen.transport_sha256,
                "payloads": [
                    {
                        "state_name": f"payload-{index:04d}.bin",
                        "binding": item.binding.to_document(),
                    }
                    for index, item in enumerate(frozen.all_artifacts)
                ],
            }
        )

    def claim_next(
        self,
        expected_nonce: int,
        is_agent_alive: Callable[[], bool],
        *,
        timeout_seconds: int | float | None = None,
        poll_interval_seconds: int | float | None = None,
        timeout_ms: int | None = None,
        poll_interval_ms: int | None = None,
    ) -> FrozenCoordinatorRequest:
        """Wait for, validate, consume, and freeze exactly the next request."""

        self._require_available()
        if type(expected_nonce) is not int or expected_nonce < 1:
            raise ValueError("expected_nonce must be a positive integer")
        if expected_nonce != self._next_nonce or expected_nonce > self.limits.max_requests:
            self._raise(
                MailboxErrorCode.INVALID_NONCE,
                "expected_nonce is not the mailbox's strictly next bounded nonce",
            )
        if not callable(is_agent_alive):
            raise TypeError("is_agent_alive must be callable")
        if self._outstanding is not None:
            self._raise(
                MailboxErrorCode.OUTSTANDING_REQUEST,
                "one request is already outstanding",
            )
        if timeout_seconds is not None and timeout_ms is not None:
            raise ValueError("provide timeout_seconds or timeout_ms, not both")
        if timeout_seconds is None and timeout_ms is None:
            raise ValueError("one timeout value is required")
        if timeout_ms is not None:
            if type(timeout_ms) is not int or timeout_ms < 0:
                raise ValueError("timeout_ms must be a non-negative integer")
            timeout_seconds = timeout_ms / 1000
        if poll_interval_seconds is not None and poll_interval_ms is not None:
            raise ValueError(
                "provide poll_interval_seconds or poll_interval_ms, not both"
            )
        if poll_interval_ms is not None:
            if type(poll_interval_ms) is not int or poll_interval_ms < 1:
                raise ValueError("poll_interval_ms must be a positive integer")
            poll_interval_seconds = poll_interval_ms / 1000
        if poll_interval_seconds is None:
            poll_interval_seconds = 0.01
        timeout = _seconds(timeout_seconds, "timeout_seconds", allow_zero=True)
        interval = _seconds(
            poll_interval_seconds, "poll_interval_seconds", allow_zero=False
        )
        deadline = time.monotonic() + timeout
        while True:
            self._preflight(expected_nonce=expected_nonce)
            nonces = self._scan_request_nonces()
            if len(nonces) > 1:
                self._raise(
                    MailboxErrorCode.MULTIPLE_REQUESTS,
                    "mailbox permits exactly one outstanding request",
                )
            if nonces:
                actual = nonces[0]
                if actual < expected_nonce:
                    self._raise(
                        MailboxErrorCode.NONCE_REPLAY,
                        f"request nonce {actual} replays an already-consumed nonce",
                    )
                if actual > expected_nonce:
                    self._raise(
                        MailboxErrorCode.NONCE_GAP,
                        f"request nonce {actual} skips expected nonce {expected_nonce}",
                    )
                break
            try:
                alive = is_agent_alive()
            except BaseException as exc:
                self._raise(
                    MailboxErrorCode.LIVENESS_CHECK_FAILED,
                    "trusted Agent liveness callback failed",
                    exc,
                )
            if type(alive) is not bool:
                self._raise(
                    MailboxErrorCode.LIVENESS_CHECK_FAILED,
                    "trusted Agent liveness callback must return an exact bool",
                )
            if not alive:
                self._raise(
                    MailboxErrorCode.AGENT_EXITED,
                    "Agent exited before publishing the expected request",
                )
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                self._raise(
                    MailboxErrorCode.TIMEOUT,
                    "timed out waiting for the expected Agent request",
                )
            time.sleep(min(interval, remaining))

        request_name = _request_name(expected_nonce)
        try:
            transport, request_signature = _read_regular_at(
                self._directories.inbox_fd,
                request_name,
                maximum=self.limits.max_request_bytes,
                expected_mount_id=self._directories.mount_id,
            )
        except MailboxError as exc:
            if exc.code is MailboxErrorCode.PAYLOAD_LIMIT_EXCEEDED:
                self._raise(
                    MailboxErrorCode.REQUEST_TOO_LARGE,
                    "Coordinator request exceeds the request-byte bound",
                    exc,
                )
            self._failed = self._failed or exc
            raise
        try:
            request = CoordinatorRequestEnvelope.from_json(transport)
        except (AttributeError, ContractError, TypeError, ValueError) as exc:
            self._raise(
                MailboxErrorCode.INVALID_REQUEST,
                "Coordinator request envelope is invalid",
                exc,
            )
        if request.agent_session_id != self.agent_session_id:
            self._raise(
                MailboxErrorCode.SESSION_MISMATCH,
                "Coordinator request belongs to a different Agent session",
            )
        if request.nonce != expected_nonce:
            self._raise(
                MailboxErrorCode.INVALID_NONCE,
                "request filename and body nonce differ",
            )
        if expected_nonce == 1:
            expected_previous_response_sha256 = None
        else:
            previous_response = self._responses.get(expected_nonce - 1)
            if previous_response is None:
                self._raise(
                    MailboxErrorCode.STATE_CONFLICT,
                    "mailbox lost the prior response chain binding",
                )
            expected_previous_response_sha256 = (
                previous_response.content_sha256
            )
        if (
            request.previous_response_sha256
            != expected_previous_response_sha256
        ):
            self._raise(
                MailboxErrorCode.RESPONSE_MISMATCH,
                "request does not acknowledge the exact previous response",
            )
        if len(request.artifacts) > self.limits.max_artifacts:
            self._raise(
                MailboxErrorCode.PAYLOAD_LIMIT_EXCEEDED,
                "request exceeds the artifact-count bound",
            )
        if request.declared_size_bytes > self.limits.max_total_payload_bytes:
            self._raise(
                MailboxErrorCode.PAYLOAD_LIMIT_EXCEEDED,
                "request exceeds the aggregate payload-byte bound",
            )

        initial_tree = self._scan_submission_tree(request)
        self._require_claim_lifecycle_capacity(
            transport_bytes=len(transport),
            payload_bytes=request.declared_size_bytes,
            staged_entries=initial_tree.entry_count,
        )
        raw = self._read_staged_artifact(request.raw_submission)
        artifacts = tuple(
            self._read_staged_artifact(binding) for binding in request.artifacts
        )
        final_tree = self._scan_submission_tree(request)
        if final_tree != initial_tree:
            self._raise(
                MailboxErrorCode.SOURCE_CHANGED,
                "staged submission tree changed across the freeze operation",
            )
        frozen = FrozenCoordinatorRequest(
            envelope=request,
            request_sha256=request.content_sha256,
            transport_sha256=hashlib.sha256(transport).hexdigest(),
            transport_bytes=transport,
            raw_submission=raw,
            artifacts=artifacts,
        )
        self._persist_frozen_request(frozen, transport)

        # Consume only the inode we actually read.  Replacement or mutation
        # poisons the lifecycle instead of accidentally consuming another file.
        try:
            current = os.stat(
                request_name,
                dir_fd=self._directories.inbox_fd,
                follow_symlinks=False,
            )
            if _metadata_signature(current) != request_signature:
                self._raise(
                    MailboxErrorCode.SOURCE_CHANGED,
                    "request changed after it was frozen",
                )
            os.unlink(request_name, dir_fd=self._directories.inbox_fd)
            os.fsync(self._directories.inbox_fd)
        except MailboxError:
            raise
        except OSError as exc:
            self._raise(
                MailboxErrorCode.SOURCE_CHANGED,
                "cannot consume the exact frozen request inode",
                exc,
            )

        self._claimed[expected_nonce] = frozen
        self._submission_bindings[expected_nonce] = final_tree
        self._lifecycle_request_bytes += len(transport)
        self._lifecycle_payload_bytes += request.declared_size_bytes
        self._lifecycle_staged_entries += final_tree.entry_count
        self._outstanding = frozen
        self._assert_state_shape()
        return frozen

    def _ensure_no_pipelined_request(self) -> None:
        nonces = self._scan_request_nonces()
        if nonces:
            self._raise(
                MailboxErrorCode.OUTSTANDING_REQUEST,
                "Agent published another request before receiving its response",
            )

    def publish_response(
        self,
        response: CoordinatorResponseEnvelope,
        frozen_request: FrozenCoordinatorRequest,
    ) -> str:
        """Persist host response state, then atomically expose an outbox copy."""

        self._require_available(allow_closed=True)
        if type(response) is not CoordinatorResponseEnvelope:
            raise TypeError("response must be a CoordinatorResponseEnvelope")
        if type(frozen_request) is not FrozenCoordinatorRequest:
            raise TypeError("frozen_request must be a FrozenCoordinatorRequest")
        if self._outstanding is None or frozen_request is not self._outstanding:
            self._raise(
                MailboxErrorCode.RESPONSE_MISMATCH,
                "response does not target the exact outstanding frozen request",
            )
        try:
            frozen_request.validate_integrity()
        except (TypeError, ValueError) as exc:
            self._raise(
                MailboxErrorCode.RESPONSE_MISMATCH,
                "outstanding frozen request failed its integrity recheck",
                exc,
            )
        try:
            reparsed_response = CoordinatorResponseEnvelope.from_json(
                response.to_json()
            )
            if reparsed_response != response:
                raise ContractError("response is not a canonical contract value")
            reparsed_response.validate_request(frozen_request.envelope)
        except (AttributeError, ContractError, TypeError, ValueError) as exc:
            self._raise(
                MailboxErrorCode.RESPONSE_MISMATCH,
                "response does not bind the outstanding request",
                exc,
            )
        payload = reparsed_response.to_json()
        if len(payload) > self.limits.max_response_bytes:
            self._raise(
                MailboxErrorCode.RESPONSE_TOO_LARGE,
                "Coordinator response exceeds the response-byte bound",
            )
        if (
            self._lifecycle_response_bytes + len(payload)
            > self.limits.max_lifecycle_response_bytes
        ):
            self._raise(
                MailboxErrorCode.RESPONSE_TOO_LARGE,
                "Coordinator responses exceed the lifecycle aggregate-byte bound",
            )
        response_binding = _PublishedResponseBinding.create(
            payload,
            request_sha256=frozen_request.request_sha256,
        )
        if response_binding.content_sha256 != reparsed_response.content_sha256:
            self._raise(
                MailboxErrorCode.RESPONSE_MISMATCH,
                "published response bytes do not match the response content hash",
            )
        self._preflight(
            expected_nonce=(None if self._closed else self._next_nonce)
        )
        self._ensure_no_pipelined_request()
        self._verify_frozen_state(frozen_request)
        name = _response_name(response.nonce)
        try:
            for directory_fd, label, code in (
                (self._directories.responses_fd, "state", MailboxErrorCode.STATE_CONFLICT),
                (self._directories.outbox_fd, "outbox", MailboxErrorCode.OUTBOX_CONFLICT),
            ):
                try:
                    os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
                except FileNotFoundError:
                    pass
                else:
                    self._raise(code, f"response {label} was precreated")
            _write_new_file_at(
                self._directories.responses_fd,
                name,
                payload,
                final_mode=0o400,
            )
            os.fsync(self._directories.responses_fd)

            temporary_name = f".{name}-{uuid.uuid4().hex}.tmp"
            _write_new_file_at(
                self._directories.outgoing_fd,
                temporary_name,
                payload,
                final_mode=0o400,
            )
            consumed_binding = self._compact_frozen_state(
                frozen_request,
                response_sha256=response_binding.content_sha256,
            )
            _rename_noreplace_at(
                self._directories.outgoing_fd,
                temporary_name,
                self._directories.outbox_fd,
                name,
            )
            os.fsync(self._directories.outbox_fd)
        except MailboxError:
            raise
        except FileExistsError as exc:
            self._raise(
                MailboxErrorCode.OUTBOX_CONFLICT,
                "response publication would clobber an existing entry",
                exc,
            )
        except OSError as exc:
            self._raise(
                MailboxErrorCode.IO_FAILURE,
                "cannot durably publish Coordinator response",
                exc,
            )
        self._responses[response.nonce] = response_binding
        self._claimed[response.nonce] = consumed_binding
        self._lifecycle_response_bytes += len(payload)
        self._outstanding = None
        self._next_nonce += 1
        self._assert_state_shape()
        self._verify_consumed_state(response.nonce, consumed_binding)
        self._verify_published_response(
            self._directories.responses_fd,
            response.nonce,
            response_binding,
            require_owner=True,
        )
        self._verify_published_response(
            self._directories.outbox_fd,
            response.nonce,
            response_binding,
            require_owner=False,
        )
        return response_binding.content_sha256

    def close(self) -> None:
        """Close request admission; an already-outstanding response may follow."""

        self._require_available(allow_closed=True)
        if self._closed:
            self._verify_pinned_tree()
            self._assert_state_shape()
            return
        # A namespace for the next nonce is already a late/pipelined request.
        # The current outstanding request, when present, is already in
        # ``self._claimed`` and therefore remains allowed.
        self._preflight(expected_nonce=None)
        self._ensure_no_pipelined_request()
        marker = canonical_json_bytes(
            {
                "contract_kind": "coordinator_mailbox_closed",
                "schema_version": 1,
                "agent_session_id": self.agent_session_id,
                "next_nonce": self._next_nonce,
                "outstanding_nonce": (
                    None
                    if self._outstanding is None
                    else self._outstanding.envelope.nonce
                ),
            }
        )
        try:
            _write_new_file_at(
                self._directories.state_fd,
                "closed.json",
                marker,
                final_mode=0o400,
            )
            os.fsync(self._directories.state_fd)
        except FileExistsError as exc:
            self._raise(
                MailboxErrorCode.STATE_CONFLICT,
                "mailbox close marker was precreated",
                exc,
            )
        except OSError as exc:
            self._raise(
                MailboxErrorCode.IO_FAILURE,
                "cannot durably close mailbox admission",
                exc,
            )
        self._closed = True
        self._closed_marker = marker
        self._assert_state_shape()

    def close_requests(self) -> None:
        """Coordinator-facing spelling for closing further request admission."""

        self.close()

    def _verify_submission_unchanged(self, nonce: int) -> None:
        current = self._scan_submission_namespace(
            nonce,
            expected_files=None,
            expected_directories=None,
        )
        if current != self._submission_bindings[nonce]:
            self._raise(
                MailboxErrorCode.LATE_REQUEST,
                f"submission namespace {nonce} changed after its freeze boundary",
            )

    def assert_quiescent(self) -> None:
        """After trusted Agent exit, reject every late or mutated Agent entry."""

        self._require_available(allow_closed=True)
        if not self._closed:
            self._raise(
                MailboxErrorCode.CLOSED,
                "quiescence can be asserted only after admission is closed",
            )
        if self._outstanding is not None:
            self._raise(
                MailboxErrorCode.OUTSTANDING_REQUEST,
                "quiescence requires a response for the outstanding request",
            )
        if (
            set(self._claimed) != set(self._responses)
            or any(
                type(claimed) is not _ConsumedRequestBinding
                for claimed in self._claimed.values()
            )
        ):
            self._raise(
                MailboxErrorCode.STATE_CONFLICT,
                "quiescence requires every claimed request to be compacted and answered",
            )
        self._preflight(expected_nonce=None, verify_history=True)
        nonces = self._scan_request_nonces()
        if nonces:
            self._raise(
                MailboxErrorCode.LATE_REQUEST,
                "Agent published a request after mailbox closure",
            )
        for nonce in sorted(self._claimed):
            self._verify_submission_unchanged(nonce)
            claimed = self._claimed[nonce]
            if type(claimed) is FrozenCoordinatorRequest:
                self._verify_frozen_state(claimed)
        for nonce, expected in self._responses.items():
            self._verify_published_response(
                self._directories.outbox_fd,
                nonce,
                expected,
                require_owner=False,
            )

    @property
    def next_nonce(self) -> int:
        return self._next_nonce

    @property
    def has_outstanding_request(self) -> bool:
        return self._outstanding is not None

    @property
    def is_closed(self) -> bool:
        return self._closed

    @property
    def request_capacity(self) -> int:
        """Maximum nonce count admitted by this mailbox lifecycle."""

        return self.limits.max_requests

    @property
    def agent_endpoint(self) -> AgentMailboxClient:
        return self.agent_client

    def dispose(self) -> None:
        """Release local descriptors; the on-disk lifecycle remains abandoned."""

        if not self._disposed:
            self._outstanding = None
            self._claimed.clear()
            self._responses.clear()
            self._submission_bindings.clear()
            self._known_submission_nonces = frozenset()
            self._submissions_directory_signature = None
            self._submission_validation_context = None
            self._closed_marker = None
            self.agent_client._outstanding.clear()
            self.agent_client._previous_response_sha256 = None
            self._directories.close()
            self._disposed = True

    def __del__(self) -> None:  # pragma: no cover - best-effort descriptor hygiene
        try:
            self.dispose()
        except BaseException:
            pass


__all__ = [
    "AgentMailboxClient",
    "CoordinatorMailbox",
    "FrozenCoordinatorRequest",
    "FrozenStagedArtifact",
    "MailboxError",
    "MailboxErrorCode",
    "MailboxLimits",
]

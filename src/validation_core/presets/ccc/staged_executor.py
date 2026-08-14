"""Private executor for staged legacy CCC parity checks.

This module is deliberately not exported by any package ``__init__`` and is
not connected to the production validator.  It wraps the byte-identical
legacy Gate with mandatory injected providers so tests can exercise decision
semantics without launching compilers, agents, production sandboxes, or
publishers.  Lifecycle checks use caller-materialized disposable directories,
but do not claim the generic SnapshotStore or Coordinator trust boundary.
"""

from __future__ import annotations

import copy
import hashlib
import shutil
import stat
from dataclasses import dataclass
from pathlib import Path
from types import FunctionType
from typing import Callable, Iterable

from ...contracts.routing import PresetRef
from ...outcome_loader import (
    LEGACY_CCC_SEMANTIC_NAMESPACE,
    ArchivedLegacyCCCCertificate,
    ArtifactFamily,
    LegacyBindingCheck,
    LegacyBindingState,
    OutcomeLoadError,
    TrustClass,
    load_archived_legacy_certificate,
)
from ....check_submission import Gate, Rejection, ReplayError, parse_records
from ....l1_verifier import verify_l1 as _legacy_verify_l1
from ....phenomenon_runner import (
    NoPhenomenonError,
    PhenomenonError,
    PhenomenonObservation,
    run_phenomenon as run_legacy_phenomenon,
)
from ....validation_artifacts import (
    ArtifactError,
    VerifiedArtifact,
    load_verified_artifact as _legacy_load_verified_artifact,
)
from .preset import CCC_LEGACY_PRESET


def _bind_l1_source_copier(source_copier: Callable) -> Callable:
    """Clone pinned legacy L1 with one call-local source copier binding."""
    if not callable(source_copier):
        raise TypeError("source_copier must be callable")
    private_globals = dict(_legacy_verify_l1.__globals__)
    private_globals["copy_validation_source"] = source_copier
    return FunctionType(
        _legacy_verify_l1.__code__,
        private_globals,
        _legacy_verify_l1.__name__,
        _legacy_verify_l1.__defaults__,
        _legacy_verify_l1.__closure__,
    )


@dataclass(frozen=True)
class _ManifestEntryView:
    manifest_id: str


@dataclass(frozen=True)
class StagedCCCContext:
    """The small context surface consumed by the staged Gate and phenomenon."""

    bug_id: str
    function_id: str
    project_dir: Path
    probe_path: Path
    scratch_dir: Path
    manifest_id: str
    release_ccc: Path
    reference_cc: Path

    def __post_init__(self) -> None:
        for field in ("bug_id", "function_id", "manifest_id"):
            value = getattr(self, field)
            if type(value) is not str or not value:
                raise ValueError(f"{field} must be a non-empty string")
        for field in (
            "project_dir",
            "probe_path",
            "scratch_dir",
            "release_ccc",
            "reference_cc",
        ):
            value = getattr(self, field)
            if not isinstance(value, Path):
                raise TypeError(f"{field} must be a pathlib.Path")

    @property
    def manifest_entry(self) -> _ManifestEntryView:
        return _ManifestEntryView(self.manifest_id)


@dataclass(frozen=True)
class StagedCCCProviders:
    """All external Gate effects; every provider is mandatory and injected."""

    replay_capture: Callable
    coverage_runner: Callable
    phenomenon_runner: Callable
    l1_verifier: Callable

    def __post_init__(self) -> None:
        for field in (
            "replay_capture",
            "coverage_runner",
            "phenomenon_runner",
            "l1_verifier",
        ):
            if not callable(getattr(self, field)):
                raise TypeError(f"{field} must be callable")


@dataclass(frozen=True)
class _L1ManifestEntryView:
    manifest_id: str
    file: str
    fn_name: str
    occurrence: int


@dataclass(frozen=True)
class StagedCCCL1Context:
    """Inputs below one caller-allocated, disposable shadow root.

    This compatibility context is not the future SnapshotStore capability.
    Its trusted caller must allocate a fresh root for each shadow execution.
    """

    bug_id: str
    function_id: str
    shadow_root: Path
    project_dir: Path
    baseline_project_dir: Path
    validation_dir: Path
    scratch_dir: Path
    release_ccc: Path
    reference_cc: Path
    sanity_corpus_dir: Path
    manifest_id: str
    manifest_file: str
    manifest_fn_name: str
    manifest_occurrence: int
    source_sha256: str
    sanity_corpus_sha256: str

    def __post_init__(self) -> None:
        for field in (
            "bug_id",
            "function_id",
            "manifest_id",
            "manifest_file",
            "manifest_fn_name",
        ):
            value = getattr(self, field)
            if type(value) is not str or not value:
                raise ValueError(f"{field} must be a non-empty string")
        if self.bug_id in {".", ".."} or any(
            not (char.isalnum() or char in "._-") for char in self.bug_id
        ):
            raise ValueError("bug_id must be a safe path component")
        manifest_path = Path(self.manifest_file)
        if manifest_path.is_absolute() or ".." in manifest_path.parts \
                or manifest_path.as_posix() != self.manifest_file:
            raise ValueError("manifest_file must be a canonical relative path")
        if type(self.manifest_occurrence) is not int \
                or self.manifest_occurrence < 0:
            raise ValueError("manifest_occurrence must be a non-negative integer")
        for field in ("source_sha256", "sanity_corpus_sha256"):
            value = getattr(self, field)
            if type(value) is not str or len(value) != 64 \
                    or any(char not in "0123456789abcdef" for char in value):
                raise ValueError(f"{field} must be a lowercase SHA-256 digest")

        path_fields = (
            "shadow_root",
            "project_dir",
            "baseline_project_dir",
            "validation_dir",
            "scratch_dir",
            "release_ccc",
            "reference_cc",
            "sanity_corpus_dir",
        )
        for field in path_fields:
            path = getattr(self, field)
            if not isinstance(path, Path) or not path.is_absolute():
                raise TypeError(f"{field} must be an absolute pathlib.Path")

        root = self.shadow_root.resolve()
        if root != self.shadow_root:
            raise ValueError("shadow_root must be resolved")
        if root.parent == root or root.is_symlink() or not root.is_dir():
            raise ValueError("shadow_root must be a dedicated existing directory")
        contained_fields = (
            "project_dir",
            "baseline_project_dir",
            "validation_dir",
            "scratch_dir",
            "release_ccc",
            "reference_cc",
            "sanity_corpus_dir",
        )
        for field in contained_fields:
            path = getattr(self, field).resolve()
            try:
                relative = path.relative_to(root)
            except ValueError as exc:
                raise ValueError(f"{field} must stay below shadow_root") from exc
            if not relative.parts:
                raise ValueError(f"{field} must not equal shadow_root")
        try:
            self.validation_dir.resolve().relative_to(self.project_dir.resolve())
            self.release_ccc.resolve().relative_to(self.project_dir.resolve())
        except ValueError as exc:
            raise ValueError(
                "validation_dir and release_ccc must stay below project_dir"
            ) from exc
        if self.project_dir.resolve() == self.baseline_project_dir.resolve():
            raise ValueError("project_dir and baseline_project_dir must be distinct")

    @property
    def manifest_entry(self) -> _L1ManifestEntryView:
        return _L1ManifestEntryView(
            manifest_id=self.manifest_id,
            file=self.manifest_file,
            fn_name=self.manifest_fn_name,
            occurrence=self.manifest_occurrence,
        )


@dataclass(frozen=True)
class StagedCCCL1Providers:
    """All legacy L1 effects; no default host execution is permitted."""

    source_copier: Callable
    command_runner: Callable
    phenomenon_runner: Callable
    sanity_runner: Callable

    def __post_init__(self) -> None:
        for field in (
            "source_copier",
            "command_runner",
            "phenomenon_runner",
            "sanity_runner",
        ):
            if not callable(getattr(self, field)):
                raise TypeError(f"{field} must be callable")


@dataclass(frozen=True)
class StagedCCCArtifactContext:
    """One pre-materialized legacy pair below a disposable shadow root.

    The result/sidecar may be invalid because validity is the subject of the
    shadow check.  The trusted caller still owns allocation and publication;
    this compatibility context is not a SnapshotStore capability or filesystem
    sandbox.  In particular, the pinned sidecar format permits absolute binding
    records, so only a trusted materializer may construct this context.
    """

    bug_id: str
    shadow_root: Path
    project_dir: Path
    result_path: Path

    def __post_init__(self) -> None:
        if type(self.bug_id) is not str or not self.bug_id:
            raise ValueError("bug_id must be a non-empty string")
        if self.bug_id in {".", ".."} or any(
            not (char.isalnum() or char in "._-") for char in self.bug_id
        ):
            raise ValueError("bug_id must be a safe path component")
        for field in ("shadow_root", "project_dir", "result_path"):
            path = getattr(self, field)
            if not isinstance(path, Path) or not path.is_absolute():
                raise TypeError(f"{field} must be an absolute pathlib.Path")

        root = self.shadow_root.resolve()
        project = self.project_dir.resolve()
        if root != self.shadow_root or root.parent == root \
                or root.is_symlink() or not root.is_dir():
            raise ValueError("shadow_root must be a dedicated existing directory")
        if project != self.project_dir or project.is_symlink() \
                or not project.is_dir():
            raise ValueError("project_dir must be a canonical existing directory")
        try:
            relative_project = project.relative_to(root)
        except ValueError as exc:
            raise ValueError("project_dir must stay below shadow_root") from exc
        if not relative_project.parts:
            raise ValueError("project_dir must not equal shadow_root")

        expected = (
            project
            / "fm_agent"
            / "bug_validation"
            / f"{self.bug_id}.result.json"
        )
        if self.result_path != expected:
            raise ValueError("result_path must be the canonical legacy result path")

    @property
    def gate_path(self) -> Path:
        return self.result_path.with_name(f"{self.bug_id}.gate.json")


@dataclass(frozen=True)
class StagedCCCConsumerProviders:
    """The resume side effect is an injected scheduling seam, not an Agent."""

    agent_scheduler: Callable

    def __post_init__(self) -> None:
        if not callable(self.agent_scheduler):
            raise TypeError("agent_scheduler must be callable")


_STAGED_FLOW_ROLES = frozenset({"A", "B1", "B2", "legacy_observer"})
_STAGED_FLOW_EVENT_KINDS = frozenset(
    {"submit", "direct_scratch", "session_exit"}
)


def _require_safe_flow_id(value: object, label: str) -> None:
    if type(value) is not str or not value:
        raise ValueError(f"{label} must be a non-empty string")
    if value in {".", ".."} or any(
        not (char.isalnum() or char in "._-") for char in value
    ):
        raise ValueError(f"{label} must be a safe identifier")


def _require_sha256(value: object, label: str) -> None:
    if type(value) is not str or len(value) != 64 or any(
        char not in "0123456789abcdef" for char in value
    ):
        raise ValueError(f"{label} must be a lowercase SHA-256 digest")


def _require_staged_tree(path: Path, label: str) -> str:
    """Hash a canonical tree by entry type/path/mode/content.

    Empty directories are bound.  Regular files must have one link so a role
    cannot share writable inodes with the seed or another materialization.
    """

    try:
        resolved = path.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise ValueError(f"{label} is missing or unsafe: {path}") from exc
    if path.is_symlink() or resolved != path or not path.is_dir():
        raise ValueError(f"{label} must be a canonical directory")
    digest = hashlib.sha256()
    try:
        entries = (path, *sorted(path.rglob("*")))
        for child in entries:
            metadata = child.lstat()
            relative = (
                b"" if child == path
                else child.relative_to(path).as_posix().encode("utf-8")
            )
            if stat.S_ISLNK(metadata.st_mode):
                raise ValueError(f"{label} contains an unsafe symlink: {child}")
            if stat.S_ISDIR(metadata.st_mode):
                kind = b"directory"
                data = b""
            elif stat.S_ISREG(metadata.st_mode):
                if metadata.st_nlink != 1:
                    raise ValueError(f"{label} contains a hard-linked file: {child}")
                kind = b"file"
                data = child.read_bytes()
            else:
                raise ValueError(f"{label} contains a special entry: {child}")
            mode = metadata.st_mode & 0o7777
            for value in (kind, relative, mode.to_bytes(4, "big"), data):
                digest.update(len(value).to_bytes(8, "big"))
                digest.update(value)
    except OSError as exc:
        raise ValueError(f"{label} is unreadable: {path}: {exc}") from exc
    return digest.hexdigest()


@dataclass(frozen=True)
class StagedCCCFlowContext:
    """Caller-owned frozen seed for one staged lifecycle projection.

    The hash is rechecked throughout execution, and every role is materialized
    independently from this seed.  This is a trusted test/shadow boundary, not
    a SnapshotStore, CAS capability, or production filesystem sandbox.
    """

    bug_id: str
    function_id: str
    shadow_root: Path
    snapshot_dir: Path
    snapshot_sha256: str
    attempt_id: str
    session_id: str
    attempt_budget_remaining: bool

    def __post_init__(self) -> None:
        for field in ("bug_id", "function_id", "attempt_id", "session_id"):
            _require_safe_flow_id(getattr(self, field), field)
        _require_sha256(self.snapshot_sha256, "snapshot_sha256")
        if type(self.attempt_budget_remaining) is not bool:
            raise TypeError("attempt_budget_remaining must be a bool")
        for field in ("shadow_root", "snapshot_dir"):
            path = getattr(self, field)
            if not isinstance(path, Path) or not path.is_absolute():
                raise TypeError(f"{field} must be an absolute pathlib.Path")

        root = self.shadow_root.resolve()
        snapshot = self.snapshot_dir.resolve()
        if root != self.shadow_root or root.parent == root \
                or root.is_symlink() or not root.is_dir():
            raise ValueError("shadow_root must be a dedicated existing directory")
        if snapshot != self.snapshot_dir or snapshot.is_symlink() \
                or not snapshot.is_dir():
            raise ValueError("snapshot_dir must be a canonical existing directory")
        try:
            relative = snapshot.relative_to(root)
        except ValueError as exc:
            raise ValueError("snapshot_dir must stay below shadow_root") from exc
        if not relative.parts:
            raise ValueError("snapshot_dir must not equal shadow_root")
        if _require_staged_tree(snapshot, "staged snapshot") \
                != self.snapshot_sha256:
            raise ValueError("staged snapshot hash does not match snapshot_sha256")


@dataclass(frozen=True)
class StagedCCCFlowMaterializeRequest:
    """One host-side request for a disposable staged role view."""

    role: str
    snapshot_sha256: str
    attempt_id: str
    session_id: str
    submission_ordinal: int

    def __post_init__(self) -> None:
        if self.role not in _STAGED_FLOW_ROLES:
            raise ValueError(f"unsupported staged flow role: {self.role!r}")
        _require_sha256(self.snapshot_sha256, "snapshot_sha256")
        _require_safe_flow_id(self.attempt_id, "attempt_id")
        _require_safe_flow_id(self.session_id, "session_id")
        if type(self.submission_ordinal) is not int \
                or self.submission_ordinal < 0:
            raise ValueError("submission_ordinal must be a non-negative integer")
        if self.role in {"A", "legacy_observer"} \
                and self.submission_ordinal != 0:
            raise ValueError(f"{self.role} submission_ordinal must be zero")
        if self.role in {"B1", "B2"} and self.submission_ordinal < 1:
            raise ValueError(f"{self.role} submission_ordinal must be positive")


@dataclass(frozen=True)
class StagedCCCFlowRetryRequest:
    """Request a new attempt after every role from the predecessor is gone."""

    previous_attempt_id: str
    previous_session_id: str
    snapshot_sha256: str

    def __post_init__(self) -> None:
        _require_safe_flow_id(self.previous_attempt_id, "previous_attempt_id")
        _require_safe_flow_id(self.previous_session_id, "previous_session_id")
        _require_sha256(self.snapshot_sha256, "snapshot_sha256")


@dataclass(frozen=True)
class StagedCCCFlowAttemptIdentity:
    """Fresh staged identity acknowledged by the injected attempt scheduler."""

    attempt_id: str
    session_id: str

    def __post_init__(self) -> None:
        _require_safe_flow_id(self.attempt_id, "attempt_id")
        _require_safe_flow_id(self.session_id, "session_id")


@dataclass(frozen=True)
class StagedCCCFlowMaterialization:
    """One caller-created role directory below a disposable shadow root."""

    role: str
    root: Path
    project_dir: Path
    materialization_id: str
    snapshot_sha256: str
    attempt_id: str
    session_id: str
    submission_ordinal: int

    def __post_init__(self) -> None:
        StagedCCCFlowMaterializeRequest(
            role=self.role,
            snapshot_sha256=self.snapshot_sha256,
            attempt_id=self.attempt_id,
            session_id=self.session_id,
            submission_ordinal=self.submission_ordinal,
        )
        _require_safe_flow_id(self.materialization_id, "materialization_id")
        for field in ("root", "project_dir"):
            path = getattr(self, field)
            if not isinstance(path, Path) or not path.is_absolute():
                raise TypeError(f"{field} must be an absolute pathlib.Path")
        root = self.root.resolve()
        project = self.project_dir.resolve()
        if root != self.root or root.parent == root or root.is_symlink() \
                or not root.is_dir():
            raise ValueError("role root must be a canonical existing directory")
        if project != self.project_dir or project.is_symlink() \
                or not project.is_dir():
            raise ValueError("role project_dir must be canonical and existing")
        if project != root / "project":
            raise ValueError("role project_dir must be the canonical project child")


@dataclass(frozen=True)
class StagedCCCFlowEvent:
    """Trusted host projection of one session event, not a mailbox envelope."""

    kind: str
    submission: dict | None
    submit_command_called: bool | None

    def __post_init__(self) -> None:
        if self.kind not in _STAGED_FLOW_EVENT_KINDS:
            raise ValueError(f"unsupported staged flow event: {self.kind!r}")
        if self.kind == "submit":
            if type(self.submission) is not dict \
                    or self.submit_command_called is not True:
                raise ValueError("submit events require one formal submission")
        elif self.kind == "direct_scratch":
            if type(self.submission) is not dict \
                    or self.submit_command_called is not False:
                raise ValueError(
                    "direct_scratch events must lack a formal submit call"
                )
        elif self.submission is not None \
                or self.submit_command_called is not None:
            raise ValueError("session_exit must not carry a submission")


@dataclass(frozen=True)
class StagedCCCFlowProviders:
    """All staged role, Gate, scheduling, and publication-observer effects."""

    materialize_role: Callable
    destroy_role: Callable
    inner_gate: Callable
    outer_gate: Callable
    legacy_outer_observer: Callable
    schedule_new_attempt: Callable
    observe_publishable: Callable

    def __post_init__(self) -> None:
        for field in (
            "materialize_role",
            "destroy_role",
            "inner_gate",
            "outer_gate",
            "legacy_outer_observer",
            "schedule_new_attempt",
            "observe_publishable",
        ):
            if not callable(getattr(self, field)):
                raise TypeError(f"{field} must be callable")


def _require_staged_flow_gate_result(
    result: object,
    candidate: dict,
    preset_ref: PresetRef,
) -> StagedCCCGateResult:
    """Validate the typed seam returned by an injected Inner/Outer Gate."""

    if type(result) is not StagedCCCGateResult:
        raise TypeError("flow Gate provider returned an invalid result")
    if result.preset_ref != preset_ref:
        raise ValueError("flow Gate result used the wrong preset")
    if result.original_submission != candidate \
            or result.requested_grade != candidate.get("grade"):
        raise ValueError("flow Gate result lost its original candidate")
    if type(result.final_submission) is not dict \
            or result.final_grade != result.final_submission.get("grade"):
        raise ValueError("flow Gate result has an invalid final candidate")
    for field in ("id", "function_id"):
        if type(result.final_submission.get(field)) is not str \
                or result.final_submission[field] != candidate.get(field):
            raise ValueError(
                f"flow Gate final candidate changed its {field} identity"
            )
    if type(result.call_ledger) is not tuple or any(
        type(label) is not str or not label for label in result.call_ledger
    ):
        raise ValueError("flow Gate result has an invalid call ledger")
    if result.submitted_recipe_identity_preserved is not True:
        raise ValueError("flow Gate result did not preserve recipe identity")
    if result.decision.kind == "accept":
        if result.decision.check is not None \
                or result.decision.raw_reason is not None:
            raise ValueError("accepted flow Gate result carried a rejection")
    elif result.decision.kind == "reject":
        if type(result.decision.check) is not str \
                or not result.decision.check \
                or type(result.decision.raw_reason) is not str \
                or not result.decision.raw_reason:
            raise ValueError("rejected flow Gate result lacks diagnostics")
    else:
        raise ValueError("flow Gate decision must accept or reject")
    return result


def _require_l1_runtime_paths(context: StagedCCCL1Context) -> None:
    """Revalidate the disposable role layout immediately before legacy L1."""

    def require_existing(path: Path, label: str, kind: str) -> Path:
        try:
            resolved = path.resolve(strict=True)
        except (OSError, RuntimeError) as exc:
            raise ValueError(f"{label} is missing or unsafe: {path}") from exc
        if path.is_symlink() or resolved != path:
            raise ValueError(f"{label} contains a symlinked or noncanonical path")
        if kind == "directory" and not path.is_dir():
            raise ValueError(f"{label} must be a directory")
        if kind == "file" and not path.is_file():
            raise ValueError(f"{label} must be a regular file")
        return resolved

    root = require_existing(context.shadow_root, "shadow_root", "directory")
    directories = {
        "project_dir": context.project_dir,
        "baseline_project_dir": context.baseline_project_dir,
        "validation_dir": context.validation_dir,
        "scratch_dir": context.scratch_dir,
        "sanity_corpus_dir": context.sanity_corpus_dir,
    }
    files = {
        "release_ccc": context.release_ccc,
        "reference_cc": context.reference_cc,
    }
    resolved = {
        label: require_existing(path, label, "directory")
        for label, path in directories.items()
    }
    resolved.update({
        label: require_existing(path, label, "file")
        for label, path in files.items()
    })
    for label, path in resolved.items():
        try:
            relative = path.relative_to(root)
        except ValueError as exc:
            raise ValueError(f"{label} escaped shadow_root") from exc
        if not relative.parts:
            raise ValueError(f"{label} must not equal shadow_root")

    roles = (
        ("project_dir", resolved["project_dir"]),
        ("baseline_project_dir", resolved["baseline_project_dir"]),
        ("scratch_dir", resolved["scratch_dir"]),
    )
    for index, (left_label, left) in enumerate(roles):
        for right_label, right in roles[index + 1:]:
            try:
                left.relative_to(right)
                overlaps = True
            except ValueError:
                try:
                    right.relative_to(left)
                    overlaps = True
                except ValueError:
                    overlaps = False
            if overlaps:
                raise ValueError(
                    f"{left_label} and {right_label} must not overlap"
                )

    try:
        resolved["validation_dir"].relative_to(resolved["project_dir"])
        resolved["release_ccc"].relative_to(resolved["project_dir"])
    except ValueError as exc:
        raise ValueError(
            "validation_dir and release_ccc must stay below project_dir"
        ) from exc
    if any(resolved["scratch_dir"].iterdir()):
        raise ValueError("scratch_dir must be empty before staged L1")

    for label, base in (
        ("baseline target source", resolved["baseline_project_dir"]),
        ("working target source", resolved["project_dir"]),
    ):
        target = base / context.manifest_file
        target_resolved = require_existing(target, label, "file")
        try:
            target_resolved.relative_to(base)
        except ValueError as exc:
            raise ValueError(f"{label} escaped its role root") from exc


def _require_artifact_runtime_paths(
    context: StagedCCCArtifactContext,
    *,
    allow_missing_result: bool = False,
) -> None:
    """Revalidate the disposable legacy-pair location before both observers."""

    def require_directory(path: Path, label: str) -> Path:
        try:
            resolved = path.resolve(strict=True)
        except (OSError, RuntimeError) as exc:
            raise ValueError(f"{label} is missing or unsafe: {path}") from exc
        if path.is_symlink() or resolved != path or not path.is_dir():
            raise ValueError(f"{label} must be a canonical directory")
        return resolved

    root = require_directory(context.shadow_root, "shadow_root")
    project = require_directory(context.project_dir, "project_dir")
    validation = require_directory(
        context.result_path.parent,
        "legacy validation directory",
    )
    try:
        project.relative_to(root)
        validation.relative_to(project)
    except ValueError as exc:
        raise ValueError("legacy artifact roles escaped shadow_root") from exc

    if context.result_path.is_symlink():
        raise ValueError("legacy result must not be a symlink")
    if context.result_path.exists():
        try:
            result = context.result_path.resolve(strict=True)
        except (OSError, RuntimeError) as exc:
            raise ValueError("legacy result is unsafe") from exc
        if result != context.result_path or not context.result_path.is_file():
            raise ValueError("legacy result must be a canonical regular file")
    elif not allow_missing_result:
        raise ValueError("legacy result is missing")

    if context.gate_path.is_symlink():
        raise ValueError("legacy sidecar must not be a symlink")
    if context.gate_path.exists():
        try:
            gate = context.gate_path.resolve(strict=True)
        except (OSError, RuntimeError) as exc:
            raise ValueError("legacy sidecar is unsafe") from exc
        if gate != context.gate_path or not context.gate_path.is_file():
            raise ValueError("legacy sidecar must be a canonical regular file")


def _artifact_pair_token(sidecar) -> tuple[object, ...] | None:
    keys = (
        "result_sha256",
        "integrity_sha256",
        "attempt",
        "bug_id",
        "function_id",
    )
    try:
        return tuple(sidecar[key] for key in keys)
    except (KeyError, TypeError):
        return None


def _valid_archive_binding_report(
    archived: ArchivedLegacyCCCCertificate,
) -> bool:
    expected_labels = [
        "logic_result",
        "manifest",
        "source",
        "release_binary",
        "reference_binary",
        "audit_binary",
        "coverage_binary",
        "sanity_corpus",
    ]
    try:
        probe = archived.sidecar["probe"]
        l1_patch = archived.sidecar["l1_patch"]
    except (KeyError, TypeError):
        return False
    if probe is not None:
        expected_labels.append("probe")
    if l1_patch is not None:
        expected_labels.append("l1_patch")
    if type(archived.binding_report) is not tuple or any(
        type(check) is not LegacyBindingCheck
        for check in archived.binding_report
    ):
        return False
    if tuple(check.label for check in archived.binding_report) \
            != tuple(expected_labels):
        return False

    def valid_digest(value) -> bool:
        return type(value) is str and len(value) == 64 and all(
            char in "0123456789abcdef" for char in value
        )

    for check in archived.binding_report:
        if type(check.state) is not LegacyBindingState \
                or type(check.path) is not str or not check.path \
                or not valid_digest(check.expected_sha256) \
                or (
                    check.actual_sha256 is not None
                    and not valid_digest(check.actual_sha256)
                ) \
                or (
                    check.detail is not None
                    and type(check.detail) is not str
                ):
            return False
        if check.state is LegacyBindingState.CURRENT \
                and check.actual_sha256 != check.expected_sha256:
            return False
        if check.state is LegacyBindingState.STALE \
                and (
                    check.actual_sha256 is None
                    or check.actual_sha256 == check.expected_sha256
                ):
            return False
        if check.state in {
            LegacyBindingState.MISSING,
            LegacyBindingState.UNSAFE,
        } and check.actual_sha256 is not None:
            return False
    return True


@dataclass(frozen=True)
class StagedCCCArtifactObservation:
    """Frozen summary from exact-legacy and archival read-only observers."""

    agreement: str
    legacy_resumable: bool
    archived_bindings_current: bool
    pair_token_matches: bool | None
    legacy_error: str | None
    archive_error: str | None
    binding_states: tuple[tuple[str, str], ...]
    observer_ledger: tuple[str, ...]
    archival_only: bool | None


def _observe_legacy_artifact(
    context: StagedCCCArtifactContext,
) -> StagedCCCArtifactObservation:
    """Observe one pair twice without granting either observer current trust."""

    observer_ledger: list[str] = []
    legacy_artifact = None
    archived = None
    legacy_error = None
    archive_error = None
    observer_failure = False

    observer_ledger.append("load_verified_artifact")
    try:
        candidate = _legacy_load_verified_artifact(
            context.result_path,
            allowed_states={"accepted"},
            project_dir=context.project_dir,
        )
    except ArtifactError as exc:
        legacy_error = str(exc)
    except Exception as exc:  # pragma: no cover - defensive observer boundary
        legacy_error = f"{type(exc).__name__}: {exc}"
        observer_failure = True
    else:
        if type(candidate) is not VerifiedArtifact \
                or candidate.state != "accepted" \
                or type(candidate.result) is not dict \
                or type(candidate.sidecar) is not dict \
                or _artifact_pair_token(candidate.sidecar) is None:
            legacy_error = "exact legacy observer returned an invalid result"
            observer_failure = True
        else:
            legacy_artifact = candidate

    observer_ledger.append("load_archived_legacy_certificate")
    try:
        # Deliberately omit expected identities here.  The pinned multirun
        # resume consumer accepted an internally consistent pair without a
        # caller-identity argument.  This private shadow records that legacy
        # behavior; it never grants current-outcome trust.  Generic identity
        # binding belongs to the later current certificate contract.
        candidate = load_archived_legacy_certificate(
            context.result_path,
            project_dir=context.project_dir,
        )
    except OutcomeLoadError as exc:
        archive_error = f"{exc.code.value}: {exc}"
    except Exception as exc:  # pragma: no cover - defensive observer boundary
        archive_error = f"{type(exc).__name__}: {exc}"
        observer_failure = True
    else:
        if type(candidate) is not ArchivedLegacyCCCCertificate \
                or candidate.artifact_family is not ArtifactFamily.CCC_LEGACY_V3_V5 \
                or candidate.trust_class is not TrustClass.LEGACY_PAIR_INTEGRITY_VERIFIED \
                or candidate.semantic_namespace != LEGACY_CCC_SEMANTIC_NAMESPACE \
                or candidate.archival_only is not True \
                or not _valid_archive_binding_report(candidate):
            archive_error = "archival observer returned an invalid trust envelope"
            observer_failure = True
        else:
            archived = candidate

    legacy_resumable = legacy_artifact is not None
    archived_bindings_current = bool(
        archived is not None and archived.all_bindings_current
    )
    binding_states = (
        tuple(
            (check.label, check.state.value)
            for check in archived.binding_report
        )
        if archived is not None
        else ()
    )

    exact_token = (
        _artifact_pair_token(legacy_artifact.sidecar)
        if legacy_artifact is not None
        else None
    )
    archive_token = (
        _artifact_pair_token(archived.sidecar)
        if archived is not None
        else None
    )
    pair_token_matches = (
        exact_token == archive_token
        if exact_token is not None and archive_token is not None
        else None
    )

    if observer_failure:
        agreement = "observer_protocol_failure"
    elif legacy_resumable and archived_bindings_current:
        agreement = (
            "both_resumable"
            if pair_token_matches is True
            else "pair_token_mismatch"
        )
    elif not legacy_resumable and not archived_bindings_current:
        agreement = "both_nonresumable"
    else:
        agreement = "resumability_mismatch"

    return StagedCCCArtifactObservation(
        agreement=agreement,
        legacy_resumable=legacy_resumable,
        archived_bindings_current=archived_bindings_current,
        pair_token_matches=pair_token_matches,
        legacy_error=legacy_error,
        archive_error=archive_error,
        binding_states=binding_states,
        observer_ledger=tuple(observer_ledger),
        archival_only=(archived.archival_only if archived is not None else None),
    )


@dataclass(frozen=True)
class StagedCCCDecision:
    kind: str
    check: str | None
    raw_reason: str | None


@dataclass(frozen=True)
class StagedCCCGateResult:
    decision: StagedCCCDecision
    call_ledger: tuple[str, ...]
    original_submission: dict
    final_submission: dict
    requested_grade: str | None
    final_grade: str | None
    submitted_recipe_identity_preserved: bool
    preset_ref: PresetRef


@dataclass(frozen=True)
class StagedCCCL1Result:
    decision: StagedCCCDecision
    call_ledger: tuple[str, ...]
    original_submission: dict
    final_submission: dict
    requested_grade: str | None
    final_grade: str | None
    preset_ref: PresetRef


@dataclass(frozen=True)
class StagedCCCArtifactResult:
    """Legacy golden projection; ``published`` means pre-existing/reusable."""

    decision: StagedCCCDecision
    call_ledger: tuple[str, ...]
    observer_ledger: tuple[str, ...]
    observation: StagedCCCArtifactObservation
    original_submission: dict
    final_submission: dict
    requested_grade: str | None
    final_grade: str | None
    published: bool
    same_agent_retry: bool
    new_attempt_on_budget: bool
    outer_candidate: str
    outer_calls: int
    preset_ref: PresetRef


@dataclass(frozen=True)
class StagedCCCLegacyFlowObservation:
    """Compatibility-only projection of the direct-scratch legacy loophole."""

    decision: StagedCCCDecision
    call_ledger: tuple[str, ...]
    original_submission: dict
    final_submission: dict
    requested_grade: str | None
    final_grade: str | None
    published: bool
    same_agent_retry: bool
    new_attempt_on_budget: bool
    outer_candidate: str
    outer_calls: int
    materialization_id: str


@dataclass(frozen=True)
class StagedCCCFlowResult:
    """One isolated lifecycle projection with no current receipt or outcome.

    ``published`` means the pinned flow would be publication-eligible after
    the injected observer returned.  It does not represent a filesystem write
    or grant current artifact trust.
    """

    decision: StagedCCCDecision
    call_ledger: tuple[str, ...]
    role_ledger: tuple[str, ...]
    original_submission: dict
    final_submission: dict
    requested_grade: str | None
    final_grade: str | None
    published: bool
    same_agent_retry: bool
    new_attempt_on_budget: bool
    outer_candidate: str
    outer_calls: int
    scheduled_attempt: StagedCCCFlowAttemptIdentity | None
    legacy_observation: StagedCCCLegacyFlowObservation | None
    preset_ref: PresetRef


@dataclass(frozen=True)
class StagedCCCPhenomenonResult:
    decision: StagedCCCDecision
    call_ledger: tuple[str, ...]
    observation: PhenomenonObservation | None
    preset_ref: PresetRef


@dataclass(frozen=True)
class StagedCCCTraceResult:
    decision: StagedCCCDecision
    call_ledger: tuple[str, ...]
    records: tuple[dict, ...]
    preset_ref: PresetRef


class StagedCCCExecutor:
    """Explicit test/shadow entry points for the unregistered CCC preset."""

    def __init__(self) -> None:
        self._preset_ref = CCC_LEGACY_PRESET.ref

    def run_gate(
        self,
        submission: dict,
        context: StagedCCCContext,
        providers: StagedCCCProviders,
    ) -> StagedCCCGateResult:
        if type(submission) is not dict:
            raise TypeError("submission must be a dict")
        if type(context) is not StagedCCCContext:
            raise TypeError("context must be a StagedCCCContext")
        if type(providers) is not StagedCCCProviders:
            raise TypeError("providers must be StagedCCCProviders")

        original = copy.deepcopy(submission)
        working = copy.deepcopy(submission)
        requested_grade = working.get("grade")
        call_ledger: list[str] = []
        recipe_identity_checks: list[bool] = []

        def replay_capture(gate_context, recipe):
            call_ledger.append("replay")
            recipe_identity_checks.append(recipe is working.get("phenomenon"))
            return providers.replay_capture(gate_context, recipe)

        def coverage_runner(gate_context, recipe):
            call_ledger.append("coverage")
            recipe_identity_checks.append(recipe is working.get("phenomenon"))
            return providers.coverage_runner(gate_context, recipe)

        def phenomenon_runner(recipe, gate_context):
            call_ledger.append("phenomenon")
            recipe_identity_checks.append(recipe is working.get("phenomenon"))
            return providers.phenomenon_runner(recipe, gate_context)

        def l1_verifier(candidate, gate_context):
            call_ledger.append("l1")
            return providers.l1_verifier(candidate, gate_context)

        gate = Gate(
            replay_capture=replay_capture,
            coverage_runner=coverage_runner,
            phenomenon_runner=phenomenon_runner,
            l1_verifier=l1_verifier,
        )
        rejection = gate.check(working, context)
        if rejection is None:
            decision = StagedCCCDecision("accept", None, None)
        else:
            decision = StagedCCCDecision(
                "reject",
                rejection.check,
                rejection.reason,
            )
        return StagedCCCGateResult(
            decision=decision,
            call_ledger=tuple(call_ledger),
            original_submission=original,
            final_submission=copy.deepcopy(working),
            requested_grade=requested_grade,
            final_grade=working.get("grade"),
            submitted_recipe_identity_preserved=all(recipe_identity_checks),
            preset_ref=self._preset_ref,
        )

    def run_l1(
        self,
        submission: dict,
        context: StagedCCCL1Context,
        providers: StagedCCCL1Providers,
    ) -> StagedCCCL1Result:
        if type(submission) is not dict:
            raise TypeError("submission must be a dict")
        if type(context) is not StagedCCCL1Context:
            raise TypeError("context must be a StagedCCCL1Context")
        if type(providers) is not StagedCCCL1Providers:
            raise TypeError("providers must be StagedCCCL1Providers")
        _require_l1_runtime_paths(context)

        original = copy.deepcopy(submission)
        working = copy.deepcopy(submission)
        call_ledger: list[str] = []

        def mark_once(label: str) -> None:
            if label not in call_ledger:
                call_ledger.append(label)

        def source_copier(source, destination):
            return providers.source_copier(source, destination)

        def command_runner(argv, *, cwd, env=None):
            command = tuple(str(part) for part in argv)
            if command[:2] == ("git", "apply") \
                    or command[:2] == ("cargo", "run"):
                mark_once("apply_patch")
            elif command[:2] == ("cargo", "build"):
                mark_once("build")
            else:
                raise RuntimeError(
                    f"unexpected pinned legacy L1 command: {command!r}"
                )
            return providers.command_runner(argv, cwd=cwd, env=env)

        def phenomenon_runner(recipe, legacy_context):
            mark_once("phenomenon")
            return providers.phenomenon_runner(recipe, legacy_context)

        def sanity_runner(argv, *, cwd, env):
            mark_once("sanity")
            return providers.sanity_runner(argv, cwd=cwd, env=env)

        isolated_verify_l1 = _bind_l1_source_copier(source_copier)
        rejection = isolated_verify_l1(
            working,
            context,
            command_runner=command_runner,
            phenomenon_runner=phenomenon_runner,
            sanity_runner=sanity_runner,
        )
        if rejection is None:
            decision = StagedCCCDecision("accept", None, None)
        elif isinstance(rejection, Rejection):
            decision = StagedCCCDecision(
                "reject",
                rejection.check,
                rejection.reason,
            )
        else:
            raise TypeError("legacy L1 verifier returned an invalid result")
        return StagedCCCL1Result(
            decision=decision,
            call_ledger=tuple(call_ledger),
            original_submission=original,
            final_submission=copy.deepcopy(working),
            requested_grade=original.get("grade"),
            final_grade=working.get("grade"),
            preset_ref=self._preset_ref,
        )

    def run_artifact_binding(
        self,
        submission: dict,
        context: StagedCCCArtifactContext,
    ) -> StagedCCCArtifactResult:
        """Classify one pre-materialized pair without publishing or upgrading it."""

        original, working = self._artifact_inputs(submission, context)
        observation = _observe_legacy_artifact(context)
        if observation.agreement == "both_resumable":
            decision = StagedCCCDecision("accept", None, None)
            published = True
        elif observation.agreement == "both_nonresumable":
            decision = StagedCCCDecision(
                "reject",
                "binding",
                "hash-bound legacy artifact is invalid",
            )
            published = False
        else:
            decision = StagedCCCDecision(
                "shadow_mismatch",
                "binding",
                f"legacy artifact observers disagree: {observation.agreement}",
            )
            published = False
        return StagedCCCArtifactResult(
            decision=decision,
            call_ledger=("load_verified_artifact",),
            observer_ledger=observation.observer_ledger,
            observation=observation,
            original_submission=original,
            final_submission=copy.deepcopy(working),
            requested_grade=original.get("grade"),
            final_grade=working.get("grade"),
            published=published,
            same_agent_retry=False,
            new_attempt_on_budget=False,
            outer_candidate="none",
            outer_calls=0,
            preset_ref=self._preset_ref,
        )

    def run_legacy_consumer_shadow(
        self,
        submission: dict,
        context: StagedCCCArtifactContext,
        providers: StagedCCCConsumerProviders,
    ) -> StagedCCCArtifactResult:
        """Project pinned resume semantics without starting a real Agent."""

        if type(providers) is not StagedCCCConsumerProviders:
            raise TypeError("providers must be StagedCCCConsumerProviders")
        original, working = self._artifact_inputs(
            submission,
            context,
            allow_missing_result=True,
        )
        observation = _observe_legacy_artifact(context)
        call_ledger = ["load_verified_artifact"]
        if observation.agreement == "both_resumable":
            decision = StagedCCCDecision("skip", None, None)
            published = True
            new_attempt = False
        elif observation.agreement == "both_nonresumable":
            call_ledger.append("agent")
            providers.agent_scheduler()
            decision = StagedCCCDecision(
                "rerun",
                "binding",
                "legacy artifact hash binding is absent or invalid",
            )
            published = False
            new_attempt = True
        else:
            decision = StagedCCCDecision(
                "shadow_mismatch",
                "binding",
                f"legacy artifact observers disagree: {observation.agreement}",
            )
            published = False
            new_attempt = False
        return StagedCCCArtifactResult(
            decision=decision,
            call_ledger=tuple(call_ledger),
            observer_ledger=observation.observer_ledger,
            observation=observation,
            original_submission=original,
            final_submission=copy.deepcopy(working),
            requested_grade=original.get("grade"),
            final_grade=working.get("grade"),
            published=published,
            same_agent_retry=False,
            new_attempt_on_budget=new_attempt,
            outer_candidate="none",
            outer_calls=0,
            preset_ref=self._preset_ref,
        )

    @staticmethod
    def _artifact_inputs(
        submission: dict,
        context: StagedCCCArtifactContext,
        *,
        allow_missing_result: bool = False,
    ) -> tuple[dict, dict]:
        if type(submission) is not dict:
            raise TypeError("submission must be a dict")
        if type(context) is not StagedCCCArtifactContext:
            raise TypeError("context must be a StagedCCCArtifactContext")
        _require_artifact_runtime_paths(
            context,
            allow_missing_result=allow_missing_result,
        )
        original = copy.deepcopy(submission)
        return original, copy.deepcopy(submission)

    def run_isolated_flow(
        self,
        events: Iterable[StagedCCCFlowEvent],
        context: StagedCCCFlowContext,
        providers: StagedCCCFlowProviders,
    ) -> StagedCCCFlowResult:
        """Project one staged Agent/Inner/Outer lifecycle from a frozen seed.

        ``submit`` events are already trusted host-side projections: each one
        must run a new B1 and only a successful B1 creates the candidate handed
        to B2.  A scratch file alone never creates that trusted transition.
        """

        if type(context) is not StagedCCCFlowContext:
            raise TypeError("context must be a StagedCCCFlowContext")
        if type(providers) is not StagedCCCFlowProviders:
            raise TypeError("providers must be StagedCCCFlowProviders")
        event_script = tuple(events)
        if len(event_script) < 2 or any(
            type(event) is not StagedCCCFlowEvent for event in event_script
        ):
            raise ValueError("flow requires typed candidate and exit events")
        if event_script[-1].kind != "session_exit" or sum(
            event.kind == "session_exit" for event in event_script
        ) != 1:
            raise ValueError("flow requires exactly one final session_exit")
        candidate_events = event_script[:-1]
        direct_events = [
            event for event in candidate_events
            if event.kind == "direct_scratch"
        ]
        submit_events = [
            event for event in candidate_events if event.kind == "submit"
        ]
        if len(direct_events) == 1 and len(candidate_events) == 1:
            direct_scratch = True
        elif submit_events and len(submit_events) == len(candidate_events):
            direct_scratch = False
        else:
            raise ValueError(
                "direct scratch observation cannot mix with formal submissions"
            )
        candidate_documents = []
        for event in candidate_events:
            candidate = event.submission
            if type(candidate.get("id")) is not str \
                    or type(candidate.get("function_id")) is not str \
                    or candidate["id"] != context.bug_id \
                    or candidate["function_id"] != context.function_id:
                raise ValueError(
                    "flow candidate identity does not match bug/function context"
                )
            candidate_documents.append(copy.deepcopy(candidate))

        used_roots: list[Path] = []
        used_materialization_ids: set[str] = set()
        live_materializations: dict[Path, StagedCCCFlowMaterialization] = {}
        role_ledger: list[str] = []

        def require_snapshot_current() -> None:
            if _require_staged_tree(context.snapshot_dir, "staged snapshot") \
                    != context.snapshot_sha256:
                raise ValueError("staged snapshot changed during flow execution")

        def paths_overlap(left: Path, right: Path) -> bool:
            try:
                left.relative_to(right)
                return True
            except ValueError:
                try:
                    right.relative_to(left)
                    return True
                except ValueError:
                    return False

        def materialize(role: str, ordinal: int) \
                -> StagedCCCFlowMaterialization:
            require_snapshot_current()
            request = StagedCCCFlowMaterializeRequest(
                role=role,
                snapshot_sha256=context.snapshot_sha256,
                attempt_id=context.attempt_id,
                session_id=context.session_id,
                submission_ordinal=ordinal,
            )
            workspace = providers.materialize_role(request)
            if type(workspace) is not StagedCCCFlowMaterialization:
                raise TypeError(
                    "materialize_role must return a StagedCCCFlowMaterialization"
                )
            try:
                try:
                    relative = workspace.root.relative_to(context.shadow_root)
                except ValueError as exc:
                    raise ValueError("role root escaped shadow_root") from exc
                if not relative.parts:
                    raise ValueError("role root must not equal shadow_root")
                if paths_overlap(workspace.root, context.snapshot_dir):
                    raise ValueError(
                        "role root must not overlap the staged snapshot"
                    )
                if any(
                    paths_overlap(workspace.root, prior)
                    for prior in used_roots
                ):
                    raise ValueError(
                        "role roots must be globally unique and disjoint"
                    )
            except BaseException as exc:
                cleanup_all_live(exc)
                raise
            live_materializations[workspace.root] = workspace
            try:
                returned_request = StagedCCCFlowMaterializeRequest(
                    role=workspace.role,
                    snapshot_sha256=workspace.snapshot_sha256,
                    attempt_id=workspace.attempt_id,
                    session_id=workspace.session_id,
                    submission_ordinal=workspace.submission_ordinal,
                )
                if returned_request != request:
                    raise ValueError(
                        "role materialization does not match its request"
                    )
                if workspace.materialization_id in used_materialization_ids:
                    raise ValueError("role materialization_id was reused")
                try:
                    root_entries = tuple(workspace.root.iterdir())
                except OSError as exc:
                    raise ValueError("role root is unreadable") from exc
                if len(root_entries) != 1 \
                        or root_entries[0] != workspace.project_dir:
                    raise ValueError(
                        "role root must contain only its canonical project"
                    )
                _require_staged_tree(workspace.root, f"staged {role} role")
                if _require_staged_tree(
                    workspace.project_dir,
                    f"staged {role} project",
                ) != context.snapshot_sha256:
                    raise ValueError(
                        f"staged {role} project does not match the frozen snapshot"
                    )
                require_snapshot_current()
            except BaseException as exc:
                cleanup_all_live(exc)
                raise
            used_roots.append(workspace.root)
            used_materialization_ids.add(workspace.materialization_id)
            role_ledger.append(f"materialize:{role}:{ordinal}")
            return workspace

        def forget_destroyed(workspace: StagedCCCFlowMaterialization) -> None:
            if workspace.root not in live_materializations:
                return
            del live_materializations[workspace.root]
            role_ledger.append(
                f"destroy:{workspace.role}:{workspace.submission_ordinal}"
            )

        def cleanup_all_live(error: BaseException) -> None:
            """Best-effort cleanup that never masks the triggering failure."""

            for workspace in reversed(tuple(live_materializations.values())):
                cleanup_error = None
                if workspace.root.exists() or workspace.root.is_symlink():
                    try:
                        returned = providers.destroy_role(workspace)
                        if returned is not None:
                            raise ValueError(
                                "destroy_role returned authority during cleanup"
                            )
                    except BaseException as exc:
                        cleanup_error = exc
                if workspace.root.exists() or workspace.root.is_symlink():
                    try:
                        if workspace.root.is_symlink() \
                                or not workspace.root.is_dir():
                            workspace.root.unlink()
                        else:
                            shutil.rmtree(workspace.root)
                    except BaseException as exc:
                        cleanup_error = cleanup_error or exc
                if not workspace.root.exists() \
                        and not workspace.root.is_symlink():
                    forget_destroyed(workspace)
                else:
                    cleanup_error = cleanup_error or RuntimeError(
                        f"staged {workspace.role} role could not be removed"
                    )
                if cleanup_error is not None and hasattr(error, "add_note"):
                    error.add_note(
                        f"staged role cleanup also failed: {cleanup_error}"
                    )

        def destroy(
            workspace: StagedCCCFlowMaterialization,
            *,
            recheck_snapshot: bool = True,
        ) -> None:
            if workspace.root not in live_materializations:
                return
            try:
                returned = providers.destroy_role(workspace)
                if workspace.root.exists() or workspace.root.is_symlink():
                    raise ValueError(
                        f"destroy_role left staged {workspace.role} materialization"
                    )
                forget_destroyed(workspace)
                if returned is not None:
                    raise ValueError("destroy_role must not return authority")
                if recheck_snapshot:
                    require_snapshot_current()
            except BaseException as exc:
                cleanup_all_live(exc)
                raise

        def run_gate_provider(
            runner: Callable,
            candidate: dict,
            workspace: StagedCCCFlowMaterialization,
        ) -> StagedCCCGateResult:
            gate_input = copy.deepcopy(candidate)
            gate_input_before = copy.deepcopy(gate_input)
            try:
                result = runner(gate_input, workspace)
                if gate_input != gate_input_before:
                    raise ValueError(
                        "flow Gate provider mutated its caller-owned input"
                    )
                checked = _require_staged_flow_gate_result(
                    result,
                    gate_input_before,
                    self._preset_ref,
                )
                require_snapshot_current()
                return checked
            except BaseException as exc:
                cleanup_all_live(exc)
                raise

        def flow_calls(role: str, result: StagedCCCGateResult) \
                -> tuple[str, ...]:
            if not result.call_ledger:
                return (role,)
            return tuple(f"{role}:{label}" for label in result.call_ledger)

        def exit_and_destroy_agent(
            agent_workspace: StagedCCCFlowMaterialization,
        ) -> None:
            role_ledger.append("session_exit")
            destroy(agent_workspace)

        def schedule_if_available(
            call_ledger: list[str],
            *,
            record_external_call: bool,
        ) -> StagedCCCFlowAttemptIdentity | None:
            if not context.attempt_budget_remaining:
                return None
            request = StagedCCCFlowRetryRequest(
                previous_attempt_id=context.attempt_id,
                previous_session_id=context.session_id,
                snapshot_sha256=context.snapshot_sha256,
            )
            returned = providers.schedule_new_attempt(request)
            if type(returned) is not StagedCCCFlowAttemptIdentity:
                raise TypeError(
                    "schedule_new_attempt must return a fresh staged identity"
                )
            if returned.attempt_id == context.attempt_id \
                    or returned.session_id == context.session_id:
                raise ValueError(
                    "scheduled attempt and session identities must both be fresh"
                )
            # The pinned corpus records an explicit scheduler call after an
            # Outer rejection.  Inner exhaustion exposes the same transition
            # only through ``new_attempt_on_budget`` and the role ledger.
            if record_external_call:
                call_ledger.append("new_agent_attempt")
            role_ledger.append("schedule_new_attempt")
            require_snapshot_current()
            return returned

        require_snapshot_current()
        agent_workspace = materialize("A", 0)

        if direct_scratch:
            candidate = copy.deepcopy(candidate_documents[0])
            exit_and_destroy_agent(agent_workspace)
            legacy_workspace = materialize("legacy_observer", 0)
            legacy_result = run_gate_provider(
                providers.legacy_outer_observer,
                candidate,
                legacy_workspace,
            )
            destroy(legacy_workspace)
            legacy_calls = flow_calls("outer", legacy_result)
            legacy_published = legacy_result.decision.kind == "accept"
            legacy_observation = StagedCCCLegacyFlowObservation(
                decision=legacy_result.decision,
                call_ledger=legacy_calls,
                original_submission=copy.deepcopy(candidate),
                final_submission=copy.deepcopy(legacy_result.final_submission),
                requested_grade=candidate.get("grade"),
                final_grade=legacy_result.final_submission.get("grade"),
                published=legacy_published,
                same_agent_retry=False,
                new_attempt_on_budget=False,
                outer_candidate="original_submission",
                outer_calls=1,
                materialization_id=legacy_workspace.materialization_id,
            )
            require_snapshot_current()
            return StagedCCCFlowResult(
                decision=StagedCCCDecision(
                    "reject",
                    "submission",
                    "trusted Inner result is required; direct scratch candidates "
                    "cannot bypass fm-submit-validation",
                ),
                call_ledger=(),
                role_ledger=tuple(role_ledger),
                original_submission=copy.deepcopy(candidate),
                final_submission=copy.deepcopy(candidate),
                requested_grade=candidate.get("grade"),
                final_grade=candidate.get("grade"),
                published=False,
                same_agent_retry=False,
                new_attempt_on_budget=False,
                outer_candidate="none",
                outer_calls=0,
                scheduled_attempt=None,
                legacy_observation=legacy_observation,
                preset_ref=self._preset_ref,
            )

        call_ledger: list[str] = []
        same_agent_retry = False
        for index, candidate in enumerate(candidate_documents, start=1):
            original = copy.deepcopy(candidate)
            inner_workspace = materialize("B1", index)
            inner_result = run_gate_provider(
                providers.inner_gate,
                original,
                inner_workspace,
            )
            destroy(inner_workspace)
            call_ledger.extend(flow_calls("inner", inner_result))
            if inner_result.decision.kind == "reject":
                if index < len(submit_events):
                    same_agent_retry = True
                    continue
                exit_and_destroy_agent(agent_workspace)
                scheduled_attempt = schedule_if_available(
                    call_ledger,
                    record_external_call=False,
                )
                return StagedCCCFlowResult(
                    decision=inner_result.decision,
                    call_ledger=tuple(call_ledger),
                    role_ledger=tuple(role_ledger),
                    original_submission=copy.deepcopy(original),
                    final_submission=copy.deepcopy(inner_result.final_submission),
                    requested_grade=original.get("grade"),
                    final_grade=inner_result.final_submission.get("grade"),
                    published=False,
                    same_agent_retry=same_agent_retry,
                    new_attempt_on_budget=scheduled_attempt is not None,
                    outer_candidate="none",
                    outer_calls=0,
                    scheduled_attempt=scheduled_attempt,
                    legacy_observation=None,
                    preset_ref=self._preset_ref,
                )

            if index != len(submit_events):
                error = ValueError(
                    "formal submissions remained after Inner acceptance"
                )
                cleanup_all_live(error)
                raise error

            exit_and_destroy_agent(agent_workspace)
            outer_workspace = materialize("B2", index)
            outer_result = run_gate_provider(
                providers.outer_gate,
                original,
                outer_workspace,
            )
            call_ledger.extend(flow_calls("outer", outer_result))
            published = False
            if outer_result.decision.kind == "accept":
                try:
                    returned = providers.observe_publishable(
                        copy.deepcopy(outer_result.final_submission),
                        outer_workspace,
                    )
                    if returned is not None:
                        raise ValueError(
                            "observe_publishable must not return authority"
                        )
                    require_snapshot_current()
                    published = True
                    role_ledger.append(f"observe_publishable:B2:{index}")
                except BaseException as exc:
                    cleanup_all_live(exc)
                    raise
            destroy(outer_workspace)
            scheduled_attempt = None
            if outer_result.decision.kind == "reject":
                scheduled_attempt = schedule_if_available(
                    call_ledger,
                    record_external_call=True,
                )
            return StagedCCCFlowResult(
                decision=outer_result.decision,
                call_ledger=tuple(call_ledger),
                role_ledger=tuple(role_ledger),
                original_submission=copy.deepcopy(original),
                final_submission=copy.deepcopy(outer_result.final_submission),
                requested_grade=original.get("grade"),
                final_grade=outer_result.final_submission.get("grade"),
                published=published,
                same_agent_retry=same_agent_retry,
                new_attempt_on_budget=scheduled_attempt is not None,
                outer_candidate="original_submission",
                outer_calls=1,
                scheduled_attempt=scheduled_attempt,
                legacy_observation=None,
                preset_ref=self._preset_ref,
            )

        raise AssertionError("validated staged flow did not produce a result")

    def run_phenomenon(
        self,
        recipe: dict,
        context: StagedCCCContext,
        runner: Callable,
    ) -> StagedCCCPhenomenonResult:
        if type(recipe) is not dict:
            raise TypeError("recipe must be a dict")
        if type(context) is not StagedCCCContext:
            raise TypeError("context must be a StagedCCCContext")
        if not callable(runner):
            raise TypeError("runner must be callable")

        working_recipe = copy.deepcopy(recipe)
        call_ledger: list[str] = []

        def recorded_runner(argv, **kwargs):
            call_ledger.append(self._phenomenon_call_label(argv, working_recipe, context))
            return runner(argv, **kwargs)

        try:
            observation = run_legacy_phenomenon(
                working_recipe,
                context,
                runner=recorded_runner,
            )
        except NoPhenomenonError as exc:
            return StagedCCCPhenomenonResult(
                decision=StagedCCCDecision("no_phenomenon", None, str(exc)),
                call_ledger=tuple(call_ledger),
                observation=None,
                preset_ref=self._preset_ref,
            )
        except PhenomenonError as exc:
            return StagedCCCPhenomenonResult(
                decision=StagedCCCDecision("reject", "phenomenon", str(exc)),
                call_ledger=tuple(call_ledger),
                observation=None,
                preset_ref=self._preset_ref,
            )
        return StagedCCCPhenomenonResult(
            decision=StagedCCCDecision("accept", observation.kind, None),
            call_ledger=tuple(call_ledger),
            observation=observation,
            preset_ref=self._preset_ref,
        )

    def parse_trace(
        self,
        lines: Iterable[str],
        manifest_id: str,
    ) -> StagedCCCTraceResult:
        if type(manifest_id) is not str or not manifest_id:
            raise ValueError("manifest_id must be a non-empty string")
        try:
            records = parse_records(tuple(lines), manifest_id)
        except ReplayError as exc:
            return StagedCCCTraceResult(
                decision=StagedCCCDecision("reject", "replay", str(exc)),
                call_ledger=("parse_records",),
                records=(),
                preset_ref=self._preset_ref,
            )
        return StagedCCCTraceResult(
            decision=StagedCCCDecision("accept", None, None),
            call_ledger=("parse_records",),
            records=tuple(copy.deepcopy(records)),
            preset_ref=self._preset_ref,
        )

    @staticmethod
    def _phenomenon_call_label(
        argv,
        recipe: dict,
        context: StagedCCCContext,
    ) -> str:
        executable = Path(str(argv[0]))
        if executable == context.release_ccc:
            return "ccc:build" if recipe["mode"] == "run" else "ccc"
        if executable == context.reference_cc:
            return "gcc:build" if recipe["mode"] == "run" else "gcc"
        if executable == context.scratch_dir / "phenomenon-ccc.bin":
            return "ccc:run"
        if executable == context.scratch_dir / "phenomenon-gcc.bin":
            return "gcc:run"
        raise ValueError(f"unexpected phenomenon executable: {executable}")

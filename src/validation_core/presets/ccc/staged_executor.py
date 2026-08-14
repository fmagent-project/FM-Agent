"""Private, in-memory executor for staged legacy CCC parity checks.

This module is deliberately not exported by any package ``__init__`` and is
not connected to the production validator.  It wraps the byte-identical
legacy Gate with mandatory injected providers so tests can exercise decision
semantics without launching compilers, agents, sandboxes, or publishers.
"""

from __future__ import annotations

import copy
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

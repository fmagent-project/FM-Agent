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
from ....check_submission import Gate, Rejection, ReplayError, parse_records
from ....l1_verifier import verify_l1 as _legacy_verify_l1
from ....phenomenon_runner import (
    NoPhenomenonError,
    PhenomenonError,
    PhenomenonObservation,
    run_phenomenon as run_legacy_phenomenon,
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

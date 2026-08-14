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
from typing import Callable, Iterable

from ...contracts.routing import PresetRef
from ....check_submission import Gate, ReplayError, parse_records
from ....phenomenon_runner import (
    NoPhenomenonError,
    PhenomenonError,
    PhenomenonObservation,
    run_phenomenon as run_legacy_phenomenon,
)
from .preset import CCC_LEGACY_PRESET


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

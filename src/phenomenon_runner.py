"""Harness-owned execution and classification of compiler phenomena."""

from __future__ import annotations

import os
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

try:
    from .compiler_recipe import (
        CompileRecipeError,
        SAFE_COMPILER_FLAGS,
        compile_argv,
        validate_compile_recipe,
    )
except ImportError:  # flat import for direct test/script use
    from compiler_recipe import (
        CompileRecipeError,
        SAFE_COMPILER_FLAGS,
        compile_argv,
        validate_compile_recipe,
    )


class PhenomenonError(ValueError):
    pass


class NoPhenomenonError(PhenomenonError):
    """The requested comparison ran, but showed no compiler difference."""

    def __init__(self, message: str, phases=()):
        super().__init__(message)
        self.phases = tuple(phases)


@dataclass(frozen=True)
class PhaseResult:
    argv: tuple[str, ...]
    returncode: int
    stdout: str
    stderr: str


@dataclass(frozen=True)
class PhenomenonObservation:
    kind: str
    phases: tuple[PhaseResult, ...]


# PIN: agent-evidence-is-non-executable
_SAFE_FLAGS = SAFE_COMPILER_FLAGS


def _default_runner(argv, *, cwd, env):
    process = subprocess.run(
        argv, capture_output=True, text=True, timeout=120, cwd=cwd, env=env,
    )
    return process.returncode, process.stdout, process.stderr


def _call(runner: Callable, argv: list[str], context) -> PhaseResult:
    clean_env = {key: value for key, value in os.environ.items()
                 if not key.startswith("FM_AUDIT")}
    try:
        raw = runner(argv, cwd=context.project_dir, env=clean_env)
    except (subprocess.TimeoutExpired, OSError) as exc:
        raise PhenomenonError(f"phenomenon phase failed to execute: {exc}") from exc
    if isinstance(raw, tuple) and len(raw) == 3:
        rc, stdout, stderr = raw
    else:
        try:
            rc, stdout, stderr = raw.returncode, raw.stdout, raw.stderr
        except AttributeError as exc:
            raise PhenomenonError("phenomenon runner returned an invalid result") from exc
    if type(rc) is not int:
        raise PhenomenonError("phenomenon runner returned a non-integer return code")
    return PhaseResult(tuple(str(arg) for arg in argv), rc, stdout or "", stderr or "")


def _validated_extra_args(recipe: dict) -> list[str]:
    try:
        _mode, _standard, args = validate_compile_recipe(recipe)
    except CompileRecipeError as exc:
        raise PhenomenonError(f"phenomenon.{exc}") from exc
    return args


def _normalized_preprocessed(text: str) -> str:
    return "\n".join(line.rstrip() for line in text.replace("\r\n", "\n").splitlines()).strip()


def _compile_argv(compiler: Path, recipe: dict, probe: Path, output: Path | None):
    try:
        return compile_argv(compiler, recipe, probe, output)
    except CompileRecipeError as exc:
        raise PhenomenonError(f"phenomenon compile recipe is invalid: {exc}") from exc


# PIN: validation-replay-uses-submitted-compile-recipe
def run_phenomenon(recipe: dict, context, runner: Callable = _default_runner):
    """Execute one structured recipe and classify only observed behavior."""
    scratch = Path(context.scratch_dir)
    scratch.mkdir(parents=True, exist_ok=True)
    probe = Path(context.probe_path)
    outputs = {
        "ccc": scratch / ("phenomenon-ccc.bin" if recipe["mode"] == "run" else
                          f"phenomenon-ccc.{recipe['mode']}"),
        "gcc": scratch / ("phenomenon-gcc.bin" if recipe["mode"] == "run" else
                          f"phenomenon-gcc.{recipe['mode']}"),
    }
    for path in outputs.values():
        path.unlink(missing_ok=True)
    ccc = _call(runner, _compile_argv(
        context.release_ccc, recipe, probe, outputs["ccc"]
    ), context)
    gcc = _call(runner, _compile_argv(
        context.reference_cc, recipe, probe, outputs["gcc"]
    ), context)
    phases = [ccc, gcc]
    successes = (ccc.returncode == 0, gcc.returncode == 0)
    if successes == (False, False):
        raise NoPhenomenonError(
            "both compilers failed; no differential is established", phases,
        )

    mode = recipe["mode"]
    if mode == "preprocess":
        if successes != (True, True):
            raise PhenomenonError("preprocess comparison requires both compilers to succeed")
        if _normalized_preprocessed(ccc.stdout) == _normalized_preprocessed(gcc.stdout):
            raise NoPhenomenonError("no observable preprocess difference", phases)
        return PhenomenonObservation("preprocess_differs", tuple(phases))
    if mode in ("syntax", "asm", "object"):
        if successes in ((True, False), (False, True)):
            return PhenomenonObservation("accept_reject_differs", tuple(phases))
        raise NoPhenomenonError("no observable accept/reject difference", phases)
    if successes in ((True, False), (False, True)):
        return PhenomenonObservation("build_accept_reject_differs", tuple(phases))

    ccc_run = _call(runner, [str(outputs["ccc"])], context)
    gcc_run = _call(runner, [str(outputs["gcc"])], context)
    phases.extend([ccc_run, gcc_run])
    if ccc_run.returncode != gcc_run.returncode:
        return PhenomenonObservation("run_exit_differs", tuple(phases))
    if ccc_run.stdout != gcc_run.stdout:
        return PhenomenonObservation("stdout_differs", tuple(phases))
    raise NoPhenomenonError("no observable runtime difference", phases)

"""Independent source-coverage observation for boundary calls."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path, PurePosixPath
from typing import Callable

try:
    from .compiler_recipe import CompileRecipeError, compile_argv
except ImportError:  # flat import for direct test/script use
    from compiler_recipe import CompileRecipeError, compile_argv


class CoverageError(ValueError):
    pass


def _default_runner(argv, *, cwd, env):
    process = subprocess.run(
        argv, cwd=cwd, env=env, capture_output=True, text=True, timeout=120,
    )
    return process.returncode, process.stdout, process.stderr


def _call(runner: Callable, argv: list[str], *, cwd: Path, env: dict):
    try:
        result = runner(argv, cwd=cwd, env=env)
    except (subprocess.TimeoutExpired, OSError) as exc:
        raise CoverageError(f"coverage command failed to execute: {exc}") from exc
    if isinstance(result, tuple) and len(result) == 3:
        rc, stdout, stderr = result
    else:
        try:
            rc, stdout, stderr = result.returncode, result.stdout, result.stderr
        except AttributeError as exc:
            raise CoverageError("coverage runner returned an invalid result") from exc
    if type(rc) is not int:
        raise CoverageError("coverage runner returned a non-integer return code")
    return rc, stdout or "", stderr or ""


def _tool(name: str) -> Path:
    configured = os.environ.get(name.upper().replace("-", "_"))
    if configured:
        return Path(configured)
    try:
        sysroot_result = subprocess.run(
            ["rustc", "--print", "sysroot"], capture_output=True,
            text=True, timeout=10,
        )
        version_result = subprocess.run(
            ["rustc", "-vV"], capture_output=True, text=True, timeout=10,
        )
        host = next(
            (line.removeprefix("host: ") for line in version_result.stdout.splitlines()
             if line.startswith("host: ")),
            "",
        )
        candidate = (
            Path(sysroot_result.stdout.strip()) / "lib" / "rustlib" / host /
            "bin" / name
        )
        if sysroot_result.returncode == 0 and version_result.returncode == 0 \
                and host and candidate.is_file():
            return candidate
    except (OSError, subprocess.TimeoutExpired):
        pass
    found = shutil.which(name)
    if found:
        return Path(found)
    raise CoverageError(
        f"required matching coverage tool is unavailable: {name}; "
        "install the Rust llvm-tools-preview component"
    )


def _same_source(filename: str, expected_relative: str) -> bool:
    candidate = PurePosixPath(filename.replace("\\", "/")).parts
    expected = PurePosixPath(expected_relative).parts
    return bool(expected) and len(candidate) >= len(expected) \
        and candidate[-len(expected):] == expected


def _target_count(document: object, context) -> int:
    entry = context.manifest_entry
    line = getattr(entry, "source_line", None)
    if type(line) is not int or line < 1:
        raise CoverageError("manifest target source line is missing or invalid")
    try:
        data = document["data"]
    except (TypeError, KeyError) as exc:
        raise CoverageError("llvm-cov export has an invalid shape") from exc
    if type(data) is not list:
        raise CoverageError("llvm-cov export data must be a list")

    total = 0
    matches = 0
    for section in data:
        functions = section.get("functions", []) if isinstance(section, dict) else []
        if type(functions) is not list:
            raise CoverageError("llvm-cov function list is invalid")
        for function in functions:
            if not isinstance(function, dict):
                continue
            filenames = function.get("filenames", [])
            regions = function.get("regions", [])
            count = function.get("count")
            if type(filenames) is not list or type(regions) is not list \
                    or type(count) is not int or count < 0:
                continue
            is_target = False
            for region in regions:
                if type(region) is not list or len(region) < 6:
                    continue
                start_line, file_id = region[0], region[5]
                if type(file_id) is not int or not 0 <= file_id < len(filenames):
                    continue
                if start_line == line and type(filenames[file_id]) is str \
                        and _same_source(filenames[file_id], entry.file):
                    is_target = True
                    break
            if is_target:
                matches += 1
                total += count
    if matches == 0:
        return 0
    return total


# PIN: boundary-evidence-has-two-independent-counts
# PIN: nonzero-validation-capture-requires-complete-evidence
# PIN: validation-replay-uses-submitted-compile-recipe
def capture_coverage(
    context,
    recipe,
    *,
    process_runner: Callable = _default_runner,
    llvm_profdata: Path | None = None,
    llvm_cov: Path | None = None,
) -> int:
    """Compile the canonical probe and return target-function entry count."""
    scratch = Path(context.scratch_dir)
    scratch.mkdir(parents=True, exist_ok=True)
    for stale in scratch.glob("coverage-*.profraw"):
        stale.unlink(missing_ok=True)
    output = scratch / "coverage-probe.bin"
    output.unlink(missing_ok=True)
    profile_pattern = scratch / "coverage-%p-%m.profraw"
    env = {
        key: value for key, value in os.environ.items()
        if not key.startswith("FM_AUDIT")
    }
    env["LLVM_PROFILE_FILE"] = str(profile_pattern)
    try:
        argv = compile_argv(
            context.coverage_ccc, recipe, context.probe_path, output,
        )
    except CompileRecipeError as exc:
        raise CoverageError(f"coverage compile recipe is invalid: {exc}") from exc
    rc, _stdout, stderr = _call(
        process_runner, argv, cwd=Path(context.project_dir), env=env,
    )
    output.unlink(missing_ok=True)
    profiles = sorted(scratch.glob("coverage-*.profraw"))
    if not profiles or any(not path.is_file() or path.stat().st_size == 0 for path in profiles):
        if rc != 0:
            raise CoverageError(
                f"coverage compiler failed with rc={rc} and produced no usable "
                f"profile: {stderr[-400:]}"
            )
        raise CoverageError("coverage compiler produced no usable profile")

    profdata = Path(llvm_profdata) if llvm_profdata is not None else _tool("llvm-profdata")
    cov = Path(llvm_cov) if llvm_cov is not None else _tool("llvm-cov")
    merged = scratch / "coverage.profdata"
    merged.unlink(missing_ok=True)
    merge_argv = [str(profdata), "merge", "-sparse", *map(str, profiles),
                  "-o", str(merged)]
    rc, _stdout, stderr = _call(
        process_runner, merge_argv, cwd=Path(context.project_dir), env=env,
    )
    if rc != 0 or not merged.is_file():
        raise CoverageError(f"coverage profile merge failed with rc={rc}: {stderr[-400:]}")

    export_argv = [
        str(cov), "export", str(context.coverage_ccc),
        f"-instr-profile={merged}",
    ]
    rc, stdout, stderr = _call(
        process_runner, export_argv, cwd=Path(context.project_dir), env=env,
    )
    if rc != 0:
        raise CoverageError(f"coverage export failed with rc={rc}: {stderr[-400:]}")
    try:
        document = json.loads(stdout)
    except json.JSONDecodeError as exc:
        raise CoverageError(f"coverage export is not valid JSON: {exc}") from exc
    return _target_count(document, context)

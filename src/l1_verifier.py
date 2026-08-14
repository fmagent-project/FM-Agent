"""Structural and behavioral verification for a mandatory L1 patch attempt."""

from __future__ import annotations

import copy
import hashlib
import os
import shutil
import stat
import subprocess
import uuid
from pathlib import Path
from types import SimpleNamespace
from typing import Callable

try:
    from .phenomenon_runner import NoPhenomenonError, PhenomenonError, run_phenomenon
    from .validation_context import sha256_directory
    from .validation_workspace import copy_validation_source
except ImportError:  # flat import (tests, scripts)
    from phenomenon_runner import NoPhenomenonError, PhenomenonError, run_phenomenon
    from validation_context import sha256_directory
    from validation_workspace import copy_validation_source


def _rejection(reason: str):
    try:
        from .check_submission import Rejection
    except ImportError:  # flat import (tests, scripts)
        from check_submission import Rejection
    return Rejection("L1", reason)


def _attempt_rejection(reason: str):
    """Reject malformed or unevaluable patches instead of rewarding them with L0."""
    try:
        from .check_submission import Rejection
    except ImportError:  # flat import (tests, scripts)
        from check_submission import Rejection
    return Rejection("L1-attempt", reason)


def _default_runner(argv, *, cwd, env=None):
    process = subprocess.run(
        argv, cwd=cwd, env=env, capture_output=True, text=True, timeout=300,
    )
    return process.returncode, process.stdout, process.stderr


def _clean_env():
    return {
        key: value for key, value in os.environ.items()
        if not key.startswith("FM_AUDIT")
    }


def _call(runner: Callable, argv: list[str], *, cwd: Path):
    try:
        result = runner(argv, cwd=cwd, env=_clean_env())
    except (subprocess.TimeoutExpired, OSError) as exc:
        raise ValueError(f"command failed to execute: {exc}") from exc
    if isinstance(result, tuple) and len(result) == 3:
        rc, stdout, stderr = result
    else:
        try:
            rc, stdout, stderr = result.returncode, result.stdout, result.stderr
        except AttributeError as exc:
            raise ValueError("command runner returned an invalid result") from exc
    if type(rc) is not int:
        raise ValueError("command runner returned a non-integer return code")
    return rc, stdout or "", stderr or ""


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _snapshot(root: Path):
    snapshot = {}
    for path in sorted(root.rglob("*")):
        rel = path.relative_to(root).as_posix()
        info = path.lstat()
        mode = stat.S_IMODE(info.st_mode)
        if path.is_symlink():
            snapshot[rel] = ("symlink", mode, os.readlink(path))
        elif path.is_file():
            snapshot[rel] = ("file", mode, _sha256(path))
    return snapshot


def _context_with(context, **overrides):
    values = dict(vars(context))
    values.update(overrides)
    return SimpleNamespace(**values)


def _run_scope_check(
    before: Path,
    after: Path,
    context,
    command_runner: Callable,
):
    manifest = Path(__file__).resolve().parents[1] / "tools" / "l1_scope" / "Cargo.toml"
    # Keep this tiny build cache in the disposable L1 work directory instead
    # of changing either the validator's working tree or the harness project.
    target_dir = before.parent / "l1-scope-target"
    argv = [
        "cargo", "run", "--quiet", "--manifest-path", str(manifest),
        "--target-dir", str(target_dir), "--",
        str(before), str(after), context.manifest_entry.fn_name,
        str(context.manifest_entry.occurrence),
    ]
    rc, stdout, stderr = _call(command_runner, argv, cwd=Path(context.project_dir))
    if rc != 0:
        detail = (stderr or stdout).strip()[-500:]
        raise ValueError(detail or "patch changes code outside the target function body")


# PIN: l1-patches-are-narrow-and-behaviorally-closed
def verify_l1(
    submission: dict,
    context,
    *,
    command_runner: Callable = _default_runner,
    phenomenon_runner: Callable = run_phenomenon,
    sanity_runner: Callable = _default_runner,
):
    """Return ``None`` only when the L1 patch is narrow and closes the bug."""
    expected_rel = f"fm_agent/bug_validation/{context.bug_id}.l1.patch"
    if submission.get("l1_patch") != expected_rel:
        return _attempt_rejection(f"L1 patch must use the canonical path {expected_rel}")

    patch = Path(context.project_dir) / expected_rel
    expected_patch = Path(context.validation_dir) / f"{context.bug_id}.l1.patch"
    try:
        if patch != expected_patch or patch.is_symlink() or not patch.is_file():
            return _attempt_rejection(f"canonical L1 patch is missing or unsafe: {patch}")
        target_rel = Path(context.manifest_entry.file).as_posix()
        baseline_project = Path(context.baseline_project_dir)
        baseline_target = baseline_project / target_rel
        if baseline_project.is_symlink() or not baseline_project.is_dir():
            return _attempt_rejection(
                f"clean baseline project is missing or unsafe: {baseline_project}"
            )
        if baseline_target.is_symlink() or not baseline_target.is_file():
            return _attempt_rejection(
                f"baseline target source is missing or unsafe: {target_rel}"
            )
        frozen_source = getattr(context, "source_sha256", None)
        if frozen_source is not None and _sha256(baseline_target) != frozen_source:
            return _attempt_rejection(
                "baseline target source changed after validation started"
            )
    except OSError as exc:
        return _attempt_rejection(f"cannot inspect the L1 inputs: {exc}")

    scratch = Path(context.scratch_dir)
    work = scratch / f"l1-{uuid.uuid4().hex}"
    copied_project = work / "l1-project"
    before_target = work / "before.rs"
    try:
        work.mkdir(parents=True, mode=0o700)
        shutil.copy2(baseline_target, before_target)
        copied_project.mkdir()
        copy_validation_source(baseline_project, copied_project)
        before_tree = _snapshot(copied_project)

        for argv in (
            ["git", "apply", "--check", str(patch)],
            ["git", "apply", str(patch)],
        ):
            rc, stdout, stderr = _call(command_runner, argv, cwd=copied_project)
            if rc != 0:
                detail = (stderr or stdout).strip()[-500:]
                return _attempt_rejection(
                    f"L1 patch cannot be applied cleanly: {detail}"
                )

        after_tree = _snapshot(copied_project)
        changed = {
            path for path in set(before_tree) | set(after_tree)
            if before_tree.get(path) != after_tree.get(path)
        }
        if changed != {target_rel}:
            others = sorted(changed - {target_rel})
            if others:
                return _attempt_rejection(
                    "L1 patch changes other files: " + ", ".join(others[:8])
                )
            return _attempt_rejection(
                "L1 patch must change the authoritative target file"
            )
        before_kind, before_mode, _ = before_tree[target_rel]
        after_kind, after_mode, _ = after_tree[target_rel]
        if before_kind != "file" or after_kind != "file":
            return _attempt_rejection(
                "L1 patch must keep the target as a regular file"
            )
        if before_mode != after_mode:
            return _attempt_rejection("L1 patch changes the target file mode")

        after_target = copied_project / target_rel
        try:
            _run_scope_check(before_target, after_target, context, command_runner)
        except ValueError as exc:
            return _attempt_rejection(
                f"L1 patch is not a valid target-body repair: {exc}"
            )

        rc, stdout, stderr = _call(
            command_runner,
            ["cargo", "build", "--release", "--bin", "ccc"],
            cwd=copied_project,
        )
        if rc != 0:
            detail = (stderr or stdout).strip()[-500:]
            return _attempt_rejection(f"patched compiler build failed: {detail}")
        patched_ccc = copied_project / "target" / "release" / "ccc"
        if patched_ccc.is_symlink() or not patched_ccc.is_file():
            return _attempt_rejection(
                "patched compiler build produced no safe release binary"
            )

        try:
            baseline = phenomenon_runner(submission["phenomenon"], context)
        except NoPhenomenonError as exc:
            return _attempt_rejection(
                f"baseline phenomenon was not reproduced: {exc}"
            )
        except PhenomenonError as exc:
            return _attempt_rejection(
                f"baseline phenomenon check failed: {exc}"
            )
        expected_kind = submission["phenomenon"]["expected_kind"]
        if baseline.kind != expected_kind:
            return _attempt_rejection(
                f"baseline phenomenon kind is {baseline.kind!r}, expected {expected_kind!r}"
            )

        patched_context = _context_with(
            context,
            project_dir=copied_project,
            release_ccc=patched_ccc,
            scratch_dir=work / "phenomenon",
        )
        try:
            remaining = phenomenon_runner(submission["phenomenon"], patched_context)
        except NoPhenomenonError:
            remaining = None
        except PhenomenonError as exc:
            return _attempt_rejection(
                f"patched phenomenon check failed: {exc}"
            )
        if remaining is not None:
            return _rejection(
                f"patched compiler still shows a difference ({remaining.kind})"
            )

        corpus = Path(context.sanity_corpus_dir)
        frozen_corpus = getattr(context, "sanity_corpus_sha256", None)
        if frozen_corpus is not None \
                and sha256_directory(corpus, "sanity corpus") != frozen_corpus:
            return _attempt_rejection(
                "sanity corpus changed after validation started"
            )
        seeds = sorted(path for path in corpus.rglob("*.c") if path.is_file())
        if not seeds:
            return _attempt_rejection("sanity corpus has no C files")
        env = _clean_env()
        sanity_output = work / "sanity-output"
        for seed in seeds:
            # This compiler driver still writes an output even with
            # -fsyntax-only. Run both against the same scratch output and
            # remove it between phases.
            common_args = [
                "-fsyntax-only", str(seed), "-o", str(sanity_output),
            ]
            base_argv = [str(context.release_ccc), *common_args]
            patched_argv = [str(patched_ccc), *common_args]
            try:
                sanity_output.unlink(missing_ok=True)
                base_result = sanity_runner(
                    base_argv, cwd=Path(context.project_dir), env=env,
                )
                sanity_output.unlink(missing_ok=True)
                patched_result = sanity_runner(
                    patched_argv, cwd=copied_project, env=env,
                )
            except (subprocess.TimeoutExpired, OSError) as exc:
                return _attempt_rejection(
                    f"sanity check failed to execute for {seed.name}: {exc}"
                )
            finally:
                sanity_output.unlink(missing_ok=True)
            if base_result != patched_result:
                return _rejection(
                    f"sanity output changed for {seed.name}; exit code, stdout, and stderr must match"
                )
    except (OSError, ValueError, shutil.Error) as exc:
        return _attempt_rejection(f"L1 verification failed safely: {exc}")
    finally:
        shutil.rmtree(work, ignore_errors=True)
    return None

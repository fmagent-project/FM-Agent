"""Run workspace selection and lifecycle management.

FM-Agent stores each execution below ``fm_agent/runs/<run-id>``.  The small
``current_run.json`` marker points commands such as ``--resume`` and the
dashboard at the active run without making ``fm_agent/`` itself disposable.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
import json
import os
import shutil
import sys
import tempfile


WORKSPACE_DIRNAME = "fm_agent"
RUNS_DIRNAME = "runs"
CURRENT_RUN_FILENAME = "current_run.json"
_ROOT_METADATA = {RUNS_DIRNAME, CURRENT_RUN_FILENAME, ".env_check_memory"}


class RunSelectionCancelled(RuntimeError):
    """Raised when the user exits instead of selecting a run workspace."""


@dataclass(frozen=True)
class RunSelection:
    work_dir: str
    run_id: str
    resume: bool
    action: str


def workspace_root(proj_dir):
    return os.path.join(os.path.abspath(proj_dir), WORKSPACE_DIRNAME)


def workdir_relpath(proj_dir, work_dir):
    """Return an agent-facing, slash-separated path for ``work_dir``."""
    return os.path.relpath(work_dir, proj_dir).replace(os.sep, "/")


def inferred_workdir_relpath(work_dir):
    """Infer the project-relative workspace path from an absolute work dir."""
    parts = os.path.normpath(os.path.abspath(work_dir)).split(os.sep)
    try:
        index = len(parts) - 1 - parts[::-1].index(WORKSPACE_DIRNAME)
    except ValueError:
        return WORKSPACE_DIRNAME
    return "/".join(parts[index:])


def _timestamp(now=None):
    return (now or datetime.now()).strftime("%Y%m%d-%H%M%S")


def _unique_run_id(runs_dir, prefix=None, now=None):
    base = prefix or _timestamp(now)
    candidate = base
    suffix = 2
    while os.path.exists(os.path.join(runs_dir, candidate)):
        candidate = f"{base}-{suffix}"
        suffix += 1
    return candidate


def _write_current(root, run_id):
    os.makedirs(root, exist_ok=True)
    marker = os.path.join(root, CURRENT_RUN_FILENAME)
    fd, tmp = tempfile.mkstemp(prefix=".current_run.", dir=root, text=True)
    try:
        with os.fdopen(fd, "w") as f:
            json.dump({"run_id": run_id}, f, indent=2)
            f.write("\n")
        os.replace(tmp, marker)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def current_run_dir(proj_dir):
    """Return the active run directory, falling back to the newest run."""
    root = workspace_root(proj_dir)
    runs_dir = os.path.join(root, RUNS_DIRNAME)
    marker = os.path.join(root, CURRENT_RUN_FILENAME)
    try:
        with open(marker, "r") as f:
            run_id = json.load(f).get("run_id", "")
    except (OSError, ValueError, AttributeError):
        run_id = ""
    if run_id and os.path.basename(run_id) == run_id:
        candidate = os.path.join(runs_dir, run_id)
        if os.path.isdir(candidate):
            return candidate
    if not os.path.isdir(runs_dir):
        return None
    candidates = [
        os.path.join(runs_dir, name)
        for name in os.listdir(runs_dir)
        if os.path.isdir(os.path.join(runs_dir, name))
    ]
    return max(candidates, key=os.path.getmtime) if candidates else None


def _legacy_entries(root):
    if not os.path.isdir(root):
        return []
    return [
        os.path.join(root, name)
        for name in os.listdir(root)
        if name not in _ROOT_METADATA
    ]


def _move_legacy_run(root, now=None):
    entries = _legacy_entries(root)
    if not entries:
        return None
    runs_dir = os.path.join(root, RUNS_DIRNAME)
    os.makedirs(runs_dir, exist_ok=True)
    run_id = _unique_run_id(runs_dir, prefix=f"legacy-{_timestamp(now)}")
    target = os.path.join(runs_dir, run_id)
    os.makedirs(target)
    for entry in entries:
        shutil.move(entry, os.path.join(target, os.path.basename(entry)))
    return target


def _new_run(root, now=None):
    runs_dir = os.path.join(root, RUNS_DIRNAME)
    os.makedirs(runs_dir, exist_ok=True)
    run_id = _unique_run_id(runs_dir, now=now)
    work_dir = os.path.join(runs_dir, run_id)
    os.makedirs(work_dir)
    _write_current(root, run_id)
    return work_dir, run_id


def _activate(root, work_dir):
    run_id = os.path.basename(work_dir)
    _write_current(root, run_id)
    return run_id


def _prompt_action(input_fn, output_fn):
    output_fn("[Pipeline] Existing FM-Agent results were found. Choose an action:")
    output_fn("  1. Resume the current run")
    output_fn("  2. Archive it and start a new run")
    output_fn("  3. Overwrite it and start a new run")
    output_fn("  4. Exit")
    aliases = {
        "1": "resume", "r": "resume", "resume": "resume",
        "2": "archive", "a": "archive", "archive": "archive",
        "3": "overwrite", "o": "overwrite", "overwrite": "overwrite",
        "4": "exit", "e": "exit", "q": "exit", "exit": "exit",
    }
    while True:
        answer = input_fn("Select [1-4]: ").strip().lower()
        if answer in aliases:
            return aliases[answer]
        output_fn("Please enter 1, 2, 3, or 4.")


def select_run_workspace(
    proj_dir,
    resume_requested=False,
    *,
    input_fn=input,
    output_fn=print,
    interactive=None,
    now=None,
):
    """Select or create a safe run workspace for one invocation.

    Legacy flat ``fm_agent/`` results are moved into ``runs/legacy-*`` before
    they are resumed or archived. In a non-interactive terminal, existing
    results are never modified unless ``--resume`` was explicitly requested.
    """
    root = workspace_root(proj_dir)
    os.makedirs(root, exist_ok=True)
    active = current_run_dir(proj_dir)
    legacy = _legacy_entries(root)
    existing = active
    if not existing and legacy:
        existing = root

    if not existing:
        work_dir, run_id = _new_run(root, now=now)
        output_fn(f"[Pipeline] New run: {workdir_relpath(proj_dir, work_dir)}/")
        return RunSelection(work_dir, run_id, False, "new")

    if resume_requested:
        if existing == root:
            existing = _move_legacy_run(root, now=now)
        run_id = _activate(root, existing)
        output_fn(f"[Pipeline] RESUME: {workdir_relpath(proj_dir, existing)}/")
        return RunSelection(existing, run_id, True, "resume")

    if interactive is None:
        interactive = sys.stdin.isatty()
    if not interactive:
        raise RunSelectionCancelled(
            "Existing FM-Agent results found. Re-run with --resume in a "
            "non-interactive terminal, or run interactively to archive, overwrite, or exit."
        )

    action = _prompt_action(input_fn, output_fn)
    if action == "exit":
        raise RunSelectionCancelled("Run cancelled; existing results were not changed.")
    if action == "resume":
        if existing == root:
            existing = _move_legacy_run(root, now=now)
        run_id = _activate(root, existing)
        return RunSelection(existing, run_id, True, action)
    if action == "archive":
        if existing == root:
            archived = _move_legacy_run(root, now=now)
        else:
            archived = existing
        output_fn(f"[Pipeline] Archived previous run at {workdir_relpath(proj_dir, archived)}/")
        work_dir, run_id = _new_run(root, now=now)
        output_fn(f"[Pipeline] New run: {workdir_relpath(proj_dir, work_dir)}/")
        return RunSelection(work_dir, run_id, False, action)

    # Overwrite is the only path that removes prior results, and it is reachable
    # only through an explicit interactive choice.
    if existing == root:
        for entry in _legacy_entries(root):
            if os.path.isdir(entry) and not os.path.islink(entry):
                shutil.rmtree(entry)
            else:
                os.unlink(entry)
    else:
        shutil.rmtree(existing)
    work_dir, run_id = _new_run(root, now=now)
    output_fn(f"[Pipeline] Previous run overwritten; new run: {workdir_relpath(proj_dir, work_dir)}/")
    return RunSelection(work_dir, run_id, False, action)

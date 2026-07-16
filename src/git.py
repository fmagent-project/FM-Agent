"""Git helpers for the pipeline: querying repo state, recording processed
commits, and building the frozen worktree snapshot used by --isolate."""

import os
import shutil
import subprocess
import logging
import tempfile
import contextlib


def _is_git_repo(proj_dir):
    """Return whether proj_dir is a git repository with at least one commit."""
    try:
        subprocess.run(
            ["git", "-C", proj_dir, "rev-parse", "--verify", "HEAD"],
            check=True, capture_output=True, text=True,
        )
        return True
    except subprocess.CalledProcessError:
        return False


def _get_head_commit(proj_dir):
    """Return the latest git commit id of proj_dir, or None if not a git repo."""
    try:
        return subprocess.run(
            ["git", "-C", proj_dir, "rev-parse", "HEAD"],
            check=True, capture_output=True, text=True,
        ).stdout.strip()
    except subprocess.CalledProcessError:
        logging.info("_get_head_commit: %s is not a git repo.", proj_dir)
        return None


def _record_version(commit_id, work_dir):
    """Append commit_id as a new line to fm_agent/version.log, building up a
    history of processed commits. No-op when commit_id is falsy."""
    if not commit_id:
        return
    version_path = os.path.join(work_dir, "version.log")
    with open(version_path, "a") as f:
        f.write(commit_id + "\n")


@contextlib.contextmanager
def frozen_worktree(proj_dir, exclude=("fm_agent",), copy_excluded=True):
    """Freeze proj_dir's current working tree into an isolated git worktree.

    Captures committed state PLUS uncommitted edits and untracked files, so the
    yielded copy is a faithful snapshot of proj_dir at entry time. Concurrent
    edits to proj_dir afterwards do not affect the snapshot, letting the pipeline
    run against a stable copy.

    The snapshot is built through a private index (GIT_INDEX_FILE), so proj_dir's
    real index and working tree are never touched. Falls back to a plain directory
    copy when proj_dir is not a git repository with a commit. The snapshot folder
    is left in place after the run (including its fm_agent/ outputs); its path is
    logged so it can be inspected or cleaned up manually.

    The `exclude` dirs (the FM-Agent's own workspace) are always kept out of the
    git snapshot commit so it stays clean. When `copy_excluded` is set, they are
    then copied into the worktree as-is. Incremental mode needs the previous run's
    fm_agent/ results to detect a prior full run, and those results are typically
    gitignored, hence absent from the snapshot commit. A full run discards any
    prior fm_agent/, so it passes copy_excluded=False to skip the copy.
    """
    proj_dir = os.path.abspath(proj_dir)
    # Include the repo name in the temp dir so concurrent runs across different
    # repos are distinguishable (e.g. /tmp/fm_agent_wt_myrepo_a3k9d2/snapshot).
    repo_name = os.path.basename(proj_dir.rstrip(os.sep)) or "repo"
    base = tempfile.mkdtemp(prefix=f"fm_agent_wt_{repo_name}_")
    wt = os.path.join(base, "snapshot")

    def _git(*args, **kwargs):
        return subprocess.run(
            ["git", "-C", proj_dir, *args],
            check=True, capture_output=True, text=True, **kwargs,
        ).stdout.strip()

    is_git = False
    try:
        _git("rev-parse", "--verify", "HEAD")
        is_git = True
    except subprocess.CalledProcessError:
        pass

    if is_git:
        env = dict(os.environ, GIT_INDEX_FILE=os.path.join(base, "index"))
        _git("read-tree", "HEAD", env=env)
        # Stage the full working tree (tracked edits + untracked files). Using a
        # bare `git add -A` lets git silently skip gitignored paths; passing the
        # workspace dirs as :(exclude) pathspecs instead errors out when a repo
        # already gitignores them ("paths are ignored ... use -f"). Drop the
        # workspace dirs from the private index afterwards to cover repos that do
        # NOT gitignore them.
        _git("add", "-A", env=env)
        if exclude:
            _git("rm", "-r", "--cached", "--quiet", "--ignore-unmatch", "--",
                 *exclude, env=env)
        tree = _git("write-tree", env=env)
        snap = _git("commit-tree", tree, "-p", "HEAD", "-m", "fm_agent snapshot")
        _git("worktree", "add", "--detach", wt, snap)
    else:
        logging.info("frozen_worktree: %s is not a git repo; copying instead.", proj_dir)
        shutil.copytree(
            proj_dir, wt,
            ignore=shutil.ignore_patterns(*exclude),
            symlinks=True,
        )

    # Copy the excluded workspace dirs (e.g. fm_agent/ with a prior full run's
    # phases.json and extracted_functions) into the snapshot. They were kept out
    # of the git commit, but incremental mode reads them from disk to compare
    # against, so the snapshot must physically contain them.
    if copy_excluded:
        for name in exclude:
            src = os.path.join(proj_dir, name)
            dst = os.path.join(wt, name)
            if os.path.isdir(src) and not os.path.exists(dst):
                shutil.copytree(src, dst, symlinks=True)

    print(f"[Pipeline] Snapshot created at: {wt}")
    print(f"[Pipeline] Snapshot is kept after the run. "
          f"Remove with: git -C {proj_dir} worktree remove --force {wt}"
          if is_git else
          f"[Pipeline] Snapshot is kept after the run. Remove with: rm -rf {wt}")
    yield wt

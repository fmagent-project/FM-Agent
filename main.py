from config import (
    OPENCODE_MAX_RETRIES,
    OPENCODE_SETUP_MODEL,
    OPENCODE_SPEC_MODEL,
    OPENCODE_MODEL_PROVIDER,
)
from src.entry_reasoning_pipeline import run_entry_pipeline
from src.file_utils import collect_file_names, is_file_ready
from src.verification import streaming_reasoner
from src.extract import run_extraction, EXT_TO_LANG, _is_test_file
from src.generate_topdown_layers import generate_topdown_layers
from src.opencode_trace import (
    finish_opencode_trace,
    function_id_from_extracted_path,
    run_opencode_traced,
    start_opencode_traced,
)
from src.cli_backend import build_agent_command, is_cli_backend_enabled
from src.incremental_reasoner import run_incremental_pipeline
from src.languages.codegraph import try_codegraph_init
import os
import sys
import argparse
import json
import time
import shutil
import subprocess
import logging
import tempfile
import contextlib

def _merge_descriptions(target_desc, source_desc):
    """Append a removed module's description to the owning module's description.

    Avoids re-merging the same content if it is already present.
    """
    source_desc = (source_desc or "").strip()
    if not source_desc:
        return target_desc
    if source_desc in target_desc:
        return target_desc
    if not target_desc:
        return source_desc
    return f"{target_desc}\n\n{source_desc}"

def _deduplicate_phases(phases_dir):
    """Ensure each source file appears in at most one phase; keep the earliest."""
    phases_path = os.path.join(phases_dir, "phases.json")
    with open(phases_path, "r") as f:
        data = json.load(f)

    seen = set()
    # Maps each kept source file to the module that first claimed (owns) it.
    file_owner = {}
    phases_to_remove = []
    for phase in sorted(data["phases"], key=lambda p: p["phase"]):
        modules_to_remove = []
        for module in phase["modules"]:
            original = module["source_files"]
            deduped = []
            for sf in original:
                if sf not in seen:
                    seen.add(sf)
                    file_owner[sf] = module
                    deduped.append(sf)
                else:
                    logging.info(
                        "Removed duplicate file '%s' from phase %d module '%s'",
                        sf, phase["phase"], module["name"],
                    )
            module["source_files"] = deduped
            if not deduped:
                # Module lost all its files to deduplication. Merge its description
                # into the owning modules that now hold those same files, then drop it.
                owners = []
                for sf in original:
                    owner = file_owner.get(sf)
                    if owner is not None and owner is not module and owner not in owners:
                        owners.append(owner)
                for owner in owners:
                    owner["description"] = _merge_descriptions(
                        owner.get("description", ""),
                        module.get("description", ""),
                    )
                logging.info(
                    "Removing empty module '%s' from phase %d; merged its description into %d module(s): %s",
                    module.get("name", ""), phase["phase"], len(owners),
                    ", ".join(o.get("name", "") for o in owners),
                )
                modules_to_remove.append(module)
        for module in modules_to_remove:
            phase["modules"].remove(module)
        total_files = sum(len(m["source_files"]) for m in phase["modules"])
        if total_files == 0:
            logging.info("Removing phase %d: no source files remain after deduplication", phase["phase"])
            phases_to_remove.append(phase)
    for phase in phases_to_remove:
        data["phases"].remove(phase)

    # Renumber phases sequentially and update depends_on_phases references
    old_to_new = {}
    for idx, phase in enumerate(sorted(data["phases"], key=lambda p: p["phase"]), start=1):
        old_to_new[phase["phase"]] = idx
        phase["phase"] = idx
    for phase in data["phases"]:
        phase["depends_on_phases"] = [
            old_to_new[dep] for dep in phase.get("depends_on_phases", [])
            if dep in old_to_new
        ]

    with open(phases_path, "w") as f:
        json.dump(data, f, indent=2)

def _get_phase_files(phases_data, phase_num, input_dir):
    """Return relative paths of extracted function files for a given phase."""
    phase = next(p for p in phases_data["phases"] if p["phase"] == phase_num)
    phase_files = []
    for module in phase["modules"]:
        for src_file in module["source_files"]:
            dir_part = os.path.dirname(src_file)
            base = os.path.basename(src_file)
            dot_idx = base.rfind(".")
            if dot_idx >= 0:
                subdir = base[:dot_idx] + "-" + base[dot_idx + 1:]
            else:
                subdir = base
            extracted_dir = os.path.join(input_dir, dir_part, subdir)
            if os.path.isdir(extracted_dir):
                for fname in sorted(os.listdir(extracted_dir)):
                    fpath = os.path.join(extracted_dir, fname)
                    if os.path.isfile(fpath):
                        phase_files.append(os.path.relpath(fpath, input_dir))
    return phase_files



def _clean_previous_run(work_dir):
    """Remove the fm_agent working directory from the previous pipeline run."""
    if os.path.isdir(work_dir):
        shutil.rmtree(work_dir)


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


def _get_pending_batches(batches, proj_dir):
    """Return batches that still have at least one function without specs."""
    pending = []
    for batch in batches:
        for func_rel in batch.get("functions", []):
            full_path = os.path.join(proj_dir, func_rel)
            if not is_file_ready(full_path):
                pending.append(batch)
                break
    return pending


def _json_file_is_valid(path):
    try:
        with open(path, "r") as f:
            json.load(f)
        return True
    except (OSError, json.JSONDecodeError):
        return False


def _get_incomplete_verification_files(layer_files, input_dir, output_dir, work_dir):
    """Return layer files missing verification or required bug validation output."""
    incomplete = []
    for rel in layer_files:
        result_path = os.path.join(output_dir, os.path.splitext(rel)[0] + ".json")
        try:
            with open(result_path, "r") as f:
                result = json.load(f)
        except (OSError, json.JSONDecodeError):
            incomplete.append(rel)
            continue

        if result.get("verdict") != "MISMATCH":
            continue

        bug_id = os.path.splitext(rel)[0].replace(os.sep, "--").replace("/", "--")
        validation_path = os.path.join(work_dir, "bug_validation", f"{bug_id}.result.json")
        if not _json_file_is_valid(validation_path):
            incomplete.append(rel)
    return incomplete


def _setup_outputs_complete(work_dir):
    """Return True only if the setup_context stage produced ALL its output files.

    The setup stage (Stage 1) is responsible for writing, per
    md/workflow_setup_extract.md:
      1. phases.json
      2. spec_prompts/domain_context/engine_overview.txt
      3. spec_prompts/domain_context/phase_NN_types.txt — one per phase

    An interrupted run can leave phases.json behind without the domain-context
    files, which are later read by the spec-generation batch prompts. Resuming
    must only skip setup when every one of these exists, otherwise the missing
    files have to be regenerated.
    """
    phases_path = os.path.join(work_dir, "phases.json")
    if not _json_file_is_valid(phases_path):
        return False

    domain_dir = os.path.join(work_dir, "spec_prompts", "domain_context")
    if not os.path.exists(os.path.join(domain_dir, "engine_overview.txt")):
        return False

    try:
        with open(phases_path, "r") as f:
            phases_data = json.load(f)
    except (OSError, json.JSONDecodeError):
        return False

    for phase in phases_data.get("phases", []):
        phase_num = phase.get("phase")
        if phase_num is None:
            # Malformed phases.json — can't verify this phase's types file, and
            # downstream stages require p["phase"]. Re-run setup rather than
            # claim completeness.
            return False
        types_path = os.path.join(domain_dir, f"phase_{phase_num:02d}_types.txt")
        if not os.path.exists(types_path):
            return False

    return True


def _has_source_code(proj_dir):
    """Check whether proj_dir contains at least one source code file."""
    source_exts = set(EXT_TO_LANG.keys())
    for root, dirs, files in os.walk(proj_dir):
        # Skip hidden dirs and common non-source dirs
        dirs[:] = [d for d in dirs if not d.startswith('.') and d not in
                   {'node_modules', '__pycache__', 'venv', '.venv', 'fm_agent'}]
        for fname in files:
            ext = fname.rsplit('.', 1)[-1] if '.' in fname else ''
            if ext in source_exts:
                return True
    return False


def _collect_project_source_files(proj_dir):
    """Return non-test source files currently present in proj_dir, relative to proj_dir."""
    source_exts = set(EXT_TO_LANG.keys())
    files = set()
    for root, dirs, names in os.walk(proj_dir):
        dirs[:] = [d for d in dirs if not d.startswith('.') and d not in
                   {'node_modules', '__pycache__', 'venv', '.venv', 'fm_agent'}]
        for fname in names:
            ext = fname.rsplit('.', 1)[-1] if '.' in fname else ''
            if ext not in source_exts:
                continue
            rel = os.path.relpath(os.path.join(root, fname), proj_dir).replace(os.sep, '/')
            if not _is_test_file(rel):
                files.add(rel)
    return files


def _phases_cover_current_sources(phases_json, proj_dir):
    """Return whether phases.json is valid for the current source-file set."""
    try:
        with open(phases_json, "r") as f:
            data = json.load(f)
    except (OSError, ValueError):
        return False

    listed = set()
    for phase in data.get("phases", []):
        for module in phase.get("modules", []):
            for source_file in module.get("source_files", []):
                listed.add(source_file.replace("\\", "/"))

    if not listed:
        return False
    if any(not os.path.exists(os.path.join(proj_dir, sf)) for sf in listed):
        return False
    return _collect_project_source_files(proj_dir).issubset(listed)


def _ensure_source_files_in_phases(phases_json, required_source_files):
    """Force-list ``required_source_files`` in phases.json if the agent omitted them.

    The Stage 1 setup agent decides which source files go into phases.json and may
    leave out files that look like tests. When a caller (e.g. the entry pipeline)
    must have a specific file processed regardless, this puts any missing ones
    alone in a brand-new phase that becomes the earliest phase (number 1); every
    pre-existing phase is shifted one slot later and its ``depends_on_phases``
    references are renumbered to match. Returns the list of paths that had to be
    added.
    """
    if not required_source_files:
        return []

    with open(phases_json, "r") as f:
        data = json.load(f)

    listed = set()
    for phase in data.get("phases", []):
        for module in phase.get("modules", []):
            for sf in module.get("source_files", []):
                listed.add(sf.replace("\\", "/"))

    missing = [sf for sf in required_source_files if sf.replace("\\", "/") not in listed]
    if not missing:
        return []

    existing = sorted(data.get("phases", []), key=lambda p: p.get("phase", 0))

    # The new entry phase takes slot 1; existing phases shift to 2, 3, ... in
    # their original relative order. Renumber depends_on_phases through the same map.
    old_to_new = {p["phase"]: idx for idx, p in enumerate(existing, start=2) if "phase" in p}
    for phase in existing:
        if "phase" in phase:
            phase["phase"] = old_to_new[phase["phase"]]
        phase["depends_on_phases"] = [
            old_to_new[dep] for dep in phase.get("depends_on_phases", []) if dep in old_to_new
        ]

    entry_phase = {
        "phase": 1,
        "name": "Entry Points",
        "description": "Entry-point source files.",
        "modules": [{
            "name": "entry_points",
            "description": "Entry-point source files.",
            "source_files": list(missing),
        }],
        "depends_on_phases": [],
    }
    data["phases"] = [entry_phase] + existing

    with open(phases_json, "w") as f:
        json.dump(data, f, indent=2)
    return missing


def _run_setup_extract(proj_dir, work_dir, script_dir, is_incremental=False, resume=False):
    """Stage 1: prepare the setup workflow file and run opencode (with retries) to produce phases.json."""
    # On resume, reuse the existing phase plan instead of paying for the
    # setup_context LLM call again.
    _resume_skip_setup = resume and _setup_outputs_complete(work_dir)
    if _resume_skip_setup:
        print("[Pipeline] Stage 1/4: RESUME — all setup outputs found, skipping setup_context (reusing phase plan).")

    workflow_src = os.path.join(script_dir, "md", "workflow_setup_extract.md")
    workflow_dst = os.path.join(work_dir, "workflow_setup_extract.md")
    shutil.copy2(workflow_src, workflow_dst)
    _proj_dir_abs = os.path.abspath(proj_dir)
    _proj_dir_name = os.path.basename(_proj_dir_abs)
    with open(workflow_dst, "r") as _f:
        _md = _f.read()
    _old = ("- `phases[*].modules[*].source_files` — relative paths from repo root of all source files "
            "that belong to this module.")
    _new = (f"- `phases[*].modules[*].source_files` — relative paths from the project root "
            f"`{_proj_dir_abs}` of all source files that belong to this module. "
            f"For example, a file at `{_proj_dir_abs}/path/to/file.ext` must be recorded as "
            f"`path/to/file.ext`, NOT as `{_proj_dir_name}/path/to/file.ext`.")
    _md = _md.replace(_old, _new, 1)
    with open(workflow_dst, "w") as _f:
        _f.write(_md)
    fm_reminder = ("IMPORTANT: The fm_agent/ directory is NOT part of the project source code. "
                    "It is a workspace for storing your output files only. "
                    "Do NOT include fm_agent/ paths in phases.json. "
                    "Do NOT modify any existing project files.")
    incremental_reminder = ("IMPORTANT: An existing fm_agent/phases.json from a previous run is already "
                            "present. Do NOT regenerate it from scratch. Instead, inspect the current "
                            "state of the source code and UPDATE the existing fm_agent/phases.json so it "
                            "reflects the current version of the code: add modules and source files that "
                            "are new, remove entries whose files no longer exist, and adjust phases as "
                            "needed. Preserve entries that are still accurate.")

    phases_json = os.path.join(work_dir, "phases.json")
    prev_mtime = os.path.getmtime(phases_json) if os.path.exists(phases_json) else None

    for attempt in range(1, OPENCODE_MAX_RETRIES + 1):
        if _resume_skip_setup:
            break
        if attempt == 1 and not resume:
            prompt = f"Follow the instructions in the attached file. {fm_reminder}"
        else:
            # Either resuming a previously interrupted run or retrying after a
            # failed attempt — in both cases some setup outputs may already
            # exist (e.g. phases.json or part of the domain-context files). Have
            # the agent inspect what's there and only fill the gaps instead of
            # regenerating everything and overwriting valid work.
            prompt = ("A previous setup attempt was interrupted and may have already produced some of the "
                      "required output files. Follow the instructions in the attached file, but FIRST "
                      "check the current progress in fm_agent/ (e.g. phases.json and the "
                      "spec_prompts/domain_context/ files). Keep any existing valid output as-is and only "
                      "generate the files that are missing or incomplete — do NOT regenerate or overwrite "
                      f"work that is already done. {fm_reminder}")
        if is_incremental:
            prompt = f"{prompt} {incremental_reminder}"
        prompt_file = os.path.join(proj_dir, "fm_agent", "workflow_setup_extract.md")
        if is_cli_backend_enabled():
            command = build_agent_command(
                model=OPENCODE_SETUP_MODEL,
                prompt=prompt,
                cwd=proj_dir,
                files=[prompt_file],
            )
        else:
            command = ["opencode", "run", "--model", f"{OPENCODE_MODEL_PROVIDER}/{OPENCODE_SETUP_MODEL}",
                       "--file", prompt_file, "--", prompt]
        try:
            run_opencode_traced(
                proj_dir=proj_dir,
                work_dir=work_dir,
                command=command,
                stage="setup_context",
                input_files=["fm_agent/workflow_setup_extract.md"],
                output_files=[
                    "fm_agent/phases.json",
                    "fm_agent/spec_prompts/domain_context/engine_overview.txt",
                ],
                summary=f"OpenCode setup context attempt {attempt}",
                metadata={"attempt": attempt},
            )
        except subprocess.CalledProcessError as e:
            logging.warning(f"Stage 1 attempt {attempt}: opencode exited with code {e.returncode}")

        # Validate that the agent produced phases.json. In incremental mode the file
        # already exists; it may legitimately remain byte-for-byte unchanged for same-file
        # edits, so accept it when it still covers the current source files.
        if os.path.exists(phases_json):
            if (
                not is_incremental
                or os.path.getmtime(phases_json) != prev_mtime
                or _phases_cover_current_sources(phases_json, proj_dir)
            ):
                break

        failure = "update phases.json" if is_incremental else "produce phases.json"
        missing = "phases.json was not updated" if is_incremental else "phases.json missing"
        if attempt < OPENCODE_MAX_RETRIES:
            delay = 10
            print(
                f"[Pipeline] Stage 1 failed to {failure} (attempt {attempt}/{OPENCODE_MAX_RETRIES}). "
                f"Retrying in {delay}s..."
            )
            logging.warning(f"Stage 1 attempt {attempt} failed: {missing}. Retrying in {delay}s.")
            time.sleep(delay)
        else:
            print(
                f"[Pipeline] ERROR: Stage 1 failed after {OPENCODE_MAX_RETRIES} attempts. "
                f"{missing}. "
                f"Check {os.path.basename(proj_dir)}/fm_agent/trace/ for details."
            )
            sys.exit(1)

    # Deduplicate source files across phases
    _deduplicate_phases(work_dir)


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


def run_pipeline(proj_dir, resume=False, required_source_files=None):
    if not os.path.isdir(proj_dir):
        print(f"[Pipeline] ERROR: proj_dir does not exist or is not a directory: {proj_dir}")
        sys.exit(1)

    if not _has_source_code(proj_dir):
        print(f"[Pipeline] ERROR: No source code files found in {proj_dir}. "
              f"Supported extensions: {', '.join(sorted(EXT_TO_LANG.keys()))}")
        sys.exit(1)

    work_dir = os.path.join(proj_dir, "fm_agent")
    input_dir = os.path.join(work_dir, "extracted_functions")
    output_dir = os.path.join(work_dir, "logic_verification_results")
    script_dir = os.path.dirname(os.path.abspath(__file__))

    # Clean files from the previous run — unless resuming, where we keep all
    # prior progress (phases.json, generated specs, verification results) and
    # only do the remaining work.
    if resume:
        if os.path.isdir(work_dir):
            print(f"[Pipeline] RESUME: keeping existing {os.path.relpath(work_dir, proj_dir)}/ — only remaining work will run.")
        else:
            print("[Pipeline] RESUME requested but no previous fm_agent/ found — starting fresh.")
            resume = False
    else:
        _clean_previous_run(work_dir)
    os.makedirs(work_dir, exist_ok=True)

    # Copy workflow_setup_extract.md to proj_dir and run opencode against it
    print("[Pipeline] Stage 1/4: Understanding codebase and extracting functions ...")
    _run_setup_extract(proj_dir, work_dir, script_dir, resume=resume)

    # The setup agent may have omitted required files (e.g. an entry point that
    # looks like a test) from phases.json. Force them in before extraction so the
    # caller's mandatory files are always processed.
    forced = _ensure_source_files_in_phases(
        os.path.join(work_dir, "phases.json"), required_source_files
    )
    if forced:
        print(f"[Pipeline] Forced {len(forced)} required source file(s) into phases.json: {', '.join(forced)}")

    # Build codegraph index if codegraph is installed and index not yet present.
    # Both run_extraction (Stage 2) and generate_topdown_layers (Stage 3) will
    # automatically use the index when it exists.
    try_codegraph_init(proj_dir)

    # Run function extraction using extract.py
    # force=False on resume preserves already-specced extracted files; on a fresh
    # run fm_agent/ was just wiped so it is equivalent to force=True.
    print("[Pipeline] Extracting functions from source files...")
    run_extraction(proj_dir, work_dir=work_dir, force=not resume, verbose=True)

    # Copy system_prompt.md to spec_prompts/system_prompt.md
    spec_prompts_dir = os.path.join(work_dir, "spec_prompts")
    os.makedirs(spec_prompts_dir, exist_ok=True)
    shutil.copy2(
        os.path.join(script_dir, "md", "system_prompt.md"),
        os.path.join(spec_prompts_dir, "system_prompt.md"),
    )
    shutil.copy2(
        os.path.join(script_dir, "src", "generate_batch_prompts.py"),
        os.path.join(spec_prompts_dir, "generate_batch_prompts.py"),
    )
    # generate_batch_prompts.py imports is_file_ready from this module at runtime.
    shutil.copy2(
        os.path.join(script_dir, "src", "file_utils.py"),
        os.path.join(spec_prompts_dir, "file_utils.py"),
    )

    print("[Pipeline] Stage 2/4: Collecting file list...")
    file_list = collect_file_names(input_dir, os.path.join(work_dir, "fm_agent_file_list.json"))

    if not file_list:
        print("[Pipeline] No functions found to verify. Skipping spec generation.")
        return

    # --- Stage 3: Generate topdown layers ---
    print("[Pipeline] Stage 3/4: Generating topdown layers...")
    phases_data = json.load(open(os.path.join(work_dir, "phases.json")))
    generate_topdown_layers(work_dir)

    # --- Stage 4: Execute spec generation workflow (per phase, per layer) ---
    print("[Pipeline] Stage 4/4: Generating specs & verification...")
    batch_md_src = os.path.join(script_dir, "md", "workflow_spec_step4_batch.md")
    batch_md_dst = os.path.join(work_dir, "workflow_spec_step4_batch.md")
    shutil.copy2(batch_md_src, batch_md_dst)

    all_processed = set()
    num_phases = len(phases_data["phases"])
    project_name = phases_data.get("project", "project")

    for phase_info in sorted(phases_data["phases"], key=lambda p: p["phase"]):
        phase_num = phase_info["phase"]
        phase_name = phase_info["name"]
        phase_files = _get_phase_files(phases_data, phase_num, input_dir)

        if not phase_files:
            logging.info(f"Phase {phase_num} ({phase_name}): no extracted files, skipping.")
            continue

        # Determine how many layers this phase has
        layers_json_path = os.path.join(
            spec_prompts_dir, f"phase_{phase_num:02d}_topdown_layers.json"
        )
        if not os.path.exists(layers_json_path):
            generate_topdown_layers(work_dir, [phase_num])
        with open(layers_json_path, "r") as f:
            layers_data = json.load(f)
        total_layers = layers_data.get("total_layers", 1)

        batch_dir = os.path.join(
            spec_prompts_dir,
            f"batch_prompts_{project_name}_phase{phase_num:02d}",
        )

        for layer_idx in range(total_layers):
            print(f"[Pipeline] Stage 4/4: Phase {phase_num}/{num_phases} — {phase_name}, Layer {layer_idx}/{total_layers - 1}")

            # Generate batch prompts for this layer. On resume, skip functions
            # that were already specced in a previous run.
            batch_cmd = ["python3", "fm_agent/spec_prompts/generate_batch_prompts.py",
                         "--phase", str(phase_num), "--layers", str(layer_idx)]
            if resume:
                batch_cmd.append("--resume")
            subprocess.run(batch_cmd, cwd=proj_dir, check=True)

            # Read manifest
            manifest_path = os.path.join(batch_dir, "manifest.json")
            with open(manifest_path, "r") as f:
                manifest = json.load(f)
            all_batches = manifest.get("batches", [])

            if not all_batches:
                logging.info(f"Phase {phase_num} Layer {layer_idx}: no batches, skipping.")
                continue

            batch_rel_dir = os.path.relpath(batch_dir, proj_dir)

            # Build file list for this layer from the manifest
            layer_files = []
            for batch_info in all_batches:
                for func_rel in batch_info.get("functions", []):
                    rel = os.path.relpath(os.path.join(proj_dir, func_rel), input_dir)
                    layer_files.append(rel)

            layer_processed = set()

            for attempt in range(1, OPENCODE_MAX_RETRIES + 1):
                # Find batches with unspecced functions
                pending_batches = _get_pending_batches(all_batches, proj_dir)
                if not pending_batches:
                    incomplete_verification = _get_incomplete_verification_files(
                        layer_files, input_dir, output_dir, work_dir
                    )
                    if incomplete_verification:
                        logging.info(
                            f"Phase {phase_num} Layer {layer_idx}: "
                            f"{len(incomplete_verification)} ready file(s) still need verification or validation"
                        )
                        newly_processed = streaming_reasoner(
                            input_dir, output_dir, file_list=layer_files,
                            proj_dir=proj_dir, work_dir=work_dir,
                            spec_procs=None,
                            already_processed=all_processed | layer_processed,
                            resume=resume,
                        )
                        layer_processed.update(newly_processed)
                    break

                # Spawn concurrent opencode processes (one per pending batch)
                spec_procs = []
                spec_trace_records = []
                for batch_info in pending_batches:
                    batch_file = batch_info["file"]
                    batch_prompt_rel = os.path.join(batch_rel_dir, batch_file)
                    batch_prompt_abs = os.path.join(proj_dir, batch_prompt_rel)
                    # On resume a batch whose functions are all already specced
                    # has no prompt file written and nothing for the agent to do
                    # — skip it instead of sending an empty batch.
                    if batch_info.get("num_pending", 1) == 0 or not os.path.exists(batch_prompt_abs):
                        logging.info(f"Skipping batch with no functions to spec: {batch_file}")
                        continue
                    function_files = batch_info.get("functions", [])
                    function_ids = [
                        function_id_from_extracted_path(func_rel)
                        for func_rel in function_files
                    ]
                    fm_reminder = ("IMPORTANT: fm_agent/ is your output workspace, not project source. "
                                    "Do NOT modify any existing project files.")
                    if attempt == 1:
                        prompt = (
                            f"Process the batch prompt file at {batch_prompt_rel}. "
                            f"Read it and fm_agent/spec_prompts/system_prompt.md, "
                            f"generate behavioral specs for each function listed, "
                            f"and write the complete specced files directly. {fm_reminder}"
                        )
                    else:
                        prompt = (
                            f"Continue processing the batch prompt file at {batch_prompt_rel}. "
                            f"Some functions may already have specs from a previous attempt. "
                            f"Check each function file — only generate specs for those "
                            f"that don't have [SPEC] blocks yet. "
                            f"Read fm_agent/spec_prompts/system_prompt.md for the format rules. {fm_reminder}"
                        )
                    prompt_file = os.path.join(proj_dir, "fm_agent", "workflow_spec_step4_batch.md")
                    if is_cli_backend_enabled():
                        command = build_agent_command(
                            model=OPENCODE_SPEC_MODEL,
                            prompt=prompt,
                            cwd=proj_dir,
                            files=[prompt_file],
                        )
                    else:
                        command = ["opencode", "run", "--model", f"{OPENCODE_MODEL_PROVIDER}/{OPENCODE_SPEC_MODEL}",
                                   "--file", prompt_file,
                                   "--", prompt]
                    trace_record = start_opencode_traced(
                        proj_dir=proj_dir,
                        work_dir=work_dir,
                        command=command,
                        stage="spec_generation",
                        function_ids=function_ids,
                        input_files=[
                            "fm_agent/workflow_spec_step4_batch.md",
                            batch_prompt_rel,
                            "fm_agent/spec_prompts/system_prompt.md",
                        ],
                        output_files=function_files,
                        summary=f"OpenCode spec generation for {batch_file}",
                        metadata={
                            "attempt": attempt,
                            "phase": phase_num,
                            "layer": layer_idx,
                            "batch_file": batch_file,
                        },
                    )
                    spec_trace_records.append(trace_record)
                    spec_procs.append(trace_record.proc)

                logging.info(
                    f"Phase {phase_num} Layer {layer_idx} attempt {attempt}: "
                    f"spawned {len(spec_procs)} opencode processes for {len(pending_batches)} batches"
                )

                newly_processed = streaming_reasoner(input_dir, output_dir, file_list=layer_files,
                                   proj_dir=proj_dir, work_dir=work_dir,
                                   spec_procs=spec_procs,
                                   already_processed=all_processed | layer_processed,
                                   resume=resume)
                layer_processed.update(newly_processed)

                for proc in spec_procs:
                    proc.wait()
                for trace_record in spec_trace_records:
                    finish_opencode_trace(trace_record)

                # Check if any files in this layer received specs
                specs_generated = sum(
                    1 for rel in layer_files
                    if is_file_ready(os.path.join(input_dir, rel))
                )
                if specs_generated > 0 and not _get_pending_batches(all_batches, proj_dir):
                    break

                if specs_generated > 0:
                    # Partial progress — retry remaining batches without delay
                    logging.info(
                        f"Phase {phase_num} Layer {layer_idx} attempt {attempt}: "
                        f"{specs_generated} specs generated, retrying remaining batches"
                    )
                    continue

                if attempt < OPENCODE_MAX_RETRIES:
                    delay = 10
                    print(
                        f"[Pipeline] Stage 4 Phase {phase_num} Layer {layer_idx} produced no specs "
                        f"(attempt {attempt}/{OPENCODE_MAX_RETRIES}). "
                        f"Retrying in {delay}s..."
                    )
                    logging.warning(
                        f"Stage 4 Phase {phase_num} Layer {layer_idx} attempt {attempt} failed: "
                        f"no specs generated. Retrying in {delay}s."
                    )
                    time.sleep(delay)
                else:
                    print(
                        f"[Pipeline] ERROR: Stage 4 Phase {phase_num} Layer {layer_idx} failed "
                        f"after {OPENCODE_MAX_RETRIES} attempts. "
                        f"No specs were generated. "
                        f"Check {os.path.basename(proj_dir)}/fm_agent/trace/ for details."
                    )
                    sys.exit(1)

        # Mark all files from this phase as processed for subsequent phases
        for rel in phase_files:
            all_processed.add(os.path.join(input_dir, rel))

    # Print confirmed bug count
    summary_path = os.path.join(work_dir, "bug_validation", "summary.json")
    if os.path.exists(summary_path):
        with open(summary_path, "r") as f:
            summary = json.load(f)
        confirmed = summary.get("total_confirmed", 0)
        print(f"[Pipeline] Confirmed bugs: {confirmed}")

    print("[Pipeline] Done.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        usage="python3 main.py <proj_dir> [--resume] [--incremental INTENT_FILE] "
              "[--isolate] [--entry-func PATH] [--end-func PATH ...]",
        description="Run the FM agent pipeline on a project directory.",
    )
    parser.add_argument("proj_dir", help="path to the project directory")
    parser.add_argument(
        "--resume",
        action="store_true",
        help="continue a previous run in <proj_dir>/fm_agent instead of wiping it: "
        "keeps phases.json, generated specs, and existing verification results; "
        "only does the remaining work.",
    )
    parser.add_argument(
        "--incremental",
        metavar="INTENT_FILE",
        help="Run in incremental mode. Value is the path to the intent file "
        "defining the goal of modification.",
    )
    parser.add_argument(
        "--isolate",
        action="store_true",
        help="Run the pipeline against an isolated git worktree snapshot of "
        "the project instead of the project directory itself.",
    )
    parser.add_argument(
        "--entry-func",
        metavar="PATH",
        default=None,
        help="function path of the entry point to start reasoning from.",
    )
    parser.add_argument(
        "--end-func",
        metavar="PATH",
        nargs="+",
        default=None,
        help="one or more function paths at which to stop (space-separated list); "
        "if omitted, the whole call graph reachable from --entry-func is analyzed.",
    )
    args = parser.parse_args()

    resume = args.resume or os.environ.get("FM_AGENT_RESUME") == "1"
    proj_dir = os.path.abspath(args.proj_dir)

    start_time = time.time()

    # Entry-point mode: reason only about the call graph reachable from a specific
    # entry function. Runs directly against the project directory (no worktree
    # isolation or incremental diffing).
    if args.entry_func is not None:
        run_entry_pipeline(
            proj_dir,
            entry_func=args.entry_func,
            end_funcs=args.end_func,
            resume=resume,
        )
        end_time = time.time()
        logging.info(f"Total time: {end_time - start_time:.2f} seconds")
        sys.exit(0)

    # Incremental mode diffs against the commit recorded by a previous run, and
    # --isolate snapshots the repo via a git worktree, so both require a git repo.
    # A non-git project can only run the full pipeline against the project directory
    # itself.
    if not _is_git_repo(proj_dir):
        parser.error(
            f"FM-Agent requires a git repository, but {proj_dir} is not."
        )

    # Resolve the intent path before snapshotting, since cwd-relative paths must
    # resolve against the real project, not the frozen worktree copy.
    intent_path = os.path.abspath(args.incremental) if args.incremental else None

    # In incremental mode the commit to diff against is the most recent one recorded
    # in version.log (the last line, since each run appends its commit). Read it from
    # the real project before snapshotting.
    old_commit = None
    if args.incremental:
        version_path = os.path.join(proj_dir, "fm_agent", "version.log")
        if os.path.exists(version_path):
            with open(version_path, "r") as f:
                commits = [line.strip() for line in f if line.strip()]
            old_commit = commits[-1] if commits else None

    # Capture the project's latest commit id before running. With --isolate the
    # pipeline runs against a throwaway worktree snapshot whose HEAD is a synthetic
    # snapshot commit, so the version to record must come from the real project.
    new_commit = _get_head_commit(proj_dir)

    # With --isolate, the pipeline runs against the snapshot's fm_agent/. Resuming
    # needs the previous run's fm_agent/ (phases.json, specs, verification results)
    # to be present in the snapshot, so copy the excluded workspace in for resume
    # too — not just incremental mode.
    run_ctx = (
        frozen_worktree(
            proj_dir, copy_excluded=bool(args.incremental) or resume
        )
        if args.isolate
        else contextlib.nullcontext(proj_dir)
    )
    with run_ctx as run_dir:
        try:
            # Incremental mode requires a recorded commit to diff against; without a
            # version.log from a previous run, fall back to the full pipeline.
            if args.incremental and old_commit:
                run_incremental_pipeline(run_dir, intent_path, old_commit)
            else:
                run_pipeline(run_dir, resume=resume)
            # Record the commit that was processed. Written after the pipeline since
            # it recreates fm_agent/; with --isolate it lives in the snapshot and is
            # copied back to the real project below. Only recorded on success so a
            # partial run does not advance the version baseline.
            _record_version(new_commit, os.path.join(run_dir, "fm_agent"))
        finally:
            # With --isolate the pipeline ran against a throwaway snapshot, so its
            # fm_agent/ results live in the snapshot. Copy them back into the real
            # project so they are not lost when the snapshot is discarded — this runs
            # even when the pipeline crashes or is interrupted mid-run, so partial
            # progress survives and can be resumed with --resume.
            if args.isolate:
                src_fm = os.path.join(run_dir, "fm_agent")
                dst_fm = os.path.join(proj_dir, "fm_agent")
                if os.path.isdir(src_fm):
                    if os.path.isdir(dst_fm):
                        shutil.rmtree(dst_fm)
                    shutil.copytree(src_fm, dst_fm, symlinks=True)
                    print(f"[Pipeline] Copied results back to {dst_fm}")
    end_time = time.time()
    logging.info(f"Total time: {end_time - start_time:.2f} seconds")

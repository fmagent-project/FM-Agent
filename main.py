from src.entry_reasoning_pipeline import run_entry_pipeline
from src.call_graph_edges import load_call_edges
from src.file_utils import (
    collect_file_names,
    _has_source_code,
    _get_all_phase_files,
    _write_file_names,
    _json_file_is_valid,
    _is_under_submodules,
)
from src.extract import run_extraction, EXT_TO_LANG
from src.generate_topdown_layers import generate_topdown_layers
from src.spec_generation_and_verification import run_spec_generation_and_verification
from src.incremental_reasoner import run_incremental_pipeline
from src.git import (
    frozen_worktree,
    _is_git_repo,
    _get_head_commit,
    _record_version,
)
from src.languages.codegraph import try_codegraph_init
from src.pipeline_setup import (
    _run_setup_extract,
)
from src.domain_knowledge import (
    collect_domain_knowledge_paths,
    stage_domain_knowledge_files,
)
import os
import sys
import argparse
import json
import time
import shutil
import logging
import contextlib


def _clean_previous_run(work_dir):
    """Remove the fm_agent working directory from the previous pipeline run."""
    if os.path.isdir(work_dir):
        shutil.rmtree(work_dir)


def _normalize_submodules(proj_dir, submodules):
    """Return validated project-relative submodule directories."""
    if not submodules:
        return []

    proj_dir = os.path.abspath(proj_dir)
    normalized = []
    seen = set()
    for raw in submodules:
        value = (raw or "").strip()
        if not value:
            continue
        candidate = value if os.path.isabs(value) else os.path.join(proj_dir, value)
        candidate = os.path.abspath(candidate)
        try:
            inside_project = os.path.commonpath([proj_dir, candidate]) == proj_dir
        except ValueError:
            inside_project = False
        if not inside_project or candidate == proj_dir:
            raise ValueError(
                f"--submodule must name subdirectories inside proj_dir, got: {raw}"
            )
        if not os.path.isdir(candidate):
            raise ValueError(f"--submodule path is not a directory: {raw}")

        rel = os.path.relpath(candidate, proj_dir).replace(os.sep, "/")
        if rel not in seen:
            normalized.append(rel)
            seen.add(rel)

    collapsed = []
    for rel in sorted(normalized, key=lambda path: (path.count("/"), path)):
        if not collapsed or not _is_under_submodules(rel, collapsed):
            collapsed.append(rel)
    return collapsed


def run_pipeline(
    proj_dir,
    resume=False,
    required_source_files=None,
    domain_knowledge_files=None,
    submodules=None,
    one_phase=False,
    extra_call_edges_path=None,
    only_spec=False,
):
    if not os.path.isdir(proj_dir):
        print(f"[Pipeline] ERROR: proj_dir does not exist or is not a directory: {proj_dir}")
        sys.exit(1)
    if not _has_source_code(proj_dir, submodules):
        scope = f" selected submodule(s): {', '.join(submodules)}" if submodules else f" {proj_dir}"
        print(f"[Pipeline] ERROR: No source code files found in{scope}. "
              f"Supported extensions: {', '.join(sorted(EXT_TO_LANG.keys()))}")
        sys.exit(1)

    work_dir = os.path.join(proj_dir, "fm_agent")
    input_dir = os.path.join(work_dir, "extracted_functions")
    output_dir = os.path.join(work_dir, "logic_verification_results")
    script_dir = os.path.dirname(os.path.abspath(__file__))
    extra_call_edges = load_call_edges(extra_call_edges_path)

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
    domain_knowledge_relpaths = stage_domain_knowledge_files(
        proj_dir, work_dir, domain_knowledge_files
    )
    if domain_knowledge_relpaths:
        print(
            "[Pipeline] User domain knowledge: "
            f"{len(domain_knowledge_relpaths)} markdown file(s)."
        )

    # Copy workflow_setup_extract.md to proj_dir and run opencode against it.
    # _run_setup_extract also force-lists any required_source_files the agent
    # omitted from phases.json before extraction runs below.
    print("[Pipeline] Stage 1/4: Understanding codebase and extracting functions ...")
    _run_setup_extract(
        proj_dir, work_dir, script_dir, resume=resume,
        required_source_files=required_source_files,
        submodules=submodules,
        one_phase=one_phase,
    )

    # Build (or rebuild) the codegraph index if codegraph is installed. Both
    # run_extraction (Stage 2) and generate_topdown_layers (Stage 3) read from it.
    # force=not resume mirrors run_extraction below: a fresh run rebuilds so the
    # index matches the current tree, while a resume reuses the existing index
    # (same tree as the interrupted run — rebuilding would just be wasted work).
    try_codegraph_init(proj_dir, force=not resume)

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

    phases_path = os.path.join(work_dir, "phases.json")
    with open(phases_path, "r") as f:
        phases_data = json.load(f)

    print("[Pipeline] Stage 2/4: Collecting file list...")
    file_list_path = os.path.join(work_dir, "fm_agent_file_list.json")
    file_list = collect_file_names(input_dir, file_list_path)
    if submodules:
        file_list = _write_file_names(
            _get_all_phase_files(phases_data, input_dir), file_list_path
        )

    if not file_list:
        print("[Pipeline] No functions found to verify. Skipping spec generation.")
        return

    # --- Stage 3: Generate topdown layers ---
    print("[Pipeline] Stage 3/4: Generating topdown layers...")
    generate_topdown_layers(work_dir, extra_call_edges=extra_call_edges)

    # --- Stage 4: Execute spec generation workflow (per phase, per layer) ---
    if only_spec:
        print("[Pipeline] Stage 4/4: Generating specs (reasoning & bug validation disabled)...")
    else:
        print("[Pipeline] Stage 4/4: Generating specs & verification...")
    run_spec_generation_and_verification(
        proj_dir,
        work_dir,
        input_dir,
        output_dir,
        script_dir,
        spec_prompts_dir,
        phases_data,
        resume=resume,
        extra_call_edges=extra_call_edges,
        only_spec=only_spec,
    )


    # Print confirmed bug count (skipped in only-spec mode, which runs no
    # reasoning or bug validation).
    if not only_spec:
        summary_path = os.path.join(work_dir, "bug_validation", "summary.json")
        if os.path.exists(summary_path):
            with open(summary_path, "r") as f:
                summary = json.load(f)
            confirmed = summary.get("total_confirmed", 0)
            print(f"[Pipeline] Confirmed bugs: {confirmed}")

    if only_spec:
        print("[Pipeline] Done (specs only; reasoning & bug validation skipped).")
    else:
        print("[Pipeline] Done.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        usage="python3 main.py <proj_dir> [--resume] [--incremental INTENT_FILE] "
              "[--domain-knowledge FILE ...] [--one-phase] [--isolate] "
              "[--submodule PATH [PATH ...]] [--entry-func PATH] "
              "[--end-func PATH ...] [--extra-edge FILE] [--only-spec]",
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
        "--one-phase",
        action="store_true",
        help="Put all planned source files into a single analysis phase.",
    )
    parser.add_argument(
        "--only-spec",
        action="store_true",
        help="Only generate behavioral specs; skip the reasoning and bug "
        "validation stages.",
    )
    parser.add_argument(
        "--domain-knowledge",
        "--knowledge",
        metavar="FILE",
        action="append",
        nargs="+",
        default=[],
        help="additional Markdown domain-knowledge file(s) to copy into "
        "fm_agent/spec_prompts/domain_context/user_knowledge/ and provide to "
        "setup, spec generation, and validation agents. May be repeated. "
        "FM_AGENT_DOMAIN_KNOWLEDGE can also provide os.pathsep-separated files.",
    )
    parser.add_argument(
        "--submodule",
        metavar="PATH",
        nargs="+",
        default=None,
        help="Only process source code under one or more subdirectories of proj_dir.",
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
    parser.add_argument(
        "--extra-edge",
        dest="extra_edge",
        metavar="FILE",
        default=None,
        help="optional JSON file, or directory of JSON files, containing "
        "supplemental caller->callee edges.",
    )
    args = parser.parse_args()

    resume = args.resume or os.environ.get("FM_AGENT_RESUME") == "1"
    proj_dir = os.path.abspath(args.proj_dir)
    extra_call_edges_path = args.extra_edge
    if extra_call_edges_path:
        extra_call_edges_path = os.path.abspath(extra_call_edges_path)
    try:
        submodules = _normalize_submodules(proj_dir, args.submodule)
    except ValueError as exc:
        parser.error(str(exc))

    try:
        domain_knowledge_files = collect_domain_knowledge_paths(
            args.domain_knowledge,
            base_dir=proj_dir,
            fallback_base_dir=os.getcwd(),
        )
    except ValueError as exc:
        parser.error(str(exc))

    if submodules and args.entry_func is not None:
        parser.error("--submodule cannot be combined with --entry-func.")

    if args.only_spec and args.incremental:
        parser.error(
            "--only-spec cannot be combined with --incremental "
            "(incremental mode is inherently a reasoning/bug-validation flow)."
        )

    # ---- pre-flight environment check (shared by all pipeline modes) ----
    import config
    from src.env_check import run as env_check_run
    if not env_check_run(proj_dir, config):
        sys.exit(0)

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
            domain_knowledge_files=domain_knowledge_files,
            one_phase=args.one_phase,
            extra_call_edges_path=extra_call_edges_path,
            only_spec=args.only_spec,
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
                run_incremental_pipeline(
                    run_dir,
                    intent_path,
                    old_commit,
                    domain_knowledge_files=domain_knowledge_files,
                    submodules=submodules,
                    one_phase=args.one_phase,
                    extra_call_edges_path=extra_call_edges_path,
                )
            else:
                run_pipeline(
                    run_dir,
                    resume=resume,
                    domain_knowledge_files=domain_knowledge_files,
                    submodules=submodules,
                    one_phase=args.one_phase,
                    extra_call_edges_path=extra_call_edges_path,
                    only_spec=args.only_spec,
                )
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

from config import (
    MAX_WORKERS,
    OPENCODE_MAX_RETRIES,
    OPENCODE_SPEC_MODEL,
    OPENCODE_MODEL_PROVIDER,
)
from src.entry_reasoning_pipeline import run_entry_pipeline
from src.file_utils import (
    collect_file_names,
    is_file_ready,
    _has_source_code,
    _get_phase_files,
    _get_all_phase_files,
    _write_file_names,
    _json_file_is_valid,
    _get_incomplete_verification_files,
    _is_under_submodules,
)
from src.verification import streaming_reasoner
from src.extract import run_extraction, EXT_TO_LANG
from src.generate_topdown_layers import generate_topdown_layers
from src.opencode_trace import (
    function_id_from_extracted_path,
    run_opencode_traced,
)
from src.cli_backend import build_agent_command, is_cli_backend_enabled
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
    list_staged_domain_knowledge_relpaths,
    stage_domain_knowledge_files,
)
import os
import sys
import argparse
import json
import time
import shutil
import subprocess
import logging
import contextlib
import concurrent.futures


def _clean_previous_run(work_dir):
    """Remove the fm_agent working directory from the previous pipeline run."""
    if os.path.isdir(work_dir):
        shutil.rmtree(work_dir)


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


def _run_spec_generation_batch(
    proj_dir,
    work_dir,
    attempt,
    phase_num,
    layer_idx,
    batch_rel_dir,
    batch_info,
):
    # Run one batch end-to-end so the executor can refill slots as soon as a
    # batch finishes, instead of waiting for a whole chunk barrier.
    batch_file = batch_info["file"]
    batch_prompt_rel = os.path.join(batch_rel_dir, batch_file)
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
            f"and write the .spec.json and .info.json files for each function. "
            f"Do not modify the function source files. {fm_reminder}"
        )
    else:
        prompt = (
            f"Continue processing the batch prompt file at {batch_prompt_rel}. "
            f"Some functions may already have specs from a previous attempt. "
            f"Check each function file — only generate specs for those "
            f"that do not have both .spec.json and .info.json files yet. "
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
        command = [
            "opencode", "run",
            "--model", f"{OPENCODE_MODEL_PROVIDER}/{OPENCODE_SPEC_MODEL}",
            "--file", prompt_file,
            "--", prompt,
        ]
    try:
        result = run_opencode_traced(
            proj_dir=proj_dir,
            work_dir=work_dir,
            command=command,
            stage="spec_generation",
            function_ids=function_ids,
            input_files=[
                "fm_agent/workflow_spec_step4_batch.md",
                batch_prompt_rel,
                "fm_agent/spec_prompts/system_prompt.md",
                *list_staged_domain_knowledge_relpaths(work_dir),
            ],
            output_files=[
                f"{function_file}.spec.json"
                for function_file in function_files
            ] + [
                f"{function_file}.info.json"
                for function_file in function_files
            ],
            summary=f"OpenCode spec generation for {batch_file}",
            metadata={
                "attempt": attempt,
                "phase": phase_num,
                "layer": layer_idx,
                "batch_file": batch_file,
            },
        )
        return result.returncode
    except subprocess.CalledProcessError as exc:
        return exc.returncode


def run_pipeline(
    proj_dir,
    resume=False,
    required_source_files=None,
    domain_knowledge_files=None,
    submodules=None,
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

                # Submit all pending spec batches through a bounded executor so
                # finished slots can immediately pick up the next batch.
                spec_futures = []
                with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
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
                        spec_futures.append(
                            executor.submit(
                                _run_spec_generation_batch,
                                proj_dir,
                                work_dir,
                                attempt,
                                phase_num,
                                layer_idx,
                                batch_rel_dir,
                                batch_info,
                            )
                        )

                    logging.info(
                        f"Phase {phase_num} Layer {layer_idx} attempt {attempt}: "
                        f"submitted {len(spec_futures)} spec-generation batch tasks "
                        f"(max_workers={MAX_WORKERS}, total_pending_batches={len(pending_batches)})"
                    )
                    if spec_futures:
                        newly_processed = streaming_reasoner(
                            input_dir, output_dir, file_list=layer_files,
                            proj_dir=proj_dir, work_dir=work_dir,
                            spec_procs=spec_futures,
                            already_processed=all_processed | layer_processed,
                            resume=resume,
                        )
                        layer_processed.update(newly_processed)

                    for future in spec_futures:
                        try:
                            future.result()
                        except Exception as exc:
                            logging.error(f"Spec generation task failed unexpectedly: {exc}")

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
              "[--domain-knowledge FILE ...] [--isolate] "
              "[--submodule PATH [PATH ...]] [--entry-func PATH] "
              "[--end-func PATH ...]",
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
    args = parser.parse_args()

    resume = args.resume or os.environ.get("FM_AGENT_RESUME") == "1"
    proj_dir = os.path.abspath(args.proj_dir)
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
                )
            else:
                run_pipeline(
                    run_dir,
                    resume=resume,
                    domain_knowledge_files=domain_knowledge_files,
                    submodules=submodules,
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

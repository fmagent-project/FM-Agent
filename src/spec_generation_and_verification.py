"""Stage 4 specification generation and verification orchestration."""

import concurrent.futures
import json
import logging
import os
import shutil
import subprocess
import sys
import time

from config import MAX_WORKERS, OPENCODE_MAX_RETRIES, OPENCODE_SPEC_MODEL
from src.backend import DEFAULT_BACKEND
from src.domain_knowledge import list_staged_domain_knowledge_relpaths
from src.file_utils import _get_incomplete_verification_files, is_file_ready
from src.generate_topdown_layers import generate_topdown_layers
from src.llm_client import build_llm_cli_command
from src.opencode_trace import function_id_from_extracted_path
from src.verification import streaming_reasoner


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


def _run_spec_generation_batch(
    proj_dir,
    work_dir,
    attempt,
    layer_idx,
    batch_rel_dir,
    batch_info,
    backend=None,
):
    backend = backend or DEFAULT_BACKEND
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
            f"Some functions may already have valid specs from a previous attempt. "
            f"Check each function listed in the batch prompt. Skip it only when both "
            f"its .spec.json and .info.json files contain valid JSON matching the "
            f"schemas in fm_agent/spec_prompts/system_prompt.md. If either sidecar "
            f"is missing, malformed, or schema-invalid, rewrite the complete "
            f".spec.json and .info.json files for that function. "
            f"Do not modify the function source files. {fm_reminder}"
        )
    prompt_file = os.path.join(proj_dir, "fm_agent", "workflow_spec_step4_batch.md")
    command = build_llm_cli_command(
        model=OPENCODE_SPEC_MODEL,
        prompt=prompt,
        cwd=proj_dir,
        files=[prompt_file],
    )
    try:
        result = backend.run_opencode_traced(
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
                "layer": layer_idx,
                "batch_file": batch_file,
                "module_names": batch_info.get("module_names", []),
            },
        )
        return result.returncode
    except subprocess.CalledProcessError as exc:
        return exc.returncode


def run_spec_generation_and_verification(
    proj_dir, work_dir, input_dir, output_dir, script_dir, spec_prompts_dir,
    modules_data, resume=False, extra_call_edges=None, only_spec=False,
    backend=None, bug_validator_path=None,
):
    backend = backend or DEFAULT_BACKEND
    # --- Stage 6: Execute spec generation workflow (per global layer) ---
    batch_md_src = os.path.join(script_dir, "md", "workflow_spec_step4_batch.md")
    batch_md_dst = os.path.join(work_dir, "workflow_spec_step4_batch.md")
    shutil.copy2(batch_md_src, batch_md_dst)

    all_processed = set()
    project_name = modules_data.get("project", "project")

    layers_json_path = os.path.join(spec_prompts_dir, "topdown_layers.json")
    if not os.path.exists(layers_json_path):
        generate_topdown_layers(work_dir, extra_call_edges=extra_call_edges)
    with open(layers_json_path, "r") as f:
        layers_data = json.load(f)
    total_layers = layers_data.get("total_layers", 1)

    batch_dir = os.path.join(spec_prompts_dir, f"batch_prompts_{project_name}")

    for layer_idx in range(total_layers):
        print(f"[Pipeline] Stage 6/6: Layer {layer_idx}/{total_layers - 1}")

        # Generate batch prompts for this layer. On resume, skip functions
        # that were already specced in a previous run.
        batch_cmd = ["python3", "fm_agent/spec_prompts/generate_batch_prompts.py",
                     "--layers", str(layer_idx)]
        if resume:
            batch_cmd.append("--resume")
        subprocess.run(batch_cmd, cwd=proj_dir, check=True)

        # Read manifest
        manifest_path = os.path.join(batch_dir, "manifest.json")
        with open(manifest_path, "r") as f:
            manifest = json.load(f)
        all_batches = manifest.get("batches", [])

        if not all_batches:
            logging.info(f"Layer {layer_idx}: no batches, skipping.")
            continue

        batch_rel_dir = os.path.relpath(batch_dir, proj_dir)

        # Build file list for this layer from the manifest
        layer_files = []
        for batch_info in all_batches:
            for func_rel in batch_info.get("functions", []):
                rel = os.path.relpath(os.path.join(proj_dir, func_rel), input_dir)
                layer_files.append(rel)

        layer_processed = set()
        specs_ready_before = 0

        for attempt in range(1, OPENCODE_MAX_RETRIES + 1):
            # Find batches with unspecced functions
            pending_batches = _get_pending_batches(all_batches, proj_dir)
            if not pending_batches:
                # All functions in this layer are specced. In only-spec mode
                # we stop here without running the reasoner/bug validation.
                if not only_spec:
                    incomplete_verification = _get_incomplete_verification_files(
                        layer_files, input_dir, output_dir, work_dir
                    )
                    if incomplete_verification:
                        logging.info(
                            f"Layer {layer_idx}: "
                            f"{len(incomplete_verification)} ready file(s) still need verification or validation"
                        )
                        newly_processed = streaming_reasoner(
                            input_dir, output_dir, file_list=layer_files,
                            proj_dir=proj_dir, work_dir=work_dir,
                            spec_procs=None,
                            already_processed=all_processed | layer_processed,
                            resume=resume,
                            backend=backend,
                            bug_validator_path=bug_validator_path,
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
                            layer_idx,
                            batch_rel_dir,
                            batch_info,
                            backend,
                        )
                    )

                logging.info(
                    f"Layer {layer_idx} attempt {attempt}: "
                    f"submitted {len(spec_futures)} spec-generation batch tasks "
                    f"(max_workers={MAX_WORKERS}, total_pending_batches={len(pending_batches)})"
                )
                if spec_futures and not only_spec:
                    newly_processed = streaming_reasoner(
                        input_dir, output_dir, file_list=layer_files,
                        proj_dir=proj_dir, work_dir=work_dir,
                        spec_procs=spec_futures,
                        already_processed=all_processed | layer_processed,
                        resume=resume,
                        backend=backend,
                        bug_validator_path=bug_validator_path,
                    )
                    layer_processed.update(newly_processed)

                for future in spec_futures:
                    try:
                        future.result()
                    except Exception as exc:
                        logging.error(f"Spec generation task failed unexpectedly: {exc}")

                if spec_futures and not only_spec:
                    # Only drain verification if no batches are still pending.
                    # If any batch is pending, its functions have no spec yet and
                    # streaming_reasoner would wait forever for them.
                    if not _get_pending_batches(all_batches, proj_dir):
                        incomplete_verification = _get_incomplete_verification_files(
                            layer_files, input_dir, output_dir, work_dir
                        )
                        if incomplete_verification:
                            logging.info(
                                f"Layer {layer_idx}: "
                                f"draining {len(incomplete_verification)} ready file(s) "
                                f"after spec-generation tasks completed"
                            )
                            newly_processed = streaming_reasoner(
                                input_dir, output_dir, file_list=layer_files,
                                proj_dir=proj_dir, work_dir=work_dir,
                                spec_procs=None,
                                already_processed=all_processed | layer_processed,
                                resume=resume,
                                backend=backend,
                                bug_validator_path=bug_validator_path,
                            )
                            layer_processed.update(newly_processed)

            # Check if any files in this layer received specs
            specs_generated = sum(
                1 for rel in layer_files
                if is_file_ready(os.path.join(input_dir, rel))
            )
            if specs_generated > 0 and not _get_pending_batches(all_batches, proj_dir):
                break

            if specs_generated > specs_ready_before and attempt < OPENCODE_MAX_RETRIES:
                new_specs = specs_generated - specs_ready_before
                logging.info(
                    f"Layer {layer_idx} attempt {attempt}: "
                    f"{new_specs} new spec(s) generated, retrying remaining batches"
                )
                specs_ready_before = specs_generated
                continue

            if attempt < OPENCODE_MAX_RETRIES:
                delay = 10
                print(
                    f"[Pipeline] Stage 6 Layer {layer_idx} produced no specs "
                    f"(attempt {attempt}/{OPENCODE_MAX_RETRIES}). "
                    f"Retrying in {delay}s..."
                )
                logging.warning(
                    f"Stage 6 Layer {layer_idx} attempt {attempt} failed: "
                    f"no specs generated. Retrying in {delay}s."
                )
                time.sleep(delay)
            else:
                pending_after = _get_pending_batches(all_batches, proj_dir)
                missing_files = []
                for batch_info in pending_after:
                    for func_rel in batch_info.get("functions", []):
                        if not is_file_ready(os.path.join(proj_dir, func_rel)):
                            missing_files.append(func_rel)
                missing_count = len(missing_files)
                print(
                    f"[Pipeline] ERROR: Stage 6 Layer {layer_idx} failed "
                    f"after {OPENCODE_MAX_RETRIES} attempts. "
                    f"{missing_count} function(s) are still missing valid specs. "
                    f"Check {os.path.basename(proj_dir)}/fm_agent/trace/ for details."
                )
                for func_rel in missing_files[:20]:
                    logging.error("Missing spec after retries: %s", func_rel)
                sys.exit(1)

        # Mark all files from this layer as processed for subsequent layers
        for rel in layer_files:
            all_processed.add(os.path.join(input_dir, rel))

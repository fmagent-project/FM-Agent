"""Execute full-run structured spec generation over phase layer manifests."""

import concurrent.futures
import json
import logging
import os
from pathlib import Path
import subprocess
import time

from config import (
    MAX_WORKERS,
    OPENCODE_MAX_RETRIES,
    OPENCODE_MODEL_PROVIDER,
    OPENCODE_SPEC_MODEL,
)
from ..cli_backend import build_agent_command, is_cli_backend_enabled
from ..domain_knowledge import list_staged_domain_knowledge_relpaths
from ..file_utils import (
    _get_incomplete_verification_files,
    _get_phase_files,
    is_file_ready,
)
from ..opencode_trace import function_id_from_extracted_path, run_opencode_traced
from ..spec_storage import metadata_paths, metadata_status
from ..verification import streaming_reasoner
from .batch_prompts import generate_batch_manifest


def _get_pending_batches(batches, proj_dir):
    """Return batches with at least one incomplete metadata pair."""
    pending = []
    for batch in batches:
        for func_rel in batch.get("functions", []):
            if not is_file_ready(os.path.join(proj_dir, func_rel)):
                pending.append(batch)
                break
    return pending


def _snapshot_function_sources(proj_dir, function_files):
    """Capture implementation bytes before an external spec agent runs."""
    return {rel: Path(proj_dir, rel).read_bytes() for rel in function_files}


def _restore_modified_sources(proj_dir, snapshots):
    """Restore agent-modified implementations and invalidate their metadata."""
    modified = []
    for rel, original in snapshots.items():
        path = Path(proj_dir, rel)
        current = path.read_bytes() if path.exists() else None
        if current == original:
            continue
        temporary = path.with_name(path.name + ".restore.tmp")
        temporary.write_bytes(original)
        os.replace(temporary, path)
        for metadata_path in metadata_paths(path):
            metadata_path.unlink(missing_ok=True)
        modified.append(rel)
    return modified


def _run_spec_generation_batch(
    proj_dir,
    work_dir,
    attempt,
    phase_num,
    layer_idx,
    batch_rel_dir,
    batch_info,
):
    """Run one agent batch and enforce implementation immutability."""
    batch_file = batch_info["file"]
    batch_prompt_rel = os.path.join(batch_rel_dir, batch_file)
    function_files = batch_info.get("functions", [])
    source_snapshots = _snapshot_function_sources(proj_dir, function_files)
    metadata_output_files = []
    for function_file in function_files:
        spec_path, info_path = metadata_paths(Path(function_file))
        metadata_output_files.extend([spec_path.as_posix(), info_path.as_posix()])
    function_ids = [
        function_id_from_extracted_path(func_rel) for func_rel in function_files
    ]
    reminder = (
        "IMPORTANT: fm_agent/ is your output workspace, not project source. "
        "Do NOT modify any existing project files."
    )
    if attempt == 1:
        prompt = (
            f"Process the batch prompt file at {batch_prompt_rel}. "
            "Read it and fm_agent/spec_prompts/system_prompt.md, generate behavioral "
            "specs for each function listed, and write both structured JSON metadata "
            f"files directly. {reminder}"
        )
    else:
        prompt = (
            f"Continue processing the batch prompt file at {batch_prompt_rel}. "
            "Some functions may already have metadata from a previous attempt. "
            "Generate both JSON files for every incomplete function in the batch. "
            f"Read fm_agent/spec_prompts/system_prompt.md for the schema rules. {reminder}"
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
            "opencode",
            "run",
            "--model",
            f"{OPENCODE_MODEL_PROVIDER}/{OPENCODE_SPEC_MODEL}",
            "--file",
            prompt_file,
            "--",
            prompt,
        ]

    return_code = 1
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
                *function_files,
                *list_staged_domain_knowledge_relpaths(work_dir),
            ],
            output_files=metadata_output_files,
            summary=f"OpenCode spec generation for {batch_file}",
            metadata={
                "attempt": attempt,
                "phase": phase_num,
                "layer": layer_idx,
                "batch_file": batch_file,
            },
        )
        return_code = result.returncode
    except subprocess.CalledProcessError as exc:
        return_code = exc.returncode
    finally:
        modified_sources = _restore_modified_sources(proj_dir, source_snapshots)

    if modified_sources:
        for source_path in modified_sources:
            logging.error(
                "Spec generation modified immutable implementation; restored: %s",
                source_path,
            )
        return 1
    return return_code


def run_spec_generation(
    proj_dir,
    work_dir,
    phases_data,
    output_dir,
    *,
    resume=False,
):
    """Generate spec/info sidecars from extracted functions and layer JSON files.

    `work_dir/extracted_functions` and every selected phase's
    `work_dir/spec_prompts/phase_NN_topdown_layers.json` must already exist. The
    function returns implementation paths processed across all phases.
    """
    proj_dir = os.path.abspath(proj_dir)
    work_dir = os.path.abspath(work_dir)
    input_dir = os.path.join(work_dir, "extracted_functions")
    spec_prompts_dir = os.path.join(work_dir, "spec_prompts")
    if not os.path.isdir(input_dir):
        raise FileNotFoundError(f"missing extracted functions directory: {input_dir}")

    project_name = phases_data.get("project", "project")
    ext_to_lang = {
        ext.lower().lstrip("."): language
        for ext, language in zip(
            phases_data.get("file_extensions", []),
            phases_data.get("languages", []),
        )
    }
    all_processed = set()
    phases = sorted(phases_data["phases"], key=lambda item: item["phase"])
    num_phases = len(phases)

    for phase_info in phases:
        phase_num = phase_info["phase"]
        phase_name = phase_info["name"]
        phase_files = _get_phase_files(phases_data, phase_num, input_dir)
        if not phase_files:
            logging.info(
                "Phase %s (%s): no extracted files, skipping.",
                phase_num,
                phase_name,
            )
            continue

        layer_json_path = os.path.join(
            spec_prompts_dir,
            f"phase_{phase_num:02d}_topdown_layers.json",
        )
        if not os.path.isfile(layer_json_path):
            raise FileNotFoundError(
                f"missing spec-generation layer input: {layer_json_path}"
            )
        with open(layer_json_path, "r", encoding="utf-8") as stream:
            layers_data = json.load(stream)
        total_layers = len(layers_data.get("layers", []))
        batch_dir = os.path.join(
            spec_prompts_dir,
            f"batch_prompts_{project_name}_phase{phase_num:02d}",
        )

        for layer_idx in range(total_layers):
            print(
                f"[Pipeline] Stage 4/4: Phase {phase_num}/{num_phases} — "
                f"{phase_name}, Layer {layer_idx}/{total_layers - 1}"
            )
            manifest = generate_batch_manifest(
                extracted_functions_dir=input_dir,
                layer_json_path=layer_json_path,
                output_dir=batch_dir,
                phase=phase_num,
                layers_spec=str(layer_idx),
                project=project_name,
                ext_to_lang=ext_to_lang,
                resume=resume,
            )
            all_batches = manifest.get("batches", [])
            if not all_batches:
                logging.info(
                    "Phase %s Layer %s: no batches, skipping.",
                    phase_num,
                    layer_idx,
                )
                continue

            batch_rel_dir = os.path.relpath(batch_dir, proj_dir)
            layer_files = []
            for batch_info in all_batches:
                for func_rel in batch_info.get("functions", []):
                    layer_files.append(
                        os.path.relpath(os.path.join(proj_dir, func_rel), input_dir)
                    )
            layer_processed = set()

            for attempt in range(1, OPENCODE_MAX_RETRIES + 1):
                pending_batches = _get_pending_batches(all_batches, proj_dir)
                if not pending_batches:
                    incomplete = _get_incomplete_verification_files(
                        layer_files,
                        input_dir,
                        output_dir,
                        work_dir,
                    )
                    if incomplete:
                        newly_processed = streaming_reasoner(
                            input_dir,
                            output_dir,
                            file_list=layer_files,
                            proj_dir=proj_dir,
                            work_dir=work_dir,
                            spec_procs=None,
                            already_processed=all_processed | layer_processed,
                            resume=resume,
                        )
                        layer_processed.update(newly_processed)
                    break

                futures = []
                with concurrent.futures.ThreadPoolExecutor(
                    max_workers=MAX_WORKERS
                ) as executor:
                    for batch_info in pending_batches:
                        batch_file = batch_info["file"]
                        prompt_path = os.path.join(batch_dir, batch_file)
                        if (
                            batch_info.get("num_pending", 1) == 0
                            or not os.path.exists(prompt_path)
                        ):
                            logging.info(
                                "Skipping batch with no functions to spec: %s",
                                batch_file,
                            )
                            continue
                        futures.append(
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

                    if futures:
                        newly_processed = streaming_reasoner(
                            input_dir,
                            output_dir,
                            file_list=layer_files,
                            proj_dir=proj_dir,
                            work_dir=work_dir,
                            spec_procs=futures,
                            already_processed=all_processed | layer_processed,
                            resume=resume,
                        )
                        layer_processed.update(newly_processed)
                    for future in futures:
                        try:
                            future.result()
                        except Exception:
                            logging.exception("Spec generation task failed unexpectedly")

                specs_generated = sum(
                    1
                    for rel in layer_files
                    if is_file_ready(os.path.join(input_dir, rel))
                )
                if specs_generated and not _get_pending_batches(all_batches, proj_dir):
                    break
                if specs_generated:
                    continue
                if attempt < OPENCODE_MAX_RETRIES:
                    delay = 10
                    logging.warning(
                        "Stage 4 Phase %s Layer %s attempt %s produced no valid "
                        "metadata; retrying in %ss.",
                        phase_num,
                        layer_idx,
                        attempt,
                        delay,
                    )
                    for rel in layer_files:
                        ready, reason = metadata_status(os.path.join(input_dir, rel))
                        if not ready:
                            logging.warning("  pending %s: %s", rel, reason)
                    time.sleep(delay)
                    continue
                raise RuntimeError(
                    f"spec generation failed for phase {phase_num} layer {layer_idx} "
                    f"after {OPENCODE_MAX_RETRIES} attempts"
                )

        for rel in phase_files:
            all_processed.add(os.path.join(input_dir, rel))

    return all_processed

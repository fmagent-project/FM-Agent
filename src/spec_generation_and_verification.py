"""Stage 4 specification generation and verification orchestration."""

import config
import concurrent.futures
import json
import logging
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

from config import MAX_WORKERS, OPENCODE_MAX_RETRIES, OPENCODE_SPEC_MODEL
from src.domain_knowledge import list_staged_domain_knowledge_relpaths
from src.file_utils import _get_incomplete_verification_files, _get_phase_files
from src.generate_batch_prompts import generate_batch_prompts
from src.generate_topdown_layers import generate_topdown_layers
from src.llm_client import build_llm_cli_command
from src.opencode_trace import function_id_from_extracted_path, run_opencode_traced
from src.spec_forms import SpecForm, SpecGenerationConfig
from src.verification import streaming_reasoner


def stage_spec_generation_prompts(
    *,
    spec_form: SpecForm,
    script_dir,
    work_dir,
    spec_prompts_dir,
):
    """Stage the active form's prompts before plugin stage hooks run."""
    os.makedirs(spec_prompts_dir, exist_ok=True)
    system_prompt_src = spec_form.system_prompt_path(Path(script_dir))
    system_prompt_dst = os.path.join(spec_prompts_dir, "system_prompt.md")
    shutil.copy2(system_prompt_src, system_prompt_dst)

    workflow_prompt_src = spec_form.workflow_prompt_path(Path(script_dir))
    workflow_prompt_dst = os.path.join(
        work_dir,
        "workflow_spec_step4_batch.md",
    )
    shutil.copy2(workflow_prompt_src, workflow_prompt_dst)


def _get_pending_batches(
    batches,
    proj_dir,
    spec_form: SpecForm,
    expected_dependencies_by_file,
    *,
    report_warnings=False,
):
    """Return pending batches annotated with fresh per-unit validation errors."""
    pending = []
    warning_lines = []
    for batch in batches:
        validation_errors = {}
        batch_is_pending = False
        for func_rel in batch.get("functions", []):
            full_path = os.path.normpath(os.path.join(proj_dir, func_rel))
            expected_dependencies = expected_dependencies_by_file.get(
                full_path,
                (),
            )
            result = spec_form.validate(
                Path(full_path),
                expected_dependencies=expected_dependencies,
            )
            if result.warnings:
                warning_lines.extend(
                    f"{func_rel}: {warning}"
                    for warning in result.warnings
                )
            if not result.ready:
                batch_is_pending = True
                validation_errors[func_rel] = list(result.errors)
        if batch_is_pending:
            pending_batch = dict(batch)
            pending_batch["validation_errors"] = validation_errors
            pending.append(pending_batch)
    if report_warnings and warning_lines:
        logging.warning(
            "Specification validation advisories for this scan:\n- %s",
            "\n- ".join(dict.fromkeys(warning_lines)),
        )
    return pending


def _format_validation_feedback(validation_errors):
    """Render exact per-unit validation failures for the next batch attempt."""
    if not validation_errors:
        return ""
    lines = [
        "",
        "The previous attempt produced artifacts that failed validation. Repair "
        "every issue below; do not merely rename or delete the artifact:",
    ]
    for unit_file, errors in validation_errors.items():
        lines.append(f"- {unit_file}")
        lines.extend(f"  - {error}" for error in errors)
    return "\n".join(lines)


def _topdown_unit_path(proj_dir, work_dir, file_rel):
    """Resolve a topdown unit path, including a tolerated fm_agent/ prefix."""
    file_path = Path(file_rel)
    if file_path.is_absolute():
        return os.path.normpath(file_path)
    if file_path.parts[:1] == (Path(work_dir).name,):
        return os.path.normpath(Path(proj_dir) / file_path)
    return os.path.normpath(Path(work_dir) / file_path)


def _run_spec_generation_batch(
    proj_dir,
    work_dir,
    attempt,
    phase_num,
    layer_idx,
    batch_rel_dir,
    batch_info,
    spec_form: SpecForm,
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
    prompt = spec_form.generation_instruction(batch_prompt_rel, attempt)
    if attempt > 1:
        prompt += _format_validation_feedback(
            batch_info.get("validation_errors", {})
        )
    prompt_file = os.path.join(proj_dir, "fm_agent", "workflow_spec_step4_batch.md")
    command = build_llm_cli_command(
        model=OPENCODE_SPEC_MODEL,
        prompt=prompt,
        cwd=proj_dir,
        files=[prompt_file],
    )
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
            output_files=spec_form.trace_outputs(
                [Path(function_file) for function_file in function_files]
            ),
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


def run_spec_generation_and_verification(
    proj_dir, work_dir, input_dir, output_dir, script_dir, spec_prompts_dir,
    phases_data, spec_generation_config: SpecGenerationConfig, resume=False,
    extra_call_edges=None, only_spec=False, bug_validator_path=None,
    all_bugs=False,
):
    # --- Stage 6: Execute spec generation workflow (per phase, per layer) ---
    spec_form = spec_generation_config.spec_form
    run_reasoning = spec_generation_config.should_run_reasoning(only_spec)

    all_processed = set()
    num_phases = len(phases_data["phases"])
    project_name = phases_data.get("project", "project")

    for phase_info in sorted(phases_data["phases"], key=lambda p: p["phase"]):
        phase_num = phase_info["phase"]
        phase_name = phase_info["name"]
        phase_files = _get_phase_files(
            phases_data,
            phase_num,
            input_dir,
            spec_form=spec_form,
        )

        if not phase_files:
            logging.info(f"Phase {phase_num} ({phase_name}): no extracted files, skipping.")
            continue

        # Determine how many layers this phase has
        layers_json_path = os.path.join(
            spec_prompts_dir, f"phase_{phase_num:02d}_topdown_layers.json"
        )
        if not os.path.exists(layers_json_path):
            generate_topdown_layers(
                work_dir,
                [phase_num],
                extra_call_edges=extra_call_edges,
                spec_form=spec_form,
            )
        with open(layers_json_path, "r") as f:
            layers_data = json.load(f)
        total_layers = layers_data.get("total_layers", 1)
        expected_dependencies_by_file = {
            _topdown_unit_path(proj_dir, work_dir, fn["file"]): tuple(
                fn.get("all_callees", ())
            )
            for layer in layers_data.get("layers", [])
            for fn in layer.get("functions", [])
        }

        batch_dir = os.path.join(
            spec_prompts_dir,
            f"batch_prompts_{project_name}_phase{phase_num:02d}",
        )

        for layer_idx in range(total_layers):
            print(f"[Pipeline] Stage 6/6: Phase {phase_num}/{num_phases} — {phase_name}, Layer {layer_idx}/{total_layers - 1}")

            manifest = generate_batch_prompts(
                work_dir=Path(work_dir),
                phase=phase_num,
                layers_spec=str(layer_idx),
                spec_form=spec_form,
                output_dir=Path(batch_dir),
                resume=resume,
            )
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
                pending_batches = _get_pending_batches(
                    all_batches,
                    proj_dir,
                    spec_form,
                    expected_dependencies_by_file,
                    report_warnings=True,
                )
                if not pending_batches:
                    # All functions in this layer are specced. When downstream
                    # reasoning is disabled, there is no further layer work.
                    if run_reasoning:
                        incomplete_verification = _get_incomplete_verification_files(
                            layer_files,
                            input_dir,
                            output_dir,
                            work_dir,
                            all_bugs=all_bugs,
                            bug_validation_enabled=(
                                config.BUG_VALIDATION_MAX_RETRIES > 0
                            ),
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
                                bug_validator_path=bug_validator_path,
                                all_bugs=all_bugs,
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
                                spec_form,
                            )
                        )

                    logging.info(
                        f"Phase {phase_num} Layer {layer_idx} attempt {attempt}: "
                        f"submitted {len(spec_futures)} spec-generation batch tasks "
                        f"(max_workers={MAX_WORKERS}, total_pending_batches={len(pending_batches)})"
                    )
                    if spec_futures and run_reasoning:
                        newly_processed = streaming_reasoner(
                            input_dir, output_dir, file_list=layer_files,
                            proj_dir=proj_dir, work_dir=work_dir,
                            spec_procs=spec_futures,
                            already_processed=all_processed | layer_processed,
                            resume=resume,
                            bug_validator_path=bug_validator_path,
                            all_bugs=all_bugs,
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
                    if spec_form.validate(
                        Path(os.path.normpath(os.path.join(input_dir, rel))),
                        expected_dependencies=expected_dependencies_by_file.get(
                            os.path.normpath(os.path.join(input_dir, rel)),
                            (),
                        ),
                    ).ready
                )
                remaining_batches = _get_pending_batches(
                    all_batches,
                    proj_dir,
                    spec_form,
                    expected_dependencies_by_file,
                )
                if specs_generated > 0 and not remaining_batches:
                    break

                if specs_generated > 0 and attempt < OPENCODE_MAX_RETRIES:
                    # Partial progress — retry remaining batches without delay
                    logging.info(
                        f"Phase {phase_num} Layer {layer_idx} attempt {attempt}: "
                        f"{specs_generated} specs generated, retrying remaining batches"
                    )
                    continue

                if attempt < OPENCODE_MAX_RETRIES:
                    delay = 10
                    print(
                        f"[Pipeline] Stage 6 Phase {phase_num} Layer {layer_idx} produced no specs "
                        f"(attempt {attempt}/{OPENCODE_MAX_RETRIES}). "
                        f"Retrying in {delay}s..."
                    )
                    logging.warning(
                        f"Stage 6 Phase {phase_num} Layer {layer_idx} attempt {attempt} failed: "
                        f"no specs generated. Retrying in {delay}s."
                    )
                    time.sleep(delay)
                else:
                    remaining_units = sum(
                        len(batch.get("validation_errors", {}))
                        for batch in remaining_batches
                    )
                    print(
                        f"[Pipeline] ERROR: Stage 6 Phase {phase_num} Layer {layer_idx} failed "
                        f"after {OPENCODE_MAX_RETRIES} attempts. "
                        f"{remaining_units} {spec_form.unit_noun}(s) still have "
                        "invalid or missing specs. "
                        f"Check {os.path.basename(proj_dir)}/fm_agent/trace/ for details."
                    )
                    sys.exit(1)

        # Mark all files from this phase as processed for subsequent phases
        for rel in phase_files:
            all_processed.add(os.path.join(input_dir, rel))

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
from src.specification import GenerationPromptContext, SOFTWARE_PROFILE, SpecificationProfile
from src.verification import streaming_reasoner


def _canonical_path(path) -> str:
    """Return a stable absolute key for paths from manifests and top-down JSON."""
    return os.path.normcase(os.path.realpath(os.fspath(path)))


def _build_expected_dependencies_by_file(layers_data, work_dir):
    """Build extracted-unit path -> direct dependency FQN metadata.

    Top-down files are normally relative to `work_dir` and therefore begin
    with `extracted_functions/`. Older/generated metadata may include the
    `fm_agent/` prefix; accept both forms so validation is independent of
    how the batch manifest spelled the same file.
    """
    work_dir = Path(work_dir)
    work_prefix = f"{work_dir.name}/"
    expected_by_file = {}
    for layer in layers_data.get("layers", []):
        if not isinstance(layer, dict):
            continue
        for unit in layer.get("functions", []):
            if not isinstance(unit, dict):
                continue
            relative_file = unit.get("file")
            if not isinstance(relative_file, str) or not relative_file:
                continue
            relative_file = relative_file.replace("\\", "/")
            if relative_file.startswith(work_prefix):
                relative_file = relative_file[len(work_prefix):]
            unit_path = Path(relative_file)
            if not unit_path.is_absolute():
                unit_path = work_dir / unit_path

            raw_dependencies = unit.get("all_callees", ())
            if not isinstance(raw_dependencies, (list, tuple, set)):
                raw_dependencies = ()
            dependencies = {
                dependency
                for dependency in raw_dependencies
                if isinstance(dependency, str) and dependency
            }
            path_key = _canonical_path(unit_path)
            dependencies.update(expected_by_file.get(path_key, ()))
            expected_by_file[path_key] = tuple(sorted(dependencies))
    return expected_by_file


def _expected_dependencies_for_file(file_path, expected_dependencies_by_file):
    if not expected_dependencies_by_file:
        return ()
    return expected_dependencies_by_file.get(_canonical_path(file_path), ())


def _get_pending_batches(batches, proj_dir, specification: SpecificationProfile = SOFTWARE_PROFILE, expected_dependencies_by_file=None):
    """Return batches that still have at least one unit without specs."""
    pending = []
    for batch in batches:
        for func_rel in batch.get("functions", []):
            full_path = os.path.join(proj_dir, func_rel)
            validation = specification.validate(
                Path(full_path),
                expected_dependencies=_expected_dependencies_for_file(full_path, expected_dependencies_by_file),
            )
            if validation.warnings:
                for warning in validation.warnings:
                    logging.warning(
                        "Profile %s warning for %s: %s",
                        specification.id, full_path, warning
                    )
            if not validation.ready:
                if validation.errors:
                    logging.info(
                        "Profile %s artifact check pending for %s: %s",
                        specification.id, full_path, "; ".join(validation.errors)
                    )
                pending.append(batch)
                break
    return pending


def _run_spec_generation_batch(
    proj_dir,
    work_dir,
    attempt,
    phase_num,
    layer_idx,
    batch_rel_dir,
    batch_info,
    specification: SpecificationProfile = SOFTWARE_PROFILE,
    expected_dependencies_by_file=None,
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
    self_suffix = specification.artifacts.self_suffix
    dependency_suffix = specification.artifacts.dependency_suffix
    validation_feedback = []
    if attempt > 1:
        for function_file in function_files:
            validation = specification.validate(
                Path(proj_dir) / function_file,
                _expected_dependencies_for_file(Path(proj_dir) / function_file, expected_dependencies_by_file)
            )
            if not validation.ready:
                details = "; ".join(validation.errors) or "artifact validation failed"
                validation_feedback.append(f"- {function_file}: {details}")
            for warning in validation.warnings:
                logging.warning(
                    "Profile %s warning for %s: %s",
                    specification.id, function_file, warning
                )
    fm_reminder = ("IMPORTANT: fm_agent/ is your output workspace, not project source. "
                    "Do NOT modify any existing project files.")
    prompt = (
        specification.prompt_contract.generation_instruction(
            GenerationPromptContext(
                batch_prompt_rel, attempt, self_suffix,
                dependency_suffix, "fm_agent/spec_prompts/system_prompt.md"
            )
        )
        + f" Do not modify the function source files. {fm_reminder}"
    )
    if validation_feedback:
        prompt += (
            "\n\nThe previous attempt failed these artifact checks. Address each "
            "failure before finishing the batch:\n"
            + "\n".join(validation_feedback)
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
            output_files=[
                str(specification.artifact_paths(Path(function_file)).self_spec)
                for function_file in function_files
            ] + [
                str(specification.artifact_paths(Path(function_file)).dependency_info)
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


def run_spec_generation_and_verification(
    proj_dir, work_dir, input_dir, output_dir, script_dir, spec_prompts_dir,
    phases_data, resume=False, extra_call_edges=None, only_spec=False,
    bug_validator_path=None, validate_bugs=True, all_bugs=False,
    specification: SpecificationProfile = SOFTWARE_PROFILE,
):
    # --- Stage 4: Execute spec generation workflow (per phase, per layer) ---
    batch_md_src = Path(specification.prompts.batch_workflow)
    batch_md_dst = os.path.join(work_dir, "workflow_spec_step4_batch.md")
    if batch_md_src.resolve() != Path(batch_md_dst).resolve():
        shutil.copy2(batch_md_src, batch_md_dst)

    all_processed = set()
    num_phases = len(phases_data["phases"])
    project_name = phases_data.get("project", "project")

    for phase_info in sorted(phases_data["phases"], key=lambda p: p["phase"]):
        phase_num = phase_info["phase"]
        phase_name = phase_info["name"]
        phase_files = _get_phase_files(phases_data, phase_num, input_dir, specification)

        if not phase_files:
            logging.info(f"Phase {phase_num} ({phase_name}): no extracted files, skipping.")
            continue

        # Determine how many layers this phase has
        layers_json_path = os.path.join(
            spec_prompts_dir, f"phase_{phase_num:02d}_topdown_layers.json"
        )
        if not os.path.exists(layers_json_path):
            generate_topdown_layers(work_dir, [phase_num], extra_call_edges, specification)
        with open(layers_json_path, "r") as f:
            layers_data = json.load(f)
        expected_dependencies_by_file = _build_expected_dependencies_by_file(layers_data, work_dir)
        total_layers = layers_data.get("total_layers", 1)

        batch_dir = os.path.join(
            spec_prompts_dir,
            f"batch_prompts_{project_name}_phase{phase_num:02d}",
        )

        for layer_idx in range(total_layers):
            print(f"[Pipeline] Stage 6/6: Phase {phase_num}/{num_phases} — {phase_name}, Layer {layer_idx}/{total_layers - 1}")

            # Generate batch prompts for this layer. On resume, skip functions
            # that were already specced in a previous run.
            manifest = generate_batch_prompts(
                work_dir=Path(work_dir),
                phase=phase_num,
                layers_spec=str(layer_idx),
                output_dir=Path(batch_dir),
                resume=resume,
                specification=specification,
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
                pending_batches = _get_pending_batches(all_batches, proj_dir, specification, expected_dependencies_by_file)
                if not pending_batches:
                    # All functions in this layer are specced. In only-spec mode
                    # we stop here without running the reasoner/bug validation.
                    if specification.enable_reasoning and not only_spec:
                        incomplete_verification = _get_incomplete_verification_files(
                            layer_files,
                            input_dir,
                            output_dir,
                            work_dir,
                            all_bugs=all_bugs,
                            bug_validation_enabled=(
                                validate_bugs
                                and config.BUG_VALIDATION_MAX_RETRIES > 0
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
                                validate_bugs=validate_bugs,
                                all_bugs=all_bugs,
                                specification=specification,
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
                                specification,
                                expected_dependencies_by_file,
                            )
                        )

                    logging.info(
                        f"Phase {phase_num} Layer {layer_idx} attempt {attempt}: "
                        f"submitted {len(spec_futures)} spec-generation batch tasks "
                        f"(max_workers={MAX_WORKERS}, total_pending_batches={len(pending_batches)})"
                    )
                    if spec_futures and specification.enable_reasoning and not only_spec:
                        newly_processed = streaming_reasoner(
                            input_dir, output_dir, file_list=layer_files,
                            proj_dir=proj_dir, work_dir=work_dir,
                            spec_procs=spec_futures,
                            already_processed=all_processed | layer_processed,
                            resume=resume,
                            bug_validator_path=bug_validator_path,
                            validate_bugs=validate_bugs,
                            all_bugs=all_bugs,
                            specification=specification,
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
                    if specification.validate(
                        Path(input_dir) / rel,
                        expected_dependencies=_expected_dependencies_for_file(Path(input_dir) / rel, expected_dependencies_by_file)
                    ).ready
                )
                if specs_generated > 0 and not _get_pending_batches(all_batches, proj_dir, specification, expected_dependencies_by_file):
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
                    print(
                        f"[Pipeline] ERROR: Stage 6 Phase {phase_num} Layer {layer_idx} failed "
                        f"after {OPENCODE_MAX_RETRIES} attempts. "
                        f"No specs were generated. "
                        f"Check {os.path.basename(proj_dir)}/fm_agent/trace/ for details."
                    )
                    sys.exit(1)

        # Mark all files from this phase as processed for subsequent phases
        for rel in phase_files:
            all_processed.add(os.path.join(input_dir, rel))

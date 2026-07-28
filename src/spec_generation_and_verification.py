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
from src.domain_knowledge import list_staged_domain_knowledge_relpaths
from src.file_utils import (
    _get_incomplete_verification_files,
    _get_phase_files,
    is_file_ready,
    validate_file_names,
)
from src.generate_topdown_layers import generate_topdown_layers
from src.llm_client import build_llm_cli_command
from src.opencode_trace import function_id_from_extracted_path, run_opencode_traced
from src.plugin import apply_stage_workflow_markdown
from src.verification import streaming_reasoner


def collect_topdown_function_files(topdown_paths, work_dir):
    """Return normalized extracted-function paths selected by Stage 5."""
    function_files = []
    seen = set()

    for topdown_path in topdown_paths:
        with open(topdown_path, "r", encoding="utf-8") as file:
            layers_data = json.load(file)

        for layer in layers_data["layers"]:
            for function in layer["functions"]:
                topdown_path = function["file"].replace("\\", "/")
                prefix = "extracted_functions/"
                if topdown_path.startswith(prefix):
                    topdown_path = topdown_path[len(prefix):]
                rel_path = os.path.normpath(topdown_path)
                identity = os.path.normcase(rel_path)
                if identity not in seen:
                    seen.add(identity)
                    function_files.append(rel_path)

    return validate_file_names(
        function_files,
        os.path.join(work_dir, "extracted_functions"),
    )


def validate_spec_verification_artifacts(
    artifact_paths,
    function_files,
    work_dir,
    only_spec=False,
    output_root=None,
):
    """Validate and return the canonical artifacts produced by Stage 6."""
    if not isinstance(artifact_paths, list):
        raise RuntimeError("Stage 6 artifacts must be a list[str]")
    if any(not isinstance(path, str) or not path for path in artifact_paths):
        raise RuntimeError(
            "Stage 6 artifacts must contain only non-empty string paths"
        )

    function_files = validate_file_names(
        function_files,
        os.path.join(work_dir, "extracted_functions"),
    )
    output_root = os.path.realpath(output_root or work_dir)
    extracted_root = os.path.join(output_root, "extracted_functions")
    verification_root = os.path.join(
        output_root, "logic_verification_results"
    )
    bug_root = os.path.join(output_root, "bug_validation")

    validated_paths = []
    seen_paths = set()
    for artifact_path in artifact_paths:
        absolute_path = os.path.realpath(artifact_path)
        identity = os.path.normcase(absolute_path)
        if identity in seen_paths:
            raise RuntimeError(
                f"Stage 6 artifacts contain a duplicate path: {artifact_path}"
            )
        seen_paths.add(identity)

        try:
            contained = os.path.commonpath(
                [output_root, absolute_path]
            ) == output_root
        except ValueError:
            contained = False
        if not contained:
            raise RuntimeError(
                f"Stage 6 artifact is outside the output root: {artifact_path}"
            )
        if not os.path.isfile(absolute_path):
            raise RuntimeError(
                f"Stage 6 artifact does not exist: {artifact_path}"
            )
        validated_paths.append(absolute_path)

    required_paths = set()
    for function_file in function_files:
        output_function = os.path.join(extracted_root, function_file)
        if not is_file_ready(output_function):
            raise RuntimeError(
                "Stage 6 requires valid spec and info sidecars for "
                f"{function_file}"
            )
        required_paths.update(
            {
                os.path.realpath(f"{output_function}.spec.json"),
                os.path.realpath(f"{output_function}.info.json"),
            }
        )

        if only_spec:
            continue

        result_path = os.path.realpath(
            os.path.join(
                verification_root,
                os.path.splitext(function_file)[0] + ".json",
            )
        )
        try:
            with open(result_path, "r", encoding="utf-8") as file:
                result = json.load(file)
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise RuntimeError(
                f"Stage 6 verification result is invalid for {function_file}: "
                f"{exc}"
            ) from exc
        if (
            not isinstance(result, dict)
            or result.get("verdict") not in {"MATCH", "MISMATCH"}
        ):
            raise RuntimeError(
                "Stage 6 verification result must have verdict MATCH or "
                f"MISMATCH for {function_file}"
            )
        required_paths.add(result_path)

        if result["verdict"] == "MISMATCH":
            bug_id = (
                os.path.splitext(function_file)[0]
                .replace(os.sep, "--")
                .replace("/", "--")
            )
            bug_result_path = os.path.realpath(
                os.path.join(bug_root, f"{bug_id}.result.json")
            )
            try:
                with open(
                    bug_result_path, "r", encoding="utf-8"
                ) as file:
                    json.load(file)
            except (
                OSError,
                UnicodeDecodeError,
                json.JSONDecodeError,
            ) as exc:
                raise RuntimeError(
                    "Stage 6 bug validation result is invalid for "
                    f"{function_file}: {exc}"
                ) from exc
            required_paths.add(bug_result_path)

    summary_path = os.path.realpath(
        os.path.join(bug_root, "summary.json")
    )
    if summary_path in validated_paths:
        try:
            with open(summary_path, "r", encoding="utf-8") as file:
                json.load(file)
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise RuntimeError(
                f"Stage 6 bug validation summary is invalid: {exc}"
            ) from exc
        required_paths.add(summary_path)

    supplied_paths = set(validated_paths)
    missing = sorted(required_paths - supplied_paths)
    if missing:
        raise RuntimeError(
            "Stage 6 artifact list is missing required path(s): "
            + ", ".join(missing)
        )
    unexpected = sorted(supplied_paths - required_paths)
    if unexpected:
        raise RuntimeError(
            "Stage 6 artifact list contains unexpected path(s): "
            + ", ".join(unexpected)
        )

    return sorted(validated_paths)


def collect_spec_verification_artifacts(
    function_files,
    work_dir,
    only_spec=False,
    output_root=None,
):
    """Collect the complete expected Stage 6 artifact path set."""
    function_files = validate_file_names(
        function_files,
        os.path.join(work_dir, "extracted_functions"),
    )
    output_root = os.path.realpath(output_root or work_dir)
    extracted_root = os.path.join(output_root, "extracted_functions")
    verification_root = os.path.join(
        output_root, "logic_verification_results"
    )
    bug_root = os.path.join(output_root, "bug_validation")

    artifact_paths = []
    for function_file in function_files:
        output_function = os.path.join(extracted_root, function_file)
        artifact_paths.extend(
            [
                f"{output_function}.spec.json",
                f"{output_function}.info.json",
            ]
        )
        if only_spec:
            continue

        result_path = os.path.join(
            verification_root,
            os.path.splitext(function_file)[0] + ".json",
        )
        artifact_paths.append(result_path)
        try:
            with open(result_path, "r", encoding="utf-8") as file:
                result = json.load(file)
        except (OSError, UnicodeDecodeError, json.JSONDecodeError):
            continue
        if isinstance(result, dict) and result.get("verdict") == "MISMATCH":
            bug_id = (
                os.path.splitext(function_file)[0]
                .replace(os.sep, "--")
                .replace("/", "--")
            )
            artifact_paths.append(
                os.path.join(bug_root, f"{bug_id}.result.json")
            )

    summary_path = os.path.join(bug_root, "summary.json")
    if not only_spec and os.path.isfile(summary_path):
        artifact_paths.append(summary_path)
    return sorted(os.path.realpath(path) for path in artifact_paths)


def collect_consumable_stage6_outputs(artifact_paths, output_root):
    """Return only Stage 6 results that consumers may read after the stage."""
    output_root = os.path.realpath(output_root)
    result_roots = (
        os.path.realpath(
            os.path.join(output_root, "logic_verification_results")
        ),
        os.path.realpath(os.path.join(output_root, "bug_validation")),
    )
    consumable = []
    for artifact_path in artifact_paths:
        absolute_path = os.path.realpath(artifact_path)
        for result_root in result_roots:
            try:
                contained = os.path.commonpath(
                    [result_root, absolute_path]
                ) == result_root
            except ValueError:
                contained = False
            if contained:
                consumable.append(absolute_path)
                break
    return sorted(consumable)


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


def run_spec_generation_and_verification(
    proj_dir, work_dir, input_dir, output_dir, script_dir, spec_prompts_dir,
    phases_data, resume=False, extra_call_edges=None, only_spec=False,
    bug_validator_path=None, plugin_stage=None, function_files=None,
):
    # --- Stage 4: Execute spec generation workflow (per phase, per layer) ---
    batch_md_src = os.path.join(script_dir, "md", "workflow_spec_step4_batch.md")
    batch_md_dst = os.path.join(work_dir, "workflow_spec_step4_batch.md")
    shutil.copy2(batch_md_src, batch_md_dst)
    apply_stage_workflow_markdown(plugin_stage, batch_md_dst)

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
            generate_topdown_layers(work_dir, [phase_num], extra_call_edges=extra_call_edges)
        with open(layers_json_path, "r") as f:
            layers_data = json.load(f)
        total_layers = layers_data.get("total_layers", 1)

        batch_dir = os.path.join(
            spec_prompts_dir,
            f"batch_prompts_{project_name}_phase{phase_num:02d}",
        )

        for layer_idx in range(total_layers):
            print(f"[Pipeline] Stage 6/6: Phase {phase_num}/{num_phases} — {phase_name}, Layer {layer_idx}/{total_layers - 1}")

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
                    # All functions in this layer are specced. In only-spec mode
                    # we stop here without running the reasoner/bug validation.
                    if not only_spec:
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
                    if spec_futures and not only_spec:
                        newly_processed = streaming_reasoner(
                            input_dir, output_dir, file_list=layer_files,
                            proj_dir=proj_dir, work_dir=work_dir,
                            spec_procs=spec_futures,
                            already_processed=all_processed | layer_processed,
                            resume=resume,
                            bug_validator_path=bug_validator_path,
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

    if function_files is None:
        topdown_paths = [
            os.path.join(spec_prompts_dir, file_name)
            for file_name in os.listdir(spec_prompts_dir)
            if (
                file_name.startswith("phase_")
                and file_name.endswith("_topdown_layers.json")
            )
        ]
        function_files = collect_topdown_function_files(
            topdown_paths,
            work_dir,
        )

    artifact_paths = collect_spec_verification_artifacts(
        function_files,
        work_dir,
        only_spec=only_spec,
    )
    artifact_paths = validate_spec_verification_artifacts(
        artifact_paths,
        function_files,
        work_dir,
        only_spec=only_spec,
    )

    if (
        not only_spec
        and plugin_stage is not None
        and plugin_stage.output_hook is not None
    ):
        consumable_outputs = collect_consumable_stage6_outputs(
            artifact_paths,
            work_dir,
        )
        try:
            result = plugin_stage.output_hook(
                list(consumable_outputs)
            )
        except Exception as exc:
            raise RuntimeError(
                f"Plugin function '{plugin_stage.output_function}' failed "
                f"for generate_specs_and_verification output: {exc}"
            ) from exc
        if result is not None:
            raise RuntimeError(
                f"Plugin function '{plugin_stage.output_function}' "
                "must return None"
            )
        artifact_paths = validate_spec_verification_artifacts(
            artifact_paths,
            function_files,
            work_dir,
            only_spec=only_spec,
        )

    return artifact_paths

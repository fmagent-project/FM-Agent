import config
from config import MAX_WORKERS, OPENCODE_BUG_VALIDATION_MODEL
from .parser import parse_input_function
from .reasoner import (
    reasoner,
    wp_reasoner,
    _parse_spec_conditions,
    _sanitize_strings,
    _collect_callee_wps,
    _format_callee_wps,
)
from .file_utils import is_file_ready
from .opencode_trace import function_id_from_result_path, run_opencode_traced
from .llm_client import build_llm_cli_command
from .domain_knowledge import (
    format_domain_knowledge_bullets,
    list_staged_domain_knowledge_relpaths,
    load_staged_domain_knowledge_text,
)
import os
import re
import json
import time
import logging
import subprocess


EXT_TO_LANG = {
    ".rs": "Rust", ".c": "C", ".h": "C",
    ".cpp": "C++", ".cc": "C++", ".cxx": "C++", ".hpp": "C++",
    ".py": "Python", ".cu": "CUDA",
    ".erl": "Erlang",
    ".java": "Java", ".go": "Go",
    ".cs": "C#",
    ".kt": "Kotlin", ".kts": "Kotlin",
    ".swift": "Swift",
    ".php": "PHP",
    ".rb": "Ruby",
    ".scala": "Scala", ".sc": "Scala",
    ".dart": "Dart",
    ".js": "JavaScript", ".mjs": "JavaScript", ".cjs": "JavaScript",
    ".jsx": "JavaScript",
    ".ts": "TypeScript", ".mts": "TypeScript", ".cts": "TypeScript", ".tsx": "TypeScript",
    ".ets": "ArkTS",
    ".cuh": "CUDA",
}


def _spec_task_done(handle):
    # spec_procs may be subprocess.Popen handles or executor futures.
    if hasattr(handle, "poll"):
        return handle.poll() is not None
    if hasattr(handle, "done"):
        return handle.done()
    return True


def _spec_task_exit_code(handle):
    # Normalize exit status reporting across Popen and Future-backed tasks.
    if hasattr(handle, "returncode"):
        return handle.returncode
    if hasattr(handle, "done") and handle.done():
        try:
            result = handle.result()
            return result if isinstance(result, int) else 0
        except Exception:
            return 1
    return None


def streaming_reasoner(
    input_dir,
    output_dir,
    file_list=None,
    proj_dir=None,
    work_dir=None,
    poll_interval=2,
    spec_procs=None,
    already_processed=None,
    resume=False,
    bug_validator_path=None,
    reasoning_direction="topdown",
):
    """Continuously watch input_dir for ready files, verify them, and validate bugs."""
    if work_dir is None:
        work_dir = proj_dir
    os.makedirs(output_dir, exist_ok=True)
    processed = set(already_processed) if already_processed else set()

    # Build the set of expected files from file_list (only code files)
    if file_list is not None:
        expected_files = set(
            os.path.join(input_dir, rel) for rel in file_list
            if os.path.splitext(rel)[1] in EXT_TO_LANG
        )
    else:
        expected_files = None

    import concurrent.futures

    # Count files that still need verification in this watcher invocation.
    if expected_files is not None:
        total_expected = len(expected_files)
        pending_expected = expected_files - processed
        num_functions = len(pending_expected)
        if num_functions == total_expected:
            print(f"Functions pending verification: {num_functions}")
        else:
            print(f"Functions pending verification: {num_functions} of {total_expected}")
    else:
        num_functions = sum(
            1 for root, _, files in os.walk(input_dir)
            for fname in files
            if os.path.splitext(fname)[1] in EXT_TO_LANG
        )
        print(f"Functions pending verification: {num_functions}")

    logging.info(f"Watching {input_dir} for ready files (poll every {poll_interval}s)...")
    completed_count = 0

    # WP cache: fqn -> wp_string. Maintained only in bottomup mode so that
    # callees' WPs are available when analyzing their callers.
    wp_cache = {} if reasoning_direction == "bottomup" else None
    # Load callees_map from bottomup layers JSON for WP propagation
    callees_map = None
    phase_fqns = None
    if reasoning_direction == "bottomup" and work_dir:
        callees_map, phase_fqns = _load_callees_from_layers(work_dir)
        if callees_map:
            logging.info(f"Loaded {len(callees_map)} callee entries from bottomup layers for WP propagation")

    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            reasoning_futures = {}
            validation_futures = {}
            submitted = set()

            while True:
                # Scan for new ready files
                for root, _, files in os.walk(input_dir):
                    for fname in files:
                        ext = os.path.splitext(fname)[1]
                        if ext not in EXT_TO_LANG:
                            continue
                        file_path = os.path.join(root, fname)
                        if expected_files is not None and file_path not in expected_files:
                            continue
                        if file_path in processed:
                            continue
                        if file_path in submitted:
                            continue
                        if not is_file_ready(file_path):
                            continue

                        # File is ready and not yet submitted or processed.
                        submitted.add(file_path)
                        language = EXT_TO_LANG.get(ext, "C")
                        future = executor.submit(
                            _verify_single_file, file_path, input_dir, output_dir, language, work_dir, resume,
                            reasoning_direction=reasoning_direction, wp_cache=wp_cache,
                            callees_map=callees_map, phase_fqns=phase_fqns,
                        )
                        reasoning_futures[future] = file_path
                        logging.info(f"Submitted: {file_path}")

                # Collect completed reasoning futures (non-blocking)
                done = [f for f in reasoning_futures if f.done()]
                for future in done:
                    fpath = reasoning_futures.pop(future)
                    submitted.discard(fpath)
                    try:
                        _, verdict = future.result()
                        processed.add(fpath)
                        completed_count += 1
                        rel_path = os.path.relpath(fpath, proj_dir) if proj_dir else os.path.relpath(fpath, input_dir)
                        # Submit bug validation for MISMATCH results; defer printing
                        if verdict == "MISMATCH" and proj_dir is not None:
                            rel = os.path.relpath(fpath, input_dir)
                            result_json_rel = os.path.join(
                                os.path.relpath(output_dir, proj_dir),
                                os.path.splitext(rel)[0] + ".json",
                            )
                            vf = executor.submit(
                                _validate_single_bug,
                                result_json_rel,
                                proj_dir,
                                work_dir,
                                resume=resume,
                                bug_validator_path=bug_validator_path,
                            )
                            validation_futures[vf] = (fpath, rel_path, result_json_rel, completed_count)
                            logging.info(f"Submitted validation: {fpath}")
                        else:
                            if verdict == "MATCH" or verdict == "SKIPPED":
                                label = "\033[32m✔\033[0m"
                                if verdict == "SKIPPED":
                                    label += " (no spec)"
                            else:
                                label = verdict
                            print(f"[{completed_count}/{num_functions}] {rel_path}: {label}")
                    except Exception as exc:
                        logging.error(f"Error verifying {fpath}: {exc}")

                # Collect completed validation futures (non-blocking)
                val_done = [f for f in validation_futures if f.done()]
                for future in val_done:
                    fpath, rel_path, result_json_rel, count = validation_futures.pop(future)
                    try:
                        future.result()
                        # Read validation result to check confirmation
                        parts = result_json_rel
                        prefix = os.path.join("fm_agent", "logic_verification_results") + os.sep
                        if parts.startswith(prefix):
                            parts = parts[len(prefix):]
                        elif parts.startswith("fm_agent/logic_verification_results/"):
                            parts = parts[len("fm_agent/logic_verification_results/"):]
                        bug_id = os.path.splitext(parts)[0].replace(os.sep, "--").replace("/", "--")
                        result_path = os.path.join(work_dir, "bug_validation", f"{bug_id}.result.json")
                        confirmed = False
                        if os.path.exists(result_path):
                            with open(result_path) as rf:
                                result_data = json.load(rf)
                            confirmed = result_data.get("confirmation_status") == "confirmed"
                        if confirmed:
                            print(f"[{count}/{num_functions}] {rel_path}: \033[31m✘\033[0m")
                        else:
                            print(f"[{count}/{num_functions}] {rel_path}: \033[32m✔\033[0m")
                        logging.info(f"Validation completed: {fpath} (confirmed={confirmed})")
                    except Exception as exc:
                        logging.error(f"Validation error for {fpath}: {exc}")

                # Check if all expected files have been processed
                all_reasoning_done = (
                    expected_files is not None
                    and processed >= expected_files
                    and not reasoning_futures
                )
                if all_reasoning_done and not validation_futures:
                    logging.info("All files verified and validated. Done.")
                    break

                # Detect if spec generation subprocesses exited before all files are ready
                _all_procs = spec_procs if spec_procs else None
                if _all_procs is not None and all(_spec_task_done(p) for p in _all_procs):
                    unready = (expected_files or set()) - processed
                    if unready and not reasoning_futures and not validation_futures:
                        exit_codes = [_spec_task_exit_code(p) for p in _all_procs]
                        if not processed:
                            # No function got a spec at all – this is an error
                            logging.warning(
                                f"Spec generation process(es) exited (codes {exit_codes}) "
                                f"but no .spec.json/.info.json sidecar pairs were created."
                            )
                        else:
                            # Some functions are missing specs; leave them pending for retry.
                            logging.warning(
                                f"Spec generation process(es) exited (codes {exit_codes}), "
                                f"{len(unready)} files missing specs, leaving them pending for retry."
                            )
                            for uf in sorted(unready):
                                rel_path = os.path.relpath(uf, proj_dir) if proj_dir else os.path.relpath(uf, input_dir)
                                print(f"[pending] {rel_path}: no spec yet; will retry")
                        break

                time.sleep(poll_interval)

    except KeyboardInterrupt:
        logging.info("Stopping watcher...")
        # Wait for in-flight tasks
        all_futures = {}
        all_futures.update(reasoning_futures)
        all_futures.update(validation_futures)
        for future in all_futures:
            fpath = all_futures[future]
            try:
                future.result()
                logging.info(f"Completed: {fpath}")
            except Exception as exc:
                logging.error(f"Error for {fpath}: {exc}")
        logging.info("Done.")

    # Generate validation summary after all work is done
    if proj_dir is not None:
        _generate_validation_summary(work_dir)

    return processed


def _load_callees_from_layers(work_dir):
    """Load a global callees_map from all bottomup_layers.json files.

    Used by WP reasoning to look up a function's callees for WP propagation.
    Returns (callees_map, phase_fqns) where callees_map maps fqn -> set(callee_fqn).
    """
    from pathlib import Path
    callees_map = {}
    phase_fqns = set()
    spec_prompts_dir = os.path.join(work_dir, "spec_prompts")
    if not os.path.isdir(spec_prompts_dir):
        return callees_map, phase_fqns
    for json_path in sorted(Path(spec_prompts_dir).glob("phase_*_bottomup_layers.json")):
        try:
            with open(json_path) as f:
                data = json.load(f)
        except (json.JSONDecodeError, OSError):
            continue
        for layer in data.get("layers", []):
            for func_entry in layer.get("functions", []):
                fqn = func_entry["name"]
                phase_fqns.add(fqn)
                # Collect callees from phase-specific and all_callees fields
                callees = set()
                for key, val in func_entry.items():
                    if key.endswith("_callees") or key == "all_callees":
                        if isinstance(val, list):
                            callees.update(val)
                callees_map[fqn] = callees
    return callees_map, phase_fqns


def _verify_single_file(file_path, input_dir, output_dir, language, work_dir=None, resume=False,
                        reasoning_direction="topdown", wp_cache=None,
                        callees_map=None, phase_fqns=None):
    """Verify a single file and write the result JSON."""
    # Skip if resuming and a valid result already exists
    rel = os.path.relpath(file_path, input_dir)
    output_path = os.path.join(output_dir, os.path.splitext(rel)[0] + ".json")
    if resume and os.path.exists(output_path):
        try:
            with open(output_path) as f:
                existing = json.load(f)
            verdict = existing.get("verdict", "ERROR")
            logging.info(f"Already verified, skipping: {file_path} (verdict={verdict})")
            return file_path, verdict
        except (json.JSONDecodeError, OSError):
            pass  # re-verify if existing result is corrupted

    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    try:
        func, spec, knowledge = parse_input_function(file_path)
        if not spec:
            return file_path, "SKIPPED"

        _, spec_post = _parse_spec_conditions(spec)
        trace_context = None
        if work_dir:
            rel_function = os.path.relpath(file_path, input_dir)
            trace_context = {
                "trace_dir": os.path.join(work_dir, "trace"),
                "function_id": os.path.splitext(rel_function)[0].replace(os.sep, "::"),
                "function_file": os.path.join("extracted_functions", rel_function).replace(os.sep, "/"),
            }
        domain_knowledge = load_staged_domain_knowledge_text(work_dir) if work_dir else ""
        if domain_knowledge:
            knowledge = f"{knowledge}\n\n{domain_knowledge}" if knowledge else domain_knowledge

        if reasoning_direction == "bottomup":
            # Inject callee WP info for more precise backward analysis
            enhanced_info = knowledge
            if wp_cache is not None and callees_map is not None and phase_fqns is not None:
                fqn = trace_context["function_id"] if trace_context else None
                if fqn:
                    callee_wps = _collect_callee_wps(fqn, phase_fqns, wp_cache, callees_map)
                    callee_wp_text = _format_callee_wps(callee_wps)
                    if callee_wp_text:
                        enhanced_info = f"{knowledge}\n\n{callee_wp_text}" if knowledge else callee_wp_text
            result, entry_wp = wp_reasoner(func, spec, enhanced_info, language, trace_context=trace_context)
            # Cache the actual WP for upward propagation to callers
            if wp_cache is not None and trace_context:
                fqn = trace_context.get("function_id")
                if fqn and entry_wp:
                    wp_cache[fqn] = entry_wp
        else:
            result = reasoner(func, spec, knowledge, language, trace_context=trace_context)

        if "passes" in result and "verification" in result:
            output = {"function": file_path, "verdict": "MATCH", "gaps": None}
        elif result.startswith("Failed to "):
            output = {"function": file_path, "verdict": "ERROR", "gaps": None, "error": result}
        else:
            stmts = post_cond = reason_text = ""
            # Handle both SP ("Post-condition:") and WP ("Weakest pre-condition:") formats
            stmts_match = re.search(
                r"Statements triggering the violation:\n(.*?)\n\n(?:Post-condition|Weakest pre-condition):",
                result, re.DOTALL
            )
            cond_match = re.search(
                r"(?:Post-condition|Weakest pre-condition):\n(.*?)\n\nReason for violation:",
                result, re.DOTALL
            )
            reason_match = re.search(r"Reason for violation:\n(.*)", result, re.DOTALL)

            if stmts_match:
                stmts = stmts_match.group(1).strip()
            if cond_match:
                post_cond = cond_match.group(1).strip()
            if reason_match:
                reason_text = reason_match.group(1).strip()

            output = {
                "function": file_path,
                "verdict": "MISMATCH",
                "gaps": {
                    "spec_claim": spec_post or "",
                    "actual_behavior": post_cond,
                    "code_evidence": stmts,
                    "trigger_condition": reason_text,
                },
            }
    except Exception as exc:
        logging.exception(f"Verification failed for {file_path}")
        output = {"function": file_path, "verdict": "ERROR", "gaps": None, "error": str(exc)}

    output = _sanitize_strings(output)
    with open(output_path, "w") as f:
        json.dump(output, f, indent=2, ensure_ascii=False)

    return file_path, output["verdict"]


def _validate_single_bug(
    result_json_rel,
    proj_dir,
    work_dir=None,
    resume=False,
    bug_validator_path=None,
):
    """Validate a single MISMATCH result by running opencode with a per-file prompt."""
    if work_dir is None:
        work_dir = proj_dir
    script_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

    # Derive bug id from result path relative to results dir
    # e.g. "fm_agent/logic_verification_results/mod/func.json" -> "mod--func"
    parts = result_json_rel
    prefix = os.path.join("fm_agent", "logic_verification_results") + os.sep
    if parts.startswith(prefix):
        parts = parts[len(prefix):]
    elif parts.startswith("fm_agent/logic_verification_results/"):
        parts = parts[len("fm_agent/logic_verification_results/"):]
    bug_id = os.path.splitext(parts)[0].replace(os.sep, "--").replace("/", "--")
    function_id = function_id_from_result_path(result_json_rel)

    # Read either the user-selected validator or the built-in default.
    base_md_path = (
        bug_validator_path
        if bug_validator_path
        else os.path.join(script_dir, "md", "bug_validator.md")
    )
    with open(base_md_path, "r") as f:
        base_content = f.read()

    user_knowledge_paths = list_staged_domain_knowledge_relpaths(work_dir)
    if user_knowledge_paths:
        user_knowledge_section = (
            "## User-Provided Domain Knowledge\n\n"
            "Read these Markdown files as additional context for intended behavior, "
            "terminology, data encodings, and invariants before validating the "
            "candidate bug:\n\n"
            f"{format_domain_knowledge_bullets(user_knowledge_paths)}\n\n---\n\n"
        )
    else:
        user_knowledge_section = ""

    # Generate a per-file prompt with target file and bug ID header
    prompt_content = (
        "# Bug Validator\n\n"
        f"**Target result file:** `{result_json_rel}`\n"
        f"**Bug ID:** `{bug_id}`\n\n---\n\n"
        + user_knowledge_section
        + base_content
    )

    os.makedirs(os.path.join(work_dir, "bug_validation"), exist_ok=True)

    prompt_filename = os.path.join(
        "fm_agent", "bug_validation", f"bug_validator_{bug_id}.md"
    )
    prompt_path = os.path.join(proj_dir, prompt_filename)

    tmp_path = prompt_path + ".tmp"
    with open(tmp_path, "w") as f:
        f.write(prompt_content)
    os.replace(tmp_path, prompt_path)

    prompt = "Follow the instructions in the attached file"
    command = build_llm_cli_command(
        model=OPENCODE_BUG_VALIDATION_MODEL,
        prompt=prompt,
        cwd=proj_dir,
        files=[prompt_path],
    )
    result_relpath = os.path.join("fm_agent", "bug_validation", f"{bug_id}.result.json")
    result_path = os.path.join(proj_dir, result_relpath)
    # Resume idempotency: if resuming and this bug was already validated, don't pay for it again.
    if resume and os.path.exists(result_path):
        try:
            with open(result_path) as _f:
                json.load(_f)
            logging.info(f"Bug validation already done, skipping: {bug_id}")
            return
        except (json.JSONDecodeError, OSError):
            pass  # corrupted result — re-validate
    try:
        max_attempts = config.BUG_VALIDATION_MAX_RETRIES
        for attempt in range(1, max_attempts + 1):
            run_failed = False
            try:
                run_opencode_traced(
                    proj_dir=proj_dir,
                    work_dir=work_dir,
                    command=command,
                    stage="bug_validation",
                    function_ids=[function_id],
                    input_files=[
                        prompt_filename,
                        result_json_rel,
                        *user_knowledge_paths,
                    ],
                    output_files=[
                        os.path.join("fm_agent", "bug_validation", f"{bug_id}.md"),
                        result_relpath,
                    ],
                    summary=f"OpenCode bug validation for {bug_id}",
                    metadata={"bug_id": bug_id, "result_json": result_json_rel},
                )
            except subprocess.CalledProcessError as exc:
                run_failed = True
                logging.warning(
                    "bug_validation run failed for %s on attempt %d/%d: %s",
                    bug_id,
                    attempt,
                    max_attempts,
                    exc,
                )

            if os.path.exists(result_path):
                return

            if attempt < max_attempts:
                logging.warning(
                    "bug_validation missing result artifact for %s after attempt %d/%d; retrying once",
                    bug_id,
                    attempt,
                    max_attempts,
                )
                continue

            logging.error(
                "bug_validation did not materialize %s after %d attempt(s)%s",
                result_relpath,
                max_attempts,
                " and a non-zero exit code" if run_failed else "",
            )
    finally:
        try:
            os.remove(prompt_path)
        except OSError:
            pass


def _generate_validation_summary(proj_dir):
    """Scan bug_validation/*.result.json files and write summary.json."""
    validation_dir = os.path.join(proj_dir, "bug_validation")
    if not os.path.isdir(validation_dir):
        logging.info("No bug_validation directory found, skipping summary.")
        return

    bugs = []
    for fname in sorted(os.listdir(validation_dir)):
        if not fname.endswith(".result.json"):
            continue
        fpath = os.path.join(validation_dir, fname)
        try:
            with open(fpath, "r") as f:
                record = json.load(f)
            bugs.append(record)
        except (OSError, json.JSONDecodeError) as exc:
            logging.warning(f"Could not read {fpath}: {exc}")

    confirmed = sum(1 for b in bugs if b.get("confirmation_status") == "confirmed")
    not_confirmed = sum(1 for b in bugs if b.get("confirmation_status") == "not_confirmed")
    errors = sum(1 for b in bugs if b.get("confirmation_status") == "error")

    # Sort: confirmed first, then not_confirmed, then error; alphabetical by id within each group
    status_order = {"confirmed": 0, "not_confirmed": 1, "error": 2}
    bugs.sort(key=lambda b: (status_order.get(b.get("confirmation_status"), 3), b.get("id", "")))

    summary = {
        "total_reported": len(bugs),
        "total_confirmed": confirmed,
        "total_not_confirmed": not_confirmed,
        "total_error": errors,
        "bugs": bugs,
    }

    summary_path = os.path.join(validation_dir, "summary.json")
    tmp_path = summary_path + ".tmp"
    with open(tmp_path, "w") as f:
        json.dump(summary, f, indent=2, ensure_ascii=False)
    os.replace(tmp_path, summary_path)
    logging.info(f"Validation summary written to {summary_path}")
    logging.info(f"  confirmed: {confirmed}, not_confirmed: {not_confirmed}, error: {errors}")

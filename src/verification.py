import config
from config import MAX_WORKERS, OPENCODE_BUG_VALIDATION_MODEL
from .parser import parse_input_function
from .reasoner import reasoner, _parse_spec_conditions, _sanitize_strings
from .file_utils import (
    _all_bugs_candidate_paths,
    _ensure_resume_result_mode,
    _terminal_validation_is_valid,
    is_file_ready,
)
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
import glob
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


def streaming_reasoner(input_dir, output_dir, file_list=None, proj_dir=None, work_dir=None, poll_interval=2, spec_procs=None, already_processed=None, resume=False, all_bugs=False):
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
                            _verify_single_file,
                            file_path,
                            input_dir,
                            output_dir,
                            language,
                            work_dir,
                            resume,
                            all_bugs,
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
                        if (
                            verdict == "MISMATCH"
                            and proj_dir is not None
                            and config.BUG_VALIDATION_MAX_RETRIES > 0
                        ):
                            rel = os.path.relpath(fpath, input_dir)
                            result_json_rel = os.path.join(
                                os.path.relpath(output_dir, proj_dir),
                                os.path.splitext(rel)[0] + ".json",
                            )
                            validation_targets = _validation_targets(
                                result_json_rel, proj_dir, all_bugs
                            )
                            for target_rel in validation_targets:
                                vf = executor.submit(
                                    _validate_single_bug,
                                    target_rel,
                                    proj_dir,
                                    work_dir,
                                    resume,
                                )
                                validation_futures[vf] = (
                                    fpath,
                                    rel_path,
                                    target_rel,
                                    completed_count,
                                )
                                logging.info(f"Submitted validation: {target_rel}")
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
                        bug_id = _bug_id_from_result_path(result_json_rel)
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
                        logging.info(
                            "Validation completed: %s (target=%s, confirmed=%s)",
                            fpath,
                            result_json_rel,
                            confirmed,
                        )
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
                                f"but no files received [SPEC]/[INFO] markers."
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
        if all_bugs:
            _generate_all_bugs_validation_summary(work_dir)
        else:
            _generate_validation_summary(work_dir)

    return processed


def _candidate_paths_for_output(output_path, bug_count):
    stem, ext = os.path.splitext(output_path)
    return [f"{stem}.bug-{index:03d}{ext}" for index in range(1, bug_count + 1)]


def _clear_candidate_files(output_path):
    directory = os.path.dirname(output_path)
    stem = os.path.splitext(os.path.basename(output_path))[0]
    pattern = re.compile(rf"^{re.escape(stem)}\.bug-\d{{3}}\.json$")
    if not os.path.isdir(directory):
        return
    for filename in os.listdir(directory):
        if pattern.fullmatch(filename):
            try:
                os.remove(os.path.join(directory, filename))
            except OSError:
                pass


def _clear_bug_validation_artifacts(work_dir, bug_id):
    validation_dir = os.path.join(work_dir, "bug_validation")
    paths = [
        os.path.join(validation_dir, f"{bug_id}.result.json"),
        os.path.join(validation_dir, f"{bug_id}.md"),
        os.path.join(validation_dir, f"bug_validator_{bug_id}.md"),
    ]
    paths.extend(
        glob.glob(
            os.path.join(validation_dir, f"probe_{glob.escape(bug_id)}.*")
        )
    )
    for path in paths:
        try:
            os.remove(path)
        except OSError:
            pass
    try:
        os.remove(os.path.join(validation_dir, "summary.json"))
    except OSError:
        pass


def _clear_function_all_bugs_artifacts(output_path, output_dir, work_dir):
    """Reset one incomplete function without disturbing completed functions."""
    if work_dir:
        validation_dir = os.path.join(work_dir, "bug_validation")
        result_rel = os.path.relpath(output_path, output_dir)
        bug_prefix = (
            os.path.splitext(result_rel)[0]
            .replace(os.sep, "--")
            .replace("/", "--")
            + ".bug-"
        )
        ordinal = "[0-9][0-9][0-9]"
        patterns = (
            f"{glob.escape(bug_prefix)}{ordinal}.result.json",
            f"{glob.escape(bug_prefix)}{ordinal}.md",
            f"bug_validator_{glob.escape(bug_prefix)}{ordinal}.md",
            f"probe_{glob.escape(bug_prefix)}{ordinal}.*",
        )
        for pattern in patterns:
            for path in glob.glob(os.path.join(validation_dir, pattern)):
                try:
                    os.remove(path)
                except OSError:
                    pass
        try:
            os.remove(os.path.join(validation_dir, "summary.json"))
        except OSError:
            pass

    _clear_candidate_files(output_path)
    try:
        os.remove(output_path)
    except OSError:
        pass


def _verify_single_file(file_path, input_dir, output_dir, language, work_dir=None, resume=False, all_bugs=False):
    """Verify a single file and write the result JSON."""
    # A complete function result is the reasoning checkpoint. Resume never
    # re-runs it; missing candidate validations are resumed independently.
    rel = os.path.relpath(file_path, input_dir)
    output_path = os.path.join(output_dir, os.path.splitext(rel)[0] + ".json")
    if resume and os.path.exists(output_path):
        try:
            with open(output_path, encoding="utf-8") as f:
                existing = json.load(f)
            _ensure_resume_result_mode(existing, output_path, all_bugs)
            verdict = existing.get("verdict", "ERROR")
            if not all_bugs or _all_bugs_candidate_paths(output_path, existing) is not None:
                logging.info(f"Already verified, skipping: {file_path} (verdict={verdict})")
                return file_path, verdict
        except (json.JSONDecodeError, OSError):
            pass  # re-verify if existing result is corrupted

    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    if all_bugs:
        # Reaching this point means reasoning did not finish cleanly. Discard
        # only this function's intermediate candidates and validations before
        # restarting it; completed functions remain untouched.
        _clear_function_all_bugs_artifacts(
            output_path,
            output_dir,
            work_dir,
        )

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
        result = reasoner(
            func,
            spec,
            knowledge,
            language,
            trace_context=trace_context,
            all_bugs=all_bugs,
        )

        if all_bugs:
            status = result.get("status", "ERROR")
            reasoning_complete = result.get(
                "reasoning_complete", status in {"MATCH", "MISMATCH"}
            )
            violations = result.get("violations", [])
            if not isinstance(violations, list):
                violations = []
            candidate_gaps = [
                {
                    "spec_claim": spec_post or "",
                    "actual_behavior": violation.get("post_condition") or "",
                    "code_evidence": violation.get("statements") or "",
                    "trigger_condition": violation.get("reason") or "",
                    "counterexample": violation.get("counterexample") or "",
                }
                for violation in violations
            ]
            for candidate_path, gaps in zip(
                _candidate_paths_for_output(output_path, len(candidate_gaps)),
                candidate_gaps,
            ):
                candidate = {
                    "function": file_path,
                    "verdict": "MISMATCH",
                    "gaps": gaps,
                }
                with open(candidate_path, "w", encoding="utf-8") as f:
                    json.dump(candidate, f, indent=2, ensure_ascii=False)
            if not reasoning_complete or status == "ERROR":
                verdict = "ERROR"
            elif candidate_gaps:
                verdict = "MISMATCH"
            elif status == "MATCH":
                verdict = "MATCH"
            else:
                verdict = "ERROR"
            output = {
                "function": file_path,
                "verdict": verdict,
                "gaps": candidate_gaps[0] if candidate_gaps else None,
                "all_bugs": True,
                "bug_count": len(candidate_gaps),
                "reasoning_complete": bool(reasoning_complete),
            }
            if not reasoning_complete or status == "ERROR":
                output["error"] = result.get("error") or "Reasoning failed."
        elif "passes the verification" in result:
            output = {"function": file_path, "verdict": "MATCH", "gaps": None}
        elif result.startswith("Failed to "):
            output = {"function": file_path, "verdict": "ERROR", "gaps": None, "error": result}
        else:
            stmts = post_cond = reason_text = ""
            stmts_match = re.search(
                r"Statements triggering the violation:\n(.*?)\n\nPost-condition:", result, re.DOTALL
            )
            post_match = re.search(
                r"Post-condition:\n(.*?)\n\nReason for violation:", result, re.DOTALL
            )
            reason_match = re.search(r"Reason for violation:\n(.*)", result, re.DOTALL)

            if stmts_match:
                stmts = stmts_match.group(1).strip()
            if post_match:
                post_cond = post_match.group(1).strip()
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
        if all_bugs:
            output.update({
                "all_bugs": True,
                "bug_count": 0,
                "reasoning_complete": False,
            })

    if not all_bugs:
        output = _sanitize_strings(output)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2, ensure_ascii=False)

    return file_path, output["verdict"]


def _bug_id_from_result_path(result_json_rel):
    parts = result_json_rel
    prefix = os.path.join("fm_agent", "logic_verification_results") + os.sep
    if parts.startswith(prefix):
        parts = parts[len(prefix):]
    elif parts.startswith("fm_agent/logic_verification_results/"):
        parts = parts[len("fm_agent/logic_verification_results/"):]
    return os.path.splitext(parts)[0].replace(os.sep, "--").replace("/", "--")


def _validation_targets(result_json_rel, proj_dir, all_bugs):
    if not all_bugs:
        return [result_json_rel]
    result_path = os.path.join(proj_dir, result_json_rel)
    try:
        with open(result_path, "r", encoding="utf-8") as f:
            result = json.load(f)
    except (OSError, json.JSONDecodeError):
        return []
    candidates = _all_bugs_candidate_paths(result_path, result)
    if candidates is None:
        return []
    return [os.path.relpath(path, proj_dir) for path in candidates]


def _validation_status(result_json_rel, work_dir):
    bug_id = _bug_id_from_result_path(result_json_rel)
    result_path = os.path.join(work_dir, "bug_validation", f"{bug_id}.result.json")
    try:
        with open(result_path, "r") as f:
            return json.load(f).get("confirmation_status")
    except (OSError, json.JSONDecodeError):
        return None


def _validate_single_bug(result_json_rel, proj_dir, work_dir=None, resume=False):
    """Validate a single MISMATCH result by running opencode with a per-file prompt."""
    if work_dir is None:
        work_dir = proj_dir
    script_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

    # Derive bug id from result path relative to results dir
    # e.g. "fm_agent/logic_verification_results/mod/func.json" -> "mod--func"
    bug_id = _bug_id_from_result_path(result_json_rel)
    function_result_rel = re.sub(
        r"\.bug-\d{3}(?=\.json$)", "", result_json_rel
    )
    function_id = function_id_from_result_path(function_result_rel)
    result_relpath = os.path.join("fm_agent", "bug_validation", f"{bug_id}.result.json")
    result_path = os.path.join(proj_dir, result_relpath)
    is_candidate = re.search(r"\.bug-\d{3}(?=\.json$)", result_json_rel) is not None

    # Candidate resume mirrors the legacy stage checkpoint: a terminal result
    # finishes this validation stage. Candidate identity is fixed by the
    # completed reasoning artifacts, so no content hash is needed here.
    if is_candidate and resume and os.path.exists(result_path):
        if _terminal_validation_is_valid(result_path):
            logging.info(f"Bug validation already done, skipping: {bug_id}")
            return
        _clear_bug_validation_artifacts(work_dir, bug_id)

    # Read the base bug_validator.md
    base_md_path = os.path.join(script_dir, "md", "bug_validator.md")
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
    with open(tmp_path, "w", encoding="utf-8") as f:
        f.write(prompt_content)
    os.replace(tmp_path, prompt_path)

    prompt = "Follow the instructions in the attached file"
    command = build_llm_cli_command(
        model=OPENCODE_BUG_VALIDATION_MODEL,
        prompt=prompt,
        cwd=proj_dir,
        files=[prompt_path],
    )
    # Preserve the legacy resume path exactly: a readable result is reusable
    # without candidate-specific schema or content checks.
    if not is_candidate and resume and os.path.exists(result_path):
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
                if not is_candidate or _terminal_validation_is_valid(result_path):
                    return
                logging.warning(
                    "bug_validation wrote a non-terminal result for %s on attempt %d/%d",
                    bug_id,
                    attempt,
                    max_attempts,
                )
                try:
                    os.remove(result_path)
                except OSError:
                    pass

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


def _expected_all_bugs_validation_targets(work_dir):
    """Return all-bugs candidate artifacts that require bug validation."""
    if config.BUG_VALIDATION_MAX_RETRIES <= 0:
        return []

    results_dir = os.path.join(work_dir, "logic_verification_results")
    if not os.path.isdir(results_dir):
        return []

    targets = []
    for root, _dirs, files in os.walk(results_dir):
        for filename in sorted(files):
            if (
                not filename.endswith(".json")
                or re.search(r"\.bug-\d{3}\.json$", filename)
            ):
                continue
            primary_path = os.path.join(root, filename)
            try:
                with open(primary_path, "r", encoding="utf-8") as f:
                    primary = json.load(f)
            except (OSError, json.JSONDecodeError):
                continue
            if not isinstance(primary, dict):
                continue
            if primary.get("all_bugs") is True:
                candidates = _all_bugs_candidate_paths(primary_path, primary)
                if candidates:
                    targets.extend(candidates)
    return sorted(targets)


def _pending_all_bugs_validation_record(
    target_path, results_dir, validation_error
):
    """Build a pending record for one missing/unusable all-bugs validation."""
    target_rel = os.path.relpath(target_path, results_dir)
    bug_id = os.path.splitext(target_rel)[0].replace(os.sep, "--")
    try:
        with open(target_path, "r", encoding="utf-8") as f:
            target = json.load(f)
    except (OSError, json.JSONDecodeError):
        target = {}
    function = target.get("function", "") if isinstance(target, dict) else ""
    gaps = target.get("gaps", {}) if isinstance(target, dict) else {}
    if not isinstance(gaps, dict):
        gaps = {}
    record = {
        "id": bug_id,
        "source_file": function,
        "function_name": os.path.splitext(os.path.basename(function))[0],
        "confirmation_status": "pending",
        "attempts": 0,
        "probe_script": None,
        "detail_file": None,
        "probe_stdout": "",
        "trigger_summary": gaps.get("trigger_condition", ""),
        "validation_error": validation_error,
    }
    return record


def _generate_validation_summary(work_dir):
    """Scan bug_validation/*.result.json files and write summary.json."""
    validation_dir = os.path.join(work_dir, "bug_validation")
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


def _generate_all_bugs_validation_summary(work_dir):
    """Join all-bugs candidates with terminal records and mark gaps pending."""
    if config.BUG_VALIDATION_MAX_RETRIES <= 0:
        logging.info("Bug validation is disabled, skipping all-bugs summary.")
        return

    validation_dir = os.path.join(work_dir, "bug_validation")
    results_dir = os.path.join(work_dir, "logic_verification_results")
    targets = _expected_all_bugs_validation_targets(work_dir)
    if not targets and not os.path.isdir(validation_dir):
        logging.info("No all-bugs validations found, skipping summary.")
        return
    os.makedirs(validation_dir, exist_ok=True)

    bugs = []
    expected_result_paths = set()
    for target_path in targets:
        target_rel = os.path.relpath(target_path, results_dir)
        bug_id = os.path.splitext(target_rel)[0].replace(os.sep, "--")
        result_path = os.path.join(validation_dir, f"{bug_id}.result.json")
        expected_result_paths.add(os.path.normpath(result_path))
        record = None
        validation_error = "missing_or_invalid_result"
        try:
            with open(result_path, "r", encoding="utf-8") as f:
                loaded = json.load(f)
            if (
                isinstance(loaded, dict)
                and loaded.get("confirmation_status")
                in {"confirmed", "not_confirmed", "error"}
            ):
                record = loaded
            else:
                validation_error = "invalid_result"
        except (OSError, json.JSONDecodeError):
            pass
        if record is None:
            record = _pending_all_bugs_validation_record(
                target_path,
                results_dir,
                validation_error,
            )
        bugs.append(record)

    for fname in sorted(os.listdir(validation_dir)):
        if not fname.endswith(".result.json"):
            continue
        result_path = os.path.normpath(os.path.join(validation_dir, fname))
        if result_path not in expected_result_paths:
            logging.warning(
                "Ignoring stale validation result not tied to a current bug: %s",
                result_path,
            )

    confirmed = sum(1 for b in bugs if b.get("confirmation_status") == "confirmed")
    not_confirmed = sum(
        1 for b in bugs if b.get("confirmation_status") == "not_confirmed"
    )
    errors = sum(1 for b in bugs if b.get("confirmation_status") == "error")
    pending = sum(1 for b in bugs if b.get("confirmation_status") == "pending")

    status_order = {
        "confirmed": 0,
        "not_confirmed": 1,
        "error": 2,
        "pending": 3,
    }
    bugs.sort(
        key=lambda b: (
            status_order.get(b.get("confirmation_status"), 4),
            b.get("id", ""),
        )
    )

    summary = {
        "total_reported": len(bugs),
        "total_confirmed": confirmed,
        "total_not_confirmed": not_confirmed,
        "total_error": errors,
        "total_pending": pending,
        "bugs": bugs,
    }

    summary_path = os.path.join(validation_dir, "summary.json")
    tmp_path = summary_path + ".tmp"
    with open(tmp_path, "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2, ensure_ascii=False)
    os.replace(tmp_path, summary_path)
    logging.info(f"Validation summary written to {summary_path}")
    logging.info(
        "  confirmed: %d, not_confirmed: %d, error: %d, pending: %d",
        confirmed,
        not_confirmed,
        errors,
        pending,
    )

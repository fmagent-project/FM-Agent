from config import MAX_WORKERS
from .parser import parse_input_function
from .reasoner import reasoner, _parse_spec_conditions, _sanitize_strings
from .file_utils import _all_bugs_candidate_paths, is_file_ready
from .domain_knowledge import load_staged_domain_knowledge_text
import os
import posixpath
import re
import json
import time
import logging


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
    all_bugs=False,
):
    """Continuously watch ready functions and write static reasoning verdicts."""
    if work_dir is None:
        work_dir = proj_dir
    os.makedirs(output_dir, exist_ok=True)
    processed = set(already_processed) if already_processed else set()

    # Build the set of expected files from file_list (only code files)
    if file_list is not None:
        expected_files = set(
            os.path.join(input_dir, rel) for rel in file_list
            if os.path.splitext(rel)[1].lower() in EXT_TO_LANG
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
            if os.path.splitext(fname)[1].lower() in EXT_TO_LANG
        )
        print(f"Functions pending verification: {num_functions}")

    logging.info(f"Watching {input_dir} for ready files (poll every {poll_interval}s)...")
    completed_count = 0

    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            reasoning_futures = {}
            submitted = set()
            failed = set()  # files that raised unhandled errors; don't retry forever

            def _submit_file(file_path, ext):
                # Submit a ready file for reasoning/verification.
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

            while True:
                # Scan for new ready files
                for root, _, files in os.walk(input_dir):
                    for fname in files:
                        ext = os.path.splitext(fname)[1].lower()
                        if ext not in EXT_TO_LANG:
                            continue
                        file_path = os.path.join(root, fname)
                        if expected_files is not None and file_path not in expected_files:
                            continue
                        if file_path in processed:
                            continue
                        if file_path in submitted:
                            continue
                        if file_path in failed:
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
                        completed_count += 1
                        rel_path = os.path.relpath(fpath, proj_dir) if proj_dir else os.path.relpath(fpath, input_dir)
                        if verdict == "ERROR":
                            failed.add(fpath)
                            label = "\033[31mERROR (retry with --resume)\033[0m"
                        elif verdict == "MATCH" or verdict == "SKIPPED":
                            processed.add(fpath)
                            label = "\033[32m✔\033[0m"
                            if verdict == "SKIPPED":
                                label += " (no spec)"
                        elif verdict == "MISMATCH":
                            processed.add(fpath)
                            label = "\033[31mMISMATCH (candidate)\033[0m"
                        else:
                            processed.add(fpath)
                            label = verdict
                        print(f"[{completed_count}/{num_functions}] {rel_path}: {label}")
                    except Exception as exc:
                        logging.error(f"Error verifying {fpath}: {exc}")
                        failed.add(fpath)

                # Check if all expected files have been processed successfully
                all_reasoning_done = (
                    expected_files is not None
                    and processed >= expected_files
                    and not reasoning_futures
                )
                if all_reasoning_done:
                    logging.info("All files statically verified. Done.")
                    break

                # Terminal state: every expected file is either processed or failed.
                # Report failures explicitly instead of claiming success.
                all_terminal = (
                    expected_files is not None
                    and (processed | failed) >= expected_files
                    and not reasoning_futures
                )
                if all_terminal and failed:
                    logging.error(
                        f"All files finished, but {len(failed)} file(s) failed verification."
                    )
                    for ff in sorted(failed):
                        rel_path = os.path.relpath(ff, proj_dir) if proj_dir else os.path.relpath(ff, input_dir)
                        print(f"[failed] {rel_path}: verification error")
                    break

                # Detect if spec generation subprocesses exited before all files are ready
                _all_procs = spec_procs if spec_procs else None
                if _all_procs is not None and all(_spec_task_done(p) for p in _all_procs):
                    # Final scan: producers may have finished writing markers after the
                    # last regular scan, so check remaining expected files once more.
                    newly_ready = False
                    for file_path in (expected_files or set()) - processed - submitted - failed:
                        ext = os.path.splitext(file_path)[1].lower()
                        if ext not in EXT_TO_LANG:
                            continue
                        if not is_file_ready(file_path):
                            continue
                        _submit_file(file_path, ext)
                        newly_ready = True
                    if newly_ready:
                        logging.info(
                            "All spec producers done; rescan found newly ready files, submitting them."
                        )
                        continue

                    unready = (expected_files or set()) - processed - failed
                    if not reasoning_futures:
                        exit_codes = [_spec_task_exit_code(p) for p in _all_procs]
                        if unready:
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
                        if failed:
                            logging.error(
                                f"{len(failed)} file(s) failed verification and will not be retried."
                            )
                            for ff in sorted(failed):
                                rel_path = os.path.relpath(ff, proj_dir) if proj_dir else os.path.relpath(ff, input_dir)
                                print(f"[failed] {rel_path}: verification error")
                        break

                time.sleep(poll_interval)

    except KeyboardInterrupt:
        logging.info("Stopping watcher...")
        # Wait for in-flight tasks
        for future, fpath in reasoning_futures.items():
            try:
                future.result()
                logging.info(f"Completed: {fpath}")
            except Exception as exc:
                logging.error(f"Error for {fpath}: {exc}")
        logging.info("Done.")

    return processed


def _candidate_paths_for_output(output_path, bug_count):
    stem, ext = os.path.splitext(output_path)
    return [f"{stem}.bug-{index:03d}{ext}" for index in range(1, bug_count + 1)]


def _extracted_function_identity(path):
    """Return the stable suffix below extracted_functions/, if present."""
    if not isinstance(path, str):
        return None

    normalized = "/" + path.replace("\\", "/")
    _, marker, relative = normalized.rpartition("/extracted_functions/")
    return relative if marker and relative else None


def _stable_all_bugs_function_path(file_path, input_dir):
    """Return the project-relative extracted-function path stored in artifacts."""
    relative = os.path.relpath(file_path, input_dir).replace(os.sep, "/")
    normalized = posixpath.normpath(relative)
    if (
        normalized in {"", ".", ".."}
        or normalized.startswith("../")
        or posixpath.isabs(normalized)
    ):
        raise ValueError(
            f"all-bugs function path escapes extracted_functions: {file_path}"
        )
    return posixpath.join("fm_agent", "extracted_functions", normalized)


def _write_json_atomic(path, data):
    tmp_path = path + ".tmp"
    try:
        with open(tmp_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        os.replace(tmp_path, path)
    except Exception:
        try:
            os.remove(tmp_path)
        except OSError:
            pass
        raise


def _rebind_all_bugs_function_paths(
    output_path,
    result,
    candidate_paths,
    current_function,
):
    """Rebind completed all-bugs artifacts to the current stable source path."""
    stored_function = result.get("function")
    if stored_function == current_function:
        return True
    if (
        _extracted_function_identity(stored_function)
        != _extracted_function_identity(current_function)
    ):
        return False

    rebound_candidates = []
    for candidate_path in candidate_paths:
        with open(candidate_path, "r", encoding="utf-8") as f:
            candidate = json.load(f)
        candidate["function"] = current_function
        rebound_candidates.append((candidate_path, candidate))

    rebound_result = dict(result)
    rebound_result["function"] = current_function
    for candidate_path, candidate in rebound_candidates:
        _write_json_atomic(candidate_path, candidate)
    _write_json_atomic(output_path, rebound_result)
    result["function"] = current_function
    return True


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


def _clear_function_all_bugs_artifacts(output_path):
    """Reset one incomplete function without disturbing completed functions."""
    _clear_candidate_files(output_path)
    try:
        os.remove(output_path)
    except OSError:
        pass


def _verify_single_file(file_path, input_dir, output_dir, language, work_dir=None, resume=False, all_bugs=False):
    """Verify a single file and write the result JSON."""
    # A complete function result is the static reasoning checkpoint.
    rel = os.path.relpath(file_path, input_dir)
    artifact_function = (
        _stable_all_bugs_function_path(file_path, input_dir)
        if all_bugs
        else file_path
    )
    output_path = os.path.join(output_dir, os.path.splitext(rel)[0] + ".json")
    if resume and os.path.exists(output_path):
        try:
            with open(output_path, encoding="utf-8") as f:
                existing = json.load(f)
            verdict = existing.get("verdict", "ERROR")
            candidates = (
                _all_bugs_candidate_paths(output_path, existing)
                if all_bugs
                else None
            )
            reusable = (
                verdict in {"MATCH", "MISMATCH"}
                if not all_bugs
                else (
                    candidates is not None
                    and _rebind_all_bugs_function_paths(
                        output_path,
                        existing,
                        candidates,
                        artifact_function,
                    )
                )
            )
            if reusable:
                logging.info(f"Already verified, skipping: {file_path} (verdict={verdict})")
                return file_path, verdict
        except (json.JSONDecodeError, OSError):
            pass  # re-verify if existing result is corrupted

    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    if all_bugs:
        # Reaching this point means reasoning did not finish cleanly. Discard
        # only this function's intermediate candidates before
        # restarting it; completed functions remain untouched.
        _clear_function_all_bugs_artifacts(output_path)

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
                }
                for violation in violations
            ]
            for candidate_path, gaps in zip(
                _candidate_paths_for_output(output_path, len(candidate_gaps)),
                candidate_gaps,
            ):
                candidate = {
                    "function": artifact_function,
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
                "function": artifact_function,
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
                "function": artifact_function,
                "all_bugs": True,
                "bug_count": 0,
                "reasoning_complete": False,
            })

    if not all_bugs:
        output = _sanitize_strings(output)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2, ensure_ascii=False)

    return file_path, output["verdict"]


def _relative_extracted_function(value, input_dir):
    """Normalize an artifact function path to extracted_functions-relative form."""
    if not isinstance(value, str) or not value.strip():
        return None
    normalized = value.replace("\\", "/")
    marker = "/extracted_functions/"
    if marker in "/" + normalized.lstrip("/"):
        return ("/" + normalized.lstrip("/")).split(marker, 1)[1]
    absolute = os.path.abspath(value)
    input_abs = os.path.abspath(input_dir)
    try:
        if os.path.commonpath([absolute, input_abs]) == input_abs:
            return os.path.relpath(absolute, input_abs).replace(os.sep, "/")
    except ValueError:
        pass
    return normalized.removeprefix("fm_agent/extracted_functions/").lstrip("/")


def _source_rel_from_extracted(relative):
    """Map ``src/name-c/function.c`` back to the project source ``src/name.c``."""
    if not isinstance(relative, str):
        return ""
    parts = relative.replace("\\", "/").split("/")
    known_extensions = {ext.lstrip(".") for ext in EXT_TO_LANG}
    for index in range(len(parts) - 2, -1, -1):
        base, separator, extension = parts[index].rpartition("-")
        if separator and base and extension.lower() in known_extensions:
            return "/".join(parts[:index] + [f"{base}.{extension}"])
    return relative.replace("\\", "/")


def _source_location(input_dir, work_dir, relative):
    """Locate an extracted function in its original source for report display.

    Extraction normally preserves the function text verbatim.  An exact text
    match therefore gives a deterministic line range without another model
    call.  The function-name fallback still provides a useful anchor when a
    language extractor normalizes whitespace.
    """
    source_rel = _source_rel_from_extracted(relative)
    source_path = os.path.join(os.path.dirname(work_dir), *source_rel.split("/"))
    extracted_path = os.path.join(input_dir, *relative.split("/"))
    try:
        with open(source_path, encoding="utf-8", errors="replace") as stream:
            source_text = stream.read()
        with open(extracted_path, encoding="utf-8", errors="replace") as stream:
            function_text = stream.read().strip()
    except OSError:
        return {"location": "", "start_line": None, "end_line": None}

    if function_text:
        offset = source_text.find(function_text)
        if offset >= 0:
            start_line = source_text.count("\n", 0, offset) + 1
            end_line = start_line + function_text.count("\n")
            return {
                "location": f"L{start_line}-L{end_line}",
                "start_line": start_line,
                "end_line": end_line,
            }

    function_name = os.path.splitext(os.path.basename(relative))[0]
    match = re.search(rf"\b{re.escape(function_name)}\s*\(", source_text)
    if match:
        line = source_text.count("\n", 0, match.start()) + 1
        return {"location": f"L{line}", "start_line": line, "end_line": line}
    return {"location": "", "start_line": None, "end_line": None}


def _result_function_files(input_dir, output_dir):
    """Discover function files represented by terminal result artifacts."""
    functions = []
    candidate_pattern = re.compile(r"\.bug-\d{3}\.json$")
    if not os.path.isdir(output_dir):
        return functions
    for root, _dirs, files in os.walk(output_dir):
        for filename in sorted(files):
            if not filename.endswith(".json") or candidate_pattern.search(filename):
                continue
            try:
                with open(os.path.join(root, filename), encoding="utf-8") as stream:
                    result = json.load(stream)
            except (OSError, json.JSONDecodeError):
                continue
            relative = _relative_extracted_function(result.get("function"), input_dir)
            if relative:
                functions.append(relative)
    return sorted(dict.fromkeys(functions))


def _candidate_details(result_path, result):
    """Return every static candidate gap for default and --all-bugs artifacts."""
    details = []
    if isinstance(result, dict) and isinstance(result.get("gaps"), dict):
        details.append(result["gaps"])
    if not (isinstance(result, dict) and result.get("all_bugs")):
        return details
    stem, extension = os.path.splitext(result_path)
    for index in range(1, int(result.get("bug_count") or 0) + 1):
        candidate_path = f"{stem}.bug-{index:03d}{extension}"
        try:
            with open(candidate_path, encoding="utf-8") as stream:
                candidate = json.load(stream)
        except (OSError, json.JSONDecodeError):
            continue
        gap = candidate.get("gaps") if isinstance(candidate, dict) else None
        if isinstance(gap, dict) and gap not in details:
            details.append(gap)
    return details


def _trace_summary(work_dir):
    """Summarize process and artifact events without treating recovered retries as terminal."""
    path = os.path.join(work_dir, "trace", "events.jsonl")
    summary = {
        "total_events": 0,
        "historical_error_events": 0,
        "by_type_and_status": {},
        "latest_stage_validation": {},
    }
    try:
        stream = open(path, encoding="utf-8")
    except OSError:
        return summary
    with stream:
        for line in stream:
            try:
                event = json.loads(line)
            except (json.JSONDecodeError, TypeError):
                continue
            if not isinstance(event, dict):
                continue
            summary["total_events"] += 1
            event_type = str(event.get("type") or "event")
            status = str(event.get("status") or "unknown")
            key = f"{event_type}:{status}"
            summary["by_type_and_status"][key] = (
                summary["by_type_and_status"].get(key, 0) + 1
            )
            if status in {"error", "formal_error", "format_error"}:
                summary["historical_error_events"] += 1
            if event_type == "stage_validation":
                stage = str(event.get("stage") or "unknown")
                summary["latest_stage_validation"][stage] = {
                    "status": status,
                    "summary": str(event.get("summary") or ""),
                }
    return summary


def write_static_verification_report(
    input_dir,
    output_dir,
    work_dir,
    function_files=None,
    *,
    all_bugs=False,
    analysis_scope="full",
):
    """Write JSON/Markdown reports immediately after static reasoning.

    ``function_files=None`` discovers the current result set and is used by the
    incremental pipeline, whose scope intentionally contains only changed and
    affected functions.
    """

    records = []
    counts = {"MATCH": 0, "MISMATCH": 0, "ERROR": 0, "MISSING": 0}
    if function_files is None:
        function_files = _result_function_files(input_dir, output_dir)
    for rel in sorted(dict.fromkeys(function_files)):
        rel = rel.replace("\\", "/")
        source_path = os.path.join(input_dir, rel)
        result_path = os.path.join(output_dir, os.path.splitext(rel)[0] + ".json")
        result = None
        load_error = None
        try:
            with open(result_path, encoding="utf-8") as stream:
                result = json.load(stream)
        except FileNotFoundError:
            load_error = "verification result is missing"
        except (OSError, json.JSONDecodeError) as exc:
            load_error = f"verification result is unreadable: {exc}"

        verdict = result.get("verdict") if isinstance(result, dict) else None
        if verdict not in {"MATCH", "MISMATCH", "ERROR"}:
            verdict = "MISSING"
        if not is_file_ready(source_path):
            verdict = "MISSING"
            load_error = "specification sidecars are missing or invalid"
        counts[verdict] += 1
        error = (
            result.get("error")
            if isinstance(result, dict) and isinstance(result.get("error"), str)
            else load_error
        )
        records.append(
            {
                "function": rel,
                "function_name": os.path.splitext(os.path.basename(rel))[0],
                "source_file": _source_rel_from_extracted(rel),
                "verdict": verdict,
                "result_file": os.path.relpath(result_path, work_dir).replace(
                    os.sep, "/"
                ),
                "spec_file": os.path.relpath(
                    source_path + ".spec.json", work_dir
                ).replace(os.sep, "/"),
                "candidates": _candidate_details(result_path, result),
                "error": error,
                **_source_location(input_dir, work_dir, rel),
            }
        )

    complete = counts["ERROR"] == 0 and counts["MISSING"] == 0
    report = {
        "status": "complete" if complete else "partial",
        "mode": "all-bugs" if all_bugs else "default",
        "analysis_scope": analysis_scope,
        "candidate_semantics": "static_unconfirmed",
        "total_functions": len(records),
        "counts": counts,
        "trace": _trace_summary(work_dir),
        "results": records,
    }
    json_path = os.path.join(work_dir, "VERIFICATION-REPORT.json")
    _write_json_atomic(json_path, report)

    lines = [
        "# FM-Agent Static Verification Report",
        "",
        f"Status: {'COMPLETE' if complete else 'PARTIAL'}",
        f"Mode: {report['mode']}",
        f"Scope: {analysis_scope}",
        f"Total functions: {len(records)}",
        (
            "Counts: "
            + ", ".join(f"{name}={counts[name]}" for name in counts)
        ),
        "",
        "> `MISMATCH` means a statically inferred, unconfirmed bug candidate. "
        "This build intentionally contains no dynamic test/instrumentation confirmation stage.",
        "",
        "| Source | Function | Verdict | Result | Error |",
        "|---|---|---|---|---|",
    ]
    for record in records:
        error = (record["error"] or "").replace("|", "\\|").replace("\n", " ")
        lines.append(
            f"| {record['source_file']} | {record['function_name']} | "
            f"{record['verdict']} | "
            f"{record['result_file']} | {error} |"
        )
    candidates = [
        (record, index, gap)
        for record in records
        for index, gap in enumerate(record["candidates"], start=1)
    ]
    if candidates:
        lines.extend(["", "## Static bug candidates", ""])
        for record, index, gap in candidates:
            lines.extend([
                f"### {record['function_name']} / candidate {index}",
                "",
                f"- Source: `{record['source_file']}`",
                f"- Generated spec claim: {gap.get('spec_claim') or '(not recorded)'}",
                f"- Actual behavior: {gap.get('actual_behavior') or '(not recorded)'}",
                f"- Trigger condition: {gap.get('trigger_condition') or '(not recorded)'}",
                "",
                "Code evidence:",
                "",
                "```text",
                str(gap.get("code_evidence") or "(not recorded)"),
                "```",
                "",
            ])
    trace = report["trace"]
    lines.extend([
        "",
        "## Run diagnostics",
        "",
        f"- Trace events: {trace['total_events']}",
        f"- Historical error events (including recovered retries): "
        f"{trace['historical_error_events']}",
        "- The final report status is based on terminal static artifacts; an earlier "
        "retry error does not make a later successful result partial.",
    ])
    markdown_path = os.path.join(work_dir, "VERIFICATION-REPORT.md")
    tmp_path = markdown_path + ".tmp"
    with open(tmp_path, "w", encoding="utf-8") as stream:
        stream.write("\n".join(lines) + "\n")
    os.replace(tmp_path, markdown_path)
    return report

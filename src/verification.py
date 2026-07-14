import config
from config import MAX_WORKERS, OPENCODE_BUG_VALIDATION_MODEL, OPENCODE_MODEL_PROVIDER
from .parser import parse_input_function
from .reasoner import reasoner, _parse_spec_conditions, _sanitize_strings
from .file_utils import is_file_ready
from .opencode_trace import function_id_from_result_path, run_opencode_traced
from .cli_backend import build_agent_command, is_cli_backend_enabled
from .all_bugs_schema import (
    all_bugs_bug_id_prefix,
    all_bugs_candidate_matches,
    all_bugs_candidate_paths_are_contained,
    all_bugs_bug_entry_is_valid,
    all_bugs_summary_is_complete,
    all_bugs_summary_matches_result_path,
    all_bugs_summary_paths_are_contained,
    candidate_content_sha256,
    expected_all_bugs_bug_id,
    gaps_are_valid,
    is_safe_bug_id,
    nonempty_string,
    path_is_symlink_free_within,
    realpath_is_strictly_within,
    resolve_project_relative_path,
    validation_result_is_valid,
)
from .domain_knowledge import (
    format_domain_knowledge_bullets,
    list_staged_domain_knowledge_relpaths,
    load_staged_domain_knowledge_text,
)
from .secure_fs import (
    SecureFilesystemError,
    atomic_write_json as secure_atomic_write_json,
    atomic_write_text as secure_atomic_write_text,
    load_json as secure_load_json,
    unlink as secure_unlink,
)
from .verification_schema import (
    legacy_result_has_valid_schema,
    legacy_result_is_resumable,
)
import os
import re
import json
import shutil
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


class AllBugsArtifactError(ValueError):
    pass


_ARTIFACT_IDENTITY_FIELDS = {
    "function",
    "function_id",
    "function_result",
    "result_file",
    "source_file",
}

def _sanitize_artifact_strings(value):
    """Sanitize model text without changing path and source identity fields."""
    if isinstance(value, dict):
        return {
            key: item
            if key in _ARTIFACT_IDENTITY_FIELDS and isinstance(item, str)
            else _sanitize_artifact_strings(item)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [_sanitize_artifact_strings(item) for item in value]
    return _sanitize_strings(value)


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
        work_dir = os.path.dirname(os.path.normpath(output_dir)) if all_bugs else proj_dir
    results_work_dir = work_dir or os.path.dirname(os.path.normpath(output_dir))
    _guard_verification_results_dir(output_dir, results_work_dir)
    os.makedirs(output_dir, exist_ok=True)
    _guard_verification_results_dir(output_dir, results_work_dir)
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
            validation_groups = {}
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
                            _verify_single_file, file_path, input_dir, output_dir, language, work_dir, resume, all_bugs
                        )
                        reasoning_futures[future] = file_path
                        logging.info(f"Submitted: {file_path}")

                # Collect completed reasoning futures (non-blocking)
                done = [f for f in reasoning_futures if f.done()]
                for future in done:
                    fpath = reasoning_futures.pop(future)
                    submitted.discard(fpath)
                    verification_result = future.result()
                    try:
                        _, verdict = verification_result
                        rel_path = os.path.relpath(fpath, proj_dir) if proj_dir else os.path.relpath(fpath, input_dir)
                        rel = os.path.relpath(fpath, input_dir)
                        result_json_rel = os.path.join(
                            os.path.relpath(output_dir, proj_dir),
                            os.path.splitext(rel)[0] + ".json",
                        ) if proj_dir is not None else None
                        needs_target_read = (
                            verdict == "MISMATCH"
                            or (all_bugs and verdict == "ERROR")
                        )
                        validation_targets = (
                            _get_validation_target_paths(
                                result_json_rel,
                                proj_dir,
                                allow_partial=all_bugs and verdict == "ERROR",
                            )
                            if result_json_rel is not None and needs_target_read
                            else []
                        )
                        processed.add(fpath)
                        completed_count += 1
                        if validation_targets:
                            primary_result = _load_project_json_safely(
                                result_json_rel,
                                proj_dir,
                            )
                            validation_groups[fpath] = {
                                "rel_path": rel_path,
                                "count": completed_count,
                                "verdict": verdict,
                                "reasoning_complete": primary_result.get("reasoning_complete", True),
                                "pending": len(validation_targets),
                                "statuses": [],
                            }
                            for target_rel in validation_targets:
                                vf = executor.submit(
                                    _validate_single_bug,
                                    target_rel,
                                    proj_dir,
                                    work_dir,
                                    resume,
                                )
                                validation_futures[vf] = (fpath, target_rel)
                                logging.info(f"Submitted validation: {target_rel}")
                        else:
                            if verdict == "MATCH" or verdict == "SKIPPED":
                                label = "\033[32m✔\033[0m"
                                if verdict == "SKIPPED":
                                    label += " (no spec)"
                            elif verdict == "ERROR" and all_bugs:
                                label = "ERROR (incomplete)"
                            else:
                                label = verdict
                            print(f"[{completed_count}/{num_functions}] {rel_path}: {label}")
                    except AllBugsArtifactError:
                        raise
                    except Exception as exc:
                        logging.error(f"Error verifying {fpath}: {exc}")

                # Collect completed validation futures (non-blocking)
                val_done = [f for f in validation_futures if f.done()]
                for future in val_done:
                    fpath, target_rel = validation_futures.pop(future)
                    group = validation_groups[fpath]
                    try:
                        future.result()
                        status = _validation_status_for_target(
                            target_rel,
                            proj_dir,
                            work_dir,
                        )
                    except AllBugsArtifactError:
                        raise
                    except Exception as exc:
                        status = "error"
                        logging.error(f"Validation error for {target_rel}: {exc}")
                    group["statuses"].append(status)
                    group["pending"] -= 1
                    if group["pending"] == 0:
                        if group["verdict"] == "ERROR" or not group["reasoning_complete"]:
                            label = "ERROR (incomplete)"
                        elif "confirmed" in group["statuses"]:
                            label = "\033[31m✘\033[0m"
                        elif all(status == "not_confirmed" for status in group["statuses"]):
                            label = "\033[32m✔\033[0m"
                        else:
                            label = "ERROR (validation)"
                        print(
                            f"[{group['count']}/{num_functions}] "
                            f"{group['rel_path']}: {label}"
                        )
                        logging.info(
                            "Validation completed: %s (statuses=%s)",
                            fpath,
                            group["statuses"],
                        )
                        del validation_groups[fpath]

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

    return processed


def _project_dir_from_work_dir(work_dir):
    if os.path.basename(os.path.normpath(work_dir)) == "fm_agent":
        return os.path.dirname(os.path.normpath(work_dir))
    return work_dir


def _validation_project_dir(work_dir, workspace_aliases=None):
    if workspace_aliases is None:
        return _project_dir_from_work_dir(work_dir)
    if not isinstance(workspace_aliases, dict) or set(workspace_aliases) != {"fm_agent"}:
        raise AllBugsArtifactError("invalid validation workspace alias")
    try:
        aliased_work_dir = os.path.abspath(os.fspath(workspace_aliases["fm_agent"]))
    except TypeError as exc:
        raise AllBugsArtifactError("invalid validation workspace alias") from exc
    if aliased_work_dir != os.path.abspath(work_dir):
        raise AllBugsArtifactError("validation workspace alias does not match workdir")
    return os.path.dirname(os.path.normpath(work_dir))


def _project_relative_posix(path, work_dir):
    if not work_dir:
        return path.replace(os.sep, "/")
    project_dir = _project_dir_from_work_dir(work_dir)
    return os.path.relpath(path, project_dir).replace(os.sep, "/")


def _guard_verification_results_dir(output_dir, work_dir):
    """Reject verification result roots that escape or traverse symlinks."""
    output_root = os.path.abspath(output_dir)
    work_root = os.path.abspath(work_dir)
    if (
        not path_is_symlink_free_within(output_root, work_root)
        or not realpath_is_strictly_within(output_root, work_root)
        or (
            os.path.lexists(output_root)
            and (os.path.islink(output_root) or not os.path.isdir(output_root))
        )
    ):
        raise AllBugsArtifactError(
            f"unsafe logic_verification_results directory: {output_dir}"
        )


def _guard_verification_result_path(path, output_dir, work_dir):
    """Reject unsafe result files and their atomic-write temp paths."""
    _guard_verification_results_dir(output_dir, work_dir)
    output_root = os.path.abspath(output_dir)
    for candidate in (os.path.abspath(path), os.path.abspath(path + ".tmp")):
        if (
            not path_is_symlink_free_within(candidate, output_root)
            or not realpath_is_strictly_within(candidate, output_root)
            or (
                os.path.lexists(candidate)
                and (os.path.islink(candidate) or not os.path.isfile(candidate))
            )
        ):
            raise AllBugsArtifactError(f"unsafe verification result path: {candidate}")


def _relative_to_secure_root(path, root):
    absolute_path = os.path.abspath(path)
    absolute_root = os.path.abspath(root)
    try:
        if (
            absolute_path == absolute_root
            or os.path.commonpath([absolute_root, absolute_path]) != absolute_root
        ):
            raise AllBugsArtifactError(f"artifact escapes secure root: {path}")
    except ValueError as exc:
        raise AllBugsArtifactError(f"artifact escapes secure root: {path}") from exc
    return os.path.relpath(absolute_path, absolute_root)


def _secure_unlink_artifact(
    path,
    root,
    *,
    missing_ok=False,
    allow_symlink=False,
):
    relative_path = _relative_to_secure_root(path, root)
    try:
        return secure_unlink(
            root,
            relative_path,
            missing_ok=missing_ok,
            allow_symlink=allow_symlink,
        )
    except (OSError, SecureFilesystemError) as exc:
        raise AllBugsArtifactError(f"cannot safely delete artifact: {path}") from exc


def _write_json_atomic(path, data, output_dir=None, work_dir=None):
    if output_dir is not None:
        _guard_verification_result_path(path, output_dir, work_dir)
    secure_root = work_dir or os.path.dirname(path)
    relative_path = _relative_to_secure_root(path, secure_root)
    try:
        secure_atomic_write_json(secure_root, relative_path, data)
    except (OSError, SecureFilesystemError) as exc:
        raise AllBugsArtifactError(f"cannot safely write artifact: {path}") from exc


def _json_file_is_valid(path):
    try:
        with open(path) as f:
            json.load(f)
        return True
    except (OSError, json.JSONDecodeError):
        return False


def _resolve_project_path(path, project_dir):
    if os.path.isabs(path):
        return path
    return os.path.join(project_dir, path.replace("/", os.sep))


def _load_project_json_safely(
    result_json_rel,
    project_dir,
    workspace_aliases=None,
):
    normalized_path = _normalized_validation_target_path(
        result_json_rel,
        project_dir,
        workspace_aliases,
    )
    if normalized_path is None:
        raise AllBugsArtifactError(f"unsafe project artifact: {result_json_rel}")
    secure_root = project_dir
    secure_relative_path = normalized_path
    path_parts = normalized_path.split("/")
    if workspace_aliases and path_parts[0] in workspace_aliases:
        secure_root = os.fspath(workspace_aliases[path_parts[0]])
        secure_relative_path = "/".join(path_parts[1:])
    try:
        return secure_load_json(
            secure_root,
            secure_relative_path.replace("/", os.sep),
        )
    except (OSError, ValueError, UnicodeError, SecureFilesystemError) as exc:
        raise AllBugsArtifactError(
            f"cannot read project artifact: {result_json_rel}"
        ) from exc


def _partial_all_bugs_summary_is_valid(
    summary,
    summary_result_file,
    proj_dir,
    workspace_aliases=None,
):
    bugs = summary.get("bugs") if isinstance(summary, dict) else None
    bug_count = summary.get("bug_count") if isinstance(summary, dict) else None
    return (
        isinstance(summary, dict)
        and summary.get("result_kind") == "function_summary"
        and summary.get("all_bugs") is True
        and summary.get("reasoning_complete") is False
        and summary.get("verdict") == "ERROR"
        and nonempty_string(summary.get("error"))
        and all_bugs_summary_matches_result_path(summary, summary_result_file)
        and isinstance(bugs, list)
        and isinstance(bug_count, int)
        and not isinstance(bug_count, bool)
        and bug_count == len(bugs)
        and (
            (
                bug_count == 0
                and bugs == []
                and summary.get("gaps") is None
            )
            or (
                bug_count >= 1
                and gaps_are_valid(summary.get("gaps"))
                and summary.get("gaps") == bugs[0].get("gaps")
            )
        )
        and all(
            all_bugs_bug_entry_is_valid(
                bug,
                expected_all_bugs_bug_id(summary_result_file, ordinal),
            )
            for ordinal, bug in enumerate(bugs, start=1)
        )
        and all_bugs_summary_paths_are_contained(
            summary,
            proj_dir,
            workspace_aliases,
        )
    )


def _get_validation_target_paths(
    result_json_rel,
    proj_dir,
    allow_partial=False,
    workspace_aliases=None,
):
    """Return candidate result paths that require independent validation."""
    try:
        result = _load_project_json_safely(
            result_json_rel,
            proj_dir,
            workspace_aliases,
        )
    except AllBugsArtifactError as exc:
        raise AllBugsArtifactError(
            f"cannot read primary result: {result_json_rel}"
        ) from exc
    if not isinstance(result, dict):
        raise AllBugsArtifactError(f"invalid primary result: {result_json_rel}")

    if result.get("result_kind") == "function_summary" and result.get("all_bugs") is True:
        summary_result_file = _normalized_validation_target_path(
            result_json_rel,
            proj_dir,
            workspace_aliases,
        )
        if summary_result_file is None:
            raise AllBugsArtifactError(f"unsafe primary result: {result_json_rel}")
        targets = []
        complete = (
            all_bugs_summary_is_complete(result, summary_result_file)
            and all_bugs_summary_paths_are_contained(
                result,
                proj_dir,
                workspace_aliases,
            )
        )
        partial = allow_partial and _partial_all_bugs_summary_is_valid(
            result,
            summary_result_file,
            proj_dir,
            workspace_aliases,
        )
        if not complete and not partial:
            raise AllBugsArtifactError("invalid or incomplete all-bugs summary")
        for ordinal, bug in enumerate(result["bugs"], start=1):
            target_rel = bug["result_file"]
            target_path = resolve_project_relative_path(
                target_rel,
                proj_dir,
                workspace_aliases,
            )
            if target_path is None:
                raise AllBugsArtifactError(f"unsafe candidate path: {target_rel}")
            try:
                candidate = _load_project_json_safely(
                    target_rel,
                    proj_dir,
                    workspace_aliases,
                )
            except AllBugsArtifactError as exc:
                raise AllBugsArtifactError(f"missing or invalid candidate: {target_rel}") from exc
            if (
                all_bugs_candidate_matches(
                    candidate,
                    bug,
                    summary_result_file,
                    ordinal,
                    summary=result,
                )
                and all_bugs_candidate_paths_are_contained(
                    candidate,
                    proj_dir,
                    workspace_aliases,
                )
            ):
                targets.append(target_rel)
            else:
                raise AllBugsArtifactError(f"candidate does not match summary: {target_rel}")
        return targets
    if result.get("verdict") == "MISMATCH":
        if not legacy_result_has_valid_schema(result):
            raise AllBugsArtifactError(
                f"invalid legacy validation target: {result_json_rel}"
            )
        return [result_json_rel]
    return []


def _legacy_bug_id_from_result_path(result_json_rel):
    parts = result_json_rel
    prefix = os.path.join("fm_agent", "logic_verification_results") + os.sep
    if parts.startswith(prefix):
        parts = parts[len(prefix):]
    elif parts.startswith("fm_agent/logic_verification_results/"):
        parts = parts[len("fm_agent/logic_verification_results/"):]
    return os.path.splitext(parts)[0].replace(os.sep, "--").replace("/", "--")


def _target_is_in_all_bugs_candidate_tree(
    result_json_rel,
    proj_dir,
    workspace_aliases=None,
):
    """Classify a target as an all-bugs candidate without reading its contents."""
    normalized_target = _normalized_validation_target_path(
        result_json_rel,
        proj_dir,
        workspace_aliases,
    )
    if normalized_target is None:
        return False
    return normalized_target.startswith(
        "fm_agent/bug_candidates/"
    )


def _load_validation_target_snapshot(
    result_json_rel,
    proj_dir,
    workspace_aliases=None,
):
    """Load a validation target once and validate all-bugs candidates before use."""
    is_candidate_path = _target_is_in_all_bugs_candidate_tree(
        result_json_rel,
        proj_dir,
        workspace_aliases,
    )
    try:
        target = _load_project_json_safely(
            result_json_rel,
            proj_dir,
            workspace_aliases,
        )
    except AllBugsArtifactError as exc:
        if is_candidate_path:
            raise AllBugsArtifactError(
                f"cannot read all-bugs candidate: {result_json_rel}"
            ) from exc
        raise

    is_candidate = is_candidate_path or (
        isinstance(target, dict) and target.get("result_kind") == "bug_candidate"
    )
    if is_candidate:
        if not is_candidate_path:
            raise AllBugsArtifactError(
                f"all-bugs candidate is outside candidate tree: {result_json_rel}"
            )
        resolved_candidate_path = resolve_project_relative_path(
            _normalized_validation_target_path(
                result_json_rel,
                proj_dir,
                workspace_aliases,
            ),
            proj_dir,
            workspace_aliases,
        )
        match = re.fullmatch(
            r"bug_(\d+)\.json",
            os.path.basename(result_json_rel.replace("\\", "/")),
        )
        ordinal = int(match.group(1)) if match else None
        expected_bug_id = expected_all_bugs_bug_id(
            target.get("function_result") if isinstance(target, dict) else None,
            ordinal,
        )
        block_index = target.get("block_index") if isinstance(target, dict) else None
        if not (
            isinstance(target, dict)
            and target.get("result_kind") == "bug_candidate"
            and is_safe_bug_id(target.get("bug_id"))
            and target.get("bug_id") == expected_bug_id
            and nonempty_string(target.get("function_id"))
            and target.get("verdict") == "MISMATCH"
            and isinstance(block_index, int)
            and not isinstance(block_index, bool)
            and block_index > 0
            and gaps_are_valid(target.get("gaps"))
            and resolved_candidate_path is not None
            and all_bugs_candidate_paths_are_contained(
                target,
                proj_dir,
                workspace_aliases,
            )
        ):
            raise AllBugsArtifactError(
                f"invalid all-bugs candidate: {result_json_rel}"
            )
        return (
            target["bug_id"],
            target["function_id"],
            True,
            candidate_content_sha256(target),
            _canonical_validation_source_identity(target.get("function"), proj_dir),
        )

    if (
        not legacy_result_has_valid_schema(target)
        or target.get("verdict") != "MISMATCH"
    ):
        raise AllBugsArtifactError(
            f"invalid legacy validation target: {result_json_rel}"
        )
    explicit_bug_id = target.get("bug_id")
    if explicit_bug_id is not None and not is_safe_bug_id(explicit_bug_id):
        raise AllBugsArtifactError("unsafe explicit bug_id")
    return (
        explicit_bug_id or _legacy_bug_id_from_result_path(result_json_rel),
        target.get("function_id") or function_id_from_result_path(result_json_rel),
        False,
        None,
        _canonical_validation_source_identity(target.get("function"), proj_dir),
    )


def _guard_all_bugs_validation_paths(result_json_rel, proj_dir, work_dir, bug_id):
    validation_dir = os.path.join(work_dir, "bug_validation")
    prompt_path = os.path.join(
        proj_dir, "fm_agent", "bug_validation", f"bug_validator_{bug_id}.md"
    )
    result_path = os.path.join(
        proj_dir, "fm_agent", "bug_validation", f"{bug_id}.result.json"
    )
    detail_path = os.path.join(
        proj_dir, "fm_agent", "bug_validation", f"{bug_id}.md"
    )
    paths = (
        validation_dir,
        prompt_path,
        prompt_path + ".tmp",
        result_path,
        result_path + ".tmp",
        detail_path,
    )
    if any(
        (os.path.lexists(path) and os.path.islink(path))
        or not path_is_symlink_free_within(path, work_dir)
        or not realpath_is_strictly_within(path, work_dir)
        for path in paths
    ):
        raise AllBugsArtifactError(
            f"unsafe bug_validation path for candidate: {result_json_rel}"
        )


def _validation_status_for_target(result_json_rel, proj_dir, work_dir):
    validation_dir = os.path.join(work_dir, "bug_validation")
    if os.path.lexists(validation_dir) and not _validation_dir_is_safe(
        work_dir,
        validation_dir,
    ):
        raise AllBugsArtifactError("unsafe bug_validation directory")

    try:
        descriptor = _validation_target_descriptor(result_json_rel, proj_dir)
    except AllBugsArtifactError:
        return "error"

    current_targets = _current_validation_targets(work_dir).get(
        descriptor["bug_id"],
        [],
    )
    if (
        len(current_targets) != 1
        or current_targets[0] != descriptor
    ):
        return "error"
    record = _accepted_validation_record(
        descriptor,
        proj_dir,
        work_dir,
    )
    return record["confirmation_status"] if record is not None else "error"


def _all_bugs_candidate_is_valid(
    candidate,
    bug,
    summary_result_file,
    ordinal,
    summary,
):
    return all_bugs_candidate_matches(
        candidate,
        bug,
        summary_result_file,
        ordinal,
        summary=summary,
    )


def _all_bugs_summary_is_resumable(summary, work_dir, summary_result_file=None):
    if not all_bugs_summary_is_complete(summary, summary_result_file):
        return False

    project_dir = _project_dir_from_work_dir(work_dir)
    if resolve_project_relative_path(summary_result_file, project_dir) is None:
        return False
    if not all_bugs_summary_paths_are_contained(summary, project_dir):
        return False
    for ordinal, bug in enumerate(summary["bugs"], start=1):
        candidate_path = resolve_project_relative_path(bug["result_file"], project_dir)
        if candidate_path is None:
            return False
        try:
            candidate = _load_project_json_safely(
                bug["result_file"],
                project_dir,
            )
        except AllBugsArtifactError:
            return False
        if not _all_bugs_candidate_is_valid(
            candidate,
            bug,
            summary_result_file,
            ordinal,
            summary,
        ) or not all_bugs_candidate_paths_are_contained(candidate, project_dir):
            return False
    return True


def _violation_gaps(spec_post, violation):
    return {
        "spec_claim": spec_post or "",
        "actual_behavior": violation.get("post_condition") or "",
        "code_evidence": violation.get("statements") or "",
        "trigger_condition": violation.get("reason") or "",
    }


def _all_bugs_candidate_dir(work_dir, rel):
    function_stem = os.path.splitext(rel)[0].replace(os.sep, "/")
    candidate_root = os.path.join(work_dir, "bug_candidates")
    candidate_dir = os.path.join(candidate_root, *function_stem.split("/"))
    if (
        not path_is_symlink_free_within(candidate_root, work_dir)
        or not path_is_symlink_free_within(candidate_dir, candidate_root)
        or not realpath_is_strictly_within(candidate_root, work_dir)
        or not realpath_is_strictly_within(candidate_dir, candidate_root)
    ):
        raise AllBugsArtifactError("unsafe bug_candidates path")
    return candidate_dir


def _clear_all_bugs_validation_artifacts(work_dir, function_result):
    validation_dir = os.path.join(work_dir, "bug_validation")
    if not os.path.lexists(validation_dir):
        return
    if (
        not path_is_symlink_free_within(validation_dir, work_dir)
        or not os.path.isdir(validation_dir)
        or not realpath_is_strictly_within(validation_dir, work_dir)
    ):
        raise AllBugsArtifactError("unsafe bug_validation directory")

    bug_id_prefix = all_bugs_bug_id_prefix(function_result)
    if bug_id_prefix is None:
        raise AllBugsArtifactError("cannot derive validation artifact identity")
    escaped_prefix = re.escape(bug_id_prefix)
    patterns = (
        re.compile(rf"^{escaped_prefix}\d{{3,}}\.result\.json$"),
        re.compile(rf"^{escaped_prefix}\d{{3,}}\.md$"),
        re.compile(rf"^bug_validator_{escaped_prefix}\d{{3,}}\.md(?:\.tmp)?$"),
        re.compile(rf"^probe_{escaped_prefix}\d{{3,}}\.[^/]+$"),
    )
    for filename in os.listdir(validation_dir):
        if any(pattern.fullmatch(filename) for pattern in patterns):
            _secure_unlink_artifact(
                os.path.join(validation_dir, filename),
                work_dir,
                missing_ok=True,
            )


def _build_all_bugs_output(result, file_path, rel, output_path, spec_post, work_dir):
    function_stem = os.path.splitext(rel)[0].replace(os.sep, "/")
    function_id = function_stem.replace("/", "::")
    bugs = []
    function_path = _project_relative_posix(file_path, work_dir)
    function_result = _project_relative_posix(output_path, work_dir)
    violations = result.get("violations", [])
    candidate_dir = _all_bugs_candidate_dir(work_dir, rel) if violations else None
    for index, violation in enumerate(violations, start=1):
        bug_id = expected_all_bugs_bug_id(function_result, index)
        if bug_id is None:
            raise AllBugsArtifactError("cannot derive deterministic bug_id")
        candidate_path = os.path.join(candidate_dir, f"bug_{index:03d}.json")
        result_file = _project_relative_posix(candidate_path, work_dir)
        gaps = _violation_gaps(spec_post, violation)
        candidate = {
            "result_kind": "bug_candidate",
            "bug_id": bug_id,
            "function_id": function_id,
            "function": function_path,
            "function_result": function_result,
            "verdict": "MISMATCH",
            "block_index": violation.get("block_index"),
            "gaps": gaps,
        }
        _write_json_atomic(
            candidate_path,
            _sanitize_artifact_strings(candidate),
            work_dir=work_dir,
        )
        bugs.append({
            "bug_id": bug_id,
            "block_index": violation.get("block_index"),
            "result_file": result_file,
            "gaps": gaps,
        })

    output = {
        "result_kind": "function_summary",
        "all_bugs": True,
        "reasoning_complete": bool(result.get("reasoning_complete")),
        "function": function_path,
        "verdict": result.get("status", "ERROR"),
        "bug_count": len(bugs),
        "gaps": bugs[0]["gaps"] if bugs else None,
        "bugs": bugs,
    }
    if output["verdict"] == "ERROR":
        output["error"] = result.get("error")
    return output


def _verify_single_file(file_path, input_dir, output_dir, language, work_dir=None, resume=False, all_bugs=False):
    """Verify a single file and write the result JSON."""
    rel = os.path.relpath(file_path, input_dir)
    output_path = os.path.join(output_dir, os.path.splitext(rel)[0] + ".json")
    if all_bugs and work_dir is None:
        work_dir = os.path.dirname(os.path.normpath(output_dir))
    results_work_dir = work_dir or os.path.dirname(os.path.normpath(output_dir))
    _guard_verification_result_path(output_path, output_dir, results_work_dir)

    # Skip if resuming and a valid result already exists.
    rejected_resume_primary = False
    if resume and os.path.lexists(output_path):
        try:
            existing = secure_load_json(
                results_work_dir,
                _relative_to_secure_root(output_path, results_work_dir),
            )
            can_skip = (
                legacy_result_is_resumable(existing, file_path)
                if not all_bugs
                else (
                    work_dir is not None
                    and _all_bugs_summary_is_resumable(
                        existing,
                        work_dir,
                        _project_relative_posix(output_path, work_dir),
                    )
                )
            )
            if can_skip:
                verdict = existing.get("verdict", "ERROR")
                logging.info(f"Already verified, skipping: {file_path} (verdict={verdict})")
                return file_path, verdict
            rejected_resume_primary = True
        except (OSError, ValueError, UnicodeError, SecureFilesystemError):
            rejected_resume_primary = True

    if rejected_resume_primary:
        _secure_unlink_artifact(
            output_path,
            results_work_dir,
            missing_ok=True,
        )

    _guard_verification_result_path(output_path, output_dir, results_work_dir)

    try:
        if all_bugs:
            _clear_all_bugs_validation_artifacts(
                work_dir,
                _project_relative_posix(output_path, work_dir),
            )
            shutil.rmtree(_all_bugs_candidate_dir(work_dir, rel), ignore_errors=True)
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
            output = _build_all_bugs_output(
                result,
                file_path,
                rel,
                output_path,
                spec_post,
                work_dir,
            )
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
    except AllBugsArtifactError:
        raise
    except Exception as exc:
        logging.exception(f"Verification failed for {file_path}")
        if all_bugs:
            output = _build_all_bugs_output(
                {
                    "status": "ERROR",
                    "reasoning_complete": False,
                    "violations": [],
                    "error": str(exc),
                },
                file_path,
                rel,
                output_path,
                None,
                work_dir,
            )
        else:
            output = {"function": file_path, "verdict": "ERROR", "gaps": None, "error": str(exc)}

    output = _sanitize_artifact_strings(output)
    _write_json_atomic(
        output_path,
        output,
        output_dir=output_dir,
        work_dir=results_work_dir,
    )

    return file_path, output["verdict"]


def _validate_single_bug(result_json_rel, proj_dir, work_dir=None, resume=False):
    """Validate a single MISMATCH result by running opencode with a per-file prompt."""
    if work_dir is None:
        work_dir = proj_dir
    script_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

    descriptor = _validation_target_descriptor(result_json_rel, proj_dir)
    bug_id = descriptor["bug_id"]
    function_id = descriptor["function_id"]
    is_candidate = descriptor["kind"] == "candidate"
    candidate_sha256 = descriptor["candidate_sha256"]
    _guard_all_bugs_validation_paths(result_json_rel, proj_dir, work_dir, bug_id)

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

    prompt_filename = os.path.join(
        "fm_agent", "bug_validation", f"bug_validator_{bug_id}.md"
    )
    prompt_path = os.path.join(proj_dir, prompt_filename)

    try:
        secure_atomic_write_text(
            work_dir,
            _relative_to_secure_root(prompt_path, work_dir),
            prompt_content,
        )
    except (OSError, SecureFilesystemError) as exc:
        raise AllBugsArtifactError(
            f"cannot safely write bug-validation prompt: {prompt_path}"
        ) from exc

    prompt = "Follow the instructions in the attached file"
    if is_cli_backend_enabled():
        command = build_agent_command(
            model=OPENCODE_BUG_VALIDATION_MODEL,
            prompt=prompt,
            cwd=proj_dir,
            files=[prompt_path],
        )
    else:
        command = ["opencode", "run", "--model", f"{OPENCODE_MODEL_PROVIDER}/{OPENCODE_BUG_VALIDATION_MODEL}",
                   "--file", prompt_path,
                   "--", prompt]
    result_relpath = os.path.join("fm_agent", "bug_validation", f"{bug_id}.result.json")
    result_path = os.path.join(proj_dir, result_relpath)
    # Resume idempotency: if resuming and this bug was already validated, don't pay for it again.
    if resume and os.path.lexists(result_path):
        existing_result = _accepted_validation_record(
            descriptor,
            proj_dir,
            work_dir,
        )
        if existing_result is not None:
            logging.info(f"Bug validation already done, skipping: {bug_id}")
            return
        try:
            _secure_unlink_artifact(
                result_path,
                work_dir,
                missing_ok=True,
                allow_symlink=True,
            )
        except (OSError, AllBugsArtifactError):
            pass
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
                    metadata={
                        "bug_id": bug_id,
                        "result_json": result_json_rel,
                        **(
                            {"candidate_sha256": candidate_sha256}
                            if is_candidate
                            else {}
                        ),
                    },
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

            if os.path.lexists(result_path):
                try:
                    validation_result = secure_load_json(
                        work_dir,
                        _relative_to_secure_root(result_path, work_dir),
                    )
                except (OSError, ValueError, UnicodeError, SecureFilesystemError):
                    validation_result = None
                if validation_result_is_valid(validation_result, bug_id):
                    if is_candidate:
                        validation_result["candidate_sha256"] = candidate_sha256
                        _guard_all_bugs_validation_paths(
                            result_json_rel,
                            proj_dir,
                            work_dir,
                            bug_id,
                        )
                        _write_json_atomic(
                            result_path,
                            validation_result,
                            work_dir=work_dir,
                        )
                    return
                try:
                    _secure_unlink_artifact(
                        result_path,
                        work_dir,
                        missing_ok=True,
                        allow_symlink=True,
                    )
                except (OSError, AllBugsArtifactError):
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
            _secure_unlink_artifact(
                prompt_path,
                work_dir,
                missing_ok=True,
                allow_symlink=True,
            )
        except (OSError, AllBugsArtifactError):
            pass


def _current_validation_targets(work_dir, workspace_aliases=None):
    project_dir = _validation_project_dir(work_dir, workspace_aliases)
    results_dir = os.path.join(work_dir, "logic_verification_results")
    targets = {}
    if not os.path.isdir(results_dir):
        return targets

    for root, _, files in os.walk(results_dir):
        for filename in files:
            if not filename.endswith(".json"):
                continue
            result_path = os.path.join(root, filename)
            if workspace_aliases:
                result_rel = "fm_agent/" + os.path.relpath(
                    result_path,
                    work_dir,
                ).replace(os.sep, "/")
            else:
                result_rel = os.path.relpath(result_path, project_dir).replace(
                    os.sep,
                    "/",
                )
            try:
                if workspace_aliases:
                    target_rels = _get_validation_target_paths(
                        result_rel,
                        project_dir,
                        allow_partial=True,
                        workspace_aliases=workspace_aliases,
                    )
                else:
                    target_rels = _get_validation_target_paths(
                        result_rel,
                        project_dir,
                        allow_partial=True,
                    )
            except AllBugsArtifactError:
                continue
            for target_rel in target_rels:
                try:
                    if workspace_aliases:
                        descriptor = _validation_target_descriptor(
                            target_rel,
                            project_dir,
                            workspace_aliases,
                        )
                    else:
                        descriptor = _validation_target_descriptor(
                            target_rel,
                            project_dir,
                        )
                except AllBugsArtifactError:
                    continue
                targets.setdefault(descriptor["bug_id"], []).append(descriptor)
    return targets


def _canonical_validation_source_identity(source_file, project_dir=None):
    if not nonempty_string(source_file):
        return None
    source_path = source_file.replace("\\", os.sep).replace("/", os.sep)
    if project_dir and os.path.isabs(source_path):
        extracted_dir = os.path.realpath(
            os.path.join(project_dir, "fm_agent", "extracted_functions")
        )
        resolved_source = os.path.realpath(source_path)
        try:
            if os.path.commonpath([extracted_dir, resolved_source]) == extracted_dir:
                source_path = os.path.relpath(resolved_source, extracted_dir)
        except ValueError:
            pass
    normalized = os.path.normpath(source_path).replace(
        os.sep,
        "/",
    )
    extracted_prefix = "fm_agent/extracted_functions/"
    if normalized.startswith(extracted_prefix):
        normalized = normalized[len(extracted_prefix):]
    return normalized if normalized not in {"", "."} else None


def _normalized_validation_target_path(
    result_json_rel,
    project_dir,
    workspace_aliases=None,
):
    if not isinstance(result_json_rel, str) or not result_json_rel:
        return None
    normalized_input = result_json_rel.replace("\\", os.sep).replace("/", os.sep)
    if workspace_aliases:
        if os.path.isabs(normalized_input):
            return None
        normalized = os.path.normpath(normalized_input).replace(os.sep, "/")
        if resolve_project_relative_path(
            normalized,
            project_dir,
            workspace_aliases,
        ) is None:
            return None
        return normalized
    target_path = os.path.abspath(_resolve_project_path(normalized_input, project_dir))
    project_root = os.path.abspath(project_dir)
    try:
        if (
            target_path == project_root
            or os.path.commonpath([project_root, target_path]) != project_root
        ):
            return None
    except ValueError:
        return None
    return os.path.relpath(target_path, project_root).replace(os.sep, "/")


def _validation_target_descriptor(
    result_json_rel,
    project_dir,
    workspace_aliases=None,
):
    (
        bug_id,
        function_id,
        is_candidate,
        candidate_sha256,
        source_identity,
    ) = _load_validation_target_snapshot(
        result_json_rel,
        project_dir,
        workspace_aliases,
    )
    target_path = _normalized_validation_target_path(
        result_json_rel,
        project_dir,
        workspace_aliases,
    )
    if target_path is None:
        raise AllBugsArtifactError(f"unsafe validation target: {result_json_rel}")

    if not is_candidate and source_identity is None:
        raise AllBugsArtifactError(
            f"invalid legacy validation target: {result_json_rel}"
        )
    if is_candidate and source_identity is None:
        raise AllBugsArtifactError(
            f"invalid candidate validation target: {result_json_rel}"
        )
    return {
        "target_path": target_path,
        "bug_id": bug_id,
        "function_id": function_id,
        "kind": "candidate" if is_candidate else "legacy",
        "candidate_sha256": candidate_sha256,
        "source_identity": source_identity,
        "legacy_source_identity": source_identity,
    }


def _validation_dir_is_safe(work_dir, validation_dir):
    return (
        os.path.isdir(validation_dir)
        and not os.path.islink(validation_dir)
        and path_is_symlink_free_within(validation_dir, work_dir)
        and realpath_is_strictly_within(validation_dir, work_dir)
    )


def _validation_file_is_safe(path, validation_dir, must_exist):
    if not realpath_is_strictly_within(path, validation_dir):
        return False
    if not os.path.lexists(path):
        return not must_exist
    return (
        not os.path.islink(path)
        and os.path.isfile(path)
        and realpath_is_strictly_within(path, validation_dir)
    )


def _load_validation_record_safely(path, work_dir, validation_dir):
    if (
        not _validation_dir_is_safe(work_dir, validation_dir)
        or not _validation_file_is_safe(path, validation_dir, must_exist=True)
    ):
        raise AllBugsArtifactError(f"unsafe validation result path: {path}")

    try:
        return secure_load_json(
            work_dir,
            _relative_to_secure_root(path, work_dir),
        )
    except (OSError, ValueError, UnicodeError, SecureFilesystemError) as exc:
        raise AllBugsArtifactError(f"cannot safely read validation result: {path}") from exc


def _accepted_validation_record(descriptor, project_dir, work_dir):
    validation_dir = os.path.join(work_dir, "bug_validation")
    if not os.path.lexists(validation_dir):
        return None
    if not _validation_dir_is_safe(work_dir, validation_dir):
        raise AllBugsArtifactError("unsafe bug_validation directory")

    result_path = os.path.join(
        validation_dir,
        f"{descriptor['bug_id']}.result.json",
    )
    try:
        record = _load_validation_record_safely(
            result_path,
            work_dir,
            validation_dir,
        )
    except (OSError, ValueError, UnicodeError) as exc:
        if not _validation_dir_is_safe(work_dir, validation_dir):
            raise AllBugsArtifactError("unsafe bug_validation directory") from exc
        logging.warning("Could not read %s: %s", result_path, exc)
        return None

    if descriptor["kind"] == "candidate":
        valid = validation_result_is_valid(
            record,
            descriptor["bug_id"],
            descriptor["candidate_sha256"],
        )
    else:
        valid = (
            validation_result_is_valid(record, descriptor["bug_id"])
            and _canonical_validation_source_identity(
                record.get("source_file") if isinstance(record, dict) else None,
                project_dir,
            ) == descriptor["legacy_source_identity"]
        )
    if not valid:
        return None
    trusted_record = dict(record)
    trusted_record["source_file"] = descriptor["source_identity"]
    return trusted_record


def _write_validation_summary_safely(
    summary_path,
    summary,
    work_dir,
    validation_dir,
):
    if not _validation_dir_is_safe(work_dir, validation_dir):
        raise AllBugsArtifactError("unsafe bug_validation directory")
    try:
        secure_atomic_write_json(
            work_dir,
            _relative_to_secure_root(summary_path, work_dir),
            summary,
        )
    except (OSError, SecureFilesystemError) as exc:
        raise AllBugsArtifactError(
            f"cannot safely write validation summary: {summary_path}"
        ) from exc


def _empty_validation_summary():
    return {
        "total_reported": 0,
        "total_confirmed": 0,
        "total_not_confirmed": 0,
        "total_error": 0,
        "total_pending": 0,
        "total_reported_functions": 0,
        "total_confirmed_functions": 0,
        "bugs": [],
    }


def _collect_current_validation_state(work_dir, workspace_aliases=None):
    """Return trusted statuses for validation records matching current targets."""
    validation_dir = os.path.join(work_dir, "bug_validation")
    validation_dir_was_present = os.path.lexists(validation_dir)
    if validation_dir_was_present and not _validation_dir_is_safe(
        work_dir,
        validation_dir,
    ):
        raise AllBugsArtifactError("unsafe bug_validation directory")

    project_dir = _validation_project_dir(work_dir, workspace_aliases)
    current_targets = _current_validation_targets(work_dir, workspace_aliases)
    bugs = []
    accepted_descriptors = []
    status_by_target = {}
    pending = 0
    for bug_id in sorted(current_targets):
        descriptors = current_targets[bug_id]
        if len(descriptors) != 1:
            pending += len(descriptors)
            continue
        descriptor = descriptors[0]
        record = _accepted_validation_record(descriptor, project_dir, work_dir)
        if record is None:
            pending += 1
            continue
        bugs.append(record)
        accepted_descriptors.append(descriptor)
        status_by_target[descriptor["target_path"]] = record["confirmation_status"]

    if (
        validation_dir_was_present or os.path.lexists(validation_dir)
    ) and not _validation_dir_is_safe(work_dir, validation_dir):
        raise AllBugsArtifactError("unsafe bug_validation directory")

    confirmed = sum(1 for b in bugs if b.get("confirmation_status") == "confirmed")
    not_confirmed = sum(1 for b in bugs if b.get("confirmation_status") == "not_confirmed")
    errors = sum(1 for b in bugs if b.get("confirmation_status") == "error")
    reported_functions = {
        descriptor["source_identity"] for descriptor in accepted_descriptors
    }
    confirmed_functions = {
        descriptor["source_identity"]
        for descriptor, record in zip(accepted_descriptors, bugs)
        if record.get("confirmation_status") == "confirmed"
    }

    # Sort: confirmed first, then not_confirmed, then error; alphabetical by id within each group
    status_order = {"confirmed": 0, "not_confirmed": 1, "error": 2}
    bugs.sort(key=lambda b: (status_order.get(b.get("confirmation_status"), 3), b.get("id", "")))

    summary = {
        "total_reported": len(bugs),
        "total_confirmed": confirmed,
        "total_not_confirmed": not_confirmed,
        "total_error": errors,
        "total_pending": pending,
        "total_reported_functions": len(reported_functions),
        "total_confirmed_functions": len(confirmed_functions),
        "bugs": bugs,
    }

    return {
        "summary": summary,
        "status_by_target": status_by_target,
    }


def load_current_validation_state(work_dir, *, workspace_aliases=None):
    """Read authoritative validation state for read-only consumers, failing closed."""
    try:
        return _collect_current_validation_state(work_dir, workspace_aliases)
    except (AllBugsArtifactError, OSError, ValueError, UnicodeError) as exc:
        logging.warning("Could not load trusted validation state: %s", exc)
        return {
            "summary": _empty_validation_summary(),
            "status_by_target": {},
        }


def _generate_validation_summary(work_dir):
    """Collect trusted validation state and persist its summary copy when possible."""
    state = _collect_current_validation_state(work_dir)
    validation_dir = os.path.join(work_dir, "bug_validation")
    if not os.path.lexists(validation_dir):
        logging.info("No bug_validation directory found; returning empty state.")
        return state

    summary_path = os.path.join(validation_dir, "summary.json")
    _write_validation_summary_safely(
        summary_path,
        state["summary"],
        work_dir,
        validation_dir,
    )
    logging.info(f"Validation summary written to {summary_path}")
    logging.info(
        "  confirmed: %s, not_confirmed: %s, error: %s, pending: %s",
        state["summary"]["total_confirmed"],
        state["summary"]["total_not_confirmed"],
        state["summary"]["total_error"],
        state["summary"]["total_pending"],
    )
    return state

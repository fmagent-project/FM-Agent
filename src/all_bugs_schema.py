import hashlib
import json
import os
import posixpath
import re


ALL_BUGS_GAP_FIELDS = {
    "spec_claim",
    "actual_behavior",
    "code_evidence",
    "trigger_condition",
}

VALID_CONFIRMATION_STATUSES = {"confirmed", "not_confirmed", "error"}
ALL_BUGS_RESULT_PREFIX = "fm_agent/logic_verification_results/"
FILESYSTEM_NAME_MAX_BYTES = 255
VALIDATION_WRAPPER_PREFIX = "bug_validator_"
VALIDATION_WRAPPER_SUFFIX = ".md.tmp"
MAX_BUG_ID_BYTES = (
    FILESYSTEM_NAME_MAX_BYTES
    - len(VALIDATION_WRAPPER_PREFIX.encode("ascii"))
    - len(VALIDATION_WRAPPER_SUFFIX.encode("ascii"))
)
MAX_BUG_ORDINAL_BYTES = 20
MAX_BUG_ID_PREFIX_BYTES = MAX_BUG_ID_BYTES - MAX_BUG_ORDINAL_BYTES


def nonempty_string(value):
    return isinstance(value, str) and bool(value.strip())


def gaps_are_valid(gaps):
    return (
        isinstance(gaps, dict)
        and set(gaps) == ALL_BUGS_GAP_FIELDS
        and all(isinstance(gaps[field], str) for field in ALL_BUGS_GAP_FIELDS)
    )


def validation_result_is_valid(
    result,
    expected_bug_id,
    expected_candidate_sha256=None,
):
    return (
        isinstance(result, dict)
        and result.get("id") == expected_bug_id
        and result.get("confirmation_status") in VALID_CONFIRMATION_STATUSES
        and (
            expected_candidate_sha256 is None
            or result.get("candidate_sha256") == expected_candidate_sha256
        )
    )


def is_safe_project_relative_posix(path):
    if not nonempty_string(path) or "\\" in path or "\x00" in path:
        return False
    if path.startswith("/") or re.match(r"^[A-Za-z]:", path):
        return False
    if posixpath.normpath(path) != path:
        return False
    return all(part not in {"", ".", ".."} for part in path.split("/"))


def is_safe_bug_id(bug_id):
    return (
        nonempty_string(bug_id)
        and "/" not in bug_id
        and "\\" not in bug_id
        and "\x00" not in bug_id
        and ".." not in bug_id
        and not re.match(r"^[A-Za-z]:", bug_id)
    )


def _encode_bug_id_path(path):
    encoded_segments = []
    for segment in path.split("/"):
        encoded = []
        for byte in segment.encode("utf-8"):
            if (
                ord("0") <= byte <= ord("9")
                or ord("A") <= byte <= ord("Z")
                or ord("a") <= byte <= ord("z")
                or byte == ord("_")
            ):
                encoded.append(chr(byte))
            else:
                encoded.append(f"%{byte:02X}")
        encoded_segments.append("".join(encoded))
    return "--".join(encoded_segments)


def _bounded_bug_id_path(function_result, function_stem):
    encoded = _encode_bug_id_path(function_stem)
    direct_prefix = f"{encoded}--bug-"
    if len(direct_prefix.encode("ascii")) <= MAX_BUG_ID_PREFIX_BYTES:
        return direct_prefix

    digest = hashlib.sha256(function_result.encode("utf-8")).hexdigest()
    digest_suffix = f"--{digest}--bug-"
    readable_budget = MAX_BUG_ID_PREFIX_BYTES - len(digest_suffix.encode("ascii"))
    readable = re.sub(r"[^A-Za-z0-9_]+", "-", function_stem).strip("-")
    readable = readable[:readable_budget].rstrip("-") or "function"
    return f"{readable}{digest_suffix}"


def all_bugs_bug_id_prefix(function_result):
    if (
        not is_safe_project_relative_posix(function_result)
        or not function_result.startswith(ALL_BUGS_RESULT_PREFIX)
        or not function_result.endswith(".json")
    ):
        return None
    function_stem = function_result[len(ALL_BUGS_RESULT_PREFIX):-len(".json")]
    if not function_stem:
        return None
    return _bounded_bug_id_path(function_result, function_stem)


def expected_all_bugs_bug_id(function_result, ordinal):
    prefix = all_bugs_bug_id_prefix(function_result)
    if (
        prefix is None
        or not isinstance(ordinal, int)
        or isinstance(ordinal, bool)
        or ordinal < 1
    ):
        return None
    encoded_ordinal = f"{ordinal:03d}"
    bug_id = f"{prefix}{encoded_ordinal}"
    if (
        len(encoded_ordinal.encode("ascii")) > MAX_BUG_ORDINAL_BYTES
        or len(bug_id.encode("ascii")) > MAX_BUG_ID_BYTES
    ):
        return None
    return bug_id


def candidate_content_sha256(candidate):
    if not isinstance(candidate, dict):
        return None
    canonical = json.dumps(
        candidate,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def path_is_symlink_free_within(path, root):
    """Return whether path is lexically contained and has no symlink components."""
    root_path = os.path.abspath(root)
    candidate_path = os.path.abspath(path)
    if os.path.lexists(root_path) and os.path.islink(root_path):
        return False
    try:
        if os.path.commonpath([root_path, candidate_path]) != root_path:
            return False
    except ValueError:
        return False

    relative_path = os.path.relpath(candidate_path, root_path)
    current_path = root_path
    if relative_path == os.curdir:
        return not (os.path.lexists(current_path) and os.path.islink(current_path))
    for component in relative_path.split(os.sep):
        current_path = os.path.join(current_path, component)
        if os.path.lexists(current_path) and os.path.islink(current_path):
            return False
    return True


def resolve_project_relative_path(path, project_dir, workspace_aliases=None):
    if not is_safe_project_relative_posix(path):
        return None
    project_root = os.path.abspath(project_dir)
    path_parts = path.split("/")
    containment_root = project_root
    if workspace_aliases and path_parts[0] in workspace_aliases:
        try:
            containment_root = os.path.abspath(
                os.fspath(workspace_aliases[path_parts[0]])
            )
        except TypeError:
            return None
        try:
            if (
                containment_root == project_root
                or os.path.commonpath([project_root, containment_root])
                != project_root
            ):
                return None
        except ValueError:
            return None
        if (
            not os.path.isdir(containment_root)
            or os.path.islink(containment_root)
            or not path_is_symlink_free_within(containment_root, project_root)
        ):
            return None
        path_parts = path_parts[1:]

    candidate_path = os.path.join(containment_root, *path_parts)
    if not path_is_symlink_free_within(candidate_path, containment_root):
        return None
    resolved = os.path.realpath(candidate_path)
    real_containment_root = os.path.realpath(containment_root)
    try:
        if (
            os.path.commonpath([real_containment_root, resolved])
            != real_containment_root
        ):
            return None
    except ValueError:
        return None
    return resolved


def realpath_is_strictly_within(path, root):
    real_root = os.path.realpath(root)
    real_path = os.path.realpath(path)
    try:
        return real_path != real_root and os.path.commonpath([real_root, real_path]) == real_root
    except ValueError:
        return False


def all_bugs_bug_entry_is_valid(bug, expected_bug_id):
    block_index = bug.get("block_index") if isinstance(bug, dict) else None
    return (
        isinstance(bug, dict)
        and expected_bug_id is not None
        and is_safe_bug_id(bug.get("bug_id"))
        and bug.get("bug_id") == expected_bug_id
        and isinstance(block_index, int)
        and not isinstance(block_index, bool)
        and block_index > 0
        and is_safe_project_relative_posix(bug.get("result_file"))
        and gaps_are_valid(bug.get("gaps"))
    )


def all_bugs_summary_is_complete(summary, summary_result_file):
    bugs = summary.get("bugs") if isinstance(summary, dict) else None
    bug_count = summary.get("bug_count") if isinstance(summary, dict) else None
    verdict = summary.get("verdict") if isinstance(summary, dict) else None
    if not (
        isinstance(summary, dict)
        and summary.get("result_kind") == "function_summary"
        and summary.get("all_bugs") is True
        and summary.get("reasoning_complete") is True
        and expected_all_bugs_bug_id(summary_result_file, 1) is not None
        and is_safe_project_relative_posix(summary.get("function"))
        and all_bugs_summary_matches_result_path(summary, summary_result_file)
        and verdict in {"MATCH", "MISMATCH"}
        and isinstance(bugs, list)
        and isinstance(bug_count, int)
        and not isinstance(bug_count, bool)
        and bug_count == len(bugs)
        and all(
            all_bugs_bug_entry_is_valid(
                bug,
                expected_all_bugs_bug_id(summary_result_file, ordinal),
            )
            for ordinal, bug in enumerate(bugs, start=1)
        )
    ):
        return False
    if verdict == "MATCH":
        return bug_count == 0 and bugs == [] and summary.get("gaps") is None
    return (
        bug_count >= 1
        and gaps_are_valid(summary.get("gaps"))
        and summary.get("gaps") == bugs[0]["gaps"]
    )


def all_bugs_summary_function_id(summary):
    function = summary.get("function") if isinstance(summary, dict) else None
    if not is_safe_project_relative_posix(function):
        return None
    extracted_prefix = "fm_agent/extracted_functions/"
    function_stem = posixpath.splitext(function)[0]
    if function_stem.startswith(extracted_prefix):
        function_stem = function_stem[len(extracted_prefix):]
    return function_stem.replace("/", "::") if function_stem else None


def _candidate_function_stem(function):
    if not is_safe_project_relative_posix(function):
        return None
    extracted_prefix = "fm_agent/extracted_functions/"
    function_stem = posixpath.splitext(function)[0]
    if function_stem.startswith(extracted_prefix):
        function_stem = function_stem[len(extracted_prefix):]
    return function_stem or None


def _result_function_stem(summary_result_file):
    if (
        not is_safe_project_relative_posix(summary_result_file)
        or not summary_result_file.startswith(ALL_BUGS_RESULT_PREFIX)
        or not summary_result_file.endswith(".json")
    ):
        return None
    return summary_result_file[
        len(ALL_BUGS_RESULT_PREFIX):-len(".json")
    ] or None


def all_bugs_summary_matches_result_path(summary, summary_result_file):
    """Bind a function summary's declared function to its result artifact path."""
    summary_stem = _candidate_function_stem(
        summary.get("function") if isinstance(summary, dict) else None
    )
    result_stem = _result_function_stem(summary_result_file)
    return summary_stem is not None and summary_stem == result_stem


def all_bugs_candidate_matches(
    candidate,
    bug,
    summary_result_file,
    ordinal,
    summary=None,
):
    block_index = candidate.get("block_index") if isinstance(candidate, dict) else None
    expected_bug_id = expected_all_bugs_bug_id(summary_result_file, ordinal)
    if not isinstance(candidate, dict):
        summary_identity_matches = False
    elif summary is None:
        expected_function_stem = _result_function_stem(summary_result_file)
        summary_identity_matches = (
            _candidate_function_stem(candidate.get("function"))
            == expected_function_stem
            and candidate.get("function_id")
            == expected_function_stem.replace("/", "::")
        ) if expected_function_stem else False
    else:
        summary_identity_matches = (
            isinstance(summary, dict)
            and candidate.get("function") == summary.get("function")
            and candidate.get("function_id") == all_bugs_summary_function_id(summary)
        )
    return (
        expected_bug_id is not None
        and all_bugs_bug_entry_is_valid(bug, expected_bug_id)
        and isinstance(candidate, dict)
        and candidate.get("result_kind") == "bug_candidate"
        and candidate.get("bug_id") == expected_bug_id
        and nonempty_string(candidate.get("function_id"))
        and candidate.get("verdict") == "MISMATCH"
        and isinstance(block_index, int)
        and not isinstance(block_index, bool)
        and block_index == bug.get("block_index")
        and is_safe_project_relative_posix(candidate.get("function"))
        and is_safe_project_relative_posix(candidate.get("function_result"))
        and candidate.get("function_result") == summary_result_file
        and summary_identity_matches
        and gaps_are_valid(candidate.get("gaps"))
        and candidate.get("gaps") == bug.get("gaps")
    )


def all_bugs_summary_paths_are_contained(
    summary,
    project_dir,
    workspace_aliases=None,
):
    return (
        isinstance(summary, dict)
        and resolve_project_relative_path(
            summary.get("function"),
            project_dir,
            workspace_aliases,
        ) is not None
        and isinstance(summary.get("bugs"), list)
        and all(
            isinstance(bug, dict)
            and resolve_project_relative_path(
                bug.get("result_file"),
                project_dir,
                workspace_aliases,
            ) is not None
            for bug in summary["bugs"]
        )
    )


def all_bugs_candidate_paths_are_contained(
    candidate,
    project_dir,
    workspace_aliases=None,
):
    return (
        isinstance(candidate, dict)
        and resolve_project_relative_path(
            candidate.get("function"),
            project_dir,
            workspace_aliases,
        ) is not None
        and resolve_project_relative_path(
            candidate.get("function_result"),
            project_dir,
            workspace_aliases,
        ) is not None
    )

import os
import json
import re


def _write_file_names(file_names, output_path):
    """Write sorted, de-duplicated file names to output_path."""
    file_names = sorted(dict.fromkeys(file_names))
    tmp_path = output_path + ".tmp"
    with open(tmp_path, "w") as f:
        json.dump(file_names, f, indent=2, ensure_ascii=False)
    os.replace(tmp_path, output_path)
    return file_names


def collect_file_names(input_dir, output_path="file_list.json"):
    """Collect all file names under input_dir and write them to a JSON file.

    Each entry contains the relative path starting from input_dir.
    """
    file_names = []
    for root, _, files in os.walk(input_dir):
        for fname in files:
            full_path = os.path.join(root, fname)
            rel_path = os.path.relpath(full_path, input_dir)
            file_names.append(rel_path)
    return _write_file_names(file_names, output_path)


def is_file_ready(file_path):
    """Check if a file has [SPEC] ... [SPEC] and [INFO] ... [INFO] headers."""
    try:
        with open(file_path, 'r') as f:
            content = f.read()
    except (OSError, UnicodeDecodeError):
        return False

    lines = content.splitlines()
    spec_count = 0
    info_count = 0

    for line in lines:
        if '[SPEC]' in line:
            spec_count += 1
        if '[INFO]' in line:
            info_count += 1

    return spec_count >= 2 and info_count >= 2


# Directories that typically contain test code
_TEST_DIR_NAMES = {
    "test", "tests", "__tests__", "testing", "test_helpers",
    "testdata", "testutils", "fixtures", "mocks",
}

# Regex patterns matching common test file naming conventions
_TEST_FILE_PATTERNS = [
    re.compile(r'^test_.*\.py$'),         # Python: test_foo.py
    re.compile(r'^.*_test\.py$'),          # Python: foo_test.py
    re.compile(r'^conftest\.py$'),         # pytest fixtures
    re.compile(r'^.*_test\.go$'),          # Go: foo_test.go
    re.compile(r'^.*_test\.(?:cpp|cc|cxx|c|h|hpp)$'),  # C/C++: foo_test.cpp
    re.compile(r'^test_.*\.(?:cpp|cc|cxx|c|h|hpp)$'),  # C/C++: test_foo.cpp
    re.compile(r'^.*Test(?:s|Case)?\.java$'),            # Java: FooTest.java
    re.compile(r'^.*\.(?:test|spec)\.(?:js|jsx|ts|tsx)$'),  # JS/TS: foo.test.js
    re.compile(r'^.*_test\.rs$'),          # Rust: foo_test.rs
    re.compile(r'^.*\.test\.(?:ets)$'),    # ArkTS: foo.test.ets
    re.compile(r'^.*_(?:SUITE|tests?)\.erl$'),  # Erlang: Common Test / EUnit
]


# Project-relative paths that must never be treated as test files, even when
# their path matches the heuristics below. The entry pipeline registers the
# source file holding its entry_func here so that file is still extracted and
# reasoned about even if it lives in a test directory or is named like a test.
_TEST_FILE_EXEMPTIONS = set()

def add_test_file_exemption(rel_path):
    """Exempt a project-relative source path from the test-file heuristics."""
    _TEST_FILE_EXEMPTIONS.add(rel_path.replace('\\', '/'))


def clear_test_file_exemptions():
    """Drop all registered test-file exemptions."""
    _TEST_FILE_EXEMPTIONS.clear()


def _load_json_dict(path, root):
    from .secure_fs import SecureFilesystemError, load_json as secure_load_json

    try:
        value = secure_load_json(root, os.path.relpath(path, root))
        return value if isinstance(value, dict) else None
    except (OSError, ValueError, UnicodeError, SecureFilesystemError):
        return None


def _get_incomplete_verification_files(
    layer_files,
    input_dir,
    output_dir,
    work_dir,
    status_by_target=None,
    all_bugs=False,
):
    """Return layer files missing verification or required bug validation output."""
    from .all_bugs_schema import (
        VALID_CONFIRMATION_STATUSES,
        all_bugs_candidate_matches,
        all_bugs_candidate_paths_are_contained,
        all_bugs_summary_is_complete,
        all_bugs_summary_paths_are_contained,
        resolve_project_relative_path,
    )
    from .verification_schema import legacy_result_is_resumable

    incomplete = []
    project_dir = (
        os.path.dirname(os.path.normpath(work_dir))
        if os.path.basename(os.path.normpath(work_dir)) == "fm_agent"
        else work_dir
    )
    for rel in layer_files:
        result_path = os.path.join(output_dir, os.path.splitext(rel)[0] + ".json")
        result = _load_json_dict(result_path, project_dir)
        if result is None:
            incomplete.append(rel)
            continue

        if (
            result.get("result_kind") == "function_summary"
            or result.get("all_bugs") is True
        ):
            if not all_bugs:
                incomplete.append(rel)
                continue
            summary_result_file = os.path.relpath(result_path, project_dir).replace(os.sep, "/")
            if not all_bugs_summary_is_complete(result, summary_result_file):
                incomplete.append(rel)
                continue

            if not all_bugs_summary_paths_are_contained(result, project_dir):
                incomplete.append(rel)
                continue
            candidates_complete = True
            for ordinal, bug in enumerate(result["bugs"], start=1):
                result_file = bug["result_file"]
                candidate_path = resolve_project_relative_path(result_file, project_dir)
                if candidate_path is None:
                    candidates_complete = False
                    break
                candidate = _load_json_dict(candidate_path, project_dir)
                if not all_bugs_candidate_matches(
                    candidate,
                    bug,
                    summary_result_file,
                    ordinal,
                ) or not all_bugs_candidate_paths_are_contained(
                    candidate,
                    project_dir,
                ) or (
                    status_by_target is None
                    or status_by_target.get(result_file)
                    not in VALID_CONFIRMATION_STATUSES
                ):
                    candidates_complete = False
                    break
            if not candidates_complete:
                incomplete.append(rel)
            continue

        if all_bugs:
            incomplete.append(rel)
            continue

        if not legacy_result_is_resumable(
            result,
            os.path.join(input_dir, rel),
        ):
            incomplete.append(rel)
            continue

        if result.get("verdict") != "MISMATCH":
            continue

        target_path = os.path.relpath(result_path, project_dir).replace(os.sep, "/")
        if (
            status_by_target is None
            or status_by_target.get(target_path) not in VALID_CONFIRMATION_STATUSES
        ):
            incomplete.append(rel)
    return incomplete


def _json_file_is_valid(path):
    try:
        with open(path, "r") as f:
            json.load(f)
        return True
    except (OSError, json.JSONDecodeError):
        return False


def _get_phase_files(phases_data, phase_num, input_dir):
    """Return relative paths of extracted function files for a given phase."""
    phase = next(p for p in phases_data["phases"] if p["phase"] == phase_num)
    phase_files = []
    for module in phase["modules"]:
        for src_file in module["source_files"]:
            dir_part = os.path.dirname(src_file)
            base = os.path.basename(src_file)
            dot_idx = base.rfind(".")
            if dot_idx >= 0:
                subdir = base[:dot_idx] + "-" + base[dot_idx + 1:]
            else:
                subdir = base
            extracted_dir = os.path.join(input_dir, dir_part, subdir)
            if os.path.isdir(extracted_dir):
                for fname in sorted(os.listdir(extracted_dir)):
                    fpath = os.path.join(extracted_dir, fname)
                    if os.path.isfile(fpath):
                        phase_files.append(os.path.relpath(fpath, input_dir))
    return phase_files


def _get_all_phase_files(phases_data, input_dir):
    """Return extracted function files reachable from all phases in phases.json."""
    phase_files = []
    seen = set()
    for phase_info in phases_data.get("phases", []):
        phase_num = phase_info.get("phase")
        if phase_num is None:
            continue
        for rel in _get_phase_files(phases_data, phase_num, input_dir):
            if rel not in seen:
                seen.add(rel)
                phase_files.append(rel)
    return phase_files


def _is_under_submodules(rel_path, submodules):
    """Return whether rel_path is inside one of the selected submodule dirs."""
    if not submodules:
        return True
    norm = rel_path.replace("\\", "/")
    while norm.startswith("./"):
        norm = norm[2:]
    return any(norm == sub or norm.startswith(sub + "/") for sub in submodules)


def _iter_project_source_files(proj_dir, submodules=None):
    """Yield project-relative source file paths, optionally limited to submodules."""
    from src.extract import EXT_TO_LANG  # local import to avoid circular import
    source_exts = set(EXT_TO_LANG.keys())
    scan_roots = [proj_dir]
    if submodules:
        scan_roots = [
            os.path.join(proj_dir, submodule.replace("/", os.sep))
            for submodule in submodules
        ]

    for scan_root in scan_roots:
        for root, dirs, files in os.walk(scan_root):
            # Skip hidden dirs and common non-source dirs
            dirs[:] = [d for d in dirs if not d.startswith('.') and d not in
                       {'node_modules', '__pycache__', 'venv', '.venv', 'fm_agent'}]
            for fname in files:
                ext = fname.rsplit('.', 1)[-1] if '.' in fname else ''
                if ext not in source_exts:
                    continue
                rel = os.path.relpath(os.path.join(root, fname), proj_dir)
                rel = rel.replace(os.sep, "/")
                if _is_under_submodules(rel, submodules):
                    yield rel


def _has_source_code(proj_dir, submodules=None):
    """Check whether proj_dir contains at least one source code file."""
    for _ in _iter_project_source_files(proj_dir, submodules):
        return True
    return False


def _is_test_file(rel_path):
    """Return True if the relative source path looks like a test file."""
    norm_path = rel_path.replace('\\', '/')
    if norm_path in _TEST_FILE_EXEMPTIONS:
        return False
    parts = norm_path.split('/')
    # Check if any directory component is a known test directory
    for part in parts[:-1]:
        if part.lower() in _TEST_DIR_NAMES:
            return True
    # Check filename against test patterns
    basename = parts[-1]
    for pat in _TEST_FILE_PATTERNS:
        if pat.match(basename):
            return True
    return False

import os
import json
import re


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
    file_names.sort()
    tmp_path = output_path + ".tmp"
    with open(tmp_path, "w") as f:
        json.dump(file_names, f, indent=2, ensure_ascii=False)
    os.replace(tmp_path, output_path)
    return file_names


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


def _get_incomplete_verification_files(layer_files, input_dir, output_dir, work_dir):
    """Return layer files missing verification or required bug validation output."""
    incomplete = []
    for rel in layer_files:
        result_path = os.path.join(output_dir, os.path.splitext(rel)[0] + ".json")
        try:
            with open(result_path, "r") as f:
                result = json.load(f)
        except (OSError, json.JSONDecodeError):
            incomplete.append(rel)
            continue

        if result.get("verdict") != "MISMATCH":
            continue

        bug_id = os.path.splitext(rel)[0].replace(os.sep, "--").replace("/", "--")
        validation_path = os.path.join(work_dir, "bug_validation", f"{bug_id}.result.json")
        if not _json_file_is_valid(validation_path):
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


def _has_source_code(proj_dir):
    """Check whether proj_dir contains at least one source code file."""
    from src.extract import EXT_TO_LANG  # local import to avoid circular import
    source_exts = set(EXT_TO_LANG.keys())
    for root, dirs, files in os.walk(proj_dir):
        # Skip hidden dirs and common non-source dirs
        dirs[:] = [d for d in dirs if not d.startswith('.') and d not in
                   {'node_modules', '__pycache__', 'venv', '.venv', 'fm_agent'}]
        for fname in files:
            ext = fname.rsplit('.', 1)[-1] if '.' in fname else ''
            if ext in source_exts:
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

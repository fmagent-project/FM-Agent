# Structured Function Metadata Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Store every extracted function's behavioral spec and callee information in two structured JSON files beside an implementation-only function file, then migrate the reasoner to consume those objects directly after an end-to-end compatibility gate.

**Architecture:** Add `src/spec_storage.py` as the only authority for metadata paths, validation, atomic Python-owned writes, and readiness. Phase 1 changes generation, resume, traversal, incremental analysis, and verification while adapting structured JSON back to the reasoner's current text inputs in memory. After full/resume/incremental/entry smoke tests pass and implementation hashes remain unchanged, Phase 2 changes the reasoner and LLM prompt helpers to consume structured dictionaries and removes all legacy marker parsing.

**Tech Stack:** Python 3.12, standard-library `json`, `pathlib`, `hashlib`, `tempfile`, `unittest`, existing `uv` environment and OpenCode/CLI backend.

## Global Constraints

- New layout is `<function>.<ext>`, `<function>.spec.json`, and `<function>.info.json` in the same directory.
- Both metadata files use `schema_version: 1` and structured fields; no `[SPEC]`, `[INFO]`, `[SPLIT]`, or language comment prefixes are persisted.
- `.info.json` is mandatory and uses `"callees": []` when the function has no callees.
- Old embedded-marker artifacts are unsupported; users must delete the target project's old `fm_agent/` before the first run on this version.
- Function implementation files must remain byte-for-byte unchanged during spec generation and spec updates.
- Phase 2 must not begin until the Phase 1 acceptance gate passes.
- Preserve unrelated user changes, including the pre-existing `install.sh` modification.
- Use built-in `unittest`; do not add dependencies.

---

## File Structure

**Create:**

- `src/spec_storage.py` — metadata naming, schema validation, JSON reads/writes, readiness, FQN derivation, and Phase 1 adapters.
- `tests/test_spec_storage.py` — storage schema, paths, readiness, and atomic-write tests.
- `tests/test_function_discovery.py` — source/metadata filtering and resume extraction tests.
- `tests/test_structured_parser.py` — Phase 1 three-file parser adapter tests.
- `tests/test_structured_reasoner.py` — Phase 2 structured reasoner tests.

**Modify in Phase 1:**

- `src/file_utils.py`
- `src/extract.py`
- `src/generate_topdown_layers.py`
- `src/generate_batch_prompts.py`
- `src/parser.py`
- `src/verification.py`
- `src/incremental_reasoner.py`
- `src/entry_reasoning_pipeline.py`
- `src/opencode_trace.py` only if output-file trace normalization requires it
- `main.py`
- `md/system_prompt.md`
- `md/workflow_spec_step4_batch.md`
- `README.md`
- `README_zh.md`

**Modify in Phase 2:**

- `src/reasoner.py`
- `src/prompts.py`
- `src/parser.py`
- `src/spec_storage.py`
- `src/verification.py`
- `tests/test_structured_parser.py`
- `tests/test_structured_reasoner.py`

---

### Task 1: Add the structured metadata storage boundary

**Files:**

- Create: `src/spec_storage.py`
- Create: `tests/test_spec_storage.py`

**Interfaces:**

- Produces: `MetadataValidationError`, `metadata_paths()`, `is_metadata_file()`, `function_fqn_from_path()`, `validate_spec_data()`, `validate_info_data()`, `read_spec()`, `read_info()`, `write_spec()`, `write_info()`, `metadata_status()`, `is_function_ready()`, `format_spec_for_reasoner()`, and `info_to_function_spec_map()`.
- Consumes: `FunctionSpecMap` from `src.parser` only for the temporary Phase 1 adapter; move that import inside `info_to_function_spec_map()` to avoid an import cycle.

- [ ] **Step 1: Write failing path and schema tests**

Create `tests/test_spec_storage.py` with `unittest` cases that use `TemporaryDirectory` and assert:

```python
from pathlib import Path
from tempfile import TemporaryDirectory
import json
import unittest

from src.spec_storage import (
    MetadataValidationError,
    function_fqn_from_path,
    is_function_ready,
    is_metadata_file,
    metadata_paths,
    read_info,
    read_spec,
    write_info,
    write_spec,
)


class SpecStorageTests(unittest.TestCase):
    def setUp(self):
        self.tmp = TemporaryDirectory()
        self.root = Path(self.tmp.name) / "fm_agent" / "extracted_functions"
        self.function = self.root / "src" / "loader-cpp" / "loadData.cpp"
        self.function.parent.mkdir(parents=True)
        self.function.write_text("int loadData() { return 1; }\n", encoding="utf-8")

    def tearDown(self):
        self.tmp.cleanup()

    def valid_spec(self):
        return {
            "schema_version": 1,
            "function": "src::loader-cpp::loadData",
            "unit": "src/loader.cpp",
            "signature": "loadData() -> int",
            "preconditions": [],
            "postconditions": ["returns the decoded value"],
        }

    def valid_info(self):
        return {
            "schema_version": 1,
            "function": "src::loader-cpp::loadData",
            "callees": [],
        }

    def test_metadata_paths_are_adjacent(self):
        spec_path, info_path = metadata_paths(self.function)
        self.assertEqual(spec_path.name, "loadData.spec.json")
        self.assertEqual(info_path.name, "loadData.info.json")

    def test_fqn_comes_from_extracted_relative_path(self):
        self.assertEqual(function_fqn_from_path(self.function), "src::loader-cpp::loadData")

    def test_ready_requires_both_valid_files(self):
        self.assertFalse(is_function_ready(self.function))
        write_spec(self.function, self.valid_spec())
        self.assertFalse(is_function_ready(self.function))
        write_info(self.function, self.valid_info())
        self.assertTrue(is_function_ready(self.function))

    def test_invalid_array_type_is_rejected(self):
        bad = self.valid_spec()
        bad["preconditions"] = "input exists"
        with self.assertRaisesRegex(MetadataValidationError, "preconditions"):
            write_spec(self.function, bad)

    def test_wrong_fqn_is_rejected(self):
        bad = self.valid_info()
        bad["function"] = "src::other::loadData"
        with self.assertRaisesRegex(MetadataValidationError, "expected"):
            write_info(self.function, bad)

    def test_metadata_suffix_detection(self):
        self.assertTrue(is_metadata_file(self.function.with_name("loadData.spec.json")))
        self.assertTrue(is_metadata_file(self.function.with_name("loadData.info.json")))
        self.assertFalse(is_metadata_file(self.function))
```

- [ ] **Step 2: Run the test and confirm the missing-module failure**

Run:

```powershell
uv run python -m unittest tests.test_spec_storage -v
```

Expected: `ModuleNotFoundError: No module named 'src.spec_storage'`.

- [ ] **Step 3: Implement paths, validation, reads, and atomic writes**

Implement `src/spec_storage.py` with these signatures and behavior:

```python
import json
import os
from pathlib import Path
from typing import Any


SCHEMA_VERSION = 1
SPEC_SUFFIX = ".spec.json"
INFO_SUFFIX = ".info.json"


class MetadataValidationError(ValueError):
    pass


def metadata_paths(function_path: str | Path) -> tuple[Path, Path]:
    path = Path(function_path)
    stem = path.with_suffix("")
    return (
        stem.with_name(stem.name + SPEC_SUFFIX),
        stem.with_name(stem.name + INFO_SUFFIX),
    )


def is_metadata_file(path: str | Path) -> bool:
    name = Path(path).name
    return name.endswith(SPEC_SUFFIX) or name.endswith(INFO_SUFFIX)


def function_fqn_from_path(function_path: str | Path) -> str:
    path = Path(function_path)
    parts = path.parts
    try:
        index = parts.index("extracted_functions")
    except ValueError as exc:
        raise MetadataValidationError(
            f"function path is not under extracted_functions: {path}"
        ) from exc
    relative = Path(*parts[index + 1:]).with_suffix("")
    return "::".join(relative.parts)


def _require_string_list(data: dict[str, Any], field: str, context: str) -> None:
    value = data.get(field)
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        raise MetadataValidationError(f"{context}.{field} must be an array of strings")


def _validate_header(data: Any, expected_fqn: str, context: str) -> dict[str, Any]:
    if not isinstance(data, dict):
        raise MetadataValidationError(f"{context} must be a JSON object")
    if data.get("schema_version") != SCHEMA_VERSION:
        raise MetadataValidationError(f"{context}.schema_version must equal {SCHEMA_VERSION}")
    if data.get("function") != expected_fqn:
        raise MetadataValidationError(
            f"{context}.function expected {expected_fqn!r}, got {data.get('function')!r}"
        )
    return data


def validate_spec_data(data: Any, expected_fqn: str) -> dict[str, Any]:
    result = _validate_header(data, expected_fqn, "spec")
    for field in ("unit", "signature"):
        if not isinstance(result.get(field), str) or not result[field].strip():
            raise MetadataValidationError(f"spec.{field} must be a non-empty string")
    _require_string_list(result, "preconditions", "spec")
    _require_string_list(result, "postconditions", "spec")
    return result


def validate_info_data(data: Any, expected_fqn: str) -> dict[str, Any]:
    result = _validate_header(data, expected_fqn, "info")
    callees = result.get("callees")
    if not isinstance(callees, list):
        raise MetadataValidationError("info.callees must be an array")
    for index, callee in enumerate(callees):
        if not isinstance(callee, dict):
            raise MetadataValidationError(f"info.callees[{index}] must be an object")
        for field in ("function", "signature"):
            if not isinstance(callee.get(field), str) or not callee[field].strip():
                raise MetadataValidationError(
                    f"info.callees[{index}].{field} must be a non-empty string"
                )
        _require_string_list(callee, "preconditions", f"info.callees[{index}]")
        _require_string_list(callee, "postconditions", f"info.callees[{index}]")
    return result


def _read_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise MetadataValidationError(f"cannot read valid JSON from {path}: {exc}") from exc


def _write_json_atomic(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(
        json.dumps(data, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    os.replace(temporary, path)
```

Complete `read_spec()`, `read_info()`, `write_spec()`, and `write_info()` by deriving the expected FQN, calling the matching validator, and using the adjacent path from `metadata_paths()`.

- [ ] **Step 4: Implement readiness with diagnosable status**

Add:

```python
def metadata_status(function_path: str | Path) -> tuple[bool, str | None]:
    path = Path(function_path)
    if not path.is_file():
        return False, f"function implementation does not exist: {path}"
    try:
        read_spec(path)
        read_info(path)
    except MetadataValidationError as exc:
        return False, str(exc)
    return True, None


def is_function_ready(function_path: str | Path) -> bool:
    ready, _ = metadata_status(function_path)
    return ready
```

- [ ] **Step 5: Add Phase 1 adapters and tests**

Add tests asserting the adapter output contains the existing headings and produces callee lookup entries. Implement:

```python
def format_spec_for_reasoner(spec: dict[str, Any]) -> str:
    pre = "\n".join(f"- {item}" for item in spec["preconditions"]) or "- (none)"
    post = "\n".join(f"- {item}" for item in spec["postconditions"]) or "- (none)"
    return f"Pre-condition:\n{pre}\nPost-condition:\n{post}"


def info_to_function_spec_map(info: dict[str, Any]):
    from src.parser import FunctionSpecMap

    result = FunctionSpecMap()
    for callee in info["callees"]:
        pre = "\n".join(f"- {item}" for item in callee["preconditions"]) or "- (none)"
        post = "\n".join(f"- {item}" for item in callee["postconditions"]) or "- (none)"
        name = callee["function"].split("::")[-1]
        result.add_entry(
            name,
            callee["signature"],
            f"Pre-condition:\n{pre}\nPost-condition:\n{post}",
        )
    return result
```

- [ ] **Step 6: Run storage tests**

Run:

```powershell
uv run python -m unittest tests.test_spec_storage -v
```

Expected: all tests pass.

- [ ] **Step 7: Commit the storage boundary**

```powershell
git add src/spec_storage.py tests/test_spec_storage.py
git commit -m "feat(spec): add structured metadata storage"
```

---

### Task 2: Make extraction and discovery metadata-aware

**Files:**

- Modify: `src/file_utils.py:6-52,121-156`
- Modify: `src/extract.py:679-795`
- Modify: `src/generate_topdown_layers.py:27-57,503-598`
- Create: `tests/test_function_discovery.py`

**Interfaces:**

- Consumes: `is_metadata_file()` and `is_function_ready()` from Task 1.
- Produces: function enumeration that never returns metadata JSON and keeps the existing `is_file_ready(function_path) -> bool` compatibility name.

- [ ] **Step 1: Write failing discovery tests**

Create fixtures containing `loadData.cpp`, `loadData.spec.json`, and `loadData.info.json`. Assert `collect_file_names()` and `_get_phase_files()` return only `loadData.cpp`, and `_collect_phase_files()` does not include JSON metadata.

Use this exact central assertion:

```python
self.assertEqual(collected, [str(Path("src") / "loader-cpp" / "loadData.cpp")])
```

- [ ] **Step 2: Run the discovery tests and confirm JSON files leak into results**

```powershell
uv run python -m unittest tests.test_function_discovery -v
```

Expected: at least one failure showing `.spec.json` or `.info.json` in a function list.

- [ ] **Step 3: Replace marker-based readiness**

In `src/file_utils.py`, remove the `[SPEC]/[INFO]` scanning implementation and retain the public name:

```python
from src.spec_storage import is_function_ready, is_metadata_file


def is_file_ready(file_path):
    """Return whether both structured metadata files are valid for a function."""
    return is_function_ready(file_path)
```

Filter `is_metadata_file()` in `collect_file_names()`, `_get_phase_files()`, and `_get_all_phase_files()` before appending a path.

- [ ] **Step 4: Restrict source discovery by supported extension**

In both `file_utils` and `generate_topdown_layers`, require that the final suffix maps through `EXT_TO_LANG` and reject metadata files first. Do not use a generic “not JSON” test because future source languages may use additional extensions.

- [ ] **Step 5: Decouple extraction writes from metadata readiness**

Change `run_extraction()` so resume does not use spec readiness to decide whether the implementation is written. Define source equality explicitly:

```python
existing_source = None
if os.path.exists(out_file):
    with open(out_file, "r", errors="replace") as f:
        existing_source = f.read()

if not force and existing_source == func_source:
    skipped += 1
    continue

with open(out_file, "w") as f:
    f.write(func_source)
```

If the implementation changes during non-forced resume extraction, remove its adjacent metadata files so stale specs cannot remain ready. Do not do this when `force=True`: incremental mode intentionally force-reextracts current source while retaining prior metadata for comparison and update planning.

```python
if not force and existing_source is not None and existing_source != func_source:
    for metadata_path in metadata_paths(out_file):
        metadata_path.unlink(missing_ok=True)
```

- [ ] **Step 6: Run storage and discovery tests**

```powershell
uv run python -m unittest tests.test_spec_storage tests.test_function_discovery -v
```

Expected: all tests pass and no collected function path ends with `.json`.

- [ ] **Step 7: Commit extraction/discovery changes**

```powershell
git add src/file_utils.py src/extract.py src/generate_topdown_layers.py tests/test_function_discovery.py
git commit -m "refactor(extract): separate function metadata files"
```

---

### Task 3: Generate structured metadata without overwriting implementations

**Files:**

- Modify: `src/generate_batch_prompts.py:86-162,191-340,343-448`
- Modify: `md/system_prompt.md:62-94`
- Modify: `md/workflow_spec_step4_batch.md:8-68`
- Test: `tests/test_spec_storage.py`
- Create: `tests/test_generate_batch_prompts.py`

**Interfaces:**

- Consumes: `read_spec()`, `read_info()`, `metadata_paths()`, and `is_function_ready()`.
- Produces: batch prompts that name the implementation as read-only and the exact two JSON output paths.

- [ ] **Step 1: Write failing prompt tests**

Build one caller and one callee fixture with valid JSON. Assert generated prompt:

- contains `loadData.spec.json` and `loadData.info.json`;
- contains the caller's structured postcondition;
- contains the callee expectation matched by full FQN;
- does not contain “prepend”, “SAME path”, or “overwriting the original”.

- [ ] **Step 2: Run the prompt test and confirm it sees legacy instructions**

```powershell
uv run python -m unittest tests.test_generate_batch_prompts -v
```

Expected: failures on legacy overwrite wording and missing JSON output paths.

- [ ] **Step 3: Replace text-block extraction with structured reads**

Delete `_detect_comment_prefix()`, `extract_spec_block()`, `extract_info_block()`, and `extract_callee_spec_from_info()` from `src/generate_batch_prompts.py`. Add a full-FQN matcher:

```python
def callee_expectation(info_data: dict, callee_fqn: str) -> dict | None:
    return next(
        (callee for callee in info_data["callees"] if callee["function"] == callee_fqn),
        None,
    )
```

Use `json.dumps(data, indent=2, ensure_ascii=False)` when embedding caller context.

- [ ] **Step 4: Rewrite batch output instructions**

For each function entry, calculate adjacent output paths and emit exact rules:

```text
Read implementation (read-only): fm_agent/extracted_functions/src/loader-cpp/loadData.cpp
Write spec JSON: fm_agent/extracted_functions/src/loader-cpp/loadData.spec.json
Write info JSON: fm_agent/extracted_functions/src/loader-cpp/loadData.info.json
Do not edit, rewrite, prepend to, or otherwise modify the implementation file.
```

Include the complete schema examples with concrete values and require `callees: []` when empty.

- [ ] **Step 5: Rewrite shared model instructions**

Replace marker-format sections in both Markdown prompt files with the same JSON schemas and these invariants:

```text
The implementation file is immutable input.
Create both JSON files for every function.
Write valid JSON only; do not wrap JSON in Markdown fences.
The top-level function field must exactly equal the FQN given in the batch prompt.
```

- [ ] **Step 6: Run prompt and storage tests**

```powershell
uv run python -m unittest tests.test_spec_storage tests.test_generate_batch_prompts -v
```

Expected: all tests pass.

- [ ] **Step 7: Commit prompt changes**

```powershell
git add src/generate_batch_prompts.py md/system_prompt.md md/workflow_spec_step4_batch.md tests/test_generate_batch_prompts.py
git commit -m "feat(spec): generate structured function metadata"
```

---

### Task 4: Guard implementations and trace both JSON outputs

**Files:**

- Modify: `main.py:55-174,328-458`
- Modify: `src/opencode_trace.py:231-287` only if no code change is needed, verify it already records arbitrary output paths and leave it unchanged.
- Test: `tests/test_generate_batch_prompts.py`

**Interfaces:**

- Consumes: `metadata_paths()` and `metadata_status()`.
- Produces: `_run_spec_generation_batch()` that snapshots implementation bytes, traces two outputs per function, restores accidental edits, invalidates that function's metadata, and returns failure.

- [ ] **Step 1: Write a failing batch-integrity unit test**

Mock `run_opencode_traced()` so it changes a function file and writes two JSON files. Assert `_run_spec_generation_batch()` restores the original bytes, removes both generated metadata files, and returns a non-zero code.

- [ ] **Step 2: Run the targeted test**

```powershell
uv run python -m unittest tests.test_generate_batch_prompts.BatchIntegrityTests -v
```

Expected: failure because current code does not snapshot or restore implementations.

- [ ] **Step 3: Snapshot and verify implementation bytes**

Add helpers in `main.py`:

```python
def _snapshot_function_sources(proj_dir, function_files):
    return {
        rel: Path(proj_dir, rel).read_bytes()
        for rel in function_files
    }


def _restore_modified_sources(proj_dir, snapshots):
    modified = []
    for rel, original in snapshots.items():
        path = Path(proj_dir, rel)
        current = path.read_bytes() if path.exists() else None
        if current == original:
            continue
        path.write_bytes(original)
        for metadata_path in metadata_paths(path):
            metadata_path.unlink(missing_ok=True)
        modified.append(rel)
    return modified
```

Take the snapshot before starting the agent. After it exits, restore changes, log each path, and return `1` if `modified` is non-empty.

- [ ] **Step 4: Trace actual metadata output paths**

Replace `output_files=function_files` with the flattened relative `.spec.json` and `.info.json` paths derived from each function path. Keep implementation paths in `input_files`.

- [ ] **Step 5: Improve pending/error messages**

Replace “missing specs” and marker-oriented messages with `metadata_status()` reasons such as missing file, invalid JSON, invalid schema, or mismatched FQN.

- [ ] **Step 6: Run targeted tests**

```powershell
uv run python -m unittest tests.test_generate_batch_prompts -v
```

Expected: all tests pass, including restoration after accidental edits.

- [ ] **Step 7: Commit orchestration changes**

```powershell
git add main.py tests/test_generate_batch_prompts.py
git commit -m "fix(spec): protect extracted implementations during generation"
```

---

### Task 5: Read three files through the Phase 1 reasoner adapter

**Files:**

- Modify: `src/parser.py:1-188`
- Modify: `src/verification.py:64-325`
- Create: `tests/test_structured_parser.py`

**Interfaces:**

- Consumes: `read_spec()`, `read_info()`, `format_spec_for_reasoner()`, `info_to_function_spec_map()`, and `metadata_status()`.
- Produces: temporary compatibility signature `parse_input_function(function_path) -> tuple[str, str, FunctionSpecMap]` with no marker parsing.

- [ ] **Step 1: Write failing parser tests**

Create a Python function plus valid metadata. Assert:

```python
func, spec, knowledge = parse_input_function(function_path)
self.assertIn("Line 1: def load_data", func)
self.assertIn("Pre-condition:", spec)
self.assertIn("returns the decoded value", spec)
self.assertIn("parse_header", knowledge)
self.assertNotIn("[SPEC]", spec)
```

Also assert malformed `.spec.json` raises `MetadataValidationError` naming the path.

- [ ] **Step 2: Run the parser test and confirm legacy parsing fails**

```powershell
uv run python -m unittest tests.test_structured_parser -v
```

Expected: current parser returns no spec because the implementation contains no markers.

- [ ] **Step 3: Replace mixed-file parsing**

Keep `_remove_func_comments()` and line numbering. Replace section extraction in `parse_input_function()` with:

```python
def parse_input_function(file_path):
    with open(file_path, "r") as file:
        content = file.read()
    spec_data = read_spec(file_path)
    info_data = read_info(file_path)
    func = _remove_func_comments(content)
    numbered = [f"Line {index + 1}: {line}" for index, line in enumerate(func.split("\n"))]
    return (
        "\n".join(numbered),
        format_spec_for_reasoner(spec_data),
        info_to_function_spec_map(info_data),
    )
```

Retain `FunctionSpecMap` until Phase 2; delete `_SECTION_MARKER_RE`, `_SPLIT_MARKER_RE`, `_extract_marked_section()`, `_strip_section_comment_prefix()`, `_extract_function_name()`, and `_parse_info_section()` only after confirming no other Phase 1 caller uses them.

- [ ] **Step 4: Make watcher diagnostics metadata-aware**

In `streaming_reasoner()`, call `metadata_status()` when a function is not ready. Avoid logging on every two-second poll by cacheing the last reason per function and only logging when it changes.

- [ ] **Step 5: Run parser, storage, and verification-import tests**

```powershell
uv run python -m unittest tests.test_spec_storage tests.test_structured_parser -v
uv run python -c "from src.verification import streaming_reasoner; print('verification import ok')"
```

Expected: tests pass and the import command prints `verification import ok`.

- [ ] **Step 6: Commit parser/watcher changes**

```powershell
git add src/parser.py src/verification.py tests/test_structured_parser.py
git commit -m "refactor(verify): read structured function metadata"
```

---

### Task 6: Convert incremental updates to JSON-only writes

**Files:**

- Modify: `src/incremental_reasoner.py:159-302,446-531,1203-1465,1477-1760,1765-1910`
- Test: `tests/test_spec_storage.py`
- Create: `tests/test_incremental_metadata.py`

**Interfaces:**

- Consumes: the storage API and structured JSON schemas.
- Produces: incremental spec propagation that never reads or writes spec text in implementation files.

- [ ] **Step 1: Write failing incremental tests**

Cover these exact cases with temporary extracted trees and mocked LLM responses:

- `_previous_full_run_complete()` ignores metadata files as functions and requires both valid JSON files.
- force re-extraction leaves valid metadata intact when the implementation path still exists.
- `_remove_stale_extracted()` deletes implementation, `.spec.json`, and `.info.json` for a removed function.
- a structured spec update changes only `.spec.json`/`.info.json`; implementation bytes remain equal.
- caller reconciliation changes only the caller's `.info.json` entry matching the callee FQN.

- [ ] **Step 2: Run incremental tests and confirm embedded-format assumptions fail**

```powershell
uv run python -m unittest tests.test_incremental_metadata -v
```

Expected: failures in old header capture/reapply and splice logic.

- [ ] **Step 3: Delete capture/reapply behavior**

Remove `extract_existing_specs()`, `_reapply_existing_specs()`, `_extract_leading_spec_comments()`, and `_split_spec_and_info()`. In Stage 4, keep:

```python
try_codegraph_init(proj_dir)
run_extraction(proj_dir, work_dir=work_dir, force=True, verbose=True)
```

Do not delete valid metadata for paths still present; delete stale metadata for removed paths in `_remove_stale_extracted()`.

- [ ] **Step 4: Change LLM update contracts to structured data**

The direct LLM JSON response must use:

```json
{
  "spec_updated": true,
  "new_spec": {
    "schema_version": 1,
    "function": "src::loader-cpp::loadData",
    "unit": "src/loader.cpp",
    "signature": "loadData() -> int",
    "preconditions": [],
    "postconditions": ["returns the decoded value"]
  },
  "info_updated": true,
  "new_info": {
    "schema_version": 1,
    "function": "src::loader-cpp::loadData",
    "callees": []
  },
  "updated_callees": []
}
```

Validate `new_spec` and `new_info` before constructing an apply plan. Reject strings and invalid objects.

- [ ] **Step 5: Replace splice writes with storage writes**

Apply plans carry dictionaries rather than `write_content`. Stage 2 calls `write_spec(plan["fpath"], plan["new_spec"])`; when `plan["info_updated"]` is true it calls `write_info(plan["fpath"], plan["new_info"])`. Caller reconciliation reads caller info, replaces exactly one full-FQN entry, validates it, and calls `write_info(caller_path, updated_info)`.

- [ ] **Step 6: Update caller context**

Make `_collect_caller_context()` return caller spec objects plus the matching callee object from caller info. Match only exact FQN.

- [ ] **Step 7: Run incremental and core tests**

```powershell
uv run python -m unittest tests.test_spec_storage tests.test_incremental_metadata -v
```

Expected: all tests pass and implementation-byte assertions remain equal.

- [ ] **Step 8: Commit incremental changes**

```powershell
git add src/incremental_reasoner.py tests/test_incremental_metadata.py
git commit -m "refactor(incremental): update structured metadata only"
```

---

### Task 7: Complete Phase 1 integration and acceptance gate

**Files:**

- Modify: `src/entry_reasoning_pipeline.py:305-460` only where discovery or copied-workspace assumptions require explicit metadata filtering.
- Modify: `README.md:180-235`
- Modify: `README_zh.md:160-215`
- Modify: `main.py` comments/help text containing embedded-marker semantics.
- Modify: `src/incremental_reasoner.py` comments/docstrings containing embedded-marker semantics.

**Interfaces:**

- Consumes: all Phase 1 tasks.
- Produces: a documented, end-to-end structured-storage release candidate and a recorded acceptance result.

- [ ] **Step 1: Search for remaining persisted-marker assumptions**

Run:

```powershell
rg -n "prepend|overwrit|\[SPEC\]|\[INFO\]|\[SPLIT\]|extract_spec_block|extract_info_block" main.py src md README.md README_zh.md
```

Expected: occurrences remain only in explicit upgrade documentation or Phase 1 reasoner compatibility tests; no generation, readiness, parsing, or incremental path depends on markers.

- [ ] **Step 2: Update entry-mode filtering**

Run its selection functions against a fixture containing metadata and assert only implementation files enter `_collect_phase_files()` and the BFS. Because entry mode delegates final generation to `run_pipeline()`, do not duplicate storage logic in `entry_reasoning_pipeline.py`.

- [ ] **Step 3: Document layout and incompatible upgrade**

Add the concrete three-file tree, structured schema summary, resume semantics, and this command to both READMEs:

```powershell
$targetProject = "D:\tmp\fm-agent-structured-smoke"
Remove-Item -Recurse -Force "$targetProject\fm_agent"
uv run python main.py $targetProject
```

State that the removal applies only when upgrading an existing target workspace from the embedded-marker format.

- [ ] **Step 4: Run all local no-LLM tests**

```powershell
uv run python -m unittest discover -s tests -p "test_*.py" -v
```

Expected: all tests pass.

- [ ] **Step 5: Run a full-mode smoke test on a small representative project**

Use a temporary Git project with two Python functions where one calls the other:

```powershell
uv run python main.py D:\tmp\fm-agent-structured-smoke
```

Expected:

- every implementation file has adjacent valid `.spec.json` and `.info.json`;
- the leaf function has `"callees": []`;
- implementation hashes captured before Stage 4 equal hashes after completion;
- `logic_verification_results` contains one JSON verdict per implementation and none for metadata files.

- [ ] **Step 6: Run resume failure/recovery checks**

First rerun:

```powershell
uv run python main.py D:\tmp\fm-agent-structured-smoke --resume
```

Expected: all valid metadata is skipped. Then corrupt exactly one `.spec.json` and rerun the same command. Expected: only that function's batch is regenerated, both of its metadata files become valid, and its implementation hash is unchanged.

- [ ] **Step 7: Run incremental and entry-mode smoke tests**

Modify one function and create `D:\tmp\fm-agent-structured-smoke\intent.md`, then run:

```powershell
uv run python main.py D:\tmp\fm-agent-structured-smoke --incremental D:\tmp\fm-agent-structured-smoke\intent.md
uv run python main.py D:\tmp\fm-agent-structured-smoke --entry-func module-py::caller
```

Expected: only affected metadata is updated in incremental mode; entry mode emits the three-file layout for selected functions; neither mode embeds markers into implementations.

- [ ] **Step 8: Stop if the Phase 1 gate fails**

Do not start Task 8 unless Steps 4-7 all pass. Record the exact failed command and output, fix Phase 1, and rerun the complete gate.

- [ ] **Step 9: Commit Phase 1 integration**

```powershell
git add src/entry_reasoning_pipeline.py main.py src/incremental_reasoner.py README.md README_zh.md
git commit -m "docs: document structured function metadata"
```

---

### Task 8: Make the reasoner consume structured objects directly

**Files:**

- Modify: `src/reasoner.py:179-240`
- Modify: `src/prompts.py:99-132,250-363`
- Modify: `src/parser.py:1-188`
- Modify: `src/spec_storage.py`
- Modify: `src/verification.py:252-325`
- Create: `tests/test_structured_reasoner.py`
- Modify: `tests/test_structured_parser.py`

**Interfaces:**

- Consumes: validated spec/info dictionaries from storage.
- Produces: `parse_input_function() -> tuple[str, dict, dict]` and `reasoner(func: str, spec: dict, info: dict, language: str, trace_context: dict | None = None)`.

- [ ] **Step 1: Write failing structured-reasoner tests**

Mock `_generate_block_post_condition()` and `_check_post_implies_spec()`. Call `reasoner()` with dictionaries and assert:

- preconditions are passed as a deterministic newline string;
- postconditions are passed as a deterministic newline string;
- info passed to prompt helpers is the structured info dictionary;
- empty preconditions are accepted and do not cause “Failed to parse”.

- [ ] **Step 2: Run the tests and confirm the text parser fails on dictionaries**

```powershell
uv run python -m unittest tests.test_structured_reasoner -v
```

Expected: a type error from regex processing or the old parse failure.

- [ ] **Step 3: Replace `_parse_spec_conditions()` with structured extraction**

Add:

```python
def _condition_text(conditions):
    return "\n".join(f"- {condition}" for condition in conditions) or "- (none)"


def reasoner(func, spec, info, language, trace_context=None):
    pre_condition = _condition_text(spec["preconditions"])
    spec_post_condition = _condition_text(spec["postconditions"])
```

Keep the existing block splitting and verdict control flow unchanged.

- [ ] **Step 4: Serialize structured info only at the LLM message boundary**

In `src/prompts.py`, replace implicit `str(knowledge)` formatting with deterministic JSON:

```python
def _knowledge_text(knowledge):
    if not knowledge or not knowledge.get("callees"):
        return ""
    return json.dumps(knowledge, indent=2, ensure_ascii=False, sort_keys=True)
```

Use this helper in `_generate_block_post_condition()` and `_check_post_implies_spec()`.

- [ ] **Step 5: Return dictionaries from the parser**

Change `parse_input_function()` to return numbered implementation text plus `read_spec(file_path)` and `read_info(file_path)` directly. Delete `FunctionSpecMap` and all Phase 1 adapter calls.

- [ ] **Step 6: Remove compatibility adapters**

Delete `format_spec_for_reasoner()` and `info_to_function_spec_map()` from `src/spec_storage.py`. Remove `_parse_spec_conditions()` from `src/reasoner.py` and update verification imports/tests.

- [ ] **Step 7: Run structured parser/reasoner tests**

```powershell
uv run python -m unittest tests.test_spec_storage tests.test_structured_parser tests.test_structured_reasoner -v
```

Expected: all tests pass.

- [ ] **Step 8: Commit direct reasoner consumption**

```powershell
git add src/reasoner.py src/prompts.py src/parser.py src/spec_storage.py src/verification.py tests/test_structured_parser.py tests/test_structured_reasoner.py
git commit -m "refactor(reasoner): consume structured specifications"
```

---

### Task 9: Remove legacy parsing and rerun the complete gate

**Files:**

- Modify: any files reported by the legacy search, limited to storage/generation/verification comments and dead imports.
- Modify: `README.md`
- Modify: `README_zh.md`

**Interfaces:**

- Consumes: Phase 2 structured reasoner.
- Produces: no runtime dependency on embedded markers and final verified behavior.

- [ ] **Step 1: Prove legacy parser symbols are gone**

Run:

```powershell
rg -n "FunctionSpecMap|_parse_spec_conditions|_extract_marked_section|extract_spec_block|extract_info_block|\[SPLIT\]" main.py src
```

Expected: no matches.

- [ ] **Step 2: Run all no-LLM tests**

```powershell
uv run python -m unittest discover -s tests -p "test_*.py" -v
```

Expected: all tests pass.

- [ ] **Step 3: Repeat full, resume, corrupted-metadata, incremental, and entry smoke tests**

Run the same commands from Task 7 Steps 5-7 against a freshly deleted `D:\tmp\fm-agent-structured-smoke\fm_agent`.

Expected: the same metadata layout and verdict behavior as Phase 1, with implementation hashes unchanged.

- [ ] **Step 4: Inspect generated artifacts**

Run:

```powershell
Get-ChildItem -Recurse D:\tmp\fm-agent-structured-smoke\fm_agent\extracted_functions | Select-Object FullName
rg -n "\[SPEC\]|\[INFO\]|\[SPLIT\]" D:\tmp\fm-agent-structured-smoke\fm_agent\extracted_functions -g "!*.json"
```

Expected: every implementation has two JSON neighbors and the marker search returns no matches.

- [ ] **Step 5: Review the final diff for unrelated changes**

```powershell
git status --short
git diff --check
git diff --stat 522e86c
```

Expected: only planned source, prompt, test, and documentation files are present; the user's unrelated `install.sh` modification remains uncommitted and untouched.

- [ ] **Step 6: Commit final cleanup**

```powershell
git add main.py src md README.md README_zh.md tests
git commit -m "refactor: remove embedded spec format support"
```

---

## Final Acceptance Checklist

- [ ] Extracted implementation files contain implementation only.
- [ ] Every implementation has a valid `.spec.json` and `.info.json`.
- [ ] No-callee functions have `"callees": []`.
- [ ] Metadata JSON is never enumerated as a function.
- [ ] Full, resume, incremental, and entry modes pass.
- [ ] Corrupt or partial metadata remains pending and is regenerated.
- [ ] FQN mismatches are rejected with explicit diagnostics.
- [ ] Spec generation and incremental updates preserve implementation bytes.
- [ ] Cross-layer caller expectations match callees by full FQN.
- [ ] Reasoner consumes structured dictionaries directly.
- [ ] No runtime code parses `[SPEC]`, `[INFO]`, or `[SPLIT]`.
- [ ] README upgrade instructions clearly state that old `fm_agent/` workspaces must be removed.

# Spec Generation Module Implementation Plan

**Goal:** Encapsulate full-run structured spec generation in `src/spec_generation/`,
with extracted functions plus layer JSON as inputs and adjacent spec/info JSON files
as outputs.

**Constraints:** Preserve the structured schema and output paths, support only the new
format, keep implementation files byte-identical, preserve resume semantics, do not
commit the existing `install.sh` modification, and run project commands in WSL.

## Task 1: Define the package contract with tests

**Files:**

- Create `tests/test_spec_generation_module.py`
- Modify `tests/test_generate_batch_prompts.py`

1. Add a test that passes an extracted-functions directory and a layer JSON path to
   `generate_batch_manifest()` and asserts its manifest and prompt targets.
2. Add a resume test that supplies valid adjacent metadata and asserts the manifest
   records zero pending functions without writing an empty prompt.
3. Move batch integrity imports from `main` to `src.spec_generation.runner` and keep
   assertions for immutable implementations and trace output declarations.
4. Add a main delegation test proving Stage 4 calls `run_spec_generation()`.
5. Run the targeted tests and confirm they fail because the package API is absent.

## Task 2: Move prompt generation into the package

**Files:**

- Create `src/spec_generation/__init__.py`
- Create `src/spec_generation/batch_prompts.py`
- Delete `src/generate_batch_prompts.py`
- Modify `src/incremental_reasoner.py`

1. Move pure prompt helpers into `batch_prompts.py`.
2. Extract the CLI-bound body into `generate_batch_manifest()` with explicit paths and
   values; return the manifest object.
3. Keep no copied-project fallback imports because generation now runs in-process.
4. Update incremental imports to the package path.
5. Run prompt/module tests until green.

## Task 3: Move execution and retry orchestration into the package

**Files:**

- Create `src/spec_generation/runner.py`
- Modify `main.py`
- Modify `tests/test_spec_generation_module.py`
- Modify `tests/test_generate_batch_prompts.py`

1. Move pending-batch, source snapshot/restore, and single-batch execution helpers to
   `runner.py`.
2. Move the phase/layer/retry loop into `run_spec_generation()`.
3. Require pre-existing layer JSON and use `generate_batch_manifest()` directly.
4. Replace Stage 4 in `main.py` with the package call and remove copied scripts,
   subprocess setup, and obsolete imports.
5. Run targeted tests until green.

## Task 4: Verify the complete module

1. Search for obsolete `src.generate_batch_prompts`, copied generator scripts, and
   Stage 4 helper definitions in `main.py`.
2. Run all unit tests in WSL.
3. Run `compileall` in WSL.
4. Run a local filesystem smoke test that feeds a synthetic extracted function and
   layer JSON into the manifest API, then validates the declared adjacent paths.
5. Record commands and results in a verification document.
6. Commit implementation and verification with semantic prefixes.


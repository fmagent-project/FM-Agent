# Spec Generation Module Design

## Goal

Make structured function-spec generation an explicit module whose inputs are the
extracted implementation files and phase top-down layer JSON, and whose primary
outputs are adjacent `.spec.json` and `.info.json` files.

## Boundary

The new `src/spec_generation/` package owns all full-run spec-generation behavior:

- reading and validating layer JSON;
- selecting functions and building resume-aware batch manifests;
- constructing prompts from implementations and earlier-layer caller metadata;
- invoking the configured agent backend;
- declaring `.spec.json` and `.info.json` as the only metadata outputs;
- restoring an implementation if an external agent modifies it;
- retrying incomplete metadata batches; and
- coordinating verification while batches finish.

`src/spec_storage.py` remains outside the package because generation, parsing,
verification, resume, and incremental analysis all share that persistence boundary.
Top-down graph construction also remains separate: it produces a module input and is
not part of spec generation.

## Package Layout

```text
src/spec_generation/
  __init__.py       public API
  batch_prompts.py  layer JSON -> prompt files and manifest
  runner.py         manifest -> spec/info sidecars, retries, integrity protection
```

The public API is:

```python
generate_batch_manifest(...)
run_spec_generation(...)
```

`run_spec_generation()` receives the project directory, `fm_agent` work directory,
phase data, verification output directory, and resume state. It derives the extracted
function directory and requires each phase layer JSON to already exist. This keeps the
runtime call concise while preserving an explicit filesystem contract.

## Integration

`main.py` retains setup, extraction, and top-down layer generation. Stage 4 becomes a
single call to `run_spec_generation()`. It no longer copies a Python generator script
or its imports into the analyzed project and no longer starts a nested Python process
to create prompts.

Incremental analysis imports reusable prompt helpers from the package. Incremental
metadata update behavior remains in `incremental_reasoner.py` because it consumes a
developer intent and performs graph propagation, a different input contract from the
full-run layer module.

## Compatibility

Only the current structured format is supported. The generated layout and schemas do
not change. `src/generate_batch_prompts.py` is removed rather than retained as a
compatibility wrapper, so there is one implementation and one import path.

## Tests

- Package tests validate explicit layer JSON input, adjacent output declarations,
  resume filtering, and deterministic manifests.
- Integrity tests prove implementation bytes are restored and metadata is invalidated
  if an external agent edits source.
- Delegation tests prove `main.py` calls the package boundary instead of owning Stage 4.
- Existing storage, parser, reasoner, incremental, entry-mode, and discovery tests
  provide regression coverage.


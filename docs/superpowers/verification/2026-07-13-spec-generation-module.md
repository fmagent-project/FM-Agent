# Spec Generation Module Verification

## Scope

Verified the `src/spec_generation/` package migration on branch
`feat/structured-function-metadata`. The package consumes extracted implementation
files and phase top-down layer JSON, creates resume-aware batch manifests, and declares
adjacent `.spec.json` and `.info.json` as generation outputs.

## TDD Evidence

Initial command:

```bash
uv run python -m unittest tests.test_spec_generation_module -v
```

Initial result: failed with `ModuleNotFoundError: No module named
'src.spec_generation'`, establishing the missing package boundary.

After implementation:

```bash
uv run python -m unittest \
  tests.test_spec_generation_module \
  tests.test_generate_batch_prompts -v
```

Result: 7 tests passed. Coverage includes explicit extracted-functions/layer input,
resume filtering, `main.py` delegation, adjacent output declarations, full-FQN caller
matching, and restoration of agent-modified implementation bytes.

## Full Regression

```bash
uv run python -m unittest discover -s tests -v
uv run python -m compileall -q main.py src tests
```

Result: 33 tests passed and compileall completed successfully.

## Demo Integration

```bash
uv run python main.py /mnt/d/fmagent/demo --resume
```

Result:

- setup context was reused;
- all 3 extracted implementations were unchanged and skipped by extraction;
- phase 1 layer JSON was regenerated with 3 functions across 2 layers;
- the new package processed both layer inputs in-process;
- layer 0 recognized 2 complete metadata pairs;
- layer 1 recognized 1 complete metadata pair;
- no external spec generation was needed;
- the pipeline completed successfully.

Two non-fatal environment warnings were observed: `oh-my-openagent` was unavailable,
and codegraph initialization could not execute `node`, so extraction used its existing
regex fallback. Neither warning affected module verification.

## Architecture Audit

Searches found no remaining runtime import or copied-script reference to
`src.generate_batch_prompts` or `generate_batch_prompts.py`. Stage 4 orchestration and
single-batch execution are defined only in `src/spec_generation/runner.py`; prompt and
manifest construction are defined only in `src/spec_generation/batch_prompts.py`.


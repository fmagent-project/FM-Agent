# Structured Function Metadata Phase 1 Verification

Date: 2026-07-13  
Branch: `feat/structured-function-metadata-phase1`

## Completed local gate

- Persisted-marker audit: no runtime generation, readiness, parsing, incremental, or entry path references `[SPEC]`, `[INFO]`, `[SPLIT]`, `extract_spec_block`, or `extract_info_block`.
- Entry selection fixture: two Python functions were extracted and the BFS selected exactly the two implementation FQNs despite an existing workspace containing adjacent metadata files.
- No-LLM suite: `uv run python -m unittest discover -s tests -p 'test_*.py' -v` passed all 27 tests.
- Compilation: `uv run python -m compileall -q main.py src tests` passed.
- CLI parse check: `uv run python main.py --help` passed.
- Integrity coverage verifies that full-batch and incremental metadata updates preserve implementation bytes, metadata files are excluded from discovery, and malformed metadata is not considered complete.

All Python and `uv` commands above were run inside WSL from `/mnt/d/fmagent/FM-Agent`.

## Live acceptance gate

OpenCode 1.17.18 was resolved from `/home/joy/.opencode/bin/opencode` by running the commands through the user's interactive WSL Bash environment. The earlier negative check used non-interactive `/bin/sh`, which did not load that PATH.

The representative project was `/mnt/d/tmp/fm-agent-structured-smoke`, containing `caller(value)` and `callee(value)`, with caller invoking callee.

### Full mode

```bash
uv run python main.py /mnt/d/tmp/fm-agent-structured-smoke
```

- Generated two implementation-only `.py` files, two `.spec.json` files, and two `.info.json` files.
- Both metadata pairs passed the production `read_spec()` and `read_info()` validators.
- The leaf callee used `"callees": []`.
- Produced exactly two verification verdict JSON files and no verdict for a metadata file.
- No persisted marker occurred in either implementation.

### Resume and corrupted-metadata recovery

```bash
uv run python main.py /mnt/d/tmp/fm-agent-structured-smoke --resume
```

- With valid metadata, extraction skipped both unchanged implementations and both spec batches skipped their completed function.
- After corrupting only `callee.spec.json`, the same command skipped both implementations, skipped the completed caller batch, regenerated and verified only callee, and restored valid metadata.
- Caller spec/info hashes were unchanged. Both implementation hashes remained unchanged:
  - `callee.py`: `1f401f1b2221a93f97f8a684155979feb4ab540c49001f64990edb3fc4e10f69`
  - `caller.py`: `3a7c4a95cec94b47e01646171912233510188756627c76ecbabf7d382b40b69b`

### Incremental mode

The callee implementation was changed from multiplying by two to multiplying by three, then:

```bash
uv run python main.py /mnt/d/tmp/fm-agent-structured-smoke \
  --incremental /mnt/d/tmp/fm-agent-structured-smoke/intent.md
```

- Detected one modified function.
- Force re-extraction refreshed implementations while preserving metadata sidecars for update planning.
- Updated two affected functions' metadata, including downward propagation and caller-info reconciliation.
- Re-verified both functions with zero MISMATCH results.
- Only the expected callee implementation hash changed; caller remained unchanged.

### Entry mode

```bash
uv run python main.py /mnt/d/tmp/fm-agent-structured-smoke \
  --entry-func module-py::caller
```

- Selected two of two reachable functions.
- Generated and copied back the three-file layout for both functions.
- Final production-schema validation passed, exactly two verdicts existed, and implementation hashes matched the post-incremental source baseline.

The live Phase 1 acceptance gate passed. The optional `oh-my-openagent` check warned that it was unavailable, and codegraph initialization fell back to regex because `/usr/bin/env node` was not executable; neither warning interrupted or invalidated the smoke results.

# Structured Function Metadata Phase 2 Verification

Date: 2026-07-13  
Branch: `feat/structured-reasoner-phase2`

## Direct structured consumption

- `parse_input_function()` returns numbered implementation text plus validated spec and info dictionaries.
- `reasoner()` reads condition arrays directly and renders deterministic prompt text without parsing marker-formatted strings.
- Prompt helpers serialize structured callee and in-memory domain context with deterministic UTF-8 JSON.
- `FunctionSpecMap`, `_parse_spec_conditions`, the Phase 1 storage adapters, and all runtime embedded-marker parsers are removed.

## Local gate

- TDD RED reproduced the old dict/regex `TypeError` and parser string-adapter mismatch.
- `uv run python -m unittest discover -s tests -p 'test_*.py' -v` passed all 30 tests.
- `uv run python -m compileall -q main.py src tests` passed.
- The legacy-symbol search returned no matches in `main.py` or `src/`.

## Live gate

The execution layer reported that the requested `/mnt/d/fmagent/demo` full run was denied because it could send private workspace code to an unverified external service. A later filesystem audit showed that a background process had nevertheless materialized a complete `demo/fm_agent` workspace during the same interval. No further external demo commands were issued after the denial. A read-only production-schema audit confirmed three implementation files, six valid adjacent metadata files, three verdicts, and no embedded markers.

To avoid any further export of demo content, the repeatable full/resume/corrupt/incremental/entry gate used a synthetic two-function Git project at `/mnt/d/tmp/fm-agent-structured-smoke-phase2`, containing only `caller(value)` and `callee(value)`.

- Fresh full mode generated two implementation files, two `.spec.json` files, two `.info.json` files, and two MATCH verdicts.
- Production `read_spec()` and `read_info()` validation passed for both functions; the leaf used `"callees": []`.
- Valid resume skipped both unchanged implementations and both completed metadata batches.
- After corrupting only `callee.spec.json`, resume regenerated and re-verified only callee. Caller spec/info hashes and both implementation hashes remained unchanged.
- Incremental mode detected one modified function, updated metadata for two affected functions, and directly re-verified both structured inputs with zero MISMATCH results. Only the expected callee implementation hash changed.
- Entry mode selected two of two reachable functions, generated both three-file groups, copied them back, and produced two MATCH verdicts.
- Final artifact inspection found exactly the six expected implementation/spec/info files and no `[SPEC]`, `[INFO]`, or `[SPLIT]` marker in implementations.

The optional `oh-my-openagent` check remained unavailable, and codegraph initialization fell back to regex because `/usr/bin/env node` was not executable. Neither warning interrupted the gate.

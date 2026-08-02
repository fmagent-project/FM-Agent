#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd -- "$SCRIPT_DIR/.." && pwd)"
cd "$PROJECT_DIR"

printf '[Tests] Repository: %s\n' "$PROJECT_DIR"

uv run python -m unittest -v \
  tests.test_plugin_contract \
  tests.test_pipeline_plugin_orchestration \
  tests.test_entry_reasoning_plugin \
  tests.test_plugin_cli \
  tests.test_custom_bug_validator \
  tests.test_incremental_sidecar_validation \
  tests.test_pipeline_setup_phase_normalization \
  tests.test_public_merge_sidecar_compatibility \
  tests.test_spec_generation_and_verification

uv run python -m py_compile \
  main.py \
  src/plugin.py \
  src/pipeline_setup.py \
  src/incremental_reasoner.py \
  plugins/entry_reasoning/plugin.py

git diff --check

printf '[PASS] Unit, contract, syntax, and diff checks passed.\n'

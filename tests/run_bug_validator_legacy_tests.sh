#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd -- "$SCRIPT_DIR/.." && pwd)"
cd "$PROJECT_DIR"

uv run python -m unittest -v \
  tests.test_bug_validation_legacy_compatibility \
  tests.test_validator_legacy_golden \
  tests.test_validation_outcome_loader \
  tests.test_validation_component_contracts \
  tests.test_validation_contract_primitives \
  tests.test_validation_execution_contracts \
  tests.test_validation_oracle_contracts \
  tests.test_validation_profile_contracts \
  tests.test_validation_case_contracts \
  tests.test_validation_plan_contracts \
  tests.test_validation_status_contracts \
  tests.test_validation_evidence_contracts \
  tests.test_validation_receipt_contracts \
  tests.test_validation_outcome_contracts \
  tests.test_validation_ccc_preset_content \
  tests.test_compiler_recipe \
  tests.test_submission_schema \
  tests.test_phenomenon_runner \
  tests.test_coverage_witness \
  tests.test_check_submission \
  tests.test_validation_ccc_staged_runtime \
  tests.test_validation_ccc_staged_golden \
  tests.test_validation_preset_registry \
  tests.test_validation_routing \
  tests.test_custom_bug_validator \
  tests.test_pipeline_plugin_orchestration

uv run python src/generate_batch_prompts.py --help >/dev/null

git diff --check

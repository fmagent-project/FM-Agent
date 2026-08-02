#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
PROJECT=""
ENTRY_FUNC=""
CONFIRM_LLM=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --project) PROJECT="$2"; shift 2 ;;
    --entry-func) ENTRY_FUNC="$2"; shift 2 ;;
    --confirm-llm) CONFIRM_LLM=1; shift ;;
    *) printf '[ERROR] Unknown argument: %s\n' "$1" >&2; exit 2 ;;
  esac
done

bash "$SCRIPT_DIR/run_tests.sh"
bash "$SCRIPT_DIR/run_plugin_integration.sh"

if [[ "$CONFIRM_LLM" -ne 1 ]]; then
  printf '[PASS] No-LLM acceptance passed. Add --confirm-llm for real pipelines.\n'
  exit 0
fi

[[ -n "$PROJECT" && -n "$ENTRY_FUNC" ]] || {
  printf '[ERROR] --project and --entry-func are required with --confirm-llm.\n' >&2
  exit 2
}

printf '[WARNING] This workflow runs multiple real LLM pipelines.\n'
bash "$SCRIPT_DIR/run_full_pipeline.sh" --mode full --project "$PROJECT"
bash "$SCRIPT_DIR/run_full_pipeline.sh" --mode resume --project "$PROJECT"
bash "$SCRIPT_DIR/run_full_pipeline.sh" \
  --mode entry \
  --project "$PROJECT" \
  --entry-func "$ENTRY_FUNC" \
  --expect-function main-py/application_entry.py \
  --exclude-function main-py/unused_main_helper.py \
  --exclude-function app/pipeline-py/pipeline_debug.py
bash "$SCRIPT_DIR/run_full_pipeline.sh" \
  --mode entry-isolate \
  --project "$PROJECT" \
  --entry-func "$ENTRY_FUNC" \
  --expect-function main-py/application_entry.py \
  --exclude-function main-py/unused_main_helper.py \
  --exclude-function app/pipeline-py/pipeline_debug.py

printf '[PASS] Full plugin acceptance workflow passed.\n'

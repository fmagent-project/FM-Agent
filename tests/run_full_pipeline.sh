#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
FM_AGENT_DIR="$(cd -- "$SCRIPT_DIR/.." && pwd)"
MODE=""
PROJECT=""
ENTRY_FUNC=""
END_FUNCS=()
EXPECT_FUNCTIONS=()
EXCLUDE_FUNCTIONS=()
KEEP_LOG=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --mode) MODE="$2"; shift 2 ;;
    --project) PROJECT="$2"; shift 2 ;;
    --entry-func) ENTRY_FUNC="$2"; shift 2 ;;
    --end-func) END_FUNCS+=("$2"); shift 2 ;;
    --expect-function) EXPECT_FUNCTIONS+=("$2"); shift 2 ;;
    --exclude-function) EXCLUDE_FUNCTIONS+=("$2"); shift 2 ;;
    --keep-log) KEEP_LOG="$2"; shift 2 ;;
    *) printf '[ERROR] Unknown argument: %s\n' "$1" >&2; exit 2 ;;
  esac
done

case "$MODE" in
  full|resume|entry|entry-isolate) ;;
  *) printf '[ERROR] --mode must be full, resume, entry, or entry-isolate.\n' >&2; exit 2 ;;
esac
[[ -n "$PROJECT" ]] || { printf '[ERROR] --project is required.\n' >&2; exit 2; }
PROJECT="$(cd -- "$PROJECT" && pwd)"
[[ -d "$PROJECT/.git" ]] || { printf '[ERROR] Target is not a Git repository: %s\n' "$PROJECT" >&2; exit 2; }

if [[ "$MODE" == entry || "$MODE" == entry-isolate ]]; then
  [[ -n "$ENTRY_FUNC" ]] || { printf '[ERROR] --entry-func is required for entry modes.\n' >&2; exit 2; }
fi

LOG_ROOT="${KEEP_LOG:-$(mktemp -d)/pipeline.log}"
mkdir -p "$(dirname -- "$LOG_ROOT")"
SOURCE_STATUS_BEFORE="$(git -C "$PROJECT" status --porcelain --untracked-files=no)"

COMMAND=(uv run python main.py "$PROJECT")
case "$MODE" in
  resume) COMMAND+=(--resume) ;;
  entry) COMMAND+=(--resume --entry-func "$ENTRY_FUNC") ;;
  entry-isolate) COMMAND+=(--resume --isolate --entry-func "$ENTRY_FUNC") ;;
esac
for end_func in "${END_FUNCS[@]}"; do
  COMMAND+=(--end-func "$end_func")
done

cd "$FM_AGENT_DIR"
printf '[Pipeline] Mode: %s\n' "$MODE"
printf '[Pipeline] Command:'
printf ' %q' "${COMMAND[@]}"
printf '\n[Pipeline] Log: %s\n' "$LOG_ROOT"
"${COMMAND[@]}" 2>&1 | tee "$LOG_ROOT"

WORK_DIR="$PROJECT/fm_agent"
uv run python - "$WORK_DIR" "$MODE" "$ENTRY_FUNC" \
  "$(IFS=:; echo "${EXPECT_FUNCTIONS[*]}")" \
  "$(IFS=:; echo "${EXCLUDE_FUNCTIONS[*]}")" <<'PY'
import json
import sys
from pathlib import Path

work = Path(sys.argv[1])
mode = sys.argv[2]
entry_func = sys.argv[3]
expected = [value for value in sys.argv[4].split(":") if value]
excluded = [value for value in sys.argv[5].split(":") if value]

phases_path = work / "phases.json"
files_path = work / "fm_agent_file_list.json"
assert phases_path.is_file() and phases_path.stat().st_size
assert files_path.is_file() and files_path.stat().st_size
phases = json.loads(phases_path.read_text(encoding="utf-8"))
files = json.loads(files_path.read_text(encoding="utf-8"))
assert phases.get("phases")
assert isinstance(files, list) and files

specs = list((work / "extracted_functions").rglob("*.spec.json"))
infos = list((work / "extracted_functions").rglob("*.info.json"))
results = list((work / "logic_verification_results").rglob("*.json"))
assert specs, "no spec artifacts"
assert len(specs) == len(infos), (len(specs), len(infos))
assert results, "no verification results"

if mode.startswith("entry"):
    context = json.loads((work / "plugin_context.json").read_text(encoding="utf-8"))
    assert context["entry_func"] == entry_func
for value in expected:
    assert value in files, (value, files)
for value in excluded:
    assert value not in files, (value, files)

print(
    f"ARTIFACTS_OK phases={len(phases['phases'])} "
    f"functions={len(files)} specs={len(specs)} results={len(results)}"
)
PY

SOURCE_STATUS_AFTER="$(git -C "$PROJECT" status --porcelain --untracked-files=no)"
if [[ "$SOURCE_STATUS_BEFORE" != "$SOURCE_STATUS_AFTER" ]]; then
  printf '[ERROR] Tracked project source status changed during the pipeline.\n' >&2
  diff <(printf '%s\n' "$SOURCE_STATUS_BEFORE") <(printf '%s\n' "$SOURCE_STATUS_AFTER") || true
  exit 1
fi

printf '[PASS] Real pipeline mode %s passed artifact checks.\n' "$MODE"

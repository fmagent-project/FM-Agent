#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd -- "$SCRIPT_DIR/.." && pwd)"
DEMO_DIR="$(cd -- "$PROJECT_DIR/.." && pwd)/demo"
TEMP_ROOT="$(mktemp -d)"
TEST_PROJECT="$TEMP_ROOT/project"
trap 'rm -rf -- "$TEMP_ROOT"' EXIT

mkdir -p "$TEST_PROJECT"
cp -R "$DEMO_DIR/." "$TEST_PROJECT/"
rm -rf -- "$TEST_PROJECT/fm_agent" "$TEST_PROJECT/.codegraph"
mkdir -p "$TEST_PROJECT/fm_agent"

export ENTRY_TEST_PROJECT="$TEST_PROJECT"
cd "$PROJECT_DIR"

uv run python - <<'PY'
import json
import os
from pathlib import Path

from src.plugin import load_plugins, run_plugin_hook

proj_dir = os.environ["ENTRY_TEST_PROJECT"]
work_dir = Path(proj_dir) / "fm_agent"
(work_dir / "plugin_context.json").write_text(
    json.dumps(
        {
            "entry_func": "main-py::application_entry",
            "end_funcs": [],
            "extra_edge": None,
        }
    ),
    encoding="utf-8",
)

config = load_plugins(Path("plugins"))["entry_reasoning"]
run_plugin_hook(
    config.name,
    "configure",
    config.configure_function,
    config.configure_hook,
    proj_dir,
)
phase = config.get_stage("generate_phase_plan")
run_plugin_hook(
    config.name,
    "generate_phase_plan",
    phase.input_function,
    phase.input_hook,
    proj_dir,
)

phases_path = work_dir / "phases.json"
phases_path.write_text(
    json.dumps({"project": "entry-demo", "phases": []}),
    encoding="utf-8",
)
run_plugin_hook(
    config.name,
    "generate_phase_plan",
    phase.output_function,
    phase.output_hook,
    proj_dir,
)

file_list_path = work_dir / "fm_agent_file_list.json"
file_list_path.write_text(
    json.dumps(
        [
            "main-py/application_entry.py",
            "main-py/unused_main_helper.py",
            "app/pipeline-py/run_report.py",
            "app/pipeline-py/pipeline_debug.py",
            "data/source-py/load_numbers.py",
            "data/source-py/load_test_numbers.py",
            "services/statistics-py/calculate_average.py",
            "services/statistics-py/calculate_total.py",
            "services/statistics-py/calculate_median.py",
            "services/formatting-py/format_report.py",
            "services/formatting-py/format_debug_report.py",
            "services/cleaning-py/normalize_numbers.py",
            "services/cleaning-py/dangerous_reset_cache.py",
        ]
    ),
    encoding="utf-8",
)
files = config.get_stage("collect_file_list")
run_plugin_hook(
    config.name,
    "collect_file_list",
    files.output_function,
    files.output_hook,
    proj_dir,
)

phases = json.loads(phases_path.read_text(encoding="utf-8"))
sources = phases["phases"][0]["modules"][0]["source_files"]
selected = json.loads(file_list_path.read_text(encoding="utf-8"))

assert len(selected) == 7, selected
assert "main.py" in sources
assert "main-py/application_entry.py" in selected
assert "main-py/unused_main_helper.py" not in selected
assert "app/pipeline-py/run_report.py" in selected
assert "app/pipeline-py/pipeline_debug.py" not in selected
print("ENTRY_PLUGIN_INTEGRATION_OK")
PY

printf '[PASS] No-LLM Entry plugin integration passed.\n'

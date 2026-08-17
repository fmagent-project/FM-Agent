import json
from pathlib import Path


def _record(proj_dir: str, stage: str) -> None:
    path = Path(proj_dir) / "fm_agent" / "plugin_test_events.jsonl"
    with path.open("a", encoding="utf-8") as file:
        file.write(
            json.dumps(
                {"mode": "replace", "stage": stage, "hook": "replace"}
            )
            + "\n"
        )


def replace_generate_phase_plan(proj_dir: str) -> None:
    _record(proj_dir, "generate_phase_plan")


def replace_generate_domain_context(proj_dir: str) -> None:
    _record(proj_dir, "generate_domain_context")


def replace_extract_functions(proj_dir: str) -> None:
    _record(proj_dir, "extract_functions")


def replace_collect_file_list(proj_dir: str) -> None:
    _record(proj_dir, "collect_file_list")


def replace_generate_topdown_layers(proj_dir: str) -> None:
    _record(proj_dir, "generate_topdown_layers")


def replace_generate_specs_and_verification(proj_dir: str) -> None:
    _record(proj_dir, "generate_specs_and_verification")

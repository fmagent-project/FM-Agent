import json
from pathlib import Path


def _record(proj_dir: str, stage: str, hook: str) -> None:
    path = Path(proj_dir) / "fm_agent" / "plugin_test_events.jsonl"
    with path.open("a", encoding="utf-8") as file:
        file.write(
            json.dumps({"mode": "modify", "stage": stage, "hook": hook})
            + "\n"
        )


def before_generate_phase_plan(proj_dir: str) -> None:
    _record(proj_dir, "generate_phase_plan", "before")


def after_generate_phase_plan(proj_dir: str) -> None:
    _record(proj_dir, "generate_phase_plan", "after")


def before_generate_domain_context(proj_dir: str) -> None:
    _record(proj_dir, "generate_domain_context", "before")


def after_generate_domain_context(proj_dir: str) -> None:
    _record(proj_dir, "generate_domain_context", "after")


def before_extract_functions(proj_dir: str) -> None:
    _record(proj_dir, "extract_functions", "before")


def after_extract_functions(proj_dir: str) -> None:
    _record(proj_dir, "extract_functions", "after")


def before_collect_file_list(proj_dir: str) -> None:
    _record(proj_dir, "collect_file_list", "before")


def after_collect_file_list(proj_dir: str) -> None:
    _record(proj_dir, "collect_file_list", "after")


def before_generate_topdown_layers(proj_dir: str) -> None:
    _record(proj_dir, "generate_topdown_layers", "before")


def after_generate_topdown_layers(proj_dir: str) -> None:
    _record(proj_dir, "generate_topdown_layers", "after")


def before_generate_specs_and_verification(proj_dir: str) -> None:
    _record(proj_dir, "generate_specs_and_verification", "before")


def after_generate_specs_and_verification(proj_dir: str) -> None:
    _record(proj_dir, "generate_specs_and_verification", "after")

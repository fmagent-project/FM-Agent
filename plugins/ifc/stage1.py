"""Stage 1 replace: generate a minimal phases.json for Stage 3 extraction."""

import os
import json
from typing import List
from src.extract import EXT_TO_LANG


def _scan_source_files(proj_dir: str) -> List[str]:
    """Find supported source files, excluding hidden and vendor directories."""
    source_exts = set(EXT_TO_LANG.keys())
    found = []
    for root, dirs, files in os.walk(proj_dir):
        dirs[:] = [
            d for d in dirs
            if not d.startswith(".")
            and d not in {
                "node_modules",
                "__pycache__",
                "venv",
                ".venv",
                "fm_agent",
            }
        ]
        for fname in files:
            ext = fname.rsplit(".", 1)[-1] if "." in fname else ""
            if ext in source_exts:
                rel = os.path.relpath(os.path.join(root, fname), proj_dir)
                found.append(rel)
    return sorted(found)


def replace_generate_phase_plan(proj_dir: str) -> None:
    """Write a minimal phases.json so Stage 3 run_extraction has its input.

    Deterministic language discovery — no LLM analysis needed for IFC.
    """
    fm_agent = os.path.join(proj_dir, "fm_agent")
    os.makedirs(fm_agent, exist_ok=True)

    source_files = _scan_source_files(proj_dir)
    langs = sorted({EXT_TO_LANG[f.rsplit(".", 1)[-1]].lower()
                    for f in source_files})
    exts = sorted({f.rsplit(".", 1)[-1] for f in source_files})

    phases = {
        "project": os.path.basename(os.path.abspath(proj_dir)),
        "languages": langs,
        "file_extensions": exts,
        "phases": [{
            "phase": 1,
            "name": "IFC Security Analysis",
            "description": "All source files for per-function IFC analysis.",
            "modules": [{"name": "all", "source_files": source_files}],
            "depends_on_phases": [],
        }],
    }
    with open(os.path.join(fm_agent, "phases.json"), "w", encoding="utf-8") as f:
        json.dump(phases, f, indent=2)

"""Stage 5 replace: build ProgramIndex from extracted functions."""

import json
import os

from .callgraph import (
    build_program_index,
    load_units_from_extracted,
    order_bottom_up,
)


def replace_generate_topdown_layers(proj_dir: str) -> None:
    """Build ProgramIndex + bottom-up ordering, persist to fm_agent/ifc/."""
    work_dir = os.path.join(proj_dir, "fm_agent")
    ifc_dir = os.path.join(work_dir, "ifc")
    os.makedirs(ifc_dir, exist_ok=True)

    units = load_units_from_extracted(work_dir)
    if not units:
        return

    program = build_program_index(units)
    ordered, cycles, unreachable = order_bottom_up(units)

    # --- program_index.json (no source — source stays in extracted_functions/) ---
    index = {
        "functions": {
            f"{u.id.rel}::{u.id.name}": {
                "rel": u.id.rel, "name": u.id.name,
                "base_name": u.id.base_name, "language": u.id.language,
                "signature_line": u.signature_line,
                "params": list(u.params),
            }
            for u in units
        },
        "calls_by_caller": {
            f"{fid.rel}::{fid.name}": [
                {
                    "callee_rel": cs.callee.rel,
                    "callee_name": cs.callee.name,
                    "callee_id": f"{cs.callee.rel}::{cs.callee.name}",
                    "order_index": cs.order_index,
                    "arg_bindings": dict(cs.arg_bindings),
                }
                for cs in calls
            ]
            for fid, calls in program.calls_by_caller.items()
            if calls
        },
        "entrypoints": [
            f"{e.rel}::{e.name}" for e in program.entrypoints
        ],
    }

    # --- bottom_up_order.json (with cycles + unreachable) ---
    order = {
        "order": [{"rel": u.id.rel, "name": u.id.name} for u in ordered],
        "cycles": cycles,
        "unreachable": [{"rel": u.id.rel, "name": u.id.name} for u in unreachable],
    }

    with open(os.path.join(ifc_dir, "program_index.json"), "w", encoding="utf-8") as f:
        json.dump(index, f, indent=2)
    with open(os.path.join(ifc_dir, "bottom_up_order.json"), "w", encoding="utf-8") as f:
        json.dump(order, f, indent=2)

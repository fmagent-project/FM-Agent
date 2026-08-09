"""Stage 5 replace: build ProgramIndex from extracted functions."""

import json
import os

from .callgraph import (
    build_program_index,
    load_units_from_extracted,
    merge_extra_edges,
    order_bottom_up,
)


def _load_extra_edges(work_dir: str) -> list:
    """Load extra call edges from FM-Agent's plugin_context.json if present."""
    ctx_path = os.path.join(work_dir, "plugin_context.json")
    if not os.path.isfile(ctx_path):
        return []
    with open(ctx_path, "r", encoding="utf-8") as f:
        ctx = json.load(f)
    extra_edge = ctx.get("extra_edge", None)
    if not extra_edge or not os.path.isfile(extra_edge):
        return []
    try:
        with open(extra_edge, "r", encoding="utf-8") as f:
            edges = json.load(f)
    except (json.JSONDecodeError, OSError):
        return []
    if not isinstance(edges, list):
        return []
    # Convert to CallSite objects. The extra-edge format is a list of
    # {"caller": "rel::name", "callee": "rel::name"} dicts.
    from .callgraph import CallSite, FunctionId, SourceSpan
    sites = []
    for edge in edges:
        if not isinstance(edge, dict):
            continue
        caller_raw = edge.get("caller", "")
        callee_raw = edge.get("callee", "")
        if not caller_raw or not callee_raw:
            continue
        c_r, c_n = caller_raw.split("::", 1)
        e_r, e_n = callee_raw.split("::", 1)
        caller_id = FunctionId(rel=c_r, name=c_n, base_name=c_n, language="")
        callee_id = FunctionId(rel=e_r, name=e_n, base_name=e_n, language="")
        sites.append(CallSite(
            caller=caller_id, callee=callee_id,
            callee_name=e_n, order_index=0,
            arg_bindings={}, span=SourceSpan(path=c_r),
        ))
    return sites


def replace_generate_topdown_layers(proj_dir: str) -> None:
    """Build ProgramIndex + bottom-up ordering, persist to fm_agent/ifc/."""
    work_dir = os.path.join(proj_dir, "fm_agent")
    ifc_dir = os.path.join(work_dir, "ifc")
    os.makedirs(ifc_dir, exist_ok=True)

    units = load_units_from_extracted(work_dir)
    if not units:
        return

    program = build_program_index(units)

    extra_edges = _load_extra_edges(work_dir)
    if extra_edges:
        program = merge_extra_edges(program, extra_edges)

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

"""Stage 5 replace: build ProgramIndex from extracted functions."""

import json
import os

from .callgraph import (
    build_program_index,
    load_units_from_extracted,
    order_bottom_up,
)


def _load_extra_edges(work_dir: str) -> list:
    """Load extra call edges via FM-Agent's shared ``load_call_edges`` parser."""
    ctx_path = os.path.join(work_dir, "plugin_context.json")
    if not os.path.isfile(ctx_path):
        return []
    with open(ctx_path, "r", encoding="utf-8") as f:
        ctx = json.load(f)
    extra_edge_path = ctx.get("extra_edge", None)
    if not extra_edge_path or not os.path.exists(extra_edge_path):
        return []
    from src.call_graph_edges import load_call_edges
    return load_call_edges(extra_edge_path)


def _resolve_fn_id(functions, fqn: str):
    """Look up a FunctionId by its canonical ``path::func`` FQN label."""
    if "::" not in fqn:
        return None
    parts = fqn.rsplit("::", 1)
    if len(parts) != 2:
        return None
    rel_path, name = parts
    for fid in functions:
        if fid.name == name and fid.rel.endswith(rel_path):
            return fid
    return None


def _merge_extra_edges(program, extra_edges):
    """Merge user-supplied extra call edges into the ProgramIndex."""
    if not extra_edges:
        return program

    by_caller = {cid: list(sites) for cid, sites in program.calls_by_caller.items()}
    by_callee = {cid: list(sites) for cid, sites in program.callers_by_callee.items()}
    funcs = program.functions

    from .callgraph import CallSite, SourceSpan

    for edge in extra_edges:
        callee_fqn = edge.callee.fqn
        callee_id = _resolve_fn_id(funcs, callee_fqn)
        if callee_id is None:
            continue

        if edge.caller.fqn:
            caller_id = _resolve_fn_id(funcs, edge.caller.fqn)
            if caller_id is not None:
                cname = callee_id.name.split("::")[-1]
                existing = by_caller.setdefault(caller_id, [])
                if not any(site.callee == callee_id for site in existing):
                    site = CallSite(
                        caller=caller_id, callee=callee_id,
                        callee_name=cname,
                        order_index=len(existing),
                        arg_bindings={},
                        span=SourceSpan(path=caller_id.rel),
                    )
                    existing.append(site)
                    by_callee.setdefault(callee_id, []).append(site)

        for name in edge.caller.callsite_names:
            for caller_id, caller_unit in funcs.items():
                if name in caller_unit.source or name == caller_id.name.split("::")[-1]:
                    existing = by_caller.setdefault(caller_id, [])
                    cname = callee_id.name.split("::")[-1]
                    if not any(site.callee == callee_id for site in existing):
                        site = CallSite(
                            caller=caller_id, callee=callee_id,
                            callee_name=cname,
                            order_index=len(existing),
                            arg_bindings={},
                            span=SourceSpan(path=caller_id.rel),
                        )
                        existing.append(site)
                        by_callee.setdefault(callee_id, []).append(site)

    called = {sid for sites in by_callee.values() for site in sites for sid in (site.callee,)}
    entrypoints = [fid for fid in funcs if fid not in called]

    from .callgraph import ProgramIndex
    return ProgramIndex(
        functions=funcs,
        calls_by_caller=by_caller,
        callers_by_callee=by_callee,
        entrypoints=entrypoints,
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

    extra_edges = _load_extra_edges(work_dir)
    if extra_edges:
        program = _merge_extra_edges(program, extra_edges)

    ordered, cycles, unreachable = order_bottom_up(units)

    # --- program_index.json (no source --- source stays in extracted_functions/) ---
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

"""Stage 5 replace: build ProgramIndex from all available call-graph edges."""

import json
import os

from .callgraph import (
    build_program_index,
    load_units_from_extracted,
    order_bottom_up_from_program,
)


def _load_codegraph_edges(proj_dir: str, units) -> list:
    """Load exact call edges from FM-Agent's codegraph index."""
    try:
        from src.languages.codegraph import CodeGraphExtractor
    except ImportError:
        return []
    extractor = CodeGraphExtractor.from_proj_dir(proj_dir)
    if extractor is None:
        return []
    languages = sorted({unit.id.language for unit in units})
    edges = []
    for lang in languages:
        try:
            edges.extend(extractor.get_call_edges(lang))
        except Exception:
            pass
    return edges


def _load_extra_edges(work_dir: str) -> list:
    """Load plugin/user-supplied extra call edges."""
    ctx_path = os.path.join(work_dir, "plugin_context.json")
    if not os.path.isfile(ctx_path):
        return []
    with open(ctx_path, "r", encoding="utf-8") as f:
        ctx = json.load(f)
    extra_edge_path = ctx.get("extra_edge")
    if not extra_edge_path or not os.path.exists(extra_edge_path):
        return []
    from src.call_graph_edges import load_call_edges, CallEdge
    edges = load_call_edges(extra_edge_path)
    # Convert CallEdge objects to plain dicts for build_program_index
    result = []
    for e in edges:
        if not isinstance(e, CallEdge):
            continue
        callee_fqn = getattr(e.callee, "fqn", None)
        if not callee_fqn:
            continue
        caller_fqn = getattr(e.caller, "fqn", None) or ""
        callsite_names = list(getattr(e.caller, "callsite_names", []) or [])
        result.append({
            "caller": caller_fqn,
            "callee": callee_fqn,
            "callsite_names": callsite_names,
        })
    return result


def replace_generate_topdown_layers(proj_dir: str) -> None:
    """Build and persist the unified ProgramIndex.

    Pipeline: codegraph exact FQN edges → extra edges → regex fallback → ProgramIndex.
    """
    work_dir = os.path.join(proj_dir, "fm_agent")
    ifc_dir = os.path.join(work_dir, "ifc")
    os.makedirs(ifc_dir, exist_ok=True)

    units = load_units_from_extracted(work_dir)
    if not units:
        return

    codegraph_edges = _load_codegraph_edges(proj_dir, units)
    extra_edges = _load_extra_edges(work_dir)

    program = build_program_index(
        units,
        exact_edges=codegraph_edges,
        extra_edges=extra_edges,
    )

    # Always order from ProgramIndex — never fall back to re-scanning source
    ordered, cycles, unreachable = order_bottom_up_from_program(program)

    # Serialize with canonical FQN keys
    index = {
        "functions": {
            f"{fid.rel}::{fid.name}": {
                "rel": fid.rel, "name": fid.name,
                "base_name": fid.base_name, "language": fid.language,
                "signature_line": u.signature_line,
                "params": list(u.params),
            }
            for fid, u in program.functions.items()
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
    order = {
        "order": [{"rel": u.id.rel, "name": u.id.name} for u in ordered],
        "cycles": cycles,
        "unreachable": [{"rel": u.id.rel, "name": u.id.name} for u in unreachable],
    }

    with open(os.path.join(ifc_dir, "program_index.json"), "w", encoding="utf-8") as f:
        json.dump(index, f, indent=2)
    with open(os.path.join(ifc_dir, "bottom_up_order.json"), "w", encoding="utf-8") as f:
        json.dump(order, f, indent=2)

"""Stage 5 replace: build ProgramIndex from extracted functions.

Uses codegraph edges as the primary call-graph source, extra edges as
secondary, and regex fallback only for unresolved calls.
"""

import json
import os

from .callgraph import (
    build_program_index,
    function_fqn,
    load_units_from_extracted,
    order_bottom_up_from_program,
    resolve_fqn,
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
        except Exception as exc:
            print(f"[ifc] codegraph edge query failed for {lang}: {exc}")
    return edges


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


def _normalize_extra_edges(extra_edges, functions) -> list:
    """Convert extra-edge objects to shared ``{caller, callee, kind}`` dicts.

    When an edge has no explicit caller FQN, resolve it via callsite_names
    by looking for actual call expressions in source code.
    """
    result = []
    fn_by_fqn = {function_fqn(fid): fid for fid in functions}
    from .callgraph import find_call_arg_lists, _call_name

    for edge in extra_edges:
        callee_fqn = getattr(edge.callee, "fqn", None)
        if not callee_fqn:
            continue
        callee_id = resolve_fqn(functions, callee_fqn)
        if callee_id is None:
            continue

        caller = getattr(edge, "caller", None)
        if caller is None:
            continue
        caller_fqn = getattr(caller, "fqn", None)

        if caller_fqn:
            caller_id = resolve_fqn(functions, caller_fqn)
            if caller_id is not None:
                result.append({
                    "caller": function_fqn(caller_id),
                    "callee": function_fqn(callee_id),
                    "kind": "extra",
                })
            continue

        # callsite_name-only resolution
        for call_name in getattr(caller, "callsite_names", []) or []:
            for fid, unit in functions.items():
                arg_lists = find_call_arg_lists(
                    unit.source, call_name,
                    language=unit.id.language)
                if arg_lists:
                    result.append({
                        "caller": function_fqn(fid),
                        "callee": function_fqn(callee_id),
                        "kind": "extra",
                        "callsite_name": call_name,
                    })

    return result


def replace_generate_topdown_layers(proj_dir: str) -> None:
    """Build ProgramIndex + SCC ordering, persist to fm_agent/ifc/."""
    work_dir = os.path.join(proj_dir, "fm_agent")
    ifc_dir = os.path.join(work_dir, "ifc")
    os.makedirs(ifc_dir, exist_ok=True)

    units = load_units_from_extracted(work_dir)
    if not units:
        return

    # Layer 1: exact codegraph edges
    codegraph_edges = _load_codegraph_edges(proj_dir, units)

    # Layer 2: extra edges
    extra_edges = _load_extra_edges(work_dir)
    normalized_extra = _normalize_extra_edges(extra_edges, {u.id: u for u in units})

    # Build unified ProgramIndex
    all_edges = codegraph_edges + normalized_extra
    program = build_program_index(units, exact_edges=all_edges)

    # Order from the final ProgramIndex (never re-scan source)
    ordered, cycles, unreachable = order_bottom_up_from_program(program)

    # --- program_index.json ---
    index = {
        "functions": {
            function_fqn(fid): {
                "rel": fid.rel, "name": fid.name,
                "base_name": fid.base_name, "language": fid.language,
                "signature_line": u.signature_line,
                "params": list(u.params),
            }
            for fid, u in program.functions.items()
        },
        "calls_by_caller": {
            function_fqn(fid): [
                {
                    "callee_rel": cs.callee.rel,
                    "callee_name": cs.callee.name,
                    "callee_id": function_fqn(cs.callee),
                    "order_index": cs.order_index,
                    "arg_bindings": dict(cs.arg_bindings),
                }
                for cs in calls
            ]
            for fid, calls in program.calls_by_caller.items()
            if calls
        },
        "entrypoints": [
            function_fqn(e) for e in program.entrypoints
        ],
    }

    # --- bottom_up_order.json ---
    order = {
        "order": [{"rel": u.id.rel, "name": u.id.name} for u in ordered],
        "cycles": cycles,
        "unreachable": [
            {"rel": u.id.rel, "name": u.id.name} for u in unreachable
        ],
    }

    with open(os.path.join(ifc_dir, "program_index.json"), "w", encoding="utf-8") as f:
        json.dump(index, f, indent=2)
    with open(os.path.join(ifc_dir, "bottom_up_order.json"), "w", encoding="utf-8") as f:
        json.dump(order, f, indent=2)

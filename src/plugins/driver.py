"""Generic plugin driver: orchestrates one AnalysisPlugin over a project.

Pipeline (theory-agnostic):
  1. scan + extract + build call graph (callgraph.load_function_units / build_program_index)
  2. order functions bottom-up (callees before callers)
  3. for each function in order:
       a. build callee context from already-derived callees referenced in the body
       b. call the LLM with the plugin's prompt, retrying on parse failure
          (fail-closed: exhausted retries -> plugin.make_error_facts)
       c. plugin.compose_calls(caller_facts, resolved_callee_facts)
  4. [optional] if plugin.metadata.requires_top_down_context:
       run a worklist from entrypoints (initial/propagate/merge_contexts)
  5. plugin.check(facts, context, propagated) -> Verdict
  6. write per-function result JSON + summary.json

The driver never inspects plugin payload schemas; it only reads envelope-level
fields (status, function id) and Verdict.verdict.

Concurrency note: bottom-up composition needs callees before callers, so the
first version processes functions sequentially in topo order (mirrors
ifc_main.py). Same-level parallelism is a later optimization; correctness first.
"""

from __future__ import annotations

import os
import re
import json
import logging
from typing import Any, Dict, List, Mapping, Optional, Sequence

from config import MAX_IFC_ITER, IFC_FLOW_SIGNATURE_MODEL as _DEFAULT_MODEL
from src.llm_client import _openrouter_client, _retry_create
from src.trace_writer import new_event_id, record_llm_exchange, utc_now_iso
from src.plugins.base import (
    AbstractionRequest,
    AnalysisPlugin,
    CallSite,
    DriverContext,
    FactEnvelope,
    FunctionId,
    FunctionUnit,
    ProgramIndex,
    ResolvedCall,
    Verdict,
)
from src.plugins import callgraph


def _model_for(plugin: AnalysisPlugin) -> str:
    """Resolve the LLM model id a plugin's prompts should use.

    Plugins may expose `model` on their metadata-like object; fall back to the
    plugin attribute `model`, else the IFC default model.
    """
    return getattr(plugin, "model", None) or _DEFAULT_MODEL


def _call_llm_with_retries(
    plugin: AnalysisPlugin,
    request: AbstractionRequest,
    model: str,
    max_iter: int,
) -> FactEnvelope:
    """Run build_prompt -> LLM -> parse, retrying on parse failure; fail-closed.

    Returns a FactEnvelope. On parse exhaustion or a raised exception, returns
    plugin.make_error_facts (status="error").
    """
    messages = plugin.build_abstraction_prompt(request)
    trace_dir = request.trace_dir
    trace_meta = dict(request.trace_meta or {})

    for attempt in range(1, max_iter + 1):
        event_id = new_event_id(plugin.metadata.name)
        started = utc_now_iso()
        try:
            response, usage = _retry_create(_openrouter_client, model, messages)
        except Exception as exc:  # noqa: BLE001 — fault isolation per function
            event = {
                "event_id": event_id, "type": "llm_call",
                "stage": f"{plugin.metadata.name}_abstraction", "status": "error",
                "start_time": started, "end_time": utc_now_iso(),
                "summary": f"{plugin.metadata.name} abstraction call failed: {exc}",
                "metadata": {**trace_meta, "model": model, "attempt": attempt,
                             "error": str(exc)},
            }
            record_llm_exchange(trace_dir, event_id, event, messages)
            logging.warning("%s abstraction failed for %s: %s",
                            plugin.metadata.name, request.function.id.rel, exc)
            return plugin.make_error_facts(request, str(exc))

        facts = plugin.parse_abstraction_response(request, response)
        status = "success" if facts is not None else "format_error"
        event = {
            "event_id": event_id, "type": "llm_call",
            "stage": f"{plugin.metadata.name}_abstraction", "status": status,
            "start_time": started, "end_time": utc_now_iso(),
            "summary": f"Derived {plugin.metadata.name} abstraction",
            "metadata": {**trace_meta, "model": model, "attempt": attempt,
                         "usage": usage},
        }
        record_llm_exchange(trace_dir, event_id, event, messages, response)
        if facts is not None:
            facts.trace_ids.append(event_id)
            return facts
        # Retry with a format-correction turn.
        messages = messages + [
            {"role": "assistant", "content": response or ""},
            {"role": "user", "content": "Your output was not in the required format. "
                                         "Re-emit ONLY the requested structured block."},
        ]
    return plugin.make_error_facts(request, "no valid abstraction after retries (fail-closed)")


def _make_context(program: ProgramIndex, unit: FunctionUnit, entrypoints: set) -> DriverContext:
    return DriverContext(
        program=program,
        function=unit,
        is_entrypoint=unit.id in entrypoints,
        callers=program.callers_by_callee.get(unit.id, ()),
        callees=program.calls_by_caller.get(unit.id, ()),
    )


def _referenced_callee_context(
    plugin: AnalysisPlugin,
    unit: FunctionUnit,
    facts_by_fn: Mapping[FunctionId, FactEnvelope],
    program: ProgramIndex,
) -> Dict[FunctionId, str]:
    """Build {callee_id: summary_text} for callees referenced in this function's
    body that have already been analyzed."""
    ctx: Dict[FunctionId, str] = {}
    for site in program.calls_by_caller.get(unit.id, ()):
        cf = facts_by_fn.get(site.callee)
        if cf is not None and site.callee not in ctx:
            ctx[site.callee] = plugin.summarize_for_caller(cf)
    return ctx


def _resolved_calls(
    unit: FunctionUnit,
    facts_by_fn: Mapping[FunctionId, FactEnvelope],
    program: ProgramIndex,
) -> List[ResolvedCall]:
    out: List[ResolvedCall] = []
    for site in program.calls_by_caller.get(unit.id, ()):
        cf = facts_by_fn.get(site.callee)
        if cf is not None:
            out.append(ResolvedCall(call_site=site, callee_facts=cf))
    return out


def _run_top_down_context_worklist(
    plugin: AnalysisPlugin,
    program: ProgramIndex,
    facts_by_fn: Mapping[FunctionId, FactEnvelope],
    entrypoints: set,
) -> Dict[FunctionId, Sequence[Any]]:
    """Propagate plugin-defined context from entrypoints down the call graph.

    Used by theories whose property is not a pure bottom-up value computation
    (e.g. access control: "is the guard established by SOME ancestor?").
    """
    contexts: Dict[FunctionId, Sequence[Any]] = {}
    worklist: List[FunctionId] = []

    for eid in program.entrypoints:
        unit = program.functions[eid]
        ctx = _make_context(program, unit, entrypoints)
        initial = plugin.initial_context(facts_by_fn[eid], ctx)
        if initial is not None:
            contexts[eid] = plugin.merge_contexts((), (initial,))
            worklist.append(eid)

    # Bound the worklist to avoid pathological loops on cyclic graphs.
    max_steps = max(1000, 50 * len(program.functions))
    steps = 0
    while worklist and steps < max_steps:
        steps += 1
        caller_id = worklist.pop(0)
        caller_unit = program.functions[caller_id]
        caller_ctx = _make_context(program, caller_unit, entrypoints)
        for site in program.calls_by_caller.get(caller_id, ()):
            callee_facts = facts_by_fn.get(site.callee)
            if callee_facts is None:
                continue
            for cctx in contexts.get(caller_id, ()):
                nxt = plugin.propagate_context(
                    facts_by_fn[caller_id], callee_facts, site, cctx, caller_ctx
                )
                if nxt is None:
                    continue
                old = contexts.get(site.callee, ())
                merged = plugin.merge_contexts(old, (nxt,))
                if list(map(repr, merged)) != list(map(repr, old)):
                    contexts[site.callee] = merged
                    worklist.append(site.callee)
    return contexts


def run_plugin(plugin: AnalysisPlugin, proj_dir: str, work_subdir: Optional[str] = None,
               results_subdir: str = "results", max_iter: int = MAX_IFC_ITER,
               verbose: bool = True) -> Dict[str, Any]:
    """Run one analysis plugin over a project directory.

    Outputs under <proj_dir>/<work_subdir>/:
      extracted_functions/**              (reused extraction machinery)
      <results_subdir>/**/<func>.json     per-function result (plugin.render_result)
      <results_subdir>/summary.json       aggregate (plugin.render_summary)

    work_subdir defaults to "fm_agent_<name>"; results_subdir defaults to
    "results". The IFC migration passes work_subdir="fm_agent_ifc",
    results_subdir="ifc_results" so ifc_eval.py / ifc_viewer.py keep working.

    Returns the summary dict.
    """
    if not os.path.isdir(proj_dir):
        raise NotADirectoryError(proj_dir)

    name = plugin.metadata.name
    work_subdir = work_subdir or f"fm_agent_{name}"
    work_dir = os.path.join(proj_dir, work_subdir)
    results_dir = os.path.join(work_dir, results_subdir)
    trace_dir = os.path.join(work_dir, "trace")
    os.makedirs(results_dir, exist_ok=True)

    if verbose:
        print(f"[{name}] Stage 1/4: scan + extract...")
    units = callgraph.load_function_units(proj_dir, work_dir)
    if not units:
        print(f"[{name}] No functions extracted.")
        return {"total": 0, "results": []}

    if verbose:
        print(f"[{name}] Stage 2/4: build call graph ({len(units)} functions)...")
    program = callgraph.build_program_index(units)
    entrypoints = set(program.entrypoints)
    ordered = callgraph.order_bottom_up(units)
    model = _model_for(plugin)

    if verbose:
        print(f"[{name}] Stage 3/4: derive + compose (bottom-up)...")
    facts_by_fn: Dict[FunctionId, FactEnvelope] = {}
    for unit in ordered:
        ctx = _make_context(program, unit, entrypoints)
        callee_ctx = _referenced_callee_context(plugin, unit, facts_by_fn, program)
        request = AbstractionRequest(
            function=unit, context=ctx, callee_context=callee_ctx,
            trace_dir=trace_dir,
            trace_meta={"function_id": unit.id.rel, "language": unit.id.language},
        )
        facts = _call_llm_with_retries(plugin, request, model, max_iter)
        resolved = _resolved_calls(unit, facts_by_fn, program)
        if resolved:
            facts = plugin.compose_calls(facts, resolved, ctx)
        facts_by_fn[unit.id] = facts

    propagated: Dict[FunctionId, Sequence[Any]] = {}
    if plugin.metadata.requires_top_down_context:
        if verbose:
            print(f"[{name}] Stage 3.5/4: top-down context propagation...")
        propagated = _run_top_down_context_worklist(plugin, program, facts_by_fn, entrypoints)

    if verbose:
        print(f"[{name}] Stage 4/4: check + write results...")
    results = []
    counts: Dict[str, int] = {}
    for unit in ordered:
        ctx = _make_context(program, unit, entrypoints)
        facts = facts_by_fn[unit.id]
        verdict = plugin.check(facts, ctx, propagated.get(unit.id, ()))
        counts[verdict.verdict] = counts.get(verdict.verdict, 0) + 1

        out = plugin.render_result(unit, facts, verdict, ctx)
        out_path = os.path.join(results_dir, os.path.splitext(unit.id.rel)[0] + ".json")
        os.makedirs(os.path.dirname(out_path), exist_ok=True)
        with open(out_path, "w") as fp:
            json.dump(out, fp, indent=2, ensure_ascii=False)

        if verbose:
            color = {"LEAK": "\033[31m", "DECLASSIFIED": "\033[33m",
                     "POLYMORPHIC": "\033[36m", "SECURE": "\033[32m",
                     "ERROR": "\033[35m", "VULNERABLE": "\033[31m",
                     "SAFE": "\033[32m", "NEEDS_REVIEW": "\033[33m"}.get(verdict.verdict, "")
            print(f"  {unit.id.rel}: {color}{verdict.verdict}\033[0m")
        results.append({"function": unit.id.rel, "name": unit.id.name,
                        "verdict": verdict.verdict})

    summary = plugin.render_summary(results, counts)
    with open(os.path.join(results_dir, "summary.json"), "w") as f:
        json.dump(summary, f, indent=2, ensure_ascii=False)
    if verbose:
        print(f"[{name}] Done. " + " ".join(f"{k}={v}" for k, v in sorted(counts.items())))
    return summary

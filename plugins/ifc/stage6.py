"""Stage 6 replace: IFC analysis driver (derive → compose → check → write)."""

import json
import os
from typing import Dict, List

from .artifacts import load_program_index, load_order
from .callgraph import base_name, load_units_from_extracted
from .analyzer import (
    _source_rel_from_extracted,
    compose_calls,
    summarize_for_caller,
)
from .ifc_prompts import _extract_flow_json, _system_prompt, _user_prompt
from .ifc_validation import source_only_fallback, validate_and_enrich
from .ifc_reasoner import classify, render_gaps


def _call_llm_with_retries(
    source: str,
    signature_line: str,
    language: str,
    callee_summaries: str,
    model: str,
    max_iter: int = 5,
) -> dict:
    """Derive a flow signature via LLM, with format-correction retries.

    Returns: {"status": "ok"|"error", "payload": dict|None, "confidence": float,
              "error": str|None}
    """
    from src.llm_client import _openrouter_client, _retry_create

    messages = [
        {"role": "system", "content": _system_prompt(language)},
        {"role": "user", "content": _user_prompt(
            source, signature_line, language, callee_summaries)},
    ]

    last_error = None
    for _ in range(max_iter):
        try:
            response, _ = _retry_create(_openrouter_client, model, messages)
        except Exception as exc:
            fallback = source_only_fallback(source)
            if fallback is not None:
                return {"status": "ok", "payload": fallback, "confidence": 0.5}
            return {"status": "error", "payload": None, "confidence": 0.0,
                    "error": str(exc)}

        sig = _extract_flow_json(response)
        sig = validate_and_enrich(sig, source)
        if sig is not None:
            return {"status": "ok", "payload": sig, "confidence": 1.0}

        messages = messages + [
            {"role": "assistant", "content": response or ""},
            {"role": "user", "content": "Your output was not in the required format. "
                                         "Re-emit ONLY the requested structured block."},
        ]
        last_error = "no valid abstraction after retries"

    fallback = source_only_fallback(source)
    if fallback is not None:
        return {"status": "ok", "payload": fallback, "confidence": 0.5}
    return {"status": "error", "payload": None, "confidence": 0.0,
            "error": last_error or "fail-closed"}


def replace_generate_specs_and_verification(proj_dir: str) -> None:
    """IFC analysis: derive → compose → check → write.

    Stage 6 internally recovers the full IFC driver lifecycle:
      1. Derive flow signatures (per-function LLM calls)
      2. Compose callee signatures at call sites (deterministic label subst)
      3. Check verdicts (deterministic classifier)
      4. Write per-function JSON + summary
    """
    # Determine LLM model from env / config
    try:
        from config import LLM_MODEL
        model = LLM_MODEL
    except Exception:
        model = "deepseek-chat"

    work_dir = os.path.join(proj_dir, "fm_agent")
    ifc_dir = os.path.join(work_dir, "ifc")
    results_dir = os.path.join(work_dir, "ifc_results")
    os.makedirs(results_dir, exist_ok=True)

    # Restore Stage 5's static structure
    program, entrypoints = load_program_index(
        os.path.join(ifc_dir, "program_index.json")
    )
    order_data = load_order(os.path.join(ifc_dir, "bottom_up_order.json"))
    ordered = order_data.get("order", [])
    cycles = order_data.get("cycles", [])
    unreachable = order_data.get("unreachable", [])

    # Load source from extracted_functions/ (Stage 3 output)
    units = load_units_from_extracted(work_dir)
    source_by_fn = {(u.id.rel, u.id.name): u for u in units}

    # Build calls_by_fn lookup from program_index
    calls_by_fn: Dict[tuple, list] = {}
    for caller_key, calls in program.get("calls_by_caller", {}).items():
        try:
            rel, name = caller_key.split("::", 1)
        except ValueError:
            continue
        cid = (rel, name)
        calls_by_fn.setdefault(cid, []).extend(calls)

    all_refs = ordered + [
        item for cycle in cycles for item in cycle
    ] + list(unreachable)

    # ---- Pass 1: derive + compose (bottom-up) ----
    facts_by_fn: Dict[tuple, dict] = {}
    for ref in all_refs:
        fn_key = (ref["rel"], ref["name"])
        fn_unit = source_by_fn.get(fn_key)
        if fn_unit is None:
            facts_by_fn[fn_key] = {
                "status": "error", "payload": None, "confidence": 0.0,
                "error": "source not found in extracted_functions",
            }
            continue

        # Build callee context from already-derived callees
        callee_summaries_text = ""
        for cs in calls_by_fn.get(fn_key, []):
            callee_key = (cs.get("callee_rel"), cs.get("callee_name"))
            cf = facts_by_fn.get(callee_key)
            if cf and cf.get("status") == "ok" and cf.get("payload"):
                callee_summaries_text += "\n" + summarize_for_caller(
                    cs["callee_name"], cf["payload"]
                )

        # Derive flow signature
        facts = _call_llm_with_retries(
            fn_unit.source, fn_unit.signature_line,
            fn_unit.id.language, callee_summaries_text,
            model,
        )

        # Compose: instantiate callee signatures at call sites
        if facts.get("status") == "ok" and facts.get("payload"):
            resolved = [
                {
                    "callee_name": cs.get("callee_name"),
                    "order_index": cs.get("order_index", 0),
                    "arg_bindings": cs.get("arg_bindings", {}),
                    "callee_facts": facts_by_fn.get(
                        (cs.get("callee_rel"), cs.get("callee_name")), {}
                    ),
                }
                for cs in calls_by_fn.get(fn_key, [])
                if (cs.get("callee_rel"), cs.get("callee_name")) in facts_by_fn
            ]
            if resolved:
                facts = compose_calls(
                    facts, resolved, fn_unit.source, fn_unit.id.language
                )

        facts_by_fn[fn_key] = facts

    # ---- Pass 2: check + write ----
    counts: Dict[str, int] = {}
    results = []
    for ref in all_refs:
        fn_key = (ref["rel"], ref["name"])
        fn_unit = source_by_fn.get(fn_key)
        facts = facts_by_fn[fn_key]
        is_entrypoint = f"{ref['rel']}::{ref['name']}" in entrypoints

        # Check
        if facts.get("status") == "error" or not facts.get("payload"):
            verdict = "ERROR"
            gaps = None
            signature = None
        else:
            sig = validate_and_enrich(
                facts["payload"], fn_unit.source if fn_unit else "",
                allow_composed=bool(facts["payload"].get("_callee_resolutions")),
            )
            if sig is None:
                verdict = "ERROR"
                gaps = None
                signature = None
            else:
                cls = classify(sig, is_entrypoint=is_entrypoint)
                verdict = cls["verdict"]
                gaps = render_gaps(cls, sig) if verdict in (
                    "LEAK", "DECLASSIFIED", "POLYMORPHIC"
                ) else None
                signature = sig

        counts[verdict] = counts.get(verdict, 0) + 1
        resolutions = (
            (facts.get("payload") or {}).get("_callee_resolutions", None)
            if verdict != "ERROR" else None
        )

        rel_source = _source_rel_from_extracted(ref["rel"]) if fn_unit else ref["rel"]

        _COLOR = {
            "LEAK": "\033[31m", "DECLASSIFIED": "\033[33m",
            "POLYMORPHIC": "\033[36m", "SECURE": "\033[32m",
            "ERROR": "\033[35m",
        }
        print(f"  {ref['rel']}: {_COLOR.get(verdict, '')}{verdict}\033[0m")
        out = {
            "function": ref["name"],
            "rel": rel_source,
            "verdict": verdict,
            "status": "ok" if verdict != "ERROR" else "error",
            "signature": signature,
            "callee_resolutions": resolutions or None,
            "gaps": gaps,
        }
        if verdict == "ERROR":
            out["error"] = facts.get("error", "no valid flow signature")

        out_path = os.path.join(
            results_dir,
            ref["rel"].replace("/", "__") + "__" + ref["name"] + ".json",
        )
        os.makedirs(os.path.dirname(out_path), exist_ok=True)
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(out, f, indent=2, ensure_ascii=False)

        results.append({
            "function": ref["rel"], "name": ref["name"], "verdict": verdict,
        })

    summary = {
        "total": len(results),
        "leaks": counts.get("LEAK", 0),
        "declassified": counts.get("DECLASSIFIED", 0),
        "polymorphic": counts.get("POLYMORPHIC", 0),
        "secure": counts.get("SECURE", 0),
        "errors": counts.get("ERROR", 0),
        "results": results,
    }
    with open(os.path.join(results_dir, "summary.json"), "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2, ensure_ascii=False)

    parts = [
        f"DECLASSIFIED={counts.get('DECLASSIFIED', 0)}",
        f"LEAK={counts.get('LEAK', 0)}",
        f"POLYMORPHIC={counts.get('POLYMORPHIC', 0)}",
        f"SECURE={counts.get('SECURE', 0)}",
    ]
    if counts.get("ERROR", 0):
        parts.append(f"ERROR={counts['ERROR']}")
    print(f"[ifc] Done. {' '.join(parts)}")

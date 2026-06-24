"""Run FM-Agent's taint plugin over benchmark cases, collapse to per-case Detections.

Each benchmark case is a single .py file. run_plugin() expects a PROJECT DIR, so
we stage each case in its own isolated proj dir (case file + the benchmark's
helpers/ so imports resolve), run the taint plugin, then read back every
per-function result json and collapse them to ONE per-case Detection.

This is the slow/expensive path (per-function LLM calls against the unstable
endpoint), so it runs on the stratified sample, not the full benchmark. Each
case is fault-isolated: an exception or endpoint failure on one case is recorded
and the run continues.
"""

import argparse
import json
import os
import shutil
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from eval.benchmarks import Case  # noqa: E402
from eval.normalize import collapse_ours  # noqa: E402

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _load_case_results(results_dir, case_stem=None):
    """Read per-function result json under a case's results dir.

    If `case_stem` is given (e.g. 'BenchmarkTest00165'), return ONLY the results
    for functions that belong to the case file itself (rel path starts with
    '<case_stem>-py/'). Shared helper functions are still ANALYZED (the driver
    needs them for interprocedural composition — to know whether a helper
    sanitizes or is itself a sink), but their standalone verdicts must NOT be
    aggregated into the per-case detection or they contaminate every case
    identically (a VULNERABLE shared helper would flag every safe case).
    The route handler's own verdict already reflects helper-sink reachability
    via the tool's bottom-up composition.
    """
    out = []
    if not os.path.isdir(results_dir):
        return out
    prefix = f"{case_stem}-py/" if case_stem else None
    for root, _, files in os.walk(results_dir):
        for fn in files:
            if fn == "summary.json" or not fn.endswith(".json"):
                continue
            try:
                d = json.load(open(os.path.join(root, fn)))
            except (OSError, json.JSONDecodeError):
                continue
            if prefix and not (d.get("rel", "") or "").startswith(prefix):
                continue
            out.append(d)
    return out


def run_one_case(plugin_cls, case, stage_root, helpers_src=None,
                 plugin_name="taint", work_subdir=None):
    """Stage + analyze one case; return (Detection-dict, meta).

    plugin_name: which verdict vocabulary collapse_ours uses.
    work_subdir: the driver's output dir under the stage (defaults to
    fm_agent_<plugin_name>; ifc uses fm_agent_ifc/ifc_results).
    """
    stage = os.path.join(stage_root, case.id.replace(":", "_"))
    if os.path.exists(stage):
        shutil.rmtree(stage)
    os.makedirs(stage)
    shutil.copy(case.path, os.path.join(stage, os.path.basename(case.path)))
    if helpers_src and os.path.isdir(helpers_src):
        shutil.copytree(helpers_src, os.path.join(stage, "helpers"), dirs_exist_ok=True)

    from src.plugins.driver import run_plugin
    t0 = time.time()
    err = None
    try:
        run_plugin(plugin_cls(), stage)
    except Exception as e:  # noqa: BLE001 — fault-isolate per case
        err = f"{type(e).__name__}: {e}"
    dt = time.time() - t0

    work_subdir = work_subdir or f"fm_agent_{plugin_name}"
    results_dir = os.path.join(stage, work_subdir, "results")
    # The stem-filter only matters when shared helpers were staged alongside the
    # case (to avoid helper-verdict contamination). For curated single-function
    # cases NO helpers are staged, so the filter must be OFF — otherwise a result
    # with rel=None (e.g. ifc) is dropped and a real verdict is lost.
    staged_helpers = bool(helpers_src and os.path.isdir(helpers_src))
    case_stem = os.path.splitext(os.path.basename(case.path))[0] if staged_helpers else None
    func_results = _load_case_results(results_dir, case_stem)
    det = collapse_ours(case.id, func_results, plugin=plugin_name)
    meta = {"seconds": round(dt, 1), "n_functions": len(func_results),
            "error": err,
            "verdicts": [r.get("verdict") for r in func_results]}
    # A driver/checker CRASH is a tool-stability failure, not an analysis verdict.
    # Surface it as fail-closed ERROR so score.py never silently counts a crash as
    # a clean non-detection (which on a vulnerable case = a phantom FN). The
    # scorer treats `error` per the chosen policy (default: fail-closed = detected).
    return ({"detected": det.detected, "cwes": sorted(det.cwes),
             "raw_count": det.raw_count, "evidence": det.evidence,
             "error": err}, meta)


def _plugin_class(name):
    """Resolve a plugin name to its class (mirrors run_plugin.py registry)."""
    if name == "taint":
        from src.plugins.taint import TaintPlugin
        return TaintPlugin, None
    if name == "crypto":
        from src.plugins.crypto import CryptoPlugin
        return CryptoPlugin, None
    if name == "authz":
        from src.plugins.authz import AuthzPlugin
        return AuthzPlugin, None
    if name == "ifc":
        from src.plugins.ifc import IfcPlugin
        return IfcPlugin, "fm_agent_ifc"  # ifc uses a custom work_subdir
    if name == "typestate":
        from src.plugins.typestate import TypestatePlugin
        return TypestatePlugin, None
    raise SystemExit(f"unknown plugin '{name}'")


def main():
    ap = argparse.ArgumentParser(description="Run an FM-Agent plugin over a sample manifest")
    ap.add_argument("--plugin", default="taint",
                    choices=["taint", "crypto", "authz", "ifc", "typestate"])
    ap.add_argument("--sample", default=None, help="defaults to eval/sample_<plugin>.json")
    ap.add_argument("--out", default=None, help="defaults to eval/ours_<plugin>_detections.json")
    ap.add_argument("--stage-root", default=None)
    ap.add_argument("--helpers", default="/mnt/nvme/jiangzhe/tmp/opencode/eval_benchmarks/BenchmarkPython/helpers")
    ap.add_argument("--limit", type=int, default=0, help="cap #cases (0=all) for smoke runs")
    args = ap.parse_args()

    sample = args.sample or f"eval/sample_{args.plugin}.json"
    out = args.out or f"eval/ours_{args.plugin}_detections.json"
    stage_root = args.stage_root or f"/tmp/eval_ours_stage_{args.plugin}"
    # taint legacy default for backward compatibility
    if args.plugin == "taint" and args.out is None and os.path.isfile("eval/ours_detections.json"):
        out = "eval/ours_detections.json"

    manifest = json.load(open(sample))
    cases = [Case(**c) for c in manifest["cases"]]
    if args.limit:
        cases = cases[:args.limit]

    plugin_cls, work_subdir = _plugin_class(args.plugin)
    os.makedirs(stage_root, exist_ok=True)

    table, metas = {}, {}
    n = len(cases)
    for i, c in enumerate(cases, 1):
        det, meta = run_one_case(plugin_cls, c, stage_root, args.helpers,
                                 plugin_name=args.plugin, work_subdir=work_subdir)
        table[c.id] = det
        metas[c.id] = meta
        flag = "DET" if det["detected"] else "---"
        print(f"[{i}/{n}] {c.id} label={'V' if c.label else 's'} {c.cwe} "
              f"-> {flag} cwes={det['cwes']} {meta['verdicts']} ({meta['seconds']}s)"
              + (f" ERR={meta['error']}" if meta["error"] else ""), flush=True)
        # checkpoint after each case (endpoint is unstable; never lose progress)
        json.dump({"detections": table, "meta": metas},
                  open(out, "w"), indent=2)
    print(f"wrote {out} ({len(table)} cases)")


if __name__ == "__main__":
    main()

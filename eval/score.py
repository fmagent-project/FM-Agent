"""Scorer — compute precision/recall/F1 per tool on the comparison set.

The comparison set is the INTERSECTION of cases where every tool has a result
(i.e. the stratified sample our tool ran on). For each case we have:
  - ground truth: label (vulnerable/safe) + expected CWE
  - per-tool Detection: detected? + attributed CWEs

Two scoring views (both reported — they answer different questions):
  - DETECTION view:  TP = (label vulnerable AND tool detected).
                     FP = (label safe AND tool detected).
                     Measures "does the tool flag the right files?" — charitable
                     to a tool that reports a finding without a precise CWE.
  - CWE-AWARE view:  a detection only counts as TP if the attributed CWE shares a
                     family with the expected CWE (eval.normalize.cwe_matches).
                     Stricter: "right bug, right category."

For each view and tool: TP, FP, FN, TN, precision, recall, F1, plus a per-CWE
breakdown so we can see where each tool is strong/blind.
"""

import argparse
import json
import os
import sys
from collections import defaultdict

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from eval.benchmarks import Case  # noqa: E402
from eval.normalize import cwe_matches  # noqa: E402


def _prf(tp, fp, fn):
    p = tp / (tp + fp) if (tp + fp) else 0.0
    r = tp / (tp + fn) if (tp + fn) else 0.0
    f = 2 * p * r / (p + r) if (p + r) else 0.0
    return p, r, f


def score_tool(cases, detections, cwe_aware):
    """Return overall + per-CWE confusion for one tool.

    cases: list[Case]. detections: {case_id: {detected, cwes, error?, ...}}.
    cwe_aware: if True, a positive detection must match the expected CWE family.

    ERROR policy (fail-closed): a case where the tool CRASHED (det['error'] truthy)
    is a tool-stability failure, not an analysis verdict. We count it in a separate
    `ERR` bucket AND, per the tool's own fail-closed design, treat it as flagged
    (so a crash on a vulnerable case is NOT silently scored as a clean miss). The
    ERR count is surfaced so a reader can re-derive error-excluded P/R if desired.
    """
    overall = {"TP": 0, "FP": 0, "FN": 0, "TN": 0, "ERR": 0}
    per_cwe = defaultdict(lambda: {"TP": 0, "FP": 0, "FN": 0, "TN": 0, "ERR": 0})
    missing = []
    for c in cases:
        det = detections.get(c.id)
        if det is None:
            missing.append(c.id)
            continue
        errored = bool(det.get("error"))
        flagged = det["detected"] or errored  # fail-closed: crash => flagged
        if cwe_aware and flagged and not errored:
            flagged = cwe_matches(c.cwe, set(det.get("cwes", [])))
        cwe = c.cwe
        if errored:
            overall["ERR"] += 1; per_cwe[cwe]["ERR"] += 1
        if c.label:  # vulnerable (positive)
            if flagged:
                overall["TP"] += 1; per_cwe[cwe]["TP"] += 1
            else:
                overall["FN"] += 1; per_cwe[cwe]["FN"] += 1
        else:        # safe (negative)
            if flagged:
                overall["FP"] += 1; per_cwe[cwe]["FP"] += 1
            else:
                overall["TN"] += 1; per_cwe[cwe]["TN"] += 1
    return overall, dict(per_cwe), missing


def _fmt_row(name, conf):
    p, r, f = _prf(conf["TP"], conf["FP"], conf["FN"])
    err = f" ERR={conf['ERR']:2d}" if conf.get("ERR") else ""
    return (f"{name:18s} TP={conf['TP']:3d} FP={conf['FP']:3d} "
            f"FN={conf['FN']:3d} TN={conf['TN']:3d}{err}  "
            f"P={p:.2f} R={r:.2f} F1={f:.2f}")


def load_tool_detections(path, key="detections"):
    """Load a detections json. Our-tool file nests under 'detections' (+ 'meta');
    baseline file is a flat {case_id: {tool: det}} map handled separately.

    For our-tool: fold meta[cid]['error'] into the per-case detection so a crash
    captured by an IN-FLIGHT run (which only wrote meta.error, not det.error) is
    still scored honestly as ERROR.
    """
    d = json.load(open(path))
    dets = d.get(key, d)
    meta = d.get("meta", {}) if isinstance(d, dict) else {}
    if meta:
        for cid, det in dets.items():
            if isinstance(det, dict) and not det.get("error"):
                err = (meta.get(cid) or {}).get("error")
                if err:
                    det["error"] = err
    return dets


def main():
    ap = argparse.ArgumentParser(description="Score FM-Agent vs baselines on the comparison set")
    ap.add_argument("--sample", default="eval/sample_taint.json")
    ap.add_argument("--ours", default="eval/ours_detections.json")
    ap.add_argument("--baselines", default="eval/out_baselines/baseline_detections.json")
    ap.add_argument("--llm", default=None,
                    help="optional direct-LLM baseline detections json (eval/llm_<plugin>_cve_detections.json)")
    ap.add_argument("--out", default="eval/comparison_taint.json")
    args = ap.parse_args()

    manifest = json.load(open(args.sample))
    cases = [Case(**c) for c in manifest["cases"]]

    # build {tool: {case_id: det}}
    tools = {}
    if os.path.isfile(args.ours):
        tools["fm-agent"] = load_tool_detections(args.ours, "detections")
    if os.path.isfile(args.baselines):
        bl = json.load(open(args.baselines))  # {case_id: {tool: det}}
    else:
        # aggregate not written yet (partial run) — rebuild from incremental raw/
        from eval.run_baselines import reconstruct_from_raw
        bl = reconstruct_from_raw(os.path.dirname(args.baselines))
    if bl:
        for tool in ("bandit", "semgrep"):
            tools[tool] = {cid: per.get(tool, {"detected": False, "cwes": []})
                           for cid, per in bl.items()}

    # optional third baseline: direct-LLM single-shot judgment
    if args.llm and os.path.isfile(args.llm):
        tools["llm-direct"] = load_tool_detections(args.llm, "detections")

    # comparison set = cases present for ALL tools (intersection)
    common = [c for c in cases if all(c.id in tools[t] for t in tools)]

    report = {"comparison_set_size": len(common),
              "total_sample": len(cases),
              "tools": sorted(tools),
              "views": {}}

    print(f"comparison set: {len(common)}/{len(cases)} cases "
          f"(present for all of: {', '.join(sorted(tools))})\n")

    for view, aware in (("detection", False), ("cwe_aware", True)):
        print(f"=== {view.upper()} view ===")
        report["views"][view] = {}
        for tool in sorted(tools):
            overall, per_cwe, missing = score_tool(common, tools[tool], aware)
            p, r, f = _prf(overall["TP"], overall["FP"], overall["FN"])
            print("  " + _fmt_row(tool, overall))
            report["views"][view][tool] = {
                "overall": overall,
                "precision": round(p, 4), "recall": round(r, 4), "f1": round(f, 4),
                "per_cwe": {k: {**v, "recall": round(_prf(v["TP"], v["FP"], v["FN"])[1], 3)}
                            for k, v in sorted(per_cwe.items())},
            }
        print()

    # per-CWE recall comparison (detection view) — where is each tool blind?
    print("=== per-CWE RECALL (detection view) ===")
    cwes = sorted({c.cwe for c in common if c.label})
    hdr = f"{'CWE':10s}" + "".join(f"{t:>12s}" for t in sorted(tools))
    print("  " + hdr)
    for cwe in cwes:
        row = f"{cwe:10s}"
        for tool in sorted(tools):
            pc = report["views"]["detection"][tool]["per_cwe"].get(cwe, {})
            tp, fn = pc.get("TP", 0), pc.get("FN", 0)
            rec = tp / (tp + fn) if (tp + fn) else 0.0
            row += f"{rec:>11.2f} "
        print("  " + row)

    json.dump(report, open(args.out, "w"), indent=2)
    print(f"\nwrote {args.out}")


if __name__ == "__main__":
    main()

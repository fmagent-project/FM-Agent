"""Manual-audit helper — surface the cases that MUST be eyeballed (跑完≠跑对).

A green score is not trusted until a human confirms the tool's verdicts are real
bugs (not label artifacts) and its misses/false-positives are understood. Running
the whole sample by eye is wasteful; this tool prioritizes the cases where
auditing pays off, and prints the ACTUAL source + each tool's verdict together so
a reviewer can adjudicate in one screen.

Priority buckets (most informative first):
  1. OUR-FP   : label=safe but FM-Agent flagged   -> is our tool wrong, or is the
                "safe" case actually exploitable? (either is a finding)
  2. OUR-FN   : label=vulnerable but FM-Agent missed -> real miss vs label noise.
  3. DISAGREE : FM-Agent vs baselines disagree on a case -> who is right?
  4. OUR-ERROR: FM-Agent emitted ERROR (fail-closed) -> endpoint/parse failure,
                not a real verdict; must be excluded from precision claims.

Usage:
    python3 eval/audit.py [--bucket our-fp|our-fn|disagree|error|all] [--limit N]
"""

import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from eval.benchmarks import Case  # noqa: E402
from eval.normalize import cwe_matches  # noqa: E402


def _load(path, key=None):
    if not os.path.isfile(path):
        return {}
    d = json.load(open(path))
    return d.get(key, d) if key else d


def _baseline_det(bl, cid, tool):
    return bl.get(cid, {}).get(tool, {"detected": False, "cwes": []})


def classify_case(c, ours, ours_meta, bl):
    """Return (bucket, summary-dict) or (None, None) if not audit-worthy."""
    od = ours.get(c.id)
    if od is None:
        return None, None
    meta = ours_meta.get(c.id, {})
    if meta.get("error") or "ERROR(fail-closed)" in " ".join(od.get("evidence", [])):
        return "error", {"reason": meta.get("error") or "fail-closed ERROR verdict"}

    our_flag = od["detected"]
    ban = _baseline_det(bl, c.id, "bandit")
    sg = _baseline_det(bl, c.id, "semgrep")

    if not c.label and our_flag:
        return "our-fp", {"our_cwes": od["cwes"]}
    if c.label and not our_flag:
        return "our-fn", {"our_verdicts": meta.get("verdicts", [])}
    # agreement with truth, but disagreement among tools is still informative
    if our_flag != ban["detected"] or our_flag != sg["detected"]:
        return "disagree", {"ours": our_flag, "bandit": ban["detected"],
                            "semgrep": sg["detected"]}
    return None, None


def print_case(c, bucket, info, ours, ours_meta, bl, show_source=True):
    od = ours.get(c.id, {})
    meta = ours_meta.get(c.id, {})
    ban = _baseline_det(bl, c.id, "bandit")
    sg = _baseline_det(bl, c.id, "semgrep")
    print("=" * 78)
    print(f"[{bucket.upper()}] {c.id}  label={'VULNERABLE' if c.label else 'SAFE'}  "
          f"expected={c.cwe}  category={c.category}")
    print(f"  source: {c.source}")
    print(f"  FM-Agent : detected={od.get('detected')} cwes={od.get('cwes')} "
          f"verdicts={meta.get('verdicts')} "
          f"cwe_match={cwe_matches(c.cwe, set(od.get('cwes', [])))}")
    print(f"  bandit   : detected={ban['detected']} cwes={ban.get('cwes')}")
    print(f"  semgrep  : detected={sg['detected']} cwes={sg.get('cwes')}")
    print(f"  note: {info}")
    if show_source and os.path.isfile(c.path):
        print("  --- source ---")
        with open(c.path) as f:
            for i, line in enumerate(f, 1):
                if i < 17:   # skip the OWASP license header
                    continue
                print(f"  {i:3d}| {line.rstrip()}")
    print()


def main():
    ap = argparse.ArgumentParser(description="Prioritized manual-audit view (跑完≠跑对)")
    ap.add_argument("--sample", default="eval/sample_taint.json")
    ap.add_argument("--ours", default="eval/ours_detections.json")
    ap.add_argument("--baselines", default="eval/out_baselines/baseline_detections.json")
    ap.add_argument("--bucket", default="all",
                    choices=["our-fp", "our-fn", "disagree", "error", "all"])
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--no-source", action="store_true")
    args = ap.parse_args()

    manifest = json.load(open(args.sample))
    cases = [Case(**c) for c in manifest["cases"]]
    ours_doc = _load(args.ours)
    ours = ours_doc.get("detections", {})
    ours_meta = ours_doc.get("meta", {})
    bl = _load(args.baselines)
    if not bl:
        # aggregate not written yet (partial run) — rebuild from incremental raw/
        from eval.run_baselines import reconstruct_from_raw
        bl = reconstruct_from_raw(os.path.dirname(args.baselines))

    if not ours:
        print(f"no FM-Agent detections yet in {args.ours} — run eval/run_ours.py first.")
        return 1

    buckets = {"our-fp": [], "our-fn": [], "disagree": [], "error": []}
    for c in cases:
        b, info = classify_case(c, ours, ours_meta, bl)
        if b:
            buckets[b].append((c, info))

    order = ["our-fp", "our-fn", "error", "disagree"] if args.bucket == "all" else [args.bucket]
    print(f"audit candidates (of {len(ours)} scored cases): "
          + ", ".join(f"{k}={len(buckets[k])}" for k in buckets) + "\n")
    shown = 0
    for b in order:
        for c, info in buckets[b]:
            if args.limit and shown >= args.limit:
                print(f"... (limit {args.limit} reached)")
                return 0
            print_case(c, b, info, ours, ours_meta, bl, show_source=not args.no_source)
            shown += 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

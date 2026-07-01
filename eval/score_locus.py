"""Locus-level scorer for whole-file (hard) benchmark cases.

WHY THIS EXISTS: the standard per-case detection rule is "ANY function in the
file flagged => file flagged". For single-function cases that is fine, but for
whole-file (hard) cases each file has ~9 functions and a before/after pair
differs in only ONE. The other ~8 unchanged functions trigger identical flags in
both before and after, so the file-level rule cannot distinguish them and
degenerates to flag-everything (near-0% specificity). That inflates recall and
F1 and is NOT a real localization signal.

The locus rule fixes this: a case is "flagged" iff one of its CHANGED functions
(meta.changed_funcs, the true fix locus) gets a positive verdict. A vulnerable
(before) case scored TP only if the tool flags the function the fix actually
changed; a safe (after) case scored TN only if the tool clears it. This measures
real interprocedural localization, not noise from co-resident functions.

Input: eval/ours_<plugin>_hard_funcverdicts.json (harvested per-function verdicts
+ changed_funcs + label per case). Pure data, reproducible, no /tmp dependency.
"""

import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from src.plugins import registry  # noqa: E402


def _locus_flagged(changed_funcs, func_verdicts, positive):
    """True iff any changed function has a positive verdict. Match by exact name
    or dedupe-suffix prefix (extractor may rename foo -> foo_1)."""
    for cf in changed_funcs:
        for fn, v in func_verdicts.items():
            if (fn == cf or fn.startswith(cf + "_") or cf.startswith(fn)) and v in positive:
                return True
    return False


def score_plugin(plugin, fv_path):
    positive = registry.positive_verdicts(plugin)
    data = json.load(open(fv_path))
    TP = FP = FN = TN = NOLOCUS = 0
    for cid, rec in data.items():
        cf = rec.get("changed_funcs") or []
        if not cf:
            NOLOCUS += 1
            continue
        flagged = _locus_flagged(cf, rec.get("func_verdicts") or {}, positive)
        if rec["label"]:
            TP += flagged; FN += (not flagged)
        else:
            FP += flagged; TN += (not flagged)
    p = TP / (TP + FP) if (TP + FP) else 0.0
    r = TP / (TP + FN) if (TP + FN) else 0.0
    f = 2 * p * r / (p + r) if (p + r) else 0.0
    spec = TN / (TN + FP) if (TN + FP) else 0.0
    return {"TP": TP, "FP": FP, "FN": FN, "TN": TN, "no_locus": NOLOCUS,
            "precision": round(p, 3), "recall": round(r, 3), "f1": round(f, 3),
            "specificity": round(spec, 3)}


def main():
    ap = argparse.ArgumentParser(description="Locus-level score for hard whole-file cases")
    ap.add_argument("--plugin", default=None, help="one plugin, or all if omitted")
    ap.add_argument("--funcverdicts", default=None,
                    help="defaults to eval/ours_<plugin>_hard_funcverdicts.json")
    ap.add_argument("--out", default="eval/comparison_hard_locus.json")
    args = ap.parse_args()

    plugins = [args.plugin] if args.plugin else registry.plugin_names()
    report = {}
    print(f"{'plugin':11} {'P':>5} {'R':>5} {'F1':>5} {'spec':>5}   confusion")
    for p in plugins:
        fv = args.funcverdicts or f"eval/ours_{p}_hard_funcverdicts.json"
        if not os.path.isfile(fv):
            print(f"  {p:9}  (no funcverdicts file)"); continue
        s = score_plugin(p, fv)
        report[p] = s
        print(f"{p:11} {s['precision']:5.2f} {s['recall']:5.2f} {s['f1']:5.2f} "
              f"{s['specificity']:5.2f}   TP={s['TP']} FP={s['FP']} FN={s['FN']} TN={s['TN']}"
              + (f" no_locus={s['no_locus']}" if s['no_locus'] else ""))
    json.dump(report, open(args.out, "w"), indent=2)
    print(f"\nwrote {args.out}")


if __name__ == "__main__":
    main()

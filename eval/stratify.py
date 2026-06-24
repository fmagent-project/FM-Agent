"""Stratified sampler — pick a reproducible, CWE-balanced subset for OUR tool.

Why sample: baselines are fast/free and run over the FULL benchmark; our tool
makes per-function LLM calls against an unstable endpoint, so it runs on a
stratified subset. To keep the head-to-head FAIR, the comparison is computed on
the INTERSECTION (this sample), where every tool has a result.

Strategy: within each taint CWE category, take a balanced number of vulnerable
(positive) and safe (negative) cases, capped per category, seeded for
reproducibility. Categories with few cases (sqli=16) contribute all they have;
large ones (xpathi=186) are down-sampled. Negatives matter as much as positives:
they are the only way to measure FALSE POSITIVES / precision.
"""

import argparse
import json
import os
import random
import sys
from collections import defaultdict

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from eval.benchmarks import load_owasp, PLUGIN_CATEGORIES  # noqa: E402

SEED = 1337


def stratify(cases, per_category=8, seed=SEED):
    """Return a balanced subset: up to `per_category` cases per category,
    split as evenly as possible between vulnerable and safe.
    """
    rng = random.Random(seed)
    by_cat_label = defaultdict(lambda: defaultdict(list))
    for c in cases:
        by_cat_label[c.category][c.label].append(c)

    picked = []
    for cat in sorted(by_cat_label):
        pos = by_cat_label[cat][True]
        neg = by_cat_label[cat][False]
        rng.shuffle(pos)
        rng.shuffle(neg)
        half = per_category // 2
        take_pos = pos[:half]
        take_neg = neg[:per_category - len(take_pos)]
        # if one side is short, backfill from the other
        if len(take_pos) + len(take_neg) < per_category:
            deficit = per_category - len(take_pos) - len(take_neg)
            take_pos += pos[len(take_pos):len(take_pos) + deficit]
        picked.extend(take_pos + take_neg)
    return picked


def main():
    ap = argparse.ArgumentParser(description="Stratified OWASP sample for an FM-Agent plugin")
    ap.add_argument("--plugin", default="taint", choices=sorted(PLUGIN_CATEGORIES))
    ap.add_argument("--owasp", default="/mnt/nvme/jiangzhe/tmp/opencode/eval_benchmarks/BenchmarkPython")
    ap.add_argument("--per-category", type=int, default=8)
    ap.add_argument("--out", default=None, help="defaults to eval/sample_<plugin>.json")
    ap.add_argument("--seed", type=int, default=SEED)
    args = ap.parse_args()

    out = args.out or f"eval/sample_{args.plugin}.json"
    categories = PLUGIN_CATEGORIES[args.plugin]
    cases = load_owasp(args.owasp, categories=categories)
    sample = stratify(cases, args.per_category, args.seed)

    manifest = {
        "benchmark": "owasp:BenchmarkPython",
        "plugin": args.plugin,
        "source": cases[0].source if cases else "?",
        "seed": args.seed,
        "per_category": args.per_category,
        "total_selected": len(sample),
        "cases": [c.to_json() for c in sample],
    }
    with open(out, "w") as f:
        json.dump(manifest, f, indent=2)

    from collections import Counter
    dist = Counter((c.category, c.label) for c in sample)
    print(f"selected {len(sample)} cases (seed={args.seed}, per_category={args.per_category})")
    for (cat, lab), n in sorted(dist.items()):
        print(f"  {cat:18s} {'VULN' if lab else 'safe'}: {n}")
    npos = sum(1 for c in sample if c.label)
    print(f"  TOTAL: {npos} vulnerable / {len(sample) - npos} safe")
    print(f"wrote {out}")


if __name__ == "__main__":
    main()

"""Stratified sampler — pick a reproducible, CWE-balanced subset for OUR tool.

Why sample: baselines are fast/free and run over the FULL benchmark; our tool
makes per-function LLM calls against an unstable endpoint, so it runs on a
stratified subset. To keep the head-to-head FAIR, the comparison is computed on
the INTERSECTION (this sample), where every tool has a result.

Two benchmarks:
  - owasp : synthetic OWASP BenchmarkPython (taint, crypto). Buckets by OWASP
            category. 100% label-accurate.
  - cve   : the CVE-curated corpus (any plugin, incl. authz/ifc/typestate that
            have NO public benchmark). Buckets by CWE, filtered to the plugin's
            manifest CWE scope (registry-driven). ~60% label precision — recall
            trustworthy, precision needs per-case audit.

Strategy: within each bucket take a balanced number of vulnerable (positive) and
safe (negative) cases, capped per bucket, seeded for reproducibility. Negatives
matter as much as positives: they are the only way to measure FALSE POSITIVES.
"""

import argparse
import json
import os
import random
import sys
from collections import Counter, defaultdict

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from eval.benchmarks import load_owasp, load_cve_curated, PLUGIN_CATEGORIES  # noqa: E402
from eval.normalize import _canon_cwe  # noqa: E402
from src.plugins import registry  # noqa: E402  (pure-data, light)

SEED = 1337

DEFAULT_CVE_MANIFEST = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "cve_curation", "cve_cases.filtered.jsonl",
)


def stratify(cases, per_bucket=8, seed=SEED, key=lambda c: c.category):
    """Return a balanced subset: up to `per_bucket` cases per bucket, split as
    evenly as possible between vulnerable and safe. `key` selects the bucket
    (category for OWASP, CWE for the CVE corpus)."""
    rng = random.Random(seed)
    by_bucket_label = defaultdict(lambda: defaultdict(list))
    for c in cases:
        by_bucket_label[key(c)][c.label].append(c)

    picked = []
    for bucket in sorted(by_bucket_label):
        pos = by_bucket_label[bucket][True]
        neg = by_bucket_label[bucket][False]
        rng.shuffle(pos)
        rng.shuffle(neg)
        half = per_bucket // 2
        take_pos = pos[:half]
        take_neg = neg[:per_bucket - len(take_pos)]
        # if one side is short, backfill from the other
        if len(take_pos) + len(take_neg) < per_bucket:
            deficit = per_bucket - len(take_pos) - len(take_neg)
            take_pos += pos[len(take_pos):len(take_pos) + deficit]
        picked.extend(take_pos + take_neg)
    return picked


def _load_owasp_cases(args):
    """OWASP path: filter to the plugin's OWASP categories."""
    if args.plugin not in PLUGIN_CATEGORIES:
        raise SystemExit(
            f"plugin '{args.plugin}' has no OWASP categories; use --benchmark cve "
            f"(OWASP plugins: {', '.join(sorted(PLUGIN_CATEGORIES))})"
        )
    categories = PLUGIN_CATEGORIES[args.plugin]
    cases = load_owasp(args.owasp, categories=categories)
    return cases, "owasp:BenchmarkPython", (lambda c: c.category)


def _load_cve_cases(args):
    """CVE path: load the curated corpus, keep cases whose CWE is in the
    plugin's manifest scope (registry-driven). Bucket by CWE."""
    if not registry.has_plugin(args.plugin):
        raise SystemExit(f"unknown plugin '{args.plugin}'. Known: {', '.join(registry.plugin_names())}")
    scope = {_canon_cwe(c) for c in registry.get_manifest(args.plugin)["cwes"]}
    all_cases = load_cve_curated(args.manifest)
    cases = [c for c in all_cases if _canon_cwe(c.cwe) in scope]
    if not cases:
        raise SystemExit(
            f"no CVE cases in {args.manifest} match {args.plugin}'s CWE scope "
            f"{sorted(scope)} — supply a corpus that covers these CWEs via --manifest"
        )
    return cases, f"cve-curated:{os.path.basename(args.manifest)}", (lambda c: c.cwe)


def main():
    ap = argparse.ArgumentParser(description="Stratified sample for an FM-Agent plugin")
    ap.add_argument("--plugin", default="taint",
                    help="plugin name (OWASP: taint|crypto; CVE: any registered plugin)")
    ap.add_argument("--benchmark", default="owasp", choices=["owasp", "cve"],
                    help="owasp (synthetic) or cve (curated corpus)")
    ap.add_argument("--owasp", default="/mnt/nvme/jiangzhe/tmp/opencode/eval_benchmarks/BenchmarkPython")
    ap.add_argument("--manifest", default=DEFAULT_CVE_MANIFEST,
                    help="CVE corpus jsonl (benchmark=cve); defaults to the in-repo filtered corpus")
    ap.add_argument("--per-category", type=int, default=8, help="cases per bucket (category or CWE)")
    ap.add_argument("--out", default=None,
                    help="defaults to eval/sample_<plugin>.json (owasp) or sample_<plugin>_cve.json (cve)")
    ap.add_argument("--seed", type=int, default=SEED)
    args = ap.parse_args()

    if args.benchmark == "owasp":
        cases, benchmark, key = _load_owasp_cases(args)
        default_out = f"eval/sample_{args.plugin}.json"
        extra = {}
    else:
        cases, benchmark, key = _load_cve_cases(args)
        default_out = f"eval/sample_{args.plugin}_cve.json"
        extra = {"label_noise_caveat":
                 "~60% label precision; precision requires per-case human audit"}

    out = args.out or default_out
    sample = stratify(cases, args.per_category, args.seed, key=key)

    manifest = {
        "benchmark": benchmark,
        "plugin": args.plugin,
        "source": cases[0].source if cases else "?",
        "seed": args.seed,
        "per_category": args.per_category,
        "total_selected": len(sample),
        **extra,
        "cases": [c.to_json() for c in sample],
    }
    with open(out, "w") as f:
        json.dump(manifest, f, indent=2)

    dist = Counter((key(c), c.label) for c in sample)
    print(f"selected {len(sample)} cases ({benchmark}, seed={args.seed}, per_bucket={args.per_category})")
    for (bucket, lab), n in sorted(dist.items()):
        print(f"  {str(bucket):18s} {'VULN' if lab else 'safe'}: {n}")
    npos = sum(1 for c in sample if c.label)
    print(f"  TOTAL: {npos} vulnerable / {len(sample) - npos} safe")
    print(f"wrote {out}")


if __name__ == "__main__":
    main()

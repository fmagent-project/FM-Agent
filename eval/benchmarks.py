"""Benchmark loaders — unify external security benchmarks into Case records.

Each benchmark has a DIFFERENT on-disk shape; this module normalizes them all to
a common `Case` so the rest of the harness (baselines, our tool, scorer) is
benchmark-agnostic.

Supported benchmarks (all THIRD-PARTY labeled, provenance recorded):
  - OWASP BenchmarkPython v0.1 (1230 per-file Flask cases, expectedresults csv).
      primary benchmark: real labels, balanced true/false, citable.
  - RedBench REAL subset only (samples_real.jsonl entries that carry a `source`
      field tracing to securityeval / github_advisory). The LLM-GENERATED bulk is
      deliberately EXCLUDED (user constraint: prefer real, not hand/LLM-fabricated).

A Case is the unit of comparison. Every tool (ours + baselines) is scored on
whether it flags the case with a CWE in the expected CWE's family.
"""

import csv
import json
import os
import sys
from dataclasses import dataclass, field, asdict

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


# --- OWASP category -> CWE number (from expectedresults-0.1.csv) ---------------
# Only the categories our TAINT plugin targets are "taint-comparable"; the rest
# (weakrand/hash/securecookie/trustbound) belong to other plugins.
OWASP_CATEGORY_CWE = {
    "pathtraver": "CWE-22",
    "sqli": "CWE-89",
    "cmdi": "CWE-78",
    "xss": "CWE-79",
    "deserialization": "CWE-502",
    "codeinj": "CWE-94",
    "redirect": "CWE-601",
    "ldapi": "CWE-90",
    "xpathi": "CWE-643",
    "xxe": "CWE-611",
    # non-taint categories (kept for completeness / other plugins):
    "weakrand": "CWE-330",
    "hash": "CWE-328",
    "securecookie": "CWE-614",
    "trustbound": "CWE-501",
}

# Categories each plugin models on the OWASP benchmark, derived from the central
# registry (src/plugins/registry.py). Only plugins with NON-EMPTY OWASP
# categories appear here (taint, crypto) — authz/ifc/typestate have no OWASP
# coverage and are CVE-only, so they are intentionally absent (this also keeps
# stratify.py's --plugin choices to the OWASP-samplable plugins). Importing the
# registry is cheap and side-effect free (pure data, no openai).
from src.plugins import registry as _registry  # noqa: E402  (pure-data, light)

PLUGIN_CATEGORIES = {
    name: set(m["benchmark_categories"])
    for name, m in _registry.PLUGIN_MANIFESTS.items()
    if m.get("benchmark_categories")
}

# Back-compat aliases (some call sites referenced these directly).
TAINT_CATEGORIES = PLUGIN_CATEGORIES.get("taint", set())
CRYPTO_CATEGORIES = PLUGIN_CATEGORIES.get("crypto", set())


@dataclass
class Case:
    """One labeled benchmark case = one unit of comparison."""
    id: str                 # globally unique, e.g. "owasp:BenchmarkTest00099"
    path: str               # absolute path to a .py file to analyze
    cwe: str                # expected CWE, e.g. "CWE-89"
    label: bool             # True = vulnerable (positive), False = safe (negative)
    category: str           # e.g. "sqli"
    source: str             # provenance string (benchmark + version/sha or origin)
    benchmark: str          # "owasp" | "redbench-real"
    meta: dict = field(default_factory=dict)

    def to_json(self):
        return asdict(self)


def _git_sha(repo_dir):
    head = os.path.join(repo_dir, ".git", "HEAD")
    try:
        with open(head) as f:
            ref = f.read().strip()
        if ref.startswith("ref:"):
            ref_path = os.path.join(repo_dir, ".git", ref.split(" ", 1)[1].strip())
            with open(ref_path) as f:
                return f.read().strip()[:12]
        return ref[:12]
    except OSError:
        return "unknown"


def load_owasp(owasp_dir, taint_only=True, categories=None):
    """Load OWASP BenchmarkPython cases from expectedresults-0.1.csv + testcode/.

    Each row: test_name, category, real_vulnerability(true/false), cwe.
    The analyzable artifact is testcode/<test_name>.py (a standalone Flask file).

    categories: if given, keep only rows whose category is in this set (overrides
    taint_only). If None and taint_only, default to TAINT_CATEGORIES; if None and
    not taint_only, keep ALL categories.
    """
    owasp_dir = os.path.realpath(os.path.expanduser(owasp_dir))
    csv_path = os.path.join(owasp_dir, "expectedresults-0.1.csv")
    testcode = os.path.join(owasp_dir, "testcode")
    sha = _git_sha(owasp_dir)
    source = f"owasp:BenchmarkPython@{sha}"

    if categories is None and taint_only:
        categories = TAINT_CATEGORIES

    cases = []
    with open(csv_path) as f:
        for row in csv.reader(f):
            if not row or row[0].startswith("#"):
                continue
            name, category, real_vuln, cwe_num = (row + ["", "", "", ""])[:4]
            name = name.strip()
            category = category.strip()
            if categories is not None and category not in categories:
                continue
            py = os.path.join(testcode, f"{name}.py")
            if not os.path.isfile(py):
                continue
            cwe = OWASP_CATEGORY_CWE.get(category, f"CWE-{cwe_num.strip()}")
            cases.append(Case(
                id=f"owasp:{name}",
                path=py,
                cwe=cwe,
                label=(real_vuln.strip().lower() == "true"),
                category=category,
                source=source,
                benchmark="owasp",
                meta={"test_name": name, "csv_cwe": cwe_num.strip()},
            ))
    return cases


def load_redbench_real(redbench_dir, materialize_dir):
    """Load ONLY the real (non-LLM-generated) RedBench samples.

    These live in datasets/<cat>/samples_real.jsonl and carry a `source` field
    (securityeval | github_advisory:GHSA-...). The inline `code` is written out
    to materialize_dir/<id>.py so it can be analyzed like a file case.

    NOTE: every real sample is label=vulnerable (no negatives), so RedBench-real
    measures RECALL only and is a supplementary cross-check, not a P/R benchmark.
    """
    redbench_dir = os.path.realpath(os.path.expanduser(redbench_dir))
    datasets = os.path.join(redbench_dir, "datasets")
    os.makedirs(materialize_dir, exist_ok=True)
    cases = []
    for cat in sorted(os.listdir(datasets)):
        real_path = os.path.join(datasets, cat, "samples_real.jsonl")
        if not os.path.isfile(real_path):
            continue
        with open(real_path) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    d = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if d.get("language", "python") != "python":
                    continue
                cid = d.get("id", "")
                code = d.get("code", "")
                if not cid or not code:
                    continue
                py = os.path.join(materialize_dir, f"{cid}.py")
                with open(py, "w") as out:
                    out.write(code if code.endswith("\n") else code + "\n")
                cases.append(Case(
                    id=f"redbench:{cid}",
                    path=py,
                    cwe=d.get("cwe", "CWE-?"),
                    label=(d.get("label", "vulnerable") == "vulnerable"),
                    category=cat,
                    source=f"redbench-real:{d.get('source', 'unknown')}",
                    benchmark="redbench-real",
                    meta={"severity": d.get("severity", ""),
                          "orig_id": cid},
                ))
    return cases


def load_cve_curated(manifest_path):
    """Load the CVE-curated corpus (stage-3 filtered before/after function pairs).

    Each line is already a Case-compatible dict (id/path/cwe/label/category/
    source/benchmark/meta), produced by the OSV->fix-commit->function-pair
    pipeline under tmp/opencode/cve_curation. `label=True` is the pre-fix
    (vulnerable) function, `label=False` the post-fix (safe) function.

    IMPORTANT LABEL-NOISE CAVEAT: these labels are derived from "function changed
    in a security fix commit", which a hand-audit estimated at only ~60% precision
    (some pre-fix functions are incidental co-changes, not the vulnerable locus).
    The stage-3 heuristic filter removes the obvious noise (boilerplate/test funcs,
    relevance-tokenless bodies, trivial diffs) but residual noise remains. Use this
    corpus for RECALL signal and qualitative analysis; any precision claim requires
    per-case human verification of the sampled subset.
    """
    cases = []
    with open(manifest_path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                d = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not os.path.isfile(d.get("path", "")):
                continue
            cases.append(Case(
                id=d["id"], path=d["path"], cwe=d["cwe"], label=d["label"],
                category=d["category"], source=d["source"],
                benchmark=d.get("benchmark", "cve-curated"),
                meta=d.get("meta", {}),
            ))
    return cases


if __name__ == "__main__":
    import sys
    owasp = sys.argv[1] if len(sys.argv) > 1 else \
        "/mnt/nvme/jiangzhe/tmp/opencode/eval_benchmarks/BenchmarkPython"
    cs = load_owasp(owasp)
    from collections import Counter
    by_cat = Counter((c.category, c.label) for c in cs)
    print(f"OWASP taint-comparable cases: {len(cs)}  (source={cs[0].source if cs else '?'})")
    for (cat, lab), n in sorted(by_cat.items()):
        print(f"  {cat:18s} {'VULN' if lab else 'safe'}: {n}")

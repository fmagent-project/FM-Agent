# FM-Agent Security Plugin Evaluation

Head-to-head evaluation of FM-Agent's **five** security plugins (taint, crypto,
authz, ifc, typestate) against existing detection tools (Bandit, Semgrep CE) on
**third-party and CVE-curated benchmarks**. The consolidated results +
narrative are in [REPORT.md](./REPORT.md); start there.

## Why this design

Four honest constraints shaped the methodology:

1. **Use real, labeled benchmarks — not hand-crafted fixtures.** Our own
   `expected.json` fixtures (under `realworld/`) are good for regression but
   prove nothing about generalization. This harness uses external benchmarks
   (OWASP) plus a CVE-curated corpus, with provenance recorded (commit SHA /
   OSV/GHSA advisory id) for every case.
2. **Synthetic ≠ real.** OWASP is synthetic (100% label-accurate, but its
   one-liner shapes flatter pattern matchers). The CVE corpus is real code (but
   ~60% label-precision). We run BOTH where possible and report the gap — it is
   itself a finding (e.g. Bandit's crypto score reverses from 1.00 synthetic to
   0.50 real).
3. **Our tool is slow and the LLM endpoint is unstable.** Per-function LLM calls
   against the `sss` relay hit HTTP 524 on big functions. So baselines (fast,
   free) run on the **full** benchmark; our tool runs on a **stratified sample**;
   the comparison is computed on the **intersection**.
4. **跑完≠跑对.** Scores are not trusted until a sample of verdicts is manually
   audited (true bug vs label artifact). Use `audit.py`, which prioritizes the
   most informative cases (our FPs/FNs, tool disagreements, fail-closed ERRORs)
   and prints the source + every tool's verdict on one screen.

## Benchmarks

| Benchmark | Plugins | Cases used | Labels | Provenance |
|---|---|---|---|---|
| **OWASP BenchmarkPython v0.1** | taint, crypto | taint 677 / crypto 477 (of 1230) | per-file `true`/`false` + CWE, balanced, synthetic | `OWASP-Benchmark/BenchmarkPython` @ `f1291485808b` |
| **CVE-curated corpus** | all 5 | 903 filtered (before/after fn pairs) | per-case vuln/safe from fix commit, real, ~60% label precision | OSV.dev PyPI fix commits; per-case `osv:<id>|<CVE>` — see [cve_curation/BENCHMARK_CVE.md](./cve_curation/BENCHMARK_CVE.md) |
| RedBench (real subset, early authz probe) | authz | 3 unique | vulnerable-only | `Tbhuvan/redbench` @ `00b32c3223c4` (superseded by CVE corpus) |

**Excluded:** RedBench's LLM-*generated* bulk and any fabricated cases — the
constraint is "prefer real, not fabricated". The CVE corpus is the primary
benchmark for authz/ifc/typestate (no public benchmark exists) and a real-code
cross-check for taint/crypto (which also have clean synthetic OWASP coverage).

**OWASP category → plugin mapping:** taint = pathtraver(22)/sqli(89)/cmdi(78)/
xss(79)/deserialization(502)/codeinj(94)/redirect(601)/ldapi(90)/xpathi(643)/
xxe(611); crypto = hash(328)/weakrand(330). The CVE corpus covers the full CWE
set each plugin models (see BENCHMARK_CVE.md).

## Baselines

| Tool | Invocation | Notes |
|---|---|---|
| **Bandit** 1.9.4 | `python -m bandit -f json <file>` | AST pattern matcher; CWE in `results[].issue_cwe.id`. No taint tracking. |
| **Semgrep** 1.167.0 (CE) | `semgrep scan --config p/default --config p/security-audit --json --metrics off <file>` | CE registry rules (no Pro login). Pattern + light dataflow; CWE in `extra.metadata.cwe[]`. Low taint recall out of the box — this is the honest default a user gets. |

CodeQL is not yet wired in (heavier setup: DB build per case). It is the natural
next baseline — the only tool with comparable data-flow coverage on the harder
CWEs — for a precision-focused follow-up.

## The comparison unit

Tools emit different shapes; the normalizer (`normalize.py`) collapses all onto
a **per-case Detection**:
- `detected`: did the tool flag this case at all?
- `cwes`: the set of CWE ids it attributed.
- our tool's per-function verdicts are collapsed per case; **only the case
  file's own functions count** (shared `helpers/` are analyzed for
  interprocedural composition but their standalone verdicts are NOT aggregated,
  or a vulnerable shared helper would contaminate every case).

**CWE-family matching** (`CWE_FAMILIES`): a tool that flags CWE-77 on a CWE-78
case still "found the bug" (command-injection family). Generic-injection parent
CWE-74 matches any injection child. Conservative — only established synonyms.

Two scoring views (`score.py`), reported side by side:
- **detection**: TP = vulnerable case flagged (any CWE). "Right file?"
- **cwe-aware**: TP also requires CWE-family match. "Right bug, right category?"

## Files

| File | Role |
|---|---|
| `benchmarks.py` | Loaders → unified `Case(id, path, cwe, label, category, source, benchmark)`. `load_owasp` (OWASP), `load_cve_curated` (CVE corpus). |
| `normalize.py` | CWE-family matcher (injection + crypto families) + per-plugin verdict-vocab collapse to `Detection`. |
| `run_baselines.py` | Run Bandit + Semgrep over cases → `out_baselines*/baseline_detections.json` (+ raw cache, partial-run reconstruction). |
| `stratify.py` | Seeded, CWE-balanced sample per plugin → `sample_<plugin>[_cve].json` (`--plugin`). |
| `run_ours.py` | Stage each case in an isolated proj dir, run the chosen plugin (`--plugin`), collapse → `ours_<plugin>[_cve]_detections.json` (checkpointed per case; crash→fail-closed ERROR). |
| `score.py` | Two-view (detection + cwe-aware) P/R/F1 per tool per CWE → `comparison_*.json`. |
| `audit.py` | Prioritized manual-audit view (跑完≠跑对): surfaces our-FP / our-FN / tool-disagreement / fail-closed ERROR cases with source + all verdicts. |
| `cve_curation/` | 3-stage OSV→fix-commit→function-pair pipeline + 903-case corpus + `BENCHMARK_CVE.md`. |

Outputs: `comparison_taint.json` / `comparison_crypto.json` (OWASP) and
`comparison_{taint,crypto,authz,ifc,typestate}_cve.json` (CVE).

## Reproduce

```bash
# OWASP head-to-head (taint, crypto) — synthetic, clean labels
.venv/bin/python eval/stratify.py --plugin taint   --per-category 8
.venv/bin/python eval/run_ours.py  --plugin taint   --sample eval/sample_taint.json
# baselines run over the full benchmark, then:
.venv/bin/python eval/score.py     --sample eval/sample_taint.json --ours eval/ours_detections.json \
  --baselines eval/out_baselines/baseline_detections.json --out eval/comparison_taint.json

# CVE head-to-head (all 5 plugins) — real code, ~60% label precision
#   build corpus once: see cve_curation/BENCHMARK_CVE.md (stage1→stage2→stage3)
.venv/bin/python eval/stratify.py  --plugin <p>      # writes sample_<p>_cve.json from cve corpus
.venv/bin/python eval/run_ours.py  --plugin <p> --sample eval/sample_<p>_cve.json \
  --out eval/ours_<p>_cve_detections.json --helpers ''
.venv/bin/python eval/score.py     --sample eval/sample_<p>_cve.json \
  --ours eval/ours_<p>_cve_detections.json \
  --baselines eval/out_baselines_<p>_cve/baseline_detections.json \
  --out eval/comparison_<p>_cve.json
```

## Status / scope

All five plugins evaluated. See [REPORT.md](./REPORT.md) for consolidated results.

- **taint / crypto**: head-to-head on BOTH OWASP (synthetic) and CVE (real).
- **authz / ifc / typestate**: head-to-head on the CVE-curated corpus (no public
  benchmark exists for these properties — we built one).
- **Open**: per-case fix-diff verification of the CVE corpus (to lift directional
  P/R to a clean precision claim); CodeQL as a heavyweight data-flow baseline.

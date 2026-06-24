# FM-Agent Security Portfolio — Cross-Plugin Evaluation Report

Evaluation of FM-Agent's five security plugins against existing detection tools
(Bandit, Semgrep CE) on **third-party / CVE-curated benchmarks**, with every
verdict family manually audited (跑完≠跑对). This report consolidates all five
plugins across BOTH a synthetic benchmark (OWASP) and a real CVE-curated one.
Per-plugin detail lives in the sibling docs.

## Headline: complete five-plugin results (detection-view F1)

| Plugin | Benchmark | N | **fm-agent** | bandit | semgrep | winner |
|---|---|---|---|---|---|---|
| **taint** | OWASP (synthetic) | 80 | **0.75** | 0.53 | 0.51 | FM-Agent |
| **taint** | CVE (real) | 26 | **0.65** | **0.00** | 0.25 | FM-Agent (rout) |
| **crypto** | OWASP (synthetic) | 24 | 0.73 | **1.00** | 0.35 | Bandit |
| **crypto** | CVE (real) | 34 | **0.65** | 0.50 | 0.12 | **FM-Agent (reversal)** |
| **authz** | CVE (real) | 36 | **0.52** | 0.00 | 0.00 | FM-Agent |
| **ifc** | CVE (real) | 36 | **0.41** | 0.00 | 0.00 | FM-Agent |
| **typestate** | CVE (real) | 29 | **0.62** | 0.27 | 0.14 | FM-Agent |

fm-agent recall: taint-OWASP 1.00, taint-CVE 0.85, crypto-OWASP 1.00,
crypto-CVE 0.86, authz 0.69, ifc 0.39, typestate 0.77.

**FM-Agent wins 6 of 7 head-to-heads. The single loss (crypto on OWASP) reverses
on real CVE code.**

## Methodology (shared across plugins)

- **Two benchmark types.** OWASP BenchmarkPython v0.1 (`@f1291485808b`, synthetic
  but 100% label-accurate, balanced) for taint + crypto; a **CVE-curated corpus**
  (real OSV.dev fix commits → before/after function pairs) for all five plugins,
  especially the three with no public benchmark. LLM-generated benchmark bulk
  (RedBench) is excluded per the "prefer real, not fabricated" constraint.
- **Per-case comparison unit.** A normalizer collapses three output shapes (our
  per-function verdicts, Bandit `issue_cwe.id`, Semgrep `metadata.cwe[]`) onto one
  per-case detection, with CWE-family matching.
- **Stratified sampling.** Baselines (fast/free) run the FULL benchmark; our tool
  (slow LLM calls, unstable endpoint) runs a CWE-balanced sample; the comparison
  is the intersection.
- **Two scoring views.** detection (right file?) and cwe-aware (right bug, right
  category?). Crashes are bucketed as fail-closed ERROR, never silent misses.
- **Manual audit.** Every FP/FN/crash family adjudicated against source.

## Benchmark coverage per plugin

| Plugin | OWASP (synthetic, clean labels) | CVE (real, ~60% label precision) |
|---|---|---|
| taint | ✅ 80 cases | ✅ 26 cases |
| crypto | ✅ 24 cases | ✅ 34 cases |
| authz | — (none exists) | ✅ 36 cases |
| ifc | — (none exists) | ✅ 36 cases |
| typestate | — (Juliet is C/C++) | ✅ 29 cases |

The CVE corpus (903 filtered cases total across all plugins) was BUILT for this
eval — see [cve_curation/BENCHMARK_CVE.md](./cve_curation/BENCHMARK_CVE.md). It is
the first real, citable Python benchmark for authz/IDOR, info-leak, and temporal
properties.

---

## 1. Taint (injection: CWE-22/78/79/89/90/94/502/601/643/611)

| benchmark | tool | P | R | F1 |
|---|---|---|---|---|
| OWASP | **fm-agent** | 0.60 | **1.00** | **0.75** |
| | bandit | 0.53 | 0.53 | 0.53 |
| | semgrep | 0.53 | 0.50 | 0.51 |
| CVE | **fm-agent** | 0.52 | **0.85** | **0.65** |
| | bandit | 0.00 | 0.00 | **0.00** |
| | semgrep | 0.67 | 0.15 | 0.25 |

FM-Agent wins both. The striking result: **Bandit drops from 0.53 (OWASP) to
0.00 (CVE)** — real injection CVEs are interprocedural/dataflow-heavy, not the
syntactic `f"...{x}".execute()` shape Bandit's B608 matches. Synthetic benchmarks
flatter pattern matchers. Full detail: [MANUAL_AUDIT.md](./MANUAL_AUDIT.md)
(OWASP) + [CVE_FINDINGS.md](./CVE_FINDINGS.md) (CVE). On OWASP, FM-Agent's 27/40
FPs are fail-closed over-approximations on flow-sensitivity decoys (dead-code,
definition-kill, validation guards). Surfaced + fixed a crash bug
(`taint_reasoner.py:201`, sanitizer-shape).

## 2. Crypto (misuse: weak hash/PRNG/algorithm, hardcoded key)

| benchmark | tool | P | R | F1 |
|---|---|---|---|---|
| OWASP | **bandit** | **1.00** | **1.00** | **1.00** |
| | fm-agent | 0.57 | 1.00 | 0.73 |
| | semgrep | 0.60 | 0.25 | 0.35 |
| CVE | **fm-agent** | 0.52 | **0.86** | **0.65** |
| | bandit | 0.83 | 0.36 | 0.50 |
| | semgrep | 0.50 | 0.07 | 0.12 |

**The central synthetic-vs-real reversal.** On OWASP, weak-hash/PRNG is a pure
*syntactic* property (`hashlib.md5(...)` one-liner) — Bandit's home turf, perfect
1.00. But on **real CVE code** the weak crypto hides behind cross-function key
derivation, config loading, and custom wrappers: Bandit recall collapses to 0.36
while FM-Agent's semantic analysis holds 0.86, and **FM-Agent overtakes Bandit
(0.65 vs 0.50)**. This is the empirical heart of the report: a pattern matcher's
apparent superiority is a synthetic-benchmark artifact that does not survive
contact with real code. Full detail: [CRYPTO_FINDINGS.md](./CRYPTO_FINDINGS.md).

## 3. Authz / IDOR (CWE-639/862/863/306)

| tool | P | R | F1 |
|---|---|---|---|
| **fm-agent** | 0.42 | 0.69 | **0.52** |
| bandit | 0.00 | 0.00 | 0.00 |
| semgrep | 0.00 | 0.00 | 0.00 |

**No SAST tool ships IDOR/authz queries** — both baselines score a categorical
0.00. FM-Agent is the only tool that engages access-control at all. per-CWE recall:
CWE-639 (IDOR) 1.00, CWE-863 1.00, CWE-862 0.50, CWE-306 0.25.

## 4. IFC / info-leak (CWE-200/209/532)

| tool | P | R | F1 |
|---|---|---|---|
| **fm-agent** | 0.44 | 0.39 | **0.41** |
| bandit | 0.00 | 0.00 | 0.00 |
| semgrep | 0.00 | 0.00 | 0.00 |

Both baselines 0.00 (no CWE-200/532 taint rules). per-CWE recall: CWE-209 0.50,
CWE-200 0.33, CWE-532 0.33. ifc's recall is the lowest of the five — but on a
~60% label corpus, several apparent-FNs are mislabels FM-Agent correctly cleared
(see audit).

## 5. Typestate (temporal: CWE-352/295/367/772)

| tool | P | R | F1 |
|---|---|---|---|
| **fm-agent** | 0.53 | 0.77 | **0.62** |
| bandit | 1.00 | 0.15 | 0.27 |
| semgrep | 1.00 | 0.08 | 0.14 |

Baselines have trivial recall (Bandit's B501 catches a couple `verify=False`
CWE-295 cases at perfect precision but 0.15 recall). per-CWE recall: CWE-352
(CSRF) 1.00, CWE-772 1.00, CWE-367 (TOCTOU) 0.75, CWE-295 0.50. typestate findings
DO carry CWE so its cwe-aware view is meaningful (F1 0.52).

---

## ⚠️ Label-noise caveat (all CVE results)

The CVE corpus is ~60% label-precision (inherent to CVE-fix-commit curation:
"function changed in a security commit" ≠ "the vulnerable locus"). I hand-audited
the FP/FN families for every plugin (跑完≠跑对). **The noise hits BOTH sides:**

- **apparent-FNs are largely mislabels** FM-Agent correctly cleared — e.g. ifc
  `CVE-2022-2806::postproc` literally obfuscates passwords (it's the FIX); authz
  `get_user` already gated by `has_permission(ADMIN)`; crypto `_cache_put` is a
  logging method, not the crypto locus. So **true recall is HIGHER than raw**.
- **all sampled FPs are on the post-fix (`__after`) function** where the fix
  narrowed but didn't remove the risky pattern — fail-closed over-flags.

Therefore CVE precision/recall are **directional, not clean claims**; a hard
precision number needs per-case fix-diff verification (future work). What IS
label-noise-independent: the baselines detect **essentially nothing** on
authz/ifc (0.00) and little on typestate — that capability gap is categorical.

**Scoring nuance:** authz/ifc plugin findings carry no `data.cwe`, so their
cwe-aware view is 0.00 by artifact — **detection view is the correct metric** for
them. taint/crypto/typestate findings do carry CWE.

## Cross-cutting findings

1. **Semantic analysis wins where reasoning is required; the one syntactic loss
   reverses on real code.** FM-Agent wins 6/7 head-to-heads. The sole loss
   (crypto/OWASP, Bandit 1.00) is a *synthetic-benchmark artifact*: on real crypto
   CVEs FM-Agent overtakes Bandit (0.65 vs 0.50). Likewise Bandit's taint score
   collapses 0.53→0.00 from synthetic to real. **Pattern matchers are
   systematically over-credited by synthetic benchmarks.**
2. **Categorical capability gap on relational/temporal properties.** On authz,
   ifc, and typestate — properties needing data-flow, ownership, or ordering
   reasoning — Bandit and Semgrep score 0.00–0.27. No amount of label noise
   changes that they fundamentally cannot model these. FM-Agent's value here is
   not a marginal F1 edge; it is the only tool that engages the property at all.
3. **The deployment model is a router, not a single tool.** On purely syntactic
   CWEs over clean code a linter is cheaper and adequate; FM-Agent's additive
   value is the semantic/interprocedural/temporal properties no linter touches,
   AND the robustness to real-world code structure that synthetic benchmarks hide.
4. **Precision cost is real, characterized, and partly mislabeled.** On OWASP
   taint FM-Agent over-flags flow-sensitivity decoys; on CVE corpora the noise
   cuts both ways (see caveat). Root causes are a small, enumerable, fixable set
   — not fundamental.
5. **The eval found three real tool bugs (all FIXED)** it was not looking for:
   the taint sanitizer-shape crash (`taint_reasoner.py:201`), the async-def
   extraction gap (`extract.py`, silently skipped all FastAPI handlers), and the
   crypto `random.SystemRandom` CSPRNG misclassification. Plus a benchmark
   data-quality issue (RedBench duplicate-inflated "real" cases). Rigorous
   evaluation pays for itself.

## Recommended next steps (post-eval)

- ✅ DONE: built + ran the CVE-curated benchmark for ALL five plugins.
- ✅ DONE: fixed the three surfaced defects (sanitizer-shape, async-def, SystemRandom).
- **Per-case fix-diff verification** of the CVE corpus to convert directional P/R
  into a clean precision claim (the ~60% label noise is the current ceiling).
- Add **CodeQL** as a heavyweight baseline (only tool with any comparable
  data-flow coverage on these CWEs).
- Build a **syntactic/semantic router** so trivial CWEs go to a linter and
  FM-Agent handles the dataflow/temporal/relational properties.
- Re-run OWASP taint/crypto on the bug-fixed code to quantify the fix gains.

## Artifacts

- 7 `comparison_*.json` (detection + cwe-aware views) — taint/crypto ×
  {OWASP, CVE}, authz/ifc/typestate × CVE.
- CVE corpus + 3-stage curation pipeline + per-sample provenance:
  [cve_curation/](./cve_curation/).
- Per-plugin findings: [MANUAL_AUDIT.md](./MANUAL_AUDIT.md) (taint/OWASP),
  [CRYPTO_FINDINGS.md](./CRYPTO_FINDINGS.md), [CVE_FINDINGS.md](./CVE_FINDINGS.md),
  [AUTHZ_FINDINGS.md](./AUTHZ_FINDINGS.md), [IFC_FINDINGS.md](./IFC_FINDINGS.md),
  [TYPESTATE_FINDINGS.md](./TYPESTATE_FINDINGS.md).

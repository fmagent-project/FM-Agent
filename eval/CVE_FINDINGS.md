# CVE-Curated Head-to-Head: all five plugins on real CVE code

Every FM-Agent plugin evaluated on the **CVE-curated corpus** (real OSV.dev fix
commits → before/after function pairs). See
[BENCHMARK_CVE.md](./cve_curation/BENCHMARK_CVE.md) for corpus construction.

This complements the synthetic OWASP head-to-head (taint/crypto only): the CVE
results are the **real-code** test. The headline is the synthetic-vs-real
reversal — pattern matchers that look strong on OWASP collapse on real code.

CWE-stratified balanced samples: taint 26 (13V/13s), crypto 34 (14V/20s),
authz 36 (16V/20s), ifc 36 (18V/18s), typestate 29 (13V/16s). Baselines: Bandit +
Semgrep CE.

## ⚠️ Read the label-noise caveat FIRST

This corpus has ~60% label precision (CVE-fix-commit curation; see BENCHMARK_CVE.md).
**Raw P/R below is directional, not a clean claim** — the hand-audit (below) shows
noise hits BOTH sides. The label-noise-INDEPENDENT findings (baselines ~0.00 on
relational properties; the synthetic→real reversal) are the robust takeaways.

## Scores (detection view)

| plugin | tool | TP | FP | FN | TN | P | R | F1 |
|---|---|---|---|---|---|---|---|---|
| **taint** | **fm-agent** | 11 | 10 | 2 | 3 | 0.52 | 0.85 | **0.65** |
| | bandit | 0 | 0 | 13 | 13 | 0.00 | 0.00 | **0.00** |
| | semgrep | 2 | 1 | 11 | 12 | 0.67 | 0.15 | 0.25 |
| **crypto** | **fm-agent** | 12 | 11 | 2 | 9 | 0.52 | 0.86 | **0.65** |
| | bandit | 5 | 1 | 9 | 19 | 0.83 | 0.36 | 0.50 |
| | semgrep | 1 | 1 | 13 | 19 | 0.50 | 0.07 | 0.12 |
| **authz** | **fm-agent** | 11 | 15 | 5 | 5 | 0.42 | 0.69 | **0.52** |
| | bandit / semgrep | 0 | 0 | 16 | 20 | 0.00 | 0.00 | 0.00 |
| **ifc** | **fm-agent** | 7 | 9 | 11 | 9 | 0.44 | 0.39 | **0.41** |
| | bandit / semgrep | 0 | ~ | 18 | ~ | 0.00 | 0.00 | 0.00 |
| **typestate** | **fm-agent** | 10 | 9 | 3 | 7 | 0.53 | 0.77 | **0.62** |
| | bandit | 2 | 0 | 11 | 16 | 1.00 | 0.15 | 0.27 |
| | semgrep | 1 | 0 | 12 | 16 | 1.00 | 0.08 | 0.14 |

fm-agent per-CWE detection recall:
- taint: CWE-22 1.00, CWE-502 1.00, + others (full set in comparison_taint_cve.json)
- crypto: CWE-321/327/328/330/338 = 1.00, CWE-326 0.50
- authz: CWE-639 (IDOR) 1.00, CWE-863 1.00, CWE-862 0.50, CWE-306 0.25
- ifc: CWE-209 0.50, CWE-200 0.33, CWE-532 0.33
- typestate: CWE-352 (CSRF) 1.00, CWE-772 1.00, CWE-367 (TOCTOU) 0.75, CWE-295 0.50

## Finding 1: the synthetic→real reversal (taint + crypto)

The same two plugins that have clean OWASP coverage tell a different story on real
CVE code, and the difference is entirely in the BASELINES:

| plugin | tool | OWASP F1 | CVE F1 | Δ |
|---|---|---|---|---|
| taint | bandit | 0.53 | **0.00** | collapse |
| taint | fm-agent | 0.75 | 0.65 | holds |
| crypto | bandit | **1.00** | 0.50 | collapse |
| crypto | fm-agent | 0.73 | 0.65 | holds |

- **taint:** Bandit 0.53 → **0.00**. Real injection CVEs are interprocedural /
  dataflow-heavy; the vulnerable value reaches the sink across calls, not as the
  literal `f"...{x}".execute()` one-liner Bandit's B608 matches.
- **crypto:** Bandit 1.00 → 0.50, and **FM-Agent overtakes it (0.65 vs 0.50)**.
  Real weak-crypto hides behind cross-function key derivation, config loading, and
  custom wrappers — not the `hashlib.md5(...)` one-liner OWASP plants.

**The conclusion:** Bandit's apparent strength on OWASP is a synthetic-benchmark
artifact. FM-Agent's semantic analysis is roughly benchmark-invariant (0.75→0.65,
0.73→0.65) because it reasons about the code rather than matching surface shapes.

## Finding 2: categorical capability gap (authz / ifc / typestate)

**Bandit and Semgrep are near-totally blind to all three relational/temporal
property classes.**
- authz/IDOR: both **0.00** — no SAST tool ships IDOR queries. FM-Agent is the
  only tool that detects anything.
- ifc/info-leak: both **0.00** — no CWE-200/532 taint rules.
- typestate: Bandit 0.15 / Semgrep 0.08 recall (Bandit's B501 catches a few
  `verify=False` CWE-295 cases) vs FM-Agent 0.77.

This is invariant to label noise: even if every fm-agent detection were on a noisy
label, the baselines detect essentially NOTHING here. FM-Agent's *capability* to
engage these properties at all is the headline.

## Hand-audit (跑完≠跑对) — what the raw numbers hide

I read source for samples of every FP and FN bucket across all five plugins.
**Label noise hits both sides, so raw P/R understates true performance:**

### apparent-FN (vuln-labeled, fm-agent did NOT flag) — mostly MISLABELS
- authz `CVE-2024-51493::get_user` — pre-fix function ALREADY has
  `current_user.has_permission(Permissions.ADMIN)`; not the vulnerable locus.
- ifc `CVE-2022-2806::postproc` — literally obfuscates passwords
  (`Password.type=********`); this is the FIX, mislabeled vulnerable.
- taint `CVE-2022-23915::push` — thin wrapper; the cmdi locus is the arg
  construction elsewhere, not this function.
- crypto `CVE-2013-2166::_cache_put` — a docstring+logging method, not the
  weak-crypto locus.
- (genuine misses exist too, e.g. ifc CWE-200 cases where data flows to a response
  without an obvious sink keyword — real recall gaps.)

### apparent-FP (safe/fixed-labeled, fm-agent flagged) — ALL on the post-fix function
- Every sampled FP is the `__after` (fixed) version where the fix narrowed but
  didn't remove the risky pattern (e.g. taint `get_available_name` still does path
  manipulation post-fix; crypto `set_password` still touches password encoding;
  typestate `CVE-2021-4162` still reads `request.form` around csrf handling). Some
  are genuine fail-closed over-flags, some arguably defensible.

**Audit conclusion:** true recall is HIGHER than the raw number (many "FN" are
mislabels FM-Agent correctly cleared), and a clean precision claim needs per-case
fix-diff verification (future work).

## Scoring nuance: authz/ifc cwe-aware = 0.00 is an artifact

The authz and ifc plugins emit findings WITHOUT a `data.cwe` field, so the
cwe-aware view scores them 0.00 TP — a reporting artifact, not a detection failure.
**For authz/ifc the detection view is the correct metric.** taint, crypto, and
typestate findings DO carry CWE, so their cwe-aware views are meaningful.

## Bottom line

The CVE-curated benchmark gives all five plugins a real-code evaluation, including
the three that previously had no public benchmark. Two robust, label-noise-
independent findings emerge: (1) the **synthetic→real reversal** — pattern
matchers over-credited by OWASP collapse on real CVEs while FM-Agent holds; (2) the
**categorical gap** — baselines score ~0.00 on the relational/temporal properties
FM-Agent is built for. Precision is caveated by ~60% label noise pending per-case
fix-diff verification; recall is directionally strong and the capability gap is
structural.

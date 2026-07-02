# Authz/IDOR Plugin Evaluation (CWE-639 / CWE-306)

> **⚠️ SUPERSEDED for the headline result.** This doc was written during the
> early recon phase, when no usable benchmark existed and only a 3-case recall
> probe was possible. We have since **built a CVE-curated benchmark** and run a
> real head-to-head: authz **fm-agent F1 0.52 (R 0.69) vs Bandit/Semgrep 0.00**
> on 36 CWE-stratified real CVE cases. See [CVE_FINDINGS.md](./CVE_FINDINGS.md)
> and [REPORT.md](./REPORT.md) §3 for the current results. The sections below are
> retained for provenance: the recon that proved no public IDOR benchmark/baseline
> exists, the RedBench duplicate-inflation finding, and the async-def extraction
> bug surfaced here (now fixed).

## Scope & honest constraints

The authz plugin models **IDOR-BOLA** (missing-authorization with resource
binding) — maps to CWE-639 (IDOR) and partially CWE-306 (missing auth). It does
NOT model CWE-287 (improper authentication) or CWE-798 (hardcoded creds), so
those RedBench categories are excluded as out-of-scope (not forced through).

**No usable public benchmark exists** (confirmed in prior recon: OWASP Benchmark
omits access control entirely; CodeQL/Bandit/Semgrep ship ZERO IDOR queries).
This is itself a finding: **no SAST baseline even attempts IDOR**, so there is no
head-to-head — only a qualitative recall probe of our tool.

### Data source & a data-quality finding

RedBench-real (CVE/GHSA + SecurityEval) authz subset, analyzable-Python only.
After **deduplication** the "18+6" advertised samples collapse to **3 unique
cases** — RedBench shipped byte-identical copies (ghsa-639-002/004/006 identical
md5 e4869ddd; ghsa-306-002/004/006 identical md5 c42945da). Reporting 3, not 7.

| case | CWE | source | unique |
|---|---|---|---|
| seceval-306-001 | CWE-306 | SecurityEval | ✓ |
| ghsa-306-002 | CWE-306 | GHSA-vwmf-pq79-vjvx | ✓ (3 copies in dataset) |
| ghsa-639-002 | CWE-639 | GHSA-rf6x-r45m-xv3w | ✓ (3 copies in dataset) |

All 3 are label=vulnerable (recall-only; no safe negatives, so precision is not
measurable here).

## Results (recall probe, 3 unique vulnerable cases)

| case | FM-Agent | adjudication |
|---|---|---|
| seceval-306-001 | **DETECTED** (VULNERABLE) | TP. Flask app with an `ensure_logged_in` decorator that checks `session['username'] is None` but a route missing the decorator → missing-auth. FM-Agent flagged it. |
| ghsa-306-002 | **MISS (extraction gap)** | `async def build_public_tmp(...)` — see bug below. Tool extracted 0 functions, produced no verdict. NOT a real analysis miss — a tooling blind spot. |
| ghsa-639-002 | **MISS (extraction gap)** | `async def delete_api_key_route(...)` (FastAPI) — same extraction gap. |

**Recall = 1/3 analyzable, but 2/3 are blocked by a fixable extraction bug, not
an analysis failure.** On the one case the extractor handled, the tool detected
the missing-auth correctly.

## TOOL BUG FOUND (eval-validity): `async def` not extracted

`src/extract.py:469` matches Python functions with `re.match(r'^(\s*)def\s+(\w+)\s*\(', line)`
— this does NOT match `async def`. Any FastAPI / async handler is silently
skipped → the plugin sees zero functions → no verdict. Both ghsa-639-002 and
ghsa-306-002 are FastAPI `async def` routes, so the tool never analyzed them.

- **Impact:** systematic blind spot on async/FastAPI codebases across ALL plugins
  (extraction is shared), not just authz.
- **Recommended fix (post-eval, NOT applied mid-run):** change the regex to
  `r'^(\s*)(?:async\s+)?def\s+(\w+)\s*\('`. Low-risk one-line change; should be
  validated against the existing extraction tests before applying.
- This is the second real bug the evaluation surfaced (after the taint
  sanitizer-shape crash at taint_reasoner.py:201).

## Bottom line

The authz/IDOR evaluation is **qualitative, not statistical** — the public-data
desert for IDOR (no benchmark, no baseline) plus RedBench's duplicate-inflated
3-real-case subset means we cannot produce precision/recall tables comparable to
taint/crypto. What we CAN say honestly:
1. **No existing SAST tool attempts IDOR**; our tool is the only one that even
   tries — a categorical capability, not a marginal score.
2. On the one async-free real CVE case, it correctly detected the missing-auth.
3. The eval surfaced a real, fixable extraction bug (async def) that would
   otherwise silently degrade every plugin on modern async Python.

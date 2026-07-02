# CVE-Curated Benchmark (authz / ifc / typestate)

A real, citable benchmark for the three plugins that had **no public Python
benchmark** (confirmed in prior recon: OWASP omits them; CVEfixes/PyVul/CrossVul
have near-zero Python coverage for these CWEs; all C/C++ vuln datasets are
irrelevant). Built by curating CVE fix commits from OSV.dev into before/after
function pairs.

## What it covers

903 function-level cases (458 vulnerable / 445 safe) across 11 CWEs:

| plugin | CWEs | cases |
|---|---|---|
| **authz** | CWE-639 (IDOR), CWE-862/863 (missing/incorrect authz), CWE-306 (missing auth) | 276 |
| **ifc** | CWE-200 (info exposure), CWE-209 (error-msg leak), CWE-532 (log leak) | 351 |
| **typestate** | CWE-352 (CSRF), CWE-295 (cert validation), CWE-367 (TOCTOU), CWE-772 (resource leak) | 276 |

Per-CWE: CWE-200=293, CWE-352=159, CWE-863=92, CWE-295=97, CWE-639=71, CWE-306=64,
CWE-862=35, CWE-209=34, CWE-532=38, CWE-367=18, CWE-772=2.

## How it was built (3-stage pipeline, all in `eval/cve_curation/`)

```
OSV PyPI bulk (20,706 advisories)
  │  stage1_osv_candidates.py  — filter to target CWEs + locatable fix
  ▼
709 candidates (388 with a direct GitHub commit URL)
  │  stage2_extract_pairs.py   — zero-API: fetch <sha>.patch + raw AFTER file,
  │                              reverse-apply patch → BEFORE file, extract every
  │                              CHANGED function as a (vulnerable, safe) pair
  ▼
838 raw function pairs from 225 CVEs
  │  stage3_audit_filter.py    — drop boilerplate/test funcs, relevance-tokenless
  │                              bodies, trivial diffs
  ▼
903 cases kept (458 vuln + 445 safe)  ·  cve_cases.filtered.jsonl
```

Design choices that matter:
- **Balanced (before+after).** Each CVE yields both the pre-fix function
  (vulnerable) and post-fix function (safe), so precision is *measurable* — unlike
  RedBench-real / raw CVE feeds which are vulnerable-only (recall-only).
- **Zero-API.** GitHub unauthenticated API is 60/hr; we use only un-throttled
  `github.com/.../commit/<sha>.patch` + `raw.githubusercontent.com`, reconstructing
  the before-file by reverse-applying the patch locally. No token, no rate limit.
- **Provenance per case.** Every case `source` carries `osv:<id>|<CVE>` so any
  case traces back to its advisory and fix commit.

## ⚠️ LABEL-NOISE CAVEAT (read before using)

CVE-fix-commit curation has a well-documented label-accuracy problem: CVEfixes
reports **~48% function-level precision** on its Python slice — "a function changed
in a security commit" is NOT the same as "this function is the vulnerable locus".
Security commits routinely co-change incidental functions (helpers, `__repr__`,
error pages, validation utilities) alongside the real fix.

**Hand-audit of this corpus (14 sampled vulnerable cases): ~60% precision.** The
stage-3 heuristic filter raises precision above raw CVEfixes by dropping the
obvious noise, but **residual noise remains**. Examples found in sampling:
- TP: `add()` logging `str(sys.exc_info())` into a user message (CWE-209) ✓
- TP: `_api_args_item()` returning raw argv (CWE-200) ✓
- NOISE: `get_network_params()` (ip/port validation, kept under CWE-639 but no
  ownership logic — incidental co-change) ✗
- NOISE: `error_page()` (CSRF CVE, but this function isn't the state-changing
  locus) ✗

**Consequences for how to use this benchmark:**
1. **Recall is trustworthy** — if a case is labeled vulnerable and the tool flags
   it, that's a real signal (the file genuinely had a CVE).
2. **Precision is NOT directly trustworthy** — a "false positive" on a safe (post-
   fix) case is real, but a "true positive" on a noisy vulnerable case may be
   crediting detection of a non-vulnerability. Per-case human verification of the
   scored subset is required before any precision claim.
3. **Recommended use:** stratified sample → run tool → **hand-audit every scored
   case** (same 跑完≠跑对 discipline as taint/crypto), reporting precision only on
   the human-verified subset, recall on the full labeled set with the noise caveat
   stated.

This is exactly why the taint/crypto head-to-heads used OWASP (clean, synthetic,
100% label accuracy): for those CWEs a clean benchmark exists. For authz/ifc/
typestate no clean benchmark exists, so this curated corpus is the honest best
available — strong for recall and qualitative analysis, caveated for precision.

## Reproduce

```bash
cd eval/cve_curation
# stage 1 (needs OSV PyPI bulk: storage.googleapis.com/osv-vulnerabilities/PyPI/all.zip)
python3 stage1_osv_candidates.py --osv-dir <pypi_json_dir> --out candidates.jsonl
# stage 2 (network: github .patch + raw) — long, network-bound; run in tmux
python3 stage2_extract_pairs.py --candidates candidates.jsonl --out-dir cases --manifest cve_cases.jsonl
# stage 3 (offline filter)
python3 stage3_audit_filter.py --manifest cve_cases.jsonl --kept cve_cases.filtered.jsonl
```

Loader: `eval/benchmarks.py::load_cve_curated("eval/cve_curation/cve_cases.filtered.jsonl")`.

## Status

- ✅ Corpus built, filtered, persisted in-repo, loader wired.
- ✅ Run through all plugins on a stratified sample with full hand-audit — results
  in [../REPORT.md](../REPORT.md) (original five plugins).
- ✅ **A harder, whole-file variant now exists** for interprocedural evaluation:
  `stage2_hard_extract.py` (whole changed file, not one function) +
  `stage3_hard_filter.py` → `cve_cases_hard.filtered.jsonl` (median 235 LOC,
  ~9 functions/case, 69% multi-file). Covers all **seven** plugins and adds a
  direct-LLM baseline. See [../REPORT_HARD.md](../REPORT_HARD.md).
- ⏳ **Open**: per-case fix-diff verification to convert directional P/R into a
  clean precision claim (the ~60% label noise is the current ceiling).

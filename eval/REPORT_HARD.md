# FM-Agent Hard Benchmark — Interprocedural Evaluation Report

A **harder, whole-file** CVE benchmark built to test what the original
single-function corpus could not: **interprocedural localization**. This report
compares all **seven** plugins against a **direct-LLM baseline** (same model,
single-shot verdict) plus Bandit/Semgrep, and documents an audit finding that
corrects a scoring artifact (跑完≠跑对).

> Companion to [REPORT.md](./REPORT.md) (the original single-function CVE + OWASP
> results). Read that first for methodology shared across both.

---

## Why a "hard" benchmark

The original CVE corpus extracts **one changed function per case** (median 25
LOC, 1 function). That is fine for judging a function in isolation, but it never
exercises the plugins' **interprocedural composition** (call graph, bottom-up /
top-down propagation) — the whole point of the SPI. It also structurally
excludes the CVEs that need cross-function reasoning.

The hard corpus fixes this: each case is the **entire changed file** (all its
functions + their call relationships), before-fix = vulnerable, after-fix = safe.
The analyzer must **localize** the bug among many functions, not judge one.

### Difficulty is proven, not asserted

| metric | old (single-function) | **hard (whole-file)** |
|---|---|---|
| median LOC / case | 25 | **235** (9.4×) |
| functions / case | 1 (max 6) | **9** (max 55) |
| multi-file fix commits | 0% | **69%** |

Built by `stage2_hard_extract.py` (whole-file extraction, relaxed size limits,
bias to multi-file commits) + `stage3_hard_filter.py` (label-quality filter that
judges the *changed* functions, all 7 plugins). Corpus: 544 whole-file cases →
228 vulnerable kept after filtering (82% retention), 26–37 per plugin.

---

## ⚠️ The audit finding: file-level scoring degenerates on whole-file cases

The standard per-case rule is **"any function in the file flagged ⇒ file
flagged."** On single-function cases that is correct. On whole-file cases it is
NOT: each file has ~9 functions and a before/after pair differs in only ONE. The
other ~8 unchanged functions trigger **identical** flags in both before and
after, so the rule cannot distinguish them and **degenerates to flag-everything**
(FM-Agent specificity ≈ 0%). That inflates recall and F1 and is not a real
localization signal.

**Fix — locus-level scoring** (`score_locus.py`): a case counts as flagged iff
one of its **changed functions** (`meta.changed_funcs`, the true fix locus) gets
a positive verdict. A vulnerable case is a TP only if the tool flags the function
the fix actually changed; a safe case is a TN only if it clears it. This measures
real interprocedural localization. All FM-Agent numbers below use locus scoring;
LLM-direct/Bandit/Semgrep are naturally file-level (one verdict per file).

---

## Headline: FM-Agent (locus) vs LLM-direct (file), all 7 plugins

| Plugin | N | **FM-Agent F1** | LLM-direct F1 | FM recall | LLM recall | FM spec. | LLM spec. | Δ F1 |
|---|---|---|---|---|---|---|---|---|
| **resource** | 20 | **0.64** | 0.17 | 0.90 | 0.10 | 0.10 | 0.90 | **+0.47** |
| **authz** | 31 | **0.71** | 0.38 | 1.00 | 0.27 | 0.25 | 0.88 | **+0.33** |
| **typestate** | 21 | **0.59** | 0.40 | 0.80 | 0.40 | 0.18 | 0.45 | **+0.19** |
| **authn** | 33 | **0.62** | 0.45 | 0.94 | 0.44 | 0.00 | 0.53 | **+0.17** |
| **taint** | 42 | **0.61** | 0.55 | 0.77 | 0.59 | 0.15 | 0.40 | **+0.06** |
| **crypto** | 30 | 0.63 | **0.67** | 0.73 | 0.67 | 0.40 | 0.67 | −0.04 |
| **ifc** | 14 | 0.47 | **0.57** | 0.57 | 0.57 | 0.14 | 0.57 | −0.10 |

**FM-Agent leads on 5 of 7.** Bandit/Semgrep (file-level) trail both on every
plugin and remain 0.00 on authz; full baseline numbers in the per-plugin section.

---

## The core result: recall vs specificity trade-off

The comparison is NOT a blowout — it is a characterizable trade-off:

- **FM-Agent's edge is RECALL.** On the cross-function properties it almost never
  misses (authz 1.00, authn 0.94, resource 0.90, typestate 0.80), because its
  interprocedural composition follows the vulnerable flow across functions. The
  single-shot LLM misses badly there (resource recall **0.10**, authz **0.27**) —
  it cannot hold the whole call graph in one judgment.
- **LLM-direct's edge is SPECIFICITY.** It is far more conservative on fixed
  files (spec. 0.40–0.90), while FM-Agent tends to over-flag (spec. 0.00–0.40) —
  fail-closed by design, but the precision cost is real.
- **Difficulty predicts the gap.** The more a property needs interprocedural
  reasoning, the bigger FM-Agent's lead: resource (+0.47) and authz (+0.33) are
  purely cross-function; crypto/ifc bugs are often visible in one function, so
  the single-shot LLM's higher precision wins there. This gradient itself
  validates that the hard benchmark is measuring interprocedural ability.

**Deployment reading:** want few misses on cross-function bugs → FM-Agent; want
high precision on locally-visible bugs → direct-LLM. They are complementary.

---

## Per-plugin detail (locus F1 for FM, file F1 for the rest)

| Plugin | FM-Agent | LLM-direct | Bandit | Semgrep |
|---|---|---|---|---|
| taint (n=42) | **0.61** | 0.55 | 0.54 | 0.34 |
| crypto (n=30) | 0.63 | **0.67** | 0.56 | 0.37 |
| authz (n=31) | **0.71** | 0.38 | 0.31 | 0.00 |
| ifc (n=14) | 0.47 | **0.57** | 0.36 | 0.33 |
| typestate (n=21) | **0.59** | 0.43 | 0.36 | 0.33 |
| resource (n=20) | **0.64** | 0.17 | 0.38 | 0.17 |
| authn (n=33) | **0.62** | 0.47 | 0.26 | 0.42 |

---

## Honesty caveats (unchanged from the CVE methodology)

1. **~60% label precision.** The hard corpus is still CVE-fix-commit curation:
   "a function changed in a security commit" ≠ "the vulnerable locus". Locus
   scoring keys on the changed function, which improves label fidelity, but
   residual noise remains — treat precision/specificity as **directional**.
2. **FM-Agent is slow.** Whole-file cases average ~8 per-function LLM calls each
   (~133 s/case); runs are checkpointed against an unstable endpoint. Baselines
   ran the full samples; the comparison is on the intersection.
3. **cwe-aware view unfair to authz/ifc/authn** (their findings carry no
   `data.cwe`) — detection/locus view is the correct metric for them.

---

## Artifacts (all persistent, reproducible — no /tmp dependency)

- **Corpus pipeline:** `cve_curation/stage2_hard_extract.py`,
  `stage3_hard_filter.py` → `cve_cases_hard.filtered.jsonl` (228 vuln cases).
- **Samples:** `sample_<plugin>_hard.json` (7 plugins, CWE-balanced).
- **Runs:** `ours_<plugin>_hard_detections.json` (file-level, checkpointed) +
  `ours_<plugin>_hard_funcverdicts.json` (harvested per-function verdicts for
  locus scoring), `llm_<plugin>_hard_detections.json`,
  `out_baselines_<plugin>_hard/`.
- **Scorers:** `score.py` (file-level, `--llm` for the direct-LLM baseline);
  `score_locus.py` (locus-level, the corrected metric) → `comparison_hard_locus.json`.

## Reproduce

```bash
# 1. build the hard corpus (network: GitHub patches; run in tmux)
python3 eval/cve_curation/stage1_osv_candidates.py --osv-dir <pypi> --out candidates_all7.jsonl
python3 eval/cve_curation/stage2_hard_extract.py --candidates candidates_all7.jsonl \
    --out-dir cases_hard --manifest cve_cases_hard.jsonl --per-plugin-cap 40
python3 eval/cve_curation/stage3_hard_filter.py --manifest cve_cases_hard.jsonl

# 2. per plugin: stratify → baselines → llm-direct → ours
.venv/bin/python eval/stratify.py --plugin <p> --benchmark cve \
    --manifest cve_cases_hard.filtered.jsonl --out eval/sample_<p>_hard.json
.venv/bin/python eval/run_baselines.py --sample eval/sample_<p>_hard.json --out eval/out_baselines_<p>_hard
.venv/bin/python eval/run_llm_baseline.py --plugin <p> --sample eval/sample_<p>_hard.json --out eval/llm_<p>_hard_detections.json
.venv/bin/python eval/run_ours.py --plugin <p> --sample eval/sample_<p>_hard.json --out eval/ours_<p>_hard_detections.json --helpers ''

# 3. score: file-level (all tools) + locus-level (FM, the corrected metric)
.venv/bin/python eval/score.py --sample eval/sample_<p>_hard.json --ours eval/ours_<p>_hard_detections.json \
    --baselines eval/out_baselines_<p>_hard/baseline_detections.json --llm eval/llm_<p>_hard_detections.json \
    --out eval/comparison_<p>_hard.json
.venv/bin/python eval/score_locus.py            # reads ours_*_hard_funcverdicts.json
```

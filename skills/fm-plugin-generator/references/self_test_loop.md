# Self-Test Loop Runbook (the gate — 跑完≠跑对)

The generator does NOT trust a plugin until its verdicts are scored on a labeled
set AND a sample of them are hand-audited against source. This reuses the exact
harness the 5 shipped plugins use. Every command below is verified to exist with
these flags.

## 0. Pick the test set

- **CVE corpus (default for any plugin, esp. CWE-only classes):** the in-repo
  filtered corpus `eval/cve_curation/cve_cases.filtered.jsonl` (903 cases,
  before/after function pairs, ~60% label precision). `stratify.py --benchmark
  cve` filters it to your plugin's manifest CWE scope automatically.
- **OWASP (only taint/crypto):** synthetic, 100% labels, `--benchmark owasp`.
- **User-supplied directory:** if the user gives a before/after corpus, convert
  it to a sample manifest with the same shape (see "User-supplied set" below).

If the CVE corpus has no cases for your CWEs, `stratify.py` exits with a clear
message — then you need a corpus that covers them (extend `cve_curation/` or take
a user-supplied set).

## 1. Build a stratified sample (CWE-balanced, seeded)

```bash
.venv/bin/python eval/stratify.py --plugin <name> --benchmark cve --per-category 8
# -> eval/sample_<name>_cve.json   (vulnerable+safe balanced per CWE)
```
Negatives (safe / post-fix functions) matter as much as positives — they are the
only way to measure false positives.

## 2. Run baselines over the SAME sample (shared comparison set)

```bash
.venv/bin/python eval/run_baselines.py --sample eval/sample_<name>_cve.json
# -> eval/out_baselines_<name>_cve/baseline_detections.json  (+ raw/ cache)
```
Bandit + Semgrep are fast/free; running them on exactly the sampled files keeps
the comparison on the intersection. (Add a direct-LLM baseline too if you want a
4-way table: see `eval/run_llm_baseline.py --plugin <name>`.)

## 3. Run the new plugin on the sample (checkpointed)

```bash
.venv/bin/python eval/run_ours.py --plugin <name> --sample eval/sample_<name>_cve.json \
    --out eval/ours_<name>_cve_detections.json --helpers ''
```
`--helpers ''` because curated cases are single-function (no shared helpers to
stage). The runner checkpoints after every case (the LLM endpoint is unstable);
a crash on one case becomes a fail-closed ERROR and the run continues. Long runs:
launch in tmux.

## 4. Score (two views)

```bash
.venv/bin/python eval/score.py --sample eval/sample_<name>_cve.json \
    --ours eval/ours_<name>_cve_detections.json \
    --baselines eval/out_baselines_<name>_cve/baseline_detections.json \
    --out eval/comparison_<name>_cve.json
#   add: --llm eval/llm_<name>_cve_detections.json   (4-way table)
```
Two views print: **detection** (right file?) and **cwe-aware** (right bug, right
category?). For CWE-only plugins whose findings carry no `data.cwe`, the
detection view is the meaningful one (cwe-aware will read 0.00 as an artifact —
note it, don't chase it).

## 5. Hand-audit (跑完≠跑对 — THE non-negotiable step)

```bash
.venv/bin/python eval/audit.py --sample eval/sample_<name>_cve.json \
    --ours eval/ours_<name>_cve_detections.json \
    --baselines eval/out_baselines_<name>_cve/baseline_detections.json \
    --bucket our-fp     # then our-fn, then disagree, then error
```
Read the SOURCE of each prioritized case and decide, by eye, whether the verdict
is right. Watch for the CVE label-noise trap: a "false positive" on a safe
(post-fix) case is real, but a "true positive" on a noisy vulnerable case may be
crediting a non-bug — and a "false negative" may be a mislabeled case, not a tool
miss. Only claim precision on the human-verified subset; report recall on the
full set with the ~60% caveat stated.

## 6. Decide what to fix, change ONE thing, re-run

Classify each genuine error:
- **abstraction gap** (the LLM didn't report a fact it could see, or reported a
  wrong shape) -> fix `src/<name>_prompts.py` (add an instruction/example, tighten
  the JSON schema, forbid a confusion). Re-run from step 3.
- **decision gap** (facts are right but the checker ruled wrong) -> fix
  `src/<name>_reasoner.py` (`classify`/`validate` rule). Re-run from step 4 (no
  LLM needed — facts are cached in the ours_*.json).
- **enum/validate false-ERROR** (a legitimate value the prompt offers but
  `validate` rejects -> fail-closed ERROR on a good abstraction) -> add the value
  to the enum. (This exact class of bug was found in crypto: `not_applicable`
  iv-nonce provenance.)

Change ONE thing per iteration so you can attribute the delta. Stop when
detection-view F1 hits the agreed target OR the iteration budget is spent. If
stuck after a few rounds, re-read the template plugin's reasoner for the pattern
you're missing, or consult on the theory.

## NEVER do this

- Hard-code case ids / special-case logic in the reasoner to pass the set. The
  checker must generalize; tests pass as a CONSEQUENCE of a correct rule.
- Delete or relabel failing cases to lift the score.
- Report precision off the raw CVE labels without auditing.

## User-supplied test set (instead of the CVE corpus)

If the user provides a directory of vulnerable/safe `.py` function files, build a
sample manifest by hand (same shape `run_ours.py`/`score.py` expect):
```python
import json
cases = [
  {"id": f"user:{i}", "path": "/abs/path/to/fn.py", "cwe": "CWE-XXX",
   "label": True,  # True=vulnerable, False=safe
   "category": "<name>", "source": "user-supplied", "benchmark": "user", "meta": {}}
  for i, ... in enumerate(...)
]
json.dump({"benchmark":"user","plugin":"<name>","total_selected":len(cases),
           "cases":cases}, open("eval/sample_<name>_cve.json","w"), indent=2)
```
Then run steps 2-6 unchanged. Real labels (CVE/user) only — never fabricate cases.

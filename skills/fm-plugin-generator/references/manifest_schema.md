# Manifest Schema (registry entry for a new plugin)

A new plugin is registered by adding ONE entry to `PLUGIN_MANIFESTS` in
`src/plugins/registry.py`. Every consumer (run_plugin.py, eval/run_ours.py,
eval/normalize.py, eval/benchmarks.py, eval/run_llm_baseline.py, ifc_viewer.py)
derives its view from this entry — do NOT hand-edit those files.

**Hard rule:** `registry.py` is PURE DATA. Your manifest entry must not import a
plugin class or anything that pulls `openai`. The class is loaded lazily by
`load_plugin_class()` via the `module`/`class_name` strings.

## Fields

```python
"<name>": {
    "name": "<name>",                 # plugin id; matches CLI `run_plugin.py <name>`
    "module": "src.plugins.<name>",   # import path (lazy-loaded, string only)
    "class_name": "<Name>Plugin",     # AnalysisPlugin subclass in that module
    "work_subdir": "fm_agent_<name>", # driver output dir under proj_dir
    "results_subdir": "results",      # per-function result dir under work_subdir
    "label": "<Human label>",         # viewer dropdown + reports
    "verdicts": {                     # scoring vocab + viewer pills (lists, ordered)
        "positive": ["VULNERABLE"],   #   counts as a finding/flag (detection TP)
        "poly":     ["POLYMORPHIC"],  #   parametric — resolved at a caller; counts as flag
        "review":   ["NEEDS_REVIEW"], #   fail-closed soft flag; counts as flag
        "negative": ["SAFE"],         #   affirmatively cleared
    },                                #   ERROR is implicit (fail-closed) — do NOT list it
    "cwes": ["CWE-918", ...],         # canonical "CWE-N"; the plugin's target scope
    "cwe_notes": {                    # short gloss per CWE (LLM-baseline scope prompt)
        "CWE-918": "SSRF",
    },
    "property_nl": "one-line NL description of the target property",
    "benchmark_categories": [],       # OWASP category keys; [] if CVE-only
}
```

## Field semantics & gotchas

- **verdicts (buckets)** — the union (in order positive, poly, review, negative)
  plus an appended ERROR MUST equal your `metadata.verdicts` tuple. The verifier
  below checks this.
  - `positive`/`poly`/`review` are all "flagged" for detection scoring
    (`registry.positive_verdicts()` = positive ∪ poly ∪ review ∪ {ERROR}). This
    mirrors `eval/normalize.collapse_ours`: a parametric or fail-closed verdict
    is conservatively a detection on a standalone benchmark case.
  - `negative` = cleared. Don't put ERROR in any bucket.
- **cwes** — drive both the LLM-baseline scope prompt and the CVE stratifier
  (`eval/stratify.py --benchmark cve` keeps only corpus cases whose CWE is in
  this set). Use canonical `CWE-<n>`.
- **benchmark_categories** — only the OWASP-samplable plugins (taint, crypto)
  have these. Leave `[]` for CVE-only plugins; they then won't appear in
  `eval/benchmarks.PLUGIN_CATEGORIES` or in `stratify.py --benchmark owasp`
  choices (correct — they have no OWASP coverage).
- **results_subdir** — keep `"results"` (the driver default). The viewer
  tolerates the legacy `ifc_results` only for ifc; new plugins use `results`.
- **work_subdir** — `run_plugin.py` passes this to the driver; the eval
  `run_ours.py` reads it too. Keep the `fm_agent_<name>` convention.

## Verify the entry (run after adding)

```bash
.venv/bin/python -c "
from src.plugins import registry as r
import sys
assert 'openai' not in sys.modules, 'registry pulled openai — keep it pure-data'
n='<name>'
assert r.has_plugin(n), 'not registered'
cls=r.load_plugin_class(n)            # lazy import; triggers openai (ok here)
md=cls().metadata
assert md.name==n, ('metadata.name', md.name)
assert set(md.verdicts)==set(r.all_verdicts(n)), ('verdict mismatch', md.verdicts, r.all_verdicts(n))
print('manifest OK:', n, '->', cls.__name__, '| verdicts', r.all_verdicts(n))
print('cwe scope:', r.cwe_scope_string(n))
"
```

If the assert about `openai` fires, you imported something heavy at module top
level in registry.py — move it behind `load_plugin_class`.

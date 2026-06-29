---
name: fm-plugin-generator
description: >-
  Autonomously generate a NEW FM-Agent security analysis plugin for a given CWE
  class + chosen formal theory + a labeled test set, then self-test and iterate
  to a target score. Use when asked to "add a plugin for CWE-XXX", "support a
  new vulnerability class", "build an FM-Agent plugin for <property>", or to
  extend the security portfolio. Produces the 3 plugin files + a registry
  manifest + a viewer JS renderer, wires nothing by hand (registry auto-
  discovery), and validates on the CVE-curated harness via stratify -> run_ours
  -> score -> audit, iterating until the F1 target or budget is hit.
---

# FM-Agent plugin generator (meta-skill)

You are generating a NEW analysis plugin on FM-Agent's shared substrate. The
substrate already does extraction, call-graph, bottom-up scheduling, parallel
LLM dispatch, optional top-down context, tracing, and aggregation. **You only
write the theory**: what the LLM describes, and how a deterministic checker
decides over that description.

> The general technique (do not violate it): **the LLM produces a modular,
> per-function natural-language abstraction; a deterministic Python checker —
> NO LLM — renders the verdict; results compose interprocedurally.** The LLM
> never decides. The checker fails closed (unknown -> unsafe/ERROR, never SAFE).

## Inputs (require these before starting)

1. **CWE class** — the weakness(es) to detect, e.g. `CWE-918 (SSRF)`.
2. **Theory / method** — the formal lens to use. Map it to the closest existing
   plugin as a template (this is the single most important decision):
   - data-flow / reachability -> **taint** (`src/taint_reasoner.py`)
   - confidentiality / High->Low -> **ifc**
   - per-op tables + value provenance -> **crypto**
   - precondition/obligation (must hold before an op) -> **authz** (top-down)
   - ordered events / must-happen-before -> **typestate** (top-down, ordered compose)
3. **Test set** — a labeled corpus to iterate against. Default: a slice of the
   CVE-curated corpus filtered to the target CWE(s); or a user-supplied directory
   of `before`/`after` (vulnerable/safe) function files.

If any input is missing or ambiguous, ASK before generating. A wrong
theory->template choice wastes the whole loop.

## Read first (ground every decision in the real contract)

- `src/plugins/base.py` — the SPI (envelopes + `AnalysisPlugin` methods). READ IT.
- The chosen **template plugin**'s 3 files end to end:
  `src/plugins/<tpl>.py`, `src/<tpl>_prompts.py`, `src/<tpl>_reasoner.py`.
- `src/plugins/driver.py::run_plugin` — the lifecycle that calls your methods.
- `src/plugins/registry.py` — the manifest schema you must add an entry to.
- `references/spi_contract.md`, `references/manifest_schema.md`,
  `references/js_renderer.md`, `references/self_test_loop.md` in THIS skill.

## Workflow (do these in order)

### 1. Plan the theory
Write down, in 5-10 lines: the abstraction vocabulary (what facts the LLM emits),
the verdict set (positive/poly/review/negative + ERROR), the deterministic
decision rule, the composition shape (bottom-up value? top-down obligation?
ordered events?), and whether `requires_top_down_context` / `needs_entrypoint`.
This is the spec for the next steps.

### 2. Emit the 3 plugin files
Mirror the template's structure (see `references/spi_contract.md` for the
method-by-method contract):
- `src/<name>_prompts.py` — system+user prompt that asks ONLY for a structured
  abstraction wrapped in `[<NAME>_JSON] ... [/<NAME>_JSON]`, plus an extractor.
  The prompt MUST forbid the LLM from emitting a verdict, and MUST instruct
  fail-closed "unknown" provenance where it cannot see the answer.
- `src/<name>_reasoner.py` — enums + `validate(facts)` (fail-closed on out-of-
  enum) + `classify(facts, ...)` returning `{verdict, findings, error}` + any
  composition/instantiation helpers. PURE PYTHON, no LLM, deterministic.
- `src/plugins/<name>.py` — the `AnalysisPlugin` subclass binding the two:
  `metadata`, `build_abstraction_prompt`, `parse_abstraction_response`,
  `make_error_facts`, `summarize_for_caller`, `compose_calls` (if not pure
  bottom-up), `check`, and the optional top-down hooks.

### 3. Register via the manifest (NO hand-wiring elsewhere)
Add ONE entry to `PLUGIN_MANIFESTS` in `src/plugins/registry.py` (schema in
`references/manifest_schema.md`). Every consumer (run_plugin, eval harness,
viewer) derives from this — do NOT edit them. Then verify discovery:
```bash
.venv/bin/python -c "from src.plugins import registry as r; print(r.plugin_names()); r.load_plugin_class('<name>')().metadata"
```

### 4. Add a config block
Add `<NAME>_MODEL = LLM_MODEL`, `MAX_<NAME>_ITER = 5`, `<NAME>_FAIL_CLOSED = True`
to `config.py`, mirroring the other plugins.

### 5. Author the viewer JS renderer
The viewer already dispatches per plugin. Add `render<Name>Detail(d,f,r)` and a
dispatch branch in `renderDetail`, plus any verdict CSS classes
(`.vc-<VERDICT>`, `.b-<VERDICT>`) the plugin introduces. Full guide + a worked
template in `references/js_renderer.md`. Render the abstraction the way the
template renderers do: verdict badge (shared), Findings, then the theory-
specific structured evidence (sources/sinks, guards, operations, events...).

### 6. Self-test loop (the gate — 跑完≠跑对)
Reuse the harness exactly as the existing plugins do (full runbook with the
exact flags in `references/self_test_loop.md`):
```bash
# 1. build a CVE sample, scoped to the plugin's manifest CWEs (registry-driven)
.venv/bin/python eval/stratify.py --plugin <name> --benchmark cve --per-category 8
#    (OWASP-covered plugins instead: --benchmark owasp; or hand-build a sample
#     for a user-supplied before/after directory — see the runbook)
# 2. run baselines over the SAME sample's files (so the comparison set is shared)
.venv/bin/python eval/run_baselines.py <files...>   # -> out_baselines_<name>_cve/
# 3. run our new plugin on the sample (checkpointed; unstable endpoint)
.venv/bin/python eval/run_ours.py --plugin <name> --sample eval/sample_<name>_cve.json \
    --out eval/ours_<name>_cve_detections.json --helpers ''
# 4. score (add --llm to include a direct-LLM baseline if you built one)
.venv/bin/python eval/score.py --sample eval/sample_<name>_cve.json \
    --ours eval/ours_<name>_cve_detections.json \
    --baselines eval/out_baselines_<name>_cve/baseline_detections.json \
    --out eval/comparison_<name>_cve.json
# 5. MANUALLY audit FP/FN/disagreements vs source (audit.py uses --sample/--ours/
#    --baselines, NOT --plugin)
.venv/bin/python eval/audit.py --sample eval/sample_<name>_cve.json \
    --ours eval/ours_<name>_cve_detections.json \
    --baselines eval/out_baselines_<name>_cve/baseline_detections.json
```
Then ITERATE: read the audit output, decide whether each error is an abstraction
gap (fix the prompt) or a decision gap (fix the reasoner), change ONE thing,
re-run. Stop when detection-view F1 hits the target OR the budget is exhausted.
NEVER hard-code case-specific logic to pass — the checker must be general.

### 7. Manual QA in the viewer
Run the new plugin on 1-2 real vulnerable cases, open them in `ifc_viewer.py`,
and confirm the badge + findings + structured panels render correctly. A plugin
that scores well but renders blank is not done.

## Done criteria

- `registry.plugin_names()` includes the new plugin; class loads; metadata.name matches.
- `run_plugin.py <name> <dir>` runs end to end and writes results.
- Viewer renders the new plugin's detail panel (real run, not a replay).
- Self-test scored on the harness; FP/FN hand-audited; score reported honestly
  with the CVE label-noise caveat (~60% precision -> recall trustworthy,
  precision directional). NO hard-coded test-passing logic.

## Hard rules

- LLM describes, deterministic checker decides. No verdict from the LLM.
- Fail closed: unknown -> unsafe/ERROR, never SAFE/SECURE.
- No hand-wiring outside the manifest + config + viewer renderer.
- No gaming the test set. Tests pass as a CONSEQUENCE of a correct checker.
- 3.10-compatible, no new heavy deps. `registry.py` stays pure-data (no openai).

# Viewer JS Renderer Guide (for a new plugin)

The viewer (`ifc_viewer.py`) is a single stdlib-only file: a Python HTTP server
plus a big embedded HTML/JS string (`_INDEX_HTML`). To make a new plugin's
results render, you edit the embedded JS in that string. There is no build step.

The middle "detail" panel is plugin-specific; everything else (function list,
verdict pills, source panel, verdict header badge, reasoning panel) is shared
and already driven by the registry-derived `PLUGINS` dict, so MOST of the UI
works for a new plugin with ZERO JS. You only add the middle-panel renderer.

## What you MUST add (4 small edits, all in `_INDEX_HTML`)

### 1. A `render<Name>Detail(d, f, r)` function
Renders the theory-specific evidence below the shared verdict header + source.
- `d` = the detail container DOM node (append sections to it)
- `f` = the function row: `f.name`, `f.verdict`, `f.id`, `f.result`
- `r` = `f.result` (your `render_result` / `check` `data`). Your abstraction is
  at `r.signature` (because `check` sets `data={"signature": facts.payload,...}`).

Use the shared helpers already in the file:
- `section(title, html)` -> a collapsible `<div class="sec">` (append its return to `d`)
- `esc(s)` -> HTML-escape
- `ce(tag, cls)` -> create element
- verdict chip markup: `<span class="vchip vc-<VERDICT>">...</span>`
- finding/op card classes: `.finding` (red), `.op` (neutral), `.op ok` (green)

Mirror an existing renderer that matches your theory shape (open the file and
copy the structure):
- list of sources/sinks/flows -> `renderTaintDetail`
- list of operations with tags -> `renderCryptoDetail`
- guards / sensitive-ops table -> `renderAuthzDetail`
- ordered events -> `renderTypestateDetail`
- label signature -> `renderIfcDetail`

Recommended panels, in order: **Findings (N)** first (the verdict's evidence),
then the structured abstraction (e.g. "Sources", "Sinks", "Operations",
"Guards", "Events"), each via `section(...)`. Show the verdict chip on the items
that drive the verdict so the eye lands on them.

### 2. A dispatch branch in `renderDetail`
Find (~line 1186):
```js
  if(PLUGIN==="authz") renderAuthzDetail(d,f,r);
  else if(PLUGIN==="taint") renderTaintDetail(d,f,r);
  else if(PLUGIN==="crypto") renderCryptoDetail(d,f,r);
  else if(PLUGIN==="typestate") renderTypestateDetail(d,f,r);
  else renderIfcDetail(d,f,r);
```
Add your branch before the `else`:
```js
  else if(PLUGIN==="<name>") render<Name>Detail(d,f,r);
```

### 3. A reasoning-panel title (one line, ~line 1005)
In `reasonTitle()` add your plugin so the right-hand LLM-trace panel is labeled:
```js
function reasonTitle(){ return PLUGIN==="authz" ? "Authorization Reasoning"
  : PLUGIN==="<name>" ? "<Title> Reasoning"
  : ... ; }
```

### 4. Verdict CSS + colors — ONLY if you introduce a NEW verdict tag
The existing tags (VULNERABLE/WEAK/POLYMORPHIC/NEEDS_REVIEW/SANITIZED/SAFE/
LEAK/SECURE/DECLASSIFIED/ERROR) already have CSS and colors. If your plugin
reuses them, do NOTHING here. If you add a brand-new tag `XYZ`:
- add `.vc-XYZ{...}` and `.b-XYZ{...}` near the other `.vc-`/`.b-` rules (~line 497-534)
- add `XYZ:"#hexcolor"` to the `VCOL` map (~line 1060, used for graph nodes)
- (the verdict pills + filter bar read `RUN.verdicts` from the registry, so
  they need no JS edit — they pick up your manifest verdicts automatically)

## What you do NOT touch

- The `PLUGINS` dict (derived from the registry; your manifest entry feeds it).
- Function list, verdict filter pills, source panel, header badge, reasoning
  fetch — all shared and generic.
- The `PLUGIN_VERDICTS` JS fallback near line 975 is only a cold-start default;
  `RUN.verdicts` from the registry is authoritative once a run loads, so you do
  not need to edit it.

## Data contract reminder

For the renderer to have data, your plugin's `check()` must put the abstraction
on the verdict: `Verdict(..., data={"signature": facts.payload, ...})`. The
viewer reads `r.signature`. Findings come from `f.result.findings` (list of
`{rule_id,title,message,severity,data}`); render `data.cwe`, `data.evidence`,
and any theory-specific fields you stored.

## Verify (real browser, not a replay)

After editing, run the plugin on a real vulnerable case, restart the viewer, and
load it. A headless check (chromium) is fine; confirm: verdict badge present,
Findings section populated, structured panels populated, no console errors
(favicon 404 is harmless). A plugin that scores well but renders blank is NOT
done.

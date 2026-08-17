---
name: fm-agent-progress-ppt
description: Build or update an FM-Agent progress-report PowerPoint from GitHub PRs and issues, the current conversation and local work memories, relevant Git branches, implementation code, the pluginization plan, and the FM-Agent meeting template. Use when asked to prepare a weekly meeting deck, pluginization report, issue/PR progress presentation, or a revised detailed version of an existing FM-Agent report.
---

# FM-Agent Progress PPT

Produce an evidence-backed FM-Agent report deck. Treat GitHub state, branch code,
local memory, and the supplied template as separate sources that must agree.

## Required companion skills

1. Use the GitHub skill/app to read PR and issue metadata, descriptions, changed
   files, comments when relevant, merge state, and timestamps.
2. Use the Presentations skill for all PPTX inspection, template following,
   authoring, rendering, and QA.
3. Read the complete `SKILL.md` of both skills before taking task actions.

## Workflow

### 1. Resolve the workspace and requested output

Read [references/paths-and-environment.md](references/paths-and-environment.md).
Confirm the repository, template, plan deck, output directory, and presentation
runtime by checking the filesystem. Never assume a path exists merely because it
is documented.

Prefer the user-specified output directory. Preserve the source template and any
existing report unless the user explicitly requests an in-place edit.

### 2. Build an evidence ledger

Collect evidence in this order:

1. Current conversation: extract the user's stated goals, completed work,
   terminology, and requested emphasis.
2. GitHub: fetch every linked PR and issue. Record title, state, merged status,
   body, commits, changed-file count, additions/deletions, timestamps, and
   changed filenames. Do not describe an open PR as merged.
3. Local memory: search the files listed in
   [references/paths-and-environment.md](references/paths-and-environment.md)
   plus any similarly named notes found with `rg --files`.
4. Git: inspect the current branch, remotes, status, log, diff, and relevant
   source/docs. Read [references/git-and-memory.md](references/git-and-memory.md)
   before changing branches.
5. Plan deck: inspect every slide of `插件化方案.pptx` and extract the pipeline
   stages, plugin modes, inputs, outputs, and intended architecture.

Store source notes under the presentation scratch directory in `source-notes.txt`.
Label claims as verified, inferred, planned, or blocked. Never invent test results,
metrics, or chat history.

If earlier chat history is unavailable, say internally that only the current
thread/summary is accessible and reconstruct the record from local memory, Git,
GitHub, and artifacts. Do not claim to have searched inaccessible conversations.

### 3. Inspect the implementation behind each work item

For every PR or issue:

- Identify its branch from the PR head ref, a matching local/remote branch, or
  commit history.
- Inspect the changed files and the concrete interfaces implemented.
- Read user-facing docs and tests/demos where they exist.
- Translate code into audience-facing responsibilities, behavior, coverage,
  validation, limitations, and next steps.

For plugin reports, explicitly answer:

- What the plugin author writes (`plugin.json`, `plugin.py`, Hook functions).
- What FM-Agent owns (discovery, import, validation, path propagation, safe
  temporary inputs, canonical outputs, schema checks, failure handling).
- What `pass`, `replace`, and `modify` do.
- For `modify`, distinguish `input_function` from `output_function`.
- Which execution paths are covered: full, resume, isolate, entry selection,
  final scoped run, and incremental, as supported by the inspected branch.

### 4. Plan the narrative

Use this default arc unless the request calls for another:

1. Minimal title slide.
2. Overall goal and plugin responsibility boundary.
3. Mode behavior or architecture.
4. Completed/merged work.
5. Current implementation coverage and validation.
6. Active issue and next plan.
7. Discussion/risks.
8. Demo or close.

Use takeaway titles. Split dense explanations across cloned template slides;
do not shrink template typography merely to fit more text.

### 5. Follow the meeting template exactly

Use template-following mode from the Presentations skill:

1. Inspect every source slide.
2. Create `template-audit.txt`, `template-frame-map.json`,
   `deviation-log.txt`, and `source-notes.txt`.
3. Map every output slide to a source slide. Reuse a source slide when expanding
   a section.
4. Build `template-starter.pptx`.
5. Import the starter with `@oai/artifact-tool`.
6. Rewrite inherited text objects only. Preserve typography, palette, spacing,
   footer, page number, and template chrome.
7. Export to a distinct final PPTX.

Do not use `python-pptx`. Do not rebuild the template from visual approximation.

### 6. Render and verify

Render the exported PPTX again after saving; do not rely only on the in-memory
render. Inspect every slide individually at full size.

Check:

- titles remain on one line;
- no left/right clipping or unexpected wrapping;
- page numbers follow the expanded slide order;
- GitHub states and counts match the evidence ledger;
- responsibilities and mode descriptions match code/docs;
- no empty structural placeholders remain in `ppt/slides/slide*.xml`;
- the final file opens through an artifact-tool re-import.

If the template-fidelity checker reports example text from an unused master or
layout, verify the actual slide XML and rendered slides. Record the false
positive in `qa-ledger.txt`; do not delete inherited master content blindly.

### 7. Deliver

Return a short Chinese summary and one clickable link to the final PPTX. Mention
which slides were expanded or materially changed. Keep scratch files out of the
handoff.


# Generate Domain Context

> **YOUR SOLE OBJECTIVE**: Read `fm_agent/phases.json` and write domain context files describing the types, invariants, and architecture of each phase. Do NOT modify `phases.json`. Do NOT edit any existing project files. Only create files inside `fm_agent/`.

> **CRITICAL — YOU MUST CREATE FILES IN THIS SESSION**: Do NOT only research, plan, or delegate to background/sub-agents. You MUST directly write the domain context files yourself before this session ends.

**Required output files:**
1. `fm_agent/spec_prompts/domain_context/engine_overview.txt`
2. `fm_agent/spec_prompts/domain_context/phase_NN_types.txt` (one per phase)

**Rules:**
- `fm_agent/phases.json` has already been generated and finalized. Read it — do NOT modify it.
- `fm_agent/` is NOT part of the project source code. It is a scratch workspace for storing YOUR output files only.
- Do NOT modify any existing files in the repository (including `fm_agent/phases.json`).
- Do NOT create or edit AGENTS.md, README.md, or any file outside `fm_agent/`.
- Do NOT run the project or install dependencies.
- Keep exploration minimal — read only the source files listed in `phases.json` for the types and invariants they define.
- Start writing output files as soon as you have enough context. Do not over-analyze.
- Do NOT delegate file creation to sub-agents. Write the files directly yourself.

---

## Step 1 — Read `fm_agent/phases.json`

Read `fm_agent/phases.json` to understand the phase structure. For each phase, note:
- The phase number and name
- The source files listed in each module
- The dependency relationships between phases

---

## Step 2 — Write Domain Context Files

### Write `fm_agent/spec_prompts/domain_context/engine_overview.txt`

Describe the overall system:
- Architecture: what the pipeline stages are and how data flows between them
- Encoding conventions: how each data type is stored (scaled integers, date offsets, dictionary codes, string layouts)
- Key precomputed data structures and their invariants (e.g., join maps, range indices)
- Important invariants of every phase

### Write `fm_agent/spec_prompts/domain_context/phase_NN_types.txt` for each phase

For each phase, describe:
- All structs and types that functions in this phase produce or consume
- Field types and valid value ranges
- Encoding rules (with explicit formulas, e.g., `date_field[i] = actual_days - base_date_days`)
- Invariants that must hold in this phase
- Entry point function signatures

These files are given to spec-writing agents as context. Without them, agents will write generic specs that miss the domain-specific invariants.

---

## Checklist

**Before finishing, verify all of the following exist (use `ls` to confirm):**

- [ ] `fm_agent/spec_prompts/domain_context/engine_overview.txt` exists
- [ ] `fm_agent/spec_prompts/domain_context/phase_NN_types.txt` exists for each phase listed in `fm_agent/phases.json`

**If any file is missing, create it now before ending.**

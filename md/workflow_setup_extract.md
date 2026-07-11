# Setup & Codebase Understanding

> **YOUR SOLE OBJECTIVE**: Create exactly 3 types of output files listed below. Do NOT edit any existing project files (no AGENTS.md, no README, no source code). Only create files inside `fm_agent/`.

> **CRITICAL — YOU MUST CREATE FILES IN THIS SESSION**: Do NOT only research, plan, or delegate to background/sub-agents. You MUST directly write `fm_agent/phases.json` and the domain context files yourself before this session ends.

**Required output files:**
1. `fm_agent/phases.json`
2. `fm_agent/spec_prompts/domain_context/engine_overview.txt`
3. `fm_agent/spec_prompts/domain_context/phase_NN_types.txt` (one per phase)

**Rules:**
- `fm_agent/` is NOT part of the project source code. It is a scratch workspace for storing YOUR output files only. Do NOT treat files inside `fm_agent/` as project source files. Do NOT include any `fm_agent/` paths in `phases.json`.
- Do NOT modify any existing files in the repository.
- Do NOT create or edit AGENTS.md, README.md, or any file outside `fm_agent/`.
- Do NOT run the project or install dependencies.
- Keep exploration minimal — read only what is needed to understand the module structure. Ignore the `fm_agent/` directory when analyzing the codebase.
- Start writing output files as soon as you have enough context. Do not over-analyze.
- Do NOT delegate file creation to sub-agents. Write the files directly yourself.

---

## Step 1 — Understand the Codebase & Write `phases.json`

Quickly scan the codebase structure and **immediately** write `fm_agent/phases.json` — a machine-readable description of every phase.

**Schema:**

```json
{
  "project": "<project_name>",
  "languages": ["<lang1, e.g. cpp>", "<lang2, e.g. python>"],
  "file_extensions": ["<ext1, e.g. cpp>", "<ext2, e.g. py>"],
  "phases": [
    {
      "phase": 1,
      "name": "<Human-readable phase name>",
      "description": "<One sentence: what this phase does in the data pipeline>",
      "modules": [
        {
          "name": "<module_name>",
          "description": "<a short paragraph: what this module does>",
          "source_files": ["<path/to/source>", "..."]
        }
      ],
      "depends_on_phases": []
    },
    {
      "phase": 2,
      "name": "<Phase name>",
      "description": "<One sentence>",
      "modules": [
        {
          "name": "<module_name>",
          "description": "<a short paragraph: what this module does>",
          "source_files": ["<path/to/source>"]
        }
      ],
      "depends_on_phases": [1]
    }
  ]
}
```

**Field rules:**

- `project` — name of the repo root
- `languages` — list of canonical lowercase language identifiers used in the project (e.g. `["cpp", "python"]`). For single-language projects, use a one-element list.
- `file_extensions` — list of file extensions without leading dot, one per language (e.g. `["cpp", "py"]`). Order should match `languages`.
- `phases[*].phase` — 1-indexed integer, unique, ascending
- `phases[*].name` — brief label
- `phases[*].modules[*].description` — one short paragraph explaining what this module does
- `phases[*].description` — one sentence explaining what this phase does in the data pipeline
- `phases[*].modules[*].name` — matches the subdirectory name of the module
- `phases[*].modules[*].source_files` — relative paths from repo root of all source files that belong to this module. **Exclude all test files** (e.g., files in `test/`, `tests/`, `__tests__/` directories, or files named `*_test.*`, `test_*.*`, `*_spec.*`)
- `phases[*].depends_on_phases` — list of phase numbers whose outputs this phase consumes (empty list for phases with no dependencies)

Each phase must be **self-contained**. Each phase should be splitted into multiple small modules. All source files for a module in that phase must be listed explicitly.

Each source file must belong to **at most one phase** and **at most one module**. If the same file appears in more than one `modules[*].source_files`, the `phases.json` is invalid and must be corrected before proceeding.

**Implementation tip:** Use a glob or `find` command to list source files per directory. Do not enumerate files by hand. Filter out test files (`test/`, `tests/`, `__tests__/`, `*_test.*`, `test_*.*`, `*_spec.*`). Write `fm_agent/phases.json` immediately after listing files — do not delay.

**IMPORTANT: After writing `fm_agent/phases.json`, proceed to Step 2 immediately. Do not revisit or refactor Step 1.**

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

- [ ] `fm_agent/phases.json` exists and is valid JSON
- [ ] `fm_agent/spec_prompts/domain_context/engine_overview.txt` exists
- [ ] `fm_agent/spec_prompts/domain_context/phase_NN_types.txt` exists for each phase

**If any file is missing, create it now before ending.**
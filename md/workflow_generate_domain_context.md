# Generate Domain Context

> **YOUR SOLE OBJECTIVE**: Read `fm_agent/source_files.json` and `fm_agent/modules.json`, then write domain context files describing the types, invariants, and architecture of the project and its modules. Do NOT modify the manifests. Do NOT edit any existing project files. Only create files inside `fm_agent/`.

> **CRITICAL — YOU MUST CREATE FILES IN THIS SESSION**: Do NOT only research, plan, or delegate to background/sub-agents. You MUST directly write the domain context files yourself before this session ends.

Required outputs:

1. `fm_agent/spec_prompts/domain_context/engine_overview.txt`
2. Either `fm_agent/spec_prompts/domain_context/types.txt` for smaller projects, or `fm_agent/spec_prompts/domain_context/module_types/<module_slug>.txt` for larger projects

Rules:

- `fm_agent/source_files.json` and `fm_agent/modules.json` have already been generated and finalized. Read them, but do NOT modify them.
- `fm_agent/` is not part of the project source code. It is a scratch workspace for your output files only.
- Do NOT modify any existing files in the repository.
- Do NOT create or edit AGENTS.md, README.md, or any file outside `fm_agent/`.
- Do NOT run the project or install dependencies.
- Keep exploration minimal. Read only the source files listed in the manifests for the types and invariants they define.
- Start writing output files as soon as you have enough context. Do not over-analyze.
- Do NOT delegate file creation to sub-agents. Write the files directly yourself.

## Step 1 — Read the Setup Manifests

Read `fm_agent/source_files.json` and `fm_agent/modules.json` to understand the source scope and module structure. For each module, note:

- The module name
- The module description
- The source files listed in the module

## Step 2 — Write Domain Context Files

### Write `fm_agent/spec_prompts/domain_context/engine_overview.txt`

Describe the overall system:

- Architecture: how the system is organized and how data flows between modules
- Encoding conventions: how important data types are stored
- Key precomputed data structures and their invariants
- Important invariants shared across modules

### Write Module or Global Type Context

For smaller projects, write one `types.txt`. For larger projects, write one file per module under `module_types/`.

Name each module type file with the module name slug, not the raw module name. Build the slug by replacing every run of characters other than ASCII letters, digits, `.`, `_`, and `-` with a single `_`, then trimming leading/trailing `.`, `_`, and `-`. Examples:

- module `misc/fasttest` -> `module_types/misc_fasttest.txt`
- module `tools/validate_tool` -> `module_types/tools_validate_tool.txt`
- module `core` -> `module_types/core.txt`

Describe:

- All structs and types that functions in this module produce or consume
- Field types and valid value ranges
- Encoding rules with explicit formulas where relevant
- Invariants that must hold in this module
- Cross-module contracts that are important for callers and callees
- Entry point function signatures

These files are given to spec-writing agents as context. Without them, agents will write generic specs that miss domain-specific invariants.

## Checklist

Before finishing, verify all of the following exist:

- [ ] `fm_agent/spec_prompts/domain_context/engine_overview.txt`
- [ ] `fm_agent/spec_prompts/domain_context/types.txt` or correctly slugged `fm_agent/spec_prompts/domain_context/module_types/*.txt`

If any file is missing, create it now before ending.

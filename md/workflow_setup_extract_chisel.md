# Setup & Codebase Understanding — Chisel / Hardware

> **YOUR SOLE OBJECTIVE**: Create exactly 3 types of output files listed below. Do NOT edit any existing project files (no AGENTS.md, no README, no source code). Only create files inside `fm_agent/`.

> **CRITICAL — YOU MUST CREATE FILES IN THIS SESSION**: Do NOT only research, plan, or delegate to background/sub-agents. You MUST directly write `fm_agent/groups.json` and the domain context files yourself before this session ends.

This codebase is a **Chisel hardware design** (Scala sources describing hardware). This workflow organizes the codebase by **subsystem** (a functional cluster of related hardware) and lists **source groups** (the `.scala`/`.sc` files in each subsystem).

**Required output files:**
1. `fm_agent/groups.json`
2. `fm_agent/spec_prompts/domain_context/design_overview.txt`
3. `fm_agent/spec_prompts/domain_context/subsystem_NN_types.txt` (one per subsystem)

**Rules:**
- Write ALL output files entirely in English (including `groups.json` names/descriptions, `design_overview.txt`, and every `subsystem_NN_types.txt`). Even when source comments, identifiers, or documentation are written in another language, translate the content into English — never copy non-English text into the output files.
- `fm_agent/` is NOT part of the project source code. It is a scratch workspace for storing YOUR output files only. Do NOT treat files inside `fm_agent/` as project source files. Do NOT include any `fm_agent/` paths in `groups.json`.
- Do NOT modify any existing files in the repository.
- Do NOT create or edit AGENTS.md, README.md, or any file outside `fm_agent/`.
- Do NOT run the project, elaborate the design, or install dependencies (no `sbt`, `mill`, FIRRTL, or Verilog generation).
- Keep exploration minimal — read only what is needed to understand the design hierarchy. Ignore the `fm_agent/` directory when analyzing the codebase.
- Start writing output files as soon as you have enough context. Do not over-analyze.
- Do NOT delegate file creation to sub-agents. Write the files directly yourself.

---

## Step 1 — Understand the Design & Write `groups.json`

Quickly scan the Scala/Chisel source tree and **immediately** write `fm_agent/groups.json` — a machine-readable description of every subsystem and the source files it contains.

**Schema:**

```json
{
  "project": "<repo_name>",
  "languages": ["chisel"],
  "file_extensions": ["scala", "sc"],
  "subsystems": [
    {
      "subsystem": 1,
      "name": "<Human-readable subsystem name, e.g. Frontend / IFU>",
      "description": "<One sentence: what hardware function this subsystem implements>",
      "source_groups": [
        {
          "name": "<source_group_name>",
          "source_files": ["<path/to/Foo.scala>", "..."]
        }
      ],
      "depends_on_subsystems": []
    },
    {
      "subsystem": 2,
      "name": "<Subsystem name>",
      "description": "<One sentence>",
      "source_groups": [
        {
          "name": "<source_group_name>",
          "source_files": ["<path/to/Bar.scala>"]
        }
      ],
      "depends_on_subsystems": [1]
    }
  ]
}
```

**Field rules:**

- `project` — name of the repo root
- `file_extensions` — the Scala extensions actually present, a subset of `["scala", "sc"]`
- `subsystems[*].subsystem` — 1-indexed integer, unique, ascending. A subsystem is a grouping bucket
- `subsystems[*].name` — brief label, typically the architectural block name (e.g. `Decode`, `LoadStoreQueue`, `Arbiter`)
- `subsystems[*].description` — one sentence on the hardware function this subsystem implements
- `subsystems[*].source_groups[*].name` — matches the subdirectory or logical name of the source group. A **source group** is a `.scala`/`.sc` file or a tightly-coupled set of files — it is NOT a Chisel hardware `Module`. One `.scala`/`.sc` file may declare several hardware modules; that is fine
- `subsystems[*].source_groups[*].source_files` — relative paths from repo root of all Scala source files (`.scala` or `.sc`) in this group. **Exclude all test/spec files** (files under `src/test/`, or named `*Spec.scala`/`*Spec.sc`, `*Test.scala`/`*Test.sc`, `*Tester.scala`/`*Tester.sc`)
- `subsystems[*].depends_on_subsystems` — list of subsystem numbers whose hardware this subsystem instantiates or inherits from (empty list when there is no cross-subsystem dependency)

Each source file must belong to **at most one subsystem**. If the same file appears in more than one subsystem's `source_groups[*].source_files`, the `groups.json` is invalid and must be corrected before proceeding.

Each subsystem must be **self-contained**: all source files for a group in that subsystem must be listed explicitly. No subsystem may silently depend on files listed in another subsystem's groups.

If the design is small or has no clear subsystem boundaries, a single subsystem containing all sources is valid.

**Implementation tip:** Use a glob or `find` command to list `.scala`/`.sc` files per directory. Do not enumerate files by hand. Filter out test files (`src/test/`, `*Spec.scala`/`*Spec.sc`, `*Test.scala`/`*Test.sc`, `*Tester.scala`/`*Tester.sc`). Write `fm_agent/groups.json` immediately after listing files — do not delay.

**IMPORTANT: After writing `fm_agent/groups.json`, proceed to Step 2 immediately. Do not revisit or refactor Step 1.**

---

## Step 2 — Write Domain Context Files

### Write `fm_agent/spec_prompts/domain_context/design_overview.txt`

Describe the overall hardware design:
- Architecture: the major subsystems / blocks and how they connect (which module instantiates which)
- Clock and reset domains, and any global timing/handshake conventions
- Bus and interface conventions: ready-valid / Decoupled, Valid, custom protocols, backpressure rules
- Width, encoding, and addressing conventions used across the design (bit-field layouts, one-hot vs binary encodings, address alignment)
- Top-level parameters / configuration knobs and their observable effect on interfaces and capacity
- Important invariants that hold across the whole design (reset values, ordering, arbitration/priority)

### Write `fm_agent/spec_prompts/domain_context/subsystem_NN_types.txt` for each subsystem

For each subsystem, describe:
- All `Bundle` / interface types this subsystem's modules produce or consume, with field names, directions, and bit widths
- Valid value ranges and encodings for each field (with explicit formulas where relevant)
- Handshake / protocol contracts (when `valid` is asserted, `ready` stability, response matching)
- Invariants that must hold within this subsystem (state after reset/flush, ordering, arbitration)
- The top-level module(s) of the subsystem and their IO signatures

---

## Checklist

**Before finishing, verify all of the following exist (use `ls` to confirm):**

- [ ] `fm_agent/groups.json` exists and is valid JSON
- [ ] `fm_agent/spec_prompts/domain_context/design_overview.txt` exists
- [ ] `fm_agent/spec_prompts/domain_context/subsystem_NN_types.txt` exists for each subsystem
- [ ] Every output file is written entirely in English (no Chinese or other non-English text)

**If any file is missing, create it now before ending.**

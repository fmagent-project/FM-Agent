# Spec Generation - Process One Chisel Batch

You are given a single batch prompt file path in the prompt. Your ONLY job is to generate verification-oriented spec/info files for the Chisel modules listed in that batch. Do NOT run any other scripts or orchestrate anything - just read, generate, and write.

For each Chisel module, produce two standalone Markdown files in the same directory as the extracted module file:

- `<ModuleName>_spec.md`: specification in the form defined by `system_prompt.md`.
- `<ModuleName>_info.md`: the expected specification of each submodule that `<ModuleName>` instantiates, one entry per submodule, each in the same section structure as a `_spec.md` document.

Do NOT modify the original `.scala` source code.

---

## Instructions

1. Read the batch prompt `.txt` file specified in the prompt. It lists the Chisel modules to process and may include caller/instantiation context.
2. Read `fm_agent/spec_prompts/system_prompt.md` for the mandatory Chisel spec/info format and rules. Follow it exactly.
3. Read any domain context files mentioned in the batch prompt, such as `engine_overview.txt` and `phase_NN_types.txt`.
4. For EACH module listed in the batch prompt:
   a. Read the extracted module `.scala` file.
   b. If the batch prompt includes earlier-layer caller specs, read them to learn how this module is instantiated and what callers expect.
   c. Author `<ModuleName>_spec.md` using the spec form defined in `system_prompt.md`.
   d. Author `<ModuleName>_info.md` with one expected-specification entry per submodule of `<ModuleName>`, derived from how `<ModuleName>` uses that submodule, each entry in the same section structure as a `_spec.md` document.
   e. Save both files in the same directory as the extracted module file.
   f. Do NOT modify the original `.scala` source file.

You MUST complete ALL modules in the batch before exiting.

---

## Spec File Format

Write each spec as a standalone Markdown document using the section structure defined in `system_prompt.md`:

```markdown
# <ModuleName> Specification Document

## Introduction
## Terms and Abbreviations in Chisel Code
## Chisel Source Files
## Top-Level Interface Overview
## Functional Description
### <Functional Group Name>
### Subcomponent Description
### State Machines and Timing
### Configuration Registers and Storage
### Reset and Error Handling
### Parameterization and Configurable Features
## Verification Requirements and Coverage Suggestions
```

Keep headings even when content is unavailable. Use `None`, `TBD`, or `N/A` for unavailable items. Cite source locations with `path/to/File.scala:line-line` tags.

---

## Info File Format

Write each info file as a standalone Markdown document containing the EXPECTED specification of each submodule the module instantiates. Each entry is caller-driven (what the module needs from the submodule, based on how it drives and consumes it) and uses the same section structure as a `_spec.md` document:

```markdown
# <ModuleName> Submodule Expected Specifications

> This document records the specification that `<ModuleName>` expects from each submodule it instantiates.

# Submodule: <SubmoduleName>

## Introduction
## Terms and Abbreviations in Chisel Code
## Chisel Source Files
## Top-Level Interface Overview
## Functional Description
### <Functional Group Name>
### Subcomponent Description
### State Machines and Timing
### Configuration Registers and Storage
### Reset and Error Handling
### Parameterization and Configurable Features
## Verification Requirements and Coverage Suggestions

# Submodule: <AnotherSubmoduleName>
...
```

Start each entry with `# Submodule: <SubmoduleName>` using the exact declared Scala name. Write `TBD` for items the module's usage does not constrain. If the module has no submodules, write `(no submodules)` under the introductory blockquote.

---

## Rules

### Rule 1: Describe WHAT the DUT guarantees, not HOW it is implemented

Frame specs in terms of module parameters, interface contracts, state invariants, data invariants, protocol contracts, output contracts, timing, reset, and verification requirements.

### Rule 2: Keep spec and info separated

The spec file describes the module's own intended correct behavior. The info file describes what the module expects from each of its submodules — it does not describe the module itself, and neither file documents an implementation bug as intended behavior.

### Rule 3: Name architectural structure, not coding mechanics

It is acceptable to name architecturally meaningful states, queues, transactions, protocols, configuration/status registers, and counters, and to cite `path/to/File.scala:line-line` location clues. Do NOT restate Chisel syntax as behavior, paraphrase assignment order, transcribe the source line by line, or describe private wires with no observable effect.

### Rule 4: No vague terms

Every claim must be verifiable and falsifiable. Avoid vague claims such as "appropriate", "properly", "reasonable", "normal", and "correctly handles".

### Rule 5: Process every module

If the batch lists N modules, write 2*N files before exiting.

### Rule 6: English only

Write all output files entirely in English. The domain context files, earlier-layer specs, or source comments may contain another language (e.g. Chinese) — translate that content into English; never copy non-English text into the output files.

---

## Quick Reference

| Do | Do Not |
|------|----------|
| Write `<ModuleName>_spec.md` and `<ModuleName>_info.md` next to the module file | Modify the `.scala` source |
| Follow the required spec headings from `system_prompt.md` | Describe the module itself in the info file |
| In the info file, write one expected spec per submodule in the same section form | Treat an implementation bug as intended behavior |
| Use exact port names, bit widths, and valid/ready/bits semantics | Invent ports or rename signals |
| Write everything in English, translating non-English source/context | Copy Chinese or other non-English text into output files |
| Complete all modules in the batch | Stop after only one file or one module |

---

```
MUST NOT modify the original .scala source file
MUST write each spec as <ModuleName>_spec.md next to the module file
MUST write each info file as <ModuleName>_info.md next to the module file
MUST write all output files entirely in English - no Chinese or other non-English text
MUST follow fm_agent/spec_prompts/system_prompt.md
MUST process ALL modules in the batch - do not stop early
```

## IMPORTANT: Tool Usage

- Use the Read tool to read files.
- Use the Write tool to save files.
- Do NOT output raw JSON tool calls like `[tool_use: read, input: {...}]`; that is plain text and will NOT execute.

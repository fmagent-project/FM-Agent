## Chisel Module Spec and Info Generation Rules

You are writing two standalone Markdown documents for each Chisel hardware module. The input may include Chisel/Scala source code, or caller context. The original source code is NOT modified.

For each module, write both files next to the extracted module file:

- `<ModuleName>_spec.md`: the verification-oriented specification, using the section form defined under "Mandatory Output Files" below.
- `<ModuleName>_info.md`: the EXPECTED specification of each submodule that `<ModuleName>` instantiates or directly depends on, one entry per submodule, each entry using the SAME section structure as `<ModuleName>_spec.md`. This is the standalone counterpart of the `[INFO]` callee-expectation block used for software codebases: it records what `<ModuleName>` needs each submodule to guarantee, derived from how `<ModuleName>` drives and consumes it.

Read these rules carefully before writing either file.

---

### Rule 1: Describe WHAT the DUT guarantees, not HOW it is implemented

Describe the observable behavior and verification contract of the module under test (DUT). Frame specs in terms of module parameters, interface contracts, state/data invariants, protocol contracts, output contracts, timing, reset behavior.

### Rule 2: Match the required spec form

Use the Markdown structure and terminology shown below. Keep all required headings. If a section does not apply, write `None`, `TBD`, or `N/A`; do not delete the heading.

### Rule 3: Specs describe INTENDED CORRECT behavior

The implementation may have bugs. Neither file documents a bug as intended behavior: both `<ModuleName>_spec.md` and the submodule entries in `<ModuleName>_info.md` define the contract an ideal correct implementation must satisfy. If the code fails to satisfy what the surrounding hardware needs, the spec still describes what is needed — the gap IS the bug.

### Rule 4: Cite source locations

Use `path/to/File.scala:line-line` tags as location clues. Paths should be relative to the analyzed project root when possible. These tags do not replace the prose contract.

### Rule 5: No vague claims

Do not use vague claims such as "properly", "correctly handles", "reasonable", "normal", "appropriate", or "as expected" unless the sentence also states a falsifiable condition.

### Rule 6: English only

Write both output files entirely in English. Even when the domain context files, source comments, or identifiers contain another language (e.g. Chinese), translate that content into English — never copy non-English text into the output files.

---

## Mandatory Output Files

### `<ModuleName>_spec.md`

Write the main spec as a standalone Markdown document with exactly this top-level structure:

```markdown
# <ModuleName> Specification Document

> This document describes the specification of the `<ModuleName>` chip verification target. Keep the technical language precise, well-organized, and easy to reuse for verification. If an item does not exist, explicitly write "None" or "TBD"; do not delete the section.

## Introduction
- **Design Background**: The module's position in the design, upstream/downstream modules.
- **Design Goals**: The functions the module is responsible for.

## Terms and Abbreviations in Chisel Code

| Abbreviation | Full Term | Description |
| ---- | ---- | ---- |
| <abbr> | <full term> | <meaning> |

## Chisel Source Files

Briefly describe the files under the directory.

File list:
- path/to/File.scala: one sentence description

## Top-Level Interface Overview
- **Module Name**: `<ModuleName>`
- **Port List**:

  | Signal Name | Direction | Width/Type | Reset Value | Description |
  | ------ | ---- | -------- | ------ | ---- |
  | clock | input | Clock | N/A | Clock signal |
  | reset | input | Reset | N/A | Reset signal |
  | <signal> | <input/output> | <Chisel/protocol type, bit width> | <reset value or N/A> | <semantics> |

- **Clock and Reset Requirements**: Clock domain, synchronous/asynchronous reset, observable reset values.
- **External Dependencies**: Assumptions about upstream/downstream interfaces, handshakes, ordering, and response matching.

## Functional Description

Decompose the overall functionality into several functional groups. Use a `###` heading for each group, including an overview, execution flow, boundaries and exceptions, and performance and constraints. Use `####` subsections to describe fine-grained behavior.

### <Functional Group Name>
- **Overview**: The channels, transactions, capacity, and bit width this functional group covers.
- **Execution Flow**: Trigger condition -> state/data effect -> output obligation; describe rules rather than restating the source line by line.
- **Boundaries and Exceptions**: Handling rules for conflicts, backpressure, flush, replay, timeout, and erroneous inputs.
- **Performance and Constraints**: Concurrency and timing constraints.

#### <Fine-Grained Behavior>

More details about the  behavioral contract of the functional group.

### Subcomponent Description

#### Component <SubmoduleName>
<Observable behavior this DUT relies on the subcomponent to provide.> Only when `<SubmoduleName>` is itself being specced in this run (its own extracted `.scala` file is present and a `<SubmoduleName>_spec.md` will be written) add: For details, refer to the document `<SubmoduleName>_spec.md`. Otherwise describe the relied-upon behavior inline here and do NOT link to a `_spec.md` that will not exist.

### State Machines and Timing
- **State Machine List**: List architecturally visible states and their observable meaning.
- **State Transition Conditions**: Trigger condition -> next state.
- **Key Timing**: Pipeline stages, counter thresholds, and cycle relationships.

### Configuration Registers and Storage
| Register Name/Address | Access Attribute | Bit Field | Default | Description | Read/Write Side Effects |
| ------------- | -------- | ---- | ------ | ---- | ---------- |
| <name> | <internal/MMIO> | <bit range> | <default> | <observable meaning> | <update/clear conditions> |

- **Register Map Base Address**: Bus interface and base address; if none, write "No direct bus interface".
- **Configuration Flow**: Reset values and the effect of runtime configuration on observable behavior.

### Reset and Error Handling
- **Reset Behavior**: Observable state after reset.
- **Error Reporting**: Signals or states for timeout, retry, mismatch, and faults.
- **Self-Recovery Strategy**: retry/replay/drain/clear behavior and its boundaries.

### Parameterization and Configurable Features
- **Module Parameters**:

  | Parameter Name | Type/Range | Default | Functional Effect |
  | ------ | ------------- | ------ | -------- |
  | <param> | <type/range> | <instantiated value> | <observable effect> |

- **Runtime Configuration**: ...
- **Compile Macros/Generation Options**: ...

## Verification Requirements and Coverage Suggestions
- **Functional Coverage Points**: Checkable scenarios.
- **Constraints and Assumptions**: Input timing and protocol assumptions the testbench must satisfy.
- **Test Interfaces**: Driver, reference model, monitor, and assertion interfaces.
```

### `<ModuleName>_info.md`

Write the expected submodule specifications as a separate Markdown document. A "submodule" is a hardware unit `<ModuleName>` instantiates (e.g. `Module(new Sub)`), inherits from, or directly depends on (e.g. a Bundle type it exchanges on its interfaces). Each submodule entry is CALLER-DRIVEN: describe what `<ModuleName>` requires the submodule to guarantee, derived from how `<ModuleName>` instantiates, drives, and consumes it — not from the submodule's own implementation. Use the SAME section structure as `<ModuleName>_spec.md` for every entry; write `TBD` for items `<ModuleName>`'s usage does not constrain.

```markdown
# <ModuleName> Submodule Expected Specifications

> This document records the specification that `<ModuleName>` expects from each submodule it instantiates or directly depends on. It does not describe `<ModuleName>` itself. Each entry uses the same section structure as a `_spec.md` document.

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

<same section structure as above>
```

Start each entry with a `# Submodule: <SubmoduleName>` heading, where `<SubmoduleName>` is the exact declared Scala name, so downstream tooling can locate the entry for each submodule. If `<ModuleName>` has no submodules, write `(no submodules)` under the introductory blockquote and end the document.

---

## Content Requirements

- Include all top-level DUT ports in the spec. Preserve exact signal names from generated RTL or Chisel IO when available.
- Expand important Bundle, Decoupled, Valid, Vec, and nested fields into readable rows when relevant for verification.
- Include every public parameter or constructor argument that changes interface width, capacity, supported transaction count, timing, or protocol behavior.
- Verification goals must be checkable and falsifiable.
- The info file entries must reflect what the parent module relies on, so a submodule spec written later can be checked against them.

## Quick Reference

| Do | Do Not |
| :--- | :--- |
| Write both `<ModuleName>_spec.md` and `<ModuleName>_info.md` | Modify the `.scala` source |
| Keep the spec in the required section form | Document an implementation bug as intended behavior |
| Describe public IO, protocol, timing, reset, and data relationships | Restate source assignments line by line |
| Cite relevant source locations with `path/to/File.scala:line-line` tags | Invent ports or rename signals |
| In the info file, write one expected spec per submodule in the same section form | Describe `<ModuleName>` itself in the info file |
| Write everything in English, translating non-English source/context | Copy Chinese or other non-English text into output files |

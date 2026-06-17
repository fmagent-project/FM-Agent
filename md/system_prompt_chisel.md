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

Decompose the overall functionality into several functional groups. Use a `###` heading for each functional group, including an overview, execution flow, boundaries and exceptions, and performance and constraints. Every functional group MUST contain at least one function point, written as a `####` subsection. A function point names a single, verifiable behavior of the group; it is the unit that downstream coverage testing targets. Never leave a functional group without at least one function point.

### Coverage Tags

Every functional group, function point, and check point MUST carry an explicit coverage tag so the downstream checker tool can parse them. The tag format is strict:

- Functional group: `<FG-{group-name}>` placed on its own line immediately after the `###` group heading.
- Function point: `<FC-{function-name}>` placed on its own line immediately after the `####` function-point heading.
- Check point: `<CK-{check-point-name}>` placed at the start of each check-point bullet.

Tag placement rules:
- A `<FG-...>`/`<FC-...>` tag is on its own line, separated from the heading and the following prose by blank lines. Do NOT append a tag to the heading line itself.
- `{group-name}`, `{function-name}`, and `{check-point-name}` are short uppercase identifiers (words joined by `-`), e.g. `FG-ARITHMETIC`, `FC-ADD`, `CK-OVERFLOW`.
- The tags form a tree: sibling nodes under the same parent MUST NOT share the same name (two function points in one group cannot both be `<FC-ADD>`; check-point names need only be unique within their function point).
- A check point is referenced by joining the tags with `/`, e.g. `FG-ARITHMETIC/FC-ADD/CK-OVERFLOW`.

The spec MUST include a `<FG-API>` functional group: the test-API group covering the standard APIs needed to verify the DUT (drivers, reference-model hooks, monitors). Include it in addition to the behavioral functional groups.

### <Functional Group Name>

<FG-{GROUP-NAME}>

- **Overview**: The channels, transactions, capacity, and bit width this functional group covers.
- **Execution Flow**: Trigger condition -> state/data effect -> output obligation; describe rules rather than restating the source line by line.
- **Boundaries and Exceptions**: Handling rules for conflicts, backpressure, flush, replay, timeout, and erroneous inputs.
- **Performance and Constraints**: Concurrency and timing constraints.

#### <Function Point Name>

<FC-{FUNCTION-NAME}>

A function point describes one fine-grained, verifiable behavior of the functional group (also called a test point). State its behavioral contract precisely: trigger condition, the data/state effect, and the observable output obligation. Add one `####` function point per distinct behavior, and ensure each functional group has at least one.

Every function point MUST list at least one check point (also called a test bin) under a `**Check points:**` line, with one bullet per check point. A check point is a concrete, falsifiable scenario that verifies part of the function point — e.g. a normal case, a boundary, an overflow, an error condition, or a reset case. Keep check points independent from one another, with no cross-coverage of the same condition. Never leave a function point without at least one check point.

**Check points:**
- <CK-{CHECK-POINT-NAME-1}> Check point 1: the specific condition exercised and the expected observable result.
- <CK-{CHECK-POINT-NAME-2}> Check point 2: another distinct, falsifiable scenario.

### Subcomponent Description

#### Component <SubmoduleName>
<Observable behavior this DUT relies on the subcomponent to provide.> Only when `<SubmoduleName>` is itself being specced in this run (its own extracted `.scala` file is present and a `<SubmoduleName>_spec.md` will be written) add: For details, refer to the document `<SubmoduleName>_spec.md`. Otherwise describe the relied-upon behavior inline here and do NOT link to a `_spec.md` that will not exist. Never write meta-commentary about the spec-generation process itself (e.g. "this submodule is not specced in this run", "no `_spec.md` is generated"); the document describes the hardware contract only.

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
| Give every functional group at least one `####` function point | Leave a functional group with no function point |
| Give every function point at least one check point under `**Check points:**` | Leave a function point with no check point |
| Tag every group/point/check point with `<FG-...>`/`<FC-...>`/`<CK-...>` and include the `<FG-API>` group | Omit a coverage tag, append a tag to a heading line, or reuse a sibling name |
| Describe public IO, protocol, timing, reset, and data relationships | Restate source assignments line by line |
| Cite relevant source locations with `path/to/File.scala:line-line` tags | Invent ports or rename signals |
| In the info file, write one expected spec per submodule in the same section form | Describe `<ModuleName>` itself in the info file |
| Write everything in English, translating non-English source/context | Copy Chinese or other non-English text into output files |

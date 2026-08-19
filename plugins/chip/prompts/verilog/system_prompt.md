# Verilog/SystemVerilog Module Specification Rules

Write two standalone English Markdown documents beside every extracted
Verilog/SystemVerilog module source. Never modify the extracted source or the
original project source.

- `<ExtractedStem>_spec.md` defines the intended observable contract of that
  extracted hardware module.
- `<ExtractedStem>_info.md` defines what the module requires each direct
  instantiated module to guarantee.

Use the exact extracted filename stem for both artifact names. The extracted
stem can differ from the declared module name when declarations were
canonicalized or deduplicated.

## Behavioral boundary

- Describe what the elaborated RTL guarantees, not a line-by-line account of
  assignments, procedural blocks, continuous assignments, or generate code.
- Treat preprocessor macros, parameter overrides, package configuration, and
  `generate` conditions as compile/elaboration-time choices. Describe their
  observable effect on ports, widths, capacity, topology, timing, or supported
  features; do not present them as runtime clocked behavior.
- Preserve exact declared module, parameter, port, interface, struct field, and
  direct dependency names.
- Record every observable port with its direction, packed/unpacked width or
  type, signedness when relevant, and protocol meaning. Expand
  verification-relevant interfaces, modports, arrays, structs, unions, enums,
  and nested fields when the source establishes them.
- Distinguish combinational behavior from edge-triggered sequential behavior.
  Cover clock/reset domains, reset polarity and kind, state transitions,
  transaction boundaries, ordering, backpressure, arbitration, latency,
  throughput, and error behavior when observable and established.
- Do not infer behavior from signal naming alone. Do not invent ports, widths,
  signedness, reset values, submodules, cycle relationships, or protocol rules.
  Mark genuinely unresolved facts as `TBD`.
- Describe intended correct behavior. An implementation defect is not part of
  the intended contract.
- Use precise, falsifiable English. Avoid claims such as "properly",
  "correctly handles", "appropriate", or "as expected" unless the exact
  condition and observable result are stated.
- Cite relevant project-relative source locations and line numbers when they
  are available.

## `<ExtractedStem>_spec.md`

Use this top-level structure. A section that does not apply must say `None`,
`N/A`, or `TBD`; do not silently omit required information.

```markdown
# <DeclaredModuleName> Specification Document

## Introduction
## Terms and Abbreviations in RTL Code
## RTL Source Files
## Top-Level Interface Overview
## Functional Description
## Subcomponent Description
## State Machines and Timing
## Configuration Registers and Storage
## Reset and Error Handling
## Parameterization and Configurable Features
## Verification Requirements and Coverage Suggestions
```

The interface overview must identify the declared module and every observable
port, including exact direction, width/type, signedness, and clock/reset
semantics. The parameterization section must separate parameters, macros, and
generate-time choices from runtime configuration. State/timing sections must
state trigger, state/data effect, sampling edge or combinational condition, and
observable result rather than transcribing RTL statements.

### Coverage tree

Organize all observable behavior as a machine-checkable FG/FC/CK tree:

- Each functional group has a `###` heading followed by an `<FG-NAME>` tag on
  its own line.
- Each group contains at least one function point with a `####` heading followed
  by an `<FC-NAME>` tag on its own line.
- Each function point contains at least one check-point bullet carrying a
  `<CK-NAME>` tag.
- Names use only uppercase letters, digits, and dashes. Functional-group names
  are document-unique, function-point names are unique within their group, and
  check-point names are unique within their function point.
- Every function point states a falsifiable trigger, state/data effect, and
  observable result, including cycle relationships only when established.
- Include an `<FG-API>` group covering the drivers, monitors, reference-model
  observations, clock/reset control, and assertions needed to verify the
  module's interfaces.

Example shape:

```markdown
### Interface API

<FG-API>

#### Request handshake

<FC-REQUEST-HANDSHAKE>

**Check points:**
- <CK-BACKPRESSURE> When request valid is held while ready is low, no transfer
  occurs and request information remains stable as required by the interface.
```

## `<ExtractedStem>_info.md`

This document is caller-driven: derive each entry from how the parent connects,
drives, samples, and depends on the child, not from a summary of the child's own
implementation.

Start every known direct module dependency with exactly:

```markdown
# Submodule: <ExactDeclaredName>
```

Under the heading, state the ports, parameter assumptions, timing, reset,
protocol, ordering, and data guarantees the parent requires. Use the exact
declared module type, not an instance label, interface type, package name,
filename, or file-qualified graph identifier. Include each direct module type
once even when several instances or a generate loop instantiate it.

Verilog dependency coverage is blocking: every direct module dependency
provided in the batch context must have a non-empty matching entry. Do not omit
a dependency merely because its implementation is external, encrypted, or not
part of this run; describe the caller-visible requirement supported by the
parent source and use `TBD` for facts the parent does not constrain.

If the module has no known direct submodules, write the exact marker
`(no submodules)` and do not add a `# Submodule:` entry. Never combine the leaf
marker with submodule entries, and never invent a dependency.

## Final checks

Before finishing each module, confirm that:

1. Both sibling Markdown artifacts exist and the extracted source is unchanged.
2. The spec contains `<FG-API>` and every FG contains an FC with at least one CK.
3. Module, parameter, port, width/type, clock/reset, and protocol claims are
   supported by source or domain context.
4. Every known direct instantiated module type has one non-empty
   `# Submodule:` entry, or the module is explicitly marked `(no submodules)`.
5. Repeated instances are folded into one module-type dependency contract.
6. Both documents are entirely in English.

# Chisel Module Specification Rules

Write two standalone English Markdown documents beside every extracted Chisel
module source. Never modify the extracted source or the original project source.

- `<ExtractedStem>_spec.md` defines the intended observable contract of that
  extracted hardware module.
- `<ExtractedStem>_info.md` defines what the module requires each direct
  submodule to guarantee.

Use the exact extracted filename stem for both artifact names. The extracted
stem can differ from the declared Scala name when declarations were
canonicalized or deduplicated.

## Behavioral boundary

- Describe what the elaborated hardware guarantees, not a line-by-line account
  of Chisel assignments or Scala control flow.
- Treat constructor arguments, Scala conditionals/loops, generators, implicits,
  and type-level computation as elaboration-time behavior. Describe their
  observable effect on ports, widths, capacity, topology, or supported features;
  do not present them as runtime clocked behavior.
- Preserve exact port, Bundle field, parameter, and declared submodule names.
- Treat a Chisel Bundle, trait, or base type that is directly used by the
  target as dependency context even when it has no standalone artifact. Its
  fields, inherited parameters, and width expressions may be required to
  explain the target interface or the caller's dependency contract.
- Expand verification-relevant `Bundle`, `Vec`, `Decoupled`, `Valid`, enum, and
  nested interface fields. State direction, width/type, and handshake meaning
  only when supported by the source or domain context.
- Cover clock/reset behavior, state transitions, transaction boundaries,
  ordering, backpressure, arbitration, latency, throughput, and error behavior
  when they are observable and established.
- Do not invent ports, widths, reset values, submodules, cycle relationships, or
  protocol rules. Mark genuinely unresolved facts as `TBD`.
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
## Terms and Abbreviations in Chisel Code
## Chisel Source Files
## Top-Level Interface Overview
## Functional Description
## Subcomponent Description
## State Machines and Timing
## Configuration Registers and Storage
## Reset and Error Handling
## Parameterization and Configurable Features
## Verification Requirements and Coverage Suggestions
```

The interface overview must identify the declared module, all observable ports
and nested fields, their directions and widths/types, and clock/reset semantics.
The parameterization section must separate elaboration parameters from runtime
configuration. The state/timing sections must state trigger, state/data effect,
and observable result rather than transcribing implementation statements.

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
  observable result.
- Include an `<FG-API>` group covering the drivers, monitors, reference-model
  observations, and assertions needed to verify the module's interfaces.

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

## Dependency versus artifact boundary

The standalone artifact boundary is narrower than the Chisel dependency
boundary. A declaration without `val io` is context-only: do not write its own
`_spec.md` or `_info.md`, but do not erase it from a parent module's dependency
analysis. When the parent directly instantiates, exchanges, extends, or mixes
in a Chisel declaration, describe the guarantee the parent requires under a
`# Submodule: <ExactDeclaredName>` entry. External declarations that are not
available in the extracted scope should be identified as external and kept
qualified with `TBD` details rather than invented.

## `<ExtractedStem>_info.md`

This document is caller-driven: derive each entry from how the parent drives,
observes, and depends on the child, not from a summary of the child's own
implementation.

Start every direct dependency with exactly:

```markdown
# Submodule: <ExactDeclaredName>
```

Under the heading, state the interface, timing, reset, protocol, ordering, and
data guarantees the parent requires. For Chisel, a direct dependency may be a
hardware module, a Bundle exchanged through an interface, or a trait/base type
whose parameters or fields affect the target. Use the declared Chisel name, not
an instance variable name or a file-qualified graph identifier. Include each
known direct dependency once even when it is instantiated multiple times. A
context-only dependency may appear here without receiving standalone artifacts.

If the module has no known direct submodules, write the exact marker
`(no submodules)` and do not add a `# Submodule:` entry. Never combine the leaf
marker with submodule entries. Dynamic elaboration may make source-derived
dependency information incomplete; do not invent a dependency to compensate.

## Final checks

Before finishing each module, confirm that:

1. Both sibling Markdown artifacts exist and the extracted source is unchanged.
2. The spec contains `<FG-API>` and every FG contains an FC with at least one CK.
3. Port, Bundle field, parameter, clock/reset, and protocol claims are supported.
4. Every known direct Chisel dependency has one non-empty `# Submodule:` entry,
   or the module is explicitly marked `(no submodules)` when no dependency is
   known. This includes directly consumed context-only Bundle/trait/base types.
5. Cover each applicable behavior with falsifiable normal, boundary, conflict,
   reset/flush/replay, latency/backpressure, and error cases without inventing
   unsupported cases.
6. Both documents are entirely in English.

# Generate Chisel Domain Context

Read the finalized `fm_agent/phases.json`, then create only:

- `fm_agent/spec_prompts/domain_context/engine_overview.txt`
- one `fm_agent/spec_prompts/domain_context/phase_NN_types.txt` for every phase

Do not modify `phases.json`, project sources, or files outside those output
paths. Write all output in English.

## `engine_overview.txt`

Describe the project-wide hardware contract and architecture:

- major hardware modules and their direct instantiation hierarchy;
- data and control flow between modules;
- clock and reset domains, including reset kind, polarity, and observable reset
  behavior when the source establishes them;
- Decoupled/ready-valid, Valid, memory, interrupt, bus, and custom protocol
  conventions, including backpressure and ordering rules;
- shared width, encoding, addressing, alignment, arbitration, and priority
  conventions;
- top-level constructor parameters and elaboration choices that change ports,
  capacity, topology, or supported behavior;
- cross-module invariants relevant to verification.

State uncertainty explicitly. Do not infer a cycle relationship, reset value,
port, width, or protocol guarantee that the sources do not establish.

## `phase_NN_types.txt`

For each phase, read every source file assigned to that phase and document the
hardware modules plus the context declarations they use. Cover, where present:

- module constructor parameters and their observable hardware effects;
- top-level IO and nested `Bundle`, `Vec`, `Decoupled`, `Valid`, enum, and custom
  interface fields with exact names, directions, widths/types, and encodings;
- clock/reset expectations and clock-domain crossings;
- registers, memories, queues, visible state machines, and reset values;
- transaction triggers, handshake completion, backpressure, ordering, latency,
  throughput, arbitration, flush/replay, and error behavior;
- direct submodule relationships and the behavior each parent relies on;
- elaboration conditions that add/remove modules, fields, widths, or features.

Bundle, parameter, type, constant, and helper-only files are context, not
independent hardware specification units. Clearly distinguish elaboration-time
Scala behavior from behavior observable after the circuit has been elaborated.

Do not run sbt, mill, Chisel generators, CIRCT, firtool, simulators, or any
other project toolchain. Base the context only on the source and supplied domain
knowledge.

Before finishing, confirm that `engine_overview.txt` and every required
`phase_NN_types.txt` exist, are non-empty, are written in English, and match the
final phase numbering and source-file assignments.

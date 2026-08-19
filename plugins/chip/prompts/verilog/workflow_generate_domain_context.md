# Generate Verilog/SystemVerilog Domain Context

Read the finalized `fm_agent/phases.json`, then create only:

- `fm_agent/spec_prompts/domain_context/engine_overview.txt`
- one `fm_agent/spec_prompts/domain_context/phase_NN_types.txt` for every phase

Do not modify `phases.json`, project sources, or files outside those output
paths. Write all output in English.

## `engine_overview.txt`

Describe the project-wide RTL contract and architecture:

- major modules and their direct instantiation hierarchy, using module types
  rather than instance labels;
- data and control flow between modules;
- clock and reset domains, including synchronous/asynchronous behavior,
  polarity, and observable reset state when established by the source;
- ready/valid, request/response, streaming, memory, interrupt, bus, and custom
  protocol conventions, including backpressure and ordering rules;
- shared width, encoding, addressing, alignment, arbitration, priority, and
  error conventions;
- top-level parameters, macros, and generate choices that alter ports, widths,
  capacity, topology, timing, or supported features;
- cross-module invariants relevant to verification.

State uncertainty explicitly. Do not infer a cycle relationship, reset value,
port, width, instance, or protocol guarantee that the sources do not establish.

## `phase_NN_types.txt`

For each phase, read every source file assigned to that phase and document the
design modules plus the context declarations they use. Cover, where present:

- module parameters and local parameters, their defaults/overrides, and their
  observable hardware effects;
- exact port names, directions, packed/unpacked widths, signedness, interface
  modports, structs/unions/enums, arrays, and relevant package typedefs;
- clock/reset expectations, multiple clock domains, and clock-domain crossings;
- registers, memories, queues, visible state machines, and established reset
  values;
- combinational versus sequential behavior and transaction trigger, handshake,
  backpressure, ordering, latency, throughput, arbitration, flush/replay, and
  error rules;
- direct instantiated module types, parameter overrides, port connections, and
  the behavior each parent relies on;
- preprocessor macros, include/header context, package imports, interfaces, and
  `generate` conditions that change the elaborated design.

Package, interface, header, macro, typedef, parameter, and helper-only files are
context, not independent module specification units. Clearly separate
compile/preprocessor and generate-time configuration from behavior observable
after RTL elaboration.

Do not run preprocessors, compilers, linters, simulators, synthesis,
elaboration, Verible, Verilator, Icarus Verilog, Yosys, or any project
toolchain. Base the context only on source and supplied domain knowledge.

Before finishing, confirm that `engine_overview.txt` and every required
`phase_NN_types.txt` exist, are non-empty, are written in English, and match the
final phase numbering and source-file assignments.

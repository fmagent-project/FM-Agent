# Generate Chisel Domain Context

Read the finalized `fm_agent/phases.json`, then create only:

- `fm_agent/spec_prompts/domain_context/engine_overview.txt`
- one `fm_agent/spec_prompts/domain_context/phase_NN_types.txt` for every phase

Do not modify `phases.json` or any project source.

In `engine_overview.txt`, describe the hardware architecture, module hierarchy,
data/control flow, clock and reset domains, protocols, and major elaboration
conditions. In each phase file, document the Chisel modules and relevant
Bundles, parameters, widths/types, directions, Decoupled or other handshake
semantics, state transitions, timing guarantees, and invariants used by that
phase.

Distinguish elaboration-time Scala behavior from observable hardware behavior.
Do not invent widths, ports, submodules, cycle relationships, or protocol rules
that the listed sources do not establish. Do not run sbt, CIRCT, firtool, or any
other Chisel toolchain.

Before finishing, confirm that `engine_overview.txt` and every required
`phase_NN_types.txt` exist and are non-empty.

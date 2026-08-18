# Generate Verilog/SystemVerilog Domain Context

Read the finalized `fm_agent/phases.json`, then create only:

- `fm_agent/spec_prompts/domain_context/engine_overview.txt`
- one `fm_agent/spec_prompts/domain_context/phase_NN_types.txt` for every phase

Do not modify `phases.json` or any project source.

In `engine_overview.txt`, describe the RTL architecture, module hierarchy,
data/control flow, clock and reset domains, interfaces, and major protocols. In
each phase file, document modules, ports, directions, widths, parameters,
relevant macros and typedefs, instantiated children, state transitions, cycle
relationships, handshake rules, and invariants used by that phase.

Separate compile/elaboration configuration from observable RTL behavior. Do not
invent widths, ports, instances, timing guarantees, or protocol rules that the
listed sources do not establish. Do not run simulations or synthesis.

Before finishing, confirm that `engine_overview.txt` and every required
`phase_NN_types.txt` exist and are non-empty.

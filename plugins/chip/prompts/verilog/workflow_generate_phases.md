# Generate a Verilog/SystemVerilog Phase Plan

Write only `fm_agent/phases.json`. Do not edit project sources or create domain
context files in this stage.

Inspect the RTL design and group its source files into dependency-ordered
hardware phases. A phase is an architectural grouping, not a compiler, lint,
simulation, or synthesis step. Use module instantiation, shared interfaces, and
data/control flow to choose the grouping.

The output must use this standard shape:

```json
{
  "project": "<project name>",
  "languages": ["verilog"],
  "file_extensions": ["v", "sv", "svh"],
  "phases": [
    {
      "phase": 1,
      "name": "<phase name>",
      "description": "<hardware responsibility>",
      "modules": [
        {
          "name": "<subsystem name>",
          "description": "<module responsibilities and interfaces>",
          "source_files": ["rtl/module.sv"]
        }
      ],
      "depends_on_phases": []
    }
  ]
}
```

## Verilog/SystemVerilog source model

- Every `module` declaration is a hardware specification unit. A source file
  may declare several modules; keep the file in one source group because later
  stages extract the individual modules.
- Packages, interfaces, headers, macros, parameters, typedefs, and helper-only
  files are context. Do not describe them as independent design modules, but
  their source files still belong in the phase plan when they are in scope.
- A module type is distinct from its instance labels. Repeated instances of one
  module type express one module-level dependency.
- Preprocessor choices, parameter overrides, and `generate` constructs select
  elaborated RTL structure. Do not present them as runtime clock cycles.

## Required rules

- `languages` must be exactly `["verilog"]`.
- `file_extensions` must be exactly `["v", "sv", "svh"]`, even when the
  project happens to use only a subset of those extensions.
- Include every in-scope, non-test `.v`, `.sv`, and `.svh` source file exactly
  once. This includes package, interface, macro, typedef, include/header, and
  helper-only files because design modules may require them as context.
- Source paths must be project-relative. Never list a file more than once.
- Exclude testbench, test, verification, and simulation trees and files;
  generated/build output; hidden workspace directories; and `fm_agent/`.
- Exclude every Scala/Chisel source. Mixed-language analysis is not part of this
  run.
- Preserve module-instantiation dependency order: a phase may depend only on
  earlier phases.
- Every phase and source group must have a concrete hardware-oriented name and
  description. Do not call a package, interface, header, or helper a module.
- Do not run compilers, preprocessors, linters, simulators, synthesis,
  elaboration, Verible, Verilator, Icarus Verilog, Yosys, or install tools.

Before finishing, parse the JSON and confirm that every in-scope Verilog or
SystemVerilog source is listed exactly once and at least one source file is
present.

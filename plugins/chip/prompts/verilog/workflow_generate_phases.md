# Generate a Verilog/SystemVerilog Phase Plan

Write only `fm_agent/phases.json`. Do not edit project sources or create domain
context files in this stage.

Inspect the RTL design and group design modules into dependency-ordered phases.
Top-level `module` declarations are hardware units. Packages, interfaces,
headers, macros, typedef-only files, and helpers may provide context but must not
be represented as independent modules when they contain no design module.

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

Rules:

- `languages` must be exactly `["verilog"]`.
- `file_extensions` must be exactly `["v", "sv", "svh"]`.
- Source paths are project-relative and each source file appears at most once.
- Include only `.v`, `.sv`, and `.svh` design sources.
- Exclude testbench, simulation, test, generated/build output, and `fm_agent/`
  trees, and exclude all Scala/Chisel sources.
- Preserve module-instantiation dependency order: a phase may depend only on
  earlier phases.
- Do not run simulations, synthesis, or install tools.

Before finishing, parse the JSON and confirm that at least one Verilog or
SystemVerilog source is listed.

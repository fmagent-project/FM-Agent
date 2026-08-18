# Generate a Chisel Phase Plan

Write only `fm_agent/phases.json`. Do not edit project sources or create domain
context files in this stage.

Inspect the Chisel design and group its hardware modules into dependency-ordered
phases. Treat top-level declarations extending `Module`, `RawModule`,
`BlackBox`, `ExtModule`, or `MultiIOModule` as hardware units. Bundles, ordinary
Scala classes/objects/traits, parameters, and helpers may inform grouping but
must not become independent hardware units.

The output must use this standard shape:

```json
{
  "project": "<project name>",
  "languages": ["chisel"],
  "file_extensions": ["scala", "sc"],
  "phases": [
    {
      "phase": 1,
      "name": "<phase name>",
      "description": "<hardware responsibility>",
      "modules": [
        {
          "name": "<subsystem name>",
          "description": "<module responsibilities and interfaces>",
          "source_files": ["src/main/scala/example/Module.scala"]
        }
      ],
      "depends_on_phases": []
    }
  ]
}
```

Rules:

- `languages` must be exactly `["chisel"]`.
- `file_extensions` must be exactly `["scala", "sc"]`.
- Source paths are project-relative and each source file appears at most once.
- Include only `.scala` and `.sc` sources that contribute Chisel hardware.
- Exclude `src/test`, test/testbench trees, generated/build output, `fm_agent/`,
  and all Verilog/SystemVerilog sources. Verilog blackboxes may be read for
  context but are not independent specification units in this run.
- Preserve dependency order: a phase may depend only on earlier phases.
- Do not run the project, invoke sbt, elaborate Chisel, or install tools.

Before finishing, parse the JSON and confirm that at least one Chisel source is
listed.

# Generate a Chisel Phase Plan

Write only `fm_agent/phases.json`. Do not edit project sources or create domain
context files in this stage.

Inspect the Chisel design and group its source files into dependency-ordered
hardware phases. A phase is an architectural grouping, not a Scala compilation
step. Use module instantiation, shared interfaces, and data/control flow to
choose the grouping.

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
          "name": "<source group name>",
          "description": "<hardware and context responsibilities>",
          "source_files": ["src/main/scala/example/Module.scala"]
        }
      ],
      "depends_on_phases": []
    }
  ]
}
```

## Chisel source model

- Top-level declarations extending `Module`, `RawModule`, `BlackBox`,
  `ExtModule`, or `MultiIOModule` are hardware specification units.
- Bundles, ordinary Scala classes/objects/traits, parameters, type aliases, and
  helpers are context. They must not be described as independent hardware
  modules, but their source files still belong in the phase plan.
- A single source file may declare several hardware modules. Keep that source
  file in one source group; later stages extract the individual modules.
- Distinguish Scala elaboration-time dependencies from runtime hardware data
  flow. Use both when arranging phases, but do not claim that elaboration
  executes in hardware cycles.

## Required rules

- `languages` must be exactly `["chisel"]`.
- `file_extensions` must be exactly `["scala", "sc"]`, even when the project
  happens to use only one of the two extensions.
- Include every in-scope, non-test `.scala` and `.sc` source file exactly once.
  This includes files containing only Bundles, parameters, types, constants,
  annotations, or helper code because hardware modules may require them as
  context.
- Source paths must be project-relative. Never list a file more than once.
- Exclude `src/test`, test/spec/testbench trees and files, generated/build
  output, hidden workspace directories, and `fm_agent/`.
- Exclude every Verilog/SystemVerilog file. Blackbox RTL may be read as context,
  but it is not a Chisel specification unit in this run.
- Preserve dependency order: a phase may depend only on earlier phases.
- Every phase and source group must have a concrete hardware-oriented name and
  description. Do not call a Bundle/helper source a hardware module.
- Do not run the project, invoke sbt, elaborate Chisel, invoke CIRCT/firtool, or
  install tools.

Before finishing, parse the JSON and confirm that every in-scope Chisel source
is listed exactly once and at least one source file is present.

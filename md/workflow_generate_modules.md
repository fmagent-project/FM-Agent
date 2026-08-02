# Generate Source and Module Manifests

> **YOUR SOLE OBJECTIVE**: Write `fm_agent/source_files.json` and `fm_agent/modules.json`. Do NOT write domain context files yet. Do NOT edit project source files. Only create files inside `fm_agent/`.

Required outputs:

1. `fm_agent/source_files.json`
2. `fm_agent/modules.json`

`fm_agent/` is not part of the project source code. Do not include any `fm_agent/` path in either manifest.

## Write `source_files.json`

Scan `<project root>` and list all non-test source files that should be analyzed.
Exclude test files and test directories such as `test/`, `tests/`, `__tests__/`, `*_test.*`, `test_*.*`, and `*.spec.*`.

Use this shape:

```json
{
  "project": "<project directory name>",
  "languages": ["<language names>"],
  "file_extensions": ["<extensions without dots>"],
  "source_files": ["relative/path/from/project/root.ext"]
}
```

## Write `modules.json`

Group the source files into semantic modules: small, functionally complete
components with coherent responsibilities, data ownership, protocols, or
invariants. Use directory layout as evidence only; do not mirror the directory
tree unless it also matches a real component boundary.

Use this shape:

```json
{
  "project": "<project directory name>",
  "languages": ["<language names>"],
  "file_extensions": ["<extensions without dots>"],
  "modules": [
    {
      "name": "<module_name>",
      "description": "<what this module owns and the invariants it maintains>",
      "source_files": ["relative/path/from/project/root.ext"]
    }
  ]
}
```

Rules:

- Every `modules[*].source_files[]` entry must also appear in `source_files.json`.
- Each source file should appear in at most one module.
- Keep module names stable, short, and semantic. Use slug names without `/`, such
  as `tools_validate`, `fasttest_compiler`, or `orchestration`.
- Do not create parent/child directory modules such as `tools` and
  `tools_validate` unless they own clearly different responsibilities.
- Each module description must explain what the module owns and the key
  invariants or contracts it maintains.

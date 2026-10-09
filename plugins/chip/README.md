# Chip plugin

[English](README.md) | [中文](README_zh.md)

The built-in `chip` plugin generates verification-oriented behavioral
specifications for Chisel and Verilog/SystemVerilog modules, then writes a
Chinese design and functional-checkpoint document for the selected root DUT.
It reuses the public Stage 1–6 Pipeline for source scoping, planning,
extraction, dependency ordering, LLM scheduling, validation, retries, and
traces. A chip run does not run software reasoning or bug validation.

## Quick start

The target must be a Git repository. Configure FM-Agent and its LLM provider as
described in the [root README](../../README.md), then run:

```bash
uv run python main.py /path/to/hardware-repo --plugin chip
```

Limit a mixed or monorepo checkout to one hardware subtree with a project-
relative directory:

```bash
uv run python main.py /path/to/repo --plugin chip --submodule rtl
```

Without `--resume`, FM-Agent starts a fresh run and replaces the existing
`fm_agent/` workspace. Resume an interrupted run with the same source scope and
configuration:

```bash
uv run python main.py /path/to/hardware-repo --plugin chip --resume
```

## Dialect selection

The plugin scans the selected source scope before Stage 1:

| In-scope source | Selected Profile |
| --- | --- |
| `.scala` or `.sc` | `chip-chisel` |
| `.v`, `.sv`, or `.svh`, with no Chisel source | `chip-verilog` |

When both dialects are present, Chisel wins and FM-Agent emits a warning. The
same run does not analyze both dialects, and there is no explicit dialect flag.
Use a narrower project directory or `--submodule` to run the intended subtree.
If no supported hardware source is found, the run fails before making LLM calls.

Hidden directories and common generated or dependency directories such as
`target`, `build`, `out`, `dist`, `node_modules`, virtual environments, and
`fm_agent` are excluded from hardware source discovery. Testbench-style files
and directories are also excluded from normal extraction.

## Chisel backends

### Source analysis

Source analysis is the default and requires no Chisel build tool. It extracts
Scala classes, objects, traits, and definitions as dependency context. Only a
declaration classified as a hardware `Module` and defining `val io` receives
standalone `_spec.md` and `_info.md` artifacts. Other declarations remain in
the dependency graph so that Bundle, trait, base-class, and companion-object
requirements can still inform module specifications.

Source analysis does not elaborate Scala. Dynamically selected
`Module(...)` constructions and dependencies created only by generators may be
unresolved; FM-Agent warns when it recognizes a dynamic construction it cannot
map. Use CIRCT when the elaborated module graph is required.

### Direct CIRCT analysis

CIRCT analysis is opt-in because FM-Agent needs an already elaborated FIRRTL
`.fir` or MLIR `.mlir` file. Install the pinned `firtool` and matching graph
pass plugin with:

```bash
./install.sh --with-chisel
```

Ensure `~/.local/bin` is on `PATH`, then provide the elaborated input:

```bash
FM_AGENT_CHISEL_CIRCT_INPUT=/absolute/path/to/design.fir \
uv run python main.py /path/to/chisel-repo --plugin chip
```

The following variables override tool discovery:

| Variable | Meaning |
| --- | --- |
| `FM_AGENT_CHISEL_CIRCT_INPUT` | Elaborated `.fir` or `.mlir` input; relative paths resolve from the target repository |
| `FM_AGENT_CHISEL_CIRCT_COMMAND` | `firtool` command and fixed arguments; default `firtool` |
| `FM_AGENT_CHISEL_CIRCT_PLUGIN` | Exact graph pass plugin path |
| `FM_AGENT_CHISEL_CIRCT_TIMEOUT_SECONDS` | Command timeout; default `180` |

The installed plugin is discovered automatically under `~/.local/lib`.
Successful direct analysis writes
`fm_agent/chisel_circt_module_graph.json`; the selected backend is also recorded
in `fm_agent/chip/eligibility.json`. Missing input, tools, incompatible output,
or execution failure produces a warning and falls back to source analysis
instead of aborting the run. See
[`tools/chisel-circt/README.md`](../../tools/chisel-circt/README.md) for manual
build details.

## Verilog/SystemVerilog backends

FM-Agent uses `verible-verilog-syntax` when that executable is available on
`PATH`. Verible supplies syntax-aware module spans and direct instantiation
edges. If it is unavailable, rejects a source file, or exposes an unsupported
syntax-tree schema, FM-Agent falls back to built-in source analysis. A valid
Verible result with no dependencies remains authoritative for a leaf module.

Force source analysis for comparison or diagnostics with:

```bash
FM_AGENT_NO_VERIBLE=1 \
uv run python main.py /path/to/verilog-repo --plugin chip
```

The source fallback recognizes common Verilog/SystemVerilog module declarations
and direct instantiations but is not a compiler or elaborator. Preprocessor-
dependent or heavily generated designs may therefore have a less complete
module graph than a Verible-backed run.

## Outputs and validation

Each eligible extracted module is stored below
`fm_agent/extracted_functions/` with two adjacent Markdown artifacts:

```text
fm_agent/extracted_functions/<unit>/
├── <Module>.<source-extension>
├── <Module>_spec.md
└── <Module>_info.md
```

- `_spec.md` describes the module's observable interface and behavioral
  contract as an FG/FC/CK coverage tree, including the mandatory `<FG-API>`
  group.
- `_info.md` records caller-driven requirements for each known direct
  dependency under `# Submodule: <DeclaredModuleName>`. A leaf uses the exact
  marker `(no submodules)`.

Both artifacts must exist and satisfy the Markdown structure before a module is
ready. Missing known dependency coverage is advisory for Chisel and blocking
for Verilog. Invalid artifacts are regenerated through the public Stage 6 retry
path. Run metadata and diagnostics remain under `fm_agent/trace/`; generated
source copies are never written back to the original RTL files.

After the module artifacts are ready, the chip plugin also generates:

```text
fm_agent/chip/design_document.md
```

This Chinese design and functional-checkpoint document follows the bundled
v4.0.0 template and combines module specs/info with source context. Generation
requires exactly one artifact-eligible root DUT; use `--submodule` to narrow
the analysis scope when necessary.

The selected directories define the document target. The agent may explore
related callers, interfaces, and configuration elsewhere in the repository.
Unresolved configuration and evidence remain OPEN. The document is regenerated
each time Stage 6 completes, including on `--resume`.

## Command-line compatibility

The chip plugin supports the common contracts for `--resume`, `--submodule`,
`--one-phase`, `--domain-knowledge`/`--knowledge`, `--extra-edge`, fresh
`--isolate` runs, and `--only-spec`. Because chip Profiles do not enter the
later software reasoning stages, `--only-spec` is optional; the design document
is generated in either mode.

The plugin rejects `--incremental`, `--end-func`, `--all-bugs`,
`--bug-validator`, and `--estimate`. Rejected combinations fail before creating
or modifying the run workspace and before invoking an LLM.

## Current limitations

- One run selects one dialect; mixed Chisel and Verilog analysis is not
  combined.
- Chip Profiles generate module specifications and the final design document.
  They do not perform the software reasoning and bug-validation stages.
- Chisel source analysis cannot guarantee complete resolution of dynamic or
  elaboration-only dependencies.
- Verilog source analysis is a fallback parser, not full preprocessing and
  elaboration.
- CIRCT input generation belongs to the target project's Chisel build; FM-Agent
  consumes an elaborated `.fir` or `.mlir` file but does not run `sbt`, Mill, or
  a project generator to create it.

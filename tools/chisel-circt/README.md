# FM-Agent Chisel CIRCT pass

This directory builds a `firtool` pass plugin that emits the elaborated FIRRTL
module and instantiation graph as JSON. It does not emit or parse Verilog.

Build it against the same CIRCT tree that supplies `firtool`:

```sh
cmake -G Ninja -S tools/chisel-circt -B tools/chisel-circt/build \
  -DCIRCT_DIR=/path/to/circt/build/lib/cmake/circt \
  -DMLIR_DIR=/path/to/circt/build/lib/cmake/mlir \
  -DLLVM_DIR=/path/to/circt/build/lib/cmake/llvm
ninja -C tools/chisel-circt/build FMAgentChiselCirctPlugin
```

Alternatively, `./install.sh --with-chisel` builds `firtool` and the plugin in
`$FM_AGENT_CIRCT_ROOT` (default: `~/.cache/fm-agent/circt`) and installs them
under `~/.local`. The installer pins a tested CIRCT commit; set
`FM_AGENT_CIRCT_REVISION` to intentionally test another revision and
`FM_AGENT_CIRCT_JOBS` to control build parallelism.

The Chisel handler enables the direct backend when
`FM_AGENT_CHISEL_CIRCT_INPUT` points to an elaborated `.fir` or `.mlir` file.
The remaining settings are optional:

- `FM_AGENT_CHISEL_CIRCT_COMMAND`: `firtool` command, including fixed arguments.
- `FM_AGENT_CHISEL_CIRCT_PLUGIN`: exact plugin library path.
- `FM_AGENT_CHISEL_CIRCT_TIMEOUT_SECONDS`: execution timeout; default `180`.

The pass output uses schema version 1 and contains `top`, `modules`, and
caller-to-callee `edges`. FM-Agent stores the successful, fingerprinted result
as `fm_agent/chisel_circt_module_graph.json`. Tool discovery or execution
failures are diagnostic-only and fall back to Chisel source analysis.

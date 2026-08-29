//===----------------------------------------------------------------------===//
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//===----------------------------------------------------------------------===//

#ifndef FM_AGENT_CHISEL_CIRCT_PASSES
#define FM_AGENT_CHISEL_CIRCT_PASSES

include "mlir/Pass/PassBase.td"

def EmitModuleGraph
    : Pass<"fm-agent-emit-chisel-module-graph", "circt::firrtl::CircuitOp"> {
  let summary = "Emit a Chisel module graph JSON file from FIRRTL";
  let description = [{
    Walks FIRRTL modules and instances, builds a module-level instantiation
    graph, and writes a JSON manifest with module symbols, source locations,
    instance edges, and the circuit top module.
  }];
  let options = [
    Option<"outputFile", "output-file", "std::string", "\"\"",
           "Path of the JSON graph file to write">
  ];
  let dependentDialects = ["::circt::firrtl::FIRRTLDialect"];
}

#endif // FM_AGENT_CHISEL_CIRCT_PASSES

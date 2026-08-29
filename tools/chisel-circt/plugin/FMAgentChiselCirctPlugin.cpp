//===----------------------------------------------------------------------===//
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//===----------------------------------------------------------------------===//

#include "FMAgentChiselCirct/Passes.h"
#include "llvm/Config/llvm-config.h"
#include "llvm/Support/Compiler.h"
#include "mlir/Tools/Plugins/PassPlugin.h"

extern "C" LLVM_ATTRIBUTE_WEAK mlir::PassPluginLibraryInfo
mlirGetPassPluginInfo() {
  return {
      MLIR_PLUGIN_API_VERSION,
      "FMAgentChiselCirctPasses",
      LLVM_VERSION_STRING,
      []() { fm_agent::chisel_circt::registerPasses(); },
  };
}

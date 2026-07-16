//===----------------------------------------------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#ifndef FM_AGENT_CHISEL_CIRCT_PASSES_H
#define FM_AGENT_CHISEL_CIRCT_PASSES_H

#include "mlir/Pass/Pass.h"
#include <memory>
#include <string>

namespace circt {
namespace firrtl {
class CircuitOp;
} // namespace firrtl
} // namespace circt

namespace fm_agent {
namespace chisel_circt {

#define GEN_PASS_DECL
#include "FMAgentChiselCirct/Passes.h.inc"

#define GEN_PASS_REGISTRATION
#include "FMAgentChiselCirct/Passes.h.inc"

std::unique_ptr<mlir::Pass> createEmitModuleGraphPass(std::string outputFile);

} // namespace chisel_circt
} // namespace fm_agent

#endif // FM_AGENT_CHISEL_CIRCT_PASSES_H

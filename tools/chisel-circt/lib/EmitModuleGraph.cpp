//===----------------------------------------------------------------------===//
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//===----------------------------------------------------------------------===//

#include "FMAgentChiselCirct/Passes.h"

#include "circt/Dialect/FIRRTL/FIRRTLOps.h"
#include "llvm/ADT/StringMap.h"
#include "llvm/ADT/StringSet.h"
#include "llvm/Support/FileSystem.h"
#include "llvm/Support/FormatVariadic.h"
#include "llvm/Support/JSON.h"
#include "llvm/Support/raw_ostream.h"
#include "mlir/IR/BuiltinAttributes.h"
#include "mlir/IR/BuiltinOps.h"
#include "mlir/IR/Location.h"
#include "mlir/IR/SymbolTable.h"

#include <optional>
#include <string>
#include <system_error>
#include <utility>

namespace fm_agent {
namespace chisel_circt {

#define GEN_PASS_DEF_EMITMODULEGRAPH
#include "FMAgentChiselCirct/Passes.h.inc"

namespace {

struct SourceLocation {
  std::string file;
  unsigned line = 0;
  unsigned column = 0;
};

static std::optional<SourceLocation> findSourceLocation(mlir::Location loc) {
  if (auto fileLoc = llvm::dyn_cast<mlir::FileLineColLoc>(loc))
    return SourceLocation{fileLoc.getFilename().str(), fileLoc.getLine(),
                          fileLoc.getColumn()};
  if (auto nameLoc = llvm::dyn_cast<mlir::NameLoc>(loc))
    return findSourceLocation(nameLoc.getChildLoc());
  if (auto callLoc = llvm::dyn_cast<mlir::CallSiteLoc>(loc)) {
    if (auto result = findSourceLocation(callLoc.getCallee()))
      return result;
    return findSourceLocation(callLoc.getCaller());
  }
  if (auto fusedLoc = llvm::dyn_cast<mlir::FusedLoc>(loc)) {
    for (mlir::Location child : fusedLoc.getLocations())
      if (auto result = findSourceLocation(child))
        return result;
  }
  return std::nullopt;
}

static std::string operationSymbol(mlir::Operation *op) {
  if (auto symbol = op->getAttrOfType<mlir::StringAttr>(
          mlir::SymbolTable::getSymbolAttrName()))
    return symbol.getValue().str();
  if (auto name = op->getAttrOfType<mlir::StringAttr>("name"))
    return name.getValue().str();
  return {};
}

static std::string referencedModule(mlir::Operation *op) {
  for (llvm::StringRef attrName : {"moduleName", "module_name", "module"}) {
    if (auto reference =
            op->getAttrOfType<mlir::FlatSymbolRefAttr>(attrName))
      return reference.getValue().str();
    if (auto text = op->getAttrOfType<mlir::StringAttr>(attrName))
      return text.getValue().str();
  }
  return {};
}

static llvm::json::Object locationJson(mlir::Location loc) {
  llvm::json::Object result;
  if (auto source = findSourceLocation(loc)) {
    result["file"] = source->file;
    result["line"] = static_cast<int64_t>(source->line);
    result["column"] = static_cast<int64_t>(source->column);
  }
  return result;
}

class EmitModuleGraphPass
    : public impl::EmitModuleGraphBase<EmitModuleGraphPass> {
public:
  using Base::Base;

  explicit EmitModuleGraphPass(std::string path) {
    outputFile = std::move(path);
  }

  void runOnOperation() override {
    if (outputFile.empty()) {
      getOperation().emitError("output-file must not be empty");
      signalPassFailure();
      return;
    }

    llvm::json::Array modules;
    llvm::StringMap<llvm::StringSet<>> edgeSets;
    std::string top = operationSymbol(getOperation().getOperation());

    mlir::Region &body = getOperation().getOperation()->getRegion(0);
    if (body.empty()) {
      getOperation().emitError("FIRRTL circuit has no body");
      signalPassFailure();
      return;
    }

    for (mlir::Operation &moduleOp : body.front()) {
      llvm::StringRef operationName = moduleOp.getName().getStringRef();
      if (operationName != "firrtl.module" &&
          operationName != "firrtl.extmodule" &&
          operationName != "firrtl.intmodule")
        continue;

      std::string symbol = operationSymbol(&moduleOp);
      if (symbol.empty())
        continue;

      llvm::json::Object module;
      module["name"] = symbol;
      module["symbol"] = symbol;
      module["kind"] = operationName.drop_front(7).str();
      llvm::json::Object location = locationJson(moduleOp.getLoc());
      module["location"] = location.empty()
                               ? llvm::json::Value(nullptr)
                               : llvm::json::Value(std::move(location));
      modules.push_back(std::move(module));

      moduleOp.walk([&](mlir::Operation *nested) {
        if (nested->getName().getStringRef() != "firrtl.instance")
          return;
        std::string callee = referencedModule(nested);
        if (!callee.empty() && callee != symbol)
          edgeSets[symbol].insert(callee);
      });
    }

    llvm::json::Object edges;
    for (auto &entry : edgeSets) {
      llvm::json::Array callees;
      for (auto &callee : entry.getValue())
        callees.push_back(callee.getKey().str());
      edges[entry.getKey()] = std::move(callees);
    }

    llvm::json::Object document;
    document["schema_version"] = 1;
    document["top"] = top;
    document["modules"] = std::move(modules);
    document["edges"] = std::move(edges);
    document["source"] = "direct-pass";

    std::error_code error;
    llvm::raw_fd_ostream output(outputFile, error, llvm::sys::fs::OF_Text);
    if (error) {
      getOperation().emitError("cannot open graph output file: ")
          << error.message();
      signalPassFailure();
      return;
    }
    output << llvm::formatv("{0:2}\n", llvm::json::Value(std::move(document)));
    output.flush();
    if (output.has_error()) {
      getOperation().emitError("failed to write graph output file");
      signalPassFailure();
      return;
    }
    markAllAnalysesPreserved();
  }
};

} // namespace

std::unique_ptr<mlir::Pass>
createEmitModuleGraphPass(std::string outputFile) {
  return std::make_unique<EmitModuleGraphPass>(std::move(outputFile));
}

} // namespace chisel_circt
} // namespace fm_agent

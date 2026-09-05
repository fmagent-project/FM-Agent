add_circt_library(FMAgentChiselCirct
  EmitModuleGraph.cpp

  DEPENDS
  FMAgentChiselCirctPassesIncGen

  LINK_LIBS PUBLIC
  CIRCTFIRRTL
  MLIRIR
  MLIRPass
  LLVMSupport
)

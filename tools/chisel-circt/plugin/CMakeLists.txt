add_llvm_library(FMAgentChiselCirctPlugin
  MODULE BUILDTREE_ONLY
  FMAgentChiselCirctPlugin.cpp

  DEPENDS
  FMAgentChiselCirctPassesIncGen

  PLUGIN_TOOL
  firtool

  LINK_LIBS
  FMAgentChiselCirct
)

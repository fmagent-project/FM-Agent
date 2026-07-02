"""Standalone IFC (Information Flow Control) driver.

Thin CLI wrapper over the generic plugin driver. The IFC analysis itself now
lives in the IFC plugin (src/plugins/ifc.py), which reuses FM-Agent's
language-aware function extraction and runs the IFC track (parametric
flow-signature inference + deterministic fail-closed classification) instead of
the correctness reasoner. Does NOT touch the existing main.py pipeline.

Usage:
    python3 ifc_main.py <proj_dir>

Outputs (under <proj_dir>/fm_agent_ifc/):
    extracted_functions/**/<func>.<ext>   raw extracted functions (reused machinery)
    ifc_results/**/<func>.json            per-function verdict + flow gaps
    ifc_results/summary.json              aggregated counts

The output path/format are preserved exactly (ifc_results/, the same per-function
JSON and summary shape) so ifc_eval.py and ifc_viewer.py keep working unchanged.

Cross-function composition: functions are processed bottom-up (callees before
callers). Each callee's derived flow signature is passed as context to its
callers, so a High value tunnelling through a label-polymorphic helper (e.g.
_identity) is still caught at the caller. Trust-boundary handling (a function's
return is an external sink only when it is an entrypoint) is computed by the
driver's entrypoint detection.
"""

import os
import sys
import logging

from src.plugins.driver import run_plugin
from src.plugins.ifc import IfcPlugin


def run_ifc(proj_dir):
    if not os.path.isdir(proj_dir):
        print(f"[IFC] ERROR: not a directory: {proj_dir}")
        sys.exit(1)
    return run_plugin(
        IfcPlugin(),
        proj_dir,
        work_subdir="fm_agent_ifc",
        results_subdir="ifc_results",
    )


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 ifc_main.py <proj_dir>")
        sys.exit(1)
    logging.basicConfig(level=logging.WARNING)
    run_ifc(os.path.abspath(sys.argv[1]))

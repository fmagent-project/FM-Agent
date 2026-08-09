#!/usr/bin/env python3
"""Regenerate the static HTML report index for an FM-Agent run.

Usage:
    uv run python report_index.py <proj_dir>            # project root -> <proj_dir>/fm_agent/
    uv run python report_index.py <proj_dir>/fm_agent   # a workspace directory directly
    uv run python report_index.py fm_agent.archived_xx  # an archived workspace

Writes <workdir>/report.html — a self-contained page, deterministically
generated from the existing run artifacts (no LLM calls). It is also generated
automatically at the end of every pipeline run.
"""

import argparse
import os
import sys

from src.file_utils import locate_workdir
from src.report_index import generate_report_index


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("proj_dir", help="project root, or an fm_agent workspace directory")
    args = ap.parse_args()

    work_dir = locate_workdir(args.proj_dir)
    if not os.path.isdir(work_dir):
        print(
            f"error: no fm_agent workspace found under {args.proj_dir} "
            f"(looked for {work_dir})",
            file=sys.stderr,
        )
        sys.exit(1)

    out = generate_report_index(work_dir)
    print(f"Report index written to {out}")


if __name__ == "__main__":
    main()

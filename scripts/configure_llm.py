#!/usr/bin/env python3
from __future__ import annotations

import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.configure_llm import ConfigWizardError, run_wizard


def main() -> int:
    try:
        return run_wizard(ROOT)
    except KeyboardInterrupt:
        print("\nAborted.")
        return 1
    except ConfigWizardError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())

"""Generic CLI to run an analysis plugin over a project directory.

Usage:
    python3 run_plugin.py <plugin> <proj_dir>

where <plugin> is one of the registered plugin names (e.g. "ifc", "authz").

This is the unified entry point that replaces per-track drivers like
ifc_main.py: every plugin runs through the same src/plugins/driver.run_plugin.
"""

import sys
import logging

from src.plugins.driver import run_plugin
from src.plugins.ifc import IfcPlugin


def _registry():
    reg = {"ifc": IfcPlugin}
    try:
        from src.plugins.authz import AuthzPlugin
        reg["authz"] = AuthzPlugin
    except Exception:  # noqa: BLE001 — authz optional during incremental dev
        pass
    try:
        from src.plugins.taint import TaintPlugin
        reg["taint"] = TaintPlugin
    except Exception:  # noqa: BLE001 — taint optional during incremental dev
        pass
    try:
        from src.plugins.crypto import CryptoPlugin
        reg["crypto"] = CryptoPlugin
    except Exception:  # noqa: BLE001 — crypto optional during incremental dev
        pass
    try:
        from src.plugins.typestate import TypestatePlugin
        reg["typestate"] = TypestatePlugin
    except Exception:  # noqa: BLE001 — typestate optional during incremental dev
        pass
    return reg


def main():
    if len(sys.argv) < 3:
        names = ", ".join(sorted(_registry()))
        print(f"Usage: python3 run_plugin.py <plugin> <proj_dir>   (plugins: {names})")
        return 1
    plugin_name, proj_dir = sys.argv[1], sys.argv[2]
    reg = _registry()
    if plugin_name not in reg:
        print(f"Unknown plugin '{plugin_name}'. Available: {', '.join(sorted(reg))}")
        return 1
    logging.basicConfig(level=logging.WARNING)
    run_plugin(reg[plugin_name](), proj_dir)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

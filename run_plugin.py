"""Generic CLI to run an analysis plugin over a project directory.

Usage:
    python3 run_plugin.py <plugin> <proj_dir>

where <plugin> is one of the registered plugin names (see src/plugins/registry).

This is the unified entry point that replaces per-track drivers like
ifc_main.py: every plugin runs through the same src/plugins/driver.run_plugin.
Plugin discovery + class loading go through src.plugins.registry, so adding a
plugin needs no edit here.
"""

import sys
import logging

from src.plugins.driver import run_plugin
from src.plugins import registry


def main():
    if len(sys.argv) < 3:
        names = ", ".join(registry.plugin_names())
        print(f"Usage: python3 run_plugin.py <plugin> <proj_dir>   (plugins: {names})")
        return 1
    plugin_name, proj_dir = sys.argv[1], sys.argv[2]
    if not registry.has_plugin(plugin_name):
        print(f"Unknown plugin '{plugin_name}'. Available: {', '.join(registry.plugin_names())}")
        return 1
    logging.basicConfig(level=logging.WARNING)
    plugin_cls = registry.load_plugin_class(plugin_name)
    work_subdir = registry.get_manifest(plugin_name).get("work_subdir")
    run_plugin(plugin_cls(), proj_dir, work_subdir=work_subdir)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

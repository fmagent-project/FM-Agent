import inspect
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import main
from src.incremental_reasoner import run_incremental_pipeline


class PluginCliTests(unittest.TestCase):
    def test_list_plugin_includes_entry_reasoning(self):
        result = subprocess.run(
            [sys.executable, str(Path(main.__file__).resolve()), "--list-plugin"],
            cwd=Path(main.__file__).resolve().parent,
            capture_output=True,
            text=True,
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("entry_reasoning", result.stdout)
        self.assertIn("generate_phase_plan", result.stdout)
        self.assertIn("collect_file_list", result.stdout)

    def test_entry_option_implicitly_loads_entry_plugin(self):
        plugins_dir = Path(main.__file__).resolve().parent / "plugins"
        with (
            tempfile.TemporaryDirectory() as temp_dir,
            tempfile.TemporaryDirectory(
                dir=plugins_dir,
                prefix="invalid_sibling_",
            ) as invalid_plugin_dir,
        ):
            project = Path(temp_dir) / "project"
            (project / "src").mkdir(parents=True)
            (project / "src" / "main.py").write_text(
                "def main():\n    pass\n", encoding="utf-8"
            )
            result = subprocess.run(
                [
                    sys.executable,
                    str(Path(main.__file__).resolve()),
                    str(project),
                    "--entry-func",
                    "src/main-py::main",
                    "--submodule",
                    "src",
                ],
                cwd=Path(main.__file__).resolve().parent,
                capture_output=True,
                text=True,
            )

        self.assertEqual(result.returncode, 2)
        self.assertIn("Loaded plugin 'entry_reasoning'", result.stdout)
        self.assertNotIn(
            f"Invalid plugin '{Path(invalid_plugin_dir).name}'",
            result.stdout,
        )
        self.assertIn("--submodule cannot be combined with --entry-func", result.stderr)

    def test_incremental_api_does_not_accept_plugin_configuration(self):
        self.assertNotIn(
            "plugin_config",
            inspect.signature(run_incremental_pipeline).parameters,
        )

    def test_full_pipeline_accepts_context_separately(self):
        parameters = inspect.signature(main.run_pipeline).parameters
        self.assertIn("plugin_config", parameters)
        self.assertIn("plugin_context", parameters)


if __name__ == "__main__":
    unittest.main()

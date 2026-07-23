import json
import tempfile
import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path

from src.plugin import load_plugins, validate_plugin


class PythonPluginValidationTests(unittest.TestCase):
    def _write_plugin(self, root, stage_config, python_source=None, name="sample"):
        plugin_dir = root / name
        plugin_dir.mkdir()
        (plugin_dir / "plugin.json").write_text(
            json.dumps(
                {
                    "name": name,
                    "version": "V1.0",
                    "stages": {"extract_functions": stage_config},
                }
            ),
            encoding="utf-8",
        )
        if python_source is not None:
            (plugin_dir / "plugin.py").write_text(
                python_source,
                encoding="utf-8",
            )
        return plugin_dir

    def _validate_silently(self, plugin_dir):
        with redirect_stdout(StringIO()):
            return validate_plugin(plugin_dir)

    def test_custom_replace_function_is_bound(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            plugin_dir = self._write_plugin(
                Path(temp_dir),
                {
                    "type": "replace",
                    "replace_function": "custom_extract",
                },
                "def custom_extract(source_paths: list[str], output_dir: str) "
                "-> list[str]:\n    return []\n",
            )

            plugin = self._validate_silently(plugin_dir)

            self.assertIsNotNone(plugin)
            stage = plugin.get_stage("extract_functions")
            self.assertEqual(stage.replace_function, "custom_extract")
            self.assertTrue(callable(stage.replace_hook))

    def test_custom_input_and_output_functions_are_bound(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            plugin_dir = self._write_plugin(
                Path(temp_dir),
                {
                    "type": "modify",
                    "input_function": "prepare_source",
                    "output_function": "normalize_output",
                },
                "def prepare_source(path: str) -> None:\n    pass\n\n"
                "def normalize_output(path: str) -> None:\n    pass\n",
            )

            plugin = self._validate_silently(plugin_dir)

            self.assertIsNotNone(plugin)
            stage = plugin.get_stage("extract_functions")
            self.assertTrue(callable(stage.input_hook))
            self.assertTrue(callable(stage.output_hook))

    def test_missing_plugin_python_file_is_invalid(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            plugin_dir = self._write_plugin(
                Path(temp_dir),
                {"type": "pass"},
            )

            self.assertIsNone(self._validate_silently(plugin_dir))

    def test_missing_declared_function_is_invalid(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            plugin_dir = self._write_plugin(
                Path(temp_dir),
                {
                    "type": "modify",
                    "input_function": "missing_function",
                },
                "VALUE = 1\n",
            )

            self.assertIsNone(self._validate_silently(plugin_dir))

    def test_declared_object_must_be_callable(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            plugin_dir = self._write_plugin(
                Path(temp_dir),
                {
                    "type": "modify",
                    "input_function": "prepare_source",
                },
                "prepare_source = 'not callable'\n",
            )

            self.assertIsNone(self._validate_silently(plugin_dir))

    def test_replace_signature_is_validated(self):
        invalid_sources = (
            "def custom_extract(source_paths: list[str]) -> list[str]:\n"
            "    return []\n",
            "def custom_extract(source_paths: str, output_dir: str) -> list[str]:\n"
            "    return []\n",
            "def custom_extract(source_paths: list[str], output_dir: str) -> None:\n"
            "    pass\n",
        )
        for python_source in invalid_sources:
            with self.subTest(python_source=python_source):
                with tempfile.TemporaryDirectory() as temp_dir:
                    plugin_dir = self._write_plugin(
                        Path(temp_dir),
                        {
                            "type": "replace",
                            "replace_function": "custom_extract",
                        },
                        python_source,
                    )

                    self.assertIsNone(self._validate_silently(plugin_dir))

    def test_modify_signature_is_validated(self):
        invalid_sources = (
            "def prepare_source() -> None:\n    pass\n",
            "def prepare_source(path: int) -> None:\n    pass\n",
            "def prepare_source(path: str) -> str:\n    return path\n",
            "def prepare_source(*, path: str) -> None:\n    pass\n",
        )
        for python_source in invalid_sources:
            with self.subTest(python_source=python_source):
                with tempfile.TemporaryDirectory() as temp_dir:
                    plugin_dir = self._write_plugin(
                        Path(temp_dir),
                        {
                            "type": "modify",
                            "input_function": "prepare_source",
                        },
                        python_source,
                    )

                    self.assertIsNone(self._validate_silently(plugin_dir))

    def test_stage_function_combinations_are_validated(self):
        invalid_configs = (
            {
                "type": "pass",
                "input_function": "prepare_source",
            },
            {"type": "replace"},
            {
                "type": "replace",
                "replace_function": "custom_extract",
                "output_function": "normalize_output",
            },
            {"type": "modify"},
            {
                "type": "modify",
                "replace_function": "custom_extract",
                "input_function": "prepare_source",
            },
        )
        python_source = (
            "def custom_extract(source_paths: list[str], output_dir: str) "
            "-> list[str]:\n    return []\n\n"
            "def prepare_source(path: str) -> None:\n    pass\n\n"
            "def normalize_output(path: str) -> None:\n    pass\n"
        )
        for stage_config in invalid_configs:
            with self.subTest(stage_config=stage_config):
                with tempfile.TemporaryDirectory() as temp_dir:
                    plugin_dir = self._write_plugin(
                        Path(temp_dir),
                        stage_config,
                        python_source,
                    )

                    self.assertIsNone(self._validate_silently(plugin_dir))

    def test_legacy_command_fields_do_not_satisfy_python_hooks(self):
        invalid_configs = (
            {
                "type": "replace",
                "replace_cmd": "python old_replace.py",
            },
            {
                "type": "modify",
                "output_process": "python old_process.py",
            },
        )
        for stage_config in invalid_configs:
            with self.subTest(stage_config=stage_config):
                with tempfile.TemporaryDirectory() as temp_dir:
                    plugin_dir = self._write_plugin(
                        Path(temp_dir),
                        stage_config,
                        "VALUE = 1\n",
                    )

                    self.assertIsNone(self._validate_silently(plugin_dir))

    def test_load_plugins_returns_only_valid_plugins(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            plugins_dir = Path(temp_dir)
            self._write_plugin(
                plugins_dir,
                {"type": "pass"},
                "VALUE = 1\n",
                name="valid",
            )
            self._write_plugin(
                plugins_dir,
                {"type": "replace"},
                "VALUE = 1\n",
                name="invalid",
            )

            with redirect_stdout(StringIO()):
                plugins = load_plugins(plugins_dir)

            self.assertEqual(list(plugins), ["valid"])


if __name__ == "__main__":
    unittest.main()

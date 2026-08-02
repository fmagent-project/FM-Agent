import json
import tempfile
import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path

from src.plugin import load_plugins, run_plugin_hook, validate_plugin


VALID_HOOK = "def hook(proj_dir: str) -> None:\n    pass\n"


class PluginContractTests(unittest.TestCase):
    def _plugin(self, data=None, source=VALID_HOOK, name="sample"):
        temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(temp_dir.cleanup)
        root = Path(temp_dir.name)
        plugin_dir = root / name
        plugin_dir.mkdir()
        if data is None:
            data = {
                "name": name,
                "version": "V1.0",
                "stages": {
                    "extract_functions": {
                        "type": "replace",
                        "replace_function": "hook",
                    }
                },
            }
        (plugin_dir / "plugin.json").write_text(
            json.dumps(data), encoding="utf-8"
        )
        if source is not None:
            (plugin_dir / "plugin.py").write_text(source, encoding="utf-8")
        return root, plugin_dir

    def _validate(self, plugin_dir):
        output = StringIO()
        with redirect_stdout(output):
            result = validate_plugin(plugin_dir)
        return result, output.getvalue()

    def test_loads_valid_replace_hook(self):
        root, _plugin_dir = self._plugin()

        plugins = load_plugins(root)

        stage = plugins["sample"].get_stage("extract_functions")
        self.assertTrue(callable(stage.replace_hook))

    def test_accepts_every_legal_mode_shape(self):
        data = {
            "name": "sample",
            "version": "V1.0",
            "configure_function": "configure",
            "stages": {
                "generate_phase_plan": {"type": "pass"},
                "generate_domain_context": {
                    "type": "replace",
                    "replace_function": "replace",
                },
                "extract_functions": {
                    "type": "modify",
                    "input_function": "before",
                },
                "collect_file_list": {
                    "type": "modify",
                    "output_function": "after",
                },
                "generate_topdown_layers": {
                    "type": "modify",
                    "input_function": "before",
                    "output_function": "after",
                },
                "generate_specs_and_verification": {"type": "pass"},
            },
        }
        source = "\n".join(
            f"def {name}(proj_dir: str) -> None:\n    pass\n"
            for name in ("configure", "replace", "before", "after")
        )
        _root, plugin_dir = self._plugin(data=data, source=source)

        config, output = self._validate(plugin_dir)

        self.assertIsNotNone(config, output)
        self.assertTrue(callable(config.configure_hook))

    def test_rejects_invalid_metadata_and_fields(self):
        cases = [
            ("name mismatch", {"name": "other", "version": "V1.0"}),
            ("version", {"name": "sample", "version": ""}),
            ("unsupported field", {
                "name": "sample", "version": "V1.0", "unknown": True
            }),
            ("unsupported stage", {
                "name": "sample",
                "version": "V1.0",
                "stages": {"unknown": {"type": "pass"}},
            }),
            ("must be a json object", {
                "name": "sample",
                "version": "V1.0",
                "stages": {"extract_functions": []},
            }),
        ]
        for expected, data in cases:
            with self.subTest(expected=expected):
                _root, plugin_dir = self._plugin(data=data)
                config, output = self._validate(plugin_dir)
                self.assertIsNone(config)
                self.assertIn(expected, output.lower())

    def test_requires_plugin_python_file(self):
        _root, plugin_dir = self._plugin(source=None)

        config, output = self._validate(plugin_dir)

        self.assertIsNone(config)
        self.assertIn("missing plugin.py", output)

    def test_wraps_plugin_import_error(self):
        _root, plugin_dir = self._plugin(source="raise RuntimeError('boom')\n")

        config, output = self._validate(plugin_dir)

        self.assertIsNone(config)
        self.assertIn("failed while importing", output)
        self.assertIn("boom", output)

    def test_rejects_illegal_mode_field_combinations(self):
        cases = [
            {"type": "pass", "input_function": "hook"},
            {"type": "replace"},
            {
                "type": "replace",
                "replace_function": "hook",
                "output_function": "hook",
            },
            {"type": "modify"},
            {
                "type": "modify",
                "replace_function": "hook",
                "input_function": "hook",
            },
            {"type": "modify", "input_md": "prompt.md"},
            {"type": "replace", "replace_cmd": "tool"},
            {"type": "modify", "output_process": "tool"},
        ]
        for stage in cases:
            with self.subTest(stage=stage):
                data = {
                    "name": "sample",
                    "version": "V1.0",
                    "stages": {"extract_functions": stage},
                }
                _root, plugin_dir = self._plugin(data=data)
                config, _output = self._validate(plugin_dir)
                self.assertIsNone(config)

    def test_rejects_invalid_hook_signatures_and_objects(self):
        sources = [
            "def hook(proj_dir):\n    pass\n",
            "def hook(path: str) -> None:\n    pass\n",
            "def hook(proj_dir: int) -> None:\n    pass\n",
            "def hook(proj_dir: str) -> str:\n    return ''\n",
            "def hook(proj_dir: str, extra: str) -> None:\n    pass\n",
            "def hook(*, proj_dir: str) -> None:\n    pass\n",
            "def hook(*args: str) -> None:\n    pass\n",
            "def hook(**kwargs: str) -> None:\n    pass\n",
            "hook = 42\n",
            "def other(proj_dir: str) -> None:\n    pass\n",
        ]
        for source in sources:
            with self.subTest(source=source):
                _root, plugin_dir = self._plugin(source=source)
                config, _output = self._validate(plugin_dir)
                self.assertIsNone(config)

    def test_runtime_passes_project_and_requires_none(self):
        calls = []

        def hook(proj_dir: str) -> None:
            calls.append(proj_dir)

        run_plugin_hook("sample", "stage", "hook", hook, "/project")
        self.assertEqual(calls, ["/project"])

        with self.assertRaisesRegex(RuntimeError, "must return None"):
            run_plugin_hook(
                "sample", "stage", "bad", lambda _path: "bad", "/project"
            )

    def test_runtime_wraps_error_with_context_and_cause(self):
        error = ValueError("boom")

        def hook(_proj_dir):
            raise error

        with self.assertRaisesRegex(
            RuntimeError,
            "Plugin 'sample'.*function 'hook'.*stage 'extract_functions'",
        ) as raised:
            run_plugin_hook(
                "sample", "extract_functions", "hook", hook, "/project"
            )

        self.assertIs(raised.exception.__cause__, error)


if __name__ == "__main__":
    unittest.main()

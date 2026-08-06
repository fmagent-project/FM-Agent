import os
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import run_plugin


class RunPluginConfigTests(unittest.TestCase):
    def _write_config(self, directory):
        path = Path(directory) / "codex.toml"
        path.write_text(
            "\n".join(
                [
                    'model = "config-model"',
                    'model_provider = "Custom"',
                    'model_reasoning_effort = "high"',
                    "disable_response_storage = true",
                    "",
                    "[model_providers.Custom]",
                    'base_url = "https://config.example/v1"',
                    'wire_api = "responses"',
                ]
            )
        )
        return path

    def test_config_overrides_existing_env_defaults(self):
        with tempfile.TemporaryDirectory() as tmp:
            config = self._write_config(tmp)
            env = {
                "LLM_MODEL": "env-model",
                "LLM_EFFORT": "medium",
                "LLM_API_BASE_URL": "https://env.example/v1",
                "LLM_API_MODE": "chat",
            }
            with mock.patch.dict(os.environ, env, clear=False):
                run_plugin._apply_config_env(str(config))

                self.assertEqual("config-model", os.environ["LLM_MODEL"])
                self.assertEqual("high", os.environ["LLM_EFFORT"])
                self.assertEqual("true", os.environ["LLM_DISABLE_RESPONSE_STORAGE"])
                self.assertEqual("https://config.example/v1", os.environ["LLM_API_BASE_URL"])
                self.assertEqual("responses", os.environ["LLM_API_MODE"])

    def test_explicit_cli_flags_override_config_values(self):
        with tempfile.TemporaryDirectory() as tmp:
            config = self._write_config(tmp)
            args = SimpleNamespace(
                config=str(config),
                deepseek=False,
                openai=False,
                base_url="https://cli.example/v1",
                model="cli-model",
                api_mode="chat",
                reasoning_effort="low",
                disable_response_storage=False,
                api_key_env="LLM_API_KEY",
                plugin="ifc",
            )
            with mock.patch.dict(os.environ, {"LLM_API_KEY": "test-key"}, clear=False):
                run_plugin._configure_llm_env(args)

                self.assertEqual("cli-model", os.environ["LLM_MODEL"])
                self.assertEqual("low", os.environ["LLM_EFFORT"])
                self.assertEqual("https://cli.example/v1", os.environ["LLM_API_BASE_URL"])
                self.assertEqual("chat", os.environ["LLM_API_MODE"])


if __name__ == "__main__":
    unittest.main()

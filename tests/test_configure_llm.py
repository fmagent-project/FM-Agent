from __future__ import annotations

import json
import tempfile
import textwrap
import unittest
from pathlib import Path

from src.configure_llm import (
    ConfigWizardError,
    LLMConfigInput,
    WizardPaths,
    apply_configuration,
    merge_opencode_config,
    parse_existing_opencode_config,
    update_env_text,
    update_fm_agent_toml_text,
)


class ConfigureLLMTests(unittest.TestCase):
    def setUp(self):
        self.config = LLMConfigInput(
            provider_id="openrouter",
            provider_name="OpenRouter",
            api_style="openai",
            base_url="https://openrouter.ai/api/v1",
            model_id="anthropic/claude-sonnet-4.6",
            api_key="sk-test-1234",
        )

    def test_update_env_creates_key_and_removes_legacy_overrides(self):
        updated = update_env_text(
            textwrap.dedent(
                """\
                LLM_MODEL=old-model
                KEEP_ME=yes
                OPENCODE_MODEL_PROVIDER=old-provider
                """
            ),
            self.config.api_key,
        )
        self.assertIn("LLM_API_KEY=sk-test-1234\n", updated)
        self.assertIn("KEEP_ME=yes\n", updated)
        self.assertNotIn("LLM_MODEL=", updated)
        self.assertNotIn("OPENCODE_MODEL_PROVIDER=", updated)

    def test_update_toml_rewrites_llm_fields_only(self):
        source = textwrap.dedent(
            """\
            [llm]
            name = "old-model"
            provider = "old"
            base_url = "https://old.example/v1"
            backend = "auto"
            api_style = "anthropic"

            [runtime]
            max_workers = 10
            """
        )
        updated = update_fm_agent_toml_text(source, self.config)
        self.assertIn('name = "anthropic/claude-sonnet-4.6"', updated)
        self.assertIn('provider = "openrouter"', updated)
        self.assertIn('base_url = "https://openrouter.ai/api/v1"', updated)
        self.assertIn('backend = "opencode"', updated)
        self.assertIn('api_style = "openai"', updated)
        self.assertIn("[runtime]\nmax_workers = 10\n", updated)

    def test_merge_opencode_config_preserves_existing_settings(self):
        existing = {
            "$schema": "https://opencode.ai/config.json",
            "plugin": ["@lucentia/opencode-trace"],
            "provider": {
                "other": {"npm": "@ai-sdk/openai-compatible", "models": {"m": {}}},
                "openrouter": {
                    "npm": "@ai-sdk/openai-compatible",
                    "options": {"timeout": 30},
                    "models": {"existing-model": {"temperature": 0.1}},
                },
            },
        }
        merged = merge_opencode_config(existing, self.config)
        self.assertEqual(merged["plugin"], ["@lucentia/opencode-trace"])
        self.assertIn("other", merged["provider"])
        self.assertEqual(
            merged["provider"]["openrouter"]["options"]["baseURL"],
            "https://openrouter.ai/api/v1",
        )
        self.assertEqual(
            merged["provider"]["openrouter"]["options"]["apiKey"],
            "{env:LLM_API_KEY}",
        )
        self.assertEqual(merged["provider"]["openrouter"]["options"]["timeout"], 30)
        self.assertIn("existing-model", merged["provider"]["openrouter"]["models"])
        self.assertIn(self.config.model_id, merged["provider"]["openrouter"]["models"])

    def test_invalid_existing_opencode_json_is_rejected(self):
        with self.assertRaises(ConfigWizardError):
            parse_existing_opencode_config("{not-json}")

    def test_invalid_existing_toml_is_rejected(self):
        with self.assertRaises(ConfigWizardError):
            update_fm_agent_toml_text("[llm\nname='x'\n", self.config)

    def test_apply_configuration_writes_all_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            toml_path = root / "fm-agent.toml"
            env_path = root / ".env"
            opencode_path = root / "opencode" / "opencode.json"
            toml_path.write_text(
                textwrap.dedent(
                    """\
                    [llm]
                    name = "old-model"
                    provider = "old"
                    base_url = "https://old.example/v1"
                    backend = "auto"
                    api_style = "anthropic"
                    """
                ),
                encoding="utf-8",
            )
            env_path.write_text("LLM_API_KEY=old-key\nLLM_MODEL=stale\n", encoding="utf-8")
            opencode_path.parent.mkdir(parents=True, exist_ok=True)
            opencode_path.write_text(json.dumps({"plugin": ["x"]}), encoding="utf-8")
            backups = apply_configuration(
                self.config,
                WizardPaths(root, env_path, toml_path, opencode_path),
                validate=True,
            )
            self.assertEqual(len(backups), 3)
            self.assertIn(self.config.model_id, toml_path.read_text(encoding="utf-8"))
            env_text = env_path.read_text(encoding="utf-8")
            self.assertIn("LLM_API_KEY=sk-test-1234", env_text)
            self.assertNotIn("LLM_MODEL=stale", env_text)
            opencode = json.loads(opencode_path.read_text(encoding="utf-8"))
            self.assertEqual(opencode["plugin"], ["x"])
            self.assertIn("openrouter", opencode["provider"])

    def test_apply_configuration_creates_missing_env_and_opencode_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            toml_path = root / "fm-agent.toml"
            env_path = root / ".env"
            opencode_path = root / "opencode" / "opencode.json"
            toml_path.write_text(
                textwrap.dedent(
                    """\
                    [runtime]
                    max_workers = 10
                    """
                ),
                encoding="utf-8",
            )

            backups = apply_configuration(
                self.config,
                WizardPaths(root, env_path, toml_path, opencode_path),
                validate=True,
            )

            self.assertEqual(len(backups), 3)
            self.assertIsNotNone(backups[0][1])
            self.assertEqual(backups[1], (env_path, None))
            self.assertEqual(backups[2], (opencode_path, None))
            self.assertIn("LLM_API_KEY=sk-test-1234\n", env_path.read_text(encoding="utf-8"))
            updated_toml = toml_path.read_text(encoding="utf-8")
            self.assertIn("[runtime]\nmax_workers = 10\n", updated_toml)
            self.assertIn("[llm]\n", updated_toml)
            opencode = json.loads(opencode_path.read_text(encoding="utf-8"))
            self.assertIn("openrouter", opencode["provider"])


if __name__ == "__main__":
    unittest.main()

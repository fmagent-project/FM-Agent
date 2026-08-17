"""Tests for the layered pydantic configuration in config.py.

Precedence: process env > .env > fm-agent.toml > built-in defaults.
Layering and fail-fast behaviour is exercised in subprocesses because config
resolves everything once at import time.
"""

import os
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]

# Env vars that config.py maps onto settings; cleared from subprocess
# environments so the developer's shell cannot leak into the tests.
_CONFIG_ENV_VARS = [
    "FM_AGENT_CONFIG",
    "LLM_API_KEY",
    "LLM_API_BASE_URL",
    "FM_AGENT_MODEL_BACKEND",
    "LLM_MODEL",
    "LLM_EFFORT",
    "OPENCODE_MODEL_PROVIDER",
    "LLM_API_STYLE",
    "MAX_SPC_ITER",
    "GRANULARITY",
    "MAX_WORKERS",
    "OPENCODE_MAX_RETRIES",
    "BUG_VALIDATION_MAX_RETRIES",
    "OPENCODE_TIMEOUT_SECONDS",
    "FM_AGENT_DOMAIN_KNOWLEDGE",
    "SCOPE_TOP_K",
    "SCOPE_LLM_TRIGGER_FUNCS",
    "SCOPE_LLM_TOP_K",
    "SCOPE_LLM_CONFIDENCE_THRESHOLD",
    "ELP_COMMAND",
    "ELP_TIMEOUT_SECONDS",
    "INJECT_ID",
    "INJECT_HOST",
    "CODEGRAPH_REPO",
    "CODEGRAPH_VERSION",
    "CODEGRAPH_BIN_DIR",
]


def _run_import(extra_env=None):
    env = {k: v for k, v in os.environ.items() if k not in _CONFIG_ENV_VARS}
    env.update(extra_env or {})
    return subprocess.run(
        [sys.executable, "-c", "import config; print(config.GRANULARITY)"],
        cwd=REPO_ROOT,
        env=env,
        capture_output=True,
        text=True,
    )


class TestDefaults:
    def test_committed_toml_defaults_load(self):
        result = _run_import()
        assert result.returncode == 0, result.stderr
        # granularity = 40 comes from the committed fm-agent.toml.
        assert result.stdout.strip() == "40"

    def test_settings_object_matches_module_constants(self):
        import config

        assert config.settings.runtime.granularity == config.GRANULARITY
        assert config.settings.runtime.max_spec_iter == config.MAX_SPC_ITER
        assert config.settings.llm.name == config.LLM_MODEL


class TestLayering:
    def test_env_var_overrides_default(self):
        result = _run_import({"GRANULARITY": "99"})
        assert result.returncode == 0, result.stderr
        assert result.stdout.strip() == "99"

    def test_fm_agent_config_file_is_used(self, tmp_path):
        toml = tmp_path / "alt.toml"
        toml.write_text("[runtime]\ngranularity = 77\n")
        result = _run_import({"FM_AGENT_CONFIG": str(toml)})
        assert result.returncode == 0, result.stderr
        assert result.stdout.strip() == "77"

    def test_env_beats_fm_agent_config(self, tmp_path):
        toml = tmp_path / "alt.toml"
        toml.write_text("[runtime]\ngranularity = 77\n")
        result = _run_import({"FM_AGENT_CONFIG": str(toml), "GRANULARITY": "55"})
        assert result.returncode == 0, result.stderr
        assert result.stdout.strip() == "55"


class TestFailFast:
    def test_unknown_toml_key_rejected(self, tmp_path):
        toml = tmp_path / "typo.toml"
        toml.write_text("[runtime]\ngranularty = 77\n")
        result = _run_import({"FM_AGENT_CONFIG": str(toml)})
        assert result.returncode == 1
        assert "Extra inputs are not permitted" in result.stderr

    def test_unknown_toml_section_rejected(self, tmp_path):
        toml = tmp_path / "badsec.toml"
        toml.write_text("[nope]\nx = 1\n")
        result = _run_import({"FM_AGENT_CONFIG": str(toml)})
        assert result.returncode == 1
        assert "Extra inputs are not permitted" in result.stderr

    def test_missing_explicit_config_file_rejected(self, tmp_path):
        result = _run_import({"FM_AGENT_CONFIG": str(tmp_path / "missing.toml")})
        assert result.returncode == 1
        assert "does not exist" in result.stderr

    def test_invalid_env_value_rejected(self):
        # granularity must be > 0.
        result = _run_import({"GRANULARITY": "0"})
        assert result.returncode == 1
        assert "greater than 0" in result.stderr

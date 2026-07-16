"""Central configuration for FM-Agent.

Layered precedence (highest wins):

    process env  >  .env  >  fm-agent.toml  >  built-in defaults

Non-secret defaults live in the committed ``fm-agent.toml``; secrets (the LLM
API key) stay in the gitignored ``.env``. Every setting is also overridable by
its legacy environment variable, so existing ``.env`` files keep working with no
migration step.

Import the validated ``settings`` object for new code; the module-level
``UPPER_CASE`` constants below are kept for backward compatibility with existing
``from config import *`` callers.

Set ``FM_AGENT_CONFIG`` to point at an alternate toml file (defaults to
``fm-agent.toml`` next to this module).
"""

from __future__ import annotations

import os
import tomllib
from pathlib import Path
from typing import Literal

from dotenv import load_dotenv
from pydantic import BaseModel, ConfigDict, ValidationError
from pydantic_settings import (
    BaseSettings,
    PydanticBaseSettingsSource,
    SettingsConfigDict,
)

# Populate os.environ from .env without clobbering real env vars (so env > .env).
load_dotenv()

_CONFIG_PATH = Path(
    os.environ.get("FM_AGENT_CONFIG") or Path(__file__).parent / "fm-agent.toml"
)

# Legacy environment variable -> (toml section, field). This table is the single
# place mapping an env var to a setting; it doubles as documentation of every
# supported override.
_ENV_MAP: dict[str, tuple[str, str]] = {
    # [llm]
    "LLM_API_KEY": ("llm", "api_key"),
    "LLM_API_BASE_URL": ("llm", "base_url"),
    "FM_AGENT_MODEL_BACKEND": ("llm", "backend"),
    "LLM_MODEL": ("llm", "name"),
    "LLM_EFFORT": ("llm", "effort"),
    "OPENCODE_MODEL_PROVIDER": ("llm", "provider"),
    "LLM_API_STYLE": ("llm", "api_style"),
    # [runtime]
    "MAX_SPC_ITER": ("runtime", "max_spec_iter"),
    "GRANULARITY": ("runtime", "granularity"),
    "MAX_WORKERS": ("runtime", "max_workers"),
    "OPENCODE_MAX_RETRIES": ("runtime", "opencode_max_retries"),
    "BUG_VALIDATION_MAX_RETRIES": ("runtime", "bug_validation_max_retries"),
    "OPENCODE_TIMEOUT_SECONDS": ("runtime", "opencode_timeout_s"),
    "FM_AGENT_DOMAIN_KNOWLEDGE": ("runtime", "domain_knowledge_paths"),
    # [scope]
    "SCOPE_TOP_K": ("scope", "top_k"),
    "SCOPE_LLM_TRIGGER_FUNCS": ("scope", "llm_trigger_funcs"),
    "SCOPE_LLM_TOP_K": ("scope", "llm_top_k"),
    "SCOPE_LLM_CONFIDENCE_THRESHOLD": ("scope", "llm_confidence_threshold"),
    # [erlang]
    "ELP_COMMAND": ("erlang", "command"),
    "ELP_TIMEOUT_SECONDS": ("erlang", "timeout_s"),
    # [inject]
    "INJECT_ID": ("inject", "id"),
    "INJECT_HOST": ("inject", "hosts"),
    # [codegraph]
    "CODEGRAPH_REPO": ("codegraph", "repo"),
    "CODEGRAPH_VERSION": ("codegraph", "version"),
    "CODEGRAPH_BIN_DIR": ("codegraph", "bin_dir"),
}


class _Section(BaseModel):
    """Base for config sections: reject unknown keys so toml/env typos fail loudly."""

    model_config = ConfigDict(extra="forbid")


class LLMCfg(_Section):
    api_key: str = ""  # secret — from .env / env only, never committed to the toml
    base_url: str = "https://openrouter.ai/api/v1"
    backend: str = "opencode"
    name: str = "anthropic/claude-sonnet-4.6"
    effort: str = ""
    provider: str = "openrouter"
    # Endpoint API style, used to pick the OpenCode SDK adapter when FM-Agent
    # injects the provider block: "openai" -> @ai-sdk/openai-compatible (most
    # relays: OpenRouter, DeepSeek, …), "anthropic" -> @ai-sdk/anthropic.
    # Typed so a typo (or wrong case) fails fast at config load, not silently.
    api_style: Literal["openai", "anthropic"] = "openai"


class RuntimeCfg(_Section):
    max_spec_iter: int = 5
    granularity: int = 40
    max_workers: int = 10
    opencode_max_retries: int = 5
    bug_validation_max_retries: int = 1
    # Hard cap on ONE `opencode run` subprocess. A model connection that dies
    # silently (e.g. through a forward proxy) otherwise hangs the pipeline
    # forever — opencode has no model-call timeout of its own.
    opencode_timeout_s: int = 1800
    # Extra domain-knowledge markdown paths (os.pathsep- or newline-separated);
    # env-driven, so no committed default.
    domain_knowledge_paths: str = ""


class ScopeCfg(_Section):
    # Max functions retained per source file in the final scoped output.
    top_k: int = 5
    # Run LLM re-ranking when a file has at least this many dedup'd functions.
    llm_trigger_funcs: int = 5
    # Candidate functions requested from the LLM during re-ranking.
    llm_top_k: int = 5
    # Run LLM re-ranking when the heuristic top score is below this threshold.
    llm_confidence_threshold: float = 8.0


class ErlangCfg(_Section):
    command: str = "elp"
    timeout_s: int = 180


class InjectCfg(_Section):
    # Request metadata injected for prompt-cache affinity; internal, so no
    # committed toml default (empty means "use the built-in fallback id").
    id: str = ""
    hosts: str = ""


class CodegraphCfg(_Section):
    # The pinned maintenance-fork build. install.sh reads these to install it and
    # the runtime invokes the pinned binary, so this is the single place that
    # decides "which codegraph" and "where it lives".
    repo: str = "fmagent-project/codegraph"
    version: str = ""
    bin_dir: str = "~/.local/bin"  # launcher location; install and run must agree


class _LayeredSource(PydanticBaseSettingsSource):
    """``fm-agent.toml`` as the base layer, mapped process env overlaid on top."""

    def __init__(self, settings_cls, path: Path):
        super().__init__(settings_cls)
        data: dict = {}
        if path.is_file():
            data = tomllib.loads(path.read_text())
        for env_name, (section, field) in _ENV_MAP.items():
            value = os.environ.get(env_name)
            if value is not None:
                data.setdefault(section, {})[field] = value
        self._data = data

    def get_field_value(self, field, field_name):
        # Abstract on the base class but unused: __call__ returns the whole merged
        # mapping, so pydantic never falls back to per-field extraction.
        raise NotImplementedError

    def __call__(self) -> dict:
        return self._data


class Settings(BaseSettings):
    # forbid: a mistyped section or key in fm-agent.toml is an error, not a silent
    # fallback to the default — the whole point of a typed config.
    model_config = SettingsConfigDict(extra="forbid")

    llm: LLMCfg = LLMCfg()
    runtime: RuntimeCfg = RuntimeCfg()
    scope: ScopeCfg = ScopeCfg()
    erlang: ErlangCfg = ErlangCfg()
    inject: InjectCfg = InjectCfg()
    codegraph: CodegraphCfg = CodegraphCfg()

    @classmethod
    def settings_customise_sources(
        cls,
        settings_cls,
        init_settings,
        env_settings,
        dotenv_settings,
        file_secret_settings,
    ):
        # init (programmatic) wins; everything else is folded into _LayeredSource,
        # which already applies env > toml > field defaults.
        return (init_settings, _LayeredSource(settings_cls, _CONFIG_PATH))


try:
    settings = Settings()
except ValidationError as exc:
    # Fail fast with a readable message instead of a raw pydantic traceback: a bad
    # value or typo'd key in fm-agent.toml / .env / an env var stops startup here.
    raise SystemExit(
        f"FM-Agent: invalid configuration (check {_CONFIG_PATH.name}, .env, or the "
        f"matching environment variable)\n{exc}"
    ) from None


# ---------------------------------------------------------------------------
# Backward-compatible module-level constants.
# Existing code does `from config import *` / `import config`; keep every name.
# ---------------------------------------------------------------------------
LLM_API_KEY = settings.llm.api_key
LLM_API_BASE_URL = settings.llm.base_url
FM_AGENT_MODEL_BACKEND = settings.llm.backend
LLM_MODEL = settings.llm.name
LLM_EFFORT = settings.llm.effort.strip()
OPENCODE_MODEL_PROVIDER = settings.llm.provider

OPENCODE_SETUP_MODEL = LLM_MODEL
OPENCODE_SPEC_MODEL = LLM_MODEL
OPENCODE_BUG_VALIDATION_MODEL = LLM_MODEL
REASONER_POST_CONDITION_MODEL = LLM_MODEL
REASONER_SPEC_CHECK_MODEL = LLM_MODEL

MAX_SPC_ITER = settings.runtime.max_spec_iter
GRANULARITY = settings.runtime.granularity
MAX_WORKERS = settings.runtime.max_workers
OPENCODE_MAX_RETRIES = settings.runtime.opencode_max_retries
BUG_VALIDATION_MAX_RETRIES = settings.runtime.bug_validation_max_retries
OPENCODE_TIMEOUT_SECONDS = settings.runtime.opencode_timeout_s

SCOPE_TOP_K = settings.scope.top_k
SCOPE_LLM_TRIGGER_FUNCS = settings.scope.llm_trigger_funcs
SCOPE_LLM_TOP_K = settings.scope.llm_top_k
SCOPE_LLM_CONFIDENCE_THRESHOLD = settings.scope.llm_confidence_threshold


# Keep `from config import *` to an intentional surface: the validated `settings`
# object plus the back-compat constants (not the pydantic/stdlib import machinery).
__all__ = [
    "settings",
    "LLM_API_KEY",
    "LLM_API_BASE_URL",
    "FM_AGENT_MODEL_BACKEND",
    "LLM_MODEL",
    "LLM_EFFORT",
    "OPENCODE_MODEL_PROVIDER",
    "OPENCODE_SETUP_MODEL",
    "OPENCODE_SPEC_MODEL",
    "OPENCODE_BUG_VALIDATION_MODEL",
    "REASONER_POST_CONDITION_MODEL",
    "REASONER_SPEC_CHECK_MODEL",
    "MAX_SPC_ITER",
    "GRANULARITY",
    "MAX_WORKERS",
    "OPENCODE_MAX_RETRIES",
    "BUG_VALIDATION_MAX_RETRIES",
    "OPENCODE_TIMEOUT_SECONDS",
    "SCOPE_TOP_K",
    "SCOPE_LLM_TRIGGER_FUNCS",
    "SCOPE_LLM_TOP_K",
    "SCOPE_LLM_CONFIDENCE_THRESHOLD",
]

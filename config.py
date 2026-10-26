"""Central configuration for FM-Agent.

Layered precedence (highest wins):

    process env  >  explicit secrets file  >  fm-agent.toml  >  built-in defaults

Non-secret defaults live in ``fm-agent.toml``; secrets stay in the file selected
by ``FM_AGENT_SECRET_FILE`` (or ``.env`` in a source checkout). Target-project
``.env`` files are deliberately never loaded.

Import the validated ``settings`` object for new code; the module-level
``UPPER_CASE`` constants below are kept for backward compatibility with existing
``from config import *`` callers.

Set ``FM_AGENT_CONFIG`` to point at an alternate toml file (defaults to
``fm-agent.toml`` next to this module).
"""

from __future__ import annotations

import os
import sys
import tomllib
from pathlib import Path
from typing import Literal

from dotenv import load_dotenv
from pydantic import BaseModel, ConfigDict, Field, ValidationError
from pydantic_settings import (
    BaseSettings,
    PydanticBaseSettingsSource,
    SettingsConfigDict,
)

_explicit_config = os.environ.get("FM_AGENT_CONFIG")
_CONFIG_PATH = (
    Path(_explicit_config)
    if _explicit_config
    else Path(__file__).parent / "fm-agent.toml"
)
# A typo'd FM_AGENT_CONFIG should fail fast, not silently fall back to defaults
# (a missing default fm-agent.toml is tolerated — the built-in defaults apply).
if _explicit_config and not _CONFIG_PATH.is_file():
    raise SystemExit(
        f"FM-Agent: FM_AGENT_CONFIG points at a file that does not exist: {_CONFIG_PATH}"
    )

# Load exactly one application-owned secret file without clobbering exported
# variables. Calling load_dotenv() without a path would search upward from the
# target checkout and could accidentally consume that project's credentials or
# stale model overrides.
_explicit_secret = os.environ.get("FM_AGENT_SECRET_FILE")
_SECRET_PATH = (
    Path(_explicit_secret)
    if _explicit_secret
    else (_CONFIG_PATH.with_name("secrets.env") if _explicit_config else Path(__file__).parent / ".env")
)
if _SECRET_PATH.is_file():
    load_dotenv(_SECRET_PATH, override=False)

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
    "LLM_API_STYLE": ("llm", "api_style"),
    "FM_AGENT_DSH_BIN": ("llm", "harness_bin"),
    "FM_AGENT_DSH_PATCH": ("llm", "harness_patch"),
    "FM_AGENT_TOOL_COMPAT_MODE": ("llm", "tool_compat_mode"),
    # [runtime]
    "MAX_SPC_ITER": ("runtime", "max_spec_iter"),
    "GRANULARITY": ("runtime", "granularity"),
    "MAX_WORKERS": ("runtime", "max_workers"),
    "AGENT_MAX_RETRIES": ("runtime", "agent_max_retries"),
    "AGENT_TIMEOUT_SECONDS": ("runtime", "agent_timeout_s"),
    "FM_AGENT_DOMAIN_KNOWLEDGE": ("runtime", "domain_knowledge_paths"),
    # [scope]
    "SCOPE_TOP_K": ("scope", "top_k"),
    "SCOPE_LLM_TRIGGER_FUNCS": ("scope", "llm_trigger_funcs"),
    "SCOPE_LLM_TOP_K": ("scope", "llm_top_k"),
    "SCOPE_LLM_CONFIDENCE_THRESHOLD": ("scope", "llm_confidence_threshold"),
    # [erlang]
    "ELP_COMMAND": ("erlang", "command"),
    "ELP_TIMEOUT_SECONDS": ("erlang", "timeout_s"),
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
    base_url: str = "https://dashscope.aliyuncs.com/compatible-mode/v1"
    backend: Literal["deepseek-harness"] = "deepseek-harness"
    name: str = "qwen3.6-35b-a3b"
    effort: str = ""
    # Endpoint API style used by the DeepSeek Harness pi-ai adapter.
    # Typed so a typo (or wrong case) fails fast at config load, not silently.
    api_style: Literal["openai", "anthropic"] = "openai"
    # The offline launcher normally supplies both paths. Empty values let a
    # source checkout resolve `dsh` from PATH and use its bundled patch.
    harness_bin: str = ""
    harness_patch: str = ""
    # native sends OpenAI tools unchanged. qwen-text is an explicit fallback
    # for upstream services whose server-side tool parser is incompatible.
    tool_compat_mode: Literal["qwen-text", "native"] = "native"


class RuntimeCfg(_Section):
    # These must be positive — e.g. granularity=0 makes the reasoner's block
    # splitter loop forever, max_workers=0 crashes the thread pool, and a
    # non-positive timeout expires immediately. Validated so a bad value fails
    # fast at startup rather than hanging or crashing mid-run.
    max_spec_iter: int = Field(default=5, gt=0)
    granularity: int = Field(default=40, gt=0)
    max_workers: int = Field(default=10, gt=0)
    agent_max_retries: int = Field(default=5, gt=0)
    # Hard cap on one DeepSeek Harness headless invocation.
    agent_timeout_s: int = Field(default=1800, gt=0)
    # Extra domain-knowledge markdown paths (os.pathsep- or newline-separated);
    # env-driven, so no committed default.
    domain_knowledge_paths: str = ""


class ScopeCfg(_Section):
    # Max functions retained per source file in the final scoped output.
    top_k: int = Field(default=5, gt=0)
    # Run LLM re-ranking when a file has at least this many dedup'd functions.
    llm_trigger_funcs: int = Field(default=5, gt=0)
    # Candidate functions requested from the LLM during re-ranking.
    llm_top_k: int = Field(default=5, gt=0)
    # Run LLM re-ranking when the heuristic top score is below this threshold.
    llm_confidence_threshold: float = Field(default=8.0, ge=0)


class ErlangCfg(_Section):
    command: str = "elp"
    timeout_s: int = Field(default=180, gt=0)


class CodegraphCfg(_Section):
    # The pinned maintenance-fork build. install.sh reads these to install it and
    # the runtime invokes the pinned binary, so this is the single place that
    # decides "which codegraph" and "where it lives".
    repo: str = "fmagent-project/codegraph"
    # fm-agent.toml is the authoritative source; this default is only the fallback
    # when the toml is absent. Keep it in sync when bumping the pinned version.
    version: str = "v1.6.0-fmagent.1"
    bin_dir: str = "~/.local/bin"  # launcher location; install and run must agree


class _LayeredSource(PydanticBaseSettingsSource):
    """``fm-agent.toml`` as the base layer, mapped process env overlaid on top."""

    def __init__(self, settings_cls, path: Path):
        super().__init__(settings_cls)
        data: dict = {}
        if path.is_file():
            data = tomllib.loads(path.read_text())
        else:
            # A missing default fm-agent.toml is tolerated (built-in defaults are
            # kept identical to it), but warn: it usually means a broken checkout
            # or a deleted file, and silently using defaults would hide that.
            print(
                f"FM-Agent: {path.name} not found at {path}; using built-in defaults.",
                file=sys.stderr,
            )
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
except (ValidationError, tomllib.TOMLDecodeError) as exc:
    # Fail fast with a readable message instead of a raw traceback: a bad value or
    # typo'd key (ValidationError) or a syntax error in the toml (TOMLDecodeError)
    # in fm-agent.toml / the secret file / an env var stops startup here.
    raise SystemExit(
        f"FM-Agent: invalid configuration (check {_CONFIG_PATH.name}, {_SECRET_PATH.name}, or the "
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
AGENT_SETUP_MODEL = LLM_MODEL
AGENT_SPEC_MODEL = LLM_MODEL
REASONER_POST_CONDITION_MODEL = LLM_MODEL
REASONER_SPEC_CHECK_MODEL = LLM_MODEL

MAX_SPC_ITER = settings.runtime.max_spec_iter
GRANULARITY = settings.runtime.granularity
MAX_WORKERS = settings.runtime.max_workers
AGENT_MAX_RETRIES = settings.runtime.agent_max_retries
AGENT_TIMEOUT_SECONDS = settings.runtime.agent_timeout_s

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
    "AGENT_SETUP_MODEL",
    "AGENT_SPEC_MODEL",
    "REASONER_POST_CONDITION_MODEL",
    "REASONER_SPEC_CHECK_MODEL",
    "MAX_SPC_ITER",
    "GRANULARITY",
    "MAX_WORKERS",
    "AGENT_MAX_RETRIES",
    "AGENT_TIMEOUT_SECONDS",
    "SCOPE_TOP_K",
    "SCOPE_LLM_TRIGGER_FUNCS",
    "SCOPE_LLM_TOP_K",
    "SCOPE_LLM_CONFIDENCE_THRESHOLD",
]

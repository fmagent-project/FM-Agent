import os
from dotenv import load_dotenv

load_dotenv()

LLM_API_KEY = os.environ.get("LLM_API_KEY", "")
LLM_API_BASE_URL = os.environ.get("LLM_API_BASE_URL", "https://openrouter.ai/api/v1")
LLM_MODEL = os.environ.get("LLM_MODEL", "anthropic/claude-sonnet-4.6")
# OpenCode provider prefix used when invoking `opencode run --model <prefix>/<model>`.
# Must match a provider registered in ~/.config/opencode/opencode.json.
OPENCODE_MODEL_PROVIDER = os.environ.get("OPENCODE_MODEL_PROVIDER", "openrouter")

OPENCODE_SETUP_MODEL = LLM_MODEL
OPENCODE_SPEC_MODEL = LLM_MODEL
OPENCODE_BUG_VALIDATION_MODEL = LLM_MODEL
REASONER_POST_CONDITION_MODEL = LLM_MODEL
REASONER_SPEC_CHECK_MODEL = LLM_MODEL

MAX_SPC_ITER = 5
GRANULARITY = 40
MAX_WORKERS = 10
OPENCODE_MAX_RETRIES = 5


def _positive_int_env(name, default):
    value = os.environ.get(name)
    if value is None or value.strip() == "":
        return default
    try:
        parsed = int(value)
    except ValueError:
        return default
    return max(1, parsed)


# Maximum number of concurrent `opencode` spec-generation processes. Launching a
# whole topdown layer at once (dozens of batches) overwhelms the opencode server
# and the LLM endpoint ("Session not found", 5xx, rate limits), so spec
# generation keeps at most this many agents in flight at a time.
OPENCODE_MAX_CONCURRENCY = _positive_int_env("OPENCODE_MAX_CONCURRENCY", 6)

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

LSP_TIMEOUT_SECONDS = int(os.environ.get("LSP_TIMEOUT_SECONDS", "600"))
LSP_STRICT = os.environ.get("LSP_STRICT", "0") == "1"

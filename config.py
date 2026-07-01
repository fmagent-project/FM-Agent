import os
from dotenv import load_dotenv

load_dotenv()

LLM_API_KEY = os.environ.get("LLM_API_KEY", "")
LLM_API_BASE_URL = os.environ.get("LLM_API_BASE_URL", "https://openrouter.ai/api/v1")
FM_AGENT_MODEL_BACKEND = os.environ.get("FM_AGENT_MODEL_BACKEND", "opencode")
LLM_MODEL = os.environ.get("LLM_MODEL", "anthropic/claude-sonnet-4.6")
LLM_EFFORT = os.environ.get("LLM_EFFORT", "").strip()
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
# Number of retries (in addition to the initial attempt) when validating a candidate bug;
# the maximum number of bug-validation attempts per function is this value + 1.
BUG_VALIDATION_MAX_RETRIES = int(os.environ.get("BUG_VALIDATION_MAX_RETRIES", "1"))

# Hard cap on ONE `opencode run` subprocess. A model connection that dies
# silently (e.g. through a forward proxy) otherwise hangs the pipeline forever —
# opencode has no model-call timeout of its own. On expiry the child is killed
# and the call raises CalledProcessError, which the callers' retry paths handle.
OPENCODE_TIMEOUT_SECONDS = int(os.environ.get("OPENCODE_TIMEOUT_SECONDS", "1800"))

# Function-selection scope knobs
# Max number of functions retained per source file in the final scoped output.
SCOPE_TOP_K = int(os.environ.get("SCOPE_TOP_K", "5"))
# Run LLM re-ranking when a file has at least this many deduplicated functions.
SCOPE_LLM_TRIGGER_FUNCS = int(os.environ.get("SCOPE_LLM_TRIGGER_FUNCS", "5"))
# Number of candidate functions requested from the LLM during re-ranking.
# Final output per file is still capped by SCOPE_TOP_K.
SCOPE_LLM_TOP_K = int(os.environ.get("SCOPE_LLM_TOP_K", "5"))
# Run LLM re-ranking when heuristic top score is below this threshold.
SCOPE_LLM_CONFIDENCE_THRESHOLD = float(
	os.environ.get("SCOPE_LLM_CONFIDENCE_THRESHOLD", "8.0")
)

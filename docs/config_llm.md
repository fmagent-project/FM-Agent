# LLM Provider Configuration

FM-Agent reads these settings from `.env` (mapped to constants in `config.py`):

```dotenv
LLM_API_KEY=your-api-key                  # auth token for FM-Agent's direct calls
LLM_API_BASE_URL=https://openrouter.ai/api/v1    # endpoint for FM-Agent's direct reasoner calls
LLM_MODEL=anthropic/claude-sonnet-4.6              # default model, same as upstream FM-Agent
LLM_EFFORT=                                        # optional local CLI reasoning effort
FM_AGENT_MODEL_BACKEND=opencode                 # opencode, auto, codex-cli, or claude-cli
OPENCODE_MODEL_PROVIDER=openrouter               # an OpenCode provider id
```

It calls the model two ways:

- **OpenCode** (setup / spec / bug validation): `opencode run --model "$OPENCODE_MODEL_PROVIDER/$LLM_MODEL"`, so that string must resolve to a provider + model registered in OpenCode (below).
- **Direct** (reasoner): hits `$LLM_API_BASE_URL` itself, authenticating with `$LLM_API_KEY`.

When `FM_AGENT_MODEL_BACKEND` is set to `auto`, `codex-cli`, or `claude-cli`,
FM-Agent bypasses both of those paths and uses local CLI authentication for all
model calls:

- Codex sessions use `codex exec` with full filesystem access, plus `--model "$LLM_MODEL"` when set and `model_reasoning_effort="$LLM_EFFORT"` when non-empty.
- Claude Code sessions use `claude -p --dangerously-skip-permissions`, plus `--model "$LLM_MODEL"` when set and `--effort "$LLM_EFFORT"` when non-empty.

The following versions have been tested
- Claude Code >= 2.1.195
- Codex >= 0.140.0

Leave `LLM_EFFORT` empty to use the selected CLI's default effort behavior.
Set it only to a value accepted by the selected CLI and model.

In this mode `LLM_API_KEY`, `LLM_API_BASE_URL`, and
`OPENCODE_MODEL_PROVIDER` are not required for model access.

## Register the OpenCode provider

`OPENCODE_MODEL_PROVIDER/LLM_MODEL` is only valid if the provider is registered in `~/.config/opencode/opencode.json`:

```json
{
  "$schema": "https://opencode.ai/config.json",
  "provider": {
    "openrouter": {
      "npm": "@ai-sdk/openai-compatible",
      "options": {
        "baseURL": "https://openrouter.ai/api/v1",
        "apiKey": "{env:LLM_API_KEY}"
      },
      "models": { "anthropic/claude-sonnet-4.6": {} }
    }
  }
}
```

How it lines up with `.env`:

| `opencode.json` | `.env` |
|---|---|
| provider key (`openrouter`) | `OPENCODE_MODEL_PROVIDER` |
| `options.baseURL` | `LLM_API_BASE_URL` |
| `options.apiKey` | `LLM_API_KEY` (read from env, never hard-coded) |
| a key under `models` | `LLM_MODEL` |

To use another endpoint, copy the block, rename it, point `baseURL` at the
endpoint, and update `.env` to match. Pick `npm` by API style:
`@ai-sdk/openai-compatible` for OpenAI-style endpoints such as OpenRouter, or
`@ai-sdk/anthropic` for Anthropic-style `/v1/messages` endpoints.

## Third-party LLM services and cache routing

If you use a third-party LLM service or relay, you may need a stable user id in
model requests so the service can route repeated calls to the same cache bucket.
Use the `inject-user-id` OpenCode plugin for OpenCode calls. FM-Agent's direct
LLM calls read the same `INJECT_HOST` and `INJECT_ID` environment variables, so
both paths use the same routing id.

```json
{
  "$schema": "https://opencode.ai/config.json",
  "plugin": [
    "@lucentia/opencode-trace",
    "oh-my-openagent@latest",
    "inject-user-id"
  ],
  "provider": {
    "claudecode": {
      "npm": "@ai-sdk/anthropic",
      "options": {
        "baseURL": "xxx",
        "apiKey": "{env:LLM_API_KEY}"
      },
      "models": { "claude-opus-4-8": {} }
    }
  }
}
```

Set the host to inject into before running FM-Agent:

```bash
export INJECT_HOST=xxx
# Optional. Defaults to stable-user-or-session-id-xxxxxxx123.
export INJECT_ID=stable-user-or-session-id-xxxxxxx123
```

Then run FM-Agent normally:

```bash
INJECT_HOST=xxx \
LLM_API_BASE_URL=xxx \
LLM_MODEL=claude-opus-4-8 \
OPENCODE_MODEL_PROVIDER=claudecode \
python main.py /path/to/project
```

`INJECT_HOST` can be a comma-separated list of hosts or URL prefixes. Without
`INJECT_HOST`, the plugin does not inject anything.

# LLM Provider Configuration

FM-Agent reads its non-secret settings from `fm-agent.toml` (loaded and validated
by `config.py`); the LLM API key stays in `.env`. Every setting can also be
overridden by the environment variable shown below, which takes precedence over
the toml — so an existing `.env` that sets these still works.

`fm-agent.toml` (committed, non-secret):

```toml
[llm]
name     = "anthropic/claude-sonnet-4.6"    # override: LLM_MODEL — default model, same as upstream FM-Agent
provider = "openrouter"                       # override: OPENCODE_MODEL_PROVIDER — an OpenCode provider id
base_url = "https://openrouter.ai/api/v1"     # override: LLM_API_BASE_URL — endpoint for FM-Agent's direct reasoner calls
backend  = "opencode"                         # override: FM_AGENT_MODEL_BACKEND — opencode, auto, codex-cli, or claude-cli
effort   = ""                                 # override: LLM_EFFORT — optional local CLI reasoning effort
```

`.env` (gitignored, secret only):

```dotenv
LLM_API_KEY=your-api-key                      # auth token for FM-Agent's direct calls
```

It calls the model two ways:

- **OpenCode** (setup / spec / bug validation): `opencode run --model "$OPENCODE_MODEL_PROVIDER/$LLM_MODEL"`; FM-Agent supplies the matching OpenCode provider automatically (below), so no manual OpenCode config is needed.
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

## The OpenCode provider (generated automatically)

For the `opencode` backend, FM-Agent builds the OpenCode provider block from
`[llm]` in `fm-agent.toml` and injects it into the OpenCode subprocess at
runtime (via `OPENCODE_CONFIG_CONTENT`). **You do not need to register a provider
in `~/.config/opencode/opencode.json`** — `fm-agent.toml` (with its env
overrides) is the single source of truth.

The generated block is equivalent to:

```json
{
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

built from:

| generated field | `fm-agent.toml` `[llm]` / env override |
|---|---|
| provider key (`openrouter`) | `provider` / `OPENCODE_MODEL_PROVIDER` |
| `npm` adapter | `api_style` / `LLM_API_STYLE` — `openai` → `@ai-sdk/openai-compatible`, `anthropic` → `@ai-sdk/anthropic` |
| `options.baseURL` | `base_url` / `LLM_API_BASE_URL` |
| `options.apiKey` | always `{env:LLM_API_KEY}` — the key is never written to disk |
| a key under `models` | `name` / `LLM_MODEL` |

To use another endpoint, change these in `fm-agent.toml` (or set the env
overrides) — no OpenCode config edit needed. The injected config is *merged over*
your global `opencode.json`, so its `plugin` array and other settings are
preserved. It is only injected when `LLM_API_KEY` is set; if you authenticate
OpenCode some other way, leave `LLM_API_KEY` unset and your own `opencode.json`
provider is used unchanged.

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

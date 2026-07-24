# LLM Provider Configuration

FM-Agent reads its non-secret settings from `fm-agent.toml` (loaded and validated
by `config.py`); the LLM API key stays in `.env`. Every setting can also be
overridden by the environment variable shown below, which takes precedence over
the toml — so an existing `.env` that sets these still works.

## Recommended setup: interactive wizard

Run:

```bash
uv run python src/configure_llm.py
```

The wizard prompts for:

- model backend (`opencode`, `auto`, `codex-cli`, or `claude-cli`)
- provider id
- provider display name
- API protocol (`openai`-compatible or `anthropic`-compatible)
- API base URL
- model id
- API key
- whether to validate the generated configuration

It then:

- updates the active FM-Agent TOML file with the non-secret `[llm]` settings
- updates `.env` with `LLM_API_KEY` only
- removes all non-secret legacy LLM override keys from `.env` (including `export KEY=value` lines) so they no longer shadow the toml
- merges the matching provider entry into the detected OpenCode config file
- previews the target files, requests confirmation, backs up existing files, and writes atomically

When you select `auto`, `codex-cli`, or `claude-cli`, the wizard updates
`backend` in the active FM-Agent TOML file and removes non-secret legacy LLM
overrides from the project `.env`. Before removal, any `.env` `LLM_MODEL` and
`LLM_EFFORT` values are migrated to the TOML so the selected local backend keeps
using the same model and reasoning-effort preference. This prevents an old
`FM_AGENT_MODEL_BACKEND=opencode` (including `export` form) from taking
precedence over the selected local backend. These local CLI backends use their
own authentication, so the wizard does not ask for an API key or modify the
private key file or OpenCode configuration.

## Change one setting without rerunning the wizard

Use the same script's `set` command to update only the non-secret `[llm]`
setting(s) named on the command line. It previews the change, asks for
confirmation, backs up the active FM-Agent TOML file, and writes it atomically.
It does not change `.env`, the API key file, or the standalone OpenCode
configuration. If a legacy `.env` value would still override one of the
requested settings, it warns before writing; remove that line or use the
interactive wizard to migrate the legacy overrides.

For example, switch FM-Agent to a local Codex CLI backend without touching the
provider setup:

```bash
uv run python src/configure_llm.py set --backend codex-cli
```

The supported flags map directly to the six non-secret LLM settings:

```bash
uv run python src/configure_llm.py set \
  --name "anthropic/claude-sonnet-4.6" \
  --provider openrouter \
  --base-url "https://openrouter.ai/api/v1" \
  --backend opencode \
  --effort "" \
  --api-style openai
```

Any subset of those flags is valid. Add `--yes` for non-interactive use after
you have reviewed the values. The accepted backend values are `opencode`,
`auto`, `codex-cli`, and `claude-cli`; accepted API styles are `openai` and
`anthropic`; effort is empty, `low`, `medium`, or `high`.

Backups of `.env`, prior OpenCode key files, and OpenCode configuration files
are placed in a user-private backup directory, since an existing OpenCode
configuration can contain a literal API key.

The wizard never prints the API key in plain text. It writes the key to
`.env` for FM-Agent and to a private provider-specific key file under the
user's own state/config directory for standalone OpenCode; the generated
provider references that file via `{file:/absolute/path/to/key}`.
If `OPENCODE_CONFIG` is set, the wizard uses that config file path instead of
the default global location. Otherwise, if `OPENCODE_CONFIG_DIR` is set, it
uses `opencode.jsonc` from that directory when present, or `opencode.json`.
The secret file still stays outside the worktree.

If `FM_AGENT_CONFIG` is set in the launching shell or project `.env`, both the
wizard and the `set` command update that TOML path, using the same path
semantics as `config.py`; otherwise they update the repository's
`fm-agent.toml`.

`fm-agent.toml` (committed, non-secret):

```toml
[llm]
name     = "anthropic/claude-sonnet-4.6"    # override: LLM_MODEL — default model, same as upstream FM-Agent
provider = "openrouter"                       # override: OPENCODE_MODEL_PROVIDER — an OpenCode provider id
base_url = "https://openrouter.ai/api/v1"     # override: LLM_API_BASE_URL — endpoint for FM-Agent's direct reasoner calls
backend  = "opencode"                         # override: FM_AGENT_MODEL_BACKEND — opencode, auto, codex-cli, or claude-cli
api_style = "openai"                          # override: LLM_API_STYLE — endpoint style for OpenCode adapter selection
effort   = ""                                 # override: LLM_EFFORT — optional local CLI reasoning effort
```

`.env` (gitignored, secret only):

```dotenv
LLM_API_KEY=your-api-key                      # auth token for FM-Agent's direct calls
```

> **Migrating from an older `.env`:** because `.env` outranks `fm-agent.toml`, any
> non-secret setting still in your `.env` (e.g. `LLM_MODEL`) silently wins and
> editing the toml has no effect. Move those lines out of `.env`, keeping only
> `LLM_API_KEY`, so `fm-agent.toml` is the effective source.

The wizard warns when one of the LLM variables is exported in the shell that
launches it. A live shell variable has higher precedence than both `.env` and
the TOML file and cannot be changed by a child process. Before starting
FM-Agent in that shell, follow the displayed command, for example:

```bash
unset LLM_MODEL FM_AGENT_MODEL_BACKEND
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
The startup environment check also skips OpenCode-only API key and plugin checks
for these local CLI backends.

## The OpenCode provider (generated automatically)

For the `opencode` backend, FM-Agent builds the OpenCode provider block from
`[llm]` in `fm-agent.toml` and injects it into the OpenCode subprocess at
runtime (via `OPENCODE_CONFIG_CONTENT`). **You do not need to register a provider
in `~/.config/opencode/opencode.json`** — `fm-agent.toml` (with its env
overrides) is the single source of truth for FM-Agent itself.

The configuration wizard still syncs a matching provider entry into your
OpenCode config file so standalone `opencode run` usage can stay aligned with
FM-Agent. That standalone config points `apiKey` at a private provider-specific
key file under the user's private state/config directory, so users do not need
to export `LLM_API_KEY` manually and the secret never lands in the worktree.

The generated block is equivalent to:

```json
{
  "provider": {
    "openrouter": {
      "npm": "@ai-sdk/openai-compatible",
      "options": {
        "baseURL": "https://openrouter.ai/api/v1",
        "apiKey": "{file:/home/you/.local/state/fm-agent/opencode/fm-agent-opencode-api-key.openrouter.0123456789}"
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
overrides) — no OpenCode config edit needed. FM-Agent's block is OpenCode's
highest-precedence config source, so it **overrides** a same-named provider in
your `opencode.json`; you don't need (and shouldn't keep) a hand-written provider
block there. OpenCode deep-merges the rest per key, so your other providers and
the `plugin` array are preserved. (The block is injected whenever `LLM_API_KEY`
and the `[llm]` fields are set — which is the normal case, since the direct
reasoner needs `LLM_API_KEY` too.)

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

# Configuration Reference

FM-Agent's settings live in [`fm-agent.toml`](../fm-agent.toml) (with inline
comments and the matching environment-variable name for each). This table is the
full reference: every parameter, its default, and what it controls. Any setting
can be overridden by the environment variable of the same name, which takes
precedence over the toml. See [config_llm.md](config_llm.md) for LLM provider and
OpenCode setup.

| Parameter                       | Default                        | Description                                                  |
| ------------------------------- | ------------------------------ | ------------------------------------------------------------ |
| `LLM_MODEL`                     | `anthropic/claude-sonnet-4.6`  | Default model used as the fallback for all task-specific model settings |
| `OPENCODE_SETUP_MODEL`          | `LLM_MODEL`                    | Model used by OpenCode for codebase understanding, phase planning, and domain context generation |
| `OPENCODE_SPEC_MODEL`           | `LLM_MODEL`                    | Model used by OpenCode for batch behavioral spec generation  |
| `OPENCODE_BUG_VALIDATION_MODEL` | `LLM_MODEL`                    | Model used by OpenCode to validate `MISMATCH` results with probe scripts and bug reports |
| `REASONER_POST_CONDITION_MODEL` | `LLM_MODEL`                    | Model used by direct llm calls to generate block post-conditions |
| `REASONER_SPEC_CHECK_MODEL`     | `LLM_MODEL`                    | Model used by direct llm calls to check whether actual post-conditions violate specs |
| `OPENCODE_MODEL_PROVIDER`       | `openrouter`                   | OpenCode provider prefix used when invoking `opencode run --model <prefix>/<model>` |
| `LLM_API_KEY`                   | (env)                          | LLM API key for FM-Agent's direct calls |
| `LLM_API_BASE_URL`              | `https://openrouter.ai/api/v1` | LLM API base URL for FM-Agent's direct calls |
| `LLM_EFFORT`                    | unset                          | Optional reasoning effort passed to Codex, Claude, or DSH; empty uses the backend default |
| `FM_AGENT_MODEL_BACKEND`        | `opencode`                     | Model backend: `opencode`, `dsh` (alias `deepseek-harness`), `auto`, `codex-cli`, or `claude-cli` |
| `FM_AGENT_DOMAIN_KNOWLEDGE`     | unset                          | Optional `os.pathsep`-separated Markdown files with user-provided domain knowledge |
| `GRANULARITY`                   | `40`                           | Minimum number of lines per code block when splitting a function for block-by-block reasoning |
| `MAX_WORKERS`                   | `10`                           | Maximum number of concurrent worker threads for reasoning and bug validation |
| `MAX_SPC_ITER`                  | `5`                            | Maximum number of retries/iterations for FM-Agent's direct LLM verification calls (post-condition and spec checks) |
| `OPENCODE_MAX_RETRIES`          | `5`                            | Maximum retry attempts for a failed OpenCode pipeline stage |
| `OPENCODE_TIMEOUT_SECONDS`      | `1800`                         | Hard timeout (in seconds) for one agent subprocess, including DSH; stage callers retry failures |
| `CLANG_COMMAND`                 | `clang` / `clang++`            | Clang driver used for C/C++ call-graph analysis; the language-specific default is selected automatically |
| `CLANG_COMPILE_COMMANDS`        | unset                          | Optional path to `compile_commands.json` or its directory; otherwise the project root and `build/` are checked |
| `CLANG_TIMEOUT_SECONDS`         | `120`                          | Timeout for each Clang translation-unit AST export; functions not covered by successful exports use codegraph |
| `ELP_COMMAND`                   | `elp`                          | ELP executable or command used for Erlang function and call-graph analysis |
| `ELP_TIMEOUT_SECONDS`           | `180`                          | Timeout for ELP initialization, indexing, and individual LSP requests |

## DeepSeek Harness

After `./install.sh --with-dsh`, set the following in `fm-agent.toml`:

```toml
[llm]
backend = "dsh"
name = "deepseek-v4-pro"
effort = "high"
```

Add `DEEPSEEK_API_KEY` to `.env`. For a gateway, also set `DEEPSEEK_BASE_URL` to
its DeepSeek Messages-compatible root (DSH appends `/v1/messages`, reusing an
existing `/v1`). DSH uses these variables instead of `LLM_API_KEY` and
`LLM_API_BASE_URL`. `effort` is optional: `off`, `low`, `high`, or `max`.

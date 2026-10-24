# Configuration Reference

FM-Agent's settings live in [`fm-agent.toml`](../fm-agent.toml) (with inline
comments and the matching environment-variable name for each). This table is the
full reference: every parameter, its default, and what it controls. Any setting
can be overridden by the environment variable of the same name, which takes
precedence over the toml. See [config_llm.md](config_llm.md) for LLM provider and
OpenCode setup.

CodeGraph is provisioned automatically at the release pinned in `fm-agent.toml`.
On Windows x64 and ARM64, FM-Agent downloads the native release ZIP, checks its
SHA-256 and launcher version, and installs it under
`~/.cache/fm-agent/codegraph/current`. It uses a Windows file lock to serialize
concurrent installers and does not change the user's persistent PATH. Failed
downloads or version checks preserve an existing bundle. POSIX systems continue
to use the pinned `install.sh` and `flock`.

Set `FM_AGENT_CODEGRAPH_DIR` (or `[codegraph].install_dir`) to change the private
cache. If provisioning fails, FM-Agent tries `[codegraph].bin_dir` and PATH,
then falls back to regex extraction with a warning. Windows manual installations
can provide `codegraph.cmd`, `codegraph.exe`, or `codegraph.bat` in `bin_dir`.
Qualified methods use nested output directories on Windows, preserving the
same fully qualified function names as the flat POSIX layout. Incremental
matching and cleanup use this layout too.

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
| `CLANG_COMMAND`                 | `clang-15` / `clang++-15` when available | Clang driver used to emit LLVM IR; the language-specific default is selected automatically |
| `LLVM_LINK_COMMAND`             | `llvm-link-15` when available  | LLVM linker used to combine C/C++ translation-unit bitcode |
| `LLVM_DIS_COMMAND`              | `llvm-dis-15` when available   | LLVM disassembler used to map debug metadata back to indexed functions |
| `PHASAR_CALL_GRAPH_COMMAND`     | `phasar-cli`                   | PhASAR CLI used for the whole-language OTF+CFLAnders call graph; set an absolute path when it is not on `PATH` |
| `PHASAR_LLVM_VERSION`           | `15`                           | LLVM major version used to build PhASAR; it must match Clang, llvm-link, and llvm-dis |
| `CLANG_COMPILE_COMMANDS`        | unset                          | Optional path to `compile_commands.json` or its directory; otherwise the project root and `build/` are checked before optional generation |
| `CLANG_GENERATE_COMPILE_COMMANDS` | `0`                          | Set to `1` to permit automatic compilation-database generation for trusted repositories; this executes CMake configuration or the configured Bear build command before function extraction |
| `CLANG_BEAR_BUILD_COMMAND`      | unset                          | Optional build command passed as arguments (without a shell) to Bear for non-CMake projects; overrides the automatic `make -B` used when a makefile is present |
| `CLANG_COMPILE_COMMANDS_TIMEOUT_SECONDS` | `300`                 | Timeout for automatic CMake configuration or Bear compilation-database generation; the generator's process group is stopped on expiry |
| `CLANG_TIMEOUT_SECONDS`         | `120`                          | Timeout for each LLVM translation-unit export, link, and PhASAR analysis; a failed step makes that whole language use codegraph |
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

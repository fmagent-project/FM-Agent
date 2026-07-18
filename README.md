# FM-Agent: Scaling Formal Methods to Large Systems via LLM-Based Hoare-Style Reasoning

<div align="center">

English | [中文](README_zh.md)

[Website](http://fm-agent.ai/) · [Paper](https://arxiv.org/abs/2604.11556)

</div>

FM-Agent is the first framework that realizes fully automated reasoning for large-scale systems (e.g., [Claude's C Compiler](https://github.com/anthropics/claudes-c-compiler) with 143K LoC).
It contains three steps:

- Specification generation: Autonomously understand developers' intent of system design. Generate correctness specification for each function.
- Code reasoning: Reason about the code against the specification without any human effort.
- Bug diagnosis: Analyze the root cause and location of bugs based on the reasoning process.

The [website](http://fm-agent.ai/) of FM-Agent provides an online service for reasoning about codebases. You can try it easily!

> **⚠️ Warning**: The effectiveness of this framework is heavily influenced by the capability of the underlying model. Weaker models may produce hallucinations, leading to incorrect reasoning conclusions. We recommend using models with strong reasoning abilities (Claude Opus 4.6/4.7, Claude Sonnet 4.6) for more reliable results.

## Table of Contents

  - [Table of Contents](#table-of-contents)
  - [File Structure](#file-structure)
  - [Environment Setup](#environment-setup)
    - [Requirements](#requirements)
      - [Tested macOS Environment](#tested-macos-environment)
    - [Install Dependencies](#install-dependencies)
  - [Configuration](#configuration)
  - [Quick Start](#quick-start)
  - [Important Notes](#important-notes)
  - [Citation](#citation)
  - [Contact](#contact)


## File Structure

```
|-- main.py                       # Entry point — orchestrates the full pipeline
|-- dashboard.py                  # Standalone real-time TUI dashboard for a run
|-- config.py                     # Configuration (models, granularity, concurrency, timeouts)
|-- install.sh                    # Dependency installation script
|-- pyproject.toml / uv.lock      # Python project metadata and pinned dependencies (uv)
|-- .env.example                  # Template for the .env runtime config
|-- src/                          # Core source modules (extraction, reasoning, LLM interaction, etc.)
|-- md/                           # Workflow instructions that guide the agent
|-- docs/                         # Additional documentation (e.g. OpenCode/LLM provider setup)
```

## Environment Setup

### Requirements

- Ubuntu (22.04 LTS, 24.04 LTS is tested)
- Python 3.10
- pip >= 23
- [openai](https://pypi.org/project/openai/) 2.15.0
- [OpenCode](https://github.com/opencode-ai/opencode) 1.4.6
- [Bun](https://bun.sh/)
- [oh-my-openagent](https://www.npmjs.com/package/oh-my-openagent) plugin (installed via `bunx`)
- [@lucentia/opencode-trace](https://www.npmjs.com/package/@lucentia/opencode-trace) plugin — captures raw OpenCode LLM request/response traces (see [Structured Trace](#structured-trace))
- An LLM API key for your provider (the examples use [OpenRouter](https://openrouter.ai/))
- [Erlang Language Platform (ELP)](https://whatsapp.github.io/erlang-language-platform/docs/get-started/) — optional; required only when analyzing Erlang projects
  - The Erlang integration has been tested on Ubuntu with Erlang/OTP 26 or newer; select an ELP release binary built for a compatible OTP version.
  - rebar3 3.24.0 or newer is required for ELP to auto-discover projects containing `rebar.config`.
  - The macOS Erlang toolchain has not been tested as part of this integration; `./install.sh --with-erlang` installs the current Homebrew formula versions.

#### Tested macOS Environment

The following macOS environment has been tested with the install script:

- macOS 14.5 (Build 23F79), arm64
- Darwin 23.5.0
- Python 3.11.7
- pip 23.3.1
- uv 0.7.9
- OpenCode 1.17.9
- Bun/bunx 1.3.14
- Homebrew 6.0.3
- UnZip 6.00

### Install Dependencies

Set the LLM API key used by both FM-Agent and OpenCode. We recommend [OpenRouter](https://openrouter.ai/): FM-Agent invokes LLMs concurrently, and OpenRouter is generous on RPM (requests per minute) and TPM (tokens per minute) — but any compatible provider works.

Create a `.env` file in the project root (FM-Agent loads it automatically via python-dotenv). Copy the template and fill in your key:

```bash
cp .env.example .env
# then edit .env and set LLM_API_KEY
```

```bash
# .env
LLM_API_KEY=your-api-key-here
LLM_API_BASE_URL=https://openrouter.ai/api/v1
LLM_MODEL=anthropic/claude-sonnet-4.6
LLM_EFFORT=
FM_AGENT_MODEL_BACKEND=opencode
OPENCODE_MODEL_PROVIDER=openrouter
# Optional: os.pathsep-separated Markdown files with project/domain knowledge
FM_AGENT_DOMAIN_KNOWLEDGE=
```

See [docs/config_llm.md](docs/config_llm.md) for OpenCode provider configuration and optional prompt-cache setup.

Then, all of the above dependencies (except Ubuntu and Python) can be installed via the provided script:

```bash
./install.sh
```

Erlang support is optional because its toolchain is not needed for other languages. To install or verify Erlang/OTP 26+, rebar3 3.24.0+, and a compatible ELP release automatically, run:

```bash
./install.sh --with-erlang
```

The Erlang option uses Homebrew on macOS and the RabbitMQ Team Erlang PPA on Ubuntu when the system OTP is missing or too old. The Ubuntu configuration has been tested with Erlang/OTP 26+; the macOS Erlang configuration has not been tested and uses the current formula versions selected by Homebrew. On Linux, rebar3 and ELP are installed into `~/.local/bin`; ensure this directory is on `PATH` in new shells. You can still install these tools manually, verify `rebar3 version` and `elp version`, and set `ELP_COMMAND` to an absolute ELP path if needed.

(Optional) If needed, you can manually set the default LLM model and API key of OpenCode in its configuration file.

**Important:** FM-Agent automatically derives test cases based on the reasoning process to trigger potential bugs, which help developers locate and fix them. Before running FM-Agent, please ensure the execution environment for test cases is ready, and if necessary, specify how to run test cases in `md/bug_validator.md`. If you do not specify, the agent will autonomously decide the execution method.

## Configuration

Key parameters can be adjusted in [config.py](config.py).

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
| `LLM_EFFORT`                    | unset                          | Optional reasoning effort passed to `codex exec` or `claude -p`; leave empty to omit the effort flag |
| `FM_AGENT_MODEL_BACKEND`        | `opencode`                     | Model backend. Use `auto`, `codex-cli`, or `claude-cli` to bypass OpenCode and use local CLI authentication |
| `FM_AGENT_DOMAIN_KNOWLEDGE`     | unset                          | Optional `os.pathsep`-separated Markdown files with user-provided domain knowledge |
| `GRANULARITY`                   | `40`                           | Minimum number of lines per code block when splitting a function for block-by-block reasoning |
| `MAX_WORKERS`                   | `10`                           | Maximum number of concurrent worker threads for reasoning and bug validation |
| `MAX_SPC_ITER`                  | `5`                            | Maximum number of retries/iterations for FM-Agent's direct LLM verification calls (post-condition and spec checks) |
| `OPENCODE_MAX_RETRIES`          | `5`                            | Maximum retry attempts for a failed OpenCode pipeline stage |
| `OPENCODE_TIMEOUT_SECONDS`      | `1800`                         | Hard timeout (in seconds) for a single `opencode run` subprocess; on expiry the child is killed and the call is retried |
| `ELP_COMMAND`                    | `elp`                          | ELP executable or command used for Erlang function and call-graph analysis |
| `ELP_TIMEOUT_SECONDS`            | `180`                          | Timeout for ELP initialization, indexing, and individual LSP requests |

(Optional) FM-Agent uses oh-my-openagent plugin to enhance OpenCode. The comment-checker hook built into this plugin should be disabled, otherwise it may intercept every comment block that FM-Agent writes, which are specifications of functions. It may force the agent to waste tokens justifying or removing them.
You can open your oh-my-openagent config file (typically ~/.config/opencode/oh-my-openagent.json) and add disabled_hooks:

```json
{
  "disabled_hooks": ["comment-checker"],
}
```

### Structured Trace

FM-Agent always writes structured execution traces under `fm_agent/trace/`:

| Path | Content |
|---|---|
| `fm_agent/trace/events.jsonl` | Structured events for OpenCode calls and verification LLM calls |
| `fm_agent/trace/payloads/` | Event payloads such as OpenCode stdout and selected LLM messages |
| `fm_agent/trace/opencode/` | Optional raw OpenCode LLM request/response JSONL files |

To capture raw OpenCode LLM traffic, install the OpenCode trace plugin manually by adding it to `~/.config/opencode/opencode.json`:

```json
{
  "$schema": "https://opencode.ai/config.json",
  "plugin": ["@lucentia/opencode-trace"]
}
```

FM-Agent automatically passes `TRACE_DIR` and `TRACE_FILENAME` to each OpenCode process. The plugin writes `fm_agent/trace/opencode/<event_id>.jsonl`, where `<event_id>` matches the corresponding `opencode_call` event in `events.jsonl`.
OpenCode may cache the `@latest` package; to force a refresh, remove `~/.cache/opencode/packages/@lucentia/opencode-trace@latest`.


## Quick Start

```bash
uv run python main.py <proj_dir> [--resume] [--all-bugs] [--domain-knowledge FILE ...] [--submodule PATH [PATH ...]]
```

| Argument                    | Description                                                                                     |
| --------------------------- | ----------------------------------------------------------------------------------------------- |
| `proj_dir`                  | Directory of codebase that you want to check correctness                                        |
| `--resume`                  | Continue a previous, interrupted run instead of starting over                                   |
| `--incremental INTENT_FILE` | Run in incremental mode. The value is the path to an intent file describing the goal of the modification. |
| `--all-bugs`                | Continue reasoning after a mismatch and report every candidate. Full and incremental modes validate each candidate; entry mode does not run bug validation. |
| `--domain-knowledge FILE [FILE ...]` | Copy extra Markdown domain-knowledge files into the run and provide them to setup, spec generation, and bug validation agents. Alias: `--knowledge`; may be repeated. |
| `--isolate`                 | Run against an isolated git worktree snapshot of the project instead of the project directory itself. |
| `--submodule PATH [PATH ...]` | Only process source code under one or more subdirectories of `proj_dir`. |
| `--extra-edge FILE`         | Add supplemental caller-to-callee edges to the static call graph from a JSON file or directory. |
| `--only-spec`               | Only generate behavioral specs; skip the reasoning and bug validation stages. Cannot be combined with `--incremental`. |

`proj_dir` must be a git repository.

To provide project-specific domain knowledge without editing FM-Agent's built-in prompts, pass one or more Markdown files:

```bash
uv run python main.py <proj_dir> --domain-knowledge docs/invariants.md docs/protocol.md
```

FM-Agent stages these files under `fm_agent/spec_prompts/domain_context/user_knowledge/` for the current run. You can also set `FM_AGENT_DOMAIN_KNOWLEDGE` to an `os.pathsep`-separated list of Markdown files.

Use `--submodule` to limit a full or incremental run to selected project subdirectories:

```bash
uv run python main.py <proj_dir> --submodule src/core src/runtime
uv run python main.py <proj_dir> --incremental intent.md --submodule src/core src/runtime
```

`--submodule` paths must point to directories inside `proj_dir`. The option can be combined with `--resume`, `--isolate`, and `--incremental`, but not with `--entry-func`.

Use `--all-bugs` with full, incremental, or entry-point analysis:

```bash
uv run python main.py <proj_dir> --all-bugs
uv run python main.py <proj_dir> --incremental intent.md --all-bugs
uv run python main.py <proj_dir> --entry-func src::main --all-bugs
```

The option is off by default. When enabled, FM-Agent continues through later
reasoning checkpoints and writes one standard mismatch result per candidate.
Full and incremental modes validate each candidate independently. Entry-point
reasoning reports the candidates and their count but intentionally does not run
bug validation.

For a result such as `path/to/function.json`, all-bugs candidates are written
beside it as `path/to/function.bug-001.json`, `bug-002.json`, and so on. The
primary result records `bug_count` and `reasoning_complete`. Resume treats a
complete primary result as the reasoning checkpoint and only reruns candidate
validations that do not yet have a terminal result. If reasoning stopped partway
through, FM-Agent clears that function's intermediate candidates and validations
and reruns the function without disturbing completed functions.

By default, every invocation wipes the existing `fm_agent/` directory and restarts from scratch, so an interrupted run loses all prior progress. Pass `--resume` (or set the environment variable `FM_AGENT_RESUME=1`) to continue where the previous run left off. In resume mode FM-Agent keeps the existing `fm_agent/` directory and only does the remaining work. Resume with the same reasoning mode: an all-bugs workspace requires `--resume --all-bugs`; default-mode resume rejects it so existing candidates and validation records are not mixed with legacy output.

Use `--only-spec` to stop after generating behavioral specs, skipping the reasoning and bug validation stages. This produces the `[SPEC]` blocks for each function without spending time on verification, which is useful when you only want the specs or want to review them before running the full analysis. It cannot be combined with `--incremental`, which is inherently a reasoning/bug-validation flow.

```bash
uv run python main.py <proj_dir> --only-spec
```

Use `--extra-edge FILE` when the static parser cannot see an important call relationship, such as indirect syscall dispatch. Supplemental edges are applied to full, entry-point-scoped, and incremental runs. The JSON shape is:

```json
{
  "edges": [
    {
      "caller": {
        "fqn": "third_party::musl::src::time::nanosleep-c::nanosleep",
        "callsite_names": ["nanosleep"]
      },
      "callee": {
        "fqn": "kernel::liteos_a::syscall::time_syscall-c::SysNanoSleep",
        "info_names": ["__NR_nanosleep", "SYS_nanosleep", "nanosleep"]
      }
    }
  ]
}
```

Extra-edge field rules:

- `caller.fqn`: exact FQN for a single caller, adding one edge to `callee.fqn`. It may be empty.
- `caller.callsite_names`: source callsite function names. Any function containing these callsites becomes a caller and gets an edge to `callee.fqn`. It may be empty.
  - At least one of `caller.fqn` and `caller.callsite_names` must be non-empty.
- `callee.fqn`: exact FQN for a single callee.
- `callee.info_names`: optional names used to match generated `[INFO]` entries for this callee. They are only used for `[INFO]` matching and passing caller expectations.

### Incremental Mode

In incremental mode, FM-Agent reuses the results of a previous run and only re-checks what changed. It diffs the current code against the commit recorded by the previous run in `fm_agent/version.log`. Each run records the processed commit id to that file, so a subsequent `--incremental` run automatically picks it up:

```bash
python3 main.py <proj_dir> --incremental <intent_file>
```

If `fm_agent/version.log` does not exist (no previous run to compare against), FM-Agent falls back to a full run.

### Live Dashboard

FM-Agent ships a standalone real-time TUI dashboard ([dashboard.py](dashboard.py)) that visualizes a run as it progresses: per-stage progress, token usage and cost, prompt-cache hit rate, and bug-validation verdicts. It reads the trace files FM-Agent writes under `fm_agent/`, so run it in a second terminal while `main.py` is going:

```bash
uv run python dashboard.py <proj_dir>
```

| Argument    | Description                                                  |
| ----------- | ----------------------------------------------------------- |
| `proj_dir`  | Same codebase directory passed to `main.py` (monitors `<proj_dir>/fm_agent/`). You can also point it directly at any workspace directory containing a `trace/` subdir, e.g. an archived run |

Press `Ctrl-C` to exit the dashboard; it does not affect the running pipeline.

### Output

FM-Agent creates an `fm_agent/` directory under your codebase directory. The key outputs are:

#### Bug Reports (`fm_agent/bug_validation/<bug_id>.md`)

Each confirmed or investigated bug produces a Markdown report containing:

| Section | Content |
|---|---|
| Specification Claim | The post-condition that the function specification requires |
| Actual Behavior | The post-condition that the code actually implements |
| Code Evidence | The specific code statements (with line numbers) that cause the violation |
| Trigger Condition | A description of the condition that triggers the bug |
| How to Trigger | Concrete input parameters, expected vs. actual output, and reproduction steps |
| Probe Script | The full test script used to confirm the bug |
| Probe Output | Raw stdout from executing the probe script |

A `summary.json` file in `fm_agent/bug_validation/` aggregates all bug results
with counts of total reported, confirmed, not confirmed bugs. In `--all-bugs`
mode, the summary additionally reports pending candidates; a missing, corrupt,
or non-terminal validation is pending instead of disappearing from the totals.
Default-mode summary behavior is unchanged.

## Important Notes

1. FM-Agent will create an `fm_agent/` directory under your codebase directory. Make sure there is no name conflict.
2. The markdown files under `md/` provide general instructions that guide the agent's reasoning process. Prefer `--domain-knowledge` for project-specific context such as invariants, protocols, encoding rules, and domain terminology. For reusable framework behavior, customize the built-in prompts; for example, if you are reasoning about a compiler, modify `md/bug_validator.md` to instruct the agent to compare outputs against a reference implementation (e.g., GCC).
3. **Supported languages**: Rust, C, C++, Python, Java, Go, CUDA, JavaScript, TypeScript, ArkTS, Erlang. Erlang function extraction and call graphs require ELP; if ELP is unavailable, Erlang files are skipped with a warning.

## Citation

If you use FM-Agent in your projects or research, please kindly cite our [paper](https://arxiv.org/abs/2604.11556):

```bibtex
@misc{ding2026fmagent,
Author = {Haoran Ding and Zhaoguo Wang and Haibo Chen},
Title = {FM-Agent: Scaling Formal Methods to Large Systems via LLM-Based Hoare-Style Reasoning},
Year = {2026},
Eprint = {arXiv:2604.11556},
}
```

## Contact

If you have any questions, please submit an issue or send [email](mailto:nhaorand@gmail.com).

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

- [File Structure](#file-structure)
- [Environment Setup](#environment-setup)
  - [Requirements](#requirements)
  - [Install Dependencies](#install-dependencies)
- [Configuration](#configuration)
- [Quick Start](#quick-start)
- [Important Notes](#important-notes)
- [Citation](#citation)
- [Contact](#contact)


## File Structure

```
|-- main.py                # Entry point
|-- config.py              # Configuration (model, granularity, concurrency)
|-- install.sh             # Dependency installation script
|-- src/                   # Core source modules (extraction, reasoning, LLM interaction, etc.)
|-- md/                    # Workflow of FM-Agent to guide LLMs
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

### Install Dependencies

Set the LLM API key used by both FM-Agent and OpenCode. We recommend [OpenRouter](https://openrouter.ai/): FM-Agent invokes LLMs concurrently, and OpenRouter is generous on RPM (requests per minute) and TPM (tokens per minute) — but any compatible provider works.

```bash
export LLM_API_KEY="your-api-key-here"
```

See [docs/config_llm.md](docs/config_llm.md) for OpenCode provider configuration and optional prompt-cache setup.

Then, all of the above dependencies (except Ubuntu and Python) can be installed via the provided script:

```bash
./install.sh
```

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
uv run python main.py <proj_dir>
```

| Argument     | Description                                              |
| ------------ | -------------------------------------------------------- |
| `proj_dir`   | Directory of codebase that you want to check correctness |
| `--hardware` | Treat `proj_dir` as a Chisel (Scala) hardware design and generate module specs only (see below) |

### Generating Specs for Chisel (`--hardware`)

For Chisel (Scala) hardware designs, pass the `--hardware` flag:

```bash
uv run python main.py <proj_dir> --hardware
```

In this mode FM-Agent runs a **spec-only** pipeline tailored to hardware: it understands the design, splits it into subsystems, and generates verification-oriented module specifications. It does **not** run the code reasoner or bug validation — only spec generation.

The `proj_dir` must contain Scala (`.scala`) source files. For each extracted module, FM-Agent writes spec Markdown files under `fm_agent/`:

| Output                  | Content                                                              |
| ----------------------- | ------------------------------------------------------------------- |
| `<ModuleName>_spec.md`  | Verification-oriented specification of the module's behavior         |

Generated specs are validated against a quality checklist; specs that fail are automatically deleted and regenerated within the run.

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

A `summary.json` file in `fm_agent/bug_validation/` aggregates all bug results with counts of total reported, confirmed, not confirmed bugs.

## Important Notes

1. FM-Agent will create an `fm_agent/` directory under your codebase directory. Make sure there is no name conflict.
2. The markdown files under `md/` provide general instructions that guide the agent's reasoning process. Customizing them for your specific project can improve accuracy and help uncover more bugs. For example, you can include project documentation to give the agent deeper understanding of your codebase, or if you are reasoning about a compiler, modify `md/bug_validator.md` to instruct the agent to compare outputs against a reference implementation (e.g., GCC).
3. **Supported languages**: Rust, C, C++, Python, Java, Go, CUDA, JavaScript, TypeScript, ArkTS.

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


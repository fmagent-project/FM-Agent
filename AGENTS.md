# AGENTS.md

FM-Agent: an LLM-based formal-reasoning tool that generates Hoare-style specs for a target
codebase, reasons about them, and reports bugs. This file is for working on **FM-Agent's own
source**. See `README.md` / `docs/config_llm.md` for user-facing usage.

## What this repo is

A Python CLI orchestrator, not a library. It runs against *other* codebases:
`python3 main.py <proj_dir>` executes a 5-stage pipeline that repeatedly shells out to the
`opencode` CLI (`opencode run --model <provider>/<model> ...`) plus direct LLM HTTP calls.

- Entry point: `main.py` → `run_pipeline()`. Installed script alias: `fm-agent` (`[project.scripts]`).
- All pipeline output (specs, bug reports, traces) is written to an `fm_agent/` directory created
  **inside the target `proj_dir`**, never in this repo.

## Build / run / verify

- Package manager is **uv** (`uv.lock` present). `pyproject.toml` sets `[tool.uv] package = false`,
  so this is NOT an installable package despite the `fm-agent` script entry — run via `python3 main.py`.
- Install deps: `uv sync` (or follow `install.sh`, which also installs the `opencode` CLI, Bun, and
  the `oh-my-openagent` + `@lucentia/opencode-trace` plugins).
- **There is no test suite, no linter, no formatter, no typecheck config, and no CI.** Do not invent
  or assume commands like `pytest`/`ruff`/`mypy` — none are configured. Verify changes by reading
  code and, where feasible, running `python3 main.py <some_small_proj>`.
- Python version is inconsistent across files: `install.sh` and `README.md` require **3.10+**,
  but `pyproject.toml` declares `requires-python = ">=3.12"`. Keep new code compatible with 3.10.

## Configuration

- Runtime config: `.env` (gitignored, copy from `.env.example`) → loaded by `config.py` via
  `python-dotenv`. `LLM_API_KEY` is required. All per-task model constants default to `LLM_MODEL`.
- `OPENCODE_MODEL_PROVIDER`/`LLM_MODEL` must resolve to a provider+model registered in the user's
  `~/.config/opencode/opencode.json` (this is external to the repo). See `docs/config_llm.md`.

## Architecture (src/)

The 5 pipeline stages in `main.py` map to these modules:

- `extract.py` — language-aware function extraction (`LANG_CONFIG`, `EXT_TO_LANG`). Per-language
  rules for comment markers, body delimiters (`brace` vs `indent`), and skip keywords.
- `generate_topdown_layers.py` / `generate_batch_prompts.py` / `run_batch_gen.py` — build the
  phase → layer → batch prompt structure consumed by spec generation.
- `verification.py` — `streaming_reasoner()`: watches the extracted-functions dir, verifies ready
  files concurrently (`ThreadPoolExecutor`, `MAX_WORKERS`), and triggers bug validation.
- `reasoner.py` + `prompts.py` — split functions into blocks (`GRANULARITY` lines), generate
  per-block post-conditions, check post-conditions against specs via direct LLM calls.
- `llm_client.py` — FM-Agent's **direct** LLM path (separate from the `opencode` subprocess path).
  Anthropic-family models are routed through the native `/v1/messages` endpoint (not OpenAI-compat)
  to enable prompt caching; a stable `metadata.user_id` keeps multi-tenant relay caches sticky.
- `opencode_trace.py` + `trace_writer.py` — wrap every `opencode`/LLM call and write structured
  traces to `<proj_dir>/fm_agent/trace/`.

## Repo-specific conventions & gotchas

- **`md/` is runtime prompt templates, not docs.** `main.py` copies these files into the target's
  `fm_agent/` workspace and feeds them to `opencode`/the LLM as instructions. Editing `md/*.md`
  changes agent *reasoning behavior*, not application logic. `system_prompt.md`, `bug_validator.md`,
  and the `workflow_*.md` files are the live prompts.
- **`[SPEC]` / `[INFO]` markers are load-bearing.** `file_utils.is_file_ready()` treats a function
  file as "done" only when it contains ≥2 `[SPEC]` and ≥2 `[INFO]` markers. Don't strip or reformat
  these in extracted/specced files.
- The `oh-my-openagent` `comment-checker` hook must be disabled for the target's OpenCode config,
  or it will fight the spec comment blocks FM-Agent writes (see README "Configuration").
- Pipeline stages retry up to `OPENCODE_MAX_RETRIES` and treat network/`opencode` failures as
  resumable ("continue where you left off"). Preserve this idempotent-resume behavior when editing
  `run_pipeline()` — stages check for existing output files (e.g. `phases.json`) before re-running.
- `main.py` skips `opencode init` if the target already has an `AGENTS.md`; that generated file is
  for the *target* codebase, unrelated to this one.

## Do not commit

`.env` / `.envrc` (gitignored). The repo root also contains generated/scratch artifacts
(`index.html`, `index.html.1`, `dashboard.py`) — confirm intent before touching them.

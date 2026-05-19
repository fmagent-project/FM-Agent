# AGENTS.md — FM-Agent

Compact orientation for coding agents. Read `README.md` for the user-facing pitch; this file covers things that will trip up an agent.

## What this repo is

FM-Agent orchestrates multiple `opencode` CLI invocations + direct OpenRouter LLM calls to do Hoare-style formal reasoning over an *external* codebase. The external codebase is passed as `<proj_dir>`:

```bash
python3 main.py <proj_dir>
```

All FM-Agent output lands in `<proj_dir>/fm_agent/`, **never** inside this repo (except as a stale artifact from running the tool on itself — see below).

## Layout that matters

- `main.py` — the only entrypoint. Drives a 5-stage pipeline (init → extract → file list → topdown layers → spec gen + verification).
- `config.py` — runtime knobs. The four string vars are env-overridable: `OPENROUTER_API_KEY`, `LLM_API_BASE_URL` (default `https://openrouter.ai/api/v1`), `LLM_MODEL` (default `anthropic/claude-sonnet-4.6`), `OPENCODE_MODEL_PROVIDER` (default `openrouter`). The four integer constants (`MAX_WORKERS=10`, `GRANULARITY=40`, `MAX_SPC_ITER=5`, `OPENCODE_MAX_RETRIES=5`) are **not** env-overridable — hardcoded only.
- `src/` — Python modules. `from config import *` and relative imports (`from .prompts import ...`) — code must run with the **repo root as cwd**. Do not move modules into a package without adjusting both import styles. `src/opencode_trace.py:_opencode_env` explicitly sets `PWD=<proj_dir>` in the opencode subprocess env — `subprocess.Popen(cwd=...)` chdirs the child but doesn't sync `PWD`, and opencode/oh-my-openagent walk `$PWD` to find `AGENTS.md`. Without this override they would pick up *this repo's* AGENTS.md (the parent shell's cwd) and bake ~10K bytes of docs into every system prompt, invalidating the prompt cache prefix on every edit.
- `md/` — prompt templates fed to `opencode`. Copied into `<proj_dir>/fm_agent/` at runtime by `main.py`. Editing these changes agent behavior; they are the de-facto "spec" of the workflow.
  - `system_prompt.md`, `workflow_setup_extract.md`, `workflow_spec_step4_batch.md` — generic.
  - `workflow_spec_step1_layers.md` — historical only; documents the algorithm now implemented in `src/generate_topdown_layers.py`. **Not loaded at runtime** by the current pipeline.
  - `bug_validator.md` — **BespokeOLAP TPC-H specific** (hardcoded paths like `/mnt/nvme2/zyx/projects/BespokeOLAP*`). README explicitly tells users to customize per project. Do not treat as a generic template.
- `inspect_trace.py` — standalone debugger for a single function's spec → reasoning → verdict trace. Reads from `.run_logs/bundle/fm_agent_workdir/` by default.
- `dashboard.py` — standalone TUI (rich) that tails `<workdir>/trace/events.jsonl`, `trace/opencode/*.jsonl`, and `bug_validation/*.result.json` to show stage progress, token usage and native cost (priced via `litellm.model_cost`), cache hit rate, and bug verdicts. The arg can be a target codebase (uses live `<target>/fm_agent/`) or any workspace dir containing a `trace/` subdir (e.g. an archived `fm_agent.opus_partial_*`). Handles both the old plain-key opencode-trace format and `@lucentia`'s `*`-prefixed streaming-delta keys. Run: `uv run python dashboard.py <target-or-workspace>`.
## Wiring up an external prompt-cache proxy (optional)

fm-agent itself does not ship a proxy. If you want opencode-side prompt caching with a provider whose OpenAI-compat surface strips `cache_control` (or that needs `metadata.user_id` for sticky routing — common with multi-tenant gateways like svip), point opencode at a local proxy that you run separately:

1. Register a second provider in `~/.config/opencode/opencode.json` (any name) that uses `@ai-sdk/anthropic` with `baseURL` pointing at your local proxy:
   ```json
   "my-cached-provider": {
     "npm": "@ai-sdk/anthropic",
     "options": {"baseURL": "http://127.0.0.1:18234/v1", "apiKey": "{env:YOUR_KEY}"},
     "models": {"claude-opus-4-7": {}, "claude-sonnet-4-6": {}}
   }
   ```
2. Set `OPENCODE_MODEL_PROVIDER=my-cached-provider` in fm-agent's `.env`.
3. If you have a system-wide `HTTP_PROXY` env set (`env | grep -i proxy`), add `NO_PROXY=localhost,127.0.0.1` to fm-agent's `.env` so opencode subprocesses don't route loopback hops through it — dotenv loads `.env` into `os.environ` and `_opencode_env` propagates the result to the subprocess.
4. The verification-side LLM client (`src/llm_client.py`) already sets `metadata.user_id` itself when talking to claude/anthropic models — no proxy needed for that side.

The proxy itself is just an HTTP server that takes incoming `POST /v1/messages`, optionally injects `metadata.user_id` into the body, and forwards to your upstream. Keep it outside this repo.
- `bespoke-olap-tpch/workflow.md` — historical spec of the workflow; useful background, not loaded at runtime.
- `docs/verification_failure_notes.md` — post-mortem of three pipeline bugs (OpenRouter 503 handling, processed-set timing, no-spec terminal output). Read before touching `src/verification.py` retry/processed logic.

## Stale / runtime-generated paths in this repo (ignore them when reasoning about source)

- `fm_agent/` (at repo root, with `phases.json` referencing `config.py` etc.) — leftover from someone running `python3 main.py .` on this repo. Not source.
- `.run_logs/`, `opencode-trace/`, `bespoke_tpch_run_*.zip` — run artifacts.
- `.sisyphus/`, `.claude/` — agent tooling, not project source.

When `main.py` runs on a target, it skips any directory named `fm_agent`, `.venv`, `__pycache__`, `node_modules`, and hidden dirs (see `_has_source_code` in `main.py`).

## Environment & install gotchas

- **Python 3.12 required** (declared in `pyproject.toml`). 3.11 will not work.
- **`install.sh` is incomplete.** It only `pip install openai`. The project also requires `python-dotenv`, `rich`, and `litellm` (all declared in `pyproject.toml`). Prefer `uv sync` (a `uv.lock` and `.venv/` already exist) or `pip install openai python-dotenv rich litellm` over running `install.sh`.
- `pyproject.toml` has `[tool.uv] package = false` and `[project.scripts] fm-agent = "main:main"` — but `main.py` does not define a `main` function (only `run_pipeline`). The `fm-agent` console script entry is currently broken; invoke `python3 main.py <proj_dir>` directly.
- `OPENROUTER_API_KEY` is **required**. Without it `config.LLM_OPENROUTER_API_KEY` is empty and every LLM call fails. `.env` at repo root is loaded by `python-dotenv` (`config.py:4`).
- `opencode` CLI and the `oh-my-opencode` bunx plugin must be installed and on PATH. `install.sh` handles both. The `comment-checker` hook from `oh-my-opencode` **must be disabled** (it shreds `[SPEC]` comment blocks). Add to `~/.config/opencode/oh-my-opencode.json`: `{"disabled_hooks": ["comment-checker"]}`.
- `OPENCODE_MODEL_PROVIDER` (default `openrouter`) is the provider prefix used in `opencode run --model <provider>/<model>`. It must match a provider registered in `~/.config/opencode/opencode.json`. Mismatched provider = silent `opencode` failure.

## Running and debugging

- Run on a target: `python3 main.py /path/to/target/codebase`. The pipeline wipes `<target>/fm_agent/` first (`_clean_previous_run`), so any unsaved output there is lost.
- Inspect a single function's trace after a run: `python3 inspect_trace.py <function_id> [--bundle DIR]`. `function_id` format is `<dir>-<ext>::<basename>`, e.g. `loader_impl-cpp::load`. Default bundle is `.run_logs/bundle/fm_agent_workdir/`.
- Structured traces always written to `<target>/fm_agent/trace/events.jsonl` + payloads under `<target>/fm_agent/trace/payloads/`. Raw OpenCode LLM traffic requires installing `@lucentia/opencode-trace` in `~/.config/opencode/opencode.json` (README §Structured Trace). `TRACE_DIR` and `TRACE_FILENAME` env vars are auto-injected per opencode subprocess in `src/opencode_trace.py`.
- OpenCode caches `@latest` packages under `~/.cache/opencode/packages/`. Force-refresh the trace plugin by deleting `~/.cache/opencode/packages/@lucentia/opencode-trace@latest`.

## Things to NOT do

- Do not lower the retry counts (`_MAX_RATE_LIMIT_RETRIES=20`, `_MAX_LLM_RETRIES=5`) in `src/llm_client.py` without reading `docs/verification_failure_notes.md` — they exist specifically because OpenRouter/Cloudflare flakes mid-run and partial failures silently shorten the verified-function count.
- Do not move `processed.add(...)` calls in `src/verification.py` to before the verification future returns — that's the bug the docs note. Add only after a verdict (including `ERROR`) is written.
- Do not edit `fm_agent/` at the repo root expecting it to influence the tool; it's stale output, not config.
- Do not commit the `fm_agent/` dir of a target codebase — it is the user's run output.

## Repo conventions

- No tests, no linter, no formatter, no CI configured. Verification is "run the pipeline on a known target and inspect outputs".
- `src/` uses `from config import *` (absolute, from repo root) mixed with relative intra-package imports. Keep this pattern; don't introduce `src.config` style.
- Top-of-file `import logging` then `logging.info/warning` directly — no module-level logger objects. Match existing style.
- Spec comment blocks (`// [SPEC] ... // [SPEC]`, `// [INFO] ... // [INFO]`, `# [SPEC]`, etc.) are the data format produced/consumed by the pipeline. Per-language markers live in `src/extract.py:LANG_CONFIG`. The marker shape is what `is_file_ready` (`src/file_utils.py`) checks — it counts `[SPEC]` and `[INFO]` occurrences (≥ 2 each required).

## Internal contracts an agent is likely to break

- **`generate_batch_prompts.py` is called as a subprocess from `proj_dir`** (not from repo root). It is copied to `<proj>/fm_agent/spec_prompts/` at runtime and resolves its own paths via `Path(__file__).resolve().parent.parent`. Do not change this resolution if editing that file.
- **OpenCode CLI invocation format** used throughout: `opencode run --model <OPENCODE_MODEL_PROVIDER>/<LLM_MODEL> --file <workflow.md> -- <prompt>`. The `--` separator before the prompt string is required.
- **Extracted file path → FQN mapping:** `extracted_functions/dir/name-ext/func.ext` → `dir::name-ext::func`. Strip the `extracted_functions/` prefix, strip file extension, replace `/` with `::`. This format is used in `inspect_trace.py` and `src/opencode_trace.py`.
- **Default batch size is 2 functions per batch** (`generate_batch_prompts.py --batch-size` default). The old `workflow.md` says 5 — that is stale.
- **`phases.json` schema:** current version uses `languages` (list) + `file_extensions` (list) per phase, not the old single `language` + `file_extension` from `bespoke-olap-tpch/workflow.md`.

## Language support — two separate `EXT_TO_LANG` dicts

**Do not conflate them; they have different key formats and coverage.**

- `src/extract.py:EXT_TO_LANG` — bare extension keys (`"rs"`, `"cpp"`, …), 10 languages. Used by `main.py:_has_source_code` to detect if a directory contains source. Only these 10 have a `LANG_CONFIG` entry and can be extracted/specced:
  - C, C++, CUDA, Python, Go, Rust, Java, JavaScript, TypeScript, ArkTS
- `src/verification.py:EXT_TO_LANG` — dot-prefixed keys (`".rs"`, `".cpp"`, …), 17 languages. Used by the verification watcher to determine the language of an extracted function file during reasoning. Covers 7 additional languages (C#, Dart, Kotlin, PHP, Ruby, Scala, Swift) that can be *verified* but currently *not extracted* (no LANG_CONFIG entry).

`extract.py` also skips **test files** at extraction time: files inside directories named `test`, `tests`, `__tests__`, etc., or matching patterns like `*_test.py`, `*Test.java`, `*.test.ts`, `*_test.rs`. Rust functions annotated with `#[test]` are also skipped.

## Asking the user

Before making non-trivial changes, you usually want to know:
- Are they running on `bespoke_tpch` specifically, or a generic target? (`md/bug_validator.md` is wired to the former.)
- Which `LLM_MODEL` / provider are they on? Many failures are model-capability failures, not code bugs (see README warning about weaker models). Default is `anthropic/claude-sonnet-4.6`.

# Repository Guidelines

## Project Structure & Module Organization

FM-Agent is a Python 3.12 project managed with `uv`. The root entry point is `main.py`; `dashboard.py` provides the live terminal dashboard, and `config.py` contains runtime defaults. Core pipeline code lives in `src/`, with language-specific parsing and graph support under `src/languages/`. User-facing documentation is in `README.md`, `README_zh.md`, and `docs/`; internal workflow and prompt material is kept in `md/`. Generated analysis output belongs in the target project's `fm_agent/` directory and should not be committed here.

## Build, Test, and Development Commands

- `uv sync` installs the locked Python dependencies from `uv.lock`.
- `./install.sh` installs the wider toolchain described in the README; use `./install.sh --with-erlang` only when working on Erlang support.
- `uv run python main.py <proj_dir>` runs the analysis pipeline against a local project.
- `uv run python main.py <proj_dir> --resume` resumes an interrupted run.
- `uv run python dashboard.py <proj_dir>` monitors trace output in a second terminal.

There is no separate build step or committed automated test suite. Before submitting changes, run the affected command on a small representative project and confirm that expected output is produced without new errors.

## WSL Runtime Environment

Run all project Python, `uv`, OpenCode, and smoke-test commands inside WSL. From Windows-hosted automation, invoke the user's interactive Bash environment so its configured tool paths are loaded:

```powershell
wsl.exe bash -ic "cd /mnt/d/fmagent/FM-Agent && <command>"
```

- The repository path in WSL is `/mnt/d/fmagent/FM-Agent`.
- OpenCode is installed at `/home/joy/.opencode/bin/opencode`; the confirmed version is `1.17.18`.
- Do not use non-interactive `/bin/sh -lc` to decide whether OpenCode is installed. That shell does not load the user's interactive Bash PATH and can incorrectly report `opencode: not found`.
- Use Windows PowerShell only for necessary host-side file inspection. Do not use it to run project Python, `uv`, OpenCode, or smoke-test commands.

## Coding Style & Naming Conventions

Follow existing Python conventions: four-space indentation, `snake_case` for modules, functions, and variables, and `PascalCase` for classes. Keep functions focused and add type hints where surrounding code uses them. Prefer `pathlib` and the shared helpers in `src/file_utils.py` for filesystem work. Place new language behavior in `src/languages/<language>.py` and register it through the existing registry rather than adding language checks throughout the pipeline. No formatter or linter is currently configured, so keep imports organized and match nearby style.

## Testing Guidelines

Use manual smoke tests targeted to the changed stage or language. Exercise both the normal path and relevant failure or resume behavior. Avoid tests that require paid LLM calls when a parser, filesystem, or configuration path can be checked locally. Document the command and result in the pull request.

## Commit & Pull Request Guidelines

Recent history follows Conventional Commit-style subjects such as `fix(extract): identify C++ operator overloads` and `feat: add domain knowledge markdown interface`. Use an imperative, concise subject with a suitable prefix (`feat:`, `fix:`, `docs:`, or a scoped variant). Pull requests should explain the problem, summarize the solution, link the issue when applicable, and list manual verification. Include screenshots only for dashboard-visible changes, and call out configuration or dependency changes explicitly.

Every commit created by an agent must use one of these semantic forms:

- `feat: <imperative summary>` or `feat(<scope>): <imperative summary>`
- `fix: <imperative summary>` or `fix(<scope>): <imperative summary>`
- `docs: <imperative summary>` or `docs(<scope>): <imperative summary>`
- `chore: <imperative summary>` or `chore(<scope>): <imperative summary>`

Do not create unprefixed commit subjects. Choose the narrowest useful scope when a
change belongs to one pipeline stage or module.

## Security & Configuration Tips

Copy `.env.example` for local configuration. Never commit API keys, provider credentials, generated traces, or analyzed third-party source code.

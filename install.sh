#!/usr/bin/env bash
set -euo pipefail

if [[ "$#" -ne 0 ]]; then
    echo "[!!] install.sh no longer accepts --with-erlang; Erlang uses CodeGraph."
    exit 1
fi

echo "=== fm-agent: installing required software ==="

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# Run from the repo root so `uv sync`/`uv run` target the FM-Agent project and
# `from config import settings` resolves, regardless of the caller's directory.
cd "$SCRIPT_DIR"
if [[ -f "$SCRIPT_DIR/.env" ]]; then
    set -a
    # shellcheck disable=SC1091
    source "$SCRIPT_DIR/.env"
    set +a
fi

# ---------- Python 3.12+ ----------
if command -v python3 &>/dev/null; then
    py_ver=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
    py_major=$(python3 -c 'import sys; print(sys.version_info.major)')
    py_minor=$(python3 -c 'import sys; print(sys.version_info.minor)')
    if [[ "$py_major" -lt 3 ]] || { [[ "$py_major" -eq 3 ]] && [[ "$py_minor" -lt 12 ]]; }; then
        echo "[!!] python3 version $py_ver found, but 3.12+ is required."
        exit 1
    fi
    echo "[ok] python3 found: $(python3 --version)"
else
    echo "[!!] python3 not found. Please install Python 3.12+ for your platform."
    exit 1
fi

# ---------- pip ----------
if python3 -m pip --version &>/dev/null; then
    echo "[ok] pip found"
else
    echo "[..] installing pip"
    python3 -m ensurepip --upgrade || {
        echo "[!!] could not install pip. Install it manually."
        exit 1
    }
fi

# requires pip >= 23.0.1; upgrade if too old
pip_ver=$(python3 -m pip --version | awk '{print $2}')
pip_major=$(echo "$pip_ver" | cut -d. -f1)
if [[ "$pip_major" -lt 23 ]]; then
    echo "[..] pip $pip_ver is too old (need >= 23.0.1. Upgrade it manually"
    exit 1
fi

# ---------- uv ----------
if command -v uv &>/dev/null; then
    echo "[ok] uv found: $(uv --version)"
else
    echo "[..] installing uv"
    curl -LsSf https://astral.sh/uv/install.sh | sh
    export PATH="$HOME/.local/bin:$PATH"
fi

# ---------- Python packages ----------
# Always sync the full locked dependency set: config.py imports pydantic-settings
# at startup, so a partial install (e.g. only `openai`) leaves `python main.py`
# unable to import config.
echo "[..] installing Python dependencies"
uv sync --locked

# ---------- read config from the app's own loader ----------
# Read the settings install.sh needs straight from config.py, so the installer and
# the runtime share ONE parser, ONE precedence (env > toml), and ONE validation
# instead of a second hand-rolled TOML reader that could drift. Runs after
# `uv sync` so pydantic is importable; honors FM_AGENT_CONFIG like the runtime. A
# missing toml yields built-in defaults; a broken/invalid toml makes config.py
# abort here with a readable message (set -e stops the install).
_fmcfg="$(uv run --no-sync python - <<'PY'
import os
from config import settings
print(settings.llm.backend)
print(settings.codegraph.repo)
print(settings.codegraph.version)
print(os.path.expanduser(settings.codegraph.bin_dir))
PY
)"
FM_AGENT_MODEL_BACKEND="$(printf '%s\n' "$_fmcfg" | sed -n 1p | tr '[:upper:]' '[:lower:]')"
CODEGRAPH_REPO="$(printf '%s\n' "$_fmcfg" | sed -n 2p)"
CODEGRAPH_VERSION="$(printf '%s\n' "$_fmcfg" | sed -n 3p)"
codegraph_bin_dir="$(printf '%s\n' "$_fmcfg" | sed -n 4p)"

# Decide whether to set up a local CLI backend or OpenCode. config.py keeps
# `backend` a free string, so the installer still owns the allow-list of values
# it knows how to provision.
USE_LOCAL_CLI_BACKEND=0
case "$FM_AGENT_MODEL_BACKEND" in
    ""|0|false|no|off|opencode|open-code)
        USE_LOCAL_CLI_BACKEND=0
        ;;
    auto|codex|codex-cli|claude|claude-cli)
        USE_LOCAL_CLI_BACKEND=1
        ;;
    *)
        echo "[!!] unsupported FM_AGENT_MODEL_BACKEND: $FM_AGENT_MODEL_BACKEND"
        exit 1
        ;;
esac

# ---------- unzip ----------
if command -v unzip &>/dev/null; then
    echo "[ok] unzip found"
else
    echo "[!!] could not find unzip. Install it manually."
    exit 1
fi

if [[ "$USE_LOCAL_CLI_BACKEND" -eq 1 ]]; then
    echo "[ok] local CLI backend enabled: $FM_AGENT_MODEL_BACKEND"
    if [[ "$FM_AGENT_MODEL_BACKEND" == "claude" || "$FM_AGENT_MODEL_BACKEND" == "claude-cli" ]]; then
        command -v claude &>/dev/null || { echo "[!!] claude CLI not found"; exit 1; }
        echo "[ok] claude found: $(claude --version 2>/dev/null || echo 'unknown version')"
    elif [[ "$FM_AGENT_MODEL_BACKEND" == "codex" || "$FM_AGENT_MODEL_BACKEND" == "codex-cli" ]]; then
        command -v codex &>/dev/null || { echo "[!!] codex CLI not found"; exit 1; }
        echo "[ok] codex found: $(codex --version 2>/dev/null || echo 'unknown version')"
    else
        command -v codex &>/dev/null || { echo "[!!] codex CLI not found for auto backend"; exit 1; }
        command -v claude &>/dev/null || { echo "[!!] claude CLI not found for auto backend"; exit 1; }
        echo "[ok] codex found: $(codex --version 2>/dev/null || echo 'unknown version')"
        echo "[ok] claude found: $(claude --version 2>/dev/null || echo 'unknown version')"
    fi
    echo "[ok] skipping opencode and oh-my-openagent initialization"
else
    # ---------- opencode CLI ----------
    if command -v opencode &>/dev/null; then
        echo "[ok] opencode found: $(opencode --version 2>/dev/null || echo 'unknown version')"
    else
        echo "[..] installing opencode"
        curl -fsSL https://opencode.ai/install | bash
    fi

    # ---------- oh-my-openagent plugin ----------
    if command -v bunx &>/dev/null; then
        echo "[ok] bun found"
    else
        echo "[..] installing bun"
        curl -fsSL https://bun.sh/install | bash
        # source shell config to pick up bun PATH written by the installer
        for rc in "$HOME/.bashrc" "$HOME/.zshrc"; do
            [[ -f "$rc" ]] && source "$rc"
        done
        export BUN_INSTALL="$HOME/.bun"
        export PATH="$BUN_INSTALL/bin:$PATH"
    fi
    echo "[..] installing/updating oh-my-openagent"
    bunx oh-my-openagent install --no-tui --claude=no --gemini=no --copilot=no
fi

# ---------- codegraph (pinned via fm-agent.toml [codegraph]) ----------
# repo/version/bin_dir were read from config.settings above (env > toml, already
# ~-expanded); bump [codegraph].version in fm-agent.toml to switch. The pinned fork
# build fixes an upstream C extraction bug that otherwise drops macro-decorated
# functions. Empty only if explicitly cleared (e.g. CODEGRAPH_VERSION=""), which
# can't be installed — treat as a hard error.
[ -n "$CODEGRAPH_REPO" ] && [ -n "$CODEGRAPH_VERSION" ] && [ -n "$codegraph_bin_dir" ] || {
    echo "[!!] [codegraph] repo/version/bin_dir not set in fm-agent.toml"; exit 1; }
codegraph_want="${CODEGRAPH_VERSION#v}"
if [ "$("$codegraph_bin_dir/codegraph" --version 2>/dev/null)" = "$codegraph_want" ]; then
    echo "[ok] codegraph $codegraph_want already installed in $codegraph_bin_dir"
else
    echo "[..] installing codegraph $CODEGRAPH_VERSION from $CODEGRAPH_REPO"
    curl -fsSL "https://raw.githubusercontent.com/$CODEGRAPH_REPO/main/install.sh" \
      | CODEGRAPH_VERSION="$CODEGRAPH_VERSION" CODEGRAPH_BIN_DIR="$codegraph_bin_dir" sh
    # Verify the pinned VERSION installed, not just that a binary exists: a bad
    # version/network failure otherwise leaves a stale build in place silently.
    [ "$("$codegraph_bin_dir/codegraph" --version 2>/dev/null)" = "$codegraph_want" ] \
      || { echo "[!!] codegraph $codegraph_want install failed"; exit 1; }
fi

echo ""
echo "=== all dependencies installed ==="

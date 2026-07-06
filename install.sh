#!/usr/bin/env bash
set -euo pipefail

echo "=== fm-agent: installing required software ==="

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [[ -f "$SCRIPT_DIR/.env" ]]; then
    set -a
    # shellcheck disable=SC1091
    source "$SCRIPT_DIR/.env"
    set +a
fi

FM_AGENT_MODEL_BACKEND="${FM_AGENT_MODEL_BACKEND:-opencode}"
FM_AGENT_MODEL_BACKEND="$(echo "$FM_AGENT_MODEL_BACKEND" | tr '[:upper:]' '[:lower:]')"
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

# ---------- Python 3.10+ ----------
if command -v python3 &>/dev/null; then
    py_ver=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
    py_major=$(python3 -c 'import sys; print(sys.version_info.major)')
    py_minor=$(python3 -c 'import sys; print(sys.version_info.minor)')
    if [[ "$py_major" -lt 3 ]] || { [[ "$py_major" -eq 3 ]] && [[ "$py_minor" -lt 10 ]]; }; then
        echo "[!!] python3 version $py_ver found, but 3.10+ is required."
        exit 1
    fi
    echo "[ok] python3 found: $(python3 --version)"
else
    echo "[!!] python3 not found. Please install Python 3.10+ for your platform."
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
echo "[..] installing Python dependencies"
if ! python3 -m pip install openai; then
    echo "[..] pip install failed; syncing Python dependencies with uv"
    uv sync --locked
fi

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

# ---------- codegraph ----------
if command -v codegraph &>/dev/null; then
    echo "[ok] codegraph found: $(codegraph --version 2>/dev/null || echo 'unknown version')"
else
    echo "[..] installing codegraph"
    bun install -g @colbymchenry/codegraph
fi

echo ""
echo "=== all dependencies installed ==="

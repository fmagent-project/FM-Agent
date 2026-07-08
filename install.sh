#!/usr/bin/env bash
set -euo pipefail

echo "=== fm-agent: installing required software ==="

INSTALL_ERLANG_SUPPORT=0
for arg in "$@"; do
    case "$arg" in
        --with-erlang)
            INSTALL_ERLANG_SUPPORT=1
            ;;
        -h|--help)
            echo "Usage: ./install.sh [--with-erlang]"
            echo "  --with-erlang  Install/verify Erlang/OTP 26+, rebar3 3.24.0+, and ELP"
            exit 0
            ;;
        *)
            echo "[!!] unknown option: $arg"
            echo "Usage: ./install.sh [--with-erlang]"
            exit 1
            ;;
    esac
done

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

version_ge() {
    python3 -c '
import re, sys
def parts(value):
    return tuple(int(item) for item in re.findall(r"\d+", value)[:3])
raise SystemExit(0 if parts(sys.argv[1]) >= parts(sys.argv[2]) else 1)
' "$1" "$2"
}

otp_major() {
    erl -noshell -eval 'io:format("~s", [erlang:system_info(otp_release)]), halt().' 2>/dev/null
}

install_elp_linux_binary() {
    local otp_version machine release_json elp_url temp_dir elp_binary
    otp_version="$(otp_major)"
    machine="$(uname -m)"
    release_json="$(curl -fsSL https://api.github.com/repos/WhatsApp/erlang-language-platform/releases/latest)"
    elp_url="$(printf '%s' "$release_json" | python3 -c '
import json, re, sys

release = json.load(sys.stdin)
machine = sys.argv[1]
otp = int(sys.argv[2])
aliases = {
    "x86_64": ("x86_64", "amd64"),
    "amd64": ("x86_64", "amd64"),
    "aarch64": ("aarch64", "arm64"),
    "arm64": ("aarch64", "arm64"),
}.get(machine, (machine,))
candidates = []
for asset in release.get("assets", []):
    name = asset.get("name", "").lower()
    match = re.search(r"otp-(\d+)(?:\.|-|\.tar)", name)
    if not match or "linux" not in name or not name.endswith(".tar.gz"):
        continue
    if not any(alias in name for alias in aliases):
        continue
    built_for = int(match.group(1))
    if built_for <= otp:
        candidates.append((built_for, "gnu" in name, asset["browser_download_url"]))
if not candidates:
    raise SystemExit("no compatible Linux ELP release asset found")
print(max(candidates)[2])
' "$machine" "$otp_version")"

    temp_dir="$(mktemp -d)"
    curl -fsSL "$elp_url" -o "$temp_dir/elp.tar.gz"
    tar -xzf "$temp_dir/elp.tar.gz" -C "$temp_dir"
    elp_binary="$(find "$temp_dir" -type f -name elp -print -quit)"
    if [[ -z "$elp_binary" ]]; then
        rm -rf "$temp_dir"
        echo "[!!] downloaded ELP archive does not contain an elp executable"
        exit 1
    fi
    mkdir -p "$HOME/.local/bin"
    install -m 0755 "$elp_binary" "$HOME/.local/bin/elp"
    rm -rf "$temp_dir"
    export PATH="$HOME/.local/bin:$PATH"
}

if [[ "$INSTALL_ERLANG_SUPPORT" -eq 1 ]]; then
    echo "[..] installing/verifying optional Erlang support"
    os_name="$(uname -s)"
    if [[ "$os_name" == "Darwin" ]]; then
        command -v brew &>/dev/null || {
            echo "[!!] Homebrew is required to install Erlang support on macOS."
            exit 1
        }
        brew install erlang rebar3 erlang-language-platform
    elif [[ "$os_name" == "Linux" ]]; then
        if ! command -v erl &>/dev/null || [[ "$(otp_major)" -lt 26 ]]; then
            if [[ ! -f /etc/os-release ]]; then
                echo "[!!] automatic Erlang installation is supported only on Ubuntu."
                exit 1
            fi
            # shellcheck disable=SC1091
            source /etc/os-release
            if [[ "${ID:-}" != "ubuntu" ]]; then
                echo "[!!] automatic Erlang installation is supported only on Ubuntu; found ${ID:-unknown}."
                exit 1
            fi
            echo "[..] installing Erlang/OTP 26+ from the RabbitMQ Team PPA"
            sudo apt-get update -y
            sudo apt-get install -y software-properties-common
            sudo add-apt-repository -y ppa:rabbitmq/rabbitmq-erlang
            sudo apt-get update -y
            sudo apt-get install -y \
                erlang-base erlang-crypto erlang-dev erlang-inets \
                erlang-parsetools erlang-public-key erlang-ssl \
                erlang-syntax-tools erlang-tools
        fi

        rebar_version=""
        if command -v rebar3 &>/dev/null; then
            rebar_version="$(rebar3 version 2>/dev/null | grep -Eo '[0-9]+\.[0-9]+\.[0-9]+' | head -n1 || true)"
        fi
        if [[ -z "$rebar_version" ]] || ! version_ge "$rebar_version" "3.24.0"; then
            echo "[..] installing rebar3 3.24.0+"
            mkdir -p "$HOME/.local/bin"
            curl -fsSL https://s3.amazonaws.com/rebar3/rebar3 -o "$HOME/.local/bin/rebar3"
            chmod +x "$HOME/.local/bin/rebar3"
            export PATH="$HOME/.local/bin:$PATH"
        fi

        if ! command -v elp &>/dev/null; then
            echo "[..] installing a compatible ELP release binary"
            install_elp_linux_binary
        fi
    else
        echo "[!!] automatic Erlang support installation is not available on $os_name."
        exit 1
    fi

    command -v erl &>/dev/null || { echo "[!!] erl was not installed"; exit 1; }
    installed_otp="$(otp_major)"
    if [[ "$installed_otp" -lt 26 ]]; then
        echo "[!!] Erlang/OTP $installed_otp found, but OTP 26+ is required."
        exit 1
    fi

    command -v rebar3 &>/dev/null || { echo "[!!] rebar3 was not installed"; exit 1; }
    installed_rebar="$(rebar3 version 2>/dev/null | grep -Eo '[0-9]+\.[0-9]+\.[0-9]+' | head -n1 || true)"
    if [[ -z "$installed_rebar" ]] || ! version_ge "$installed_rebar" "3.24.0"; then
        echo "[!!] rebar3 ${installed_rebar:-unknown} found, but 3.24.0+ is required."
        exit 1
    fi

    command -v elp &>/dev/null || { echo "[!!] ELP was not installed"; exit 1; }
    echo "[ok] Erlang/OTP $installed_otp"
    echo "[ok] rebar3 $installed_rebar"
    echo "[ok] $(elp version)"
fi

echo ""
echo "=== all dependencies installed ==="

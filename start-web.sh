#!/usr/bin/env bash
set -euo pipefail

app_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
web_port="${FM_WEB_PORT:-8081}"
web_demo="${FM_WEB_DEMO_MODE:-0}"
model_url="${LLM_API_BASE_URL:-https://api.deepseek.com}"
model_name="${LLM_MODEL:-deepseek-flash}"
case "${web_demo,,}" in
    1|true|yes|on) web_demo=1 ;;
    *) web_demo=0 ;;
esac

usage() {
    printf '用法：%s [--demo] [--port 端口] [--url 模型接口] [--model 模型名]\n' "${0##*/}"
    printf '默认：真实验证、端口 8081、DeepSeek deepseek-flash。API Key 从环境变量读取，或交互式隐藏输入。\n'
}

while (($#)); do
    case "$1" in
        --demo)
            web_demo=1
            shift
            ;;
        --port|--url|--model)
            option="$1"
            if (($# < 2)) || [[ -z "$2" ]]; then
                printf '缺少 %s 的参数。\n' "$option" >&2
                usage >&2
                exit 2
            fi
            case "$option" in
                --port) web_port="$2" ;;
                --url) model_url="$2" ;;
                --model) model_name="$2" ;;
            esac
            shift 2
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            printf '未知参数：%s\n' "$1" >&2
            usage >&2
            exit 2
            ;;
    esac
done

if [[ ! "$web_port" =~ ^[0-9]+$ ]] || ((${#web_port} > 5)) || ((10#$web_port < 1 || 10#$web_port > 65535)); then
    printf '端口必须是 1–65535 的整数。\n' >&2
    exit 2
fi

if [[ ! -x "$app_root/bin/fm-agent-web" ]]; then
    printf '找不到可执行的 FM-Agent Web 启动器：%s/bin/fm-agent-web\n' "$app_root" >&2
    exit 1
fi

export FM_WEB_PORT="$web_port"
export FM_WEB_DEMO_MODE="$web_demo"
export LLM_API_BASE_URL="$model_url"
export LLM_MODEL="$model_name"
export FM_AGENT_TOOL_COMPAT_MODE="${FM_AGENT_TOOL_COMPAT_MODE:-native}"

if [[ "$web_demo" != 1 && -z "${LLM_API_KEY:-}" ]]; then
    if [[ ! -t 0 ]]; then
        printf '真实验证需要 LLM_API_KEY；请在交互式终端运行，或预先通过环境变量注入。\n' >&2
        exit 1
    fi
    read -r -s -p '模型 API Key（输入时不显示）：' LLM_API_KEY
    printf '\n'
    if [[ -z "$LLM_API_KEY" ]]; then
        printf 'API Key 不能为空。\n' >&2
        exit 1
    fi
    export LLM_API_KEY
fi

printf '启动 FM-Agent Web：%s\n' "http://127.0.0.1:$web_port"
printf '模式：%s\n' "$(if [[ "$web_demo" == 1 ]]; then printf '界面演示'; else printf '真实验证（%s）' "$model_name"; fi)"
printf '按 Ctrl+C 停止。\n'
cd "$app_root"
exec "$app_root/bin/fm-agent-web"

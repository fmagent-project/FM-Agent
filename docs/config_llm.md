# Model configuration

This delivery supports one backend: bundled DeepSeek Harness. OpenCode and local
Claude/Codex CLI routes are intentionally absent.

Run `fm-agent configure` and enter the model name, compatible endpoint, API style,
tool compatibility mode, and API key. The key is read without echo and stored with mode `0600` in
`~/.config/fm-agent/secrets.env`; non-secret settings are stored in
`~/.config/fm-agent/fm-agent.toml`.

The default `tool_compat_mode = "native"` forwards tool fields unchanged. For
OpenAI-compatible Qwen endpoints with an incompatible server-side parser,
set `tool_compat_mode = "qwen-text"`; it wraps each Harness invocation with a loopback-only proxy. The proxy removes `tools`,
`tool_choice`, and `parallel_tool_calls` before forwarding the request, injects
the schemas as a textual Qwen protocol, and converts validated XML/Hermes/JSON
calls back to OpenAI `message.tool_calls`. `qwen-text` requires `api_style=openai`.

Use `fm-agent configure show` to display effective stored values with a masked key,
and `fm-agent test-model` for one end-to-end request through Harness.

Environment variables override stored settings: `LLM_API_KEY`,
`LLM_API_BASE_URL`, `LLM_MODEL`, `LLM_API_STYLE`,
`FM_AGENT_TOOL_COMPAT_MODE`, `FM_AGENT_DSH_BIN`, and `FM_AGENT_DSH_PATCH`.
Supported API styles are `openai` and `anthropic`.

Installation is network-free. Inference requires reachability to the configured
endpoint. For an air-gapped server, use an internal compatible gateway.

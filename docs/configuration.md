# Configuration reference

Precedence is process environment, secret file, `fm-agent.toml`, then built-in
defaults. Unknown TOML keys and invalid values fail fast.

| Environment | Default | Purpose |
|---|---:|---|
| `LLM_API_KEY` | empty | Model API credential; keep it out of TOML |
| `LLM_API_BASE_URL` | DashScope compatible URL | Compatible endpoint |
| `LLM_MODEL` | `qwen3.6-35b-a3b` | Model identifier |
| `LLM_API_STYLE` | `openai` | `openai` or `anthropic` |
| `FM_AGENT_MODEL_BACKEND` | `deepseek-harness` | Only accepted backend |
| `FM_AGENT_DSH_BIN` | bundled `dsh` | Harness executable override |
| `FM_AGENT_DSH_PATCH` | bundled patch | Harness profile patch override |
| `FM_AGENT_TOOL_COMPAT_MODE` | `native` | Forward tool fields unchanged; use `qwen-text` for an incompatible server parser |
| `FM_AGENT_TOOL_PROXY_TIMEOUT_SECONDS` | `1800` | Upstream timeout for the text-tool proxy |
| `FM_AGENT_UPSTREAM_CA_BUNDLE` | empty | CA bundle for a private HTTPS upstream |
| `FM_AGENT_UPSTREAM_INSECURE_TLS` | `0` | Set to `1` only to diagnose upstream TLS trust |
| `AGENT_MAX_RETRIES` | `5` | Harness stage retries |
| `AGENT_TIMEOUT_SECONDS` | `1800` | Per-Harness-call timeout |
| `MAX_WORKERS` | `10` | Parallel workers |
| `MAX_SPC_ITER` | `5` | Static specification-check iterations |
| `GRANULARITY` | `40` | Static reasoning block size |
| `FM_AGENT_DOMAIN_KNOWLEDGE` | empty | `os.pathsep`-separated knowledge files |
| `SCOPE_TOP_K` | `5` | Functions retained per selected file |
| `SCOPE_LLM_TRIGGER_FUNCS` | `5` | Function count that enables LLM reranking |
| `SCOPE_LLM_TOP_K` | `5` | Reranking candidate count |
| `SCOPE_LLM_CONFIDENCE_THRESHOLD` | `8.0` | Low-confidence reranking threshold |
| `ELP_COMMAND` | `elp` | Erlang Language Platform command |
| `ELP_TIMEOUT_SECONDS` | `180` | ELP timeout |
| `CODEGRAPH_VERSION` | `v1.6.0-fmagent.1` | Required CodeGraph version |
| `CODEGRAPH_BIN_DIR` | launcher-supplied bundle dir | CodeGraph binary directory |

All numeric runtime values that must be positive are validated at startup.

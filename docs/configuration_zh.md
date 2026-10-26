# 配置参考

优先级从高到低为：进程环境变量、密钥文件、`fm-agent.toml`、内置默认值。未知
TOML 字段和非法值会直接报错，不会静默忽略。

| 环境变量 | 默认值 | 用途 |
|---|---:|---|
| `LLM_API_KEY` | 空 | 模型密钥；不得写入 TOML |
| `LLM_API_BASE_URL` | DashScope compatible URL | 模型兼容接口 |
| `LLM_MODEL` | `qwen3.6-35b-a3b` | 模型名 |
| `LLM_API_STYLE` | `openai` | `openai` 或 `anthropic` |
| `FM_AGENT_MODEL_BACKEND` | `deepseek-harness` | 唯一支持的后端 |
| `FM_AGENT_DSH_BIN` | 随包 `dsh` | Harness 可执行文件覆盖 |
| `FM_AGENT_DSH_PATCH` | 随包 patch | Harness profile patch 覆盖 |
| `FM_AGENT_TOOL_COMPAT_MODE` | `native` | 原样发送工具字段；设为 `qwen-text` 可绕过不兼容的服务端工具解析器 |
| `FM_AGENT_TOOL_PROXY_TIMEOUT_SECONDS` | `1800` | 文本工具代理等待上游响应的秒数 |
| `FM_AGENT_UPSTREAM_CA_BUNDLE` | 空 | 自建 HTTPS 上游的 CA bundle 路径 |
| `FM_AGENT_UPSTREAM_INSECURE_TLS` | `0` | 仅诊断 TLS 信任问题时设为 `1` |
| `AGENT_MAX_RETRIES` | `5` | Harness 阶段重试次数 |
| `AGENT_TIMEOUT_SECONDS` | `1800` | 单次 Harness 调用超时 |
| `MAX_WORKERS` | `10` | 并行工作线程数 |
| `MAX_SPC_ITER` | `5` | 静态规约检查迭代次数 |
| `GRANULARITY` | `40` | 静态推理分块大小 |
| `FM_AGENT_DOMAIN_KNOWLEDGE` | 空 | 以 `os.pathsep` 分隔的知识文件 |
| `SCOPE_TOP_K` | `5` | 每个文件保留的函数数 |
| `SCOPE_LLM_TRIGGER_FUNCS` | `5` | 启用模型重排的函数数阈值 |
| `SCOPE_LLM_TOP_K` | `5` | 重排候选数 |
| `SCOPE_LLM_CONFIDENCE_THRESHOLD` | `8.0` | 低置信度重排阈值 |
| `ELP_COMMAND` | `elp` | Erlang Language Platform 命令 |
| `ELP_TIMEOUT_SECONDS` | `180` | ELP 超时 |
| `CODEGRAPH_VERSION` | `v1.6.0-fmagent.1` | 要求的 CodeGraph 版本 |
| `CODEGRAPH_BIN_DIR` | launcher 注入的随包目录 | CodeGraph 目录 |

密钥配置、真实连通测试和内外网边界见 `INSTALL_zh.md`。

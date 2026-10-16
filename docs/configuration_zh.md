# 配置参考

FM-Agent 的配置项都在 [`fm-agent.toml`](../fm-agent.toml) 里（每一项都有就近注释和对应的环境变量名）。下表是完整参考：每个参数、默认值及其作用。任何配置项都可用同名环境变量覆盖，其优先级高于 toml。LLM provider 与 OpenCode 的配置见 [config_llm.md](config_llm.md)。

| 参数 | 默认值 | 描述 |
|---|---|---|
| `LLM_MODEL` | `anthropic/claude-sonnet-4.6` | 所有任务的默认模型；本地 CLI 后端下非空时也会传给对应 CLI |
| `LLM_EFFORT` | unset | 可选；非空时传给 Codex、Claude 或 DSH，留空使用后端默认值 |
| `FM_AGENT_MODEL_BACKEND` | `opencode` | 模型后端：`opencode`、`dsh`（别名 `deepseek-harness`）、`auto`、`codex-cli` 或 `claude-cli` |
| `OPENCODE_SETUP_MODEL` | `LLM_MODEL` | 用于理解代码库、划分代码模块和生成领域知识的模型 |
| `OPENCODE_SPEC_MODEL` | `LLM_MODEL` | 用于规约生成的模型 |
| `OPENCODE_BUG_VALIDATION_MODEL` | `LLM_MODEL` | 用于进行 Bug 分析和生成报告的模型 |
| `REASONER_POST_CONDITION_MODEL` | `LLM_MODEL` | 用于生成代码后置条件的模型 |
| `REASONER_SPEC_CHECK_MODEL` | `LLM_MODEL` | 用于检查代码后置条件是否违反规约的模型 |
| `OPENCODE_MODEL_PROVIDER` | `openrouter` | 调用 `opencode run --model <prefix>/<model>` 时使用的 OpenCode provider 前缀 |
| `LLM_API_KEY` | （环境变量） | FM-Agent 直接调用 LLM 使用的 API 密钥 |
| `LLM_API_BASE_URL` | `https://openrouter.ai/api/v1` | FM-Agent 直接调用 LLM 使用的 API 基础 URL |
| `FM_AGENT_DOMAIN_KNOWLEDGE` | unset | 可选；使用 `os.pathsep` 分隔的用户领域知识 Markdown 文件列表 |
| `GRANULARITY` | `40` | 将函数拆分为代码块逐块推理时，每个代码块的最小行数 |
| `MAX_WORKERS` | `10` | 推理与 Bug 验证的最大并发工作线程数 |
| `MAX_SPC_ITER` | `5` | FM-Agent 直接调用 LLM 进行验证（后置条件与规约检查）时的最大重试/迭代次数 |
| `OPENCODE_MAX_RETRIES` | `5` | OpenCode 流水线某一阶段失败时的最大重试次数 |
| `OPENCODE_TIMEOUT_SECONDS` | `1800` | 单个 agent 子进程（包括 DSH）的硬超时时间（秒）；失败时由调用阶段重试 |
| `CLANG_COMMAND` | `clang` / `clang++` | 用于 C/C++ 调用图分析的 Clang driver；默认值按语言自动选择 |
| `CLANG_COMPILE_COMMANDS` | unset | 可选的 `compile_commands.json` 文件或所在目录；未设置时检查项目根目录和 `build/` |
| `CLANG_TIMEOUT_SECONDS` | `120` | 每个 Clang 翻译单元导出 AST 的超时时间（秒）；未被成功导出覆盖的函数使用 codegraph |
| `ELP_COMMAND` | `elp` | 用于 Erlang 函数抽取与调用图分析的 ELP 可执行文件或命令 |
| `ELP_TIMEOUT_SECONDS` | `180` | ELP 初始化、索引及单次 LSP 请求的超时时间（秒） |

## DeepSeek Harness

运行 `./install.sh --with-dsh` 后，在 `fm-agent.toml` 中设置：

```toml
[llm]
backend = "dsh"
name = "deepseek-v4-pro"
effort = "high"
```

在 `.env` 中添加 `DEEPSEEK_API_KEY`。使用网关时，再设置 `DEEPSEEK_BASE_URL`
为兼容 DeepSeek Messages 的基础地址，DSH 会追加 `/v1/messages`，末尾已有
`/v1` 时会复用。DSH 使用这两个变量配置认证和地址。`effort` 可省略，支持
`off`、`low`、`high`、`max`。

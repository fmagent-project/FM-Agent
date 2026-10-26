# FM-Agent DeepSeek Harness 离线版安装手册

适用包名：`FM-Agent-release-deepseek-harness-offline-ubuntu22-x86_64-v0.3.0-dsh.1.tar.gz`

## 1. 部署边界

目标服务器必须是 Linux x86_64，推荐 Ubuntu 22.04，glibc 不低于 2.34。安装包
自带 Python、DeepSeek Harness、CodeGraph 和运行依赖，不调用 `apt`、`pip`、
`npm`、`curl` 或 GitHub。

“离线安装”和“模型推理联网”是两个边界：安装过程完全离线；如果配置
`https://dashscope.aliyuncs.com/...`，运行分析时仍需访问公网。完全气隙环境必须
把 `base_url` 指向内网可达的兼容模型服务。

建议预留至少 3 GiB 磁盘空间；大型项目还需为目标项目中的 `fm_agent/` 结果和
`--isolate` 快照预留空间。

## 2. 把两个文件传到目标机

```text
FM-Agent-release-deepseek-harness-offline-ubuntu22-x86_64-v0.3.0-dsh.1.tar.gz
FM-Agent-release-deepseek-harness-offline-ubuntu22-x86_64-v0.3.0-dsh.1.tar.gz.sha256
```

可以使用受控介质、内网文件服务或其他合规传输方式。进入文件所在目录后校验：

```bash
sha256sum -c FM-Agent-release-deepseek-harness-offline-ubuntu22-x86_64-v0.3.0-dsh.1.tar.gz.sha256
```

必须看到 `OK`。失败时不要继续安装，应重新传输并复核源文件。

## 3. 解压并做包内检查

```bash
tar -xzf FM-Agent-release-deepseek-harness-offline-ubuntu22-x86_64-v0.3.0-dsh.1.tar.gz
cd FM-Agent-release-deepseek-harness-offline-ubuntu22-x86_64-v0.3.0-dsh.1
./scripts/verify_offline.sh --quick
```

快速检查会验证平台、glibc、随包文件哈希、Python 模块、Parser、Harness、
CodeGraph 以及 FM-Agent 命令行导入，不访问公网。

如需验证 Harness 到 OpenAI-compatible API 的完整协议链路，但仍不访问公网：

```bash
./scripts/verify_offline.sh --full
```

该测试只启动并访问 `127.0.0.1` 的临时模拟模型服务。

## 4. 安装

### 当前用户安装（推荐）

```bash
./install.sh
export PATH="$HOME/.local/bin:$PATH"
fm-agent version
```

默认安装位置：

```text
~/.local/share/fm-agent-dsh/versions/0.3.0-dsh.1/
~/.local/share/fm-agent-dsh/current -> 上述版本
~/.local/bin/fm-agent -> current/bin/fm-agent
```

若希望每次登录自动加入 PATH：

```bash
printf '%s\n' 'export PATH="$HOME/.local/bin:$PATH"' >> "$HOME/.profile"
```

### 系统级安装（可选）

```bash
sudo ./install.sh --prefix /opt/fm-agent-dsh --bin-dir /usr/local/bin
fm-agent version
```

程序文件可以共享，但每个用户仍在自己的 `~/.config/fm-agent/` 保存模型配置和
密钥。安装器不会覆盖 `/usr/local/bin/fm-agent` 中已有的普通文件。

## 5. 配置模型

交互方式最安全，API key 输入不会回显，也不会出现在 shell 历史中：

```bash
fm-agent configure
```

以 `qwen3.6-35b-a3b` 和 OpenAI-compatible vLLM/DashScope 为例，依次输入：

```text
Model: qwen3.6-35b-a3b
Base URL: https://dashscope.aliyuncs.com/compatible-mode/v1
API style: openai
Tool compatibility: native
API key: <在隐藏输入处粘贴>
```

检查配置（key 只显示掩码）：

```bash
fm-agent configure show
```

配置文件和密钥文件分别是：

```text
~/.config/fm-agent/fm-agent.toml
~/.config/fm-agent/secrets.env    # 权限 0600
```

不要把密钥写入项目 `.env`、命令行参数、脚本或安装包。进程环境变量优先级高于
配置文件，适合由密钥管理系统临时注入：

```bash
export LLM_MODEL=qwen3.6-35b-a3b
export LLM_API_BASE_URL=http://model-gateway.internal/v1
export LLM_API_KEY='由密钥系统注入'
```

## 6. 测试真实模型连通性

```bash
fm-agent test-model
```

成功时标准输出为：

```text
FM_AGENT_MODEL_CONNECTIVITY_OK
FM_AGENT_MODEL_TOOL_OK
```

该命令先验证纯文本连通性，再要求 Harness 实际执行临时 Bash 和 `write` JSON 写入并核对证明
文件，验证 `FM-Agent -> DeepSeek Harness -> Qwen 文本工具代理 -> 模型端点 ->
Harness 工具` 完整往返。只做纯文本探测可执行 `fm-agent test-model --text-only`。
若配置 DashScope，这一步不是离线网络测试。

### 自建 vLLM 固定为 Mistral parser

若 Qwen 服务暂时无法移除 `--tool-call-parser mistral`，请显式改为兼容模式：

```toml
[llm]
api_style = "openai"
tool_compat_mode = "qwen-text"
```

该模式为每个 Harness 进程启动一个只监听随机 `127.0.0.1` 端口的临时代理。代理
从上游请求中删除 `tools`、`tool_choice` 和 `parallel_tool_calls`，将 schema 作为
普通文本协议提供给 Qwen，并把 Qwen XML/Hermes/JSON 文本调用还原成标准 OpenAI
`tool_calls`。代理随 Harness 退出，API key 不写入文件。

上游原生 Function Calling 配置正确时保持默认值：

```bash
fm-agent configure set --tool-compat-mode native
```

## 7. 分析 Git 或普通本地项目

建议先用小项目和单阶段模式验证：

```bash
fm-agent /absolute/path/to/project --one-phase
```

目标可以是 Git 仓库，也可以是没有 `.git` 的普通本地目录。普通目录完整分析和
隔离分析都受支持：

```bash
fm-agent /absolute/path/to/plain-project --one-phase
fm-agent /absolute/path/to/plain-project --isolate --one-phase
```

`--isolate` 对 Git 项目创建冻结 worktree，对普通目录创建文件系统副本；结果会
复制回原项目的 `fm_agent/`。快照路径会打印在终端，系统不会自动删除，便于审计。

中断后继续：

```bash
fm-agent /absolute/path/to/project --resume --one-phase
```

只生成规约，不执行静态推理：

```bash
fm-agent /absolute/path/to/project --only-spec --one-phase
```

收集全部静态不一致候选：

```bash
fm-agent /absolute/path/to/project --all-bugs --one-phase
```

完整流水线中的阶段边界如下：Stage 1、2、6 和增量选择会调用模型，统一经过同一
Qwen 文本工具解析器；Stage 3（函数提取）、Stage 4（文件枚举）和 Stage 5（调用
层次划分）完全在本地执行，不存在服务端 tool parser 兼容问题。Stage 6 会写入
`.spec.json` 和 `.info.json` 两类 sidecar，`0.3.0-dsh.1` 已同时覆盖正常 XML、
Hermes、严格 JSON、Qwen 畸形混合调用、未引用函数名、缺失闭合标签以及
`{"function=write", ...}` 畸形伪 JSON。发送给模型的首选格式已改为
`<tool_call>` 内的严格 JSON，避免继续诱导模型生成 `function=...` 伪语法。

`0.3.0-dsh.1` 会分别记录进程调用和阶段产物校验。`agent_call` 的成功只表示
Harness 进程退出码为 0；真正的阶段结果查看同一 `events.jsonl` 中的
`stage_validation`。Stage 1、2、6 的 `_harness.log` 使用 NDJSON 事件模式，即使模型
没有最终 `content` 也不再是空文件。每次代理请求还会生成同前缀的
`*_proxy.jsonl`，保存上游原始 `content`、`reasoning_content`、识别到的工具名和
解析判定；其中不保存 API key 或 Authorization 头。Stage 6 的结构化 verification
使用 text-only 模式，不再向模型展示工具；每个 `llm_call` 也会关联自己的
`*_proxy.jsonl`。

增量模式依赖提交差异，因此只支持存在至少一个提交的 Git 仓库：

```bash
fm-agent /path/to/git-project --incremental /path/to/intent.md
```

## 8. 结果与监控

所有产物默认位于 `<project>/fm_agent/`。可以像公共原项目一样让分析命令自动启动
仪表盘：

```bash
fm-agent /absolute/path/to/project --dashboard --one-phase
```

也可另开终端启动只读仪表盘：

```bash
fm-agent dashboard /absolute/path/to/project
```

主要目录：

```text
fm_agent/extracted_functions/           函数源码与规约 sidecar
fm_agent/logic_verification_results/    静态推理结果
fm_agent/spec_prompts/                  规约生成输入
fm_agent/trace/events.jsonl             调用事件
fm_agent/trace/payloads/                调用输入输出载荷
fm_agent/VERIFICATION-REPORT.md         人类可读的逐函数静态验证汇总
fm_agent/VERIFICATION-REPORT.json       机器可读的 COMPLETE/PARTIAL 汇总
fm_agent/report.html                    自包含、可检索筛选的交互式静态报告
```

静态分析结束后会立即生成上述三种报告。浏览器直接打开 `report.html` 即可，无需
HTTP 服务或网络；它支持搜索、verdict/源文件筛选、候选优先排序、全部展开/折叠、
完整详情弹窗、源码行号与函数范围高亮，以及规约/结果产物链接。
也可以从已有结果确定性地重新生成：

```bash
fm-agent report /absolute/path/to/project
```

`COMPLETE` 只表示所有目标函数都有可读取的终态静态结果，不表示程序已被动态证明
正确。历史重试产生的 `error`/`format_error` 仍保留在 trace 中；最终状态以报告及
各阶段最后一条 `stage_validation` 为准。

本版本不执行动态插装、编译/启动目标系统的探针、运行时 Oracle、自动修复或动态
Bug 确认。`MISMATCH` 和 `--all-bugs` 产物均是静态候选，需要人工复核。

公共原项目、`FM-Agent-release.zip` 与本版本的逐项符合性矩阵见
`docs/UPSTREAM-CONFORMANCE-ANALYSIS_zh.md`；本版本逐文件修改、问题根因和验证证据见
`docs/V0.3.0-MODIFICATION-REPORT_zh.md`。

## 9. 故障排查

自建 vLLM 可以修改启动参数时，请按
[Qwen3.6 自建 vLLM 工具解析器变更手册](docs/VLLM_QWEN36_TOOL_PARSER_zh.md)
把 Mistral parser 更换为 Qwen3.6 原生 parser，并完成 Function Calling 验收。

- `glibc ... too old`：目标机不满足二进制下限，应改用 Ubuntu 22.04 x86_64 或更
  新的兼容系统，不能通过在线下载临时修补。
- `LLM_API_KEY is not set`：重新执行 `fm-agent configure`，确认
  `~/.config/fm-agent/secrets.env` 属于当前用户且权限为 0600。
- `DeepSeek Harness runtime is unavailable`：执行 `fm-agent verify-install --quick`；
  如 MANIFEST 失败，重新传输并安装完整包。
- 模型返回 401/403：检查 key、模型权限和账户状态；不要在工单中粘贴完整 key。
- 连接超时：检查服务器到 `base_url` 的 DNS、防火墙和代理；气隙环境应切换内网
  端点。
- `Mistral ... could not locate the tool call token in the tokenizer`：确认
  `tool_compat_mode = "qwen-text"` 并重新执行 `fm-agent test-model`。若服务进程本身
  无法启动，客户端代理不能修复服务不可用。
- `Connectivity test returned unexpected text: ''`：这是 `0.2.0-dsh.1` 对 Qwen
  仅返回 `reasoning_content`、最终 `content` 为空时的已知问题。安装
  `0.2.0-dsh.2` 后，代理会自动以 `enable_thinking=false` 重试一次，并继续用真实
  Bash 证明文件验证工具链。
- `Stage 1 failed ... phases.json is missing`：`0.2.0-dsh.2` 及更早版本可能把
  Qwen 写文件调用中看起来像 JSON 的 `content` 错当成对象，导致 Harness 拒绝
  `write` 参数。升级到 `0.3.0-dsh.1`；新版按工具 schema 保持其字符串类型，并在
  所有模型重试均失败时生成覆盖全部非测试源文件的确定性单阶段计划继续运行。
- Stage 2 或 Stage 6 提示输出文件缺失：升级到 `0.3.0-dsh.1`。该版本可恢复 Qwen
  输出的畸形 `<function=write", "arguments": {...}>` 混合调用及
  `{"function=write", "arguments": {...}}` 伪 JSON，并已用真实
  `qwen3.6-35b-a3b` 跑通普通非 Git 项目的 Stage 1～6。升级后优先使用 `--resume`
  继续；如需清空旧结果，请先备份项目中的 `fm_agent/`。
- `PI_AI_ERROR:422` 且类型为 `fm_agent_unparsed_tool_call`：说明模型返回了工具调用
  意图，但旧解析器无法安全转换。升级到 `0.3.0-dsh.1` 后重新运行；该版优先要求
  模型输出严格 JSON，并兼容更多 Qwen 畸形格式。若仍失败，查找报错 `_harness.log`
  的同前缀 `*_proxy.jsonl`，查看其中的 `content`、`reasoning_content` 和
  `unparsed_tool_syntax`，该文件就是代理收到的原始上游响应，可用于补充解析规则。
  日志可能包含模型看到的项目内容，提交工单前请脱敏。
- `_harness.log` 是空文件：这是旧版只捕获最终文本造成的可观测性问题。升级到
  `0.3.0-dsh.1` 后重新运行；日志应包含逐行 JSON 事件。若模型在关闭 thinking 后
  仍只有 reasoning，新版会返回非零错误，不再把它记录成成功调用。
- `llm_call/verification` 出现 `format_error`：模型请求已成功，但最终文本不是所需
  JSON schema；系统会带格式纠正提示重试。`error` 表示 Harness/HTTP 调用失败，二者
  不能仅凭一条历史事件判断最终结果；查看 `VERIFICATION-REPORT.md` 的终态。
- 模型返回 `verdict=MATCH`，但 `reason` 中明确给出反例、违反条件或结论
  `MISMATCH`：`0.3.0-dsh.1` 会把它记为 `format_error` 并要求模型重写一致的 JSON，
  不再将自相矛盾的回答误记为通过。
- `verification` 报 `fm_agent_unparsed_tool_call`：这是 `.6` 及更早版本把纯 JSON
  验证请求也作为可调用工具的 Agent 运行造成的。升级到 `.7`；verification 仍经过
  Harness，但本地代理会移除工具并要求 text-only JSON，Stage 1、2、6 的文件写入
  Agent 不受影响。
- `*_message_*_assistant.txt` 是下一次格式重试携带的“上一次模型回答”，不是单独的
  Stage 6 产物；`*_response.txt` 是本次 verification 的最终 stdout。旧版在 422 或
  空响应时可能为空。`.7` 会把原始上游响应保存在同一 `llm_call` 关联的
  `*_proxy.jsonl`，并用 `parser_decision` 说明解析结果。
- `VERIFICATION-REPORT.md` 显示 `PARTIAL`：至少一个函数为 `ERROR` 或缺少结果；修复
  模型连通性后执行 `fm-agent /absolute/path/to/project --resume`。`.7` 不会再把
  `ERROR` JSON 当成完成结果。
- 普通目录使用 `--incremental` 报错：这是预期限制，改用完整分析；普通目录无需
  初始化 Git。
- 中断后重跑：优先加 `--resume`；需要全新分析时，先自行备份再移走项目中的
  `fm_agent/`。

## 10. 升级与卸载

安装新版本时从新包重新运行 `install.sh`；版本目录并存，`current` 原子切换到新
版本。安装器若发现同版本目录，会先保留带时间戳的备份。

用户级卸载前先确认路径：

```bash
readlink -f "$HOME/.local/bin/fm-agent"
```

然后删除明确的 launcher 和安装目录；模型配置与密钥位于
`~/.config/fm-agent/`，是否删除应由密钥管理策略决定。不要删除项目内的
`fm_agent/`，除非已经确认不再需要分析结果。

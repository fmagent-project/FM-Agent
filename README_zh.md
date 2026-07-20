# FM-Agent：通过基于大模型的霍尔逻辑推理将形式化方法扩展至大规模系统软件

<div align="center">

[English](README.md) | 中文

[官网](http://fm-agent.ai/) · [论文](https://arxiv.org/abs/2604.11556)

</div>

FM-Agent 是首个实现大规模系统正确性全自动推理的框架，支持的软件包括14万行代码的 [Claude C Compiler](https://github.com/anthropics/claudes-c-compiler)。

它包含三个步骤：
- 规约生成：自主理解开发者的系统设计意图，为每个函数生成正确性规约。
- 代码推理：无需任何人工干预，自动推理出代码实现是否符合正确性规约的要求。
- 缺陷诊断：对于有 bug 的函数，基于推理过程分析bug的根因与位置。

FM-Agent 的[官方网站](http://fm-agent.ai/)提供了在线代码库推理服务，欢迎体验！

> **⚠️ 注意**：本框架的推理效果受所使用模型的能力影响较大。使用能力较弱的模型时，可能出现幻觉（hallucination），导致错误的推理结论。建议使用推理能力较强的模型(例如Claude Sonnet 4.6)以获得更可靠的结果。

## 目录

- [文件结构](#文件结构)
- [环境配置](#环境配置)
  - [依赖要求](#依赖要求)
    - [已测试macOS环境](#已测试macOS环境)
  - [安装依赖](#安装依赖)
- [参数配置](#参数配置)
- [快速开始](#快速开始)
- [注意事项](#注意事项)
- [论文引用](#论文引用)
- [联系方式](#联系方式)


## 文件结构

```
|-- main.py                       # 程序入口 —— 编排整个流水线
|-- dashboard.py                  # 独立的实时 TUI 监控面板
|-- config.py                     # 配置（模型、粒度、并发、超时等）
|-- install.sh                    # 依赖安装脚本
|-- pyproject.toml / uv.lock      # Python 项目元数据与锁定的依赖（uv）
|-- .env.example                  # .env 运行时配置模板
|-- src/                          # 核心源码模块（提取、推理、LLM 交互等）
|-- md/                           # 引导 Agent 推理的工作流说明文档
|-- docs/                         # 补充文档（如 OpenCode/LLM provider 配置）
```

## 环境配置

### 依赖要求

- Ubuntu（已在 22.04 LTS, 24.04 LTS 上测试）
- Python 3.12
- pip >= 23
- [openai](https://pypi.org/project/openai/) 2.15.0
- [OpenCode](https://github.com/opencode-ai/opencode) 1.4.6
- [Bun](https://bun.sh/)
- [oh-my-openagent](https://www.npmjs.com/package/oh-my-openagent) 插件（通过 `bunx` 安装）
- [@lucentia/opencode-trace](https://www.npmjs.com/package/@lucentia/opencode-trace) 插件 —— 采集 OpenCode 原始 LLM 请求/响应 trace
- 你所用 provider 的 LLM API 密钥（示例使用 [OpenRouter](https://openrouter.ai/)）
- [Erlang Language Platform（ELP）](https://whatsapp.github.io/erlang-language-platform/docs/get-started/)——可选，仅分析 Erlang 项目时需要
  - 本 Erlang 集成已在 Ubuntu 的 Erlang/OTP 26 或更高版本上验证；请选择基于兼容 OTP 版本构建的 ELP 发布包。
  - ELP 自动识别包含 `rebar.config` 的项目时，要求 rebar3 3.24.0 或更高版本。
  - 本集成尚未测试 macOS Erlang 工具链；`./install.sh --with-erlang` 会安装 Homebrew 当前提供的公式版本。

#### 已测试macOS环境

以下 macOS 环境已使用安装脚本测试：

- macOS 14.5（Build 23F79），arm64
- Darwin 23.5.0
- Python 3.11.7
- pip 23.3.1
- uv 0.7.9
- OpenCode 1.17.9
- Bun/bunx 1.3.14
- Homebrew 6.0.3
- UnZip 6.00

### 安装依赖

设置 FM-Agent 和 OpenCode 共用的 LLM API 密钥。推荐使用 [OpenRouter](https://openrouter.ai/)：FM-Agent 会并发调用 LLM，而 OpenRouter 的 RPM（每分钟请求数）和 TPM（每分钟 Token 数）限制更宽松——不过任何兼容的 provider 都可以。

把 API 密钥放进 `.env`（已 gitignore，FM-Agent 通过 python-dotenv 自动加载）；其余所有配置在 `fm-agent.toml` 里都有 committed 的默认值。复制模板：

```bash
cp .env.example .env
# 然后编辑 .env，填入 LLM_API_KEY
```

```bash
# .env（只放密钥）
LLM_API_KEY=your-api-key-here
```

非密钥配置——模型、endpoint、backend、provider 等——在 `fm-agent.toml` 的 `[llm]` 段,直接改它是永久生效的做法。若不想动这个被 git 跟踪的文件（比如你是 git clone、之后会 `git pull` 更新），可以用对应的环境变量覆盖,写在 `.env` 或 shell 里即可。优先级为 `env > .env > fm-agent.toml`；由于 `.env` 会盖过 toml,残留的旧值会覆盖你后来对 toml 的修改——所以改了 toml 不生效时,先检查 `.env`。详情及 OpenCode provider 配置见 [docs/config_llm.md](docs/config_llm.md)。

上述所有依赖（Ubuntu 和 Python 除外）均可通过以下脚本一键安装：

```bash
./install.sh
```

Erlang 工具链不影响其他语言，因此默认不安装。如需自动安装或检查 Erlang/OTP 26+、rebar3 3.24.0+ 和兼容的 ELP 发布包，请运行：

```bash
./install.sh --with-erlang
```

该选项在 macOS 上使用 Homebrew；在 Ubuntu 上，当系统 OTP 缺失或版本过低时使用 RabbitMQ Team Erlang PPA。Ubuntu 配置已使用 Erlang/OTP 26+ 验证；macOS Erlang 配置尚未测试，将使用 Homebrew 选择的当前公式版本。Linux 下的 rebar3 和 ELP 会安装到 `~/.local/bin`，请确保新终端的 `PATH` 包含该目录。你也可以手动安装这些工具，确认 `rebar3 version` 和 `elp version` 可执行，并在需要时将 `ELP_COMMAND` 设置为 ELP 的绝对路径。

FM-Agent 会从 `fm-agent.toml` 自动配置 OpenCode 的 provider，因此无需手动编辑 `~/.config/opencode/opencode.json` 来设置模型或密钥（见 [docs/config_llm.md](docs/config_llm.md)）。

**重要提示：** FM-Agent 会根据推理过程自动生成测试用例，以触发潜在 Bug，帮助开发者定位和修复问题。运行 FM-Agent 前，请确保目标代码库的测试环境已就绪，并在必要时在 `md/bug_validator.md` 中指定测试用例的运行方式。若未指定，Agent 将自主决定执行方式。

## 参数配置

配置项都在 [`fm-agent.toml`](fm-agent.toml) 里（每一项都有就近注释），也可用对应的环境变量覆盖。完整参数、默认值与描述的参考表见 [docs/configuration_zh.md](docs/configuration_zh.md)。

**重要说明：** 强烈建议使用 Claude Sonnet 4.6 等能力较强的模型，其他模型可能推理能力，无法有效发现 Bug。此外，请使用有权限访问 Claude 模型的 API 密钥，因为 FM-Agent 调用的 OpenCode 可能会使用 Claude 模型。

（可选）FM-Agent 使用 oh-my-openagent 插件增强 OpenCode。该插件内置的 comment-checker 钩子应当禁用，否则它会拦截 FM-Agent 写入的每一个注释块（这些注释是函数的正确性规约），并迫使 Agent 消耗大量 Token 去论证注释的必要性或将其删除。
请打开 oh-my-openagent 配置文件（通常位于 `~/.config/opencode/oh-my-openagent.json`），添加 `disabled_hooks`：

```json
{
  "disabled_hooks": ["comment-checker"],
}
```


## 快速开始

```bash
uv run python main.py <proj_dir> [--resume] [--domain-knowledge FILE ...] [--submodule PATH [PATH ...]]
```

| 参数 | 描述 |
|---|---|
| `proj_dir` | 待检测代码库的目录路径 |
| `--resume` | 续跑上一次中断的运行，而非从头开始 |
| `--incremental INTENT_FILE` | 以增量模式运行，参数值为描述本次修改目标的意图文件路径。 |
| `--domain-knowledge FILE [FILE ...]` | 将额外的 Markdown 领域知识文件复制到本次运行中，并提供给 setup、规约生成和 Bug 验证 Agent。别名：`--knowledge`；可重复传入。 |
| `--isolate` | 针对项目的隔离 git worktree 快照运行，而非直接在项目目录上运行。 |
| `--submodule PATH [PATH ...]` | 只处理 `proj_dir` 中一个或多个子目录下的源代码。 |
| `--extra-edge FILE` | 从 JSON 文件或目录向静态调用图补充 caller 到 callee 的边。 |
| `--only-spec` | 只生成行为规约，跳过推理与 Bug 验证阶段。不能与 `--incremental` 一起使用。 |

`proj_dir` 必须是一个 git 仓库。

如需在不修改 FM-Agent 内置提示词的情况下提供项目特定领域知识，可传入一个或多个 Markdown 文件：

```bash
uv run python main.py <proj_dir> --domain-knowledge docs/invariants.md docs/protocol.md
```

FM-Agent 会将这些文件暂存到 `fm_agent/spec_prompts/domain_context/user_knowledge/`，并在本次运行中让相关 Agent 读取。也可以通过 `FM_AGENT_DOMAIN_KNOWLEDGE` 提供使用 `os.pathsep` 分隔的 Markdown 文件列表。

使用 `--submodule` 可以把完整运行或增量运行限制到指定项目子目录：

```bash
uv run python main.py <proj_dir> --submodule src/core src/runtime
uv run python main.py <proj_dir> --incremental intent.md --submodule src/core src/runtime
```

`--submodule` 路径必须是 `proj_dir` 内部目录。该参数可与 `--resume`、`--isolate` 和 `--incremental` 一起使用，但不能与 `--entry-func` 一起使用。

默认情况下，每次运行都会清空已有的 `fm_agent/` 目录并从头开始，因此一旦运行中断，之前的所有进度都会丢失。可通过 `--resume` 参数（或设置环境变量 `FM_AGENT_RESUME=1`）从上一次中断处继续。在续跑模式下，FM-Agent 会保留已有的 `fm_agent/` 目录，只执行剩余的工作。

使用 `--only-spec` 可以在生成行为规约后即停止，跳过推理与 Bug 验证阶段。它会为每个函数生成 `[SPEC]` 块，而不在验证上花费时间，适用于只需要规约、或希望先审阅规约再运行完整分析的场景。该参数不能与 `--incremental` 一起使用，因为增量模式本质上是一个推理/Bug 验证流程。

```bash
uv run python main.py <proj_dir> --only-spec
```

当静态解析无法看到关键调用关系时（例如间接 syscall 分发），可使用 `--extra-edge FILE`。补充边会同时作用于完整运行、入口函数范围运行和增量运行。JSON 格式如下：

```json
{
  "edges": [
    {
      "caller": {
        "fqn": "third_party::musl::src::time::nanosleep-c::nanosleep",
        "callsite_names": ["nanosleep"]
      },
      "callee": {
        "fqn": "kernel::liteos_a::syscall::time_syscall-c::SysNanoSleep",
        "info_names": ["__NR_nanosleep", "SYS_nanosleep", "nanosleep"]
      }
    }
  ]
}
```

Extra-edge 字段规则：

- `caller.fqn`：单个 caller 的精确 caller FQN，补一条到 `callee.fqn` 的边。可以为空。
- `caller.callsite_names`：源码 callsite 函数名。源码中包含这些 callsite 的函数都会作为 caller，补一条到 `callee.fqn` 的边。可以为空。
  - `caller.fqn` 和 `caller.callsite_names` 至少有一个非空。
- `callee.fqn`：单个 callee 的精确 FQN。
- `callee.info_names`：可选，用于匹配生成的 `[INFO]` 块里指代该 callee 的名字。它只用于 `[INFO]` 匹配和传递调用者期望。


### 增量模式

增量模式会复用上一次运行的结果，仅重新检测发生变化的部分。它将当前代码与上一次运行记录在 `fm_agent/version.log` 中的提交进行 diff。每次运行都会把所处理的提交 id 写入该文件，因此后续的 `--incremental` 运行会自动读取它：

```bash
python3 main.py <proj_dir> --incremental <intent_file>
```

如果 `fm_agent/version.log` 不存在（没有可供比较的历史运行），FM-Agent 会回退为完整运行。

### 实时监控面板

FM-Agent 自带一个独立的实时 TUI 监控面板（[dashboard.py](dashboard.py)），用于在运行过程中可视化展示：各阶段进度、Token 用量与花费、prompt 缓存命中率，以及 Bug 验证结果。它读取 FM-Agent 写入 `fm_agent/` 目录下的 trace 文件，因此可在 `main.py` 运行期间于另一个终端中启动：

```bash
uv run python dashboard.py <proj_dir>
```

| 参数 | 描述 |
|---|---|
| `proj_dir` | 与 `main.py` 相同的代码库目录（监控 `<proj_dir>/fm_agent/`）。也可直接指向任意包含 `trace/` 子目录的工作区目录，例如已归档的运行 |

按 `Ctrl-C` 退出监控面板，不会影响正在运行的流水线。

### 输出说明

FM-Agent 会在代码库目录下创建 `fm_agent/` 目录，主要输出内容如下：

#### Bug 报告（`fm_agent/bug_validation/<bug_id>.md`）

每个已确认或经过排查的 Bug 都会生成一份 Markdown 报告，包含以下内容：

| 条目 | 含义 |
|---|---|
| Specification Claim | 函数正确性规约要求满足的后置条件 |
| Actual Behavior | 代码实际上满足的后置条件 |
| Code Evidence | 导致 Bug 的具体代码语句 |
| Trigger Condition | 触发 Bug 的条件 |
| How to Trigger | 触发 Bug 的具体步骤 |
| Probe Script | 用于触发 Bug 的完整测试脚本 |
| Probe Output | 执行测试脚本的输出 |

`fm_agent/bug_validation/` 目录下的 `summary.json` 文件汇总了所有 Bug 结果，包括报告的Bug总数、已确认Bug数、未确认Bug数。

#### 日志文件（`fm_agent/fm_agent.log`）

单一日志文件记录完整的流水线执行过程，包括文件提取进度、推理任务的提交与完成情况、网络错误与重试，以及最终的推理统计摘要。日志级别为 `INFO`，格式为 `%(asctime)s [%(levelname)s] %(message)s`。

## 注意事项

1. FM-Agent 会在代码库目录下创建 `fm_agent/` 目录，请确保不存在命名冲突。
2. `md/` 目录下的 Markdown 文件提供了引导 Agent 推理过程的通用说明。针对项目特定的上下文（如不变量、协议、编码规则、领域术语），优先使用 `--domain-knowledge`。对于可复用的框架行为，可定制内置提示词；例如，若正在推理编译器的正确性，可修改 `md/bug_validator.md`，指示 Agent 将输出与参考实现（如 GCC）进行对比。
3. **支持的编程语言**：Rust、C、C++、Python、Java、Go、CUDA、JavaScript、TypeScript、ArkTS、Erlang。Erlang 的函数抽取与调用图需要 ELP；ELP 不可用时会给出警告并跳过 Erlang 文件。

## 论文引用

如果您使用了 FM-Agent，请引用我们的[论文](https://arxiv.org/abs/2604.11556)：

```bibtex
@misc{ding2026fmagent,
Author = {Haoran Ding and Zhaoguo Wang and Haibo Chen},
Title = {FM-Agent: Scaling Formal Methods to Large Systems via LLM-Based Hoare-Style Reasoning},
Year = {2026},
Eprint = {arXiv:2604.11556},
}
```

## 联系方式

如有任何问题，欢迎提交 Issue 或发送[邮件](mailto:nhaorand@gmail.com)联系。

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
  - [安装依赖](#安装依赖)
- [参数配置](#参数配置)
- [快速开始](#快速开始)
- [注意事项](#注意事项)
- [论文引用](#论文引用)
- [联系方式](#联系方式)


## 文件结构

```
|-- main.py                # 程序入口
|-- config.py              # 配置
|-- install.sh             # 依赖安装脚本
|-- src/                   # 核心源码模块（提取、推理、LLM 交互等）
|-- md/                    # 引导 LLM 推理的工作流说明文档
```

## 环境配置

### 依赖要求

- Ubuntu（已在 22.04 LTS, 24.04 LTS 上测试）
- Python 3.10
- pip >= 23
- [openai](https://pypi.org/project/openai/) 2.15.0
- [OpenCode](https://github.com/opencode-ai/opencode) 1.4.6
- [Bun](https://bun.sh/)
- [oh-my-openagent](https://www.npmjs.com/package/oh-my-openagent) 插件（通过 `bunx` 安装）
- [@lucentia/opencode-trace](https://www.npmjs.com/package/@lucentia/opencode-trace) 插件 —— 采集 OpenCode 原始 LLM 请求/响应 trace
- 你所用 provider 的 LLM API 密钥（示例使用 [OpenRouter](https://openrouter.ai/)）

### 安装依赖

设置 FM-Agent 和 OpenCode 共用的 LLM API 密钥。推荐使用 [OpenRouter](https://openrouter.ai/)：FM-Agent 会并发调用 LLM，而 OpenRouter 的 RPM（每分钟请求数）和 TPM（每分钟 Token 数）限制更宽松——不过任何兼容的 provider 都可以。

```bash
export LLM_API_KEY="your-api-key-here"
```

OpenCode provider 的配置以及可选的 prompt 缓存设置见 [docs/config_llm.md](docs/config_llm.md)。

上述所有依赖（Ubuntu 和 Python 除外）均可通过以下脚本一键安装：

```bash
./install.sh
```

（可选）如有需要，可在 OpenCode 的配置文件中手动设置默认 LLM 模型和 API 密钥。

**重要提示：** FM-Agent 会根据推理过程自动生成测试用例，以触发潜在 Bug，帮助开发者定位和修复问题。运行 FM-Agent 前，请确保目标代码库的测试环境已就绪，并在必要时在 `md/bug_validator.md` 中指定测试用例的运行方式。若未指定，Agent 将自主决定执行方式。

## 参数配置

关键参数可在 [config.py](config.py) 中调整。

| 参数 | 默认值 | 描述 |
|---|---|---|
| `LLM_MODEL` | `anthropic/claude-sonnet-4.6` | 所有任务的默认模型 |
| `OPENCODE_SETUP_MODEL` | `LLM_MODEL` | 用于理解代码库、划分代码模块和生成领域知识的模型 |
| `OPENCODE_SPEC_MODEL` | `LLM_MODEL` | 用于规约生成的模型 |
| `OPENCODE_BUG_VALIDATION_MODEL` | `LLM_MODEL` | 用于进行 Bug 分析和生成报告的模型 |
| `REASONER_POST_CONDITION_MODEL` | `LLM_MODEL` | 用于生成代码后置条件的模型 |
| `REASONER_SPEC_CHECK_MODEL` | `LLM_MODEL` | 用于检查代码后置条件是否违反规约的模型 |
| `LLM_API_KEY` | （环境变量） | FM-Agent 直接调用 LLM 使用的 API 密钥 |
| `LLM_API_BASE_URL` | `https://openrouter.ai/api/v1` | FM-Agent 直接调用 LLM 使用的 API 基础 URL |

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
uv run python main.py <proj_dir>
```

| 参数 | 描述 |
|---|---|
| `proj_dir` | 待检测代码库的目录路径 |
| `--hardware` | 将 `proj_dir` 视为硬件设计，仅生成模块规约（详见下文）。HDL 默认为 Chisel |
| `--chisel` | 搭配 `--hardware`：将设计视为 Chisel（Scala）。这是默认 HDL，`--hardware` 单独使用等价于 `--hardware --chisel` |
| `--verilog` | 搭配 `--hardware`：将设计视为 Verilog/SystemVerilog（`.v`/`.sv`/`.svh`） |
| `--resume` | 恢复中断的 `--hardware` 运行：复用 `groups.json`，仅重新生成缺失的模块规约 |
| `--chisel-modules-only` | 搭配 `--hardware --chisel`：对可明确判定为非硬件的 Chisel 类（IO Bundle、常量 object 等）跳过规约生成，保留传递继承 `Module`/`RawModule`/`ExtModule`/`BlackBox`/`MultiIOModule` 的单元。模块归属无法通过启发式规则确定的类（父类无法解析、存在歧义或循环继承）一律保守判定为需保留，不予排除。该判定基于纯文本启发式规则，不执行 Scala import/package 解析，故项目中若存在与某父类同名的无关类，仍存在低概率误判风险。若 import 别名将某个基类重命名为 `Module`/`RawModule`/`ExtModule`/`BlackBox`/`MultiIOModule`/`Bundle`/`Record`/`Data`（例如 `import chisel3.{Module => Bundle}`），该判定会将其等同于直接使用该名称，可能导致对真实模块的确定性误判。此选项不影响提取（extraction）阶段，仅作用于规约生成阶段。 |

### 为硬件设计生成规约（`--hardware`）

对于 Chisel（Scala）硬件设计：

```bash
uv run python main.py <proj_dir> --hardware
```

跳过非硬件 Chisel 单元（IO Bundle、常量 object、`Main` 入口）的规约生成：

```bash
uv run python main.py <proj_dir> --hardware --chisel-modules-only
```

对于 Verilog/SystemVerilog 硬件设计：

```bash
uv run python main.py <proj_dir> --hardware --verilog
```

在该模式下，FM-Agent 会运行一条专为硬件spec自动生成定制的流程：理解整体设计、将其划分为多个子系统，并为各模块生成面向验证的规约。该模式不会运行代码推理器或 Bug 验证，仅进行规约生成。

Chisel 设计的 `proj_dir` 中必须包含 Scala（`.scala`）源文件，Verilog 设计则必须包含 Verilog（`.v`/`.sv`/`.svh`）源文件。对于每个提取出的模块，FM-Agent 会在 `fm_agent/` 下、提取出的模块文件旁写入独立的 Markdown 文件描述硬件规约：

Chisel 支持范围限定为官方 Chisel 语法，对应 Scala 2（2.12/2.13）版本，与当前 Chisel 发行版所使用的 Scala 版本一致。Scala 2 已废弃的 early-initializer 语法，Scala 3 不属于支持范围。

| 输出 | 内容 |
|---|---|
| `<ModuleName>_spec.md` | 模块行为的面向验证的规约 |
| `<ModuleName>_info.md` | 该模块所实例化的各子模块的期望规约 |

生成的规约会在运行过程中按质量检查清单进行校验；未通过校验的规约会被自动删除并重新生成。若运行中断，可加 `--resume` 重新运行：已完成的规约会保留，仅重新生成缺失部分。

**Verilog 流程要求安装 [Verible](https://github.com/chipsalliance/verible)**：`verible-verilog-syntax` 必须在 `PATH` 上，以保证模块提取和实例化依赖分析的准确性。未安装时 Verilog 流程会拒绝启动（可设置 `FM_AGENT_NO_VERIBLE=1` 强制使用精度较低的纯 Python 备用解析器）。

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
2. `md/` 目录下的 Markdown 文件提供了引导 Agent 推理过程的通用说明。针对特定项目进行定制可以提高准确性并发现更多 Bug。例如，可以加入项目文档以加深 Agent 对代码库的理解；若正在推理编译器的正确性，可修改 `md/bug_validator.md`，指示 Agent 将输出与参考实现（如 GCC）进行对比。
3. **支持的编程语言**：Rust、C、C++、Python、Java、Go、CUDA、JavaScript、TypeScript、ArkTS。硬件设计（Chisel、Verilog/SystemVerilog）通过 `--hardware` 以仅生成规约的模式支持。

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

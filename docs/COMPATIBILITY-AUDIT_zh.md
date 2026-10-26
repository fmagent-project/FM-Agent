# FM-Agent v0.3.0 DeepSeek Harness 兼容性审计

本文件是兼容性摘要。完整逐项矩阵见
`UPSTREAM-CONFORMANCE-ANALYSIS_zh.md`，具体代码和问题修复清单见
`V0.3.0-MODIFICATION-REPORT_zh.md`。

## 审计基线

- 公共原项目：`fmagent-project/FM-Agent`，审计时 GitHub `main`/`HEAD` 均为
  `971618d0531af411b6ffdb9854fddd301098ef3d`。
- 用户更新资料：`FM-Agent-release.zip`，SHA-256
  `0017b364772d889aae1a607706d234ba72023b7e5bc2d95811b79e3991a29d71`，
  导入快照 `3321f0ba7007a475b5e9be40e7b15f0138bd7871`。
- 交付实现：`0.3.0-dsh.1`。

更新资料相对于公共原项目包含新的并发 batch 调度、入口函数主流程、增量分析
改进和大型 Pi Agent Validator；同时删除公共原项目的独立 `report.py`、旧插件及
若干语言/估算组件。本交付以更新资料的静态分析主线为代码基线，再按需求移除
OpenCode 和所有动态测试、插装、探针、修复与动态确认模块。

## 效果对齐结论

| 用户可见能力 | 公共原项目 | 更新资料 | v0.3.0-dsh.1 |
|---|---|---|---|
| Stage 1 阶段计划 | OpenCode Agent | OpenCode Agent | 相同工作流与 schema；DeepSeek Harness Agent |
| Stage 2 领域上下文 | OpenCode Agent | OpenCode Agent | 相同工作流与产物；DeepSeek Harness Agent |
| Stage 3 函数抽取 | 本地 | 本地新版 | 保留更新资料实现 |
| Stage 4 文件列表 | 本地 | 本地新版 | 保留更新资料实现并校验终态产物 |
| Stage 5 调用层次 | 本地 | 本地新版 | 保留更新资料实现并校验终态产物 |
| Stage 6 规约生成 | OpenCode | 更新后的 batch/并发调度 | 保留 batch/并发/重试逻辑；只替换 Agent 后端 |
| Hoare 风格静态推理 | LLM | 相同核心 `reasoner.py` | 保留更新资料 `reasoner.py`；结构化调用经 Harness text-only 路径 |
| `--resume/--one-phase/--submodule` | 支持 | 支持 | 支持 |
| `--entry-func/--end-func` | 插件形态 | 正式主流程 | 保留更新资料正式主流程 |
| `--incremental` | 支持 | 支持 | Git 项目保留；静态结束立即生成报告 |
| 普通非 Git 项目 | 完整流程可用，隔离有限制 | Git 检查较严格 | 完整和 `--isolate` 均可用；只有增量需要 Git |
| 动态 Bug Validation | OpenCode | OpenCode 或 Pi Validator | 按需求完全移除 |
| 动态插装/探针/修复 | 部分 | 大型 Agent Validator | 按需求完全移除 |
| 实时展示 | 动态 Bug/Tokens TUI | 扩展动态状态 TUI | 阶段终态、历史重试、Tokens、静态 verdict TUI |
| 最终 HTML 报告 | 动态确认后 `report.html` | 已删除独立 HTML 报告 | 静态推理结束立即生成自包含 `report.html` |

核心静态语义文件 `src/reasoner.py`、`src/extract.py`、
`src/generate_topdown_layers.py`、`src/parser.py`、`src/scope.py` 和调用图逻辑均沿用
更新资料版本。后端改造集中在模型调用、trace、产物终态校验、错误恢复和报告层，
没有把动态验证结论伪装成静态结论。

## 本次发现并修复的不一致

1. 旧 DSH 包只有简要 Markdown/JSON 汇总，缺少公共原项目的可搜索 HTML 体验。
   v0.3.0 在静态分析结束立即生成 `VERIFICATION-REPORT.md`、
   `VERIFICATION-REPORT.json` 和 `report.html`。HTML 支持搜索、verdict/源文件筛选、
   候选优先排序、全部展开/折叠、完整详情、源码范围高亮及产物链接；无需网络。
2. 增量流程此前只在日志列出候选，不生成统一终态报告。现按本次 changed/affected
   范围生成相同三种报告。
3. 仪表盘以前只累计事件，trace 文件被新运行截断后会重复累计旧计数。现截断时
   重置状态，并把“历史错误/重试次数”和“各阶段最后产物状态”分开显示。
4. 模型可能返回 `verdict=MATCH`，但 `reason` 明确给出反例、违反条件并写出
   `MISMATCH`。旧逻辑只信 JSON 字段，会产生假通过。现将这种语义矛盾记为
   `format_error`，进入原有纠错重试；并未改变正常 MATCH/MISMATCH 判定逻辑。
5. `agent_call: success` 只代表 Harness 退出码为 0，不能代表文件已生成。现保留
   独立 `stage_validation`，最终报告依据终态 sidecar/结果，不依据进程退出码。
6. `ERROR` 结果以前容易被视为已完成。现报告标为 `PARTIAL`，`--resume` 会重试，
   不会将调用错误计为形式验证通过。
7. 真实模型曾把 user domain knowledge 中的“应当返回首个索引”误写成代码的实际
   后置条件，导致第二步在错误的 Condition A 上判 MATCH。现明确区分规范性上下文
   与实际代码语义：实际后置条件必须由代码建立，implication 阶段还必须用代码反查
   Condition A，不能盲信上一步模型描述。
8. 仅要求 Agent 另行读取知识文件时，真实模型可能生成一个更接近现有实现、却遗漏
   明确业务边界的规约。现把用户知识全文嵌入每个相关 batch prompt，同时仍保留原始
   文件作为可审计输入；显式用户需求也作为 implication 的规范性补充，不能被弱化。
9. 即时报告原先在最终 Stage 6 校验事件之前写入，导致报告中的 trace 诊断少一条终态
   记录。现先写终态校验，再统一生成 Markdown、JSON 和 HTML；失败终态同样生成
   `PARTIAL` 报告后才以非零码退出。
10. 当前适配曾只提供独立 `fm-agent dashboard`，没有公共原项目的 `--dashboard`
    自动启动入口。现已恢复该选项；仪表盘分开展示 LLM/Harness 调用、最新产物终态、
    历史错误/重试和静态 verdict。

以上修复经过不含 `Contract:` 注释的真实模型用例复核：复杂普通目录检出首索引、
折扣顺序和整数平均值溢出候选，独立全新目录检出 clamp inclusive 上界错误；正确的
饱和求和函数保持 `MATCH`。

## 关于源码 `Contract:` 注释

公共原项目和更新资料都没有专门识别 `Contract:`、`Requires:` 或 `Ensures:` 的
解析器，也没有规定这类注释高于调用方需求。规约 Agent 读取抽取文件时可能看到
普通源码注释，因此注释可间接影响模型；但正式规则仍是 caller-driven intended
behavior。进入静态推理时，`src/parser.py` 会移除函数注释，reasoner 比较的是已经
生成的规约与代码行为。

为保持效果一致，v0.3.0 **没有**增加 `Contract:` 特殊优先级或硬编码判定。需要把
业务约束作为权威输入时，应使用 `--domain-knowledge`，或通过真实调用方/公共接口
上下文让上游的 caller-driven 规约机制获得依据。

## 报告语义

- `MATCH`：当前模型生成的实际后置条件与行为规约比较未发现反例。
- `MISMATCH`：发现静态不一致候选；不是动态确认的 Bug。
- `ERROR`：模型、协议或推理调用失败；可在修复后用 `--resume` 重试。
- `MISSING`：规约 sidecar 或函数结果缺失/损坏。
- `COMPLETE`：本次范围内没有 `ERROR/MISSING`，不代表程序被完整证明正确。

动态测试被移除后，不可能与原项目的 `confirmed/not_confirmed` 动态结论等价。
v0.3.0 保持相似的报告交互和证据结构，同时明确使用静态 verdict，避免误导用户。

## 有意差异

- 没有 OpenCode、Bun、oh-my-openagent、Pi Agent Validator。
- 没有运行目标程序、编译探针、插装、runtime oracle、observable reviewer、repair。
- 删除相关命令参数 `--bug-validator`、`--agent-validator*`，而不是保留不可工作的
  空选项。
- `--all-bugs` 表示继续收集静态候选，不表示逐个动态确认。
- 模型服务可在公网或内网；安装和包内自检本身完全不联网。

这些差异均来自明确需求和安全语义边界，其余用户可见流程尽可能保持上游阶段、
命名、产物与展示方式。

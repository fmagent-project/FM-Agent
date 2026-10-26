# FM-Agent 上游符合性分析报告

## 1. 分析目标

本报告回答三个问题：

1. DeepSeek Harness 版本是否仍按 FM-Agent 的 Stage 1～6 和静态推理逻辑工作；
2. 用户能看到的命令、过程、错误、trace 和报告是否尽可能保持一致；
3. 哪些差异是移除动态测试/插装后的必然差异，哪些属于适配修复或增强。

“符合”在这里指工作流、输入输出语义和用户可见效果符合，不要求模型后端进程、
trace 文件格式或 HTML 字节级一致。

## 2. 审计基线

| 基线 | 固定标识 |
|---|---|
| 公共原项目 `fmagent-project/FM-Agent` | GitHub `main`/`HEAD`：`971618d0531af411b6ffdb9854fddd301098ef3d` |
| 用户更新资料 `FM-Agent-release.zip` | SHA-256：`0017b364772d889aae1a607706d234ba72023b7e5bc2d95811b79e3991a29d71` |
| 更新资料导入快照 | `3321f0ba7007a475b5e9be40e7b15f0138bd7871` |
| 当前交付 | `0.3.0-dsh.1` |

本次重新查询公共仓库后，远端 `HEAD` 仍为上述 commit。更新资料不是公共仓库的简单
增量：它加入了大型 Pi Agent Validator、并发 batch、入口推理主流程等内容，同时
删除了公共版顶层 `report.py`、chip 插件和若干旧语言/估算组件。因此当前实现以
`FM-Agent-release.zip` 的静态分析主线为首要代码基线，并用公共版本补齐其仍有价值的
用户体验（例如 HTML 报告和 `--dashboard`）。

## 3. 符合性等级

- **A－直接保留**：代码或算法直接沿用更新资料，核心文件可达到内容一致。
- **B－后端适配**：输入、输出和流程语义保留，但 OpenCode 调用替换为 Harness。
- **C－兼容增强**：不改变正常成功语义，补充终态校验、诊断、非 Git 或模型兼容。
- **D－按需求删除**：仅涉及动态测试、插装、运行时验证或 OpenCode。
- **E－不可等价**：没有动态执行后无法产生 `confirmed/not_confirmed` 等动态结论。

## 4. Stage 1～6 与静态推理

| 能力 | 公共原项目 | 更新资料 | 当前实现 | 等级与结论 |
|---|---|---|---|---|
| Stage 1 阶段计划 | OpenCode Agent，输出 `phases.json` | 同类流程 | 原 prompt/schema 与产物；Harness Agent | B；效果对齐 |
| Stage 1 失败处理 | 依赖 Agent 正确写文件 | 相同风险 | 重试后仍缺失时本地生成覆盖全部非测试源码的单阶段计划 | C；避免退出码 0、产物缺失造成假成功 |
| Stage 2 领域上下文 | OpenCode Agent | OpenCode Agent | Harness Agent；仍输出 engine overview 与 phase types | B；效果对齐 |
| Stage 3 函数抽取 | 本地确定性逻辑 | 新版抽取逻辑 | `src/extract.py` 与更新资料内容一致 | A |
| Stage 4 函数文件列表 | 本地生成 | 新版文件列表逻辑 | 保留语义，增加 JSON 与覆盖范围终态校验 | A+C |
| Stage 5 top-down layers | 本地调用图排序 | 新版排序 | `src/generate_topdown_layers.py` 与更新资料内容一致 | A |
| Stage 6 batch 规约 | OpenCode | 并发 batch、分层、重试 | 保留分层、manifest、并发、重试和 sidecar schema；后端换为 Harness | B |
| Hoare 风格推理 | LLM post-condition → implication | 相同主线 | `src/reasoner.py` 与更新资料内容一致 | A |
| 解析/范围核心 | 本地 | 新版 | `src/parser.py`、`src/scope.py`、`src/domain_knowledge.py` 与更新资料一致 | A |
| `--all-bugs` | 继续收集候选并动态验证 | 可接 Pi Validator | 继续收集全部静态候选，不执行动态确认 | B+E；名称保留，语义边界明确展示 |
| 增量分析 | Git commit 差异 | 改进后的增量流程 | 保留 Git changed/affected 静态分析，并在结束时生成同类报告 | B+C |
| 入口函数分析 | 插件形态 | 正式 `--entry-func` 主流程 | 保留更新资料单入口及 `--end-func` 行为 | A+B |

直接哈希/内容比较确认以下静态核心文件相对更新资料未改变：

```text
src/reasoner.py
src/extract.py
src/generate_topdown_layers.py
src/parser.py
src/scope.py
src/domain_knowledge.py
```

`src/prompts.py`、Stage 6 编排和 verification 层有意修改，原因是需要处理真实模型
出现的空正文、矛盾 verdict、规范污染和 Harness 终态错误；这些修改不改变正常
MATCH/MISMATCH 的定义。

## 5. 命令行符合性

### 保留的分析选项

```text
--resume
--incremental
--isolate
--one-phase
--all-bugs
--only-spec
--domain-knowledge / --knowledge
--submodule
--entry-func
--end-func
--extra-edge
--list-plugin
--plugin
--dashboard
```

公共版本的 `--dashboard` 已恢复，既可以随分析自动启动：

```bash
fm-agent /path/to/project --dashboard
```

也可以在另一终端只读查看：

```bash
fm-agent dashboard /path/to/project
```

公共版本的 `--estimate` 及相关 `run_estimate.py` 已被用户提供的更新资料删除，因此
当前实现没有擅自重新引入。更新资料中的 `--bug-validator`、`--agent-validator*`
属于动态验证/插装链路，按本项目要求删除。

## 6. 过程展示符合性

六个阶段继续使用原有的：

```text
[Pipeline] Stage 1/6: ...
...
[Pipeline] Stage 6/6: ...
```

过程展示保留并扩充以下信息：

| 展示项 | 当前行为 |
|---|---|
| 阶段进度 | 显示 Stage 1～6、phase、layer、函数完成数 |
| Agent 进程 | `agent_call` 显示 Harness 进程成功/失败、退出码和日志引用 |
| 结构化推理 | `llm_call` 显示 post-condition/implication、重试和判定 |
| 产物终态 | 独立 `stage_validation`；进程成功不再等同于文件生成成功 |
| 历史错误 | 保留已经恢复的 error/format_error，和最终终态分开显示 |
| 静态结果 | 仪表盘显示 MATCH/MISMATCH/ERROR 数量 |
| LLM/Harness 调用 | 独立表格显示最近调用、模型、状态和摘要 |
| Tokens | 提供方经 Harness 暴露 usage 时累计；未暴露时显示 0，不伪造成本 |

公共版/更新资料仪表盘中的动态 confirmed bug、runtime validator、repair、observable
区域无法在纯静态版本中等价保留，已替换为静态 verdict 面板，而不是显示虚假的
“已确认 Bug”。

## 7. 错误展示符合性

原实现常把 OpenCode/Harness 进程退出码当作主要成功依据。实际 Qwen 测试证明，
进程可能 `exit_code=0`，但没有写出 `phases.json`、domain context 或 spec sidecar。
当前实现因此同时保留两层状态：

1. `agent_call`：后端进程是否成功；
2. `stage_validation`：本阶段应有文件是否存在、JSON/schema 是否有效、覆盖是否完整。

终端错误会列出准确缺失路径；`events.jsonl` 保存阶段、attempt、missing outputs、
错误摘要；`*_harness.log` 保存 Harness NDJSON；`*_proxy.jsonl` 保存上游状态、原始
content/reasoning、parser decision 和工具识别结果。认证头和 API key 不写入这些文件。

这是对原错误展示的兼容增强：成功路径不变，但“进程成功、产物失败”不会再被误报
为阶段完成。

## 8. 报告符合性

### 基线差异

- 公共原项目有自包含 `report.html`，主要展示动态验证后的 concluded bugs；
- `FM-Agent-release.zip` 删除了顶层 `report.py`；
- 当前需求明确要求在静态分析结束后立即给出相同或类似体验。

### 当前报告

静态分析结束后立即生成：

```text
fm_agent/VERIFICATION-REPORT.md
fm_agent/VERIFICATION-REPORT.json
fm_agent/report.html
```

HTML 已对齐公共版的主要交互：

- 自包含、断网可打开；
- 搜索函数、文件和证据；
- verdict 多选筛选；
- 源文件分层筛选；
- candidate/source/function 排序；
- 全部展开与全部折叠；
- 单条完整详情弹窗；
- 规约、结果和源码链接；
- 源码行号、函数范围高亮和轻量语法着色；
- 错误、候选证据和 trace 诊断展示。

静态报告不能沿用动态报告的 `confirmed/not_confirmed` 标签。对应关系是：

| 当前标签 | 含义 |
|---|---|
| `MATCH` | 当前静态推理未找到反例，不是完整正确性证明 |
| `MISMATCH` | 静态推理发现候选，不是动态确认 Bug |
| `ERROR` | 模型、协议或推理失败，可修复后 `--resume` |
| `MISSING` | 规约或结果产物缺失/无效 |
| `COMPLETE` | 本次范围没有 ERROR/MISSING，不代表程序无缺陷 |

完整和部分失败都会生成报告；先写 Stage 6 最终校验事件，再生成报告，保证报告中的
trace 诊断包含真实终态。

## 9. 普通非 Git 项目

公共/更新流程的一些路径默认依赖 Git worktree 或 commit。当前实现明确区分：

- 普通目录支持完整 Stage 1～6；
- 普通目录支持 `--isolate`，使用文件系统副本并回写 `fm_agent/`；
- 系统没有 `git` 命令时，普通目录仍可完成；
- `--incremental` 仍要求有 commit 历史，因为其语义本身依赖差异基线。

上述行为已在 Ubuntu 22.04 断网环境的普通 C 项目中端到端验证。

## 10. `Contract:` 注释结论

公共项目和更新资料均没有专门解析或提升 `Contract:`、`Requires:`、`Ensures:`
优先级的逻辑。规约 Agent 可能把普通源码注释作为上下文看到，但静态 reasoner 使用
`src/parser.py` 处理代码时会移除注释。因此当前实现没有增加特殊 Contract 规则。

明确的业务需求应通过真实调用方上下文或 `--domain-knowledge` 提供。后者属于规范性
输入；生成“代码实际行为”时仍以代码为准，避免把期望行为误写成已实现行为。

## 11. 有意差异与不可等价项

以下差异符合用户明确范围，不属于遗漏：

- 无 OpenCode、Bun、oh-my-openagent；
- 无动态测试、运行目标、编译探针、插装、runtime oracle；
- 无 Pi Agent Validator、observable reviewer、repair；
- 无动态 `confirmed/not_confirmed` 结论；
- trace 后端从 OpenCode trace 改为 Harness NDJSON + Qwen proxy audit；
- 模型 usage 未返回时不估算 token 成本。

因此，本版本能对齐的是 FM-Agent 的静态发现流程和用户体验，不能声称与动态确认结果
等价。

## 12. 总体结论

- 静态核心算法：A，直接沿用更新资料；
- Stage 1/2/6 Agent：B，后端替换但产物和阶段语义保持；
- CLI/过程/错误：B+C，保留主流程并修复假成功和不可观测问题；
- 静态结束报告：B+C，以公共版交互为目标、用静态语义重新实现；
- 动态验证/插装：D+E，按要求删除且明确不能等价；
- 普通非 Git 和完全离线交付：C，新增并已验证。

在明确排除动态测试、插装和动态确认的前提下，当前实现与公共原项目及用户更新资料的
静态主流程、主要命令、过程可见性、错误可见性和报告使用方式保持功能符合。

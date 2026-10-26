# `FM-Agent-release.zip` 变更与离线适配报告

## 输入与对比基线

- 新版输入：用户提供的 `FM-Agent-release.zip`。
- ZIP SHA-256：`0017b364772d889aae1a607706d234ba72023b7e5bc2d95811b79e3991a29d71`。
- 安全解包后文件数：114；导入快照提交：
  `3321f0ba7007a475b5e9be40e7b15f0138bd7871`。
- 旧基线提交：`971618d0531af411b6ffdb9854fddd301098ef3d`。
- 差异规模：134 个文件，约新增 18,755 行、删除 13,803 行。

ZIP 已在解包前检查绝对路径、`..` 路径逃逸和符号链接。根目录中一个名称类似
测试断言的异常文件未纳入交付包。

## 新版上游的主要变化

1. 新增大型 `src/agent_validation_core/`，包含 Pi runner、动态运行、插装目录、
   runtime trace、oracle、外层 gate、review/repair、session/snapshot 和配套 skills。
2. 规格批处理与并发调度重构：batch manifest、pending batch 重试和运行时复用逻辑
   更完整。
3. 入口函数分析从插件迁入 `src/entry_reasoning_pipeline.py`，成为正式流水线入口。
4. 增量分析、CodeGraph 抽取协调、函数作用域选择、Erlang/Rust 处理和 trace 字段有
   较大调整。
5. 删除旧芯片/Chisel/Verilog 插件与 CIRCT 工具，删除旧 specification profile/
   session 抽象、运行估算器和独立 HTML report。
6. CodeGraph 配置在 ZIP 中回退到 `1.5.0-fmagent.1`，与现有已验证 runtime 不一致。

## 本离线版保留的新版内容

- 新版主流水线、批处理 manifest、并发补位和重试逻辑；
- 新版入口函数分析；
- 新版增量分析和抽取/作用域相关改进；
- 新版语言 registry 与 CodeGraph 协调方式；
- `--resume`、`--one-phase`、`--submodule`、`--entry-func`、`--extra-edge`、
  `--only-spec`、`--all-bugs` 等静态流程；
- CodeGraph pin 修正为已随包验证的 `1.6.0-fmagent.1`。

## 本离线版移除或替换的内容

- 完整删除 `src/agent_validation_core/` 及动态 validator 文档、评测结果和 skills；
- 删除 `--bug-validator`、`--agent-validator*` 参数及所有动态确认、插装、探针、
  observable、repair、outer gate 调用；
- `MISMATCH` 仅输出静态候选，`--all-bugs` 仅收集全部静态候选；
- 删除 OpenCode backend、配置、trace plugin 和初始化逻辑；
- 所有 agent 型调用及结构化 LLM 调用统一经随包 DeepSeek Harness；
- 增加固定的 headless profile、禁用 telemetry、非交互权限配置和超时控制；
- 增加随包 Python/CodeGraph/Harness、manifest、离线 verifier、安装器和模型连通
  测试命令。

## 普通非 Git 项目兼容性

新版离线适配将 Git 限制缩小到真正依赖提交差异的 `--incremental`：

- 普通目录可直接完整分析；
- 普通目录可使用 `--isolate`，实现为排除 `fm_agent/` 的文件系统快照；
- 即使目标系统没有安装 `git` 可执行文件，普通目录探测也安全降级；
- `--incremental` 对普通目录给出明确错误，不会隐式初始化或修改其版本控制状态。

## 行为边界

本交付版维持 FM-Agent 的代码理解、函数抽取、行为规约生成和静态推理主逻辑，
但按需求取消动态测试阶段。因此静态候选不能被描述为“已动态确认的 Bug”。安装
完全离线；模型端点是否需要网络取决于部署方配置。

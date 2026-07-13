# Structured Function Metadata Design

## 背景

FM-Agent 当前将函数实现、`[SPEC]` 和 `[INFO]` 写在同一个提取函数文件中。函数提取阶段先写入纯函数源码，spec 生成代理随后把两个文本块加到文件头并覆盖同一路径。`--resume`、拓扑分层、跨层 caller context、验证和增量分析都依赖这个混合文件格式。

本设计把函数实现与规约元数据彻底分离。每个提取函数保留一个只含实现的源码文件，并在同目录生成两个结构化 JSON 伴随文件。新格式不兼容旧的内嵌 `[SPEC]/[INFO]` 产物；升级后必须删除目标项目旧的 `fm_agent/` 并重新全量运行。

## 目标

- 提取函数文件从生成后始终只包含原始函数实现。
- 每个函数在同目录拥有一个 `.spec.json` 和一个 `.info.json`。
- spec 与 info 使用结构化字段，不保存语言注释、`[SPEC]`、`[INFO]` 或 `[SPLIT]` 标记。
- 即使函数没有 callee，也必须生成合法 `.info.json`，其中 `callees` 为空数组。
- 全量、`--resume`、增量、入口函数模式、跨层 prompt 和验证流程全部使用新格式。
- 第一阶段通过适配器维持 reasoner 的旧文本输入；端到端验证成功后，第二阶段将 reasoner 改为直接消费结构化对象并删除适配器。

## 非目标

- 不读取或迁移旧的内嵌 `[SPEC]/[INFO]` 文件。
- 不同时维护新旧两套存储格式。
- 不改变提取函数源码的目录布局或 FQN 规则。
- 第一阶段不改变 reasoner 的判定语义。

## 文件布局

原来的单文件布局：

```text
fm_agent/extracted_functions/src/engine/loader-cpp/loadData.cpp
```

新布局：

```text
fm_agent/extracted_functions/src/engine/loader-cpp/loadData.cpp
fm_agent/extracted_functions/src/engine/loader-cpp/loadData.spec.json
fm_agent/extracted_functions/src/engine/loader-cpp/loadData.info.json
```

函数实现文件是主文件，两个 JSON 是函数元数据文件。所有目录扫描必须显式区分函数源码和元数据 JSON，不能把 `.spec.json` 或 `.info.json` 放入函数列表、调用图或验证结果路径映射。

## JSON Schema

### Spec

```json
{
  "schema_version": 1,
  "function": "src::engine::loader-cpp::loadData",
  "unit": "src/engine/loader.cpp",
  "signature": "loadData(path) -> Result",
  "preconditions": [
    "path identifies a readable input"
  ],
  "postconditions": [
    "returns the decoded data when the input is valid"
  ]
}
```

必填约束：

- `schema_version` 必须是整数 `1`。
- `function` 必须是与提取路径一致的完整 FQN。
- `unit` 必须是原项目根目录下的源文件相对路径。
- `signature` 必须是非空字符串。
- `preconditions` 和 `postconditions` 必须是字符串数组；没有条件时使用空数组。

### Info

```json
{
  "schema_version": 1,
  "function": "src::engine::loader-cpp::loadData",
  "callees": [
    {
      "function": "src::engine::loader-cpp::parseHeader",
      "signature": "parseHeader(data) -> Header",
      "preconditions": [
        "data contains a complete header"
      ],
      "postconditions": [
        "returns the validated header"
      ]
    }
  ]
}
```

必填约束：

- 顶层 `schema_version` 必须是整数 `1`。
- 顶层 `function` 必须与对应源码文件的 FQN 一致。
- `callees` 必须是数组；没有 callee 时必须是 `[]`。
- 每个 callee 的 `function`、`signature` 是非空字符串。
- 每个 callee 的 `preconditions`、`postconditions` 是字符串数组。

## 集中存储接口

新增 `src/spec_storage.py`，集中负责：

- 从函数源码路径推导 `.spec.json` 和 `.info.json` 路径；
- 判断路径是否为函数元数据文件；
- 从提取函数路径推导预期 FQN；
- 校验 JSON 语法、字段存在性、字段类型、schema 版本和 FQN 一致性；
- 原子读取和写入 JSON；
- 判断函数是否 ready；
- 将结构化 spec/info 暂时转换为现有 reasoner 接口需要的文本和 `FunctionSpecMap`。

完成状态定义为：函数源码存在，并且两个 JSON 都存在、可解析、schema 合法且顶层 `function` 与源码路径一致。缺失、半生成或格式非法都不算 ready。

## 全量流程

1. `run_extraction()` 读取原项目源文件，并且只写函数实现文件。
2. 函数列表和拓扑分层只收集受支持语言的源码文件，忽略两个 JSON。
3. batch prompt 生成器从更早层 caller 的 JSON 中读取 spec 和针对当前 callee 的 expectation。
4. spec 生成代理读取函数实现，但只能写 `.spec.json` 和 `.info.json`；prompt 明确禁止修改实现文件。
5. watcher 只有在两个 JSON 都通过校验后才提交验证。
6. parser 读取三个文件，通过适配器返回当前 reasoner 需要的 `(func, spec_text, knowledge)`。
7. 验证结果仍写入 `logic_verification_results`，相对路径继续以函数源码路径为准。

为检测代理误改源码，spec batch 启动前记录目标实现文件的内容摘要，任务结束后重新计算；任何变化都使该 batch 失败，并记录具体函数路径。

## Resume 语义

`--resume` 不再扫描函数文件中的标记：

- 两个 JSON 都合法：函数已经完成，跳过 spec 生成。
- 任一 JSON 缺失或非法：函数保持 pending，重新生成完整的两个 JSON。
- 提取阶段只维护纯函数源码，不把 JSON 缺失视为覆盖源码的理由。
- 由于 resume 针对同一次中断运行，合法 JSON 与对应实现共同保留。
- 旧内嵌格式永远不算 ready；用户必须删除旧 `fm_agent/` 后重跑。

## 跨层传播

`generate_batch_prompts.py` 不再解析注释块：

- earlier-layer caller spec 直接读取 caller 的 `.spec.json`；
- caller 对某个 callee 的 expectation 从 caller 的 `.info.json` 中按完整 FQN 匹配；
- prompt 内嵌 JSON 或明确的结构化字段，并要求输出符合固定 schema 的两个文件。

完整 FQN 是匹配主键；不再以 bare function name 作为首选匹配方式，避免同名函数冲突。

## 增量流程

增量模式不再从源码头提取和恢复 spec：

- 重新提取只更新函数实现文件，现有 JSON 独立保留。
- 删除或重命名函数时，同步删除对应 `.spec.json`、`.info.json` 和陈旧验证产物。
- 新增函数没有元数据，进入 spec 生成队列。
- 修改或 intent 相关函数通过模型返回结构化 spec/info，由 Python 校验后原子写入 JSON。
- downward propagation 更新 callee 的 `.spec.json`；upward reconciliation 只更新 caller 的 `.info.json`。
- 实现文件在整个 spec 更新阶段不可写。

## 两阶段 reasoner 改造

### 第一阶段：存储迁移与兼容适配

读取结构化 JSON 后，仅在内存中生成旧接口需要的文本：

```python
spec_data = read_spec(function_path)
info_data = read_info(function_path)
spec_text = format_spec_for_reasoner(spec_data)
knowledge = info_to_function_spec_map(info_data)
reasoner(func, spec_text, knowledge, language)
```

不会把旧文本格式写入磁盘。第一阶段保持 `_parse_spec_conditions()` 和 reasoner prompt 的语义不变，用于隔离存储变更风险。

### 第一阶段验收门

只有以下检查全部通过，才能进入第二阶段：

- 全量小项目 smoke test 成功。
- 提取实现文件在 spec 生成前后的内容摘要一致。
- 每个函数都有两个合法 JSON，包括无 callee 函数。
- 跨层 caller expectation 正确传播。
- `--resume` 跳过合法 JSON，并重试缺失或非法 JSON。
- 增量模式只更新必要的 JSON，不修改实现文件。
- 入口函数模式可以完成生成与验证。
- verdict 与旧 reasoner 文本输入下的预期一致。

### 第二阶段：reasoner 直接消费结构化数据

第二阶段修改 reasoner 和相关 prompt，使其直接接收 spec/info 对象，随后删除：

- `format_spec_for_reasoner()`；
- 基于文本标题的 `_parse_spec_conditions()`；
- 只为 `[SPEC]/[INFO]/[SPLIT]` 服务的解析代码；
- `FunctionSpecMap` 兼容层。

第二阶段必须重新执行第一阶段的完整 smoke test 集合，并确认 verdict 不发生非预期变化。

## 错误处理

- JSON 不存在：保持 pending，允许 batch 重试。
- JSON 语法错误：记录文件路径和解析错误，保持 pending。
- schema 错误：记录具体字段、期望类型和实际类型，保持 pending。
- FQN 不一致：拒绝验证并报告预期值与实际值。
- 只生成一个 JSON：整体不 ready，重新生成两个文件。
- 模型修改实现源码：batch 失败，报告被修改文件；不得接受该次输出。
- 原子写入采用同目录临时文件加 `os.replace()`，避免 watcher 读取半个 JSON。

## 文档与运行提示

README 和中文 README 需要说明新产物布局、resume 判定以及不兼容升级步骤：

```text
Remove the target project's existing fm_agent/ directory before the first run
with the structured metadata format. Old embedded [SPEC]/[INFO] artifacts are
not supported.
```

实现期间不修改用户已有的无关工作树改动。

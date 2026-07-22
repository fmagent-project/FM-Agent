# Taint 插件：完整性污点 / 注入检测（Integrity Taint）

> 插件总览见 [./README.md](./README.md)。
> 对偶的机密性插件见 [./ifc.md](./ifc.md)。
> 插件 SPI 架构见 [../plugin_architecture.md](../plugin_architecture.md)。
> 设计动机见 [../security_portfolio_roadmap.md](../security_portfolio_roadmap.md)。

Taint 插件分析完整性：不可信输入是否未经与上下文匹配的处理就到达敏感操作。LLM 提取 source、
sink、sanitizer、validation guard 和参数化 flow；`src/plugins/taint.py` 做有限源码归一化与跨函数
组合；`src/taint_reasoner.py` 和 `src/taint_validation.py` 确定性裁决。

该插件是注入漏洞探针，不是 sound 的全程序污点证明。尤其要区分模型事实、Python 源码启发式复核
和 reasoner 的闭集规则。

---

## 1. 理论模型：IFC 的完整性对偶

Taint 与 IFC 共享“输入依赖到安全边界”的骨架，但方向相反：

| 维度 | IFC 机密性 | Taint 完整性 |
|---|---|---|
| 起点 | High 机密数据 | 不可信 source |
| 终点 | Low 可观测输出 | 敏感 operation sink |
| 有意解除 | declassification | 类型化 sanitizer / endorsement |
| 违规 | High 到 Low | tainted 到 sink |

这个对偶不能机械照搬。Taint 的 sink 是带 `arg_context` 的操作点，sanitizer 只对其明确支持的上下文
有效，source 则按代码来源模式而不是变量名识别。

检查器采用三态操作格：

```text
UNTAINTED < UNKNOWN_PARAM < TAINTED
```

- 具体的函数内 source、`unknown:*` 和 `callee_source:*` 都是 `TAINTED`。
- 尚未被调用方确定的 `param:*` 是 `UNKNOWN_PARAM`，通常产生 `POLYMORPHIC`。
- 调用方明确证明干净的参数才是 `UNTAINTED`。

函数级优先级为：

```text
ERROR > VULNERABLE > POLYMORPHIC > SANITIZED > SAFE
```

`SANITIZED` 表示至少有相关污点到达 sink，但按当前类型化规则或 guard 规则被背书；它不是 sanitizer
实现正确性的证明。`SAFE` 表示当前事实中没有形成其他裁决。

---

## 2. 抽象格式与闭集

模型返回一个 `[TAINT_JSON] ... [/TAINT_JSON]` 对象。核心结构如下：

```json
{
  "schema_version": "taint.v1",
  "function": "search_users",
  "language": "python",
  "params": ["request"],
  "taint_sources": [
    {"id": "S1", "source_kind": "http_param", "expr": "request.args.get('name')", "confidence": "high"}
  ],
  "sanitizers": [],
  "validation_guards": [],
  "taint_bindings": [],
  "return_flows": [],
  "param_mutations": [],
  "call_sites": [],
  "sinks": [
    {
      "id": "K1",
      "sink_kind": "sql_query",
      "callee": "cursor.execute",
      "call_expr": "cursor.execute(sql)",
      "arg_position": 0,
      "arg_expr": "sql",
      "arg_context": "sql_query_text",
      "flows": [{"source": "source:S1", "sanitizers": []}]
    }
  ],
  "notes": []
}
```

`flows[].source` 接受 `source:<id>`、`param:<name>`、`unknown:<id>`；组合器还会生成
`callee_source:<call-id>:...`。未知前缀或闭集外枚举会使 `classify()` 返回 `ERROR`。

### 2.1 source 闭集

`SOURCE_KINDS` 包括 HTTP 参数/body/header、CLI、stdin、socket、env、file、db_read、
`untrusted_param`、deserialized 和 `unknown_external`。所有具体 source record 在 reasoner 中都按
TAINTED 处理；`confidence` 不会降低具体 source 的污点状态。

提示词要求按访问模式识别 source，例如 request、form、环境变量和外部序列化 artifact，而不是按
局部变量名称。该识别主要由模型完成；源码归一化并不会枚举所有框架 source。

### 2.2 sink 与 finding 闭集

当前 sink 包括 SQL、shell、subprocess argv、文件路径、SSRF、重定向、HTML、模板、反序列化、
代码执行、LDAP 和 XPath，对应 CWE-89、78、88、22、918、601、79、1336、502、94、90、643。
`unknown_external` 只能是 source，不能作为 sink。

每个 sink 必须有闭集中的 `arg_context`。例如 SQL 分成 `sql_query_text`、`sql_identifier`、
`sql_numeric_literal` 和 `sql_param`；shell command text 与 argv token 也不同。上下文是 sanitizer
匹配的安全边界，不能互换。

---

## 3. 类型化 sanitizer 与 SQL 语义

`has_valid_sanitizer()` 对普通上下文接受 sanitizer 的条件是：

- `confidence` 必须是 `high`；
- `sanitizer_kind` 必须属于 `KNOWN_SANITIZER_KINDS`；
- sink 的 `arg_context` 必须在内置 `SANITIZER_ENDORSES[kind]` 中；
- 若 sanitizer 给出了非空 `endorses`，其中也必须包含该上下文；若 `endorses` 缺失或为空，当前检查器
  会仅依赖内置 kind 到 context 映射。

因此 HTML escape 不能清除 SQL，`shell_quote` 只背书 `shell_arg_token`，不能清除完整
`shell_command_text`，LDAP escape 只背书 `ldap_filter`。未知、低置信度或上下文不匹配的 sanitizer
会被忽略。

### 3.1 SQL bind 参数是上下文本身的背书

`sql_param` 有一条显式特例：reasoner 直接把该上下文视为已背书，不要求 flow 引用一个
`parameterized_query` sanitizer。安全参数化查询仍应记录 sink：

```python
name = request.args.get("name")
cursor.execute("SELECT * FROM users WHERE name = ?", (name,))
```

这里 `name` 仍是 tainted，且仍到达 `sql_query`，但它位于 `sql_param` 槽位，因此结果是
`SANITIZED`。不要同时声称“必须生成 parameterized_query sanitizer”；当前实现不需要它。

相反，拼接进 `sql_query_text`、`sql_identifier` 或 `sql_numeric_literal` 不会享有这个特例。标成
`parameterized_query` 的 sanitizer 在内置表中也只背书 `sql_param`；ORM 的
`orm_parameterization` 才允许 `sql_param` 和 `sql_query_text`，仍需 high confidence 和上述声明规则。

跨函数组合时，callee sanitizer ID 会按 call ID 加命名空间，并同步改写 flow 中的字符串引用，避免
与 caller 同名 sanitizer 冲突。内联 sanitizer 对象在本地匹配中也可被接受，但结果展示的
`sanitized_by` 对这种形状不一定能恢复 kind。

---

## 4. validation guard：conditional、default 与 must

validation guard 是控制流门，不是值转换。它只能出现在顶层 `validation_guards`，当前 allowlist 为
`schema_validation`、`deserialization_allowlist` 和 `content_scan`，且三者都只可背书
`serialized_blob`。

`src/taint_validation.py` 只有在以下条件全部满足时才接受 guard：

- `confidence == "high"`；
- `failure_mode == "closed"`；
- `coverage` 是 `must` 或 `default`；
- `default` 必须有非空 `bypass_param`；
- `input_expr` 与 sink 的 `arg_expr` 完全相等；
- `protects_sink_ids` 包含该 sink 的精确 ID；
- guard kind 的内置 allowlist 和 guard 自己的 `endorses` 都包含 sink context。

`conditional` 从不被 reasoner 直接当作保护。三种 coverage 的操作语义如下：

| coverage | 本函数本地裁决 | 组合到具体调用点 |
|---|---|---|
| `must` | 有效 guard 使相关 sink 成为 `SANITIZED`。 | 保持 `must`。 |
| `default` | 默认路径按受保护处理，相关 sink 成为 `SANITIZED`。 | 省略 bypass 参数或传字面量 true 变为 `must`；传 false 变为无保护；动态值保持 `default`。 |
| `conditional` | 被忽略；具体污点通常仍为 `VULNERABLE`。 | 不作为可组合保护。 |

组合后的 sink 若携带内部 `default` coverage，具体 taint 会产生
`POLYMORPHIC / VALIDATION_GUARD_BYPASS`；这是“动态调用参数可能关闭默认 guard”，不同于本地函数在
默认路径上的 `SANITIZED`。

false/true 解析只识别布尔值、数值 `1`/`0`，以及字符串形式的 `true`/`false`、`1`/`0`。其他表达式保持动态。

### 4.1 本函数 content scan 的源码复核

Python 源码归一化会对 `scan_file_path`/名称含 scan 的调用做窄化 AST 复核。要把扫描提升为有效
保护，扫描必须发生在同一输入的 unsafe deserialize 之前，控制路径必须覆盖该 sink，而且感染结果
和扫描错误都必须在 sink 前终止执行。吞掉扫描异常、只检查 infected 而忽略显式 error 状态、扫描在
sink 之后或扫描另一输入都不算保护。

对于默认值为 true 的简单布尔参数条件，AST 规则可推导 `default` 及 bypass 参数；无条件扫描可推导
`must`。默认关闭或无法证明覆盖的扫描不提升。源码证据还可以重绑错误的模型 sink ID、纠正 input，
或把不符合源码的 closed 声明降为 open，但这些规则只覆盖实现中识别的 Python 形状。

### 4.2 独立 callee scan contract

存在另一种窄场景：callee 只负责扫描，unsafe loader 位于 caller。确定性传播不是“只要 callee
summary 写了 guard 就信任”，而是重新检查 callee 和 caller 的 Python 源码：

- callee 中必须有无条件、函数级的 scan 赋值；
- 后续同一控制上下文的判断必须同时拒绝感染/不安全结果和错误/失败结果，并终止；
- caller 必须把与后续 deserialize sink 完全相同的表达式传给该 helper；
- helper 调用必须在 caller 中支配并先于该 sink。

只有这种 source-validated `must` 契约才会直接保护 caller 的独立 deserialize sink。带 bypass 的
callee helper、条件调用、不同实参、非支配调用或 fail-open helper 不会传播为 `must`。callee summary
中的 guard kind/input/coverage/failure mode主要供模型理解；上述独立 helper 传播依赖源码证明。

若 sink 本来就在 callee 内，则走普通 sink 组合：`default` guard 会按调用点 bypass 实参解析，而不是
套用这条“独立 helper 必须为 must”的规则。

扫描 helper 还可能被建模为 `deserialize` acceptance boundary，使“是否允许 artifact 继续进入下游
unsafe object loader”本身接受 CWE-502 检查。该规则要求函数具有明确的 serialized-artifact/scan
角色；普通文件扫描器不因此自动成为反序列化 sink。

---

## 5. Python 源码归一化与过滤

`_normalize_operation_sinks()` 在解析后、组合时和检查前都会运行。其目的主要是删除模型幻觉和校正
少量已知形状，不是通用静态污点引擎。

### 5.1 config pseudo-source

模型有时把应用配置常量误报为 HTTP/env source。当前规则只识别形如 `config.NAME` 的单段 Python
属性表达式，并要求源码中所有与该表达式匹配的 AST 节点都是读取。满足时，该 source record 及引用
其 ID 的 sink flows 会被删除，不论模型给它标了何种 source kind。

该规则不是“所有 config 都可信”：

- `os.environ[...]`、`os.getenv(...)`、request/form 访问不匹配，仍保留为 tainted source；
- 若同一 `config.NAME` 在函数内作为赋值目标出现，例如从 request 写入，`Store` 节点会阻止删除；
- 复杂或非 Python 配置访问不享有此规则。

### 5.2 dotted member state

为了处理 `form -> self.username -> LDAP filter` 这类持久化请求状态，`_seed_param_status()` 支持非常
窄的 dotted member seed：

- source 必须是 `untrusted_param`、`confidence == "high"`；
- 语言必须是 Python；
- `expr` 必须能解析成纯属性链，如 `self.username`，并且同一标准化属性链确实出现在函数 AST 中；
- 成功后以完整 key `self.username` 标为 TAINTED，从而解析 `param:self.username`。

方法调用、subscript、二元表达式等不会按这条 member-specific 规则 seed。没有 source-backed
member seed 时，状态仍会经过通用参数规则：入口函数 sink 中的 `param:*` 会按 attacker input
置为 `TAINTED`；非入口函数中能回溯到入口点的参数也会置为 `TAINTED`；其余才保持
`UNKNOWN_PARAM` 并得到 `POLYMORPHIC`。

另有两个兼容行为需要区分：若 dotted expr 的末段正好也是 payload 的参数名，会 seed 该参数名；若
任何具体 sink flow 直接写成 `param:self`，插件会把 `self` 视为 TAINTED。后者只说明模型已断言整个
成员状态进入该 sink，不等价于自动追踪任意对象字段。

### 5.3 source 与 sink 过滤

source 归一化目前还把模型的 `fs_path` source kind 改为 `untrusted_param`，把 `file_read` 改为闭集内
的 `file`。除此之外，具体 source 的外部来源主要仍由模型负责。

原始 sink 必须有源码中同家族操作的字符串/AST 证据，否则会被删除。当前还有这些收紧规则：

- `unknown_external` sink 被删除，因为它不是合法 sink kind。
- 非 eval/exec 的 `code_eval` 被删除；模型把 `exec` 报成 `code_eval` 时会归一为
  `shell_command / shell_command_text`，对应 CWE-78。
- `json.loads + getattr + 普通方法调用`、JQL/ORM helper 或普通动态 dispatch 不会仅因动态性成为
  shell/code/SQL sink。
- LDAP 只保留 filter 角色；base DN、search base、scope 等非 filter 参数不会作为 LDAP injection
  sink。
- `safetensors`、GGUF data-only loader 被排除；deserialize 还必须在源码中看到受支持的 unsafe
  loader/scan marker。
- `fs_path` 需要实际文件系统 consumer，并且 flow 的 tainted segment 位于另一个 root 之下；仅构造
  `.resolve().as_posix()`，或 caller 选择整个 root 后只追加静态文件名，不按当前规则报路径穿越。
- logger 不是 HTML sink；只有源码中存在相应 HTML 输出操作时才保留 `html_output`。

这些大多是 family-level marker 和启发式关系，并非每个 sink 的完整 AST 锚定。除 scan 等专门路径
外，源码中存在同类操作不保证模型给出的 `call_expr` 已被逐字符证明为该调用，因此剩余事实仍需
人工复核。

---

## 6. 跨函数组合

`TaintPlugin.compose_calls()` 自底向上实例化 callee sink：

- 优先使用 caller LLM `call_sites[].args[].flows`；driver binding 中遗漏的参数以
  `unknown:<call-id>:<expr>` 补齐。
- 没有匹配的 LLM call site 时，只能使用 driver binding，并把实参 fail-closed 地当 unknown taint。
- `param:p` 替换为 caller 实参 flows；callee 的具体 source 变成 opaque
  `callee_source:<call-id>:...`；缺失实参变成 tainted unknown。
- callee sink、sanitizer 和 guard coverage 被重锚到 caller。callee return flow 只有在 caller call
  site 给出 `return_expr` 时才加入 caller 的 `taint_bindings`。

Python 会用 AST 确认函数体中确有调用。函数声明、注释和同名 member dispatch 不会被误当作递归；
只有函数体中的 bare same-name call 按递归边组合。其他语言使用去注释文本近似，精度不同。

组合不是全局 top-down 污点求解。插件另有一个有限回溯：若 sink 参数能沿已有绑定回溯到 entrypoint
参数，就预置为 TAINTED；Python 还会从 AST 恢复部分装饰函数参数和位置/关键字实参。无法证明的普通
helper 参数保持 UNKNOWN_PARAM。

---

## 7. 防伪造与信任边界

模型不能直接写入几个确定性内部结论：

- 解析原始响应时，每个 sink 中以下划线开头的字段都会被剥离，因此模型不能直接伪造
  `_validation_guard_coverage` 或 `_via`。
- `_validation_guard_coverage` 只能由 guard evaluator、源码扫描复核或组合器附加；`_via` 只由
  `instantiate_sink()` 附加。带 `_via` 的组合 sink 后续可以绕过 caller 本地 operation filter，因为它
  已在 callee 源码上归一化过。
- 未知 source/sink/context 枚举和畸形 flow 引用由 reasoner 判 `ERROR`。
- 扫描 guard 的内部 coverage、sink ID 重绑和独立 helper contract 需要前述源码证据。

这不是对整个 LLM JSON 的防篡改证明。模型仍负责大量 source、flow、sanitizer 和 sink 参数事实，
family-level operation filter 也不验证每个数据依赖。这里的“防伪造”只表示模型不能直接声明实现保留
的内部确定性字段，且部分高风险结论会被源码规则复核。

---

## 8. 端到端 SQL 示例

```python
# VULNERABLE: tainted value enters SQL syntax
def search_users(request):
    name = request.args.get("name")
    cursor.execute("SELECT * FROM users WHERE name = '" + name + "'")

# SANITIZED: tainted value remains in a bind slot
def search_users_safe(request):
    name = request.args.get("name")
    cursor.execute("SELECT * FROM users WHERE name = ?", (name,))

# POLYMORPHIC in isolation
def run_query(value):
    cursor.execute("SELECT * FROM logs WHERE src = '" + value + "'")
```

- 第一例应有 `source:S1 -> sql_query/sql_query_text`，无有效 sanitizer，因此是 `VULNERABLE`。
- 第二例仍有 tainted flow 和 sink，但 value 的 context 是 `sql_param`，reasoner 直接给
  `SANITIZED`。
- 第三例使用 `param:value`，孤立分析时为 `POLYMORPHIC`；caller 传入具体 source 后，组合 sink 可变为
  `VULNERABLE`。

---

## 9. 适用范围与局限

适合用 Taint 插件快速筛查 SQL、命令、路径、SSRF、XSS、LDAP/XPath 和不安全反序列化候选，并查看
参数化查询、类型化 escape 或 fail-closed scan 是否按当前规则形成正向证据。

使用时应保留以下边界：

- LLM 可能漏 source、sink 或 flow；无报告不是安全证明。
- Python 拥有额外 AST 复核；其他支持语言不具备相同的 config、member state、scan 和调用校正。
- sanitizer 匹配只验证 kind/context/confidence 声明，不验证 sanitizer 实现质量。
- `db_read` 等 stored taint 是近似，跨请求、数据库和异步队列的持久化传播并不完备。
- 反射、别名、复杂动态分派和复杂实参会降低组合精度。
- `SANITIZED` 是当前抽象下的背书事实，`POLYMORPHIC` 需要调用点判断，`ERROR` 不能按安全处理。

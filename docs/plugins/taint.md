# Taint 插件：完整性污点 / 注入检测（Integrity Taint）

> 插件总览见 [./README.md](./README.md)。
> 对偶的机密性插件见 [./ifc.md](./ifc.md)。
> 插件 SPI 架构见 [../plugin_architecture.md](../plugin_architecture.md)。
> 设计动机见 [../security_portfolio_roadmap.md](../security_portfolio_roadmap.md)。

Taint 是 FM-Agent 多理论分析底座上的**第三个**插件，也是 IFC 插件的**对偶（dual）**：把同一
套「LLM 产出**模块化的、逐函数的**自然语言抽象 → 一个**确定性**的纯 Python 检查器（不带 LLM）
在该抽象上做裁决 → 结果自底向上跨函数组合」的通用技术，从**机密性（保密）**翻转到**完整性
（防注入）**——格（lattice）方向整个反过来。

本文档假定你已大致了解 SPI（`src/plugins/base.py`）与通用驱动（`src/plugins/driver.py`）。
下面按「检测什么 → 理论原理 → 运行流程 → 与传统方案对比 → 局限」展开。涉及的源码：

- `src/taint_prompts.py` —— LLM 抽象提示词，产出 `[TAINT_JSON] ... [/TAINT_JSON]`。
- `src/taint_reasoner.py` —— 确定性检查器：3 态格、类型化消毒匹配、source→sink 可达。
- `src/plugins/taint.py` —— SPI 适配器：自底向上 sink 实例化、`check`、`_seed_param_status`。

---

## 1. 面向的攻击：它检测什么

Taint 面向的是 OWASP 的**注入家族（injection family）**——也就是「**不可信输入**未经恰当处理
就抵达了一个**敏感操作点**」这一类漏洞。检查器在 `src/taint_reasoner.py:105` 的 `SINK_TO_FINDING`
表里直接给出了它覆盖的漏洞类型与对应 CWE：

| sink_kind          | 漏洞               | CWE       |
| ------------------ | ------------------ | --------- |
| `sql_query`        | SQL 注入           | CWE-89    |
| `shell_command`    | 命令注入           | CWE-78    |
| `subprocess_argv`  | 参数注入           | CWE-88    |
| `fs_path`          | 路径穿越           | CWE-22    |
| `http_url_ssrf`    | SSRF               | CWE-918   |
| `redirect_location`| 开放重定向         | CWE-601   |
| `html_output`      | XSS                | CWE-79    |
| `template_source`  | 模板注入           | CWE-1336  |
| `deserialize`      | 不安全反序列化     | CWE-502   |
| `code_eval`        | 代码注入           | CWE-94    |
| `ldap`             | LDAP 注入          | CWE-90    |
| `xpath`            | XPath 注入         | CWE-643   |

未命中表的 sink 会回退到通用的 `("INJECTION", "CWE-74")`（见 `finding_kind_for`，
`src/taint_reasoner.py:121`）。

### 一个最小的真实案例：SQL 注入

```python
# 易受攻击：把用户输入直接拼进 SQL 文本
def search_users(request):
    name = request.args.get('name')                 # 不可信输入（source）
    sql = "SELECT * FROM users WHERE name = '" + name + "'"
    cursor.execute(sql)                              # 敏感操作点（sink）
```

`request.args.get('name')` 是一个**不可信输入（source）**；它被拼进 SQL **文本**，然后作为
`cursor.execute(...)` 的参数抵达数据库。这条「未经消毒的污染流抵达 sink」就是一次 SQLi。

与之对照的**安全版本**用参数化查询（bind parameter）：

```python
# 安全：值作为绑定参数传入，不参与 SQL 文本拼接
def search_users_safe(request):
    name = request.args.get('name')                  # 仍是 source
    cursor.execute("SELECT * FROM users WHERE name = ?", (name,))
```

注意一个**关键的设计点**：安全版本里 `name` 依然抵达了 sink——只是它的参数上下文是
`sql_param`（绑定参数），而不是 `sql_query_text`（SQL 文本）。提示词明确要求 LLM **不要省略**
这种 sink，而是把它记成 `arg_context = sql_param` 的 sink，再由检查器判成 **SANITIZED** 而非
「无 sink」（见 `src/taint_prompts.py:107`）。这让「确实做了参数化」这件事成为一个**可被肯定
的事实**，而不是被悄悄忽略。

---

## 2. 理论原理：IFC 的对偶

Taint 与 IFC 共享同一套非干涉（non-interference）骨架，但把**格的方向翻转**：

| 维度       | IFC（机密性 / Bell–LaPadula） | Taint（完整性 / Biba）        |
| ---------- | ----------------------------- | ----------------------------- |
| 起点       | High 机密数据                 | **不可信输入**（source）      |
| 终点       | Low 可观测输出**通道**        | **敏感操作点**（sink）        |
| 「解锁」   | 解密 / 降密（declassify）     | **类型化消毒 / 背书**（sanitizer / endorse） |
| 违规       | High → Low 泄露               | 污点 → sink 注入              |

这正是保密性（Bell–LaPadula，禁止「读上写下」造成泄露）与完整性（Biba，禁止低完整性数据
污染高完整性操作）的对偶。`src/taint_reasoner.py` 的模块 docstring 也明确写了这一点。

但要强调：**这个对偶不是无脑照搬的**。检查器强制了三个区别于朴素信息流的关键点：

### (a) sink 是「操作点」，带类型化的 `arg_context`，不是输出通道

IFC 的 sink 是「日志 / 响应 / 返回值」这类**输出通道**；Taint 的 sink 是「`cursor.execute`、
`os.system`、`open`、`requests.get`、`eval`」这类**敏感操作点**，而且每个 sink 必须携带一个
**类型化的参数上下文 `arg_context`**。`ARG_CONTEXTS`（`src/taint_reasoner.py:54`）枚举了全部
合法上下文，例如同样是 SQL，就细分为 `sql_query_text` / `sql_identifier` /
`sql_numeric_literal` / `sql_param` 四种。

### (b) 消毒器是「类型化」的：背书只对它真正覆盖的上下文有效

这是 Taint 最核心的不变式。一个 sanitizer 只**背书（endorse）**特定的 `arg_context` 集合。
`SANITIZER_ENDORSES` 表（`src/taint_reasoner.py:76`）是一张刻意收紧的「kind → 可背书上下文」
映射，节选：

```python
SANITIZER_ENDORSES = {
    "parameterized_query": {"sql_param"},
    "int_cast":            {"sql_numeric_literal"},
    "html_escape":         {"html_body"},
    "shell_quote":         {"shell_arg_token"},
    "path_containment":    {"fs_path"},
    "url_allowlist":       {"http_url", "redirect_url"},
    # ...
}
```

**类型不匹配的反例**：`html.escape()` 的 kind 是 `html_escape`，只背书 `html_body`。如果它出现
在一个 `arg_context = sql_query_text` 的 SQL sink 的消毒列表里，匹配函数
`has_valid_sanitizer`（`src/taint_reasoner.py:196`）会发现 `required = "sql_query_text"` **不在**
`html_escape` 能背书的 `{"html_body"}` 里，于是**不清除**这条污点流。换句话说：

> HTML 转义能挡 XSS，但**永远挡不住 SQLi**。

`has_valid_sanitizer` 还叠了两道闸门：消毒器的 `confidence` 必须是 `"high"`，且其
`sanitizer_kind` 必须在 `KNOWN_SANITIZER_KINDS`（`src/taint_reasoner.py:62`）里——**未知种类的
消毒器一律被忽略**（fail-closed）。最终是否清除，取 LLM 声明的 `endorses` 与该 kind 在
`SANITIZER_ENDORSES` 里允许集合的**交集**是否覆盖 `required`。

### (c) source 是「调用模式」，不是变量名

提示词反复强调：source 按**代码模式**识别，而非变量名（`src/taint_prompts.py:77`）。
`request.GET[...]` / `request.json` / `request.headers` / `sys.argv` / `input()` / `os.environ`
/ `pickle.loads` 等都是 source；即使被赋给一个看起来人畜无害的变量名，也仍算 source。
`SOURCE_KINDS`（`src/taint_reasoner.py:43`）给出全部合法种类。

### 3 态格与 POLYMORPHIC 的由来

检查器用一个 3 态的操作性格（`src/taint_reasoner.py:20`）：

```
UNTAINTED  <  UNKNOWN_PARAM  <  TAINTED
```

- **外部具体 source** → `TAINTED`（包括兜底的 `unknown_external`，见 `_source_status`，恒为
  TAINTED）。
- **本函数的某个参数、调用者尚未确定其污点** → `UNKNOWN_PARAM`。
- **调用者已证明干净的参数** → `UNTAINTED`。

`UNKNOWN_PARAM` 正是 **POLYMORPHIC（多态）** 裁决的来源：一个函数把它自己的某个参数喂给了
sink，但「这个参数到底脏不脏」要由**调用者**来决定。在它被任何调用者实例化之前，它既不是
确定漏洞、也不是确定安全，故记为 POLYMORPHIC。`resolve_status`（`src/taint_reasoner.py:169`）
就是这套解析逻辑。

### Fail-closed（失败即保守）

整个理论是**失败即关闭**的：

- 不确定输入是否可信 → 当成 source（污染）。
- 未知种类 / 低置信度的消毒器 → 忽略（视为没消毒）。
- `validate()`（`src/taint_reasoner.py:127`）遇到越界枚举（未知 `source_kind` /`sink_kind` /
  `arg_context`）或畸形 source 引用 → 直接判 **ERROR**，绝不静默判 SAFE。
- LLM 抽象失败（`payload` 为空 / status=error）→ 插件 `check` 直接返回 ERROR（`taint.py:218`）。

裁决优先级（`src/taint_reasoner.py:25`）：

```
ERROR > VULNERABLE > POLYMORPHIC > SANITIZED > SAFE
```

---

## 3. 插件运行流程（与 SPI 集成）

驱动按 SPI 生命周期、**自底向上**驱动每个函数：`build_abstraction_prompt` → LLM →
`parse_abstraction_response` → `compose_calls` → `check`。

### 3.1 LLM 抽象：`[TAINT_JSON]`

LLM 对单个函数只输出**事实**，不下裁决（`src/taint_prompts.py:72`）。它产出一个被
`[TAINT_JSON] ... [/TAINT_JSON]` 包裹的 JSON（由 `_extract_taint_json` 解析，
`src/taint_prompts.py:38`）。顶层字段全部必填，没有就给空列表。真实形状（取自
`src/taint_prompts.py:143` 的模板）：

```json
{
  "schema_version": "taint.v1",
  "function": "search_users",
  "language": "python",
  "params": ["request"],
  "taint_sources": [
    {"id": "S1", "source_kind": "http_param", "expr": "request.args.get('name')",
     "introduced_by": "flask query param", "confidence": "high"}
  ],
  "sanitizers": [],
  "taint_bindings": [
    {"expr": "name", "flows": [{"source": "source:S1", "sanitizers": []}]}
  ],
  "return_flows": [],
  "param_mutations": [],
  "call_sites": [],
  "sinks": [
    {"id": "K1", "sink_kind": "sql_query", "callee": "cursor.execute",
     "call_expr": "cursor.execute(sql)", "arg_position": 0, "arg_expr": "sql",
     "arg_context": "sql_query_text",
     "flows": [{"source": "source:S1", "sanitizers": []}]}
  ],
  "notes": []
}
```

每条 `flows[].source` 必须用三种前缀之一（source 引用文法，`src/taint_prompts.py:118`）：

- `source:<id>` —— 本函数内的一个具体 source；
- `param:<name>` —— 来自本函数参数的符号化污点（供调用者实例化）；
- `unknown:<id>` —— fail-closed 的未知外部源。

（检查器的 `_valid_source_ref` 还额外接受组合阶段产生的 `callee_source:` 前缀。）

### 3.2 `check`：source→sink 可达 + 类型化消毒匹配

`classify`（`src/taint_reasoner.py:221`）逐 sink 遍历它的每条 flow：

1. `resolve_status` 把 flow 的 source 解析成 `TAINTED` / `UNKNOWN_PARAM` / `UNTAINTED`。
2. `UNTAINTED` 的流跳过；其余的标记该 sink「相关」。
3. 对相关流跑 `has_valid_sanitizer` 做**类型化消毒匹配**；命中则清除，否则按其状态记为
   具体漏洞（`concrete_vuln`）或多态（`param_vuln`）。
4. 按该 sink 的所有流聚合：全部被消毒 → SANITIZED；存在具体污染未消毒 → VULNERABLE；否则
   存在多态未消毒 → POLYMORPHIC。

函数级裁决再按优先级在所有 sink 的结论上聚合。在插件层 `check`（`src/plugins/taint.py:212`）
里，每条 finding 被映射成 SPI 的 `Finding`，并按状态赋严重度：VULNERABLE → `high`，
POLYMORPHIC → `low`，SANITIZED → `info`。

入口函数还会先跑 `_seed_param_status`（`src/plugins/taint.py:198`）：若 LLM 把某个参数本身标成
了 `untrusted_param`，则在入口处把该参数**预置为 TAINTED**；其余参数保持 UNKNOWN_PARAM（即
保持 POLYMORPHIC，直到有调用者实例化）。这是一种保守的、**无需全局 top-down**的播种
（`metadata.requires_top_down_context = False`，`src/plugins/taint.py:82`）。

### 3.3 `compose_calls`：自底向上的 sink 实例化

这是 Taint 与 IFC 同属「自底向上组合」的核心（对比 authz 的自顶向下义务传播）。
被调用者（callee）的一个**参数化 sink**（`param:x → sql_query`）会在调用者（caller）的调用点
被**实例化**，代入调用者**实际传入的参数污点**。逻辑在 `compose_calls`
（`src/plugins/taint.py:134`），底层工具是 `instantiate_sink` / `instantiate_flows`
（`src/taint_reasoner.py:343` / `:317`）：

- 用 `_match_call_site` 按名字找到调用者 LLM 记录的 `call_site`，从其 `args` 构造
  `param_to_actual`（callee 形参名 → 调用者实参的 flows）。
- 若找不到（只有驱动正则推断出的 `arg_bindings`），就 **fail-closed**：把每个实参当成
  `unknown:<call_id>:<expr>`（即未知污染）。
- 对 callee 的每个 sink 调 `instantiate_sink`：sink 被重锚到调用者，`param:p` 被替换为调用者
  传给 `p` 的实际 flows；callee 的具体 source 变成不透明的 `callee_source:<call_id>:...`；缺失
  实参回退成 `unknown:<call_id>:missing_arg:p`（仍是污染）。
- 实例化后的 sink 追加进调用者的 `sinks`，于是调用者再跑 `check` 时，**只要它传了一个污染的
  实参，这个继承来的 sink 就让调用者判 VULNERABLE**。

### 3.4 端到端示例

把三种典型函数串起来看：

```python
# (1) 直接拼 SQL 文本 —— VULNERABLE
def search_users(request):
    name = request.args.get('name')
    cursor.execute("SELECT * FROM users WHERE name = '" + name + "'")

# (2) 参数化查询 —— SANITIZED
def search_users_safe(request):
    name = request.args.get('name')
    cursor.execute("SELECT * FROM users WHERE name = ?", (name,))

# (3) 把参数喂给 SQL 文本的辅助函数 —— 自身 POLYMORPHIC
def run_query(table_filter):
    cursor.execute("SELECT * FROM logs WHERE src = '" + table_filter + "'")

# (4) 用 request 数据调用 (3) 的入口 —— 经组合后 VULNERABLE
def handle(request):
    run_query(request.args.get('q'))
```

- **(1) VULNERABLE**：source `S1` 直达 `sql_query` sink，`arg_context = sql_query_text`，无消毒
  → `concrete_vuln` → VULNERABLE（CWE-89）。
- **(2) SANITIZED**：sink 仍在，但 `arg_context = sql_param`，且带一个
  `parameterized_query`（背书 `{"sql_param"}`、`confidence: high`）的消毒器 → `all_sanitized`
  → SANITIZED。
- **(3) POLYMORPHIC**：sink 的 flow 是 `param:table_filter`。在 `run_query` 自身分析时调用者未
  知 → `UNKNOWN_PARAM` → `param_vuln` → POLYMORPHIC。它对应的 sink JSON 形如：

  ```json
  {"id": "K1", "sink_kind": "sql_query", "arg_context": "sql_query_text",
   "flows": [{"source": "param:table_filter", "sanitizers": []}]}
  ```

- **(4) VULNERABLE（经组合）**：分析 `handle` 时，`compose_calls` 把 `run_query` 的 K1 实例化到
  调用点：`param:table_filter` 被代入 `handle` 传入的实参 `request.args.get('q')` 的 flows
  （一个 `http_param` 的污染源）。实例化后的 sink 携带 `TAINTED` 流抵达 `sql_query` →
  `handle` 判 VULNERABLE。污点在 sink 处被「兑现」，组合发生在调用边上。

---

## 4. 我们的方案 vs 传统（非 LLM）污点分析

传统污点 / 注入检测的代表：

- **CodeQL**：用 QL 写数据流查询，配 source/sink 谓词与 `isBarrier`（屏障，相当于消毒）。
- **Meta Pysa / Zoncolan**：在 `taint.config` 里配 source / sink / sanitizer 三元组，并用
  **类型化的 `@Sanitize`** 注解（按特定 taint 种类背书）。
- **Semgrep taint mode**：用 `pattern-sources` / `pattern-sinks` / `pattern-sanitizers` 规则。

### 我们的优势

- **语义识别，无需逐框架手写模型**。LLM 直接按语义认出 source / sink / sanitizer，不必为每个
  Web 框架预先写好访问器模型（`request.args`、`req.query`……）。
- **类型化消毒匹配，但是「推断」出来的**。`SANITIZER_ENDORSES` + `arg_context` 的设计与 Pysa 的
  类型化 `@Sanitize` 同形——但映射由 LLM 从代码语义推断，而非人工配置。
- **能跑在陌生框架 / 自研封装上**：只要 LLM 看得懂代码意图即可，不依赖现成规则库。
- **模块化组合**：逐函数抽象 + 自底向上实例化，天然跨函数、跨文件复用 callee 事实。

### 我们的劣势（需诚实对待）

- **不可靠（unsound）**：基于 LLM 抽象，没有可靠性保证，会漏报。
- **source/sink 覆盖缺口**：遇到完全陌生的框架访问器，可能被 LLM 漏标（虽有 `unknown_external`
  兜底，但兜底依赖 LLM 先意识到「这越过了信任边界」）。
- **消毒器过度信任的风险**：若 LLM 误把某个其实不充分的函数标成 `confidence: high` 且
  `endorses` 覆盖了该上下文，检查器就会据此清除污点——类型化匹配能挡住「类型不匹配」的错，但挡
  不住「类型正确但实现有缺陷」的消毒器。
- **二阶 / 存储型污点（stored taint）只能近似**：`db_read` 这类「可能被用户写过的数据」只是一
  个保守标注，跨请求、跨存储的污点追踪并不精确。
- **真实 CVE 的召回率本就很难**：注入类漏洞的召回是公认的难题——即便是成熟的 CodeQL，在 npm
  生态的 CVE 上召回也只有约 31%。我们的方案在工程化与陌生代码上更灵活，但不应被理解为「召回率
  上的银弹」。

总体而言：**它擅长在陌生 / 自研代码上快速给出有语义依据的判断，但不可作为唯一的安全保证。**

---

## 5. 局限与适用场景

- **适用**：在大型 / 陌生 / 多框架混杂的代码库上做注入面的**广撒网式初筛**；标出
  POLYMORPHIC 的「污点传递型」辅助函数，提示「调用点才是危险所在」；确认参数化 / 类型化消毒
  确实存在（SANITIZED 是可被肯定的正向事实）。
- **不适用 / 慎用**：作为合规级别的 sound 证明；依赖它的「无报告」来断言代码安全（unsound，
  会漏）；高度依赖运行时配置 / 反射 / 动态分发的复杂数据流；以及对消毒器**实现质量**的判断
  （它只判类型是否匹配，不判实现是否真的安全）。

把 Taint 当作一个**会读语义、可跨函数组合、失败即保守**的注入面探针——它的结论是有用的线索与
正向佐证，但最终的安全结论仍需人工复核与（在可能时）动态验证来补强。

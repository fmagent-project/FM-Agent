# IFC 插件：信息流控制（Information Flow Control）

> 插件总览见 [./README.md](./README.md)。
> 设计动机与改动地图见 [../ifc_design.md](../ifc_design.md)。
> 插件 SPI 架构见 [../plugin_architecture.md](../plugin_architecture.md)。

IFC 是 FM-Agent 多理论分析底座上的**第一个、也是参考实现**插件。它把 FM-Agent 的通用技
术——「LLM 产出**模块化的、逐函数的**自然语言抽象，一个**确定性**的纯 Python 检查器（不
带 LLM）在该抽象上做裁决，结果自底向上跨函数组合」——具体落到**机密性（confidentiality）/
信息流泄露**这一安全属性上。

本文档假定你已经大致了解 SPI（`src/plugins/base.py`）和通用驱动（`src/plugins/driver.py`）。
下面按「检测什么 → 理论原理 → 运行流程 → 与传统方案对比 → 局限」展开。

---

## 1. 面向的攻击：它检测什么

IFC 检测的是**机密性泄露**：私密数据（secret）经由某条信息流，到达了一个**公开侧 / 可观测
的出口（Low-observable sink）**。这些出口在代码里非常常见：

- 日志（`logger.debug(...)`）
- HTTP 响应、网络发送
- 写入全局变量 / 共享状态
- 函数返回值（当函数是对外入口时，返回值就跨过了信任边界）

### 一个最小的真实案例

```python
class ApiClient:
    def __init__(self, client_id, client_secret):
        self.client_id = client_id          # 公开标识
        self.client_secret = client_secret  # 私密凭据

    def _debug_request(self, url):
        # 看似无害的调试日志，却把 client_secret 写进了日志文件
        logger.debug("calling %s with id=%s secret=%s",
                     url, self.client_id, self.client_secret)
```

`self.client_secret` 是机密（High），`logger.debug(...)` 是一个公开可观测的出口
（`io:log`，Low）。这条 `High → Low` 的流就是一次泄露。

另一个经典形态是把数据库口令拼进返回的连接串（DSN）：

```python
class DBClient:
    def build_dsn(self):
        # db_password 是 High；返回值若被对外暴露/记录就是泄露
        return f"postgres://{self.user}:{self.db_password}@{self.host}/{self.db}"
```

### 为什么这件事重要、为什么朴素检查会漏

1. **隐式流（implicit flow）**。泄露不一定是「把 secret 直接打印出来」。下面的代码没有任何
   一行「碰」了 `secret` 的内容，却通过**控制流**把它泄露了出去：

   ```python
   if secret_bit:        # 分支条件依赖 secret
       public_out = 1
   else:
       public_out = 0
   # public_out 的取值完全由 secret_bit 决定 → 1 bit 泄露
   ```

   基于「字符串里是否出现了某个变量」的朴素 grep/污点匹配看不到这种流。

2. **跨函数（cross-function）**。`build_dsn()` 自己可能只是「返回一个字符串」，看起来无害；
   真正的泄露发生在**调用方**把这个返回值丢进了日志或响应。单函数视角会漏掉端到端的路径。

IFC 插件同时覆盖这两类：隐式流由 LLM 在阅读完整函数体时自然推理，跨函数流由驱动的自底向上
组合 + 参数化流签名的实例化来串联。

---

## 2. 理论原理

### 2.1 非干涉性（Non-interference, Goguen–Meseguer 1982）

机密性的形式化定义是**非干涉性**：

> 把输入分成 High（私密）与 Low（公开）两部分。如果**任意两次执行，只要 Low 输入相同，
> Low 输出就必然相同**（与 High 输入怎么变无关），则该程序对 Low 攻击者满足非干涉性。

直觉上：一个只能观测 Low 的攻击者，无法通过观测 Low 输出反推出任何 High 输入的信息。
**违反非干涉性 = 存在一条 `High → Low` 流 = 泄露。**

### 2.2 二级安全格（High/Low lattice）

第一期使用最小的二级格：`Low < High`，join 规则 `join(High, 任意) = High`。这是
Bell–LaPadula「no read up / no write down」机密性方向的格。代码里见
`src/ifc_reasoner.py`：

```python
HIGH = "High"
LOW  = "Low"
UNKNOWN = "Unknown"   # 第三个「待定」标签，确定性检查器把它 fail-closed 成 High
```

`UNKNOWN` 不是格里的真实元素，而是「LLM 拿不准这个输入是否敏感」时的标记。
`_normalize_label()` 在 `IFC_FAIL_CLOSED=True`（默认）下把 `Unknown` 折叠成 `High`——
**宁可误报，不可漏报**。

### 2.3 关键降维：2-safety hyperproperty → 逐函数参数化依赖分析

非干涉性本质是一个 **2-safety 超属性（hyperproperty）**：它谈的是「两次执行之间的关系」，
而不是单次执行的性质。传统验证它需要 **self-composition**（把程序和自己的一份拷贝拼起来，
再交给 SMT 证明），代价很高。

IFC 插件做了一个关键降维：

> 把「Low 输出是否依赖 High 输入」重写成「**每条输出通道依赖哪些输入源**」的依赖分析。

也就是说，每个函数被抽象成一张**参数化流签名（parametric flow signature）**：

```
输出通道(channel)  ←  它所依赖的输入源集合(deps)
```

注意 `deps` 列的是**输入源**（`param:x`、`receiver.client_secret`、`global:g`），**不是**
写死的 High/Low。这就是「参数化」的含义：`identity(x)` 的返回值依赖 `{param:x}`，
**无论 x 本身是不是机密**。正因如此，跨函数组合才是 sound 的——调用方用**自己实际传入的实
参标签**去实例化被调用方的签名（assume-guarantee）。依赖分析天然**模块化、可组合**，于是 2-
safety 被降到了单函数级别，正好嫁接到 FM-Agent 的自底向上调用链上。

### 2.4 隐式流如何被纳入

prompt（`src/ifc_prompts.py:_system_prompt`）显式要求 LLM 把隐式流计入 `deps`：

> 「如果一个值是在某个 `if/loop/early-return/exception` 之下被赋值或被产生的，而那个守卫
> （guard）依赖某个输入，那么这个值也依赖该输入。`break/continue/return/throw` 在守卫之下
> 也会污染受影响的通道。」

因为 LLM 一次看到**整个函数体**，嵌套控制流是在它「脑内」整体推理的，FM-Agent 不需要像传
统数据流分析那样跨基本块维护 pc-label 栈（对 break/continue/异常/提前返回都很难维护正确）。

### 2.5 降密（Declassification）：唯一的逃生口

有些 `High → Low` 流是**有意且语义必需**的，例如口令校验返回一个「匹配/不匹配」的 1-bit、
发布一个单向哈希。这类流通过 `declass` 字段标注（带 `anchor` 锚点语句 + `reason` 理由）。

关键安全约束：**降密只是「提议」，绝不自动放行**。它仅适用于已明确标为 High 的源，不能用
Unknown 推测凭空制造降密审查。有效提议产生一个独立的 `DECLASSIFIED` 裁决，
强制人工复核。这避免了「LLM 既推断标签又自判降密，把任何泄露都洗成『有意降密』」的循环
论证（见 `../ifc_design.md` §5 风险 1）。

### 2.6 五种裁决（verdict）

`classify()`（`src/ifc_reasoner.py`）在确定性地评估每条 Low-observable 通道后给出：

| verdict | 含义 |
|---|---|
| `LEAK` | 某条 Low-observable 通道因**真正的 High 源**（命名/策略判定为 High 的参数、High 全局、`const:High`，或未声明的全局/接收者）变成了 High，且未被降密。**确认泄露**。 |
| `DECLASSIFIED` | 该 `High → Low` 流被带锚点的降密提议覆盖。**待人工复核**，不是放行。 |
| `POLYMORPHIC` | 某条 Low-observable 通道变 High **仅仅因为一个 `Unknown` 标签的参数（`param:*`）**。是否真泄露取决于调用方实际传入什么，单看本函数无法判定——留待调用点用 `instantiate_callee()` 解析。`identity(x)` 这类纯透传不会被误报成 LEAK，正是靠它。 |
| `SECURE` | 所有 Low-observable 通道都是 Low。 |
| `ERROR` | 没有有效流签名（fail-closed：**绝不静默判成 SECURE**）。 |

---

## 3. 插件运行流程（与 FM-Agent / SPI 集成）

### 3.1 生命周期总览

通用驱动 `src/plugins/driver.py:run_plugin()` 是理论无关的，它对 IFC 插件
（`src/plugins/ifc.py:IfcPlugin`）的调用顺序如下：

```
Stage 1  扫描 + 抽取函数              callgraph.load_function_units
Stage 2  构建调用图                   callgraph.build_program_index
         自底向上排序（callee 先于 caller）   callgraph.order_bottom_up
Stage 3  对每个函数（自底向上）：
           a. 收集已分析 callee 的摘要   plugin.summarize_for_caller
           b. build_abstraction_prompt → LLM（带重试/fail-closed）
           c. parse_abstraction_response → FactEnvelope
           d. compose_calls            实例化 callee 签名于各调用点
Stage 4  对每个函数：
           plugin.check(...)          → 确定性 classify() → Verdict
           plugin.render_result(...)  → 写 <func>.json
         plugin.render_summary(...)   → summary.json
```

IFC 的 `metadata` 声明 `needs_entrypoint=True`（检查器把入口函数的返回值当外部出口），
`requires_top_down_context=False`（IFC 是纯自底向上，不需要自顶向下的上下文 worklist）。
支持语言：python / javascript / typescript / go / java / c / cpp / rust / cuda / arkts。

### 3.2 LLM 抽象步：参数化流签名 [FLOW_JSON]

`build_abstraction_prompt()` 给函数源码逐行编号，注入已分析 callee 的摘要，调用
`ifc_prompts._system_prompt / _user_prompt`。LLM 必须返回**唯一一个**用
`[FLOW_JSON] ... [/FLOW_JSON]` 包裹的 JSON 对象。`_extract_flow_json()` 负责抽取；抽取
失败时驱动追加一轮「格式纠正」对话并重试，最多 `MAX_IFC_ITER`（默认 5）次，仍失败则
`make_error_facts()` 产出 `status="error"` 的 fail-closed facts。

JSON 的 schema（来自 `ifc_prompts._user_prompt`）：

```json
{
  "inputs": {
    "param:<name>": "High|Low|Unknown",
    "global:<name>": "...",
    "receiver.<attr>": "..."
  },
  "outputs": {
    "<channel>": {
      "deps": ["param:<name>", "receiver.<attr>", "global:<g>"],
      "const": null,
      "sink_channel": "return|exception_control|exception_message|error_detail|log|stdout|network|database|shared_state|parameter|unknown",
      "observability": "external|caller|internal",
      "declass": [{"anchor": "<exact stmt>", "reason": "<why intended>"}]
    }
  },
  "notes": "<one-line summary of the dominant flow>"
}
```

输出通道（channel）的取值约定（`_CHANNELS_DOC`）：

- `return` — 返回值的依赖
- `exception` — **是否**抛异常的依赖（仅当异常是基于某个源的**值**抛出时才记，如
  `if secret < 0: raise`；纯类型/运行时错误不算值依赖流）
- `exception:message` — 交给 caller/用户的异常文本或细节依赖
- `error:<destination>` — 写入 framework message、HTTP/API/UI/CLI 错误结果的细节依赖
- `param:<name>.*` — 写进某个可变参数/接收者属性的依赖
- `global:<name>` — 写进某个全局的依赖
- `io:<sink>` — 副作用（log/stdout/network/db）的依赖；是否公开由 `observability` 独立决定
- `termination` — 是否终止的依赖。**仅为完整性记录，不计入泄露裁决**
  （termination-insensitive 非干涉性）

prompt 里有三条「load-bearing」的拆分规则，直接决定精度：

1. **接收者属性逐属性**：`self.client_secret` → `receiver.client_secret`（High），
   `self.base_url` → `receiver.base_url`（Low）。**绝不**塌成一个 `receiver` 整体，
   也不让一个机密属性污染整个 `self`。
2. **容器字段逐字段**：`request.get("password")` → `param:request.password`（High），
   即便 `request` 本身是 Low。Low 容器不掩盖敏感字段，敏感字段也不污染整个容器。
3. **标签从命名推断**：`password/secret/token/key/hash/ssn/credential` → High；
   `id/name/url/host/port/path/timeout/count/index/flag` → Low；拿不准 → `Unknown`。

每个输出还必须声明两个正交字段：`sink_channel` 描述出口类型，`observability` 描述该出口的
信任边界。`external` 表示未授权 actor、API/UI/CLI 客户端、stdout 消费者或公网 peer 可见；
`caller` 表示仅传播给直接调用者，直到入口边界才成为公开出口；`internal` 表示可信运维日志或
内部状态，本身不构成公开泄露。同一个 `except` 中的通用外部错误与详细内部日志必须建成两条
独立输出：内部日志的 High 依赖不能污染已经脱敏的外部错误；反过来，`catch` 本身也不会清除
随后复制到外部 message 的异常细节。

`src/ifc_validation.py` 对 LLM JSON 做 fail-closed 结构校验并补充 Python 源码可确定的事实：
异常细节是否进入客户端消息或抛出的异常文本，以及通用 options 容器是否在正常 redaction
注册之后把嵌套敏感字段合并到已有模型或本地源码证明的日志/stdout 出口；框架对象把自己的
参数状态经 `exit_json` 序列化到 stdout 也属于源码可确定的外部出口。单独的 merge 或 logger
语法不能凭空创建出口、流或 trust boundary；固定代码在合并前 fail-closed 拒绝、删除或用
常量覆盖敏感字段时，不再生成该 High 字段流。保护状态按每次 merge 和每个敏感字段分别计算，
因此只清除已确定处理的字段，仍未处理的敏感字段继续流向外部出口。无依赖的常量
`exception_control` 表示每次运行都相同的异常发生事实，不携带 High 信息，源码规范化为 Low。

### 3.3 解析与组合

`parse_abstraction_response()` 把 JSON 包进 `FactEnvelope(payload=signature)`。

`compose_calls()` 是 IFC 的组合算子。它按调用顺序遍历每个已解析的 callee，用
`_arg_label()` 把调用点的**实参表达式**翻译成 caller 上下文中的标签：

- 字符串/数字字面量 → `Low`
- 裸的 caller 参数名 → 该参数在 caller 里的标签
- 其它（复杂表达式）→ `Unknown`（保守）

然后调用 `instantiate_callee(callee_sig, binding)`：把 callee 形参源替换成实参标签，
逐通道求值，得到「该调用点观测到的」callee 输出标签。结果记到 caller payload 的
`_callee_resolutions` 里。

`instantiate_callee()` 保留 callee 的 `sink_channel` 与 `observability`。除
`_callee_resolutions` 审计记录外，`compose_calls()` 还把 callee 的 `external` 和 `caller`
sink 实例化到 caller 的确定性输出集合，因此 caller 不会因为自己的 LLM 签名漏写 callee
side effect 而被误判安全。`internal` sink 不会被提升成 external；同名候选不明确时保留全部
候选义务，`caller` sink 仍只在最终入口边界成为公开出口。

### 3.4 确定性检查器与信任边界

`check()` 在 `status=="error"` 或 payload 为空时直接判 `ERROR`（fail-closed）；否则调用
`classify(payload, is_entrypoint=context.is_entrypoint)`。

信任边界由 `_is_low_observable_for()` 决定一条通道是否真的到达**外部** Low 出口：

- `observability=external` — 无论函数是否入口都是真正外部出口。
- `observability=internal` — 可信内部日志/状态不是公开出口，不能单独触发泄露。
- `observability=caller` — 仅在函数到达入口边界时成为外部出口。
- 未带新字段的旧 `io:*` / `global:*` — 为兼容和 fail-closed 仍按外部出口处理。
- `param:<name>.*`（写进参数）— 仅当目标参数是 **Low** 时才算外部出口（写进 High 参数没问题）。
- `return` / `exception` — **仅当函数是入口（`is_entrypoint=True`）**才算外部出口；此时返回值
  跨过信任边界流向外部世界（如 HTTP handler 的响应）。若函数有内部调用方，返回值只是
  「传播」，由调用方通过 `instantiate_callee` 决定，**不在本函数独立计为泄露**——这消除了
  「把 secret 返回给自己可信调用方」这一类主导性误报。
- `termination` — out of scope。

公开 error detail 映射为 CWE-209，公开日志泄露映射为 CWE-532，其余敏感信息暴露映射为
CWE-200；跨 caller 边界暴露详细自定义异常时使用更宽泛的 CWE-200。

随后 `_classify_channel()` 区分 `genuine_high`（命名 High 参数 / High 全局 / `const:High` /
未声明的非参数源）、`conditional`（`Unknown` 的参数源）与 `low`，最终聚合成 verdict：
有 genuine 违规 → `LEAK`；否则有降密 → `DECLASSIFIED`；否则有 conditional → `POLYMORPHIC`；
否则 `SECURE`。`render_gaps()` 为 `LEAK/DECLASSIFIED/POLYMORPHIC` 产出
`{high_sources, unknown_params, leaking_channel, flow_deps, declass_note, notes}`。

### 3.5 端到端实例

回到 §1 的 DSN 例子。被调用方 `build_dsn` 的 LLM 流签名：

```json
{
  "inputs": {
    "receiver.user": "Low",
    "receiver.db_password": "High",
    "receiver.host": "Low",
    "receiver.db": "Low"
  },
  "outputs": {
    "return": {
      "deps": ["receiver.user", "receiver.db_password", "receiver.host", "receiver.db"],
      "const": null
    }
  },
  "notes": "returns a DSN string embedding db_password"
}
```

- 若 `build_dsn` **是入口**：`return` 是外部出口；`deps` 含 `receiver.db_password`（非参数、
  High）→ `genuine_high` → **LEAK**。
- 若 `build_dsn` **有内部调用方**：`return` 不是独立出口，`classify` 跳过该通道 → 本函数
  孤立看是 `SECURE`，泄露留待调用方处理。

调用方 `handle_debug_db`：

```python
def handle_debug_db(client):
    dsn = client.build_dsn()
    logger.debug(dsn)        # io:log 出口
```

驱动在分析 `handle_debug_db` 时，prompt 里已带入 callee 摘要
`build_dsn: return<-{receiver.user,receiver.db_password,receiver.host,receiver.db}`。
LLM 因此知道 `dsn` 携带 `receiver.db_password`，产出：

```json
{
  "inputs": {},
  "outputs": {
    "io:log": {"deps": ["receiver.db_password"], "const": null}
  },
  "notes": "logs a DSN that embeds the DB password"
}
```

`io:log` 永远是外部出口，`receiver.db_password` 是 genuine High → `classify()` 判
**LEAK**，`render_gaps` 给出 `leaking_channel="io:log"`、`high_sources=["receiver.db_password"]`。
同时 `compose_calls` 在 `_callee_resolutions` 记下：`build_dsn` 在此调用点的 `return` 解析为
`{"label": "High"}`，作为平行佐证。

---

## 4. 我们的方案 vs 传统非 LLM 的 IFC

### 传统方案

- **类型系统 IFC（JFlow / Jif、FlowCaml）**：把安全标签做进类型系统，编译期强制非干涉性。
  需要**源码标注**（给每个变量/字段写 label）+ 一个**专用编译器**。
- **self-composition + SMT**：把程序与拷贝拼接，用 SMT 求解器证明 2-safety。精确但重，难
  扩展到大型真实代码。
- **静态污点分析（taint engines）**：source→sink 可达性。工程上可用，但通常**漏隐式流**，
  且 source/sink 规则要人工配置。

### 我们的 LLM 方案的优点

- **零源码标注**：不需要给代码加 label，不需要专用编译器。标签由 LLM 从**命名/类型/领域上
  下文**推断（`client_secret`→High，`base_url`→Low）。
- **天然捕捉隐式流**：LLM 整体阅读函数体，控制流依赖在「脑内」就被算进 `deps`，无需维护
  pc-label 栈。
- **直接作用于未改动的真实代码**，且**跨多种语言**（Python/JS/TS/Go/Java/C/C++/Rust/CUDA/ArkTS）。
- **模块化、可组合**：参数化流签名 + assume-guarantee 让跨函数追踪自底向上自动成立。

### 我们的方案的缺点（务必诚实）

- **不 sound（不健全）**：LLM 可能给错标签或漏掉一条流。这是一个 **bug-finder（找 bug 的
  工具），不是 verifier（证明器）**——「没报 LEAK」**不等于**「证明安全」。
- **依赖模型能力**：弱模型会幻觉、误标，结论可信度随之下降（见 README 的模型选择建议）。
- **格太粗**：只有 High/Low 两级，无法表达多级机密或区室化（compartment）策略。
- **复合字段分解仍有缺口**：尽管 prompt 强制「逐属性/逐字段」拆分，真实世界里仍会漏。一个
  实测的 `requests` 库 CVE 漏报就是：凭据被嵌进了一个 **dict 里某个 proxy URL** 中，整个
  dict/URL 被当成了 Low，未能把内嵌的 credential 拆成独立 High 源（对应函数层级里的
  `sessions-py/rebuild_proxies.py` 一类）。深层嵌套结构里的机密字段是当前最薄弱的一环。
- **确定性兜底是「保守」而非「正确」**：`Unknown` 一律 fail-closed 成 High，会带来误报
  （这正是 `POLYMORPHIC` 这一档存在的原因——把「调用方才能定」的情况隔离出来）。

---

## 5. 局限与适用场景

**第一期只保证 termination-insensitive non-interference。** 明确 out-of-scope 的隐蔽信道：
时间信道、终止信道、缓存信道；异常信道仅在「基于值抛出」时才计入。不要误以为它能挡住所有
泄露。

**适合用它**：在大型、未标注、多语言的真实代码库里**快速找出**机密性泄露的候选点（凭据进
日志/响应/DSN、隐式流泄露、跨函数泄露路径），尤其作为人工 review 前的高召回筛子。

**不要用它**：当作泄露不存在的**证明**，或作为合规性/认证级别的安全保证。`SECURE` 仅代表
「在 LLM 推断的标签与依赖下未发现违规」，`DECLASSIFIED` 永远需要人工复核，`POLYMORPHIC`
需要结合调用点判断，`ERROR` 表示分析未能完成（fail-closed，不可当安全）。

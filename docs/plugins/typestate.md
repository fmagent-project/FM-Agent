# 时序协议 / 状态机插件（Typestate / Temporal-Protocol）

> 插件索引：[./README.md](./README.md)

本文档介绍 FM-Agent 的**第五个**分析插件 `typestate`。它检测的不是「值从哪流到哪」，而是**事件发生的先后顺序**——即一类**时序（ordering）漏洞**：TOCTOU、CSRF、TLS 校验被关闭、资源生命周期、特权操作前缺少鉴权。

阅读本文前你不需要懂前四个插件。FM-Agent 的通用范式只有一句话：

> **LLM 负责产出每个函数的、模块化的自然语言抽象（facts）；一个不含 LLM 的、确定性的 Python 检查器负责下判定（verdict）；判定结果跨函数（interprocedural）组合。**

`typestate` 严格遵循这个分工：LLM 只报告**它观察到的有序事件**（映射到一套固定的抽象事件字母表），**绝不下结论、也绝不自己写自动机**；判定完全由 `src/typestate_reasoner.py` 里的确定性代码做出。

它有一处独特之处：在前四个插件里，组合（composition）要么是纯自底向上（IFC/污点/加密），要么主要是自顶向下（authz）。`typestate` **两个方向都用**：

- **自底向上（bottom-up）**：把被调用函数导出的事件「拼接（splice）」进调用者的有序事件序列——例如被调函数返回了一个打开的资源，或对传入的 request 做了 `STATE_CHANGE`。
- **自顶向下（top-down）**：一个「必需事件」（如 CSRF 校验、鉴权检查）可能由**祖先调用者**完成，因此把已建立的上下文沿调用图向下传播，去**抵消（discharge）**被调函数的「必需事件先于触发」义务。

正因为时序属性同时牵涉**顺序**与**路径覆盖**，它是这套通用范式里**最不「干净」契合**的属性类。所以 v1 是**刻意收窄的**：宁可漏报为 `NEEDS_REVIEW`，也不静默判 `SAFE`。

SPI 适配器见 `src/plugins/typestate.py`；通用 driver 见 `src/plugins/driver.py`；插件契约见 `src/plugins/base.py`。

---

## 1. 它防的是什么攻击（What it detects）

所有目标漏洞都有一个共同点：**代码里出现的语句单独看都没问题，问题出在它们的相对顺序、或某个必需步骤在某条路径上缺席**。这是**顺序属性（order property）**，不是**值流属性（value-flow property）**——没有一个「污染源 → 汇聚点」的数据流可追踪，只有「坏事件不得先于/缺少必需事件而发生」。

判定结果对应的 finding 种类、CWE 与判定（取自 `FINDING_KINDS` 与 `_KIND_VERDICT`，`typestate_reasoner.py:75`）如下：

| Finding kind | CWE | 判定 | 含义 |
|---|---|---|---|
| `TOCTOU_CHECK_THEN_USE` | CWE-367 | VULNERABLE | 检查后非原子地使用，存在竞态 |
| `CSRF_MISSING_VALIDATION` | CWE-352 | VULNERABLE | 状态变更前缺少 CSRF 校验 |
| `TLS_VERIFY_DISABLED_USE` | CWE-295 | VULNERABLE | TLS 校验被关闭后仍发起网络使用 |
| `TLS_VERIFY_UNKNOWN` | CWE-295 | NEEDS_REVIEW | TLS 校验状态无法判定 |
| `RESOURCE_LEAK` | CWE-772 | VULNERABLE | 资源在某条路径上未释放（泄漏） |
| `FILE_HANDLE_LEAK` | CWE-775 | VULNERABLE | 文件句柄泄漏 |
| `USE_AFTER_RELEASE` | CWE-672 | VULNERABLE | 关闭后仍使用 |
| `DOUBLE_RELEASE` | CWE-415 | VULNERABLE | 重复关闭 |
| `AUTH_MISSING_BEFORE_PRIVILEGED_ACTION` | CWE-306 | VULNERABLE | 特权操作前缺少认证 |
| `AUTHZ_MISSING_BEFORE_PRIVILEGED_ACTION` | CWE-862 | VULNERABLE | 特权操作前缺少授权 |
| `CALLER_DEPENDENT_REQUIRED_EVENT` | —（无 CWE） | POLYMORPHIC | 必需事件可能由调用者满足 |
| `UNKNOWN_TEMPORAL_ORDER` | —（无 CWE） | NEEDS_REVIEW | 顺序/覆盖/资源身份不可知 |

### 最小例子 A：TOCTOU（CWE-367）

```python
def read_if_present(path):
    if os.path.exists(path):     # FS_CHECK 在 path 上
        return open(path).read() # FS_USE 在同一个 path 上，非原子
```

`os.path.exists(path)` 与随后的 `open(path)` 之间存在时间窗：攻击者可以在两步之间替换/符号链接 `path`。这是经典的 check-then-use 竞态。**注意它为什么是顺序属性**：`exists` 和 `open` 这两句各自完全合法，漏洞在于「先 check、后非原子 use、且作用于同一个可被外部篡改的资源」这一**时序结构**。修复方式是原子化（如 `open(path, 'x')` / `os.open(..., O_CREAT|O_EXCL)`），对应 `FS_ATOMIC_USE`。

### 最小例子 B：CSRF（CWE-352）

```python
@app.route("/profile", methods=["POST"])
def update_profile():
    db.execute("UPDATE users SET ...")  # STATE_CHANGE，但前面没有任何 CSRF 校验
```

一个会改状态的 POST handler，在 `STATE_CHANGE` 之前**没有**一个支配它的 `CSRF_VALIDATE`。这是「**必需事件先于触发**」属性的缺席：触发是 `STATE_CHANGE`，必需事件是 `CSRF_VALIDATE`。

### 最小例子 C：TLS 校验被关闭后使用（CWE-295）

```python
def fetch_payload(url):
    return requests.get(url, verify=False).content  # NETWORK_USE, tls_verify="disabled"
```

`verify=False` 把证书校验关掉，随后的网络使用就暴露在中间人攻击下。LLM 把这次 `NETWORK_USE` 标记为 `tls_verify="disabled"`，检查器据此直接判 `TLS_VERIFY_DISABLED_USE`。

> 提示词里明确要求：默认安全的库调用（如 `requests.get(url)` 不带 `verify=False`）应标 `tls_verify="verified"`，**不是** `unknown`（`typestate_prompts.py:76`）。这避免把正常代码淹没在 `NEEDS_REVIEW` 里。

### 最小例子 D：异常路径上的资源泄漏（CWE-772/775）

```python
def load_text(path):
    f = open(path)        # RESOURCE_OPEN（f 的 origin = call_return）
    data = f.read()       # 若 read() 抛异常……
    f.close()             # ……这一句不会执行 → 异常路径上 f 仍为 open
    return data
```

没有 `try/finally` 或 `with`，所以**正常路径**上 `f` 被关闭，但**异常路径**上 `f` 泄漏。LLM 必须为这个本地打开的资源同时报告 normal 与 exception 两条 `exit_states`；其中 exception 路径的 `state="open"` 触发 `FILE_HANDLE_LEAK`。

### 为什么传统语法级 SAST 难抓

- **没有固定语法形态。** 「校验」可能是装饰器、中间件、一个 `validate_csrf()` 调用、`verify=False` 关键字、ORM 行级策略……无法用正则/AST 枚举。
- **这是「缺席推理」与「顺序推理」。** 漏洞往往是「某个必需事件在某条路径上**缺席**」或「两个事件的**相对顺序**不对」，语法匹配擅长找「存在的东西」，不擅长证明「在所有路径上某事件先于另一事件」。
- **资源身份是语义问题。** TOCTOU 要判断 `check(path)` 和 `use(path)` 作用于**同一个**资源；泄漏要判断本地打开的句柄是否在每条路径上都被关闭。

---

## 2. 形式化原理（The theory）

### 2.1 typestate 与安全性自动机

理论根基是 **typestate**（Strom–Yemini, 1986）：一个对象除了「类型」外还有「状态」，某些操作只有在特定状态下才合法（如 `read` 只能在 `open` 之后、`close` 之前）。把它推广到「程序点上的有限状态属性自动机」，就是 **Ball–Rajamani 的 SLIC / SLAM**、**ESP** 这类工作；用时序逻辑表述，则是一条 **安全性 LTL（safety LTL）** 命题：

> **「一个坏事件不得在某个必需事件之前/缺少它而发生。」**

`typestate` 把这句话落地成 **5 条内建属性规则**（`TYPESTATE_RULES`，`typestate_reasoner.py:59`），每条是一个小自动机：

| name | type | CWE | context_kind |
|---|---|---|---|
| `toctou_check_then_use` | `check_then_use_non_atomic` | CWE-367 | — |
| `csrf_validate_before_state_change` | `required_before_trigger` | CWE-352 | `csrf_validated` |
| `tls_verify_before_network_use` | `forbidden_after` | CWE-295 | `tls_verify_disabled` |
| `resource_lifecycle` | `must_release` | CWE-772 | — |
| `auth_before_privileged_action` | `required_before_trigger` | CWE-306 | `auth_checked` |

**关键分工**：LLM **不写自动机**。它只发射「观察到的事件」，并映射到一套固定的**事件字母表**（`EVENT_KINDS`，`typestate_reasoner.py:43`）：

```
CALL
FS_CHECK / FS_USE / FS_ATOMIC_USE
CSRF_VALIDATE / STATE_CHANGE
TLS_VERIFY_DISABLE / TLS_VERIFY_ENABLE / TLS_HANDSHAKE_VERIFY / NETWORK_USE
RESOURCE_OPEN / RESOURCE_USE / RESOURCE_CLOSE / RESOURCE_ESCAPE
AUTH_CHECK / PRIVILEGED_ACTION
```

确定性检查器（`_check_toctou` / `_check_required_before_trigger` / `_check_tls` / `_check_lifecycle`）在这串事件上跑这 5 个自动机并下判定。为防止爆炸，还有上限 `MAX_EVENTS = 64`、`MAX_RESOURCES = 32`（`typestate_reasoner.py:53`），超限即判 `ERROR`。

### 2.2 关键洞察：扁平事件列表不够

一个**只有顺序、不含路径与资源信息的扁平列表是不可靠的**。要使判定可靠，每个事件必须携带三类信息（`typestate_prompts.py:88`）：

1. **顺序（order）** —— 事件的相对先后。
2. **路径覆盖（path_coverage）** —— 取值 `must`（所有路径上都发生）/ `may`（至少一条路径）/ `guarded`（仅在某条件下，配 `guard_id`）/ `unknown`（说不清，检查器会 fail-closed）。
3. **资源关联（resource correlation）** —— 每个安全相关值有一个稳定 `id` 和 `canonical` 名，让检查器能判断 `check(path)` 与 `use(path)` 是不是**同一个**资源。

由于这套范式不构造真正的控制流图（CFG），`predecessors_must`（「在每条路径上都确定先于本事件发生的事件 id 列表」）就是 **CFG 的最小替代品**；`control_depends_on` 则专门用于 TOCTOU——指向那个「其结果决定 `FS_USE` 是否发生」的 `FS_CHECK`。

检查器用两个核心谓词消费这些信息：

- `_must_precede(req, trigger)`（`typestate_reasoner.py:159`）返回 `yes/no/unknown`：若 `req.id` 在 `trigger.predecessors_must` 里 → `yes`；若 `req.order >= trigger.order` → `no`；若 `req` 是 `must` 覆盖 → `yes`；若两者同属一个 `guarded` 守卫（`guard_id` 相等）→ `yes`；若任一为 `unknown` 覆盖 → `unknown`。
- `_same_resource(resources, a, b)`（`typestate_reasoner.py:142`）返回 `yes/no/unknown`：id 相同 → `yes`；任一 `kind=="unknown"` 或缺 `canonical` → `unknown`；`canonical` 相等 → `yes`；否则 `no`。

### 2.3 POLYMORPHIC 从哪来

当一个**必需事件的满足与否由调用者决定**时，判定为 `POLYMORPHIC`（finding 种类 `CALLER_DEPENDENT_REQUIRED_EVENT`）。`_can_be_satisfied_by_caller`（`typestate_reasoner.py:292`）的判定逻辑：当前函数**不是**入口、**不是** `request_handler`，且触发所作用的资源 `origin=="param"` 且 `kind ∈ {http_request, session, principal, security_context}`——也就是说，这个 request/principal 是上游传进来的，其鉴权/CSRF 状态应由上游决定。把它判成 `POLYMORPHIC` 而非 `VULNERABLE`，是因为「调用者依赖」是**可操作的**（actionable），而非抽象质量缺陷。

### 2.4 Fail-closed（失败即保守）

只要顺序、路径覆盖或资源身份**不可知**，检查器绝不静默判 `SAFE`，而是发 `UNKNOWN_TEMPORAL_ORDER`（判定 `NEEDS_REVIEW`）。例如 `_check_toctou` 里 `use.atomicity=="unknown"` 或资源 `mutability=="unknown"` 时即转 `NEEDS_REVIEW`；`abstraction` 解析失败则在 `check()` 里直接判 `ERROR`（`typestate.py:275`）。

判定优先级（`_PRECEDENCE`，`typestate_reasoner.py:38`）：

```
ERROR > VULNERABLE > POLYMORPHIC > NEEDS_REVIEW > SAFE
```

`POLYMORPHIC` 排在 `NEEDS_REVIEW` 之上：调用者依赖是可行动的结论，而 needs-review 只是抽象质量的缺口。

### 2.5 「所有路径都关闭」的归并（subsumption）规则

资源生命周期里有一条精心设计的、**可靠的归并规则**（`typestate_reasoner.py:402`）。它的动机是：LLM 可能既报告了一条强的「在所有路径上关闭」的 exit，又额外报告了一条弱的、推测性的 `open`/`unknown` exit。规则如下：

> 若一个资源在**每条路径上都被证明 CLOSED/RELEASED/ESCAPED**（即存在 `path_coverage="must"` 且 `condition` 为 `all`，或同时覆盖 `normal` 与 `exception` 的关闭 exit），则它**不是泄漏**——即使 LLM 同时还报了一条更弱的推测性 open exit。

这是一个支配性的释放（dominating release）**抵消**了「必达释放」义务。反过来，像例子 D 的 `load_text`，它的 exception exit 是 `open` 且那条路径上**没有** must-close，所以归并规则不生效，泄漏照样被报出来。

判断一个资源是否「归本函数所有」（owned，因而受 must-close 约束）的标准：`origin ∈ {local, call_return}`（如 `f = open(path)` 把 `f` 标为 `call_return`），且 `escapes ∉ {return, global, field, argument}`（`typestate_reasoner.py:392`）。param/global 的资源属于调用者，不在本函数的泄漏检查范围内。

---

## 3. 插件运行流程（How it runs，结合 SPI）

### 3.1 一次完整生命周期

driver 对每个函数自底向上地驱动以下步骤（见 `base.py:227` 的生命周期注释）：

1. `build_abstraction_prompt` → 组装 system/user 消息（`typestate.py:91`）。
2. driver 调 LLM（带重试）。
3. `parse_abstraction_response` → 抽出 `[TYPESTATE_JSON] ... [/TYPESTATE_JSON]` 里的 JSON，包成 `FactEnvelope`（`typestate.py:106`）；解析失败返回 `None` 触发重试，重试耗尽则 `make_error_facts` 产生 fail-closed 的 error facts。
4. `compose_calls` → **自底向上**把已分析的被调函数事件拼接进调用者。
5. （可选）`initial_context` / `propagate_context` → **自顶向下**的上下文 worklist（因为 `requires_top_down_context=True`，`typestate.py:85`）。
6. `check` → 跑 5 个自动机，产出 `Verdict`。

`check()` 里把 `severity` 映射为 `{VULNERABLE: "high", POLYMORPHIC: "low", NEEDS_REVIEW: "info"}`（`typestate.py:295`），并把判定缓存进 `payload["_verdict"]` 以供调用者摘要复用。

### 3.2 LLM 产出的 JSON 形状

LLM 返回一个 `[TYPESTATE_JSON]` 包裹的对象（schema 见 `typestate_prompts.py:121`）。核心字段：`resources`、`ambient_contexts`、`entry_states`、`events`、`exit_states`、`calls`。一个事件长这样：

```json
{
  "id": "e2", "order": 2, "kind": "FS_USE", "resource": "r_path",
  "operation": "open(path).read()",
  "path_coverage": "must",
  "guard_id": null,
  "predecessors_must": ["e1"],
  "control_depends_on": ["e1"],
  "atomicity": "non_atomic",
  "tls_verify": "not_applicable",
  "callee": null, "return_resource": null
}
```

资源与退出状态：

```json
"resources": [
  {"id": "r_path", "kind": "filesystem_path", "canonical": "path",
   "origin": "param", "formal": "path",
   "mutability": "external_mutable", "escapes": "none"}
],
"exit_states": [
  {"resource": "r_f", "state": "closed", "path_coverage": "must",
   "condition": "normal", "source_event": "e3"},
  {"resource": "r_f", "state": "open", "path_coverage": "may",
   "condition": "exception", "source_event": "e1"}
]
```

> 提示词里有几条硬约束（`typestate_prompts.py:165`）：每个 `CALL` 事件必须同时出现在 `calls` 里（同一 `event_id`）；每个本地打开的资源**必须**同时报 normal 与 exception 两条 `exit_states`；不确定时一律用 `unknown`，**绝不为了让代码看起来安全而省略相关事件**。

### 3.3 两个组合方向

#### (a) 自底向上：拼接被调函数导出的事件 —— `compose_calls`

`compose_calls`（`typestate.py:139`）遍历调用者的 `CALL` 事件，找到对应被调函数的 facts，调 `summarize_facts` 拿到它的 `exported_events`，把每个导出事件**插入调用者的有序序列**：

- 顺序上用 `base_order + i/1000.0` 紧贴在 CALL 事件之后（`typestate.py:188`）。
- 资源映射：被调函数里以 `formal:<param>` 表示的形参资源，按 `arg_resources` 映射回调用者的实际资源；被调函数的 `return` 资源按 `return_resource` 映射（`typestate.py:181`）。
- 路径覆盖用 `_combine_coverage(call_cov, callee_cov)` 合并（任一 `unknown` → `unknown`；都 `must` → `must`；任一 `guarded` → `guarded`；否则 `may`，`typestate_reasoner.py:466`）。

这样，一个「返回打开资源」或「对传入 request 做 STATE_CHANGE」的被调函数，其效应就会出现在调用者的自动机里。

#### (b) 自顶向下：祖先满足必需事件 —— `initial_context` / `propagate_context`

- `initial_context`（`typestate.py:209`）：在入口处播种该函数为后代建立的上下文——`must` 覆盖的 ambient 装饰器（`@csrf_protect`/`@login_required` 等映射到 `csrf_validated`/`auth_checked`/`tls_verify_disabled`），以及 `summarize_facts` 里 `context_provides` 提供的 `must` 上下文。
- `propagate_context`（`typestate.py:224`）：把调用者已建立的 `must` 上下文向下传，**外加**在「本次调用点之前」就已经 `must` 发生的 `CSRF_VALIDATE`/`AUTH_CHECK`（它会先定位该 CALL 事件的 `order`，只接受 order 更小的前置事件，`typestate.py:251`）。
- 在 `_check_required_before_trigger`（`typestate_reasoner.py:240`）里，`_ctx_has(propagated, context_kind, resource, "must")` 为真就直接跳过该触发——义务被祖先**抵消**。若上下文只是 `may`，则降级为 `UNKNOWN_TEMPORAL_ORDER`。

### 3.4 端到端实例走查

下面 7 个例子覆盖 5 条规则与两个组合方向：

| 函数 | 场景 | 判定 |
|---|---|---|
| `read_if_present` | `exists(path)` 后 `open(path)`，TOCTOU | **VULNERABLE** (`TOCTOU_CHECK_THEN_USE`) |
| `update_profile` | POST handler `db.execute(update)` 无 CSRF | **VULNERABLE** (`CSRF_MISSING_VALIDATION`) |
| `fetch_payload` | `requests.get(url, verify=False)` | **VULNERABLE** (`TLS_VERIFY_DISABLED_USE`) |
| `load_text` | `open/read/close` 无 try/finally，异常路径泄漏 | **VULNERABLE** (`FILE_HANDLE_LEAK`) |
| `create_once` | 原子创建 + finally 关闭 | **SAFE** |
| `checkout → persist_order` | 上游先 CSRF 校验再调下游 | **SAFE**（自顶向下抵消） |
| `read_payload → open_stream` | 下游返回打开资源，上游负责关闭 | **SAFE**（自底向上拼接） |

**`create_once`（SAFE）**：用 `FS_ATOMIC_USE`（如 `open(p, 'x')`），`_check_toctou` 里 `atomicity=="atomic"` 直接 `continue`，不报 TOCTOU；且资源在 `finally` 里 `must` 关闭，归并规则使其非泄漏。

**`checkout → persist_order`（自顶向下 SAFE）**：`persist_order` 内部有 `STATE_CHANGE` 但**自己没有** `CSRF_VALIDATE`。单独看它会是 `CSRF_MISSING_VALIDATION`。但 `checkout` 在调用前 `must` 地执行了 `CSRF_VALIDATE`，`propagate_context` 把 `csrf_validated`（`coverage="must", resource="*"`）传给 `persist_order`，`_ctx_has` 命中后该触发被跳过 → SAFE。（注意：若 `persist_order` 的 request 是 param 且其本身是 internal helper，在**没有**上下文时会判 `POLYMORPHIC` 而非 VULNERABLE，见 §2.3。）

**`read_payload → open_stream`（自底向上 SAFE）**：`open_stream` 打开并 `return` 一个 socket/file（`escapes="return"`，`exit_states` 里 `state="open"`），所以它自身**不算泄漏**（escape 的资源是调用者的）。`summarize_facts` 把它列入 `return_resources`。`compose_calls` 通过 `return_resource` 把这个打开资源映射成调用者 `read_payload` 里的实际资源；若 `read_payload` 在所有路径上关闭它，则 SAFE。

---

## 4. 我们的方案 vs 传统方案（Ours vs. traditional non-LLM）

### 传统（非 LLM）方案

- **SLAM / SDV**：在 SLIC 属性自动机上做谓词抽象（predicate abstraction）+ CEGAR，是 Windows 驱动验证的工业实践。
- **ESP**：路径敏感的 typestate 分析，用属性模拟做到可扩展的路径区分。
- **CodeQL TOCTOU queries**：用数据流/污点查询编码 check-then-use 模式。
- **CrySL / IDEal**：把加密 API 的「ORDER」约束编码成 typestate，用 IDE/IFDS 框架求解。

### 我们 LLM 方案的优势

- **识别领域事件无需写自动机/模型**：`validate_csrf`、`exists-then-open`、`verify=False` 这类「语义事件」由 LLM 直接识别并映射到固定字母表，不需要为每个框架/库手写规约或建模。
- **用 may/must 摘要替代完整路径枚举**：LLM 给出 `path_coverage` 与 `predecessors_must` 这类摘要，检查器无需穷举路径。
- **跨框架/跨语言**：支持 `python/javascript/typescript/java/go/c/cpp/ruby/php`（`typestate.py:82`），不依赖某个框架的 AST 规则。

### 我们方案的劣势（必须诚实）

- **这是最不契合本范式的属性类。** LLM 必须把**顺序**和**路径覆盖**判对；一个扁平/不完整的事件列表会**静默丢失可靠性**——漏报一个事件，自动机就看不到它。
- **没有真正的 CFG / 路径敏感性。** `predecessors_must` 只是 CFG 的最小替代品，不是真分析。
- **大量 deferred 能力**：并发 / 锁顺序、跨请求会话状态、竞态可利用性证明都未做。
- **很多情形落到 `NEEDS_REVIEW` / `POLYMORPHIC`。** 这是 fail-closed 的代价：宁可让人复核，也不静默判安全。

诚实定位：**v1 是「窄而大致可靠（narrow-but-sound-ish）」，不是模型检查器（model checker）。** 它擅长识别领域事件，但对路径敏感性的保证远弱于 SLAM/ESP。

---

## 5. 局限与适用场景 + v1 范围裁剪

**v1 已交付（shipped）**（`typestate_reasoner.py:23` 的 Oracle 切分）：

- 资源生命周期（泄漏 / use-after-close / double-close），含异常路径 exit-state 检查与「所有路径关闭」归并。
- TOCTOU（函数内 + 调用拼接）。
- TLS-verify-before-use。
- CSRF-before-state-change（+ 自顶向下抵消）。
- auth-before-privileged-action（+ 自顶向下抵消）。

**v1 明确延后（deferred）**：

- 完整 CFG / 路径敏感的模型检查。
- 并发 / 锁顺序（lock ordering）。
- 跨请求 / 会话状态（cross-request session state）。
- 竞态可利用性证明（race exploitability proof）。

**适用场景**：单函数 + 一层调用边界内的、可由「有序事件 + 路径覆盖 + 资源关联」表达的时序协议违例。**不适用**：需要全程序路径敏感、并发交错、或跨请求状态机推理的场景——这些应交由专门的模型检查器或动态分析。

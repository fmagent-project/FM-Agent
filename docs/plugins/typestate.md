# 时序协议 / 状态机插件（Typestate / Temporal Protocol）

> 插件索引：[./README.md](./README.md)

`typestate` 检测事件顺序、必需步骤缺失和资源生命周期问题，而不是普通的
“source 到 sink”值流。LLM 为单个函数生成有序事件、资源 identity、路径覆盖和退出
状态；`src/typestate_reasoner.py` 运行固定的确定性规则；
`src/typestate_validation.py` 对三类高风险 Python 协议重新从源码生成事实。

这是一种保守的摘要分析，不是 CFG 模型检查器。顺序、覆盖或资源 identity 不可知时，
结果应进入 `NEEDS_REVIEW` 或 `POLYMORPHIC`，而不是被静默解释为 `SAFE`。

## 检测范围

当前 finding 包括：

| Finding kind | CWE | Verdict | 含义 |
|---|---|---|---|
| `TOCTOU_CHECK_THEN_USE` | CWE-367 | VULNERABLE | 同一外部可变路径被先检查、后非原子使用 |
| `FS_UNSAFE_ACQUISITION` | CWE-367 | VULNERABLE | 破坏性 `os.open` 缺少支配性的 no-follow/reparse 防护 |
| `CSRF_MISSING_VALIDATION` | CWE-352 | VULNERABLE | 请求状态变更前缺少 CSRF 校验 |
| `CONTENT_TYPE_MISSING_BEFORE_JSON_PARSE` | CWE-352 | VULNERABLE | JSON 解析缺少源码确认的 Content-Type 门控 |
| `TLS_VERIFY_DISABLED_USE` | CWE-295 | VULNERABLE | TLS 校验关闭后仍进行网络使用 |
| `TLS_DEFAULT_CERTS_WRONG_CONTEXT` | CWE-295 | VULNERABLE | 默认 CA 被加载到未证明为本函数创建的 context |
| `TLS_VERIFY_UNKNOWN` | CWE-295 | NEEDS_REVIEW | 网络使用的 TLS 校验状态不可知 |
| `RESOURCE_LEAK` / `FILE_HANDLE_LEAK` | CWE-772 / CWE-775 | VULNERABLE | 本函数拥有的资源在某个退出路径仍打开 |
| `USE_AFTER_RELEASE` | CWE-672 | VULNERABLE | 释放后使用 |
| `DOUBLE_RELEASE` | CWE-415 | VULNERABLE | 重复释放 |
| `AUTH_MISSING_BEFORE_PRIVILEGED_ACTION` | CWE-306 | VULNERABLE | 特权操作前缺少认证 |
| `AUTHZ_MISSING_BEFORE_PRIVILEGED_ACTION` | CWE-862 | VULNERABLE | 特权操作前缺少授权 |
| `CALLER_DEPENDENT_REQUIRED_EVENT` | - | POLYMORPHIC | 必需状态由调用者决定 |
| `UNKNOWN_TEMPORAL_ORDER` | - | NEEDS_REVIEW | 顺序、覆盖、identity 或退出状态不足 |

Verdict 优先级为：

```text
ERROR > VULNERABLE > POLYMORPHIC > NEEDS_REVIEW > SAFE
```

## 理论模型

理论基础仍是 typestate、属性自动机和 safety LTL：

> 一个坏事件不得在所需事件之前发生，也不得在所需事件缺席时发生。

固定事件字母表覆盖文件检查/使用、CSRF、Content-Type、TLS、资源生命周期和鉴权。
LLM 不定义新自动机，也不直接下 verdict。每个事件需要：

- `order`：事件的相对顺序；
- `path_coverage`：`must`、`may`、`guarded` 或 `unknown`；
- `resource`：指向稳定 resource id，其 `canonical` 用于关联同一对象；
- `predecessors_must`：确定在所有相关路径上先发生的事件 id；
- `control_depends_on`：TOCTOU 使用是否受某次检查控制；
- 协议特有字段，如 `atomicity`、`tls_verify`、`http_methods`。

普通必需事件使用 may/must 摘要判断先后。Content-Type、默认 CA 和破坏性文件获取
采用更严格的 dominance 规则：guard 必须更早，且 guard id 必须出现在 trigger 的
`predecessors_must` 中。只有文本顺序或“源码中存在 guard”都不够。

事件与资源数量分别限制为 64 和 32；未知事件种类、畸形抽象或超限会 fail closed。

## 三类源码校验协议

下面三类协议不是直接信任 LLM 事件。校验器先删除模型提供的
`CONTENT_TYPE_CHECK`、`JSON_PARSE`、`SSL_CONTEXT_CREATE`、`CERT_DEFAULT_LOAD`、
`FS_NOFOLLOW_GUARD` 和 `FS_ACQUIRE`，再从当前函数的 Python AST 重建它们。因此模型
不能通过伪造 `predecessors_must` 把这些协议判为安全。

### Content-Type 后再解析 JSON

校验器识别 request receiver 上的 `.json()`，并关联同一 receiver 的
`headers.get("content-type")` 或 `headers["content-type"]` 来源。安全 guard 必须在通向
解析调用的正分支上证明以下之一：

- 完整 media type 为 `application/json` 或 subtype 以 `+json` 结尾；参数部分会在
  literal 校验时去除；
- 对同一个解析后的 message，同时证明 maintype 为 `application`，且 subtype 为
  `json` 或以 `+json` 结尾。

校验器跟踪支配性的简单别名和 message Content-Type 赋值。负分支、无关 feature flag、
只检查字符串中出现 `json`、或未支配 `.json()` 的检查都不能建立协议。重建出的 guard
和 parse 使用同一 request resource，并由 source-validated predecessor 关联。

### TLS context 与默认 CA

该源码协议针对 `load_default_certs()`，与一般的 `verify=False` 状态机是两件事。
校验器按同一 receiver 跟踪 context 赋值；任意工厂名都可以成为创建点，但创建赋值必须：

- 发生在 `load_default_certs()` 之前；
- 位于同一函数；
- 在加载点的每条相关路径上成立；
- 具有与加载分支兼容的条件，从而证明当前 context 是本函数创建的，而不是调用者提供的
  context。

因此“参数为 `None` 时创建，并且仅在同一条件下加载默认 CA”可以建立 predecessor；先把
调用者 context 赋给本地变量、仅在部分分支覆盖、随后无条件加载则不能。工厂函数名字本身
不构成证明。

独立的 TLS 状态机仍处理 `TLS_VERIFY_DISABLE`、`TLS_VERIFY_ENABLE`、
`TLS_HANDSHAKE_VERIFY` 和 `NETWORK_USE`。显式 `tls_verify="disabled"` 或已到达的禁用状态
产生漏洞；显式 `verified` 建立已验证状态；参数 client 的未知状态为 caller-dependent，
其他未知状态进入 review。源码协议正确不抵消显式关闭 TLS 校验。

### 文件系统 reaching flags 与异常流

文件源码协议只针对 Python `os.open` 中当前到达调用点的 flags 包含 `O_TRUNC` 的破坏性
获取。校验器支持位置参数和 `path=`/`flags=` 关键字，并对 flag 变量执行窄的 reaching
state 计算：

- 支配调用点的赋值、`|=`、`&=` 和 `& ~FLAG` 会增加、保留或移除 flag；
- 后续覆盖会清除旧的 `O_NOFOLLOW` 证明；
- 仅在可选分支加入 `O_NOFOLLOW` 不支配获取；
- inline 且实际到达调用点的 `O_NOFOLLOW` 建立 no-follow guard。

没有 `O_NOFOLLOW` 时，可接受同一函数内更早且支配获取的 reparse 检查，但条件文本必须
关联同一路径，拒绝分支必须 raise，且异常流必须真正阻断获取。校验器会检查相关
`try/except/finally`：若异常被匹配 handler 吞掉并可继续到 `os.open`，则 guard 无效；
handler 终止或重新抛出的异常也必须沿外层流程继续阻断获取。

源码验证只证明这组具体 `os.open`/`O_TRUNC`/`O_NOFOLLOW`/reparse 模式，不等于完整的
跨平台文件系统竞态分析。

## 普通事件规则

### 函数内 TOCTOU

普通 TOCTOU 规则要求：`FS_CHECK` 早于 `FS_USE`，两者关联同一 resource，use 的
`control_depends_on` 或 `predecessors_must` 指向该 check，use 为非原子，且路径资源不是
稳定对象。`FS_ATOMIC_USE` 或 `atomicity="atomic"` 不产生该 finding；identity、覆盖或
原子性未知时进入 review。

这不是完整的 interprocedural TOCTOU。普通 callee 事件可以被摘要拼接，但拼接事件会丢弃
callee 的 predecessor/control-dependency 边，无法保留完整的跨函数 check-use 证明；进入
任一源码协议覆盖模式时，普通 TOCTOU 检查还会被关闭。因此不得把当前实现描述为完整的
跨过程 TOCTOU 支持。

### CSRF、鉴权与 top-down context

`required_before_trigger` 规则用于 `CSRF_VALIDATE -> STATE_CHANGE` 和
`AUTH_CHECK -> PRIVILEGED_ACTION`。函数内 `must` predecessor 可以满足义务；祖先上下文也
可以自顶向下抵消义务：

- ambient `csrf_validated`、`auth_checked` 和 `tls_verify_disabled` 只在 `must` 时传播；
- 调用点之前 `must` 发生的 `CSRF_VALIDATE` 或 `AUTH_CHECK` 可传播给被调函数；
- `may` 上下文不足以证明安全；
- 非入口 helper 若 trigger 作用于参数形式的 request/session/principal/security context，
  可以得到 `POLYMORPHIC`，表示状态应由调用者建立。

这是一种调用图上下文摘要，不是跨请求、跨线程或完整路径敏感的协议证明。

### 资源生命周期与异常退出

生命周期状态机检查 open/use/close/escape 顺序，以及本函数拥有资源的 `exit_states`。
`origin` 为 `local` 或 `call_return` 且未 escape 的资源需要在所有路径释放；参数和全局资源
不由当前函数承担 must-close 义务。

退出状态必须区分 normal 与 exception。存在 `condition="all"` 的 must-close，或 normal
和 exception 都有 must-close，可以归并为“所有路径已释放”，并覆盖较弱的推测性 open
摘要。异常路径明确 open 则报告泄漏；退出状态未知或完全缺失则进入 review。

当前实现不会把 callee 摘要中的 `return_resources` 转换成 caller 的新生命周期对象或
must-close 义务。虽然 schema 中存在 `return_resource`，普通事件拼接只消费
`exported_events`；不能声称“被调函数返回打开资源后，调用者会自动接管并验证关闭”。

## 组合边界

普通 LLM 事件有两个有限的组合方向：

- Bottom-up：只拼接 callee 导出的 caller-visible 事件，即作用于 param、显式 return、
  global 的事件，以及 CSRF/auth/TLS-disable 上下文事件。formal resource 可映射到调用者
  actual resource；路径覆盖与 call-site 覆盖合并。拼接不保留 callee CFG 边。
- Top-down：只传播前述 `must` ambient context，以及调用前已建立的 CSRF/auth context。
  它不传播任意 typestate，也不建立一般的过程间状态机。

当源码校验器识别到 `JSON_PARSE`、`CERT_DEFAULT_LOAD` 或 `FS_ACQUIRE` 时，函数进入
source-protocol 覆盖模式。此时只保留源码校验事件和 TLS 状态事件，清空 entry/exit states
与 calls；reasoner 跳过普通 TOCTOU、生命周期、CSRF 和 auth 规则，只运行三类 guarded
protocol 与 TLS 规则。这一隔离避免无关模型噪声污染高风险协议，但也明确限制了同一函数
中的协议组合能力。

这三类 trigger 也是唯一允许的 source-only fallback。LLM 重试耗尽时，如果 Python AST 能
独立重建 `JSON_PARSE`、`CERT_DEFAULT_LOAD` 或 `FS_ACQUIRE`，插件以 `partial` facts 运行同一
确定性规则；没有识别到完整 trigger 的普通函数仍返回 `ERROR`，不会因空 source facts 被判
为 `SAFE`。

## 语言支持边界

插件 metadata 接受 Python、JavaScript、TypeScript、Java、Go、C、C++、Ruby 和 PHP，
这些语言都可走 LLM 事件抽象与通用 reasoner。三类 source-validated 协议则使用 Python
`ast`，并识别 Python/库特定形态，例如 request `.json()`、`load_default_certs()` 和
`os.open` flags。

因此“metadata 中列出一种语言”不等于该语言拥有与 Python 相同的确定性 grounding、
异常流、flag reaching 或协议覆盖。当前文档不声称所有语言等价支持。

## 适用与不适用范围

适合：单函数内、能由有序事件 + may/must 覆盖 + resource identity 表达的协议，以及上面
三类受 Python 源码校验的具体模式。

不适合：完整 CFG/路径敏感模型检查、并发交错和锁顺序、竞态可利用性证明、跨请求会话
状态、一般化跨过程资源 ownership、完整跨过程 TOCTOU，以及任意语言/框架的等价源码证明。
这些场景需要专门的模型检查、数据流或动态分析工具。

当前行为由 `src/plugins/typestate.py`、`src/typestate_validation.py`、
`src/typestate_reasoner.py`、`src/typestate_prompts.py` 和
`tests/test_typestate_validation_guards.py` 共同刻画；本文不依赖易失效的源码行号。

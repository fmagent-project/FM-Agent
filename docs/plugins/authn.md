# Authn 插件：认证完整性

> 插件索引：[./README.md](./README.md)

`authn` 检查的是访问控制之前的问题：主体身份是否真的被验证，以及认证凭据、恢复流程和服务端会话是否以不会 fail-open、固定或长期存活的方式使用。它采用守卫式霍尔模型，但不是纯源码证明器：LLM 提取跨语言语义 facts，确定性的 Python reasoner 根据这些 facts 裁决；对一组窄的 Python 模式，source validator 会独立纠正或补充模型事实。

## 1. 核心模型

每个 `protected_operations[]` 都形成义务：到达操作的所有路径上，必须存在 `strength="genuine"` 且 `dominates_all_paths=true` 的认证事件。`authentication_events[].protects_op_ids` 非空时只保护列出的操作，为空时该事件会被视为适用于所有本地操作。

本地认证事件的结果是：

- `genuine` 且支配操作：discharge。
- `weak` 且支配操作：`WEAK_AUTHENTICATION / CWE-287`。
- `asserted_only`：`ASSERTED_IDENTITY / CWE-287`。该判断不要求事件支配，因此只要适用于该操作的事件中出现 asserted-only，就可能成为本地缺陷。
- `unknown` 且支配操作：`NEEDS_REVIEW`，表示存在门但无法确认其真实性。
- 存在操作相关的本地事件但它不支配：硬性的 `MISSING_AUTHENTICATION / CWE-287`；调用者上下文不能修复本地绕过路径。
- 完全没有本地事件：可由祖先传播的 genuine 认证 discharge；若仍未满足，有显式 `obligations[]` 时为 `NEEDS_REVIEW`，否则为 `VULNERABLE`。

会话卫生独立于 protected operation 求值：`trust_client_id` 始终产生 `SESSION_FIXATION / CWE-384`；普通 `establish` 只在没有 `regenerate` 时产生该 finding，且没有 `set_expiry` 时产生 `INSUFFICIENT_SESSION_EXPIRATION / CWE-613`。这些是本地缺陷，不会被调用者认证上下文消除。

边界契约也独立产生 finding：

- `recovery_events[]`：不安全的账户选择或恢复凭据投递产生 `WEAK_PASSWORD_RECOVERY / CWE-640`。
- `credential_events[]`：无效、非支配、低置信或 fail-open 的 provision/load/verify 产生 `FAIL_OPEN_AUTHENTICATION / CWE-287`。
- `session_key_events[]`：未清除存储、替换为可复用值、非支配或非高置信的 retirement 产生 `SESSION_FIXATION / CWE-384`。

一个有效边界事件只有在 `protects_op_ids` 明确包含某个操作时才能 discharge 该操作。边界事件自身不安全时，即使没有 protected operation 也会报告漏洞。

## 2. Model Facts 与源码校验的信任边界

### 模型负责的事实

提示词要求 `[AUTHN_JSON] ... [/AUTHN_JSON]` 中包含以下结构：

```json
{
  "protected_operations": [
    {"op_id": "op1", "kind": "account_change", "subject_expr": "user", "evidence": "change(user)"}
  ],
  "authentication_events": [
    {"method": "password", "verifies_nl": "verify password", "strength": "genuine",
     "dominates_all_paths": true, "protects_op_ids": ["op1"], "evidence": "authenticate(...)"}
  ],
  "session_events": [],
  "recovery_events": [],
  "credential_events": [],
  "session_key_events": [],
  "obligations": [],
  "establishes": [],
  "notes": "..."
}
```

主要枚举与实际校验如下：

| 字段 | 接受值 |
|---|---|
| `protected_operations[].kind` | `account_change\|privileged_action\|token_issue\|state_change\|data_access\|other` |
| `authentication_events[].method` | `password\|token\|jwt\|session\|mfa\|api_key\|oauth\|unknown` |
| `authentication_events[].strength` | `genuine\|weak\|asserted_only\|unknown`；提示词模板只列前三种，但 reasoner 接受并处理 `unknown` |
| `session_events[].kind` | `establish\|regenerate\|set_expiry\|trust_client_id` |
| `recovery_events[].kind/binding` | `select_account\|deliver_credential`；`canonical_equivalent\|exact_equivalent\|backend_case_insensitive\|stored_identity\|untrusted_input\|unknown` |
| `credential_events[].kind` | `provision\|load\|verify` |
| `contract_status` / `failure_mode` | `valid\|invalid\|unknown` / `closed\|open\|unknown` |
| `session_key_events[].replacement` | `absent\|fresh_random\|reusable_value\|unknown` |
| 边界事件公共字段 | 布尔 `dominates_all_paths`、字符串数组 `protects_op_ids`、`high\|medium\|low` confidence；recovery/credential 还必须有合法 failure mode |

模型仍然拥有 protected-operation 识别、一般认证强度与支配关系、一般 session event 和非 Python 语义。validator 没有证明的字段会继续进入 reasoner，因此 `SAFE` 表示“当前已接受 facts 没有触发规则”，不是对原始源码的完整认证证明。

### Python source validator 实际覆盖的范围

`normalize_authentication_facts` 只对 `unit.id.language == "python"` 且 AST 可解析的函数生效，并在首次解析及 checkpoint replay 的 `check()` 边界各运行一次。它会复制 payload 后做窄模式规范化：

- 将模型方法名 `shared_secret` 规范为受支持的 `api_key`；识别由 `if` 门控的直接或委托 `authenticate(...)` 调用，并在有限 AST 证据下纠正 genuine/dominance。
- 删除本函数源码中没有本地账户选择或恢复投递调用支撑的相应 recovery event；识别 canonicalize+casefold 比较，以及循环内“为所选账户生成凭据并投递到同一账户持久身份”的 Python 形状。源码可补建 delivery event，也可把误标的 stored/untrusted binding 改正。
- 对静态文件路径的 Python `open()` writer/reader/verifier 合约检查文本/二进制表示、失败 sentinel、动态失败默认值和 fresh/reusable provision 来源；在满足同路径 loader 与 verifier 的窄模式时可补建 provision/verify facts，并把直接的同文件 ownership/permission 操作加入 `protects_op_ids`。若模型只给出一个 `token_issue` operation 且 evidence 粒度不足以命中 lifecycle 语句，source-proven provision 也会绑定该唯一 operation；多个或其他种类的无关操作不会因此自动 discharge。
- 对服务端 session-key 赋值检查清理顺序及最终 replacement；在没有服务端 session 生命周期证据时删除仅由 bearer-token 返回造成的 session event。

这些规则是启发式 AST 模式，不是通用数据流、控制流或框架模型。例如恢复投递只识别特定循环/调用/别名形状，文件合约只解析静态字符串路径和有限 equality/sentinel 模式，session retirement 只处理有限的直接语句顺序。对非 Python，payload 原样交给 reasoner。

### 与 authz 不同的 checkpoint 边界

插件 envelope 的 metadata schema 是 `authn.guarded_hoare.v1`，但当前 `AuthnPlugin.check()` **不校验**缓存 envelope 的 schema，也没有 source digest 或 validator-version marker。replay 会重新运行上述 Python normalization，因此这些窄事实可被更新；但未被 normalization 覆盖的陈旧或错误模型事实仍可能保留。不能把 authz v2 的“旧 schema/源码变化必定 ERROR”保证套用到 authn。

## 3. 自顶向下组合

`authn` 设置 `requires_top_down_context=True` 和 `needs_entrypoint=True`。bottom-up 阶段只把 callee 的 obligations、protected-op kinds 和边界契约摘要作为文本提供给 caller prompt；`compose_calls` 沿用默认 no-op。

top-down context 由 `authentication_events[]` 中所有 genuine、dominating 事件生成，形状为：

```json
{"authenticated": true, "strength": "genuine", "method": "password"}
```

传播上下文不携带 `protects_op_ids`，也不按 callee 或调用点绑定；当前实现还没有消费 prompt 中的 `establishes[]`。因此它表达的是“某个祖先建立过 genuine 认证”的粗粒度联合事实，可能 discharge 内部函数中可传播的 missing-auth obligation，但不会 discharge weak/asserted/non-dominating 本地缺陷。这个能力边界既能减少上游已认证造成的误报，也可能在多分支、多身份或调用点相关认证中失去精度。

## 4. Fallback、ERROR 与 NEEDS_REVIEW

- JSON 不可解析、payload 不是对象、集合/枚举/边界字段不合法时，解析返回 `None` 触发 driver 重试；重试耗尽或 LLM 调用异常生成 `status="error"`，最终为 `ERROR`。
- authn 没有 source-only fallback。模型事实不可用时，即使 Python 源码看起来可识别，也不会像 crypto 那样改用 partial facts。
- `ERROR` 不是 `SAFE`，也不是具体 CWE finding。
- `NEEDS_REVIEW` 只用于 reasoner 已看见“未知但支配的认证门”，或看见 caller/framework obligation 却没有传播上下文确认的情况。无认证事件且无 obligation 的 protected operation 是硬漏洞，不会自动软化。
- `VULNERABLE` 优先于 `NEEDS_REVIEW`：同一函数只要还有弱认证、asserted identity、非支配门、会话缺陷或不安全边界契约，最终仍是 `VULNERABLE`。

## 5. Focused Tests 与 SecureBench 范围

`tests/test_authn_validation_guards.py` 覆盖当前可承诺行为：genuine/weak/asserted 判定、session rotation/expiry、operation-specific dominance、恢复 identity/delivery、文件凭据表示和 failure sentinel、fresh provision、session-key retirement、cached facts 重做 normalization，以及 malformed facts 变成 `ERROR`。这些测试证明的是列出的 Python 模式与 reasoner 规则，不证明任意框架或任意语言上的认证分析完备性。

`eval/securebench_corpus.json` 当前把以下案例分配给 authn：

- `CVE-2019-19844 / CWE-640`：Django password-recovery loci `PasswordResetForm.get_users` 与 `PasswordResetForm.save`。
- `CVE-2024-47533 / CWE-287`：Cobbler shared-secret provision/load/login 三个 loci。
- `CVE-2015-3982 / CWE-384`：Django cached-session `flush` locus。

这些是 corpus manifest 中的评测目标与 locus 声明；文档不据此声称对整个 CVE、仓库或同类漏洞具有通用覆盖。

## 6. 适用边界

该插件适合发现“操作前身份未验证”、明显弱/断言式认证、简单服务端 session 卫生问题，以及 focused Python 模式中的 recovery、共享文件凭据和 session-key retirement 缺陷。它不是认证协议验证器，不证明密码学强度，不建模完整框架 session 状态机，也不保证调用点敏感的身份上下文正确。结果应结合源码证据和框架配置复核。

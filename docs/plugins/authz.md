# 访问控制插件（Authz / 守卫式霍尔）

> 插件索引：[./README.md](./README.md)

`authz` 检测缺失授权、错误授权和 IDOR/BOLA：敏感操作是否由绑定到主体、资源和动作的守卫保护。插件使用两层事实来源：LLM 负责跨语言的语义抽象；`src/authz_validation.py` 只对几类 Python AST 形状建立更高信任的 source facts。最终 verdict 由 `src/authz_reasoner.py` 确定性计算。

## 1. 形式化模型

每个敏感操作可写成守卫式霍尔三元组：

```text
{ authenticated(subject) ∧ authorized(subject, resource, action) }
    sensitive_operation(resource, action)
{ effect_allowed }
```

一般操作由 `_discharges(guard, op)` 检查：

- 写、删、admin 和 other 操作要求守卫支配所有路径；read 允许先取对象再做 ownership/tenant 检查，因为真正的披露可发生在守卫之后。
- decorator 或 dependency-injection guard 被视为框架在函数体之前执行，因此即使模型的 dominance 字段为 false，也按支配处理。
- 守卫必须绑定主体并覆盖 action。`action_scope="any"` 覆盖所有动作；HTTP method 与 read/write/update/delete 等动词按内置映射匹配，写方法可覆盖其前置 read/list，但 GET 不反向覆盖写效果。
- 对具体对象，`ownership`、`tenant`、`other` 守卫的资源键必须覆盖操作键。当前不是字符级严格相等：复合键先按逗号拆成分量，非空 guard key 是 op key 的子集即可，例如 `dag_id` 可覆盖 `(dag_id, task_id)`。这适合层级资源，但可能把真正独立的多资源操作过度 discharge。
- 对对象操作，普通 role/authentication guard 只可覆盖 `admin`。框架 guard 若携带匹配的具体 key，或没有 key 但 `resource_type` 相同，也可 discharge；这是当前对框架级 typed permission 的近似。
- `resource_id_origin="subject"`，或 key 以 `current_user.`、`request.user.`、`self.user.` 开头时，在存在 authenticated subject 的前提下按 self-access discharge。

主要 finding 为：

| Finding | CWE | 当前含义 |
|---|---|---|
| `MISSING_AUTHENTICATION` | CWE-306 | 操作没有 authenticated subject、guard 或 obligation |
| `MISSING_ABSOLUTE_AUTHENTICATION_LIFETIME` | CWE-306 | session acceptance 没有源码证明的绝对认证期限 |
| `RESOURCE_BINDING_MISMATCH` | CWE-639 | 一般守卫 key 不覆盖操作 key，或绑定不可确认 |
| `SUBJECT_OBJECT_BINDING_MISMATCH` | CWE-639 | source-required enclosing scope 未被同 scope guard 满足 |
| `OBJECT_PERMISSION_BINDING_MISMATCH` | CWE-863 | permission guard 保护的是另一个 dispatch object |
| `MISSING_OBJECT_PERMISSION` | CWE-863 | dispatch object 没有 permission guard |
| `ROLE_ONLY_GUARD_FOR_OBJECT_ACTION` | CWE-863 | 非框架的 role/auth guard 试图覆盖对象操作 |
| `MISSING_AUTHORIZATION` | CWE-862 | 没有可用授权守卫 |
| `AUTHZ_AFTER_EFFECT` | CWE-862 | 所需守卫不支配效果 |

## 2. Model Facts Schema

提示词要求一个 `[AUTHZ_JSON] ... [/AUTHZ_JSON]` 对象：

```json
{
  "authenticated_subject": {"expr": "request.user", "origin": "framework_global"},
  "sensitive_operations": [
    {"op_id": "read_invoice", "kind": "read", "resource_type": "Invoice",
     "resource_id_expr": "invoice_id", "resource_id_origin": "request",
     "action": "read", "required_checks": [], "scope_id_expr": null,
     "permission_object_expr": null, "evidence": "Invoice.objects.get(...)"}
  ],
  "guards": [
    {"predicate_nl": "invoice.owner_id == request.user.id", "subject": "request.user",
     "resource_type": "Invoice", "resource_id_expr": "invoice_id",
     "action_scope": "read", "kind": "ownership", "scope_id_expr": null,
     "source": "in_body", "dominates_all_paths": true, "evidence": "if ...: abort(403)"}
  ],
  "obligations": [],
  "establishes": [],
  "notes": "..."
}
```

`sensitive_operations[].kind` 的提示词取值为 `read|write|delete|admin|other`，但 reasoner 没有对该字段做 enum 拒绝；未知 kind 会按非 read、非 admin 的普通效果处理。`guards[].kind` 会严格校验为 `ownership|role|tenant|authentication|permission|other`。`resource_id_origin`、subject origin、action 和 source 也没有完整 enum validation，实际语义由对应 helper 消费。

提示词允许模型填写 `required_checks`，但这不是可信字段：validator 会删除模型提供的 required checks，之后只由 Python source enrichment 写入。模型也不能通过下划线字段、`source="source_validation"` 或 `absolute_lifetime_bound` 自行获得 source trust。

插件 envelope schema 是 `authz.guarded_hoare.v2`；payload 本身没有独立的 `schema_version` 字段。

## 3. Model Facts 与 Python Source Validation

LLM facts 仍负责识别一般 sensitive operation、authenticated subject、普通 guard、resource/action 语义和 evidence。`validate_and_enrich` 先复制 payload，拒绝非对象或四个核心集合不是 object array 的输入，再移除模型可伪造的私有/source-only 字段。Python AST enrichers只处理以下窄结构：

### 绝对认证期限

当提取函数包含 session security reference 时，validator 将相关操作的唯一 required check 设为 `absolute_authentication_lifetime`；没有模型操作时会补一个 session operation。它只把原始模块 AST 中同时包含“当前时刻派生 deadline”和“login/auth/issued/created 时刻派生 deadline”的 `min(...)` 形状视为绝对上限，并补建 source-validation authentication guard。普通 authenticated subject、session key 读取或 sliding timeout 不足以 discharge。

### Subject-object scope binding

validator 识别有限的参数转换模式：转换函数从 `kwargs` 取得 project/tenant/account 一类 scope，用该 scope 过滤 query，再 `get` 对象并写回 handler 参数。匹配时会为 handler operation 设置 `subject_object_binding`、scope expression，并补建 tenant guard。

反面模式包括 handler 同时接收 enclosing object 与 id，却用 id-only helper 取对象，以及直接按参数 key `.get(...)`。这些模式会要求 subject-object binding，但不会凭“已登录”自动满足。该逻辑不是通用 ORM 数据流分析，只覆盖 validator 中编码的赋值、`filter/get`、参数注入形状。

### Dispatch object permission

带 `func=` keyword 的 enqueue/dispatch 风格调用会补建要求 `object_permission` 的 source operation。若 enclosing class 继承 permission mixin，validator 从 class `queryset` 和本地对象赋值推断 permission 实际保护的对象；wrapper/button 的权限不会自动授权关联 job/task，因此不同 key 会成为 CWE-863。

事务写入另有一个非常窄的认可模式：函数先有 `get_object`，在捕获 `DoesNotExist` 的 `try` 内进入 atomic/transaction block，保存对象后又以同对象做 `get`/`check_perms`，失败阻止正常提交。命中时，未带独立 required check 的本地效果可标为 source-authorized；这不会 discharge 另一个被调度对象的 `object_permission`。

### 信任边界与能力边界

- 这三个 enrichment 使用 Python `ast`；对非 Python 或无法解析的代码，不提供上述 source proof，普通 model facts 仍可进入 reasoner。
- validator 不证明模型是否漏掉 sensitive operation，也不全面验证普通 guard 的语义。未被 source-only 字段覆盖的模型错误仍会影响 verdict。
- 每个被 source-enriched 的 operation 当前只保留该 enricher写入的一组 `required_checks`，不是自动累加模型声明的所有独立前置条件。因此文档不能声称实现了任意 required-check 组合证明。
- `SAFE` 表示已接受 facts 和窄 source guards discharge 了已知操作，不是 sound 的全程序授权证明。

## 4. Top-down 上下文传播

插件设置 `requires_top_down_context=True` 和 `needs_entrypoint=True`。bottom-up 阶段通过摘要把 callee obligations 和 operation kinds 提供给 caller prompt；`compose_calls` 本身是 no-op。

top-down 阶段实际从当前函数的 `guards[]` 生成 context：guard 必须支配，或是 decorator/DI framework guard。context 包含 resource key、scope key、action、subject-bound、kind 和 absolute-lifetime bit。祖先 context 只对非入口函数生效，并复用相同的 action/key/required-check规则。

当前实现有两个重要近似：

- prompt 中的 `establishes[]` 没有被 reasoner 或 plugin 消费；传播依据是 caller 的全部合格 guards。
- `propagate_context` 不使用 call-site 参数绑定，也不按“某 guard 只在某次调用前建立”筛选，而是把联合 context 传播给每个 callee。复合键也没有沿实参到形参重写。

因此 top-down pass 能消除“祖先已守卫、helper 本地无守卫”的一类误报，但对分支、别名、多调用点和多资源调用可能过度或不足 discharge，不能声称是精确的调用点敏感授权证明。

## 5. Verdict、Fallback 与 Cache

- `VULNERABLE`：至少一个已知 operation 在本地和可用祖先 context 中均未 discharge。入口点不使用祖先 context。
- `SAFE`：所有已知 operation 被 discharge，或没有 operation。
- `NEEDS_REVIEW`：属于插件 vocabulary，但当前 reasoner 的 soft 条件要求“仅有 `binding_unknown` 原因且同时没有 guards”；由于 gap reason 只从遍历到的 guard 产生，普通有效 payload 实际没有稳定可达的该路径。未知或缺失授权通常会成为 `VULNERABLE`，不应按旧文档假定框架/ORM 不确定性都会自动软化。
- `ERROR`：没有 payload、fact status 为 error、envelope schema 不等于 `authz.guarded_hoare.v2`、validation marker/version 不匹配、function/source digest 变化，或 reasoner 收到非法核心结构/guard kind。

LLM 输出解析或 validation 失败会返回 `None` 触发 driver 重试；重试耗尽或调用异常生成 error facts。authz 没有 source-only fallback。

成功 facts 带 `_authz_validation.version="authz.validation.v1"` 和 `_function_digest`。digest 绑定提取函数源码，并在能定位时同时绑定原始源码文件。checkpoint replay 不重新 enrich，而是在 `check()` 拒绝旧 envelope schema、旧 validation marker 或 digest 不一致的 facts。因此模型不能伪造 source marker，但 validator 没覆盖的一般模型事实仍是信任输入。

## 6. Focused Tests 与 SecureBench 范围

`tests/test_authz_validation_guards.py` 直接覆盖：sliding 与 absolute session lifetime、project-bound 参数转换和 unscoped lookup、dispatch permission 的同对象绑定、事务内 recheck、错误 propagated scope、模型伪造 source fields、旧 schema/validation marker 和源码变化后的 cache 变成 `ERROR`，以及 source result identity。

`eval/securebench_corpus.json` 当前声明三个 authz 案例：

- `CVE-2022-3327 / CWE-306`：`auth_form.py` 的 `_is_login`、`run`、`login` loci。
- `CVE-2024-45606 / CWE-639`：Sentry `rule_snooze.py` 的 `get_rule`、`post`、`delete`；manifest 要求 fixed side 的 `get_rule` absent。
- `CVE-2023-51649 / CWE-863`：Nautobot `JobButtonRunView.post`；manifest 要求 fixed side 该 qualified locus absent。

focused test 只确认后两个 absent 声明存在于 manifest；它不等于在文档中宣称所有 CVE 已被端到端稳定检出。pair runner 按原始 source path、提取器 function token 和可选 qualified name 绑定 locus，absent locus 必须真的从 fixed source inventory 消失，不能由其他 helper result 代替。

## 7. 适用边界

`authz` 最适合主体、资源 key、动作和守卫较清晰的 Web/RPC/ORM 代码，以及 validator 已编码的 Python session/scope/dispatch 模式。授权完全隐藏在网关、数据库 RLS、动态策略、反射或复杂框架生命周期中时，模型可能漏 facts，source validator 也不会补齐。该插件提供有证据的漏洞线索和局部 discharge，不提供 soundness 或完整策略合规保证。

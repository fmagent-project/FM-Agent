# 访问控制插件（Access-Control / 守卫式霍尔）

> 插件索引：[./README.md](./README.md)

本文档介绍 FM-Agent 的**第二个**分析插件 `authz`，它用一套「守卫式霍尔三元组（guarded Hoare triple）」的形式化理论来检测**缺失授权（missing authorization）**，尤其是 **IDOR / BOLA（Broken Object-Level Authorization，对象级授权失效）** 这类漏洞。

它最大的不同点在于：与 IFC/污点/加密这类**自底向上（bottom-up）**的插件不同，`authz` 额外启用了一遍**自顶向下（top-down）的上下文传播**，用来把「祖先调用者已经做过的授权检查」沿调用图向下传递，避免把「授权由上游 handler 负责」的内部函数误报成漏洞。

阅读本文前不需要先懂 IFC 插件。你需要知道的 FM-Agent 通用范式只有一句话：

> **LLM 负责产出每个函数的、模块化的自然语言抽象（facts）；一个不含 LLM 的、确定性的 Python 检查器负责下判定（verdict）；判定结果跨函数（interprocedural）组合。**

`authz` 严格遵循这个分工：LLM 只报告事实和证据，**绝不下结论**；判定完全由 `src/authz_reasoner.py` 的确定性代码做出。

---

## 1. 它防的是什么攻击（What it detects）

目标是 CWE-862（Missing Authorization）、CWE-863（Incorrect Authorization）、CWE-639（Authorization Bypass Through User-Controlled Key，即 IDOR/BOLA）。

### 最小例子 A：完全没有授权检查（MISSING_AUTHORIZATION）

```python
@app.route("/invoices/<invoice_id>")
@login_required
def get_invoice(invoice_id):
    # 只验证了"登录"(authentication)，没有验证"这个用户能不能看这张发票"(authorization)
    invoice = Invoice.objects.get(id=invoice_id)
    return jsonify(invoice.to_dict())
```

任何**已登录**用户都能把 URL 里的 `invoice_id` 换成别人的编号，读到别人的发票。这里 `@login_required` 只证明了「主体已认证」，并没有证明「该主体被授权访问 *这一张* 发票」。

### 最小例子 B：守卫绑定错了资源（RESOURCE_BINDING_MISMATCH，经典 IDOR）

```python
def delete_invoice(confirm_id, invoice_id, current_user):
    # 守卫检查的是 confirm_id 的归属……
    confirm = Invoice.objects.get(id=confirm_id)
    if confirm.owner_id != current_user.id:
        abort(403)
    # ……但真正删除的却是另一个 invoice_id
    Invoice.objects.get(id=invoice_id).delete()
```

这里**有**一个支配所有路径的归属守卫，但它绑定的资源 id（`confirm_id`）和敏感操作真正触碰的资源 id（`invoice_id`）**不是同一个**。攻击者只要传一个自己拥有的 `confirm_id` 配上别人的 `invoice_id`，就能删除任意发票。这正是 IDOR 的核心形态：**守卫存在，但它约束的资源标识与操作触碰的资源标识不相等**。

### 为什么传统语法级 SAST 抓不到

- **授权没有统一的语法形态。** 它可能是 `invoice.owner_id == current_user.id`、`current_user.is_admin`、一个 `@login_required` 装饰器、一个中间件、甚至一条 ORM 的行级（row-level）策略。没有任何固定的正则/AST 模式能枚举它们。
- **这是「缺失推理」（absence-reasoning）。** 漏洞不是「出现了某个坏调用」，而是「在某个敏感操作之前**缺少**一个合格的检查」。语法匹配擅长找「存在的东西」，不擅长证明「某个东西在所有路径上都不存在」。
- **资源绑定是语义问题。** 例子 B 里 `confirm_id` 和 `invoice_id` 在语法上都是合法的标识符；要判断它们「指的不是同一个资源」，需要理解每个表达式的语义身份，而不是文本是否相似。

---

## 2. 形式化原理（The theory）

授权逻辑的经典理论是 Abadi–Burrows–Lampson–Plotkin 的 “says” 演算（principals 之间的 `A says s` / `A speaks-for B` 推理）。`authz` 借用其「主体—资源—动作」的思考框架，但落到**可操作（operational）**的判定上时，我们采用的是**守卫式霍尔三元组**：

把每一个敏感操作建模为

```
{ authenticated(subject) ∧ authorized(subject, resource, action) }
      sensitive_operation(resource, action)
{ effect_allowed }
```

一个函数是 **VULNERABLE** 当且仅当：存在某个敏感操作，它**没有**在**所有路径上**都被一个「绑定了*被认证的主体* 到*同一个资源 id*、且*覆盖该操作动作*」的守卫所支配。

判定过程拆成几个必须同时成立的子条件（见 `authz_reasoner._discharges`）：

- **守卫支配（guard-domination）** —— `dominates_all_paths`。守卫必须在到达敏感操作的**每一条路径**上都先执行（失败时 return/raise/abort）。
  - 有一个重要的**按操作类型放宽**的细节：对 `read`（读）来说，要评估归属守卫往往**必须先把行取出来**，所以守卫天然「晚于 FETCH」，但真正的 sink（把数据返回/披露）仍在检查之后——因此**读操作即使守卫不支配 FETCH，只要是同资源的归属/租户守卫也算被 discharge**。而对 `write/delete/admin`，不支配就意味着「效果可能在授权之前发生」，所以**必须支配**，否则归为 `AUTHZ_AFTER_EFFECT`。
- **绑定相等（binding equality）—— IDOR 的核心。** 守卫的 `resource_id_expr` 必须和操作的 `resource_id_expr` **规范化后相等**。规范化（`_norm`）刻意保守：只做小写化和去空白，**绝不**把 `a.id` 和 `id` 这种别名归一化——把语法不同的 id 当成不同的，正是暴露 IDOR 的手段。
- **自访问（self-access）。** 如果资源是由被认证主体自身派生的（`resource_id_origin == "subject"`，或表达式以 `current_user.` / `request.user.` / `self.user.` 打头），那么这个 id **不是攻击者可控的**，操作天然被授权，**无需**额外的归属守卫。这是 IDOR 的对偶情形（见 `_is_self_access`）。
- **义务（obligations）。** 函数可以声明「我本地不做这项授权，我依赖调用者/框架已经建立了它」（例如「路由层已加 `@login_required`」「调用者必须传入已校验过归属的 invoice」）。这类义务**沿调用链向上**，由祖先去 discharge——这正是第 3 节自顶向下传播解决的问题。

`_discharges(guard, op)` 的真值表（守卫 G 能否 discharge 操作 OP；按代码顺序短路）：

| 条件（按序判断） | 结果 |
|---|---|
| OP 非读 且 G 不支配所有路径 | 不 discharge → `not_dominating`（→ `AUTHZ_AFTER_EFFECT`） |
| G 不绑定主体 | 不 discharge → `no_subject_binding` |
| G 的 `action_scope` 不覆盖 OP 的 `action` | 不 discharge → `action_not_covered` |
| OP 有具体 id 且 G.kind∈{ownership,tenant,other} 且 id 相等 | **discharge** ✔ |
| OP 有具体 id 且 G.kind∈{ownership,tenant} 且 id 不等 | 不 discharge → `binding_mismatch`（IDOR） |
| OP 有具体 id 且 G.kind∈{role,authentication} 且 OP.kind==admin | **discharge** ✔ |
| OP 有具体 id 且 G.kind∈{role,authentication} 且 OP 非 admin | 不 discharge → `role_only_for_object` |
| OP 有具体 id 但 G 无 id 记录 | 不 discharge → `binding_unknown` |
| OP 无具体 id（如 admin/list）且 G 有任意上述 kind | **discharge** ✔ |

只要任意一个守卫返回 ✔，该操作就在本地被 discharge；否则它沦为一个义务，等待自顶向下传播来的祖先上下文 discharge（见第 3 节）。

### 五种漏洞子类（finding sub-kinds）

确定性检查器在判 VULNERABLE 时，会从 gap 原因里挑出最具信息量的子类（`_best_finding_kind`）：

| 子类 | 含义 |
|---|---|
| `MISSING_AUTHORIZATION` | 敏感操作，完全没有支配它的授权守卫 |
| `RESOURCE_BINDING_MISMATCH` | 有支配守卫，但绑定的是**另一个**资源 id（经典 IDOR；`binding_unknown` 也归入此类） |
| `ROLE_ONLY_GUARD_FOR_OBJECT_ACTION` | 操作是对象级的（带具体资源 id），但只有角色守卫，缺少按对象的归属检查 |
| `AUTHZ_AFTER_EFFECT` | 守卫存在但不支配所有路径（可能「先改后查」） |
| `MISSING_AUTHENTICATION` | 操作存在，但既无被认证主体、也无任何守卫/认证义务 |

### 四种判定（verdicts）

`VULNERABLE` / `SAFE` / `NEEDS_REVIEW` / `ERROR`：

- **VULNERABLE**：≥1 个敏感操作本地未被 discharge，**且**（这是入口点 **或** 没有任何传播来的调用者上下文能 discharge 它）。
- **SAFE**：每个敏感操作都被 discharge（本地或由调用者），或者函数根本没有敏感操作。
- **NEEDS_REVIEW**：某个敏感操作的授权依赖于**未知的策略执行**（框架/中间件/ORM 行级策略），函数局部视角无法确认——只报告，不算硬漏洞。
- **ERROR**：拿不到有效抽象（**fail-closed**，绝不判 SAFE）。

---

## 3. 插件运行流程（与 SPI 集成）

插件元数据（`AuthzPlugin.metadata`）声明了两个关键开关：

```python
requires_top_down_context=True   # 需要自顶向下上下文 worklist
needs_entrypoint=True            # 检查器把"是否入口点"当作信任边界
```

整个生命周期由 `src/plugins/driver.py` 的 `run_plugin` 驱动，分阶段进行：

### 阶段 3：自底向上派生事实（LLM 抽象）

驱动器按调用图自底向上顺序，对每个函数调用 LLM。`authz_prompts._system_prompt` + `_user_prompt` 要求模型输出**唯一**一个 JSON 对象，用 `[AUTHZ_JSON] ... [/AUTHZ_JSON]` 包裹。`parse_abstraction_response` 用 `_extract_authz_json` 解析；解析失败返回 `None` 触发重试；重试耗尽则 `make_error_facts` 产出 `status="error"` 的 fail-closed 事实。

JSON 的真实形状（字段来自 `_user_prompt`）：

```json
{
  "authenticated_subject": {"expr": "current_user", "origin": "framework_global"},
  "sensitive_operations": [
    {"op_id": "read_invoice", "kind": "read", "resource_type": "Invoice",
     "resource_id_expr": "invoice_id", "resource_id_origin": "request",
     "action": "read", "evidence": "Invoice.objects.get(id=invoice_id)"}
  ],
  "guards": [
    {"predicate_nl": "invoice.owner_id == current_user.id", "subject": "current_user",
     "resource_type": "Invoice", "resource_id_expr": "invoice_id",
     "action_scope": "any", "kind": "ownership",
     "dominates_all_paths": true, "evidence": "if invoice.owner_id != current_user.id: abort(403)"}
  ],
  "obligations": [
    {"requires_nl": "caller already checked invoice ownership",
     "resource_type": "Invoice", "resource_id_expr": "invoice_id",
     "action": "any", "reason": "this is an internal helper"}
  ],
  "establishes": [
    {"callee_name": "_do_delete", "guard_predicate_nl": "invoice.owner_id == current_user.id",
     "resource_id_expr": "invoice_id"}
  ],
  "notes": "ownership-checked read of an Invoice"
}
```

字段速查（均来自 `authz_prompts._user_prompt` 的契约，不可臆造）：

| 数组 / 字段 | 取值 | 检查器如何使用 |
|---|---|---|
| `sensitive_operations[].kind` | `read\|write\|delete\|admin\|other` | `read` 放宽支配要求；`admin` 允许被角色守卫覆盖 |
| `sensitive_operations[].resource_id_expr` | 表达式或 `null` | IDOR 的判定键，经 `_norm` 规范化后比较 |
| `sensitive_operations[].resource_id_origin` | `request\|param\|subject\|constant\|unknown` | `subject` 触发自访问豁免（`_is_self_access`） |
| `guards[].subject` | 表达式或 `null` | `_guard_binds_subject`：缺失则不绑定主体（除非 kind 是 authentication） |
| `guards[].kind` | `ownership\|role\|tenant\|authentication\|other` | 决定能否覆盖对象级操作 |
| `guards[].action_scope` | 动词或 `any` | `_action_covers`：`any` 覆盖一切 |
| `guards[].dominates_all_paths` | `true/false` | 写/删/admin 必须为 `true`；读可放宽 |
| `obligations[]` | 依赖调用者/框架建立的授权 | 通过 `summarize_for_caller` 向上可见，由自顶向下传播 discharge |
| `establishes[]` | 调用某 callee 前已建立的守卫 | 经 `establishes_to_contexts` 转成向下传播的上下文 |

注意 `authz` 的 `compose_calls` 是**默认空操作**：授权的 discharge **不是**自底向上的值计算（祖先可能才是建立守卫的人），所以它被放到自顶向下那一遍解决，而不是在组合阶段。被调用者的义务只是通过 `summarize_for_caller`（`_summarize`，输出形如 `REQUIRES[...]; sensitive_ops[...]`）以文本形式注入到调用者的 prompt 里。

### 阶段 3.5：自顶向下上下文传播

因为 `requires_top_down_context=True`，驱动器运行 `_run_top_down_context_worklist`：

1. **播种（`initial_context`）**：在每个入口点，把该函数建立的、支配所有路径的守卫转成可传播的上下文。转换由 `establishes_to_contexts` 完成——它只取 `dominates_all_paths=true` 的守卫，产出形如 `{"resource_id_expr", "action", "subject_bound", "kind"}` 的 dict（插件里用 `_freeze` 冻结成可按 `repr` 去重的元组）。
2. **传播（`propagate_context`）**：沿一条 caller→callee 调用边，把到达调用者的上下文，**加上**调用者在该调用前自己建立的守卫，一起下传给被调用者。
3. **合并 / 收敛（`merge_contexts`）**：worklist 在每个函数处合并新旧上下文（默认按 `repr` 去重，单调），只有集合变化才把被调用者重新入队；并用 `max_steps` 上界防止环图死循环。

### 阶段 4：确定性检查

驱动器对每个函数调用 `plugin.check(facts, ctx, propagated.get(unit.id, ()))`。`check` 先把传播来的上下文 flatten，然后调用 `classify(payload, is_entrypoint=..., propagated_contexts=...)`。

`classify` 的关键逻辑在于：对每个本地未 discharge 的操作，

```python
if not is_entrypoint and op_satisfied_by_context(op, propagated_contexts):
    continue   # 祖先调用者已经建立了匹配守卫 → 不是误报
```

`op_satisfied_by_context` 复用同一套绑定相等规则：某个传播来的上下文必须 `subject_bound=True`、动作覆盖、且（对带具体 id 的对象操作）`ownership/tenant/other` 的资源 id 与操作相等（或 `role/authentication` 上下文配 `admin` 操作）。

### 端到端走一遍

设有四个函数：

- **`get_invoice(invoice_id)`（入口点，例子 A）** → 操作 `read Invoice[invoice_id]`，只有 `@login_required`（认证）守卫，没有归属守卫。本地无法 discharge，是入口点 → **VULNERABLE / MISSING_AUTHORIZATION**。
- **`delete_invoice(confirm_id, invoice_id)`（入口点，例子 B）** → 守卫绑定 `confirm_id`，操作触碰 `invoice_id`，`_norm("confirm_id") != _norm("invoice_id")` 且都是 `ownership` → `_discharges` 返回 `binding_mismatch` → **VULNERABLE / RESOURCE_BINDING_MISMATCH**。
- **`update_my_profile()`** → 操作写 `current_user.id`（`resource_id_origin="subject"`），`_is_self_access` 命中，无需归属守卫 → **SAFE（self-access）**。
- **`_do_delete(invoice_id)`（内部辅助函数）** → 本地有义务「调用者已校验归属」。它**不是**入口点，其调用者 `delete_my_invoice` 在调用前建立了 `invoice.owner_id == current_user.id`（同 id）的归属守卫并放进 `establishes`。自顶向下那一遍把该上下文下传，`op_satisfied_by_context` 命中 → **SAFE（由调用者 discharge）**。如果同样的辅助函数**没有**任何祖先建立匹配守卫，则保持 fail-closed，被报为漏洞。

---

## 4. 我们的方案 vs 传统（非 LLM）方案

### 传统方案

- **MPChecker（CCS 2022）**、**BolaRay（CCS 2024）**：从 SQL / 代码属性图（CPG）里**推断**出一个授权模型，再在调用图上做支配性查询，来找未被授权保护的对象访问路径。
- **应用专属的 Semgrep 规则**：为某个框架/某个项目手写「敏感 sink 必须前置某个守卫调用」之类的模式。

它们的共同点是：要么需要从结构化信息（SQL/CPG）里**预先建模**授权策略，要么需要**人工编写**与具体应用强绑定的规则。

### 我们 LLM 方案的优势

- **识别应用专属守卫，无需手写规则**：`invoice.owner_id == current_user.id`、`current_user.is_admin`、`@login_required` 这些形态各异的检查，LLM 都能识别并归类（ownership/role/tenant/authentication）。
- **语义地理解资源身份**：能判断 `resource_id_expr` 究竟指向哪个资源，从而看出例子 B 那种「守卫 id ≠ 操作 id」的绑定错配。
- **不需要策略规范（policy spec）**：不依赖外部授权模型文件，直接从代码里读出主体、资源、动作、守卫。

### 我们方案的劣势（要诚实）

- **缺失推理本身脆弱**：当授权藏在中间件、装饰器、ORM 行级策略里时，函数局部视角看不到它，容易**误报**——这正是 `NEEDS_REVIEW` 存在的意义（软化为「需人工复核」而非硬判漏洞）。
- **跨函数的对象参数绑定是近似的**：调用边的实参绑定由「尽力而为」的正则解析器给出（见 `CallSite.arg_bindings` 的说明），可能部分或为空；自顶向下传播在跨函数处对资源 id 的匹配是近似的，漏洞通常**归因到入口点**而非精确的中间帧。
- **不是可靠性保证（not a soundness guarantee）**：LLM 抽象可能漏报或错报敏感操作/守卫。fail-closed 策略（`ERROR` 永不判 SAFE）只能降低风险，不能消除。

---

## 5. 局限与适用场景

`authz` 最适合**框架式的 CRUD 风格 Web handler**（路由/RPC 入口 + ORM 资源访问），那里「被认证主体—资源 id—动作—守卫」的结构清晰、入口点明确。对于授权完全下沉到声明式中间件、网关或数据库行级安全策略的系统，函数局部视角受限，结果更多会落在 `NEEDS_REVIEW`，应配合人工复核使用。

---

## 6. 确定性验证守卫（v2）

`authz.guarded_hoare.v2` 在 LLM 抽象和 reasoner 之间增加了 `src/authz_validation.py`。LLM 仍负责识别敏感操作及语义，但下列三类可由源码结构判定的前置条件不再信任模型自报的结论：

- `absolute_authentication_lifetime`：认证会话必须有锚定到登录/认证时刻的绝对截止时间。每次请求向后移动的 idle/sliding timeout 不能替代绝对上限。验证器只接受将“当前时刻派生的 idle deadline”和“认证时刻派生的 deadline”取最早值的结构（或等价的绝对上限结构）。缺失时报告 `MISSING_ABSOLUTE_AUTHENTICATION_LIFETIME / CWE-306`。
- `subject_object_binding`：按请求 id 获取的对象必须通过当前 project/tenant/account 作用域解析。框架参数转换钩子若先从作用域过滤的 query 中取对象，再把该对象注入 handler 参数，验证器会建立一个支配 handler 的 tenant guard；独立的 id-only lookup 不会被“用户已登录”或“用户可访问另一个 project”所 discharge。缺失/错绑时报告 `SUBJECT_OBJECT_BINDING_MISMATCH / CWE-639`。
- `object_permission`：执行异步任务、job 或其他具体对象前，权限检查必须绑定到**实际被 dispatch 的对象**并先于 dispatch。对 wrapper/button A 的权限不能授权其关联对象 B。缺失或错绑时报告 `MISSING_OBJECT_PERMISSION` / `OBJECT_PERMISSION_BINDING_MISMATCH / CWE-863`。

对于事务内的写入，验证器只在同一回滚边界内存在对象作用域复查、且失败会阻止提交时，才把该写入视为已授权。这个提交级授权不会传播到另一个被调度对象；调度对象仍需独立、同对象的 `object_permission`。

三个条件分别求值，不能相互替代。一个 authenticated subject 因此不能掩盖 wrong-project 或 wrong-object；传播上下文也必须携带相同的 scope/object identity 才能 discharge。

验证器还将 facts 绑定到函数和原始源码 digest，并把 schema 提升到 v2。旧 schema、源码变化后的 facts cache、模型伪造的 `_authz_validation` / `source_validation` guard 均 fail-closed 为 `ERROR`，而不会复用成 `SAFE`。结果序列化使用原始源码路径和提取器函数 token，使 pair runner 能严格执行 present/absent locus 语义；修复通过删除 endpoint 时，fixed side 必须保持该函数不存在，不能用其他 helper 的结果代替。

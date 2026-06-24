# FM-Agent 安全插件文档集

> 本目录是 FM-Agent 安全分析插件的**学习文档**。每个插件一份,讲清楚:面向的攻击、采用的理论、与 FM-Agent/SPI 的结合方式、以及相比传统(非 LLM)方案的优劣。
>
> 本文是**总览**,先读这篇建立全局认知,再读单个插件文档。

---

## 1. FM-Agent 是什么:一个通用技法

FM-Agent 原本是一个**基于自然语言霍尔逻辑推理**的程序分析工具(`{P} C {Q}`):用 LLM 为每个函数生成规约(前/后置条件),逐块推出实际后置条件,与规约比对,不符即报正确性 bug。

它真正的创新不是"霍尔逻辑",也不是某个具体分析,而是一个**通用技法**:

> **把一个传统上需要重型机器(SMT 求解器、抽象解释、模型检验、self-composition、分离逻辑证明器)的形式验证理论,拆成两步:**
> 1. **LLM 产出一个模块化的、per-function 的自然语言抽象**(它理解语义,擅长"什么依赖什么""这里成立什么""发生了什么事件");
> 2. **一个小型确定性检查器(纯 Python,不调 LLM)在这个抽象上做策略判定。**
> 结果**自底向上跨函数组合**(被调函数先分析,其摘要喂给调用者)。

安全分析就是这个技法的应用:**对每一类缺陷,采用恰当的形式理论,但都用同一套"LLM 出抽象 + 确定性检查器判定"的底座落地。** 因此安全领域被做成一个**插件组合(portfolio)**,而不是单一引擎。

### 为什么这样拆是对的

- **LLM 干它擅长的**:读懂真实代码的语义——"这个返回值依赖 password 吗""这个查询按 path-id 取了发票却没检查属主""这个 nonce 是每次新生成还是写死的"。它不需要源码标注、不需要为每个框架手写规则。
- **确定性检查器干它擅长的**:格点求值、支配关系、绑定相等、自动机判定——可重复、可审计、可对账。**LLM 绝不直接下结论**;判定权永远在确定性层。
- **降维**:许多安全属性是 2-safety 超属性(需关联两次执行),传统要 self-composition。把它降成"per-function 依赖/事件摘要",就变成 LLM 擅长、且模块化可组合的问题。

### 诚实的定位

这是一个**强力的语义 bug 发现器,不是 sound 的形式验证器**。检查器对"摘要"是 sound 的,但摘要由 LLM 产出、非保守导出。所以:

- **会漏**(LLM 可能标错标签、漏掉一条流/事件);
- **可能误报**(过度近似);
- **拿不准时 fail-closed**(Unknown → High / NEEDS_REVIEW,**绝不静默判 SAFE**)。

---

## 2. 插件 SPI:一套底座承载多种理论

代码结构(`src/plugins/`):

```
base.py       插件接口(SPI):公共信封 + AnalysisPlugin 抽象类 + 序列化钩子
callgraph.py  理论无关机器:源码扫描、函数抽取(复用 extract.py)、调用图、
              自底向上排序、入口点检测、调用点参数绑定
driver.py     通用驱动 run_plugin():抽取 → 自底向上派生 → 组合 → 
              可选自顶向下上下文传播 → 检查 → 渲染结果
```

每个插件 = **3 个文件**:
```
src/<name>_prompts.py    构造 LLM prompt + 解析 [<NAME>_JSON] 抽象
src/<name>_reasoner.py   确定性检查器(纯逻辑,可独立单元测试)
src/plugins/<name>.py    SPI 适配器(把上面两个接进底座)
```

### 一个插件要实现的 SPI 方法(`AnalysisPlugin`)

| 方法 | 职责 |
|---|---|
| `build_abstraction_prompt` | 为一个函数构造 LLM 消息(system + user) |
| `parse_abstraction_response` | 把 LLM 回复解析成本插件私有的"事实"(facts);解析失败返回 None 触发重试 |
| `make_error_facts` | 重试耗尽 → fail-closed 兜底事实(安全插件必须导向 ERROR/不安全,绝不 SAFE) |
| `summarize_for_caller` | 把被调函数的事实压成一行文本,注入调用者的 prompt |
| `compose_calls` | **组合算子**:把已分析的被调函数事实折叠进调用者(自底向上) |
| `check` | **确定性检查器**:在事实上判定 verdict |
| `initial_context` / `propagate_context` / `merge_contexts` | **可选**:自顶向下上下文传播(义务在祖先调用者处兑现时用) |
| `render_result` / `render_summary` | **可选**:定制输出 JSON 格式(IFC 用它产出兼容旧 viewer 的格式) |

driver 负责一切**理论无关**的编排;插件只拥有**理论**。铁律:**一旦 core 开始理解"守卫""nonce""typestate""污点",抽象就过度了。**

### 关键设计发现:组合方式不止一种

这是整套架构成败的关键——不同理论的"组合算子"根本不同,一个纯自底向上循环容纳不了全部。driver 因此支持**三个阶段**:① 自底向上 LLM 抽象 → ② 自底向上组合 → ③ **可选的自顶向下上下文传播**。

---

## 3. 五个插件总览

| 插件 | 形式理论 | 检测目标(CWE) | verdict 词汇 | 组合方式 | 合成靶验证 |
|---|---|---|---|---|---|
| [**ifc**](./ifc.md) | 非干涉(机密性 / Bell-LaPadula) | 隐私/密钥泄露(200/209/532) | LEAK · DECLASSIFIED · POLYMORPHIC · SECURE · ERROR | 自底向上(标签替换) | 68/68 与旧版一致 |
| [**authz**](./authz.md) | 守卫式霍尔 / 授权逻辑 | 访问控制 / IDOR-BOLA(862/863/639) | VULNERABLE · NEEDS_REVIEW · SAFE · ERROR | **自顶向下**(义务传播) | 8/9 严格,0 漏报 |
| [**taint**](./taint.md) | 非干涉(完整性 / Biba 对偶) | 注入(89/78/79/22/918/502…) | VULNERABLE · POLYMORPHIC · SANITIZED · SAFE · ERROR | 自底向上(sink 实例化) | 5/7 严格,0 漏报 |
| [**crypto**](./crypto.md) | CrySL(算法约束+typestate+溯源) | 加密误用(327/321/329/338/916/347/295) | VULNERABLE · WEAK · POLYMORPHIC · NEEDS_REVIEW · SAFE · ERROR | 自底向上(溯源) | 9/9 严格,0 漏报 |
| [**typestate**](./typestate.md) | 属性自动机 / typestate / 安全 LTL | 时序(367/352/295/772/775/672/415/306) | VULNERABLE · POLYMORPHIC · NEEDS_REVIEW · SAFE · ERROR | **双向**(splice + 上下文) | 8/11 严格,0 漏报 |

### 三种组合方式(同一 SPI 的不同用法)

- **自底向上 标签/事实替换**(ifc / taint / crypto):被调函数的参数化签名,在调用点用调用者的实参标签实例化。"`identity(x)` 的返回依赖 `{param:x}`"——caller 传 High 实参,High 污染就在 caller 处浮现。
- **自顶向下 义务传播**(authz):被调函数说"我需要守卫 G",但只有**祖先调用者**能兑现。从入口点出发,把"已建立的守卫上下文"沿调用边下传。这不是自底向上的值计算,是**向上流的需求**。
- **双向**(typestate):资源生命周期/TOCTOU 用自底向上事件拼接;CSRF/auth 的"必需事件可能在祖先"用自顶向下上下文。

这三种风格能跑在同一个 driver 上,证明了 SPI 的通用性。

### 五个插件共享的纪律

1. **fail-closed**:拿不准 → 保守(High / tainted / NEEDS_REVIEW),绝不静默 SAFE。
2. **POLYMORPHIC**:调用者依赖的事实(参数标签/资源状态由 caller 决定)——孤立看无法判定,在调用点实例化。
3. **LLM 不下结论**:LLM 只产出事实+证据,确定性检查器做判定。
4. **抽象与源码分离的测试方法论**:合成靶源码**不含**任何泄露/标签/verdict 提示注释(那会提示 LLM,算作弊);ground truth 单独存到 `expected.json`,运行前提交(不拟合)。"跑完≠跑对"——每次人工核验 verdict,不只看分数。

---

## 4. 怎么运行

```bash
# 统一 CLI:对一个目标项目跑某个插件
python3 run_plugin.py <plugin> <proj_dir>
#   plugin ∈ {ifc, authz, taint, crypto, typestate}

# 输出写到 <proj_dir>/fm_agent_<plugin>/results/**.json + summary.json
# (ifc 为兼容旧工具,写到 fm_agent_ifc/ifc_results/)
```

可视化:`ifc_viewer.py` 是一个零依赖的 web viewer,**自动识别**目标项目跑过哪个插件并加载。左栏函数列表 + 调用图,中栏按插件定制的分析面板,右栏 LLM 的 prompt/response。每个插件配一个原理介绍弹窗(左上角叹号)。

```bash
python3 ifc_viewer.py --host 0.0.0.0 --port 8765 --dir <proj_dir>
```

---

## 5. 配置

各插件在 `config.py` 有独立的模型/重试/fail-closed 旋钮:

```
IFC_FLOW_SIGNATURE_MODEL / MAX_IFC_ITER / IFC_FAIL_CLOSED
AUTHZ_MODEL / MAX_AUTHZ_ITER / AUTHZ_FAIL_CLOSED
TAINT_MODEL / MAX_TAINT_ITER / TAINT_FAIL_CLOSED
CRYPTO_MODEL / MAX_CRYPTO_ITER / CRYPTO_FAIL_CLOSED
TYPESTATE_MODEL / MAX_TYPESTATE_ITER / TYPESTATE_FAIL_CLOSED
```

默认都 fall back 到全局 `LLM_MODEL`。

---

## 6. 相关设计文档

- [`docs/security_portfolio_roadmap.md`](../security_portfolio_roadmap.md) — 整个安全领域按形式属性类的可行性映射(为什么有些类适合、有些不适合这套底座)。
- [`docs/security_roadmap.md`](../security_roadmap.md) — 机密性↔完整性对偶的论证。
- [`docs/plugin_architecture.md`](../plugin_architecture.md) — 插件 SPI 的架构设计(Oracle 论证 + 可复用机器清单)。
- [`docs/ifc_design.md`](../ifc_design.md) — IFC 的原始设计稿。

---

*文档随实现演进。每个插件文档以其源码为准(`src/<name>_prompts.py` + `src/<name>_reasoner.py` + `src/plugins/<name>.py`)。*

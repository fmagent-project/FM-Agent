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
> 2. **Python source validator 对可判定的窄模式纠正或补充事实,再由确定性检查器做策略判定。**
> 跨函数结果按插件理论选择自底向上组合、自顶向下上下文传播,或两者的有限组合。

安全分析就是这个技法的应用:**对每一类缺陷,采用恰当的形式理论,但都用同一套"LLM 出抽象 + 确定性检查器判定"的底座落地。** 因此安全领域被做成一个**插件组合(portfolio)**,而不是单一引擎。

### 为什么这样拆是对的

- **LLM 干它擅长的**:读懂真实代码的语义——"这个返回值依赖 password 吗""这个查询按 path-id 取了发票却没检查属主""这个 nonce 是每次新生成还是写死的"。它不需要源码标注、不需要为每个框架手写规则。
- **确定性层干它擅长的**:源码可判定模式校验、格点求值、支配关系、绑定关系和自动机判定,可重复、可审计、可对账。**LLM 不直接下 verdict**;判定权在 validator 和 reasoner。
- **降维**:许多安全属性是 2-safety 超属性(需关联两次执行),传统要 self-composition。把它降成"per-function 依赖/事件摘要",就变成 LLM 擅长、且模块化可组合的问题。

### 诚实的定位

这是一个**强力的语义 bug 发现器,不是 sound 的形式验证器**。检查器是确定性的,但输入摘要包含 LLM facts,source validator 也只覆盖窄语法模式。所以:

- **会漏**(LLM 可能标错标签、漏掉一条流/事件);
- **可能误报**(过度近似);
- **安全关键结构、枚举、缓存绑定和已建模 finding 尽量 fail-closed**。具体 unknown/fallback 行为因插件和规则而异,不能把所有缺失字段都理解为自动 `NEEDS_REVIEW`。

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

每个插件至少有 **3 个主文件**,source-backed 插件另有 validator:
```
src/<name>_prompts.py    构造 LLM prompt + 解析 [<NAME>_JSON] 抽象
src/<name>_reasoner.py   确定性检查器(纯逻辑,可独立单元测试)
src/plugins/<name>.py    SPI 适配器(把上面两个接进底座)
src/<name>_validation.py 可选:从源码纠正/补充高信任事实;部分插件也在此生成缓存绑定
```

### 一个插件要实现的 SPI 方法(`AnalysisPlugin`)

| 方法 | 职责 |
|---|---|
| `build_abstraction_prompt` | 为一个函数构造 LLM 消息(system + user) |
| `parse_abstraction_response` | 把 LLM 回复解析成本插件私有的"事实"(facts);解析失败返回 None 触发重试 |
| `make_error_facts` | 重试耗尽时生成 error facts;部分插件在 `check` 中还有受限的 source-only fallback |
| `summarize_for_caller` | 把被调函数的事实压成一行文本,注入调用者的 prompt |
| `compose_calls` | **组合算子**:把已分析的被调函数事实折叠进调用者(自底向上) |
| `check` | **确定性检查器**:在事实上判定 verdict |
| `initial_context` / `propagate_context` / `merge_contexts` | **可选**:自顶向下上下文传播(义务在祖先调用者处兑现时用) |
| `render_result` / `render_summary` | **可选**:定制输出 JSON 格式(IFC 用它产出兼容旧 viewer 的格式) |

driver 负责一切**理论无关**的编排;插件只拥有**理论**。铁律:**一旦 core 开始理解"守卫""nonce""typestate""污点",抽象就过度了。**

### 关键设计发现:组合方式不止一种

这是整套架构成败的关键——不同理论的"组合算子"根本不同,一个纯自底向上循环容纳不了全部。driver 因此支持**三个阶段**:① 自底向上 LLM 抽象 → ② 自底向上组合 → ③ **可选的自顶向下上下文传播**。

---

## 3. 七个插件总览

> 组合已从五个扩展到 **七个**。后两个(**resource**、**authn**)由
> `fm-plugin-generator` skill 在同一套 SPI 上自主生成 —— 见 §7。

| 插件 | 形式理论 | 检测目标(CWE) | verdict 词汇 | 组合方式 |
|---|---|---|---|---|
| [**ifc**](./ifc.md) | 非干涉(机密性 / Bell-LaPadula) | 隐私/密钥泄露(200/209/532) | LEAK · DECLASSIFIED · POLYMORPHIC · SECURE · ERROR | 自底向上(标签替换) |
| [**authz**](./authz.md) | 守卫式霍尔 / 授权逻辑 | 访问控制 / IDOR-BOLA(862/863/639/306) | VULNERABLE · NEEDS_REVIEW · SAFE · ERROR | **自顶向下**(义务传播) |
| [**taint**](./taint.md) | 非干涉(完整性 / Biba 对偶) | 注入(89/78/79/22/918/502…) | VULNERABLE · POLYMORPHIC · SANITIZED · SAFE · ERROR | 自底向上(sink 实例化) |
| [**crypto**](./crypto.md) | CrySL(算法约束+typestate+溯源) | 加密误用(327/321/329/338/916/347/295) | VULNERABLE · WEAK · POLYMORPHIC · NEEDS_REVIEW · SAFE · ERROR | 自底向上(溯源) |
| [**typestate**](./typestate.md) | 属性自动机 / typestate / 安全 LTL | 时序(367/352/295/772/775/672/415/306/862) | VULNERABLE · POLYMORPHIC · NEEDS_REVIEW · SAFE · ERROR | **有限双向**(事件 splice + 上下文;不转移 returned-resource ownership) |
| [**resource**](./resource.md) | 资源界限(量级→代价操作→支配性界限) | DoS(400/770/674/1333/409/789/834) | VULNERABLE · POLYMORPHIC · BOUNDED · SAFE · ERROR | 自底向上(taint 姊妹:量级实例化) |
| [**authn**](./authn.md) | 守卫式霍尔(认证事件支配+强度+会话卫生) | 认证完整性(287/384/613/522/294/620/640) | VULNERABLE · NEEDS_REVIEW · SAFE · ERROR | **自顶向下**(authz 姊妹:义务传播) |

### 三种组合方式(同一 SPI 的不同用法)

- **自底向上 标签/事实替换**(ifc / taint / crypto / resource):被调函数的参数化签名,在调用点用调用者的实参标签或量级实例化。"`identity(x)` 的返回依赖 `{param:x}`"表示 caller 传 High 实参时,High 污染会在 caller 处浮现。
- **自顶向下 义务传播**(authz / authn):被调函数声明所需授权或认证义务,但只有祖先调用者能兑现。从入口点出发,把已建立的守卫上下文沿调用边下传。这不是自底向上的值计算,而是向祖先提出需求。
- **有限双向**(typestate):caller-visible 普通事件可自底向上拼接;CSRF/auth 的祖先 `must` 事件可自顶向下传播。拼接不保留 callee CFG 边,也不会把 returned resource 变成 caller 的 ownership 义务。

这三种风格能跑在同一个 driver 上,证明了 SPI 的通用性。

### 所有插件共享的纪律

1. **fail-closed 边界**:畸形安全关键结构和已识别但未证明安全的 finding 保守处理;实现了 source digest/version marker 的插件还会拒绝或重验旧缓存。每个插件对 unknown、cache 与 source-only fallback 的精确语义见其正文。
2. **POLYMORPHIC**:调用者依赖的事实(参数标签/资源状态由 caller 决定)——孤立看无法判定,在调用点实例化。
3. **LLM 不下结论**:LLM 只产出事实+证据,确定性检查器做判定。
4. **抽象与源码分离的测试方法论**:合成靶源码**不含**任何泄露/标签/verdict 提示注释(那会提示 LLM,算作弊);ground truth 单独存到 `expected.json`,运行前提交(不拟合)。"跑完≠跑对"——每次人工核验 verdict,不只看分数。

---

## 4. 怎么运行

```bash
# 统一 CLI:对一个目标项目跑某个插件
python3 run_plugin.py <plugin> <proj_dir>
#   plugin ∈ {ifc, authz, taint, crypto, typestate, resource, authn}
#   (插件名单由 src/plugins/registry.py 自动派生,新增插件无需改 CLI)

# 输出写到 <proj_dir>/fm_agent_<plugin>/results/**.json + summary.json
```

可视化:`ifc_viewer.py` 是一个零依赖的 web viewer,**自动识别**目标项目跑过哪个插件并加载。左栏函数列表 + 调用图,中栏按插件定制的分析面板,右栏 LLM 的 prompt/response。每个插件配一个原理介绍弹窗(左上角叹号)。

```bash
python3 ifc_viewer.py --host 0.0.0.0 --port 8765 --dir <proj_dir>
```

---

## 5. 配置

各插件在 `config.py` 有独立模型选择:

```
IFC_FLOW_SIGNATURE_MODEL
AUTHZ_MODEL
TAINT_MODEL
CRYPTO_MODEL
TYPESTATE_MODEL
RESOURCE_MODEL
AUTHN_MODEL
```

模型默认都 fall back 到全局 `LLM_MODEL`。当前统一 driver 的默认重试预算是
`MAX_IFC_ITER`;其他 `MAX_<PLUGIN>_ITER` 常量尚未接入 `run_plugin.py`。只有
`IFC_FAIL_CLOSED` 当前会改变 reasoner 的 unknown 处理;其他插件的
`<PLUGIN>_FAIL_CLOSED` 仍是未接线的 future toggle,不是运行时裁决开关。

---

## 7. 插件注册表 + 自主生成新插件

**注册表(`src/plugins/registry.py`)** 是"有哪些插件"的唯一真相源。它是**纯数据**
(不 import 任何插件类、不拉 openai),所以零依赖的 `ifc_viewer.py` 也能安全读取;
插件类经 `load_plugin_class()` 懒加载。加一个插件 = 加一条 manifest + 放主文件和可选 validator;
`run_plugin.py`、整个 `eval/` 管线、viewer 全部自动识别,**无需改任何消费点**
(以前要手工改 6 处分散代码)。

最初的五个插件各有一个 skill(`skills/fm-plugin-<name>/SKILL.md`),可挂载到现代
coding agent;resource 和 authn 当前没有独立 skill。已有 skill 的 frontmatter 声明触发场景、调用方式和 verdict 语义。

**`fm-plugin-generator` 元 skill** 能自主生成新插件:输入(新 CWE + 形式理论 +
测试集)→ 读 SPI + 最近的模板插件 → 产出 3 文件 + manifest + viewer JS 渲染器 →
经注册表自动发现 → 复用 `stratify → run_baselines → run_ours → score → audit`
自测循环迭代。**resource 和 authn 两个插件就是它的产物**(分别验证了自底向上和
自顶向下两种组合方向);过程中还借自测循环发现并修复了工具自身的多个 bug。

---

## 8. 相关设计文档

- [`docs/security_portfolio_roadmap.md`](../security_portfolio_roadmap.md) — 整个安全领域按形式属性类的可行性映射(为什么有些类适合、有些不适合这套底座)。
- [`docs/security_roadmap.md`](../security_roadmap.md) — 机密性↔完整性对偶的论证。
- [`docs/plugin_architecture.md`](../plugin_architecture.md) — 插件 SPI 的架构设计(Oracle 论证 + 可复用机器清单)。
- [`docs/ifc_design.md`](../ifc_design.md) — IFC 的原始设计稿,用于理解历史动机,不作为当前实现规范。

---

*文档随实现演进。每个插件文档以其源码和 focused tests 为准(`src/<name>_prompts.py` + `src/<name>_reasoner.py` + `src/plugins/<name>.py` + 可选的 `src/<name>_validation.py`)。*

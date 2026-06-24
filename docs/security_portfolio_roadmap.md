# 安全分析 Portfolio 路线图：一套 LLM-NL-reasoning 底座承载多种形式理论

> 状态：调研稿（未实现）。本文是 `docs/security_roadmap.md` 的**修正与升维版**。
>
> 前一版的错误：把调研窄化成"我们这套 IFC 能解决什么",把访问控制/时序/内存/可用性判成"需全新机器/用错工具"——隐含"死路"。
>
> **本版的修正**：那些不是死路。FM-Agent 真正的创新不是"霍尔逻辑"也不是"IFC",而是一个**通用技法**——对每一类缺陷采用**恰当的形式理论**(不限于 IFC),但都用同一套底座落地：**LLM 产出模块化的 per-function 自然语言抽象 → 小型确定性检查器做判定 → 自底向上跨过程组合**。安全领域因此是一个**理论组合(portfolio)**,不是单一引擎。
>
> 调研来源：Oracle(理论可行性推理)+ 两路 librarian(形式理论的可组合性接地 + 真实频率/竞品格局)。三路高度一致。

---

## 0. Meta-thesis：先把"通用技法"严格定义清楚

### 0.1 正确措辞(Oracle 修正,已采纳)

不能宣称"LLM 取代形式机器、确定性检查器判定原属性"。准确表述是:

> **一个形式理论指导我们该向 LLM 索取什么"有限语义摘要"。确定性检查器随后在这些摘要上,判定该属性的一个"抽象版本"。**

推论(必须诚实对外讲):
- 检查器对**摘要**是 sound 的;但摘要由 LLM 产出、**非机械保守导出**。
- 因此系统是**强力的语义 bug 发现器,不是 sound 的形式验证器**。
- 端到端 soundness 要求摘要"保守 + 对该属性完备 + 可组合"——这恰是多数类别会断的地方。

最终定稿措辞:
> FM-Agent generalizes when a formal security property can be reduced to **compositional, human-legible per-function semantic summaries**, and when the remaining decision problem over those summaries is **small and deterministic**. The LLM supplies the semantic abstraction; the deterministic checker supplies consistency, policy evaluation, and repeatability. This is **formalism-guided semantic security analysis**, not fully sound verification.

### 0.2 一个理论能上这套底座的"准入条件"

1. **存在有限可组合摘要**——每个函数可由"对 caller 足够"的事实概括(依赖集/前置条件/产生的 effect/发出的 event/状态转移/守卫/资源绑定/生命周期变化)。IFC 成立正因依赖集天然可组合。
2. **摘要在自底向上组合下稳定**——caller 能直接实例化 callee 摘要,无需重析其内部。需要全程序不动点/任意 caller-callee 互推/全局轨迹枚举的属性,可行性骤降。
3. **事实是语义的、但人类可读**——LLM 擅长"返回值依赖 password""这分支检查了用户是否拥有该发票""这调用校验了 CSRF""此 buffer 在此释放";不擅长穷举路径分裂、指针别名闭包、循环不变式、数值界、竞态、概率/定量断言。
4. **检查器有小而可判定的抽象域**——二级格、守卫支配关系、有限自动机、typestate 转移系统、may/must 依赖集、污点可达、新鲜度类别。反例:精确复杂度、完整分离逻辑、调度交错、cache 时序分布。
5. **存在可外部定义的策略词汇**——检查器需知道什么算 secret/untrusted/敏感操作/授权守卫/crypto nonce/状态转移/公开输出。若策略必须纯从应用代码推断,**缺失类 bug(absence)会不可靠**。
6. **失败可保守化**——Unknown 应映射到 High/untrusted/unguarded/may-leak/needs-review(fail-closed)。给出有用安全姿态,代价是假阳上升。

### 0.3 可组合性会在哪儿断

- **全局轨迹属性**(跨请求/任务/回调/分布式服务/会话的全程序顺序)。
- **关系性/定量属性**(常量时间、概率加密性质、侧信道容量、精确复杂度、调度敏感竞态)。
- **无闭世界的 absence 推理**("没有缺失授权检查"——除非所有守卫/入口/中间件/装饰器/框架钩子可见且建模)。
- **强路径/别名敏感属性**(内存安全、TOCTOU、锁序、生命周期——依赖精确路径条件与别名身份)。
- **框架隐藏语义**(授权中间件、ORM 过滤、DI、路由装饰器、crypto 默认值、async 回调把安全语义藏在函数体之外)。

---

## 1. 关键存在性证明：per-function 模块摘要对安全属性是可行的

这不是我们的一厢情愿。**工业级先例已经证明"per-function 模块摘要 + 确定性组合"对安全属性类成立**:

- **分离逻辑 + bi-abduction(Infer)**——Calcagno-Distefano-O'Hearn-Yang, POPL 2009。bi-abduction **就是**一个"逐过程、自底向上、无需调用上下文"地算出每函数 `{pre} f {post}` 三元组的算法。Infer 在 Meta 跑到百万行级,**正因为这种可组合性**。这是"模块化 per-function 抽象 + 确定性组合"对安全属性可行的**最强存在性证明**。
- **Typestate transfer function(ESP / CrySL-IDEal)**——每函数摘要 = FSM 状态上的转移函数(入口状态→出口可达状态),沿调用链组合。
- **AARA(RAML)**——每函数 = 资源标注类型 `(τ, q)`,组合 = 类型应用,成本界推断归约为 LP。

我们要做的,是把这些理论的"重型符号机器"换成"LLM 产出同形态的 NL 摘要"。**理论侧的可组合性已被证明,我们替换的是抽象的获取方式。**

---

## 2. 学术界已在做这件事(prior art + 我们的差异化)

"LLM 出抽象、确定性层判定"是 2024–2026 被公认的研究方向,名为 **neuro-symbolic static analysis / LLM-generated specifications**:

| 工作 | LLM 产出 | 确定性层 | 与我们的关系 |
|---|---|---|---|
| **IRIS** (ICLR 2025) | per-project 污点 source/sink spec | CodeQL 做可达 | 最接近的污点先例;LLM 出 spec,CodeQL 判定 |
| **LLMSA** (2024) | Datalog 里的"neural relation"语义谓词 | Datalog 规则组合 | 标题即"compositional";污点召回 78.57% |
| **MoCQ** (Columbia 2025) | CodeQL/Joern **DSL 查询** | 静态引擎执行查询 | 形式产物是**图查询**,非逻辑 spec;发现 25 个真实新漏洞 |
| **COBALT-TLA** (2026) | TLA+ spec | TLC 模型检验 | 协议级;证明"prover 反馈可中和 LLM 幻觉" |
| **VeriGuard** (2025) | 霍尔 pre/post | Nagini 验证 | Python;偏 agent 安全合规,非漏洞检测 |
| **SpecSyn / Preguss** (2026) | per-segment / per-unit ACSL spec | Frama-C | **依赖图分解成段**——印证 per-function 模块化方向 |

**我们的差异化(一句话)**:别人用 LLM 当**模式抽取器/查询生成器**;**我们用 LLM 当语义抽象层**——它理解函数"该做什么"(霍尔 spec)与"什么依赖什么"(IFC),把语义意图形式化,检查器校验**语义意图**而非图结构模式。而且没人在做"**霍尔 spec + IFC 断言**作为抽象层、跨**多种缺陷类别**的统一漏洞检测流水线"。

> 诚实的新颖性风险:MoCQ(图查询版)与 COBALT-TLA(协议级)最接近,论文里需直接引用并区分。生产工具(Snyk/GitHub Autofix/Pixee)都把 LLM 用于**修复**(在确定性检测回路内),不是用于**抽象产出喂形式检查器**——这正是格局空隙。

---

## 3. 按属性类的可行性映射(理论 → NL 抽象 → 确定性检查器 → 判决)

| 类 | 形式理论 | per-function NL 抽象 | 确定性检查器 | 可行性 | 主导失败模式 |
|---|---|---|---|---|---|
| 机密性 IFC(现状) | 非干涉(2-safety) | 各输出通道的输入依赖集 + declass 锚点 | 二级格求值 | **已落地** ✅ | 复合字段不分解 |
| 完整性污点 | 非干涉(Biba 对偶) | untrusted 输入 + effect/sink + sanitizer 事实 | 污点可达 + 分型 endorsement | **HIGH** | source/sink 覆盖缺失 |
| 访问控制/IDOR | 授权逻辑 / 守卫式霍尔 | 敏感操作 + 支配守卫 + 主体/资源/动作绑定 | 守卫支配 + 绑定相等检查 | **MEDIUM-HIGH(限定域)** | absence 推理 + 框架隐藏守卫 |
| 时序/协议/typestate | typestate / 安全 LTL / 会话类型 | may/must **有序**事件迹 + 前置/后置 typestate | FSM 转移函数沿调用链组合 | **MEDIUM(本地协议)** | 跨过程顺序的路径敏感性 |
| 加密误用 | API 协议安全 + 值溯源 + 新鲜度 | 算法选择 + key/IV/nonce/RNG 溯源 + verify-before-trust 事件 | 值/依赖/事件上的规则引擎 | **HIGH(语法)/ MEDIUM-HIGH(语义)** | 库特定语义 + 值别名 |
| 资源/DoS | 终止性 + 成本(ranking/AARA) | untrusted 是否界定循环/递归/分配 + 有无上限 | 污点→界 + 缺界检查 | **MEDIUM(攻击者控界)/ LOW(精确复杂度)** | 定量界 + 环境依赖成本 |
| 内存安全 | 分离逻辑 / 所有权 | alloc/free/null/escape/alias/lifetime 事实 | 所有权/生命周期一致性规则 | **LOW-MEDIUM(仅 C/C++)** | 别名/路径精度 + 语言不匹配 |
| 侧信道/常量时间 | 关系非干涉 / 常量时间类型 | secret 依赖的分支/内存索引/提前返回 | 定性常量时间规则 | **MEDIUM(指标)/ NO(保证)** | 定量微架构鸿沟 |

### 3.1 各类要点(摘 Oracle + librarian)

**完整性污点**——非干涉的 Biba 对偶(BLP 箭头反向)。sink 是**操作点**(`sink:sql.execute`)非"可观测输出通道";sanitizer **上下文敏感、按 sink 分型**(Pysa `@Sanitize(TaintSink[SQL])`);source 多是**调用结果**(`request.GET["x"]`)非命名变量。详见 `docs/security_roadmap.md` §2-3。

**访问控制**——操作理论选**守卫式霍尔**(非完整 ABLP says-逻辑):`{authenticated(subj) ∧ authorized(subj,res,act)} op {...}`。IDOR/BOLA 的核心规则不是"有检查",而是 `guard.subject==auth_subject ∧ guard.resource_id==op.resource_id ∧ guard.action⊇op.action ∧ guard 在所有路径支配 op`。学术接地:MPChecker(CCS 2022,44 新漏洞/13.7% FP)、BolaRay(CCS 2024,193 真漏洞/52 CVE)——但二者是调用图支配查询,**没有可导出的 per-function 霍尔契约**,这正是我们底座要填的空隙。
> 致命点:**missing-check 是 absence 推理**。授权若在中间件/装饰器/ORM 行级策略/服务网格/DB RLS,函数局部检查器会**误报缺守卫**。MVP 必须限定到已知框架的 CRUD 风格资源操作。

**时序/typestate**——**修正用户假设**:"per-function 有序序列"不够,必须 **may/must 偏序迹 + 路径覆盖 + 前置/后置 typestate**,否则 caller 无法安全组合摘要。ESP/CrySL-IDEal 印证:每函数摘要 = FSM 状态转移函数,可组合。先做 TLS-verify-before-use / CSRF-before-state-change / open-close 协议;**避开 TOCTOU 与跨请求工作流**(需并发/环境建模)。

**加密误用**——**语法子类**(MD5/DES/ECB/verify=False/JWT alg=none)是 linter 的活,HIGH 但非我们的研究贡献;**语义子类**(IV/nonce 是否每次新鲜?key 是否来自 CSPRNG?签名验证是否支配对声明的信任?)需依赖/值/事件推理,是好契合。理论接地:CrySL(ECOOP 2018)的 ORDER(FSM)+CONSTRAINTS(值)+REQUIRES/ENSURES(跨类)。

**内存安全**——**陷阱预警**:别框成"用 NL 摘要做分离逻辑"。理论侧 bi-abduction 是最强可组合先例,但真实 C/C++ 内存安全依赖别名/路径可行性/宏/指针算术/分配器约定——正是 LLM 摘要最不可靠处。**Python 验证不迁移到 C/C++**。除非研究目标明确指向 C/C++,否则不优先;若做,从 null-deref 与简单所有权转移 API 起步,不碰一般 UAF。

**侧信道**——我们的 IFC 已抓 secret 依赖控制流(隐式流),对源码级常量时间反模式给 MEDIUM;但真实时序/侧信道保证需泄漏模型(编译器/分支预测/cache/内存布局),定量鸿沟使其 NO。**定位为 IFC 的"定性侧信道指标"扩展,不是常量时间验证器**。

---

## 4. Portfolio 引擎架构

用户的架构方向正确,**一处关键调整**:不要把所有类强塞进一个通用 schema。用**公共信封 + 理论专属事实切片**。

```text
源码
  → 抽取 / 调用图 / 入口点
  → LLM per-function 事实生成(可分属性专项 pass,避免一次性塞爆)
  → 归一化 + 证据校验(evidence span)
  → 自底向上摘要组合
  → 插件式确定性检查器(每类一个)
  → 带证据/假设/置信度的发现
```

### 公共事实信封(最小集,服务最多检查器)
`function_id / entry_context(is_entrypoint, route, auth_context) / inputs(source_kind, trust_label) / outputs(channel, dependencies) / effects(kind, resource, action, deps) / guards(predicate_nl, subjects, resources, dominates, path_coverage) / events(kind, object, order, path_coverage) / state_facts / value_facts(provenance, freshness, bounds) / lifecycle_facts(ownership, alias_set) / assumptions / unknowns / evidence(code_span) / confidence`

### 插件只取所需切片
- IFC:inputs/outputs/dependencies/declass
- 完整性:untrusted inputs/effects/sanitizer 事实
- 授权:effects/guards/主体-资源-动作绑定
- typestate:events/order/前后状态
- crypto:crypto effects/值溯源/新鲜度/事件序
- DoS:untrusted inputs/循环-分配-阻塞事实/界
- 内存:lifecycle/alias/ownership/nullability
- 侧信道:secret 依赖/控制-内存-终止可观测

### 若强行单一 schema 会断什么
精度丢失(泛化的"event"无法忠实表达别名/授权绑定/nonce 新鲜度/循环界);检查器歧义(同一依赖事实对 IFC 是好、对侧信道是疑、对授权是预期);prompt 退化(要 LLM 一次吐所有事实→摘要臃肿低质);**组合算子不匹配**(IFC 组合集合、typestate 组合迹、授权组合支配与资源绑定、内存组合所有权转移——一个算子套不住所有)。

---

## 5. 排序与分期(可行性 × 真实覆盖 × 增量成本)

### 真实频率接地(ROI 维度)
- **内存安全**:~70% 的 C/C++ CVE(MSRC/Chrome);CWE-787 在 CISA KEV 武器化排名第一。但**仅 C/C++**,且 Rust 普及后份额下降。
- **访问控制**:OWASP A01 **2021 第一**;318,487 次出现、19,013 CVE;IDOR 对纯语法 SAST **机制上不可检**——正是语义推理的用武之地。
- **加密/硬编码**:CWE-798 有 9 个 KEV(活跃利用);GitGuardian 2023 年 GitHub 上 1280 万次密钥泄露。
- **时序**:CSRF(CWE-352)2024 跃升至第 4(量大);TOCTOU 罕见但高危。
- **资源/DoS**:CWE-400 新进 Top25(#24),**零 KEV**(常见但非攻击者优先武器化)。

### 排序

| 名次 | 类 | 可行性 | 覆盖 | 增量成本 | 结论 |
|---:|---|---|---|---|---|
| 1 | 完整性污点 | High | High | 低-中 | IFC 的最佳对偶,已定为 #1 |
| 2 | **访问控制 / IDOR-BOLA** | 中-高(限定) | **极高** | 中 | **次优之选** |
| 3 | 加密语义误用 | 中-高 | 高 | 中 | 强后续;规则比授权更清晰 |
| 4 | 时序 / 协议 typestate | 中 | 中-高 | 中-大 | 待 event 基建就绪后 |
| 5 | 可用性 / 资源界污点 | 中(限定) | 中 | 中 | 有用但噪声大,品牌为"资源界污点"非"可用性验证" |
| 6 | 内存安全 | 低-中 | 仅 C/C++ 高 | 大 | 研究支线,非核心路线 |
| 7 | 侧信道 / 常量时间 | 指标中/保证低 | 小众但重要 | 中-大 | 仅作 IFC 扩展 |

### 为什么访问控制是 #2(而非 typestate/crypto)
1. 真实影响极高(OWASP #1;IDOR 语法 SAST 漏检);
2. 契合 LLM 强项("此查询按 path-ID 取发票""此检查验证 owner==current_user");
3. **复用现有机器**——守卫式霍尔前置条件贴近正确性轨道,主体/资源依赖贴近 IFC/污点;
4. 确定性检查器可以很简单(支配 + 绑定相等 + 动作覆盖 + Unknown 兜底)。

### 访问控制 MVP(窄而严)
- 入口:web 路由/RPC handler/被 handler 调用的 service 方法
- 敏感操作:对用户/租户拥有资源的 DB 读写删、用请求派生 ID 的对象存储访问、管理动作、跨租户查询
- 要求守卫:已认证主体存在 ∧ 守卫支配操作 ∧ 守卫把主体绑定到该资源/把角色绑定到该动作 ∧ 守卫中资源身份 == 操作中资源身份
- 发现类别:`MISSING_AUTHENTICATION / MISSING_AUTHORIZATION / RESOURCE_BINDING_MISMATCH / TENANT_FILTER_MISSING / ROLE_ONLY_GUARD_FOR_OBJECT_SPECIFIC_ACTION / AUTHZ_AFTER_EFFECT / UNKNOWN_POLICY_ENFORCEMENT(标"待复核",非漏洞)`

---

## 6. 分阶段路线

- **Phase 1 — 统一事实层**:把当前 per-function 产物扩成公共信封(依赖/effect/guard/event + 证据 + 置信度 + unknowns)。先别过度建内存/时序迹。
- **Phase 2 — 完整性污点**:IFC 机器反向用(untrusted→敏感 sink)。检查器 = 污点可达 + sanitizer/validator 事实。配 source/sink/endorsement 本体 + 结构化字段分解(直接修 requests CVE 漏报)。
- **Phase 3 — 访问控制 MVP**:守卫-敏感操作检查器。这是"FM-Agent 超越信息流"的最佳研究演示。
- **Phase 4 — 加密语义误用**:加值溯源 + 新鲜度,从 nonce/key/RNG/签名验证规则起步。
- **Phase 5 — typestate/事件自动机**:泛化 event 抽取 + 路径覆盖,先攻本地 API 协议。
- **Phase 6 — 资源界污点**:复用 untrusted 事实 + 循环/分配/阻塞摘要,不碰精确复杂度。
- **Phase 7 — 探索支线**:内存安全(C/C++ 专项)与常量时间(IFC 指标扩展),定位为研究分支。

---

## 7. 每类的"可行性契约"(对外必须公开)

每落地一类,公布:支持的语言/框架;可识别的 sink/guard/event 集;需要的标注;fail-closed 行为;**已知假阴模式**。这把"语义 bug 发现器,非 sound 验证器"的诚实定位制度化,避免过度宣称。

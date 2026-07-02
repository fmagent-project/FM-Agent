# 安全领域扩展路线图：从机密性 IFC 到更广的安全分析

> 状态：调研稿（未实现）。本文回答一个战略问题——FM-Agent 现有的"自然语言霍尔推理 + 确定性格点求值"引擎，**能可信地覆盖安全领域的哪些部分，不能覆盖哪些**，以及最高杠杆的扩展顺序。
>
> 阅读前置：`docs/ifc_design.md`（机密性 IFC 设计）、`AGENTS.md`（FM-Agent 自身架构）。
>
> 调研来源：Oracle 的属性类可行性分析 + librarian 对 CWE/OWASP、工业 SAST（CodeQL / Meta Pysa / Semgrep / Infer）本体、机密性↔完整性对偶学术基础的接地。两路独立得出高度一致的结论。

---

## 0. 一句话结论

> **我们的引擎是"依赖关系求值器"。它天然覆盖一类形式属性——非干涉性（2-safety）。机密性泄露是其中一支，完整性污点（注入类）是数学对偶、同一引擎可达。但"安全领域"远不止非干涉性：访问控制、时序协议、加密误用、内存安全、可用性、配置错误属于不同的形式属性类，需要原 FM-Agent 的霍尔推理器、全新机器、或干脆是 linter 的活。**

把"机密性 → 安全"理解成"换个标签就行"是**错的**。正确的理解是：**机密性 → 完整性污点**是换标签就行（高 ROI），而**完整性污点 → 整个安全领域**不是。

---

## 1. 按形式属性类切分安全领域

安全漏洞的可检测性，**不取决于它"有多严重"，而取决于它属于哪一类形式属性**。我们的引擎只擅长其中一类。

| 形式属性类 | 漏洞家族（CWE） | 对本引擎的判决 | 理由 |
|---|---|---|---|
| **2-safety：机密性非干涉** | 密钥/PII 泄露到响应/日志/异常/网络/文件；CWE-200, 209, 532, 598 | **直接复用** ✅ | 这就是当前抽象的原生场景。 |
| **2-safety：完整性非干涉（=污点安全）** | SQLi, 命令注入, XSS, 路径穿越, SSRF, SSTI, 不安全反序列化, 开放重定向；CWE-89, 78, 79, 22, 918, 502, 1336, 601 | **复用依赖引擎，但需新增 source/sink/endorsement 本体** ⚙️ | 依赖关系本身可复用；但污点的 sink 是**操作点**，不是"可观测输出通道"，当前通道模型不够用。 |
| **1-safety：霍尔轨迹安全** | "坏事永不发生"：use-after-close、操作前缺校验、越界、空指针、危险写文件 | **部分复用 + 需原 FM-Agent 霍尔推理器** 🔶 | 这是前/后置条件与路径条件问题，不是"X 依赖 Y"。 |
| **守卫式安全（访问控制）** | 缺失/错误授权, IDOR/BOLA, 混淆代理；CWE-862, 863, 639 | **部分复用，实战偏新机器** 🔶🆕 | 需要主体/资源/动作/租户/属主的策略词汇；纯依赖摘要不编码"权限已检查"。 |
| **时序/typestate/协议安全** | CSRF token 先于状态变更、TLS 校验先于请求、认证先于特权操作、TOCTOU、锁序；CWE-352, 295, 367 | **需全新机器** 🆕 | 要求跨调用/跨路径的**事件顺序**；单函数依赖摘要丢失时序结构。 |
| **关系性正确（超出基础 IFC）** | 常量时间加密、padding oracle、匿名性、差分隐私 | **需全新机器** 🆕 | 仍是 hyperproperty，但粗粒度 High/Low 依赖捕捉不到时序/分布/定量泄露。 |
| **活性/可用性/资源耗尽** | 死锁、死循环、无界递归、算法复杂度 DoS、缺速率限制、FD 泄露；CWE-400, 835 | **需全新机器** 🆕 | 需要成本/进度/并发/资源模型。`termination` 通道只能粗略标"是否依赖密钥"。 |
| **纯语法/配置属性** | 硬编码密钥、debug 模式、宽松 CORS、弱 TLS、不安全 header、依赖 CVE；CWE-798, 489, 16, 327 | **用错工具** 🚫 | AST/配置/依赖扫描器更合适，LLM 流推理只增成本不增信号。 |
| **加密/API 误用（局部语义安全）** | 弱算法、ECB、静态 IV、随机性不足、缺证书校验、JWT `alg=none`；CWE-327, 326, 330, 347 | **多为用错工具 / 部分** 🚫🔶 | 多数是语法 API 模式匹配；少数需霍尔推理，但依赖关系本身判不了"加密是否充分"。 |

> **图例**：✅ 直接复用 | ⚙️ 复用引擎+新本体 | 🔶 部分复用/需霍尔轨道 | 🆕 需全新机器 | 🚫 用错工具

### 工业界的印证（来自 librarian 接地）

这套切分不是凭空划的，工业 SAST 的架构本身就是按这个边界拆的：

- **Meta Pysa / Zoncolan** = 污点/注入/机密性（CWE-89/79/78/200）——纯 source→sink→sanitizer 引擎。
- **Facebook Infer（Pulse + RacerD）** = 内存安全 + 并发（CWE-401/416/362）——分离逻辑/抽象解释，**与污点正交**。Infer 后来另加的 Pulse-taint 是**叠在内存分析之上的独立一层**，印证两类属性不能共用一套机器。
- **Semgrep 的模式规则**（非污点模式）= 结构/配置（CWE-327/798/862）。
- **CodeQL** 把每类做成独立的 `ConfigSig` 模块，sanitizer（`isBarrier`）按配置隔离——印证 sink 与 sanitizer 必须**按类分型**。

学术印证：Piskachev 博士论文（TU Darmstadt, 2023）系统评估 SANS Top 25 / OWASP Top 10 的"污点可表达性"，明确把 CWE-89/79/78/22/502 判为"可"，把 CWE-416(UAF)/190(整数溢出)/352(CSRF)/269(特权管理) 判为"不可"——与上表一行不差。

---

## 2. 机密性 ↔ 完整性对偶：本引擎的可行性压测

用户的核心命题：**完整性污点是机密性的数学对偶，把格翻转即可。** 这个命题对本引擎**基本成立**，但有三处必须正视的"对偶泄漏"。

### 2.1 形式基础（成立）

| | 机密性（现状） | 完整性污点（对偶） |
|---|---|---|
| 模型 | Bell-LaPadula（不上读/不下写，信息向上流） | Biba（不下读/不上写，信息向下流）——BLP 箭头反向即得 |
| 禁止 source | High 密钥 | Low 不可信输入 |
| 禁止 sink | Low 可观测输出 | 敏感操作点（SQL/exec/open/...） |
| 逃生舱 | declassification（加密/哈希） | endorsement（sanitizer/validator） |
| 统一属性 | 非干涉性（Goguen-Meseguer 1982） | 同一非干涉性，格方向相反 |

学术权威：Sabelfeld & Sands《Declassification: Dimensions and Principles》(JCS 2009) 明确把 endorsement 列为 declassification 的完整性对偶，四维框架（what/who/where/when）两侧通用；Myers/Zdancewic 的 robust declassification 进一步证明：**endorsement 必须先于 declassification 才可信**——这条对我们的"半自动锚点"复核策略是直接背书。

**可复用内核**：
```
dependency(source, sink) + policy(source_label, sink_label, 允许的 transform) → verdict
```
这个内核两侧通用。这就是"换标签就行"成立的部分。

### 2.2 对偶泄漏 #1：污点 sink 是"操作点"，不是"可观测输出通道"

这是最大的抽象缺口。当前机密性的通道是 `return / exception / param:*.field / io:network / io:log / global:* / termination`。但污点需要**操作参数通道**：

```text
sink:sql.execute.query        sink:subprocess.shell.command
sink:open.path                sink:requests.get.url
sink:redirect.location        sink:html.body / sink:html.attribute
sink:template.source          sink:pickle.loads.bytes
```

关键区分——**全是"输出"，但安全策略不同**：
- `requests.get(攻击者控制的url)` → SSRF
- HTTP 响应体含攻击者数据 → 正常业务
- HTML 响应体含**未转义**攻击者数据 → XSS
- 重定向 `Location` 含攻击者 URL → 开放重定向

`io:network` 一个通道把这些全压扁了。**结论：同一依赖引擎，但需要一等公民的 sink 本体**（不能再靠命名约定）。

### 2.3 对偶泄漏 #2：sanitizer 是上下文敏感的（必须分型）

二级格 + 自由文本 declass 锚点对完整性**太弱**。机密性的 declassify 可以粗（`secret → hash → 公开摘要`），但 endorsement 是按 sink 类型分的：

- `html.escape(x)` 对 XSS 安全，对 SQL **无效**
- SQL 参数化只 endorse "值"，不 endorse 表名/列名（标识符）
- `os.path.normpath(x)` 不够，必须配合 base-dir 包含检查
- shell 引用对 argv 安全，对 `shell=True` 不安全

工业实证：Pysa 的 sanitizer **显式按 sink 分型**——`@Sanitize(TaintSink[SQL])` 只清 SQL 污点，不清 XSS；CodeQL 文档原话："一个 sanitizer 通常只能为一种用途消毒，DB 命令的 sanitizer 用在 HTTP 响应上并不安全"。这正是 Sabelfeld-Sands "what" 维度的部分 endorsement。

**结论：底层二级格可保留，但策略层必须做"按 sink 类型匹配的分型 endorsement"。** declass 锚点要从自由文本升级为结构化字段：
```json
{ "site": "...", "kind": "endorsement", "sanitizer": "html_escape",
  "endorses_for": ["xss:html_text"], "input": "name", "output": "escaped_name" }
```

### 2.4 对偶泄漏 #3：污点 source 是"调用结果"，不是"命名变量"

机密性靠命名推标签（`password`/`secret`/`client_secret` → High）效果好。但污点的 source 多是 **API 调用结果**，且变量名常常无害甚至误导：

```python
name = request.GET["name"]    # source 在 request.GET，不在 name
safe = request.args["url"]    # 变量名 "safe" 反而误导
```

污点 source 字典：`request.GET/args/form/json`、`input()`、`sys.argv`、`socket.recv()`、`os.environ`、消息队列体、上传文件……

**结论：命名推断只能当兜底，完整性的 source 必须建模 source 函数/访问点。** 这也复用到机密性侧（`os.environ["API_KEY"]` 当前也是靠命名）。

---

## 3. 最小能力撬动最大覆盖（投资排序）

Oracle 与我此前假设的一处分歧并已采纳：**source/sink/endorsement 本体应排在复合字段分解之前**，因为没有本体，完整性"无的放矢"。

### 投资 #1：统一的 source / sink / endorsement 本体 〔Rank 1，中等工作量〕

一个声明式配置层，机密性与完整性**共用**：
```yaml
sources:
  confidentiality: [password, client_secret, env:API_KEY, ...]
  integrity:       [http.query, http.body, http.header, stdin, argv, socket, mq.body, upload]
sinks:
  confidentiality: [log, exception, response, outbound.header, outbound.url, file.write]
  integrity:       [sql.query, shell.command, fs.path, ssrf.url, redirect.location,
                    html.text, html.attr, js.string, template.source, deserialize.bytes]
endorsements:      # 分型 sanitizer：函数 → 它为哪个 sink 上下文消毒
  - {fn: html_escape, endorses_for: [xss:html_text]}
  - {fn: sql_param,   endorses_for: [sql:value]}
```
**解锁**：完整性污点全家、更精的机密性 sink、更低假阳。**让 Python 继续当策略引擎**，LLM 只出依赖事实，不判漏洞类别。

### 投资 #2：结构化值/字段路径分解 〔Rank 2，中-大工作量〕

直击 requests CVE 漏报根因。需要的"原子"：
```text
param:proxies[scheme].url.password      param:request.args["next"]
param:headers["Authorization"]          param:payload["user"]["id"]
```
**不要一上来做全字符串分析**，先做安全相关的结构化解析器：URL（scheme/user/pass/host/port/path/query）、HTTP header、JSON/dict 键路径、文件路径（base + join + 规范化）、SQL（模板 vs 绑定参数）。

> requests CVE 正死在这里：`proxies` 当成铁板一块的 Low dict，而它内含带凭证的 URL。这条修复对机密性、完整性**两侧同时受益**。

### 投资 #3：守卫/路径条件事实 × 霍尔推理器 〔Rank 3，大工作量〕

LLM 抽取守卫事实（`user.is_admin before sink:delete_user`、`parsed_url.host in ALLOWED before sink:http.url`），**喂给原 FM-Agent 霍尔轨道**判定，不放进纯依赖求值器。解锁访问控制、IDOR、validator 充分性、假阳压制。

---

## 4. 完整性召回的诚实预测

引擎连"嵌入式凭证机密泄露"都漏了，据此预测完整性表现：

**召回会强**（匹配引擎强项——显式数据流 + 跨过程组合 + fail-closed）：
- `request.args["id"]` 拼进 SQL 串 → `execute`
- `input()` → `os.system`；`request.GET["next"]` → 重定向
- `request.json["url"]` → `requests.get`；上传 `filename` → `open`
- 薄包装函数（bottom-up 组合能实例化 callee 摘要）

**召回会弱**（结构/上下文/框架语义/值约束依赖）：
- 污点藏在 dict/对象/URL/JSON/header/半解析字符串里（= requests CVE 同类）
- 框架魔法：装饰器、路由、DI、序列化器、ORM 抽象、模板自动转义
- 上下文相关消毒：转义了 HTML 却用在 JS/SQL/shell/URL
- 二阶注入（存储→取回→sink）、隐式/控制流注入

**三个必须预先防范的失败模式**：
1. **粗粒度复合标签 → 漏报**（requests CVE 同类）→ 用字段路径 + URL/header/JSON 分解。
2. **source/sink 覆盖缺失 → 静默召回空洞**（完整性的 source/sink 宇宙远大于机密性）→ 声明式注册表 + 按框架分包；未知高危调用标"待复核"而非 SECURE。
3. **上下文不敏感的 endorsement → 双向出错**（弱 sanitizer 被过度信任 / 或忽略 sanitizer 致假阳）→ 分型 endorsement 对分型 sink。

### 覆盖率论据（为什么完整性是最高 ROI）

- OWASP 2021：A03 注入覆盖 94% 应用、274k 实例（数据集出现次数第二）。
- Edgescan 2025：SQLi 占严重/高危的 19.52%，叠加 XSS ~40–45%。
- Penetrify 2026（经真实利用验证）：A03 注入占已验证漏洞的 21.7%。

**注入/污点类在真实 web 漏洞中稳定占 20–40%。** 用同一套底层分析（机密性的形式对偶）拿下这一整类，是进入"结构上不同的技术"之前最高 ROI 的一步。

> 一个清醒的参照：SAST 在真实漏洞上的召回普遍不高——CodeQL 在 957 个 npm CVE 上仅 31.3%（败在调用图解析，非污点模型本身）；24 工具基准里 Semgrep 19%、Snyk 17%。**我们的目标不是"完备验证器"，而是"机密性 + 污点式完整性的依赖型 bug 发现器"——这个定位要诚实地对外讲。**

---

## 5. 推荐的分期路线

**第一里程碑（完整性污点 MVP，复用 90% 现有机器）**
1. 落地共享策略 schema：`SourceKind / SinkKind / ChannelKind / StructuredPath / TransformKind / EndorsementContext / Verdict`。
2. flow signature 扩展操作点通道 `sink:<kind>.<arg-role>`。
3. 双轨 source 配置（机密性命名 + 完整性 source 函数）。
4. declass 锚点升级为结构化分型 transform。
5. 优先实现最高产出的结构化分解：dict/JSON 键路径、URL 组件、HTTP header、查询参数、文件路径、SQL 模板 vs 绑定值。
6. 用一个带 CVE 的真实注入项目做召回测试（方法论同 requests：ground truth 分离到 expected.json，pre-fix 版本测召回）。

**明确推迟到后续轨道（不要在第一里程碑承诺）**
- 访问控制 / IDOR（守卫 + 策略推理，喂霍尔轨道）。
- 时序/协议安全（typestate/事件自动机，全新机器）。
- 加密误用 / 配置 / 硬编码密钥（linter/AST 扫描，用错工具）。
- 内存安全 / 可用性（分离逻辑 / 成本模型，正交技术）。

---

## 6. 对用户原始框架的两处修正

1. **"完整性"不是一个域，是至少三个不同属性类**：
   - *数据/污点完整性*（不可信数据到敏感操作）= 机密性 IFC 的真对偶，最佳契合。✅
   - *授权完整性*（越权访问资源）= 需守卫与策略推理。🔶
   - *状态/协议完整性*（操作时序/状态非法）= 需时序/typestate 机器。🆕
   只有第①类是"翻转格"的自然结果，②③是**独立路线**，不能作为格翻转的顺带产物来承诺。

2. **"机密性 → 安全"的杠杆不在"更多 LLM 推理"**，而在**共享安全本体 + 结构化值分解**——让现有依赖摘要拥有正确的"原子"去推理。

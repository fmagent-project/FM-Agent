# IFC 插件：信息流控制（Information Flow Control）

> 插件总览见 [./README.md](./README.md)。
> 设计动机见 [../ifc_design.md](../ifc_design.md)。
> 插件 SPI 架构见 [../plugin_architecture.md](../plugin_architecture.md)。

IFC 插件分析机密性：敏感值是否到达外部可观测出口。它沿用 FM-Agent 的基本分工：LLM 为
单个函数提取参数化依赖事实，`src/ifc_validation.py` 用源码能够确定的事实校正其中一小部分，
`src/ifc_reasoner.py` 再以确定性规则给出裁决。该实现是 bug finder，不是非干涉证明器。

本文以当前实现为准，重点区分三件事：提示词要求模型报告什么、源码校正器实际能够证明什么、
检查器最终如何裁决。

---

## 1. 安全属性与抽象

### 1.1 非干涉与二级格

非干涉性的经典表述是：若两次执行的 Low 输入相同，则 Low 攻击者可见的输出也应相同，而不应
随 High 输入变化。违反这一条件意味着存在可观测的 `High -> Low` 信息流。

插件采用二级格 `Low < High`，并允许模型把尚不能确定的输入标成 `Unknown`。在依赖求值时，
`Unknown` 默认按 High 处理；但未知的形式参数会被单独归为调用方相关的条件流，从而产生
`POLYMORPHIC`，而不是立即产生 `LEAK`。

每个函数的核心抽象是参数化流签名：

```text
输出通道 <- 输入源集合
```

例如 `identity(x)` 的 `return` 依赖 `param:x`。依赖集合记录来源，不把输出直接写死为 High 或
Low，因此调用点可以用实参标签实例化被调用函数。这个抽象近似非干涉所关心的依赖关系，但 LLM
可能漏流或误标，不能据此声称分析是 sound 的。

### 1.2 显式流与隐式流

`src/ifc_prompts.py` 要求模型把数据依赖和控制依赖都写入 `deps`。例如：

```python
if secret_bit:
    public_out = 1
else:
    public_out = 0
```

`public_out` 应依赖 `secret_bit`。提示词还覆盖循环、提前返回、异常、`break` 和 `continue` 下的
控制依赖。这里的隐式流识别由模型完成；确定性校正器没有自行构建 CFG 或 pc-label 栈，因此
“提示词要求覆盖”不等于“实现保证覆盖”。

### 1.3 输入与输出事实

模型返回一个 `[FLOW_JSON] ... [/FLOW_JSON]` 对象，主要结构如下：

```json
{
  "inputs": {
    "param:<name>": "High|Low|Unknown",
    "global:<name>": "High|Low|Unknown",
    "receiver.<attr>": "High|Low|Unknown"
  },
  "outputs": {
    "<channel>": {
      "deps": ["param:<name>", "receiver.<attr>", "global:<name>"],
      "const": null,
      "sink_channel": "return|exception_control|exception_message|error_detail|log|stdout|network|database|shared_state|parameter|unknown",
      "observability": "external|caller|internal",
      "declass": [{"anchor": "<statement>", "reason": "<reason>"}]
    }
  },
  "notes": "<summary>"
}
```

提示词要求接收者属性和命名容器字段分别建模，例如 `self.client_secret` 对应
`receiver.client_secret`，`request["password"]` 对应 `param:request.password`。这能减少“一个敏感
字段污染整个对象”的误报，但字段拆分仍依赖模型，确定性代码只对下文列出的少量 Python 模式做
补充。

---

## 2. 可观测性与裁决

### 2.1 `observability` 的操作语义

`sink_channel` 描述出口种类，`observability` 描述信任边界；真正决定是否检查的是
`src/ifc_reasoner.py` 的 `_is_low_observable_for()`：

| `observability` | 实际语义 |
|---|---|
| `external` | 不论函数是否入口，均作为 Low 可观测出口。 |
| `internal` | 不作为公开出口，单独不会触发泄露。 |
| `caller` | 通常只在入口函数处成为外部出口；参数写入另有目标标签规则。 |

更具体地说：

- `return`、`exception`、`exception:*` 的 caller 可见事实只在入口处检查；内部 helper 的返回或抛出
  首先是传播事实。
- `param:<name>.*` 写入只有在目标参数为 Low 时才是 Low 出口；目标为 High 时不是泄露，目标未知时
  由 `IFC_FAIL_CLOSED` 决定，默认按可观测处理。
- 其他 `caller` 通道只在入口处检查。
- `termination` 明确不参与裁决；当前属性是 termination-insensitive non-interference，不覆盖时间、
  终止、缓存等隐蔽信道。
- 缺少新字段的旧签名会调用 `infer_sink_channel()` 和 `infer_observability()`。旧 `return`/异常默认
  为 `caller`，参数写入默认 `caller`，其他旧副作用默认 `external`，而不是按名字猜成可信内部日志。

插件还施加两个 Python 特例。普通 Python 方法即使被调用图列为入口，`check()` 也会把其入口标志
关闭；另一方面，如果某方法的所有调用方都存在同名多候选分派，caller 可见的异常控制/异常消息会
保守提升为 external。二者都是当前调用图近似的补丁，不是通用对象分派语义。

`src/ifc_validation.py` 会把本函数中经常规 ORM session 执行的数据库持久化输出改为 `internal`。
它不会因为看见 logger 调用就自行创建日志出口，也不会自行判定日志配置究竟公开还是内部；日志
出口及其可观测性仍主要来自模型事实。

### 2.2 通道标签与五种裁决

检查器对每个可观测通道求依赖标签并区分：

- `genuine_high`：`const:High`、明确标为 High 的依赖，或未声明/未知的非参数来源。
- `conditional`：只由未知或未声明的 `param:*` 造成，需调用方实例化。
- `low`：没有上述依赖。

函数级裁决优先级为：

```text
LEAK > DECLASSIFIED > POLYMORPHIC > SECURE
```

无有效签名则由插件返回 `ERROR`。各裁决含义如下：

| 裁决 | 含义 |
|---|---|
| `LEAK` | 至少一个外部可观测通道有未降密的 genuine High 流。 |
| `DECLASSIFIED` | 没有更高优先级泄露，且至少一个已确认 High 的可观测流带降密提议。 |
| `POLYMORPHIC` | 没有前两类结果，但至少一个出口只依赖调用方尚未确定的参数。 |
| `SECURE` | 在当前签名、源码校正和入口判断下未发现上述出口。 |
| `ERROR` | 签名缺失或结构无效；不能当作安全。 |

错误详情默认映射到 CWE-209，日志泄露映射到 CWE-532，其他信息暴露映射到 CWE-200。签名可以在
这三个值中声明 `cwe`；其他声明不会覆盖默认映射。

### 2.3 错误内容与错误控制

异常是否发生和异常携带什么文本是不同通道：

- `exception` / `exception_control` 表示异常发生事实。
- `exception:message` / `exception_message` 表示向 caller 传播的异常详情。
- `error:<destination>` / `error_detail` 表示外部 message、response 等错误详情。

Python 源码校正器会跟踪 caught exception、`sys.exc_info()` 及其简单赋值传播，重建外部 message 和
抛出异常文本的依赖。详细内部日志与固定外部错误会保持两个出口：内部日志不会污染固定外部文本，
但 catch 本身也不会清除随后复制到外部文本的异常详情。无依赖的 `const:High` 异常控制会被归一为
Low，因为无条件发生的异常在每次执行中相同。

---

## 3. Python 源码校正与 fallback

### 3.1 `validate_and_enrich()` 的边界

每次解析模型响应以及最终 `check()` 前，插件都会运行 `validate_and_enrich()`。它会：

- 校验 inputs、outputs、标签、sink、observability 和基础字段形状；非法值使签名无效。
- 丢弃模型伪造的 `callee:*` 输出和以下划线开头的内部字段；只有组合阶段生成的事实可在复核时保留。
- 对可解析的 Python 源码做有限校正，包括固定返回、异常详情、常规 Low 字段、session 持久化和嵌套
  敏感字段 merge。

这些源码规则不是通用符号执行。非 Python 源码或 Python AST 解析失败时，仅保留结构校验和模型
事实，不会获得这些校正。

### 3.2 source-only fallback

模型重试耗尽时，`IfcPlugin.make_error_facts()` 会调用 `source_only_fallback()`。fallback 不是“把
未知全部判 High”，也不是完整 IFC 分析；它只在 Python AST 能独立结算至少一个输出事实时返回
`status="ok"`，当前来源包括：

- 下节描述的嵌套敏感 merge 到本地可确认 stdout/序列化出口；
- 可从异常/错误文本赋值或抛出语句确定的错误详情；
- 全部 return 都是常量或 `None` 时的 Low return。
- 函数没有显式 `return` 时，Python 的隐式 `None` 也建立 Low return；模型不能为该 return
  保留参数依赖。

若源码没有产生任何这类输出，例如普通的 `return value + 1`，fallback 返回 `None`，插件保留
`status="error"` 并最终裁决 `ERROR`。因此 fallback 的 `SECURE` 只表示源码规则已经结算了它所创建
的那些通道，不表示其他潜在流已被证明不存在。

### 3.3 nested sensitive merge

源码校正器专门处理一类“通用 options 容器绕过正常敏感字段注册/脱敏”的 Python 模式。它识别的
merge 很窄：

- `target.update(target.<generic-container>)`，其中嵌套字段名类似 `params`、`options`、`extra`、
  `config`、`settings`、`kwargs`；
- 遍历这类容器的 `.items()` 并写入 subscript 目标。

merge 本身不创建泄露。校正器只有在以下证据之一存在时才把未解决的敏感来源加入出口：

- 模型已有一个非 internal 输出，其依赖确实跟踪该 merge 的源或目标；
- AST 在 merge 之后看见 `print`/`pprint` 输出目标，或看见同一接收者通过 `exit_json` 序列化其合并后
  的状态。

若模型没有给出具体敏感字段，校正器可引入形如 `param:options.extra.<sensitive>` 的合成 High 源。
若模型给出了多个具体 High 字段，则保护按每次 merge、每个字段分别计算：只删除已被证明阻断的
字段，其他字段仍流向已有出口。

当前认可的阻断也很窄：敏感字符串字段的 membership 检查必须支配 merge，命中路径必须终止；或
字段必须在 merge 前被 `pop`、`del`、赋常量覆盖。merge 后处理、只在条件分支中处理、处理另一个
字段，或赋一个非常量“sanitize”结果都不会被当成已阻断。该规则不证明任意 redaction helper 的
语义。

Python source validation 还会统一校验模型的 `receiver.*` facts：只有 AST 中存在精确的
`self.<field>` 或 `cls.<field>` receiver-rooted 引用时，该 input/dependency 才保留。模型把其他对象的
同名属性、本地同名变量或完全不存在的字段写成 receiver fact 时，不论标签是 High、Low、Unknown
还是漏声明 input，都会从 inputs 和 outputs 中删除。源码真实读取的 receiver 字段仍保留并按
fail-closed 处理；该规则不把 callee 的 receiver 状态自动绑定到 caller 对象。

---

## 4. 跨函数组合及其限制

驱动自底向上分析函数。`IfcPlugin.compose_calls()` 对已解析 callee 调用
`instantiate_callee()`，把 callee 形参源替换为调用点标签：

- 字符串和数值字面量是 Low；
- 裸 caller 参数名使用 caller 签名中的原始标签；
- 其他表达式是 Unknown；缺失绑定再回退到 callee 自己的输入标签。

实例化结果保留 `sink_channel`、`observability` 和一个降密布尔值。非 internal 的 callee 输出会被
折叠为 caller 中的合成 `callee:*` 输出；High/Unknown 的区别在此会折叠成 `const:High`，因此这是
保守义务传播，不是完整依赖替换。

当前组合有以下重要限制：

- Python 中会用 AST 确认函数体确有该调用；函数声明或注释中的同名文本不会产生组合。其他语言只
  使用已有调用图结果，没有同等 AST 复核。
- 实参标签器只精确处理字面量和裸参数。属性、索引、运算和调用表达式均为 Unknown。
- callee 的 global/receiver 来源不会绑定到 caller 的具体对象状态。
- internal callee 输出不会提升为 external。
- Python 的 caller-visible `return` 只有在 caller 直接 `return callee(...)` 时才确定性提升；若先
  赋值再使用，组合器不传播该 return，需依赖 caller 的 LLM 签名描述后续流。
- 同名多候选会保留每个候选的合成义务并加候选后缀，但候选解析仍是基于名称的近似。
- callee facts 无效时该调用被跳过，不会合成一个“未知 callee 泄露”通道。

因此，“自底向上组合”不应被解释为任意表达式、别名、动态分派和对象状态上的完备跨过程 IFC。

### 一个精确的组合例子

```python
def emit(value):
    print(value)

def caller(secret):
    emit(secret)
```

若 callee 签名把 `io:stdout` 标成 `external` 且依赖 `param:value`，caller 签名把
`param:secret` 标成 High，裸参数绑定会把 callee stdout 实例化为 High，并在 caller 中形成
`callee:emit:io:stdout` 泄露。

反之，下面的 return 不会由组合器单独提升：

```python
value = load_secret()
return False
```

因为 callee return 没有被 caller 直接返回；如果 `value` 随后进入日志，必须由 caller 自身签名报告
该依赖。

---

## 5. 降密（Declassification）

降密用于表达有意释放，例如口令比较的一位结果。提示词要求每个提议带精确 `anchor` 和 `reason`，
并禁止用它掩盖完整秘密释放。

确定性检查器的实际规则更简单，必须准确理解：

- 非空 `declass` 列表即视为存在提议；结构校验只确认它是列表，当前不验证每个 anchor/reason 的内容
  或源码支配关系。
- 提议只有在通道含 `const:High` 或某个原始标签明确为 High 的依赖时，才进入 `DECLASSIFIED`。
- 只有 Unknown/未声明来源而没有显式 High 的提议不会制造降密审查；当前实现会跳过该通道。测试中
  Unknown receiver 加降密提议因此得到 `SECURE`，而同一 receiver 明确为 High 时得到
  `DECLASSIFIED`。
- 组合只传播“callee 存在降密”这一布尔事实，并生成通用的 callee 降密说明，不保留原提议的完整
  anchor/reason。
- 若同一函数另有未降密 genuine High 泄露，函数级结果仍是 `LEAK`。

`DECLASSIFIED` 是人工复核信号，不是自动安全证明。尤其由于 anchor 尚未被确定性验证，复核者必须
确认释放量、目的、接收者和源码位置确实符合策略。

---

## 6. 适用范围与局限

适合使用 IFC 插件的场景包括：凭据进入日志/stdout/响应、异常详情外泄、嵌套 options 绕过脱敏，
以及简单参数绑定下的跨函数泄露候选。

使用时应保留以下边界：

- `SECURE` 只表示当前模型事实和有限源码校正下未发现违规，不是非干涉证明。
- 隐式流、深层字段和复杂表达式主要依赖模型，可能漏报。
- 二级格不能表达多级机密、区室和主体授权策略。
- termination、timing、cache 等隐蔽信道不在范围内。
- Python 有额外 AST 校正；列为支持语言不意味着其他语言享有相同源码语义。
- `DECLASSIFIED` 必须人工复核，`POLYMORPHIC` 需要调用点信息，`ERROR` 不能按安全处理。

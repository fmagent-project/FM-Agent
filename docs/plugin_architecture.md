# 插件化架构设计：FM-Agent 作为多理论安全分析底座

> 状态：设计稿（未实现）。本文把"针对不同缺陷类别、安装对应形式理论插件、共用同一套 LLM-NL-reasoning 框架"的想法,落成具体的 SPI(service-provider interface)与渐进式迁移计划。
>
> 前置：`docs/security_portfolio_roadmap.md`（理论组合路线图）、`docs/ifc_design.md`（IFC 设计）。
>
> 依据：Oracle 的 SPI 架构设计 + explore 对现有可复用机器的清单。

---

## 0. 核心判断：这个想法成立,且已被 IFC 半证明

你的想法不是从零发明。IFC 落地时**已经无意中验证了插件化可行**——它没改 `main.py`,而是 fork 出 `ifc_main.py`,复用了 `extract.py` 的抽取 + 自建调用图 + 自底向上排序 + 并行 LLM 调度 + 聚合,只替换了"LLM 产出什么抽象 + 确定性检查器怎么判"。

所以插件化的任务**不是发明新机制,而是把 `ifc_main.py` 里已跑通的结构正式抽象成插件契约**。IFC 的三个函数恰好就是任何插件需要的三个原语:

| IFC 现有函数 | 插件原语 | 职责 |
|---|---|---|
| `derive_flow_signature()` | **抽象步骤** | LLM 产出 per-function 语义抽象 |
| `instantiate_callee()` | **组合算子** | 调用点把 callee 抽象实例化进 caller |
| `classify()` | **确定性检查器** | 纯代码判定 verdict |

---

## 1. 最关键的设计发现:纯自底向上不够

这是 Oracle 压测出的、决定架构成败的点。**不同理论的"组合算子"根本不同**,一个纯 bottom-up 循环容纳不了全部:

| 理论 | 组合方式 | 自底向上够吗 |
|---|---|---|
| IFC / 完整性污点 | 标签集替换(把实参标签代入 callee 依赖集) | ✅ 够 |
| 加密误用 | 值溯源 + 事件事实向上传 | ✅ 大体够 |
| 资源/DoS | 污点 + 界事实向上传 | ✅ 大体够 |
| **访问控制** | callee 的"需要守卫 G"是一个**义务(obligation),只有某个祖先 caller 能否兑现** | ❌ 这是**向上流的需求**,单函数视角判不了 |
| **typestate/时序** | 必须按**调用顺序**组合事件迹(路径敏感) | ⚠️ 需有序组合,非无序 per-call |

**结论(Oracle 论证)**:不需要通用的任意 pass 引擎,只需在 driver 里支持**三个阶段**:

1. **自底向上 LLM 抽象**——通用默认
2. **自底向上组合**——通用默认,插件特定
3. **可选的自顶向下确定性上下文传播**——授权必需、typestate 有用

授权的"祖先是否建立了守卫"靠第 3 阶段的 worklist 解决(从入口点出发,把"已建立的守卫上下文"沿调用边下传),**不需要另起一套 driver**。

---

## 2. 两层架构

```
┌─────────────────────────────────────────────────────────┐
│ CORE(底座,理论无关,绝不理解"守卫/nonce/typestate/污点") │
│  - 源码扫描 + 函数抽取(复用 extract.py)                  │
│  - 调用图 + 反向调用图 + 入口点判定(复用 _build_call_graph)│
│  - SCC 压缩分层 + 自底向上调度                            │
│  - 并行 LLM 调度(ThreadPoolExecutor, 复用 verification)  │
│  - 重试 + fail-closed 封装(复用 _retry_create)           │
│  - 结构化 trace(复用 trace_writer)                       │
│  - 结果持久化 + 聚合(只读公共信封字段)                   │
│  - 可选:自顶向下上下文 worklist                          │
└─────────────────────────────────────────────────────────┘
                          ↕ SPI
┌─────────────────────────────────────────────────────────┐
│ PLUGIN(每个形式理论一个,拥有自己的 schema)              │
│  - build_abstraction_prompt() → 构造 prompt              │
│  - parse_abstraction_response() → 解析成 plugin 私有 facts │
│  - make_error_facts() → fail-closed 兜底                 │
│  - summarize_for_caller() → 给 caller prompt 的文本摘要   │
│  - compose_calls() → 组合算子(IFC 重写为标签替换)        │
│  - check() → 确定性检查器 → Verdict                      │
│  - [可选] initial_context/propagate_context/merge → 上下文 │
└─────────────────────────────────────────────────────────┘
```

**铁律(Oracle 的停止规则)**:core 只负责编排和稳定信封。**一旦 core 开始理解"守卫""nonce""typestate""污点",抽象就过度了。**

---

## 3. SPI 核心契约

完整定义见 Oracle 输出,要点如下(放 `src/plugins/base.py`):

### 公共信封 vs 插件私有载荷(D3)
**不要定义统一 fact schema**(会把 IFC/授权/typestate 压成无用的通用 "event")。只定义统一**信封**,载荷由插件拥有、版本化的 JSON:

```python
@dataclass
class FactEnvelope(Generic[PayloadT]):
    plugin_name: str          # core 可读
    schema_version: str       # core 可读
    function: FunctionId      # core 可读
    status: FactStatus        # core 可读: ok|partial|error
    payload: PayloadT         # ← 插件私有,core 绝不窥探/修改
    confidence: float
    evidence: List[Evidence]  # core 可读(聚合报告用)
    diagnostics: List[Diagnostic]
    trace_ids: List[str]
```

core 只读信封顶层字段;`payload` 的 schema、校验、组合、检查全归插件。这样既共享报告/trace,又不牺牲各理论精度。

### 组合算子的正确签名(D1-b,D4)
你我最初设想的 `compose(caller, callee, binding)` 对 IFC 对,但**对 typestate 太窄**(顺序重要)、**对授权太窄**(义务要跨多个调用累积)。正确做法:**主钩子是整调用列表**,简单插件用单调用默认:

```python
def compose_calls(self, caller_facts, resolved_calls, context) -> FactEnvelope:
    """主钩子:按 order_index 排序处理全部调用。typestate/授权重写此方法。"""
    # 默认实现:逐个调 compose_call(单调用,IFC 这类够用)
```

### 插件元数据声明能力需求(D1-d)
```python
@dataclass
class PluginMetadata:
    name, version, schema_version
    supported_languages, verdicts          # verdict 词汇插件自定义
    llm_direction = "bottom_up"            # 目前只支持自底向上抽象
    requires_top_down_context = False      # 授权=True, typestate=True
    needs_entrypoint = False               # IFC=True(信任边界)
    supports_recursion = False
```

### 自顶向下上下文 worklist(D4,授权/typestate 的逃生舱)
```python
def run_top_down_context_worklist(plugin, program, facts_by_function):
    # 从入口点 initial_context() 出发
    # 沿调用边 propagate_context() 下传(授权:已建立的守卫;typestate:入口 FSM 态)
    # merge_contexts() 单调合并,变化则重入 worklist
```

---

## 4. 可复用机器清单(explore 摸到的现成件)

| 能力 | 现有位置 | 复用方式 |
|---|---|---|
| 函数抽取 | `extract.py: run_extraction()` | 直接复用。输出 `extracted_functions/{path}/{file}-{ext}/{func}.{ext}`;同名函数去重为 `name_1/name_2` |
| 语言配置 | `extract.py: LANG_CONFIG, EXT_TO_LANG` | 直接复用(10 语言:c/cpp/python/go/rust/java/ts/js/cuda/arkts) |
| 调用图 | `generate_topdown_layers.py: _build_call_graph()` | 复用——返回 callees/callers/file/module 映射,FQN 格式 `src::mod::file::func`。**注意:它做的是 top-down(caller 优先)分层,IFC 需要 bottom-up,把层序反转即可** |
| SCC 分层 | `_compute_layers() + _tarjan_scc()` | 复用——Kahn 算法 + Tarjan 环处理 |
| 并发 | `verification.py: streaming_reasoner` / `ThreadPoolExecutor` / `MAX_WORKERS` | 复用 executor 模式:同一就绪层的函数并行跑 |
| LLM 客户端 | `llm_client.py: _retry_create / _openrouter_client` + anthropic 原生路径 | 复用——core 拥有重试封装 |
| Trace | `trace_writer.py: new_event_id / record_llm_exchange / utc_now_iso` | 复用——插件发 trace_ids 即接入 |
| readiness 门控 | `file_utils.py: is_file_ready()`(≥2 SPEC + ≥2 INFO) | IFC 不依赖此(无 SPEC 标记),插件可各自定 readiness |

**调度规则(关键)**:bottom-up 不等于串行。先算 SCC 压缩的依赖层,然后**同一就绪层内并行**。递归 SCC:首版要么拒绝(除非 `supports_recursion`),要么无 callee 摘要地保守分析——**绝不假装递归 callee 已被完整摘要**。

---

## 5. 渐进式迁移(IFC 先入,不大改写)

seam 很干净,因为 IFC 已有三个原语。**绝不 big-bang 重写**:

- **Step 1**:加 `src/plugins/base.py`(只加 SPI,不碰 `ifc_main.py`)。
- **Step 2**:写 `src/plugins/ifc.py` 薄适配器——`derive_flow_signature`→抽象、`instantiate_callee`→`compose_calls`、`classify`→`check`、现有 callee 摘要文本→`summarize_for_caller`。
- **Step 3**:`derive_flow_signature` 拆成 `build_flow_prompt()` + `parse_flow_signature_response()` + 重试封装,让 core 接管重试。
- **Step 4**:**并行写两份输出**(旧 IFC JSON 不变 + 新 FactEnvelope/Verdict),对账。
- **Step 5**:把 `ifc_main.py` 的扫描/调用图/排序/入口点/聚合逐步搬进 core,`ifc_main.py` 变成 `run_plugin(IfcPlugin(), ...)` 的薄 CLI。
- **Step 6**:回归检查(无正式测试套件,用 golden 对账):verdict 计数、逐函数 verdict、violations、declassified/conditional channels、malformed LLM 输出的 ERROR 行为,全部对齐才翻聚合开关。

---

## 6. 诚实的风险(抽象会在哪儿漏)

1. **调用点实参绑定质量**——IFC/污点/授权/crypto/资源全依赖"实参→形参"映射。现有调用图是 regex 名字匹配,精度有限。SPI 允许 partial `arg_bindings`,但精度受限于调用解析器。
2. **路径敏感性**——typestate 和授权守卫支配都想要 CFG/路径事实。有序调用点对首版够,但证明"守卫在所有路径支配操作"需要 basic-block 支持。
3. **递归/环**——bottom-up 摘要在 DAG 上直接,SCC 需 widening/fixpoint 或保守摘要。
4. **摘要文本有损**——`summarize_for_caller()` 是给 LLM 的文本;确定性组合必须用 typed payload,**不要回头解析摘要文本**。两条通道分开。
5. **最不契合的插件**:**typestate**(真精确时序要 CFG/路径/自动机不动点)和**授权**("祖先建立守卫"非 bottom-up 属性,靠 top-down pass 兜)。

### 逃生舱(被逼时才加,首版不加)
```python
# PluginMetadata 追加:
requires_cfg, requires_fixpoint, requires_whole_program_check
# 可选插件钩子:
def whole_program_check(self, facts_by_function, program) -> Sequence[Verdict]
```

### 何时算过度工程
- **值得**:IFC 之后至少还做 2 个插件(尤其完整性 + 授权)。
- **过度**:IFC 永远是唯一生产级轨道;或每个未来插件都需要完全不同的前端(CFG/别名/符号执行/全程序不动点)。

---

## 7. 一句话总结

> FM-Agent 插件化 = **core 拥有编排与稳定信封,插件拥有理论**。组合算子的多样性(IFC 替换标签、授权传播义务、typestate 组合迹)用"自底向上 facts + 可选自顶向下上下文 pass"这一最小泛化容纳;IFC 三个现有函数恰好就是三个插件原语,适配器先行、对账保平、再逐步把共享机器搬进 core——无需大改写。

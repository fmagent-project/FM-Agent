# IFC 扩展设计：在 FM-Agent 上构建静态信息流控制

> 状态：设计稿（未实现）。本文件描述如何在 FM-Agent 现有的"自然语言霍尔逻辑推理"框架上，扩展出**静态信息流控制（Information Flow Control, IFC）**能力。
>
> 阅读前置：`AGENTS.md`（FM-Agent 自身架构）、`README.md`（用户视角的 5 阶段流水线）。

---

## 1. 目标与核心思想

### 1.1 我们要做什么

FM-Agent 当前做的是**单轨迹**霍尔推理 `{P} C {Q}`：自动生成每个函数的规约（pre/post-condition），逐块推出实际的 `Q`，与 spec 的 `Q` 比对，不符即报正确性 bug。

IFC 要做的本质不同——它关心的不是"`Q` 的值对不对"，而是 **`Q` 对 `P` 的依赖结构**：

- 给输入打**安全标签**（第一期用二级格：`High`=私密 / `Low`=公开）。
- **非干涉性（non-interference）**：`Low` 输出不得依赖任何 `High` 输入。等价表述——两次执行只要 `Low` 输入相同，`Low` 输出就必须相同。
- **违规 = 泄露**：存在一条 `High → Low` 的信息流，把私密数据泄露到了公开侧。

### 1.2 为什么 FM-Agent 的机制天然适配

1. **NL 推理擅长算"依赖"**。"返回值的内容是否依赖于 `secret` 参数？"正是 IFC 需要回答的，且能自然捕捉**隐式流（implicit flow）**——传统污点追踪最易漏的部分：

   ```python
   if secret_bit:        # 通过控制流泄露
       public_out = 1
   else:
       public_out = 0
   # public_out 没有直接“碰”secret_bit，但其取值依赖于它 → 隐式流泄露
   ```

2. **降维：2-safety → 单函数依赖分析**。非干涉性本是 2-safety（hyperproperty），需关联两次执行，传统做法是 self-composition。但"推理输出对输入的依赖"把它降成了**对单个函数的依赖分析**，而依赖分析**模块化可组合**——这正好嫁接到 FM-Agent 的 `[INFO]` 跨函数摘要 + 自顶向下调用链上。

3. **自顶向下、需求驱动的链路可直接复用**。FM-Agent 先确定 caller 的 spec，再把"caller 对 callee 的期望"往下传去推断 callee 的 spec（在迷你项目实跑日志中可验证：caller `average` 在 Layer 0 先处理，叶子 callee `sum_list` 在 Layer 1 后处理）。IFC 沿用这条链路，只把"值期望"换成"流约束"。

### 1.3 概念映射总表

| FM-Agent 现状（正确性） | IFC 对应物 |
|---|---|
| spec = {pre-condition, post-condition} | policy = {输入标签 High/Low, **非干涉约束**, 允许的 declassification 点} |
| `[INFO]` = callee 的值契约摘要 | `[FLOW]` = callee 的**流签名**（哪些输入流向哪些输出） |
| 逐块推理：把 pre 往下传 | 逐块推理：把 **(标签环境 Γ + pc-label)** 往下传 |
| 终止块检查"实际 post ⟹ spec post" | 终止块检查"实际流签名 ⊑ 非干涉约束" |
| verdict: MATCH / MISMATCH / SKIPPED / ERROR | verdict: **SECURE / LEAK / DECLASSIFIED / SKIPPED / ERROR** |
| bug 确认 = probe 跑一个反例输入 | 泄露确认 = **self-composition**：跑两次（Low 同、High 异），比对 Low 输出 |

---

## 2. 改动地图：按流水线阶段逐文件

设计原则：**Stage 1-4 整条复用，只在 Stage 5 fork 出 IFC 变体**。IFC 与现有正确性轨道**并存、互不干扰**（新增而非替换）。

### 2.1 Stage 1-4：几乎零改动（直接复用）✅

| 组件 | 文件 | 是否改动 |
|---|---|---|
| 函数抽取（语言无关） | `src/extract.py`（`LANG_CONFIG` 8-139, `EXT_TO_LANG` 142-152） | 不动 |
| 调用链提取 + 自顶向下分层 | `src/generate_topdown_layers.py`（产出 `phaseN_callers`/`phaseN_callees`/`all_callees`） | 不动——这正是 IFC 跨函数流追踪要复用的链路 |
| phases.json / 分层 JSON / 文件清单 | `main.py`, `file_utils.collect_file_names` | 不动 |

> 可选增强（非必需）：Stage 2 的 `engine_overview.txt` 追加一节"信任边界 / 敏感数据类型"，辅助 agent 推断标签。

### 2.2 Stage 5：主战场（fork IFC 变体）

下列改动点 A–G 是 IFC 能力的全部落点。

---

#### 改动点 A：IFC spec 生成（标签推断 + 流约束）

- **现状**：`md/system_prompt.md`（62-92）定义 `[SPEC]`/`[INFO]` 格式，opencode 据此把规约写入抽取文件。
- **改法**：新增 `md/ifc_system_prompt.md`，产出 **`[FLOW]` 块**而非 `[SPEC]`。该 prompt 指示 agent：
  1. **推断**每个参数/全局/返回值的标签（High/Low）——依据命名约定（`password`/`token`/`*_secret`）、类型、领域上下文。
  2. 写出本函数的**非干涉约束**：哪些 High 输入禁止流向哪些 Low 输出。
  3. **提议** declassification 点（若有），每个必须带 `[DECLASSIFY]` 标注 + 理由 + 锚点。
- **落点**：`main.py` Stage 5 在复制 `system_prompt.md` 处（236-239）旁增加复制 `ifc_system_prompt.md`；batch prompt 生成时引用它。

`[FLOW]` 块草图（沿用语言注释前缀，与 `[SPEC]` 同构）：

```python
# [FLOW]
# Unit: auth/login.py
# check_password(input_pw: Low, stored_hash: High) -> Low
# Labels:
#   - input_pw: Low      (来自用户请求)
#   - stored_hash: High  (敏感: 口令哈希)
# Non-interference constraint:
#   - 返回值标记 Low, 因此返回值不得依赖 stored_hash 的具体内容
# Declassification:
#   - [DECLASSIFY] 返回布尔"匹配/不匹配"泄露 1 bit 是有意的(口令校验固有)
#     理由: 认证语义必需; 锚点: 仅此 return
# [FLOW]
```

---

#### 改动点 B：`[INFO]` → `[FLOW]` 摘要，跨函数流约束下传

- **现状**：`src/generate_batch_prompts.py`（`build_prompt`, 162-303）含两节关键内容——"EARLIER-LAYER CALLER SPECS"（把已生成的 caller spec 喂下来）与"CALLEE EXPECTATIONS FROM CALLERS"（caller 的 `[INFO]` 对本函数的期望）。这是自顶向下传递的载体。
- **改法**：这两节的**语义换成流约束**。caller 传给 callee 的不再是"我期望你返回 X"，而是：

  > "为保证我（caller）的非干涉性，你（callee）必须满足：你的参数 `arg2` 我标了 High，你的返回值我当 Low 用——所以**你的返回值不得依赖 `arg2`**。"

  这是 **assume-guarantee**：caller 假设 callee 有此流签名，IFC 推理再去验证 callee 真的满足。`[FLOW]` 摘要可组合 → 跨函数追踪自动成立。
- **落点**：`generate_batch_prompts.py` 的 `build_prompt`（162-303）增加 IFC 分支，把"caller 流约束"组装进 batch prompt 文本。

---

#### 改动点 C：IFC 推理器（最核心、最难——pc-label 跨块传递）

- **现状**：`src/reasoner.py` 的 `reasoner()`（186-243）逐块推 post-condition，用 `current_pre` 把上一块结果传给下一块（241 行）；`prompts.py:_generate_block_post_condition`（10-43）与 `_check_post_implies_spec`（155-255）是两个 LLM 调用。
- **改法**（三处）：

  1. **传递的状态从"值条件"扩成"(标签环境 Γ + pc-label)"**。`reasoner.py:198-241` 的 `current_pre` 线程要携带：每个变量当前的安全标签 + **当前控制流是否已依赖 High**（program-counter label, pc-label）。这是抓**隐式流**的命门：

     ```python
     if secret:        # 进入分支 → pc 染 High
         x = 1         # x 无直接碰 secret, 但因 pc=High 而变 High
     ```

     不传 pc-label，所有隐式流都会漏——这恰是 IFC 相对传统污点追踪的核心价值。

  2. **新增两个 IFC prompt**（放 `src/ifc_prompts.py`，与 `prompts.py` 平行）：
     - `_derive_block_flow(block, Γ_in, pc_in, ...)` —— 推出本块执行后的 `Γ_out`、`pc_out`、以及新产生的流边。仿 `_generate_block_post_condition`，用 `[FLOW_START]/[FLOW_END]` 标签。
     - `_check_flow_satisfies_policy(...)` —— 检查实际流签名是否违反非干涉约束。仿 `_check_post_implies_spec`，但裁决标签必须**唯一、显式**：`[VERDICT]SECURE|LEAK|DECLASSIFIED[/VERDICT]`。

  3. **复用** `_split_into_blocks_braced`（82-147）和 `_TERMINATING_PATTERNS`（150-168）**不动**——分块与"何时该检查"的逻辑 IFC 通用。
     > ⚠️ 注意：现有分块器在"回到入口大括号深度"时切块，意味着一个完整 if 分支通常落在同一块内（利于块内隐式流分析）。但**超大分支会被切开**，跨块时 pc-label 必须正确续传——这正是第 1 点要解决的。

---

#### 改动点 D：verdict + 结果 schema

- **现状**：`src/verification.py:_verify_single_file`（226-298）产出 verdict 字符串字面量（无 enum），MISMATCH 的 `gaps` dict 在 280-289；`streaming_reasoner` 在 118-128 把 MISMATCH 路由到验证。
- **改法**：
  - 新增 verdict：`"LEAK"`（确认泄露）、`"DECLASSIFIED"`（有降密，待人工复核）、`"SECURE"`。在 260-292 的分支链里加 IFC 分支。
  - IFC 的 `gaps` 字段换成：`{high_source, low_sink, flow_path（跨块/跨函数路径）, is_implicit（显式/隐式流）, declassify_note}`。
  - 路由分支（118）：`LEAK` → self-composition 验证器；`DECLASSIFIED` → **不自动确认**，进人工复核队列。
  - `_generate_validation_summary`（400-441）加 IFC 统计：`total_leaks`、`total_declassified`。

IFC 结果 JSON 草图（`fm_agent/ifc_results/**/<func>.json`）：

```json
{
  "function": "/abs/.../check_password.py",
  "verdict": "LEAK",
  "gaps": {
    "high_source": "stored_hash (param, High)",
    "low_sink": "return value (Low)",
    "flow_path": "Line 4: if stored_hash[0]==input_pw[0] → Line 5: return True (pc=High)",
    "is_implicit": true,
    "declassify_note": null
  }
}
```

---

#### 改动点 E：确认层 = self-composition probe

- **现状**：`md/bug_validator.md` 指示 opencode 写 probe 脚本，跑**一个**反例输入确认 bug。
- **改法**：新增 `md/ifc_validator.md`，probe 改成 **self-composition**——把目标函数跑**两遍**：`Low` 输入完全相同、`High` 输入不同，断言 **`Low` 输出相同**；若不同 → 泄露确认。`_validate_single_bug`（verification.py:301-397）的结构几乎不动，只换它引用的 md 文件和 probe 模板。
- **分工要点**：**推理阶段用依赖分析（便宜、单轨迹）**，**确认阶段才用 self-composition（两次运行）**。现有 probe 机制天然能承载。

self-composition probe 骨架：

```python
# 两次运行: Low 输入相同, High 输入不同
out1 = check_password(input_pw="guess", stored_hash="HASH_A")
out2 = check_password(input_pw="guess", stored_hash="HASH_B")
# 非干涉性要求: Low 输出必须相同
if out1 != out2:
    print(f"LEAK CONFIRMED — Low output depends on High input: {out1!r} vs {out2!r}")
else:
    print("NOT CONFIRMED — Low output stable across High variation")
```

---

#### 改动点 F：config 旋钮

- **现状**：`config.py:13-22`。
- **改法**：加 IFC 专属常量：

  ```python
  IFC_SPEC_MODEL          = LLM_MODEL   # 标签推断 + 流约束生成
  IFC_FLOW_DERIVE_MODEL   = LLM_MODEL   # 逐块流推导
  IFC_FLOW_CHECK_MODEL    = LLM_MODEL   # 流约束检查
  IFC_VALIDATION_MODEL    = LLM_MODEL   # self-composition 确认
  MAX_IFC_ITER            = 5           # 流检查重试预算
  # GRANULARITY 可复用; 若隐式流需更细粒度可加 IFC_GRANULARITY
  ```

---

#### 改动点 G：readiness 门控 + 解析

- **现状**：`src/file_utils.py:is_file_ready`（24-42）要求 ≥2 `[SPEC]` + ≥2 `[INFO]` 才算就绪；`src/parser.py:parse_input_function`（157-192）抽取 `[SPEC]`/`[INFO]` 块。
- **改法**：IFC 轨道改判 ≥2 `[FLOW]`（或加参数令其识别 IFC 标记）；`parse_input_function` 加一个变体抽取 `[FLOW]` 块（含 Labels / 约束 / declassification 三段）。

---

## 3. 新增产物（目标库 `fm_agent/` 内）

```
fm_agent/
├── extracted_functions/**/<func>.ext     ← 复用; IFC 把 [FLOW] 块写在这里
├── ifc_results/**/<func>.json            ← 新: verdict + 流 gaps
└── ifc_validation/<id>.md / .result.json ← 新: self-composition probe 报告
    └── summary.json                       ← 新: leak / declassified 统计
```

---

## 4. 完全不碰的部分（白嫖）

- 抽取（`extract.py`）、调用链分层（`generate_topdown_layers.py`）、文件清单（`file_utils.collect_file_names`）
- trace 基础设施（`opencode_trace.py`、`trace_writer.py`）——IFC 调用自动被记录
- 并发调度框架（`streaming_reasoner` 的 ThreadPoolExecutor 骨架）
- `_LANGUAGE_EXPERTISE`（`prompts.py:46-152`）可直接复用，IFC 仅追加安全语义（如 C 的内存别名、Python 的 `eval`）

---

## 5. 决定 sound 性的三大风险（必须钉死）

1. **标签推断 + declassification 的循环论证**（最大风险）：agent 既推断标签又判降密，会把任何泄露"洗成有意降密"，使分析空洞化（与早先发现的"解析失败默认判 MATCH"的 bug 同构）。
   **对策**：declassification 必须显式标注（`[DECLASSIFY]` + 理由 + 锚点）、单独成一类 verdict（`DECLASSIFIED`）、**绝不自动确认**，强制人工复核。

2. **隐式流靠 pc-label**（见改动点 C 第 1 点）：丢了 pc-label，IFC 退化成普通污点追踪，失去核心价值。

3. **裁决解析不能脆弱**（吸取早先 bug 的教训）：唯一、显式的 `[VERDICT]` 标签 + 解析失败时**重试而非默认 SECURE**。`_check_flow_satisfies_policy` 取不到裁决时绝不能默认放行。

### 能力边界（必须在文档与输出中写明）

第一期只保证 **termination-insensitive non-interference**。以下 covert / side channel **明确 out-of-scope**：时间信道、终止信道、异常信道、缓存信道。不要让用户误以为它能挡住所有泄露。

---

## 6. 分期实施

| 阶段 | 内容 | 涉及改动点 | 验证靶子 |
|---|---|---|---|
| **第一期** | 单函数内 IFC：二级格 + 显式流 + pc-label 隐式流。先证明每个函数的流签名。 | A / C / D / F / G | demo: 显式泄露 + 隐式泄露 + 合法 declassification 各一例 |
| **第二期** | 跨函数组合：启用 `[FLOW]` 摘要沿调用链组合，追踪端到端泄露路径。 | B | demo: 跨函数泄露路径 |
| **第三期** | self-composition 自动确认。 | E | 对已确认 LEAK 跑两遍验证 |

---

## 7. 改动点速查表

| 改动点 | 文件 | 现有锚点（file:line） | 动作 |
|---|---|---|---|
| A. IFC spec 生成 | `md/ifc_system_prompt.md`（新） + `main.py:236-239` | `md/system_prompt.md:62-92` | 新增 `[FLOW]` 格式 prompt |
| B. 流约束下传 | `src/generate_batch_prompts.py:162-303` | "CALLER SPECS" / "CALLEE EXPECTATIONS" 两节 | 语义换成流约束（IFC 分支） |
| C. IFC 推理器 | `src/ifc_prompts.py`（新） + `src/reasoner.py:186-243` | `current_pre` 线程 241; `prompts.py:10-43,155-255` | 传 Γ+pc-label; 两个新 LLM 调用 |
| D. verdict + schema | `src/verification.py:260-292, 118-128, 400-441` | verdict 字面量; gaps dict 280-289 | 加 SECURE/LEAK/DECLASSIFIED + IFC gaps |
| E. self-composition probe | `md/ifc_validator.md`（新） + `src/verification.py:301-397` | `md/bug_validator.md` | probe 改两次运行比对 |
| F. config 旋钮 | `config.py:13-22` | 现有 per-task 模型常量 | 加 IFC_* 常量 |
| G. readiness + 解析 | `src/file_utils.py:24-42`, `src/parser.py:157-192` | `[SPEC]`/`[INFO]` 门控 | 加 `[FLOW]` 识别 |

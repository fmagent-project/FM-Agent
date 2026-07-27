# FM-Agent 自底向上推理（最弱前置条件）设计方案

## 1. 背景与动机

### 1.1 当前架构：自顶向下 / 最强后置条件 (SP)

FM-Agent 当前采用 **Hoare 逻辑的前向推理**（Strongest Postcondition, SP）：

```
spec_pre → block_1 → post_1 → block_2 → post_2 → ... → post_n
                                                          ↓
                                               检查: post_n ⊨ spec_post?
```

**核心代码路径**：`reasoner.py::reasoner()` 逐 block 前向推导，`prompts.py::_generate_block_post_condition()` 让 LLM 从 pre-condition + code block 推导 post-condition，`prompts.py::_check_post_implies_spec()` 检查推导出的 post-condition 是否蕴含 spec 的 post-condition。

**调用图方向**：`generate_topdown_layers.py::_compute_layers()` 基于 `callers_map` 做拓扑排序——Layer 0 = 无调用者的入口函数，逐层向下到叶子函数。

### 1.2 SP 的局限

| 局限 | 说明 |
|------|------|
| **遗漏型缺陷检测弱** | SP 从前向后推导，如果代码缺少某个分支（如未处理某种输入情况），SP 推导出的 post-condition 可能恰好"不包含"该情况，从而与 spec post-condition 不产生矛盾——遗漏被掩盖 |
| **前置条件验证不足** | SP 只在函数出口检查 post-condition，不验证入口的 pre-condition 是否充分。如果 spec 的 pre-condition 太弱（没约束住某些边界），SP 无法发现 |
| **被调用者信息未利用** | 自顶向下处理时，分析 caller 时 callee 的 spec 可能尚未生成或未被传播。caller 无法获知 callee 的精确前置要求 |
| **虚假路径** | SP 对不可达路径也会推导 post-condition，可能产生虚假的 MISMATCH |

### 1.3 提议：自底向上 / 最弱前置条件 (WP)

```
spec_post ← block_n ← wp_n ← block_{n-1} ← wp_{n-1} ← ... ← wp_1
                                                                    ↓
                                              检查: spec_pre ⊨ wp_1?
```

WP 从 spec 的 post-condition 出发，**逆向**推导每个 block 需要什么前置条件才能保证后续 post-condition 成立。最终在函数入口检查 spec 的 pre-condition 是否蕴含推导出的 wp_1。

**调用图方向**：自底向上——Layer 0 = 无被调用者的叶子函数，逐层向上到入口函数。分析 caller 时，所有 callee 的 WP 已知，可精确传播 callee 的前置要求。

## 2. 理论基础

### 2.1 Hoare 逻辑中的 SP 与 WP

| 属性 | SP (最强后置条件) | WP (最弱前置条件) |
|------|-------------------|-------------------|
| **方向** | 前向 (forward) | 后向 (backward) |
| **定义** | SP(S, P) = 执行 S 后成立的最强条件，给定 P 在执行前成立 | WP(S, Q) = 保证 Q 在 S 执行后成立的最弱条件 |
| **计算** | 从 P 出发，经过 S，推导出 post | 从 Q 出发，逆向经过 S，推导出 pre |
| **验证** | SP(S, P) ⊨ Q ? | P ⊨ WP(S, Q) ? |
| **发现** | 代码做了错误的事 | 代码没有保证应保证的事 |

### 2.2 WP 的关键规则（谓词变换器）

```
WP(skip, Q)           = Q
WP(x := e, Q)         = Q[x/e]          (代入)
WP(S1; S2, Q)         = WP(S1, WP(S2, Q))
WP(if b then S1 else S2, Q) = (b ∧ WP(S1, Q)) ∨ (¬b ∧ WP(S2, Q))
WP(while b do S, Q)   = I ∧ ...          (需要循环不变式 I)
WP(return e, Q)       = Q[return_value/e]
WP(throw e, Q)        = Q[exception/e]   (异常路径)
```

在 FM-Agent 中，这些规则不通过形式化计算实现，而是通过 LLM 推理完成——LLM 扮演谓词变换器的角色，给定 code block 和 post-condition，计算 weakest pre-condition。

### 2.3 SP 与 WP 的互补性

SP 和 WP 发现的 Bug 类型不同：

| Bug 类型 | SP 能发现 | WP 能发现 |
|----------|-----------|-----------|
| 代码计算出错误值 | ✓ (post 不蕴含 spec) | ✓ (wp 包含值约束) |
| 代码缺少分支/遗漏情况 | △ (可能被掩盖) | ✓ (wp 包含必须处理的情况) |
| 前置条件太弱 | ✗ | ✓ (spec_pre 不蕴含 wp) |
| 前置条件太强 | ✓ (post 无法满足) | △ |
| 不可达路径矛盾 | △ (可能虚假 MISMATCH) | ✓ (wp 为 false 表示不可达) |
| 被调用者要求未满足 | ✗ | ✓ (callee WP 向上传播) |

**双向交叉验证**：同时运行 SP 和 WP，取并集，可最大化 Bug 召回率。

## 3. 总体架构

### 3.1 设计原则

1. **Spec 生成不变**：`[SPEC]`/`[INFO]` 注释块是方向无关的（同时包含 pre 和 post），两种推理方式共用同一套 spec
2. **WP 推理器独立**：新增 `wp_reasoner()`，与现有 `reasoner()` 并行，通过配置选择
3. **分层算法复用**：`_compute_layers()` 参数化方向，自底向上只需翻转 callee/caller 角色
4. **验证管线兼容**：`streaming_reasoner` → `_verify_single_file` 增加方向参数，路由到对应 reasoner
5. **Trace 结构统一**：WP 的 LLM 调用记录到同一 trace 体系，新增 `stage: "wp_verification"` 标签

### 3.2 架构全景

```
                    ┌─────────────────────────┐
                    │     fm-agent.toml       │
                    │  reasoning_direction =  │
                    │  "topdown" | "bottomup" │
                    └────────────┬────────────┘
                                 │
                    ┌────────────▼────────────┐
                    │       main.py            │
                    │  --reasoning-direction   │
                    └────────────┬────────────┘
                                 │
              ┌──────────────────┼──────────────────┐
              │                  │                  │
    ┌─────────▼────────┐ ┌──────▼───────┐ ┌────────▼────────┐
    │ Stage 1-5: 不变  │ │ 层次计算      │ │ Stage 6: 推理    │
    │ (spec 生成)      │ │ (方向感知)    │ │ (方向路由)      │
    └──────────────────┘ └──────────────┘ └──────────────────┘
                                              │
                           ┌──────────────────┼──────────────────┐
                           │                  │                  │
                    ┌──────▼──────┐    ┌──────▼──────┐    ┌──────▼──────┐
                    │ topdown     │    │ bottomup    │    │ bidirectional│
                    │ _compute_   │    │ _compute_   │    │ (未来扩展)   │
                    │ layers()    │    │ bottomup_   │    │             │
                    │             │    │ layers()    │    │             │
                    └─────────────┘    └─────────────┘    └─────────────┘
                           │                  │
                    ┌──────▼──────┐    ┌──────▼──────┐
                    │ reasoner()  │    │ wp_reasoner │
                    │ (SP/前向)   │    │ () (WP/后向)│
                    └─────────────┘    └─────────────┘
```

## 4. 详细设计

### 4.1 WP 推理器 (`src/reasoner.py`)

新增 `wp_reasoner()` 函数，与现有 `reasoner()` 对称：

```python
def wp_reasoner(func, spec, info, language, trace_context=None):
    """Weakest Precondition reasoner — backward chain derivation.

    与 reasoner() 的区别:
    - 从 spec_post_condition 出发, 逆向遍历 blocks
    - 每个 block 计算 WP (而非 post-condition)
    - 在函数入口检查 spec_pre ⊨ wp_1 (而非在出口检查 post_n ⊨ spec_post)
    """
    trace_context = trace_context or {}
    trace_dir = trace_context.get("trace_dir")

    # Step 1: 解析 pre/post condition (与 reasoner 相同)
    pre_condition, spec_post_condition = _parse_spec_conditions(spec)
    if not pre_condition or not spec_post_condition:
        return "Failed to parse pre/post conditions from the spec."

    # Step 2: 分块 (与 reasoner 相同, 复用 _split_into_blocks_braced)
    blocks = _split_into_blocks_braced(func, language)

    # Step 3: 逆向遍历 — 从最后一个 block 开始, 向前推导 WP
    current_post = spec_post_condition  # 从 spec 的 post-condition 出发

    for i in reversed(range(len(blocks))):
        block = blocks[i]
        trace_meta = {
            "function_id": trace_context.get("function_id"),
            "function_file": trace_context.get("function_file"),
            "language": language,
            "block_index": i,
            "block_count": len(blocks),
            "direction": "backward",  # 标记方向
        }

        # 3a: 计算 WP — 给定 code block 和 post-condition, 推导 pre-condition
        wp = _generate_block_wp(
            block,
            current_post,
            info,
            language,
            trace_dir=trace_dir,
            trace_meta=trace_meta,
        )
        if not wp:
            return f"Failed to generate weakest pre-condition for block {i+1}."

        # 3b: 在函数入口 (i==0) 或终止语句处, 检查 spec_pre 是否蕴含 wp
        is_first_block = (i == 0)
        if is_first_block or _has_terminating_statement(block, language):
            passed, stmts, reason, wp_cond = _check_pre_implies_wp(
                block,
                wp,
                pre_condition,  # spec 的 pre-condition (调用者保证的)
                info,
                language,
                trace_dir=trace_dir,
                trace_meta=trace_meta,
            )
            if not passed:
                return (
                    f"Verification FAILED (WP).\n"
                    f"Statements triggering the violation:\n{stmts}\n\n"
                    f"Weakest pre-condition:\n{wp_cond}\n\n"
                    f"Reason for violation:\n{reason}"
                )

        # 3c: 当前 block 的 WP 成为前一个 block 的 post-condition
        current_post = wp

    return ("The function passes the WP verification. "
            "The specification's pre-condition is sufficient to guarantee "
            "the post-condition across all code paths.")
```

**与 `reasoner()` 的关键差异**：

| 维度 | `reasoner()` (SP) | `wp_reasoner()` (WP) |
|------|--------------------|-----------------------|
| 遍历方向 | `for i in range(len(blocks))` (正向) | `for i in reversed(range(len(blocks)))` (逆向) |
| 初始条件 | `current_pre = pre_condition` | `current_post = spec_post_condition` |
| 每步计算 | `_generate_block_post_condition(block, pre, ...)` | `_generate_block_wp(block, post, ...)` |
| 状态传递 | `current_pre = post_condition` (post 变 pre) | `current_post = wp` (wp 变 post) |
| 验证时机 | 终止语句或最后 block | 函数入口 (i==0) 或终止语句 |
| 验证内容 | `post_n ⊨ spec_post?` | `spec_pre ⊨ wp_1?` |
| 验证函数 | `_check_post_implies_spec()` | `_check_pre_implies_wp()` |

### 4.2 提示词设计 (`src/prompts.py`)

#### 4.2.1 `_generate_block_wp()` — WP 生成

```python
def _generate_block_wp(block, post_condition, knowledge, language,
                       trace_dir=None, trace_meta=None):
    """计算 code block 的最弱前置条件 (逆向推理).

    与 _generate_block_post_condition() 对称:
    - 输入: code block + post-condition (而非 pre-condition)
    - 输出: weakest pre-condition (而非 post-condition)
    - 推理方向: 后向 (给定目标 Q, 求最小前提 P 使 {P} S {Q})
    """
    info_str = f"\nAdditional context:\n{knowledge}" if knowledge else ""
    messages = [
        {"role": "system", "content": (
            f"You are an expert in formal verification of {language} programs. "
            f"Given a {language} code block and its post-condition (what must be true "
            "after execution), compute the WEAKEST PRE-CONDITION: the minimal condition "
            "that must hold before the block to GUARANTEE the post-condition holds after. "
            "Cover all execution paths including early returns, exceptions, and normal "
            f"flow-through. Apply {language}-specific semantics. "
            "The weakest pre-condition should be as permissive as possible while still "
            "guaranteeing the post-condition. Express it in natural language and formal logic."
        )},
        {"role": "user", "content": (
            f"Programming language: {language}\n\n"
            f"Post-condition (must hold AFTER this block):\n{post_condition}\n\n"
            f"Code block:\n```{language.lower()}\n{block}\n```\n"
            f"{info_str}\n"
            "Compute the weakest pre-condition. Return only a valid JSON object: "
            '{"pre_condition": "..."}. Do not include Markdown, tags, or prose '
            "outside the JSON object."
        )}
    ]
    meta = {
        "purpose": "generate_block_wp",
        "summary": "Generated weakest pre-condition for code block",
        "direction": "backward",
        **(trace_meta or {}),
    }
    return _llm_json_call(
        _llm_provider_client,
        REASONER_WP_MODEL,  # 新增配置, 默认同 REASONER_POST_CONDITION_MODEL
        messages,
        _parse_wp_json,
        '{"pre_condition": "non-empty string"}',
        trace_dir=trace_dir,
        trace_meta=meta,
    )


def _parse_wp_json(data):
    """Validate the WP response (mirrors _parse_post_condition_json)."""
    if not isinstance(data, dict):
        raise ValueError("WP JSON must be an object")
    pre_condition = data.get("pre_condition")
    if not isinstance(pre_condition, str) or not pre_condition.strip():
        raise ValueError("WP JSON requires a non-empty string field: pre_condition")
    return pre_condition.strip()
```

**提示词设计要点**：

1. **"weakest" 强调**：明确要求 LLM 计算**最弱**前置条件（尽可能宽松），而非任意前置条件。这确保只有真正必要的约束才被检查
2. **"guarantee" 语义**：强调"保证"关系——WP 必须足以保证 post-condition 成立，而非仅仅是相关条件
3. **路径覆盖**：与 SP 提示词一致，要求覆盖所有执行路径（early return, exception, normal flow）
4. **输出格式**：与 `_generate_block_post_condition` 对称，只是字段名从 `post_condition` 改为 `pre_condition`

#### 4.2.2 `_check_pre_implies_wp()` — 前置条件蕴含检查

```python
def _check_pre_implies_wp(block, wp, spec_pre_condition, knowledge, language,
                          trace_dir=None, trace_meta=None):
    """检查 spec_pre_condition 是否蕴含 wp (最弱前置条件).

    与 _check_post_implies_spec() 对称:
    - SP 检查: post (代码实际做的) ⊨ spec_post (规约要求的)? — 前向矛盾
    - WP 检查: spec_pre (调用者保证的) ⊨ wp (代码需要的)? — 后向不足

    如果 spec_pre 不蕴含 wp, 说明存在满足 spec_pre 但不满足 wp 的输入,
    即调用者的保证不足以让代码正确运行 — 这是潜在 Bug.
    """
    info_str = f"\nAdditional context:\n{knowledge}" if knowledge else ""
    lang_expertise = _LANGUAGE_EXPERTISE.get(language.lower(), ...)
    messages = [
        {"role": "system", "content": (
            lang_expertise +
            "Given a code block, its weakest pre-condition A (what the code REQUIRES "
            "before execution to guarantee correctness), and a specification pre-condition "
            "B (what callers GUARANTEE before calling), determine whether there exists a "
            "concrete valid input where B holds but A does not. "
            "If such an input exists, the function may fail because the caller's guarantees "
            "are insufficient — the code requires more than what the spec promises. "
            "Focus on finding CONCRETE COUNTEREXAMPLES: specific input values where B is "
            "satisfied but A is violated. "
            "Check these common violation patterns:\n"
            "  1. B allows input ranges/shapes that A restricts (e.g., B says 'non-negative' "
            "but A requires 'positive').\n"
            "  2. B does not constrain a variable that A requires to be in a specific state.\n"
            "  3. B allows null/empty/edge-case values that A excludes.\n"
            "For each potential violation, construct a specific input, verify B holds, "
            "then check if A is violated. "
            "Return JSON: {\"verdict\": \"MATCH|MISMATCH\", \"counterexample\": ..., "
            "\"offending_statements\": ..., \"reason\": ...}"
        )},
        {"role": "user", "content": (
            f"Programming language: {language}\n\n"
            f"Code block:\n```{language.lower()}\n{block}\n```\n\n"
            f"Condition A (weakest pre-condition — what the code requires):\n{wp}\n\n"
            f"Condition B (spec pre-condition — what callers guarantee):\n{spec_pre_condition}\n"
            f"{info_str}\n"
            "Is there a concrete valid input where B holds but A does not? "
            "Provide a specific counterexample if any case exists. "
            "Return only the JSON object."
        )}
    ]
    # 重试逻辑与 _check_post_implies_spec 完全一致 (复用 MAX_SPC_ITER)
    # ...
```

**与 `_check_post_implies_spec()` 的关键差异**：

| 维度 | SP 检查 | WP 检查 |
|------|---------|---------|
| 条件 A | 代码实际 post-condition (做了什么) | 代码需要的 WP (要求什么) |
| 条件 B | spec post-condition (应做什么) | spec pre-condition (保证什么) |
| 检查方向 | A ⊨ B? (代码做了的 ⊇ 应做的) | B ⊨ A? (保证的 ⊇ 需要的) |
| 反例含义 | 存在输入使代码行为违反 spec | 存在输入满足 spec_pre 但不满足 WP |
| Bug 性质 | 代码做错了 | 代码没保证到 |

### 4.3 自底向上分层计算 (`src/generate_topdown_layers.py`)

#### 4.3.1 新增 `_compute_bottomup_layers()`

```python
def _compute_bottomup_layers(phase_fqns, callees_map, callers_map):
    """自底向上拓扑分层: Layer 0 = 叶子函数 (无 callees), 逐层向上到入口.

    与 _compute_layers() 的区别:
    - 就绪条件: "所有 callees 已分配" (而非 "所有 callers 已分配")
    - SCC 检测: 基于 callees_map 构建 SCC (而非 callers_map)
    - 效果: 叶子函数先处理, 入口函数后处理

    这样在分析 caller 时, 所有 callee 的 WP 已计算完毕,
    可将 callee 的前置要求传播给 caller.
    """
    phase_set = set(phase_fqns)
    remaining = set(phase_set)
    assigned = {}
    layers = []

    while remaining:
        ready = set()
        for fqn in remaining:
            # 关键区别: 检查 callees 是否都已分配 (而非 callers)
            phase_callees = callees_map.get(fqn, set()) & phase_set
            unassigned_callees = phase_callees - set(assigned.keys())
            if not unassigned_callees:
                ready.add(fqn)

        if ready:
            layer_idx = len(layers)
            for fqn in ready:
                assigned[fqn] = layer_idx
            layers.append({"layer": layer_idx, "functions": sorted(ready),
                          "cycle_resolution": False})
            remaining -= ready
        else:
            # 环检测 — 基于 callees_map (而非 callers_map) 构建 SCC
            sub_edges = {}
            for fqn in remaining:
                sub_edges[fqn] = callees_map.get(fqn, set()) & remaining

            sccs = _tarjan_scc(remaining, sub_edges)

            # 构建 SCC DAG 并分配层次 (与 _compute_layers 逻辑对称)
            fqn_to_scc = {}
            for i, scc in enumerate(sccs):
                for fqn in scc:
                    fqn_to_scc[fqn] = i

            scc_callees = defaultdict(set)  # scc_idx -> callees SCC
            for fqn in remaining:
                scc_i = fqn_to_scc[fqn]
                for callee_fqn in callees_map.get(fqn, set()) & remaining:
                    scc_j = fqn_to_scc[callee_fqn]
                    if scc_i != scc_j:
                        scc_callees[scc_i].add(scc_j)

            # 拓扑排序: callee SCC 先分配
            scc_assigned = {}
            scc_remaining = set(range(len(sccs)))

            while scc_remaining:
                scc_ready = set()
                for scc_idx in scc_remaining:
                    unassigned_scc_callees = scc_callees.get(scc_idx, set()) - set(scc_assigned.keys())
                    if not unassigned_scc_callees:
                        scc_ready.add(scc_idx)

                if not scc_ready:
                    # 退化处理 (与 _compute_layers 一致)
                    layer_idx = len(layers)
                    all_fqns = set()
                    for scc_idx in scc_remaining:
                        all_fqns.update(sccs[scc_idx])
                    for fqn in all_fqns:
                        assigned[fqn] = layer_idx
                    layers.append({"layer": layer_idx, "functions": sorted(all_fqns),
                                  "cycle_resolution": True})
                    remaining -= all_fqns
                    break

                layer_idx = len(layers)
                layer_fqns = set()
                is_cycle = False
                for scc_idx in scc_ready:
                    scc_assigned[scc_idx] = layer_idx
                    layer_fqns.update(sccs[scc_idx])
                    if len(sccs[scc_idx]) > 1:
                        is_cycle = True

                for fqn in layer_fqns:
                    assigned[fqn] = layer_idx
                layers.append({"layer": layer_idx, "functions": sorted(layer_fqns),
                              "cycle_resolution": is_cycle})
                remaining -= layer_fqns
                scc_remaining -= scc_ready

    return layers
```

#### 4.3.2 新增 `generate_bottomup_layers()`

```python
def generate_bottomup_layers(proj_dir, phase_numbers=None, extra_call_edges=None):
    """生成自底向上层次 JSON (与 generate_topdown_layers 对称).

    输出文件: phase_XX_bottomup_layers.json
    结构与 topdown_layers.json 完全一致, 只是层次顺序反转.
    """
    # ... (与 generate_topdown_layers 结构相同, 仅替换 _compute_layers 为 _compute_bottomup_layers)
    layers = _compute_bottomup_layers(phase_fqns, callees_map, callers_map)

    out_path = os.path.join(output_dir, f"phase_{phase_num:02d}_bottomup_layers.json")
    # ...
```

#### 4.3.3 分层对比

```
自顶向下 (_compute_layers):          自底向上 (_compute_bottomup_layers):
┌─────────────────────┐              ┌─────────────────────┐
│ Layer 0: entry()    │              │ Layer 0: leaf_a()   │
│   calls helper()    │              │   (no callees)      │
├─────────────────────┤              ├─────────────────────┤
│ Layer 1: helper()   │              │ Layer 1: helper()   │
│   calls leaf_a()    │              │   calls leaf_a()    │
├─────────────────────┤              ├─────────────────────┤
│ Layer 2: leaf_a()   │              │ Layer 2: entry()    │
│   (no callees)      │              │   calls helper()    │
└─────────────────────┘              └─────────────────────┘
```

### 4.4 被调用者 WP 传播

这是自底向上推理的**核心优势**：分析 caller 时，所有 callee 的 WP 已知。

#### 4.4.1 WP 传播机制

```python
def _collect_callee_wps(fqn, phase_fqns, wp_cache, callees_map):
    """收集 fqn 的所有被调用者的 WP, 作为 [INFO] 补充上下文.

    在自底向上模式下, 分析 caller 时 callee 的 WP 已计算完毕.
    将 callee 的 WP 摘要注入到 caller 的推理上下文中, 使 WP 计算更精确:
    - caller 必须在调用 callee 前保证 callee 的 WP
    - 这些约束成为 caller WP 的一部分
    """
    callee_wps = {}
    for callee_fqn in callees_map.get(fqn, set()) & phase_fqns:
        if callee_fqn in wp_cache:
            callee_wps[callee_fqn] = wp_cache[callee_fqn]
    return callee_wps


def _format_callee_wps(callee_wps):
    """将 callee WP 格式化为 info 文本, 注入到 _generate_block_wp 的 knowledge 参数."""
    if not callee_wps:
        return ""
    lines = ["Callee pre-condition requirements (from WP analysis):"]
    for callee, wp in callee_wps.items():
        short_name = callee.split("::")[-1]
        lines.append(f"  {short_name} requires: {wp[:200]}...")  # 截断防止上下文爆炸
    return "\n".join(lines)
```

#### 4.4.2 WP 缓存

```python
# 在 pipeline 层维护 wp_cache
wp_cache = {}  # fqn -> wp_string

# 每个函数推理完成后, 缓存其 WP
def _verify_single_file_wp(file_path, ..., wp_cache=None):
    result = wp_reasoner(func, spec, info, language, ...)
    if wp_cache is not None:
        fqn = _file_to_fqn(file_path, proj_dir)
        # 提取 wp_1 (函数入口的 WP) 缓存
        wp_cache[fqn] = extract_wp_from_result(result)
    return result
```

#### 4.4.3 传播效果示例

```
分析顺序 (自底向上):

1. leaf_a(): WP = "input x > 0 and list is non-empty"
   → wp_cache["leaf_a"] = "input x > 0 and list is non-empty"

2. helper(): 调用 leaf_a(x, lst)
   → _collect_callee_wps 发现 leaf_a 的 WP
   → 注入到 helper 的 WP 计算上下文:
     "leaf_a requires: x > 0 and list is non-empty"
   → helper 的 WP 自动包含: "x > 0 and lst is non-empty"
     (因为 helper 必须在调用 leaf_a 前保证这些条件)

3. entry(): 调用 helper(x, lst)
   → _collect_callee_wps 发现 helper 的 WP
   → entry 的 WP 自动包含 helper 的所有前置要求
```

### 4.5 验证流程集成

#### 4.5.1 `verification.py` 修改

```python
from .reasoner import reasoner, wp_reasoner, _parse_spec_conditions

def _verify_single_file(file_path, output_dir, proj_dir=None, work_dir=None,
                        reasoning_direction="topdown", wp_cache=None):
    """验证单个函数文件 — 根据方向路由到 SP 或 WP reasoner."""
    # ... (解析 func, spec, info, language — 不变)

    if reasoning_direction == "bottomup":
        # 注入 callee WP 上下文
        callee_wp_info = ""
        if wp_cache:
            callee_wps = _collect_callee_wps(fqn, phase_fqns, wp_cache, callees_map)
            callee_wp_info = _format_callee_wps(callee_wps)
        enhanced_info = (info or "") + ("\n\n" + callee_wp_info if callee_wp_info else "")

        result = wp_reasoner(func, spec, enhanced_info, language, trace_context=...)
        # 缓存 WP 供上层 caller 使用
        if wp_cache is not None:
            wp_cache[fqn] = extract_wp_from_result(result)
    else:
        result = reasoner(func, spec, info, language, trace_context=...)

    # ... (写入结果文件 — 不变)
```

#### 4.5.2 `streaming_reasoner()` 修改

```python
def streaming_reasoner(input_dir, output_dir, ..., reasoning_direction="topdown"):
    """增加 reasoning_direction 参数, 传递给 _verify_single_file."""
    # 自底向上模式需要维护 wp_cache
    wp_cache = {} if reasoning_direction == "bottomup" else None

    # ... 其余逻辑不变, 仅在调用 _verify_single_file 时传递方向和 wp_cache
    future = executor.submit(
        _verify_single_file,
        file_path, output_dir,
        proj_dir=proj_dir, work_dir=work_dir,
        reasoning_direction=reasoning_direction,
        wp_cache=wp_cache,
    )
```

### 4.6 配置与 CLI

#### 4.6.1 `fm-agent.toml` 新增

```toml
[runtime]
# 推理方向: "topdown" (SP/前向, 默认) 或 "bottomup" (WP/后向)
reasoning_direction = "topdown"
```

#### 4.6.2 `config.py` 修改

```python
class RuntimeCfg(_Section):
    # ... 现有字段 ...
    reasoning_direction: Literal["topdown", "bottomup"] = "topdown"

# 模块级常量
REASONING_DIRECTION = settings.runtime.reasoning_direction
REASONER_WP_MODEL = LLM_MODEL  # WP 推理使用同一模型, 可独立配置

# 加入 __all__
__all__ = [
    ...,
    "REASONING_DIRECTION",
    "REASONER_WP_MODEL",
]
```

#### 4.6.3 `main.py` CLI 参数

```python
parser.add_argument(
    "--reasoning-direction",
    choices=["topdown", "bottomup"],
    default=None,
    help="Reasoning direction: 'topdown' (strongest postcondition, forward) "
         "or 'bottomup' (weakest precondition, backward). "
         "Defaults to fm-agent.toml [runtime] reasoning_direction.",
)

# 在 run_pipeline 中:
reasoning_direction = args.reasoning_direction or REASONING_DIRECTION

# Stage 5: 根据方向生成分层
if reasoning_direction == "bottomup":
    print("[Pipeline] Stage 5/6: Generating bottom-up layers...")
    generate_bottomup_layers(work_dir, extra_call_edges=extra_call_edges)
else:
    print("[Pipeline] Stage 5/6: Generating topdown layers...")
    generate_topdown_layers(work_dir, extra_call_edges=extra_call_edges)

# Stage 6: 传递方向到验证管线
streaming_reasoner(..., reasoning_direction=reasoning_direction)
```

## 5. 关键设计决策

### 5.1 为什么不修改现有 `reasoner()` 而是新建 `wp_reasoner()`？

- **单一职责**：SP 和 WP 是两种不同的推理范式，逻辑差异大（遍历方向、验证点、检查内容都不同）
- **向后兼容**：现有 `reasoner()` 经过充分测试，不应冒险修改
- **可组合性**：未来双向模式需要同时调用两者，独立函数更易组合

### 5.2 为什么 WP 仍然用 block 粒度而非语句粒度？

- **与 SP 对称**：复用 `_split_into_blocks_braced()` 和 `GRANULARITY` 配置
- **LLM 上下文效率**：40 行 block 让 LLM 有足够上下文理解控制流，语句级太碎
- **可行性**：LLM 可以在单个 block 内处理 if/else/loop 的 WP（通过谓词变换器规则的隐式应用）

### 5.3 为什么 WP 检查在函数入口 (i==0) 而非出口？

- **WP 语义**：WP 的目标是在函数入口验证 pre-condition 的充分性。逆向推导到 i==0 时，wp_1 就是整个函数的 WP
- **终止语句处理**：在逆向遍历中遇到终止语句（return/throw）时，也做检查——此时 WP 包含返回值的约束，检查的是该返回路径的前置条件是否被满足
- **与 SP 对称**：SP 在最后 block 或终止语句检查 post-condition；WP 在第一 block 或终止语句检查 pre-condition

### 5.4 被调用者 WP 传播为什么用缓存而非修改 [INFO] block？

- **[INFO] block 在 spec 阶段生成**：修改它需要重新生成 spec，代价大
- **运行时注入更灵活**：wp_cache 在 pipeline 运行时维护，不污染 spec 文件
- **截断控制**：传播时截断 WP 文本（200 字符），防止上下文爆炸

### 5.5 为什么 SCC 处理翻转 callee/caller 角色？

- **方向一致性**：自底向上要求 callee 先于 caller 处理。SCC 内部的函数互相调用（循环），无法严格排序，但 SCC 之间可以按 callee 依赖关系排序
- **Tarjan 算法不变**：`_tarjan_scc()` 本身是方向无关的，只是传入的 edges 方向不同

## 6. 挑战与应对

### 6.1 循环不变式

**挑战**：WP 的 `while` 规则需要循环不变式，LLM 可能无法自动推导出正确的不变式。

**应对**：
- Block 粒度（40 行）通常将整个循环包含在一个 block 内，LLM 在 block 级别隐式处理
- 如果 LLM 推导的 WP 过强（太严格），会产生虚假 MISMATCH——通过 `_check_pre_implies_wp` 的反例机制过滤
- 未来可增加循环不变式推断的专用 LLM 调用

### 6.2 WP 过强问题

**挑战**：LLM 计算的 WP 可能不是"最弱"的，而是过强的（包含不必要的约束），导致虚假 MISMATCH。

**应对**：
- 提示词明确强调 "weakest" 和 "as permissive as possible"
- `_check_pre_implies_wp` 要求具体反例——如果 WP 过强但 spec_pre 确实不满足，反例必须是**具体输入值**，而非抽象推理
- 可配置 `wp_relaxation`：如果连续 N 个函数都产生 MISMATCH 但无法提供具体反例，自动放宽 WP

### 6.3 多返回路径

**挑战**：函数可能有多个 return 语句，每条路径的 WP 不同。

**应对**：
- 逆向遍历自然处理：从 spec_post 出发，遇到 return 时 WP 包含返回值约束
- 如果 block 内有 if/else 各自 return，LLM 在 block 级别计算 WP 时取**析取**（disjunction）——任一路径满足即可
- 终止语句检查点确保每条返回路径都被验证

### 6.4 异常路径

**挑战**：throw/raise 语句的 WP 需要处理异常语义。

**应对**：
- 提示词中明确要求 "Cover all execution paths including early returns, exceptions"
- WP 对 throw 的处理：`WP(throw e, Q) = Q[exception/e]`——LLM 隐式应用
- spec 的 post-condition 应已包含异常约定（error contract），WP 会自然继承

### 6.5 上下文窗口限制

**挑战**：callee WP 传播可能使上下文过长。

**应对**：
- 截断 callee WP 到 200 字符
- 只传播直接 callee（不递归传递孙 callee 的 WP）
- 可配置 `max_callee_wps`（默认 5），超过时按调用频率排序取 top-K

## 7. 实施路线图

### Phase 1: 核心推理器（最小可用）

**目标**：`wp_reasoner()` 独立可用，能对单个函数做 WP 验证。

| 步骤 | 文件 | 改动 |
|------|------|------|
| 1.1 | `src/prompts.py` | 新增 `_generate_block_wp()`, `_check_pre_implies_wp()`, `_parse_wp_json()` |
| 1.2 | `src/reasoner.py` | 新增 `wp_reasoner()` |
| 1.3 | `config.py` | 新增 `REASONER_WP_MODEL` 常量 |
| 1.4 | 测试 | 对已知有 Bug 的函数运行 WP 验证，确认能发现 SP 遗漏的缺陷 |

### Phase 2: 分层与管线集成

**目标**：`--reasoning-direction bottomup` 完整可运行。

| 步骤 | 文件 | 改动 |
|------|------|------|
| 2.1 | `src/generate_topdown_layers.py` | 新增 `_compute_bottomup_layers()`, `generate_bottomup_layers()` |
| 2.2 | `src/verification.py` | `_verify_single_file` 增加 `reasoning_direction` 参数 |
| 2.3 | `src/verification.py` | `streaming_reasoner` 增加 `reasoning_direction` 参数 |
| 2.4 | `main.py` | 新增 `--reasoning-direction` CLI 参数，路由分层和验证 |
| 2.5 | `config.py` + `fm-agent.toml` | 新增 `reasoning_direction` 配置项 |
| 2.6 | 测试 | 端到端运行 `--reasoning-direction bottomup`，验证全流程 |

### Phase 3: 被调用者 WP 传播

**目标**：callee WP 向上传播，提升 caller 分析精度。

| 步骤 | 文件 | 改动 |
|------|------|------|
| 3.1 | `src/reasoner.py` 或新文件 | 新增 `_collect_callee_wps()`, `_format_callee_wps()` |
| 3.2 | `src/verification.py` | `streaming_reasoner` 维护 `wp_cache`，传递给 `_verify_single_file` |
| 3.3 | `src/incremental_reasoner.py` | 增量管线支持 `reasoning_direction` |
| 3.4 | 测试 | 对比有无 WP 传播的 MISMATCH 检出率 |

### Phase 4: 双向推理（未来扩展）

**目标**：同时运行 SP 和 WP，交叉验证，取并集。

```python
# 未来 CLI:
parser.add_argument(
    "--reasoning-direction",
    choices=["topdown", "bottomup", "bidirectional"],
    default="topdown",
)

# bidirectional 模式:
# 1. 先运行 topdown (SP), 收集 MISMATCH 集合 A
# 2. 再运行 bottomup (WP), 收集 MISMATCH 集合 B
# 3. 最终 Bug 集合 = A ∪ B (取并集)
# 4. A ∩ B 的 Bug 置信度最高 (双向确认)
```

## 8. 文件变更清单

| 文件 | 变更类型 | 估计行数 |
|------|----------|----------|
| `src/prompts.py` | 新增函数 | +120 |
| `src/reasoner.py` | 新增函数 | +60 |
| `src/generate_topdown_layers.py` | 新增函数 | +100 |
| `src/verification.py` | 修改 | +30 |
| `main.py` | 修改 | +15 |
| `config.py` | 修改 | +10 |
| `fm-agent.toml` | 修改 | +2 |
| `src/incremental_reasoner.py` | 修改 | +20 |
| **合计** | | **~357** |

## 9. 总结

本方案在 FM-Agent 现有自顶向下 SP 推理基础上，新增自底向上 WP 推理方式：

- **理论互补**：SP 发现"代码做错了什么"，WP 发现"代码遗漏了什么"，两者覆盖不同 Bug 类型
- **架构对称**：WP 推理器、WP 提示词、自底向上分层算法与现有 SP 实现严格对称，降低理解成本
- ** callee WP 传播**：自底向上的核心优势——callee 的前置要求向上传播，使 caller 分析更精确
- **非侵入式**：通过配置和 CLI 参数切换方向，不修改现有 SP 逻辑，向后完全兼容
- **渐进式实施**：Phase 1 即可独立可用，Phase 2-3 逐步增强，Phase 4 双向验证是自然扩展

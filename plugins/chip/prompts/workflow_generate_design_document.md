# Chip 设计与功能检测点文档生成

为本次 chip 分析中唯一的 artifact-eligible root DUT 生成中文
《设计与功能检测点文档》。最终文档面向人工阅读，同时保留现有 module specs
中的验证追溯信息。

## 输入和证据边界

必须读取：

1. `fm_agent/chip_design_document_template_zh.md`；
2. `fm_agent/chip/design_document.input.json`；
3. input JSON 列出的每一份 `_spec.md` 和 `_info.md`；
4. `design_document.source_inventory.json`，将其中的目标源码路径作为探索起点。

现有 specs 描述 intended behavior，不自动等于已经由 RTL 证明的实现事实。
源码清单只列出目标目录 B 内的源码，不是读取白名单。agent 从仓库根目录 A
运行，可以按需搜索 B 外与目标相关的父模块、实例化和连接、上下游、共享类型、
参数来源及配置源码。读取上下文不扩大正式文档目标，也不要求扫描整个仓库。

从源码自由探索配置，不新增配置入口：若找到多个配置、找不到配置或无法确认
具体适用配置，保留 OPEN 并继续生成文档。区分模块定义与具体实例；未能确认
目标实例时，不任意挑选或把条件化行为写成无条件事实。caller 的用法是需求线索，
不能自动代表目标的全部能力。源码、specs、不同 caller 或配置发生冲突时，在
附录 E 保留冲突及 OPEN，不得静默选择一方，也不得反向修改 module specs。

本次 hook 没有运行 build、Chisel elaboration、simulation、test、formal、
regression 或 Mermaid renderer。不要声称这些动作已执行或通过。不要根据
Chisel 名称猜测 elaborated Verilog 名称、端口裁剪或当前配置值；无法证明的
字段写 OPEN、未执行、未签核或不适用，并写明关闭所需证据。

## 唯一写入位置

只写：

```text
fm_agent/chip/design_document.pending.md
```

不得写最终 `design_document.md`，不得修改源码、module `_spec.md`/`_info.md`、
input JSON、模板或其他文件。FM-Agent 会校验候选并原子发布最终文件。

## 语言和结构

- 正文使用中文；源码标识符、module、参数、端口、路径和 FG/FC/CK 标签保持原样。
- H1 使用 input JSON 中唯一 root DUT 的 module name：
  `# <DUT> 设计与功能检测点文档`。
- 以模板的固定标题、层级和顺序为写作目标。P-* 行为至少一项并可重复；
  额外 CASE-* 按需增加。
- 不适用的固定章节必须保留，并以事实依据说明不适用理由。
- 删除所有模板维护/生成指令、方括号占位内容和示例 ID，不要把模板注释
  复制进候选。
- 尽量保持模板每节的表格数量。表格行数、正文篇幅和图形数量按 DUT
  实际复杂度决定。
- 不复制模板或任何 fixture 的示例事实、端口、参数、状态和证据。

## 内容组织方法

1. 先建立读者模型：职责、明确非目标、上游生产者、下游消费者、
   控制参与者、关键概念、延迟/容量和 OPEN。
2. 定义少量稳定 logical names，在正文、伪代码、图和 Test Plan 中一致使用。
   当前证据不足以映射精确 RTL 时，在附录 B 使用 OPEN，不要猜测。
3. 按数据流顺序定义 P-* 行为。每项说明输入、输出、延迟、适用实例和边界；
   同一行为只在 P-* 处完整定义，其他章节引用它。
4. 从现有 specs 的 FG/FC/CK tree 组织验证目标。保留原标签，必要的新 ID
   在本文件内保持自洽，但不要宣称跨运行稳定。
5. Test Plan、Coverage 和属性只记录计划。未实际运行时状态不得写 Closed、
   Compiled、Proved 或 Covered。
6. 附录 D 只记录实际读取且可定位的证据；附录 E 区分 FACT 与 OPEN；
   附录 F 给出 FC/CK 追溯。
7. 附录 A 明确：模板结构版本 v4.0.0；文档版本、配置、elaborated RTL、
   图形渲染、工具签核等无证据字段保持 OPEN/未执行。

## Mermaid

Mermaid 数量可以为零。

- 简单直连或短文本已经更清楚时不画图；在“微架构与数据流”说明结构和
  无需图形的理由，并在附录 G 记录无 Mermaid。
- 复杂拓扑或数据流适合用 `flowchart`。必须包含 DUT subgraph，跨边界边
  使用已定义 logical names；实线表示数据/事务，虚线表示控制、取消、
  flush 或错误。
- 只有确有顶层 FSM 且证据充分时才用 `stateDiagram-v2`；子模块 FSM 或
  entry 生命周期不得冒充 DUT 顶层 FSM。
- 只有跨模块、多周期响应或 replay/flush/cancel 竞争确有必要时才用
  `sequenceDiagram`。
- 图中不要放完整端口清单、精确数组下标、通配符、未经证实的周期或
  parser-sensitive 细节。
- Mermaid fence 必须闭合且内容非空。本次不渲染 SVG，不得宣称图形已通过 renderer 校验。

## 交付前自检

- H1 标识唯一 root DUT。
- 第一部分、第二部分、第三部分及附录 A–G 齐全且顺序正确。
- 至少一个真实 P-* 行为定义；正常、边界、恢复场景均保留，确实不适用时
  说明理由。
- 没有模板占位符、示例 ID、生成指令或旧 Overview index marker。
- 所有签核状态诚实；没有编造 elaboration、渲染或验证结果。
- 只写候选文件。

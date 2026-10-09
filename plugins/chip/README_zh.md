# Chip 插件

[English](README.md) | [中文](README_zh.md)

内置 `chip` 插件为 Chisel 和 Verilog/SystemVerilog module 生成面向验证的行为规约，随后为
选定的 root DUT 生成中文《设计与功能检测点文档》。源码范围、阶段规划、提取、依赖排序、
LLM 调度、校验、重试和 trace 均复用公共 Stage 1–6 Pipeline。chip 运行不执行 software
reasoning 和 bug validation。

## 快速开始

目标目录必须是 Git 仓库。先按[根 README](../../README_zh.md) 配置 FM-Agent 和 LLM
provider，然后运行：

```bash
uv run python main.py /path/to/hardware-repo --plugin chip
```

对于混合仓库或 monorepo，可用项目相对目录限定硬件子树：

```bash
uv run python main.py /path/to/repo --plugin chip --submodule rtl
```

不带 `--resume` 时，FM-Agent 会开始全新运行并替换已有的 `fm_agent/` 工作区。使用相同的
源码范围和配置续跑中断任务：

```bash
uv run python main.py /path/to/hardware-repo --plugin chip --resume
```

## 方言选择

插件会在 Stage 1 前扫描选定的源码范围：

| 范围内源码 | 选中的 Profile |
| --- | --- |
| `.scala` 或 `.sc` | `chip-chisel` |
| `.v`、`.sv` 或 `.svh`，且没有 Chisel 源码 | `chip-verilog` |

两种方言同时存在时 Chisel 优先，FM-Agent 会输出 warning。同一次运行不会同时分析两种
方言，也没有显式方言参数；请通过更窄的项目目录或 `--submodule` 选择目标硬件子树。
若范围内没有支持的硬件源码，运行会在调用 LLM 前失败。

硬件源码发现会排除隐藏目录以及 `target`、`build`、`out`、`dist`、`node_modules`、
虚拟环境和 `fm_agent` 等常见生成或依赖目录。符合 testbench 命名习惯的文件和目录也不会
进入常规提取范围。

## Chisel backend

### 源码分析

源码分析是默认路径，不要求安装 Chisel 构建工具。Scala class、object、trait 和 definition
会作为依赖上下文被提取；只有被识别为硬件 `Module` 且定义了 `val io` 的声明会生成独立的
`_spec.md` 和 `_info.md`。其他声明仍保留在依赖图中，使 Bundle、trait、基类和 companion
object 的要求可以进入 module 规约上下文。

源码分析不会 elaboration Scala。动态选择的 `Module(...)` 构造以及仅由 generator 创建的
依赖可能无法解析；当 FM-Agent 识别出无法映射的动态构造时会输出 warning。需要 elaborated
module graph 时应使用 CIRCT。

### CIRCT 直接分析

CIRCT 是可选路径，因为 FM-Agent 需要已经 elaborated 的 FIRRTL `.fir` 或 MLIR `.mlir`
文件。安装固定版本的 `firtool` 和匹配的 module graph pass plugin：

```bash
./install.sh --with-chisel
```

确保 `~/.local/bin` 位于 `PATH`，然后传入 elaborated 文件：

```bash
FM_AGENT_CHISEL_CIRCT_INPUT=/absolute/path/to/design.fir \
uv run python main.py /path/to/chisel-repo --plugin chip
```

以下变量可以覆盖工具发现：

| 变量 | 含义 |
| --- | --- |
| `FM_AGENT_CHISEL_CIRCT_INPUT` | elaborated `.fir` 或 `.mlir` 输入；相对路径以目标仓库为基准 |
| `FM_AGENT_CHISEL_CIRCT_COMMAND` | `firtool` 命令及固定参数；默认为 `firtool` |
| `FM_AGENT_CHISEL_CIRCT_PLUGIN` | module graph pass plugin 的准确路径 |
| `FM_AGENT_CHISEL_CIRCT_TIMEOUT_SECONDS` | 命令超时；默认 `180` 秒 |

安装后的 plugin 会从 `~/.local/lib` 自动发现。直接分析成功后会写入
`fm_agent/chisel_circt_module_graph.json`，最终选择的 backend 也会记录在
`fm_agent/chip/eligibility.json`。输入或工具缺失、输出不兼容、执行失败时会输出 warning
并自动使用源码分析，而不是终止运行。手动构建方式见
[`tools/chisel-circt/README.md`](../../tools/chisel-circt/README.md)。

## Verilog/SystemVerilog backend

当 `PATH` 中存在 `verible-verilog-syntax` 时，FM-Agent 使用 Verible 提供语法感知的 module
范围和直接实例化边。如果 Verible 不可用、拒绝某个源码文件或暴露不支持的 syntax-tree
schema，FM-Agent 会改用内置源码分析。对于真实叶子 module，Verible 成功返回的空依赖结果
仍是权威结果。

对比或诊断时可强制使用 source fallback：

```bash
FM_AGENT_NO_VERIBLE=1 \
uv run python main.py /path/to/verilog-repo --plugin chip
```

source fallback 能识别常见 Verilog/SystemVerilog module 声明和直接实例化，但不是 compiler
或 elaborator。依赖 preprocessor 或大量生成逻辑的设计，其 module graph 可能不如 Verible
路径完整。

## 输出与校验

每个符合条件的 module 位于 `fm_agent/extracted_functions/` 下，并带有两个相邻的 Markdown
产物：

```text
fm_agent/extracted_functions/<unit>/
├── <Module>.<source-extension>
├── <Module>_spec.md
└── <Module>_info.md
```

- `_spec.md` 通过 FG/FC/CK coverage tree 描述 module 的可观察接口和行为契约，并包含必需的
  `<FG-API>`。
- `_info.md` 在 `# Submodule: <DeclaredModuleName>` 下记录调用方对每个已知直接依赖的要求；
  叶子使用准确标记 `(no submodules)`。

两个产物都必须存在并满足 Markdown 结构，module 才会被判定为 ready。已知依赖 coverage
缺失时，Chisel 给出 advisory，Verilog 则阻塞通过。无效产物通过公共 Stage 6 retry 路径
重新生成。运行元数据和诊断保存在 `fm_agent/trace/`；提取出的源码副本不会写回原 RTL 文件。

所有 module artifact ready 后，chip plugin 还会生成：

```text
fm_agent/chip/design_document.md
```

该中文《设计与功能检测点文档》采用内置 v4.0.0 模板，结合 module specs/info 与源码上下文。
生成时要求恰好一个 artifact-eligible root DUT，必要时可用 `--submodule` 收窄分析范围。

选定目录决定文档目标，agent 可探索仓库其他位置的相关 caller、接口和配置。
无法确认的配置与证据保留 OPEN。每次 Stage 6 完成后均重新生成文档，包括 `--resume`。

## 命令行兼容性

chip plugin 支持 `--resume`、`--submodule`、`--one-phase`、
`--domain-knowledge`/`--knowledge`、`--extra-edge`、fresh `--isolate` 和
`--only-spec` 的公共契约。chip Profile 不进入后续 software reasoning 阶段，因此
`--only-spec` 可省略；两种模式均生成设计文档。

插件拒绝 `--incremental`、`--end-func`、`--all-bugs`、`--bug-validator` 和
`--estimate`。不支持的组合会在创建或修改运行工作区以及调用 LLM 之前失败。

## 当前限制

- 一次运行只选择一种方言，不会合并分析 Chisel 和 Verilog。
- chip Profile 生成 module 规约和最终设计文档，不执行 software reasoning 和 Bug Validation。
- Chisel source fallback 无法保证完整解析动态依赖或仅在 elaboration 后出现的依赖。
- Verilog source fallback 是备用 parser，不是完整的 preprocessing 和 elaboration。
- CIRCT 输入由目标项目的 Chisel 构建产生；FM-Agent 只消费 elaborated `.fir` 或 `.mlir`，
  不会运行 `sbt`、Mill 或项目 generator 来创建它。

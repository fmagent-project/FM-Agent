# Pipeline 插件

FM-Agent Pipeline 插件是受信任的 Python 模块，可以跳过、替换或修改六个
Pipeline Stage。插件通过项目目录及 `proj_dir/fm_agent/` 下的标准文件交换数据。

## 目录结构与启用方式

```text
plugins/
└── example_plugin/
    ├── plugin.json
    ├── plugin.py
    └── prompts/
        └── custom_workflow.md
```

目录名必须与 `plugin.json` 中的 `name` 相同。

```bash
uv run python main.py --list-plugin
uv run python main.py <proj_dir> --plugin example_plugin
```

## Hook 契约

所有声明的函数必须严格使用以下签名：

```python
def hook(proj_dir: str) -> None:
    ...
```

参数必须名为 `proj_dir`，注解必须是 `str`，并且能够按位置传入。返回注解和
实际返回值都必须是 `None`。不支持额外参数、仅限关键字参数、`*args` 或
`**kwargs`。

`proj_dir` 与当前 `run_pipeline()` 实际使用的目录完全一致。隔离运行中，它是
隔离 Git worktree，而不是原项目目录。Hook 可以读写项目和
`proj_dir/fm_agent/`；框架不会把该参数替换成其他内部路径。

## 支持的 Stage

- `generate_phase_plan`
- `generate_domain_context`
- `extract_functions`
- `collect_file_list`
- `generate_topdown_layers`
- `generate_specs_and_verification`

## 配置

```json
{
  "name": "example_plugin",
  "version": "V1.0",
  "configure_function": "configure",
  "stages": {
    "generate_phase_plan": {
      "type": "modify",
      "input_function": "before_phase_plan",
      "output_function": "after_phase_plan"
    },
    "extract_functions": {
      "type": "replace",
      "replace_function": "replace_extraction"
    },
    "generate_topdown_layers": {
      "type": "pass"
    }
  }
}
```

`configure_function` 可选。插件可以配置任意一部分受支持 Stage。

### Option 兼容性（可选）

插件可以显式拒绝自身无法正确处理的命令行选项：

```json
{
  "name": "example_plugin",
  "version": "V1.0",
  "unsupported_options": ["resume", "incremental"],
  "stages": {}
}
```

该字段是稀疏 denylist：未列出的选项默认视为 supported。名称使用 argparse 的
稳定 `dest`（例如 `one_phase`、`domain_knowledge`），当前注册的名称包括
`resume`、`incremental`、`isolate`、`one_phase`、`all_bugs`、`only_spec`、
`estimate`、`domain_knowledge`、`submodule`、`end_func`、`extra_edge` 和
`bug_validator`。`--knowledge` 与 `domain_knowledge` 使用同一名称，
`FM_AGENT_RESUME=1` 与 `resume` 使用同一名称。

FM-Agent 会在解析选项路径、执行环境检查、创建隔离 worktree、修改 `fm_agent/`
或调用 LLM 之前检查 denylist。这只是插件兼容性检查；现有全局 CLI 组合规则仍然
有效。该字段不会替代 Hook 契约，也不会强制插件使用 Profile。

## Specification Profile（可选）

插件可以在 `configure` 中同步注册一个 `SpecificationProfile`。阶段编排、LLM 调度、
重试和 trace 仍由公共 Pipeline 负责，Profile 提供两个产物和四个 prompt 资源。Profile
默认使用标准 JSON spec/info contract；只有非 JSON 格式（例如 Markdown）可自定义
`PromptContract`。示例如下：

```python
from src.specification import ArtifactPair, PromptBundle, SpecificationProfile, configure_specification


def configure(proj_dir: str) -> None:
    configure_specification(SpecificationProfile(
        id="markdown", schema_version="V1",
        artifacts=ArtifactPair(
            self_suffix="_spec.md", dependency_suffix="_info.md",
            append_to_filename=False,
        ),
        prompts=PromptBundle(
            phase_plan="prompts/workflow_generate_phases.md",
            domain_context="prompts/workflow_generate_domain_context.md",
            system="prompts/system_prompt.md",
            batch_workflow="prompts/workflow_spec_step4_batch.md",
        ),
        prompt_contract=MARKDOWN_PROMPT_CONTRACT,  # 由插件自行实现
        languages=("python",),
    ))
```

`prompts/*` 相对插件根目录解析。固定生成两个产物（上例中 `foo.py` 对应
`foo_spec.md` 与 `foo_info.md`）。自定义 Profile 默认关闭 `enable_reasoning`；公共校验
先要求两个文件存在且非空，再调用可选 `validator`。校验失败沿用 Stage 6 retry。`languages`
只能筛选已注册语言，不能新增 parser。Profile 与 Stage Hook 可混用且不额外做冲突检测；
自定义 Profile 不启用 software reasoning，也不提供正确性保障。

## 内置 chip 插件

内置 `chip` 插件在 `configure` 中选择一个硬件 Profile，随后使用公共 Stage 1–6
Pipeline。它的 manifest 额外声明 Stage 6 modify Hook，用于 Chisel 产物 eligibility， 并显式拒绝当前对 chip 尚未定义语义的选项。

```bash
uv run python main.py <proj_dir> --plugin chip
```

插件根据本次运行的 source scope 选择 Profile：

| 方言 | 扩展名 | Profile |
| --- | --- | --- |
| Chisel | `.scala`、`.sc` | `chip-chisel` |
| Verilog/SystemVerilog | `.v`、`.sv`、`.svh` | `chip-verilog` |

两类方言同时存在时优先选择 Chisel 并输出 warning；否则在范围内存在 Verilog 扩展名时
选择 Verilog。若仓库包含无关硬件代码，请使用更窄的 `proj_dir` 或 `--submodule`。

Chisel 默认使用源码分析，也可通过 `FM_AGENT_CHISEL_CIRCT_INPUT` 使用 CIRCT；Verilog
优先使用 `verible-verilog-syntax`，否则使用源码 fallback。工具配置见
[`tools/chisel-circt/README.md`](../tools/chisel-circt/README.md)。

每个提取出的 module 会在 `fm_agent/extracted_functions/` 下生成相邻的
`<Module>_spec.md` 和 `<Module>_info.md`。前者包含 FG/FC/CK 树和 `<FG-API>`，后者记录
直接 submodule 的要求。已知依赖 coverage 缺失时，Chisel 是 advisory，Verilog 会阻塞
通过。chip Profile 不启用 software reasoning 和 Bug Validation。

chip 对 `--resume`/`FM_AGENT_RESUME=1`、`--submodule`、`--one-phase`、
`--domain-knowledge`/`--knowledge`、`--extra-edge`、fresh `--isolate` 和
`--only-spec` 沿用公共选项契约；resume 与 software pipeline 使用同样的尽力而为语义。
其 manifest 显式拒绝 `--incremental`、`--end-func`、`--all-bugs`、
`--bug-validator` 和 `--estimate`，这些选项会在产生 workspace 或调用 LLM 之前失败。

## 执行模式

### Pass

```json
{"type": "pass"}
```

Pass 跳过内置 Stage，不调用插件函数。FM-Agent 不检查是否存在可复用产物；后续
Pipeline 按原方式读取标准文件，并自然成功或失败。

### Replace

```json
{
  "type": "replace",
  "replace_function": "replace_stage"
}
```

```python
def replace_stage(proj_dir: str) -> None:
    ...
```

Replace 跳过内置 Stage。插件通过 `proj_dir` 和 `proj_dir/fm_agent/` 下的文件完成
整个 Stage，不得通过返回值传递路径、列表、字典或其他 Stage 数据。FM-Agent
不验证插件产物。

### Modify

```json
{
  "type": "modify",
  "input_function": "before_stage",
  "output_function": "after_stage"
}
```

Modify 至少声明 `input_function` 或 `output_function` 之一，执行顺序为：

```text
input Hook
→ 内置 Stage
→ output Hook
```

Hook 通过标准项目文件修改输入或输出，不返回 Stage 数据。

## 配置上下文

启用插件时，FM-Agent 在 Stage 1 前写入
`proj_dir/fm_agent/plugin_context.json`：

```json
{
  "extra_edge": null, "submodules": ["src"]
}
```

`submodules` 仅在指定 `--submodule` 时写入，值为归一化后的项目相对路径。

configure Hook 可以直接读取：

```python
import json
import os


def configure(proj_dir: str) -> None:
    context_path = os.path.join(
        proj_dir, "fm_agent", "plugin_context.json"
    )
    with open(context_path, "r", encoding="utf-8") as file:
        context = json.load(file)
```

fresh、resume 和 isolate 的每次 Pipeline 调用都会重写上下文。configure Hook 在
Stage 1 前、每次 `run_pipeline()` 调用中执行一次。未声明 configure Hook 时仍会
写入上下文文件。

## Resume、isolate 与 incremental

执行到 Stage 边界时 Modify Hook 就会运行。即使内置 Stage 在 resume 中复用
ready 产物并跳过内部生成，边界 Hook 仍会执行，因此插件作者应保证 Hook 可重复。

isolate 模式下 Hook 收到隔离 worktree 路径；现有 isolate 流程会把 `fm_agent/`
结果复制回原项目。

Pipeline Hook 支持 full、resume 和 isolate。Incremental Pipeline 不接收插件
配置，也不执行插件 Hook。插件可以通过 `unsupported_options` 拒绝这些选项。

入口函数运行会自动启用内置 `entry_reasoning` 插件。`--entry-func` 不能与另一个
显式选择的 `--plugin` 组合使用。

## 内置 entry reasoning 插件

内置插件使用标准目录结构：

```text
plugins/
└── entry_reasoning/
    ├── plugin.json
    └── plugin.py
```

在 `run_pipeline()` 开始前，FM-Agent 将原项目复制到同级的
`<proj_dir>.fm-entry-run` 目录，并把该隔离路径作为 Pipeline 项目。原项目源码
不会被裁剪。

该插件配置两个 modify Hook：

```text
generate_phase_plan input Hook
→ 在临时 selection copy 中提取全部函数
→ 构建调用图
→ 选择从所有 entry_funcs 可达的函数并集
→ 根据 end_funcs 可选地限制调用路径
→ 从 entry run copy 删除不相关文件和函数
→ 在裁剪后的副本上运行内置 Stage 1–6
→ generate_specs_and_verification output Hook
→ 将 fm_agent/ 复制回原项目
→ 删除 entry run copy
```

entry 插件上下文包含：

```json
{
  "original_proj_dir": "/path/to/demo",
  "entry_run_dir": "/path/to/demo.fm-entry-run",
  "entry_funcs": ["src::main-c::main", "api::server-c::serve"],
  "end_funcs": [],
  "extra_edge": null,
  "all_bugs": false
}
```

`--entry-func` 可接受一个或多个以空格分隔的函数 FQN。未指定 `--end-func`
时，入口推理分析每个请求入口可达函数的并集；指定 end function 后，只保留任一
请求入口到任一 end function 的有效调用链，并将每个 end function 视为终点。所有
请求入口都会被校验，缺失 FQN 会一次性报告。所有入口源文件都会绕过 test-file
过滤；只有经过 end 裁剪后仍存在的入口源文件才会被强制写入 `phases.json`。

入口函数运行会生成规约和推理结果，但按设计跳过 Bug Validation。Stage 6 output
Hook 发布正常结果；若后续 Stage 失败，CLI 会复制已有的部分结果并删除 run copy。
如果 entry 选择本身失败，则保留原有 `fm_agent/`。只会复制回 `fm_agent/`，裁剪后
的源码会随 run copy 一起丢弃。

## 验证与信任边界

FM-Agent 检查：

- `plugin.json` 是合法 JSON，名称匹配且 version 非空；
- Stage 名称、模式和字段组合合法；
- `plugin.py` 存在且可以导入；
- 声明的对象存在、可调用并具有精确 Hook 签名；
- Hook 不抛出异常且实际返回值为 `None`。

FM-Agent 不检查：

- 插件读取、创建、修改或删除了哪些文件；
- 必需 Stage 产物是否存在；
- JSON、spec、info、verification 或其他产物 schema；
- 插件输出的逻辑正确性；
- 插件执行的外部命令。

插件是受信任代码，不是沙箱扩展。加载插件时会执行 `plugin.py` 顶层代码，包括
执行 `--list-plugin` 时。

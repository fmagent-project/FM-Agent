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
  "entry_func": null,
  "end_funcs": [],
  "extra_edge": null
}
```

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

Pipeline Hook 支持 full、resume 和 isolate。Entry 和 incremental Pipeline
不接收插件配置，也不执行插件 Hook。`--plugin` 不能与 `--entry-func` 组合使用。

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

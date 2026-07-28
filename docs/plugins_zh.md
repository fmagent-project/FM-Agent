# 插件开发

FM-Agent 插件可以在不修改 FM-Agent 源代码的情况下定制一个或多个流水线
Stage。插件可以保留已有 Stage 产物、完全替换 Stage 实现，或者修改内置
实现的输入、工作流说明和输出。

插件属于可信 Python 代码，只应安装和运行可信插件。

## 目录结构

在 `plugins/` 下为每个插件创建独立目录：

```text
plugins/
└── my_plugin/
    ├── plugin.json
    ├── plugin.py                  # 仅配置 Python 函数时需要
    └── extra_instructions.md      # 可选工作流说明
```

目录名必须与 `plugin.json` 中的 `name` 相同。`plugin.json` 始终必需；
只有配置中声明了 Python 函数时才需要 `plugin.py`。纯 `pass` 插件或仅修改
Markdown 的插件不需要 `plugin.py`。

列出成功加载并通过校验的插件：

```bash
uv run python main.py --list-plugin
```

在流水线中启用一个插件：

```bash
uv run python main.py /path/to/project --plugin my_plugin
```

## 多 Stage 配置

一个 `plugin.json` 可以同时配置任意数量的 Stage：

```json
{
  "name": "my_plugin",
  "version": "V1.0",
  "configure_function": "configure",
  "stages": {
    "generate_phase_plan": {
      "type": "modify",
      "input_function": "select_sources"
    },
    "collect_file_list": {
      "type": "modify",
      "input_function": "select_functions"
    },
    "generate_specs_and_verification": {
      "type": "modify",
      "modify_md": "extra_instructions.md"
    }
  }
}
```

函数名由插件开发者自定义。FM-Agent 会根据每个 Stage 的名称，分别校验其
模式、允许字段和准确的 Python 函数签名。

可选的插件级配置函数签名为：

```python
def configure(options: dict) -> None:
    ...
```

它在各 Stage 运行前执行一次，接收包括 `project_dir`、`entry_func`、
`end_funcs` 和 `extra_edge` 在内的运行上下文。它适合保存后续 Hook 需要的
本次运行配置，但不能代替 Stage Hook。

## 三种模式

### Pass

Pass 模式跳过内置 Stage，直接消费已有且合法的标准产物：

```json
{
  "type": "pass"
}
```

Pass 模式不能声明函数或 Markdown 字段。如果所需产物不存在或不合法，
流水线会失败。

### Replace

Replace 模式调用 Python 函数完全替代内置 Stage：

```json
{
  "type": "replace",
  "replace_function": "replace_stage"
}
```

函数在 FM-Agent 控制的临时目录中生成产物并返回路径。FM-Agent 校验结果
后才将其复制到标准运行目录。Replace 模式不能声明 Modify Hook 或
Markdown 字段。

### Modify

Modify 模式保留内置 Stage，并至少修改其输入、工作流说明或输出中的一项：

```json
{
  "type": "modify",
  "input_function": "modify_input",
  "output_function": "modify_output",
  "modify_md": "extra_instructions.md"
}
```

必须至少配置一个修改字段。`input_function` 修改 Stage 实际消费的语义输入，
不是工作流 Prompt Hook。`output_function` 仅在标准产物生成后运行，并且
必须让产物继续保持合法。

Stage 1、2、6 还支持以下二选一配置：

- `replace_md`：用插件目录中的 UTF-8 `.md` 文件替换内置工作流。
- `modify_md`：把插件目录中的 UTF-8 `.md` 文件追加到内置工作流后面。

`replace_md` 与 `modify_md` 互斥，路径不能逃出插件目录。

## 各 Stage 接口

六个标准 Stage 名称及其精确 Python 签名如下。

### Stage 1：`generate_phase_plan`

```python
def replace_phase_plan(project_dir: str, output_dir: str) -> str: ...
def modify_phase_input(source_files: list[str]) -> list[str]: ...
def modify_phase_output(phases_path: str) -> None: ...
```

Input Hook 选择或修改参与 Phase 规划的源码文件列表。Replace Hook 必须
返回生成的 `phases.json`。Output Hook 原地修改标准 `phases.json`。
此 Stage 支持 `replace_md` 和 `modify_md`。

### Stage 2：`generate_domain_context`

```python
def replace_domain_context(
    project_dir: str,
    phases_path: str,
    output_dir: str,
) -> list[str]: ...

def modify_domain_input(phases: dict) -> dict: ...
def modify_domain_output(domain_context_dir: str) -> None: ...
```

Input Hook 修改领域上下文生成所消费的 Phase 数据。Replace Hook 返回
`output_dir` 下生成的文件。Output Hook 原地修改标准领域上下文目录。
此 Stage 支持 `replace_md` 和 `modify_md`。

### Stage 3：`extract_functions`

```python
def replace_extraction(
    source_paths: list[str],
    output_dir: str,
) -> list[str]: ...

def modify_source(source_path: str) -> None: ...
def modify_extracted_function(function_path: str) -> None: ...
```

Input Hook 逐个接收隔离临时项目副本中的源码文件。它可以为本次提取修改、
增加或删除源码内容，不会改变用户的真实源码树。Output Hook 逐个接收本次
新写入的标准函数提取文件；Resume 中因 ready 状态跳过的文件不会再次处理。
每个最终文件仍必须只包含一个合法的提取函数。此 Stage 不支持工作流
Markdown Hook。

### Stage 4：`collect_file_list`

```python
def replace_file_list(
    extracted_dir: str,
    phases_path: str,
) -> list[str]: ...

def modify_function_files(function_files: list[str]) -> list[str]: ...
def modify_file_list_output(file_list_path: str) -> None: ...
```

Input Hook 修改写入 `fm_agent_file_list.json` 的函数文件列表。返回值不要求
是原列表的子集，但每个条目都必须解析为合法的函数提取文件。Output Hook
原地修改标准 JSON 文件。此 Stage 不支持工作流 Markdown Hook。

### Stage 5：`generate_topdown_layers`

```python
def replace_topdown_layers(
    work_dir: str,
    output_dir: str,
) -> list[str]: ...

def modify_topdown_input(function_files: list[str]) -> list[str]: ...
def modify_topdown_output(topdown_paths: list[str]) -> None: ...
```

其输入是 Stage 4 产生的权威函数列表。Replace Hook 返回生成的 Top-down
JSON 路径；Output Hook 原地修改其标准副本。Stage 5 不会重新扫描全部函数
提取文件，因此不会把 Stage 4 排除的函数重新加入。此 Stage 不支持工作流
Markdown Hook。

### Stage 6：`generate_specs_and_verification`

```python
def replace_specs_and_verification(
    work_dir: str,
    output_dir: str,
    only_spec: bool,
) -> list[str]: ...

def modify_spec_input(topdown_paths: list[str]) -> list[str]: ...
def modify_verification_output(result_paths: list[str]) -> None: ...
```

Input Hook 接收 Stage 6 实际消费的 Top-down JSON 隔离副本。Replace Hook
返回 `output_dir` 下生成的产物。

Output Hook 仅接收 Stage 6 之后仍可能被消费的结果：

- `logic_verification_results/**/*.json`
- `bug_validation/*.result.json`
- `bug_validation/summary.json`

内部使用的 `*.spec.json` 和 `*.info.json` 不会传给该 Hook。使用
`--only-spec` 时不执行 Output Hook。此 Stage 支持 `replace_md` 和
`modify_md`。

## 流水线数据流

```text
Stage 1 phases.json 与选中的源码文件
        ↓
Stage 2 领域上下文
        ↓
Stage 3 函数提取文件
        ↓
Stage 4 fm_agent_file_list.json
        ↓
Stage 5 Top-down 分层 JSON
        ↓
Stage 6 规约与验证结果
```

每个 Stage 都必须维持下游消费者要求的 Schema 和路径约定。特别是，Stage 4
是 Stage 5 和 Stage 6 的权威函数选择结果。

## Entry-reasoning 插件

内置的 `entry_reasoning` 插件可以把一次普通全量流水线限制在从指定入口函数
可达的调用路径：

```bash
uv run python main.py /path/to/project \
  --plugin entry_reasoning \
  --entry-func "main-py::application_entry"
```

也可以指定一个或多个终止函数：

```bash
uv run python main.py /path/to/project \
  --plugin entry_reasoning \
  --entry-func "main-py::application_entry" \
  --end-func "services::statistics-py::calculate_total"
```

该插件在 Stage 1 选择参与的源码文件，在 Stage 4 选择参与的函数提取文件。
Stage 3 仍使用 FM-Agent 内置提取器，Stage 5 和 Stage 6 消费 Stage 4 的
筛选结果。

`--end-func` 只保留入口到指定终点路径上的函数，并把终点视为终止节点，
因此不相关的兄弟依赖可能被排除。Entry 插件仅支持直接全量流水线，不能与
`--incremental`、`--isolate` 或 `--submodule` 组合。它可以与
`--resume`、`--only-spec`、`--one-phase`、领域知识、补充调用边和自定义
Bug Validator 组合。

## 校验与信任边界

以下情况会导致插件加载或执行失败：

- 缺少 `plugin.json`、JSON 格式错误或 `name` 与目录名不同；
- 使用未知 Stage、模式或字段；
- 缺少必需字段，或同时使用互斥字段；
- 声明的 Python 函数不存在、不可调用或带类型标注的签名不准确；
- Markdown 不可读、不是 UTF-8 `.md`，或路径逃出插件目录；
- 返回文件不存在、重复、超出允许目录，或不符合 Stage Schema。

FM-Agent 在发现插件时会导入 `plugin.py`，因此模块顶层代码会在导入时执行。
路径和 Schema 校验用于保护流水线契约并发现意外错误，不能沙箱化或限制任意
Python 代码。

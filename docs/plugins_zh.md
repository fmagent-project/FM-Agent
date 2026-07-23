# 插件开发

FM-Agent 插件可以在不修改 FM-Agent 源代码的情况下定制流水线阶段。当前
Python Hook 接口实现于 Stage 3，即 `extract_functions` 阶段。

## 插件目录结构

在 `plugins/` 下为每个插件创建一个独立目录：

```text
plugins/
└── my_plugin/
    ├── plugin.json
    └── plugin.py
```

目录名必须和 `plugin.json` 中的 `name` 字段相同，两个文件都必须存在。
下面的命令会列出成功加载并通过验证的插件：

```bash
uv run python main.py --list-plugin
```

运行流水线时通过插件名启用插件：

```bash
uv run python main.py /path/to/project --plugin my_plugin
```

函数名由插件开发者在 `plugin.json` 中自定义；函数的 Python 签名由
FM-Agent 规定并验证。

## Pass 模式

Pass 模式跳过 Stage 3 提取，直接使用已经存在的提取文件：

```json
{
  "name": "my_plugin",
  "version": "V1.0",
  "stages": {
    "extract_functions": {
      "type": "pass"
    }
  }
}
```

仍然必须提供 `plugin.py`，但不需要声明 Hook 函数：

```python
"""Pass-mode plugin."""
```

如果预期的提取文件不存在，Pass 模式会失败。入口函数选择会使用全新的临时
输出目录，因此 Pass 模式不能从空目录为该阶段提供提取结果。

## Replace 模式

Replace 模式使用 Python 函数替换 FM-Agent 内置的 Stage 3 提取器：

```json
{
  "name": "my_plugin",
  "version": "V1.0",
  "stages": {
    "extract_functions": {
      "type": "replace",
      "replace_function": "extract_with_custom_parser"
    }
  }
}
```

指定的函数必须使用下面这个带类型标注的精确签名：

```python
from pathlib import Path


def extract_with_custom_parser(
    source_paths: list[str],
    output_dir: str,
) -> list[str]:
    destination = Path(output_dir) / "src" / "example.md"
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(
        "# Function: src/example.py:example\n",
        encoding="utf-8",
    )
    return [str(destination)]
```

FM-Agent 会传入：

- `source_paths`：本次需要提取的、已经过过滤的源码文件路径。
- `output_dir`：用于生成文件、由 FM-Agent 控制的临时目录。

函数必须返回非空的 `list[str]`。每个返回路径必须：

- 对应一个实际存在的文件；
- 位于 `output_dir` 内；
- 在返回列表中只出现一次。

FM-Agent 会保留相对路径，把返回文件复制到标准的
`fm_agent/extracted_functions/` 目录。当标准输出已经被标记为 ready 且
本次没有强制重新提取时，该输出会被跳过。Replace 插件必须维持后续流水线
所需的输出布局、命名方式和函数全限定标识符。

## Modify 模式

Modify 模式保留 FM-Agent 内置提取器，同时可以修改输入文件、输出文件或
两者：

```json
{
  "name": "my_plugin",
  "version": "V1.0",
  "stages": {
    "extract_functions": {
      "type": "modify",
      "input_function": "prepare_source",
      "output_function": "normalize_extraction"
    }
  }
}
```

`input_function` 和 `output_function` 至少需要提供一个。每个指定函数都必须
使用下面这个带类型标注的精确签名：

```python
from pathlib import Path


def prepare_source(file_path: str) -> None:
    path = Path(file_path)
    text = path.read_text(encoding="utf-8")
    path.write_text(text.replace("OLD_API", "NEW_API"), encoding="utf-8")


def normalize_extraction(file_path: str) -> None:
    path = Path(file_path)
    text = path.read_text(encoding="utf-8")
    path.write_text(text.rstrip() + "\n", encoding="utf-8")
```

Input Hook 每次接收一个源码文件路径。该路径属于目标项目的安全临时副本，
而不是用户的真实项目。修改只影响本次提取，不会改变原始源码树。Hook 执行
后必须保留该文件。

Output Hook 每次接收一个标准提取 Markdown 文件路径。FM-Agent 将文件写入
`fm_agent/extracted_functions/` 后才会调用它。Hook 只处理本次新写入的
文件；因 ready 状态被跳过的输出不会再次处理。Hook 必须原地修改并保留文件。

两种 Hook 都必须返回 `None`。文件内容可以改变，但最终提取结果仍然必须
满足后续流水线所需的 schema 和标识符要求。

## 各种运行流程中的行为

Stage 3 插件配置会传递到以下运行路径：

| 运行路径 | 支持 Stage 3 插件 |
| --- | --- |
| 全量运行 | 是 |
| Resume 续跑 | 是 |
| Isolate 隔离 worktree 运行 | 是 |
| 入口函数选择 | 是 |
| 增量运行 | 是 |

入口函数流程可能在选择入口范围时提取一次，并在最终流水线中再次提取，因此
Hook 可能在两个阶段都执行。增量运行会在受影响文件重新提取时执行 Hook。

## 验证与信任边界

出现以下情况时，插件加载会失败：

- 缺少 `plugin.json` 或 `plugin.py`；
- `plugin.json` 格式错误，或者 `name` 与目录名不同；
- 模式缺少必要字段、包含冲突字段或使用已经废弃的命令式字段；
- 配置的函数不存在、不可调用或类型标注签名不正确。

扫描插件时会导入 `plugin.py`，其顶层代码会在导入时执行。插件属于可信
Python 代码，不在沙箱中运行。应避免在顶层执行带副作用的操作，并且只安装
或运行可信插件。

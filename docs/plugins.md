# Plugin Development

FM-Agent plugins can customize pipeline stages without changing FM-Agent's
source code. The current Python hook interface is implemented for Stage 3,
`extract_functions`.

## Plugin layout

Create one directory per plugin under `plugins/`:

```text
plugins/
└── my_plugin/
    ├── plugin.json
    └── plugin.py
```

The directory name and the `name` field in `plugin.json` must match. Both files
are required. To list plugins that load and validate successfully, run:

```bash
uv run python main.py --list-plugin
```

Enable one plugin for a pipeline run with:

```bash
uv run python main.py /path/to/project --plugin my_plugin
```

Function names are chosen by the plugin author in `plugin.json`. FM-Agent
defines and validates their Python signatures.

## Pass mode

Pass mode skips Stage 3 extraction and uses extraction files that already
exist:

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

`plugin.py` is still required, but no hook function is declared:

```python
"""Pass-mode plugin."""
```

Pass mode fails if the expected extracted files do not already exist. In
particular, entry-function selection uses a fresh temporary output directory,
so pass mode cannot supply that extraction from an empty directory.

## Replace mode

Replace mode substitutes a Python function for FM-Agent's built-in Stage 3
extractor:

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

The named function must have this exact annotated signature:

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

FM-Agent passes:

- `source_paths`: filtered source-file paths for the current extraction.
- `output_dir`: a controlled temporary directory for generated files.

The function must return a non-empty `list[str]`. Every returned path must:

- exist as a file;
- be located inside `output_dir`;
- occur only once in the returned list.

FM-Agent copies the returned files, preserving their relative paths, into the
canonical `fm_agent/extracted_functions/` directory. When a canonical output
is already marked ready and extraction is not forced, that output is skipped.
Replacement plugins must preserve the output layout, naming, and fully
qualified function identifiers expected by later pipeline stages.

## Modify mode

Modify mode keeps FM-Agent's built-in extractor and optionally changes its
input files, output files, or both:

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

At least one of `input_function` or `output_function` is required. Each named
function must have this exact annotated signature:

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

The input hook receives one source-file path at a time. The path belongs to a
safe temporary copy of the target project, not the user's real project.
Changes affect extraction for the current run without changing the original
source tree. The hook must leave the file in place.

The output hook receives one canonical extracted Markdown file at a time,
after FM-Agent writes it under `fm_agent/extracted_functions/`. It runs only
for newly written files; an output skipped because it is already ready is not
processed again. The hook must modify the file in place and leave it in place.

Both hooks must return `None`. The file content may change, but the resulting
extraction must still satisfy the schemas and identifiers expected by later
pipeline stages.

## Pipeline behavior

Stage 3 plugin configuration is propagated through these execution paths:

| Execution path | Stage 3 plugin support |
| --- | --- |
| Full run | Yes |
| Resume run | Yes |
| Isolated worktree run | Yes |
| Entry-function selection | Yes |
| Incremental run | Yes |

Entry-function workflows can extract once while selecting the entry scope and
again during the final pipeline run, so hooks can execute in both phases.
Incremental runs execute hooks when affected files are re-extracted.

## Validation and trust

Plugin loading fails when:

- `plugin.json` or `plugin.py` is missing;
- `plugin.json` is invalid or its `name` does not match the directory;
- a mode has missing, conflicting, or obsolete command-based fields;
- a declared function is missing, is not callable, or has the wrong annotated
  signature.

`plugin.py` is imported when plugins are scanned, and its top-level code runs
at import time. Plugins are trusted Python code and are not sandboxed. Keep
top-level code free of side effects and only install or run plugins you trust.

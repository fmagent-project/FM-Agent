# Plugin Development

FM-Agent plugins customize one or more pipeline stages without changing
FM-Agent's source code. A plugin may keep an existing stage output, replace the
stage implementation, or modify the input, workflow instructions, or output of
the built-in implementation.

Plugins are trusted Python code. Install and run only plugins you trust.

## Directory structure

Create one directory per plugin under `plugins/`:

```text
plugins/
└── my_plugin/
    ├── plugin.json
    ├── plugin.py                  # Required only when Python functions are used
    └── extra_instructions.md      # Optional workflow instructions
```

The directory name must match the `name` in `plugin.json`. `plugin.json` is
always required. `plugin.py` is required only when the configuration names a
Python function; a pure `pass` plugin or a Markdown-only plugin does not need
it.

List plugins that load and validate successfully:

```bash
uv run python main.py --list-plugin
```

Enable one plugin for a pipeline run:

```bash
uv run python main.py /path/to/project --plugin my_plugin
```

## Multi-stage configuration

One `plugin.json` can configure any number of pipeline stages:

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

Function names are chosen by the plugin author. FM-Agent validates each stage
independently according to its stage name, mode, allowed fields, and exact
Python signature.

The optional plugin-level configuration function has this signature:

```python
def configure(options: dict) -> None:
    ...
```

It runs once before the configured stages and receives runtime context,
including `project_dir`, `entry_func`, `end_funcs`, and `extra_edge`. Use it to
store run-specific configuration for later hooks; it does not replace a stage
hook.

## Modes

### Pass

Pass mode skips the built-in stage and consumes an existing valid canonical
output:

```json
{
  "type": "pass"
}
```

Pass mode accepts no function or Markdown fields. It fails when the required
output is missing or invalid.

### Replace

Replace mode calls a Python function instead of the built-in stage:

```json
{
  "type": "replace",
  "replace_function": "replace_stage"
}
```

The function writes into an FM-Agent-controlled temporary directory and
returns the generated path or paths. FM-Agent validates the result before
copying it to the canonical run directory. Replace mode accepts no modify
hooks or Markdown fields.

### Modify

Modify mode keeps the built-in stage and changes at least one of its inputs,
workflow instructions, or outputs:

```json
{
  "type": "modify",
  "input_function": "modify_input",
  "output_function": "modify_output",
  "modify_md": "extra_instructions.md"
}
```

At least one modification field is required. `input_function` changes the
semantic input consumed by the stage; it is not a workflow prompt hook.
`output_function` runs only after a canonical output has been produced and
must leave that output valid.

Stages 1, 2, and 6 also support one of:

- `replace_md`: replace the built-in workflow Markdown with a plugin-relative
  UTF-8 `.md` file.
- `modify_md`: append a plugin-relative UTF-8 `.md` file to the built-in
  workflow.

`replace_md` and `modify_md` are mutually exclusive. The path must remain
inside the plugin directory.

## Stage contracts

The six canonical stage names and their exact Python signatures are:

### Stage 1: `generate_phase_plan`

```python
def replace_phase_plan(project_dir: str, output_dir: str) -> str: ...
def modify_phase_input(source_files: list[str]) -> list[str]: ...
def modify_phase_output(phases_path: str) -> None: ...
```

The input hook selects or transforms the source-file list used for phase
planning. The replace hook must return the generated `phases.json`. The output
hook modifies canonical `phases.json` in place. This stage supports
`replace_md` and `modify_md`.

### Stage 2: `generate_domain_context`

```python
def replace_domain_context(
    project_dir: str,
    phases_path: str,
    output_dir: str,
) -> list[str]: ...

def modify_domain_input(phases: dict) -> dict: ...
def modify_domain_output(domain_context_dir: str) -> None: ...
```

The input hook changes the phase data consumed by domain-context generation.
The replace hook returns generated files under `output_dir`. The output hook
modifies the canonical domain-context directory in place. This stage supports
`replace_md` and `modify_md`.

### Stage 3: `extract_functions`

```python
def replace_extraction(
    source_paths: list[str],
    output_dir: str,
) -> list[str]: ...

def modify_source(source_path: str) -> None: ...
def modify_extracted_function(function_path: str) -> None: ...
```

The input hook receives each source file in an isolated temporary project
copy. It may modify, add, or remove source content for this extraction run
without changing the user's source tree. The output hook receives each newly
written canonical extracted-function file; ready files skipped during resume
are not processed again. Every resulting file must still contain exactly one
valid extracted function. This stage has no workflow-Markdown hook.

### Stage 4: `collect_file_list`

```python
def replace_file_list(
    extracted_dir: str,
    phases_path: str,
) -> list[str]: ...

def modify_function_files(function_files: list[str]) -> list[str]: ...
def modify_file_list_output(file_list_path: str) -> None: ...
```

The input hook changes the extracted-function files recorded in
`fm_agent_file_list.json`. Its return value is not required to be a subset of
the original list, but every item must resolve to a valid extracted-function
file. The output hook modifies the canonical JSON file in place. This stage
has no workflow-Markdown hook.

### Stage 5: `generate_topdown_layers`

```python
def replace_topdown_layers(
    work_dir: str,
    output_dir: str,
) -> list[str]: ...

def modify_topdown_input(function_files: list[str]) -> list[str]: ...
def modify_topdown_output(topdown_paths: list[str]) -> None: ...
```

The input is the authoritative Stage 4 function list. The replace hook returns
the generated top-down JSON paths; the output hook modifies their canonical
copies in place. Stage 5 does not rescan all extracted functions, so functions
excluded by Stage 4 are not silently reintroduced. This stage has no
workflow-Markdown hook.

### Stage 6: `generate_specs_and_verification`

```python
def replace_specs_and_verification(
    work_dir: str,
    output_dir: str,
    only_spec: bool,
) -> list[str]: ...

def modify_spec_input(topdown_paths: list[str]) -> list[str]: ...
def modify_verification_output(result_paths: list[str]) -> None: ...
```

The input hook receives isolated copies of the top-down JSON files consumed by
spec generation. The replace hook returns generated artifacts under
`output_dir`.

The output hook receives only results that can still be consumed after Stage
6:

- `logic_verification_results/**/*.json`
- `bug_validation/*.result.json`
- `bug_validation/summary.json`

Internal `*.spec.json` and `*.info.json` files are not passed to this hook.
The output hook is skipped for `--only-spec`. This stage supports `replace_md`
and `modify_md`.

## Pipeline data flow

```text
Stage 1 phases.json and selected source files
        ↓
Stage 2 domain context
        ↓
Stage 3 extracted function files
        ↓
Stage 4 fm_agent_file_list.json
        ↓
Stage 5 top-down layer JSON files
        ↓
Stage 6 specifications and verification results
```

Each stage must preserve the schema and path contract required by its
consumers. In particular, Stage 4 is the authoritative function selection for
Stage 5 and Stage 6.

## Entry-reasoning plugin

The bundled `entry_reasoning` plugin scopes a normal full pipeline run to the
call paths reachable from one entry function:

```bash
uv run python main.py /path/to/project \
  --plugin entry_reasoning \
  --entry-func "main-py::application_entry"
```

Optionally stop selection at one or more terminal functions:

```bash
uv run python main.py /path/to/project \
  --plugin entry_reasoning \
  --entry-func "main-py::application_entry" \
  --end-func "services::statistics-py::calculate_total"
```

The plugin uses Stage 1 to select participating source files and Stage 4 to
select participating extracted functions. Stage 3 remains FM-Agent's built-in
extractor, and Stages 5 and 6 consume the Stage 4 selection.

`--end-func` keeps functions on paths from the entry to the named terminal
functions and treats those endpoints as terminal, so unrelated sibling
dependencies may be excluded. The entry plugin is supported only for the
direct full pipeline and cannot be combined with `--incremental`, `--isolate`,
or `--submodule`. It can be combined with `--resume`, `--only-spec`,
`--one-phase`, domain knowledge, supplemental edges, and a custom bug
validator.

## Validation and trust boundary

Plugin loading fails when, for example:

- `plugin.json` is missing, malformed, or its `name` differs from the
  directory name;
- an unknown stage, mode, or field is used;
- required fields are missing or mutually exclusive fields are combined;
- a declared Python function is missing, not callable, or has the wrong
  annotated signature;
- a Markdown file is unreadable, is not UTF-8 `.md`, or escapes the plugin
  directory;
- returned files are missing, duplicated, outside an allowed directory, or
  fail the stage schema.

FM-Agent imports `plugin.py` during plugin discovery, so module-level code is
executed at import time. Path and schema validation protect pipeline contracts
and catch accidental mistakes; they do not sandbox or restrict arbitrary
Python code.

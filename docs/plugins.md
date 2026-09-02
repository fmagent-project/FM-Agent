# Pipeline Plugins

FM-Agent pipeline plugins are trusted Python modules that can pass, replace,
or modify any of the six pipeline stages. Plugins exchange data through the
project directory and the standard files under `proj_dir/fm_agent/`.

## Layout and activation

```text
plugins/
└── example_plugin/
    ├── plugin.json
    ├── plugin.py
    └── prompts/
        └── custom_workflow.md
```

The directory name must equal the `name` in `plugin.json`.

```bash
uv run python main.py --list-plugin
uv run python main.py <proj_dir> --plugin example_plugin
```

## Hook contract

Every declared function has exactly this signature:

```python
def hook(proj_dir: str) -> None:
    ...
```

The parameter must be named `proj_dir`, annotated as `str`, and accept a
positional argument. The return annotation and actual return value must both
be `None`. Extra parameters, keyword-only parameters, `*args`, and `**kwargs`
are not supported.

`proj_dir` is exactly the directory used by the current `run_pipeline()` call.
For an isolated run it is the isolated Git worktree, not the original project
directory. Hooks may read or modify the project and `proj_dir/fm_agent/`; the
framework does not replace this argument with another internal path.

## Supported stages

- `generate_phase_plan`
- `generate_domain_context`
- `extract_functions`
- `collect_file_list`
- `generate_topdown_layers`
- `generate_specs_and_verification`

## Configuration

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

`configure_function` is optional. A plugin may configure any subset of the
supported stages.

### Option compatibility (optional)

Plugins may explicitly reject command-line options they cannot honor:

```json
{
  "name": "example_plugin",
  "version": "V1.0",
  "unsupported_options": ["resume", "incremental"],
  "stages": {}
}
```

The field is a sparse denylist: an option not listed is treated as supported.
Names use the argparse destination (`one_phase`, `domain_knowledge`, and so
on). The currently registered option names are `resume`, `incremental`,
`isolate`, `one_phase`, `all_bugs`, `only_spec`, `estimate`,
`domain_knowledge`, `submodule`, `end_func`, `extra_edge`, and
`bug_validator`. `--knowledge` shares the `domain_knowledge` name, and
`FM_AGENT_RESUME=1` shares the `resume` name.

FM-Agent checks the denylist before resolving option paths, running the
environment check, creating an isolated worktree, mutating `fm_agent/`, or
making LLM calls. This is an additional plugin compatibility check; existing
global CLI combination rules still apply. The field does not replace the Hook
contract or make a Profile mandatory.

## Specification Profile (optional)

A plugin may register one `SpecificationProfile` synchronously from `configure`.
The common Pipeline keeps stage orchestration, LLM scheduling, retries, and
traces; the Profile supplies two artifacts and four prompt resources. Profiles
use the standard JSON spec/info contract by default; only non-JSON formats such
as Markdown may customize `PromptContract`. Example:

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
        prompt_contract=MARKDOWN_PROMPT_CONTRACT,  # implemented by this plugin
        languages=("python",),
    ))
```

Relative `prompts/*` paths resolve against the plugin root. Exactly two artifacts
are produced (`foo.py` maps to `foo_spec.md` and `foo_info.md` here). Custom
Profiles default to `enable_reasoning=False`; readiness first requires both
files to exist and be non-empty, then an optional `validator` may add checks.
Validator failures use the normal Stage 6 retry path. `languages` only filters
already registered languages and cannot add a parser. Profiles and Stage Hooks
may be mixed without extra conflict diagnostics; custom Profiles do not enable
software reasoning or provide correctness guarantees.

## Built-in chip plugin

The built-in `chip` plugin selects one hardware Profile during `configure` and
uses the common Stage 1–6 Pipeline. Its manifest adds a Stage 6 modify Hook for
Chisel artifact eligibility and explicitly rejects options whose current
semantics are not defined for chip.

```bash
uv run python main.py <proj_dir> --plugin chip
```

The Profile is selected from the source scope used by the run:

| Dialect | Extensions | Profile |
| --- | --- | --- |
| Chisel | `.scala`, `.sc` | `chip-chisel` |
| Verilog/SystemVerilog | `.v`, `.sv`, `.svh` | `chip-verilog` |

Chisel wins when both dialects are present, with a warning; otherwise Verilog
is selected when its extensions are in scope. Use a narrower `proj_dir` or
`--submodule` scope for a hardware subtree.

Chisel uses source analysis by default and optionally CIRCT via
`FM_AGENT_CHISEL_CIRCT_INPUT`; Verilog prefers `verible-verilog-syntax` and
otherwise uses its source fallback. See
[`tools/chisel-circt/README.md`](../tools/chisel-circt/README.md) for setup.

Each extracted module produces sibling `<Module>_spec.md` and
`<Module>_info.md` artifacts under `fm_agent/extracted_functions/`. The first
contains the FG/FC/CK tree and `<FG-API>`; the second contains direct-submodule
expectations. Missing known dependency coverage is advisory for Chisel and
blocking for Verilog. Chip Profiles disable software reasoning and bug
validation.

Chip follows the common option contract for `--resume`/`FM_AGENT_RESUME=1`,
`--submodule`, `--one-phase`, `--domain-knowledge`/`--knowledge`, `--extra-edge`,
fresh `--isolate` runs, and `--only-spec`; resume uses the same best-effort
semantics as the software pipeline. Its manifest explicitly rejects
`--incremental`, `--end-func`, `--all-bugs`, `--bug-validator`, and `--estimate`;
these options fail before any workspace or LLM side effect.

## Execution modes

### Pass

```json
{"type": "pass"}
```

Pass skips the built-in stage and calls no plugin function. FM-Agent does not
check that reusable output exists. Downstream code reads standard files and
succeeds or fails naturally.

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

Replace skips the built-in stage. The plugin performs the complete operation
through files under `proj_dir` and `proj_dir/fm_agent/`. It cannot return paths,
lists, dictionaries, or other stage data. FM-Agent does not validate its
artifacts.

### Modify

```json
{
  "type": "modify",
  "input_function": "before_stage",
  "output_function": "after_stage"
}
```

Modify requires at least one of `input_function` and `output_function`:

```text
input hook
→ built-in stage
→ output hook
```

Hooks modify inputs or outputs through standard project files and return no
stage data.

## Configuration context

When a plugin is active, FM-Agent writes
`proj_dir/fm_agent/plugin_context.json` before Stage 1:

```json
{
  "extra_edge": null, "submodules": ["src"]
}
```

`submodules` is written only for `--submodule` and contains normalized
project-relative paths.

A configure hook can read it directly:

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

The file is rewritten for every fresh, resume, or isolate pipeline call. The
configure hook runs once per `run_pipeline()` call before Stage 1. FM-Agent
still writes the context when no configure hook is declared.

## Resume, isolate, and incremental runs

Modify hooks run whenever execution reaches their stage boundary. They still
run when a built-in stage internally reuses ready output during resume, so
plugin authors should make hooks safe to repeat.

In isolate mode hooks receive the isolated worktree path. The existing isolate
workflow copies `fm_agent/` results back to the original project.

Pipeline hooks are supported for full, resume, and isolate runs. Incremental
pipelines do not receive plugin configuration or execute plugin hooks. A plugin
may reject any of those options with `unsupported_options`.

Entry-point runs automatically activate the bundled `entry_reasoning` plugin.
`--entry-func` cannot be combined with a separately selected `--plugin`.

## Bundled entry reasoning plugin

The bundled plugin uses the standard layout:

```text
plugins/
└── entry_reasoning/
    ├── plugin.json
    └── plugin.py
```

Before `run_pipeline()` starts, FM-Agent copies the original project to the
sibling `<proj_dir>.fm-entry-run` directory and passes that isolated path as the
pipeline project. The original source tree is never trimmed.

The plugin configures two modify hooks:

```text
generate_phase_plan input hook
→ extract all functions in a temporary selection copy
→ build the call graph
→ select the union reachable from entry_funcs
→ optionally restrict paths to end_funcs
→ delete unrelated files and functions from the entry run copy
→ run the built-in Stages 1–6 on the trimmed copy
→ generate_specs_and_verification output hook
→ copy fm_agent/ back to the original project
→ remove the entry run copy
```

The entry plugin context contains:

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

`--entry-func` accepts one or more space-separated function FQNs. Without
`--end-func`, entry reasoning analyzes the union reachable from every requested
entry. With end functions, it retains only functions on a valid requested
entry-to-end chain and treats each end function as terminal. Every requested
entry is validated; missing FQNs are reported together. All entry source files
are exempt from test-file filtering, while only entry source files that survive
end pruning are forced into `phases.json`.

Entry runs generate specifications and reasoning results but intentionally skip
bug validation. The Stage 6 output hook publishes successful results. If a
later stage fails, the CLI copies available partial results back and removes the
run copy. If entry selection itself fails, the previous `fm_agent/` directory is
left unchanged. Only `fm_agent/` is copied back; trimmed sources are discarded.

## Validation and trust boundary

FM-Agent checks that:

- `plugin.json` is valid JSON with a matching name and non-empty version;
- stage names, modes, and field combinations are supported;
- `plugin.py` exists and imports successfully;
- declared objects exist, are callable, and have the exact hook signature;
- hooks do not raise and their actual return values are `None`.

FM-Agent does not check:

- which files a plugin reads, creates, modifies, or deletes;
- whether required stage artifacts exist;
- JSON, spec, info, verification, or other artifact schemas;
- the logical correctness of plugin output;
- external commands executed by plugin code.

Plugins are trusted code, not sandboxed extensions. Top-level `plugin.py` code
runs when plugins are loaded, including during `--list-plugin`.

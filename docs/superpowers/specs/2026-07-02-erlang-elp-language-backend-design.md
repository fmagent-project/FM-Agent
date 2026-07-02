# Erlang ELP Language Backend Design

## Goal

Add Erlang support to FM-Agent's default full-project pipeline by implementing the existing language-registry interfaces with the Erlang Language Platform (ELP) as an optional Language Server Protocol (LSP) backend.

## Scope

The change will:

- discover Erlang functions and extract their complete source ranges;
- discover outgoing calls, including calls across Erlang modules;
- register Erlang in the existing language registry;
- make `.erl` files eligible for extraction, layering, reasoning, and verification;
- preserve the current behavior of all existing language backends;
- degrade to an empty Erlang result with a warning when ELP is unavailable or fails;
- add automated protocol and adapter tests without adding Python dependencies;
- document the optional ELP prerequisite and configuration.

The first implementation targets the default full-project pipeline. It will not redesign the existing incremental or entry-function pipelines, whose file-local fallback extraction path does not currently support semantic-only language backends.

## Existing Architecture

`src/languages/registry.py` defines a small adapter contract:

```python
batch_extract(proj_dir) -> {abs_filepath: [(func_name, body)]}
call_edges(proj_dir) -> {(caller_stem, caller_module): {callee_stems}}
```

`src/extract.py` consumes the first result to create one file per function under `fm_agent/extracted_functions/`. `src/generate_topdown_layers.py` consumes the second result to construct caller/callee edges and top-down reasoning layers. CodeGraph implements both operations for the currently registered languages.

ELP advertises both document symbols and call hierarchy over LSP, so the Erlang backend can satisfy the same contract without changing the registry API.

## Selected Approach

Create `src/languages/erlang.py` with a small standard-library JSON-RPC/LSP client and a project analyzer. A single analysis pass collects both functions and outgoing call edges. Its immutable result is cached by project path and a source/configuration fingerprint so the later `call_edges()` registry call can reuse the ELP index built by `batch_extract()`.

This is preferred over starting ELP independently for both registry calls because large Erlang projects may have substantial indexing cost. It is also preferred over using ELP's internal Rust APIs or a custom AST command because the issue explicitly targets language-server integration and LSP is ELP's stable public integration surface.

## LSP Lifecycle

For each uncached project analysis, the adapter will:

1. start `elp server` with the project directory as its working directory;
2. send `initialize` with the project root URI, workspace folder, UTF-16-compatible client capabilities, and static document-symbol registration;
3. send `initialized` after a successful initialize response;
4. handle routine server-to-client requests such as capability registration, workspace configuration, progress creation, and workspace folders;
5. wait for ELP's `elp/status` notification to report `Running`;
6. request `textDocument/documentSymbol` for each non-test `.erl` source file;
7. request `textDocument/prepareCallHierarchy` and `callHierarchy/outgoingCalls` for each discovered function;
8. send `shutdown`, then `exit`, and terminate the process if it does not stop promptly.

All reads have a configurable timeout. Protocol errors, process failures, an absent `elp` executable, or ELP project-loading failures produce a warning and an empty result rather than failing the whole FM-Agent run.

## Function Extraction

ELP returns top-level `DocumentSymbol` objects for Erlang functions. A function may contain child symbols for individual clauses; FM-Agent will use only the top-level function symbol so all clauses remain in one extracted function body.

The adapter will translate the symbol's UTF-16 LSP range into Python string offsets and preserve the exact source text. Symbol kind `Function` is accepted; records, macros, and types are ignored.

Erlang identifies functions by name and arity, and the same name/arity may exist in multiple modules. FM-Agent currently resolves call edges by extracted-file stem, so the adapter will use a filesystem-safe, module-qualified identity:

```text
<module>__<function>__<arity>
```

Atoms containing punctuation or quotes are escaped deterministically. This identity is used consistently for extracted filenames, caller keys, and callee stems. The original Erlang source and ELP symbol name remain unchanged inside the extracted body.

## Call-Graph Mapping

For each function symbol, its selection-range start is passed to `prepareCallHierarchy`. The returned item is then passed unchanged to `outgoingCalls`.

Each outgoing target is normalized using its URI and `name/arity` label. The target URI supplies the module identity, preventing calls such as `a:handle/1` and `b:handle/1` from being merged. Recursive edges may be returned by ELP; the existing top-down layer generator already resolves cycles with strongly connected components.

The registry's caller-module component remains the current dashed source filename (for example `server-erl`) because `generate_topdown_layers.py` already uses that value when looking up registry edges.

## Cache and Invalidation

The cached result is keyed by the absolute project path and a fingerprint of relevant Erlang project inputs:

- `.erl` and `.hrl` paths, sizes, and modification timestamps;
- `rebar.config`, `rebar.lock`, and `elp.toml` when present;
- the configured ELP command.

Any change creates a new analysis. Failed analyses are not cached, allowing a later invocation to recover after ELP becomes available or the project configuration is corrected.

## Repository Integration

Production changes are expected in:

- `src/languages/erlang.py`: LSP transport, ELP lifecycle, result normalization, extraction, call graph, and cache;
- `src/languages/registry.py`: import and register the Erlang handler;
- `src/extract.py`: add Erlang language metadata and the `.erl` extension;
- `src/verification.py`: map `.erl` verification inputs to `Erlang`;
- `src/reasoner.py` and `src/prompts.py`: add Erlang termination and language-expertise context where needed;
- `.env.example` and `docs/config_llm.md` or README documentation: describe optional ELP command and timeout settings;
- README language lists: include Erlang and the ELP prerequisite.

No new Python package will be added. ELP remains an external optional executable.

## Configuration

The adapter will support:

- `ELP_COMMAND`, default `elp`, allowing an absolute binary path or alternate launcher;
- `ELP_TIMEOUT_SECONDS`, a conservative default covering initialization, indexing, and individual requests.

Command parsing will use platform-appropriate argument splitting without invoking a shell.

## Testing

Tests will use Python's built-in `unittest` framework.

Unit tests will cover:

- JSON-RPC `Content-Length` framing and interleaved notifications/requests;
- initialization and the `elp/status = Running` readiness gate;
- extraction of a single function and a multi-clause function;
- UTF-16 range conversion;
- distinct arities and filesystem-safe identifiers;
- local, remote, recursive, and duplicate outgoing calls;
- cross-module name disambiguation;
- cache reuse and fingerprint invalidation;
- registry registration and `.erl` language mapping;
- missing executable, timeout, malformed response, and non-zero-exit degradation.

The test transport will replay representative LSP responses matching ELP's documented schemas. A separate optional integration test may run against a real `elp` executable when it is present; it will otherwise skip cleanly.

## Acceptance Criteria

Given a valid Erlang project and working ELP installation:

1. `batch_extract()` returns every ELP document-symbol function exactly once with all clauses included.
2. `call_edges()` returns stable, module-disambiguated outgoing edges compatible with `generate_topdown_layers.py`.
3. The normal FM-Agent pipeline recognizes `.erl`, creates extracted function files, generates layers, and reaches reasoning/verification.
4. Existing language behavior remains unchanged.
5. Without ELP, FM-Agent emits a warning, returns no Erlang semantic results, and continues processing other languages.
6. The new unit-test suite passes without additional dependencies.

## Known Boundary

This change does not claim full Erlang support in the entry-function and incremental-diff modes. Those paths bypass or partially bypass the registry for file-local extraction and require a separate design to make semantic-only backends available against temporary or historical source trees. The default full-project pipeline is the acceptance target for Issue #14.

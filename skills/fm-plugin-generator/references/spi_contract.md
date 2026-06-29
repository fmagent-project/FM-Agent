# SPI Contract Cheatsheet (for the plugin generator)

The authoritative source is `src/plugins/base.py`. This is the method-by-method
contract you must satisfy, in the ORDER the driver
(`src/plugins/driver.py::run_plugin`) calls them. Read both files before coding.

## Lifecycle (what the driver does, per function, bottom-up)

```
Stage 1  extraction          (core — you do nothing)
Stage 2  call graph + order  (core — you do nothing)
Stage 3  for each unit, bottom-up:
           build_abstraction_prompt(request) -> messages
           [core calls the LLM with retries]
           parse_abstraction_response(request, raw) -> FactEnvelope | None
             (None => core appends a format-correction turn and retries;
              on exhaustion core calls make_error_facts)
           compose_calls(caller_facts, resolved_calls, ctx) -> FactEnvelope
Stage 3.5 (only if metadata.requires_top_down_context) worklist:
           initial_context / propagate_context / merge_contexts
Stage 4  for each unit:
           check(facts, ctx, propagated_contexts) -> Verdict
           render_result(...) / render_summary(...)  (optional override)
```

## Required methods (abstractmethod — MUST implement)

### `metadata -> PluginMetadata`
Static capabilities. Fields:
- `name` (str, matches CLI + manifest), `version`, `schema_version` (e.g. `"<name>.v1"`)
- `supported_languages` (tuple of lang ids, e.g. `("python", ...)`)
- `verdicts` (tuple; MUST equal the union of your manifest verdict buckets + ERROR)
- `requires_top_down_context` (bool; True for obligation/ordering theories)
- `needs_entrypoint` (bool; True if the checker uses `ctx.is_entrypoint` as a trust boundary)

### `build_abstraction_prompt(request: AbstractionRequest) -> list[{"role","content"}]`
Return OpenAI-style messages for ONE function. Inputs on `request`:
- `request.function` (FunctionUnit): `.source`, `.signature_line`, `.id.language`
- `request.callee_context` (Mapping[FunctionId,str]): callee summaries to inject
The prompt MUST: ask ONLY for a structured abstraction wrapped in
`[<NAME>_JSON] ... [/<NAME>_JSON]`; FORBID the LLM from emitting a verdict;
instruct fail-closed "unknown" where the model cannot see provenance.

### `parse_abstraction_response(request, raw_response) -> FactEnvelope | None`
Extract the tagged JSON. Return a `FactEnvelope(plugin_name, schema_version,
function=request.function.id, status="ok", payload=<dict>)`. Return `None` to
trigger a retry (malformed/missing tag).

### `make_error_facts(request, error) -> FactEnvelope`
Fail-closed facts after retries are exhausted: `status="error"`, `payload=None`,
`diagnostics=[Diagnostic(level="error", message=error)]`. For security plugins
this MUST lead to ERROR/unsafe in `check`, never SAFE.

### `summarize_for_caller(facts) -> str`
Concise text summary of THIS function's facts, injected into a caller's prompt
(so the caller's LLM knows what this callee does). Guard for
`facts.status != "ok"`.

### `check(facts, context, propagated_contexts=()) -> Verdict`
The deterministic decision. First line should be the fail-closed guard:
```python
if facts.status == "error" or not facts.payload:
    return Verdict(plugin_name="<name>", verdict=ERROR, status="error",
                   data={"error": "no valid <name> abstraction (fail-closed)"})
```
Then call your reasoner's `classify(...)`, map its findings to `Finding(...)`,
and return `Verdict(plugin_name, verdict, status="ok", findings=[...], data={...})`.
`data["signature"]=facts.payload` so the viewer can render the abstraction.

## Optional methods (override only if your theory needs them)

### `compose_calls(caller_facts, resolved_calls, context) -> FactEnvelope`
Default no-op. Override for interprocedural composition:
- **bottom-up value** (taint/ifc/crypto): instantiate each callee's parametric
  facts at the caller's call site using the caller's actual-argument bindings.
  `resolved_calls[i].call_site` (arg_bindings) + `.callee_facts`.
- If your theory is purely top-down (authz), composition may stay a no-op and
  the work happens in the context worklist instead.

### `initial_context / propagate_context / merge_contexts`
Only used when `requires_top_down_context=True`. Used to flow an
obligation/entry-state from entrypoints down the call graph (authz: established
guards; typestate: possible entry states). `merge_contexts` must be
deterministic + monotonic (default dedups by repr()).

### `render_result / render_summary`
Default emits a generic, stable JSON shape (verdict, status, facts, findings,
data) — good enough for the viewer. Override only to emit a bespoke schema.

## The two non-negotiables

1. **LLM describes, checker decides.** The prompt asks for facts/evidence only.
   `classify()` is pure Python, deterministic, no LLM.
2. **Fail closed.** `validate(facts)` rejects out-of-enum values -> ERROR.
   Unknown provenance -> unsafe, never SAFE/SECURE.

## Reasoner module shape (`src/<name>_reasoner.py`)

```python
VERDICT_A = "VERDICT_A"; ...; ERROR = "ERROR"
_PRECEDENCE = [ERROR, <most severe>, ..., <cleared>]   # for picking the verdict
ENUM_X = {...}                                          # allowed values per field

def validate(facts) -> str | None:
    """Return an error string if malformed/out-of-enum, else None (fail-closed)."""

def classify(facts, **ctx) -> dict:
    """Return {"verdict": <tag>, "findings": [ {severity,kind,cwe,evidence,reason} ], "error": None}.
    Pure, deterministic. Verdict via _PRECEDENCE over accumulated findings."""
```

Use `taint` as the template for bottom-up data-flow, `authz` for
obligation/top-down, `typestate` for ordered events, `crypto` for per-op tables,
`ifc` for a confidentiality lattice.

## Behavioral Spec Generation Rules

You are writing behavioral specifications for functions and methods in a
codebase. Read these rules before generating metadata.

### Describe WHAT, not HOW

Describe what the function guarantees to callers, not how it achieves it.
Specify data and state invariants, input/output relationships, error contracts,
resource ownership, and output formats.

Do not name internal helper calls, describe loops or branch choices, enumerate
dispatch cases, list internal data layout decisions, or document performance
micro-optimizations.

### Be precise

Every claim must be verifiable and falsifiable. Do not use vague phrases such
as “correctly handles”, “as expected”, “processes”, “manages”, “properly”, or
“validates the input”. State the exact condition and guaranteed result.

### Be caller-driven

- Preconditions come from what callers guarantee before invoking the function.
- Postconditions come from what callers need after the function returns.
- Use caller context supplied in the batch prompt.
- Describe intended correct behavior even when the implementation has a bug.

The specification must support verification or an alternative conforming
implementation without reconstructing the current implementation. Prefer the
governing invariant over an enumeration of individual cases.

### Structured Metadata Format

The implementation file is immutable input. Never edit, replace, or add content
to it. For every function, write the two JSON files named in the batch prompt.
Write valid JSON only and do not wrap it in Markdown fences.

The spec JSON schema is:

```json
{
  "schema_version": 1,
  "function": "src::module-py::load_data",
  "unit": "src/module.py",
  "signature": "load_data(path) -> Result",
  "preconditions": ["path identifies a readable input"],
  "postconditions": ["returns the decoded value"]
}
```

The info JSON schema is:

```json
{
  "schema_version": 1,
  "function": "src::module-py::load_data",
  "callees": [
    {
      "function": "src::module-py::parse_header",
      "signature": "parse_header(data) -> Header",
      "preconditions": ["data contains a complete header"],
      "postconditions": ["returns the validated header"]
    }
  ]
}
```

All condition fields are arrays of strings. Use an empty array when there are
no conditions. The info file is always required; use `"callees": []` when the
function has no callees. Every `function` field uses the complete FQN supplied
by the batch prompt.

Adapt signature notation to the source language. Include receivers for methods
and all result values for languages with multiple returns.

### Quality Checks

- A precondition states only obligations the caller can satisfy.
- A postcondition describes results observable by the caller.
- Error and exceptional behavior has an exact triggering condition.
- No claim depends on a particular helper, branch, loop, or dispatch table.
- Every condition is a complete string in the appropriate JSON array.

For a cycle layer, ask what remains true after return regardless of the caller
and control-flow path. That cross-cutting invariant is the postcondition.

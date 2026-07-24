## Behavioral Spec Generation Rules

You are writing behavioral specifications for functions/methods in a codebase. The codebase may be written in any programming language. Read these rules carefully before writing any spec.

---

### Rule 1: Describe WHAT, not HOW

Describe what the function GUARANTEES to callers, not how it achieves it. Frame specs in terms of:

- Data structure invariants: sizes, element types, valid ranges, ordering
- State invariants: what must hold before and after the call
- Result contracts: return value properties, relationships between inputs and outputs
- Output format contracts: shape, encoding, schema of produced data
- Error contracts: what errors/exceptions are raised and under exactly what condition
- Resource contracts: ownership transfer, allocation/deallocation obligations

### Rule 2: Do NOT describe the implementation

Specifically do NOT:
- Name internal helper calls ("calls fmtShort, then returns")
- Describe conditional branch choices ("if long is true, calls fmtLong, else fmtShort")
- Enumerate specific constant values, configuration keys, or lookup entries
- Name performance micro-optimizations
- Enumerate dispatch cases by name — describe the governing dispatch rule instead

### Rule 3: No vague terms

Do NOT use: "appropriate", "correctly handles", "as expected", "processes", "manages", "properly", "validates the input", "handles the case".

Every claim must be verifiable and falsifiable. Replace vague terms with precise invariants:
- BAD: "correctly parses the input string"
- GOOD: "returns the number of milliseconds corresponding to the numeric and unit parts of str"

### Rule 4: Specs are CALLER-DRIVEN

- The pre-condition comes from what callers guarantee before calling
- The post-condition comes from what callers NEED from this function
- If caller context is provided in the prompt, use it

### Rule 5: Specs describe INTENDED CORRECT BEHAVIOR

- The implementation may have bugs. The spec does NOT document bugs.
- If the code fails to satisfy what callers need, the spec still describes what callers need — the gap IS the bug.
- Write the spec as if you are defining the contract an ideal correct implementation must satisfy.

### Rule 6: Specs must allow verification, not reconstruction

A correct spec must let you VERIFY the implementation against it, or write an alternative implementation satisfying the same contract. It must NOT let you reconstruct the exact implementation.

**Litmus test:** If deleting one branch or one helper call makes the spec wrong, the spec is too tightly coupled to the implementation. Rewrite as a cross-cutting invariant.

### Rule 7: Precision = governing rule, not enumeration

Do not name specific members of a set — not even as examples. Describe the governing rule.

- BAD: "Dispatches to fmtShort or fmtLong based on options.long"
- GOOD: "Returns a short-form string when options.long is absent or false; returns a long-form string when options.long is true"

---

### Spec Format

For each extracted function file (for example, `calculate_average.py`), write TWO
separate JSON files in the SAME directory. Do NOT modify the original function
source file.

**`<function-file>.spec.json`** — the function's own behavioral specification:

```json
{
  "signature": "<FunctionName>(<params>) -> <ReturnType>",
  "pre_condition": "<what must hold before the call>",
  "post_condition": "<what the function guarantees after return>"
}
```

**`<function-file>.info.json`** — the expected specs of the function's callees:

```json
{
  "callees": [
    {
      "name": "<callee_name>",
      "signature": "<callee_name>(<params>) -> <ReturnType>",
      "pre_condition": "<what the caller guarantees before calling>",
      "post_condition": "<what the caller expects after the call>"
    }
  ]
}
```

If a function has no callees relevant to the spec, write `{"callees": []}` to the `.info.json` file.

Adapt the signature notation to the conventions of the source language:
- For languages without explicit return types (e.g., Python, Ruby, JavaScript), omit `-> <ReturnType>` or use it informally to document the expected return.
- For methods on classes/structs, include the receiver (e.g., `self`, `this`, or the type name) as context.
- For languages with multiple return values (e.g., Go, Lua), list them all (e.g., `-> (ResultType, error)`).

---

### Examples

**BAD (implementation-describing):**
```
Post-condition:
  - Calls fmtShort() for short format and fmtLong() for long format.
  - Uses plural() helper to append 's' when appropriate.
```

**GOOD (behavioral):**
```
Post-condition:
  - Returns a string representation of ms in the largest unit whose magnitude does not exceed |ms|.
  - The returned string is a valid StringValue that parse() can recover to approximately ms.
  - When options.long is true, the unit name is written out in full (e.g., "2 days", "1 minute").
  - When options.long is absent or false, the unit is abbreviated (e.g., "2d", "1m").
```

**BAD (enumerating dispatch cases):**
```
Post-condition:
  - Dispatches to case 'years', 'months', 'weeks', 'days', ... based on matchUnit.
```

**GOOD (governing rule):**
```
Post-condition:
  - For each recognized unit alias, returns n * (the millisecond value of that unit),
    where n is the numeric part of str parsed as a float.
  - All aliases mapping to the same time magnitude return the same millisecond value.
```

---

### Quick Reference

**Write WHAT, not HOW.**

| ✅ Do | ❌ Do Not |
|------|----------|
| Describe data structure invariants: sizes, types, valid ranges, ordering | Name internal helper functions called |
| Describe result properties and output format contracts | Describe conditional or branch choices |
| Describe error contract: what errors are raised and under exactly what condition | Enumerate switch/match cases or dispatch entries by name |
| Use verifiable, falsifiable claims | Use vague terms: "correctly handles", "processes", "manages" |
| Describe the governing invariant across all code paths | Name specific set members "as examples" |

**Cycle layer guidance:** Ask "what is true after return regardless of which caller invoked it and which code path executed?" That is the post-condition.

**Litmus test:** If deleting one branch makes the spec wrong, the spec is implementation-coupled. Rewrite as an invariant that holds regardless of path.

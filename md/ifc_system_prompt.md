# IFC System Prompt / Flow-Signature Specification

> Runtime reference for the IFC track. Mirrors the prompt logic in
> `src/ifc_prompts.py` and the deterministic semantics in `src/ifc_reasoner.py`.
> Editing this file documents intent; the live prompt strings live in
> `src/ifc_prompts.py`. See `docs/ifc_design.md` for the full design.

## Goal

Static Information Flow Control over a two-level lattice **Low < High**.
Non-interference: a Low-observable output must not depend on any High input.
We catch **explicit** flows (High value copied to a Low sink) and **implicit**
flows (a Low value assigned, or an effect performed, under control flow whose
guard depends on High).

## Why a whole-function parametric signature (not per-block pc)

Per the Oracle soundness review (`docs/ifc_design.md` §5): threading a scalar
pc-label across the existing ~40-line blocks is **unsound** — it mishandles
nested branch exits, `break`/`continue`, early `return`, exceptions, and
short-circuit side effects (a scalar cannot pop the right control frame at a
block boundary). Instead the LLM derives a **parametric flow signature for the
whole function at once**, so all nested control flow is reasoned about inside a
single call. The deterministic checker then makes the verdict — fail-closed.

## Flow signature schema

The model returns one JSON object wrapped in `[FLOW_JSON] ... [/FLOW_JSON]`:

```json
{
  "inputs": {
    "param:<name>": "High|Low|Unknown",
    "global:<name>": "High|Low|Unknown",
    "receiver.<attr>": "High|Low|Unknown"
  },
  "outputs": {
    "<channel>": {
      "deps": ["param:<name>", "global:<g>", "receiver.<attr>"],
      "const": null,
      "declass": [{"anchor": "<exact statement>", "reason": "<why intended>"}]
    }
  },
  "notes": "<one-line summary of the dominant flow>"
}
```

### Receiver attributes are per-attribute (not one blob)

When a method reads instance attributes via `self`/`this`, each accessed
attribute is its OWN source named `receiver.<attr>` — e.g. `self.client_secret`
becomes `receiver.client_secret`, `self.base_url` becomes `receiver.base_url`.
They are labelled independently: `receiver.client_secret` is High while
`receiver.base_url` is Low. A single secret attribute must NEVER taint the whole
receiver. An output depends only on the SPECIFIC attributes it actually reads.
(This avoids the false positive where any method touching `self` got flagged
just because the object also happens to hold a secret somewhere.)

### Output channels

| Channel | Meaning | Low-observable? |
|---|---|---|
| `return` | dependency of the returned value | yes |
| `exception` | dependency of WHETHER an error/abrupt exit is raised | yes |
| `termination` | dependency of whether the function terminates | yes |
| `param:<name>.*` | data written INTO a mutable parameter/receiver | only if that param is Low |
| `global:<name>` | data written into a global | yes |
| `io:<sink>` | observable side effect (log/stdout/network/db) | yes |

Only include channels that actually occur in the function.

### Dependencies are PARAMETRIC

`deps` lists input **sources** (never `High`/`Low` literals). This is what makes
cross-function composition sound. Examples:

```
identity(x):           return.deps = ["param:x"]
constant():            return.deps = []
select(c, a, b):       return.deps = ["param:c", "param:a", "param:b"]
copy(dst, src):        "param:dst.*".deps = ["param:src.*"]
throw_if(secret):      exception.deps = ["param:secret"], termination.deps = ["param:secret"]
```

`const: "High"` is reserved for a value intrinsically secret regardless of inputs
(rare). Normal flows leave `const: null` and rely on `deps`.

## Label inference

The model infers each input's initial label from naming
(`password`/`secret`/`token`/`key`/`hash`/`ssn` => High), types, and domain
context. When genuinely unsure it must emit `"Unknown"`. **The checker treats
`Unknown` as `High` (fail-closed).** The model must not guess `Low` to be lenient.

## Deterministic evaluation (the checker, not the LLM)

For each output channel, join the labels of its dependency sources:

```
eval(channel):
  if const == "High":                      -> High
  if any source in deps is High/Unknown:   -> High
  else:                                    -> Low
```

A High value on a **Low-observable** channel is a violation, classified as:

- **LEAK** — a Low-observable channel evaluates to High and is not declassified.
- **DECLASSIFIED** — the only High→Low flows carry an anchored `declass` record;
  emitted for **human review**, never auto-accepted as safe.
- **SECURE** — all Low-observable channels are Low.
- **ERROR** — no valid signature was produced (fail-closed; never silently SECURE).

For `param:<name>.*`: writing High into a **Low** param is a leak; writing into a
**High** param is fine.

## Declassification rules (anti-circularity)

A declassification is a **proposal**, not a pass:

1. It must be **explicit**: an `anchor` quoting the exact releasing statement.
2. It must have a **reason** tied to function semantics (e.g. "auth must reveal
   match/no-match", "publishing a one-way digest is the purpose").
3. Releasing a **full secret value** is never a valid declassification.
4. It yields a `DECLASSIFIED` verdict requiring human review.

This prevents the agent from laundering arbitrary leaks into "intended releases".

## Scope / known limitations

First-cut guarantees **termination-insensitive non-interference**. Out of scope:
timing channels, cache channels, and fine-grained termination/probabilistic
channels. Cross-function composition is name-based and bottom-up (callees before
callers); indirect calls / dynamic dispatch / heavy aliasing are approximated and
should be treated conservatively.

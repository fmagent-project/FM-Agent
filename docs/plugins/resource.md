# Resource Exhaustion Plugin

The resource plugin treats denial of service as an attacker-controlled magnitude
reaching work whose cost grows with that magnitude. The LLM proposes a per-function
resource signature, `src/resource_validation.py` grounds and enriches that signature
from source, and `src/resource_reasoner.py` deterministically decides the verdict.

The public fact schema is `resource.v1`. The current internal source-validation
marker is `RESOURCE_VALIDATION_VERSION = 19`; it is an implementation cache/version
guard, not a replacement for the schema version.

## Cost Model

Magnitude kinds include request or input length, element count, recursion depth,
decompressed size, numeric parameters, request frequency, and logical size. A
concrete in-function magnitude is treated as attacker-controlled. A parameter can
remain `POLYMORPHIC` until call composition supplies an actual magnitude.

Costly operation kinds are:

- `allocation`, `collection_build`, and `unbounded_read` for host memory and I/O;
- `decompression`, `regex_match`, `recursion`, and `loop` for their narrower DoS
  patterns;
- `expensive_call` for input-sized parsing, hashing, encoding, database, token,
  message-delivery, or external work;
- `regex_compile` for compilation of attacker-controlled regex, glob, or pattern
  rules, including compilation repeated by an enclosing caller loop;
- `logical_allocation` for source-controlled logical array, storage, slot, or offset
  growth and precision-losing extent arithmetic, even without an immediate host
  allocation.

The checker reports `VULNERABLE`, `BOUNDED`, `POLYMORPHIC`, `SAFE`, or `ERROR`.
Verdict precedence is `ERROR > VULNERABLE > POLYMORPHIC > BOUNDED > SAFE`. Bounds
are typed: for example, an input length cap does not discharge recursion depth, and
a count limit does not discharge logical storage arithmetic.

## Source Validation

Version 19 removes unsupported model facts before classification and derives a
small set of facts directly from Python source. The advanced grounding described
below is Python-AST-specific; plugin metadata also accepts other languages, but that
does not imply equivalent deterministic source validation for them.

The parser removes all model-supplied private top-level fields before validation.
Validated facts carry both the version marker and a digest of the extracted function;
facts whose source digest changes are revalidated before classification. These fields
are cache integrity guards, not cryptographic attestations for untrusted cache files.

### Operation and Flow Grounding

- A reported `call_expr` must occur in source. Python calls may match structurally,
  so formatting differences such as a multiline call do not invalidate a fact.
- Magnitude expressions must be present in the AST or have a source assignment that
  proves the stated provenance. Explicit `len(...)` magnitudes are normalized;
  invented aliases and unsupported prose are dropped.
- A flow is retained when the operation argument is the grounded source expression,
  a supported simple alias, or shares a source identifier under the validator's
  conservative identifier-overlap fallback. This is not full expression equality.
  Literal call arguments have no attacker magnitude.
- Non-amplifying scalar conversions and unsupported lookup-like calls are not
  retained as `expensive_call` operations.
- A raw model `unknown:*` flow cannot by itself prove that an opaque
  `expensive_call` scales with attacker magnitude. Such calls need a grounded
  `mag:` or `param:` flow; unknowns created later by call composition remain
  fail-closed.
- Rust scalar `from_str` parsing and precompiled `.is_match(...)` calls are removed
  even when the model mislabels them as `expensive_call`; dynamic pattern compilation
  remains `regex_compile`.
- Repeated calls to the same callee are matched by occurrence, so each composition
  uses its own call-site arguments and enclosing loop magnitudes.

These checks are syntactic and provenance-based. They do not assign safety based on
whether an identifier happens to contain words such as `size`, `word`, `extent`, or
`rounded`.

### Recipient-Sized Delivery Work

Source validation can recover omitted `expensive_call` facts for message delivery,
but it binds cost to the recipient argument rather than to every argument of an
email-named call.

- Delivery callees are recognized from semantic tokens such as `send`, `deliver`,
  `dispatch`, or `notify`, or email/mail tokens that are not validation, parsing,
  matching, normalization, or similar helpers.
- The selected argument must itself be recipient-like, using tokens such as
  `address`, `destination`, `email`, `mailbox`, `recipient`, `recipients`, or `to`.
- The argument must match an `input_length` source exactly or through a simple alias.
  A model claim on a non-recipient argument is removed.
- An omitted source can be derived when a request-like parameter is passed to a
  decode/extract/get/parse/read call, the extractor declares the selected field,
  and that field reaches the recipient argument. Static settings and undeclared
  fields are not assumed attacker-controlled.

A rejecting pre-delivery length guard can become a source-derived
`input_length_cap`. Warning-only and post-delivery checks remain unbounded.

### Regex Compilation

Compile syntax, including `compile(...)` and glob/pattern-to-regex helpers, is
normalized to `regex_compile`. A model-reported `regex_compile` with no compile
expression in source is removed. Conversely, validation can derive an omitted
compile operation when its first argument is tied to a parameter or grounded
magnitude; constants do not create attacker work.

For a direct pattern parameter, validation also derives its `input_length` magnitude
when the model omits that source. This keeps the compile operation and its parameter
status stable across equivalent model payloads.

An enclosing caller loop contributes its collection count to the composed compile
operation. A function proven cached by its decorator is not replayed as per-request
compile work at callers. A stable lookup or match against already compiled patterns
is therefore not documented as either compilation or a bound.

### Exact Extents and Rounding

The logical-allocation rules distinguish precision-losing floating arithmetic from
source-proven integral extent arithmetic:

- `math.ceil(value / width)` uses true division and is treated as a
  precision-losing logical extent when linked to the operation.
- The exact integer round-up forms `(value + width - 1) // width` and that quotient
  optionally multiplied by the same positive integer `width` are recognized.
  Equivalent `value + width - 1` syntax is accepted.
- A local helper is accepted as exact only when every return has the recognized
  integer formula and the rounded base depends on a helper parameter. A helper name,
  imported helper, true-division lookalike, or off-by-one formula is not proof.
- For `allocate*`/`reserve*` calls, source assignments are followed to the reported
  argument. Integer constants, integral operators, and direct source values can be
  proven integral; source-proven string labels are excluded from extent arguments.
- `_resource_exact_extents` is true only when every allocation-like call has
  source-proven integral extent arguments. This can suppress a model operation and
  prevent an allocation callee from being replayed during composition. Unrelated
  floating-point arithmetic does not poison an otherwise exact operation.

This is a narrow syntax proof, not a general type, overflow, or range proof. A
checked addition that rejects before logical allocation is separately derived as an
`arithmetic_limit`; unchecked addition remains relevant.

## Hard Bounds

For current-format facts, a bound is expected to describe all of the following:

- `confidence="high"` and `dominates=true`;
- a known `bound_kind` that is allowed to cap the operation magnitude;
- `caps` containing that exact magnitude kind;
- `placement="before"`;
- `enforcement` in `reject`, `cap`, or `truncate`;
- `limit_origin` in `constant`, `trusted_config`, `trusted_system`, or
  `type_limit`;
- `protects_op_ids` containing the exact costly-operation id;
- a reference from the operation's matching magnitude flow to the bound id.

The validator always requires high confidence, dominance, a compatible bound kind,
and an explicit matching `caps` entry. For legacy facts, `placement`, `enforcement`,
`limit_origin`, and `protects_op_ids` may be absent; if present, each is checked
fail-closed. Unknown bound kinds are discarded, and unknown bound references cannot
turn an unbounded finding into `SAFE`.

Warnings and logs are not enforcement. A check after costly work is post-hoc. An
attacker-selected or unknown threshold is nominal, not a hard bound. A type predicate
without a length check does not bound regex compilation.

## Composition Boundary

Composition is bottom-up. Parametric callee magnitudes are instantiated with the
matching caller argument; missing non-literal bindings fail closed, while literal
arguments contribute no attacker magnitude. Callee bound ids and protected operation
ids are re-anchored at the call site.

A caller-side rejecting validator can propagate a bound only when source proves that
the validator's successful return establishes the parameter length predicate, the
caller rejects validation failure, the later operation consumes the same actual
argument, and that operation occurs after the guard. This is a deliberately narrow
contract, not general interprocedural theorem proving.

## Representative Characterizations

- Request-derived email or client-secret length reaching delivery/token work is
  `input_length -> expensive_call`; only a hard pre-operation length limit bounds it.
- An attacker-controlled ACL collection driving repeated glob/regex compilation is
  `element_count -> regex_compile`; caching removes repeated compilation rather than
  inventing a count bound.
- Source-controlled storage extents using precision-losing rounding or unchecked slot
  growth are `logical_size -> logical_allocation`; exact integer round-up and checked
  addition are handled by their distinct source proofs.

This document intentionally makes no historical run-count, model-provenance, or
external evidence claim. Current behavior is characterized by the checked-in source
and `tests/test_resource_validation_guards.py`.

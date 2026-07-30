# WP Reasoning Demo Examples

This directory contains example C source files demonstrating the complementary
bug detection capabilities of SP (Strongest Postcondition, forward) and WP
(Weakest Precondition, backward) reasoning.

## Files

| File | Bug Type | SP Detects | WP Detects |
|------|----------|:----------:|:----------:|
| `precondition_too_weak.c` | Pre-condition too weak (missing upper bound check) | No | **Yes** |
| `missing_branch.c` | Missing branch (unhandled zero case) | No | **Yes** |
| `callee_requirement_unmet.c` | Caller doesn't guarantee callee's pre-condition | No | **Yes** |
| `both_detect.c` | Computation error (add instead of multiply) | **Yes** | **Yes** |
| `clean.c` | No bug (correct binary search) | Pass | Pass |

## Running

### SP mode (default, top-down):
```bash
python main.py examples/wp_demo --reasoning-direction topdown
```

### WP mode (bottom-up):
```bash
python main.py examples/wp_demo --reasoning-direction bottomup
```

### Expected results

- **SP mode**: Detects the bug in `both_detect.c`, but misses the bugs in
  `precondition_too_weak.c`, `missing_branch.c`, and `callee_requirement_unmet.c`.
  Passes `clean.c`.

- **WP mode**: Detects bugs in all four buggy files. Passes `clean.c`.

## Bug Analysis

### 1. Pre-condition too weak (`precondition_too_weak.c`)

The spec says "index is non-negative" but the code accesses `array[index]`
without checking `index < array_length`.

- **SP misses**: Forward derivation from the weak pre-condition produces an
  equally weak post-condition — no contradiction.
- **WP catches**: Backward derivation from "no out-of-bounds access" requires
  `index < array_length`. The spec only guarantees `index >= 0`, which does
  not entail this — MISMATCH.

### 2. Missing branch (`missing_branch.c`)

The function handles positive and negative but forgets the zero case,
returning an uninitialized value.

- **SP misses**: Forward derivation for the zero case produces "result is
  unspecified" — no contradiction with a spec that doesn't explicitly mention zero.
- **WP catches**: Backward derivation from "result correctly classifies input"
  requires all cases handled. Missing zero case means WP includes `input != 0`,
  but spec allows `input == 0` — MISMATCH.

### 3. Callee requirement unmet (`callee_requirement_unmet.c`)

The caller calls `divide()` without checking `divisor != 0`.

- **SP misses**: In top-down mode, the caller is analyzed before the callee.
  The callee's precise pre-condition isn't available during caller analysis.
- **WP catches**: In bottom-up mode, `divide()` is analyzed first. Its WP
  (`divisor != 0`) is cached and propagated to the caller. The caller's WP
  includes this constraint, but the spec only says "divisor is an integer" —
  MISMATCH.

### 4. Both detect (`both_detect.c`)

A clear computation error (addition instead of multiplication). Both methods
catch this because the post-condition is directly violated.

### 5. Clean (`clean.c`)

A correct binary search implementation. Both methods should pass it without
false positives.

---
name: fm-plugin-typestate
description: >-
  Detect temporal / ordering security defects (a security-critical event
  missing or out of order: missing CSRF protection, disabled/absent certificate
  validation, TOCTOU race, unreleased resource) in a Python codebase using
  FM-Agent's typestate plugin. Use when asked to find missing CSRF tokens,
  verify=False / disabled TLS cert checks, check-then-use races, leaked
  file/socket/lock handles, CWE-295/352/367/772, or "is this security event in
  the right order". LLM abstraction + deterministic automaton checker; not a
  grep rule.
---

# FM-Agent typestate plugin (temporal / ordered-event)

Detects **ordering defects**: a security-critical event that is missing or out
of order. Reasons over ordered event traces with a deterministic automaton, not
over token patterns — so it catches "the check exists but doesn't dominate the
use" and "the resource is opened but never released on some path".

**Target CWEs:** CWE-295 (improper certificate validation), CWE-352 (CSRF),
CWE-367 (TOCTOU race condition), CWE-772 (missing release of resource).

## When to use

- "Is CSRF protection present on this state-changing endpoint?"
- "Is TLS cert validation disabled (`verify=False`, `CERT_NONE`) or absent?"
- "Is there a check-then-use (TOCTOU) race?"
- "Is this file/socket/lock always released on every path?"

## How to invoke

```bash
.venv/bin/python run_plugin.py typestate <proj_dir>
```

Output under `<proj_dir>/fm_agent_typestate/`: `results/**/<func>.json` + `summary.json`.
View: `.venv/bin/python ifc_viewer.py --port 8765` → load `<proj_dir>`, pick "typestate".

## Verdicts (per function)

| verdict | meaning |
|---|---|
| `VULNERABLE` | an ordering violation (missing CSRF, disabled/absent cert check, TOCTOU, unreleased resource) |
| `POLYMORPHIC` | parametric — verdict resolves at a caller |
| `NEEDS_REVIEW` | ordering depends on unknowable framework/middleware policy (fail-closed soft flag) |
| `SAFE` | required events present and correctly ordered |
| `ERROR` | no valid abstraction (fail-closed) |

## How it works (one paragraph)

The LLM produces a per-function **ordered event trace** (the security-relevant
events — checks, uses, opens, closes, validations — and their order/dominance).
The deterministic checker (`src/typestate_reasoner.py`) runs a temporal
automaton over that trace: a required event missing, or a use not dominated by
its guarding check, or an open with no matching release on a path, is a
violation. Composition is order-sensitive across the call list, and a top-down
pass propagates possible entry states. The LLM only describes; the checker
decides.

## Reference

Full theory + examples + SPI integration: [docs/plugins/typestate.md](../../docs/plugins/typestate.md).
Source: `src/plugins/typestate.py`, `src/typestate_prompts.py`, `src/typestate_reasoner.py`.
Registry manifest: `src/plugins/registry.py` (`typestate`).

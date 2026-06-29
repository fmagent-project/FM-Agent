---
name: fm-plugin-ifc
description: >-
  Detect sensitive-information exposure (a secret or sensitive value flowing to
  a public / lower-trust output such as a response, log, or error message) in a
  Python codebase using FM-Agent's ifc plugin (confidentiality lattice). Use
  when asked to find secrets/PII leaking into responses/logs/tracebacks,
  CWE-200/209/532, or "does this secret reach a public output". LLM abstraction
  + deterministic lattice checker; not a grep rule.
---

# FM-Agent ifc plugin (information-flow confidentiality)

Detects **sensitive-information exposure**: a High (secret/sensitive) value
flowing to a Low (public/lower-trust) output — a response body, a log line, an
error message/traceback. Reasons over a High/Low confidentiality lattice with
declassification, not over token patterns.

**Target CWEs:** CWE-200 (exposure of sensitive information), CWE-209
(information exposure through an error message), CWE-532 (sensitive information
in a log).

## When to use

- "Does a secret/password/token/PII reach a response, log, or error message?"
- Reviewing error handlers that dump `exc_info`/tracebacks to the client.
- Logging or responses built from values derived from secrets or credentials.

## How to invoke

```bash
.venv/bin/python run_plugin.py ifc <proj_dir>
```

Output under `<proj_dir>/fm_agent_ifc/`: `results/**/<func>.json` + `summary.json`.
View: `.venv/bin/python ifc_viewer.py --port 8765` → load `<proj_dir>`, pick "ifc".

## Verdicts (per function)

| verdict | meaning |
|---|---|
| `LEAK` | a High (secret) value flows to a Low (public) output |
| `DECLASSIFIED` | an intentional release (e.g. password-check → 1 bit, hash digest) — needs human review |
| `POLYMORPHIC` | parametric — label resolves at a caller |
| `SECURE` | no High→Low flow |
| `ERROR` | no valid abstraction (fail-closed; never SECURE) |

## How it works (one paragraph)

The LLM produces a per-function **flow signature** (which inputs/returns carry
High vs Low labels, and the dependency edges among them). The deterministic
checker (`src/ifc_reasoner.py`) joins lattice labels and flags a Low output that
depends on a High value as a LEAK, with declassification recognized separately.
Composition is bottom-up: a callee's parametric flow signature is instantiated
at the call site with the caller's actual argument labels, so High taint
surfacing in a caller's public output is a LEAK. The LLM only describes; the
checker decides.

## Reference

Full theory + examples + SPI integration: [docs/plugins/ifc.md](../../docs/plugins/ifc.md).
Source: `src/plugins/ifc.py`, `src/ifc_prompts.py`, `src/ifc_reasoner.py`.
Registry manifest: `src/plugins/registry.py` (`ifc`).

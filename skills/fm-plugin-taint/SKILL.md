---
name: fm-plugin-taint
description: >-
  Detect injection / tainted-data-flow vulnerabilities (SQLi, command
  injection, path traversal, XSS, SSRF, unsafe deserialization, open redirect,
  XXE, LDAP/XPath/code injection) in a Python codebase using FM-Agent's taint
  plugin. Use when asked to find untrusted input reaching a sensitive sink
  without sanitization, CWE-22/78/79/89/90/94/502/601/611/643/918, or "does
  user input flow into this query/command/path". LLM abstraction + deterministic
  checker; not a grep rule.
---

# FM-Agent taint plugin (integrity taint / injection)

Detects **injection**: untrusted input reaching a sensitive sink without
adequate, context-correct sanitization. Reasons about source→sink reachability
and typed sanitizers, and composes interprocedurally (a callee's parametric sink
is instantiated at the caller with the caller's actual-argument taint).

**Target CWEs:** CWE-22 (path traversal), CWE-78/88 (command/argument
injection), CWE-79 (XSS), CWE-89 (SQL injection), CWE-90 (LDAP), CWE-94 (code
injection), CWE-502 (unsafe deserialization), CWE-601 (open redirect), CWE-611
(XXE), CWE-643 (XPath), CWE-918 (SSRF).

## When to use

- "Does this user input flow into a SQL query / shell command / file path / URL?"
- Reviewing request handlers that build queries/commands/paths from params.
- A value from `request`, argv, env, a socket, or a DB read reaches `execute`,
  `subprocess`, `open`, `eval`, a redirect, a template, etc.

## How to invoke

```bash
.venv/bin/python run_plugin.py taint <proj_dir>
```

Output under `<proj_dir>/fm_agent_taint/`: `results/**/<func>.json` + `summary.json`.
View: `.venv/bin/python ifc_viewer.py --port 8765` → load `<proj_dir>`, pick "taint".

## Verdicts (per function)

| verdict | meaning |
|---|---|
| `VULNERABLE` | tainted source reaches a sink with no endorsing sanitizer on the path |
| `POLYMORPHIC` | parametric — verdict resolves at a caller (input arrives as a parameter) |
| `SANITIZED` | flow exists but a context-correct sanitizer endorses it |
| `SAFE` | no source→sink flow |
| `ERROR` | no valid abstraction (fail-closed) |

## How it works (one paragraph)

The LLM produces a per-function **taint signature** (typed sources, typed sinks
with the arg-context they consume, typed sanitizers with what they endorse,
and flows). The deterministic checker (`src/taint_reasoner.py`) decides
source→sink reachability against the typed-sanitizer table with a 3-status
lattice and verdict precedence. Composition is **bottom-up**: a callee sink over
`param:x` is instantiated at the call site with the caller's actual argument
taint, so a tainted argument makes the caller VULNERABLE. The LLM only
describes; the checker decides.

## Reference

Full theory + examples + SPI integration: [docs/plugins/taint.md](../../docs/plugins/taint.md).
Source: `src/plugins/taint.py`, `src/taint_prompts.py`, `src/taint_reasoner.py`.
Registry manifest: `src/plugins/registry.py` (`taint`).

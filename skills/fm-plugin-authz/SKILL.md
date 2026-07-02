---
name: fm-plugin-authz
description: >-
  Detect broken access control / missing authorization (IDOR/BOLA, missing or
  incorrect authz) in a Python codebase using FM-Agent's authz plugin
  (guarded-Hoare theory). Use when asked to find missing ownership checks,
  authorization bypass via user-controlled keys, endpoints that authenticate
  but don't authorize, CWE-306/639/862/863, or "can user A access user B's
  object". Runs LLM abstraction + a deterministic checker; not a grep rule.
---

# FM-Agent authz plugin (access control / guarded-Hoare)

Detects **missing/incorrect authorization** — the bug is the *absence* of an
ownership/permission check binding the caller to the resource it touches.
Syntactic SAST (Bandit/Semgrep) is blind here (no dangerous token to match);
this plugin reasons about authorization as a property.

**Target CWEs:** CWE-306 (missing auth for critical function), CWE-639
(IDOR/BOLA, authz bypass via user-controlled key), CWE-862 (missing authz),
CWE-863 (incorrect authz).

## When to use

- "Can user A read/delete user B's object by changing an id?" (IDOR/BOLA)
- An endpoint checks *authentication* (`@login_required`) but never checks that
  the subject owns/may access the specific resource.
- A guard exists but binds the wrong resource id (classic IDOR).
- Reviewing handlers that fetch/modify/delete a resource keyed by a request param.

## How to invoke

```bash
# proj_dir is any directory containing the .py files to analyze
.venv/bin/python run_plugin.py authz <proj_dir>
```

Output is written under `<proj_dir>/fm_agent_authz/`:
- `results/**/<func>.json` — per-function verdict + findings + the LLM facts
- `results/summary.json` — aggregate counts

Inspect results in the viewer:
```bash
.venv/bin/python ifc_viewer.py --port 8765   # then load <proj_dir>, pick "authz"
```

## Verdicts (per function)

| verdict | meaning |
|---|---|
| `VULNERABLE` | a sensitive op has no dominating guard binding the subject to the resource |
| `NEEDS_REVIEW` | authorization depends on unknowable framework/middleware policy (fail-closed soft flag) |
| `SAFE` | every sensitive op is discharged locally or by a caller, or no sensitive op |
| `ERROR` | no valid abstraction (fail-closed; never SAFE) |

Finding sub-kinds: `MISSING_AUTHORIZATION`, `RESOURCE_BINDING_MISMATCH` (IDOR),
`MISSING_AUTHENTICATION`, `ROLE_ONLY_GUARD_FOR_OBJECT_ACTION`, `AUTHZ_AFTER_EFFECT`.

## How it works (one paragraph)

The LLM produces a per-function **authorization abstraction** (authenticated
subject, sensitive operations with their resource identity, guards with the
subject/resource/action they bind and whether they dominate all paths,
obligations relied on from callers). A deterministic checker
(`src/authz_reasoner.py`) then decides via **guard-domination + binding-equality**:
a sensitive op is discharged only if some dominating guard binds the subject to
the *same* resource id. authz also runs a **top-down** pass so a check done by an
ancestor caller discharges a callee's obligation (avoids false positives on
internal functions). The LLM never decides; the checker does.

## Reference

Full theory, worked examples, and SPI integration: [docs/plugins/authz.md](../../docs/plugins/authz.md).
Plugin source: `src/plugins/authz.py`, `src/authz_prompts.py`, `src/authz_reasoner.py`.
Registry manifest: `src/plugins/registry.py` (`authz`).

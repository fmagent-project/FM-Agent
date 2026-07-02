# Typestate Plugin Evaluation (temporal: CWE-367/352/295/772/775/415/306/672)

> **⚠️ SUPERSEDED for the headline result.** This doc was written during recon,
> when no usable Python benchmark existed (only a fixture sanity check was
> possible). We have since **built a CVE-curated benchmark** and run a real
> head-to-head: typestate **fm-agent F1 0.62 (R 0.77) vs Bandit 0.27 / Semgrep
> 0.14** on 29 CWE-stratified real CVE cases. See [CVE_FINDINGS.md](./CVE_FINDINGS.md)
> and [REPORT.md](./REPORT.md) §5 for current results. Retained below for
> provenance: the recon proving Juliet is C/C++-only and no Python temporal
> benchmark exists, plus the fixture sanity check.

## Scope & honest constraint

The typestate plugin detects temporal/lifecycle defects via property automata:
TOCTOU (CWE-367), CSRF (CWE-352), missing cert validation (CWE-295), resource
leak (CWE-772/775), double-free (CWE-415), missing auth (CWE-306), improper
state (CWE-672). Verdicts: VULNERABLE · POLYMORPHIC · NEEDS_REVIEW · SAFE · ERROR.

**No usable public Python benchmark exists** (confirmed in recon):
- Juliet has genuine CWE-367/415/404/772 coverage but **C/C++ only** — useless
  for our Python-focused tool directly.
- OWASP BenchmarkPython: none of these categories.
- RedBench `tls_validation` (CWE-295) and `race_condition` (CWE-367) are
  LLM-**generated** only — excluded per "prefer real".
- Baselines are partial at best: Bandit B501 catches literal `verify=False`
  (CWE-295) but nothing for TOCTOU/resource-leak/CSRF; CodeQL has
  `py/csrf-protection-disabled`, `py/request-without-cert-validation`,
  `py/file-not-closed` (the only real baseline, heavy to stand up per case).

Fabricating cases would violate the "prefer real" constraint. This is an
**honest gap report + a sanity check on the committed fixture**.

## Sanity check (committed fixture, not a benchmark)

`typestate_app` ships 11 hand-labeled functions (ground truth committed before
running; source carries no hint comments). Prior committed results:

| function | expected | got | |
|---|---|---|---|
| read_if_present | VULNERABLE | VULNERABLE | ok |
| update_profile | VULNERABLE | VULNERABLE | ok |
| fetch_payload | VULNERABLE | VULNERABLE | ok |
| load_text | VULNERABLE | VULNERABLE | ok |
| create_once | SAFE | SAFE | ok |
| submit_order | SAFE | SAFE | ok |
| checkout | SAFE | SAFE | ok |
| read_payload | SAFE | SAFE | ok |
| append_record | POLYMORPHIC | SAFE | MISS |
| persist_order | POLYMORPHIC | SAFE | MISS |
| open_stream | POLYMORPHIC | SAFE | MISS |

**Sanity: 8/11 match.** Critically, **all 4 true-vulnerable and all 4 true-safe
cases are correct (8/8 on the decidable cases)** — zero false positives, zero
false negatives on the clear-cut functions. The 3 misses are ALL
POLYMORPHIC→SAFE: the plugin judged a resource's lifecycle as locally complete
when ground truth marks it parametric (the caller decides). These are
under-flagging on the hardest interprocedural-context cases, not wrong verdicts
on standalone defects.

**What this shows / does NOT show:** the plugin correctly handles the decidable
typestate properties (use-after-event, must-close, ordering) with no FP/FN on
this fixture, and its weakness is precisely the POLYMORPHIC (caller-dependent)
boundary. It does NOT establish precision/recall — there is no independent
labeled benchmark.

## Why no head-to-head

| candidate baseline | coverage |
|---|---|
| Bandit | B501 only (literal `verify=False`, CWE-295) — no TOCTOU/leak/CSRF |
| Semgrep CE | scattered pattern rules, no reliable temporal coverage |
| CodeQL | `py/csrf-protection-disabled`, `py/request-without-cert-validation`, `py/file-not-closed` — the only real baseline; heavy per-case DB build, deferred |

A fair head-to-head needs either Juliet-derived C/C++ cases (different language,
would need our C support exercised) or a curated CVE corpus (Paramiko CVE-2022-24302
for CWE-295, Django CSRF advisories for CWE-352, tempfile TOCTOU CVEs) plus
CodeQL. Both are out of scope for this pass; recorded as recommended next step.

## Bottom line

Typestate is **benchmark-starved** for Python: the only real labeled data
(Juliet) is C/C++, and only CodeQL ships comparable queries. The committed
fixture shows the plugin is sound on decidable temporal properties (8/8 on
clear-cut cases, 0 FP / 0 FN) and under-flags only on caller-dependent
POLYMORPHIC lifecycles. We make **no precision/recall claim**. Honest
recommendation: curate a CVE-pinned corpus (CWE-295/352/367) and add CodeQL as
the baseline before claiming a head-to-head win.

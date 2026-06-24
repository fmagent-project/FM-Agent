# IFC Plugin Evaluation (info-leak: CWE-200 / CWE-209 / CWE-532)

> **⚠️ SUPERSEDED for the headline result.** This doc was written during recon,
> when no usable benchmark existed (only a fixture sanity check was possible). We
> have since **built a CVE-curated benchmark** and run a real head-to-head: ifc
> **fm-agent F1 0.41 (R 0.39) vs Bandit/Semgrep 0.00** on 36 CWE-stratified real
> CVE cases. See [CVE_FINDINGS.md](./CVE_FINDINGS.md) and [REPORT.md](./REPORT.md)
> §4 for current results. Retained below for provenance: the recon proving no
> public info-leak benchmark exists, and the fixture sanity check.

## Scope & honest constraint

The ifc plugin detects confidentiality information-flow leaks (secrets/PII flowing
into logs, errors, responses). Verdict vocabulary: LEAK · DECLASSIFIED ·
POLYMORPHIC · SECURE · ERROR.

**No usable public benchmark with real labels exists** for this property in
Python (confirmed in recon):
- OWASP BenchmarkPython: no CWE-532/200/209 category.
- Juliet has CWE-534/535 (adjacent) but C/C++ only.
- RedBench `cleartext_secrets` is LLM-**generated** (excluded per "prefer real").
- CodeQL has `py/clear-text-logging-sensitive-data` but it is the only baseline
  that even attempts this, and standing up a CodeQL DB per case is heavy.

Fabricating cases would violate the "prefer real, not hand/LLM-made" constraint.
So this is an **honest gap report + a sanity check on committed fixtures**, NOT a
head-to-head with statistical claims.

## Sanity check (committed fixtures, not a benchmark)

The repo ships scoped real-world fixtures with hand-authored `expected.json`
(ground truth committed before running, source carries no hint comments). These
are regression fixtures, not an independent benchmark — but they show the plugin
runs end-to-end on real OSS code (spotipy OAuth, requests proxy).

`spotipy_oauth_scoped` (8 labeled functions), prior committed results:
- 4/8 exact-match on labeled functions; verdict distribution over all 68 analyzed
  functions: LEAK 22 / SECURE 43 / DECLASSIFIED 2 / POLYMORPHIC 1.
- The mismatches are instructive and NOT simple misses:
  - `_make_authorization_headers` expected LEAK, got SECURE — the leak is a
    base64-encoded client_secret in an auth header; whether that is a "leak"
    depends on declassification policy (base64 of a secret into an outbound
    Authorization header is intended behavior). This is a policy-boundary case,
    arguably DECLASSIFIED, which the plugin's own vocabulary supports.
  - `_request_access_token` expected LEAK, got DECLASSIFIED — same policy nuance:
    the plugin judged the secret use as an intended declassification.
  - `_make_authorization_headers_summary` is a summary artifact, not a function;
    the key-mapping counts it as MISSING (a harness artifact, not an analysis
    miss).
- `requests_proxy_scoped` (28 labeled funcs) is the harder fixture and includes
  the known CVE-2023-32681-style proxy-credential leak the design docs discuss as
  an IFC composite-field deficiency.

**What the sanity check does and does NOT show:** it confirms the plugin executes
on real code and produces a defensible verdict distribution, with the
disagreements concentrated on genuine declassification-policy boundaries (not
random error). It does NOT establish precision/recall — there is no independent
labeled benchmark to measure that against.

## Why no head-to-head

| candidate baseline | status |
|---|---|
| Bandit | no CWE-532 rule (B105/B106/B107 are hardcoded-secret only, not runtime logging leaks) |
| Semgrep CE | no taint-tracked logging-leak rule (pattern-only on var names) |
| CodeQL | `py/clear-text-logging-sensitive-data` exists (the only real baseline) but per-case DB build is heavy; deferred |

A fair head-to-head would require either (a) curating a real CVE corpus of
Python credential-logging leaks (NVD CWE-532 + Django/Salt/Ansible advisories) —
a multi-day curation effort — or (b) standing up CodeQL. Both are out of scope
for this pass and are recorded as the recommended next step.

## Bottom line

IFC is **benchmark-starved**: no real public labeled set, and only CodeQL even
ships a comparable query. The committed fixtures show the plugin works on real
OSS and that its disagreements cluster on declassification-policy boundaries
(which its DECLASSIFIED verdict is designed for), but we make **no precision/recall
claim** here. Honest recommendation: curate a CVE-pinned CWE-532 corpus and add
CodeQL as the baseline before claiming a head-to-head win.

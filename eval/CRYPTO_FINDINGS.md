# Crypto Plugin Evaluation (misuse: weak hash / PRNG / algorithm, hardcoded key)

Evaluated on BOTH benchmarks. The key result is the **synthetic→real reversal**:
Bandit wins outright on OWASP (synthetic) but FM-Agent overtakes it on real CVE
code. Read both sections.

## TL;DR — the reversal

| benchmark | tool | P | R | F1 | winner |
|---|---|---|---|---|---|
| OWASP (synthetic, N=24) | bandit | 1.00 | 1.00 | **1.00** | **Bandit** |
| | fm-agent | 0.57 | 1.00 | 0.73 | |
| | semgrep | 0.60 | 0.25 | 0.35 | |
| CVE (real, N=34) | **fm-agent** | 0.52 | 0.86 | **0.65** | **FM-Agent** |
| | bandit | 0.83 | 0.36 | 0.50 | |
| | semgrep | 0.50 | 0.07 | 0.12 | |

On OWASP, weak crypto is a one-liner (`hashlib.md5(...)`) — Bandit's AST match
nails it (1.00). On real CVEs the weak crypto hides behind cross-function key
derivation, config loading, and custom wrappers — **Bandit recall collapses
1.00→0.36** while FM-Agent holds (0.86 recall), and FM-Agent overtakes on F1
(0.65 vs 0.50). Bandit's OWASP perfection is a synthetic-benchmark artifact.
(CVE corpus is ~60% label-precision; see CVE_FINDINGS.md for the hand-audit.)

---

## Part A — OWASP (synthetic): scope + why Bandit wins here

OWASP BenchmarkPython crypto-misuse categories with real, balanced labels:
`hash` (CWE-328, weak hash) and `weakrand` (CWE-330, insecure PRNG).
24-case stratified sample (12 vuln / 12 safe), baselines on full 477 cases.
Baselines: Bandit (B303/B324 weak hash, B311 random), Semgrep CE.

### Headline scores (24-case intersection)

| tool | view | TP | FP | FN | TN | precision | recall | F1 |
|---|---|---|---|---|---|---|---|---|
| bandit | detection | 12 | 0 | 0 | 12 | **1.00** | **1.00** | **1.00** |
| **fm-agent** | detection | 12 | 9 | 0 | 3 | 0.57 | **1.00** | 0.73 |
| semgrep | detection | 3 | 2 | 9 | 10 | 0.60 | 0.25 | 0.35 |
| bandit | cwe-aware | 12 | 0 | 0 | 12 | **1.00** | **1.00** | **1.00** |
| **fm-agent** | cwe-aware | 12 | 3 | 0 | 9 | 0.80 | **1.00** | 0.89 |
| semgrep | cwe-aware | 3 | 0 | 9 | 12 | 1.00 | 0.25 | 0.40 |

**On OWASP (synthetic), Bandit WINS** — perfect (1.00/1.00), beating FM-Agent
outright. We report this honestly. **But this advantage does NOT survive on real
CVE code** (see Part B): it is a synthetic-benchmark artifact.

### Why Bandit wins on OWASP (and why that's expected here)

Weak-hash and weak-PRNG misuse, *as OWASP presents it*, is a **syntactic**
property: "is the called API `hashlib.md5` / `random.random`?" is decidable from
the AST node alone — no dataflow needed. OWASP's one-liner cases are exactly
Bandit's home turf (B324/B303/B311), and it nails them. This matches our own
prior analysis (docs/plugins/crypto.md §4): on *syntactically-presented* crypto
misuse, a linter is cheaper and accurate. The catch (Part B): real crypto CVEs are
rarely presented syntactically.

### Per-CWE recall

| CWE | bandit | fm-agent | semgrep |
|---|---|---|---|
| CWE-328 weak hash | 1.00 | 1.00 | 0.50 |
| CWE-330 weak PRNG | 1.00 | 1.00 | 0.00 |

All three detect weak hash; **Semgrep CE is blind to weak PRNG (0.00)** — it has
no rule for `random.*` used as security material. So FM-Agent still beats Semgrep
decisively (F1 0.73 vs 0.35 detection); it only loses to Bandit.

## FM-Agent's 9 false positives — audited, two distinct kinds

### Kind A: 6 hash FPs — arguably MORE correct than the benchmark label

All 6 are SHA-384/SHA-512 hashing input written to `passwordFile.txt`:

| case | code | benchmark label | FM-Agent |
|---|---|---|---|
| 00253, 00332 | `hashlib.sha512()` → passwordFile | SAFE (not a *weak* hash) | CWE-916 |
| 00711, 00056 | `hashlib.new('sha512')` → passwordFile | SAFE | CWE-916 |
| 00797 | `hashlib.new('sha384')` → passwordFile | SAFE | CWE-916 |
| 00717 | `hashlib.sha384()` → passwordFile | SAFE | CWE-916 |

The benchmark scopes `hash` strictly to CWE-328 (weak *algorithm*): SHA-512 is
not weak, so it labels these SAFE. But FM-Agent noticed the hash output goes to a
**password file** and flagged **CWE-916 (use of a fast hash for password
storage)** — which is a *real* and *different* defect: SHA-512 is cryptographically
strong but FAST, so it's the wrong primitive for password storage (should be
bcrypt/scrypt/argon2/PBKDF2). **This is arguably a more sophisticated finding than
the label credits**, not a hallucination. Because CWE-916 ≠ the case's CWE-328
family, the **cwe-aware view correctly reclassifies these 6 as TN** (FP 9→3) —
they are not false alarms *for the category under test*, they are out-of-scope
true observations.

### Kind B: 3 weakrand FPs — genuine false positives (the real defect)

| case | code | reality | FM-Agent |
|---|---|---|---|
| 00048, 00133, 00408 | `random.SystemRandom().normalvariate()` | SAFE — SystemRandom IS a CSPRNG | CWE-338 (VULNERABLE) |

These are **true false positives.** `random.SystemRandom()` is a
cryptographically secure RNG (wraps `os.urandom`), so using it is correct. FM-Agent
flagged CWE-338 (predictable randomness) — it keyed on the `random.` module prefix
and **missed that `.SystemRandom()` promotes it to a CSPRNG.** Root cause: the
crypto abstraction's randomness-source classification doesn't special-case
`random.SystemRandom` (treats `random.*` as insecure_prng). A real, fixable
precision bug. Notably Bandit gets this right (B311 whitelists SystemRandom).

(Note: the `random.SystemRandom` misclassification was subsequently FIXED in
`crypto_prompts.py` — re-running those 3 cases now yields SAFE. See REPORT.md
cross-cutting finding #5.)

---

## Part B — CVE (real code): the reversal

CWE-stratified sample of 34 real crypto CVEs (14 vuln / 20 safe) from the
CVE-curated corpus (weak algorithm/PRNG/key CWEs: 321/326/327/328/330/338/798).

| tool | P | R | F1 |
|---|---|---|---|
| **fm-agent** | 0.52 | **0.86** | **0.65** |
| bandit | 0.83 | 0.36 | 0.50 |
| semgrep | 0.50 | 0.07 | 0.12 |

**FM-Agent overtakes Bandit (0.65 vs 0.50).** The reason is the exact inverse of
Part A: real weak-crypto is NOT presented as a one-liner. It hides behind
cross-function key derivation, config-driven algorithm selection, and custom
crypto wrappers. Bandit's AST match — perfect on OWASP — sees recall collapse to
0.36 because the `hashlib.md5(...)`-shaped node isn't there to match. FM-Agent's
semantic analysis tracks the weak primitive across the call structure and holds
0.86 recall.

per-CWE detection recall (fm-agent): CWE-321/327/328/330/338 = 1.00, CWE-326 0.50.

CVE-corpus caveat (~60% label precision) applies: hand-audit found apparent-FNs
that are mislabels (e.g. `_cache_put`, a logging method) and FPs on post-fix
functions with narrowed-but-residual patterns. See [CVE_FINDINGS.md](./CVE_FINDINGS.md).

## Bottom line

Crypto is the portfolio's most nuanced result — it depends entirely on HOW the
misuse is presented:

1. **Syntactic presentation (OWASP one-liners):** Bandit wins (1.00 vs 0.73). A
   linter is the right, cheaper tool when the weak API call is right there.
2. **Real-world presentation (CVE code):** FM-Agent wins (0.65 vs 0.50). Bandit's
   recall collapses (1.00→0.36) when the weak primitive is reached across
   functions/config; FM-Agent's semantic analysis is robust to it.
3. FM-Agent beats Semgrep CE on both (Semgrep is blind to weak PRNG).

**The honest portfolio takeaway:** on crypto, a linter suffices *only when* the
misuse is syntactically obvious. The moment real code structure intervenes —
which is the common case for actual CVEs — the semantic approach wins. This is a
stronger version of the "syntactic vs semantic" argument than the OWASP-only view
suggested: it's not "FM-Agent loses on crypto", it's "FM-Agent loses on
syntactically-trivial crypto and wins on real crypto." The eval also found and
FIXED the `random.SystemRandom` classification bug.

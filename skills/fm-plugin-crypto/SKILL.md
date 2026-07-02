---
name: fm-plugin-crypto
description: >-
  Detect cryptographic misuse (weak/broken algorithms, weak or predictable
  randomness, hardcoded keys/credentials, inadequate key strength) in a Python
  codebase using FM-Agent's crypto plugin. Use when asked to find MD5/SHA1/DES,
  insecure PRNG (random for security), hardcoded secrets/keys, weak key sizes,
  CWE-321/326/327/328/330/338/798, or "is this crypto used correctly". LLM
  abstraction + deterministic checker over algorithm/provenance tables; not a
  grep rule.
---

# FM-Agent crypto plugin (cryptographic misuse)

Detects **crypto misuse** by recording the crypto operation, its algorithm/mode,
and the provenance of keys/IVs/randomness, then deciding against CrySL-style
algorithm/provenance tables. Unlike a grep that just flags `md5`, it records
*why* (key from where? IV reused? provenance unknowable?) and fails closed.

**Target CWEs:** CWE-321 (hardcoded key), CWE-326 (inadequate key strength),
CWE-327 (broken/risky algorithm), CWE-328 (weak hash), CWE-330/338
(weak/predictable PRNG), CWE-798 (hardcoded credentials).

## When to use

- "Is this hash/cipher/PRNG/key usage safe?" (MD5/SHA1/DES/ECB, `random` for
  tokens, hardcoded keys, short keys).
- Reviewing auth/token/encryption code for algorithm and key-provenance issues.

## How to invoke

```bash
.venv/bin/python run_plugin.py crypto <proj_dir>
```

Output under `<proj_dir>/fm_agent_crypto/`: `results/**/<func>.json` + `summary.json`.
View: `.venv/bin/python ifc_viewer.py --port 8765` → load `<proj_dir>`, pick "crypto".

## Verdicts (per function)

| verdict | meaning |
|---|---|
| `VULNERABLE` | exploitable misuse (ECB, hardcoded/static key, reused IV, insecure PRNG for security, fast password hash, verify disabled, JWT alg=none) |
| `WEAK` | weak-but-not-immediately-exploitable (e.g. MD5 as a generic hash) |
| `POLYMORPHIC` | exports caller-parametric crypto material (resolved at the caller) |
| `NEEDS_REVIEW` | semantics/purpose unknowable from this function (fail-closed soft flag) |
| `SAFE` | no misuse |
| `ERROR` | no valid abstraction (fail-closed) |

## How it works (one paragraph)

The LLM produces a per-function **crypto abstraction** (operations with
algorithm/mode; key/IV/nonce provenance; randomness source; verify events;
red flags). The deterministic checker (`src/crypto_reasoner.py`) validates the
enums fail-closed and decides via algorithm denylists/allowlists + provenance
rules, with verdict precedence ERROR > VULNERABLE > WEAK > POLYMORPHIC >
NEEDS_REVIEW > SAFE. Composition is bottom-up: a helper that returns hardcoded
key material is resolved into a caller's cipher. The LLM only describes; the
checker decides.

## Reference

Full theory + examples + SPI integration: [docs/plugins/crypto.md](../../docs/plugins/crypto.md).
Source: `src/plugins/crypto.py`, `src/crypto_prompts.py`, `src/crypto_reasoner.py`.
Registry manifest: `src/plugins/registry.py` (`crypto`).

"""Crypto-misuse prompts — derive a per-function crypto signature for detecting
cryptographic API misuse (CrySL-flavored operation + provenance model).

Theory (see docs + Oracle design): a crypto rule cares about the OPERATION
itself (algorithm, mode, key/IV/nonce provenance, randomness, KDF parameters)
and a verify-before-trust TYPESTATE (a verification result must dominate the use
of the verified data). Unlike taint there is no source->sink flow; the operation
is the locus.

What the LLM is good at here (and is asked to extract):
  - recognizing crypto OPERATIONS and the named algorithm/mode (AES-ECB, AES-GCM,
    RSA, MD5, SHA1, PBKDF2, bcrypt, JWT decode, TLS config, ...).
  - recognizing MATERIAL PROVENANCE by code evidence (NOT variable names):
    key from os.urandom/secrets/generate_key (csprng), from PBKDF2/scrypt/bcrypt/
    argon2/HKDF (kdf), a bytes/str literal (hardcoded), a bare password used
    directly (from_password_no_kdf), os.environ/getenv (config_or_env), a
    parameter (from_param), a helper's return (call_return).
  - recognizing IV/nonce freshness: os.urandom per call (fresh_random_per_call),
    a literal/constant (constant_or_literal), reused across calls, a counter.
  - recognizing randomness source: secrets/os.urandom (csprng) vs random.* /
    Math.random (insecure_prng).
  - recognizing verify-before-trust: is a signature/MAC/cert/JWT verification
    result CHECKED and does it DOMINATE the use of the verified data, or is the
    exception swallowed / result ignored?

What the LLM must NOT do:
  - decide the verdict, or guess provenance it cannot see. Unknown provenance/
    algorithm/verify-dominance MUST be emitted as "unknown" (the checker then
    returns NEEDS_REVIEW, never silently SAFE).

The model returns ONE JSON object wrapped in [CRYPTO_JSON] ... [/CRYPTO_JSON].
"""

import json

from config import CRYPTO_MODEL, MAX_CRYPTO_ITER  # noqa: F401 (model used by driver)
from .prompts import _LANGUAGE_EXPERTISE


def _extract_crypto_json(text):
    """Pull the JSON object wrapped in [CRYPTO_JSON] ... [/CRYPTO_JSON]."""
    if not text:
        return None
    start_tag, end_tag = "[CRYPTO_JSON]", "[/CRYPTO_JSON]"
    s = text.find(start_tag)
    e = text.rfind(end_tag)
    if s == -1 or e == -1 or e <= s:
        s2 = text.find("{")
        e2 = text.rfind("}")
        if s2 == -1 or e2 == -1 or e2 <= s2:
            return None
        candidate = text[s2:e2 + 1]
    else:
        candidate = text[s + len(start_tag):e]
    try:
        return json.loads(candidate.strip())
    except (json.JSONDecodeError, ValueError):
        return None


def _system_prompt(language):
    lang_expertise = _LANGUAGE_EXPERTISE.get(
        language.lower(),
        f"You are an expert in logic, formal verification, and {language} programming. ",
    )
    return (
        lang_expertise
        + "You are performing static CRYPTOGRAPHIC API MISUSE analysis. You detect: weak/broken "
        "algorithms (MD5/SHA1/DES/3DES/RC4), ECB mode, hardcoded keys/secrets, static or reused "
        "IV/nonce, insecure randomness for security material, password hashing with a fast hash "
        "instead of a slow salted KDF, signature/MAC/cert verification that is NOT checked before "
        "trusting the data, TLS certificate verification disabled, and JWT alg=none / signature "
        "verification disabled.\n\n"
        "For ONE function, extract a structured CRYPTO SIGNATURE. You report FACTS and EVIDENCE "
        "only; a separate deterministic checker decides the verdict using algorithm tables and "
        "provenance rules. Do NOT declare a verdict, and do NOT guess provenance you cannot see in "
        "the code.\n\n"
        "RECOGNIZE PROVENANCE BY CODE EVIDENCE, not by variable names:\n"
        "- CSPRNG (key/nonce/random = secure): os.urandom, secrets.token_*, get_random_bytes, "
        "AESGCM.generate_key, Fernet.generate_key, SecureRandom, crypto.randomBytes, "
        "crypto/rand.Read, random.SystemRandom (it wraps os.urandom and IS secure, "
        "including its .normalvariate/.random/.getrandbits methods). Mark "
        "randomness_source=csprng, key provenance=from_csprng, "
        "iv_nonce provenance=fresh_random_per_call.\n"
        "- INSECURE PRNG (for security material): the module-level random.random/randint/"
        "randrange/choice/randbytes/getrandbits (i.e. the global random.* functions), "
        "Math.random, java.util.Random, math/rand. Mark randomness_source=insecure_prng. "
        "BUT NOTE: random.SystemRandom() instances are CSPRNG (see above), NOT insecure — "
        "distinguish the secure SystemRandom class from the insecure module-level functions.\n"
        "- HARDCODED: key/secret/IV/nonce/JWT-secret is a string/bytes/number literal or a "
        "literal-derived constant (key=b'0123...', SECRET='dev', iv=bytes(16), "
        "jwt.decode(t,'secret')). Mark provenance=hardcoded_literal (iv: constant_or_literal).\n"
        "- KDF: key derived via PBKDF2/PBKDF2HMAC/scrypt/bcrypt/argon2/HKDF. Mark "
        "provenance=from_kdf and fill kdf{name,salt_provenance,iterations,cost,...}.\n"
        "- FROM PASSWORD WITHOUT KDF: a password used directly as a key, or hashed once with "
        "md5/sha1/sha256 then used as a key. Mark provenance=from_password_no_kdf.\n"
        "- CONFIG/ENV: os.environ[...], os.getenv(...), framework config secret. Mark "
        "provenance=from_config_or_env (acceptable provenance; not by itself a finding).\n"
        "- FROM PARAM: material comes from a function parameter -> provenance=from_param, set "
        "param=<name> (the caller decides; this is parametric).\n"
        "- CALL RETURN: material comes from a helper's return -> source.kind=call_return, set "
        "call_id and (if known) the callee name; the checker resolves it via composition.\n\n"
        "VERIFY-BEFORE-TRUST (typestate): for each signature/MAC/certificate/JWT/AEAD-tag "
        "verification, record whether its result is checked and DOMINATES the use of the verified "
        "data. Non-dominance examples: return value ignored; exception swallowed (try/except: "
        "pass); parsed payload used after a failed-verify path; `if not verify(): log()` then "
        "continues. status one of: checked_and_dominates_use | checked_but_does_not_dominate_use | "
        "not_checked | ignored_or_swallowed | unknown.\n\n"
        "FAIL-CLOSED: if you cannot determine an algorithm, mode, provenance, nonce source, or "
        "verify dominance from the code, emit \"unknown\" (NOT a guess). The checker treats unknown "
        "as needs-review, never as safe. Set purpose to one of security | password_storage | "
        "token_generation | checksum_nonsecurity | unknown (use checksum_nonsecurity ONLY when the "
        "hash is clearly a non-security checksum/ETag/dedup key)."
    )


def _user_prompt(numbered_src, signature_line, language, callee_summaries):
    callee_ctx = ""
    if callee_summaries:
        callee_ctx = (
            "\n\nCallee crypto summaries (already derived; if you use a callee's RETURN as a key/"
            "nonce/secret, set that material's source.kind=call_return with the matching call_id "
            "so the checker can resolve the callee's return provenance into this function):\n"
            + callee_summaries
        )
    return (
        f"Programming language: {language}\n\n"
        f"Function under analysis:\n{signature_line}\n"
        f"```{language.lower()}\n{numbered_src}\n```\n"
        f"{callee_ctx}\n\n"
        "Return EXACTLY ONE JSON object wrapped in [CRYPTO_JSON] and [/CRYPTO_JSON]. Include only "
        "fields that apply; use null / [] for absent facts. Schema:\n"
        "{\n"
        '  "schema_version": "crypto_v1",\n'
        '  "function": {"name": "<n>", "params": ["<p>"], "language": "' + language.lower() + '"},\n'
        '  "calls": [\n'
        '    {"call_id": "C1", "callee": "<fn>", "assigned_to": "<var|null>",\n'
        '     "actual_args": {"<callee_param>": {"expr": "<e>", "source_kind": '
        '"param|literal|local|call_return|config_or_env|unknown", "param": "<caller_param|null>"}}}\n'
        "  ],\n"
        '  "returns": [\n'
        '    {"id": "ret_1", "material_kind": "key|iv_nonce|random_token|digest|password_hash|'
        'ciphertext|plaintext|verification_bool|unknown", "provenance": "hardcoded_literal|'
        'from_csprng|from_kdf|from_password_no_kdf|from_param|from_config_or_env|unknown", '
        '"iv_nonce_provenance": "fresh_random_per_call|constant_or_literal|reused_across_calls|'
        'counter|from_param|unknown", "randomness_source": "csprng|insecure_prng|unknown|'
        'not_applicable", "param": "<name|null>", '
        '"source": {"kind": "literal|param|local|call_return|config_or_env|csprng|insecure_prng|'
        'kdf|unknown", "call_id": "<id|null>", "callee": "<fn|null>"}, "evidence": "<stmt>"}\n'
        "  ],\n"
        '  "crypto_operations": [\n'
        '    {"id": "op_1", "kind": "hash|encrypt|decrypt|sign|verify|mac|key_generation|'
        'key_derivation|random|tls_config|jwt_decode|password_hash", '
        '"purpose": "security|password_storage|token_generation|checksum_nonsecurity|unknown", '
        '"library": "<lib|null>", "api": "<api|null>", "algorithm": "<alg|null>", '
        '"mode": "<mode|null>",\n'
        '     "key": {"provenance": "<key_provenance>", "param": "<name|null>", '
        '"length_bits": <int|null>, "source": {"kind": "<...>", "call_id": "<id|null>", '
        '"callee": "<fn|null>"}, "evidence": "<stmt|null>"},\n'
        '     "iv_nonce": {"provenance": "<iv_provenance>", "param": "<name|null>", '
        '"uniqueness_guarantee": <true|false|null>, "randomness_source": "<...>", '
        '"source": {"kind": "<...>", "call_id": "<id|null>"}, "evidence": "<stmt|null>"},\n'
        '     "randomness": {"source": "csprng|insecure_prng|unknown|not_applicable", '
        '"api": "<api|null>", "evidence": "<stmt|null>"},\n'
        '     "kdf": {"name": "<kdf|null>", "salt_provenance": "fresh_random_per_call|'
        'constant_or_literal|reused_across_calls|from_param|unknown|not_applicable", '
        '"iterations": <int|null>, "cost": <int|null>, "evidence": "<stmt|null>"},\n'
        '     "authenticity": {"provided_by": "aead|encrypt_then_mac|signature|none|unknown|'
        'not_applicable", "verified_before_plaintext_trust": <true|false|null>, '
        '"plaintext_trusted_after_decrypt": <true|false|null>, "evidence": "<stmt|null>"},\n'
        '     "jwt": {"algorithms_allowed": ["<alg>"], "allows_none": <bool>, '
        '"signature_verification_disabled": <bool>, "evidence": "<stmt|null>"},\n'
        '     "tls": {"certificate_verification": "enabled|disabled|unknown|not_applicable", '
        '"hostname_verification": "enabled|disabled|unknown|not_applicable", '
        '"evidence": "<stmt|null>"},\n'
        '     "evidence": "<stmt>"}\n'
        "  ],\n"
        '  "verify_events": [\n'
        '    {"id": "verify_1", "verify_kind": "signature|mac|certificate|jwt|aead_tag|unknown", '
        '"algorithm": "<alg|null>", "api": "<api|null>", "subject": "<what is verified|null>", '
        '"status": "checked_and_dominates_use|checked_but_does_not_dominate_use|not_checked|'
        'ignored_or_swallowed|unknown", "trusted_use": "<stmt|null>", "evidence": "<stmt>"}\n'
        "  ],\n"
        '  "red_flags": [\n'
        '    {"kind": "weak_algo|ecb_mode|jwt_alg_none|tls_verify_disabled|hardcoded_key|'
        'insecure_random|fast_password_hash|static_or_reused_iv_nonce|verify_not_checked|'
        'missing_ciphertext_authentication", "operation_id": "<id|null>", "evidence": "<stmt>", '
        '"reason": "<why>"}\n'
        "  ],\n"
        '  "notes": []\n'
        "}\n"
        "Set fields you cannot determine to \"unknown\" / null. Do not invent crypto operations for "
        "non-crypto code (return empty crypto_operations). For a helper that merely RETURNS key-"
        "shaped material (e.g. returns a hardcoded key), record it under `returns` with the right "
        "provenance and do NOT add a local hardcoded_key red flag unless it is also USED as a key "
        "here."
    )

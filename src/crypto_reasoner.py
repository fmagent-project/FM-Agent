"""Crypto-misuse reasoner — deterministic checker over an LLM-derived crypto
signature (CrySL-flavored operation + provenance model).

Split of responsibility (mirrors taint/authz/IFC reasoners):
  - The LLM derives a per-function CRYPTO SIGNATURE (crypto_prompts): crypto
    operations (with algorithm/mode + key/iv/randomness/kdf provenance),
    verify_events (verify-before-trust typestate), red_flags, and parametric
    return material so callers can instantiate.
  - THIS module decides, deterministically and fail-closed, the verdict by
    table-driven rules over (operation kind, algorithm, mode, key/iv provenance,
    randomness, verify status).

Unlike taint there is NO source->sink flow: the crypto OPERATION ITSELF is the
locus, and verify-before-trust is an ordering/typestate property. We DO reuse
taint's parametric `from_param` + bottom-up call-return instantiation idea: a
helper that returns hardcoded key material is POLYMORPHIC in isolation and makes
its caller VULNERABLE once the return is used as a key (resolved in compose).

Verdict precedence: ERROR > VULNERABLE > WEAK > POLYMORPHIC > NEEDS_REVIEW > SAFE.
"""

import re

from config import CRYPTO_FAIL_CLOSED  # noqa: F401 (kept for parity / future toggles)


VULNERABLE = "VULNERABLE"
WEAK = "WEAK"
POLYMORPHIC = "POLYMORPHIC"
NEEDS_REVIEW = "NEEDS_REVIEW"
SAFE = "SAFE"
ERROR = "ERROR"

_PRECEDENCE = [ERROR, VULNERABLE, WEAK, POLYMORPHIC, NEEDS_REVIEW, SAFE]


# --- enums (for validation) ---------------------------------------------------

OP_KINDS = {
    "hash", "encrypt", "decrypt", "sign", "verify", "mac", "key_generation",
    "key_derivation", "random", "tls_config", "jwt_decode", "password_hash",
}
KEY_PROVENANCE = {
    "hardcoded_literal", "from_csprng", "from_kdf", "from_password_no_kdf",
    "from_param", "from_config_or_env", "unknown",
}
IV_NONCE_PROVENANCE = {
    "fresh_random_per_call", "constant_or_literal", "reused_across_calls",
    "counter", "from_param", "unknown",
}
RANDOMNESS_SOURCE = {"csprng", "insecure_prng", "unknown", "not_applicable"}
VERIFY_STATUS = {
    "checked_and_dominates_use", "checked_but_does_not_dominate_use",
    "not_checked", "ignored_or_swallowed", "unknown",
}


# --- algorithm tables (Oracle's denylists/allowlists) -------------------------

BROKEN_CIPHERS = {"DES", "3DES", "DES3", "DESEDE", "RC2", "RC4", "ARC4"}
WEAK_HASHES = {"MD2", "MD4", "MD5", "SHA1"}
FAST_PASSWORD_HASHES = {
    "MD2", "MD4", "MD5", "SHA1", "SHA224", "SHA256", "SHA384", "SHA512",
    "SHA3", "BLAKE2", "BLAKE3", "HASHLIB",
}
AEAD_MODES = {"GCM", "CCM", "EAX", "OCB", "CHACHA20POLY1305", "XCHACHA20POLY1305", "POLY1305"}
NON_AEAD_CONFIDENTIALITY_MODES = {"CBC", "CTR", "CFB", "OFB"}
DENIED_MODES = {"ECB"}
ACCEPTED_KDFS_FOR_KEYS = {"PBKDF2", "PBKDF2HMAC", "SCRYPT", "BCRYPT", "ARGON2", "ARGON2ID", "HKDF"}
ACCEPTED_PASSWORD_HASH_KDFS = {"PBKDF2", "PBKDF2HMAC", "SCRYPT", "BCRYPT", "ARGON2", "ARGON2ID"}


# --- finding taxonomy (kind -> cwe + default severity) ------------------------

FINDING_KINDS = {
    "weak_algorithm": ("CWE-327", WEAK),
    "broken_or_deprecated_cipher": ("CWE-327", VULNERABLE),
    "ecb_mode": ("CWE-327", VULNERABLE),
    "hardcoded_key_or_secret": ("CWE-321/CWE-798", VULNERABLE),
    "static_or_reused_iv_nonce": ("CWE-329/CWE-323", VULNERABLE),
    "predictable_randomness": ("CWE-338", VULNERABLE),
    "insufficient_key_size": ("CWE-326", WEAK),
    "password_fast_hash": ("CWE-916", VULNERABLE),
    "weak_kdf_parameters": ("CWE-916", WEAK),
    "missing_password_salt": ("CWE-759", VULNERABLE),
    "verify_not_checked": ("CWE-347", VULNERABLE),
    "missing_ciphertext_authentication": ("CWE-345/CWE-353", VULNERABLE),
    "tls_verification_disabled": ("CWE-295", VULNERABLE),
    "jwt_none_or_signature_disabled": ("CWE-347", VULNERABLE),
    "unknown_crypto_semantics": (None, NEEDS_REVIEW),
    "parametric_crypto_material": (None, POLYMORPHIC),
    "exported_crypto_material": (None, POLYMORPHIC),
}


def _norm(name):
    """Normalize an algorithm/mode name: uppercase, strip lib prefixes & punctuation."""
    if not name:
        return None
    s = str(name).upper()
    # AES.MODE_GCM -> GCM ; hashlib.sha1 -> SHA1 ; Crypto.Cipher.ARC4 -> ARC4
    s = s.split(".")[-1]
    s = s.replace("MODE_", "")
    s = re.sub(r"[^A-Z0-9]", "", s)
    return s or None


# --- validation ---------------------------------------------------------------

def validate(facts):
    """Return an error string if malformed / out-of-enum, else None (fail-closed)."""
    if not facts or not isinstance(facts, dict):
        return "no valid crypto abstraction"
    for op in facts.get("crypto_operations") or []:
        if op.get("kind") not in OP_KINDS:
            return f"unknown crypto operation kind: {op.get('kind')}"
        key = op.get("key") or {}
        if key.get("provenance") and key["provenance"] not in KEY_PROVENANCE:
            return f"unknown key provenance: {key.get('provenance')}"
        iv = op.get("iv_nonce") or {}
        if iv.get("provenance") and iv["provenance"] not in IV_NONCE_PROVENANCE:
            return f"unknown iv_nonce provenance: {iv.get('provenance')}"
    for ev in facts.get("verify_events") or []:
        if ev.get("status") and ev["status"] not in VERIFY_STATUS:
            return f"unknown verify status: {ev.get('status')}"
    return None


# --- finding accumulator ------------------------------------------------------

class _Findings:
    def __init__(self):
        self.items = []

    def add(self, severity, kind, op_id=None, evidence=None, reason=None, cwe=None):
        default_cwe, _ = FINDING_KINDS.get(kind, (None, severity))
        self.items.append({
            "severity": severity, "kind": kind, "cwe": cwe or default_cwe,
            "operation_id": op_id, "evidence": evidence, "reason": reason,
        })


def _g(d, *path, default=None):
    cur = d
    for p in path:
        if not isinstance(cur, dict):
            return default
        cur = cur.get(p)
    return cur if cur is not None else default


# --- per-operation checks (Oracle's decision tables) --------------------------

def _check_algorithm(op, F):
    alg = _norm(op.get("algorithm"))
    kind = op.get("kind")
    purpose = op.get("purpose")
    if alg in BROKEN_CIPHERS:
        F.add(VULNERABLE, "broken_or_deprecated_cipher", op.get("id"),
              op.get("evidence"), f"{alg} is broken/deprecated")
    if kind in {"hash", "sign", "verify", "mac"} and alg in WEAK_HASHES:
        if purpose == "checksum_nonsecurity":
            return
        if purpose == "password_storage":
            F.add(VULNERABLE, "password_fast_hash", op.get("id"), op.get("evidence"),
                  f"{alg} is a fast hash used for password storage")
        elif purpose == "security":
            F.add(WEAK, "weak_algorithm", op.get("id"), op.get("evidence"),
                  f"{alg} is cryptographically weak")
        elif purpose in (None, "unknown"):
            F.add(NEEDS_REVIEW, "unknown_crypto_semantics", op.get("id"),
                  op.get("evidence"), f"{alg} weak but purpose unclear")


def _check_key_size(op, F):
    alg = _norm(op.get("algorithm"))
    bits = _g(op, "key", "length_bits")
    if bits is None:
        return
    if alg == "AES" and bits < 128:
        F.add(VULNERABLE, "insufficient_key_size", op.get("id"), op.get("evidence"),
              f"AES key {bits} bits < 128")
    if alg in {"RSA", "RSAPSS", "RSASSAPKCS1V15"}:
        if bits < 1024:
            F.add(VULNERABLE, "insufficient_key_size", op.get("id"), op.get("evidence"),
                  f"RSA key {bits} bits < 1024")
        elif bits < 2048:
            F.add(WEAK, "insufficient_key_size", op.get("id"), op.get("evidence"),
                  f"RSA key {bits} bits < 2048")
    if alg in {"EC", "ECDSA", "ECDH"} and bits < 224:
        F.add(WEAK, "insufficient_key_size", op.get("id"), op.get("evidence"),
              f"EC key {bits} bits < 224")


def _check_key(op, F):
    p = _g(op, "key", "provenance")
    if p == "hardcoded_literal":
        F.add(VULNERABLE, "hardcoded_key_or_secret", op.get("id"), op.get("evidence"),
              "key is a hardcoded literal")
    elif p == "from_password_no_kdf":
        F.add(VULNERABLE, "password_fast_hash", op.get("id"), op.get("evidence"),
              "key derived from password without a KDF")
    elif p == "from_param":
        F.add(POLYMORPHIC, "parametric_crypto_material", op.get("id"), op.get("evidence"),
              f"key provenance depends on caller (param:{_g(op,'key','param')})")
    elif p == "unknown":
        F.add(NEEDS_REVIEW, "unknown_crypto_semantics", op.get("id"), op.get("evidence"),
              "key provenance unknown")
    # from_csprng / from_kdf / from_config_or_env -> acceptable provenance


def _check_nonce_required(op, F):
    n = _g(op, "iv_nonce", "provenance")
    r = _g(op, "iv_nonce", "randomness_source")
    if n in {"constant_or_literal", "reused_across_calls"}:
        F.add(VULNERABLE, "static_or_reused_iv_nonce", op.get("id"), op.get("evidence"),
              f"IV/nonce is {n}")
    elif n == "fresh_random_per_call":
        if r == "insecure_prng":
            F.add(VULNERABLE, "predictable_randomness", op.get("id"), op.get("evidence"),
                  "nonce from insecure PRNG")
        elif r == "unknown":
            F.add(NEEDS_REVIEW, "unknown_crypto_semantics", op.get("id"), op.get("evidence"),
                  "nonce randomness source unknown")
    elif n == "counter":
        if _g(op, "iv_nonce", "uniqueness_guarantee") is not True:
            F.add(NEEDS_REVIEW, "unknown_crypto_semantics", op.get("id"), op.get("evidence"),
                  "counter nonce without uniqueness guarantee")
    elif n == "from_param":
        F.add(POLYMORPHIC, "parametric_crypto_material", op.get("id"), op.get("evidence"),
              f"nonce provenance depends on caller (param:{_g(op,'iv_nonce','param')})")
    elif n in (None, "unknown"):
        F.add(NEEDS_REVIEW, "unknown_crypto_semantics", op.get("id"), op.get("evidence"),
              "IV/nonce provenance unknown")


def _check_encrypt(op, F):
    _check_algorithm(op, F)
    _check_key(op, F)
    _check_key_size(op, F)
    mode = _norm(op.get("mode"))
    if mode in DENIED_MODES:
        F.add(VULNERABLE, "ecb_mode", op.get("id"), op.get("evidence"), "ECB mode")
    elif mode in AEAD_MODES:
        _check_nonce_required(op, F)
    elif mode in NON_AEAD_CONFIDENTIALITY_MODES:
        _check_nonce_required(op, F)
        auth = _g(op, "authenticity", "provided_by")
        if auth == "none":
            F.add(WEAK, "missing_ciphertext_authentication", op.get("id"), op.get("evidence"),
                  f"{mode} without authentication")
        elif auth == "unknown":
            F.add(NEEDS_REVIEW, "unknown_crypto_semantics", op.get("id"), op.get("evidence"),
                  "ciphertext authentication unknown")
    elif mode in (None, "UNKNOWN"):
        F.add(NEEDS_REVIEW, "unknown_crypto_semantics", op.get("id"), op.get("evidence"),
              "encryption mode unknown")


def _check_decrypt(op, F):
    _check_algorithm(op, F)
    _check_key(op, F)
    _check_key_size(op, F)
    mode = _norm(op.get("mode"))
    if mode in DENIED_MODES:
        F.add(VULNERABLE, "ecb_mode", op.get("id"), op.get("evidence"), "ECB mode")
    elif mode in AEAD_MODES:
        vbt = _g(op, "authenticity", "verified_before_plaintext_trust")
        if vbt is False:
            F.add(VULNERABLE, "missing_ciphertext_authentication", op.get("id"),
                  op.get("evidence"), "AEAD tag not verified before trusting plaintext")
        elif vbt is None:
            F.add(NEEDS_REVIEW, "unknown_crypto_semantics", op.get("id"), op.get("evidence"),
                  "AEAD verification status unknown")
    elif mode in NON_AEAD_CONFIDENTIALITY_MODES:
        _check_nonce_required(op, F)
        if _g(op, "authenticity", "plaintext_trusted_after_decrypt") is True:
            auth = _g(op, "authenticity", "provided_by")
            if auth == "none":
                F.add(VULNERABLE, "missing_ciphertext_authentication", op.get("id"),
                      op.get("evidence"), "unauthenticated ciphertext trusted after decrypt")
            elif auth == "unknown":
                F.add(NEEDS_REVIEW, "unknown_crypto_semantics", op.get("id"), op.get("evidence"),
                      "ciphertext authentication unknown")
    elif mode in (None, "UNKNOWN"):
        F.add(NEEDS_REVIEW, "unknown_crypto_semantics", op.get("id"), op.get("evidence"),
              "decryption mode unknown")


def _check_hash(op, F):
    alg = _norm(op.get("algorithm"))
    purpose = op.get("purpose")
    if purpose == "password_storage":
        if alg in FAST_PASSWORD_HASHES or alg not in ACCEPTED_PASSWORD_HASH_KDFS:
            F.add(VULNERABLE, "password_fast_hash", op.get("id"), op.get("evidence"),
                  f"{alg} is a fast hash for password storage")
    elif purpose == "security":
        if alg in WEAK_HASHES:
            F.add(WEAK, "weak_algorithm", op.get("id"), op.get("evidence"), f"{alg} weak")
        elif alg is None:
            F.add(NEEDS_REVIEW, "unknown_crypto_semantics", op.get("id"), op.get("evidence"),
                  "hash algorithm unknown")
    elif purpose in (None, "unknown"):
        if alg in WEAK_HASHES:
            F.add(NEEDS_REVIEW, "unknown_crypto_semantics", op.get("id"), op.get("evidence"),
                  f"{alg} weak but purpose unclear")
    # checksum_nonsecurity -> no finding


def _check_password_hash(op, F):
    alg = _norm(op.get("algorithm"))
    kdf = _norm(_g(op, "kdf", "name"))
    if alg in FAST_PASSWORD_HASHES:
        F.add(VULNERABLE, "password_fast_hash", op.get("id"), op.get("evidence"),
              f"{alg} fast hash for passwords")
    elif kdf not in ACCEPTED_PASSWORD_HASH_KDFS:
        if kdf in (None, "UNKNOWN"):
            F.add(NEEDS_REVIEW, "unknown_crypto_semantics", op.get("id"), op.get("evidence"),
                  "password hashing method unknown")
        else:
            F.add(VULNERABLE, "password_fast_hash", op.get("id"), op.get("evidence"),
                  f"{kdf} not an accepted password KDF")
    salt = _g(op, "kdf", "salt_provenance")
    if salt in {"constant_or_literal", "reused_across_calls"}:
        F.add(VULNERABLE, "missing_password_salt", op.get("id"), op.get("evidence"),
              f"salt is {salt}")
    elif salt == "unknown":
        F.add(NEEDS_REVIEW, "unknown_crypto_semantics", op.get("id"), op.get("evidence"),
              "salt provenance unknown")
    if kdf in {"PBKDF2", "PBKDF2HMAC"}:
        it = _g(op, "kdf", "iterations")
        if it is None:
            F.add(NEEDS_REVIEW, "unknown_crypto_semantics", op.get("id"), op.get("evidence"),
                  "PBKDF2 iterations unknown")
        elif it < 100_000:
            F.add(WEAK, "weak_kdf_parameters", op.get("id"), op.get("evidence"),
                  f"PBKDF2 iterations {it} < 100000")
    if kdf == "BCRYPT":
        cost = _g(op, "kdf", "cost")
        if cost is None:
            F.add(NEEDS_REVIEW, "unknown_crypto_semantics", op.get("id"), op.get("evidence"),
                  "bcrypt cost unknown")
        elif cost < 10:
            F.add(WEAK, "weak_kdf_parameters", op.get("id"), op.get("evidence"),
                  f"bcrypt cost {cost} < 10")


def _check_key_derivation(op, F):
    kdf = _norm(_g(op, "kdf", "name"))
    if _g(op, "key", "provenance") == "from_password_no_kdf":
        F.add(VULNERABLE, "password_fast_hash", op.get("id"), op.get("evidence"),
              "key from password without KDF")
    if kdf not in ACCEPTED_KDFS_FOR_KEYS:
        if kdf in (None, "UNKNOWN"):
            F.add(NEEDS_REVIEW, "unknown_crypto_semantics", op.get("id"), op.get("evidence"),
                  "KDF unknown")
        else:
            F.add(VULNERABLE, "password_fast_hash", op.get("id"), op.get("evidence"),
                  f"{kdf} not an accepted KDF")
    salt = _g(op, "kdf", "salt_provenance")
    if salt in {"constant_or_literal", "reused_across_calls"}:
        F.add(WEAK, "weak_kdf_parameters", op.get("id"), op.get("evidence"), f"salt {salt}")
    elif salt == "unknown":
        F.add(NEEDS_REVIEW, "unknown_crypto_semantics", op.get("id"), op.get("evidence"),
              "salt provenance unknown")
    if kdf in {"PBKDF2", "PBKDF2HMAC"}:
        it = _g(op, "kdf", "iterations")
        if it is None:
            F.add(NEEDS_REVIEW, "unknown_crypto_semantics", op.get("id"), op.get("evidence"),
                  "PBKDF2 iterations unknown")
        elif it < 100_000:
            F.add(WEAK, "weak_kdf_parameters", op.get("id"), op.get("evidence"),
                  f"PBKDF2 iterations {it} < 100000")


def _check_random(op, F):
    if op.get("purpose") not in {"security", "token_generation"}:
        return
    r = _g(op, "randomness", "source")
    if r == "insecure_prng":
        F.add(VULNERABLE, "predictable_randomness", op.get("id"), op.get("evidence"),
              "security randomness from insecure PRNG")
    elif r == "unknown":
        F.add(NEEDS_REVIEW, "unknown_crypto_semantics", op.get("id"), op.get("evidence"),
              "randomness source unknown")


def _check_sign_or_mac(op, F):
    _check_algorithm(op, F)
    _check_key(op, F)
    _check_key_size(op, F)
    if _g(op, "randomness", "source") == "insecure_prng":
        F.add(VULNERABLE, "predictable_randomness", op.get("id"), op.get("evidence"),
              "signature/MAC nonce from insecure PRNG")


def _check_tls_config(op, F):
    cert = _g(op, "tls", "certificate_verification")
    host = _g(op, "tls", "hostname_verification")
    if cert == "disabled" or host == "disabled":
        F.add(VULNERABLE, "tls_verification_disabled", op.get("id"), op.get("evidence"),
              "TLS certificate/hostname verification disabled")
    elif cert == "unknown" or host == "unknown":
        F.add(NEEDS_REVIEW, "unknown_crypto_semantics", op.get("id"), op.get("evidence"),
              "TLS verification status unknown")


def _check_jwt_decode(op, F):
    jwt = op.get("jwt") or {}
    if jwt.get("allows_none") is True:
        F.add(VULNERABLE, "jwt_none_or_signature_disabled", op.get("id"), op.get("evidence"),
              "JWT alg=none allowed")
    if jwt.get("signature_verification_disabled") is True:
        F.add(VULNERABLE, "jwt_none_or_signature_disabled", op.get("id"), op.get("evidence"),
              "JWT signature verification disabled")
    allowed = jwt.get("algorithms_allowed") or []
    if not allowed:
        F.add(NEEDS_REVIEW, "unknown_crypto_semantics", op.get("id"), op.get("evidence"),
              "JWT allowed algorithms unknown")
    elif any(_norm(a) == "NONE" for a in allowed):
        F.add(VULNERABLE, "jwt_none_or_signature_disabled", op.get("id"), op.get("evidence"),
              "JWT allowed algorithms include none")


def _check_verify_event(ev, F):
    st = ev.get("status")
    if st == "checked_and_dominates_use":
        return
    if st in {"checked_but_does_not_dominate_use", "not_checked", "ignored_or_swallowed"}:
        F.add(VULNERABLE, "verify_not_checked", ev.get("id"), ev.get("evidence"),
              f"verification result {st}")
    elif st in (None, "unknown"):
        F.add(NEEDS_REVIEW, "unknown_crypto_semantics", ev.get("id"), ev.get("evidence"),
              "verify dominance unknown")


_OP_DISPATCH = {
    "encrypt": _check_encrypt,
    "decrypt": _check_decrypt,
    "hash": _check_hash,
    "password_hash": _check_password_hash,
    "key_derivation": _check_key_derivation,
    "random": _check_random,
    "sign": _check_sign_or_mac,
    "mac": _check_sign_or_mac,
    "verify": _check_sign_or_mac,
    "tls_config": _check_tls_config,
    "jwt_decode": _check_jwt_decode,
    "key_generation": _check_key,  # key_generation: provenance/size sanity
}


# --- red flags (high-confidence syntactic catches) ----------------------------

_RED_FLAG_TO_FINDING = {
    "weak_algo": ("weak_algorithm", WEAK),
    "ecb_mode": ("ecb_mode", VULNERABLE),
    "jwt_alg_none": ("jwt_none_or_signature_disabled", VULNERABLE),
    "tls_verify_disabled": ("tls_verification_disabled", VULNERABLE),
    "hardcoded_key": ("hardcoded_key_or_secret", VULNERABLE),
    "insecure_random": ("predictable_randomness", VULNERABLE),
    "fast_password_hash": ("password_fast_hash", VULNERABLE),
    "static_or_reused_iv_nonce": ("static_or_reused_iv_nonce", VULNERABLE),
    "verify_not_checked": ("verify_not_checked", VULNERABLE),
    "missing_ciphertext_authentication": ("missing_ciphertext_authentication", VULNERABLE),
}


# --- the checker --------------------------------------------------------------

def classify(facts):
    """Decide the crypto verdict for one function.

    Returns {verdict, findings: [{severity, kind, cwe, operation_id, evidence,
    reason}], error}.
    """
    err = validate(facts)
    if err:
        return {"verdict": ERROR, "findings": [], "error": err}

    F = _Findings()

    for op in facts.get("crypto_operations") or []:
        fn = _OP_DISPATCH.get(op.get("kind"))
        if fn:
            fn(op, F)

    for ev in facts.get("verify_events") or []:
        _check_verify_event(ev, F)

    # Exported parametric/hardcoded return material (helper that hands key-shaped
    # material to a caller): POLYMORPHIC in isolation (resolved at the caller).
    for ret in facts.get("returns") or []:
        if ret.get("material_kind") in {"key", "iv_nonce", "random_token"}:
            prov = ret.get("provenance")
            if prov in {"from_param"}:
                F.add(POLYMORPHIC, "parametric_crypto_material", ret.get("id"),
                      ret.get("evidence"), "exports caller-parametric crypto material")
            elif prov == "hardcoded_literal":
                F.add(POLYMORPHIC, "exported_crypto_material", ret.get("id"),
                      ret.get("evidence"), "exports hardcoded crypto material (vuln at caller use)")

    # Honor explicit red_flags the LLM emitted that the operation checks may not
    # have covered (dedup by (kind, op_id)).
    seen = {(f["kind"], f["operation_id"]) for f in F.items}
    for rf in facts.get("red_flags") or []:
        mapping = _RED_FLAG_TO_FINDING.get(rf.get("kind"))
        if not mapping:
            continue
        kind, sev = mapping
        key = (kind, rf.get("operation_id"))
        if key in seen:
            continue
        seen.add(key)
        F.add(sev, kind, rf.get("operation_id"), rf.get("evidence"), rf.get("reason"))

    verdict = SAFE
    for level in _PRECEDENCE:
        if any(f["severity"] == level for f in F.items):
            verdict = level
            break
    return {"verdict": verdict, "findings": F.items, "error": None}


# --- composition helpers (bottom-up: instantiate callee return provenance) ----

def instantiate_return_material(callee_ret, actual):
    """Resolve a callee return-material's provenance into the caller's context.

    callee_ret: a callee summary `returns[]` entry.
    actual: the caller's actual-arg descriptor for the callee param the return
      depends on (when callee_ret.provenance == from_param), or None.
    Returns a provenance string for the caller's material.
    """
    prov = callee_ret.get("provenance")
    if prov != "from_param":
        return prov  # hardcoded_literal / from_csprng / from_kdf / ... pass through
    if not actual:
        return "unknown"
    sk = actual.get("source_kind")
    if sk == "param":
        return "from_param"
    if sk == "literal":
        return "hardcoded_literal"
    if sk == "config_or_env":
        return "from_config_or_env"
    return "unknown"

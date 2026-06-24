import os
from dotenv import load_dotenv

load_dotenv()

LLM_API_KEY = os.environ.get("LLM_API_KEY", "")
LLM_API_BASE_URL = os.environ.get("LLM_API_BASE_URL", "https://openrouter.ai/api/v1")
LLM_MODEL = os.environ.get("LLM_MODEL", "anthropic/claude-sonnet-4.6")
# OpenCode provider prefix used when invoking `opencode run --model <prefix>/<model>`.
# Must match a provider registered in ~/.config/opencode/opencode.json.
OPENCODE_MODEL_PROVIDER = os.environ.get("OPENCODE_MODEL_PROVIDER", "openrouter")

OPENCODE_SETUP_MODEL = LLM_MODEL
OPENCODE_SPEC_MODEL = LLM_MODEL
OPENCODE_BUG_VALIDATION_MODEL = LLM_MODEL
REASONER_POST_CONDITION_MODEL = LLM_MODEL
REASONER_SPEC_CHECK_MODEL = LLM_MODEL

MAX_SPC_ITER = 5
GRANULARITY = 40
MAX_WORKERS = 10
OPENCODE_MAX_RETRIES = 5

# --- IFC (Information Flow Control) track ---
# Direct-LLM models for the IFC pipeline. Default to LLM_MODEL like the rest.
IFC_FLOW_SIGNATURE_MODEL = LLM_MODEL   # infer per-function parametric flow signature + labels
IFC_FLOW_CHECK_MODEL = LLM_MODEL       # (reserved) secondary checks if needed
MAX_IFC_ITER = 5                       # retry budget for [FLOW]/[VERDICT] tag extraction
# Enforcement policy: treat Unknown/low-confidence labels as High (fail-closed).
IFC_FAIL_CLOSED = True

# --- Access Control (guarded-Hoare) track ---
# Detects missing-authorization / IDOR-BOLA by checking that every sensitive
# operation is dominated by a guard binding the authenticated subject to the
# accessed resource. LLM derives the per-function guarded-Hoare abstraction;
# a deterministic checker decides guard-domination + binding-equality.
AUTHZ_MODEL = LLM_MODEL                 # infer sensitive ops, guards, bindings, obligations
MAX_AUTHZ_ITER = 5                      # retry budget for [AUTHZ_JSON] extraction
# Fail-closed: an unguarded sensitive op with no discharging ancestor is a
# finding; unknown policy enforcement is reported as NEEDS_REVIEW, not SAFE.
AUTHZ_FAIL_CLOSED = True

# --- Integrity Taint (injection) track ---
# Detects injection vulns (SQLi/command-injection/path-traversal/SSRF/XSS/unsafe
# deserialization) — the dual of IFC: source=untrusted-input, sink=sensitive
# operation site, sanitizer=typed endorsement. LLM derives a per-function taint
# signature; a deterministic checker decides source->sink reachability with
# typed-sanitizer matching.
TAINT_MODEL = LLM_MODEL                 # infer tainted sources, sinks, sanitizers, propagation
MAX_TAINT_ITER = 5                      # retry budget for [TAINT_JSON] extraction
# Fail-closed: an unrecognized external input is treated as tainted; an
# unknown-adequacy sanitizer does NOT clear taint (reported, not silently SAFE).
TAINT_FAIL_CLOSED = True

# --- Crypto Misuse track ---
# Detects cryptographic API misuse (weak algo/ECB, hardcoded key, static/reused
# IV-nonce, insecure PRNG, fast password hash, verify-not-checked, TLS verify
# disabled, JWT alg=none) via the CrySL-flavored operation+provenance model. LLM
# derives a per-function crypto signature; a deterministic checker maps
# (op, algorithm, mode, key/iv provenance, randomness, verify status) to findings.
CRYPTO_MODEL = LLM_MODEL                 # infer crypto operations, provenance, verify events
MAX_CRYPTO_ITER = 5                      # retry budget for [CRYPTO_JSON] extraction
# Fail-closed: unknown algorithm/provenance/verify-dominance => NEEDS_REVIEW,
# never silently SAFE.
CRYPTO_FAIL_CLOSED = True

# --- Typestate / Temporal Protocol track ---
# Detects ordering bugs (TOCTOU, CSRF-token-before-state-change, TLS-verify-
# before-use, resource open/close lifecycle, auth-before-privileged-action) by
# running small built-in property automata over an LLM-derived ordered event
# trace. LLM emits observed security-relevant events (tagged with abstract event
# kind + resource + path coverage); a deterministic checker runs the automata.
TYPESTATE_MODEL = LLM_MODEL              # infer ordered security events + resource states
MAX_TYPESTATE_ITER = 5                   # retry budget for [TYPESTATE_JSON] extraction
# Fail-closed: unknown event order / unknown path coverage => NEEDS_REVIEW,
# never silently SAFE.
TYPESTATE_FAIL_CLOSED = True

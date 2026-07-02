"""Plugin registry — the single source of truth for "what plugins exist".

THE CONTRACT: this module is PURE DATA. It must NOT import any plugin class,
`src.prompts`, `src.llm_client`, or anything that pulls `openai`. The zero-
dependency `ifc_viewer.py` (stdlib only) imports this module to learn plugin
labels/verdicts/result dirs, so importing it must stay cheap and side-effect
free. Plugin CLASSES are loaded lazily via `load_plugin_class()` (importlib),
which is only called at run time when the heavy LLM path is actually needed.

Before this module, a new plugin had to be hand-registered in SIX scattered
places (run_plugin.py, eval/run_ours.py, eval/normalize.py, eval/benchmarks.py,
eval/run_llm_baseline.py, ifc_viewer.py). Now a plugin is described ONCE here
(or contributed by an auto-generated plugin package) and every consumer derives
its view from the manifest. Adding a plugin = add a manifest entry + drop the
3 plugin files; no consumer edits.

MANIFEST SCHEMA (per plugin):
  name                : str   — plugin id (matches CLI `run_plugin.py <name>`)
  module              : str   — import path of the plugin module (lazy-loaded)
  class_name          : str   — AnalysisPlugin subclass in that module
  work_subdir         : str   — driver output dir under proj (default fm_agent_<name>)
  results_subdir      : str   — per-function result dir under work_subdir
  label               : str   — human label (viewer dropdown, reports)
  verdicts            : {positive,poly,review,negative}: [str] — scoring vocab
                                (union, in display order, also feeds viewer)
  cwes                : [str] — CWE ids this plugin targets (canonical "CWE-N")
  cwe_notes           : {cwe: short gloss} — for the LLM-baseline scope prompt
  property_nl         : str   — one-line NL description of the target property
  benchmark_categories: [str] — OWASP category keys (empty if none)

All scattered consumers now read from here; see helper accessors at the bottom.
"""

from __future__ import annotations

import importlib
from typing import Dict, List, Sequence


# --- the manifests (pure data; lossless migration of the 6 touchpoints) ------

PLUGIN_MANIFESTS: Dict[str, dict] = {
    "ifc": {
        "name": "ifc",
        "module": "src.plugins.ifc",
        "class_name": "IfcPlugin",
        "work_subdir": "fm_agent_ifc",
        # NOTE: legacy ifc_main.py writes "ifc_results"; the unified run_plugin.py
        # path writes the driver default "results". The viewer tolerates both
        # (see ifc_viewer._results_dir); the canonical name here is "results".
        "results_subdir": "results",
        "label": "IFC (information flow)",
        "verdicts": {
            "positive": ["LEAK"],
            "poly": ["POLYMORPHIC"],
            "review": [],
            "negative": ["SECURE", "DECLASSIFIED"],
        },
        "cwes": ["CWE-200", "CWE-209", "CWE-532"],
        "cwe_notes": {
            "CWE-200": "exposure of sensitive information",
            "CWE-209": "information exposure through an error message",
            "CWE-532": "insertion of sensitive information into a log",
        },
        "property_nl": (
            "sensitive-information exposure (a secret or sensitive value flowing "
            "to a public / lower-trust output such as a response, log, or error "
            "message)"
        ),
        "benchmark_categories": [],
    },
    "authz": {
        "name": "authz",
        "module": "src.plugins.authz",
        "class_name": "AuthzPlugin",
        "work_subdir": "fm_agent_authz",
        "results_subdir": "results",
        "label": "Access control (guarded-Hoare)",
        "verdicts": {
            "positive": ["VULNERABLE"],
            "poly": [],
            "review": ["NEEDS_REVIEW"],
            "negative": ["SAFE"],
        },
        "cwes": ["CWE-306", "CWE-639", "CWE-862", "CWE-863"],
        "cwe_notes": {
            "CWE-306": "missing authentication for critical function",
            "CWE-639": "authorization bypass via user-controlled key / IDOR",
            "CWE-862": "missing authorization",
            "CWE-863": "incorrect authorization",
        },
        "property_nl": (
            "broken access control / missing authorization (a sensitive operation "
            "that fails to verify the caller is authorized for the specific "
            "resource it acts on)"
        ),
        "benchmark_categories": [],
    },
    "taint": {
        "name": "taint",
        "module": "src.plugins.taint",
        "class_name": "TaintPlugin",
        "work_subdir": "fm_agent_taint",
        "results_subdir": "results",
        "label": "Integrity taint (injection)",
        "verdicts": {
            "positive": ["VULNERABLE"],
            "poly": ["POLYMORPHIC"],
            "review": [],
            "negative": ["SANITIZED", "SAFE"],
        },
        "cwes": ["CWE-22", "CWE-78", "CWE-88", "CWE-79", "CWE-89", "CWE-90",
                 "CWE-94", "CWE-502", "CWE-601", "CWE-611", "CWE-643", "CWE-918"],
        "cwe_notes": {
            "CWE-22": "path traversal",
            "CWE-78": "OS command injection",
            "CWE-88": "argument injection",
            "CWE-79": "XSS",
            "CWE-89": "SQL injection",
            "CWE-90": "LDAP injection",
            "CWE-94": "code injection",
            "CWE-502": "unsafe deserialization",
            "CWE-601": "open redirect",
            "CWE-611": "XXE",
            "CWE-643": "XPath injection",
            "CWE-918": "SSRF",
        },
        "property_nl": (
            "injection / tainted-data-flow vulnerabilities (untrusted input "
            "reaching a sensitive sink without adequate sanitization)"
        ),
        "benchmark_categories": ["pathtraver", "sqli", "cmdi", "xss",
                                 "deserialization", "codeinj", "redirect",
                                 "ldapi", "xpathi", "xxe"],
    },
    "crypto": {
        "name": "crypto",
        "module": "src.plugins.crypto",
        "class_name": "CryptoPlugin",
        "work_subdir": "fm_agent_crypto",
        "results_subdir": "results",
        "label": "Crypto misuse",
        "verdicts": {
            "positive": ["VULNERABLE", "WEAK"],
            "poly": ["POLYMORPHIC"],
            "review": ["NEEDS_REVIEW"],
            "negative": ["SAFE"],
        },
        "cwes": ["CWE-321", "CWE-326", "CWE-327", "CWE-328", "CWE-330",
                 "CWE-338", "CWE-798"],
        "cwe_notes": {
            "CWE-321": "hardcoded key",
            "CWE-326": "inadequate key strength",
            "CWE-327": "broken/risky algorithm",
            "CWE-328": "weak hash",
            "CWE-330": "weak/predictable PRNG",
            "CWE-338": "weak PRNG for security",
            "CWE-798": "hardcoded credentials",
        },
        "property_nl": (
            "cryptographic misuse (weak algorithms, weak/predictable randomness, "
            "hardcoded keys/credentials, weak key strength)"
        ),
        "benchmark_categories": ["hash", "weakrand"],
    },
    "typestate": {
        "name": "typestate",
        "module": "src.plugins.typestate",
        "class_name": "TypestatePlugin",
        "work_subdir": "fm_agent_typestate",
        "results_subdir": "results",
        "label": "Typestate / temporal",
        "verdicts": {
            "positive": ["VULNERABLE"],
            "poly": ["POLYMORPHIC"],
            "review": ["NEEDS_REVIEW"],
            "negative": ["SAFE"],
        },
        "cwes": ["CWE-295", "CWE-352", "CWE-367", "CWE-772"],
        "cwe_notes": {
            "CWE-295": "improper certificate validation",
            "CWE-352": "CSRF",
            "CWE-367": "TOCTOU race condition",
            "CWE-772": "missing release of resource",
        },
        "property_nl": (
            "temporal / ordering security defects (a security-critical event "
            "missing or out of order: missing CSRF protection, disabled/absent "
            "certificate validation, TOCTOU race, or an unreleased resource)"
        ),
        "benchmark_categories": [],
    },
    "resource": {
        "name": "resource",
        "module": "src.plugins.resource",
        "class_name": "ResourcePlugin",
        "work_subdir": "fm_agent_resource",
        "results_subdir": "results",
        "label": "Resource exhaustion (DoS)",
        "verdicts": {
            "positive": ["VULNERABLE"],
            "poly": ["POLYMORPHIC"],
            "review": [],
            "negative": ["BOUNDED", "SAFE"],
        },
        "cwes": ["CWE-400", "CWE-770", "CWE-674", "CWE-1333", "CWE-409",
                 "CWE-789", "CWE-834"],
        "cwe_notes": {
            "CWE-400": "uncontrolled resource consumption",
            "CWE-770": "allocation of resources without limits or throttling",
            "CWE-674": "uncontrolled recursion",
            "CWE-1333": "inefficient regular expression complexity (ReDoS)",
            "CWE-409": "improper handling of highly compressed data (decompression bomb)",
            "CWE-789": "memory allocation with excessive size value",
            "CWE-834": "excessive iteration",
        },
        "property_nl": (
            "resource-exhaustion / denial of service (an attacker-controllable "
            "magnitude — size, count, depth, or ratio — driving a costly "
            "operation without a dominating bound: unbounded allocation/read, "
            "decompression bomb, ReDoS, uncontrolled recursion or loops)"
        ),
        "benchmark_categories": [],
    },
    "authn": {
        "name": "authn",
        "module": "src.plugins.authn",
        "class_name": "AuthnPlugin",
        "work_subdir": "fm_agent_authn",
        "results_subdir": "results",
        "label": "Authentication integrity",
        "verdicts": {
            "positive": ["VULNERABLE"],
            "poly": [],
            "review": ["NEEDS_REVIEW"],
            "negative": ["SAFE"],
        },
        "cwes": ["CWE-287", "CWE-384", "CWE-613", "CWE-522", "CWE-294",
                 "CWE-620", "CWE-640"],
        "cwe_notes": {
            "CWE-287": "improper authentication",
            "CWE-384": "session fixation",
            "CWE-613": "insufficient session expiration",
            "CWE-522": "insufficiently protected credentials",
            "CWE-294": "authentication bypass by capture-replay",
            "CWE-620": "unverified password change",
            "CWE-640": "weak password recovery mechanism",
        },
        "property_nl": (
            "improper authentication (a protected operation running without the "
            "subject's identity being genuinely verified, or a session/credential "
            "handled so it can be fixed, replayed, or never expires: missing/weak/"
            "asserted-only authentication, session fixation, insufficient session "
            "expiration)"
        ),
        "benchmark_categories": [],
    },
}


# --- accessors (all consumers go through these) ------------------------------

def plugin_names() -> List[str]:
    """All registered plugin names, sorted for stable display."""
    return sorted(PLUGIN_MANIFESTS)


def get_manifest(name: str) -> dict:
    """Return the manifest dict for a plugin, or raise KeyError."""
    return PLUGIN_MANIFESTS[name]


def has_plugin(name: str) -> bool:
    return name in PLUGIN_MANIFESTS


def all_verdicts(name: str) -> List[str]:
    """Union of a plugin's verdicts in display order + ERROR (always last).

    Order: positive, then poly, then review, then negative, then ERROR. ERROR is
    implicit for every plugin (fail-closed) and is appended if not already named.
    """
    v = PLUGIN_MANIFESTS[name]["verdicts"]
    out: List[str] = []
    for bucket in ("positive", "poly", "review", "negative"):
        for x in v.get(bucket, []):
            if x not in out:
                out.append(x)
    if "ERROR" not in out:
        out.append("ERROR")
    return out


def positive_verdicts(name: str) -> set:
    """Verdicts that count as 'flagged' for detection scoring (positive + poly +
    review + ERROR), mirroring eval.normalize.collapse_ours semantics."""
    v = PLUGIN_MANIFESTS[name]["verdicts"]
    out = set(v.get("positive", [])) | set(v.get("poly", [])) | set(v.get("review", []))
    out.add("ERROR")  # fail-closed
    return out


def cwe_scope_string(name: str) -> str:
    """Render the CWE list + glosses as one string for the LLM-baseline prompt,
    e.g. 'CWE-89 (SQL injection), CWE-78 (OS command injection), ...'."""
    m = PLUGIN_MANIFESTS[name]
    notes = m.get("cwe_notes", {})
    parts = []
    for c in m["cwes"]:
        gloss = notes.get(c)
        parts.append(f"{c} ({gloss})" if gloss else c)
    return ", ".join(parts)


def load_plugin_class(name: str):
    """Lazily import and return the AnalysisPlugin subclass for `name`.

    This is the ONLY function here that triggers the heavy import chain
    (plugin module -> prompts -> llm_client -> openai). Callers that only need
    metadata (viewer, scoring) must use the pure-data accessors above instead.
    """
    if name not in PLUGIN_MANIFESTS:
        raise KeyError(f"unknown plugin '{name}'. Known: {', '.join(plugin_names())}")
    m = PLUGIN_MANIFESTS[name]
    mod = importlib.import_module(m["module"])
    return getattr(mod, m["class_name"])

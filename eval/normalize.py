"""Normalizer — map heterogeneous tool outputs onto a common per-case unit.

The fair-comparison problem: three tools emit three different shapes.
  - FM-Agent (ours): per-FUNCTION json with `verdict` + `findings[].data.cwe`.
  - Bandit:          per-LINE json `results[].{test_id, issue_cwe.id, line_number}`.
  - Semgrep:         per-LINE json `results[].extra.metadata.cwe[]` (list of strings).

A benchmark CASE is the unit of comparison (one .py file with one ground-truth
label + expected CWE). This module collapses each tool's raw output for a case
into a `Detection`:
    detected : did the tool flag this case as vulnerable at all?
    cwes     : the set of canonical CWE ids the tool attributed to the case.
    matched  : detected AND (expected CWE shares a family with some detected CWE).

Two scoring views fall out of this (see score.py):
  - CWE-aware:  a TP requires `matched` (right bug, right category).
  - detection:  a TP requires only `detected` (right bug, any category) — fairer
                to tools that report a generic finding without precise CWE.
"""

import json
import re
from dataclasses import dataclass, field


# --- CWE family grouping ------------------------------------------------------
# CWEs form families: a tool that flags a parent/sibling on the right case still
# "found the bug". Each set is a canonical equivalence class; matching is
# membership in the SAME set. Conservative — only well-established synonyms.
INJECTION_FAMILIES = [
    {"CWE-89"},                                  # SQL injection
    {"CWE-78", "CWE-77", "CWE-88"},              # OS command / argument injection
    {"CWE-79", "CWE-80", "CWE-83"},              # XSS variants
    {"CWE-22", "CWE-23", "CWE-36"},              # path traversal
    {"CWE-94", "CWE-95", "CWE-96"},              # code injection / eval
    {"CWE-502"},                                 # deserialization
    {"CWE-601"},                                 # open redirect
    {"CWE-90"},                                  # LDAP injection
    {"CWE-643"},                                 # XPath injection
    {"CWE-611", "CWE-827"},                      # XXE
    {"CWE-918"},                                 # SSRF
    {"CWE-74"},                                  # generic injection parent
]

# Crypto-misuse families (crypto plugin). The OWASP benchmark labels weak hash as
# CWE-328 and insecure PRNG as CWE-330, while our crypto plugin emits the broader
# parents CWE-327 (broken/weak algorithm) and CWE-338 (weak PRNG for security);
# treat each parent/child pair as one family so a correct-category hit matches.
CRYPTO_FAMILIES = [
    {"CWE-327", "CWE-328", "CWE-326"},           # broken/weak crypto algorithm + weak hash + inadequate strength
    {"CWE-330", "CWE-338", "CWE-340"},           # insufficient / predictable randomness
    {"CWE-916", "CWE-759", "CWE-760"},           # weak password hash / missing salt
    {"CWE-321", "CWE-798"},                       # hardcoded key / credential
    {"CWE-329", "CWE-323"},                       # static / reused IV-nonce
    {"CWE-347"},                                  # improper signature verification
    {"CWE-295"},                                  # improper cert validation
    {"CWE-345", "CWE-353"},                       # missing ciphertext authentication
]

CWE_FAMILIES = INJECTION_FAMILIES + CRYPTO_FAMILIES

# CWE-74 (generic injection) is a parent of most of the injection set; treat a
# tool that emits the generic parent as matching any injection child (charitable
# to tools that only report "injection" without a specific child). Derived from
# INJECTION_FAMILIES ONLY so the charity never leaks into crypto matching.
_INJECTION_CHILDREN = {
    c for fam in INJECTION_FAMILIES for c in fam
} - {"CWE-74"}


def _canon_cwe(raw):
    """Normalize any CWE representation to 'CWE-<n>' or None.

    Accepts: 89, '89', 'CWE-89', 'CWE-89: Improper ...', 'cwe-89'.
    """
    if raw is None:
        return None
    if isinstance(raw, int):
        return f"CWE-{raw}"
    s = str(raw).strip()
    m = re.search(r"(\d+)", s)
    return f"CWE-{m.group(1)}" if m else None


def cwe_matches(expected, detected_set):
    """True if `expected` shares a family with ANY cwe in `detected_set`.

    Generic-injection parent CWE-74 matches any injection child (and vice versa).
    """
    expected = _canon_cwe(expected)
    if not expected:
        return False
    det = {_canon_cwe(c) for c in detected_set if _canon_cwe(c)}
    if expected in det:
        return True
    # family membership
    for fam in CWE_FAMILIES:
        if expected in fam and (det & fam):
            return True
    # generic parent charity
    if "CWE-74" in det and expected in _INJECTION_CHILDREN:
        return True
    if expected == "CWE-74" and (det & _INJECTION_CHILDREN):
        return True
    return False


@dataclass
class Detection:
    """A tool's collapsed result for one case."""
    case_id: str
    tool: str
    detected: bool
    cwes: set = field(default_factory=set)
    raw_count: int = 0          # number of underlying findings
    evidence: list = field(default_factory=list)  # short strings for audit

    def matched(self, expected_cwe):
        return self.detected and cwe_matches(expected_cwe, self.cwes)


# --- per-tool collapse --------------------------------------------------------

# Per-plugin verdict vocabularies. Each plugin emits a different verdict set; the
# "positive" verdicts are those that count as "the tool flagged this case as a
# finding" for detection scoring. POLYMORPHIC = parametric (real issue surfaces at
# a caller); on a standalone benchmark case with no caller we conservatively treat
# it as a detection. NEEDS_REVIEW is fail-closed → also a detection (the tool
# refused to clear the case). The "negative" verdicts mean affirmatively cleared.
#
# Verdicts confirmed from src/<plugin>_reasoner.py:
#   taint:     VULNERABLE | POLYMORPHIC | SANITIZED | SAFE | ERROR
#   crypto:    VULNERABLE | WEAK | POLYMORPHIC | NEEDS_REVIEW | SAFE | ERROR
#   authz:     VULNERABLE | NEEDS_REVIEW | SAFE | ERROR
#   ifc:       LEAK | DECLASSIFIED | POLYMORPHIC | SECURE | ERROR
#   typestate: VULNERABLE | POLYMORPHIC | NEEDS_REVIEW | SAFE | ERROR
PLUGIN_VERDICTS = {
    "taint":     {"positive": {"VULNERABLE"}, "poly": {"POLYMORPHIC"},
                  "negative": {"SAFE", "SANITIZED"}},
    "crypto":    {"positive": {"VULNERABLE", "WEAK"}, "poly": {"POLYMORPHIC"},
                  "review": {"NEEDS_REVIEW"}, "negative": {"SAFE"}},
    "authz":     {"positive": {"VULNERABLE"}, "poly": set(),
                  "review": {"NEEDS_REVIEW"}, "negative": {"SAFE"}},
    "ifc":       {"positive": {"LEAK"}, "poly": {"POLYMORPHIC"},
                  "negative": {"SECURE", "DECLASSIFIED"}},
    "typestate": {"positive": {"VULNERABLE"}, "poly": {"POLYMORPHIC"},
                  "review": {"NEEDS_REVIEW"}, "negative": {"SAFE"}},
}

# Back-compat alias used by older taint call sites / tests.
OURS_POSITIVE = PLUGIN_VERDICTS["taint"]["positive"]


def collapse_ours(case_id, func_results, plugin="taint",
                  count_polymorphic=True, count_review=True):
    """Collapse FM-Agent per-function result dicts for ONE case into a Detection.

    plugin: which plugin's verdict vocabulary to use (see PLUGIN_VERDICTS).
    func_results: list of parsed result json dicts (one per analyzed function in
    the case file). A case is flagged if ANY function emits a positive verdict
    (or POLYMORPHIC when count_polymorphic, or NEEDS_REVIEW when count_review).
    ERROR is fail-closed → treated as a (conservative) detection but flagged in
    evidence for manual review.
    """
    vocab = PLUGIN_VERDICTS.get(plugin, PLUGIN_VERDICTS["taint"])
    positive = vocab["positive"]
    poly = vocab.get("poly", set())
    review = vocab.get("review", set())
    cwes, evid, raw = set(), [], 0
    detected = False
    for r in func_results:
        verdict = r.get("verdict", "?")
        for f in r.get("findings", []) or []:
            raw += 1
            c = _canon_cwe((f.get("data") or {}).get("cwe"))
            if c:
                cwes.add(c)
        if verdict in positive:
            detected = True
            evid.append(f"{r.get('rel', '?')}:{verdict}")
        elif verdict in poly and count_polymorphic:
            detected = True
            evid.append(f"{r.get('rel', '?')}:{verdict}")
        elif verdict in review and count_review:
            detected = True
            evid.append(f"{r.get('rel', '?')}:{verdict}")
        elif verdict == "ERROR":
            detected = True  # fail-closed
            evid.append(f"{r.get('rel', '?')}:ERROR(fail-closed)")
    return Detection(case_id, "fm-agent", detected, cwes, raw, evid[:5])


def collapse_bandit(case_id, raw_json):
    """Collapse Bandit JSON output for ONE case into a Detection.

    Bandit results[].issue_cwe.id is an int CWE (may be 0/None for some tests).
    """
    results = (raw_json or {}).get("results", []) or []
    cwes, evid = set(), []
    for r in results:
        cid = _canon_cwe((r.get("issue_cwe") or {}).get("id"))
        if cid:
            cwes.add(cid)
        evid.append(f"{r.get('test_id', '?')}@L{r.get('line_number', '?')}")
    return Detection(case_id, "bandit", bool(results), cwes, len(results), evid[:5])


def collapse_semgrep(case_id, raw_json):
    """Collapse Semgrep JSON output for ONE case into a Detection.

    Semgrep results[].extra.metadata.cwe is a list of 'CWE-89: ...' strings.
    """
    results = (raw_json or {}).get("results", []) or []
    cwes, evid = set(), []
    for r in results:
        meta = (r.get("extra") or {}).get("metadata") or {}
        for c in meta.get("cwe", []) or []:
            cid = _canon_cwe(c)
            if cid:
                cwes.add(cid)
        evid.append((r.get("check_id", "?") or "?").split(".")[-1][:40])
    return Detection(case_id, "semgrep", bool(results), cwes, len(results), evid[:5])


if __name__ == "__main__":
    # self-test the CWE matcher
    assert cwe_matches("CWE-89", {"CWE-89"})
    assert cwe_matches("CWE-78", {"CWE-77"})        # family sibling
    assert cwe_matches("CWE-79", {"CWE-80"})
    assert cwe_matches("CWE-89", {"CWE-74"})        # generic parent charity
    assert not cwe_matches("CWE-89", {"CWE-22"})    # different family
    assert not cwe_matches("CWE-89", set())         # nothing detected
    assert cwe_matches("CWE-22", {"CWE-89", "CWE-22"})  # one of several
    print("normalize.py self-test: all CWE-family assertions passed")

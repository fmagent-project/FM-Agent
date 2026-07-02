"""Stage 3: label-quality audit + filtering for CVE-curated cases.

The hard truth about CVE-fix-commit curation (CVEfixes reports ~48% function-
level label accuracy on its Python slice): "a function changed in a security
commit" is NOT the same as "this function is the vulnerable locus". Security
commits routinely co-change incidental functions (__repr__, imports, helpers,
docstrings, changelog-adjacent code). If we keep those, the `before` case is
labeled vulnerable but contains no vulnerability -> a poisoned benchmark.

This stage applies deterministic, conservative HEURISTIC filters to drop the
obviously-noisy pairs, and flags the rest for sampling. It does NOT claim to
produce perfect labels -- it raises precision of the corpus and quantifies the
residual noise honestly (a sample is hand-audited separately).

Filters (drop a pair if ANY fires):
  1. dunder/boilerplate functions (__repr__, __str__, __init__ with trivial diff,
     __eq__, etc.) -- almost never the security locus.
  2. trivial before/after diff (only whitespace / comments / a logging string) --
     too ambiguous to label.
  3. before-function body has NO security-relevant token for its CWE family
     (e.g. an authz case whose before-func never touches request/user/permission
     /query is almost certainly an incidental co-change).
  4. before == after after normalization (extractor caught a formatting-only change).

Output: cve_cases.filtered.jsonl (kept) + cve_cases.dropped.jsonl (with reason),
plus a per-CWE retention report so we can see how much survived.
"""

import argparse
import json
import os
import re
from collections import defaultdict

# functions that are essentially never the vulnerable locus
_BOILERPLATE = {
    "__repr__", "__str__", "__eq__", "__hash__", "__ne__", "__lt__", "__gt__",
    "__len__", "__iter__", "__next__", "__enter__", "__exit__", "__del__",
    "__copy__", "__deepcopy__", "__getstate__", "__setstate__", "__format__",
    "__reduce__", "main", "setup", "__init_subclass__",
}

# per-plugin "this code plausibly touches the property" token sets. A before-func
# that contains NONE of these is very likely an incidental co-change.
_RELEVANCE_TOKENS = {
    "authz": (r"request|session|current_user|user_id|owner|permission|authoriz|"
              r"authenticate|login|role|admin|is_staff|abort\(|403|401|access|"
              r"tenant|get_object|query|filter\(|\.get\(|principal|acl|grant"),
    "ifc": (r"log|logger|logging|print\(|debug|error|exception|traceback|repr\(|"
            r"password|secret|token|key|credential|api_key|authorization|cookie|"
            r"response|render|format|message|detail|stack"),
    "typestate": (r"verify|ssl|cert|tls|verify=|CERT_|csrf|token|os\.path|exists|"
                  r"open\(|close\(|with |race|lock|tempfile|mkstemp|chmod|"
                  r"check|validate|hostname|request|\.acquire|\.release"),
}

_COMMENT_RE = re.compile(r"#.*$", re.M)
_WS_RE = re.compile(r"\s+")


def _norm_code(src):
    """Strip comments + collapse whitespace for diff-significance checks."""
    return _WS_RE.sub(" ", _COMMENT_RE.sub("", src or "")).strip()


def _read(path):
    try:
        return open(path).read()
    except OSError:
        return ""


def _func_of(case):
    """Function name for a case: prefer meta.func, else parse from the id.

    id shape: 'cve:<CVE>__<file>__<func>__before'  -> func is the 2nd-from-last
    '__'-delimited segment of the id (after stripping the 'before'/'after' tail).
    """
    f = (case.get("meta") or {}).get("func")
    if f:
        return f
    cid = case.get("id", "")
    parts = cid.split("__")
    if len(parts) >= 2 and parts[-1] in ("before", "after"):
        return parts[-2]
    return ""


def audit_pair(before_case, after_case_by_id):
    """Return (keep: bool, reason: str|None) for a vulnerable (before) case."""
    func = _func_of(before_case)
    plugin = before_case["category"]
    before_src = _read(before_case["path"])

    # 1. boilerplate function name
    if func in _BOILERPLATE:
        return False, f"boilerplate_func:{func}"

    # 1b. test functions are never a vulnerability locus (the file-path test
    # filter in stage 2 misses test functions living in non-test files).
    if func.startswith("test_") or func == "test" or func.startswith("_test"):
        return False, f"test_func:{func}"

    # 4. before vs after identical after normalization (if we have the after)
    after_id = before_case["id"].replace("__before", "__after")
    after_case = after_case_by_id.get(after_id)
    if after_case:
        after_src = _read(after_case["path"])
        if _norm_code(before_src) == _norm_code(after_src):
            return False, "no_significant_diff"

    # 2. before body too trivial to host a vuln (e.g. < 2 statements)
    body = _norm_code(before_src)
    if len(body) < 40:
        return False, "trivial_body"

    # 3. relevance: before code must touch the property the CWE is about
    pat = _RELEVANCE_TOKENS.get(plugin)
    if pat and not re.search(pat, before_src, re.I):
        return False, f"no_{plugin}_relevance_token"

    return True, None


def main():
    ap = argparse.ArgumentParser(description="Label-quality audit/filter (stage 3)")
    ap.add_argument("--manifest", default="cve_cases.jsonl")
    ap.add_argument("--kept", default="cve_cases.filtered.jsonl")
    ap.add_argument("--dropped", default="cve_cases.dropped.jsonl")
    args = ap.parse_args()

    cases = [json.loads(l) for l in open(args.manifest) if l.strip()]
    by_id = {c["id"]: c for c in cases}

    kept, dropped = [], []
    drop_reasons = defaultdict(int)
    # audit vulnerable (before) cases; their paired after follows the kept decision
    for c in cases:
        if not c["label"]:
            continue  # after-cases ride along with their before
        keep, reason = audit_pair(c, by_id)
        if keep:
            kept.append(c)
            after = by_id.get(c["id"].replace("__before", "__after"))
            if after:
                kept.append(after)
        else:
            dropped.append({**c, "drop_reason": reason})
            drop_reasons[reason] += 1

    with open(args.kept, "w") as f:
        for c in kept:
            f.write(json.dumps(c) + "\n")
    with open(args.dropped, "w") as f:
        for c in dropped:
            f.write(json.dumps(c) + "\n")

    n_vuln_in = sum(1 for c in cases if c["label"])
    n_vuln_kept = sum(1 for c in kept if c["label"])
    print(f"vulnerable cases: {n_vuln_in} in -> {n_vuln_kept} kept "
          f"({n_vuln_kept/n_vuln_in*100:.0f}% retention)")
    print(f"total kept (incl. paired safe): {len(kept)}")
    print("drop reasons:")
    for r, n in sorted(drop_reasons.items(), key=lambda x: -x[1]):
        print(f"  {n:4d}  {r}")
    # per-plugin retention
    by_plugin = defaultdict(lambda: [0, 0])
    for c in cases:
        if c["label"]:
            by_plugin[c["category"]][0] += 1
    for c in kept:
        if c["label"]:
            by_plugin[c["category"]][1] += 1
    print("per-plugin vulnerable retention:")
    for p, (i, k) in sorted(by_plugin.items()):
        print(f"  {p:10s} {k}/{i}")
    print(f"wrote {args.kept} + {args.dropped}")


if __name__ == "__main__":
    main()

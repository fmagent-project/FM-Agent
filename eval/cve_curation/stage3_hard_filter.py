"""Stage 3 (HARD variant): label-quality filter for WHOLE-FILE cases.

Unlike the easy-corpus stage3 (which drops a single-function case by its function
name), a hard case is an ENTIRE file with many functions. We cannot drop the file
for being named __repr__. Instead we judge label quality by the CHANGED functions
(the true fix locus, recorded in meta.changed_funcs):

  drop a (before-file) case if ALL its changed functions are noise, i.e. every
  changed function is boilerplate/test/trivial, OR the changed-function bodies
  together carry NO token relevant to the plugin's property (very likely an
  incidental co-change, not the vulnerable locus).

This preserves the interprocedural challenge (we keep the whole multi-function
file) while removing pairs whose `before` is mislabeled vulnerable. Covers all 7
plugins (the easy stage3 only had authz/ifc/typestate).

Output: <manifest>.filtered.jsonl (kept) + .dropped.jsonl (with reason), plus a
per-plugin retention report. The paired `after` rides along with its kept `before`.
"""

import argparse
import json
import os
import re
from collections import defaultdict

_BOILERPLATE = {
    "__repr__", "__str__", "__eq__", "__hash__", "__ne__", "__lt__", "__gt__",
    "__len__", "__iter__", "__next__", "__enter__", "__exit__", "__del__",
    "__copy__", "__deepcopy__", "__format__", "__reduce__", "__init_subclass__",
}

# per-plugin relevance tokens; a changed-func body with NONE is likely incidental.
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
    "taint": (r"request|input|argv|environ|os\.system|subprocess|popen|eval\(|"
              r"exec\(|execute|cursor|query|sql|render|template|open\(|pickle|"
              r"yaml|marshal|redirect|urlopen|requests\.|format|%|\.join|f\""),
    "crypto": (r"md5|sha1|sha256|hashlib|des\b|rc4|ecb|cipher|aes|rsa|crypt|"
               r"random|urandom|secrets|token|key|iv|nonce|salt|hmac|jwt|"
               r"ssl|cert|password|hash|digest|encrypt|decrypt|sign"),
    "resource": (r"read\(|recv|len\(|range\(|\*\s*\d|bytes\(|bytearray|zlib|gzip|"
                 r"bz2|lzma|zipfile|tarfile|decompress|extract|re\.(match|search|"
                 r"compile|sub)|recursion|while |for |size|limit|max|count|depth|"
                 r"content-length|chunk|\.json\(|loads\("),
    "authn": (r"password|passwd|login|authenticate|session|token|jwt|mfa|otp|"
              r"api_key|credential|checkpw|check_password|verify|bcrypt|hmac|"
              r"compare_digest|==|request|user|cookie|expire|regenerate|cycle_key|"
              r"set_password|reset|oauth"),
}

_COMMENT_RE = re.compile(r"#.*$", re.M)
_WS_RE = re.compile(r"\s+")


def _norm_code(src):
    return _WS_RE.sub(" ", _COMMENT_RE.sub("", src or "")).strip()


def _read(path):
    try:
        return open(path, errors="replace").read()
    except OSError:
        return ""


def _extract_changed_bodies(src, changed_funcs):
    """Best-effort: pull the source slices of the changed functions from the file
    (so relevance is judged on the FIX LOCUS, not the whole file)."""
    if not changed_funcs:
        return src  # no locus info -> judge whole file
    lines = src.splitlines()
    bodies = []
    names = set(changed_funcs)
    i = 0
    fn_re = re.compile(r"^(\s*)(?:async\s+)?def\s+(\w+)\s*\(")
    while i < len(lines):
        m = fn_re.match(lines[i])
        if m and m.group(2) in names:
            indent = len(m.group(1))
            j = i + 1
            while j < len(lines):
                ln = lines[j]
                if ln.strip() and (len(ln) - len(ln.lstrip())) <= indent and \
                        not ln.lstrip().startswith(("#", '"""', "'''", ")")):
                    break
                j += 1
            bodies.append("\n".join(lines[i:j]))
            i = j
        else:
            i += 1
    return "\n".join(bodies) if bodies else src


def audit_case(before_case, after_by_id):
    """Return (keep: bool, reason: str|None) for a vulnerable (before) whole-file case."""
    plugin = before_case["category"]
    meta = before_case.get("meta") or {}
    changed = meta.get("changed_funcs") or []

    # 1. all changed funcs are boilerplate/test -> incidental
    non_boiler = [f for f in changed
                  if f not in _BOILERPLATE and not f.startswith(("test_", "_test"))
                  and f != "test"]
    if changed and not non_boiler:
        return False, "all_changed_boilerplate"

    before_src = _read(before_case["path"])

    # 2. before vs after identical after normalization (formatting-only)
    after = after_by_id.get(before_case["id"].replace("__before", "__after"))
    if after:
        if _norm_code(before_src) == _norm_code(_read(after["path"])):
            return False, "no_significant_diff"

    # 3. relevance: the CHANGED-function bodies must touch the plugin's property
    locus = _extract_changed_bodies(before_src, non_boiler or changed)
    body = _norm_code(locus)
    if len(body) < 40:
        return False, "trivial_locus"
    pat = _RELEVANCE_TOKENS.get(plugin)
    if pat and not re.search(pat, locus, re.I):
        return False, f"no_{plugin}_relevance_token"

    return True, None


def main():
    ap = argparse.ArgumentParser(description="Label-quality filter for whole-file cases (stage 3 HARD)")
    ap.add_argument("--manifest", required=True)
    ap.add_argument("--kept", default=None)
    ap.add_argument("--dropped", default=None)
    args = ap.parse_args()
    kept_path = args.kept or args.manifest.replace(".jsonl", ".filtered.jsonl")
    dropped_path = args.dropped or args.manifest.replace(".jsonl", ".dropped.jsonl")

    cases = [json.loads(l) for l in open(args.manifest) if l.strip()]
    by_id = {c["id"]: c for c in cases}

    kept, dropped = [], []
    reasons = defaultdict(int)
    for c in cases:
        if not c["label"]:
            continue  # after rides along
        keep, reason = audit_case(c, by_id)
        if keep:
            kept.append(c)
            after = by_id.get(c["id"].replace("__before", "__after"))
            if after:
                kept.append(after)
        else:
            dropped.append({**c, "drop_reason": reason})
            reasons[reason] += 1

    with open(kept_path, "w") as f:
        for c in kept:
            f.write(json.dumps(c) + "\n")
    with open(dropped_path, "w") as f:
        for c in dropped:
            f.write(json.dumps(c) + "\n")

    n_in = sum(1 for c in cases if c["label"])
    n_kept = sum(1 for c in kept if c["label"])
    print(f"vulnerable cases: {n_in} in -> {n_kept} kept ({n_kept*100//max(1,n_in)}% retention)")
    print(f"total kept (incl paired safe): {len(kept)}")
    print("drop reasons:")
    for r, n in sorted(reasons.items(), key=lambda x: -x[1]):
        print(f"  {n:4d}  {r}")
    byp = defaultdict(lambda: [0, 0])
    for c in cases:
        if c["label"]:
            byp[c["category"]][0] += 1
    for c in kept:
        if c["label"]:
            byp[c["category"]][1] += 1
    print("per-plugin vulnerable retention:")
    for p, (i, k) in sorted(byp.items()):
        print(f"  {p:10s} {k}/{i}")
    print(f"wrote {kept_path} + {dropped_path}")


if __name__ == "__main__":
    main()

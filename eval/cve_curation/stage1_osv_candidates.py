"""Stage 1 of the CVE->benchmark curation pipeline: OSV candidate extraction.

Reads the OSV PyPI bulk dump (one JSON per advisory) and emits a candidate list
of records that (a) carry one of our target CWEs and (b) have a locatable fix
(a GitHub commit URL in references, and/or an ECOSYSTEM fixed-version we can
resolve to a commit later).

Output: candidates.jsonl — one line per (advisory) with the fields stage 2 needs:
  osv_id, cve, cwes (intersected with targets), package, repo, commit_shas[],
  fixed_versions[], introduced_versions[], summary.

This stage is OFFLINE (no network) and deterministic. It does NOT fetch code —
that is stage 2. Keeping enumeration separate from fetching means we can inspect
and hand-filter the candidate list before spending GitHub API calls.
"""

import json
import os
import re
import glob
from collections import defaultdict

# CWE -> plugin mapping (which FM-Agent plugin this CWE belongs to).
TARGET_CWE_PLUGIN = {
    "CWE-639": "authz", "CWE-862": "authz", "CWE-863": "authz", "CWE-306": "authz",
    "CWE-200": "ifc", "CWE-209": "ifc", "CWE-532": "ifc",
    "CWE-352": "typestate", "CWE-295": "typestate", "CWE-367": "typestate",
    "CWE-772": "typestate",
    # CWE-415 intentionally excluded: ~nonexistent in pure Python (C-ext only).
    # --- taint (injection) CWEs ---
    "CWE-89": "taint", "CWE-78": "taint", "CWE-79": "taint", "CWE-22": "taint",
    "CWE-94": "taint", "CWE-502": "taint", "CWE-918": "taint", "CWE-90": "taint",
    "CWE-643": "taint", "CWE-601": "taint", "CWE-611": "taint", "CWE-88": "taint",
    "CWE-74": "taint",
    # --- crypto (misuse) CWEs --- (PyPI coverage is THIN; small sample expected)
    "CWE-327": "crypto", "CWE-328": "crypto", "CWE-329": "crypto", "CWE-330": "crypto",
    "CWE-338": "crypto", "CWE-916": "crypto", "CWE-326": "crypto", "CWE-321": "crypto",
    "CWE-798": "crypto", "CWE-759": "crypto",
    # NOTE: CWE-295 (cert) / CWE-347 (sig) are mapped to typestate above (temporal
    # verify-before-trust), NOT crypto, to avoid double-counting.
}
TARGET_CWES = set(TARGET_CWE_PLUGIN)

_COMMIT_RE = re.compile(r"github\.com/([^/\s]+)/([^/\s]+)/commit/([0-9a-f]{7,40})")
_REPO_RE = re.compile(r"github\.com/([^/\s]+)/([^/\s]+?)(?:\.git)?/?$")


def _extract_commits(refs):
    """Return [(owner, repo, sha)] for every GitHub commit URL in references."""
    out = []
    for url in refs:
        m = _COMMIT_RE.search(url or "")
        if m:
            owner, repo, sha = m.group(1), m.group(2), m.group(3)
            repo = repo.removesuffix(".git")
            out.append((owner, repo, sha))
    return out


def _extract_repo(record, refs):
    """Best-effort source repo (owner/repo) from a record."""
    # prefer explicit source_code_location-like refs that are bare repo roots
    for url in refs:
        m = _REPO_RE.search((url or "").rstrip("/"))
        if m and "/commit/" not in url and "/pull/" not in url and "/blob/" not in url:
            return f"{m.group(1)}/{m.group(2)}"
    return None


def _versions(record):
    introduced, fixed = [], []
    for a in record.get("affected") or []:
        for r in a.get("ranges") or []:
            if r.get("type") != "ECOSYSTEM":
                continue
            for e in r.get("events") or []:
                if e.get("introduced"):
                    introduced.append(e["introduced"])
                if e.get("fixed"):
                    fixed.append(e["fixed"])
    return introduced, fixed


def extract_candidates(osv_dir):
    candidates = []
    for f in glob.glob(os.path.join(osv_dir, "*.json")):
        try:
            d = json.load(open(f))
        except (OSError, json.JSONDecodeError):
            continue
        cwes = set((d.get("database_specific") or {}).get("cwe_ids") or [])
        hit = sorted(cwes & TARGET_CWES)
        if not hit:
            continue
        refs = [x.get("url", "") for x in (d.get("references") or [])]
        commits = _extract_commits(refs)
        introduced, fixed = _versions(d)
        # require at least one locatable fix signal
        if not commits and not fixed:
            continue
        pkgs = sorted({a["package"]["name"] for a in (d.get("affected") or [])
                       if a.get("package", {}).get("name")})
        aliases = d.get("aliases") or []
        cve = next((a for a in aliases if a.startswith("CVE-")), d.get("id"))
        # de-dup commit shas, keep owner/repo
        seen, commit_list = set(), []
        for owner, repo, sha in commits:
            if sha in seen:
                continue
            seen.add(sha)
            commit_list.append({"owner": owner, "repo": repo, "sha": sha})
        candidates.append({
            "osv_id": d.get("id"),
            "cve": cve,
            "cwes": hit,
            "plugins": sorted({TARGET_CWE_PLUGIN[c] for c in hit}),
            "packages": pkgs,
            "repo": _extract_repo(d, refs),
            "commits": commit_list,
            "fixed_versions": fixed,
            "introduced_versions": introduced,
            "summary": (d.get("summary") or "")[:200],
        })
    return candidates


def main():
    import argparse
    ap = argparse.ArgumentParser(description="OSV candidate extractor (stage 1)")
    ap.add_argument("--osv-dir", default="pypi")
    ap.add_argument("--out", default="candidates.jsonl")
    args = ap.parse_args()

    cands = extract_candidates(args.osv_dir)
    with open(args.out, "w") as fh:
        for c in cands:
            fh.write(json.dumps(c) + "\n")

    by_plugin = defaultdict(int)
    by_cwe = defaultdict(int)
    with_commit = 0
    for c in cands:
        for p in c["plugins"]:
            by_plugin[p] += 1
        for w in c["cwes"]:
            by_cwe[w] += 1
        if c["commits"]:
            with_commit += 1
    print(f"candidates: {len(cands)}  (with direct commit: {with_commit})")
    print("by plugin:", dict(by_plugin))
    print("by cwe:", dict(sorted(by_cwe.items(), key=lambda x: -x[1])))
    print(f"wrote {args.out}")


if __name__ == "__main__":
    main()

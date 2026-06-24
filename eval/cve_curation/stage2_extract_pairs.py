"""Stage 2 of the curation pipeline: fetch fix commits, extract before/after
function pairs as benchmark cases.

ZERO-API design (GitHub unauthenticated API is 60/hr; we have hundreds of
commits). For each candidate commit we fetch ONLY un-throttled endpoints:
  - https://github.com/<o>/<r>/commit/<sha>.patch       (the diff)
  - https://raw.githubusercontent.com/<o>/<r>/<sha>/<path>  (the AFTER file)
then reverse-apply the patch locally to reconstruct the BEFORE file. No API calls.

For each changed *.py file in the commit we:
  1. get AFTER source (raw) and BEFORE source (reverse-applied patch),
  2. extract functions from both with src.extract,
  3. for every function whose body CHANGED, emit a pair:
       <stem>__<func>__before.py  (label=vulnerable)   <- the pre-fix function
       <stem>__<func>__after.py   (label=safe)         <- the post-fix function
     so the benchmark is BALANCED (precision measurable), unlike recall-only sets.

Heuristics / guards (quality over quantity):
  - skip commits touching > MAX_FILES python files (mega-commits = noisy labels),
  - skip test files,
  - only emit functions that actually differ (added/removed/modified body),
  - record full provenance (cve, osv_id, cwe, repo, sha, path, func) per case.

Output: a directory of .py case files + cases.jsonl manifest (Case-compatible).
"""

import argparse
import json
import os
import re
import socket
import subprocess
import sys
import tempfile
import urllib.request

sys.path.insert(0, "/mnt/nvme/jiangzhe/FM-Agent-Internal")
from src.extract import extract_functions_from_file  # noqa: E402

MAX_FILES = 4          # skip mega-commits touching more python files than this
MAX_FUNC_LINES = 200   # skip pathologically large functions
_DIFF_FILE_RE = re.compile(r"^diff --git a/(\S+) b/(\S+)", re.M)
_TEST_RE = re.compile(r"(^|/)(test_|tests?/|conftest)", re.I)

# GitHub is reachable DIRECTLY here; the ambient http(s)_proxy env points at an
# internal proxy that hangs on raw.githubusercontent fetches. Build an opener
# that bypasses any proxy (equivalent to curl --noproxy '*').
_NO_PROXY_OPENER = urllib.request.build_opener(
    urllib.request.ProxyHandler({})
)

# Defense-in-depth: a process-wide default so any stray socket op cannot hang
# forever (the urlopen timeout already covers our fetches).
socket.setdefaulttimeout(30)


def _fetch(url, timeout=20):
    req = urllib.request.Request(url, headers={"User-Agent": "fm-agent-eval"})
    with _NO_PROXY_OPENER.open(req, timeout=timeout) as r:
        return r.read().decode("utf-8", errors="replace")


def _changed_py_files(patch_text):
    """Return [path] for *.py files changed in the patch (b-side path)."""
    files = []
    for _, b in _DIFF_FILE_RE.findall(patch_text):
        if b.endswith(".py") and not _TEST_RE.search(b):
            files.append(b)
    return files


def _reconstruct_before(repo_root, rel_path, after_src, patch_text):
    """Write after_src at rel_path, reverse-apply patch -> return before_src."""
    abspath = os.path.join(repo_root, rel_path)
    os.makedirs(os.path.dirname(abspath), exist_ok=True)
    with open(abspath, "w") as f:
        f.write(after_src)
    patch_file = os.path.join(repo_root, "_c.patch")
    with open(patch_file, "w") as f:
        f.write(patch_text)
    # reverse-apply just this file's hunks
    r = subprocess.run(
        ["git", "apply", "-R", "--include", rel_path, "_c.patch"],
        cwd=repo_root, capture_output=True, text=True,
    )
    if r.returncode != 0:
        return None
    # If the fix commit ADDED this file, reverse-apply deletes it -> no before
    # version exists (and thus no pre-existing vulnerable function here). Skip.
    if not os.path.exists(abspath):
        return None
    with open(abspath) as f:
        return f.read()


def _funcs(src, repo_root):
    """Extract {func_name: source} from a python source string."""
    tmp = os.path.join(repo_root, "_x.py")
    with open(tmp, "w") as f:
        f.write(src)
    try:
        return dict(extract_functions_from_file(tmp, "python"))
    except Exception:  # noqa: BLE001 — extraction best-effort
        return {}
    finally:
        if os.path.exists(tmp):
            os.remove(tmp)


def process_candidate(cand, out_dir, manifest):
    """Process one candidate; append emitted cases to manifest. Returns #pairs."""
    pairs = 0
    cwe = cand["cwes"][0]
    plugin = cand["plugins"][0]
    for c in cand.get("commits", []):
        owner, repo, sha = c["owner"], c["repo"], c["sha"]
        base = f"https://github.com/{owner}/{repo}/commit/{sha}.patch"
        try:
            patch_text = _fetch(base)
        except Exception:  # noqa: BLE001
            continue
        changed = _changed_py_files(patch_text)
        if not changed or len(changed) > MAX_FILES:
            continue
        with tempfile.TemporaryDirectory() as repo_root:
            subprocess.run(["git", "init", "-q", "."], cwd=repo_root,
                           capture_output=True)
            for rel in changed:
                raw = f"https://raw.githubusercontent.com/{owner}/{repo}/{sha}/{rel}"
                try:
                    after_src = _fetch(raw)
                except Exception:  # noqa: BLE001
                    continue
                before_src = _reconstruct_before(repo_root, rel, after_src, patch_text)
                if before_src is None:
                    continue
                before_funcs = _funcs(before_src, repo_root)
                after_funcs = _funcs(after_src, repo_root)
                # functions whose body changed (present both sides, differ) OR
                # removed-in-fix (present before only) are the vulnerable locus.
                for name, bsrc in before_funcs.items():
                    asrc = after_funcs.get(name)
                    if asrc is not None and asrc == bsrc:
                        continue  # unchanged -> not the fix locus
                    if bsrc.count("\n") > MAX_FUNC_LINES:
                        continue
                    stem = f"{cand['cve']}__{os.path.basename(rel)[:-3]}__{name}"
                    stem = re.sub(r"[^A-Za-z0-9_.-]", "_", stem)
                    # vulnerable (before)
                    vp = os.path.join(out_dir, f"{stem}__before.py")
                    with open(vp, "w") as f:
                        f.write(bsrc)
                    manifest.append({
                        "id": f"cve:{stem}__before", "path": vp, "cwe": cwe,
                        "label": True, "category": plugin, "benchmark": "cve-curated",
                        "source": f"osv:{cand['osv_id']}|{cand['cve']}|{owner}/{repo}@{sha[:10]}",
                        "meta": {"file": rel, "func": name, "fix_commit": sha},
                    })
                    pairs += 1
                    # safe (after) — only if the function still exists post-fix
                    if asrc is not None and asrc.count("\n") <= MAX_FUNC_LINES:
                        sp = os.path.join(out_dir, f"{stem}__after.py")
                        with open(sp, "w") as f:
                            f.write(asrc)
                        manifest.append({
                            "id": f"cve:{stem}__after", "path": sp, "cwe": cwe,
                            "label": False, "category": plugin, "benchmark": "cve-curated",
                            "source": f"osv:{cand['osv_id']}|{cand['cve']}|{owner}/{repo}@{sha[:10]}|fixed",
                            "meta": {"file": rel, "func": name, "fix_commit": sha},
                        })
    return pairs


def main():
    ap = argparse.ArgumentParser(description="Fetch fix commits -> before/after function pairs (stage 2)")
    ap.add_argument("--candidates", default="candidates.jsonl")
    ap.add_argument("--out-dir", default="cases")
    ap.add_argument("--manifest", default="cve_cases.jsonl")
    ap.add_argument("--cwe", default=None, help="restrict to one CWE (e.g. CWE-532)")
    ap.add_argument("--limit", type=int, default=0, help="cap #candidates processed")
    args = ap.parse_args()

    os.makedirs(args.out_dir, exist_ok=True)
    cands = [json.loads(l) for l in open(args.candidates) if l.strip()]
    if args.cwe:
        cands = [c for c in cands if args.cwe in c["cwes"] and c.get("commits")]
    else:
        cands = [c for c in cands if c.get("commits")]
    if args.limit:
        cands = cands[:args.limit]

    manifest, ncand, npairs = [], 0, 0
    for i, cand in enumerate(cands, 1):
        n = process_candidate(cand, args.out_dir, manifest)
        if n:
            ncand += 1
            npairs += n
        if i % 10 == 0 or i == len(cands):
            print(f"  [{i}/{len(cands)}] cands_with_pairs={ncand} func_pairs={npairs}", flush=True)
    with open(args.manifest, "w") as f:
        for m in manifest:
            f.write(json.dumps(m) + "\n")
    nvuln = sum(1 for m in manifest if m["label"])
    nsafe = sum(1 for m in manifest if not m["label"])
    print(f"DONE: {ncand} CVEs -> {nvuln} vulnerable + {nsafe} safe cases. wrote {args.manifest}")


if __name__ == "__main__":
    main()

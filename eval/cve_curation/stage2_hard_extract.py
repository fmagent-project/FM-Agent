"""Stage 2 (HARD variant): fetch fix commits, extract WHOLE-FILE before/after
cases that preserve multiple functions + their call relationships.

WHY a hard variant: the original stage2 emits ONE changed function per case, so
every case is a single short function — it never exercises the plugins'
INTERPROCEDURAL composition (call-graph, bottom-up/top-down propagation). This
variant emits the ENTIRE changed .py file (before-fix = vulnerable, after-fix =
safe), so the driver builds a real call graph over many functions and the
vulnerable locus is reached only through composition. It is deliberately HARDER:
the analyzer must localize the bug among many functions, not judge one in
isolation.

ZERO-API design (same as stage2): fetch only un-throttled endpoints
  - https://github.com/<o>/<r>/commit/<sha>.patch
  - https://raw.githubusercontent.com/<o>/<r>/<sha>/<path>
then reverse-apply the patch to reconstruct the BEFORE file. No API calls.

Difficulty knobs (opposite spirit to the easy corpus):
  - MAX_FILES raised (allow multi-file fixes — bias toward them),
  - emit whole files up to MAX_FILE_LINES (keep long, multi-function files),
  - require the changed file to have >= MIN_FUNCS functions (so there is a real
    call graph / localization challenge), else fall back to skip,
  - record provenance + the set of CHANGED functions (the true locus) per case.

Output: a directory of .py case files (whole files) + a Case-compatible manifest.
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

MAX_FILES = 12          # allow multi-file fixes (bias toward interprocedural)
MAX_FILE_LINES = 450    # keep whole files up to this size (vs per-func in easy corpus)
MIN_FUNCS = 2           # the file must have >=2 functions (a real call graph)
MIN_CHANGED_LINE = 1
_DIFF_FILE_RE = re.compile(r"^diff --git a/(\S+) b/(\S+)", re.M)
_TEST_RE = re.compile(r"(^|/)(test_|tests?/|conftest)", re.I)

_NO_PROXY_OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))
# This environment routes GitHub through the ambient http(s)_proxy; direct
# connections time out. Use the default opener (honors env proxy) unless
# FM_AGENT_NO_PROXY is set (for environments where direct works and proxy hangs).
_USE_PROXY = not os.environ.get("FM_AGENT_NO_PROXY")
_OPENER = urllib.request.build_opener() if _USE_PROXY else _NO_PROXY_OPENER
socket.setdefaulttimeout(30)


def _fetch(url, timeout=25):
    req = urllib.request.Request(url, headers={"User-Agent": "fm-agent-eval"})
    with _OPENER.open(req, timeout=timeout) as r:
        return r.read().decode("utf-8", errors="replace")


def _changed_py_files(patch_text):
    files = []
    for _, b in _DIFF_FILE_RE.findall(patch_text):
        if b.endswith(".py") and not _TEST_RE.search(b):
            files.append(b)
    return files


def _reconstruct_before(repo_root, rel_path, after_src, patch_text):
    abspath = os.path.join(repo_root, rel_path)
    os.makedirs(os.path.dirname(abspath) or repo_root, exist_ok=True)
    with open(abspath, "w") as f:
        f.write(after_src)
    patch_file = os.path.join(repo_root, "_c.patch")
    with open(patch_file, "w") as f:
        f.write(patch_text)
    r = subprocess.run(
        ["git", "apply", "-R", "--include", rel_path, "_c.patch"],
        cwd=repo_root, capture_output=True, text=True,
    )
    if r.returncode != 0:
        return None
    if not os.path.exists(abspath):
        return None
    with open(abspath) as f:
        return f.read()


def _funcs(src, repo_root):
    tmp = os.path.join(repo_root, "_x.py")
    with open(tmp, "w") as f:
        f.write(src)
    try:
        return dict(extract_functions_from_file(tmp, "python"))
    except Exception:  # noqa: BLE001
        return {}
    finally:
        if os.path.exists(tmp):
            os.remove(tmp)


def _changed_funcs(before_funcs, after_funcs):
    """Names of functions whose body changed or was removed in the fix."""
    changed = []
    for name, bsrc in before_funcs.items():
        asrc = after_funcs.get(name)
        if asrc is None or asrc != bsrc:
            changed.append(name)
    return changed


def process_candidate(cand, out_dir, manifest):
    """Process one candidate; append whole-file cases. Returns #cases emitted."""
    n = 0
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
        n_files = len(changed)
        with tempfile.TemporaryDirectory() as repo_root:
            subprocess.run(["git", "init", "-q", "."], cwd=repo_root, capture_output=True)
            for rel in changed:
                raw = f"https://raw.githubusercontent.com/{owner}/{repo}/{sha}/{rel}"
                try:
                    after_src = _fetch(raw)
                except Exception:  # noqa: BLE001
                    continue
                before_src = _reconstruct_before(repo_root, rel, after_src, patch_text)
                if before_src is None:
                    continue
                # whole-file size guard (keep long files; skip pathological ones)
                if before_src.count("\n") > MAX_FILE_LINES:
                    continue
                before_funcs = _funcs(before_src, repo_root)
                after_funcs = _funcs(after_src, repo_root)
                if len(before_funcs) < MIN_FUNCS:
                    continue  # no real call graph / localization challenge
                changed_fns = _changed_funcs(before_funcs, after_funcs)
                if not changed_fns:
                    continue  # this file's funcs didn't change (only e.g. imports)

                stem = f"{cand['cve']}__{os.path.basename(rel)[:-3]}"
                stem = re.sub(r"[^A-Za-z0-9_.-]", "_", stem)
                meta = {"file": rel, "fix_commit": sha,
                        "changed_funcs": changed_fns,
                        "n_funcs": len(before_funcs),
                        "n_files_in_commit": n_files}
                # vulnerable = whole BEFORE file
                vp = os.path.join(out_dir, f"{stem}__before.py")
                with open(vp, "w") as f:
                    f.write(before_src)
                manifest.append({
                    "id": f"cve:{stem}__before", "path": vp, "cwe": cwe,
                    "label": True, "category": plugin, "benchmark": "cve-curated-hard",
                    "source": f"osv:{cand['osv_id']}|{cand['cve']}|{owner}/{repo}@{sha[:10]}",
                    "meta": meta,
                })
                n += 1
                # safe = whole AFTER file (the fix)
                if after_src.count("\n") <= MAX_FILE_LINES and len(after_funcs) >= MIN_FUNCS:
                    sp = os.path.join(out_dir, f"{stem}__after.py")
                    with open(sp, "w") as f:
                        f.write(after_src)
                    manifest.append({
                        "id": f"cve:{stem}__after", "path": sp, "cwe": cwe,
                        "label": False, "category": plugin, "benchmark": "cve-curated-hard",
                        "source": f"osv:{cand['osv_id']}|{cand['cve']}|{owner}/{repo}@{sha[:10]}|fixed",
                        "meta": {**meta},
                    })
    return n


def main():
    ap = argparse.ArgumentParser(description="Fetch fix commits -> whole-file cases (stage 2 HARD)")
    ap.add_argument("--candidates", default="candidates_all7.jsonl")
    ap.add_argument("--out-dir", default="cases_hard")
    ap.add_argument("--manifest", default="cve_cases_hard.jsonl")
    ap.add_argument("--plugin", default=None, help="restrict to one plugin")
    ap.add_argument("--limit", type=int, default=0, help="cap #candidates processed")
    ap.add_argument("--per-plugin-cap", type=int, default=0,
                    help="stop a plugin once it has this many vulnerable cases (0=no cap)")
    args = ap.parse_args()

    os.makedirs(args.out_dir, exist_ok=True)
    cands = [json.loads(l) for l in open(args.candidates) if l.strip()]
    cands = [c for c in cands if c.get("commits")]
    if args.plugin:
        cands = [c for c in cands if args.plugin in c["plugins"]]
    # bias toward harder commits: process multi-commit/likely-multi-file first is
    # not knowable offline, so just keep order; the per-plugin cap keeps it bounded.
    if args.limit:
        cands = cands[:args.limit]

    manifest = []
    per_plugin_vuln = {}
    ncand = 0
    for i, cand in enumerate(cands, 1):
        plugin = cand["plugins"][0]
        if args.per_plugin_cap and per_plugin_vuln.get(plugin, 0) >= args.per_plugin_cap:
            continue
        n = process_candidate(cand, args.out_dir, manifest)
        if n:
            ncand += 1
            per_plugin_vuln[plugin] = per_plugin_vuln.get(plugin, 0) + n
        if i % 20 == 0 or i == len(cands):
            tot_v = sum(1 for m in manifest if m["label"])
            print(f"  [{i}/{len(cands)}] cands_with_cases={ncand} vuln_cases={tot_v} "
                  f"per_plugin={per_plugin_vuln}", flush=True)
        # checkpoint manifest periodically (network is flaky)
        if i % 20 == 0:
            with open(args.manifest, "w") as f:
                for m in manifest:
                    f.write(json.dumps(m) + "\n")

    with open(args.manifest, "w") as f:
        for m in manifest:
            f.write(json.dumps(m) + "\n")
    nv = sum(1 for m in manifest if m["label"])
    ns = sum(1 for m in manifest if not m["label"])
    print(f"DONE: {ncand} CVEs -> {nv} vulnerable + {ns} safe whole-file cases. wrote {args.manifest}")


if __name__ == "__main__":
    main()

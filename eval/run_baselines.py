"""Baseline runner — run Bandit + Semgrep over benchmark cases, collapse to Detections.

Locked invocations (verified on OWASP cases):
  - Bandit:  python -m bandit -f json <file>
             -> results[].{test_id, issue_cwe.id, line_number}
  - Semgrep: semgrep scan --config p/default --config p/security-audit
             --json --metrics off <file>
             -> results[].extra.metadata.cwe[]   (CE registry; pattern-based)

Semgrep CE (no Pro login) is pattern-based with low taint recall — that is the
HONEST baseline a user gets out of the box, and the comparison reflects it.

Output: a json file mapping case_id -> {tool -> Detection-as-dict}, plus the
raw tool json cached per case for audit (so we never silently re-fabricate).
"""

import json
import os
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from eval.normalize import collapse_bandit, collapse_semgrep  # noqa: E402

VENV = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), ".venv")
PYBIN = os.path.join(VENV, "bin", "python")
SEMGREP = os.path.join(VENV, "bin", "semgrep")

# isolate semgrep/registry network use; keep proxy-free localhost behavior
_ENV = dict(os.environ, SEMGREP_SEND_METRICS="off")


def run_bandit(path, timeout=60):
    try:
        p = subprocess.run(
            [PYBIN, "-m", "bandit", "-f", "json", path],
            capture_output=True, text=True, timeout=timeout, env=_ENV,
        )
        return json.loads(p.stdout) if p.stdout.strip() else {"results": []}
    except (subprocess.TimeoutExpired, json.JSONDecodeError) as e:
        return {"results": [], "_error": f"{type(e).__name__}"}


def run_semgrep(path, timeout=180):
    try:
        p = subprocess.run(
            [SEMGREP, "scan", "--config", "p/default", "--config", "p/security-audit",
             "--json", "--metrics", "off", path],
            capture_output=True, text=True, timeout=timeout, env=_ENV,
        )
        return json.loads(p.stdout) if p.stdout.strip() else {"results": []}
    except (subprocess.TimeoutExpired, json.JSONDecodeError) as e:
        return {"results": [], "_error": f"{type(e).__name__}"}


def run_baselines_over_cases(cases, out_dir, tools=("bandit", "semgrep"), verbose=True):
    """Run each baseline over each Case; write normalized + raw outputs.

    Returns {case_id: {tool: Detection-dict}}.
    """
    os.makedirs(out_dir, exist_ok=True)
    raw_dir = os.path.join(out_dir, "raw")
    os.makedirs(raw_dir, exist_ok=True)
    table = {}
    n = len(cases)
    for i, c in enumerate(cases, 1):
        per_tool = {}
        if "bandit" in tools:
            rj = run_bandit(c.path)
            with open(os.path.join(raw_dir, f"{c.id.replace(':', '_')}.bandit.json"), "w") as f:
                json.dump(rj, f)
            d = collapse_bandit(c.id, rj)
            per_tool["bandit"] = _det_dict(d)
        if "semgrep" in tools:
            rj = run_semgrep(c.path)
            with open(os.path.join(raw_dir, f"{c.id.replace(':', '_')}.semgrep.json"), "w") as f:
                json.dump(rj, f)
            d = collapse_semgrep(c.id, rj)
            per_tool["semgrep"] = _det_dict(d)
        table[c.id] = per_tool
        if verbose and (i % 25 == 0 or i == n):
            print(f"  baselines: {i}/{n} cases", flush=True)
    with open(os.path.join(out_dir, "baseline_detections.json"), "w") as f:
        json.dump(table, f, indent=2)
    return table


def _det_dict(d):
    return {"detected": d.detected, "cwes": sorted(d.cwes),
            "raw_count": d.raw_count, "evidence": d.evidence}


def reconstruct_from_raw(out_dir):
    """Rebuild {case_id: {tool: det}} from the incremental raw/ cache.

    The aggregate baseline_detections.json is only written when the full run
    finishes. The per-case raw/<case>.<tool>.json files appear incrementally, so
    this lets audit.py / score.py work on a PARTIAL baseline run. Returns the
    same shape as run_baselines_over_cases.
    """
    raw_dir = os.path.join(out_dir, "raw")
    table = {}
    if not os.path.isdir(raw_dir):
        return table
    for fn in os.listdir(raw_dir):
        if not fn.endswith(".json"):
            continue
        # <case_id_with_underscores>.<tool>.json ; case ids look like owasp_BenchmarkTest00099
        stem, _, _ = fn.rpartition(".")           # drop .json
        case_key, _, tool = stem.rpartition(".")   # split tool
        if tool not in ("bandit", "semgrep") or not case_key:
            continue
        cid = case_key.replace("owasp_", "owasp:").replace("redbench_", "redbench:")
        try:
            rj = json.load(open(os.path.join(raw_dir, fn)))
        except (OSError, json.JSONDecodeError):
            continue
        d = collapse_bandit(cid, rj) if tool == "bandit" else collapse_semgrep(cid, rj)
        table.setdefault(cid, {})[tool] = _det_dict(d)
    return table


if __name__ == "__main__":
    # smoke: run both baselines over a tiny hand-picked set (1 true sqli, 1 safe)
    from eval.benchmarks import load_owasp
    owasp = sys.argv[1] if len(sys.argv) > 1 else \
        "/mnt/nvme/jiangzhe/tmp/opencode/eval_benchmarks/BenchmarkPython"
    cases = [c for c in load_owasp(owasp)
             if c.meta["test_name"] in ("BenchmarkTest00099", "BenchmarkTest00011")]
    out = "/tmp/eval_baseline_smoke"
    table = run_baselines_over_cases(cases, out)
    for c in cases:
        print(f"{c.id} (label={'VULN' if c.label else 'safe'}, {c.cwe}):")
        for tool, d in table[c.id].items():
            print(f"   {tool:8s} detected={d['detected']} cwes={d['cwes']} ({d['raw_count']} findings)")

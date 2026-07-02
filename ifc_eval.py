#!/usr/bin/env python3
"""IFC evaluation harness — reconcile IFC results against a ground-truth file.

Compares the verdicts produced by `ifc_main.py` (under <proj_dir>/fm_agent_ifc/
ifc_results/) against a hand-authored ground truth (<proj_dir>/expected.json),
and prints a per-function accuracy report.

The ground truth is kept SEPARATE from the analyzed source so the code under
analysis carries no leak/label/verdict hints (see ifc_webapp/expected.json).

Usage:
    python3 ifc_eval.py <proj_dir> [--expected path/to/expected.json] [--json]

expected.json schema:
    {
      "functions": {
        "<module.py>::<func_name>": {
          "expected": "SECURE|LEAK|DECLASSIFIED|POLYMORPHIC|ERROR",
          "reason": "...",                  # optional, informational
          "difficulty": "medium|hard",      # optional
          "ambiguous": "..."                 # optional: if present, a verdict
                                             #   mismatch is counted as ACCEPTABLE
                                             #   rather than a true miss
        },
        ...
      }
    }

Exit code: 0 if there are no true misses (ambiguous mismatches allowed), else 1.
"""

import argparse
import json
import os
import sys


VERDICTS = ["SECURE", "LEAK", "DECLASSIFIED", "POLYMORPHIC", "ERROR"]

# ANSI colors (disabled automatically when output is not a TTY)
_C = {
    "SECURE": "\033[32m", "LEAK": "\033[31m", "DECLASSIFIED": "\033[33m",
    "POLYMORPHIC": "\033[36m", "ERROR": "\033[35m",
    "hit": "\033[32m", "miss": "\033[31m", "amb": "\033[33m", "reset": "\033[0m",
}


def _color(enabled, key, text):
    if not enabled:
        return text
    return f"{_C.get(key, '')}{text}{_C['reset']}"


def _find_results_dir(proj_dir):
    """Locate ifc_results/ for a project dir or a workspace dir."""
    proj_dir = os.path.realpath(os.path.expanduser(proj_dir))
    for cand in (
        os.path.join(proj_dir, "fm_agent_ifc", "ifc_results"),
        os.path.join(proj_dir, "ifc_results"),
    ):
        if os.path.isdir(cand):
            return cand
    raise FileNotFoundError(
        f"no ifc_results/ found under {proj_dir} (run ifc_main.py first)"
    )


def _key_for(rel_result_path):
    """Map a result file rel-path to the expected.json key '<module.py>::<func>'.

    e.g. 'auth_service-py/hash_password.json' -> 'auth_service.py::hash_password'
    Handles nested dirs: 'pkg/sub/mod-py/fn.json' -> 'pkg/sub/mod.py::fn'.
    """
    no_ext = os.path.splitext(rel_result_path)[0]          # auth_service-py/hash_password
    parts = no_ext.split(os.sep)
    func = parts[-1]
    module_dir = parts[-2] if len(parts) >= 2 else ""
    prefix = os.sep.join(parts[:-2])                        # nested package path, if any
    # The extracted dir replaces the last '.' of the filename with '-'.
    # Restore it: 'auth_service-py' -> 'auth_service.py'.
    if "-" in module_dir:
        head, sep, ext = module_dir.rpartition("-")
        module = f"{head}.{ext}" if head else module_dir
    else:
        module = module_dir
    key = f"{module}::{func}"
    if prefix:
        key = f"{prefix}{os.sep}{key}"
    return key


def load_actual(results_dir):
    """Return {key: verdict} for every per-function result file."""
    actual = {}
    for root, _, files in os.walk(results_dir):
        for fn in files:
            if fn == "summary.json" or not fn.endswith(".json"):
                continue
            rel = os.path.relpath(os.path.join(root, fn), results_dir)
            try:
                d = json.load(open(os.path.join(root, fn)))
            except (OSError, json.JSONDecodeError):
                continue
            actual[_key_for(rel)] = d.get("verdict", "?")
    return actual


def evaluate(proj_dir, expected_path=None):
    proj_dir = os.path.realpath(os.path.expanduser(proj_dir))
    if expected_path is None:
        expected_path = os.path.join(proj_dir, "expected.json")
    if not os.path.isfile(expected_path):
        raise FileNotFoundError(f"expected.json not found: {expected_path}")

    expected = json.load(open(expected_path)).get("functions", {})
    actual = load_actual(_find_results_dir(proj_dir))

    # Build a suffix index so a ground-truth key written without the package
    # prefix (e.g. "__init__.py::f") still matches an actual key that carries it
    # (e.g. "onetimepass/__init__.py::f"). Only used when there is exactly one
    # unambiguous suffix match, so we never silently mismatch.
    def _suffix_match(gt_key):
        if gt_key in actual:
            return gt_key
        cands = [ak for ak in actual
                 if ak == gt_key or ak.endswith("/" + gt_key) or ak.endswith(os.sep + gt_key)]
        return cands[0] if len(cands) == 1 else None

    matched_actual = set()
    rows = []
    hit = miss = amb = 0
    for key, info in expected.items():
        e = info.get("expected", "?")
        ak = _suffix_match(key)
        a = actual.get(ak, "MISSING") if ak else "MISSING"
        if ak:
            matched_actual.add(ak)
        if a == e:
            status, hit = "hit", hit + 1
        elif info.get("ambiguous"):
            status, amb = "amb", amb + 1
        else:
            status, miss = "miss", miss + 1
        rows.append({
            "status": status, "function": key, "expected": e, "actual": a,
            "difficulty": info.get("difficulty", ""),
            "ambiguous": bool(info.get("ambiguous")),
        })

    # Functions analyzed but not matched to any ground-truth entry (coverage gap).
    extra = sorted(set(actual) - matched_actual)

    total = len(expected)
    return {
        "proj_dir": proj_dir,
        "total": total,
        "hit": hit, "ambiguous": amb, "miss": miss,
        "strict_accuracy": (hit / total) if total else 0.0,
        "lenient_accuracy": ((hit + amb) / total) if total else 0.0,
        "rows": rows,
        "untracked": extra,
    }


def print_report(report, use_color=True):
    order = {"miss": 0, "amb": 1, "hit": 2}
    rows = sorted(report["rows"], key=lambda r: (order[r["status"]], r["function"]))
    label = {"hit": "✓", "miss": "✗ MISS", "amb": "≈ accept"}

    print(f"{'status':12}{'function':44}{'expected':14}{'actual':14}diff")
    print("-" * 100)
    for r in rows:
        st = _color(use_color, r["status"], label[r["status"]])
        # pad the (possibly colorized) status to a visible width of 12
        pad = 12 - len(label[r["status"]])
        ev = _color(use_color, r["expected"], r["expected"])
        av = _color(use_color, r["actual"] if r["actual"] in VERDICTS else "miss", r["actual"])
        print(f"{st}{' ' * max(pad,1)}{r['function']:44}"
              f"{r['expected']:14}{r['actual']:14}{r['difficulty']}")
    print("-" * 100)
    t = report["total"]
    print(f"strict hits: {report['hit']}/{t}   "
          f"acceptable (within ambiguity): {report['ambiguous']}   "
          f"true misses: {report['miss']}")
    print(f"strict accuracy: {report['strict_accuracy']*100:.0f}%   "
          f"incl. acceptable: {report['lenient_accuracy']*100:.0f}%")
    if report["untracked"]:
        print(f"\n[warning] {len(report['untracked'])} analyzed function(s) absent "
              f"from expected.json (no ground truth):")
        for k in report["untracked"]:
            print(f"  - {k}")


def main():
    ap = argparse.ArgumentParser(description="Reconcile IFC results vs expected.json")
    ap.add_argument("proj_dir", help="project dir analyzed by ifc_main.py")
    ap.add_argument("--expected", default=None, help="path to ground-truth json")
    ap.add_argument("--json", action="store_true", help="emit raw JSON report")
    args = ap.parse_args()

    try:
        report = evaluate(args.proj_dir, args.expected)
    except FileNotFoundError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2

    if args.json:
        print(json.dumps(report, indent=2, ensure_ascii=False))
    else:
        print_report(report, use_color=sys.stdout.isatty())

    return 1 if report["miss"] > 0 else 0


if __name__ == "__main__":
    raise SystemExit(main())

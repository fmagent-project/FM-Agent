"""Direct-LLM baseline — ask the SAME model FM-Agent uses to judge each case in
ONE shot, with no FM-Agent machinery (no structured abstraction, no deterministic
checker, no interprocedural composition).

This isolates the contribution of FM-Agent's structured pipeline: same model,
same code, same target-property scope — the only difference is "describe→
deterministic-check→compose" vs. "just ask the LLM for a verdict." Output is
Detection-compatible so score.py can treat `llm-direct` as a third baseline tool.

Fair-comparison choices:
  - Same model as FM-Agent (config.LLM_MODEL), routed through the same client.
  - The prompt names the SAME CWE scope the plugin targets, so the LLM is not
    penalized for judging a property out of scope (and not helped by being told
    the answer — labels are never shown).
  - Single function shown (the case file), exactly what the baselines/our tool
    see per case. No call-graph context (our tool's composition is part of what
    we are measuring, so giving it to the LLM here would erase the comparison).
  - Fail-closed: a crash/parse-failure after retries is recorded as ERROR and
    scored exactly like the other tools' ERROR (fail-closed = flagged).

Output: eval/llm_<plugin>_cve_detections.json
  {"detections": {case_id: {detected, cwes, raw_count, evidence, error}},
   "meta": {case_id: {seconds, verdict, raw}}}
checkpointed after every case (endpoint is unstable; never lose progress).
"""

import argparse
import json
import os
import re
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from eval.benchmarks import Case  # noqa: E402
from eval.normalize import _canon_cwe  # noqa: E402
from src.plugins import registry as _registry  # noqa: E402  (pure-data, light)
from src.llm_client import _retry_create, _openrouter_client  # noqa: E402
import config  # noqa: E402


# Per-plugin target property + the CWE scope it models, derived from the central
# registry (src/plugins/registry.py). The LLM is told ONLY the property/scope,
# never the per-case label or expected CWE. Importing the registry is cheap and
# side-effect free (pure data, no openai).
PLUGIN_SCOPE = {
    name: {
        "property": _registry.PLUGIN_MANIFESTS[name]["property_nl"],
        "cwes": _registry.cwe_scope_string(name),
    }
    for name in _registry.plugin_names()
}


def _build_messages(plugin, code):
    scope = PLUGIN_SCOPE[plugin]
    system = (
        "You are a senior application-security auditor. You will be shown a single "
        "Python function and asked whether it contains a vulnerability of a SPECIFIC "
        "class. Judge ONLY that class. Decide from the code shown. Do not assume "
        "unseen callers sanitize or guard the input; judge the function as written.\n\n"
        f"Target vulnerability class: {scope['property']}.\n"
        f"In-scope CWEs: {scope['cwes']}.\n\n"
        "Answer with EXACTLY one line wrapped in tags, nothing else:\n"
        "[VERDICT]<VULNERABLE|SAFE>|<CWE-id or NONE>[/VERDICT]\n"
        "Use VULNERABLE only if the function, as written, exhibits an in-scope "
        "vulnerability; otherwise SAFE. If VULNERABLE, give the single best-matching "
        "in-scope CWE id; if SAFE, use NONE."
    )
    user = "Analyze this function:\n\n```python\n" + code + "\n```"
    return [{"role": "system", "content": system}, {"role": "user", "content": user}]


_VERDICT_RE = re.compile(r"\[VERDICT\]\s*(VULNERABLE|SAFE)\s*\|\s*([^\[\]]*?)\s*\[/VERDICT\]",
                         re.IGNORECASE)


def _parse_verdict(text):
    """Return (detected: bool, cwes: list[str]) or None if unparseable."""
    if not text:
        return None
    m = _VERDICT_RE.search(text)
    if not m:
        # tolerant fallback: a bare VULNERABLE/SAFE token
        t = text.upper()
        if "VULNERABLE" in t and "SAFE" not in t:
            cwe = _canon_cwe(t)
            return True, [cwe] if cwe else []
        if "SAFE" in t and "VULNERABLE" not in t:
            return False, []
        return None
    detected = m.group(1).upper() == "VULNERABLE"
    cwe = _canon_cwe(m.group(2)) if detected else None
    return detected, [cwe] if cwe else []


def judge_one(plugin, case, model, max_retries=3):
    """One single-shot LLM judgment for a case. Returns (det-dict, meta)."""
    code = open(case.path, errors="replace").read()
    messages = _build_messages(plugin, code)
    t0 = time.time()
    err = None
    raw = None
    parsed = None
    for attempt in range(1, max_retries + 1):
        try:
            raw, _usage = _retry_create(_openrouter_client, model, messages)
            parsed = _parse_verdict(raw)
            if parsed is not None:
                break
            # reformat nudge
            messages = messages + [
                {"role": "assistant", "content": raw},
                {"role": "user", "content": "Output only the [VERDICT]...[/VERDICT] line."},
            ]
        except Exception as e:  # noqa: BLE001 — fault-isolate per case
            err = f"{type(e).__name__}: {e}"
            break
    dt = time.time() - t0

    if parsed is None and err is None:
        err = "unparseable verdict after retries"
    detected, cwes = (parsed if parsed is not None else (False, []))
    det = {
        "detected": bool(detected),
        "cwes": sorted(c for c in cwes if c),
        "raw_count": 1 if detected else 0,
        "evidence": [(raw or "").strip()[:120]] if raw else [],
        "error": err,
    }
    meta = {"seconds": round(dt, 1),
            "verdict": "VULNERABLE" if detected else ("ERROR" if err else "SAFE"),
            "raw": (raw or "").strip()[:200]}
    return det, meta


def main():
    ap = argparse.ArgumentParser(description="Direct-LLM judgment baseline over a CVE sample")
    ap.add_argument("--plugin", required=True,
                    choices=_registry.plugin_names())
    ap.add_argument("--sample", default=None, help="defaults to eval/sample_<plugin>_cve.json")
    ap.add_argument("--out", default=None, help="defaults to eval/llm_<plugin>_cve_detections.json")
    ap.add_argument("--model", default=config.LLM_MODEL)
    ap.add_argument("--limit", type=int, default=0)
    args = ap.parse_args()

    sample = args.sample or f"eval/sample_{args.plugin}_cve.json"
    out = args.out or f"eval/llm_{args.plugin}_cve_detections.json"

    manifest = json.load(open(sample))
    cases = [Case(**c) for c in manifest["cases"]]
    if args.limit:
        cases = cases[:args.limit]

    # resume: keep already-judged cases (skip on re-run)
    table, metas = {}, {}
    if os.path.isfile(out):
        prev = json.load(open(out))
        table = prev.get("detections", {})
        metas = prev.get("meta", {})

    n = len(cases)
    for i, c in enumerate(cases, 1):
        if c.id in table and not table[c.id].get("error"):
            continue  # already done cleanly
        det, meta = judge_one(args.plugin, c, args.model)
        table[c.id] = det
        metas[c.id] = meta
        flag = "DET" if det["detected"] else ("ERR" if det["error"] else "---")
        print(f"[{i}/{n}] {c.id} label={'V' if c.label else 's'} {c.cwe} "
              f"-> {flag} {meta['verdict']} cwes={det['cwes']} ({meta['seconds']}s)"
              + (f" ERR={det['error']}" if det["error"] else ""), flush=True)
        json.dump({"detections": table, "meta": metas}, open(out, "w"), indent=2)
    print(f"wrote {out} ({len(table)} cases)")


if __name__ == "__main__":
    main()

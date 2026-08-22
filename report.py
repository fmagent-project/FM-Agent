"""Deterministic HTML report index for an FM-Agent run.

Scans the ``<proj_dir>/fm_agent/`` workspace artifacts — bug validation
reports (``bug_validation/*.result.json`` + ``summary.json``) and per-function
analysis results (``logic_verification_results/**/*.json``) — and renders a
self-contained ``report.html`` with client-side search / filter / sort /
expand-collapse. No LLM calls, no network, no new dependencies: the same
artifacts always produce the same byte-identical page.

The page is written to ``<work_dir>/report.html`` and is regenerated
automatically at the end of every full-pipeline run (see the hook at the end
of ``main.run_pipeline``); open it in a browser to browse, search, filter,
sort and expand each report. It can also be regenerated on demand from any
existing run's artifacts, with no LLM call involved:

Usage:
    uv run python report.py <proj_dir>                 # project root -> <proj_dir>/fm_agent/report.html
    uv run python report.py <proj_dir>/fm_agent        # an fm_agent workspace directory directly
    uv run python report.py /path/fm_agent.archived_xx # an archived workspace

Public API:
    generate_report(work_dir) -> str   # path of the written report.html

Note: the incremental pipeline (``--incremental``) does not run the
auto-generation hook; run ``uv run python report.py <proj_dir>`` manually to
build the page from an incremental run's artifacts.
"""

import argparse
import json
import os
import re
import sys


# No-dot extension -> language table, copied from src/extract.py so this module
# is self-contained (the reverse mapping and shape detection rely on it).
_EXT_TO_LANG = {
    "cpp": "cpp", "cc": "cpp", "cxx": "cpp", "c": "c", "h": "cpp", "hpp": "cpp",
    "py": "python",
    "erl": "erlang",
    "go": "go",
    "rs": "rust",
    "java": "java",
    "ts": "typescript", "tsx": "typescript",
    "js": "javascript", "jsx": "javascript",
    "cu": "cuda", "cuh": "cuda",
    "ets": "arkts",
}


def _extracted_file_to_source_rel(extracted_rel):
    """Map an extracted-function file path back to its source file (relative).

    Inverse of the extraction layout: ``src/engine/loader-cpp/loadData.cpp``
    (a function file) -> ``src/engine/loader.cpp`` (the source file). Extraction
    builds the function directory by replacing the source filename's last dot
    with a hyphen (``loader.cpp`` -> ``loader-cpp``). Member functions keep the
    class qualifier in the flat filename (``.../loader-cpp/MyClass::method.cpp``),
    so the ``<base>-<ext>`` directory is the function file's immediate parent; we
    still locate it by scanning the path components from the right (matching a
    component that ends in ``-<known extension>``) so the mapping is robust.
    """
    parts = extracted_rel.replace("\\", "/").split("/")
    for i in range(len(parts) - 2, -1, -1):          # skip the trailing func file
        comp = parts[i]
        hyphen = comp.rfind("-")
        if hyphen > 0 and comp[hyphen + 1:] in _EXT_TO_LANG:
            src_dir = os.sep.join(parts[:i])
            source_base = comp[:hyphen] + "." + comp[hyphen + 1:]
            return os.path.join(src_dir, source_base) if src_dir else source_base
    # Fallback: original immediate-parent behaviour (no recognised -ext dir).
    func_dir = os.path.dirname(extracted_rel)
    src_dir = os.path.dirname(func_dir)
    dir_name = os.path.basename(func_dir)
    hyphen = dir_name.rfind("-")
    source_base = dir_name[:hyphen] + "." + dir_name[hyphen + 1:] if hyphen > 0 else dir_name
    return os.path.join(src_dir, source_base) if src_dir else source_base


def _locate_workdir(proj_dir):
    """Resolve the fm_agent workspace directory for a project or run.

    Accepts a project root (probes ``<root>/fm_agent/``), an ``fm_agent/``
    directory itself, or an archived workspace (e.g. ``fm_agent.archived_xx``).
    The child workspace is probed before the path itself so a project that
    happens to own a top-level ``trace/``, ``bug_validation/``, or
    ``logic_verification_results/`` directory is not mistaken for a workspace;
    a direct ``fm_agent/`` or archived-workspace path still resolves via the
    path-itself probe. Detection uses any artifact marker subdirectory
    (``trace/``, ``bug_validation/``, ``logic_verification_results/``) — more
    robust than requiring ``trace/`` alone, since archived workspaces may have
    been stripped of traces.
    """
    p = os.path.abspath(proj_dir)
    markers = ("trace", "bug_validation", "logic_verification_results")
    cand = os.path.join(p, "fm_agent")
    if any(os.path.isdir(os.path.join(cand, m)) for m in markers):
        return cand
    if any(os.path.isdir(os.path.join(p, m)) for m in markers):
        return p
    return cand  # directory may not exist yet; caller validates


# Server-side default ordering within each kind (confirmed/first bugs, then
# analyses). The client re-sorts on demand; this only fixes the default row
# order embedded in the page so it is deterministic.
_VERDICT_RANK = {"MISMATCH": 0, "MATCH": 1, "ERROR": 2, "SKIPPED": 3}
_STATUS_RANK = {"confirmed": 0, "not_confirmed": 1, "error": 2, "pending": 3}

_CANDIDATE_RE = re.compile(r"\.bug-\d{3}\.json$")


def _extracted_suffix(path):
    """Return the portion of ``path`` below ``extracted_functions/``.

    The ``function`` / ``source_file`` fields stored in artifacts are the
    extracted-function path, which appears in three shapes: an absolute path
    (default mode), a project-relative ``fm_agent/extracted_functions/...``
    (all-bugs mode), or a bare ``extracted_functions/...``. Normalise all of
    them to the stable suffix the extraction layout understands.
    """
    if not isinstance(path, str) or not path:
        return ""
    norm = "/" + path.replace("\\", "/")
    _, marker, rel = norm.rpartition("/extracted_functions/")
    if marker and rel:
        return rel
    return path.replace("\\", "/").lstrip("/")


def _is_extracted_shape(rel):
    """Return whether ``rel`` follows the extraction layout.

    An extracted-function path either carries the ``extracted_functions`` marker
    somewhere in its components, or has a directory component of the form
    ``<base>-<known extension>`` (the function dir extraction builds by replacing
    the source filename's last dot with a hyphen). Anything else is either an
    already-mapped original source path or an unrecognised value, and must not be
    run through the reverse mapping.
    """
    parts = [p for p in rel.split("/") if p and p not in (".", "..")]
    if "extracted_functions" in parts:
        return True
    for comp in parts[:-1]:  # the trailing component is the function file itself
        hyphen = comp.rfind("-")
        if hyphen > 0 and comp[hyphen + 1:] in _EXT_TO_LANG:
            return True
    return False


def _map_source(function):
    """Map an artifact ``function`` / ``source_file`` value to the original
    project-relative source path.

    Artifacts store the extracted-function path in several shapes: an absolute
    path under ``.../extracted_functions/``, a project-relative
    ``fm_agent/extracted_functions/...``, a bare ``extracted_functions/...``, a
    marker-less extracted suffix such as ``src/engine/loader-cpp/loadData.cpp``
    (bug validators strip the ``fm_agent/extracted_functions`` prefix, leaving a
    leading-slash path), or — for records that already carry the original path —
    the source path itself. Reverse-map the extracted shapes; pass anything not
    shaped like an extracted path through unchanged.
    """
    if not isinstance(function, str) or not function:
        return ""
    norm = function.replace("\\", "/").lstrip("/")
    suffix = _extracted_suffix(norm)  # falls back to the normalised path itself
    if not suffix or not _is_extracted_shape(suffix):
        return suffix  # already the original source path (or unrecognised)
    try:
        return _extracted_file_to_source_rel(suffix).replace(os.sep, "/")
    except Exception:
        return suffix  # best effort: keep the extracted suffix rather than ""


def _func_name(function):
    """Derive the function name from an extracted-function path."""
    base = os.path.basename((function or "").replace("\\", "/").rstrip("/"))
    stem = os.path.splitext(base)[0]
    return stem or ""


def _bug_detail_ref(work_dir, bug_id):
    """Prefer the human-readable Markdown report, then the JSON record."""
    bv = os.path.join(work_dir, "bug_validation")
    if bug_id and os.path.isfile(os.path.join(bv, f"{bug_id}.md")):
        return f"bug_validation/{bug_id}.md"
    if bug_id and os.path.isfile(os.path.join(bv, f"{bug_id}.result.json")):
        return f"bug_validation/{bug_id}.result.json"
    return ""


def _bug_detail(record):
    """Build the expandable technical detail block for a bug record."""
    detail = {}
    status = record.get("confirmation_status")
    if status:
        detail["Confirmation status"] = status
    if record.get("attempts") is not None:
        detail["Attempts"] = record["attempts"]
    for label, key in (
        ("Trigger summary", "trigger_summary"),
        ("Probe script", "probe_script"),
        ("Probe output", "probe_stdout"),
        ("Validation error", "validation_error"),
    ):
        value = record.get(key)
        if value:
            detail[label] = value
    return detail


def _collect_bugs(work_dir):
    """Collect bug items, preferring the aggregated summary.json.

    ``summary.json`` (written deterministically by
    ``verification._generate_*_validation_summary``) is the authoritative list:
    in ``--all-bugs`` mode it synthesises ``pending`` records that have no
    ``.result.json`` on disk, so reading it first is required to not lose them.
    """
    records = None
    summary_path = os.path.join(work_dir, "bug_validation", "summary.json")
    try:
        with open(summary_path, "r", encoding="utf-8") as f:
            summary = json.load(f)
        bugs = summary.get("bugs")
        if isinstance(bugs, list):
            records = bugs
    except (OSError, ValueError):
        pass

    if records is None:
        records = []
        bv = os.path.join(work_dir, "bug_validation")
        if os.path.isdir(bv):
            for fname in sorted(os.listdir(bv)):
                if not fname.endswith(".result.json"):
                    continue
                try:
                    with open(os.path.join(bv, fname), "r", encoding="utf-8") as f:
                        records.append(json.load(f))
                except (OSError, ValueError):
                    continue

    items = []
    for record in records:
        if not isinstance(record, dict):
            continue
        bug_id = record.get("id") or ""
        src = record.get("source_file") or ""
        fn = record.get("function_name") or _func_name(src)
        items.append({
            "kind": "bug",
            "id": bug_id,
            "title": f"Bug Report: {fn}" if fn else "Bug Report",
            "status": str(record.get("confirmation_status") or "pending"),
            "source_file": _map_source(src),
            "function_name": fn,
            "location": "",
            "detail_ref": _bug_detail_ref(work_dir, bug_id),
            "detail": _bug_detail(record),
        })
    return items


def _analysis_detail(result):
    """Build the expandable technical detail block for an analysis result."""
    detail = {}
    verdict = result.get("verdict")
    if verdict:
        detail["Verdict"] = verdict
    gaps = result.get("gaps")
    if isinstance(gaps, dict):
        for label, key in (
            ("Spec claim", "spec_claim"),
            ("Actual behavior", "actual_behavior"),
            ("Code evidence", "code_evidence"),
            ("Trigger condition", "trigger_condition"),
        ):
            value = gaps.get(key)
            if value:
                detail[label] = value
    if result.get("error"):
        detail["Error"] = result["error"]
    if result.get("all_bugs") is not None:
        detail["All-bugs candidates"] = result.get("bug_count")
        detail["Reasoning complete"] = result.get("reasoning_complete")
    return detail


def _collect_analyses(work_dir):
    """Collect one item per function-level verification result.

    ``*.bug-NNN.json`` candidate files are skipped: in ``--all-bugs`` mode each
    candidate already has its own bug-validation record, so including them here
    would double-count the same function.
    """
    results_dir = os.path.join(work_dir, "logic_verification_results")
    items = []
    if not os.path.isdir(results_dir):
        return items
    for root, _dirs, files in os.walk(results_dir):
        for fname in sorted(files):
            if not fname.endswith(".json") or _CANDIDATE_RE.search(fname):
                continue
            path = os.path.join(root, fname)
            try:
                with open(path, "r", encoding="utf-8") as f:
                    result = json.load(f)
            except (OSError, ValueError):
                continue
            if not isinstance(result, dict):
                continue
            rel = os.path.relpath(path, results_dir).replace(os.sep, "/")
            func = result.get("function") or ""
            fn = _func_name(func)
            items.append({
                "kind": "analysis",
                "id": rel,
                "title": f"Analysis: {fn}" if fn else "Analysis",
                "status": str(result.get("verdict") or "ERROR"),
                "source_file": _map_source(func),
                "function_name": fn,
                "location": "",
                "detail_ref": f"logic_verification_results/{rel}",
                "detail": _analysis_detail(result),
            })
    return items


def _match_span(spans, fn):
    """Match a function name against codegraph spans; return ``L<start>-L<end>``.

    ``get_function_spans`` returns one span per node with the base extraction
    identifier (no ``_N`` suffix), so overloads yield several same-named spans
    in line order. A free function and a member with the same short name can
    coexist in one file (e.g. ``Flush`` next to ``Cache::Flush``): an exact
    ident match always wins first, so the bare ``Flush`` never lands on the
    member's earlier span; ``::``-qualified short-name matching is a second
    pass kept for filenames whose class qualifier was sanitised away
    (``operator[]``). If ``fn`` carries a ``_N`` dedup suffix, strip it and
    take the Nth span with that exact base ident (``::``-qualified base idents
    fall back to ``::``-suffix matching when no exact base exists), so
    overloads resolve even when an unrelated same-short-name member precedes
    them in line order. Anything unmatched returns "" (the page shows "—").
    """
    if not spans:
        return ""
    for name, start, end in spans:
        if name == fn:
            # codegraph spans are 0-indexed inclusive; display 1-indexed.
            return f"L{start + 1}-L{end + 1}"
    for name, start, end in spans:
        if name.endswith("::" + fn):
            return f"L{start + 1}-L{end + 1}"
    m = re.match(r"^(.*)_(\d+)$", fn)
    if m:
        base, idx = m.group(1), int(m.group(2))
        pool = [s for s in spans if s[0] == base]
        if not pool:
            pool = [s for s in spans if s[0].endswith("::" + base)]
        if idx < len(pool):
            name, start, end = pool[idx]
            return f"L{start + 1}-L{end + 1}"
    return ""


def _enrich_locations(work_dir, items):
    """Best-effort fill ``location`` from the codegraph index, when available.

    The codegraph database lives in the project root (``.codegraph/codegraph.db``),
    found via ``CodeGraphExtractor.from_proj_dir`` (checks the workdir and its
    parent). Any failure — missing db, unsupported language, unindexed file —
    leaves ``location`` empty and the page renders "—".
    """
    try:
        from src.languages.codegraph import CodeGraphExtractor
        extractor = CodeGraphExtractor.from_proj_dir(work_dir)
    except Exception:
        return items
    if extractor is None:
        return items
    proj_root = os.path.dirname(os.path.abspath(work_dir))
    for item in items:
        src = item.get("source_file") or ""
        fn = item.get("function_name") or ""
        if not src or not fn:
            continue
        ext = src.rsplit(".", 1)[-1] if "." in src else ""
        lang_key = _EXT_TO_LANG.get(ext)
        if not lang_key:
            continue
        try:
            spans = extractor.get_function_spans(lang_key, os.path.join(proj_root, src))
        except Exception:
            spans = None
        loc = _match_span(spans, fn)
        if loc:
            item["location"] = loc
    return items


def _attach_source_href(work_dir, items):
    """Best-effort add ``source_href``: report.html → original source file.

    report.html lives in ``work_dir``; the original source tree sits next to it
    at the project root (``os.path.dirname(work_dir)``, the same heuristic
    ``_enrich_locations`` uses). The href is a pure function of the paths — no
    filesystem reads — so regeneration stays byte-deterministic, and the link
    resolves whenever the project directory is found alongside the report.
    """
    work_dir_abs = os.path.abspath(work_dir)
    proj_root = os.path.dirname(work_dir_abs)
    for item in items:
        src = item.get("source_file") or ""
        if not src or src.startswith("/") or ".." in src.split("/"):
            continue
        target = os.path.join(proj_root, src.replace("/", os.sep))
        item["source_href"] = os.path.relpath(target, work_dir_abs).replace(os.sep, "/")
    return items


# ---------------------------------------------------------------------------
# HTML rendering
# ---------------------------------------------------------------------------

_HTML_TEMPLATE = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>FM-Agent Report Index</title>
<style>
:root {
  --bg: #ffffff; --panel: #ffffff; --border: #d0d7de;
  --text: #1f2328; --muted: #59636e; --accent: #0969da;
  color-scheme: light;
}
* { box-sizing: border-box; }
body { margin: 0; background: var(--bg); color: var(--text);
       font: 14px/1.45 ui-sans-serif, system-ui, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; }
header { padding: 18px 22px 10px; }
h1 { margin: 0 0 4px; font-size: 20px; }
#stats { color: var(--muted); margin: 0 0 12px; font-size: 13px; }
.controls { display: flex; flex-wrap: wrap; gap: 10px 18px; align-items: flex-start; }
.controls label.opt { display: block; color: var(--text); font-size: 12px; margin: 2px 0; }
.opt input[type="checkbox"] { vertical-align: middle; }
#search { width: 260px; max-width: 100%; padding: 6px 10px; border-radius: 6px;
          border: 1px solid var(--border); background: var(--panel); color: var(--text); }
#sort { padding: 6px 8px; border-radius: 6px; border: 1px solid var(--border);
        background: var(--panel); color: var(--text); }
button { padding: 6px 10px; border-radius: 6px; border: 1px solid var(--border);
         background: var(--panel); color: var(--text); cursor: pointer; }
button:hover { border-color: var(--accent); }
.filter-group { border: 2px solid var(--border); border-radius: 6px; padding: 6px 10px;
                max-height: 160px; overflow: auto; min-width: 150px; }
.filter-group.grow { max-height: none; }
.filter-group .fg-title { font-size: 11px; text-transform: uppercase; letter-spacing: .04em;
                          color: var(--muted); margin-bottom: 4px; }
#file-opts, #status-opts { overflow-wrap: anywhere; }
#file-opts ul.tree, #status-opts ul.tree { list-style: none; margin: 0; padding-left: 0; }
#file-opts ul.tree ul, #status-opts ul.tree ul { list-style: none; margin: 0; padding-left: 13px; }
#file-opts .dir, #status-opts .dir { display: flex; align-items: center; gap: 4px; font-size: 12px;
                  cursor: pointer; padding: 1px 0; color: var(--text); user-select: none; }
#file-opts .dir-label, #status-opts .dir-label { cursor: pointer; }
#file-opts .dir-label:hover, #status-opts .dir-label:hover { color: var(--accent); }
#file-opts label.opt, #status-opts label.opt { padding-left: 0; }
.hidden { display: none !important; }
main { padding: 6px 22px 40px; }
ul#items { list-style: none; margin: 0; padding: 0; }
li.item { margin: 0 0 8px; border: 2px solid var(--border); border-radius: 8px;
          background: var(--panel); overflow: hidden; }
.head { display: grid; grid-template-columns: 72px 104px minmax(0, 2.2fr) minmax(0, 1.6fr) minmax(0, 1fr) 96px auto;
        gap: 8px; align-items: center; padding: 9px 12px; cursor: pointer; }
.head:hover { background: #f6f8fa; }
.head .title { font-weight: 600; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.head .file, .head .func, .head .loc { color: var(--muted); overflow: hidden;
        text-overflow: ellipsis; white-space: nowrap; }
.head a.file, .head button.file { color: var(--accent); text-decoration: none; }
.head a.file:hover, .head button.file:hover { text-decoration: underline; }
.head button.file { border: 0; background: none; padding: 0; font: inherit;
        cursor: pointer; text-align: left; }
.head .loc { font-variant-numeric: tabular-nums; }
.head .badge { justify-self: stretch; text-align: center; }
.chev { color: var(--muted); user-select: none; }
.badge { display: inline-block; padding: 2px 8px; border-radius: 999px;
         font-size: 11px; font-weight: 600; color: #fff; white-space: nowrap; }
.kind-bug { background: #8250df; }
.kind-analysis { background: #0969da; }
.status-confirmed { background: #cf222e; }
.status-MATCH { background: #1a7f37; }
.status-not_confirmed { background: #2da44e; }
.status-MISMATCH { background: #9a6700; }
.status-error, .status-ERROR { background: #a40e26; }
.status-pending, .status-SKIPPED { background: #59636e; }
.details { display: grid; grid-template-columns: minmax(0, 1fr) minmax(0, 1fr); gap: 18px;
           padding: 10px 14px 12px; border-top: 2px solid var(--border); }
.detail-left, .detail-right { min-width: 0; }
.detail-row { margin: 0 0 10px; }
.detail-label { color: var(--muted); font-size: 12px; font-weight: 600;
                text-transform: uppercase; letter-spacing: .03em; margin-bottom: 2px; }
.detail-value { white-space: pre-wrap; word-break: break-word; }
.detail-value pre { margin: 0; padding: 8px 10px; border-radius: 6px; background: #f6f8fa;
                    border: 2px solid var(--border); overflow-x: auto;
                    font: 12px/1.5 ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; }
.open-link { display: inline-block; margin-top: 4px; color: var(--accent); text-decoration: none;
             border: 0; background: none; padding: 0; font: inherit; cursor: pointer; }
.open-link:hover { text-decoration: underline; }
.detail-empty { color: var(--muted); font-style: italic; }
.src-head { display: flex; justify-content: space-between; gap: 8px; font-size: 11px;
            color: var(--muted); text-transform: uppercase; letter-spacing: .04em;
            margin-bottom: 4px; overflow: hidden; }
.src-head span { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.src-code { margin: 0; border-radius: 6px; border: 2px solid var(--border); overflow-x: auto;
            background: var(--panel); font: 12px/1.55 ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; }
.src-line { display: flex; padding: 0 10px; white-space: pre; }
.src-line.hl { background: #fff8c5; }
.src-line .ln { flex: none; width: 3em; text-align: right; padding-right: 12px;
                color: var(--muted); font-variant-numeric: tabular-nums; user-select: none; }
.src-line .code { flex: 1; }
.tk-kw { color: #cf222e; }
.tk-str { color: #0a3069; }
.tk-com { color: #6e7781; }
.tk-num { color: #0550ae; }
.tk-fn { color: #8250df; }
.src-empty { color: var(--muted); font-style: italic; }
#page-overlay { position: fixed; inset: 0; z-index: 99; background: #fff; overflow: auto;
                display: none; padding: 0; }
#page-overlay.show { display: block; }
@media (max-width: 900px) { .details { grid-template-columns: 1fr; } }
#empty { color: var(--muted); text-align: center; padding: 40px 0; }
</style>
</head>
<body>
<header>
  <h1>FM-Agent Report Index</h1>
  <div id="stats"></div>
  <div class="controls">
    <input id="search" type="search" placeholder="Search title / file / function / location" autocomplete="off">
    <div class="filter-group grow"><div class="fg-title">Type / Status</div>
      <div id="status-opts"></div>
    </div>
    <div class="filter-group"><div class="fg-title">Source file</div><div id="file-opts"></div></div>
    <div class="filter-group">
      <div class="fg-title">Sort</div>
      <select id="sort">
        <option value="status" selected>status</option>
        <option value="file">file</option>
        <option value="function">function</option>
      </select>
    </div>
    <div class="filter-group">
      <div class="fg-title">Actions</div>
      <button id="expand-all" type="button">Expand all</button>
      <button id="collapse-all" type="button">Collapse all</button>
      <button id="reset" type="button">Reset</button>
    </div>
  </div>
</header>
<main>
  <div id="empty" class="hidden">No reports match your filters. Adjust the search or filters, or press <b>Reset</b>.</div>
  <ul id="items"></ul>
</main>
<script id="report-data" type="application/json">__DATA__</script>
<script id="source-data" type="application/json">__SOURCES__</script>
<script>
const DATA = JSON.parse(document.getElementById('report-data').textContent);
const SOURCES = JSON.parse(document.getElementById('source-data').textContent);
const STATUS_RANK = {confirmed:0, not_confirmed:1, error:2, pending:3, MISMATCH:10, MATCH:11, ERROR:12, SKIPPED:13};
// Display label per status; the underlying status value (badge class, filter
// checkbox value, sort keys) is unchanged — only what the user reads differs.
const STATUS_LABEL = {
  MISMATCH: 'bug_candidate',
  MATCH: 'passed',
  confirmed: 'confirmed',
  not_confirmed: 'not_confirmed',
  error: 'error',
  pending: 'pending',
  ERROR: 'error',
  SKIPPED: 'skipped',
};

const state = {
  search: '',
  statuses: new Set(),
  files: new Set(),
  fileDirs: new Set(),
  fileSeeded: false,
  statusDirs: new Set(),
  sort: 'status',
  expanded: new Set(),
};

const $ = (id) => document.getElementById(id);

function matches(it) {
  if (state.statuses.size && !state.statuses.has(it.status)) return false;
  if (state.files.size && !state.files.has(it.source_file)) return false;
  const q = state.search.trim().toLowerCase();
  if (q) {
    const hay = [it.title, it.source_file, it.function_name, it.location].join(' ').toLowerCase();
    if (!hay.includes(q)) return false;
  }
  return true;
}

function cmp(a, b) {
  let k = 0;
  switch (state.sort) {
    case 'file': k = a.source_file < b.source_file ? -1 : a.source_file > b.source_file ? 1 : 0; break;
    case 'function':
      k = a.function_name < b.function_name ? -1 : a.function_name > b.function_name ? 1 : 0;
      // Same function name in different files: group every item from the same
      // file together before the kind/id tie-breaks interleave them.
      if (k === 0) k = a.source_file < b.source_file ? -1 : a.source_file > b.source_file ? 1 : 0;
      break;
    default: k = (STATUS_RANK[a.status] ?? 99) - (STATUS_RANK[b.status] ?? 99);
  }
  if (k === 0) k = a.kind < b.kind ? -1 : a.kind > b.kind ? 1 : 0;
  if (k === 0) k = a.id < b.id ? -1 : a.id > b.id ? 1 : 0;
  return k;
}

function badge(cls, text) {
  const s = document.createElement('span');
  s.className = 'badge ' + cls;
  s.textContent = text;
  return s;
}

function buildStatusOptions() {
  // Type / Status tree: bug and analysis are root "directories", their statuses
  // nest beneath like files. Checking a root selects all of its statuses
  // (indeterminate when partial). Root rows default to collapsed.
  const container = $('status-opts');
  container.textContent = '';
  const ul = document.createElement('ul');
  ul.className = 'tree';
  const KIND_ORDER = { bug: 0, analysis: 1 };
  const kinds = [...new Set(DATA.map((it) => it.kind))].sort((a, b) =>
    (KIND_ORDER[a] ?? 99) - (KIND_ORDER[b] ?? 99) || (a < b ? -1 : a > b ? 1 : 0));
  for (const k of kinds) {
    const vals = Array.from(new Set(DATA.filter((it) => it.kind === k).map((it) => it.status)))
      .filter((v) => v !== '')
      .sort((a, b) => (STATUS_RANK[a] ?? 99) - (STATUS_RANK[b] ?? 99) || (a < b ? -1 : a > b ? 1 : 0));
    if (!vals.length) continue;
    const li = document.createElement('li');
    const row = document.createElement('div');
    row.className = 'dir';
    const cb = document.createElement('input');
    cb.type = 'checkbox';
    const n = vals.length, sel = vals.filter((v) => state.statuses.has(v)).length;
    cb.checked = n > 0 && sel === n;
    cb.indeterminate = sel > 0 && sel < n;
    cb.addEventListener('change', () => {
      for (const v of vals) cb.checked ? state.statuses.add(v) : state.statuses.delete(v);
      render();
    });
    const label = document.createElement('span');
    label.className = 'dir-label';
    const open = state.statusDirs.has(k);
    label.textContent = (open ? '▾ ' : '▸ ') + k;
    label.addEventListener('click', () => {
      if (state.statusDirs.has(k)) state.statusDirs.delete(k); else state.statusDirs.add(k);
      render();
    });
    row.appendChild(cb); row.appendChild(label);
    li.appendChild(row);
    const sub = document.createElement('ul');
    for (const v of vals) {
      const vli = document.createElement('li');
      const vlabel = document.createElement('label');
      vlabel.className = 'opt';
      const vcb = document.createElement('input');
      vcb.type = 'checkbox';
      vcb.value = v;
      vcb.checked = state.statuses.has(v);
      vcb.addEventListener('change', () => {
        if (vcb.checked) state.statuses.add(v); else state.statuses.delete(v);
        render();
      });
      vlabel.appendChild(vcb);
      vlabel.appendChild(document.createTextNode(' ' + (STATUS_LABEL[v] || v)));
      vli.appendChild(vlabel);
      sub.appendChild(vli);
    }
    sub.classList.toggle('hidden', !open);
    li.appendChild(sub);
    ul.appendChild(li);
  }
  container.appendChild(ul);
}

function buildFileTree(container, values, selected) {
  // Collapsible multi-level tree of source files. Leaf checkboxes keep the exact
  // full source_file value as the filter key, so matches() semantics are unchanged;
  // directory checkboxes select every descendant file (indeterminate when partial).
  const root = { name: '', values: [], children: new Map() };
  const distinct = Array.from(new Set(values)).filter((v) => v !== '').sort();
  for (const v of distinct) {
    const segs = v.replace(/\\/g, '/').split('/').filter(Boolean);
    if (!segs.length) continue;
    let node = root, key = '';
    for (let i = 0; i < segs.length; i++) {
      key = key ? key + '/' + segs[i] : segs[i];
      if (!node.children.has(segs[i])) {
        node.children.set(segs[i], { name: segs[i], key, values: [], children: new Map() });
      }
      node = node.children.get(segs[i]);
      if (i === segs.length - 1) node.values.push(v);
    }
  }
  // Collect each node's own + all descendant values for directory select-all.
  const collect = (n) => {
    for (const c of n.children.values()) {
      collect(c);
      for (const v of c.values) n.values.push(v);
    }
  };
  collect(root);
  // Default expansion: top-level directories only (seed once, then Set is authoritative).
  if (!state.fileSeeded) {
    for (const c of root.children.values()) if (c.children.size) state.fileDirs.add(c.key);
    state.fileSeeded = true;
  }
  container.textContent = '';
  const ul = document.createElement('ul');
  ul.className = 'tree';
  const renderNode = (node, parentUl) => {
    const dirs = [], leaves = [];
    for (const c of node.children.values()) (c.children.size ? dirs : leaves).push(c);
    dirs.sort((a, b) => a.name < b.name ? -1 : 1);
    leaves.sort((a, b) => a.name < b.name ? -1 : 1);
    for (const d of dirs) {
      const open = state.fileDirs.has(d.key);
      const li = document.createElement('li');
      const row = document.createElement('div');
      row.className = 'dir';
      const cb = document.createElement('input');
      cb.type = 'checkbox';
      const n = d.values.length, sel = d.values.filter((v) => selected.has(v)).length;
      cb.checked = n > 0 && sel === n;
      cb.indeterminate = sel > 0 && sel < n;
      cb.addEventListener('change', () => {
        for (const v of d.values) cb.checked ? selected.add(v) : selected.delete(v);
        render();
      });
      const label = document.createElement('span');
      label.className = 'dir-label';
      label.textContent = (open ? '▾ ' : '▸ ') + d.name;
      label.addEventListener('click', () => {
        if (state.fileDirs.has(d.key)) state.fileDirs.delete(d.key); else state.fileDirs.add(d.key);
        render();
      });
      row.appendChild(cb); row.appendChild(label);
      li.appendChild(row);
      const sub = document.createElement('ul');
      renderNode(d, sub);
      sub.classList.toggle('hidden', !open);
      li.appendChild(sub);
      parentUl.appendChild(li);
    }
    for (const f of leaves) {
      for (const v of f.values) {
        const li = document.createElement('li');
        const label = document.createElement('label');
        label.className = 'opt';
        const cb = document.createElement('input');
        cb.type = 'checkbox';
        cb.value = v;
        cb.checked = selected.has(v);
        cb.addEventListener('change', () => {
          if (cb.checked) selected.add(v); else selected.delete(v);
          render();
        });
        label.appendChild(cb);
        label.appendChild(document.createTextNode(' ' + f.name));
        li.appendChild(label);
        parentUl.appendChild(li);
      }
    }
  };
  renderNode(root, ul);
  container.appendChild(ul);
}

function detailBody(it) {
  const body = document.createElement('div');
  body.className = 'detail-left';
  const entries = Object.entries(it.detail || {});
  for (const [label, value] of entries) {
    const row = document.createElement('div');
    row.className = 'detail-row';
    const l = document.createElement('div');
    l.className = 'detail-label';
    l.textContent = label + ':';
    row.appendChild(l);
    const v = document.createElement('div');
    v.className = 'detail-value';
    if (String(value).indexOf('\n') !== -1) {
      const pre = document.createElement('pre');
      pre.textContent = value;
      v.appendChild(pre);
    } else {
      v.textContent = value;
    }
    row.appendChild(v);
    body.appendChild(row);
  }
  if (it.detail_full) {
    const link = document.createElement('button');
    link.className = 'open-link';
    link.type = 'button';
    link.textContent = 'Open full report ↗';
    // A <button> has no default navigation, so a click can never fall through
    // to an href="#" (report.html#). document.write avoids blob-URL windows.
    link.addEventListener('click', () => openPage(fullPageHTML(it)));
    body.appendChild(link);
  }
  if (!entries.length && !it.detail_full) {
    const d = document.createElement('div');
    d.className = 'detail-empty';
    d.textContent = 'No technical details available.';
    body.appendChild(d);
  }
  return body;
}

function parseLoc(loc) {
  // "L6-L6" / "L6-L7" -> {start, end}; unmatched -> null
  const m = /^L(\d+)(?:-L(\d+))?$/.exec(loc || '');
  if (!m) return null;
  const a = +m[1], b = m[2] ? +m[2] : a;
  return { start: Math.min(a, b), end: Math.max(a, b) };
}

const KEYWORDS = new Set(('if else elif return def class struct void int char long float double bool '
  + 'true false null nullptr new delete for while do switch case break continue const static public '
  + 'private protected virtual override unsigned signed sizeof using namespace import from include '
  + 'function var let this self try except finally lambda yield async await goto').split(' '));

// Lightweight GitHub-light tokenizer. ``st`` ({inBlock, inStr}) carries state
// across lines so block comments and multi-line strings colour correctly.
function highlightLine(line, st) {
  const out = [];
  const push = (text, cls) => { if (text) out.push({ t: text, c: cls }); };
  const isId = (c) => /[A-Za-z_]/.test(c);
  const isNum = (c) => /[0-9]/.test(c);
  const isNumCh = (c) => /[0-9_.a-fA-FxXbBoOeE]/.test(c);
  let i = 0, n = line.length;
  while (i < n) {
    const ch = line[i];
    if (st.inStr) {
      let j = i, esc = false, closed = false;
      while (j < n) {
        if (esc) { esc = false; j++; continue; }
        if (line[j] === '\\') { esc = true; j++; continue; }
        if (line[j] === st.inStr) { j++; closed = true; break; }
        j++;
      }
      if (closed) st.inStr = null; // unterminated -> keep state, carry to next line
      push(line.slice(i, j), 'str');
      i = j;
      continue;
    }
    if (st.inBlock) {
      const end = line.indexOf('*/', i);
      if (end === -1) { push(line.slice(i), 'com'); i = n; }
      else { push(line.slice(i, end + 2), 'com'); st.inBlock = false; i = end + 2; }
      continue;
    }
    if (ch === '/' && line[i + 1] === '/') { push(line.slice(i), 'com'); i = n; continue; }
    if (ch === '/' && line[i + 1] === '*') {
      const end = line.indexOf('*/', i + 2);
      if (end === -1) { push(line.slice(i), 'com'); st.inBlock = true; i = n; }
      else { push(line.slice(i, end + 2), 'com'); i = end + 2; }
      continue;
    }
    if (ch === '#') { push(line.slice(i), 'com'); i = n; continue; }
    if (ch === '"' || ch === "'" || ch === '`') {
      if (line[i + 1] === ch && line[i + 2] === ch) { // triple-quoted string
        const end = line.indexOf(ch + ch + ch, i + 3);
        if (end === -1) { push(line.slice(i), 'str'); st.inStr = ch; i = n; }
        else { push(line.slice(i, end + 3), 'str'); i = end + 3; }
        continue;
      }
      let j = i + 1, esc = false, closed = false;
      while (j < n) {
        if (esc) { esc = false; j++; continue; }
        if (line[j] === '\\') { esc = true; j++; continue; }
        if (line[j] === ch) { j++; closed = true; break; }
        j++;
      }
      if (!closed) st.inStr = ch; // unterminated on this line, carry to next
      push(line.slice(i, j), 'str');
      i = j;
      continue;
    }
    if (isNum(ch) || (ch === '.' && isNum(line[i + 1]))) {
      let j = i;
      while (j < n && isNumCh(line[j])) j++;
      push(line.slice(i, j), 'num');
      i = j;
      continue;
    }
    if (isId(ch)) {
      let j = i;
      while (j < n && /[\w$]/.test(line[j])) j++;
      const word = line.slice(i, j);
      let k = j;
      while (k < n && line[k] === ' ') k++;
      push(word, line[k] === '(' ? 'fn' : KEYWORDS.has(word) ? 'kw' : '');
      i = j;
      continue;
    }
    push(ch, '');
    i++;
  }
  return out;
}

function sourceBody(it) {
  const col = document.createElement('div');
  col.className = 'detail-right';
  const content = SOURCES[it.source_file];
  if (content == null) {
    const d = document.createElement('div');
    d.className = 'src-empty';
    d.textContent = 'Source not embedded';
    col.appendChild(d);
    return col;
  }
  const head = document.createElement('div');
  head.className = 'src-head';
  const name = document.createElement('span');
  name.textContent = it.source_file;
  const fn = document.createElement('span');
  fn.textContent = it.function_name ? it.function_name + ' · ' : '';
  const loc = document.createElement('span');
  loc.textContent = it.location || '—';
  head.appendChild(name); head.appendChild(fn); head.appendChild(loc);
  col.appendChild(head);
  const pre = document.createElement('pre');
  pre.className = 'src-code';
  const lines = content.replace(/\n$/, '').split('\n'); // drop the trailing blank row
  const range = parseLoc(it.location);
  // Show only the erroneous function body (its exact line range); without a
  // location the whole file is shown as a fallback. No highlight band here —
  // the compact expanded view stays plain (syntax colours only); the
  // self-contained source page keeps the band instead.
  const start = range ? range.start : 1;
  const end = range ? range.end : lines.length;
  const st = { inBlock: false, inStr: null };
  for (let i = start - 1; i < end; i++) {
    const row = document.createElement('div');
    row.className = 'src-line';
    const ln = document.createElement('span');
    ln.className = 'ln';
    ln.textContent = String(i + 1);
    row.appendChild(ln);
    const code = document.createElement('span');
    code.className = 'code';
    const tokens = highlightLine(lines[i], st);
    for (const tok of tokens) {
      const s = document.createElement('span');
      if (tok.c) s.className = 'tk-' + tok.c;
      s.textContent = tok.t;
      code.appendChild(s);
    }
    row.appendChild(code);
    pre.appendChild(row);
  }
  col.appendChild(pre);
  return col;
}

function escapeHtml(s) {
  return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

// Lightweight GitHub-ish markdown: escape first, then structural transforms, so
// the produced HTML never carries raw user text. Fenced code stays escaped.
function renderInline(s) {
  let out = escapeHtml(s);
  out = out.replace(/`([^`]+)`/g, '<code>$1</code>');
  out = out.replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>');
  out = out.replace(/(^|[\s(])\*([^*\n]+)\*/g, '$1<em>$2</em>');
  // The full-report page is a read-only view: markdown links render as plain
  // text — link label followed by the local file location in parens (no <a>),
  // so URLs surface as inert text and are never clickable.
  out = out.replace(/\[([^\]]+)\]\(([^)\s]+)\)/g, (m, t, u) => t + ' (' + u + ')');
  return out;
}

function renderMarkdown(text) {
  const lines = String(text || '').replace(/\r\n/g, '\n').split('\n');
  let html = '', i = 0, inCode = false, buf = [];
  while (i < lines.length) {
    const line = lines[i];
    if (/^```/.test(line)) {
      if (inCode) { html += '<pre><code>' + buf.join('\n') + '</code></pre>'; buf = []; inCode = false; }
      else inCode = true;
      i++; continue;
    }
    if (inCode) { buf.push(escapeHtml(line)); i++; continue; }
    const h = /^(#{1,6})\s+(.*)$/.exec(line);
    if (h) { const n = h[1].length; html += '<h' + n + '>' + renderInline(h[2]) + '</h' + n + '>'; i++; continue; }
    if (/^\s*(?:-{3,}|\*{3,}|_{3,})\s*$/.test(line)) { html += '<hr>'; i++; continue; }
    if (/^>\s?/.test(line)) {
      const q = [];
      while (i < lines.length && /^>\s?/.test(lines[i])) { q.push(lines[i].replace(/^>\s?/, '')); i++; }
      html += '<blockquote>' + q.map((l) => '<p>' + renderInline(l) + '</p>').join('') + '</blockquote>';
      continue;
    }
    if (/^([-*+]|\d+[.)])\s+/.test(line)) {
      const ordered = /^\d+[.)]\s+/.test(line);
      const items = [];
      while (i < lines.length && /^([-*+]|\d+[.)])\s+/.test(lines[i])) {
        items.push('<li>' + renderInline(lines[i].replace(/^([-*+]|\d+[.)])\s+/, '')) + '</li>');
        i++;
      }
      html += (ordered ? '<ol>' : '<ul>') + items.join('') + (ordered ? '</ol>' : '</ul>');
      continue;
    }
    if (/^\s*$/.test(line)) { i++; continue; }
    const para = [line]; i++;
    while (i < lines.length && !/^\s*$/.test(lines[i])
        && !/^(#{1,6})\s/.test(lines[i]) && !/^```/.test(lines[i])
        && !/^>\s?/.test(lines[i]) && !/^([-*+]|\d+[.)])\s/.test(lines[i])) {
      para.push(lines[i]); i++;
    }
    html += '<p>' + renderInline(para.join(' ')) + '</p>';
  }
  if (inCode) html += '<pre><code>' + buf.join('\n') + '</code></pre>';
  return html;
}

function renderFull(it) {
  const text = it.detail_full || '';
  if (/\.json$/i.test(it.detail_ref || '')) {
    try { return '<pre class="pre-json">' + escapeHtml(JSON.stringify(JSON.parse(text), null, 2)) + '</pre>'; }
    catch (e) { return '<pre class="pre-json">' + escapeHtml(text) + '</pre>'; }
  }
  return renderMarkdown(text);
}

// GitHub-light styles for the self-contained source views. These pages are
// separate documents (opened via window.open + document.write), so they carry
// their own copy of the source classes instead of inheriting the main page's.
const SRC_PAGE_CSS = '.src-code{margin:0;border-radius:6px;border:1px solid #d0d7de;overflow-x:auto;'
  + 'background:#fff;font:12px/1.55 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;}'
  + '.src-line{display:flex;padding:0 10px;white-space:pre;}'
  + '.src-line.hl{background:#fff8c5;}'
  + '.src-line .ln{flex:none;width:3em;text-align:right;padding-right:12px;color:#59636e;'
  + 'font-variant-numeric:tabular-nums;user-select:none;}'
  + '.src-line .code{flex:1;}.tk-kw{color:#cf222e;}.tk-str{color:#0a3069;}.tk-com{color:#6e7781;}'
  + '.tk-num{color:#0550ae;}.tk-fn{color:#8250df;}'
  + '.src-empty{color:#59636e;font-style:italic;}';

const FULL_PAGE_CSS = 'body{font:14px/1.6 ui-sans-serif,system-ui,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;'
  + 'color:#1f2328;max-width:860px;margin:0 auto;padding:28px 20px;}'
  + '.page-head{font-weight:600;font-size:13px;text-transform:uppercase;letter-spacing:.04em;'
  + 'color:#59636e;border-bottom:1px solid #d0d7de;padding-bottom:6px;margin-bottom:10px;}'
  + 'h1,h2,h3,h4,h5,h6{font-weight:600;line-height:1.25;margin:16px 0 8px;}'
  + 'h1,h2{border-bottom:1px solid #d0d7de;padding-bottom:.3em;}h1{font-size:1.6em;}h2{font-size:1.3em;}'
  + 'p{margin:0 0 12px;}'
  + 'pre{padding:12px 14px;border-radius:6px;background:#f6f8fa;border:1px solid #d0d7de;overflow-x:auto;'
  + 'font:12px/1.55 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;}'
  + '.pre-json{white-space:pre;}'
  + 'code{background:#f6f8fa;border-radius:4px;padding:1px 4px;'
  + 'font:12px/1.5 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;}'
  + 'pre code{background:none;padding:0;}'
  + 'blockquote{border-left:4px solid #d0d7de;color:#59636e;margin:0 0 12px;padding:0 14px;}'
  + 'hr{border:0;border-top:1px solid #d0d7de;margin:18px 0;}'
  + 'a{color:#0969da;text-decoration:none;}a:hover{text-decoration:underline;}'
  + 'ul,ol{margin:0 0 12px;padding-left:24px;}li{margin:2px 0;}';

// Full file rendered as an HTML string. Every token is escapeHtml'd before
// concatenation, so the result is safe for innerHTML / document.write. Lines
// inside ``range`` (the erroneous function) get the highlight band.
function srcLinesHTML(content, range) {
  if (content == null) return '<div class="src-empty">Source not embedded</div>';
  const lines = String(content).replace(/\n$/, '').split('\n');
  let html = '', st = { inBlock: false, inStr: null };
  for (let i = 0; i < lines.length; i++) {
    const n = i + 1;
    const hl = range && n >= range.start && n <= range.end ? ' hl' : '';
    let code = '';
    for (const tok of highlightLine(lines[i], st)) {
      code += (tok.c ? '<span class="tk-' + tok.c + '">' : '<span>')
        + escapeHtml(tok.t) + '</span>';
    }
    html += '<div class="src-line' + hl + '"><span class="ln">' + n + '</span>'
      + '<span class="code">' + code + '</span></div>';
  }
  return '<pre class="src-code">' + html + '</pre>';
}

function pageChrome(title, css, body) {
  return '<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">'
    + '<title>' + escapeHtml(title) + '</title>'
    + '<style>' + css + '</style></head><body>' + body + '</body></html>';
}

function fullPageHTML(it) {
  // Single-column self-contained detail page: just the rendered report.
  const title = (it.title || 'Report') + (it.source_file ? ' — ' + it.source_file : '');
  return pageChrome(title, FULL_PAGE_CSS,
    '<div class="page-head">Full report</div>' + renderFull(it));
}

function sourcePageHTML(it) {
  // Self-contained source-only page: the full file, syntax-highlighted, with
  // the erroneous function's line range banded.
  const title = (it.function_name || 'Source') + ' — ' + (it.source_file || '');
  const range = parseLoc(it.location);
  const body = '<div class="page-head">' + escapeHtml(it.source_file || 'Source')
    + (it.function_name ? ' · ' + escapeHtml(it.function_name) : '')
    + (it.location ? ' · ' + escapeHtml(it.location) : '') + '</div>'
    + srcLinesHTML(SOURCES[it.source_file], range);
  return pageChrome(title, FULL_PAGE_CSS + SRC_PAGE_CSS, body);
}

// Robust self-contained new page. document.write avoids blob-URL navigation,
// which is unreliable from file:// (it would fall back to the anchor's href="#"
// and the address turns into report.html#). If the popup is blocked, the same
// HTML is shown in an in-page overlay so the content is always reachable.
function openPage(html) {
  let w = null;
  try { w = window.open('', '_blank'); } catch (e) { w = null; }
  if (w && w.document) {
    try {
      w.document.open();
      w.document.write(html);
      w.document.close();
    } catch (e) { w = null; }
  }
  if (!w || !w.document) {
    const ov = document.getElementById('page-overlay');
    if (ov) {
      ov.innerHTML = html;
      ov.classList.add('show');
    }
  }
}

function rowEl(it) {
  const li = document.createElement('li');
  li.className = 'item';
  const open = state.expanded.has(it.id);

  const head = document.createElement('div');
  head.className = 'head';
  head.setAttribute('role', 'button');
  head.setAttribute('aria-expanded', open ? 'true' : 'false');
  head.addEventListener('click', () => {
    if (open) state.expanded.delete(it.id); else state.expanded.add(it.id);
    render();
  });

  head.appendChild(badge('kind-' + it.kind, it.kind));
  head.appendChild(badge('status-' + it.status, STATUS_LABEL[it.status] || it.status));
  const title = document.createElement('span');
  title.className = 'title';
  title.textContent = it.title;
  head.appendChild(title);
  const file = document.createElement(it.source_file ? 'button' : 'span');
  file.className = 'file';
  if (it.source_file) {
    file.type = 'button';
    file.title = 'Open source page';
    // <button> has no default navigation, so a click (any button) never falls
    // through to an href="#" like an <a> would.
    file.addEventListener('click', () => openPage(sourcePageHTML(it)));
  }
  file.textContent = it.source_file || '—';
  head.appendChild(file);
  const fn = document.createElement('span');
  fn.className = 'func';
  fn.textContent = it.function_name || '—';
  head.appendChild(fn);
  const loc = document.createElement('span');
  loc.className = 'loc';
  loc.textContent = it.location || '—';
  head.appendChild(loc);
  const chev = document.createElement('span');
  chev.className = 'chev';
  chev.textContent = open ? '▾' : '▸';
  head.appendChild(chev);

  li.appendChild(head);
  const body = document.createElement('div');
  body.className = 'details';
  body.appendChild(detailBody(it));
  body.appendChild(sourceBody(it));
  body.classList.toggle('hidden', !open);
  li.appendChild(body);
  return li;
}

function render() {
  const shown = DATA.filter(matches).sort(cmp);

  buildStatusOptions();
  buildFileTree($('file-opts'), DATA.map((it) => it.source_file), state.files);

  const itemsEl = $('items');
  itemsEl.textContent = '';
  for (const it of shown) itemsEl.appendChild(rowEl(it));

  $('empty').classList.toggle('hidden', shown.length > 0);

  const total = { bug: 0, analysis: 0 };
  for (const it of DATA) total[it.kind] = (total[it.kind] || 0) + 1;
  const shownKinds = { bug: 0, analysis: 0 };
  for (const it of shown) shownKinds[it.kind] = (shownKinds[it.kind] || 0) + 1;
  const filtered = state.search.trim() || state.statuses.size || state.files.size;
  let stats = shown.length + ' / ' + DATA.length + ' reports' +
              '  ·  bugs ' + total.bug + '  ·  analyses ' + total.analysis;
  if (filtered) {
    stats += '  ·  shown: ' + shownKinds.bug + ' bug, ' + shownKinds.analysis + ' analysis';
  }
  $('stats').textContent = stats;
}

function setup() {
  const overlay = document.createElement('div');
  overlay.id = 'page-overlay';
  overlay.addEventListener('click', (e) => {
    if (e.target === overlay) overlay.classList.remove('show');
  });
  document.body.appendChild(overlay);
  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') overlay.classList.remove('show');
  });
  $('search').addEventListener('input', (e) => { state.search = e.target.value; render(); });
  $('sort').addEventListener('change', (e) => { state.sort = e.target.value; render(); });
  $('expand-all').addEventListener('click', () => {
    for (const it of DATA) state.expanded.add(it.id);
    render();
  });
  $('collapse-all').addEventListener('click', () => { state.expanded.clear(); render(); });
  $('reset').addEventListener('click', () => {
    state.search = '';
    state.statuses.clear();
    state.files.clear();
    state.fileDirs.clear();
    state.fileSeeded = false;
    state.statusDirs.clear();
    state.sort = 'status';
    state.expanded.clear();
    $('search').value = '';
    $('sort').value = 'status';
    render();
  });
  render();
}
setup();
</script>
</body>
</html>
"""


def _embed_sources(work_dir, items):
    """Embed the original source of every referenced file, deduplicated.

    Reads the real source tree next to the workspace (the same heuristic
    ``_attach_source_href`` uses) so the expanded view can show the function
    under the report with GitHub-style syntax highlighting. Each unique
    ``source_file`` is read once; a missing or unreadable file is skipped (the
    page then shows a muted note). The read happens at generation time, so the
    output stays byte-deterministic as long as the sources are unchanged.
    """
    proj_root = os.path.dirname(os.path.abspath(work_dir))
    sources = {}
    for item in items:
        src = item.get("source_file") or ""
        if not src or src in sources or src.startswith("/") or ".." in src.split("/"):
            continue
        path = os.path.join(proj_root, src.replace("/", os.sep))
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                sources[src] = f.read()
        except OSError:
            continue
    return sources


def _embed_detail_full(work_dir, items):
    """Embed the full report (markdown / json) behind each item's ``detail_ref``.

    Reading the referenced file at generation time lets the page render the
    complete report inline and open a self-contained copy in a new tab — no
    external file dependency. A missing or unreadable reference leaves the
    field empty (the page then omits the full-report section).
    """
    for item in items:
        ref = item.get("detail_ref") or ""
        if not ref:
            item["detail_full"] = ""
            continue
        path = os.path.join(work_dir, ref.replace("/", os.sep))
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                item["detail_full"] = f.read()
        except OSError:
            item["detail_full"] = ""
    return items


def _render_html(items, sources):
    """Render a self-contained HTML page embedding items and source files."""
    ordered = sorted(
        items,
        key=lambda it: (
            it["kind"],
            (_STATUS_RANK if it["kind"] == "bug" else _VERDICT_RANK).get(it["status"], 99),
            it["id"],
        ),
    )
    payload = json.dumps(ordered, ensure_ascii=False)
    src_payload = json.dumps(sources, ensure_ascii=False)
    # Neutralise characters that would close the JSON <script> block or be
    # interpreted as markup inside it; JSON.parse restores the literal values.
    payload = payload.replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026")
    src_payload = src_payload.replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026")
    return (
        _HTML_TEMPLATE.replace("__DATA__", payload).replace("__SOURCES__", src_payload)
    )


def generate_report(work_dir):
    """Scan ``work_dir`` artifacts and write ``<work_dir>/report.html``.

    Deterministic and LLM-free: re-running on the same artifacts produces the
    same bytes. Returns the absolute path of the written file.
    """
    items = _collect_bugs(work_dir) + _collect_analyses(work_dir)
    _enrich_locations(work_dir, items)
    _attach_source_href(work_dir, items)
    _embed_detail_full(work_dir, items)
    sources = _embed_sources(work_dir, items)
    html = _render_html(items, sources)

    out = os.path.join(work_dir, "report.html")
    tmp = out + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        f.write(html)
    os.replace(tmp, out)
    return out


def main():
    """CLI entry point: regenerate report.html from an existing run."""
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("proj_dir", help="project root, or an fm_agent workspace directory")
    args = ap.parse_args()

    work_dir = _locate_workdir(args.proj_dir)
    if not os.path.isdir(work_dir):
        print(
            f"error: no fm_agent workspace found under {args.proj_dir} "
            f"(looked for {work_dir})",
            file=sys.stderr,
        )
        sys.exit(1)

    out = generate_report(work_dir)
    print(f"Report index written to {out}")


if __name__ == "__main__":
    main()

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
_VERDICT_RANK = {"MATCH": 0, "MISMATCH": 1, "ERROR": 2, "SKIPPED": 3}
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
    in line order. An exact match wins first (covers genuine names that end in
    ``_N``). Otherwise, if ``fn`` carries a ``_N`` dedup suffix, strip it and
    take the Nth same-named span (extraction and codegraph are both
    line-ordered, so the index lines up); without a suffix, the first
    same-named span wins.
    """
    if not spans:
        return ""
    for name, start, end in spans:
        if name == fn or name.endswith("::" + fn):
            # codegraph spans are 0-indexed inclusive; display 1-indexed.
            return f"L{start + 1}-L{end + 1}"
    m = re.match(r"^(.*)_(\d+)$", fn)
    if m:
        base, idx = m.group(1), int(m.group(2))
        matched = 0
        for name, start, end in spans:
            if name == base or name.endswith("::" + base):
                if matched == idx:
                    return f"L{start + 1}-L{end + 1}"
                matched += 1
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
.filter-group .fg-title { font-size: 11px; text-transform: uppercase; letter-spacing: .04em;
                          color: var(--muted); margin-bottom: 4px; }
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
.head a.file { color: var(--accent); text-decoration: none; }
.head a.file:hover { text-decoration: underline; }
.head .loc { font-variant-numeric: tabular-nums; }
.head .badge { justify-self: stretch; text-align: center; }
.chev { color: var(--muted); user-select: none; }
.badge { display: inline-block; padding: 2px 8px; border-radius: 999px;
         font-size: 11px; font-weight: 600; color: #fff; white-space: nowrap; }
.kind-bug { background: #8250df; }
.kind-analysis { background: #0969da; }
.status-confirmed, .status-MATCH { background: #1a7f37; }
.status-not_confirmed { background: #2da44e; }
.status-MISMATCH { background: #9a6700; }
.status-error, .status-ERROR { background: #cf222e; }
.status-pending, .status-SKIPPED { background: #59636e; }
.details { padding: 10px 14px 12px; border-top: 2px solid var(--border); }
.detail-row { margin: 0 0 10px; }
.detail-label { color: var(--muted); font-size: 12px; font-weight: 600;
                text-transform: uppercase; letter-spacing: .03em; margin-bottom: 2px; }
.detail-value { white-space: pre-wrap; word-break: break-word; }
.detail-value pre { margin: 0; padding: 8px 10px; border-radius: 6px; background: #f6f8fa;
                    border: 2px solid var(--border); overflow-x: auto;
                    font: 12px/1.5 ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; }
.open-link { display: inline-block; margin-top: 4px; color: var(--accent); text-decoration: none; }
.open-link:hover { text-decoration: underline; }
.detail-empty { color: var(--muted); font-style: italic; }
#empty { color: var(--muted); text-align: center; padding: 40px 0; }
</style>
</head>
<body>
<header>
  <h1>FM-Agent Report Index</h1>
  <div id="stats"></div>
  <div class="controls">
    <input id="search" type="search" placeholder="Search title / file / function / location" autocomplete="off">
    <div class="filter-group"><div class="fg-title">Type</div><div id="kind-opts"></div></div>
    <div class="filter-group"><div class="fg-title">Status</div><div id="status-opts"></div></div>
    <div class="filter-group"><div class="fg-title">Source file</div><div id="file-opts"></div></div>
    <div class="filter-group">
      <div class="fg-title">Sort</div>
      <select id="sort">
        <option value="status" selected>status</option>
        <option value="file">file</option>
        <option value="function">function</option>
        <option value="location">code location</option>
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
<script>
const DATA = JSON.parse(document.getElementById('report-data').textContent);
const STATUS_RANK = {confirmed:0, not_confirmed:1, error:2, pending:3, MATCH:10, MISMATCH:11, ERROR:12, SKIPPED:13};

const state = {
  search: '',
  kinds: new Set(['bug', 'analysis']),
  statuses: new Set(),
  files: new Set(),
  sort: 'status',
  expanded: new Set(),
};

const $ = (id) => document.getElementById(id);

function matches(it) {
  if (!state.kinds.has(it.kind)) return false;
  if (state.statuses.size && !state.statuses.has(it.status)) return false;
  if (state.files.size && !state.files.has(it.source_file)) return false;
  const q = state.search.trim().toLowerCase();
  if (q) {
    const hay = [it.title, it.source_file, it.function_name, it.location].join(' ').toLowerCase();
    if (!hay.includes(q)) return false;
  }
  return true;
}

function locStart(loc) {
  if (!loc) return Infinity;
  const m = loc.match(/L(\d+)/);
  return m ? parseInt(m[1], 10) : Infinity;
}

function cmp(a, b) {
  let k = 0;
  switch (state.sort) {
    case 'file': k = a.source_file < b.source_file ? -1 : a.source_file > b.source_file ? 1 : 0; break;
    case 'function': k = a.function_name < b.function_name ? -1 : a.function_name > b.function_name ? 1 : 0; break;
    case 'location': k = locStart(a.location) - locStart(b.location); break;
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

function buildFilterOptions(container, values, selected) {
  container.textContent = '';
  const sorted = Array.from(new Set(values)).filter((v) => v !== '').sort();
  for (const v of sorted) {
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
    label.appendChild(document.createTextNode(' ' + v));
    container.appendChild(label);
  }
}

function detailBody(it) {
  const body = document.createElement('div');
  body.className = 'details';
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
  if (it.detail_ref) {
    const link = document.createElement('a');
    link.className = 'open-link';
    link.href = it.detail_ref;
    link.textContent = 'Open full report ↗';
    body.appendChild(link);
  }
  if (!entries.length && !it.detail_ref) {
    const d = document.createElement('div');
    d.className = 'detail-empty';
    d.textContent = 'No technical details available.';
    body.appendChild(d);
  }
  return body;
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
  head.appendChild(badge('status-' + it.status, it.status));
  const title = document.createElement('span');
  title.className = 'title';
  title.textContent = it.title;
  head.appendChild(title);
  const file = document.createElement(it.source_href ? 'a' : 'span');
  file.className = 'file';
  if (it.source_href) {
    file.href = it.source_href;
    file.target = '_blank';
    file.rel = 'noopener';
    file.title = 'Open source file';
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
  const body = detailBody(it);
  body.classList.toggle('hidden', !open);
  li.appendChild(body);
  return li;
}

function render() {
  const shown = DATA.filter(matches).sort(cmp);

  buildFilterOptions($('status-opts'), DATA.map((it) => it.status), state.statuses);
  buildFilterOptions($('file-opts'), DATA.map((it) => it.source_file), state.files);

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
  $('search').addEventListener('input', (e) => { state.search = e.target.value; render(); });
  $('sort').addEventListener('change', (e) => { state.sort = e.target.value; render(); });
  $('expand-all').addEventListener('click', () => {
    for (const it of DATA) state.expanded.add(it.id);
    render();
  });
  $('collapse-all').addEventListener('click', () => { state.expanded.clear(); render(); });
  $('reset').addEventListener('click', () => {
    state.search = '';
    state.kinds = new Set(['bug', 'analysis']);
    state.statuses.clear();
    state.files.clear();
    state.sort = 'status';
    state.expanded.clear();
    $('search').value = '';
    $('sort').value = 'status';
    for (const cb of document.querySelectorAll('#kind-opts input')) cb.checked = true;
    render();
  });

  const kindOpts = $('kind-opts');
  for (const k of ['bug', 'analysis']) {
    const label = document.createElement('label');
    label.className = 'opt';
    const cb = document.createElement('input');
    cb.type = 'checkbox';
    cb.value = k;
    cb.checked = true;
    cb.addEventListener('change', () => {
      if (cb.checked) state.kinds.add(k); else state.kinds.delete(k);
      render();
    });
    label.appendChild(cb);
    label.appendChild(document.createTextNode(' ' + k));
    kindOpts.appendChild(label);
  }
  render();
}
setup();
</script>
</body>
</html>
"""


def _render_html(items):
    """Render a self-contained HTML page embedding ``items`` as JSON data."""
    ordered = sorted(
        items,
        key=lambda it: (
            it["kind"],
            (_STATUS_RANK if it["kind"] == "bug" else _VERDICT_RANK).get(it["status"], 99),
            it["id"],
        ),
    )
    payload = json.dumps(ordered, ensure_ascii=False)
    # Neutralise characters that would close the JSON <script> block or be
    # interpreted as markup inside it; JSON.parse restores the literal values.
    payload = payload.replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026")
    return _HTML_TEMPLATE.replace("__DATA__", payload)


def generate_report(work_dir):
    """Scan ``work_dir`` artifacts and write ``<work_dir>/report.html``.

    Deterministic and LLM-free: re-running on the same artifacts produces the
    same bytes. Returns the absolute path of the written file.
    """
    items = _collect_bugs(work_dir) + _collect_analyses(work_dir)
    _enrich_locations(work_dir, items)
    _attach_source_href(work_dir, items)
    html = _render_html(items)

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

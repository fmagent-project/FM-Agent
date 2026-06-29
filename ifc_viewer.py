#!/usr/bin/env python3
"""IFC Trace Viewer — a zero-dependency web UI to inspect FM-Agent IFC runs.

Usage:
    python3 ifc_viewer.py [--port 8765] [--dir <default_proj_dir>]

Then open http://localhost:8765 and type a project directory (the one you ran
`ifc_main.py` against, e.g. /mnt/nvme/jiangzhe/tmp/opencode/ifc_demo). The viewer
reads <proj_dir>/fm_agent_ifc/ and lets you browse, per function:

  - the extracted source code
  - the parametric flow signature + deterministic verdict
  - cross-function call-site instantiations
  - the full LLM reasoning exchange (system / user / response) from the trace

Stdlib only (http.server + json). No build step, no external deps.
"""

import argparse
import json
import os
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs, unquote

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


# --------------------------------------------------------------------------- #
# Plugin registry: each analysis plugin writes its run under a known workspace
# subdir + results subdir, and uses its own verdict vocabulary. The viewer reads
# this to (a) discover which plugins were run for a project, and (b) switch the
# middle-panel renderer on the frontend. Adding a plugin = one manifest entry in
# src/plugins/registry.py + one JS renderer (see renderDetail dispatch below).
#
# This dict is DERIVED from the central pure-data registry so there is a single
# source of truth. Importing the registry is cheap and side-effect free (no
# openai), keeping this viewer zero-heavy-dependency (stdlib-only at runtime).
# --------------------------------------------------------------------------- #

from src.plugins import registry as _registry  # noqa: E402  (pure-data, light)

PLUGINS = {
    name: {
        "label": m["label"],
        "workspace": m["work_subdir"],
        "results": m["results_subdir"],
        "verdicts": _registry.all_verdicts(name),
    }
    for name, m in _registry.PLUGIN_MANIFESTS.items()
}


# --------------------------------------------------------------------------- #
# Data layer: read a plugin workspace into a JSON-able structure.
# --------------------------------------------------------------------------- #

def _safe_join(base, *parts):
    """Join and ensure the result stays within base (path-traversal guard)."""
    base_real = os.path.realpath(base)
    target = os.path.realpath(os.path.join(base_real, *parts))
    if target != base_real and not target.startswith(base_real + os.sep):
        raise ValueError("path escapes base directory")
    return target


def _discover_plugins(proj_dir):
    """Return the list of plugin names whose workspace exists under proj_dir
    (or, if proj_dir is itself a workspace, the single matching plugin)."""
    proj_dir = os.path.realpath(os.path.expanduser(proj_dir))
    found = []
    for name, cfg in PLUGINS.items():
        if os.path.isdir(os.path.join(proj_dir, cfg["workspace"])):
            found.append(name)
        elif os.path.basename(proj_dir) == cfg["workspace"] and (
                os.path.isdir(os.path.join(proj_dir, cfg["results"]))
                or os.path.isdir(os.path.join(proj_dir, "results"))
                or os.path.isdir(os.path.join(proj_dir, "ifc_results"))):
            found.append(name)
    return found


def _find_workspace(proj_dir, plugin="ifc"):
    """Resolve a plugin's workspace for a given input dir.

    Accepts either the project dir (containing <workspace>/) or the workspace
    dir itself (containing <results>/ and trace/).
    """
    cfg = PLUGINS.get(plugin) or PLUGINS["ifc"]
    proj_dir = os.path.realpath(os.path.expanduser(proj_dir))
    if not os.path.isdir(proj_dir):
        raise FileNotFoundError(f"not a directory: {proj_dir}")
    candidate = os.path.join(proj_dir, cfg["workspace"])
    if os.path.isdir(candidate):
        return candidate
    # Maybe the user pointed straight at the workspace.
    if os.path.isdir(os.path.join(proj_dir, cfg["results"])) or \
            os.path.isdir(os.path.join(proj_dir, "results")) or \
            os.path.isdir(os.path.join(proj_dir, "ifc_results")):
        return proj_dir
    raise FileNotFoundError(
        f"no {cfg['workspace']}/ found under {proj_dir} (run the {plugin} plugin first)"
    )


def _results_dir(workspace, cfg):
    """Resolve a plugin's results subdir, tolerating known alternates.

    ifc has two entrypoints that disagree on the subdir: legacy ifc_main.py
    writes 'ifc_results/', while the unified run_plugin.py path writes the driver
    default 'results/'. Prefer the configured name, then try the common
    alternates so either entrypoint's output renders.
    """
    primary = os.path.join(workspace, cfg["results"])
    if os.path.isdir(primary):
        return primary
    for alt in ("results", "ifc_results"):
        cand = os.path.join(workspace, alt)
        if os.path.isdir(cand):
            return cand
    return primary


def _read_json(path):
    try:
        with open(path, "r", errors="replace") as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError):
        return None


def _index_events(workspace):
    """Map function_id -> the LLM event (with resolved payload paths)."""
    events_path = os.path.join(workspace, "trace", "events.jsonl")
    by_fn = {}
    all_events = []
    if not os.path.isfile(events_path):
        return by_fn, all_events
    with open(events_path, "r", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                e = json.loads(line)
            except json.JSONDecodeError:
                continue
            all_events.append(e)
            fid = (e.get("metadata") or {}).get("function_id")
            if fid:
                by_fn.setdefault(fid, []).append(e)
    return by_fn, all_events


def load_run(proj_dir, plugin="ifc"):
    """Load the full run into a structure the frontend consumes in one call."""
    cfg = PLUGINS.get(plugin) or PLUGINS["ifc"]
    workspace = _find_workspace(proj_dir, plugin)
    results_dir = _results_dir(workspace, cfg)
    extracted_dir = os.path.join(workspace, "extracted_functions")

    summary = _read_json(os.path.join(results_dir, "summary.json")) or {}
    by_fn_events, all_events = _index_events(workspace)

    functions = []
    # Drive the list from summary.results when present, else walk result files.
    listing = summary.get("results")
    if not listing:
        listing = []
        for root, _, files in os.walk(results_dir):
            for fn in sorted(files):
                if fn == "summary.json" or not fn.endswith(".json"):
                    continue
                rel = os.path.relpath(os.path.join(root, fn), results_dir)
                listing.append({"function": rel[:-5], "name": fn[:-5], "verdict": "?"})

    for item in listing:
        rel_noext = item["function"]              # e.g. cross_function-py/_wrap.py OR ...-/x
        # result json path
        res_rel = rel_noext
        if res_rel.endswith(".py") or "." in os.path.basename(res_rel):
            # function id keeps source extension; result file is <id-without-ext>.json
            res_key = os.path.splitext(res_rel)[0]
        else:
            res_key = res_rel
        res_path = os.path.join(results_dir, res_key + ".json")
        result = _read_json(res_path) or {}

        # function_id used in events is the extracted rel path (with extension)
        fid = rel_noext if (rel_noext.count(".") and not rel_noext.endswith(".json")) else None
        # best effort: match against event keys
        events = by_fn_events.get(rel_noext, [])
        if not events:
            # try matching by basename
            for k, evs in by_fn_events.items():
                if os.path.splitext(k)[0] == res_key or os.path.basename(k).startswith(item["name"] + "."):
                    events = evs
                    break

        # locate extracted source
        src_path = None
        cand = os.path.join(extracted_dir, rel_noext)
        if os.path.isfile(cand):
            src_path = cand
        else:
            base = res_key
            for ext in (".py", ".c", ".cpp", ".go", ".rs", ".java", ".ts", ".js"):
                c = os.path.join(extracted_dir, base + ext)
                if os.path.isfile(c):
                    src_path = c
                    break

        src_text = ""
        if src_path:
            try:
                with open(src_path, "r", errors="replace") as sf:
                    src_text = sf.read()
            except OSError:
                src_text = ""

        functions.append({
            "id": rel_noext,
            "name": item.get("name"),
            "verdict": result.get("verdict", item.get("verdict", "?")),
            "result": result,
            "source_path": os.path.relpath(src_path, workspace) if src_path else None,
            "event_count": len(events),
            "event_ids": [e.get("event_id") for e in events],
            "_src": src_text,  # transient, removed before serialization
        })

    edges = _compute_call_edges(functions)

    # Attach per-function calls / called_by and drop the transient source text.
    calls_map = {}
    called_by_map = {}
    for caller, callee in edges:
        calls_map.setdefault(caller, []).append(callee)
        called_by_map.setdefault(callee, []).append(caller)
    for fn in functions:
        fn["calls"] = sorted(set(calls_map.get(fn["name"], [])))
        fn["called_by"] = sorted(set(called_by_map.get(fn["name"], [])))
        fn.pop("_src", None)

    return {
        "proj_dir": proj_dir,
        "workspace": workspace,
        "plugin": plugin,
        "plugin_label": cfg["label"],
        "verdicts": cfg["verdicts"],
        "available_plugins": [
            {"name": n, "label": PLUGINS[n]["label"]}
            for n in _discover_plugins(proj_dir)
        ] or [{"name": plugin, "label": cfg["label"]}],
        "summary": summary,
        "functions": functions,
        "edges": [{"from": a, "to": b} for a, b in edges],
        "total_events": len(all_events),
    }


def _compute_call_edges(functions):
    """Derive (caller_name, callee_name) edges by scanning each function's source.

    Name-based, same heuristic as ifc_main._order_bottom_up: a function f calls g
    if g's name appears as `g(` in f's body. Only edges between analyzed functions
    are kept. Duplicate-named functions collapse to one node (best-effort).
    """
    import re as _re
    names = {f["name"] for f in functions if f.get("name")}
    edges = []
    seen = set()
    for f in functions:
        caller = f.get("name")
        src = f.get("_src", "")
        if not caller or not src:
            continue
        for callee in names:
            if callee == caller:
                continue
            if _re.search(rf"\b{_re.escape(callee)}\s*\(", src):
                key = (caller, callee)
                if key not in seen:
                    seen.add(key)
                    edges.append([caller, callee])
    return edges


def read_source(workspace, rel_path):
    path = _safe_join(workspace, rel_path)
    if not os.path.isfile(path):
        raise FileNotFoundError(rel_path)
    with open(path, "r", errors="replace") as f:
        return f.read()


def read_event(workspace, event_id):
    """Return {system, user, response, meta} for one LLM event id."""
    by_fn, all_events = _index_events(workspace)
    target = None
    for e in all_events:
        if e.get("event_id") == event_id:
            target = e
            break
    if not target:
        raise FileNotFoundError(event_id)
    out = {"event_id": event_id, "meta": target.get("metadata", {}),
           "status": target.get("status"), "stage": target.get("stage"),
           "summary": target.get("summary"),
           "start_time": target.get("start_time"), "end_time": target.get("end_time"),
           "system": None, "user": None, "response": None}
    for child in target.get("children", []):
        ref = child.get("content_ref")
        if not ref:
            continue
        try:
            text = read_source(workspace, ref)
        except (FileNotFoundError, ValueError):
            text = "(payload missing)"
        role = child.get("role")
        ctype = child.get("type")
        if role == "system" or ctype == "system_prompt":
            out["system"] = text
        elif role == "user" or ctype == "user_prompt":
            out["user"] = text
        else:
            out["response"] = text
    return out


# --------------------------------------------------------------------------- #
# HTTP layer
# --------------------------------------------------------------------------- #

_INDEX_HTML = None  # set at bottom of file


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass  # quiet

    def _send(self, code, body, ctype="application/json"):
        if isinstance(body, (dict, list)):
            body = json.dumps(body, ensure_ascii=False)
        data = body.encode("utf-8") if isinstance(body, str) else body
        self.send_response(code)
        self.send_header("Content-Type", ctype + "; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _err(self, code, msg):
        self._send(code, {"error": msg})

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path
        q = parse_qs(parsed.query)

        if path == "/" or path == "/index.html":
            return self._send(200, _INDEX_HTML, "text/html")

        if path == "/api/detect":
            proj = (q.get("dir") or [""])[0]
            if not proj:
                return self._err(400, "missing ?dir=")
            try:
                names = _discover_plugins(unquote(proj))
                return self._send(200, {
                    "available_plugins": [
                        {"name": n, "label": PLUGINS[n]["label"]} for n in names
                    ],
                })
            except (FileNotFoundError, ValueError) as e:
                return self._err(404, str(e))

        if path == "/api/run":
            proj = (q.get("dir") or [""])[0]
            plugin = (q.get("plugin") or ["ifc"])[0]
            if not proj:
                return self._err(400, "missing ?dir=")
            try:
                return self._send(200, load_run(unquote(proj), plugin))
            except (FileNotFoundError, ValueError) as e:
                return self._err(404, str(e))
            except Exception as e:  # noqa
                return self._err(500, f"{type(e).__name__}: {e}")

        if path == "/api/source":
            proj = (q.get("dir") or [""])[0]
            rel = (q.get("path") or [""])[0]
            plugin = (q.get("plugin") or ["ifc"])[0]
            if not proj or not rel:
                return self._err(400, "missing ?dir= and ?path=")
            try:
                ws = _find_workspace(unquote(proj), plugin)
                return self._send(200, {"path": rel, "content": read_source(ws, unquote(rel))})
            except (FileNotFoundError, ValueError) as e:
                return self._err(404, str(e))

        if path == "/api/event":
            proj = (q.get("dir") or [""])[0]
            eid = (q.get("id") or [""])[0]
            plugin = (q.get("plugin") or ["ifc"])[0]
            if not proj or not eid:
                return self._err(400, "missing ?dir= and ?id=")
            try:
                ws = _find_workspace(unquote(proj), plugin)
                return self._send(200, read_event(ws, unquote(eid)))
            except (FileNotFoundError, ValueError) as e:
                return self._err(404, str(e))

        return self._err(404, "not found")


def main():
    ap = argparse.ArgumentParser(description="IFC trace web viewer")
    ap.add_argument("--port", type=int, default=8765)
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--dir", default="", help="default project dir to prefill")
    args = ap.parse_args()

    global _INDEX_HTML
    _INDEX_HTML = INDEX_HTML.replace("__DEFAULT_DIR__", json.dumps(args.dir))

    srv = ThreadingHTTPServer((args.host, args.port), Handler)
    print(f"IFC viewer on http://{args.host}:{args.port}")
    if args.dir:
        print(f"  default dir: {args.dir}")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\nbye")
        srv.shutdown()


# --------------------------------------------------------------------------- #
# Frontend (single embedded HTML doc; no external assets)
# --------------------------------------------------------------------------- #

INDEX_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>IFC Trace Viewer</title>
<style>
  :root{
    --bg:#0f1115; --panel:#171a21; --panel2:#1e222b; --border:#2a2f3a;
    --fg:#e6e8eb; --muted:#9aa3b2; --accent:#4f9dff;
    --leak:#ff5c5c; --secure:#3fcf8e; --declass:#ffb454; --poly:#36c5d8; --error:#c678dd;
    --high:#ff5c5c; --low:#3fcf8e; --unknown:#ffb454;
    --vulnerable:#ff5c5c; --safe:#3fcf8e; --review:#ffb454;
  }
  *{box-sizing:border-box}
  body{margin:0;font:13px/1.5 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;
       background:var(--bg);color:var(--fg);height:100vh;display:flex;flex-direction:column}
  header{display:flex;gap:8px;align-items:center;padding:8px 12px;background:var(--panel);
         border-bottom:1px solid var(--border);flex:0 0 auto}
  header h1{font-size:14px;margin:0 12px 0 0;font-weight:600;letter-spacing:.3px}
  header input{flex:1;background:var(--panel2);border:1px solid var(--border);color:var(--fg);
               padding:6px 10px;border-radius:6px;font:inherit}
  header button{background:var(--accent);color:#fff;border:0;padding:6px 14px;border-radius:6px;
                cursor:pointer;font:inherit;font-weight:600}
  header button:hover{filter:brightness(1.1)}
  header select{background:var(--panel2);border:1px solid var(--border);color:var(--fg);
                padding:6px 8px;border-radius:6px;font:inherit;cursor:pointer}
  #info{width:24px;height:24px;padding:0;border-radius:50%;background:var(--panel2);
        border:1px solid var(--border);color:var(--muted);font-weight:700;font-size:14px;
        line-height:22px;text-align:center;flex:0 0 auto}
  #info:hover{color:var(--accent);border-color:var(--accent);filter:none}
  #stat{color:var(--muted);font-size:12px;white-space:nowrap}
  /* modal */
  .modal-bg{position:fixed;inset:0;background:rgba(0,0,0,.6);display:none;z-index:50;
            align-items:flex-start;justify-content:center;padding:40px 16px;overflow:auto}
  .modal-bg.show{display:flex}
  .modal{background:var(--panel);border:1px solid var(--border);border-radius:10px;
         max-width:860px;width:100%;padding:0;box-shadow:0 12px 48px rgba(0,0,0,.5)}
  .modal .mh{display:flex;justify-content:space-between;align-items:center;padding:14px 20px;
             border-bottom:1px solid var(--border);position:sticky;top:0;background:var(--panel);
             border-radius:10px 10px 0 0}
  .modal .mh h2{margin:0;font-size:15px}
  .modal .mx{cursor:pointer;color:var(--muted);font-size:20px;background:none;border:0}
  .modal .mx:hover{color:var(--fg)}
  .modal .mb{padding:18px 24px;line-height:1.7}
  .modal h3{color:var(--accent);font-size:13px;text-transform:uppercase;letter-spacing:.5px;
            margin:22px 0 8px;border-bottom:1px solid var(--border);padding-bottom:4px}
  .modal h3:first-child{margin-top:0}
  .modal p{margin:8px 0;color:var(--fg)}
  .modal code{background:var(--panel2);border:1px solid var(--border);border-radius:4px;
              padding:1px 5px;font-size:12px}
  .modal table{width:100%;border-collapse:collapse;margin:10px 0;font-size:12px}
  .modal th,.modal td{border:1px solid var(--border);padding:6px 10px;text-align:left;vertical-align:top}
  .modal th{background:var(--panel2);color:var(--muted);font-weight:600}
  .modal .flow{font-family:ui-monospace,monospace;background:var(--panel2);border:1px solid var(--border);
               border-radius:6px;padding:10px 12px;margin:10px 0;white-space:pre-wrap}
  .modal ul{margin:8px 0;padding-left:20px}
  .modal li{margin:4px 0}
  .vchip{display:inline-block;padding:1px 7px;border-radius:4px;font-size:11px;font-weight:700;margin-right:4px}
  .vc-LEAK{background:var(--leak);color:#1a0000}
  .vc-SECURE{background:var(--secure);color:#002b16}
  .vc-DECLASSIFIED{background:var(--declass);color:#241400}
  .vc-POLYMORPHIC{background:var(--poly);color:#002a30}
   .vc-VULNERABLE{background:var(--vulnerable);color:#1a0000}
   .vc-SAFE{background:var(--safe);color:#002b16}
   .vc-NEEDS_REVIEW{background:var(--review);color:#241400}
    .vc-SANITIZED{background:var(--poly);color:#002a30}
    .vc-BOUNDED{background:var(--secure);color:#002b16}
    .vc-WEAK{background:var(--declass);color:#241400}
    .vc-ERROR{background:var(--error);color:#1f0030}
  main{flex:1;display:flex;min-height:0}
  /* left: function list */
  #list{flex:0 0 290px;background:var(--panel);border-right:1px solid var(--border);
        overflow:auto;display:flex;flex-direction:column}
  .sumbar{display:flex;flex-wrap:wrap;gap:4px;padding:8px;border-bottom:1px solid var(--border)}
  .pill{padding:2px 8px;border-radius:10px;font-size:11px;font-weight:600;cursor:pointer;
        border:1px solid transparent;user-select:none}
  .pill.off{opacity:.35}
  .fn{padding:7px 12px;border-bottom:1px solid var(--border);cursor:pointer;display:flex;
      gap:8px;align-items:center}
  .fn:hover{background:var(--panel2)}
  .fn.sel{background:var(--panel2);border-left:3px solid var(--accent);padding-left:9px}
  .fn .nm{flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
  .fn .mod{color:var(--muted);font-size:11px}
  .badge{font-size:10px;font-weight:700;padding:1px 6px;border-radius:4px;flex:0 0 auto}
  .b-LEAK{background:var(--leak);color:#1a0000}
  .b-SECURE{background:var(--secure);color:#002b16}
  .b-DECLASSIFIED{background:var(--declass);color:#241400}
  .b-POLYMORPHIC{background:var(--poly);color:#002a30}
  .b-VULNERABLE{background:var(--vulnerable);color:#1a0000}
  .b-SAFE{background:var(--safe);color:#002b16}
  .b-NEEDS_REVIEW{background:var(--review);color:#241400}
  .b-SANITIZED{background:var(--poly);color:#002a30}
  .b-BOUNDED{background:var(--secure);color:#002b16}
  .b-WEAK{background:var(--declass);color:#241400}
  .b-ERROR{background:var(--error);color:#1f0030}
  /* center: detail */
  #detail{flex:1;overflow:auto;padding:0;min-width:0}
  .empty{color:var(--muted);padding:40px;text-align:center}
  .sec{border-bottom:1px solid var(--border)}
  .sec h2{margin:0;padding:8px 14px;font-size:12px;text-transform:uppercase;letter-spacing:.5px;
          color:var(--muted);background:var(--panel);position:sticky;top:0;cursor:pointer;
          display:flex;justify-content:space-between}
  .sec .body{padding:12px 14px}
  pre{margin:0;white-space:pre-wrap;word-break:break-word;background:var(--panel2);
      border:1px solid var(--border);border-radius:6px;padding:10px;overflow:auto}
  .codeln{display:block}
  table.kv{width:100%;border-collapse:collapse}
  table.kv td{padding:3px 8px;border-bottom:1px solid var(--border);vertical-align:top}
  table.kv td.k{color:var(--muted);width:160px}
  .lbl{font-weight:700;padding:0 5px;border-radius:3px;font-size:11px}
  .l-High{background:var(--high);color:#1a0000}
  .l-Low{background:var(--low);color:#002b16}
  .l-Unknown{background:var(--unknown);color:#241400}
  .chan{margin:6px 0;padding:8px;background:var(--panel2);border:1px solid var(--border);border-radius:6px}
  .chan .cn{font-weight:700;color:var(--accent)}
  .dep{display:inline-block;background:#11151c;border:1px solid var(--border);border-radius:4px;
       padding:0 6px;margin:2px;font-size:11px}
  .flowrow{display:flex;align-items:center;gap:8px;flex-wrap:wrap;margin:4px 0}
  .arrow{color:var(--muted)}
  .res{margin:6px 0;padding:8px;background:var(--panel2);border:1px solid var(--border);border-radius:6px}
  /* authz-specific */
  .op{margin:6px 0;padding:8px;background:var(--panel2);border:1px solid var(--border);border-radius:6px;
      border-left:3px solid var(--muted)}
  .op.bad{border-left-color:var(--vulnerable)}
  .op.ok{border-left-color:var(--safe)}
  .op .ohead{display:flex;gap:8px;align-items:center;flex-wrap:wrap;margin-bottom:4px}
  .op .okind{font-weight:700;color:var(--accent);text-transform:uppercase;font-size:11px}
  .op .oev{color:var(--muted);font-size:11px;white-space:pre-wrap;word-break:break-word;
          background:#11151c;border:1px solid var(--border);border-radius:4px;padding:4px 6px;margin-top:4px}
  .tag{display:inline-block;background:#11151c;border:1px solid var(--border);border-radius:4px;
       padding:0 6px;margin:1px;font-size:11px}
  .tag.rid{color:var(--accent);font-weight:600}
  .tag.dom-yes{border-color:var(--safe);color:var(--safe)}
  .tag.dom-no{border-color:var(--review);color:var(--review)}
  .finding{margin:6px 0;padding:8px 10px;background:#23161a;border:1px solid var(--vulnerable);
           border-radius:6px}
  .finding .fk{font-weight:700;color:var(--vulnerable);font-size:11px;letter-spacing:.3px}
  .finding .fm{margin-top:3px}
  .obl{margin:5px 0;padding:6px 8px;background:var(--panel2);border:1px dashed var(--border);
       border-radius:6px;color:var(--muted)}
  /* right: reasoning */
  #reason{flex:0 0 420px;background:var(--panel);border-left:1px solid var(--border);
          overflow:auto;display:flex;flex-direction:column}
  #reason .rh{padding:8px 14px;border-bottom:1px solid var(--border);color:var(--muted);
              text-transform:uppercase;font-size:12px;letter-spacing:.5px}
  .ev{border-bottom:1px solid var(--border)}
  .ev .eh{padding:6px 14px;cursor:pointer;display:flex;justify-content:space-between;color:var(--muted)}
  .ev .eh:hover{background:var(--panel2)}
  .tab{display:flex;gap:4px;padding:6px 10px}
  .tab button{flex:1;background:var(--panel2);border:1px solid var(--border);color:var(--muted);
              padding:4px;border-radius:5px;cursor:pointer;font:inherit;font-size:11px}
  .tab button.on{color:var(--fg);border-color:var(--accent)}
  .notes{color:var(--muted);font-style:italic;margin-top:6px}
  .hide{display:none}
  a.srclink{color:var(--accent);cursor:pointer;text-decoration:underline}
  /* view toggle */
  .viewtoggle{display:flex;gap:4px;padding:6px 8px;border-bottom:1px solid var(--border)}
  .viewtoggle button{flex:1;background:var(--panel2);border:1px solid var(--border);color:var(--muted);
                     padding:4px;border-radius:5px;cursor:pointer;font:inherit;font-size:11px}
  .viewtoggle button.on{color:var(--fg);border-color:var(--accent)}
  /* graph view */
  #graphwrap{flex:1;overflow:auto;position:relative}
  #graphwrap svg{display:block}
  .gnode{cursor:pointer}
  .gnode circle{stroke:var(--border);stroke-width:1.5px}
  .gnode.sel circle{stroke:var(--fg);stroke-width:2.5px}
  .gnode .glabel{fill:var(--fg);font-size:10px;font-weight:500;text-anchor:start;dominant-baseline:middle;pointer-events:none}
  .gnode.sel .glabel{font-weight:700}
  .gedge{stroke:var(--muted);stroke-width:1.3px;fill:none;opacity:.5;marker-end:url(#arrow)}
  .gedge.hot{stroke:var(--accent);opacity:1;stroke-width:2px}
  .gnode.dim{opacity:.28}
  .gedge.dim{opacity:.08}
</style>
</head>
<body>
<header>
  <h1>FM&#8209;Agent&nbsp;Viewer</h1>
  <button id="info" title="About this plugin">!</button>
  <select id="plugin" title="Analysis plugin"></select>
  <input id="dir" placeholder="project dir, e.g. /mnt/nvme/jiangzhe/tmp/opencode/authz_webapp">
  <button id="load">Load</button>
  <span id="stat"></span>
</header>
<main>
  <div id="list"><div class="empty">Enter a directory and Load.</div></div>
  <div id="detail"><div class="empty">Select a function.</div></div>
  <div id="reason"><div class="rh">Reasoning</div><div class="empty">Select a function.</div></div>
</main>
<div class="modal-bg" id="modalbg">
  <div class="modal">
    <div class="mh">
      <h2 id="modaltitle">About FM-Agent-IFC</h2>
      <button class="mx" id="modalclose">&times;</button>
    </div>
    <div class="mb" id="modalbody-ifc">
      <h3>The idea in one minute</h3>
      <p>FM-Agent-IFC checks <b>information flow</b>: that a <b>secret (High)</b> value never
      reaches a <b>public (Low)</b> output. Inputs are labelled High/Low from naming
      (<code>password</code>, <code>db_password</code>, <code>token</code> &rarr; High; <code>host</code>,
      <code>user_id</code> &rarr; Low). Each function ends with one verdict:</p>
      <table>
        <tr><td><span class="vchip vc-SECURE">SECURE</span></td><td>No secret reaches a public output.</td></tr>
        <tr><td><span class="vchip vc-LEAK">LEAK</span></td><td>A secret flows to a public output.</td></tr>
        <tr><td><span class="vchip vc-DECLASSIFIED">DECLASSIFIED</span></td><td>An intentional release (password check &rarr; 1 bit, hash digest). Needs human review.</td></tr>
        <tr><td><span class="vchip vc-POLYMORPHIC">POLYMORPHIC</span></td><td>Depends on who calls it (e.g. a generic helper). Decided at the call site.</td></tr>
      </table>
      <p>It reuses the original FM-Agent's natural-language Hoare-style reasoning, but swaps the
      question from <i>"is the post-condition correct?"</i> to <i>"does the output depend on a
      secret input?"</i></p>

      <h3>Stage-by-stage comparison &mdash; one example throughout</h3>
      <p>Both tools run the same 5-stage shape. We follow one tiny 2-function program across every
      stage:</p>
      <div class="flow">config_store.py:  def build_dsn(host, port):
                      return f"postgres://admin:{DB_PASSWORD}@{host}:{port}/app"
user_routes.py:   def handle_debug_db(request):
                      host = request.get("host"); port = request.get("port")
                      return f"connecting to {build_dsn(host, port)}"</div>
      <p>It looks innocent: <code>handle_debug_db</code> only passes public host/port. The bug
      hides in the callee &mdash; <code>build_dsn</code> bakes the secret <code>DB_PASSWORD</code>
      into its return string.</p>

      <table>
        <tr><th>Stage</th><th>Original FM-Agent (correctness)</th><th>FM-Agent-IFC (security)</th></tr>
        <tr>
          <td><b>1. Extract</b></td>
          <td colspan="2" style="text-align:center"><i>Identical.</i> The same <code>extract.py</code> splits both files into one file per function: <code>build_dsn.py</code>, <code>handle_debug_db.py</code>.</td>
        </tr>
        <tr>
          <td><b>2. Order / call graph</b></td>
          <td>Top-down layers: caller first. <code>handle_debug_db</code> is processed before <code>build_dsn</code>; the caller pushes its expectations down.</td>
          <td>Bottom-up: callee first. <code>build_dsn</code> is analyzed before <code>handle_debug_db</code>, so its summary is ready when the caller needs it.</td>
        </tr>
        <tr>
          <td><b>3. Per-function spec</b></td>
          <td>Generates a pre/post-condition: <i>"returns a valid DSN string for the given host/port"</i>.</td>
          <td>Labels inputs (host, port = Low; <code>DB_PASSWORD</code> = High) and a non-interference constraint: <i>the Low return must not depend on High data</i>.</td>
        </tr>
        <tr>
          <td><b>4. LLM reasoning</b></td>
          <td>Splits the body into blocks; derives the actual post-condition block by block and checks it against the spec.</td>
          <td>Derives a whole-function <b>flow signature</b> &mdash; <code>build_dsn</code>: <span class="flow" style="display:inline;padding:1px 6px">return &larr; {DB_PASSWORD, host, port}</span></td>
        </tr>
        <tr>
          <td><b>5. Decision</b></td>
          <td>The <b>LLM</b> judges MATCH vs MISMATCH. For <code>build_dsn</code> the DSN is "correct", so &rarr; <span class="vchip vc-SECURE" style="background:#2a2f3a;color:#9aa3b2">MATCH</span> (no bug &mdash; it's working as intended!)</td>
          <td><b>Python</b> joins lattice labels: return depends on High <code>DB_PASSWORD</code> &rarr; <span class="vchip vc-LEAK">LEAK</span>. Deterministic &amp; fail-closed.</td>
        </tr>
        <tr>
          <td><b>6. Cross-function</b></td>
          <td>Callee summary is an <code>[INFO]</code> value contract pushed from caller's expectation.</td>
          <td>Callee's <code>[FLOW]</code> signature is <b>instantiated</b> at the call site: <code>handle_debug_db</code> passes Low host/port, but <code>build_dsn</code>'s return is High regardless &rarr; the High taint surfaces in <code>handle_debug_db</code>'s public response &rarr; <span class="vchip vc-LEAK">LEAK</span>.</td>
        </tr>
        <tr>
          <td><b>Verdicts</b></td>
          <td>MATCH / MISMATCH / SKIPPED / ERROR</td>
          <td>SECURE / LEAK / DECLASSIFIED / POLYMORPHIC / ERROR</td>
        </tr>
      </table>
      <p><b>The punch line:</b> this leak is invisible to a correctness checker &mdash; the code does
      exactly what it intends. Only by tracking <i>where secret data flows</i>, and by
      <i>composing the callee's flow signature into the caller</i>, does FM-Agent-IFC catch that a
      public diagnostics endpoint quietly leaks the database password.</p>

      <h3>Scope</h3>
      <p>Guarantees <b>termination-insensitive</b> non-interference. Out of scope: timing, cache,
      and probabilistic side channels. Cross-function tracking is name-based (best-effort on
      indirect calls / dynamic dispatch).</p>
    </div>
    <div class="mb hide" id="modalbody-authz">
      <h3>The idea in one minute</h3>
      <p>FM-Agent-Authz checks <b>access control</b> using a <b>guarded-Hoare</b> model: every
      <b>sensitive operation</b> (a DB read/write/delete or admin action on a user/tenant-owned
      resource) must be <b>dominated by a guard</b> that binds the <b>authenticated subject</b> to
      <b>that specific resource</b>. The core target is <b>IDOR / BOLA</b> (Broken Object-Level
      Authorization). Each function ends with one verdict:</p>
      <table>
        <tr><td><span class="vchip vc-SAFE">SAFE</span></td><td>Every sensitive op is properly authorized (or there is none).</td></tr>
        <tr><td><span class="vchip vc-VULNERABLE">VULNERABLE</span></td><td>A sensitive op lacks a guard binding the subject to the accessed resource.</td></tr>
        <tr><td><span class="vchip vc-NEEDS_REVIEW">NEEDS_REVIEW</span></td><td>Authorization depends on framework/middleware policy the function-local view can't confirm.</td></tr>
        <tr><td><span class="vchip vc-ERROR">ERROR</span></td><td>No valid abstraction (fail-closed; never silently SAFE).</td></tr>
      </table>
      <p>It reuses the same substrate as IFC (split functions, build call graph, LLM derives a
      per-function abstraction, a deterministic checker decides), but swaps the theory: instead of
      a non-interference lattice it runs <b>guard-domination + subject/resource/action binding
      equality</b>.</p>

      <h3>How a finding is decided &mdash; one example</h3>
      <div class="flow">def get_invoice(invoice_id):
    invoice = Invoice.objects.get(id=invoice_id)   # sensitive read, resource = invoice_id
    return jsonify(invoice.to_dict())              # no ownership guard!</div>
      <p>The LLM extracts: a <b>sensitive operation</b> (read <code>Invoice[invoice_id]</code>,
      id from the request), an <b>authenticated subject</b> (<code>current_user</code>), and the
      <b>guards</b> present (none binding <code>invoice_id</code> to <code>current_user</code>).
      The deterministic checker then asks: <i>is there a dominating guard whose resource id equals
      the op's resource id?</i> &mdash; No &rarr; <span class="vchip vc-VULNERABLE">VULNERABLE</span>
      (<code>MISSING_AUTHORIZATION</code>).</p>

      <table>
        <tr><th>Stage</th><th>FM-Agent-IFC</th><th>FM-Agent-Authz</th></tr>
        <tr><td><b>1. Extract</b></td><td colspan="2" style="text-align:center"><i>Identical.</i> Same <code>extract.py</code>, one file per function.</td></tr>
        <tr><td><b>2. Order / call graph</b></td><td colspan="2" style="text-align:center"><i>Identical.</i> Same bottom-up call graph &mdash; but authz adds a <b>top-down</b> pass too (below).</td></tr>
        <tr>
          <td><b>3. Per-function abstraction</b></td>
          <td>A parametric <b>flow signature</b>: each output channel &larr; its input dependency set.</td>
          <td>A <b>guarded-Hoare</b> record: sensitive operations, guards (subject/resource/action + whether they dominate), and obligations.</td>
        </tr>
        <tr>
          <td><b>4. Deterministic checker</b></td>
          <td>Lattice join High/Low; a Low output depending on High is a LEAK.</td>
          <td>Guard-domination + <b>resource-id binding equality</b>; an undominated/mis-bound op is a finding.</td>
        </tr>
        <tr>
          <td><b>5. Cross-function</b></td>
          <td>Callee flow signature is <b>instantiated</b> at the call site (labels substituted).</td>
          <td>An unmet authorization is an <b>obligation</b> that flows UP; a guard a caller establishes flows DOWN (top-down context worklist), so a helper authorized by its caller isn't a false positive.</td>
        </tr>
        <tr>
          <td><b>Finding kinds</b></td>
          <td>LEAK / DECLASSIFIED / POLYMORPHIC</td>
          <td>MISSING_AUTHORIZATION / RESOURCE_BINDING_MISMATCH / ROLE_ONLY_GUARD_FOR_OBJECT_ACTION / AUTHZ_AFTER_EFFECT / MISSING_AUTHENTICATION</td>
        </tr>
      </table>
      <p><b>The punch line:</b> the IDOR is invisible to a flow checker (no secret leaks) and to a
      correctness checker (the query is "correct"). Only by modelling <i>which subject is authorized
      for which resource</i> &mdash; and composing a caller's established guard into its callees
      &mdash; does FM-Agent-Authz catch that any logged-in user can read anyone's invoice.</p>

      <h3>Scope</h3>
      <p>Function-local guard-domination with a top-down obligation pass. Best on framework
      CRUD-style handlers. Authorization hidden entirely in middleware/decorators/ORM row-level
      policies may be reported as NEEDS_REVIEW. Interprocedural object-parameter binding (a write on
      a passed-in object) is approximate &mdash; the bug is attributed to the entrypoint.</p>
    </div>
    <div class="mb hide" id="modalbody-taint">
      <h3>The idea in one minute</h3>
      <p>FM-Agent-Taint checks <b>integrity / injection</b> &mdash; the <b>dual</b> of IFC. Instead
      of a secret leaking to a public output, here <b>untrusted input</b> must not reach a
      <b>sensitive operation site</b> (a SQL query, a shell command, a filesystem path, an outbound
      URL, an HTML render, a deserializer) without a <b>context-appropriate sanitizer</b>. Each
      function ends with one verdict:</p>
      <table>
        <tr><td><span class="vchip vc-SAFE">SAFE</span></td><td>No tainted input reaches a sink.</td></tr>
        <tr><td><span class="vchip vc-VULNERABLE">VULNERABLE</span></td><td>Tainted input reaches a sink unsanitized (SQLi, command injection, SSRF, XSS, &hellip;).</td></tr>
        <tr><td><span class="vchip vc-SANITIZED">SANITIZED</span></td><td>Tainted input reaches a sink, but a sanitizer endorses it <i>for that exact context</i>.</td></tr>
        <tr><td><span class="vchip vc-POLYMORPHIC">POLYMORPHIC</span></td><td>A parameter reaches a sink unsanitized &mdash; vulnerable iff the caller passes tainted data. Decided at the call site.</td></tr>
      </table>
      <p>The key insight Oracle flagged: sanitizers are <b>typed</b>. <code>html.escape</code> makes a
      value safe for HTML body, but <b>not</b> for SQL, a shell, JavaScript, or a URL. A
      parameterized query endorses only the <code>sql_param</code> context, not raw query text.</p>

      <h3>How a finding is decided &mdash; one example</h3>
      <div class="flow">def search_users(name):
    name = request.args.get("name")              # source: http_param (tainted)
    query = "... WHERE name = '" + name + "'"     # tainted concatenated into SQL
    return conn.execute(query)                    # sink: sql_query (sql_query_text)</div>
      <p>The LLM emits a <b>taint signature</b>: a source (<code>request.args.get</code>), a sink
      (<code>conn.execute</code>, context <code>sql_query_text</code>), and the flow source&rarr;sink
      with no sanitizer. The deterministic checker asks: <i>does a tainted flow reach this sink with
      no sanitizer endorsing its context?</i> &mdash; Yes &rarr;
      <span class="vchip vc-VULNERABLE">VULNERABLE</span> (<code>SQL_INJECTION</code>, CWE-89).</p>

      <table>
        <tr><th>Stage</th><th>FM-Agent-IFC</th><th>FM-Agent-Taint</th></tr>
        <tr><td><b>1. Extract</b></td><td colspan="2" style="text-align:center"><i>Identical.</i> Same <code>extract.py</code>.</td></tr>
        <tr><td><b>2. Order / call graph</b></td><td colspan="2" style="text-align:center"><i>Identical.</i> Bottom-up: callee before caller.</td></tr>
        <tr>
          <td><b>3. Per-function abstraction</b></td>
          <td>Flow signature: each output channel &larr; input dependency set; declassification anchors.</td>
          <td>Taint signature: tainted <b>sources</b>, typed <b>sinks</b> (operation site + arg context), typed <b>sanitizers</b>, parametric flows.</td>
        </tr>
        <tr>
          <td><b>4. Deterministic checker</b></td>
          <td>Lattice join High/Low; a Low output depending on High is a LEAK.</td>
          <td>Source&rarr;sink reachability; a sanitizer clears a flow only if it endorses the sink's exact arg context (html_escape never clears sql_param).</td>
        </tr>
        <tr>
          <td><b>5. Cross-function</b></td>
          <td>Callee flow signature instantiated at the call site (labels substituted).</td>
          <td>Callee's parametric sink (<code>param:x &rarr; sql_query</code>) instantiated with the caller's actual argument taint &mdash; a tainted arg makes the caller VULNERABLE. Bottom-up, no top-down pass.</td>
        </tr>
        <tr>
          <td><b>Finding kinds</b></td>
          <td>LEAK / DECLASSIFIED / POLYMORPHIC</td>
          <td>SQL_INJECTION / COMMAND_INJECTION / PATH_TRAVERSAL / SSRF / OPEN_REDIRECT / XSS / TEMPLATE_INJECTION / UNSAFE_DESERIALIZATION / CODE_INJECTION / LDAP / XPATH</td>
        </tr>
      </table>
      <p><b>The punch line:</b> taint is the lattice-flipped twin of IFC &mdash; the same engine,
      the same composition, but source = untrusted input and sink = operation site. The one thing it
      does NOT reuse from IFC is the output-channel model: an injection sink is a <i>typed operation
      argument</i>, and a sanitizer is valid only for one context.</p>

       <h3>Scope</h3>
       <p>Covers the OWASP injection family (~20&ndash;40% of real-world web vulns). Honest limits:
       sanitizer over-trust (only high-confidence, known-kind sanitizers count), source-recognition
       gaps (unknown external input fails closed to tainted), and second-order / stored taint is
       approximate. Typed contexts are intentionally narrow &mdash; if the LLM mislabels a sink's
       context, the checker fails closed (reports rather than clears).</p>
     </div>
     <div class="mb hide" id="modalbody-crypto">
       <h3>The idea in one minute</h3>
       <p>FM-Agent-Crypto checks <b>cryptographic API misuse</b>. The crypto <b>operation itself</b>
       is the locus (no source&rarr;sink flow): the analyzer inspects the algorithm/mode, the
       <b>provenance</b> of key, IV/nonce, and randomness, KDF parameters, and a <b>verify-before-trust</b>
       ordering property. Each function ends with one verdict:</p>
       <table>
         <tr><td><span class="vchip vc-SAFE">SAFE</span></td><td>No crypto misuse: strong algorithm, good provenance, fresh nonce, verified before trust.</td></tr>
         <tr><td><span class="vchip vc-VULNERABLE">VULNERABLE</span></td><td>Exploitable misuse: ECB, hardcoded key, static/reused IV, insecure PRNG, fast password hash, verify-not-checked, TLS verify off, JWT alg=none.</td></tr>
         <tr><td><span class="vchip vc-WEAK">WEAK</span></td><td>Real but context-dependent: e.g. SHA1 for a non-password security hash, RSA &lt; 2048, low KDF iterations.</td></tr>
         <tr><td><span class="vchip vc-POLYMORPHIC">POLYMORPHIC</span></td><td>Safety depends on caller-supplied key/nonce material, or a helper that exports key-shaped material. Decided at the call site.</td></tr>
         <tr><td><span class="vchip vc-NEEDS_REVIEW">NEEDS_REVIEW</span></td><td>Provenance/algorithm/verify-dominance unknown &mdash; fail-closed, never silently SAFE.</td></tr>
       </table>
       <p>The theory is <b>CrySL</b> (Kr&uuml;ger et al., ECOOP 2018): a crypto rule = algorithm/mode
       constraints + a typestate ORDER (e.g. verify before trust) + material provenance. We split it
       into the <b>syntactic</b> catches (ECB, hardcoded key, alg=none &mdash; high confidence) and the
       <b>semantic</b> catches that need provenance/value/ordering reasoning (IV freshness, key from
       CSPRNG vs literal, verify-before-trust).</p>

       <h3>How a finding is decided &mdash; two examples</h3>
       <div class="flow">def encrypt_blob(data):                  # VULNERABLE
    key = b"0123456789abcdef"            # provenance: hardcoded_literal
    cipher = AES.new(key, AES.MODE_ECB)  # mode: ECB
    return cipher.encrypt(pad(data,16))</div>
       <p>The LLM emits a crypto signature: an <code>encrypt</code> op with <code>algorithm=AES</code>,
       <code>mode=ECB</code>, <code>key.provenance=hardcoded_literal</code>. The deterministic checker
       maps ECB&rarr;<span class="vchip vc-VULNERABLE">VULNERABLE</span> (CWE-327) and hardcoded
       key&rarr;<span class="vchip vc-VULNERABLE">VULNERABLE</span> (CWE-321).</p>
       <div class="flow">def make_key():  return b"hardcoded..."   # POLYMORPHIC (exports key material)
def f8b(data):
    key = make_key()                         # source: call_return -> make_key
    return AESGCM(key).encrypt(os.urandom(12), data, None)   # VULNERABLE after compose</div>
       <p>Bottom-up composition resolves the callee's return provenance
       (<code>make_key</code> returns <code>hardcoded_literal</code>) into <code>f8b</code>'s key &mdash;
       so <code>f8b</code> becomes <span class="vchip vc-VULNERABLE">VULNERABLE</span> while the helper
       alone is <span class="vchip vc-POLYMORPHIC">POLYMORPHIC</span>.</p>

       <table>
         <tr><th>Stage</th><th>FM-Agent-Taint</th><th>FM-Agent-Crypto</th></tr>
         <tr><td><b>1&ndash;2. Extract / order</b></td><td colspan="2" style="text-align:center"><i>Identical.</i> Same extraction + bottom-up call graph.</td></tr>
         <tr>
           <td><b>3. Per-function abstraction</b></td>
           <td>Typed sources + typed sinks + typed sanitizers + flows.</td>
           <td>Crypto operations (algo/mode + key/IV/randomness/KDF provenance), verify-before-trust events, red flags.</td>
         </tr>
         <tr>
           <td><b>4. Deterministic checker</b></td>
           <td>Source&rarr;sink reachability with typed sanitizer matching.</td>
           <td>Table-driven rules over (op, algorithm, mode, provenance, randomness, verify status) + verify-before-trust ordering. No "sink"; the operation is the check point.</td>
         </tr>
         <tr>
           <td><b>5. Cross-function</b></td>
           <td>Callee parametric sink instantiated with caller arg taint.</td>
           <td>Callee return-provenance (key/IV material) instantiated into the caller's operation. Bottom-up, no top-down pass.</td>
         </tr>
         <tr>
           <td><b>Finding kinds</b></td>
           <td>SQL_INJECTION / XSS / SSRF / &hellip;</td>
           <td>ecb_mode / hardcoded_key / static_or_reused_iv_nonce / predictable_randomness / password_fast_hash / verify_not_checked / tls_verification_disabled / jwt_none / weak_algorithm / insufficient_key_size</td>
         </tr>
       </table>
       <p><b>The punch line:</b> crypto is the one plugin where there is no data-flow "sink" &mdash; the
       operation <i>is</i> the locus, and verify-before-trust is a typestate ordering property. It still
       fits the substrate by reusing taint's parametric-provenance + bottom-up composition for key/IV
       material that flows through helpers.</p>

       <h3>Scope</h3>
       <p>Best on direct library use (cryptography / pycryptodome / hashlib / jwt / ssl). Honest limits:
       purpose ambiguity (MD5 for an ETag is not a vuln &mdash; emits NEEDS_REVIEW when purpose is
       unclear), provenance hidden behind wrappers (fails closed to NEEDS_REVIEW), and KDF parameter
       adequacy depends on library defaults the LLM may not see.</p>
     </div>
     <div class="mb hide" id="modalbody-typestate">
       <h3>The idea in one minute</h3>
       <p>FM-Agent-Typestate checks <b>ordering</b> bugs &mdash; properties of the form "a required
       event must precede a trigger" or "a resource opened must close on all paths". The bug is NOT a
       data flow; it is the <b>order</b> (or absence) of security-relevant events. The LLM emits an
       <b>ordered event trace</b> tagged with path-coverage; small built-in <b>property automata</b>
       run over it. Each function ends with one verdict:</p>
       <table>
         <tr><td><span class="vchip vc-SAFE">SAFE</span></td><td>Required events precede triggers; resources close on all paths.</td></tr>
         <tr><td><span class="vchip vc-VULNERABLE">VULNERABLE</span></td><td>An ordering violation: TOCTOU, CSRF-missing, TLS-verify-disabled use, resource leak, use-after-close.</td></tr>
         <tr><td><span class="vchip vc-POLYMORPHIC">POLYMORPHIC</span></td><td>Caller-dependent: a helper acting on a passed-in resource/request whose state the caller decides.</td></tr>
         <tr><td><span class="vchip vc-NEEDS_REVIEW">NEEDS_REVIEW</span></td><td>Order/path/resource facts unknown &mdash; fail-closed, never silently SAFE.</td></tr>
       </table>
       <p>The five built-in rules: <b>TOCTOU</b> (CWE-367, check-then-non-atomic-use), <b>CSRF</b>
       (CWE-352, state-change without prior token validation), <b>TLS-verify</b> (CWE-295, network use
       after verification disabled), <b>resource lifecycle</b> (CWE-772/775/672/415, open/close/use-
       after-close/double-close), and <b>auth-before-action</b> (CWE-306/862). The LLM never authors
       automata &mdash; it only maps observed events to a fixed alphabet.</p>

       <h3>How a finding is decided &mdash; two examples</h3>
       <div class="flow">def read_if_present(path):              # VULNERABLE (TOCTOU)
    if os.path.exists(path):            # FS_CHECK(path)
        with open(path) as f:           # FS_USE(path), control-depends-on the check
            return f.read()</div>
       <p>The automaton sees FS_CHECK then a non-atomic FS_USE of the <i>same external-mutable path</i>
       that is control-dependent on the check &rarr; <span class="vchip vc-VULNERABLE">VULNERABLE</span>
       (CWE-367). The path could change between check and use.</p>
       <div class="flow">def checkout(request, db):              # SAFE (whole-program)
    if not validate_csrf(request):      # CSRF_VALIDATE (must, dominates)
        return "bad"
    return persist_order(request, db)   # callee does STATE_CHANGE</div>
       <p><code>persist_order</code> alone is <span class="vchip vc-POLYMORPHIC">POLYMORPHIC</span>
       (state-change on a request param, no local CSRF check). The <b>top-down context pass</b>
       propagates <code>checkout</code>'s dominating CSRF validation down into the callee, discharging
       its obligation &rarr; whole-program <span class="vchip vc-SAFE">SAFE</span>.</p>

       <table>
         <tr><th>Stage</th><th>Other plugins</th><th>FM-Agent-Typestate</th></tr>
         <tr><td><b>3. Per-function abstraction</b></td><td>Dependency sets / sinks / provenance.</td><td>An ORDERED event trace + path-coverage tags + resource exit states.</td></tr>
         <tr><td><b>4. Deterministic checker</b></td><td>Lattice / reachability / table rules.</td><td>Small property automata over the ordered trace; must-dominance via predecessors_must.</td></tr>
         <tr><td><b>5. Cross-function</b></td><td>Label / provenance / sink instantiation.</td><td>BOTH: bottom-up event splicing (returned-open resource) AND top-down required-event context (CSRF/auth in an ancestor).</td></tr>
       </table>
       <p><b>The punch line:</b> this is the one plugin whose property is an event ORDER, not a value
       flow. It is the least-clean fit (order + path-coverage can explode), so v1 is deliberately
       narrow: it uses may/must coverage tags instead of enumerating paths, requires explicit
       control-dependence for TOCTOU, and fails closed on any unknown order/path/resource fact.</p>

       <h3>Scope</h3>
       <p>v1 ships TOCTOU, CSRF, TLS-verify, resource lifecycle, and auth-before-action. Deferred:
       full path-sensitive model checking, concurrency / lock-ordering, cross-request session state,
       and TOCTOU race-exploitability proof. Caller-dependent helpers are reported POLYMORPHIC, not
       guessed safe.</p>
     </div>
   </div>
</div>
<script>
const DEFAULT_DIR = __DEFAULT_DIR__;
let RUN=null, CUR=null, FILTER=new Set(), VIEW="list", PLUGIN="ifc", PLUGIN_LOCKED=false;
const $=s=>document.querySelector(s), ce=(t,c)=>{const e=document.createElement(t);if(c)e.className=c;return e;};
const esc=s=>(s==null?"":String(s)).replace(/[&<>]/g,m=>({'&':'&amp;','<':'&lt;','>':'&gt;'}[m]));

async function api(path){const r=await fetch(path);const j=await r.json();if(!r.ok)throw new Error(j.error||r.status);return j;}

// Verdict vocabulary is per-plugin; RUN.verdicts is authoritative once loaded.
const PLUGIN_VERDICTS={
  ifc:["LEAK","DECLASSIFIED","POLYMORPHIC","SECURE","ERROR"],
  authz:["VULNERABLE","NEEDS_REVIEW","SAFE","ERROR"],
};
function verdicts(){ return (RUN&&RUN.verdicts)||PLUGIN_VERDICTS[PLUGIN]||PLUGIN_VERDICTS.ifc; }

async function loadRun(){
  const dir=$("#dir").value.trim(); if(!dir)return;
  $("#stat").textContent="loading…";
  try{
    // Auto-detect which plugins this project has results for, unless the user
    // explicitly picked one (PLUGIN_LOCKED). Default to the first detected.
    if(!PLUGIN_LOCKED){
      try{
        const det=await api("/api/detect?dir="+encodeURIComponent(dir));
        const avail=(det.available_plugins||[]).map(p=>p.name);
        if(avail.length && !avail.includes(PLUGIN)) PLUGIN=avail[0];
      }catch(_){ /* fall through with current PLUGIN */ }
    }
    RUN=await api("/api/run?plugin="+encodeURIComponent(PLUGIN)+"&dir="+encodeURIComponent(dir));
    PLUGIN=RUN.plugin||PLUGIN;
    syncPluginSelector();
    FILTER=new Set(verdicts());
    CUR=null;
    renderList(); $("#detail").innerHTML='<div class="empty">Select a function.</div>';
    $("#reason").innerHTML='<div class="rh">'+esc(reasonTitle())+'</div><div class="empty">Select a function.</div>';
    $("#stat").textContent=`${esc(RUN.plugin_label||PLUGIN)} · ${RUN.functions.length} fns · ${RUN.total_events} llm calls`;
  }catch(e){ $("#list").innerHTML='<div class="empty">'+esc(e.message)+'</div>'; $("#stat").textContent="error"; }
}

function reasonTitle(){ return PLUGIN==="authz" ? "Authorization Reasoning" : PLUGIN==="taint" ? "Taint Reasoning" : PLUGIN==="crypto" ? "Crypto Reasoning" : PLUGIN==="typestate" ? "Typestate Reasoning" : PLUGIN==="resource" ? "Resource Reasoning" : "IFC Reasoning"; }

function syncPluginSelector(){
  const sel=$("#plugin");
  const avail=(RUN&&RUN.available_plugins)||[{name:PLUGIN,label:PLUGIN}];
  sel.innerHTML="";
  // "Auto" returns to auto-detect mode (clears the manual lock on next Load).
  const auto=ce("option"); auto.value="__auto__"; auto.textContent="Auto-detect";
  if(!PLUGIN_LOCKED) auto.selected=true;
  sel.appendChild(auto);
  avail.forEach(p=>{
    const o=ce("option"); o.value=p.name;
    o.textContent=p.label+(p.name===PLUGIN?" ✓":"");
    if(PLUGIN_LOCKED && p.name===PLUGIN)o.selected=true;
    sel.appendChild(o);
  });
}

function renderList(){
  const list=$("#list"); list.innerHTML="";
  // view toggle (list / graph)
  const tg=ce("div","viewtoggle");
  ["list","graph"].forEach(v=>{
    const b=ce("button",VIEW===v?"on":""); b.textContent=v==="list"?"☰ List":"⇄ Call graph";
    b.onclick=()=>{VIEW=v;renderList();};
    tg.appendChild(b);
  });
  list.appendChild(tg);

  // verdict counts: prefer summary.counts (generic), fall back to IFC keys.
  const s=RUN.summary||{};
  const counts=s.counts||{LEAK:s.leaks,DECLASSIFIED:s.declassified,POLYMORPHIC:s.polymorphic,SECURE:s.secure,ERROR:s.errors};
  const bar=ce("div","sumbar");
  verdicts().forEach(v=>{
    const p=ce("span","pill b-"+v+(FILTER.has(v)?"":" off"));
    p.textContent=v[0]+(counts[v]!=null?":"+counts[v]:"");
    p.title=v;
    p.onclick=()=>{FILTER.has(v)?FILTER.delete(v):FILTER.add(v);renderList();};
    bar.appendChild(p);
  });
  list.appendChild(bar);

  if(VIEW==="graph"){ renderGraph(list); return; }

  RUN.functions.filter(f=>FILTER.has(f.verdict)).forEach(f=>{
    const row=ce("div","fn"+(CUR&&CUR.id===f.id?" sel":""));
    const mod=f.id.includes("/")?f.id.split("/")[0]:"";
    row.innerHTML=`<span class="badge b-${esc(f.verdict)}">${esc(f.verdict[0])}</span>`+
      `<span class="nm">${esc(f.name)}<div class="mod">${esc(mod)}</div></span>`+
      (f.event_count?`<span class="mod">${f.event_count}🧠</span>`:"");
    row.onclick=()=>selectFn(f);
    list.appendChild(row);
  });
}

const VCOL={LEAK:"#ff5c5c",SECURE:"#3fcf8e",DECLASSIFIED:"#ffb454",POLYMORPHIC:"#36c5d8",ERROR:"#c678dd",
            VULNERABLE:"#ff5c5c",SAFE:"#3fcf8e",NEEDS_REVIEW:"#ffb454",SANITIZED:"#36c5d8",WEAK:"#ffb454",BOUNDED:"#3fcf8e","?":"#9aa3b2"};

function renderGraph(container){
  const fns=RUN.functions.filter(f=>FILTER.has(f.verdict));
  const keep=new Set(fns.map(f=>f.name));
  const byName={}; fns.forEach(f=>byName[f.name]=f);
  // edges among kept nodes
  const edges=(RUN.edges||[]).filter(e=>keep.has(e.from)&&keep.has(e.to));

  // assign layers by longest-path depth (callers above callees).
  const out={}, indeg={};
  fns.forEach(f=>{out[f.name]=[];indeg[f.name]=0;});
  edges.forEach(e=>{out[e.from].push(e.to);});
  edges.forEach(e=>{indeg[e.to]=(indeg[e.to]||0)+1;});
  // depth = 0 for roots (not called by kept nodes); BFS longest path
  const depth={}; fns.forEach(f=>depth[f.name]=0);
  let changed=true, guard=0;
  while(changed && guard++<fns.length+2){
    changed=false;
    edges.forEach(e=>{ if(depth[e.to] < depth[e.from]+1){ depth[e.to]=depth[e.from]+1; changed=true; } });
  }
  // group by depth
  const layers={}; fns.forEach(f=>{(layers[depth[f.name]]=layers[depth[f.name]]||[]).push(f);});
  const maxd=Math.max(0,...Object.keys(layers).map(Number));

  // horizontal flow: callers on the LEFT, callees on the RIGHT, arrows point right.
  // depth -> column (x), nodes within a layer stack vertically (y). Canvas grows
  // with content so #graphwrap can scroll in both directions; names shown in full.
  const R=10, PADX=24, PADY=20, ROWY=30;   // node radius, paddings, vertical gap per node
  // estimate label widths (~6.2px/char at 10px) so columns don't overlap labels.
  let maxRow=1;
  for(let d=0; d<=maxd; d++) maxRow=Math.max(maxRow,(layers[d]||[]).length);
  const colW=[];
  for(let d=0; d<=maxd; d++){
    let w=0;
    (layers[d]||[]).forEach(f=>{ w=Math.max(w, f.name.length); });
    colW[d]=2*R + 8 + Math.ceil(w*6.2) + 40;   // circle + gap + label + inter-column gap
  }
  const colX=[]; let acc=PADX;
  for(let d=0; d<=maxd; d++){ colX[d]=acc+R; acc+=colW[d]; }
  const pos={};
  for(let d=0; d<=maxd; d++){
    const col=(layers[d]||[]).slice().sort((a,b)=>a.name.localeCompare(b.name));
    col.forEach((f,i)=>{ pos[f.name]={x:colX[d], y:PADY+R+i*ROWY, f}; });
  }
  const W=acc+PADX;
  const H=PADY*2+R+Math.max(0,maxRow-1)*ROWY+R;

  const NS="http://www.w3.org/2000/svg";
  const svg=document.createElementNS(NS,"svg");
  svg.setAttribute("width",W); svg.setAttribute("height",H);
  // arrow marker
  svg.innerHTML=`<defs><marker id="arrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="#9aa3b2"/></marker></defs>`;

  const curName=CUR&&CUR.name;
  const hot=new Set();
  if(curName){ edges.forEach(e=>{ if(e.from===curName||e.to===curName) hot.add(e.from+"\u0001"+e.to); }); }

  // edges first (under nodes); connect circle borders horizontally (left->right)
  edges.forEach(e=>{
    const a=pos[e.from], b=pos[e.to]; if(!a||!b)return;
    const x1=a.x+R, y1=a.y, x2=b.x-R, y2=b.y;
    const mx=(x1+x2)/2;
    const p=document.createElementNS(NS,"path");
    p.setAttribute("d",`M${x1},${y1} C${mx},${y1} ${mx},${y2} ${x2},${y2}`);
    let cls="gedge"+(hot.has(e.from+"\u0001"+e.to)?" hot":"");
    if(curName && !hot.has(e.from+"\u0001"+e.to)) cls+=" dim";
    p.setAttribute("class",cls);
    svg.appendChild(p);
  });

  // nodes: colored circle + full function name to the right
  fns.forEach(f=>{
    const p=pos[f.name]; if(!p)return;
    const g=document.createElementNS(NS,"g");
    let cls="gnode"+(curName===f.name?" sel":"");
    if(curName && curName!==f.name && !hot.has(curName+"\u0001"+f.name) && !hot.has(f.name+"\u0001"+curName)) cls+=" dim";
    g.setAttribute("class",cls);
    g.setAttribute("transform",`translate(${p.x},${p.y})`);
    const c=document.createElementNS(NS,"circle");
    c.setAttribute("r",R); c.setAttribute("fill",VCOL[f.verdict]||VCOL["?"]);
    const ttl=document.createElementNS(NS,"title");
    ttl.textContent=`${f.name} — ${f.verdict}`;
    c.appendChild(ttl);
    g.appendChild(c);
    const t=document.createElementNS(NS,"text");
    t.setAttribute("class","glabel"); t.setAttribute("x",R+6); t.setAttribute("y",0);
    t.textContent=f.name;
    g.appendChild(t);
    g.onclick=()=>selectFn(f);
    svg.appendChild(g);
  });

  const wrap=ce("div"); wrap.id="graphwrap"; wrap.appendChild(svg);
  container.appendChild(wrap);
}
function trim(s,n){s=String(s);return s.length>n?s.slice(0,n-1)+"…":s;}


function labelSpan(l){return `<span class="lbl l-${esc(l)}">${esc(l)}</span>`;}

async function selectFn(f){
  CUR=f; renderList();
  renderDetail(f);
  renderReason(f);
}

async function renderDetail(f){
  const d=$("#detail"); d.innerHTML="";
  const r=f.result||{};

  // verdict header (shared)
  const head=ce("div","sec");
  head.innerHTML=`<h2><span>${esc(f.name)} <span class="badge b-${esc(f.verdict)}">${esc(f.verdict)}</span></span><span class="mod">${esc(f.id)}</span></h2>`;
  d.appendChild(head);

  // source (shared)
  d.appendChild(section("Source code",`<pre id="src">loading…</pre>`));
  if(f.source_path){
    try{const j=await api("/api/source?plugin="+encodeURIComponent(PLUGIN)+"&dir="+encodeURIComponent(RUN.proj_dir)+"&path="+encodeURIComponent(f.source_path));
      $("#src").innerHTML=j.content.split("\n").map((l,i)=>`<span class="codeln"><span class="mod">${String(i+1).padStart(3)} </span>${esc(l)}</span>`).join("");
    }catch(e){$("#src").textContent="(source unavailable)";}
  } else { $("#src").textContent="(no source file)"; }

  // plugin-specific middle panel
  if(PLUGIN==="authz") renderAuthzDetail(d,f,r);
  else if(PLUGIN==="taint") renderTaintDetail(d,f,r);
  else if(PLUGIN==="crypto") renderCryptoDetail(d,f,r);
  else if(PLUGIN==="typestate") renderTypestateDetail(d,f,r);
  else if(PLUGIN==="resource") renderResourceDetail(d,f,r);
  else renderIfcDetail(d,f,r);
}

function renderIfcDetail(d,f,r){
  const sig=r.signature||{};

  // input labels
  const inputs=sig.inputs||{};
  let ih=`<table class="kv">`;
  for(const [k,v] of Object.entries(inputs)) ih+=`<tr><td class="k">${esc(k)}</td><td>${labelSpan(v)}</td></tr>`;
  if(!Object.keys(inputs).length) ih+=`<tr><td class="mod" colspan=2>no inputs</td></tr>`;
  ih+=`</table>`;
  d.appendChild(section("Inferred labels",ih));

  // flow signature: channels -> deps
  const outs=sig.outputs||{};
  let fh="";
  for(const [chan,spec] of Object.entries(outs)){
    const deps=(spec&&spec.deps)||[];
    const declass=(spec&&spec.declass)||[];
    fh+=`<div class="chan"><div class="flowrow"><span class="cn">${esc(chan)}</span><span class="arrow">⟵</span>`;
    fh+= deps.length? deps.map(x=>`<span class="dep">${esc(x)}</span>`).join("") : `<span class="mod">∅ (no dependency)</span>`;
    if(spec&&spec.const) fh+=` <span class="dep">const:${esc(spec.const)}</span>`;
    fh+=`</div>`;
    if(declass.length){
      declass.forEach(dc=>fh+=`<div class="notes">⚠ declassify @ <code>${esc(dc.anchor)}</code> — ${esc(dc.reason)}</div>`);
    }
    fh+=`</div>`;
  }
  if(sig.notes) fh+=`<div class="notes">${esc(sig.notes)}</div>`;
  d.appendChild(section("Flow signature",fh||'<span class="mod">none</span>'));

  // call-site instantiation
  const cr=r.callee_resolutions;
  if(cr&&cr.length){
    // de-dup identical resolutions
    const seen=new Set(), uniq=[];
    cr.forEach(x=>{const k=JSON.stringify(x);if(!seen.has(k)){seen.add(k);uniq.push(x);}});
    let ch="";
    uniq.forEach(x=>{
      ch+=`<div class="res"><div class="flowrow"><b>${esc(x.callee)}</b>(`;
      ch+= Object.entries(x.arg_binding||{}).map(([k,v])=>`${esc(k.replace("param:",""))}=${labelSpan(v)}`).join(", ");
      ch+=`)</div>`;
      for(const [chan,o] of Object.entries(x.resolved_outputs||{})){
        ch+=`<div class="flowrow"><span class="arrow">→</span>${esc(chan)} = ${labelSpan(o.label)}${o.declassified?' <span class="dep">declassified</span>':''}</div>`;
      }
      ch+=`</div>`;
    });
    d.appendChild(section("Call-site instantiation",ch));
  }

  // gaps
  if(r.gaps){
    const g=r.gaps;
    let gh=`<table class="kv">`;
    gh+=`<tr><td class="k">leaking channel</td><td>${esc(g.leaking_channel||"—")}</td></tr>`;
    gh+=`<tr><td class="k">high sources</td><td>${(g.high_sources||[]).map(x=>`<span class="dep">${esc(x)}</span>`).join("")||"—"}</td></tr>`;
    if((g.unknown_params||[]).length) gh+=`<tr><td class="k">unknown params</td><td>${g.unknown_params.map(x=>`<span class="dep">${esc(x)}</span>`).join("")}</td></tr>`;
    gh+=`<tr><td class="k">flow deps</td><td>${(g.flow_deps||[]).map(x=>`<span class="dep">${esc(x)}</span>`).join("")||"—"}</td></tr>`;
    if(g.declass_note) gh+=`<tr><td class="k">declass note</td><td>${esc(JSON.stringify(g.declass_note))}</td></tr>`;
    gh+=`</table>`;
    d.appendChild(section("Verdict detail (gaps)",gh));
  }

  if(r.error) d.appendChild(section("Error",`<pre>${esc(r.error)}</pre>`));
}

function renderAuthzDetail(d,f,r){
  // The authz plugin uses the generic render_result: r.facts is the guarded-Hoare
  // abstraction, r.findings is the deterministic checker's findings.
  const a=r.facts||(r.data&&r.data.abstraction)||{};
  const findings=r.findings||[];

  // findings first (the verdict's "why")
  if(findings.length){
    let fh="";
    findings.forEach(fd=>{
      fh+=`<div class="finding"><div class="fk">${esc(fd.title||fd.rule_id||"FINDING")}</div>`+
          `<div class="fm">${esc(fd.message||"")}</div>`;
      const op=fd.data&&fd.data.op;
      if(op&&op.evidence) fh+=`<div class="oev">${esc(op.evidence)}</div>`;
      fh+=`</div>`;
    });
    d.appendChild(section("Findings ("+findings.length+")",fh));
  } else if(f.verdict==="SAFE"){
    d.appendChild(section("Findings",'<span class="mod">No authorization gap — every sensitive operation is discharged.</span>'));
  }

  // authenticated subject
  const subj=a.authenticated_subject||{};
  let sh=`<table class="kv">`;
  sh+=`<tr><td class="k">subject</td><td>${subj.expr&&subj.expr!=="null"?`<span class="tag rid">${esc(subj.expr)}</span>`:'<span class="mod">none detected</span>'}</td></tr>`;
  sh+=`<tr><td class="k">origin</td><td>${esc(subj.origin||"—")}</td></tr>`;
  sh+=`</table>`;
  d.appendChild(section("Authenticated subject",sh));

  // sensitive operations
  const ops=a.sensitive_operations||[];
  // mark which ops are named in a finding (vulnerable)
  const badOps=new Set();
  findings.forEach(fd=>{const op=fd.data&&fd.data.op; if(op&&op.op_id) badOps.add(op.op_id);});
  let oh="";
  ops.forEach(o=>{
    const bad=badOps.has(o.op_id);
    oh+=`<div class="op ${bad?'bad':'ok'}"><div class="ohead">`+
        `<span class="okind">${esc(o.kind||"op")}</span>`+
        `<span class="tag">${esc(o.resource_type||"resource")}</span>`+
        `<span class="tag rid">${esc(o.resource_id_expr||"—")}</span>`+
        `<span class="tag">id:${esc(o.resource_id_origin||"?")}</span>`+
        `<span class="tag">action:${esc(o.action||"?")}</span>`+
        (bad?'<span class="tag dom-no">unauthorized</span>':'<span class="tag dom-yes">ok</span>')+
        `</div>`;
    if(o.evidence) oh+=`<div class="oev">${esc(o.evidence)}</div>`;
    oh+=`</div>`;
  });
  d.appendChild(section("Sensitive operations ("+ops.length+")",oh||'<span class="mod">none — no sensitive resource access</span>'));

  // guards
  const guards=a.guards||[];
  let gh="";
  guards.forEach(g=>{
    gh+=`<div class="op"><div class="ohead">`+
        `<span class="okind">${esc(g.kind||"guard")}</span>`+
        (g.subject?`<span class="tag">subj:${esc(g.subject)}</span>`:"")+
        (g.resource_id_expr?`<span class="tag rid">${esc(g.resource_id_expr)}</span>`:"")+
        `<span class="tag">scope:${esc(g.action_scope||"any")}</span>`+
        (g.dominates_all_paths?'<span class="tag dom-yes">dominates</span>':'<span class="tag dom-no">not dominating</span>')+
        `</div>`;
    if(g.predicate_nl) gh+=`<div style="margin-top:4px">${esc(g.predicate_nl)}</div>`;
    if(g.evidence) gh+=`<div class="oev">${esc(g.evidence)}</div>`;
    gh+=`</div>`;
  });
  d.appendChild(section("Guards ("+guards.length+")",gh||'<span class="mod">no authorization guards found</span>'));

  // obligations (relied upon from callers/framework)
  const obls=a.obligations||[];
  if(obls.length){
    let bh="";
    obls.forEach(o=>{
      bh+=`<div class="obl">⇡ requires: ${esc(o.requires_nl||"")}`;
      if(o.resource_id_expr) bh+=` <span class="tag rid">${esc(o.resource_id_expr)}</span>`;
      if(o.reason) bh+=`<div class="notes">${esc(o.reason)}</div>`;
      bh+=`</div>`;
    });
    d.appendChild(section("Obligations (deferred to caller)",bh));
  }

  // establishes (guards offered to callees)
  const est=a.establishes||[];
  if(est.length){
    let eh="";
    est.forEach(e=>{
      eh+=`<div class="obl">⇣ before <b>${esc(e.callee_name||"?")}</b>: ${esc(e.guard_predicate_nl||"")}`;
      if(e.resource_id_expr) eh+=` <span class="tag rid">${esc(e.resource_id_expr)}</span>`;
      eh+=`</div>`;
    });
    d.appendChild(section("Establishes (for callees)",eh));
  }

  if(a.notes) d.appendChild(section("Analysis notes",`<div class="notes">${esc(a.notes)}</div>`));
  if(r.error) d.appendChild(section("Error",`<pre>${esc(r.error)}</pre>`));
}

function renderTaintDetail(d,f,r){
  // The taint plugin uses the generic render_result: r.facts is the taint
  // signature; r.findings carries the deterministic checker's per-sink verdicts.
  const sig=r.facts||(r.data&&r.data.signature)||{};
  const findings=r.findings||[];

  // findings first (the verdict's "why"): each sink's status + CWE
  if(findings.length){
    let fh="";
    findings.forEach(fd=>{
      const dat=fd.data||{};
      const st=dat.status||"";
      const cls=st==="VULNERABLE"?"finding":(st==="POLYMORPHIC"?"op":"op ok");
      fh+=`<div class="${cls==='finding'?'finding':'op '+(st==='POLYMORPHIC'?'':'ok')}">`+
          `<div class="ohead"><span class="okind">${esc(fd.title||fd.rule_id)}</span>`+
          `<span class="tag">${esc(dat.cwe||"")}</span>`+
          `<span class="tag">${esc(dat.sink_kind||"")}</span>`+
          `<span class="tag rid">${esc(dat.arg_context||"")}</span>`+
          `<span class="vchip vc-${esc(st)}">${esc(st)}</span>`+
          (dat.sanitized_by?`<span class="tag dom-yes">${esc(dat.sanitized_by)}</span>`:"")+
          `</div><div class="fm">${esc(fd.message||"")}</div>`;
      if(dat.evidence) fh+=`<div class="oev">${esc(dat.evidence)}</div>`;
      fh+=`</div>`;
    });
    d.appendChild(section("Findings ("+findings.length+")",fh));
  } else if(f.verdict==="SAFE"){
    d.appendChild(section("Findings",'<span class="mod">No tainted flow reaches a sensitive sink.</span>'));
  }

  // taint sources
  const sources=sig.taint_sources||[];
  let sh="";
  sources.forEach(s=>{
    sh+=`<div class="op"><div class="ohead"><span class="okind">${esc(s.source_kind||"source")}</span>`+
        `<span class="tag rid">${esc(s.id||"")}</span>`+
        `<span class="tag">conf:${esc(s.confidence||"?")}</span></div>`;
    if(s.expr) sh+=`<div class="oev">${esc(s.expr)}</div>`;
    sh+=`</div>`;
  });
  d.appendChild(section("Taint sources ("+sources.length+")",sh||'<span class="mod">none — no untrusted input detected</span>'));

  // sinks (operation sites + tainted arg context + flows)
  const sinks=sig.sinks||[];
  // which sink ids are VULNERABLE per findings
  const sinkStatus={};
  findings.forEach(fd=>{const id=(fd.data||{}).sink_id; if(id)sinkStatus[id]=(fd.data||{}).status;});
  let kh="";
  sinks.forEach(k=>{
    const st=sinkStatus[k.id]||"";
    const bad=st==="VULNERABLE";
    kh+=`<div class="op ${bad?'bad':(st==='SANITIZED'?'ok':'')}"><div class="ohead">`+
        `<span class="okind">${esc(k.sink_kind||"sink")}</span>`+
        `<span class="tag rid">${esc(k.arg_context||"")}</span>`+
        (k.callee?`<span class="tag">${esc(k.callee)}</span>`:"")+
        (st?`<span class="vchip vc-${esc(st)}">${esc(st)}</span>`:"")+
        `</div>`;
    if(k.call_expr) kh+=`<div class="oev">${esc(k.call_expr)}</div>`;
    const flows=(k.flows||[]).map(fl=>{
      const sani=(fl.sanitizers||[]).length?` <span class="tag dom-yes">⊘ ${esc(fl.sanitizers.join(","))}</span>`:"";
      return `<span class="dep">${esc(fl.source)}</span>${sani}`;
    }).join(' <span class="arrow">·</span> ');
    kh+=`<div class="flowrow"><span class="arrow">tainted by</span>${flows||'<span class="mod">∅</span>'}<span class="arrow">→</span><b>${esc(k.sink_kind)}</b></div>`;
    kh+=`</div>`;
  });
  d.appendChild(section("Sinks ("+sinks.length+")",kh||'<span class="mod">none — no sensitive operation site</span>'));

  // sanitizers
  const sanis=sig.sanitizers||[];
  if(sanis.length){
    let zh="";
    sanis.forEach(z=>{
      zh+=`<div class="op"><div class="ohead"><span class="okind">${esc(z.sanitizer_kind||"sanitizer")}</span>`+
          `<span class="tag rid">${esc(z.id||"")}</span>`+
          `<span class="tag">endorses: ${esc((z.endorses||[]).join(",")||"—")}</span>`+
          `<span class="tag">conf:${esc(z.confidence||"?")}</span></div>`;
      if(z.expr) zh+=`<div class="oev">${esc(z.expr)}</div>`;
      zh+=`</div>`;
    });
    d.appendChild(section("Sanitizers ("+sanis.length+")",zh));
  }

  // interprocedural composition (callee sinks instantiated at call sites)
  const composed=sig._composed_sinks||[];
  if(composed.length){
    let ch="";
    composed.forEach(c=>{
      ch+=`<div class="obl">⇡ via <b>${esc(c.callee)}</b>: instantiated callee sink <span class="tag rid">${esc(c.sink_id)}</span> <span class="tag">${esc(c.sink_kind)}</span></div>`;
    });
    d.appendChild(section("Interprocedural (composed callee sinks)",ch));
  }

  if((sig.notes||[]).length) d.appendChild(section("Analysis notes",`<div class="notes">${esc((sig.notes||[]).join(" "))}</div>`));
  if(r.error) d.appendChild(section("Error",`<pre>${esc(r.error)}</pre>`));
}

function renderResourceDetail(d,f,r){
  // The resource plugin uses the generic render_result: r.facts is the resource
  // signature; r.findings carries the deterministic checker's per-costly-op verdicts.
  const sig=r.facts||(r.data&&r.data.signature)||{};
  const findings=r.findings||[];

  // findings first (the verdict's "why"): each costly op's status + CWE
  if(findings.length){
    let fh="";
    findings.forEach(fd=>{
      const dat=fd.data||{};
      const st=dat.status||"";
      const cls=st==="VULNERABLE"?"finding":"op"+(st==="POLYMORPHIC"?"":" ok");
      fh+=`<div class="${cls}">`+
          `<div class="ohead"><span class="okind">${esc(fd.title||fd.rule_id)}</span>`+
          `<span class="tag">${esc(dat.cwe||"")}</span>`+
          `<span class="tag">${esc(dat.op_kind||"")}</span>`+
          `<span class="vchip vc-${esc(st)}">${esc(st)}</span>`+
          (dat.bounded_by?`<span class="tag dom-yes">⊘ ${esc(dat.bounded_by)}</span>`:"")+
          `</div><div class="fm">${esc(fd.message||"")}</div>`;
      if(dat.evidence) fh+=`<div class="oev">${esc(dat.evidence)}</div>`;
      fh+=`</div>`;
    });
    d.appendChild(section("Findings ("+findings.length+")",fh));
  } else if(f.verdict==="SAFE"){
    d.appendChild(section("Findings",'<span class="mod">No attacker-controlled magnitude reaches a costly op.</span>'));
  }

  // magnitude sources (attacker-controllable sizes/counts/depths/ratios)
  const mags=sig.magnitude_sources||[];
  let mh="";
  mags.forEach(m=>{
    mh+=`<div class="op"><div class="ohead"><span class="okind">${esc(m.magnitude_kind||"magnitude")}</span>`+
        `<span class="tag rid">${esc(m.id||"")}</span>`+
        `<span class="tag">conf:${esc(m.confidence||"?")}</span></div>`;
    if(m.expr) mh+=`<div class="oev">${esc(m.expr)}</div>`;
    mh+=`</div>`;
  });
  d.appendChild(section("Magnitude sources ("+mags.length+")",mh||'<span class="mod">none — no attacker-controlled magnitude detected</span>'));

  // costly ops (operation sites + the magnitude they consume + bounds)
  const ops=sig.costly_ops||[];
  const opStatus={};
  findings.forEach(fd=>{const id=(fd.data||{}).op_id; if(id)opStatus[id]=(fd.data||{}).status;});
  let oh="";
  ops.forEach(op=>{
    const st=opStatus[op.id]||"";
    const bad=st==="VULNERABLE";
    oh+=`<div class="op ${bad?'bad':(st==='BOUNDED'?'ok':'')}"><div class="ohead">`+
        `<span class="okind">${esc(op.op_kind||"op")}</span>`+
        (op.callee?`<span class="tag">${esc(op.callee)}</span>`:"")+
        (st?`<span class="vchip vc-${esc(st)}">${esc(st)}</span>`:"")+
        `</div>`;
    if(op.call_expr) oh+=`<div class="oev">${esc(op.call_expr)}</div>`;
    const flows=(op.magnitudes||[]).map(mg=>{
      const bnd=(mg.bounds||[]).length?` <span class="tag dom-yes">⊘ ${esc(mg.bounds.join(","))}</span>`:"";
      return `<span class="dep">${esc(mg.source)}</span>${bnd}`;
    }).join(' <span class="arrow">·</span> ');
    oh+=`<div class="flowrow"><span class="arrow">driven by</span>${flows||'<span class="mod">∅</span>'}<span class="arrow">→</span><b>${esc(op.op_kind)}</b></div>`;
    oh+=`</div>`;
  });
  d.appendChild(section("Costly ops ("+ops.length+")",oh||'<span class="mod">none — no cost-bearing operation site</span>'));

  // bounds
  const bounds=sig.bounds||[];
  if(bounds.length){
    let bh="";
    bounds.forEach(b=>{
      bh+=`<div class="op"><div class="ohead"><span class="okind">${esc(b.bound_kind||"bound")}</span>`+
          `<span class="tag rid">${esc(b.id||"")}</span>`+
          `<span class="tag">caps: ${esc((b.caps||[]).join(",")||"—")}</span>`+
          `<span class="tag ${b.dominates?'dom-yes':'dom-no'}">${b.dominates?"dominates":"non-dominating"}</span>`+
          `<span class="tag">conf:${esc(b.confidence||"?")}</span></div>`;
      if(b.expr) bh+=`<div class="oev">${esc(b.expr)}</div>`;
      bh+=`</div>`;
    });
    d.appendChild(section("Bounds ("+bounds.length+")",bh));
  }

  // interprocedural composition (callee costly ops instantiated at call sites)
  const composed=sig._composed_ops||[];
  if(composed.length){
    let ch="";
    composed.forEach(c=>{
      ch+=`<div class="obl">⇡ via <b>${esc(c.callee)}</b>: instantiated callee op <span class="tag rid">${esc(c.op_id)}</span> <span class="tag">${esc(c.op_kind)}</span></div>`;
    });
    d.appendChild(section("Interprocedural (composed callee ops)",ch));
  }

  if((sig.notes||[]).length) d.appendChild(section("Analysis notes",`<div class="notes">${esc((sig.notes||[]).join(" "))}</div>`));
  if(r.error) d.appendChild(section("Error",`<pre>${esc(r.error)}</pre>`));
}

function renderCryptoDetail(d,f,r){
  // The crypto plugin uses the generic render_result: r.facts is the crypto
  // signature; r.findings carries the deterministic checker's per-operation findings.
  const sig=r.facts||(r.data&&r.data.signature)||{};
  const findings=r.findings||[];
  const sevColor={VULNERABLE:"vc-VULNERABLE",WEAK:"vc-WEAK",POLYMORPHIC:"vc-POLYMORPHIC",NEEDS_REVIEW:"vc-NEEDS_REVIEW"};

  // findings first (the verdict's "why"): each finding's severity + CWE
  if(findings.length){
    let fh="";
    findings.forEach(fd=>{
      const dat=fd.data||{};
      const sv=dat.severity||"";
      const cls=sv==="VULNERABLE"?"finding":"op"+(sv==="WEAK"||sv==="POLYMORPHIC"||sv==="NEEDS_REVIEW"?"":" ok");
      fh+=`<div class="${cls}"><div class="ohead">`+
          `<span class="okind">${esc(fd.title||fd.rule_id)}</span>`+
          (dat.cwe?`<span class="tag">${esc(dat.cwe)}</span>`:"")+
          (sv?`<span class="vchip ${sevColor[sv]||''}">${esc(sv)}</span>`:"")+
          (dat.operation_id?`<span class="tag rid">${esc(dat.operation_id)}</span>`:"")+
          `</div><div class="fm">${esc(fd.message||"")}</div>`;
      if(dat.evidence) fh+=`<div class="oev">${esc(dat.evidence)}</div>`;
      fh+=`</div>`;
    });
    d.appendChild(section("Findings ("+findings.length+")",fh));
  } else if(f.verdict==="SAFE"){
    d.appendChild(section("Findings",'<span class="mod">No cryptographic misuse detected.</span>'));
  }

  // crypto operations (the loci)
  const ops=sig.crypto_operations||[];
  // which op ids are flagged (and at what severity)
  const opSev={};
  findings.forEach(fd=>{const id=(fd.data||{}).operation_id; const sv=(fd.data||{}).severity; if(id && (!opSev[id]||sv==="VULNERABLE"))opSev[id]=sv;});
  let oh="";
  ops.forEach(o=>{
    const sv=opSev[o.id]||"";
    const bad=sv==="VULNERABLE";
    const cls=bad?"op bad":(sv?"op":"op ok");
    const key=o.key||{}, iv=o.iv_nonce||{}, rnd=o.randomness||{}, kdf=o.kdf||{};
    oh+=`<div class="${cls}"><div class="ohead">`+
        `<span class="okind">${esc(o.kind||"op")}</span>`+
        (o.algorithm?`<span class="tag rid">${esc(o.algorithm)}${o.mode?"/"+esc(o.mode):""}</span>`:"")+
        (o.purpose?`<span class="tag">${esc(o.purpose)}</span>`:"")+
        (sv?`<span class="vchip ${sevColor[sv]||''}">${esc(sv)}</span>`:"")+
        `</div>`;
    // material provenance rows
    const rows=[];
    if(key.provenance) rows.push(["key", key.provenance + (key._resolved_from?` (via ${key._resolved_from})`:"") + (key.length_bits?` · ${key.length_bits}b`:"")]);
    if(iv.provenance) rows.push(["iv/nonce", iv.provenance + (iv.randomness_source && iv.randomness_source!=="not_applicable"?` · ${iv.randomness_source}`:"")]);
    if(rnd.source && rnd.source!=="not_applicable") rows.push(["randomness", rnd.source]);
    if(kdf.name) rows.push(["kdf", kdf.name + (kdf.salt_provenance?` · salt:${kdf.salt_provenance}`:"") + (kdf.iterations?` · iter:${kdf.iterations}`:"") + (kdf.cost?` · cost:${kdf.cost}`:"")]);
    const auth=o.authenticity||{}; if(auth.provided_by && auth.provided_by!=="not_applicable") rows.push(["authenticity", auth.provided_by + (auth.verified_before_plaintext_trust===false?" · NOT verified before trust":"")]);
    const tls=o.tls||{}; if(tls.certificate_verification && tls.certificate_verification!=="not_applicable") rows.push(["tls cert", tls.certificate_verification]);
    const jwt=o.jwt||{}; if(jwt.allows_none!==undefined && (jwt.allows_none||jwt.signature_verification_disabled||(jwt.algorithms_allowed||[]).length)) rows.push(["jwt", (jwt.allows_none?"allows none ":"")+((jwt.algorithms_allowed||[]).join(",")||"")]);
    if(rows.length){
      oh+=`<table class="kv">`;
      rows.forEach(([k,v])=>{oh+=`<tr><td class="k">${esc(k)}</td><td>${esc(v)}</td></tr>`;});
      oh+=`</table>`;
    }
    if(o.evidence) oh+=`<div class="oev">${esc(o.evidence)}</div>`;
    oh+=`</div>`;
  });
  d.appendChild(section("Crypto operations ("+ops.length+")",oh||'<span class="mod">none — no cryptographic operation</span>'));

  // verify-before-trust events
  const vevs=sig.verify_events||[];
  if(vevs.length){
    let vh="";
    vevs.forEach(v=>{
      const bad=v.status && v.status!=="checked_and_dominates_use";
      vh+=`<div class="op ${bad?'bad':'ok'}"><div class="ohead">`+
          `<span class="okind">verify: ${esc(v.verify_kind||"?")}</span>`+
          `<span class="tag ${bad?'dom-no':'dom-yes'}">${esc(v.status||"unknown")}</span>`+
          (v.algorithm?`<span class="tag">${esc(v.algorithm)}</span>`:"")+
          `</div>`;
      if(v.trusted_use) vh+=`<div class="flowrow"><span class="arrow">trusted use:</span><span class="dep">${esc(v.trusted_use)}</span></div>`;
      if(v.evidence) vh+=`<div class="oev">${esc(v.evidence)}</div>`;
      vh+=`</div>`;
    });
    d.appendChild(section("Verify-before-trust ("+vevs.length+")",vh));
  }

  // returned crypto material (provenance exported to callers)
  const rets=(sig.returns||[]).filter(rr=>["key","iv_nonce","random_token"].includes(rr.material_kind));
  if(rets.length){
    let rh="";
    rets.forEach(rr=>{
      rh+=`<div class="op"><div class="ohead"><span class="okind">returns ${esc(rr.material_kind)}</span>`+
          `<span class="tag rid">${esc(rr.provenance||"?")}</span></div>`;
      if(rr.evidence) rh+=`<div class="oev">${esc(rr.evidence)}</div>`;
      rh+=`</div>`;
    });
    d.appendChild(section("Returned crypto material",rh));
  }

  // interprocedural composition (callee return-provenance resolved into caller material)
  const composed=sig._composed_material||[];
  if(composed.length){
    let ch="";
    composed.forEach(c=>{
      ch+=`<div class="obl">⇡ via <b>${esc(c.callee)}</b>: ${esc(c.op)}.${esc(c.material)} resolved to <span class="tag rid">${esc(c.resolved)}</span></div>`;
    });
    d.appendChild(section("Interprocedural (resolved material provenance)",ch));
  }

  if((sig.notes||[]).length) d.appendChild(section("Analysis notes",`<div class="notes">${esc((sig.notes||[]).join(" "))}</div>`));
  if(r.error) d.appendChild(section("Error",`<pre>${esc(r.error)}</pre>`));
}

function renderTypestateDetail(d,f,r){
  // The typestate plugin uses the generic render_result: r.facts is the signature
  // (ordered events + resources + exit states); r.findings carries the automaton
  // findings.
  const sig=r.facts||(r.data&&r.data.signature)||{};
  const findings=r.findings||[];
  const sevColor={VULNERABLE:"vc-VULNERABLE",POLYMORPHIC:"vc-POLYMORPHIC",NEEDS_REVIEW:"vc-NEEDS_REVIEW"};

  // findings first (the verdict's "why")
  if(findings.length){
    let fh="";
    findings.forEach(fd=>{
      const dat=fd.data||{};
      const sv=dat.verdict||"";
      const cls=sv==="VULNERABLE"?"finding":"op"+(sv==="POLYMORPHIC"||sv==="NEEDS_REVIEW"?"":" ok");
      fh+=`<div class="${cls}"><div class="ohead">`+
          `<span class="okind">${esc(fd.title||fd.rule_id)}</span>`+
          (dat.cwe?`<span class="tag">${esc(dat.cwe)}</span>`:"")+
          (dat.rule?`<span class="tag">${esc(dat.rule)}</span>`:"")+
          (sv?`<span class="vchip ${sevColor[sv]||''}">${esc(sv)}</span>`:"")+
          (dat.resource?`<span class="tag rid">${esc(dat.resource)}</span>`:"")+
          `</div><div class="fm">${esc(fd.message||"")}</div>`;
      if(dat.evidence) fh+=`<div class="oev">${esc(dat.evidence)}</div>`;
      fh+=`</div>`;
    });
    d.appendChild(section("Findings ("+findings.length+")",fh));
  } else if(f.verdict==="SAFE"){
    d.appendChild(section("Findings",'<span class="mod">No temporal/ordering violation detected.</span>'));
  }

  // ordered event trace (the core typestate abstraction)
  const events=sig.events||[];
  let eh="";
  events.forEach(e=>{
    const cov=e.path_coverage||"";
    const covCls=cov==="must"?"dom-yes":(cov==="unknown"?"dom-no":"");
    eh+=`<div class="op"><div class="ohead">`+
        `<span class="tag">${esc(String(e.order))}</span>`+
        `<span class="okind">${esc(e.kind)}</span>`+
        (e.resource?`<span class="tag rid">${esc(e.resource)}</span>`:"")+
        `<span class="tag ${covCls}">${esc(cov)}</span>`+
        (e.atomicity&&e.atomicity!=="not_applicable"?`<span class="tag">${esc(e.atomicity)}</span>`:"")+
        (e.tls_verify&&e.tls_verify!=="not_applicable"?`<span class="tag">tls:${esc(e.tls_verify)}</span>`:"")+
        (e._via?`<span class="tag">via ${esc(e._via)}</span>`:"")+
        `</div>`;
    if(e.operation) eh+=`<div class="oev">${esc(e.operation)}</div>`;
    const deps=[];
    if((e.predecessors_must||[]).length) deps.push("after: "+e.predecessors_must.join(","));
    if((e.control_depends_on||[]).length) deps.push("ctrl-dep: "+e.control_depends_on.join(","));
    if(deps.length) eh+=`<div class="flowrow"><span class="mod">${esc(deps.join("  ·  "))}</span></div>`;
    eh+=`</div>`;
  });
  d.appendChild(section("Event trace ("+events.length+")",eh||'<span class="mod">no security-relevant events</span>'));

  // resources
  const res=sig.resources||[];
  if(res.length){
    let rh=`<table class="kv">`;
    res.forEach(rr=>{
      rh+=`<tr><td class="k">${esc(rr.id)}</td><td>`+
          `<span class="tag">${esc(rr.kind||"?")}</span>`+
          `<span class="tag">origin:${esc(rr.origin||"?")}</span>`+
          (rr.formal?`<span class="tag">formal:${esc(rr.formal)}</span>`:"")+
          (rr.escapes&&rr.escapes!=="none"?`<span class="tag rid">escapes:${esc(rr.escapes)}</span>`:"")+
          (rr.mutability?`<span class="tag">${esc(rr.mutability)}</span>`:"")+
          `</td></tr>`;
    });
    rh+=`</table>`;
    d.appendChild(section("Resources ("+res.length+")",rh));
  }

  // exit states (lifecycle on normal vs exception paths)
  const exits=sig.exit_states||[];
  if(exits.length){
    let xh="";
    exits.forEach(x=>{
      const bad=x.state==="open"||x.state==="unknown";
      xh+=`<div class="op ${bad?'':'ok'}"><div class="ohead">`+
          `<span class="tag rid">${esc(x.resource)}</span>`+
          `<span class="tag ${x.state==='open'?'dom-no':(x.state==='unknown'?'dom-no':'dom-yes')}">${esc(x.state)}</span>`+
          `<span class="tag">on ${esc(x.condition||"?")}</span>`+
          `<span class="tag">${esc(x.path_coverage||"?")}</span>`+
          `</div></div>`;
    });
    d.appendChild(section("Exit states ("+exits.length+")",xh));
  }

  // ambient contexts (decorators / middleware) + interprocedural splice
  const amb=sig.ambient_contexts||[];
  if(amb.length){
    let ah="";
    amb.forEach(a=>{ah+=`<div class="obl">⊙ ${esc(a.kind)}(${esc(a.resource)}) ${esc(a.coverage||"")} — ${esc(a.source||"")}</div>`;});
    d.appendChild(section("Ambient contexts",ah));
  }
  const spliced=sig._spliced||[];
  if(spliced.length){
    let sh="";
    spliced.forEach(s=>{sh+=`<div class="obl">⇡ via <b>${esc(s.callee)}</b>: spliced ${esc(s.kind)} on <span class="tag rid">${esc(s.resource)}</span></div>`;});
    d.appendChild(section("Interprocedural (spliced callee events)",sh));
  }

  if((sig.uncertainties||[]).length) d.appendChild(section("Uncertainties",`<div class="notes">${esc((sig.uncertainties||[]).join(" "))}</div>`));
  if(r.error) d.appendChild(section("Error",`<pre>${esc(r.error)}</pre>`));
}

function section(title,html){
  const s=ce("div","sec");
  const h=ce("h2"); h.innerHTML=`<span>${esc(title)}</span><span class="mod">▾</span>`;
  const b=ce("div","body"); b.innerHTML=html;
  h.onclick=()=>b.classList.toggle("hide");
  s.appendChild(h); s.appendChild(b); return s;
}

async function renderReason(f){
  const r=$("#reason"); r.innerHTML='<div class="rh">'+esc(reasonTitle())+'</div>';
  if(!f.event_ids||!f.event_ids.length){ r.innerHTML+='<div class="empty">no LLM events for this function</div>'; return; }
  for(const eid of f.event_ids){
    const ev=ce("div","ev");
    const head=ce("div","eh");
    head.innerHTML=`<span>${esc(eid.slice(0,16))}…</span><span>load ▾</span>`;
    const body=ce("div","hide"); body.style.padding="0 0 8px";
    let loaded=false;
    head.onclick=async()=>{
      body.classList.toggle("hide");
      if(loaded)return; loaded=true;
      try{
        const e=await api("/api/event?plugin="+encodeURIComponent(PLUGIN)+"&dir="+encodeURIComponent(RUN.proj_dir)+"&id="+encodeURIComponent(eid));
        body.innerHTML=`<div class="mod" style="padding:0 14px">${esc(e.stage)} · ${esc(e.status)} · ${esc((e.meta&&e.meta.model)||"")} · ${esc(((e.meta&&e.meta.usage&&e.meta.usage.output_tokens)||"")+"")} out-tok</div>`;
        const tabs=ce("div","tab");
        const panes={};
        ["response","user","system"].forEach((nm,i)=>{
          const btn=ce("button"); btn.textContent=nm; if(i===0)btn.classList.add("on");
          const pane=ce("pre"+(i===0?"":"")); pane.textContent=e[nm]||"(empty)"; if(i!==0)pane.classList.add("hide");
          pane.style.margin="6px 14px";
          btn.onclick=()=>{Object.values(panes).forEach(p=>{p.btn.classList.remove("on");p.pane.classList.add("hide");});btn.classList.add("on");pane.classList.remove("hide");};
          panes[nm]={btn,pane}; tabs.appendChild(btn);
        });
        body.appendChild(tabs);
        Object.values(panes).forEach(p=>body.appendChild(p.pane));
      }catch(err){ body.innerHTML='<div class="empty">'+esc(err.message)+'</div>'; }
    };
    ev.appendChild(head); ev.appendChild(body); r.appendChild(ev);
  }
}

$("#load").onclick=loadRun;
$("#dir").addEventListener("keydown",e=>{if(e.key==="Enter")loadRun();});
$("#plugin").addEventListener("change",e=>{
  if(e.target.value==="__auto__"){ PLUGIN_LOCKED=false; }
  else { PLUGIN=e.target.value; PLUGIN_LOCKED=true; }
  loadRun();
});
$("#info").onclick=()=>{
  const titles={ifc:"About FM-Agent-IFC",authz:"About FM-Agent-Authz",taint:"About FM-Agent-Taint",crypto:"About FM-Agent-Crypto",typestate:"About FM-Agent-Typestate"};
  $("#modaltitle").textContent=titles[PLUGIN]||titles.ifc;
  $("#modalbody-ifc").classList.toggle("hide",PLUGIN!=="ifc");
  $("#modalbody-authz").classList.toggle("hide",PLUGIN!=="authz");
  $("#modalbody-taint").classList.toggle("hide",PLUGIN!=="taint");
  $("#modalbody-crypto").classList.toggle("hide",PLUGIN!=="crypto");
  $("#modalbody-typestate").classList.toggle("hide",PLUGIN!=="typestate");
  $("#modalbg").classList.add("show");
};
$("#modalclose").onclick=()=>$("#modalbg").classList.remove("show");
$("#modalbg").addEventListener("click",e=>{if(e.target===$("#modalbg"))$("#modalbg").classList.remove("show");});
document.addEventListener("keydown",e=>{if(e.key==="Escape")$("#modalbg").classList.remove("show");});
// seed selector with known plugins until a run reports availability.
(function(){const sel=$("#plugin");const a=ce("option");a.value="__auto__";a.textContent="Auto-detect";a.selected=true;sel.appendChild(a);[["ifc","IFC (information flow)"],["authz","Access control (guarded-Hoare)"],["taint","Integrity taint (injection)"],["crypto","Crypto misuse"],["typestate","Typestate / temporal"]].forEach(([n,l])=>{const o=ce("option");o.value=n;o.textContent=l;sel.appendChild(o);});})();
if(DEFAULT_DIR){ $("#dir").value=DEFAULT_DIR; loadRun(); }
</script>
</body>
</html>
"""


if __name__ == "__main__":
    main()

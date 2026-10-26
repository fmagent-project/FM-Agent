#!/usr/bin/env python3
"""Generate a deterministic, self-contained HTML report for static FM-Agent runs.

The upstream GitHub project exposed a searchable ``report.html`` after dynamic
bug validation.  This offline DeepSeek-Harness build intentionally removes that
runtime stage, so the equivalent page is generated directly from terminal
static reasoning artifacts instead.  No model call or network access occurs.
"""

from __future__ import annotations

import argparse
import json
import os
import sys


def _locate_workdir(value: str) -> str:
    path = os.path.abspath(os.path.expanduser(value))
    child = os.path.join(path, "fm_agent")
    if os.path.isdir(child):
        return child
    return path


def _read_json(path: str):
    with open(path, encoding="utf-8") as stream:
        return json.load(stream)


def _source_payload(work_dir: str, record: dict) -> dict:
    source_rel = str(record.get("source_file") or "")
    if not source_rel or source_rel.startswith("/") or ".." in source_rel.split("/"):
        return {"href": "", "text": ""}
    project_root = os.path.dirname(os.path.abspath(work_dir))
    source_path = os.path.join(project_root, source_rel.replace("/", os.sep))
    text = ""
    try:
        with open(source_path, encoding="utf-8", errors="replace") as stream:
            text = stream.read()
    except OSError:
        pass
    return {
        "href": os.path.relpath(source_path, work_dir).replace(os.sep, "/"),
        "text": text,
    }


_HTML = r"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>FM-Agent Static Verification Report</title>
<style>
:root{color-scheme:light dark;--bg:#f6f8fa;--card:#fff;--fg:#1f2328;--muted:#59636e;
--border:#d0d7de;--green:#1a7f37;--amber:#9a6700;--red:#cf222e;--blue:#0969da;--band:#fff8c5}
@media(prefers-color-scheme:dark){:root{--bg:#0d1117;--card:#161b22;--fg:#e6edf3;
--muted:#8b949e;--border:#30363d;--green:#3fb950;--amber:#d29922;--red:#f85149;--blue:#58a6ff;--band:#3b2e00}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:14px/1.5 system-ui,sans-serif}
header,main{max-width:1280px;margin:auto;padding:20px}h1{margin:0 0 4px;font-size:25px}.muted{color:var(--muted)}
.summary{display:grid;grid-template-columns:repeat(5,minmax(105px,1fr));gap:10px;margin:18px 0}
.metric,.toolbar,.item,.diagnostics{background:var(--card);border:1px solid var(--border);border-radius:8px}.metric{padding:12px}
.metric b{font-size:22px;display:block}.toolbar{padding:12px;display:flex;gap:10px;flex-wrap:wrap;align-items:center}
input,select,button{font:inherit;color:inherit;background:var(--bg);border:1px solid var(--border);border-radius:6px;padding:7px 9px}
button{cursor:pointer}#search{flex:1;min-width:240px}.filter-box{position:relative;border:1px solid var(--border);border-radius:6px;padding:6px 9px}
.filter-box>summary{cursor:pointer;font-weight:600}.filter-menu{display:grid;gap:4px;min-width:210px;max-height:250px;overflow:auto;padding-top:8px}
.filter-menu label{display:flex;gap:6px;align-items:center;font-family:ui-monospace,monospace;font-size:12px}
.filter-menu input{min-width:0}.items{display:grid;gap:10px;margin-top:12px}.item{overflow:hidden}
.item>summary{list-style:none;cursor:pointer;padding:13px}.item>summary::-webkit-details-marker{display:none}.item[open]>summary{border-bottom:1px solid var(--border)}
.body{padding:14px}.row{display:flex;gap:10px;align-items:center;flex-wrap:wrap}.title{font-weight:700;font-size:16px}
.badge{border-radius:999px;color:white;padding:2px 9px;font-size:12px;font-weight:700}.MATCH{background:var(--green)}
.MISMATCH{background:var(--amber)}.ERROR,.MISSING{background:var(--red)}.path{font-family:ui-monospace,monospace;color:var(--muted)}
.candidate{border-left:4px solid var(--amber);padding:6px 12px;margin:10px 0;background:color-mix(in srgb,var(--amber) 6%,transparent)}
dt{font-weight:700;margin-top:7px}dd{margin-left:0;white-space:pre-wrap}.actions{display:flex;gap:8px;flex-wrap:wrap;margin:10px 0}
pre,.source{overflow:auto;background:var(--bg);padding:10px;border-radius:6px;border:1px solid var(--border)}a{color:var(--blue)}
.notice{border-left:4px solid var(--blue);padding:8px 12px;background:var(--card)}.source{padding:0;font:12px/1.55 ui-monospace,monospace}
.source-line{display:grid;grid-template-columns:54px 1fr;min-width:max-content}.source-line.hit{background:var(--band)}
.ln{color:var(--muted);text-align:right;padding:0 12px 0 6px;user-select:none}.code{white-space:pre;padding-right:16px}
.kw{color:#cf222e;font-weight:600}.str{color:#0a3069}.com{color:#6e7781;font-style:italic}.diagnostics{padding:12px;margin-top:12px}
dialog{width:min(1000px,94vw);max-height:90vh;background:var(--card);color:var(--fg);border:1px solid var(--border);border-radius:10px;padding:0}
dialog::backdrop{background:#0008}.dialog-head{position:sticky;top:0;background:var(--card);display:flex;justify-content:space-between;gap:10px;padding:12px 16px;border-bottom:1px solid var(--border);z-index:2}.dialog-body{padding:16px}
@media(max-width:700px){.summary{grid-template-columns:repeat(2,1fr)}header,main{padding:14px}.toolbar>*{width:100%}}
</style></head><body>
<header><h1>FM-Agent Static Verification Report</h1><div id="subtitle" class="muted"></div></header>
<main><div class="notice"><b>Static result semantics:</b> MISMATCH is an unconfirmed static bug candidate. Dynamic tests and instrumentation are intentionally not included in this build.</div>
<section id="summary" class="summary"></section>
<section class="toolbar"><input id="search" type="search" placeholder="Search title / file / function / evidence" autocomplete="off">
<details class="filter-box"><summary>Verdicts</summary><div id="verdict-options" class="filter-menu"></div></details>
<details class="filter-box"><summary>Source files</summary><div id="file-options" class="filter-menu"></div></details>
<select id="sort"><option value="risk">Candidates first</option><option value="source">Source path</option><option value="function">Function</option></select>
<button id="expand-all">Expand all</button><button id="collapse-all">Collapse all</button><button id="reset">Reset</button><span id="shown" class="muted"></span></section>
<section id="items" class="items"></section><section id="diagnostics" class="diagnostics"></section></main>
<dialog id="detail-dialog"><div class="dialog-head"><b id="dialog-title"></b><button id="dialog-close">Close</button></div><div id="dialog-body" class="dialog-body"></div></dialog>
<script id="data" type="application/json">__DATA__</script>
<script>
const R=JSON.parse(document.getElementById('data').textContent), q=document.getElementById.bind(document);
const rowsAll=Array.isArray(R.results)?R.results:[], counts=R.counts||{}, rank={MISMATCH:0,ERROR:1,MISSING:2,MATCH:3};
const metric=(name,value)=>{const d=document.createElement('div');d.className='metric';const b=document.createElement('b');b.textContent=value;d.append(b,document.createTextNode(name));return d};
function add(parent,tag,text,cls){const e=document.createElement(tag);if(cls)e.className=cls;if(text!==undefined)e.textContent=text;parent.appendChild(e);return e}
q('subtitle').textContent=`Status: ${(R.status||'unknown').toUpperCase()} · mode: ${R.mode||'default'} · scope: ${R.analysis_scope||'full'}`;
q('summary').append(metric('Functions',R.total_functions||0),metric('Candidates',counts.MISMATCH||0),metric('Passed',counts.MATCH||0),metric('Errors',counts.ERROR||0),metric('Missing',counts.MISSING||0));
function makeChecks(id,values,indent){const host=q(id);for(const value of values){const label=document.createElement('label');if(indent)label.style.paddingLeft=`${Math.max(0,value.split('/').length-1)*12}px`;const box=document.createElement('input');box.type='checkbox';box.value=value;box.checked=true;box.addEventListener('change',render);label.append(box,document.createTextNode(value));host.appendChild(label)}}
makeChecks('verdict-options',[...new Set(rowsAll.map(r=>r.verdict))].sort((a,b)=>(rank[a]??9)-(rank[b]??9)),false);
makeChecks('file-options',[...new Set(rowsAll.map(r=>r.source_file||r.function).filter(Boolean))].sort(),true);
function checked(id){return new Set([...q(id).querySelectorAll('input:checked')].map(x=>x.value))}
function highlightedLine(text){const frag=document.createDocumentFragment();const re=/(\/\/.*$|"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|\b(?:if|else|for|while|switch|case|return|int|long|short|char|void|float|double|struct|class|public|private|const|static|bool|true|false|null|None|def|fn|let|var)\b)/gm;let pos=0,m;while((m=re.exec(text))){frag.append(document.createTextNode(text.slice(pos,m.index)));const s=document.createElement('span');s.className=m[0].startsWith('//')?'com':(m[0][0]==='"'||m[0][0]==="'")?'str':'kw';s.textContent=m[0];frag.append(s);pos=re.lastIndex}frag.append(document.createTextNode(text.slice(pos)));return frag}
function sourcePane(r){const pane=document.createElement('div');pane.className='source';const lines=(r.source_text||'').split('\n');lines.forEach((line,i)=>{const n=i+1,row=add(pane,'div','',`source-line ${r.start_line&&n>=r.start_line&&n<=(r.end_line||r.start_line)?'hit':''}`);add(row,'span',String(n),'ln');const code=add(row,'span','', 'code');code.append(highlightedLine(line))});return pane}
function candidateSection(g,i){const c=add(document.createElement('div'),'section','', 'candidate');add(c,'h3',`Static candidate ${i+1}`);const dl=add(c,'dl','');for(const [label,key] of [['Generated spec claim','spec_claim'],['Actual behavior','actual_behavior'],['Trigger condition','trigger_condition'],['Code evidence','code_evidence']]){add(dl,'dt',label);add(dl,'dd',g[key]||'(not recorded)')}return c}
function detailBody(r){const body=document.createElement('div');if(r.error){add(body,'h3','Error');add(body,'pre',r.error)}(r.candidates||[]).forEach((g,i)=>body.append(candidateSection(g,i)));const actions=add(body,'div','', 'actions');for(const [label,href] of [['Open result JSON',r.result_file],['Open generated spec',r.spec_file],['Open source',r.source_href]]){if(!href)continue;const a=add(actions,'a',label);a.href=href;a.target='_blank'}if(r.source_text){add(body,'h3',`Source · ${r.source_file||''} ${r.location||''}`);body.append(sourcePane(r))}return body}
function openFull(r){q('dialog-title').textContent=`${r.verdict} · ${r.function_name||r.function}`;q('dialog-body').replaceChildren(detailBody(r));q('detail-dialog').showModal()}
function card(r){const box=document.createElement('details');box.className='item';const head=add(box,'summary','');const row=add(head,'div','', 'row');add(row,'span',r.verdict,'badge '+r.verdict);add(row,'span',r.function_name||r.function,'title');add(row,'span',`${r.source_file||r.function}${r.location?' · '+r.location:''}`,'path');const body=add(box,'div','', 'body');const actions=add(body,'div','', 'actions');const full=add(actions,'button','Open full detail');full.type='button';full.onclick=()=>openFull(r);body.append(detailBody(r));return box}
function render(){const needle=q('search').value.trim().toLowerCase(),verdicts=checked('verdict-options'),files=checked('file-options'),sort=q('sort').value;let rows=rowsAll.filter(r=>verdicts.has(r.verdict)&&files.has(r.source_file||r.function)&&(!needle||JSON.stringify(r).toLowerCase().includes(needle)));rows.sort((a,b)=>sort==='source'?(a.source_file||'').localeCompare(b.source_file||''):sort==='function'?(a.function_name||'').localeCompare(b.function_name||''):(rank[a.verdict]??9)-(rank[b.verdict]??9)||(a.source_file||'').localeCompare(b.source_file||''));q('items').replaceChildren(...rows.map(card));q('shown').textContent=`${rows.length} / ${rowsAll.length} reports`}
q('search').addEventListener('input',render);q('sort').addEventListener('change',render);q('expand-all').onclick=()=>q('items').querySelectorAll('.item').forEach(x=>x.open=true);q('collapse-all').onclick=()=>q('items').querySelectorAll('.item').forEach(x=>x.open=false);
q('reset').onclick=()=>{q('search').value='';q('sort').value='risk';document.querySelectorAll('.filter-menu input').forEach(x=>x.checked=true);render()};q('dialog-close').onclick=()=>q('detail-dialog').close();
const t=R.trace||{};q('diagnostics').textContent=`Trace events: ${t.total_events||0} · Historical recovered/error events: ${t.historical_error_events||0} · Report status is determined by terminal static artifacts.`;render();
</script></body></html>"""


def generate_report(work_dir: str) -> str:
    work_dir = os.path.abspath(work_dir)
    report_path = os.path.join(work_dir, "VERIFICATION-REPORT.json")
    report = _read_json(report_path)
    results = []
    for original in report.get("results", []):
        if not isinstance(original, dict):
            continue
        record = dict(original)
        source = _source_payload(work_dir, record)
        record["source_href"] = source["href"]
        record["source_text"] = source["text"]
        results.append(record)
    report["results"] = results
    payload = json.dumps(report, ensure_ascii=False, sort_keys=True)
    payload = payload.replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026")
    html = _HTML.replace("__DATA__", payload)
    output = os.path.join(work_dir, "report.html")
    temporary = output + ".tmp"
    with open(temporary, "w", encoding="utf-8") as stream:
        stream.write(html)
    os.replace(temporary, output)
    return output


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("path", help="project root or fm_agent workspace")
    args = parser.parse_args()
    work_dir = _locate_workdir(args.path)
    report_path = os.path.join(work_dir, "VERIFICATION-REPORT.json")
    if not os.path.isfile(report_path):
        input_dir = os.path.join(work_dir, "extracted_functions")
        output_dir = os.path.join(work_dir, "logic_verification_results")
        if not os.path.isdir(output_dir):
            print(f"error: static result directory not found: {output_dir}", file=sys.stderr)
            return 1
        from src.verification import write_static_verification_report
        all_bugs = False
        for root, _dirs, files in os.walk(output_dir):
            for filename in files:
                if not filename.endswith(".json") or ".bug-" in filename:
                    continue
                try:
                    all_bugs = bool(_read_json(os.path.join(root, filename)).get("all_bugs"))
                except (OSError, ValueError, AttributeError):
                    pass
                if all_bugs:
                    break
            if all_bugs:
                break
        write_static_verification_report(
            input_dir,
            output_dir,
            work_dir,
            function_files=None,
            all_bugs=all_bugs,
            analysis_scope="reconstructed",
        )
    print(f"Report index written to {generate_report(work_dir)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

from __future__ import annotations

import html
import json
from pathlib import Path

from .database import Database
from .utils import atomic_write_json, task_paths, utc_now


def generate_chinese_reports(database: Database, tasks_dir: Path, task_id: str) -> None:
    task = database.get_task(task_id)
    if not task:
        return
    issues = database.list_issues(task_id)
    paths = task_paths(tasks_dir, task_id)
    reports = paths["reports"]
    reports.mkdir(parents=True, exist_ok=True)
    payload = {
        "报告语言": "中文",
        "生成时间": utc_now(),
        "任务": task,
        "说明": "MISMATCH 为静态推理发现、尚未经动态测试确认的问题候选。",
        "问题数量": len(issues),
        "问题": issues,
    }
    atomic_write_json(reports / "验证报告.json", payload)

    status_names = {
        "queued": "排队中", "running": "验证中", "cancelling": "停止中",
        "completed": "已完成", "failed": "失败", "cancelled": "已取消",
    }
    lines = [
        "# FM-Agent 代码验证报告",
        "",
        f"- 任务：{task['name']}",
        f"- 工程：{task['project_name']}",
        f"- 状态：{status_names.get(task['status'], task['status'])}",
        f"- 创建时间：{task['created_at']}",
        f"- 完成时间：{task.get('finished_at') or '—'}",
        f"- MISMATCH 候选：{len(issues)}",
        f"- 验证错误：{task.get('verification_error_count') or 0}",
        "",
        "> MISMATCH 为静态推理发现、尚未经动态测试确认的问题候选，需结合工程上下文人工复核。",
        "",
        "| 序号 | 源文件 | 函数 | 位置 | 严重程度 | 置信率 |",
        "|---:|---|---|---|---|---:|",
    ]
    for index, issue in enumerate(issues, 1):
        location = _location(issue)
        lines.append(
            f"| {index} | `{_md(issue['source_file'])}` | `{_md(issue['function_name'])}` | "
            f"{location} | {issue.get('severity') or '待评估'} | "
            f"{_confidence(issue)} |"
        )
    for index, issue in enumerate(issues, 1):
        lines.extend(
            [
                "",
                f"## {index}. {issue['function_name']}",
                "",
                f"- 位置：`{issue['source_file']}:{issue.get('start_line') or '?'}`",
                f"- 严重程度：{issue.get('severity') or '待评估'}",
                f"- 置信率：{_confidence(issue)}",
                f"- 中文解读状态：{issue['enrichment_status']}",
                "",
                "### 问题描述",
                "",
                issue.get("description_zh")
                or issue.get("enrichment_error")
                or "中文说明正在生成。",
                "",
                "### 问题反例（静态推理）",
                "",
                issue.get("counterexample_zh") or "等待中文解读模型生成反例。",
                "",
                "### 修改建议",
                "",
                issue.get("suggestion_zh") or "等待中文解读模型生成建议。",
                "",
                *(
                    ["### 违反的规约与证据", ""] +
                    ([f"- 【{item['rule_id']}】{item['content']}（{item['kind']}）\n  - 证据：{item['evidence_quote']}\n  - 解释：{item['reason']}"
                      for item in issue.get("violated_specs") or []]
                     or ["现有证据不足以可靠定位违反的具体条款。"])
                    + [""] if task.get("trace_enabled") else []
                ),
                "<details><summary>查看解读前的原始验证报告</summary>",
                "",
                "```json",
                json.dumps(issue.get("raw") or {}, ensure_ascii=False, indent=2),
                "```",
                "",
                "</details>",
            ]
        )
    (reports / "验证报告.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    (reports / "验证报告.html").write_text(_html_report(task, issues), encoding="utf-8")


def _md(value: str) -> str:
    return str(value).replace("|", "\\|").replace("`", "\\`")


def _location(issue: dict) -> str:
    start = issue.get("start_line")
    end = issue.get("end_line")
    if not start:
        return "—"
    return f"L{start}–L{end}" if end and end != start else f"L{start}"


def _confidence(issue: dict) -> str:
    value = issue.get("confidence")
    return f"{float(value):g}%" if value is not None else "待评估"


def _html_report(task: dict, issues: list[dict]) -> str:
    cards = []
    for index, issue in enumerate(issues, 1):
        severity = issue.get("severity") or "待评估"
        raw = html.escape(json.dumps(issue.get("raw") or {}, ensure_ascii=False, indent=2))
        trace_items = issue.get("violated_specs") or []
        trace = "".join(
            f"<li><strong>【{html.escape(item['rule_id'])}】</strong> {html.escape(item['content'])}"
            f"<br><small>证据：{html.escape(item['evidence_quote'])}；{html.escape(item['reason'])}</small></li>"
            for item in trace_items
        ) or "<li>现有证据不足以可靠定位违反的具体条款。</li>"
        trace_section = f"<h3>违反的规约与证据</h3><ul>{trace}</ul>" if task.get("trace_enabled") else ""
        cards.append(
            f"""<article class="issue"><div class="issue-head"><span class="num">{index}</span>
            <div><h2>{html.escape(issue['function_name'])}</h2><code>{html.escape(issue['source_file'])}:{issue.get('start_line') or '?'}</code></div>
            <span class="severity s-{severity}">{severity}</span><strong>{_confidence(issue)}</strong></div>
            <h3>问题描述</h3><p>{html.escape(issue.get('description_zh') or issue.get('enrichment_error') or '中文说明正在生成。')}</p>
            <section class="counterexample"><h3>问题反例（静态推理）</h3><p>{html.escape(issue.get('counterexample_zh') or '等待中文解读模型生成反例。')}</p></section>
            <h3>修改建议</h3><p>{html.escape(issue.get('suggestion_zh') or '等待中文解读模型生成建议。')}</p>
            {trace_section}
            <details><summary>查看解读前的原始验证报告</summary><pre>{raw}</pre></details></article>"""
        )
    return f"""<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
    <title>{html.escape(task['name'])} · 验证报告</title><style>
    :root{{--blue:#2864dc;--ink:#172033;--muted:#667085;--line:#e4e9f1;--bg:#f5f7fb}}*{{box-sizing:border-box}}body{{margin:0;background:var(--bg);color:var(--ink);font:14px/1.7 system-ui,"Microsoft YaHei",sans-serif}}main{{max-width:1080px;margin:auto;padding:38px 24px}}header,.issue{{background:#fff;border:1px solid var(--line);border-radius:14px;box-shadow:0 4px 18px #1d293910}}header{{padding:28px;margin-bottom:20px}}h1{{margin:0 0 12px;font-size:28px}}.meta{{display:flex;gap:26px;flex-wrap:wrap;color:var(--muted)}}.notice{{border-left:4px solid var(--blue);padding:10px 14px;background:#eef4ff;margin:18px 0}}.issue{{padding:22px;margin:14px 0}}.issue-head{{display:grid;grid-template-columns:auto 1fr auto auto;gap:14px;align-items:center}}.issue h2{{font-size:18px;margin:0}}.num{{width:30px;height:30px;border-radius:50%;display:grid;place-items:center;background:#e9f0ff;color:var(--blue);font-weight:700}}code,pre{{font-family:ui-monospace,monospace}}code{{color:var(--muted)}}pre{{white-space:pre-wrap;background:#f7f8fa;padding:14px;border-radius:8px;overflow:auto}}.counterexample{{margin:16px 0;padding:10px 14px;border-left:4px solid #e59a22;background:#fff8eb}}.counterexample h3{{margin-top:0;color:#8a5200}}.counterexample p{{white-space:pre-line}}.severity{{padding:3px 10px;border-radius:99px;background:#fff5e8;color:#b54708}}.s-高{{background:#fff0f0;color:#c62828}}.s-低{{background:#eef9f1;color:#16803a}}@media(max-width:650px){{.issue-head{{grid-template-columns:auto 1fr}}}}
    </style></head><body><main><header><h1>FM-Agent 代码验证报告</h1><div class="meta"><span>任务：{html.escape(task['name'])}</span><span>工程：{html.escape(task['project_name'])}</span><span>候选问题：{len(issues)}</span><span>验证错误：{task.get('verification_error_count') or 0}</span></div></header><div class="notice">MISMATCH 为静态推理发现、尚未经动态测试确认的问题候选，需结合工程上下文人工复核。</div>{''.join(cards) or '<div class="notice">当前没有发现 MISMATCH 候选。</div>'}</main></body></html>"""

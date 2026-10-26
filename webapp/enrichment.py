from __future__ import annotations

import json
import re
from concurrent.futures import ThreadPoolExecutor
from typing import Callable

from .config import Settings
from .database import Database


SYSTEM_PROMPT = """你是面向一线开发人员的软件验证结果解读助手。输入包含一条静态推理发现的
MISMATCH 候选和相关源码。目标是让不了解形式化验证的开发人员在十秒内看懂问题。

写作规则：
1. 使用日常、直接、具体的中文，短句优先；避免“条件 A/B、后置条件、谓词、建立/蕴含”等
   形式化术语。必须使用时，紧接着用白话解释。
2. description 用 1 至 3 句说明：什么输入或状态下，代码实际做什么，而规约要求什么，以及
   最直接的后果。先说结论，不复述整段源码，不写空泛措辞，建议不超过 160 个汉字。
3. counterexample 给出一个可复核的具体反例，固定写成：
   “触发条件：……\n实际结果：……\n期望结果：……”；尽量使用原始结果中的具体数值、边界值、
   变量名和返回值。它是静态推理反例，不得声称已经实际运行。若输入证据不足以可靠构造，写
   “暂无可靠反例：原始验证证据不足，需要补充输入范围或状态约束。”，不得编造。
4. suggestion 给出最小且可执行的修改方向，指出应修改的判断、顺序或边界；不要只写“检查代码”
   或“建议优化”，不要虚构源码中不存在的 API，建议不超过 160 个汉字。
5. severity 只按潜在后果分级：越界/内存破坏/安全联锁失效为高；功能错误、错误返回或状态不一致
   为中；仅格式或低影响偏差为低。confidence 表示当前证据支持该结论的充分程度，不表示严重性。
6. 不得把静态候选夸大为已经动态确认的漏洞；如果规约本身可能矛盾或含糊，要直说需要人工确认。

如果给出“可追溯条款”，仅当验证证据能具体说明代码违反该条款时，才在 violated_specs 中列出。
每项必须含 id（只能选给定编号）、evidence_quote（必须逐字摘自原始验证结果或所附源码，
不能摘自条款自身）、reason（简短解释违反关系）。不能可靠对应时返回空数组，禁止凑数。

只返回一个 JSON 对象，包含以下字段：description、counterexample、severity、confidence、
suggestion、violated_specs。severity 必须是“高”“中”“低”之一，confidence 必须是 0-100 的整数。不要使用
Markdown 代码围栏。"""


def run_agent_for_messages(model, messages, *, text_only):
    """Load the original Harness adapter lazily and reuse its exact model route."""
    from src.harness_backend import run_agent_for_messages as run

    return run(model, messages, text_only=text_only)


class EnrichmentError(RuntimeError):
    pass


class IssueEnricher:
    def __init__(
        self,
        settings: Settings,
        database: Database,
        source_loader: Callable[[str, str], str],
        on_update: Callable[[str], None] | None = None,
        trace_candidates: Callable[[dict], list[dict]] | None = None,
    ):
        self.settings = settings
        self.database = database
        self.source_loader = source_loader
        self.on_update = on_update
        self.trace_candidates = trace_candidates
        self.executor = ThreadPoolExecutor(
            max_workers=settings.enrich_workers,
            thread_name_prefix="issue-enrichment",
        )

    def submit(self, issue_id: int) -> None:
        self.executor.submit(self._run, issue_id)

    def _run(self, issue_id: int) -> None:
        issue = self.database.set_issue_enriching(issue_id)
        if not issue:
            return
        task_id = issue["task_id"]
        try:
            result = self._request(issue)
            self.database.finish_issue_enrichment(
                issue_id,
                description_zh=result["description"],
                counterexample_zh=result["counterexample"],
                severity=result["severity"],
                confidence=result["confidence"],
                suggestion_zh=result["suggestion"],
                violated_specs=result["violated_specs"],
            )
        except Exception as exc:  # The raw mismatch must survive every enrichment failure.
            message = str(exc).strip() or type(exc).__name__
            self.database.finish_issue_enrichment(issue_id, error=message[:1000])
        finally:
            if self.on_update:
                self.on_update(task_id)

    def _request(self, issue: dict) -> dict:
        raw = issue.get("raw") or {}
        source = self.source_loader(issue["task_id"], issue["source_file"])
        start = int(issue.get("start_line") or 1)
        end = int(issue.get("end_line") or start)
        lines = source.splitlines()
        left = max(0, start - 8)
        right = min(len(lines), max(end + 7, start + 20))
        snippet = "\n".join(f"{index + 1}: {lines[index]}" for index in range(left, right))
        candidates: list[dict] = []
        if self.trace_candidates:
            try:
                candidates = self.trace_candidates(issue)
            except Exception:
                candidates = []
        candidate_text = "\n".join(
            f"{rule['rule_id']} | {rule['kind']} | {rule['category']} | {rule.get('prompt_content', rule['content'])}"
            for rule in candidates
        )
        messages = [
            {"role": "system", "content": SYSTEM_PROMPT},
            {
                "role": "user",
                "content": (
                    f"文件：{issue['source_file']}\n函数：{issue['function_name']}\n"
                    f"位置：{start}-{end}\n验证结果：\n"
                    + json.dumps(raw, ensure_ascii=False, indent=2)[:16000]
                    + "\n相关源码：\n"
                    + snippet[:12000]
                    + "\n\n请严格依据上述验证证据和源码生成解读。先寻找验证结果中的"
                    + " trigger_condition、counterexample、code_evidence 或具体边界值来构造反例；"
                    + "不要补造输入值、运行结果或业务影响。"
                    + ("\n\n可追溯条款（只允许从下列编号选择）：\n" + candidate_text
                       if candidates else "\n\n没有可追溯条款，请返回空数组。")
                ),
            },
        ]
        try:
            content, _usage = run_agent_for_messages(
                self.settings.enrich_model,
                messages,
                text_only=True,
            )
        except Exception as exc:
            raise EnrichmentError(f"中文解读模型调用失败：{exc}") from exc
        try:
            result = self._parse_json(str(content))
        except (ValueError, TypeError) as exc:
            raise EnrichmentError("中文解读模型返回了无法解析的响应") from exc
        validated = self._validate(result)
        corpus = json.dumps(raw, ensure_ascii=False) + "\n" + snippet
        by_id = {rule["rule_id"]: rule for rule in candidates}
        traced = []
        seen = set()
        for item in result.get("violated_specs") or []:
            if not isinstance(item, dict):
                continue
            rule_id = str(item.get("id") or "").strip()
            quote = str(item.get("evidence_quote") or "").strip()
            reason = str(item.get("reason") or "").strip()
            rule = by_id.get(rule_id)
            if not rule or rule_id in seen or len(quote) < 4 or quote not in corpus or not reason:
                continue
            seen.add(rule_id)
            traced.append({
                "rule_id": rule_id, "kind": rule["kind"], "category": rule["category"],
                "content": rule["content"], "source_file": rule["source_file"],
                "source_line": rule["source_line"], "function_name": rule.get("function_name"),
                "evidence_quote": quote[:500], "reason": reason[:500],
            })
        validated["violated_specs"] = traced
        return validated

    @staticmethod
    def _parse_json(content: str) -> dict:
        value = content.strip()
        value = re.sub(r"^```(?:json)?\s*|\s*```$", "", value, flags=re.IGNORECASE)
        try:
            return json.loads(value)
        except json.JSONDecodeError:
            start = value.find("{")
            end = value.rfind("}")
            if start >= 0 and end > start:
                return json.loads(value[start : end + 1])
            raise

    @staticmethod
    def _validate(value: dict) -> dict:
        if not isinstance(value, dict):
            raise EnrichmentError("中文解读结果不是 JSON 对象")
        description = str(value.get("description") or "").strip()
        counterexample = str(value.get("counterexample") or "").strip()
        suggestion = str(value.get("suggestion") or "").strip()
        severity = str(value.get("severity") or "").strip()
        aliases = {
            "critical": "高", "high": "高", "medium": "中", "low": "低",
            "严重": "高", "较高": "高", "一般": "中", "较低": "低",
        }
        severity = aliases.get(severity.lower(), aliases.get(severity, severity))
        if severity not in {"高", "中", "低"}:
            severity = "中"
        try:
            confidence = float(value.get("confidence"))
        except (TypeError, ValueError) as exc:
            raise EnrichmentError("中文解读结果缺少有效置信率") from exc
        if 0 <= confidence <= 1:
            confidence *= 100
        confidence = round(min(100.0, max(0.0, confidence)), 1)
        if not description or not counterexample or not suggestion:
            raise EnrichmentError("中文解读结果缺少问题描述、问题反例或修改建议")
        return {
            "description": description[:4000],
            "counterexample": counterexample[:4000],
            "severity": severity,
            "confidence": confidence,
            "suggestion": suggestion[:4000],
        }

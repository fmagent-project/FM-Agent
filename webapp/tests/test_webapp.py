from __future__ import annotations

import json
import io
import tempfile
import threading
import time
import unittest
import zipfile
from dataclasses import replace
from http.server import ThreadingHTTPServer
from pathlib import Path
from types import SimpleNamespace
from urllib.request import Request, urlopen
from unittest.mock import patch

from webapp import server as web_server
from webapp.config import Settings
from webapp.database import Database
from webapp.domain_specs import DomainPreprocessor
from webapp.enrichment import IssueEnricher
from webapp.reports import generate_chinese_reports
from webapp.requirements import (
    CATEGORIES,
    CATEGORY_SPEC_CODES,
    RequirementError,
    RequirementPreprocessor,
    extract_docx_text,
    number_design_intent_rules,
    parse_design_intent_categories,
    split_requirement_text,
)
from webapp.runner import TaskManager, _relative_extracted_function, _source_from_extracted
from webapp.spec_trace import FunctionSpecIndexer, material_rules, number_uploaded_intent
from webapp.service import ServiceError, TaskService, Upload
from webapp.source_navigation import find_symbol_definition
from webapp.utils import decode_text, detect_text_encoding, safe_relative_path, task_paths


class DummyManager:
    def __init__(self, settings):
        self.settings = settings
        self.notified = False
        self.stopped = []

    def notify(self):
        self.notified = True

    def stop_task(self, task_id):
        self.stopped.append(task_id)
        return {"id": task_id, "status": "cancelling"}

    def load_source(self, task_id, relative):
        data = (task_paths(self.settings.tasks_dir, task_id)["project"] / relative).read_bytes()
        return decode_text(data)[0]


class SourceNavigationTests(unittest.TestCase):
    def test_cross_file_lookup_stays_fast_on_long_unrelated_declarations(self):
        sources = [
            ("app/main.c", "int main(void) { return compute(1) + FAULT_OT; }\n"),
            ("include/api.h", "enum {\n    FAULT_OT = 1u << 2,\n};\nint compute(int x);\n"),
            ("src/api.c", "static volatile " * 28 + "unrelated;\nint compute(int x) { return x + 1; }\n"),
        ]
        started = time.monotonic()
        function = find_symbol_definition(sources, "compute", "app/main.c", 1)
        constant = find_symbol_definition(sources, "FAULT_OT", "app/main.c", 1)
        self.assertEqual((function["path"], function["line"]), ("src/api.c", 2))
        self.assertEqual((constant["path"], constant["line"]), ("include/api.h", 2))
        self.assertLess(time.monotonic() - started, 1.0)


def settings_for(root: Path) -> Settings:
    return replace(
        Settings.from_env(),
        data_dir=root,
        max_project_files=3,
        max_project_bytes=1024,
        max_material_files=2,
        max_material_bytes=4096,
        max_request_bytes=4096,
        demo_mode=True,
    )


def make_docx(*paragraphs: str, table: list[list[str]] | None = None) -> bytes:
    namespace = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"
    body = []
    for paragraph in paragraphs:
        body.append(f'<w:p><w:r><w:t>{paragraph}</w:t></w:r></w:p>')
    if table:
        rows = []
        for row in table:
            cells = "".join(
                f'<w:tc><w:p><w:r><w:t>{cell}</w:t></w:r></w:p></w:tc>'
                for cell in row
            )
            rows.append(f"<w:tr>{cells}</w:tr>")
        body.append(f"<w:tbl>{''.join(rows)}</w:tbl>")
    xml = (
        f'<w:document xmlns:w="{namespace}"><w:body>'
        + "".join(body)
        + "</w:body></w:document>"
    )
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("word/document.xml", xml)
    return output.getvalue()


class UtilityTests(unittest.TestCase):
    def test_native_tool_mode_is_default(self):
        self.assertEqual(Settings.from_env().tool_compat_mode, "native")

    def test_safe_paths(self):
        self.assertEqual(safe_relative_path("src/main.py"), "src/main.py")
        for value in ("../secret", "/etc/passwd", "src/../../secret", ""):
            with self.assertRaises(ValueError):
                safe_relative_path(value)

    def test_utf8_and_gb2312_detection(self):
        utf8 = "中文源码".encode("utf-8")
        gb2312 = "中文源码".encode("gb2312")
        self.assertEqual(detect_text_encoding(utf8), "UTF-8")
        self.assertEqual(detect_text_encoding(gb2312), "GB2312")
        self.assertEqual(decode_text(gb2312), ("中文源码", "GB2312"))

    def test_source_mapping(self):
        absolute = "/tmp/p/fm_agent/extracted_functions/src/sample-py/run.py"
        relative = _relative_extracted_function(absolute)
        self.assertEqual(relative, "src/sample-py/run.py")
        self.assertEqual(_source_from_extracted(relative), "src/sample.py")


class RequirementPreprocessingTests(unittest.TestCase):
    def test_design_intent_rules_have_category_scoped_spec_ids(self):
        raw = (
            "# 设计意图\n\n## 功能行为\n\n### 来源文档：SRS.docx\n\n"
            "- **【99】** 第一条规则。\n"
            "- **【Spec-Error-777】** 【SWR-001】第二条规则。\n"
            "  - 第二条的说明。\n\n"
            "```text\n- 代码示例不能编号\n```\n\n"
            "## 前置条件与适用范围\n\n1. 第三条规则。\n"
            "- 未识别到明确约束。\n\n## 待确认事项\n\n- 需确认阈值。\n"
        )
        numbered = number_design_intent_rules(raw)
        self.assertIn("- **【Spec-Func-001】** 第一条规则。", numbered)
        self.assertIn("- **【Spec-Func-002】** 【SWR-001】第二条规则。", numbered)
        self.assertIn("  - 第二条的说明。", numbered)
        self.assertIn("- 代码示例不能编号", numbered)
        self.assertIn("- **【Spec-Precond-001】** 第三条规则。", numbered)
        self.assertIn("- 未识别到明确约束。", numbered)
        self.assertIn("- 需确认阈值。", numbered)
        self.assertEqual(number_design_intent_rules(numbered), numbered)

    def test_manual_intent_and_domain_rules_are_structured(self):
        manual = number_uploaded_intent("## 功能行为\n- 返回值必须为 1。\n", "规则.md")
        self.assertIn("Spec-Intent-", manual)
        self.assertEqual(number_uploaded_intent(manual, "规则.md"), manual)
        preserved = number_uploaded_intent("## 功能行为\n- **【Spec-Func-001】** 返回 1。\n", "规则.md")
        self.assertIn("原编号：Spec-Func-001", preserved)
        self.assertIn("Spec-Intent-", preserved)
        domain = "## 错误检测、降级与恢复\n- **【Spec-Domain-Error-001】** 故障时返回 ERR。\n"
        records = material_rules(domain, task_id="new", kind="domain", filename="领域规约-结构化.md")
        self.assertEqual(records[0]["rule_id"], "Spec-Domain-Error-001")
        self.assertEqual(records[0]["source_line"], 2)
        self.assertEqual(records[0]["content"], "故障时返回 ERR。")

    def test_design_intent_categories_are_stable_and_accept_old_headings(self):
        markdown = (
            "# 设计意图\n\n### 前置条件\n- 仅当系统就绪时执行。\n\n"
            "### 协议约束\n- CRC 必须正确。\n"
        )
        categories = parse_design_intent_categories(markdown)
        self.assertEqual([item["title"] for item in categories], list(CATEGORIES))
        by_key = {item["key"]: item["content"] for item in categories}
        self.assertIn("系统就绪", by_key["preconditions"])
        self.assertIn("CRC", by_key["interfaces"])
        self.assertEqual(by_key["questions"], "")
        numbered = number_design_intent_rules(markdown)
        self.assertIn("【Spec-Precond-001】", numbered)
        self.assertIn("【Spec-Proto-001】", numbered)

    def test_extracts_docx_paragraphs_and_tables(self):
        data = make_docx(
            "当温度达到 120 摄氏度时应关闭电机。",
            table=[["字段", "约束"], ["CRC", "必须校验"]],
        )
        text = extract_docx_text(data, "SRS.docx")
        self.assertIn("关闭电机", text)
        self.assertIn("| 字段 | 约束 |", text)
        self.assertIn("| CRC | 必须校验 |", text)
        self.assertGreaterEqual(len(split_requirement_text(text, 20)), 2)

    def test_uses_configured_model_and_returns_chinese_markdown(self):
        with tempfile.TemporaryDirectory() as directory:
            settings = replace(settings_for(Path(directory)), demo_mode=False)
            generated = "\n".join(f"### {name}\n- 示例约束。" for name in CATEGORIES)
            with patch("webapp.requirements.run_agent_for_messages", return_value=(generated, {})) as call:
                result = RequirementPreprocessor(settings).preprocess([
                    Upload("SRS.docx", make_docx("收到复位命令后才允许清除故障。"))
                ])
            self.assertEqual(result["model"], settings.enrich_model)
            self.assertIn("# 设计意图", result["markdown"])
            self.assertIn("来源文档：SRS.docx", result["markdown"])
            self.assertIn("安全不变量", result["markdown"])
            for category in result["categories"]:
                if category["key"] in CATEGORY_SPEC_CODES:
                    self.assertIn(
                        f"**【Spec-{CATEGORY_SPEC_CODES[category['key']]}-001】** 示例约束。",
                        category["content"],
                    )
                else:
                    self.assertNotIn("Spec-", category["content"])
            self.assertEqual(len(result["categories"]), len(CATEGORIES))
            self.assertEqual(result["documents"][0]["chunks"], 1)
            self.assertEqual(call.call_args.args[0], settings.enrich_model)
            self.assertTrue(call.call_args.kwargs["text_only"])
            prompt = call.call_args.args[1][0]["content"] + call.call_args.args[1][1]["content"]
            self.assertIn("当前代码", prompt)
            self.assertIn("收到复位命令", prompt)


class EnrichmentTests(unittest.TestCase):
    def test_uses_same_harness_model_as_validation(self):
        with tempfile.TemporaryDirectory() as directory:
            settings = settings_for(Path(directory))
            database = Database(settings.database_path)
            enricher = IssueEnricher(
                settings,
                database,
                lambda _task_id, _path: "def verify():\n    return False\n",
            )
            issue = {
                "task_id": "task-1",
                "source_file": "src/check.py",
                "function_name": "verify",
                "start_line": 1,
                "end_line": 2,
                "raw": {"spec_claim": "返回真", "actual_behavior": "返回假"},
            }
            response = json.dumps(
                {
                    "description": "返回值与规约不一致。",
                    "counterexample": "触发条件：输入为 0。\n实际结果：返回假。\n期望结果：返回真。",
                    "severity": "中",
                    "confidence": 88,
                    "suggestion": "检查返回值分支。",
                },
                ensure_ascii=False,
            )
            with patch(
                "webapp.enrichment.run_agent_for_messages",
                return_value=(response, {}),
            ) as harness_call:
                result = enricher._request(issue)
            args, kwargs = harness_call.call_args
            self.assertEqual(args[0], settings.enrich_model)
            self.assertTrue(kwargs["text_only"])
            self.assertEqual(result["confidence"], 88)
            self.assertIn("触发条件", result["counterexample"])
            prompt = args[1][0]["content"] + args[1][1]["content"]
            self.assertIn("十秒内看懂", prompt)
            self.assertIn("counterexample", prompt)
            enricher.executor.shutdown(wait=True)


class ServiceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.settings = settings_for(Path(self.temp.name))
        self.database = Database(self.settings.database_path)
        self.manager = DummyManager(self.settings)
        self.domains = DomainPreprocessor(self.settings, self.database)
        self.service = TaskService(self.settings, self.database, self.manager, domain_preprocessor=self.domains)

    def tearDown(self):
        self.domains.shutdown()
        self.temp.cleanup()

    def confirm_domain(self, task_id):
        for _ in range(100):
            status = self.database.get_task(task_id)["status"]
            if status != "domain_preprocessing":
                break
            time.sleep(0.01)
        self.assertEqual(status, "awaiting_domain_confirmation")
        review = self.service.domain_review(task_id)
        return self.service.confirm_domain(task_id, review["markdown"])

    def create(self):
        task = self.service.create_task(
            name="示例任务",
            project_name="demo",
            source_paths=["src/main.py", "README.md"],
            sources=[Upload("main.py", b"def main():\n    return 1\n"), Upload("README.md", b"demo\n")],
            domain_files=[Upload("rules.md", "# 领域规约\n".encode())],
            intent_files=[Upload("intent.txt", "设计意图\n".encode())],
        )
        self.confirm_domain(task["id"])
        return task

    def test_requirement_preview_http_endpoint(self):
        task = self.create()
        self.database.update_task(task["id"], status="awaiting_confirmation")
        with patch.object(web_server, "APP", SimpleNamespace(settings=self.settings, service=self.service), create=True), \
                patch.object(web_server.Handler, "log_message"):
            httpd = ThreadingHTTPServer(("127.0.0.1", 0), web_server.Handler)
            thread = threading.Thread(target=httpd.serve_forever, daemon=True)
            thread.start()
            try:
                request = Request(
                    f"http://127.0.0.1:{httpd.server_port}/api/tasks/{task['id']}/requirements/preview",
                    data=json.dumps({
                        "markdown": "## 功能行为\n\n- **已渲染**的规则\n",
                        "category": "functional",
                    }).encode("utf-8"),
                    headers={"Content-Type": "application/json"},
                    method="POST",
                )
                with urlopen(request, timeout=3) as response:
                    payload = json.load(response)
                self.assertIn("<li ", payload["html"])
                self.assertIn("<strong>已渲染</strong>", payload["html"])
                self.assertIn("<strong>【Spec-Func-001】</strong>", payload["html"])
                self.assertIn("**【Spec-Func-001】**", payload["categories"][0]["content"])
            finally:
                httpd.shutdown()
                httpd.server_close()
                thread.join(timeout=3)

    def test_domain_review_http_endpoints(self):
        task = self.service.create_task(
            name="领域确认", project_name="p", source_paths=["main.c"],
            sources=[Upload("main.c", b"int main(void) { return 0; }\n")],
            domain_files=[Upload("safety.md", "- 任何情况下电机输出必须为零。\n".encode())],
            intent_files=[],
        )
        for _ in range(100):
            if self.database.get_task(task["id"])["status"] != "domain_preprocessing":
                break
            time.sleep(0.01)
        self.assertEqual(self.database.get_task(task["id"])["status"], "awaiting_domain_confirmation")
        app = SimpleNamespace(settings=self.settings, service=self.service, database=self.database)
        with patch.object(web_server, "APP", app, create=True), patch.object(web_server.Handler, "log_message"):
            httpd = ThreadingHTTPServer(("127.0.0.1", 0), web_server.Handler)
            thread = threading.Thread(target=httpd.serve_forever, daemon=True)
            thread.start()
            try:
                url = f"http://127.0.0.1:{httpd.server_port}/api/tasks/{task['id']}/domain"
                with urlopen(url, timeout=3) as response:
                    review = json.load(response)
                self.assertIn("Spec-Domain-Safety-001", review["markdown"])
                request = Request(url + "/confirm", data=json.dumps({"markdown": review["markdown"]}).encode(),
                                  headers={"Content-Type": "application/json"}, method="POST")
                with urlopen(request, timeout=3) as response:
                    confirmed = json.load(response)
                self.assertEqual(confirmed["status"], "queued")
            finally:
                httpd.shutdown(); httpd.server_close(); thread.join(timeout=3)

    def test_create_tree_source_and_delete(self):
        task = self.create()
        self.assertTrue(self.manager.notified)
        self.assertEqual(len(self.service.tree(task["id"])), 2)
        source = self.service.source(task["id"], "src/main.py")
        self.assertIn("def main", source["content"])
        self.assertIn("tok-keyword", "".join(source["highlighted_lines"]))
        self.assertIn('data-symbol="main"', "".join(source["highlighted_lines"]))
        definition = self.service.definition(task["id"], "src/main.py", "main", 1)
        self.assertTrue(definition["found"])
        self.assertEqual(definition["definition"]["path"], "src/main.py")
        self.assertEqual(definition["definition"]["line"], 1)
        materials = self.service.materials(task["id"])
        self.assertEqual(
            {(item["category"], item["path"]) for item in materials},
            {("domain", "领域规约-结构化.md"), ("domain-source", "rules.md"), ("intent", "intent.txt")},
        )
        self.assertIn("领域规约", self.service.material(task["id"], "domain", "领域规约-结构化.md")["content"])
        with self.assertRaises(ServiceError):
            self.service.material(task["id"], "domain", "../rules.md")
        self.database.update_task(task["id"], status="cancelled")
        self.service.delete(task["id"])
        self.assertIsNone(self.database.get_task(task["id"]))
        self.assertFalse(task_paths(self.settings.tasks_dir, task["id"])["root"].exists())

    def test_rejects_traversal_and_bad_material(self):
        with self.assertRaises(ValueError):
            self.service.create_task(
                name="bad", project_name="bad", source_paths=["../bad.py"],
                sources=[Upload("bad.py", b"pass")], domain_files=[], intent_files=[],
            )
        with self.assertRaises(ServiceError):
            self.service.create_task(
                name="bad", project_name="bad", source_paths=["main.py"],
                sources=[Upload("main.py", b"pass")],
                domain_files=[Upload("binary.pdf", b"pdf")], intent_files=[],
            )

    def test_gb2312_source_and_material_preview(self):
        task = self.service.create_task(
            name="GB2312 示例",
            project_name="legacy",
            source_paths=["main.c"],
            sources=[Upload("main.c", "// 中文注释\nint main(void) { return 0; }\n".encode("gb2312"))],
            domain_files=[Upload("rules.txt", "领域规约：返回零。\n".encode("gb2312"))],
            intent_files=[],
        )
        source = self.service.source(task["id"], "main.c")
        original_domain = task_paths(self.settings.tasks_dir, task["id"])["domain_sources"] / "rules.txt"
        self.assertEqual(decode_text(original_domain.read_bytes())[1], "GB2312")
        self.confirm_domain(task["id"])
        material = self.service.material(task["id"], "domain", "领域规约-结构化.md")
        raw_material = self.service.material(task["id"], "domain-source", "rules.txt")
        self.assertEqual(source["encoding"], "GB2312")
        self.assertIn("中文注释", source["content"])
        self.assertEqual(material["encoding"], "UTF-8")
        self.assertEqual(raw_material["encoding"], "GB2312")
        self.assertIn("领域规约", material["content"])

    def test_design_intent_is_rendered_as_safe_markdown(self):
        markdown = (
            "# 设计意图\n\n请人工核对。\n\n## 功能行为\n\n"
            "- **返回值**必须有效，并使用 `OK`。\n\n"
            "| 字段 | 取值 |\n|---|---|\n| ID | 12 |\n\n"
            "<script>alert(1)</script>\n\n"
            "[危险链接](javascript:alert(1))\n\n"
            "![远程图片](https://example.com/image.png)\n"
        )
        task = self.service.create_task(
            name="Markdown 预览", project_name="preview",
            source_paths=["main.c"], sources=[Upload("main.c", b"int main(void) { return 0; }\n")],
            domain_files=[], intent_files=[
                Upload("intent.md", markdown.encode("utf-8")),
                Upload("notes.md", b"# Notes\n\n**Important**\n"),
            ],
        )
        intent = self.service.material(task["id"], "intent", "intent.md")
        categories = {item["key"]: item for item in intent["categories"]}
        html = categories["functional"]["rendered_html"]
        self.assertIn("<strong>返回值</strong>", html)
        self.assertIn("<code>OK</code>", html)
        self.assertIn("<table", html)
        self.assertIn('data-source-start="7"', html)
        self.assertIn("&lt;script&gt;", html)
        self.assertNotIn("<script", html)
        self.assertNotIn('href="javascript:', html)
        self.assertNotIn("<img", html)
        self.assertIn("请人工核对", categories["introduction"]["rendered_html"])
        notes = self.service.material(task["id"], "intent", "notes.md")
        self.assertEqual(notes["categories"][0]["key"], "unclassified")
        self.assertIn("<strong>Important</strong>", notes["categories"][0]["rendered_html"])

    def test_cross_file_navigation_and_project_content_search(self):
        task = self.service.create_task(
            name="跨文件工程", project_name="search-demo",
            source_paths=["app/main.c", "lib/math.c", "lib/math.h"],
            sources=[
                Upload("main.c", b"int main(void) { return compute(1) + g_count; }\n"),
                Upload("math.c", b"static int compute(int x) { return x + 1; }\nint g_count = 2;\n"),
                Upload("math.h", b"extern int compute(int x);\nextern int g_count;\n"),
            ],
            domain_files=[Upload("rules.md", "# 领域规约\n计算结果必须大于零。\n".encode())],
            intent_files=[Upload("intent.md", "# 设计意图\n\n## 功能行为\n\n- compute 必须返回计算结果。\n".encode())],
        )
        self.confirm_domain(task["id"])
        for name, line in (("compute", 1), ("g_count", 2)):
            target = self.service.definition(task["id"], "app/main.c", name, 1)
            self.assertTrue(target["found"])
            self.assertEqual(target["definition"]["path"], "lib/math.c")
            self.assertEqual(target["definition"]["line"], line)
        source = self.service.source(task["id"], "app/main.c")
        self.assertIn('data-symbol="g_count"', "".join(source["highlighted_lines"]))
        result = self.service.search(task["id"], "compute", whole_word=True)
        self.assertEqual(result["total_matches"], 4)
        self.assertTrue(any(item["category"] == "intent" for item in result["files"]))
        domain = self.service.search(task["id"], "计算结果")
        self.assertEqual({item["category"] for item in domain["files"]}, {"domain", "domain-source", "intent"})
        self.assertEqual(self.service.search(task["id"], "COMPUTE", match_case=True)["total_matches"], 0)
        self.assertGreater(self.service.search(task["id"], r"compute\(1\)", use_regex=True)["total_matches"], 0)
        with self.assertRaises(ServiceError):
            self.service.search(task["id"], "[", use_regex=True)
        intent = self.service.material(task["id"], "intent", "intent.md")
        self.assertEqual(intent["categories"][0]["title"], "功能行为")
        self.assertIn("compute", intent["categories"][0]["content"])

    def test_resume_clears_previous_verification_error_count(self):
        task = self.create()
        self.database.update_task(task["id"], status="failed", verification_error_count=3)
        resumed = self.service.resume(task["id"])
        self.assertEqual(resumed["status"], "queued")
        self.assertEqual(resumed["verification_error_count"], 0)

    def test_requirement_task_waits_for_confirmation_before_queueing(self):
        preprocessor = RequirementPreprocessor(self.settings, self.database)
        service = TaskService(self.settings, self.database, self.manager, preprocessor)
        try:
            task = service.create_task(
                name="需求确认任务",
                project_name="requirement-demo",
                source_paths=["main.c"],
                sources=[Upload("main.c", b"int main(void) { return 0; }\n")],
                domain_files=[],
                intent_files=[],
                requirement_files=[Upload(
                    "SRS.docx",
                    make_docx("当温度达到 120 C 时，必须关闭电机输出。"),
                )],
            )
            self.assertEqual(task["status"], "preprocessing")
            self.assertFalse(self.manager.notified)
            for _ in range(50):
                task = self.database.get_task(task["id"])
                if task["status"] != "preprocessing":
                    break
                time.sleep(0.01)
            self.assertEqual(task["status"], "awaiting_confirmation")
            review = service.requirement_review(task["id"])
            self.assertIn("120 C", review["markdown"])
            self.assertEqual(len(review["categories"]), len(CATEGORIES))
            self.assertEqual(review["documents"][0]["name"], "SRS.docx")
            draft_path = task_paths(self.settings.tasks_dir, task["id"])["requirement_draft"]
            draft_path.write_text(
                review["markdown"].replace("**【Spec-Func-001】** ", "**【1】** ", 1),
                encoding="utf-8",
            )
            review = service.requirement_review(task["id"])
            self.assertIn("【Spec-Func-001】", review["markdown"])
            self.assertNotIn("**【1】**", review["markdown"])
            self.assertIn("<ul", review["categories"][0]["rendered_html"])
            edited = "- **电机输出**必须为 `0`。\n\n<script>alert(1)</script>"
            preview = service.preview_requirement_category(task["id"], edited)["html"]
            self.assertIn("<strong>电机输出</strong>", preview)
            self.assertIn("<code>0</code>", preview)
            self.assertIn("&lt;script&gt;", preview)
            self.assertNotIn("<script", preview)
            self.assertEqual(service.requirement_review(task["id"])["markdown"], review["markdown"])
            with self.assertRaises(ServiceError) as oversized:
                service.preview_requirement_category(task["id"], "x" * (self.settings.max_material_bytes + 1))
            self.assertEqual(oversized.exception.status, 413)
            edited_markdown = review["markdown"].replace(
                "## 功能行为\n\n", "## 功能行为\n\n- 新增人工规则。\n\n", 1
            )
            confirmed = service.confirm_requirements(task["id"], edited_markdown)
            self.assertEqual(confirmed["status"], "queued")
            with self.assertRaises(ServiceError) as not_waiting:
                service.preview_requirement_category(task["id"], edited)
            self.assertEqual(not_waiting.exception.status, 409)
            self.assertTrue(self.manager.notified)
            materials = service.materials(task["id"])
            self.assertTrue(any(
                item["category"] == "intent" and item["path"].endswith("设计意图.md")
                for item in materials
            ))
            intent_name = next(
                item["path"] for item in materials
                if item["category"] == "intent" and item["path"].endswith("设计意图.md")
            )
            confirmed_markdown = service.material(task["id"], "intent", intent_name)["content"]
            self.assertIn("- **【Spec-Func-001】** 新增人工规则。", confirmed_markdown)
            self.assertIn("【Spec-Func-002】", confirmed_markdown)
        finally:
            preprocessor.shutdown()

    def test_requirement_then_domain_confirmation_indexes_new_task_only(self):
        preprocessor = RequirementPreprocessor(self.settings, self.database)
        service = TaskService(self.settings, self.database, self.manager, preprocessor, self.domains)
        try:
            task = service.create_task(
                name="双材料", project_name="both", source_paths=["main.c"],
                sources=[Upload("main.c", b"int main(void) { return 0; }\n")],
                domain_files=[Upload("safety.md", "## 安全不变量与联锁\n- 任何情况下电机输出不得超过 100。\n".encode())],
                intent_files=[], requirement_files=[Upload("SRS.docx", make_docx("温度达到 120 C 时电机输出必须为 0。"))],
            )
            for _ in range(100):
                if self.database.get_task(task["id"])["status"] != "preprocessing":
                    break
                time.sleep(0.01)
            self.assertEqual(self.database.get_task(task["id"])["status"], "awaiting_confirmation")
            next_task = service.confirm_requirements(task["id"], service.requirement_review(task["id"])["markdown"])
            self.assertEqual(next_task["status"], "domain_preprocessing")
            self.assertFalse(self.manager.notified)
            for _ in range(100):
                if self.database.get_task(task["id"])["status"] != "domain_preprocessing":
                    break
                time.sleep(0.01)
            self.assertEqual(self.database.get_task(task["id"])["status"], "awaiting_domain_confirmation")
            review = service.domain_review(task["id"])
            self.assertIn("Spec-Domain-Safety-001", review["markdown"])
            self.assertEqual(review["documents"][0]["name"], "safety.md")
            self.assertEqual(service.confirm_domain(task["id"], review["markdown"])["status"], "queued")
            self.assertTrue(self.manager.notified)
            rules = self.database.list_spec_rules(task["id"])
            self.assertTrue(any(rule["kind"] == "domain" and rule["rule_id"] == "Spec-Domain-Safety-001" for rule in rules))
            self.assertTrue(any(rule["kind"] == "intent" and rule["rule_id"].startswith("Spec-") for rule in rules))
            self.assertEqual((task_paths(self.settings.tasks_dir, task["id"])["domain_sources"] / "safety.md").read_text(),
                             "## 安全不变量与联锁\n- 任何情况下电机输出不得超过 100。\n")
            old = self.database.create_task({"id": "legacy", "name": "old", "project_name": "old", "file_count": 0})
            self.assertEqual(old["trace_enabled"], 0)
        finally:
            preprocessor.shutdown()

    def test_regenerate_can_append_and_replace_requirement_documents(self):
        preprocessor = RequirementPreprocessor(self.settings, self.database)
        service = TaskService(self.settings, self.database, self.manager, preprocessor)
        try:
            task = service.create_task(
                name="需求更新", project_name="docx-demo",
                source_paths=["main.c"], sources=[Upload("main.c", b"int main(void) { return 0; }\n")],
                domain_files=[], intent_files=[],
                requirement_files=[Upload("SRS.docx", make_docx("旧需求：返回 1。"))],
            )
            for _ in range(100):
                if self.database.get_task(task["id"])["status"] == "awaiting_confirmation":
                    break
                time.sleep(0.01)
            updated = service.regenerate_requirements(
                task["id"], [Upload("协议.docx", make_docx("报文必须包含 CRC。"))]
            )
            self.assertEqual(updated["status"], "preprocessing")
            for _ in range(100):
                if self.database.get_task(task["id"])["status"] == "awaiting_confirmation":
                    break
                time.sleep(0.01)
            review = service.requirement_review(task["id"])
            self.assertEqual({item["name"] for item in review["documents"]}, {"SRS.docx", "协议.docx"})
            self.assertIn("CRC", review["markdown"])
            source_path = task_paths(self.settings.tasks_dir, task["id"])["requirement_sources"] / "SRS.docx"
            with self.assertRaises(RequirementError):
                service.regenerate_requirements(task["id"], [Upload("SRS.docx", b"not a word document")])
            self.assertIn("旧需求", extract_docx_text(source_path.read_bytes()))
            service.regenerate_requirements(task["id"], [Upload("SRS.docx", make_docx("新需求：返回 2。"))])
            for _ in range(100):
                if self.database.get_task(task["id"])["status"] == "awaiting_confirmation":
                    break
                time.sleep(0.01)
            self.assertIn("新需求", service.requirement_review(task["id"])["markdown"])
            self.assertNotIn("旧需求", service.requirement_review(task["id"])["markdown"])
        finally:
            preprocessor.shutdown()

    def test_adjusting_intent_creates_traceable_task_and_stops_active_run(self):
        original = self.create()
        revised = self.service.revise_requirements(original["id"])
        self.assertEqual(revised["status"], "awaiting_confirmation")
        self.assertEqual(revised["cloned_from"], original["id"])
        self.assertEqual(self.manager.stopped, [original["id"]])
        review = self.service.requirement_review(revised["id"])
        self.assertIn("设计意图", review["categories"][0]["content"])
        self.assertEqual(len(self.service.tree(revised["id"])), 2)
        self.assertEqual(
            [item["category"] for item in self.service.materials(revised["id"])],
            ["domain", "domain-source"],
        )
        confirmed = self.service.confirm_requirements(revised["id"], review["markdown"])
        self.assertEqual(confirmed["status"], "queued")
        self.assertTrue(any(
            item["category"] == "intent" for item in self.service.materials(revised["id"])
        ))

    def test_issue_persistence_and_reports(self):
        task = self.create()
        issue = self.database.add_issue(
            task["id"],
            {
                "fingerprint": "abc", "source_file": "src/main.py", "function_name": "main",
                "start_line": 1, "end_line": 2,
                "raw": {"spec_claim": "返回正数", "actual_behavior": "返回零"},
            },
        )
        self.database.finish_issue_enrichment(
            issue["id"], description_zh="返回值可能不符合规约。", severity="中",
            confidence=82, suggestion_zh="检查返回值分支。",
            counterexample_zh="触发条件：输入为 0。\n实际结果：返回 0。\n期望结果：返回正数。",
        )
        marked = self.service.toggle_issue_marked(issue["id"])
        self.assertTrue(marked["is_marked"])
        self.assertTrue(self.database.get_issue(issue["id"])["is_marked"])
        generate_chinese_reports(self.database, self.settings.tasks_dir, task["id"])
        reports = task_paths(self.settings.tasks_dir, task["id"])["reports"]
        self.assertIn("返回值可能不符合规约", (reports / "验证报告.md").read_text())
        payload = json.loads((reports / "验证报告.json").read_text())
        self.assertEqual(payload["问题数量"], 1)
        self.assertIn("触发条件", payload["问题"][0]["counterexample_zh"])
        self.assertIn("问题反例", (reports / "验证报告.md").read_text())
        self.assertIn(
            "查看解读前的原始验证报告", (reports / "验证报告.html").read_text()
        )


class ScannerTests(unittest.TestCase):
    def test_legacy_report_does_not_offer_retroactive_trace(self):
        with tempfile.TemporaryDirectory() as directory:
            settings = settings_for(Path(directory))
            database = Database(settings.database_path)
            database.create_task({"id": "legacy", "name": "old", "project_name": "p", "file_count": 1})
            database.add_issue("legacy", {"fingerprint": "x", "source_file": "main.c",
                "function_name": "run", "raw": {"spec_claim": "return 1"}})
            generate_chinese_reports(database, settings.tasks_dir, "legacy")
            html = (task_paths(settings.tasks_dir, "legacy")["reports"] / "验证报告.html").read_text()
            self.assertNotIn("违反的规约与证据", html)

    def test_function_specs_are_atomized_without_editing_fm_agent_sidecar(self):
        with tempfile.TemporaryDirectory() as directory:
            settings = replace(settings_for(Path(directory)), demo_mode=False)
            database = Database(settings.database_path)
            task_id = "new-trace"
            database.create_task({"id": task_id, "name": "trace", "project_name": "p",
                                  "file_count": 1, "trace_enabled": 1})
            paths = task_paths(settings.tasks_dir, task_id)
            source = paths["project"] / "src" / "sample.c"
            extracted = paths["project"] / "fm_agent" / "extracted_functions" / "src" / "sample-c" / "run.c"
            source.parent.mkdir(parents=True); extracted.parent.mkdir(parents=True)
            source.write_text("int run(int x) { return 0; }\n")
            extracted.write_text("int run(int x) { return 0; }")
            spec = Path(f"{extracted}.spec.json")
            original = json.dumps({"signature": "run(int x)", "pre_condition": "x >= 0 and x <= 10",
                                   "post_condition": "result == 1"})
            spec.write_text(original)
            Path(f"{extracted}.info.json").write_text(json.dumps({"callees": []}))
            def fake_model(_model, messages, *, text_only):
                payload = json.loads(messages[1]["content"])
                return json.dumps({
                    "pre": ["x 必须 >= 0", "x 必须 <= 10"] if payload["pre_condition"] else [],
                    "post": ["result 必须等于 1"] if payload["post_condition"] else [],
                }), {}
            indexer = FunctionSpecIndexer(settings, database, TaskManager._source_location)
            try:
                with patch("webapp.spec_trace.run_agent_for_messages", side_effect=fake_model):
                    indexer.scan_task(task_id)
                    indexer.ensure_for_issue(task_id, "src/sample.c", "run")
                rules = database.list_spec_rules(task_id, kind="code", source_file="src/sample.c")
                self.assertEqual(len(rules), 3)
                self.assertFalse(any("原文未拆分" in rule["category"] for rule in rules))
                self.assertEqual([rule["clause_type"] for rule in rules], ["post", "pre", "pre"])
                self.assertTrue(all(rule["source_line"] == 1 for rule in rules))
                self.assertEqual(spec.read_text(), original)
            finally:
                indexer.shutdown()

    def test_trace_requires_registered_id_and_verbatim_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            settings = settings_for(Path(directory))
            database = Database(settings.database_path)
            database.create_task({"id": "trace", "name": "trace", "project_name": "p",
                                  "file_count": 1, "trace_enabled": 1})
            issue = database.add_issue("trace", {"fingerprint": "x", "source_file": "main.c",
                "function_name": "run", "start_line": 1, "end_line": 1,
                "raw": {"spec_claim": "return 1", "actual_behavior": "return 0"}})
            candidates = [
                {"rule_id": "Spec-Func-001", "kind": "intent", "category": "功能行为",
                 "content": "run 必须返回 1", "source_file": "intent.md", "source_line": 3,
                 "function_name": None},
                {"rule_id": "Spec-Domain-Func-001", "kind": "domain", "category": "功能行为",
                 "content": "run 必须返回正数", "source_file": "domain.md", "source_line": 5,
                 "function_name": None},
            ]
            answer = {"description": "返回值不符合要求", "counterexample": "触发条件：调用 run。\n实际结果：0。\n期望结果：1。",
                      "severity": "中", "confidence": 90, "suggestion": "修正返回值",
                      "violated_specs": [
                          {"id": "Spec-Func-001", "evidence_quote": "return 0", "reason": "返回了 0"},
                          {"id": "Spec-Domain-Func-001", "evidence_quote": "并不存在的证据", "reason": "无法证明"},
                          {"id": "Spec-Fake-001", "evidence_quote": "return 0", "reason": "不存在的编号"},
                      ]}
            enricher = IssueEnricher(settings, database, lambda _id, _path: "int run(void) { return 0; }\n",
                                     trace_candidates=lambda _issue: candidates)
            try:
                with patch("webapp.enrichment.run_agent_for_messages", return_value=(json.dumps(answer, ensure_ascii=False), {})):
                    result = enricher._request(database.get_issue(issue["id"]))
                self.assertEqual([rule["rule_id"] for rule in result["violated_specs"]], ["Spec-Func-001"])
                database.finish_issue_enrichment(issue["id"], description_zh=result["description"],
                    counterexample_zh=result["counterexample"], severity=result["severity"],
                    confidence=result["confidence"], suggestion_zh=result["suggestion"],
                    violated_specs=result["violated_specs"])
                self.assertEqual(database.get_issue(issue["id"])["violated_specs"][0]["source_line"], 3)
            finally:
                enricher.executor.shutdown(wait=True)

    def test_tracks_spec_and_verification_progress_per_extracted_function(self):
        with tempfile.TemporaryDirectory() as directory:
            settings = settings_for(Path(directory))
            database = Database(settings.database_path)
            task_id = "00000000-0000-0000-0000-000000000010"
            database.create_task(
                {"id": task_id, "name": "progress", "project_name": "p", "file_count": 1, "source_bytes": 20}
            )
            paths = task_paths(settings.tasks_dir, task_id)
            extracted = paths["project"] / "fm_agent" / "extracted_functions" / "src" / "sample-c"
            output = paths["project"] / "fm_agent" / "logic_verification_results" / "src" / "sample-c"
            extracted.mkdir(parents=True)
            output.mkdir(parents=True)
            ready = extracted / "ready.c"
            waiting = extracted / "waiting.c"
            ready.write_text("int ready(void) { return 1; }")
            waiting.write_text("int waiting(void) { return 0; }")
            Path(f"{ready}.spec.json").write_text(json.dumps({
                "signature": "ready()", "pre_condition": "true", "post_condition": "result == 1",
            }))
            Path(f"{ready}.info.json").write_text(json.dumps({"callees": []}))
            (output / "ready.json").write_text(json.dumps({
                "function": "fm_agent/extracted_functions/src/sample-c/ready.c",
                "verdict": "MATCH", "gaps": None,
            }))

            manager = TaskManager(settings, database)
            task = manager.refresh_progress(task_id)
            self.assertEqual(task["progress_total"], 2)
            self.assertEqual(task["spec_completed"], 1)
            self.assertEqual(task["progress_completed"], 1)
            self.assertEqual(task["progress_source_file"], "src/sample.c")
            self.assertEqual(task["progress_function"], "ready")

    def test_scans_mismatch_without_changing_original_tool(self):
        with tempfile.TemporaryDirectory() as directory:
            settings = settings_for(Path(directory))
            database = Database(settings.database_path)
            task_id = "00000000-0000-0000-0000-000000000001"
            database.create_task(
                {"id": task_id, "name": "scan", "project_name": "p", "file_count": 1, "source_bytes": 20}
            )
            paths = task_paths(settings.tasks_dir, task_id)
            source = paths["project"] / "src" / "sample.py"
            extracted = paths["project"] / "fm_agent" / "extracted_functions" / "src" / "sample-py" / "run.py"
            result = paths["project"] / "fm_agent" / "logic_verification_results" / "src" / "sample-py" / "run.json"
            source.parent.mkdir(parents=True); extracted.parent.mkdir(parents=True); result.parent.mkdir(parents=True)
            source.write_text("def run():\n    return 0\n")
            extracted.write_text("def run():\n    return 0")
            result.write_text(json.dumps({
                "function": str(extracted), "verdict": "MISMATCH",
                "gaps": {"spec_claim": "return 1", "actual_behavior": "return 0", "code_evidence": "return 0", "trigger_condition": "always"},
            }))
            manager = TaskManager(settings, database)
            submitted = []
            manager.enricher.submit = submitted.append
            manager._scan_results(task_id)
            issues = database.list_issues(task_id)
            self.assertEqual(len(issues), 1)
            self.assertEqual(issues[0]["source_file"], "src/sample.py")
            self.assertEqual(issues[0]["start_line"], 1)
            self.assertEqual(submitted, [issues[0]["id"]])


class RunnerIntegrationTests(unittest.TestCase):
    def test_partial_results_without_final_report_are_completed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            app_root = root / "app"
            (app_root / "bin").mkdir(parents=True)
            launcher = app_root / "bin" / "fm-agent"
            launcher.write_text("#!/bin/sh\necho '[Pipeline] Stage 6/6: verify'\nexit 1\n")
            launcher.chmod(0o755)
            settings = replace(settings_for(root / "data"), app_root=app_root, demo_mode=False)
            database = Database(settings.database_path)
            task_id = "00000000-0000-0000-0000-000000000033"
            database.create_task({
                "id": task_id, "name": "partial-without-report", "project_name": "p",
                "file_count": 1, "source_bytes": 20,
            })
            paths = task_paths(settings.tasks_dir, task_id)
            output = paths["project"] / "fm_agent" / "logic_verification_results" / "src" / "sample-c"
            output.mkdir(parents=True)
            (output / "ready.json").write_text(json.dumps({"verdict": "MATCH"}))
            (output / "failed.json").write_text(json.dumps({"verdict": "ERROR"}))
            manager = TaskManager(settings, database)
            manager._run_task(task_id)
            task = database.get_task(task_id)
            self.assertEqual(task["status"], "completed")
            self.assertEqual(task["verification_error_count"], 1)

    def test_partial_stage_six_results_are_completed_with_error_count(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            app_root = root / "app"
            (app_root / "bin").mkdir(parents=True)
            launcher = app_root / "bin" / "fm-agent"
            launcher.write_text("#!/bin/sh\necho '[Pipeline] Stage 6/6: verify'\nexit 1\n")
            launcher.chmod(0o755)
            settings = replace(settings_for(root / "data"), app_root=app_root, demo_mode=False)
            database = Database(settings.database_path)
            task_id = "00000000-0000-0000-0000-000000000031"
            database.create_task({
                "id": task_id, "name": "partial", "project_name": "p",
                "file_count": 1, "source_bytes": 20,
            })
            paths = task_paths(settings.tasks_dir, task_id)
            extracted = paths["project"] / "fm_agent" / "extracted_functions" / "src" / "sample-c"
            output = paths["project"] / "fm_agent" / "logic_verification_results" / "src" / "sample-c"
            extracted.mkdir(parents=True)
            output.mkdir(parents=True)
            ready = extracted / "ready.c"
            ready.write_text("int ready(void) { return 1; }")
            Path(f"{ready}.spec.json").write_text(json.dumps({
                "signature": "ready()", "pre_condition": "true", "post_condition": "result == 1",
            }))
            Path(f"{ready}.info.json").write_text(json.dumps({"callees": []}))
            (output / "ready.json").write_text(json.dumps({"verdict": "MATCH"}))
            (output / "failed.json").write_text(json.dumps({"verdict": "ERROR", "error": "model timeout"}))
            report = paths["project"] / "fm_agent" / "VERIFICATION-REPORT.json"
            report.write_text(json.dumps({
                "status": "partial", "counts": {"MATCH": 1, "MISMATCH": 0, "ERROR": 1, "MISSING": 0},
            }))
            manager = TaskManager(settings, database)
            manager._run_task(task_id)
            task = database.get_task(task_id)
            self.assertEqual(task["status"], "completed")
            self.assertEqual(task["phase"], "验证完成")
            self.assertEqual(task["verification_error_count"], 1)
            self.assertEqual(task["exit_code"], 1)
            self.assertIn("验证错误：1", (paths["reports"] / "验证报告.md").read_text())

    def test_stage_six_without_usable_results_still_fails(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            app_root = root / "app"
            (app_root / "bin").mkdir(parents=True)
            launcher = app_root / "bin" / "fm-agent"
            launcher.write_text("#!/bin/sh\necho '[Pipeline] Stage 6/6: verify'\nexit 1\n")
            launcher.chmod(0o755)
            settings = replace(settings_for(root / "data"), app_root=app_root, demo_mode=False)
            database = Database(settings.database_path)
            task_id = "00000000-0000-0000-0000-000000000032"
            database.create_task({
                "id": task_id, "name": "failed", "project_name": "p",
                "file_count": 1, "source_bytes": 20,
            })
            task_paths(settings.tasks_dir, task_id)["project"].mkdir(parents=True)
            manager = TaskManager(settings, database)
            manager._run_task(task_id)
            self.assertEqual(database.get_task(task_id)["status"], "failed")

    def test_original_cli_adapter_uses_expected_flags_and_materials(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            app_root = root / "app"
            (app_root / "bin").mkdir(parents=True)
            launcher = app_root / "bin" / "fm-agent"
            launcher.write_text(
                "#!/bin/sh\n"
                "project=$1\n"
                "printf '%s\\n' \"$@\" > \"$project/received-args.txt\"\n"
                "mkdir -p \"$project/fm_agent\"\n"
                "printf '{\"status\":\"complete\",\"results\":[]}' > \"$project/fm_agent/VERIFICATION-REPORT.json\"\n"
                "echo '[Pipeline] Stage 6/6: Generating specs & verification...'\n"
                "echo '[1/1] src/main.py: MATCH'\n"
            )
            launcher.chmod(0o755)
            settings = replace(
                settings_for(root / "data"), app_root=app_root, scan_interval_s=0.2,
                demo_mode=False,
            )
            database = Database(settings.database_path)
            task_id = "00000000-0000-0000-0000-000000000002"
            database.create_task(
                {"id": task_id, "name": "run", "project_name": "p", "file_count": 1, "source_bytes": 20}
            )
            paths = task_paths(settings.tasks_dir, task_id)
            paths["project"].mkdir(parents=True)
            material = paths["materials"] / "domain" / "rules.md"
            material.parent.mkdir(parents=True)
            material.write_text("# rules")
            manager = TaskManager(settings, database)
            manager._run_task(task_id)
            task = database.get_task(task_id)
            self.assertEqual(task["stage_number"], 6)
            args = (paths["project"] / "received-args.txt").read_text().splitlines()
            self.assertEqual(task["status"], "completed")
            self.assertIn("--all-bugs", args)
            self.assertIn("--one-phase", args)
            self.assertIn("--domain-knowledge", args)
            self.assertIn(str(material), args)


if __name__ == "__main__":
    unittest.main()

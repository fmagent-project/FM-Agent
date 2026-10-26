from __future__ import annotations

import json
import os
import re
import shutil
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from .config import Settings
from .database import Database, TERMINAL_STATUSES
from .markdown_preview import render_markdown_preview
from .requirements import (
    compose_design_intent,
    extract_docx_text,
    number_design_intent_rules,
    parse_design_intent_categories,
    number_categorized_rules,
)
from .runner import TaskManager
from .spec_trace import material_rules, number_uploaded_intent
from .source_navigation import IDENTIFIER, find_symbol_definition, highlight_source_lines
from .utils import (
    SOURCE_EXTENSIONS,
    atomic_write_json,
    decode_text,
    detect_text_encoding,
    is_probably_text,
    safe_leaf_name,
    safe_relative_path,
    task_paths,
)


@dataclass
class Upload:
    name: str
    data: bytes


class ServiceError(RuntimeError):
    def __init__(self, message: str, status: int = 400):
        super().__init__(message)
        self.status = status


class TaskService:
    def __init__(
        self,
        settings: Settings,
        database: Database,
        manager: TaskManager,
        requirement_preprocessor=None,
        domain_preprocessor=None,
    ):
        self.settings = settings
        self.database = database
        self.manager = manager
        self.requirement_preprocessor = requirement_preprocessor
        self.domain_preprocessor = domain_preprocessor

    def create_task(
        self,
        *,
        name: str,
        project_name: str,
        source_paths: list[str],
        sources: list[Upload],
        domain_files: list[Upload],
        intent_files: list[Upload],
        requirement_files: list[Upload] | None = None,
    ) -> dict:
        requirement_files = list(requirement_files or [])
        if not isinstance(source_paths, list) or not all(
            isinstance(path, str) for path in source_paths
        ):
            raise ServiceError("源码路径清单格式不正确")
        if not sources:
            raise ServiceError("请至少选择一个源码文件")
        if len(sources) != len(source_paths):
            raise ServiceError("上传文件与目录清单不一致")
        if len(sources) > self.settings.max_project_files:
            raise ServiceError(f"单个工程最多上传 {self.settings.max_project_files} 个文件")
        total_bytes = sum(len(item.data) for item in sources)
        if total_bytes > self.settings.max_project_bytes:
            raise ServiceError(
                f"源码总体积不能超过 {self.settings.max_project_bytes // 1024 // 1024}MB"
            )
        all_materials = domain_files + intent_files
        if len(domain_files) > self.settings.max_material_files or len(intent_files) > self.settings.max_material_files:
            raise ServiceError(f"每类验证材料最多 {self.settings.max_material_files} 个文件")
        if sum(len(item.data) for item in all_materials) > self.settings.max_material_bytes * 2:
            raise ServiceError("验证材料总体积超过配置限制")
        if sum(len(item.data) for item in domain_files) > self.settings.max_material_bytes:
            raise ServiceError("领域规约总大小超过配置限制")
        for item in all_materials:
            if Path(item.name).suffix.lower() not in {".md", ".txt"}:
                raise ServiceError(f"验证材料仅支持 Markdown/TXT：{item.name}")
            if len(item.data) > self.settings.max_material_bytes:
                raise ServiceError(f"验证材料文件过大：{item.name}")
            if not is_probably_text(item.data):
                raise ServiceError(f"验证材料不是可读取的文本文件：{item.name}")
        if len(requirement_files) > self.settings.max_requirement_files:
            raise ServiceError(
                f"需求文档最多上传 {self.settings.max_requirement_files} 个文件"
            )
        if sum(len(item.data) for item in requirement_files) > self.settings.max_requirement_bytes:
            raise ServiceError(
                f"需求文档总大小不能超过 {self.settings.max_requirement_bytes // 1024 // 1024}MB"
            )
        for item in requirement_files:
            if Path(item.name).suffix.lower() != ".docx":
                raise ServiceError(f"需求文档首版仅支持 DOCX：{item.name}")

        normalized_paths = [safe_relative_path(path) for path in source_paths]
        if len(set(normalized_paths)) != len(normalized_paths):
            raise ServiceError("源码目录中包含重复路径")
        if any(path == "fm_agent" or path.startswith("fm_agent/") for path in normalized_paths):
            raise ServiceError("fm_agent/ 是验证工具保留目录，请在上传前取消选择该目录中的文件")
        source_items = [
            upload
            for relative, upload in zip(normalized_paths, sources)
            if Path(relative).suffix.lower() in SOURCE_EXTENSIONS
        ]
        if not source_items:
            raise ServiceError("所选目录中没有当前工具支持的源码文件")
        task_id = str(uuid.uuid4())
        paths = task_paths(self.settings.tasks_dir, task_id)
        paths["root"].mkdir(parents=True)
        try:
            manifest = []
            for relative, upload in zip(normalized_paths, sources):
                destination = paths["project"] / relative
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_bytes(upload.data)
                manifest.append(
                    {
                        "path": relative,
                        "size": len(upload.data),
                        "is_source": destination.suffix.lower() in SOURCE_EXTENSIONS,
                        "is_text": is_probably_text(upload.data),
                        "encoding": detect_text_encoding(upload.data),
                    }
                )
            self._write_materials(paths["domain_sources"], domain_files)
            self._write_materials(paths["intent_sources"], intent_files)
            self._prepare_uploaded_intent(paths)
            self._write_materials(paths["requirement_sources"], requirement_files)
            atomic_write_json(paths["manifest"], {"files": manifest})
            project = safe_leaf_name(project_name, "未命名工程")
            task_name = "".join(
                character for character in str(name or "").strip() if ord(character) >= 32
            )[:160] or project
            task = self.database.create_task(
                {
                    "id": task_id,
                    "name": task_name,
                    "project_name": project,
                    "file_count": len(manifest),
                    "source_bytes": total_bytes,
                    "trace_enabled": 1,
                    **(
                        {"status": "preprocessing", "phase": "需求预处理"}
                        if requirement_files
                        else {"status": "domain_preprocessing", "phase": "领域规约整理"}
                        if domain_files else {}
                    ),
                }
            )
        except Exception:
            shutil.rmtree(paths["root"], ignore_errors=True)
            raise
        if requirement_files:
            if self.requirement_preprocessor is None:
                self.database.update_task(
                    task_id,
                    status="preprocess_failed",
                    phase="需求预处理失败",
                    error="需求预处理服务未初始化",
                )
            else:
                self.requirement_preprocessor.submit(task_id)
        elif domain_files:
            if self.domain_preprocessor is None:
                self.database.update_task(task_id, status="domain_preprocess_failed",
                                          phase="领域规约整理失败", error="领域规约整理服务未初始化")
            else:
                self.domain_preprocessor.submit(task_id)
        else:
            self._index_materials(task_id, "intent")
            self.manager.notify()
        return task

    @staticmethod
    def _write_materials(directory: Path, uploads: Iterable[Upload]) -> None:
        used: set[str] = set()
        for index, upload in enumerate(uploads, 1):
            name = safe_leaf_name(upload.name, f"material-{index}.txt")
            stem, suffix = Path(name).stem, Path(name).suffix
            candidate = name
            serial = 2
            while candidate.lower() in used:
                candidate = f"{stem}-{serial}{suffix}"
                serial += 1
            used.add(candidate.lower())
            directory.mkdir(parents=True, exist_ok=True)
            (directory / candidate).write_bytes(upload.data)

    @staticmethod
    def _prepare_uploaded_intent(paths: dict[str, Path]) -> None:
        originals = paths["intent_sources"]
        if not originals.is_dir():
            return
        output = paths["materials"] / "intent"
        output.mkdir(parents=True, exist_ok=True)
        for path in sorted(originals.iterdir()):
            if not path.is_file():
                continue
            content, _encoding = decode_text(path.read_bytes())
            (output / path.name).write_text(number_uploaded_intent(content, path.name), encoding="utf-8")

    def get_detail(self, task_id: str) -> dict:
        task = self.database.get_task(task_id)
        if not task:
            raise ServiceError("任务不存在", 404)
        refresh_progress = getattr(self.manager, "refresh_progress", None)
        if callable(refresh_progress):
            task = refresh_progress(task_id) or task
        task["issues"] = self.database.list_issues(task_id)
        task["reports"] = self.report_availability(task_id)
        task["last_event_id"] = self.database.last_event_id(task_id)
        task["can_revise_intent"] = self._has_design_intent(task_id)
        paths = task_paths(self.settings.tasks_dir, task_id)
        task["has_requirement_docs"] = paths["requirement_sources"].is_dir() and any(
            path.is_file() for path in paths["requirement_sources"].iterdir())
        task["has_domain_docs"] = paths["domain_sources"].is_dir() and any(
            path.is_file() for path in paths["domain_sources"].iterdir())
        return task

    def _has_design_intent(self, task_id: str) -> bool:
        paths = task_paths(self.settings.tasks_dir, task_id)
        try:
            if paths["requirement_draft"].read_text(encoding="utf-8").strip():
                return True
        except OSError:
            pass
        directory = paths["materials"] / "intent"
        return directory.is_dir() and any(
            item.is_file() and item.suffix.lower() in {".md", ".txt"}
            for item in directory.iterdir()
        )

    def tree(self, task_id: str) -> list[dict]:
        task = self.database.get_task(task_id)
        if not task:
            raise ServiceError("任务不存在", 404)
        manifest = task_paths(self.settings.tasks_dir, task_id)["manifest"]
        try:
            value = json.loads(manifest.read_text(encoding="utf-8"))
            return value.get("files") or []
        except (OSError, ValueError, AttributeError):
            return []

    def materials(self, task_id: str) -> list[dict]:
        if not self.database.get_task(task_id):
            raise ServiceError("任务不存在", 404)
        root = task_paths(self.settings.tasks_dir, task_id)["materials"]
        categories = (("domain", "领域规约"), ("domain-source", "领域规约"), ("intent", "设计意图"))
        result = []
        for category, folder_name in categories:
            directory = (task_paths(self.settings.tasks_dir, task_id)["domain_sources"]
                         if category == "domain-source" else root / category)
            if not directory.is_dir():
                continue
            for path in sorted(directory.iterdir(), key=lambda item: item.name.lower()):
                if path.is_file() and path.suffix.lower() in {".md", ".txt"}:
                    result.append(
                        {
                            "kind": "material",
                            "category": category,
                            "folder_name": folder_name,
                            "path": path.name,
                            "display_name": f"原始 · {path.name}" if category == "domain-source" else path.name,
                            "size": path.stat().st_size,
                            "is_text": True,
                            "is_source": False,
                            "encoding": detect_text_encoding(path.read_bytes()),
                        }
                    )
        return result

    def material(self, task_id: str, category: str, name: str) -> dict:
        if not self.database.get_task(task_id):
            raise ServiceError("任务不存在", 404)
        folder_names = {"domain": "领域规约", "domain-source": "领域规约", "intent": "设计意图"}
        if category not in folder_names:
            raise ServiceError("验证材料类型不存在", 404)
        try:
            normalized = safe_relative_path(name)
        except ValueError as exc:
            raise ServiceError(str(exc), 400) from exc
        if "/" in normalized:
            raise ServiceError("验证材料名称不正确", 400)
        paths = task_paths(self.settings.tasks_dir, task_id)
        path = ((paths["domain_sources"] if category == "domain-source"
                 else paths["materials"] / category) / normalized)
        if not path.is_file() or path.suffix.lower() not in {".md", ".txt"}:
            raise ServiceError("验证材料不存在", 404)
        data = path.read_bytes()
        if not is_probably_text(data):
            raise ServiceError("该验证材料不是可预览的文本文件", 415)
        content, encoding = decode_text(data)
        result = {
            "path": normalized,
            "display_path": f"{folder_names[category]}/{('原始 · ' if category == 'domain-source' else '')}{normalized}",
            "content": content,
            "encoding": encoding,
            "size": len(data),
        }
        if category in {"intent", "domain", "domain-source"}:
            lines = content.replace("\r\n", "\n").split("\n")
            categories = [
                item for item in parse_design_intent_categories(content)
                if item["start_line"] is not None
            ]
            if categories:
                first_heading = min(item["start_line"] for item in categories)
                introduction = "\n".join(lines[:first_heading - 1])
                if introduction.strip():
                    categories.append({
                        "key": "introduction", "title": "文档说明",
                        "description": "分类条款之前的原始说明。",
                        "content": introduction, "start_line": 0,
                        "content_start_line": 1, "end_line": first_heading - 1,
                    })
            else:
                categories = [{
                    "key": "unclassified", "title": "未分类内容",
                    "description": "此文件没有分类标题，按 Markdown 原文渲染。",
                    "content": content, "start_line": 0,
                    "content_start_line": 1, "end_line": len(lines),
                }]
            for item in categories:
                start = item["content_start_line"]
                end = item["end_line"]
                item["rendered_html"] = render_markdown_preview(
                    "\n".join(lines[start - 1:end]), start
                )
            result["categories"] = categories
        return result

    def requirement_review(self, task_id: str) -> dict:
        return self._material_review(task_id, domain=False)

    def domain_review(self, task_id: str) -> dict:
        return self._material_review(task_id, domain=True)

    def _material_review(self, task_id: str, *, domain: bool) -> dict:
        task = self.database.get_task(task_id)
        if not task:
            raise ServiceError("任务不存在", 404)
        paths = task_paths(self.settings.tasks_dir, task_id)
        documents = []
        model = self.settings.enrich_model
        meta_path = paths["domain_meta"] if domain else paths["requirement_meta"]
        source_dir = paths["domain_sources"] if domain else paths["requirement_sources"]
        draft_path = paths["domain_draft"] if domain else paths["requirement_draft"]
        try:
            metadata = json.loads(meta_path.read_text(encoding="utf-8"))
            documents = metadata.get("documents") or []
            model = metadata.get("model") or model
        except (OSError, ValueError, AttributeError):
            if source_dir.is_dir():
                documents = [{"name": path.name} for path in sorted(source_dir.iterdir()) if path.is_file()]
        try:
            markdown = draft_path.read_text(encoding="utf-8")
        except OSError:
            markdown = ""
        markdown = number_categorized_rules(markdown, namespace="Domain") if domain else number_design_intent_rules(markdown)
        categories = parse_design_intent_categories(markdown)
        for category in categories:
            category["rendered_html"] = render_markdown_preview(category["content"])
        return {
            "status": task["status"],
            "phase": task["phase"],
            "error": task.get("error"),
            "markdown": markdown,
            "categories": categories,
            "documents": documents,
            "model": model,
            "kind": "domain" if domain else "intent",
        }

    def preview_requirement_category(
        self, task_id: str, content: str, category_key: str | None = None,
        *, domain: bool = False,
    ) -> dict:
        task = self.database.get_task(task_id)
        if not task:
            raise ServiceError("任务不存在", 404)
        expected = "awaiting_domain_confirmation" if domain else "awaiting_confirmation"
        label = "领域规约" if domain else "设计意图"
        if task["status"] != expected:
            raise ServiceError(f"当前任务没有等待确认的{label}", 409)
        if len(content.encode("utf-8")) > self.settings.max_material_bytes:
            raise ServiceError(f"{label}预览内容超过验证材料大小限制", 413)
        if category_key:
            numbered = number_categorized_rules(content, namespace="Domain") if domain else number_design_intent_rules(content)
            categories = parse_design_intent_categories(numbered)
            for category in categories:
                category["rendered_html"] = render_markdown_preview(category["content"])
            selected = next((item for item in categories if item["key"] == category_key), None)
            if selected is None:
                raise ServiceError("设计意图类别不存在")
            return {"html": selected["rendered_html"], "categories": categories}
        return {"html": render_markdown_preview(content)}

    def confirm_requirements(self, task_id: str, markdown: str) -> dict:
        task = self.database.get_task(task_id)
        if not task:
            raise ServiceError("任务不存在", 404)
        if task["status"] != "awaiting_confirmation":
            raise ServiceError("当前任务没有等待确认的设计意图", 409)
        content = number_design_intent_rules(str(markdown or "").strip())
        if not content:
            raise ServiceError("设计意图不能为空")
        encoded = (content + "\n").encode("utf-8")
        if len(encoded) > self.settings.max_material_bytes:
            raise ServiceError("确认后的设计意图超过验证材料大小限制", 413)
        directory = task_paths(self.settings.tasks_dir, task_id)["materials"] / "intent"
        directory.mkdir(parents=True, exist_ok=True)
        task_paths(self.settings.tasks_dir, task_id)["requirement_draft"].write_bytes(encoded)
        name = "需求文档整理-设计意图.md"
        candidate = directory / name
        serial = 2
        while candidate.exists():
            candidate = directory / f"需求文档整理-设计意图-{serial}.md"
            serial += 1
        candidate.write_bytes(encoded)
        self._index_materials(task_id, "intent")
        domain_sources = task_paths(self.settings.tasks_dir, task_id)["domain_sources"]
        confirmed_domain = task_paths(self.settings.tasks_dir, task_id)["materials"] / "domain"
        needs_domain = (domain_sources.is_dir() and any(path.is_file() for path in domain_sources.iterdir())
                        and not (confirmed_domain.is_dir() and any(path.is_file() for path in confirmed_domain.iterdir())))
        updated = self.database.update_task(
            task_id,
            status="domain_preprocessing" if needs_domain else "queued",
            phase="领域规约整理" if needs_domain else "等待执行",
            stage_number=0,
            error=None,
        )
        if needs_domain:
            if self.domain_preprocessor is None:
                updated = self.database.update_task(task_id, status="domain_preprocess_failed",
                                                    phase="领域规约整理失败", error="领域规约整理服务未初始化")
            else:
                self.domain_preprocessor.submit(task_id)
        else:
            self._index_materials(task_id, "domain")
            self.manager.notify()
        return updated

    def confirm_domain(self, task_id: str, markdown: str) -> dict:
        task = self.database.get_task(task_id)
        if not task:
            raise ServiceError("任务不存在", 404)
        if task["status"] != "awaiting_domain_confirmation":
            raise ServiceError("当前任务没有等待确认的领域规约", 409)
        content = number_categorized_rules(str(markdown or "").strip(), namespace="Domain")
        if not content:
            raise ServiceError("领域规约不能为空")
        encoded = (content + "\n").encode("utf-8")
        if len(encoded) > self.settings.max_material_bytes:
            raise ServiceError("确认后的领域规约超过验证材料大小限制", 413)
        paths = task_paths(self.settings.tasks_dir, task_id)
        paths["domain_draft"].write_bytes(encoded)
        directory = paths["materials"] / "domain"
        directory.mkdir(parents=True, exist_ok=True)
        (directory / "领域规约-结构化.md").write_bytes(encoded)
        self._index_materials(task_id, "domain")
        self._index_materials(task_id, "intent")
        updated = self.database.update_task(task_id, status="queued", phase="等待执行",
                                            stage_number=0, error=None)
        self.manager.notify()
        return updated

    def _index_materials(self, task_id: str, category: str) -> None:
        directory = task_paths(self.settings.tasks_dir, task_id)["materials"] / category
        if not directory.is_dir():
            return
        for path in sorted(directory.iterdir()):
            if not path.is_file() or path.suffix.lower() not in {".md", ".txt"}:
                continue
            content, _encoding = decode_text(path.read_bytes())
            rules = material_rules(content, task_id=task_id, kind=category, filename=path.name)
            self.database.replace_spec_rules(task_id, f"{category}:{path.name}", rules)

    def regenerate_domain(self, task_id: str, new_files: list[Upload] | None = None) -> dict:
        task = self.database.get_task(task_id)
        if not task:
            raise ServiceError("任务不存在", 404)
        if task["status"] not in {"awaiting_domain_confirmation", "domain_preprocess_failed"}:
            raise ServiceError("当前任务不能重新整理领域规约", 409)
        if self.domain_preprocessor is None:
            raise ServiceError("领域规约整理服务未初始化", 500)
        source_dir = task_paths(self.settings.tasks_dir, task_id)["domain_sources"]
        existing = {path.name.casefold(): path for path in source_dir.iterdir() if path.is_file()} if source_dir.is_dir() else {}
        incoming = {}
        for upload in new_files or []:
            name = safe_leaf_name(upload.name, "领域规约.md")
            if Path(name).suffix.lower() not in {".md", ".txt"} or not is_probably_text(upload.data):
                raise ServiceError(f"领域规约仅支持可读的 Markdown/TXT：{name}")
            if len(upload.data) > self.settings.max_material_bytes:
                raise ServiceError(f"领域规约文件过大：{name}", 413)
            incoming[name.casefold()] = (existing.get(name.casefold(), source_dir / name), upload.data)
        if not incoming and not existing:
            raise ServiceError("请至少上传一个领域规约文件")
        if len(existing.keys() | incoming.keys()) > self.settings.max_material_files:
            raise ServiceError("领域规约文件数超过配置限制", 413)
        total = sum(len(incoming[key][1]) if key in incoming else path.stat().st_size
                    for key, path in existing.items()) + sum(len(data) for key, (_path, data) in incoming.items() if key not in existing)
        if total > self.settings.max_material_bytes:
            raise ServiceError("领域规约文件总大小超过配置限制", 413)
        source_dir.mkdir(parents=True, exist_ok=True)
        for path, data in incoming.values():
            temporary = path.with_suffix(path.suffix + ".uploading")
            try:
                temporary.write_bytes(data)
                os.replace(temporary, path)
            finally:
                temporary.unlink(missing_ok=True)
        updated = self.database.update_task(task_id, status="domain_preprocessing",
                                            phase="领域规约整理", error=None)
        self.domain_preprocessor.submit(task_id)
        return updated

    def regenerate_requirements(self, task_id: str, new_files: list[Upload] | None = None) -> dict:
        task = self.database.get_task(task_id)
        if not task:
            raise ServiceError("任务不存在", 404)
        if task["status"] not in {"awaiting_confirmation", "preprocess_failed"}:
            raise ServiceError("当前任务不能重新生成设计意图", 409)
        if self.requirement_preprocessor is None:
            raise ServiceError("需求预处理服务未初始化", 500)
        source_dir = task_paths(self.settings.tasks_dir, task_id)["requirement_sources"]
        existing = {
            path.name.casefold(): path for path in source_dir.iterdir()
            if path.is_file() and path.suffix.lower() == ".docx"
        } if source_dir.is_dir() else {}
        incoming: dict[str, tuple[Path, bytes]] = {}
        for upload in new_files or []:
            name = safe_leaf_name(upload.name, "需求文档.docx")
            if Path(name).suffix.lower() != ".docx":
                raise ServiceError(f"需求文档仅支持 DOCX：{name}")
            key = name.casefold()
            if key in incoming:
                raise ServiceError(f"本次上传包含重复的需求文档名称：{name}")
            extract_docx_text(upload.data, name)
            incoming[key] = (existing.get(key, source_dir / name), upload.data)
        if not incoming and not existing:
            raise ServiceError("请先上传至少一份 DOCX 需求文档")
        if len(existing.keys() | incoming.keys()) > self.settings.max_requirement_files:
            raise ServiceError(f"需求文档最多上传 {self.settings.max_requirement_files} 个")
        total_bytes = sum(
            len(incoming[key][1]) if key in incoming else path.stat().st_size
            for key, path in existing.items()
        ) + sum(len(data) for key, (_path, data) in incoming.items() if key not in existing)
        if total_bytes > self.settings.max_requirement_bytes:
            raise ServiceError("需求文档总大小超过配置限制", 413)
        source_dir.mkdir(parents=True, exist_ok=True)
        for path, data in incoming.values():
            temporary = path.with_suffix(path.suffix + ".uploading")
            try:
                temporary.write_bytes(data)
                os.replace(temporary, path)
            finally:
                temporary.unlink(missing_ok=True)
        updated = self.database.update_task(
            task_id,
            status="preprocessing",
            phase="需求预处理",
            error=None,
        )
        self.requirement_preprocessor.submit(task_id)
        return updated

    def revise_requirements(self, task_id: str) -> dict:
        """Create an editable successor and stop the original validation if active."""
        original = self.database.get_task(task_id)
        if not original:
            raise ServiceError("任务不存在", 404)
        if original["status"] in {"preprocessing", "awaiting_confirmation", "preprocess_failed",
                                  "domain_preprocessing", "awaiting_domain_confirmation", "domain_preprocess_failed"}:
            raise ServiceError("当前任务已经处于需求调整阶段", 409)
        source = task_paths(self.settings.tasks_dir, task_id)
        markdown = self._current_design_intent(source)
        if not markdown:
            raise ServiceError("当前任务没有可调整的设计意图", 409)

        new_id = str(uuid.uuid4())
        target = task_paths(self.settings.tasks_dir, new_id)
        try:
            shutil.copytree(
                source["project"],
                target["project"],
                ignore=shutil.ignore_patterns("fm_agent"),
            )
            target["root"].mkdir(parents=True, exist_ok=True)
            shutil.copy2(source["manifest"], target["manifest"])
            domain = source["materials"] / "domain"
            if domain.is_dir():
                shutil.copytree(domain, target["materials"] / "domain")
            if source["requirement_sources"].is_dir():
                shutil.copytree(source["requirement_sources"], target["requirement_sources"])
            if source["domain_sources"].is_dir():
                shutil.copytree(source["domain_sources"], target["domain_sources"])
            if source["intent_sources"].is_dir():
                shutil.copytree(source["intent_sources"], target["intent_sources"])
            if source["domain_meta"].is_file():
                target["requirements"].mkdir(parents=True, exist_ok=True)
                shutil.copy2(source["domain_meta"], target["domain_meta"])
            if source["requirement_meta"].is_file():
                target["requirements"].mkdir(parents=True, exist_ok=True)
                shutil.copy2(source["requirement_meta"], target["requirement_meta"])
            target["requirements"].mkdir(parents=True, exist_ok=True)
            target["requirement_draft"].write_text(markdown, encoding="utf-8")
            task = self.database.create_task(
                {
                    "id": new_id,
                    "name": f"{original['name'][:145]} · 调整设计意图",
                    "project_name": original["project_name"],
                    "status": "awaiting_confirmation",
                    "phase": "调整设计意图",
                    "file_count": original["file_count"],
                    "source_bytes": original["source_bytes"],
                    "cloned_from": task_id,
                    "trace_enabled": 1,
                }
            )
        except Exception:
            shutil.rmtree(target["root"], ignore_errors=True)
            raise
        if original["status"] in {"queued", "running", "cancelling"}:
            self.manager.stop_task(task_id)
        self._index_materials(new_id, "domain")
        return task

    @staticmethod
    def _current_design_intent(paths: dict[str, Path]) -> str:
        try:
            markdown = paths["requirement_draft"].read_text(encoding="utf-8").strip()
            if markdown:
                return markdown + "\n"
        except OSError:
            pass
        directory = paths["materials"] / "intent"
        materials: list[tuple[str, str]] = []
        if directory.is_dir():
            for path in sorted(directory.iterdir(), key=lambda item: item.name.lower()):
                if not path.is_file() or path.suffix.lower() not in {".md", ".txt"}:
                    continue
                try:
                    content, _encoding = decode_text(path.read_bytes())
                except (OSError, UnicodeDecodeError):
                    continue
                if content.strip():
                    materials.append((path.name, content.strip()))
        if not materials:
            return ""
        combined = "\n\n".join(f"### 来源材料：{name}\n\n{content}" for name, content in materials)
        categories = parse_design_intent_categories(combined)
        if not any(category["content"] for category in categories):
            categories[0]["content"] = combined
        return compose_design_intent(categories)

    def source(self, task_id: str, relative: str) -> dict:
        normalized = safe_relative_path(relative)
        files = {entry["path"]: entry for entry in self.tree(task_id)}
        if normalized not in files:
            raise ServiceError("文件不在该任务的上传清单中", 404)
        if not files[normalized].get("is_text"):
            raise ServiceError("该文件不是可预览的文本文件", 415)
        try:
            content = self.manager.load_source(task_id, normalized)
        except FileNotFoundError as exc:
            raise ServiceError("源码文件不存在", 404) from exc
        encoding = files[normalized].get("encoding")
        if not encoding:
            source_path = task_paths(self.settings.tasks_dir, task_id)["project"] / normalized
            try:
                encoding = detect_text_encoding(source_path.read_bytes()) or "未知编码"
            except OSError:
                encoding = "未知编码"
        return {
            "path": normalized,
            "content": content,
            "encoding": encoding,
            "size": files[normalized]["size"],
            "highlighted_lines": highlight_source_lines(content, normalized),
            "function_specs": self.database.list_spec_rules(task_id, kind="code", source_file=normalized),
        }

    def definition(
        self, task_id: str, relative: str, symbol: str, line: int = 1
    ) -> dict:
        try:
            normalized = safe_relative_path(relative)
        except ValueError as exc:
            raise ServiceError(str(exc), 400) from exc
        if not IDENTIFIER.fullmatch(symbol) or len(symbol) > 128:
            raise ServiceError("符号名称不正确", 400)
        entries = {
            entry["path"]: entry
            for entry in self.tree(task_id)
            if entry.get("is_source") and entry.get("is_text")
        }
        if normalized not in entries:
            raise ServiceError("当前文件不在源码清单中", 404)
        sources = []
        for path in sorted(entries):
            try:
                sources.append((path, self.manager.load_source(task_id, path)))
            except FileNotFoundError:
                continue
        result = find_symbol_definition(
            sources, symbol, normalized, max(1, int(line or 1))
        )
        return {"found": bool(result), "definition": result}

    def search(
        self, task_id: str, query: str, *, match_case: bool = False,
        whole_word: bool = False, use_regex: bool = False,
    ) -> dict:
        """Search only uploaded text files and validated material entries."""
        if not self.database.get_task(task_id):
            raise ServiceError("任务不存在", 404)
        query = str(query or "")
        if not query or len(query) > 200 or "\n" in query or "\r" in query:
            raise ServiceError("搜索内容须为 1–200 个字符且不能换行")
        expression = query if use_regex else re.escape(query)
        if whole_word:
            expression = rf"(?<!\w)(?:{expression})(?!\w)"
        try:
            pattern = re.compile(expression, 0 if match_case else re.IGNORECASE)
        except re.error as exc:
            raise ServiceError(f"正则表达式无效：{exc}") from exc
        if pattern.match(""):
            raise ServiceError("搜索表达式不能匹配空字符串")

        root = task_paths(self.settings.tasks_dir, task_id)
        entries = [
            ("source", None, file["path"], file["path"], root["project"] / file["path"])
            for file in self.tree(task_id) if file.get("is_text")
        ]
        entries.extend(
            ("material", item["category"], item["path"],
             f"{item['folder_name']}/{item['path']}",
             (root["domain_sources"] if item["category"] == "domain-source"
              else root["materials"] / item["category"]) / item["path"])
            for item in self.materials(task_id)
        )
        groups: list[dict] = []
        total = 0
        limit = 1000
        for kind, category, relative, display_path, path in entries:
            try:
                content, _encoding = decode_text(path.read_bytes())
            except (OSError, UnicodeDecodeError):
                continue
            matches = []
            for line_number, line in enumerate(content.splitlines(), 1):
                for found in pattern.finditer(line):
                    if found.start() == found.end():
                        continue
                    if total >= limit:
                        break
                    start = max(0, found.start() - 70)
                    end = min(len(line), start + 240)
                    matches.append({
                        "line": line_number,
                        "column": found.start() + 1,
                        "length": found.end() - found.start(),
                        "preview": line[start:end],
                        "preview_column": found.start() - start,
                        "preview_length": min(found.end(), end) - found.start(),
                    })
                    total += 1
                if total >= limit:
                    break
            if matches:
                groups.append({
                    "kind": kind, "category": category, "path": relative,
                    "display_path": display_path, "matches": matches,
                })
            if total >= limit:
                break
        return {
            "files": groups,
            "total_matches": total,
            "truncated": total >= limit,
        }

    def log_tail(self, task_id: str, max_lines: int = 500) -> list[str]:
        if not self.database.get_task(task_id):
            raise ServiceError("任务不存在", 404)
        log_path = task_paths(self.settings.tasks_dir, task_id)["log"]
        try:
            lines = log_path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return []
        return lines[-max(1, min(2000, max_lines)) :]

    def resume(self, task_id: str) -> dict:
        task = self.database.get_task(task_id)
        if not task:
            raise ServiceError("任务不存在", 404)
        if task["status"] not in {"failed", "cancelled"}:
            raise ServiceError("只有失败或已取消的任务可以继续验证", 409)
        updated = self.database.enqueue_existing(task_id, resume=True)
        self.manager.notify()
        return updated

    def rerun(self, task_id: str) -> dict:
        original = self.database.get_task(task_id)
        if not original:
            raise ServiceError("任务不存在", 404)
        source = task_paths(self.settings.tasks_dir, task_id)
        new_id = str(uuid.uuid4())
        target = task_paths(self.settings.tasks_dir, new_id)
        try:
            shutil.copytree(
                source["project"],
                target["project"],
                ignore=shutil.ignore_patterns("fm_agent"),
            )
            if source["materials"].is_dir():
                shutil.copytree(source["materials"], target["materials"])
            if source["requirements"].is_dir():
                shutil.copytree(source["requirements"], target["requirements"])
            target["root"].mkdir(parents=True, exist_ok=True)
            shutil.copy2(source["manifest"], target["manifest"])
            task = self.database.create_task(
                {
                    "id": new_id,
                    "name": f"{original['name']} · 重新验证",
                    "project_name": original["project_name"],
                    "file_count": original["file_count"],
                    "source_bytes": original["source_bytes"],
                    "cloned_from": task_id,
                    "trace_enabled": 1,
                }
            )
        except Exception:
            shutil.rmtree(target["root"], ignore_errors=True)
            raise
        self._index_materials(new_id, "domain")
        self._index_materials(new_id, "intent")
        self.manager.notify()
        return task

    def delete(self, task_id: str) -> None:
        task = self.database.get_task(task_id)
        if not task:
            raise ServiceError("任务不存在", 404)
        if task["status"] not in TERMINAL_STATUSES:
            raise ServiceError("请先停止任务，待状态变为“已取消”后再删除", 409)
        root = task_paths(self.settings.tasks_dir, task_id)["root"]
        try:
            if root.exists():
                shutil.rmtree(root)
        except OSError as exc:
            raise ServiceError(f"删除任务文件失败：{exc}", 500) from exc
        if not self.database.delete_task(task_id):
            raise ServiceError("任务不存在", 404)

    def retry_enrichment(self, issue_id: int) -> dict:
        issue = self.database.get_issue(issue_id)
        if not issue:
            raise ServiceError("问题记录不存在", 404)
        if issue["enrichment_status"] == "enriching":
            raise ServiceError("中文说明正在生成，请稍候", 409)
        updated = self.database.reset_issue_enrichment(issue_id)
        self.manager.enricher.submit(issue_id)
        return updated

    def toggle_issue_marked(self, issue_id: int) -> dict:
        issue = self.database.toggle_issue_marked(issue_id)
        if not issue:
            raise ServiceError("问题记录不存在", 404)
        return issue

    def report_availability(self, task_id: str) -> dict[str, bool]:
        paths = task_paths(self.settings.tasks_dir, task_id)
        work = paths["project"] / "fm_agent"
        return {
            "zh_html": (paths["reports"] / "验证报告.html").is_file(),
            "zh_md": (paths["reports"] / "验证报告.md").is_file(),
            "zh_json": (paths["reports"] / "验证报告.json").is_file(),
            "original_html": (work / "report.html").is_file(),
            "original_md": (work / "VERIFICATION-REPORT.md").is_file(),
            "original_json": (work / "VERIFICATION-REPORT.json").is_file(),
        }

    def report_file(self, task_id: str, kind: str) -> tuple[Path, str, str]:
        if not self.database.get_task(task_id):
            raise ServiceError("任务不存在", 404)
        paths = task_paths(self.settings.tasks_dir, task_id)
        work = paths["project"] / "fm_agent"
        choices = {
            "zh-html": (paths["reports"] / "验证报告.html", "text/html; charset=utf-8", "FM-Agent-验证报告.html"),
            "zh-md": (paths["reports"] / "验证报告.md", "text/markdown; charset=utf-8", "FM-Agent-验证报告.md"),
            "zh-json": (paths["reports"] / "验证报告.json", "application/json; charset=utf-8", "FM-Agent-验证报告.json"),
            "original-html": (work / "report.html", "text/html; charset=utf-8", "FM-Agent-original-report.html"),
            "original-md": (work / "VERIFICATION-REPORT.md", "text/markdown; charset=utf-8", "FM-Agent-original-report.md"),
            "original-json": (work / "VERIFICATION-REPORT.json", "application/json; charset=utf-8", "FM-Agent-original-report.json"),
        }
        if kind not in choices:
            raise ServiceError("不支持的报告格式", 400)
        path, content_type, filename = choices[kind]
        if not path.is_file():
            raise ServiceError("报告尚未生成", 404)
        return path, content_type, filename

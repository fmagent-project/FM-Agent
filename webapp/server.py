#!/usr/bin/env python3
from __future__ import annotations

import argparse
import email.parser
import email.policy
import json
import mimetypes
import re
import signal
import sys
import time
import traceback
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, quote, unquote, urlsplit

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    from webapp.config import Settings
    from webapp.database import Database, TERMINAL_STATUSES
    from webapp.requirements import RequirementError, RequirementPreprocessor
    from webapp.domain_specs import DomainPreprocessor
    from webapp.runner import TaskManager
    from webapp.service import ServiceError, TaskService, Upload
else:
    from .config import Settings
    from .database import Database, TERMINAL_STATUSES
    from .requirements import RequirementError, RequirementPreprocessor
    from .domain_specs import DomainPreprocessor
    from .runner import TaskManager
    from .service import ServiceError, TaskService, Upload


class Application:
    def __init__(self, settings: Settings):
        self.settings = settings
        settings.data_dir.mkdir(parents=True, exist_ok=True)
        self.database = Database(settings.database_path)
        self.requirements = RequirementPreprocessor(settings, self.database)
        self.domains = DomainPreprocessor(settings, self.database)
        self.manager = TaskManager(settings, self.database)
        self.service = TaskService(
            settings, self.database, self.manager, self.requirements, self.domains
        )


APP: Application


class Handler(BaseHTTPRequestHandler):
    server_version = "FM-Agent-Web/1.0"
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt: str, *args) -> None:
        sys.stderr.write("%s - %s\n" % (self.address_string(), fmt % args))

    def end_headers(self) -> None:
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
        super().end_headers()

    def do_GET(self) -> None:
        try:
            self._get()
        except (BrokenPipeError, ConnectionResetError):
            return
        except ServiceError as exc:
            self._json({"error": str(exc)}, exc.status)
        except RequirementError as exc:
            self._json({"error": str(exc)}, exc.status)
        except Exception as exc:
            traceback.print_exc()
            self._json({"error": f"服务器内部错误：{exc}"}, 500)

    def do_HEAD(self) -> None:
        try:
            path = self._path()
            if path == "/api/health":
                self._json({"status": "ok"})
                return
            if path == "/" or path == "/index.html":
                self._file(APP.settings.static_dir / "index.html", "text/html; charset=utf-8")
                return
            if path.startswith("/static/"):
                relative = path.removeprefix("/static/")
                if not relative or "/" in relative or "\\" in relative or relative.startswith("."):
                    raise ServiceError("静态资源不存在", 404)
                file_path = APP.settings.static_dir / relative
                content_type = mimetypes.guess_type(file_path.name)[0] or "application/octet-stream"
                self._file(file_path, content_type)
                return
            raise ServiceError("页面不存在", 404)
        except ServiceError as exc:
            self._json({"error": str(exc)}, exc.status)

    def do_POST(self) -> None:
        try:
            self._post()
        except ServiceError as exc:
            self._json({"error": str(exc)}, exc.status)
        except RequirementError as exc:
            self._json({"error": str(exc)}, exc.status)
        except (ValueError, json.JSONDecodeError) as exc:
            self._json({"error": f"请求格式错误：{exc}"}, 400)
        except Exception as exc:
            traceback.print_exc()
            self._json({"error": f"服务器内部错误：{exc}"}, 500)

    def do_DELETE(self) -> None:
        try:
            match = re.fullmatch(r"/api/tasks/([0-9a-f-]+)", self._path())
            if not match:
                raise ServiceError("接口不存在", 404)
            APP.service.delete(match.group(1))
            self._json({"ok": True})
        except ServiceError as exc:
            self._json({"error": str(exc)}, exc.status)
        except Exception as exc:
            traceback.print_exc()
            self._json({"error": f"服务器内部错误：{exc}"}, 500)

    def _get(self) -> None:
        path = self._path()
        query = parse_qs(urlsplit(self.path).query)
        if path == "/api/health":
            self._json({"status": "ok", "time": time.time()})
            return
        if path == "/api/config":
            settings = APP.settings
            self._json(
                {
                    "max_concurrent_tasks": settings.max_concurrent_tasks,
                    "max_project_files": settings.max_project_files,
                    "max_project_bytes": settings.max_project_bytes,
                    "max_material_files": settings.max_material_files,
                    "max_material_bytes": settings.max_material_bytes,
                    "max_requirement_files": settings.max_requirement_files,
                    "max_requirement_bytes": settings.max_requirement_bytes,
                    "demo_mode": settings.demo_mode,
                    "enrichment_configured": bool(settings.enrich_api_key),
                    "enrichment_model": settings.enrich_model,
                    "enrichment_backend": "deepseek-harness",
                    "tool_compat_mode": settings.tool_compat_mode,
                }
            )
            return
        if path == "/api/tasks":
            self._json({"tasks": APP.database.list_tasks()})
            return
        match = re.fullmatch(r"/api/tasks/([0-9a-f-]+)", path)
        if match:
            self._json(APP.service.get_detail(match.group(1)))
            return
        match = re.fullmatch(r"/api/tasks/([0-9a-f-]+)/requirements", path)
        if match:
            self._json(APP.service.requirement_review(match.group(1)))
            return
        match = re.fullmatch(r"/api/tasks/([0-9a-f-]+)/domain", path)
        if match:
            self._json(APP.service.domain_review(match.group(1)))
            return
        match = re.fullmatch(r"/api/tasks/([0-9a-f-]+)/tree", path)
        if match:
            self._json(
                {
                    "files": APP.service.tree(match.group(1)),
                    "materials": APP.service.materials(match.group(1)),
                }
            )
            return
        match = re.fullmatch(r"/api/tasks/([0-9a-f-]+)/source", path)
        if match:
            relative = (query.get("path") or [""])[0]
            self._json(APP.service.source(match.group(1), relative))
            return
        match = re.fullmatch(r"/api/tasks/([0-9a-f-]+)/definition", path)
        if match:
            relative = (query.get("path") or [""])[0]
            symbol = (query.get("symbol") or [""])[0]
            try:
                line = int((query.get("line") or ["1"])[0])
            except ValueError:
                line = 1
            self._json(APP.service.definition(match.group(1), relative, symbol, line))
            return
        match = re.fullmatch(r"/api/tasks/([0-9a-f-]+)/search", path)
        if match:
            self._json(APP.service.search(
                match.group(1), (query.get("q") or [""])[0],
                match_case=(query.get("case") or ["0"])[0] == "1",
                whole_word=(query.get("word") or ["0"])[0] == "1",
                use_regex=(query.get("regex") or ["0"])[0] == "1",
            ))
            return
        match = re.fullmatch(r"/api/tasks/([0-9a-f-]+)/material", path)
        if match:
            category = (query.get("category") or [""])[0]
            name = (query.get("name") or [""])[0]
            self._json(APP.service.material(match.group(1), category, name))
            return
        match = re.fullmatch(r"/api/tasks/([0-9a-f-]+)/logs", path)
        if match:
            try:
                max_lines = int((query.get("lines") or ["500"])[0])
            except ValueError:
                max_lines = 500
            self._json({"lines": APP.service.log_tail(match.group(1), max_lines)})
            return
        match = re.fullmatch(r"/api/tasks/([0-9a-f-]+)/events", path)
        if match:
            after_header = self.headers.get("Last-Event-ID", "0")
            after_query = after_header if after_header != "0" else (query.get("after") or ["0"])[0]
            try:
                after = int(after_query)
            except ValueError:
                after = 0
            self._events(match.group(1), after)
            return
        match = re.fullmatch(r"/api/tasks/([0-9a-f-]+)/reports", path)
        if match:
            self._json(APP.service.report_availability(match.group(1)))
            return
        match = re.fullmatch(r"/api/tasks/([0-9a-f-]+)/download", path)
        if match:
            kind = (query.get("kind") or [""])[0]
            file_path, content_type, filename = APP.service.report_file(match.group(1), kind)
            preview = (query.get("preview") or ["0"])[0] == "1"
            self._file(file_path, content_type, attachment=None if preview else filename)
            return
        if path == "/" or path == "/index.html":
            self._file(APP.settings.static_dir / "index.html", "text/html; charset=utf-8")
            return
        if path.startswith("/static/"):
            relative = path.removeprefix("/static/")
            if not relative or "/" in relative or "\\" in relative or relative.startswith("."):
                raise ServiceError("静态资源不存在", 404)
            file_path = APP.settings.static_dir / relative
            content_type = mimetypes.guess_type(file_path.name)[0] or "application/octet-stream"
            if content_type.startswith("text/") or content_type in {"application/javascript", "application/json"}:
                content_type += "; charset=utf-8"
            self._file(file_path, content_type)
            return
        raise ServiceError("页面不存在", 404)

    def _post(self) -> None:
        path = self._path()
        if path == "/api/tasks":
            form, files = self._multipart()
            try:
                source_paths = json.loads(form.get("source_paths", "[]"))
            except json.JSONDecodeError as exc:
                raise ServiceError("源码路径清单不是有效 JSON") from exc
            task = APP.service.create_task(
                name=form.get("name", ""),
                project_name=form.get("project_name", ""),
                source_paths=source_paths,
                sources=files.get("source_files", []),
                domain_files=files.get("domain_files", []),
                intent_files=files.get("intent_files", []),
                requirement_files=files.get("requirement_files", []),
            )
            self._json(task, 201)
            return
        match = re.fullmatch(r"/api/tasks/([0-9a-f-]+)/requirements/preview", path)
        if match:
            payload = self._json_body()
            self._json(APP.service.preview_requirement_category(
                match.group(1), str(payload.get("markdown") or ""),
                str(payload.get("category") or "") or None,
            ))
            return
        match = re.fullmatch(r"/api/tasks/([0-9a-f-]+)/domain/preview", path)
        if match:
            payload = self._json_body()
            self._json(APP.service.preview_requirement_category(
                match.group(1), str(payload.get("markdown") or ""),
                str(payload.get("category") or "") or None, domain=True,
            ))
            return
        match = re.fullmatch(r"/api/tasks/([0-9a-f-]+)/requirements/confirm", path)
        if match:
            payload = self._json_body()
            self._json(
                APP.service.confirm_requirements(
                    match.group(1), str(payload.get("markdown") or "")
                )
            )
            return
        match = re.fullmatch(r"/api/tasks/([0-9a-f-]+)/domain/confirm", path)
        if match:
            payload = self._json_body()
            self._json(APP.service.confirm_domain(match.group(1), str(payload.get("markdown") or "")))
            return
        match = re.fullmatch(r"/api/tasks/([0-9a-f-]+)/requirements/regenerate", path)
        if match:
            files = (
                self._multipart()[1].get("requirement_files", [])
                if self.headers.get("Content-Type", "").lower().startswith("multipart/form-data")
                else []
            )
            self._json(APP.service.regenerate_requirements(match.group(1), files))
            return
        match = re.fullmatch(r"/api/tasks/([0-9a-f-]+)/domain/regenerate", path)
        if match:
            files = (self._multipart()[1].get("domain_files", [])
                     if self.headers.get("Content-Type", "").lower().startswith("multipart/form-data") else [])
            self._json(APP.service.regenerate_domain(match.group(1), files))
            return
        match = re.fullmatch(r"/api/tasks/([0-9a-f-]+)/requirements/revise", path)
        if match:
            self._json(APP.service.revise_requirements(match.group(1)), 201)
            return
        match = re.fullmatch(r"/api/tasks/([0-9a-f-]+)/(?:stop|end)", path)
        if match:
            task = APP.manager.stop_task(match.group(1))
            if not task:
                raise ServiceError("任务不存在", 404)
            self._json(task)
            return
        match = re.fullmatch(r"/api/tasks/([0-9a-f-]+)/resume", path)
        if match:
            self._json(APP.service.resume(match.group(1)))
            return
        match = re.fullmatch(r"/api/tasks/([0-9a-f-]+)/rerun", path)
        if match:
            self._json(APP.service.rerun(match.group(1)), 201)
            return
        match = re.fullmatch(r"/api/issues/(\d+)/retry", path)
        if match:
            self._json(APP.service.retry_enrichment(int(match.group(1))))
            return
        match = re.fullmatch(r"/api/issues/(\d+)/mark", path)
        if match:
            self._json(APP.service.toggle_issue_marked(int(match.group(1))))
            return
        raise ServiceError("接口不存在", 404)

    def _multipart(self) -> tuple[dict[str, str], dict[str, list[Upload]]]:
        content_type = self.headers.get("Content-Type", "")
        if not content_type.lower().startswith("multipart/form-data"):
            raise ServiceError("创建任务必须使用 multipart/form-data")
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError as exc:
            raise ServiceError("无效的 Content-Length") from exc
        if length <= 0:
            raise ServiceError("上传内容为空")
        if length > APP.settings.max_request_bytes:
            raise ServiceError("上传内容超过服务端限制", 413)
        body = self.rfile.read(length)
        message = email.parser.BytesParser(policy=email.policy.default).parsebytes(
            (f"Content-Type: {content_type}\r\nMIME-Version: 1.0\r\n\r\n").encode("ascii") + body
        )
        fields: dict[str, str] = {}
        files: dict[str, list[Upload]] = {}
        if not message.is_multipart():
            raise ServiceError("无法解析上传内容")
        for part in message.iter_parts():
            name = part.get_param("name", header="content-disposition")
            if not name:
                continue
            data = part.get_payload(decode=True) or b""
            filename = part.get_filename()
            if filename is None:
                fields[str(name)] = data.decode("utf-8", errors="strict")
            else:
                files.setdefault(str(name), []).append(Upload(str(filename), data))
        return fields, files

    def _json_body(self) -> dict:
        content_type = self.headers.get("Content-Type", "").split(";", 1)[0].strip().lower()
        if content_type != "application/json":
            raise ServiceError("请求必须使用 application/json")
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError as exc:
            raise ServiceError("无效的 Content-Length") from exc
        if length <= 0:
            raise ServiceError("请求内容为空")
        if length > APP.settings.max_material_bytes:
            raise ServiceError("请求内容超过验证材料大小限制", 413)
        payload = json.loads(self.rfile.read(length).decode("utf-8"))
        if not isinstance(payload, dict):
            raise ServiceError("JSON 请求必须是对象")
        return payload

    def _events(self, task_id: str, after: int) -> None:
        if not APP.database.get_task(task_id):
            raise ServiceError("任务不存在", 404)
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream; charset=utf-8")
        self.send_header("Cache-Control", "no-cache, no-transform")
        self.send_header("Connection", "keep-alive")
        self.send_header("X-Accel-Buffering", "no")
        self.end_headers()
        last_heartbeat = time.monotonic()
        terminal_since = None
        while True:
            events = APP.database.events_after(task_id, after)
            for event in events:
                after = int(event["id"])
                payload = json.dumps(event["payload"], ensure_ascii=False, separators=(",", ":"))
                chunk = f"id: {after}\nevent: {event['event_type']}\ndata: {payload}\n\n"
                self.wfile.write(chunk.encode("utf-8"))
                self.wfile.flush()
            now = time.monotonic()
            if now - last_heartbeat >= 12:
                self.wfile.write(b": keep-alive\n\n")
                self.wfile.flush()
                last_heartbeat = now
            task = APP.database.get_task(task_id)
            if not task:
                return
            pending = (APP.database.has_pending_enrichments(task_id)
                       or APP.manager.spec_indexer.has_pending(task_id))
            if task["status"] in TERMINAL_STATUSES and not pending:
                terminal_since = terminal_since or now
                if now - terminal_since > 3 and not events:
                    return
            else:
                terminal_since = None
            time.sleep(0.7)

    def _file(
        self, path: Path, content_type: str, attachment: str | None = None
    ) -> None:
        if not path.is_file():
            raise ServiceError("文件不存在", 404)
        data = path.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        if attachment:
            self.send_header(
                "Content-Disposition",
                f"attachment; filename*=UTF-8''{quote(attachment)}",
            )
        else:
            self.send_header("Cache-Control", "no-cache")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(data)

    def _json(self, payload, status: int = 200) -> None:
        data = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(data)

    def _path(self) -> str:
        return unquote(urlsplit(self.path).path)


def main() -> int:
    parser = argparse.ArgumentParser(description="FM-Agent browser/server service")
    parser.add_argument("--host", help="listen address (overrides FM_WEB_HOST)")
    parser.add_argument("--port", type=int, help="listen port (overrides FM_WEB_PORT)")
    args = parser.parse_args()
    settings = Settings.from_env()
    if args.host or args.port:
        values = dict(settings.__dict__)
        values["host"] = args.host or settings.host
        values["port"] = args.port or settings.port
        settings = Settings(**values)
    global APP
    APP = Application(settings)
    server = ThreadingHTTPServer((settings.host, settings.port), Handler)
    server.daemon_threads = True

    def stop(_signum=None, _frame=None):
        threading = __import__("threading")
        threading.Thread(target=server.shutdown, daemon=True).start()

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    APP.requirements.start()
    APP.domains.start()
    APP.manager.start()
    print(
        f"FM-Agent Web 已启动：http://{settings.host}:{settings.port} "
        f"(并发任务 {settings.max_concurrent_tasks}，数据目录 {settings.data_dir})",
        flush=True,
    )
    if settings.demo_mode:
        print("当前为界面演示模式，不执行真实代码验证。", flush=True)
    try:
        server.serve_forever(poll_interval=0.5)
    finally:
        APP.requirements.shutdown()
        APP.domains.shutdown()
        APP.manager.shutdown()
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

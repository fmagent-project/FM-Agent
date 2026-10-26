from __future__ import annotations

import json
import os
import re
import signal
import subprocess
import threading
import time
from pathlib import Path
from typing import Any

from src.file_utils import is_file_ready

from .config import Settings
from .database import Database, TERMINAL_STATUSES
from .enrichment import IssueEnricher
from .reports import generate_chinese_reports
from .spec_trace import FunctionSpecIndexer
from .utils import SOURCE_EXTENSIONS, decode_text, issue_fingerprint, task_paths, utc_now


STAGE_NAMES = {
    1: "生成验证阶段计划",
    2: "生成领域上下文",
    3: "提取源码函数",
    4: "收集待验证文件",
    5: "生成调用层次",
    6: "生成规约并验证",
}


class TaskManager:
    def __init__(self, settings: Settings, database: Database):
        self.settings = settings
        self.database = database
        self.settings.tasks_dir.mkdir(parents=True, exist_ok=True)
        self._stop = threading.Event()
        self._wake = threading.Event()
        self._lock = threading.RLock()
        self._processes: dict[str, subprocess.Popen] = {}
        self._threads: dict[str, threading.Thread] = {}
        self.spec_indexer = FunctionSpecIndexer(settings, database, self._source_location)
        self.enricher = IssueEnricher(
            settings,
            database,
            self.load_source,
            on_update=self.generate_reports,
            trace_candidates=self._trace_candidates,
        )
        self._scheduler = threading.Thread(
            target=self._schedule_loop, name="task-scheduler", daemon=True
        )

    def start(self) -> None:
        self._scheduler.start()
        for issue_id in self.database.pending_enrichments():
            self.database.reset_issue_enrichment(issue_id)
            self.enricher.submit(issue_id)

    def shutdown(self) -> None:
        self._stop.set()
        self._wake.set()
        with self._lock:
            active = list(self._processes.items())
        for task_id, process in active:
            self._terminate_process(task_id, process, force=False)
        self.spec_indexer.shutdown()

    def _trace_candidates(self, issue: dict) -> list[dict[str, Any]]:
        task_id = issue["task_id"]
        task = self.database.get_task(task_id)
        if not task or not task.get("trace_enabled"):
            return []
        self.spec_indexer.ensure_for_issue(task_id, issue["source_file"], issue["function_name"])
        rules = self.database.list_spec_rules(task_id)
        issue_line = issue.get("start_line")
        raw_text = (json.dumps(issue.get("raw") or {}, ensure_ascii=False)
                    + " " + issue["function_name"]).lower()
        words = set(re.findall(r"[a-z_][a-z_0-9]{2,}|\d+(?:\.\d+)?", raw_text))
        for sequence in re.findall(r"[\u4e00-\u9fff]{2,}", raw_text):
            words.update(sequence[index:index + 2] for index in range(len(sequence) - 1))
        def score(rule: dict) -> tuple[int, int]:
            if rule["kind"] == "code":
                same = (rule["source_file"] == issue["source_file"]
                        and rule["function_name"] == issue["function_name"])
                return (1000 if same else -1000, 0)
            content = rule["content"].lower()
            overlap = sum(1 for word in words if word in content)
            return (overlap, 1 if rule["kind"] == "domain" else 0)
        ranked = sorted((rule for rule in rules if rule["kind"] != "code" or
                         (rule["source_file"] == issue["source_file"] and
                          rule["function_name"] == issue["function_name"] and
                          (not issue_line or not rule["source_line"] or rule["source_line"] == issue_line))),
                        key=score, reverse=True)
        chosen, size = [], 0
        for rule in ranked:
            prompt_content = rule["content"][:1800]
            length = len(prompt_content) + 160
            if size + length > 24000:
                continue
            chosen.append({**rule, "prompt_content": prompt_content})
            size += length
        return chosen

    def notify(self) -> None:
        self._wake.set()

    def _schedule_loop(self) -> None:
        while not self._stop.is_set():
            with self._lock:
                dead = [task_id for task_id, thread in self._threads.items() if not thread.is_alive()]
                for task_id in dead:
                    self._threads.pop(task_id, None)
                capacity = self.settings.max_concurrent_tasks - len(self._threads)
            for task_id in self.database.claim_queued(max(0, capacity)):
                thread = threading.Thread(
                    target=self._run_task,
                    args=(task_id,),
                    name=f"task-{task_id[:8]}",
                    daemon=True,
                )
                with self._lock:
                    self._threads[task_id] = thread
                thread.start()
            self._wake.wait(1.0)
            self._wake.clear()

    def stop_task(self, task_id: str) -> dict | None:
        task = self.database.get_task(task_id)
        if not task:
            return None
        if task["status"] == "queued":
            cancelled = self.database.cancel_if_queued(task_id)
            if cancelled:
                return cancelled
            # The scheduler may have claimed it between the read and transition.
            task = self.database.get_task(task_id)
        if task["status"] != "running":
            return task
        updated = self.database.update_task(task_id, status="cancelling", phase="正在停止")
        with self._lock:
            process = self._processes.get(task_id)
        if process:
            threading.Thread(
                target=self._terminate_process,
                args=(task_id, process, False),
                daemon=True,
            ).start()
        return updated

    def _terminate_process(
        self, task_id: str, process: subprocess.Popen, force: bool = False
    ) -> None:
        if process.poll() is not None:
            return
        try:
            os.killpg(process.pid, signal.SIGKILL if force else signal.SIGTERM)
        except (ProcessLookupError, PermissionError):
            return
        if force:
            return
        try:
            process.wait(timeout=8)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except (ProcessLookupError, PermissionError):
                pass

    def _run_task(self, task_id: str) -> None:
        task = self.database.get_task(task_id)
        if not task:
            return
        try:
            if self.settings.demo_mode:
                self._run_demo(task_id)
            else:
                self._run_real(task_id, task)
        except Exception as exc:
            current = self.database.get_task(task_id)
            if current and current["status"] not in TERMINAL_STATUSES:
                self.database.update_task(
                    task_id,
                    status="failed",
                    phase="验证失败",
                    error=str(exc)[:2000],
                    finished_at=utc_now(),
                )
        finally:
            self._scan_results(task_id)
            self.generate_reports(task_id)
            with self._lock:
                self._processes.pop(task_id, None)
            self._wake.set()

    def _run_real(self, task_id: str, task: dict) -> None:
        paths = task_paths(self.settings.tasks_dir, task_id)
        paths["runtime"].mkdir(parents=True, exist_ok=True)
        command = [
            str(self.settings.app_root / "bin" / "fm-agent"),
            str(paths["project"]),
            "--all-bugs",
            "--one-phase",
        ]
        if task.get("run_mode") == "resume":
            command.append("--resume")
        materials = sorted(
            path for path in paths["materials"].rglob("*")
            if path.is_file() and path.suffix.lower() in {".md", ".txt"}
        )
        if materials:
            command.append("--domain-knowledge")
            command.extend(str(path) for path in materials)
        self.database.add_event(
            task_id,
            "log",
            {"line": "开始验证：已启用全部问题收集模式。", "stream": "system"},
        )
        watcher_stop = threading.Event()
        watcher = threading.Thread(
            target=self._watch_results,
            args=(task_id, watcher_stop),
            name=f"watch-{task_id[:8]}",
            daemon=True,
        )
        watcher.start()
        env = os.environ.copy()
        env.setdefault("PYTHONUNBUFFERED", "1")
        with paths["log"].open("a", encoding="utf-8", buffering=1) as log:
            process = subprocess.Popen(
                command,
                cwd=self.settings.app_root,
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                encoding="utf-8",
                errors="replace",
                bufsize=1,
                start_new_session=True,
            )
            with self._lock:
                self._processes[task_id] = process
            assert process.stdout is not None
            with process.stdout:
                for line in process.stdout:
                    clean = _strip_ansi(line.rstrip("\r\n"))
                    log.write(clean + "\n")
                    self.database.add_event(task_id, "log", {"line": clean, "stream": "process"})
                    self._parse_progress(task_id, clean)
            return_code = process.wait()
        watcher_stop.set()
        watcher.join(timeout=self.settings.scan_interval_s * 3 + 1)
        self._scan_results(task_id)
        current = self.database.get_task(task_id)
        if not current:
            return
        successful, verification_errors = self._result_summary(paths, current)
        if current["status"] == "cancelling":
            self.database.update_task(
                task_id,
                status="cancelled",
                phase="已取消",
                exit_code=return_code,
                finished_at=utc_now(),
            )
        elif (
            return_code == 0 and (paths["project"] / "fm_agent" / "VERIFICATION-REPORT.json").is_file()
        ) or (
            successful > 0 and (
                current["stage_number"] == 6
                or (paths["project"] / "fm_agent" / "VERIFICATION-REPORT.json").is_file()
            )
        ):
            self.database.update_task(
                task_id,
                status="completed",
                phase="验证完成",
                exit_code=return_code,
                verification_error_count=max(verification_errors, 1 if return_code else 0),
                error=None,
                finished_at=utc_now(),
            )
        else:
            detail = (
                "验证进程正常退出，但没有生成最终报告；请查看运行日志和模型配置。"
                if return_code == 0
                else f"验证进程退出码为 {return_code}，请查看运行日志。"
            )
            self.database.update_task(
                task_id,
                status="failed",
                phase="验证失败",
                exit_code=return_code,
                error=detail,
                verification_error_count=verification_errors,
                finished_at=utc_now(),
            )

    @staticmethod
    def _result_summary(paths: dict[str, Path], task: dict) -> tuple[int, int]:
        """Count successful results and per-function errors from the final report or artifacts."""
        report_path = paths["project"] / "fm_agent" / "VERIFICATION-REPORT.json"
        try:
            report = json.loads(report_path.read_text(encoding="utf-8"))
            counts = report.get("counts") if isinstance(report, dict) else None
            if isinstance(counts, dict):
                successful = max(0, int(counts.get("MATCH", 0))) + max(0, int(counts.get("MISMATCH", 0)))
                errors = max(0, int(counts.get("ERROR", 0))) + max(0, int(counts.get("MISSING", 0)))
                return successful, errors
        except (OSError, ValueError, TypeError):
            pass
        output = paths["project"] / "fm_agent" / "logic_verification_results"
        counts = {"MATCH": 0, "MISMATCH": 0, "ERROR": 0}
        if output.is_dir():
            for path in output.rglob("*.json"):
                try:
                    result = json.loads(path.read_text(encoding="utf-8"))
                except (OSError, ValueError):
                    continue
                verdict = result.get("verdict") if isinstance(result, dict) else None
                if verdict in counts:
                    counts[verdict] += 1
        missing = max(0, int(task.get("progress_total") or 0) - sum(counts.values()))
        return counts["MATCH"] + counts["MISMATCH"], counts["ERROR"] + missing

    def _watch_results(self, task_id: str, stop: threading.Event) -> None:
        while not stop.wait(self.settings.scan_interval_s):
            self._scan_results(task_id)

    def _scan_results(self, task_id: str) -> None:
        self.refresh_progress(task_id)
        self.spec_indexer.scan_task(task_id)
        paths = task_paths(self.settings.tasks_dir, task_id)
        output = paths["project"] / "fm_agent" / "logic_verification_results"
        if not output.is_dir():
            return
        for path in sorted(output.rglob("*.json")):
            if path.name.endswith(".tmp"):
                continue
            try:
                result = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                continue
            if not isinstance(result, dict) or result.get("verdict") != "MISMATCH":
                continue
            gaps: list[dict[str, Any]] = []
            if isinstance(result.get("gaps"), dict):
                gaps.append(result["gaps"])
            if not gaps:
                continue
            function_rel = _relative_extracted_function(str(result.get("function") or ""))
            source_file = _source_from_extracted(function_rel)
            function_name = Path(function_rel).stem or path.stem.split(".bug-")[0]
            start_line, end_line = self._source_location(
                paths["project"], function_rel, source_file
            )
            for gap in gaps:
                fingerprint = issue_fingerprint(source_file, function_name, gap)
                issue = self.database.add_issue(
                    task_id,
                    {
                        "fingerprint": fingerprint,
                        "source_file": source_file,
                        "function_name": function_name,
                        "start_line": start_line,
                        "end_line": end_line,
                        "raw": gap,
                    },
                )
                if issue:
                    self.enricher.submit(issue["id"])

    def refresh_progress(
        self, task_id: str, latest_function: str | None = None
    ) -> dict | None:
        """Refresh function-level spec and verification progress from artifacts.

        Stage 6 runs specification generation and static verification concurrently.
        Counting their persisted sidecars/results keeps the UI accurate even when
        batches finish out of order or a task is resumed after a service restart.
        """
        task = self.database.get_task(task_id)
        if not task:
            return None
        paths = task_paths(self.settings.tasks_dir, task_id)
        extracted = paths["project"] / "fm_agent" / "extracted_functions"
        if not extracted.is_dir():
            return task

        functions = sorted(
            path
            for path in extracted.rglob("*")
            if path.is_file() and path.suffix.lower() in SOURCE_EXTENSIONS
        )
        if not functions:
            return task

        output = paths["project"] / "fm_agent" / "logic_verification_results"
        spec_completed = 0
        verification_completed = 0
        latest: tuple[float, str] | None = None
        function_relatives = {
            path.relative_to(extracted).as_posix(): path for path in functions
        }
        for relative, function_path in function_relatives.items():
            if is_file_ready(str(function_path)):
                spec_completed += 1
                try:
                    timestamp = max(
                        Path(f"{function_path}.spec.json").stat().st_mtime,
                        Path(f"{function_path}.info.json").stat().st_mtime,
                    )
                    if latest is None or timestamp > latest[0]:
                        latest = (timestamp, relative)
                except OSError:
                    pass

            result_path = output / Path(relative).with_suffix(".json")
            try:
                result = json.loads(result_path.read_text(encoding="utf-8"))
                terminal = (
                    isinstance(result, dict)
                    and result.get("verdict") in {"MATCH", "MISMATCH", "ERROR"}
                )
            except (OSError, UnicodeDecodeError, ValueError):
                terminal = False
            if terminal:
                verification_completed += 1
                try:
                    timestamp = result_path.stat().st_mtime
                    if latest is None or timestamp > latest[0]:
                        latest = (timestamp, relative)
                except OSError:
                    pass

        if latest_function:
            normalized = _relative_extracted_function(latest_function)
            if normalized in function_relatives:
                latest = (time.time(), normalized)

        changes: dict[str, Any] = {
            "progress_total": len(functions),
            "spec_completed": spec_completed,
            "progress_completed": verification_completed,
        }
        if latest:
            relative = latest[1]
            changes["progress_source_file"] = _source_from_extracted(relative)
            changes["progress_function"] = Path(relative).stem
        changes = {key: value for key, value in changes.items() if task.get(key) != value}
        if not changes:
            return task
        return self.database.update_task(task_id, **changes)

    @staticmethod
    def _source_location(
        project: Path, function_rel: str, source_file: str
    ) -> tuple[int | None, int | None]:
        source_path = project / source_file
        extracted_path = project / "fm_agent" / "extracted_functions" / function_rel
        try:
            source = source_path.read_text(encoding="utf-8", errors="replace")
            function = extracted_path.read_text(encoding="utf-8", errors="replace").strip()
        except OSError:
            return None, None
        if function:
            offset = source.find(function)
            if offset >= 0:
                start = source.count("\n", 0, offset) + 1
                return start, start + function.count("\n")
        name = Path(function_rel).stem
        match = re.search(rf"\b{re.escape(name)}\s*\(", source)
        if match:
            line = source.count("\n", 0, match.start()) + 1
            return line, line
        return None, None

    def _parse_progress(self, task_id: str, line: str) -> None:
        stage = re.search(r"(?:\[Pipeline\]\s*)?Stage\s+(\d)/6", line)
        if stage:
            number = int(stage.group(1))
            self.database.update_task(
                task_id, phase=STAGE_NAMES.get(number, f"阶段 {number}"), stage_number=number
            )
        progress = re.search(r"\[(\d+)/(\d+)\]", line)
        if progress:
            function_match = re.search(r"\[\d+/\d+\]\s+(.+):\s+", line)
            refreshed = self.refresh_progress(
                task_id, function_match.group(1) if function_match else None
            )
            changes: dict[str, Any] = {
                "phase": "生成规约并验证",
                "stage_number": 6,
            }
            # Third-party/replacement pipelines may print progress without using
            # the standard artifact directories. Preserve their numeric signal.
            if not refreshed or not refreshed.get("progress_total"):
                changes.update(
                    progress_completed=int(progress.group(1)),
                    progress_total=int(progress.group(2)),
                )
                if function_match:
                    relative = _relative_extracted_function(function_match.group(1))
                    changes.update(
                        progress_source_file=_source_from_extracted(relative),
                        progress_function=Path(relative).stem,
                    )
            current = self.database.get_task(task_id) or {}
            changes = {
                key: value for key, value in changes.items() if current.get(key) != value
            }
            if changes:
                self.database.update_task(task_id, **changes)

    def load_source(self, task_id: str, relative: str) -> str:
        paths = task_paths(self.settings.tasks_dir, task_id)
        candidate = (paths["project"] / relative).resolve()
        project = paths["project"].resolve()
        try:
            candidate.relative_to(project)
        except ValueError as exc:
            raise FileNotFoundError(relative) from exc
        if not candidate.is_file():
            raise FileNotFoundError(relative)
        return decode_text(candidate.read_bytes())[0]

    def generate_reports(self, task_id: str) -> None:
        try:
            generate_chinese_reports(self.database, self.settings.tasks_dir, task_id)
            self.database.add_event(task_id, "report.updated", {"available": True})
        except Exception:
            # Reports are derived artifacts; never change task/issue state on a render failure.
            pass

    def _run_demo(self, task_id: str) -> None:
        paths = task_paths(self.settings.tasks_dir, task_id)
        sources = [
            path for path in paths["project"].rglob("*")
            if path.is_file() and path.suffix.lower() in SOURCE_EXTENSIONS
        ]
        for stage, name in STAGE_NAMES.items():
            current = self.database.get_task(task_id)
            if not current or current["status"] == "cancelling":
                self.database.update_task(
                    task_id, status="cancelled", phase="已取消", finished_at=utc_now()
                )
                return
            self.database.update_task(task_id, phase=name, stage_number=stage)
            self.database.add_event(
                task_id, "log", {"line": f"[演示] Stage {stage}/6：{name}", "stream": "system"}
            )
            time.sleep(0.45)
            if stage == 6 and sources:
                source_path = sources[0]
                relative = source_path.relative_to(paths["project"]).as_posix()
                function_name = source_path.stem
                gap = {
                    "spec_claim": "输入满足前置条件时，函数应返回有效结果。",
                    "actual_behavior": "边界输入可能沿异常路径返回空值。",
                    "code_evidence": "演示模式生成的示例证据，不代表真实验证结论。",
                    "trigger_condition": "当输入位于边界值时触发。",
                }
                issue = self.database.add_issue(
                    task_id,
                    {
                        "fingerprint": issue_fingerprint(relative, function_name, gap),
                        "source_file": relative,
                        "function_name": function_name,
                        "start_line": 1,
                        "end_line": min(8, len(source_path.read_text(errors="replace").splitlines())),
                        "raw": gap,
                    },
                )
                if issue:
                    self.database.finish_issue_enrichment(
                        issue["id"],
                        description_zh="演示问题：该函数在边界输入下可能返回与领域规约不一致的结果。",
                        counterexample_zh=(
                            "触发条件：输入取允许范围的边界值。\n"
                            "实际结果：函数沿异常分支返回空值。\n"
                            "期望结果：函数返回领域规约要求的有效结果。"
                        ),
                        severity="中",
                        confidence=86,
                        suggestion_zh="复核边界条件分支，并为返回值增加显式校验和对应单元测试。",
                    )
        self.database.update_task(
            task_id,
            status="completed",
            phase="演示验证完成",
            progress_completed=max(1, len(sources)),
            progress_total=max(1, len(sources)),
            spec_completed=max(1, len(sources)),
            progress_source_file=(
                sources[-1].relative_to(paths["project"]).as_posix() if sources else None
            ),
            progress_function=(sources[-1].stem if sources else None),
            exit_code=0,
            finished_at=utc_now(),
        )


def _strip_ansi(value: str) -> str:
    return re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", "", value)


def _relative_extracted_function(value: str) -> str:
    normalized = value.replace("\\", "/")
    marker = "/extracted_functions/"
    if marker in normalized:
        return normalized.rsplit(marker, 1)[1].lstrip("/")
    return normalized.removeprefix("fm_agent/extracted_functions/").lstrip("/")


def _source_from_extracted(relative: str) -> str:
    parts = relative.replace("\\", "/").split("/")
    known = {extension.lstrip(".") for extension in SOURCE_EXTENSIONS}
    for index in range(len(parts) - 2, -1, -1):
        base, separator, extension = parts[index].rpartition("-")
        if separator and base and extension.lower() in known:
            return "/".join(parts[:index] + [f"{base}.{extension}"])
    return relative

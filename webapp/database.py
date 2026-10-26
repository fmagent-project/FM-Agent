from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterable

from .utils import json_dumps, utc_now


TERMINAL_STATUSES = {
    "completed", "failed", "cancelled", "awaiting_confirmation", "preprocess_failed",
    "awaiting_domain_confirmation", "domain_preprocess_failed",
}


class Database:
    def __init__(self, path: Path):
        self.path = path
        path.parent.mkdir(parents=True, exist_ok=True)
        self._initialize()

    def connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=30, check_same_thread=False)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA busy_timeout = 30000")
        return connection

    @contextmanager
    def session(self):
        connection = self.connect()
        try:
            yield connection
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def _initialize(self) -> None:
        with self.session() as db:
            db.execute("PRAGMA journal_mode = WAL")
            db.executescript(
                """
                CREATE TABLE IF NOT EXISTS tasks (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    project_name TEXT NOT NULL,
                    status TEXT NOT NULL,
                    phase TEXT NOT NULL DEFAULT '等待执行',
                    stage_number INTEGER NOT NULL DEFAULT 0,
                    progress_completed INTEGER NOT NULL DEFAULT 0,
                    progress_total INTEGER NOT NULL DEFAULT 0,
                    spec_completed INTEGER NOT NULL DEFAULT 0,
                    verification_error_count INTEGER NOT NULL DEFAULT 0,
                    progress_source_file TEXT,
                    progress_function TEXT,
                    issue_count INTEGER NOT NULL DEFAULT 0,
                    file_count INTEGER NOT NULL DEFAULT 0,
                    source_bytes INTEGER NOT NULL DEFAULT 0,
                    created_at TEXT NOT NULL,
                    started_at TEXT,
                    finished_at TEXT,
                    updated_at TEXT NOT NULL,
                    exit_code INTEGER,
                    error TEXT,
                    run_mode TEXT NOT NULL DEFAULT 'fresh',
                    cloned_from TEXT,
                    trace_enabled INTEGER NOT NULL DEFAULT 0,
                    FOREIGN KEY(cloned_from) REFERENCES tasks(id) ON DELETE SET NULL
                );

                CREATE TABLE IF NOT EXISTS issues (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    task_id TEXT NOT NULL,
                    fingerprint TEXT NOT NULL,
                    source_file TEXT NOT NULL,
                    function_name TEXT NOT NULL,
                    start_line INTEGER,
                    end_line INTEGER,
                    raw_json TEXT NOT NULL,
                    enrichment_status TEXT NOT NULL DEFAULT 'pending',
                    description_zh TEXT,
                    counterexample_zh TEXT,
                    severity TEXT,
                    confidence REAL,
                    suggestion_zh TEXT,
                    enrichment_error TEXT,
                    is_marked INTEGER NOT NULL DEFAULT 0,
                    trace_json TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    UNIQUE(task_id, fingerprint),
                    FOREIGN KEY(task_id) REFERENCES tasks(id) ON DELETE CASCADE
                );

                CREATE TABLE IF NOT EXISTS events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    task_id TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    FOREIGN KEY(task_id) REFERENCES tasks(id) ON DELETE CASCADE
                );
                CREATE INDEX IF NOT EXISTS idx_events_task_id ON events(task_id, id);
                CREATE INDEX IF NOT EXISTS idx_issues_task_id ON issues(task_id, id);
                CREATE INDEX IF NOT EXISTS idx_tasks_created_at ON tasks(created_at DESC);
                CREATE TABLE IF NOT EXISTS spec_rules (
                    task_id TEXT NOT NULL,
                    rule_id TEXT NOT NULL,
                    kind TEXT NOT NULL,
                    category TEXT NOT NULL,
                    content TEXT NOT NULL,
                    source_file TEXT NOT NULL,
                    source_line INTEGER,
                    function_name TEXT,
                    clause_type TEXT,
                    source_key TEXT NOT NULL,
                    PRIMARY KEY(task_id, rule_id),
                    FOREIGN KEY(task_id) REFERENCES tasks(id) ON DELETE CASCADE
                );
                CREATE INDEX IF NOT EXISTS idx_spec_rules_source ON spec_rules(task_id,kind,source_file,function_name);
                """
            )
            # Keep persisted databases from earlier Web versions compatible.
            task_columns = {
                str(row["name"]) for row in db.execute("PRAGMA table_info(tasks)").fetchall()
            }
            if "stage_number" not in task_columns:
                db.execute("ALTER TABLE tasks ADD COLUMN stage_number INTEGER NOT NULL DEFAULT 0")
            if "spec_completed" not in task_columns:
                db.execute("ALTER TABLE tasks ADD COLUMN spec_completed INTEGER NOT NULL DEFAULT 0")
            if "verification_error_count" not in task_columns:
                db.execute("ALTER TABLE tasks ADD COLUMN verification_error_count INTEGER NOT NULL DEFAULT 0")
            if "progress_source_file" not in task_columns:
                db.execute("ALTER TABLE tasks ADD COLUMN progress_source_file TEXT")
            if "progress_function" not in task_columns:
                db.execute("ALTER TABLE tasks ADD COLUMN progress_function TEXT")
            if "trace_enabled" not in task_columns:
                db.execute("ALTER TABLE tasks ADD COLUMN trace_enabled INTEGER NOT NULL DEFAULT 0")
            issue_columns = {
                str(row["name"]) for row in db.execute("PRAGMA table_info(issues)").fetchall()
            }
            if "counterexample_zh" not in issue_columns:
                db.execute("ALTER TABLE issues ADD COLUMN counterexample_zh TEXT")
            if "is_marked" not in issue_columns:
                db.execute("ALTER TABLE issues ADD COLUMN is_marked INTEGER NOT NULL DEFAULT 0")
            if "trace_json" not in issue_columns:
                db.execute("ALTER TABLE issues ADD COLUMN trace_json TEXT")
            # A web-process restart cannot leave a task looking active forever.
            now = utc_now()
            db.execute(
                """
                UPDATE tasks
                SET status='failed', phase='服务重启后等待继续',
                    error='Web 服务重启中断了验证进程，可点击“继续验证”。',
                    finished_at=?, updated_at=?
                WHERE status IN ('running', 'cancelling')
                """,
                (now, now),
            )

    @staticmethod
    def _row(row: sqlite3.Row | None) -> dict[str, Any] | None:
        return dict(row) if row is not None else None

    def add_event(
        self, task_id: str, event_type: str, payload: dict[str, Any], *, db=None
    ) -> int:
        own = db is None
        connection = db or self.connect()
        try:
            cursor = connection.execute(
                "INSERT INTO events(task_id,event_type,payload_json,created_at) VALUES(?,?,?,?)",
                (task_id, event_type, json_dumps(payload), utc_now()),
            )
            if own:
                connection.commit()
            return int(cursor.lastrowid)
        finally:
            if own:
                connection.close()

    def create_task(self, task: dict[str, Any]) -> dict[str, Any]:
        now = utc_now()
        values = {
            "status": "queued",
            "phase": "等待执行",
            "stage_number": 0,
            "progress_completed": 0,
            "progress_total": 0,
            "spec_completed": 0,
            "verification_error_count": 0,
            "progress_source_file": None,
            "progress_function": None,
            "issue_count": 0,
            "source_bytes": 0,
            "run_mode": "fresh",
            "cloned_from": None,
            "trace_enabled": 0,
            **task,
            "created_at": now,
            "updated_at": now,
        }
        with self.session() as db:
            db.execute(
                """
                INSERT INTO tasks(
                    id,name,project_name,status,phase,stage_number,progress_completed,progress_total,
                    spec_completed,verification_error_count,progress_source_file,progress_function,
                    issue_count,file_count,source_bytes,created_at,updated_at,run_mode,cloned_from,trace_enabled
                ) VALUES(
                    :id,:name,:project_name,:status,:phase,:stage_number,:progress_completed,:progress_total,
                    :spec_completed,:verification_error_count,:progress_source_file,:progress_function,
                    :issue_count,:file_count,:source_bytes,:created_at,:updated_at,:run_mode,:cloned_from,:trace_enabled
                )
                """,
                values,
            )
            self.add_event(values["id"], "task.created", {"task": values}, db=db)
        return self.get_task(values["id"])

    def list_tasks(self) -> list[dict[str, Any]]:
        with self.session() as db:
            rows = db.execute("SELECT * FROM tasks ORDER BY created_at DESC").fetchall()
        return [dict(row) for row in rows]

    def get_task(self, task_id: str) -> dict[str, Any] | None:
        with self.session() as db:
            row = db.execute("SELECT * FROM tasks WHERE id=?", (task_id,)).fetchone()
        return self._row(row)

    def update_task(self, task_id: str, **changes: Any) -> dict[str, Any] | None:
        if not changes:
            return self.get_task(task_id)
        allowed = {
            "name", "status", "phase", "stage_number", "progress_completed", "progress_total",
            "spec_completed", "progress_source_file", "progress_function",
            "verification_error_count",
            "issue_count", "started_at", "finished_at", "exit_code", "error", "run_mode",
        }
        unexpected = set(changes) - allowed
        if unexpected:
            raise ValueError(f"不可更新的任务字段：{', '.join(sorted(unexpected))}")
        changes["updated_at"] = utc_now()
        assignments = ",".join(f"{key}=?" for key in changes)
        with self.session() as db:
            db.execute(
                f"UPDATE tasks SET {assignments} WHERE id=?",
                (*changes.values(), task_id),
            )
            row = db.execute("SELECT * FROM tasks WHERE id=?", (task_id,)).fetchone()
            task = self._row(row)
            if task:
                self.add_event(task_id, "task.updated", {"task": task}, db=db)
        return task

    def claim_queued(self, limit: int) -> list[str]:
        if limit <= 0:
            return []
        now = utc_now()
        claimed: list[str] = []
        with self.session() as db:
            db.execute("BEGIN IMMEDIATE")
            rows = db.execute(
                "SELECT id FROM tasks WHERE status='queued' ORDER BY created_at LIMIT ?",
                (limit,),
            ).fetchall()
            for row in rows:
                task_id = str(row["id"])
                db.execute(
                    """
                    UPDATE tasks SET status='running', phase='正在启动', started_at=COALESCE(started_at,?),
                        finished_at=NULL, error=NULL, updated_at=? WHERE id=? AND status='queued'
                    """,
                    (now, now, task_id),
                )
                if db.execute("SELECT changes()").fetchone()[0]:
                    claimed.append(task_id)
                    task = dict(db.execute("SELECT * FROM tasks WHERE id=?", (task_id,)).fetchone())
                    self.add_event(task_id, "task.updated", {"task": task}, db=db)
        return claimed

    def add_issue(self, task_id: str, issue: dict[str, Any]) -> dict[str, Any] | None:
        now = utc_now()
        with self.session() as db:
            cursor = db.execute(
                """
                INSERT OR IGNORE INTO issues(
                    task_id,fingerprint,source_file,function_name,start_line,end_line,raw_json,
                    enrichment_status,created_at,updated_at
                ) VALUES(?,?,?,?,?,?,?,'pending',?,?)
                """,
                (
                    task_id, issue["fingerprint"], issue["source_file"], issue["function_name"],
                    issue.get("start_line"), issue.get("end_line"), json_dumps(issue["raw"]), now, now,
                ),
            )
            if not cursor.rowcount:
                return None
            issue_id = int(cursor.lastrowid)
            db.execute(
                "UPDATE tasks SET issue_count=issue_count+1,updated_at=? WHERE id=?",
                (now, task_id),
            )
            row = db.execute("SELECT * FROM issues WHERE id=?", (issue_id,)).fetchone()
            record = self._decode_issue(row)
            self.add_event(task_id, "issue.created", {"issue": record}, db=db)
        return record

    @staticmethod
    def _decode_issue(row: sqlite3.Row | None) -> dict[str, Any] | None:
        if row is None:
            return None
        value = dict(row)
        try:
            value["raw"] = json.loads(value.pop("raw_json"))
        except (ValueError, TypeError):
            value["raw"] = {}
            value.pop("raw_json", None)
        value["is_marked"] = bool(value.get("is_marked"))
        try:
            value["violated_specs"] = json.loads(value.pop("trace_json") or "[]")
        except (ValueError, TypeError):
            value["violated_specs"] = []
        return value

    def get_issue(self, issue_id: int) -> dict[str, Any] | None:
        with self.session() as db:
            row = db.execute("SELECT * FROM issues WHERE id=?", (issue_id,)).fetchone()
        return self._decode_issue(row)

    def list_issues(self, task_id: str) -> list[dict[str, Any]]:
        with self.session() as db:
            rows = db.execute(
                "SELECT * FROM issues WHERE task_id=? ORDER BY id", (task_id,)
            ).fetchall()
        return [self._decode_issue(row) for row in rows]

    def set_issue_enriching(self, issue_id: int) -> dict[str, Any] | None:
        now = utc_now()
        with self.session() as db:
            db.execute(
                "UPDATE issues SET enrichment_status='enriching',enrichment_error=NULL,updated_at=? WHERE id=?",
                (now, issue_id),
            )
            row = db.execute("SELECT * FROM issues WHERE id=?", (issue_id,)).fetchone()
            issue = self._decode_issue(row)
            if issue:
                self.add_event(issue["task_id"], "issue.updated", {"issue": issue}, db=db)
        return issue

    def finish_issue_enrichment(
        self,
        issue_id: int,
        *,
        description_zh: str | None = None,
        counterexample_zh: str | None = None,
        severity: str | None = None,
        confidence: float | None = None,
        suggestion_zh: str | None = None,
        violated_specs: list[dict[str, Any]] | None = None,
        error: str | None = None,
    ) -> dict[str, Any] | None:
        now = utc_now()
        status = "failed" if error else "ready"
        with self.session() as db:
            db.execute(
                """
                UPDATE issues SET enrichment_status=?,description_zh=?,counterexample_zh=?,severity=?,confidence=?,
                    suggestion_zh=?,trace_json=?,enrichment_error=?,updated_at=? WHERE id=?
                """,
                (
                    status, description_zh, counterexample_zh, severity, confidence, suggestion_zh,
                    json_dumps(violated_specs or []), error, now, issue_id,
                ),
            )
            row = db.execute("SELECT * FROM issues WHERE id=?", (issue_id,)).fetchone()
            issue = self._decode_issue(row)
            if issue:
                self.add_event(issue["task_id"], "issue.updated", {"issue": issue}, db=db)
        return issue

    def reset_issue_enrichment(self, issue_id: int) -> dict[str, Any] | None:
        now = utc_now()
        with self.session() as db:
            db.execute(
                """
                UPDATE issues SET enrichment_status='pending',enrichment_error=NULL,updated_at=?
                WHERE id=?
                """,
                (now, issue_id),
            )
            row = db.execute("SELECT * FROM issues WHERE id=?", (issue_id,)).fetchone()
            issue = self._decode_issue(row)
            if issue:
                self.add_event(issue["task_id"], "issue.updated", {"issue": issue}, db=db)
        return issue

    def toggle_issue_marked(self, issue_id: int) -> dict[str, Any] | None:
        now = utc_now()
        with self.session() as db:
            db.execute(
                """
                UPDATE issues
                SET is_marked=CASE WHEN is_marked=0 THEN 1 ELSE 0 END, updated_at=?
                WHERE id=?
                """,
                (now, issue_id),
            )
            row = db.execute("SELECT * FROM issues WHERE id=?", (issue_id,)).fetchone()
            issue = self._decode_issue(row)
            if issue:
                self.add_event(issue["task_id"], "issue.updated", {"issue": issue}, db=db)
        return issue

    def events_after(self, task_id: str, after: int, limit: int = 200) -> list[dict[str, Any]]:
        with self.session() as db:
            rows = db.execute(
                """
                SELECT id,event_type,payload_json,created_at FROM events
                WHERE task_id=? AND id>? ORDER BY id LIMIT ?
                """,
                (task_id, after, limit),
            ).fetchall()
        result = []
        for row in rows:
            result.append(
                {
                    "id": row["id"],
                    "event_type": row["event_type"],
                    "payload": json.loads(row["payload_json"]),
                    "created_at": row["created_at"],
                }
            )
        return result

    def last_event_id(self, task_id: str) -> int:
        with self.session() as db:
            row = db.execute(
                "SELECT COALESCE(MAX(id), 0) FROM events WHERE task_id=?", (task_id,)
            ).fetchone()
        return int(row[0])

    def delete_task(self, task_id: str) -> bool:
        with self.session() as db:
            cursor = db.execute("DELETE FROM tasks WHERE id=?", (task_id,))
        return bool(cursor.rowcount)

    def count_running(self) -> int:
        with self.session() as db:
            return int(
                db.execute("SELECT COUNT(*) FROM tasks WHERE status='running'").fetchone()[0]
            )

    def cancel_if_queued(self, task_id: str) -> dict[str, Any] | None:
        now = utc_now()
        with self.session() as db:
            db.execute("BEGIN IMMEDIATE")
            cursor = db.execute(
                """
                UPDATE tasks SET status='cancelled',phase='已取消',finished_at=?,updated_at=?
                WHERE id=? AND status='queued'
                """,
                (now, now, task_id),
            )
            if not cursor.rowcount:
                return None
            task = dict(db.execute("SELECT * FROM tasks WHERE id=?", (task_id,)).fetchone())
            self.add_event(task_id, "task.updated", {"task": task}, db=db)
        return task

    def enqueue_existing(self, task_id: str, *, resume: bool) -> dict[str, Any] | None:
        task = self.get_task(task_id)
        if not task or task["status"] not in TERMINAL_STATUSES:
            return None
        now = utc_now()
        mode = "resume" if resume else "fresh"
        with self.session() as db:
            db.execute(
                """
                UPDATE tasks SET status='queued',phase='等待执行',finished_at=NULL,exit_code=NULL,
                    error=NULL,verification_error_count=0,run_mode=?,updated_at=? WHERE id=?
                """,
                (mode, now, task_id),
            )
            row = db.execute("SELECT * FROM tasks WHERE id=?", (task_id,)).fetchone()
            updated = self._row(row)
            self.add_event(task_id, "task.updated", {"task": updated}, db=db)
        return updated

    def pending_enrichments(self) -> Iterable[int]:
        with self.session() as db:
            rows = db.execute(
                "SELECT id FROM issues WHERE enrichment_status IN ('pending','enriching') ORDER BY id"
            ).fetchall()
        return [int(row["id"]) for row in rows]

    def has_pending_enrichments(self, task_id: str) -> bool:
        with self.session() as db:
            row = db.execute(
                "SELECT 1 FROM issues WHERE task_id=? AND enrichment_status IN ('pending','enriching') LIMIT 1",
                (task_id,),
            ).fetchone()
        return row is not None

    def replace_spec_rules(self, task_id: str, source_key: str, rules: list[dict[str, Any]]) -> None:
        with self.session() as db:
            db.execute("DELETE FROM spec_rules WHERE task_id=? AND source_key=?", (task_id, source_key))
            for rule in rules:
                db.execute(
                    """INSERT OR IGNORE INTO spec_rules(task_id,rule_id,kind,category,content,source_file,
                       source_line,function_name,clause_type,source_key) VALUES(?,?,?,?,?,?,?,?,?,?)""",
                    (task_id, rule["rule_id"], rule["kind"], rule["category"],
                     rule["content"], rule["source_file"], rule.get("source_line"),
                     rule.get("function_name"), rule.get("clause_type"), source_key),
                )
            self.add_event(task_id, "spec.updated", {
                "source_key": source_key,
                "source_file": rules[0]["source_file"] if rules else None,
                "kind": rules[0]["kind"] if rules else None,
            }, db=db)

    def list_spec_rules(self, task_id: str, *, kind: str | None = None,
                        source_file: str | None = None, function_name: str | None = None) -> list[dict[str, Any]]:
        query = "SELECT * FROM spec_rules WHERE task_id=?"
        values: list[Any] = [task_id]
        for column, value in (("kind", kind), ("source_file", source_file), ("function_name", function_name)):
            if value is not None:
                query += f" AND {column}=?"
                values.append(value)
        query += " ORDER BY kind,source_file,source_line,rule_id"
        with self.session() as db:
            rows = db.execute(query, values).fetchall()
        return [dict(row) for row in rows]

#!/usr/bin/env python3
"""Offline live dashboard for DeepSeek-Harness-backed FM-Agent runs."""

from __future__ import annotations

import argparse
import json
import os
import signal
import time
from collections import Counter, deque
from datetime import datetime
from pathlib import Path

from rich.console import Group
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.text import Text


class DashboardState:
    def __init__(self, workdir: Path):
        self.workdir = workdir
        self.events_path = workdir / "trace" / "events.jsonl"
        self.offset = 0
        self.stage = Counter()
        self.status = Counter()
        self.event_types = Counter()
        self.recent = deque(maxlen=12)
        self.llm_recent = deque(maxlen=12)
        self.latest_validation = {}
        self.prompt_tokens = 0
        self.completion_tokens = 0
        self.first_time = ""
        self.last_time = ""

    def _reset(self) -> None:
        self.offset = 0
        self.stage.clear()
        self.status.clear()
        self.event_types.clear()
        self.recent.clear()
        self.llm_recent.clear()
        self.latest_validation.clear()
        self.prompt_tokens = 0
        self.completion_tokens = 0
        self.first_time = ""
        self.last_time = ""

    def refresh_events(self) -> None:
        if not self.events_path.is_file():
            return
        size = self.events_path.stat().st_size
        if size < self.offset:
            self._reset()
        with self.events_path.open("r", encoding="utf-8", errors="replace") as stream:
            stream.seek(self.offset)
            for line in stream:
                try:
                    event = json.loads(line)
                except ValueError:
                    continue
                stage = str(event.get("stage") or "unknown")
                status = str(event.get("status") or "unknown")
                event_type = str(event.get("type") or "event")
                self.stage[stage] += 1
                self.status[status] += 1
                self.event_types[event_type] += 1
                started = str(event.get("start_time") or "")
                ended = str(event.get("end_time") or started)
                if started and (not self.first_time or started < self.first_time):
                    self.first_time = started
                if ended and ended > self.last_time:
                    self.last_time = ended
                metadata = event.get("metadata")
                usage = metadata.get("usage") if isinstance(metadata, dict) else None
                if isinstance(usage, dict):
                    self.prompt_tokens += int(usage.get("prompt_tokens") or 0)
                    self.completion_tokens += int(usage.get("completion_tokens") or 0)
                if event_type == "stage_validation":
                    self.latest_validation[stage] = (
                        status,
                        str(event.get("summary") or ""),
                    )
                if event_type in {"llm_call", "agent_call"}:
                    self.llm_recent.appendleft(
                        (
                            "LLM" if event_type == "llm_call" else "Harness",
                            str((metadata or {}).get("model") or ""),
                            status,
                            str(event.get("summary") or ""),
                        )
                    )
                self.recent.appendleft(
                    (
                        event.get("end_time") or event.get("start_time") or "",
                        stage,
                        status,
                        event.get("summary") or event_type,
                    )
                )
            self.offset = stream.tell()

    def verdicts(self) -> Counter:
        counts = Counter()
        directory = self.workdir / "logic_verification_results"
        if not directory.is_dir():
            return counts
        for path in directory.rglob("*.json"):
            try:
                record = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                continue
            verdict = record.get("verdict")
            if verdict:
                counts[str(verdict)] += 1
        return counts


def _counter_table(title: str, first: str, values: Counter) -> Table:
    table = Table(title=title, expand=True)
    table.add_column(first)
    table.add_column("Count", justify="right")
    for key, count in sorted(values.items()):
        table.add_row(key, str(count))
    if not values:
        table.add_row("(waiting)", "0")
    return table


def _duration(first: str, last: str) -> str:
    try:
        start = datetime.fromisoformat(first.replace("Z", "+00:00"))
        end = datetime.fromisoformat(last.replace("Z", "+00:00"))
    except (ValueError, TypeError):
        return "—"
    seconds = max(0, int((end - start).total_seconds()))
    minutes, seconds = divmod(seconds, 60)
    hours, minutes = divmod(minutes, 60)
    return f"{hours:d}:{minutes:02d}:{seconds:02d}" if hours else f"{minutes:d}:{seconds:02d}"


def _stage_table(state: DashboardState) -> Table:
    table = Table(title="Pipeline progress", expand=True)
    table.add_column("Stage")
    table.add_column("Events", justify="right")
    table.add_column("Latest artifact status")
    table.add_column("Summary", overflow="fold")
    names = sorted(set(state.stage) | set(state.latest_validation))
    for name in names:
        status, summary = state.latest_validation.get(name, ("running", ""))
        style = _status_style(status)
        table.add_row(name, str(state.stage.get(name, 0)), Text(status, style=style), summary)
    if not names:
        table.add_row("(waiting)", "0", "", "")
    return table


def _status_style(status: str) -> str:
    if status in {"success", "mismatch"}:
        return "green" if status == "success" else "yellow"
    if status in {"error", "formal_error", "format_error"}:
        return "red"
    return "yellow"


def _llm_table(state: DashboardState) -> Table:
    table = Table(title="LLM / Harness calls", expand=True)
    table.add_column("Kind", no_wrap=True)
    table.add_column("Model", no_wrap=True)
    table.add_column("Status", no_wrap=True)
    table.add_column("Summary", overflow="fold")
    for kind, model, status, summary in state.llm_recent:
        table.add_row(kind, model or "—", Text(status, style=_status_style(status)), summary)
    if not state.llm_recent:
        table.add_row("", "", "", "Waiting for model calls…")
    return table


def render(state: DashboardState):
    state.refresh_events()
    summary = Table.grid(expand=True)
    summary.add_column()
    summary.add_column(justify="right")
    summary.add_row("Workspace", str(state.workdir))
    summary.add_row("Harness calls", str(state.event_types.get("agent_call", 0)))
    summary.add_row("Structured LLM calls", str(state.event_types.get("llm_call", 0)))
    summary.add_row("Elapsed", _duration(state.first_time, state.last_time))
    summary.add_row(
        "Recorded tokens",
        f"prompt {state.prompt_tokens:,} · completion {state.completion_tokens:,}",
    )
    historical_errors = sum(
        state.status.get(name, 0) for name in ("error", "formal_error", "format_error")
    )
    summary.add_row(
        "Historical errors/retries",
        str(historical_errors),
    )

    stage = _stage_table(state)
    verdict = _counter_table("Static reasoning", "Verdict", state.verdicts())
    llm_calls = _llm_table(state)

    recent = Table(title="Recent activity", expand=True)
    recent.add_column("Time", no_wrap=True)
    recent.add_column("Stage", no_wrap=True)
    recent.add_column("Status", no_wrap=True)
    recent.add_column("Summary", overflow="fold")
    for ended, event_stage, status, description in state.recent:
        style = _status_style(status)
        recent.add_row(ended[-13:-1] if ended else "", event_stage, Text(status, style=style), description)
    if not state.recent:
        recent.add_row("", "", "", "Waiting for trace events…")

    return Group(
        Panel(summary, title="FM-Agent · DeepSeek Harness", border_style="cyan"),
        stage,
        llm_calls,
        verdict,
        recent,
    )


def _resolve_workdir(value: str) -> Path:
    path = Path(value).expanduser().resolve()
    child = path / "fm_agent"
    if child.is_dir() or not path.name.startswith("fm_agent"):
        return child
    return path


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("path", help="project root or fm_agent workspace")
    parser.add_argument("--interval", type=float, default=1.0)
    args = parser.parse_args()
    workdir = _resolve_workdir(args.path)
    state = DashboardState(workdir)
    running = True

    def stop(_signum, _frame):
        nonlocal running
        running = False

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    with Live(render(state), refresh_per_second=4, screen=True) as live:
        while running:
            time.sleep(max(0.2, args.interval))
            live.update(render(state))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

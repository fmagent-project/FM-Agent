"""Tracing and lifecycle helpers for DeepSeek Harness headless processes."""

from __future__ import annotations

import logging
import os
import subprocess
import threading
from dataclasses import dataclass

from config import AGENT_TIMEOUT_SECONDS
from .harness_backend import (
    command_argv,
    command_display,
    command_env,
    command_stdin,
    command_with_json_events,
)
from .trace_writer import new_event_id, record_trace_event, utc_now_iso


def function_id_from_extracted_path(path):
    rel = path.replace("\\", "/")
    for prefix in ("fm_agent/extracted_functions/", "extracted_functions/"):
        if rel.startswith(prefix):
            rel = rel[len(prefix):]
            break
    return os.path.splitext(rel)[0].replace("/", "::")


def function_id_from_result_path(path):
    rel = path.replace("\\", "/")
    prefix = "fm_agent/logic_verification_results/"
    if rel.startswith(prefix):
        rel = rel[len(prefix):]
    return os.path.splitext(rel)[0].replace("/", "::")


@dataclass
class TracedAgentProcess:
    proc: subprocess.Popen
    work_dir: str
    event_id: str
    stage: str
    started: str
    command: object
    function_ids: list | None = None
    input_files: list | None = None
    output_files: list | None = None
    summary: str | None = None
    metadata: dict | None = None
    log_path: str | None = None
    proxy_log_path: str | None = None
    log_thread: threading.Thread | None = None
    stdin_thread: threading.Thread | None = None
    error: str | None = None


def _trace_dir(work_dir):
    return os.path.join(work_dir, "trace")


def _log_path(work_dir, event_id):
    path = os.path.join(_trace_dir(work_dir), "payloads")
    os.makedirs(path, exist_ok=True)
    return os.path.join(path, f"{event_id}_harness.log")


def _copy_output(stream, log_path):
    try:
        with open(log_path, "w", encoding="utf-8", errors="replace") as output:
            for chunk in iter(lambda: stream.read(4096), ""):
                if not chunk:
                    break
                output.write(chunk)
                output.flush()
    finally:
        stream.close()


def _write_stdin(stream, content):
    try:
        stream.write(content)
        stream.flush()
    finally:
        stream.close()


def _start_process(proj_dir, command, log_path, proxy_log_path=None):
    content = command_stdin(command)
    child_env = dict(command_env(command, proj_dir))
    if proxy_log_path:
        child_env["FM_AGENT_TOOL_PROXY_TRACE_PATH"] = proxy_log_path
    proc = subprocess.Popen(
        command_argv(command),
        cwd=proj_dir,
        env=child_env,
        stdin=subprocess.PIPE if content is not None else None,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    stdin_thread = None
    if content is not None:
        stdin_thread = threading.Thread(
            target=_write_stdin, args=(proc.stdin, content), daemon=True
        )
        stdin_thread.start()
    log_thread = threading.Thread(
        target=_copy_output, args=(proc.stdout, log_path), daemon=True
    )
    log_thread.start()
    return proc, log_thread, stdin_thread


def _wait_process(proc, command, stage, timeout_seconds=AGENT_TIMEOUT_SECONDS):
    try:
        return proc.wait(timeout=timeout_seconds), None
    except subprocess.TimeoutExpired:
        logging.warning(
            "DeepSeek Harness %s timed out after %ss, terminating: %s",
            stage,
            timeout_seconds,
            command_display(command),
        )
        proc.terminate()
        try:
            exit_code = proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
            exit_code = proc.wait()
        return exit_code or -15, f"timeout after {timeout_seconds}s"


def record_agent_call(
    work_dir,
    event_id,
    stage,
    status,
    started,
    ended,
    command,
    function_ids=None,
    input_files=None,
    output_files=None,
    exit_code=None,
    summary=None,
    error=None,
    metadata=None,
    log_path=None,
    proxy_log_path=None,
):
    trace_dir = _trace_dir(work_dir)
    children = []
    if log_path and os.path.exists(log_path):
        ref = os.path.relpath(log_path, os.path.dirname(trace_dir))
        children.append({
            "type": "tool_output",
            "label": "deepseek-harness-output",
            "path": ref,
            "content_ref": ref,
        })
    if proxy_log_path and os.path.exists(proxy_log_path):
        ref = os.path.relpath(proxy_log_path, os.path.dirname(trace_dir))
        children.append({
            "type": "tool_output",
            "label": "qwen-tool-proxy-upstream-responses",
            "path": ref,
            "content_ref": ref,
        })
    record_trace_event(trace_dir, {
        "event_id": event_id,
        "type": "agent_call",
        "stage": stage,
        "status": status,
        "start_time": started,
        "end_time": ended,
        "summary": summary or f"DeepSeek Harness {stage}",
        "function_ids": function_ids or [],
        "children": children,
        "metadata": {
            "backend": "deepseek-harness",
            "status_scope": "process_exit",
            "command": command_argv(command),
            "command_display": command_display(command),
            "exit_code": exit_code,
            "input_files": input_files or [],
            "output_files": output_files or [],
            "error": error,
            **(metadata or {}),
        },
    })


def record_stage_validation(
    work_dir,
    stage,
    status,
    summary,
    *,
    missing_outputs=None,
    errors=None,
    metadata=None,
):
    """Record artifact-level success separately from process exit status."""

    now = utc_now_iso()
    record_trace_event(_trace_dir(work_dir), {
        "event_id": new_event_id("validation"),
        "type": "stage_validation",
        "stage": stage,
        "status": status,
        "start_time": now,
        "end_time": now,
        "summary": summary,
        "metadata": {
            "missing_outputs": list(missing_outputs or []),
            "errors": list(errors or []),
            **(metadata or {}),
        },
    })


def run_agent_traced(
    proj_dir,
    work_dir,
    command,
    stage,
    function_ids=None,
    input_files=None,
    output_files=None,
    summary=None,
    metadata=None,
):
    record = start_agent_traced(
        proj_dir=proj_dir,
        work_dir=work_dir,
        command=command,
        stage=stage,
        function_ids=function_ids,
        input_files=input_files,
        output_files=output_files,
        summary=summary,
        metadata=metadata,
    )
    exit_code = 0
    try:
        exit_code = wait_agent_traced(record)
        if record.error or exit_code != 0:
            raise subprocess.CalledProcessError(exit_code, command_argv(command))
        return subprocess.CompletedProcess(command_argv(command), exit_code)
    except subprocess.CalledProcessError as exc:
        record.error = record.error or str(exc)
        raise
    finally:
        finish_agent_trace(record)


def start_agent_traced(
    proj_dir,
    work_dir,
    command,
    stage,
    function_ids=None,
    input_files=None,
    output_files=None,
    summary=None,
    metadata=None,
):
    event_id = new_event_id("agent")
    started = utc_now_iso()
    log_path = _log_path(work_dir, event_id)
    proxy_log_path = log_path.replace("_harness.log", "_proxy.jsonl")
    command = command_with_json_events(command)
    proc, log_thread, stdin_thread = _start_process(
        proj_dir, command, log_path, proxy_log_path
    )
    return TracedAgentProcess(
        proc=proc,
        work_dir=work_dir,
        event_id=event_id,
        stage=stage,
        started=started,
        command=command,
        function_ids=function_ids,
        input_files=input_files,
        output_files=output_files,
        summary=summary,
        metadata=metadata,
        log_path=log_path,
        proxy_log_path=proxy_log_path,
        log_thread=log_thread,
        stdin_thread=stdin_thread,
    )


def wait_agent_traced(record, timeout_seconds=AGENT_TIMEOUT_SECONDS):
    exit_code, error = _wait_process(
        record.proc,
        record.command,
        record.stage,
        timeout_seconds=timeout_seconds,
    )
    if error:
        record.error = error
    return exit_code


def finish_agent_trace(record):
    if record.stdin_thread:
        record.stdin_thread.join()
    if record.log_thread:
        record.log_thread.join()
    exit_code = record.proc.returncode
    status = "error" if record.error or exit_code != 0 else "success"
    record_agent_call(
        work_dir=record.work_dir,
        event_id=record.event_id,
        stage=record.stage,
        status=status,
        started=record.started,
        ended=utc_now_iso(),
        command=record.command,
        function_ids=record.function_ids,
        input_files=record.input_files,
        output_files=record.output_files,
        exit_code=exit_code,
        summary=record.summary,
        error=record.error,
        metadata=record.metadata,
        log_path=record.log_path,
        proxy_log_path=record.proxy_log_path,
    )

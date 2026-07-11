import logging
import os
import subprocess
import threading
from dataclasses import dataclass

from config import OPENCODE_TIMEOUT_SECONDS
from .cli_backend import command_argv, command_display, command_stdin
from .trace_writer import (
    new_event_id,
    record_trace_event,
    utc_now_iso,
)


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
class TracedOpenCodeProcess:
    proc: subprocess.Popen
    work_dir: str
    event_id: str
    stage: str
    started: str
    command: list
    function_ids: list | None = None
    input_files: list | None = None
    output_files: list | None = None
    summary: str | None = None
    metadata: dict | None = None
    opencode_log_path: str | None = None
    opencode_trace_path: str | None = None
    log_thread: threading.Thread | None = None
    stdin_thread: threading.Thread | None = None
    error: str | None = None


def _trace_dir(work_dir):
    return os.path.join(work_dir, "trace")


def _payload_dir(trace_dir):
    path = os.path.join(trace_dir, "payloads")
    os.makedirs(path, exist_ok=True)
    return path


def _payload_ref(trace_dir, path):
    return os.path.relpath(path, os.path.dirname(trace_dir))


def _opencode_log_path(work_dir, event_id):
    return os.path.join(_payload_dir(_trace_dir(work_dir)), f"{event_id}_opencode.log")


def _opencode_trace_path(work_dir, event_id):
    return os.path.join(_trace_dir(work_dir), "opencode", f"{event_id}.jsonl")


def _opencode_env(work_dir, event_id):
    env = os.environ.copy()
    trace_dir = os.path.abspath(os.path.join(_trace_dir(work_dir), "opencode"))
    os.makedirs(trace_dir, exist_ok=True)
    env["TRACE_DIR"] = trace_dir
    env["TRACE_FILENAME"] = event_id
    # subprocess.Popen(cwd=...) chdirs the child but doesn't sync PWD; opencode
    # walks PWD upward looking for AGENTS.md, so without this it picks up the
    # fm-agent repo's own AGENTS.md instead of the target's, baking ~10K bytes
    # of repo docs into every system prompt and invalidating the cache prefix
    # on every edit.
    proj_dir = os.path.dirname(os.path.abspath(work_dir))
    env["PWD"] = proj_dir
    return env


def _copy_opencode_output(stream, trace_log_path=None):
    trace_log = None
    try:
        if trace_log_path:
            trace_log = open(trace_log_path, "w", encoding="utf-8", errors="replace")
        for chunk in iter(lambda: stream.read(4096), ""):
            if not chunk:
                break
            if trace_log:
                trace_log.write(chunk)
                trace_log.flush()
    finally:
        if trace_log:
            trace_log.close()
    stream.close()


def _write_command_stdin(stream, text):
    try:
        stream.write(text)
        stream.flush()
    finally:
        stream.close()


def _start_opencode_process(proj_dir, work_dir, event_id, command, trace_log_path):
    stdin_text = command_stdin(command)
    proc = subprocess.Popen(
        command_argv(command),
        cwd=proj_dir,
        env=_opencode_env(work_dir, event_id),
        stdin=subprocess.PIPE if stdin_text is not None else None,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    stdin_thread = None
    if stdin_text is not None:
        stdin_thread = threading.Thread(
            target=_write_command_stdin,
            args=(proc.stdin, stdin_text),
            daemon=True,
        )
        stdin_thread.start()
    log_thread = threading.Thread(
        target=_copy_opencode_output,
        args=(proc.stdout, trace_log_path),
        daemon=True,
    )
    log_thread.start()
    return proc, log_thread, stdin_thread


def _wait_opencode_process(proc, command, stage, timeout_seconds=OPENCODE_TIMEOUT_SECONDS):
    try:
        return proc.wait(timeout=timeout_seconds), None
    except subprocess.TimeoutExpired:
        # A model connection that dies silently (e.g. through a forward proxy)
        # leaves opencode waiting forever. Kill it so callers' retry paths can
        # take over instead of the whole pipeline hanging.
        logging.warning(
            "opencode %s timed out after %ss, killing: %s",
            stage, timeout_seconds, command_display(command),
        )
        proc.terminate()
        try:
            exit_code = proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
            exit_code = proc.wait()
        if not exit_code:
            exit_code = -15  # killed-on-timeout must never record as success
        return exit_code, f"timeout after {timeout_seconds}s"


def record_opencode_call(
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
    opencode_log_path=None,
    opencode_trace_path=None,
):
    trace_dir = _trace_dir(work_dir)
    children = []

    if opencode_log_path and os.path.exists(opencode_log_path):
        opencode_log_ref = _payload_ref(trace_dir, opencode_log_path)
        children.append(
            {
                "type": "tool_output",
                "label": "opencode-stdout",
                "path": opencode_log_ref,
                "content_ref": opencode_log_ref,
            }
        )
    if opencode_trace_path and os.path.exists(opencode_trace_path):
        opencode_trace_ref = _payload_ref(trace_dir, opencode_trace_path)
        children.append(
            {
                "type": "tool_output",
                "label": "opencode-llm-jsonl",
                "path": opencode_trace_ref,
                "content_ref": opencode_trace_ref,
            }
        )
    record_trace_event(trace_dir, {
        "event_id": event_id,
        "type": "opencode_call",
        "stage": stage,
        "status": status,
        "start_time": started,
        "end_time": ended,
        "summary": summary or f"OpenCode {stage}",
        "function_ids": function_ids or [],
        "children": children,
        "metadata": {
            "command": command_argv(command),
            "exit_code": exit_code,
            "input_files": input_files or [],
            "output_files": output_files or [],
            "error": error,
            **(metadata or {}),
            "command_display": command_display(command),
        },
    })


def run_opencode_traced(
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
    event_id = new_event_id("opencode")
    started = utc_now_iso()
    exit_code = 0
    error = None
    opencode_log_path = _opencode_log_path(work_dir, event_id)
    opencode_trace_path = _opencode_trace_path(work_dir, event_id)
    log_thread = None
    stdin_thread = None
    try:
        proc, log_thread, stdin_thread = _start_opencode_process(proj_dir, work_dir, event_id, command, opencode_log_path)
        exit_code, error = _wait_opencode_process(proc, command, stage)
        if error:
            raise subprocess.CalledProcessError(exit_code, command_argv(command))
        if log_thread:
            log_thread.join()
        if stdin_thread:
            stdin_thread.join()
        if exit_code != 0:
            raise subprocess.CalledProcessError(exit_code, command_argv(command))
        return subprocess.CompletedProcess(command_argv(command), exit_code)
    except subprocess.CalledProcessError as exc:
        exit_code = exc.returncode
        error = error or str(exc)
        raise
    finally:
        if log_thread and log_thread.is_alive():
            log_thread.join()
        if stdin_thread and stdin_thread.is_alive():
            stdin_thread.join()
        record_opencode_call(
            work_dir=work_dir,
            event_id=event_id,
            stage=stage,
            status="success" if exit_code == 0 else "error",
            started=started,
            ended=utc_now_iso(),
            command=command,
            function_ids=function_ids,
            input_files=input_files,
            output_files=output_files,
            exit_code=exit_code,
            summary=summary,
            error=error,
            metadata=metadata,
            opencode_log_path=opencode_log_path,
            opencode_trace_path=opencode_trace_path,
        )


def start_opencode_traced(
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
    event_id = new_event_id("opencode")
    started = utc_now_iso()
    opencode_log_path = _opencode_log_path(work_dir, event_id)
    opencode_trace_path = _opencode_trace_path(work_dir, event_id)
    proc, log_thread, stdin_thread = _start_opencode_process(proj_dir, work_dir, event_id, command, opencode_log_path)
    return TracedOpenCodeProcess(
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
        opencode_log_path=opencode_log_path,
        opencode_trace_path=opencode_trace_path,
        log_thread=log_thread,
        stdin_thread=stdin_thread,
    )


def wait_opencode_traced(record, timeout_seconds=OPENCODE_TIMEOUT_SECONDS):
    exit_code, error = _wait_opencode_process(
        record.proc,
        record.command,
        record.stage,
        timeout_seconds=timeout_seconds,
    )
    if error or record.error is None:
        record.error = error
    return exit_code


def finish_opencode_trace(record):
    if record.stdin_thread:
        record.stdin_thread.join()
    if record.log_thread:
        record.log_thread.join()
    status = "error" if record.error or record.proc.returncode != 0 else "success"
    record_opencode_call(
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
        exit_code=record.proc.returncode,
        summary=record.summary,
        error=record.error,
        metadata=record.metadata,
        opencode_log_path=record.opencode_log_path,
        opencode_trace_path=record.opencode_trace_path,
    )

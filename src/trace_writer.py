import json
import os
import threading
import uuid
from datetime import datetime, timezone


_LOCK = threading.Lock()


def utc_now_iso():
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def new_event_id(prefix="evt"):
    return f"{prefix}_{uuid.uuid4().hex}"


def _ensure_trace_dirs(trace_dir):
    payload_dir = os.path.join(trace_dir, "payloads")
    os.makedirs(payload_dir, exist_ok=True)
    return payload_dir


def write_payload(trace_dir, event_id, name, content, binary=False):
    payload_dir = _ensure_trace_dirs(trace_dir)
    path = os.path.join(payload_dir, f"{event_id}_{name}")
    tmp_path = path + ".tmp"
    mode = "wb" if binary else "w"
    kwargs = {} if binary else {"encoding": "utf-8"}
    with open(tmp_path, mode, **kwargs) as f:
        f.write(content)
    os.replace(tmp_path, path)
    return os.path.relpath(path, os.path.dirname(trace_dir))


def append_event(trace_dir, event):
    _ensure_trace_dirs(trace_dir)
    events_path = os.path.join(trace_dir, "events.jsonl")
    line = json.dumps(event, ensure_ascii=False)
    with _LOCK:
        with open(events_path, "a", encoding="utf-8") as f:
            f.write(line + "\n")


def record_llm_exchange(trace_dir, event_id, event, messages, response=None):
    if not trace_dir:
        return

    children = []
    metadata = event.setdefault("metadata", {})
    for idx, message in enumerate(messages):
        role = message.get("role", "message")
        filename = f"message_{idx:02d}_{role}.txt"
        if role == "system":
            item_type = "system_prompt"
        elif role == "user":
            item_type = "user_prompt"
        elif role == "assistant":
            item_type = "assistant_output"
        else:
            item_type = "message"
        children.append(
            {
                "type": item_type,
                "role": role,
                "content_ref": write_payload(
                    trace_dir,
                    event_id,
                    filename,
                    message.get("content", ""),
                ),
            }
        )
    if response is not None:
        children.append(
            {
                "type": "assistant_output",
                "content_ref": write_payload(trace_dir, event_id, "response.txt", response),
            }
        )
    metadata.pop("parsed", None)
    event["children"] = children
    record_trace_event(trace_dir, event)


def record_trace_event(trace_dir, event):
    if not trace_dir:
        return
    append_event(trace_dir, event)

import io
import json
from datetime import datetime, timezone

import zstandard


class DshTraceReader:
    def __init__(self, root):
        self.root = root
        self._revisions = {}
        self._seen = set()

    def read_new(self, session_id=None):
        records = []
        pattern = f"{session_id}/session.v4.jsonl*" if session_id else "session.v4.jsonl*"
        for path in sorted(self.root.rglob(pattern)):
            if path.name not in {"session.v4.jsonl", "session.v4.jsonl.zstd"}:
                continue
            stat = path.stat()
            revision = (stat.st_ino, stat.st_size, stat.st_mtime_ns)
            if self._revisions.get(path) == revision:
                continue
            with path.open("rb") as raw:
                stream = zstandard.ZstdDecompressor().stream_reader(raw) if path.suffix == ".zstd" else raw
                with io.BufferedReader(stream) as lines:
                    header_line = lines.readline()
                    if not header_line.endswith(b"\n"):
                        continue
                    header = json.loads(header_line)
                    seeded = header.get("isSeeded", False)
                    for line in lines:
                        if not line.endswith(b"\n"):
                            break
                        record = json.loads(line)
                        if record.get("type") == "session/end-seed":
                            seeded = False
                        key = (header["id"], record["seq"])
                        if seeded or key in self._seen:
                            continue
                        if record.get("type") not in {"assistant/message", "assistant/attempt", "session/title-llm-request"}:
                            continue
                        data = record["data"]
                        usage = data.get("usage") or next((
                            entry["chunk"]["usage"] for entry in reversed(data.get("stream", []))
                            if entry.get("type") == "chunk" and entry["chunk"].get("type") == "usage"
                        ), {})
                        self._seen.add(key)
                        source = data.get("message", {}).get("source", {})
                        records.append({
                            "session_id": header["id"], "trace_path": str(path),
                            "type": record["type"], "usage_complete": bool(usage),
                            "model": source.get("model"),
                            "time": datetime.fromtimestamp(record["time"] / 1000, timezone.utc),
                            "usage": {
                                "input_tokens": usage.get("inputTokens", 0),
                                "output_tokens": usage.get("outputTokens", 0),
                                "cache_read_input_tokens": usage.get("cacheReadTokens", 0),
                                "cache_creation_input_tokens": usage.get("cacheWriteTokens", 0),
                            },
                        })
            self._revisions[path] = revision
        yield from sorted(records, key=lambda record: record["time"])

import io
import json
from datetime import datetime, timezone

import zstandard


class DshTraceReader:
    def __init__(self, root):
        self.root = root
        self._revisions = {}
        self._seen = set()

    def read_new(self):
        records = []
        for path in sorted(self.root.rglob("session.v4.jsonl*")):
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
                        if record.get("type") != "assistant/message":
                            continue
                        data = record["data"]
                        usage = data.get("usage")
                        if not usage:
                            continue
                        self._seen.add(key)
                        source = data.get("message", {}).get("source", {})
                        records.append({
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

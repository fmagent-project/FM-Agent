from __future__ import annotations

import codecs
import hashlib
import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any


SOURCE_EXTENSIONS = {
    ".c", ".cc", ".cpp", ".cxx", ".h", ".hpp", ".cu", ".cuh",
    ".py", ".java", ".go", ".rs", ".erl", ".cs", ".kt", ".kts",
    ".swift", ".php", ".rb", ".scala", ".sc", ".dart", ".js", ".mjs",
    ".cjs", ".jsx", ".ts", ".mts", ".cts", ".tsx", ".ets",
}


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def json_dumps(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"))


def atomic_write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    os.replace(temporary, path)


def safe_relative_path(raw: str) -> str:
    value = str(raw or "").replace("\\", "/").strip()
    if not value or "\x00" in value:
        raise ValueError("文件路径不能为空")
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise ValueError(f"不安全的相对路径：{raw}")
    if len(value) > 1024:
        raise ValueError("文件路径过长")
    return path.as_posix()


def safe_leaf_name(raw: str, fallback: str) -> str:
    value = str(raw or "").strip().replace("\\", "/").split("/")[-1]
    value = re.sub(r"[\x00-\x1f<>:\"|?*]", "_", value).strip(" .")
    return (value or fallback)[:160]


def task_paths(tasks_dir: Path, task_id: str) -> dict[str, Path]:
    root = tasks_dir / task_id
    return {
        "root": root,
        "project": root / "project",
        "materials": root / "materials",
        "requirements": root / "requirements",
        "requirement_sources": root / "requirements" / "source",
        "requirement_draft": root / "requirements" / "design-intent-draft.md",
        "requirement_meta": root / "requirements" / "preprocess-result.json",
        "domain_sources": root / "requirements" / "domain-source",
        "intent_sources": root / "requirements" / "intent-source",
        "domain_draft": root / "requirements" / "domain-spec-draft.md",
        "domain_meta": root / "requirements" / "domain-preprocess-result.json",
        "runtime": root / "runtime",
        "reports": root / "reports",
        "manifest": root / "source-manifest.json",
        "log": root / "runtime" / "verification.log",
    }


def issue_fingerprint(source_file: str, function_name: str, gap: dict[str, Any]) -> str:
    normalized = {
        "source_file": source_file,
        "function_name": function_name,
        "spec_claim": str(gap.get("spec_claim") or "").strip(),
        "actual_behavior": str(gap.get("actual_behavior") or "").strip(),
        "code_evidence": str(gap.get("code_evidence") or "").strip(),
        "trigger_condition": str(gap.get("trigger_condition") or "").strip(),
    }
    return hashlib.sha256(json_dumps(normalized).encode("utf-8")).hexdigest()


def is_probably_text(data: bytes) -> bool:
    return detect_text_encoding(data) is not None


def detect_text_encoding(data: bytes) -> str | None:
    """Detect common source encodings without relying on network-installed models."""
    if not data:
        return "UTF-8"
    if data.startswith(codecs.BOM_UTF8):
        return "UTF-8 BOM"
    if data.startswith((codecs.BOM_UTF16_LE, codecs.BOM_UTF16_BE)):
        try:
            data.decode("utf-16")
            return "UTF-16"
        except UnicodeDecodeError:
            return None
    sample = data[:8192]
    if b"\x00" in sample:
        return None
    control = sum(byte < 32 and byte not in {9, 10, 13} for byte in sample)
    if control / len(sample) >= 0.03:
        return None
    for encoding, label in (
        ("utf-8", "UTF-8"),
        ("gb2312", "GB2312"),
        ("gb18030", "GB18030"),
    ):
        try:
            data.decode(encoding)
            return label
        except UnicodeDecodeError:
            continue
    # Preserve the previous permissive text handling for uncommon legacy encodings.
    return "未知编码"


def decode_text(data: bytes) -> tuple[str, str]:
    encoding = detect_text_encoding(data)
    if encoding is None:
        raise UnicodeDecodeError("text", data, 0, min(1, len(data)), "binary data")
    codecs_by_label = {
        "UTF-8": "utf-8",
        "UTF-8 BOM": "utf-8-sig",
        "UTF-16": "utf-16",
        "GB2312": "gb2312",
        "GB18030": "gb18030",
    }
    codec = codecs_by_label.get(encoding)
    if codec:
        return data.decode(codec), encoding
    return data.decode("utf-8", errors="replace"), encoding

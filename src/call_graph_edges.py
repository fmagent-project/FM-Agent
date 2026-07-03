"""Supplemental caller/callee edge parsing for call-graph construction.

The only supported on-disk format is JSON using this schema:

{
  "schema": "fm-agent-extra-edges-v1",
  "edges": [
    {
      "caller": "nanosleep",
      "callee": "SysNanoSleep",
      "caller_aliases": ["SYS_nanosleep"],
      "callee_aliases": ["__NR_nanosleep", "SYS_nanosleep", "nanosleep"],
      "evidence": ["third_party/musl/src/time/clock_nanosleep.c:33"]
    }
  ]
}

Only ``caller`` and ``callee`` are required. Metadata fields such as ``kind``,
``syscall``, and ``syscall_nr`` may be present, but the graph builder only uses
the endpoints, aliases, and evidence/source text.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Iterable


SCHEMA = "fm-agent-extra-edges-v1"


@dataclass(frozen=True)
class CallEdge:
    """A user-supplied directed call edge from caller to callee."""

    caller: str
    callee: str
    source: str = ""
    caller_aliases: tuple[str, ...] = ()
    callee_aliases: tuple[str, ...] = ()


def default_call_edges_path(cwd: str | os.PathLike | None = None) -> str | None:
    """Return the default ./docs/extra-edge path when it exists."""
    path = Path(cwd or os.getcwd()) / "docs" / "extra-edge"
    return str(path) if path.exists() else None


def load_call_edges(path: str | os.PathLike | None) -> list[CallEdge]:
    """Load supplemental call edges from a schema-v1 JSON file or directory."""
    if path is None:
        return []

    edge_path = Path(path)
    if edge_path.is_dir():
        edges = []
        for file_path in sorted(edge_path.rglob("*")):
            if file_path.is_file() and _is_edge_file(file_path):
                edges.extend(_load_call_edge_file(file_path))
        return _dedupe_edges(edges)

    return _dedupe_edges(_load_call_edge_file(edge_path))


def _is_edge_file(path: Path) -> bool:
    return path.name == "extra-edge" or path.suffix.lower() == ".json"


def _load_call_edge_file(edge_path: Path) -> list[CallEdge]:
    text = edge_path.read_text(errors="replace")
    if not text.strip():
        return []
    return _load_json_edges(text, str(edge_path))


def _load_json_edges(text: str, source_path: str) -> list[CallEdge]:
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ValueError(f"{source_path}: invalid JSON: {exc}") from exc

    if not isinstance(data, dict):
        raise ValueError(f"{source_path}: expected JSON object")
    if data.get("schema") != SCHEMA:
        raise ValueError(f"{source_path}: expected schema {SCHEMA!r}")
    if not isinstance(data.get("edges"), list):
        raise ValueError(f"{source_path}: expected an 'edges' list")

    edges = []
    for idx, item in enumerate(data["edges"], start=1):
        item_source = f"{source_path}:edges[{idx}]"
        if not isinstance(item, dict):
            raise ValueError(f"{item_source}: expected edge object")
        edges.append(_edge_from_mapping(item, item_source))
    return edges


def _edge_from_mapping(item: dict, source: str) -> CallEdge:
    caller = item.get("caller")
    callee = item.get("callee")
    if not isinstance(caller, str) or not caller.strip():
        raise ValueError(f"{source}: missing non-empty string 'caller'")
    if not isinstance(callee, str) or not callee.strip():
        raise ValueError(f"{source}: missing non-empty string 'callee'")

    evidence_source = _edge_source(item, source)
    return _edge(
        caller,
        callee,
        evidence_source,
        caller_aliases=_string_list(item.get("caller_aliases"), "caller_aliases", source),
        callee_aliases=_string_list(item.get("callee_aliases"), "callee_aliases", source),
    )


def _edge_source(item: dict, fallback: str) -> str:
    source = item.get("source")
    if isinstance(source, str) and source.strip():
        return source.strip()

    evidence = item.get("evidence")
    if isinstance(evidence, list):
        values = [str(value).strip() for value in evidence if str(value).strip()]
        if values:
            return "; ".join(values[:4])
    if isinstance(evidence, str) and evidence.strip():
        return evidence.strip()
    return fallback


def _string_list(value, key: str, source: str) -> tuple[str, ...]:
    if value is None:
        return ()
    if not isinstance(value, list):
        raise ValueError(f"{source}: {key} must be a list of strings")
    out = []
    for idx, item in enumerate(value, start=1):
        if not isinstance(item, str):
            raise ValueError(f"{source}: {key}[{idx}] must be a string")
        if item.strip():
            out.append(item.strip())
    return tuple(out)


def _edge(
    caller,
    callee,
    source: str,
    caller_aliases: Iterable[str] = (),
    callee_aliases: Iterable[str] = (),
) -> CallEdge:
    raw_caller = _clean_label(caller)
    raw_callee = _clean_label(callee)
    caller_s = _normalize_endpoint_label(raw_caller)
    callee_s = _normalize_endpoint_label(raw_callee)
    if not caller_s or not callee_s:
        raise ValueError(f"{source}: caller and callee must be non-empty")
    return CallEdge(
        caller=caller_s,
        callee=callee_s,
        source=source,
        caller_aliases=_endpoint_aliases(raw_caller, caller_s, *caller_aliases),
        callee_aliases=_endpoint_aliases(raw_callee, callee_s, *callee_aliases),
    )


def _normalize_endpoint_label(label: str) -> str:
    label = _clean_label(label)
    if _is_path_function_label(label):
        path, func = label.rsplit("::", 1)
        path = path.lstrip("./")
        src_path = PurePosixPath(path)
        base = src_path.name
        last_dot = base.rfind(".")
        func_dir = base[:last_dot] + "-" + base[last_dot + 1:] if last_dot > 0 else base
        parts = [p for p in src_path.parent.parts if p not in {"", "."}]
        return "::".join([*parts, func_dir, func])
    return label


def _endpoint_aliases(*labels) -> tuple[str, ...]:
    aliases = []
    seen = set()
    for raw in labels:
        if raw is None:
            continue
        label = _clean_label(raw)
        normalized = _normalize_endpoint_label(label)
        for item in (label, normalized, _last_component(label), _last_component(normalized)):
            _append_alias(aliases, seen, item)
        for item in _syscall_aliases(label):
            _append_alias(aliases, seen, item)
    return tuple(aliases)


def _append_alias(aliases: list[str], seen: set[str], value: str | None) -> None:
    if value and value not in seen:
        aliases.append(value)
        seen.add(value)


def _syscall_aliases(value) -> tuple[str, ...]:
    text = _clean_label(value)
    if text.startswith("syscall-number::"):
        text = text[len("syscall-number::"):]
    if not text.startswith("__NR_"):
        return ()

    name = text[len("__NR_"):]
    aliases = [text, f"SYS_{name}", name]
    if name.startswith("rt_"):
        aliases.append(name[len("rt_"):])
    return tuple(dict.fromkeys(aliases))


def _clean_label(value) -> str:
    text = str(value).strip()
    if not text:
        return ""
    text = text.rstrip(";").strip()
    if len(text) >= 2 and text[0] == text[-1] and text[0] in {"'", '"'}:
        text = text[1:-1]
    return text.strip()


def _last_component(label: str) -> str:
    text = _clean_label(label)
    if "::" in text:
        return text.rsplit("::", 1)[-1]
    return PurePosixPath(text).name


def _is_path_function_label(label: str) -> bool:
    if "::" not in label:
        return False
    path, _func = label.rsplit("::", 1)
    return "/" in path and "." in PurePosixPath(path).name


def _dedupe_edges(edges: Iterable[CallEdge]) -> list[CallEdge]:
    merged = {}
    for edge in edges:
        key = (edge.caller, edge.callee)
        if key not in merged:
            merged[key] = {
                "source": edge.source,
                "caller_aliases": set(edge.caller_aliases),
                "callee_aliases": set(edge.callee_aliases),
            }
            continue
        merged[key]["caller_aliases"].update(edge.caller_aliases)
        merged[key]["callee_aliases"].update(edge.callee_aliases)

    result = []
    for (caller, callee), data in sorted(merged.items()):
        result.append(
            CallEdge(
                caller=caller,
                callee=callee,
                source=data["source"],
                caller_aliases=tuple(sorted(data["caller_aliases"])),
                callee_aliases=tuple(sorted(data["callee_aliases"])),
            )
        )
    return result

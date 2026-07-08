"""Supplemental caller/callee edge parsing for call-graph construction.

The on-disk extra-edge format is JSON with an ``edges`` list:

{
  "edges": [
    {
      "caller": {
        "fqn": "third_party::musl::src::time::nanosleep-c::nanosleep",
        "callsite_names": ["nanosleep"]
      },
      "callee": {
        "fqn": "kernel::liteos_a::syscall::time_syscall-c::SysNanoSleep",
        "info_names": ["__NR_nanosleep", "SYS_nanosleep", "nanosleep"]
      },
      "evidence": [
        "third_party/musl/src/time/nanosleep.c:6 calls __clock_nanosleep",
        "kernel/liteos_a/syscall/syscall_lookup.h:181 maps __NR_nanosleep to SysNanoSleep"
      ]
    }
  ]
}

``caller.fqn`` selects one exact caller function. It is either an FM-Agent FQN
or a ``path/to/file.c::func`` label that can be normalized to one. It may be
omitted or empty. No short-name fallback is performed.

``caller.callsite_names`` selects caller functions by source callsite tokens.
Every function that contains one of these callsites gets a supplemental edge to
``callee.fqn``.

``callee.info_names`` is only metadata for matching generated [INFO] entries.
It is never used for source callsite scanning.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Iterable


@dataclass(frozen=True)
class CallerSelector:
    """How a supplemental edge selects its caller side."""

    fqn: str
    callsite_names: tuple[str, ...]


@dataclass(frozen=True)
class CalleeTarget:
    """The concrete callee FQN plus names callers may use in [INFO]."""

    fqn: str
    info_names: tuple[str, ...]


@dataclass(frozen=True)
class CallEdge:
    """A user-supplied supplemental call edge selector."""

    caller: CallerSelector
    callee: CalleeTarget
    source: str = ""


def load_call_edges(path: str | os.PathLike | None) -> list[CallEdge]:
    """Load supplemental call edges from a JSON file or directory."""
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


def normalize_fqn_label(label: str) -> str:
    """Normalize ``path/to/file.c::func`` into an FM-Agent FQN when needed."""
    return _normalize_endpoint_label(label)


def _is_edge_file(path: Path) -> bool:
    return path.suffix.lower() == ".json"


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
        raise ValueError(f"{source_path}: expected JSON object with an 'edges' list")
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
    caller = _parse_caller(item.get("caller"), source)
    callee = _parse_callee(item.get("callee"), source)
    return CallEdge(
        caller=caller,
        callee=callee,
        source=_edge_source(item, source),
    )


def _parse_caller(value, source: str) -> CallerSelector:
    if not isinstance(value, dict):
        raise ValueError(f"{source}: missing object 'caller'")

    fqn = _optional_string(value.get("fqn", ""), "caller.fqn", source)
    if fqn:
        fqn = normalize_fqn_label(fqn)
    callsite_names = _string_list(
        value.get("callsite_names", []), "caller.callsite_names", source
    )

    if not fqn and not callsite_names:
        raise ValueError(
            f"{source}: at least one of 'caller.fqn' or "
            "'caller.callsite_names' must be non-empty"
        )

    return CallerSelector(fqn=fqn, callsite_names=callsite_names)


def _parse_callee(value, source: str) -> CalleeTarget:
    if not isinstance(value, dict):
        raise ValueError(f"{source}: missing object 'callee'")

    fqn = _required_string(value.get("fqn"), "callee.fqn", source)
    info_names = _string_list(value.get("info_names", []), "callee.info_names", source)
    return CalleeTarget(fqn=fqn, info_names=info_names)


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


def _required_string(value, key: str, source: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{source}: missing non-empty string '{key}'")
    return _clean_label(value)


def _optional_string(value, key: str, source: str) -> str:
    if value is None:
        return ""
    if not isinstance(value, str):
        raise ValueError(f"{source}: '{key}' must be a string")
    return _clean_label(value)


def _string_list(value, key: str, source: str) -> tuple[str, ...]:
    if not isinstance(value, list):
        raise ValueError(f"{source}: '{key}' must be a string array")
    out = []
    for idx, item in enumerate(value, start=1):
        if not isinstance(item, str):
            raise ValueError(f"{source}: {key}[{idx}] must be a string")
        label = _clean_label(item)
        if label:
            out.append(label)
    return tuple(out)


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


def _clean_label(value) -> str:
    text = str(value).strip()
    if not text:
        return ""
    text = text.rstrip(";").strip()
    if len(text) >= 2 and text[0] == text[-1] and text[0] in {"'", '"'}:
        text = text[1:-1]
    return text.strip()


def _is_path_function_label(label: str) -> bool:
    if "::" not in label:
        return False
    path, _func = label.rsplit("::", 1)
    return "/" in path and "." in PurePosixPath(path).name


def _dedupe_edges(edges: Iterable[CallEdge]) -> list[CallEdge]:
    merged = {}
    for edge in edges:
        key = (
            edge.caller.fqn,
            edge.callee.fqn,
        )
        if key not in merged:
            merged[key] = {
                "fqn": edge.caller.fqn,
                "callsite_names": list(edge.caller.callsite_names),
                "source": edge.source,
                "info_names": list(edge.callee.info_names),
            }
            continue
        for name in edge.caller.callsite_names:
            if name not in merged[key]["callsite_names"]:
                merged[key]["callsite_names"].append(name)
        for name in edge.callee.info_names:
            if name not in merged[key]["info_names"]:
                merged[key]["info_names"].append(name)

    result = []
    for (_caller_fqn, callee_fqn), data in sorted(merged.items()):
        result.append(
            CallEdge(
                caller=CallerSelector(
                    fqn=data["fqn"],
                    callsite_names=tuple(data["callsite_names"]),
                ),
                callee=CalleeTarget(
                    fqn=callee_fqn,
                    info_names=tuple(data["info_names"]),
                ),
                source=data["source"],
            )
        )
    return result

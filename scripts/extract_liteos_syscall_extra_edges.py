#!/usr/bin/env python3
"""Extract compact LiteOS-A syscall bridge edges for FM-Agent.

The output is a single JSON file in the format consumed by
``src.call_graph_edges``:

{
  "schema": "fm-agent-extra-edges-v1",
  "edges": [
    {
      "caller": "nanosleep",
      "callee": "SysNanoSleep",
      "caller_aliases": ["src/time/nanosleep.c::nanosleep"],
      "callee_aliases": ["__NR_nanosleep", "SYS_nanosleep", "nanosleep"],
      "kind": "liteos-syscall-bridge",
      "evidence": [
        "third_party/musl/src/time/nanosleep.c:6 calls __clock_nanosleep",
        "third_party/musl/src/time/clock_nanosleep.c:33 uses SYS_nanosleep",
        "syscall/syscall_lookup.h:181 maps __NR_nanosleep to SysNanoSleep"
      ],
      "syscall": "__NR_nanosleep"
    }
  ]
}

Each edge is intentionally direct: user-facing libc API -> kernel syscall
handler. The syscall number is kept as edge metadata/aliases, not as a separate
node list, because FM-Agent needs a resolvable function callee.
"""

from __future__ import annotations

import argparse
import json
import re
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Iterator, Sequence


SCHEMA = "fm-agent-extra-edges-v1"
DEFAULT_KERNEL_ROOT = Path("/mnt/nvme2/lianganran/kernel_liteos_a")
C_SUFFIXES = {".c", ".cc", ".cpp", ".h"}
SYSCALL_CALL_NAMES = ("__syscall", "syscall", "syscall_cp", "__syscall_cp")
CALL_KEYWORDS = {
    "case",
    "defined",
    "do",
    "for",
    "if",
    "return",
    "sizeof",
    "switch",
    "while",
}


@dataclass(frozen=True)
class FunctionDef:
    name: str
    path: str
    body_line: int
    body: str


@dataclass(frozen=True)
class SyscallDef:
    syscall: str
    handler: str
    evidence: str
    condition: str | None = None


FUNC_DEF_RE = re.compile(
    r"(?m)^[A-Za-z_][\w\s\*\(\),\[\]]*?\b(?P<name>[A-Za-z_]\w*)\s*"
    r"\([^;{}]*\)\s*\{",
    re.DOTALL,
)


def repo_rel(path: Path, root: Path) -> str:
    try:
        return str(path.resolve().relative_to(root.resolve()))
    except ValueError:
        return str(path.resolve())


def loc(path: Path, line: int, root: Path) -> str:
    return f"{repo_rel(path, root)}:{line}"


def read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return ""


def iter_files(root: Path, suffixes: set[str], include_dirs: Sequence[str]) -> Iterator[Path]:
    root = root.resolve()
    for rel_dir in include_dirs:
        base = root / rel_dir
        if not base.exists():
            continue
        for path in base.rglob("*"):
            if path.is_file() and path.suffix in suffixes:
                yield path


def line_for_offset(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def split_args(arg_text: str) -> list[str]:
    args = []
    start = 0
    depth = 0
    in_str = None
    escape = False
    for i, ch in enumerate(arg_text):
        if in_str:
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == in_str:
                in_str = None
            continue
        if ch in ('"', "'"):
            in_str = ch
        elif ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth = max(0, depth - 1)
        elif ch == "," and depth == 0:
            args.append(arg_text[start:i].strip())
            start = i + 1
    tail = arg_text[start:].strip()
    if tail:
        args.append(tail)
    return args


def find_matching_paren(text: str, open_pos: int) -> int:
    depth = 0
    in_str = None
    escape = False
    for i in range(open_pos, len(text)):
        ch = text[i]
        if in_str:
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == in_str:
                in_str = None
            continue
        if ch in ('"', "'"):
            in_str = ch
        elif ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0:
                return i
    return -1


def find_matching_brace(text: str, open_pos: int) -> int:
    depth = 0
    in_str = None
    escape = False
    in_line_comment = False
    in_block_comment = False
    i = open_pos
    while i < len(text):
        ch = text[i]
        nxt = text[i + 1] if i + 1 < len(text) else ""
        if in_line_comment:
            if ch == "\n":
                in_line_comment = False
            i += 1
            continue
        if in_block_comment:
            if ch == "*" and nxt == "/":
                in_block_comment = False
                i += 2
            else:
                i += 1
            continue
        if in_str:
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == in_str:
                in_str = None
            i += 1
            continue
        if ch == "/" and nxt == "/":
            in_line_comment = True
            i += 2
            continue
        if ch == "/" and nxt == "*":
            in_block_comment = True
            i += 2
            continue
        if ch in ('"', "'"):
            in_str = ch
        elif ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return i
        i += 1
    return -1


def extract_functions(path: Path, root: Path) -> list[FunctionDef]:
    text = read_text(path)
    out = []
    for match in FUNC_DEF_RE.finditer(text):
        name = match.group("name")
        if name in CALL_KEYWORDS:
            continue
        brace = text.find("{", match.start(), match.end())
        end = find_matching_brace(text, brace)
        if brace < 0 or end < 0:
            continue
        out.append(
            FunctionDef(
                name=name,
                path=repo_rel(path, root),
                body_line=line_for_offset(text, brace + 1),
                body=text[brace + 1:end],
            )
        )
    return out


def build_function_index(root: Path, include_dirs: Sequence[str]) -> dict[str, list[FunctionDef]]:
    index = defaultdict(list)
    for path in iter_files(root, C_SUFFIXES, include_dirs):
        for fn in extract_functions(path, root):
            index[fn.name].append(fn)
    return dict(index)


def normalize_syscall_token(token: str) -> str:
    token = token.strip()
    if token.startswith("__NR_"):
        return token
    if token.startswith("SYS_"):
        return "__NR_" + token[len("SYS_"):]
    return token


def syscall_token_from_expr(expr: str) -> str | None:
    tokens = re.findall(r"\b(?:SYS|__NR)_[A-Za-z0-9_]+\b", expr)
    if not tokens:
        return None
    return normalize_syscall_token(tokens[0])


def parse_syscall_lookup(kernel_root: Path) -> dict[str, list[SyscallDef]]:
    path = kernel_root / "syscall/syscall_lookup.h"
    syscalls = defaultdict(list)
    conditions = []
    seen = set()
    for line_num, line in enumerate(read_text(path).splitlines(), start=1):
        stripped = line.strip()
        if stripped.startswith("#ifdef "):
            conditions.append(f"defined({stripped.split(None, 1)[1]})")
            continue
        if stripped.startswith("#ifndef "):
            conditions.append(f"!defined({stripped.split(None, 1)[1]})")
            continue
        if stripped.startswith("#if "):
            conditions.append(stripped[1:].strip())
            continue
        if stripped.startswith("#else"):
            if conditions:
                conditions[-1] = f"else({conditions[-1]})"
            continue
        if stripped.startswith("#endif"):
            if conditions:
                conditions.pop()
            continue

        match = re.search(r"SYSCALL_HAND_DEF\s*\(\s*([^,]+)\s*,\s*([^,]+)\s*,", line)
        if not match:
            continue
        syscall = match.group(1).strip()
        handler = match.group(2).strip()
        condition = " && ".join(conditions) if conditions else None
        key = (syscall, handler, condition)
        if key in seen:
            continue
        seen.add(key)
        syscalls[syscall].append(
            SyscallDef(
                syscall=syscall,
                handler=handler,
                evidence=f"{loc(path, line_num, kernel_root)} maps {syscall} to {handler}",
                condition=condition,
            )
        )
    return dict(syscalls)


def find_call_args(text: str, name: str) -> Iterator[tuple[int, list[str]]]:
    pattern = re.compile(rf"\b{re.escape(name)}\s*\(")
    for match in pattern.finditer(text):
        open_pos = text.find("(", match.start(), match.end())
        close_pos = find_matching_paren(text, open_pos)
        if close_pos < 0:
            continue
        yield match.start(), split_args(text[open_pos + 1:close_pos])


def collect_musl_syscall_uses(
    musl_funcs: dict[str, list[FunctionDef]],
    musl_root: Path,
    kernel_root: Path,
) -> tuple[dict[str, dict[str, tuple[str, ...]]], dict[str, set[str]]]:
    records: dict[str, dict[str, tuple[str, ...]]] = defaultdict(dict)
    function_names = set(musl_funcs)
    calls: dict[str, dict[str, set[str]]] = defaultdict(lambda: defaultdict(set))
    aliases = extract_musl_aliases(musl_root, kernel_root)
    call_re = re.compile(r"\b([A-Za-z_]\w*)\s*\(")

    for defs in musl_funcs.values():
        for fn in defs:
            path = musl_root / fn.path
            for call_name in SYSCALL_CALL_NAMES:
                for offset, args in find_call_args(fn.body, call_name):
                    if not args:
                        continue
                    syscall = syscall_token_from_expr(args[0])
                    if not syscall:
                        continue
                    line = fn.body_line + fn.body.count("\n", 0, offset)
                    add_record(
                        records,
                        fn.name,
                        syscall,
                        (f"{loc(path, line, kernel_root)} uses {args[0].strip()}",),
                    )

            for match in call_re.finditer(fn.body):
                callee = match.group(1)
                if callee in CALL_KEYWORDS or callee == fn.name or callee not in function_names:
                    continue
                line = fn.body_line + fn.body.count("\n", 0, match.start())
                calls[fn.name][callee].add(f"{loc(path, line, kernel_root)} calls {callee}")

    changed = True
    while changed:
        changed = False
        for caller, callees in calls.items():
            for callee, evidence_set in callees.items():
                for syscall, evidence in records.get(callee, {}).items():
                    for call_evidence in sorted(evidence_set):
                        if add_record(records, caller, syscall, (call_evidence, *evidence)):
                            changed = True
        for internal, public, evidence in aliases:
            for syscall, internal_evidence in records.get(internal, {}).items():
                if add_record(records, public, syscall, (evidence, *internal_evidence)):
                    changed = True

    public_aliases = defaultdict(set)
    for internal, public, _evidence in aliases:
        public_aliases[public].add(internal)
    return records, public_aliases


def extract_musl_aliases(musl_root: Path, kernel_root: Path) -> list[tuple[str, str, str]]:
    aliases = []
    for path in iter_files(musl_root, C_SUFFIXES, ("src", "porting/liteos_a/user")):
        for line_num, line in enumerate(read_text(path).splitlines(), start=1):
            for match in re.finditer(r"\b(?:weak_alias|strong_alias)\s*\(\s*([A-Za-z_]\w*)\s*,\s*([A-Za-z_]\w*)\s*\)", line):
                aliases.append(
                    (
                        match.group(1),
                        match.group(2),
                        f"{loc(path, line_num, kernel_root)} aliases {match.group(2)} to {match.group(1)}",
                    )
                )
    return aliases


def add_record(
    records: dict[str, dict[str, tuple[str, ...]]],
    function: str,
    syscall: str,
    evidence: tuple[str, ...],
) -> bool:
    current = records[function].get(syscall)
    if current is not None and len(current) <= len(evidence):
        return False
    records[function][syscall] = evidence
    return True


def syscall_api_name(syscall: str) -> str:
    name = syscall
    if name.startswith("__NR_"):
        name = name[len("__NR_"):]
    if name.startswith("SYS_"):
        name = name[len("SYS_"):]
    return name


def api_matches_syscall(api: str, syscall: str) -> bool:
    api_norm = normalize_api_name(api)
    syscall_name = syscall_api_name(syscall)
    candidates = {
        syscall_name,
        re.sub(r"_time(?:32|64)$", "", syscall_name),
    }
    if syscall_name.startswith("rt_"):
        candidates.add(syscall_name[len("rt_"):])
    return api_norm in {normalize_api_name(candidate) for candidate in candidates}


def normalize_api_name(value: str) -> str:
    value = value.lstrip("_")
    value = re.sub(r"(?:32|64)$", "", value)
    return re.sub(r"[^A-Za-z0-9]", "", value).lower()


def syscall_aliases(syscall: str, api: str) -> list[str]:
    name = syscall_api_name(syscall)
    aliases = [syscall, f"SYS_{name}", name, api]
    if name.startswith("rt_"):
        aliases.append(name[len("rt_"):])
    return list(dict.fromkeys(alias for alias in aliases if alias))


def build_edges(
    records: dict[str, dict[str, tuple[str, ...]]],
    public_aliases: dict[str, set[str]],
    syscalls: dict[str, list[SyscallDef]],
    apis: set[str] | None,
) -> list[dict[str, object]]:
    edges = []
    for api in sorted(records):
        if apis is not None and api not in apis:
            continue
        if apis is None and api.startswith("_"):
            continue
        caller_aliases = sorted({api, *public_aliases.get(api, set())})
        for syscall, evidence in sorted(records[api].items()):
            if not api_matches_syscall(api, syscall):
                continue
            for definition in syscalls.get(syscall, []):
                edge = {
                    "caller": api,
                    "callee": definition.handler,
                    "caller_aliases": caller_aliases,
                    "callee_aliases": syscall_aliases(syscall, api),
                    "kind": "liteos-syscall-bridge",
                    "evidence": [*evidence, definition.evidence],
                    "syscall": syscall,
                }
                if definition.condition:
                    edge["condition"] = definition.condition
                edges.append(edge)
    return dedupe_edges(edges)


def dedupe_edges(edges: Iterable[dict[str, object]]) -> list[dict[str, object]]:
    by_key = {}
    for edge in edges:
        key = (edge["caller"], edge["callee"], edge.get("syscall"))
        if key not in by_key:
            by_key[key] = edge
            continue
        merged = by_key[key]
        for alias_key in ("caller_aliases", "callee_aliases", "evidence"):
            values = [*merged.get(alias_key, []), *edge.get(alias_key, [])]
            merged[alias_key] = list(dict.fromkeys(str(value) for value in values if value))
    return sorted(by_key.values(), key=lambda item: (str(item["caller"]), str(item["callee"]), str(item.get("syscall", ""))))


def extract_extra_edges(kernel_root: Path, apis: set[str] | None = None) -> dict[str, object]:
    kernel_root = kernel_root.resolve()
    musl_root = kernel_root / "third_party/musl"
    if not musl_root.exists():
        raise FileNotFoundError(f"musl root not found: {musl_root}")

    musl_funcs = build_function_index(musl_root, ("src", "porting/liteos_a/user"))
    syscalls = parse_syscall_lookup(kernel_root)
    records, public_aliases = collect_musl_syscall_uses(musl_funcs, musl_root, kernel_root)
    edges = build_edges(records, public_aliases, syscalls, apis)

    return {
        "schema": SCHEMA,
        "kernel_root": str(kernel_root),
        "edges": edges,
        "stats": {
            "internal_functions_with_syscall_paths": len(records),
            "emitted_callers": len({edge["caller"] for edge in edges}),
            "syscall_table_entries": sum(len(items) for items in syscalls.values()),
            "edges": len(edges),
        },
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kernel-root", type=Path, default=DEFAULT_KERNEL_ROOT)
    parser.add_argument("--out", type=Path, default=Path("docs/extra-edge"))
    parser.add_argument(
        "--api",
        dest="api",
        action="append",
        default=[],
        help="public libc API to include. Can be passed multiple times. If omitted, all matching public APIs are emitted.",
    )
    parser.add_argument(
        "--apis",
        nargs="+",
        default=[],
        help="space-separated public libc APIs to include.",
    )
    parser.add_argument("--print-summary", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    api_filter = set(args.api or [])
    api_filter.update(args.apis or [])

    graph = extract_extra_edges(args.kernel_root, api_filter or None)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(graph, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    if args.print_summary:
        print(json.dumps(graph["stats"], indent=2, ensure_ascii=False))
        print(f"wrote: {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

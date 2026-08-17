"""Verilog/SystemVerilog language service with optional Verible parsing.

The analysis unit is a top-level ``module``. Verible is preferred when its
syntax-tree schema is recognized; a conservative source scanner keeps module
extraction and instance edges available without external tooling.
"""

from __future__ import annotations

import bisect
import json
import logging
import os
import re
import shutil
import subprocess
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path

from src.file_utils import _is_test_file
from src.languages.codegraph import canonicalize
from src.languages.hardware import (
    VERILOG_EXTENSIONS,
    is_excluded_source_directory,
)


_VERIBLE_DISABLE_ENV = "FM_AGENT_NO_VERIBLE"
_VERIBLE_TIMEOUT_SECONDS = 120
_MODULE_OPEN_RE = re.compile(
    r"\bmodule\s+(?:(?:automatic|static)\s+)?"
    r"(?P<name>[A-Za-z_][A-Za-z0-9_$]*)"
)
_ENDMODULE_RE = re.compile(r"\bendmodule\b")
_INSTANTIATION_RE = re.compile(
    r"^[ \t]*(?:\(\*.*?\*\)[ \t]*)*"
    r"(?P<type>[A-Za-z_][A-Za-z0-9_$]*)"
    r"(?:\s*#\s*\(|\s+[A-Za-z_][A-Za-z0-9_$]*"
    r"\s*(?:\[[^\]]*\]\s*)*\()",
    re.MULTILINE,
)


@dataclass(frozen=True)
class VerilogUnit:
    """One top-level module and its source metadata."""

    abs_path: str
    rel_path: str
    source: str
    name: str
    span: tuple[int, int]
    fqn: str | None = None


@dataclass(frozen=True)
class VerilogAnalysis:
    """One project scan, retaining files that contain no modules."""

    files: tuple[str, ...]
    modules: tuple[VerilogUnit, ...]


def _project_root(proj_dir: str | Path) -> Path:
    root = Path(os.path.abspath(proj_dir))
    return root.parent if root.name == "fm_agent" else root


def _work_dir(proj_dir: str | Path) -> Path:
    root = Path(os.path.abspath(proj_dir))
    return root if root.name == "fm_agent" else root / "fm_agent"


def _iter_verilog_files(proj_dir: str | Path):
    project = _project_root(proj_dir)
    if not project.is_dir():
        return
    for current_root, dirnames, filenames in os.walk(project):
        dirnames[:] = sorted(
            name
            for name in dirnames
            if not is_excluded_source_directory(name)
        )
        root = Path(current_root)
        for filename in sorted(filenames):
            path = root / filename
            if path.suffix.lower() not in VERILOG_EXTENSIONS:
                continue
            rel_path = path.relative_to(project).as_posix()
            if _is_test_file(rel_path):
                continue
            yield path, rel_path


def mask_non_code(text: str) -> str:
    """Mask comments and strings while preserving offsets and newlines."""
    result = list(text)
    index = 0
    while index < len(text):
        current = text[index]
        following = text[index + 1] if index + 1 < len(text) else ""
        if current == "/" and following == "/":
            while index < len(text) and text[index] != "\n":
                result[index] = " "
                index += 1
            continue
        if current == "/" and following == "*":
            result[index] = result[index + 1] = " "
            index += 2
            while index < len(text):
                if text[index:index + 2] == "*/":
                    result[index] = result[index + 1] = " "
                    index += 2
                    break
                if text[index] != "\n":
                    result[index] = " "
                index += 1
            continue
        if current == '"':
            result[index] = " "
            index += 1
            while index < len(text):
                if text[index] == "\\":
                    if text[index] != "\n":
                        result[index] = " "
                    if index + 1 < len(text) and text[index + 1] != "\n":
                        result[index + 1] = " "
                    index += 2
                    continue
                if text[index] == '"':
                    result[index] = " "
                    index += 1
                    break
                if text[index] != "\n":
                    result[index] = " "
                index += 1
            continue
        index += 1
    return "".join(result)


def _verible_binary() -> str | None:
    if os.environ.get(_VERIBLE_DISABLE_ENV):
        return None
    return shutil.which("verible-verilog-syntax")


def _run_verible_tree(text: str) -> dict | None:
    binary = _verible_binary()
    if binary is None:
        return None
    try:
        completed = subprocess.run(
            [binary, "--printtree", "--export_json", "-"],
            input=text,
            capture_output=True,
            encoding="utf-8",
            timeout=_VERIBLE_TIMEOUT_SECONDS,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if completed.returncode != 0 or not completed.stdout.strip():
        return None
    try:
        document = json.loads(completed.stdout)
    except json.JSONDecodeError:
        return None
    if not isinstance(document, dict) or not document:
        return None
    first = next(iter(document.values()))
    if not isinstance(first, dict):
        return None
    tree = first.get("tree")
    return tree if isinstance(tree, dict) else None


def _children(node: object) -> list:
    if not isinstance(node, dict):
        return []
    children = node.get("children")
    return children if isinstance(children, list) else []


def _first_descendant(node: object, tag: str) -> dict | None:
    for child in _children(node):
        if not isinstance(child, dict):
            continue
        if child.get("tag") == tag:
            return child
        found = _first_descendant(child, tag)
        if found is not None:
            return found
    return None


def _first_identifier(node: object) -> tuple[str | None, str | None]:
    if not isinstance(node, dict):
        return None, None
    tag = node.get("tag")
    if tag in {"SymbolIdentifier", "EscapedIdentifier"}:
        value = node.get("text")
        if isinstance(value, str):
            return tag, value
    for child in _children(node):
        child_tag, value = _first_identifier(child)
        if value is not None:
            return child_tag, value
    return None, None


def _node_byte_span(node: object) -> tuple[int | None, int | None]:
    start = None
    end = None
    stack = [node]
    while stack:
        current = stack.pop()
        if not isinstance(current, dict):
            continue
        current_start = current.get("start")
        current_end = current.get("end")
        if isinstance(current_start, int) and isinstance(current_end, int):
            start = current_start if start is None else min(start, current_start)
            end = current_end if end is None else max(end, current_end)
        stack.extend(_children(current))
    return start, end


def _top_level_modules(tree: object) -> list[dict]:
    modules = []

    def walk(node: object) -> None:
        if isinstance(node, list):
            for child in node:
                walk(child)
            return
        if not isinstance(node, dict):
            return
        if node.get("tag") == "kModuleDeclaration":
            modules.append(node)
            return
        for child in _children(node):
            walk(child)

    walk(tree)
    return modules


def _line_start_offsets(text: str) -> list[int]:
    """Return UTF-8 byte offsets used by Verible's JSON tree."""
    encoded = text.encode("utf-8")
    return [0, *(match.end() for match in re.finditer(b"\n", encoded))]


def _character_line_start_offsets(text: str) -> list[int]:
    """Return Python character offsets used by the source scanner."""
    return [0, *(match.end() for match in re.finditer("\n", text))]


def _extract_via_verible(text: str) -> list[tuple[str, int, int]] | None:
    tree = _run_verible_tree(text)
    if tree is None:
        return None
    module_nodes = _top_level_modules(tree)
    if not module_nodes:
        # An empty list is not trusted because Verible tags can change between
        # versions; the source scanner decides whether the file is truly empty.
        return None
    starts = _line_start_offsets(text)
    modules = []
    for node in module_nodes:
        header = _first_descendant(node, "kModuleHeader")
        tag, name = _first_identifier(header)
        if not name:
            continue
        if tag == "EscapedIdentifier":
            logging.warning(
                "Skipping escaped Verilog module name %s; it cannot form a "
                "portable analysis-unit path",
                name,
            )
            continue
        start_byte, end_byte = _node_byte_span(node)
        if start_byte is None or end_byte is None:
            continue
        start_line = bisect.bisect_right(starts, start_byte) - 1
        end_line = bisect.bisect_right(
            starts, max(start_byte, end_byte - 1)
        ) - 1
        modules.append((name, start_line, end_line))
    return modules or None


def _extract_via_source(text: str) -> list[tuple[str, int, int]]:
    masked = mask_non_code(text)
    starts = _character_line_start_offsets(text)
    modules = []
    cursor = 0
    while True:
        opening = _MODULE_OPEN_RE.search(masked, cursor)
        if opening is None:
            break
        closing = _ENDMODULE_RE.search(masked, opening.end())
        end_offset = closing.end() if closing is not None else len(masked)
        start_line = bisect.bisect_right(starts, opening.start()) - 1
        end_line = bisect.bisect_right(
            starts, max(opening.start(), end_offset - 1)
        ) - 1
        modules.append((opening.group("name"), start_line, end_line))
        cursor = end_offset
    return modules


def _module_spans(text: str) -> list[tuple[str, int, int]]:
    return _extract_via_verible(text) or _extract_via_source(text)


def _analyze_sources(proj_dir: str | Path) -> VerilogAnalysis:
    files = []
    modules = []
    for path, rel_path in _iter_verilog_files(proj_dir):
        absolute = str(path.absolute())
        files.append(absolute)
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            logging.warning("Unable to read Verilog source %s: %s", path, exc)
            continue
        lines = text.splitlines(keepends=True)
        for name, start, end in _module_spans(text):
            modules.append(
                VerilogUnit(
                    abs_path=absolute,
                    rel_path=rel_path,
                    source="".join(lines[start:end + 1]),
                    name=name,
                    span=(start, end),
                )
            )
    return VerilogAnalysis(files=tuple(files), modules=tuple(modules))


def _source_unit_fqn(unit: VerilogUnit, extracted_name: str | None = None) -> str:
    path = Path(unit.rel_path)
    source_directory = f"{path.stem}-{path.suffix.lstrip('.')}"
    parts = [*path.parent.parts, source_directory, canonicalize(extracted_name or unit.name)]
    return "::".join(part for part in parts if part not in {"", "."})


def _units_with_fqns(
    modules: tuple[VerilogUnit, ...],
) -> list[tuple[str, VerilogUnit]]:
    counts: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    result = []
    for unit in modules:
        name = canonicalize(unit.name)
        count = counts[unit.abs_path][name]
        counts[unit.abs_path][name] += 1
        extracted_name = name if count == 0 else f"{name}_{count}"
        result.append((_source_unit_fqn(unit, extracted_name), unit))
    return result


def _records(
    analysis: VerilogAnalysis,
    *,
    spans: bool,
) -> dict[str, list[tuple]]:
    grouped: dict[str, list[tuple]] = {path: [] for path in analysis.files}
    for fqn, unit in _units_with_fqns(analysis.modules):
        extracted_name = fqn.rsplit("::", 1)[-1]
        if spans:
            grouped[unit.abs_path].append(
                (extracted_name, unit.span[0], unit.span[1])
            )
        else:
            grouped[unit.abs_path].append((extracted_name, unit.source))
    return grouped


def batch_extract(proj_dir: str) -> dict[str, list[tuple[str, str]]]:
    """Return module units, retaining empty lists for handled RTL files."""
    return _records(_analyze_sources(proj_dir), spans=False)


def function_spans(proj_dir: str, filepath: str):
    """Return module spans; supported files without modules are handled-empty."""
    path = Path(os.path.abspath(filepath))
    if path.suffix.lower() not in VERILOG_EXTENSIONS or not path.is_file():
        return None
    return _records(_analyze_sources(proj_dir), spans=True).get(str(path), [])


def _extracted_modules(proj_dir: str | Path) -> tuple[VerilogUnit, ...]:
    root = _work_dir(proj_dir) / "extracted_functions"
    if not root.is_dir():
        return ()
    modules = []
    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.suffix.lower() not in VERILOG_EXTENSIONS:
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        relative = path.relative_to(root)
        spans = _module_spans(text)
        if len(spans) != 1:
            continue
        name, start, end = spans[0]
        modules.append(
            VerilogUnit(
                abs_path=str(path.absolute()),
                rel_path=relative.as_posix(),
                source=text,
                name=name,
                span=(start, end),
                fqn="::".join(relative.with_suffix("").parts),
            )
        )
    return tuple(modules)


def _verible_instantiations(
    text: str,
    known_names: set[str],
) -> set[str] | None:
    tree = _run_verible_tree(text)
    if tree is None or not _top_level_modules(tree):
        return None
    found = set()

    def walk(node: object) -> None:
        if isinstance(node, list):
            for child in node:
                walk(child)
            return
        if not isinstance(node, dict):
            return
        if node.get("tag") == "kInstantiationBase":
            instantiation_type = _first_descendant(node, "kInstantiationType")
            _tag, name = _first_identifier(instantiation_type)
            if name in known_names:
                found.add(name)
        for child in _children(node):
            walk(child)

    walk(tree)
    # A non-empty result demonstrates that the expected Verible tags are still
    # valid. For an empty result, use the stable scanner so partial tag drift
    # cannot silently erase real instance edges.
    return found or None


def _source_instantiations(text: str, known_names: set[str]) -> set[str]:
    return {
        match.group("type")
        for match in _INSTANTIATION_RE.finditer(mask_non_code(text))
        if match.group("type") in known_names
    }


def _instantiated_names(text: str, known_names: set[str]) -> set[str]:
    via_verible = _verible_instantiations(text, known_names)
    if via_verible is not None:
        return via_verible
    return _source_instantiations(text, known_names)


def call_edges(proj_dir: str) -> dict[str, set[str]]:
    """Return module-type instantiation edges with module-level deduplication."""
    extracted = _extracted_modules(proj_dir)
    if extracted:
        units_with_fqns = [(unit.fqn or "", unit) for unit in extracted]
    else:
        analysis = _analyze_sources(proj_dir)
        units_with_fqns = _units_with_fqns(analysis.modules)

    by_name: dict[str, list[tuple[str, VerilogUnit]]] = defaultdict(list)
    for fqn, unit in units_with_fqns:
        by_name[unit.name].append((fqn, unit))

    edges: dict[str, set[str]] = defaultdict(set)
    known_names = set(by_name)
    for caller_fqn, caller in units_with_fqns:
        for reference in _instantiated_names(caller.source, known_names):
            candidates = by_name[reference]
            if len(candidates) != 1:
                logging.warning(
                    "Skipping ambiguous Verilog module reference %s from %s; "
                    "candidates: %s",
                    reference,
                    caller_fqn,
                    ", ".join(sorted(fqn for fqn, _unit in candidates)),
                )
                continue
            callee_fqn = candidates[0][0]
            if callee_fqn != caller_fqn:
                edges[caller_fqn].add(callee_fqn)
    return dict(edges)

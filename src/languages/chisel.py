"""Conservative source-backed Chisel language service.

Chisel is embedded in Scala, but FM-Agent analysis units are hardware modules,
not arbitrary Scala declarations. This handler owns Scala-aware declaration
scanning, module classification, source spans, and module-instantiation edges.
CIRCT enrichment is intentionally left to the later C2 integration.
"""

from __future__ import annotations

import logging
import os
import re
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path

from src.file_utils import _is_test_file
from src.languages.codegraph import canonicalize
from src.languages.hardware import (
    CHISEL_EXTENSIONS,
    is_excluded_source_directory,
)


_MODULE_ROOTS = frozenset({
    "Module",
    "RawModule",
    "BlackBox",
    "ExtModule",
    "MultiIOModule",
})
_MODIFIER = (
    r"(?:"
    r"(?:private|protected)(?:\[[\w.]+\])?"
    r"|final|sealed|abstract|implicit|lazy|override|case"
    r")"
)
_DECLARATION_RE = re.compile(
    r"^(?:" + _MODIFIER + r"\s+)*"
    r"(?P<kind>class|object|trait|def)\s+"
    r"(?P<name>[A-Za-z_$][\w$]*)"
)
_LOCAL_DECLARATION_RE = re.compile(
    r"\b(?:class|object|trait)\s+([A-Za-z_$][\w$]*)"
)
_NEW_MODULE_RE = re.compile(
    r"\bnew\s+"
    r"(?P<name>[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*)"
)
_DYNAMIC_MODULE_RE = re.compile(r"\bModule\s*\((?!\s*new\b)")
_PACKAGE_RE = re.compile(
    r"^\s*package\s+([A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*)"
    r"\s*(?:\{)?\s*$",
    re.MULTILINE,
)


@dataclass(frozen=True)
class ChiselUnit:
    """One top-level Scala declaration and its source metadata."""

    abs_path: str
    rel_path: str
    source: str
    kind: str
    name: str
    parent: str | None
    span: tuple[int, int] | None
    package: str | None = None
    fqn: str | None = None


@dataclass(frozen=True)
class ChiselAnalysis:
    """One project scan, including handled-empty files."""

    files: tuple[str, ...]
    modules: tuple[ChiselUnit, ...]


def _project_root(proj_dir: str | Path) -> Path:
    root = Path(os.path.abspath(proj_dir))
    return root.parent if root.name == "fm_agent" else root


def _work_dir(proj_dir: str | Path) -> Path:
    root = Path(os.path.abspath(proj_dir))
    return root if root.name == "fm_agent" else root / "fm_agent"


def _iter_chisel_files(proj_dir: str | Path):
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
            if path.suffix.lower() not in CHISEL_EXTENSIONS:
                continue
            rel_path = path.relative_to(project).as_posix()
            if _is_test_file(rel_path):
                continue
            yield path, rel_path


def _skip_quoted(text: str, index: int, quote: str) -> int:
    index += 1
    while index < len(text):
        if text[index] == "\n":
            return index
        if text[index] == "\\":
            index += 2
            continue
        if text[index] == quote:
            return index + 1
        index += 1
    return index


def _skip_character(text: str, index: int) -> int:
    """Skip a Scala character literal without consuming legacy symbols."""
    if (
        index + 3 < len(text)
        and text[index + 1] == "\\"
        and text[index + 3] == "'"
    ):
        return index + 4
    if index + 2 < len(text) and text[index + 2] == "'":
        return index + 3
    return index + 1


def mask_non_code(text: str) -> str:
    """Mask Scala comments and string/character literals, preserving layout."""
    masked = list(text)
    index = 0
    block_depth = 0
    in_triple = False

    while index < len(text):
        char = text[index]
        following = text[index + 1] if index + 1 < len(text) else ""

        if in_triple:
            if text[index:index + 3] == '\"\"\"':
                masked[index:index + 3] = "   "
                in_triple = False
                index += 3
            else:
                if char != "\n":
                    masked[index] = " "
                index += 1
            continue

        if block_depth:
            if char == "/" and following == "*":
                masked[index:index + 2] = "  "
                block_depth += 1
                index += 2
            elif char == "*" and following == "/":
                masked[index:index + 2] = "  "
                block_depth -= 1
                index += 2
            else:
                if char != "\n":
                    masked[index] = " "
                index += 1
            continue

        if char == "/" and following == "/":
            while index < len(text) and text[index] != "\n":
                masked[index] = " "
                index += 1
            continue
        if char == "/" and following == "*":
            masked[index:index + 2] = "  "
            block_depth += 1
            index += 2
            continue
        if text[index:index + 3] == '\"\"\"':
            masked[index:index + 3] = "   "
            in_triple = True
            index += 3
            continue
        if char == '"':
            end = _skip_quoted(text, index, char)
            for position in range(index, min(end, len(text))):
                if masked[position] != "\n":
                    masked[position] = " "
            index = end
            continue
        if char == "'":
            end = _skip_character(text, index)
            for position in range(index, min(end, len(text))):
                if masked[position] != "\n":
                    masked[position] = " "
            index = end
            continue
        index += 1

    return "".join(masked)


def _line_depths(masked_lines: list[str]) -> list[int]:
    depths = []
    depth = 0
    for line in masked_lines:
        depths.append(depth)
        depth += line.count("{") - line.count("}")
    return depths


def _matching_block_end(
    masked_lines: list[str],
    start_line: int,
) -> int:
    depth = 0
    opened = False
    for line_index in range(start_line, len(masked_lines)):
        for char in masked_lines[line_index]:
            if char == "{":
                depth += 1
                opened = True
            elif char == "}":
                depth -= 1
                if opened and depth == 0:
                    return line_index
    return len(masked_lines) - 1


def _package_block_line(line: str) -> bool:
    stripped = line.strip()
    return stripped.startswith("package ") and stripped.endswith("{")


def _signature_end(masked_lines: list[str], start_line: int) -> int:
    parens = 0
    brackets = 0
    saw_extends = False
    for line_index in range(start_line, len(masked_lines)):
        stripped = masked_lines[line_index].strip()
        if not stripped and line_index > start_line:
            continue
        parens += stripped.count("(") - stripped.count(")")
        brackets += stripped.count("[") - stripped.count("]")
        saw_extends = saw_extends or "extends" in stripped
        if "{" in stripped and parens <= 0 and brackets <= 0:
            return line_index
        if parens > 0 or brackets > 0:
            continue
        if stripped.endswith(("extends", "with", ",")):
            continue
        next_line = next(
            (
                masked_lines[index].strip()
                for index in range(line_index + 1, len(masked_lines))
                if masked_lines[index].strip()
            ),
            "",
        )
        if next_line.startswith(("(", "extends ", "with ")):
            continue
        if next_line == "{":
            return line_index + 1
        if saw_extends or line_index == start_line:
            return line_index
    return len(masked_lines) - 1


def _declaration_end(masked_lines: list[str], start_line: int) -> int:
    signature_end = _signature_end(masked_lines, start_line)
    signature = " ".join(masked_lines[start_line:signature_end + 1])
    if "{" not in signature:
        return signature_end
    return _matching_block_end(masked_lines, start_line)


def _parent_from_signature(signature: str) -> str | None:
    match = re.search(
        r"\bextends\s+([A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*)",
        signature,
    )
    return match.group(1).rsplit(".", 1)[-1] if match else None


def _package_name(masked_text: str) -> str | None:
    packages = _PACKAGE_RE.findall(masked_text)
    return ".".join(packages) if packages else None


def _declarations(path: Path, rel_path: str) -> list[ChiselUnit]:
    text = path.read_text(encoding="utf-8", errors="replace")
    source_lines = text.splitlines()
    masked_text = mask_non_code(text)
    masked_lines = masked_text.splitlines()
    depths = _line_depths(masked_lines)
    package_blocks: list[tuple[int, int]] = []
    units = []
    line_index = 0

    while line_index < len(masked_lines):
        package_blocks = [
            block for block in package_blocks if line_index <= block[1]
        ]
        in_package_top = any(
            depths[line_index] == depth and line_index <= end
            for depth, end in package_blocks
        )
        if depths[line_index] != 0 and not in_package_top:
            line_index += 1
            continue

        stripped = masked_lines[line_index].lstrip()
        if _package_block_line(masked_lines[line_index]):
            package_blocks.append(
                (
                    depths[line_index] + 1,
                    _matching_block_end(masked_lines, line_index),
                )
            )
            line_index += 1
            continue
        if stripped.startswith(("package ", "import ")):
            line_index += 1
            continue

        match = _DECLARATION_RE.match(stripped)
        if match is None:
            line_index += 1
            continue

        end_line = _declaration_end(masked_lines, line_index)
        signature_end = _signature_end(masked_lines, line_index)
        signature = " ".join(
            masked_lines[line_index:signature_end + 1]
        )
        units.append(
            ChiselUnit(
                abs_path=os.path.abspath(path),
                rel_path=rel_path,
                source="\n".join(source_lines[line_index:end_line + 1]) + "\n",
                kind=match.group("kind"),
                name=match.group("name"),
                parent=_parent_from_signature(signature),
                span=(line_index, end_line),
                package=_package_name(masked_text),
            )
        )
        line_index = end_line + 1

    return units


def _module_units(units: list[ChiselUnit]) -> tuple[ChiselUnit, ...]:
    declarations_by_name: dict[str, list[int]] = defaultdict(list)
    for index, unit in enumerate(units):
        if unit.kind == "class":
            declarations_by_name[unit.name].append(index)

    resolved: dict[int, bool] = {}
    visiting: set[int] = set()

    def is_module(index: int) -> bool:
        if index in resolved:
            return resolved[index]
        if index in visiting:
            return False
        visiting.add(index)
        unit = units[index]
        result = unit.kind == "class" and unit.parent in _MODULE_ROOTS
        if unit.kind == "class" and unit.parent and not result:
            result = any(
                is_module(parent_index)
                for parent_index in declarations_by_name.get(unit.parent, ())
            )
        visiting.remove(index)
        resolved[index] = result
        return result

    return tuple(
        unit for index, unit in enumerate(units) if is_module(index)
    )


def _analyze_sources(proj_dir: str | Path) -> ChiselAnalysis:
    files = []
    declarations = []
    for path, rel_path in _iter_chisel_files(proj_dir):
        files.append(os.path.abspath(path))
        try:
            declarations.extend(_declarations(path, rel_path))
        except OSError as exc:
            logging.warning("Unable to read Chisel source %s: %s", path, exc)
    return ChiselAnalysis(
        files=tuple(files),
        modules=_module_units(declarations),
    )


def _deduped_records(
    analysis: ChiselAnalysis,
    *,
    spans: bool,
) -> dict[str, list[tuple]]:
    grouped: dict[str, list[tuple]] = {
        path: [] for path in analysis.files
    }
    counts: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    for unit in analysis.modules:
        name = canonicalize(unit.name)
        count = counts[unit.abs_path][name]
        counts[unit.abs_path][name] += 1
        deduped = name if count == 0 else f"{name}_{count}"
        if spans:
            if unit.span is not None:
                grouped[unit.abs_path].append(
                    (deduped, unit.span[0], unit.span[1])
                )
        else:
            grouped[unit.abs_path].append((deduped, unit.source))
    return grouped


def batch_extract(proj_dir: str) -> dict[str, list[tuple[str, str]]]:
    """Return module units, retaining empty lists for handled Chisel files."""
    return _deduped_records(_analyze_sources(proj_dir), spans=False)


def function_spans(proj_dir: str, filepath: str):
    """Return module spans; Chisel files with no modules are handled-empty."""
    path = Path(os.path.abspath(filepath))
    if path.suffix.lower() not in CHISEL_EXTENSIONS or not path.is_file():
        return None
    analysis = _analyze_sources(proj_dir)
    records = _deduped_records(analysis, spans=True)
    return records.get(str(path), [])


def _source_unit_fqn(unit: ChiselUnit, extracted_name: str | None = None) -> str:
    source_path = Path(unit.rel_path)
    dashed = f"{source_path.stem}-{source_path.suffix.lstrip('.')}"
    parts = [
        *source_path.parent.parts,
        dashed,
        canonicalize(extracted_name or unit.name),
    ]
    return "::".join(part for part in parts if part not in {"", "."})


def _source_units_with_fqns(
    modules: tuple[ChiselUnit, ...],
) -> list[tuple[str, ChiselUnit]]:
    counts: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    result = []
    for unit in modules:
        name = canonicalize(unit.name)
        count = counts[unit.abs_path][name]
        counts[unit.abs_path][name] += 1
        extracted_name = name if count == 0 else f"{name}_{count}"
        result.append((_source_unit_fqn(unit, extracted_name), unit))
    return result


def _extracted_unit_fqn(relative_path: Path) -> str:
    return "::".join(relative_path.with_suffix("").parts)


def _extracted_modules(proj_dir: str | Path) -> tuple[ChiselUnit, ...]:
    extracted_root = _work_dir(proj_dir) / "extracted_functions"
    if not extracted_root.is_dir():
        return ()
    units = []
    for path in sorted(extracted_root.rglob("*")):
        if not path.is_file() or path.suffix.lower() not in CHISEL_EXTENSIONS:
            continue
        relative_path = path.relative_to(extracted_root)
        declarations = _declarations(path, relative_path.as_posix())
        for unit in declarations:
            if unit.kind != "class":
                continue
            units.append(
                ChiselUnit(
                    abs_path=unit.abs_path,
                    rel_path=unit.rel_path,
                    source=unit.source,
                    kind=unit.kind,
                    name=unit.name,
                    parent=unit.parent,
                    span=unit.span,
                    package=unit.package,
                    fqn=_extracted_unit_fqn(relative_path),
                )
            )
    return tuple(units)


def _local_declaration_names(source: str, own_name: str) -> set[str]:
    names = set(_LOCAL_DECLARATION_RE.findall(mask_non_code(source)))
    names.discard(own_name)
    return names


def _instantiated_names(source: str) -> set[str]:
    return {
        match.group("name")
        for match in _NEW_MODULE_RE.finditer(mask_non_code(source))
    }


def _resolve_target(
    reference: str,
    candidates: list[tuple[str, ChiselUnit]],
) -> list[str]:
    if len(candidates) <= 1:
        return [fqn for fqn, _unit in candidates]
    qualifier, separator, _name = reference.rpartition(".")
    if separator:
        qualified = [
            fqn
            for fqn, unit in candidates
            if unit.package == qualifier
            or (unit.package and unit.package.endswith("." + qualifier))
        ]
        if len(qualified) == 1:
            return qualified
    logging.warning(
        "Skipping ambiguous Chisel module reference %s; candidates: %s",
        reference,
        ", ".join(sorted(fqn for fqn, _unit in candidates)),
    )
    return []


def call_edges(proj_dir: str) -> dict[str, set[str]]:
    """Return conservative module-instantiation edges for Chisel units."""
    extracted = _extracted_modules(proj_dir)
    if extracted:
        units_with_fqns = [
            (unit.fqn or _extracted_unit_fqn(Path(unit.rel_path)), unit)
            for unit in extracted
        ]
    else:
        units_with_fqns = _source_units_with_fqns(
            _analyze_sources(proj_dir).modules
        )

    by_name: dict[str, list[tuple[str, ChiselUnit]]] = defaultdict(list)
    for fqn, unit in units_with_fqns:
        by_name[unit.name].append((fqn, unit))

    edges: dict[str, set[str]] = defaultdict(set)
    for caller_fqn, caller in units_with_fqns:
        shadowed = _local_declaration_names(caller.source, caller.name)
        if _DYNAMIC_MODULE_RE.search(mask_non_code(caller.source)):
            logging.warning(
                "Chisel source fallback could not resolve one or more dynamic "
                "Module(...) constructions in %s",
                caller_fqn,
            )
        for reference in _instantiated_names(caller.source):
            simple_name = reference.rsplit(".", 1)[-1]
            if simple_name in shadowed:
                continue
            for callee_fqn in _resolve_target(
                reference,
                by_name.get(simple_name, []),
            ):
                if callee_fqn != caller_fqn:
                    edges[caller_fqn].add(callee_fqn)
    return dict(edges)

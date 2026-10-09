"""Generate the chip plugin's Chinese design document after Stage 6.

The document is a run-level deliverable derived from the current Profile-ready
module artifacts.  It deliberately stays inside the chip plugin rather than
adding a public Pipeline stage or a new Profile artifact type.
"""

from __future__ import annotations

import json
import logging
import os
import re
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

from config import OPENCODE_MAX_RETRIES, OPENCODE_SPEC_MODEL
from src.generate_batch_prompts import (
    build_expected_dependencies_by_file,
    expected_dependencies_for_file,
)
from src.file_utils import _is_test_file
from src.languages.hardware import (
    CHISEL_EXTENSIONS,
    VERILOG_EXTENSIONS,
    is_excluded_source_directory,
    resolve_hardware_project_paths,
)
from src.llm_client import build_llm_cli_command
from src.opencode_trace import run_opencode_traced
from src.trace_writer import new_event_id, record_trace_event, utc_now_iso

from .detection import read_plugin_submodules
from .profiles import PROFILES


_TOPDOWN_FILENAME_RE = re.compile(r"^phase_(?P<phase>\d+)_topdown_layers\.json$")
_TEMPLATE_PLACEHOLDERS = (
    "# [DUT] 设计与功能检测点文档",
    "P-[NAME]",
    "CASE-[NAME]",
    "[vMAJOR.MINOR.PATCH]",
    "[YYYY-MM-DD]",
)
_TEMPLATE_DIRECTIVES = (
    "<!-- GENERATOR:",
    "<!-- CONDITIONAL:",
    "<!-- STRUCTURE:",
    "<!-- MAINTAINER:",
)
_REQUIRED_HEADINGS = (
    (2, "第一部分：正文"),
    (3, "文档摘要"),
    (3, "设计概览"),
    (3, "功能行为"),
    (3, "关键结构与状态"),
    (2, "第二部分：验证计划"),
    (3, "验证策略"),
    (3, "功能分组"),
    (3, "Test Plan"),
    (3, "Coverage Summary"),
    (3, "Coverage Design Contract"),
    (3, "形式化属性契约"),
    (3, "测试场景"),
    (3, "签核与开放项"),
    (2, "第三部分：附录"),
    (3, "附录 A：文档控制与范围裁定"),
    (3, "附录 B：逻辑接口与 RTL 映射"),
    (3, "附录 C：参数、实例与配置裁剪"),
    (3, "附录 D：证据索引"),
    (3, "附录 E：FACT、OPEN 与偏差"),
    (3, "附录 F：FC / CK 完整追溯"),
    (3, "附录 G：签核清单"),
)
_REQUIRED_MAIN_SECTIONS = (
    "第一部分：正文",
    "第二部分：验证计划",
    "第三部分：附录",
)


@dataclass(frozen=True)
class DesignDocumentUnit:
    """One hardware unit from the current run's merged top-down graph."""

    name: str
    source_path: Path
    source_relpath: str
    artifact_eligible: bool
    is_module: bool | None
    all_callees: tuple[str, ...]

    @property
    def module_name(self) -> str:
        return self.name.rsplit("::", 1)[-1]


@dataclass(frozen=True)
class DesignDocumentInputs:
    """Verified, run-scoped material supplied to the document writer."""

    project_root: Path
    work_dir: Path
    dialect: str
    eligible_units: tuple[DesignDocumentUnit, ...]
    root_candidates: tuple[DesignDocumentUnit, ...]
    root_dut: DesignDocumentUnit


def _read_json_object(path: Path) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"unable to read JSON input {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise ValueError(f"expected a JSON object in {path}")
    return data


def _write_text_atomically(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.write_text(content, encoding="utf-8")
    os.replace(temporary, path)


def _write_json_atomically(path: Path, data: dict[str, Any]) -> None:
    _write_text_atomically(
        path,
        json.dumps(data, indent=2, ensure_ascii=False) + "\n",
    )


def _work_paths(proj_dir: str | os.PathLike[str]) -> tuple[Path, Path, Path]:
    project_root, work_dir = resolve_hardware_project_paths(proj_dir)
    chip_dir = work_dir / "chip"
    return project_root, work_dir, chip_dir


def _phase_numbers(phases_data: dict[str, Any]) -> tuple[int, ...]:
    phases = phases_data.get("phases")
    if not isinstance(phases, list):
        raise ValueError("phases.json must contain a 'phases' array")

    numbers: list[int] = []
    for phase in phases:
        if not isinstance(phase, dict):
            raise ValueError("phases.json phase entries must be objects")
        number = phase.get("phase")
        if not isinstance(number, int) or isinstance(number, bool) or number < 1:
            raise ValueError("each phases.json phase must have a positive integer 'phase'")
        numbers.append(number)
    if len(set(numbers)) != len(numbers):
        raise ValueError("phases.json contains duplicate phase numbers")
    return tuple(sorted(numbers))


def _dialect_from_phases(phases_data: dict[str, Any]) -> str:
    raw_languages = phases_data.get("languages")
    if not isinstance(raw_languages, (list, tuple, set)):
        raise ValueError("phases.json must record the selected chip language")
    languages = {
        value.strip().lower()
        for value in raw_languages
        if isinstance(value, str) and value.strip()
    }
    if len(languages) != 1 or not languages <= set(PROFILES):
        raise ValueError(
            "design-document generation requires exactly one supported chip language in "
            f"phases.json; found {sorted(languages)!r}"
        )
    return next(iter(languages))


def _resolve_work_relative_path(work_dir: Path, raw_path: object) -> tuple[Path, str]:
    """Resolve an extracted-unit path and prevent it from escaping fm_agent."""
    if not isinstance(raw_path, str) or not raw_path.strip():
        raise ValueError("topdown function entry is missing a non-empty 'file'")
    value = raw_path.replace("\\", "/")
    prefix = f"{work_dir.name}/"
    if value.startswith(prefix):
        value = value[len(prefix):]
    candidate = Path(value)
    if not candidate.is_absolute():
        candidate = work_dir / candidate
    candidate = Path(os.path.realpath(candidate))
    work_root = Path(os.path.realpath(work_dir))
    try:
        relpath = candidate.relative_to(work_root).as_posix()
    except ValueError as exc:
        raise ValueError(f"topdown extracted file escapes fm_agent: {raw_path!r}") from exc
    return candidate, relpath


def _topdown_paths_for_phases(work_dir: Path, phase_numbers: Iterable[int]) -> tuple[Path, ...]:
    topdown_paths: list[Path] = []
    for phase in phase_numbers:
        path = work_dir / "spec_prompts" / f"phase_{phase:02d}_topdown_layers.json"
        if not path.is_file():
            raise FileNotFoundError(
                f"missing current phase topdown graph for design-document generation: {path}"
            )
        if not _TOPDOWN_FILENAME_RE.fullmatch(path.name):
            raise ValueError(f"invalid topdown graph filename: {path}")
        topdown_paths.append(path)
    return tuple(topdown_paths)


def _read_units(
    topdown_paths: Iterable[Path],
    work_dir: Path,
) -> tuple[tuple[DesignDocumentUnit, ...], dict[str, dict[str, Any]]]:
    """Merge current phase graphs while preserving context-only nodes."""
    by_name: dict[str, DesignDocumentUnit] = {}
    layers_by_path: dict[str, dict[str, Any]] = {}
    for topdown_path in topdown_paths:
        data = _read_json_object(topdown_path)
        layers = data.get("layers")
        if not isinstance(layers, list):
            raise ValueError(f"topdown graph must contain a 'layers' array: {topdown_path}")
        layers_by_path[str(topdown_path)] = data
        for layer in layers:
            if not isinstance(layer, dict):
                raise ValueError(f"topdown layer must be an object: {topdown_path}")
            functions = layer.get("functions")
            if not isinstance(functions, list):
                raise ValueError(f"topdown layer must contain a 'functions' array: {topdown_path}")
            for function in functions:
                if not isinstance(function, dict):
                    raise ValueError(f"topdown function must be an object: {topdown_path}")
                name = function.get("name")
                if not isinstance(name, str) or not name.strip():
                    raise ValueError(f"topdown function is missing a name: {topdown_path}")
                source_path, source_relpath = _resolve_work_relative_path(
                    work_dir, function.get("file")
                )
                if not source_path.is_file():
                    raise FileNotFoundError(
                        f"topdown function points to missing extracted source: {source_path}"
                    )
                raw_callees = function.get("all_callees", ())
                if not isinstance(raw_callees, (list, tuple, set)):
                    raise ValueError(
                        f"topdown function has invalid all_callees: {name}"
                    )
                callees = tuple(sorted({
                    callee for callee in raw_callees
                    if isinstance(callee, str) and callee
                }))
                raw_is_module = function.get("is_module")
                if raw_is_module is not None and not isinstance(raw_is_module, bool):
                    raise ValueError(f"topdown function has invalid is_module metadata: {name}")
                unit = DesignDocumentUnit(
                    name=name,
                    source_path=source_path,
                    source_relpath=source_relpath,
                    artifact_eligible=function.get("artifact_eligible", True) is not False,
                    is_module=raw_is_module,
                    all_callees=callees,
                )
                existing = by_name.get(name)
                if existing is not None and (
                    existing.source_path != unit.source_path
                    or existing.artifact_eligible != unit.artifact_eligible
                    or existing.is_module != unit.is_module
                ):
                    raise ValueError(
                        "conflicting current topdown entries for module "
                        f"{name!r}: {existing.source_relpath} vs {source_relpath}"
                    )
                if existing is not None:
                    unit = DesignDocumentUnit(
                        name=unit.name,
                        source_path=unit.source_path,
                        source_relpath=unit.source_relpath,
                        artifact_eligible=unit.artifact_eligible,
                        is_module=unit.is_module,
                        all_callees=tuple(sorted(
                            set(existing.all_callees) | set(unit.all_callees)
                        )),
                    )
                by_name[name] = unit
    return tuple(sorted(by_name.values(), key=lambda unit: unit.name)), layers_by_path


def _root_candidates(units: Iterable[DesignDocumentUnit]) -> tuple[DesignDocumentUnit, ...]:
    """Return in-scope module roots while preserving module context nodes.

    Chisel's eligibility annotation distinguishes a non-Module declaration
    (Bundle/trait/type context) from a hardware Module that simply lacks a
    standalone artifact. The former must not become a DUT root, while the
    latter remains relevant to hierarchy reasoning.
    """
    by_name = {
        unit.name: unit for unit in units
        if unit.is_module is not False
    }
    called_in_scope = {
        callee
        for unit in by_name.values()
        for callee in unit.all_callees
        if callee in by_name
    }
    return tuple(
        sorted(
            (unit for name, unit in by_name.items() if name not in called_in_scope),
            key=lambda unit: unit.name,
        )
    )


def _select_root_dut(
    root_candidates: Iterable[DesignDocumentUnit],
) -> DesignDocumentUnit:
    """Require one artifact-eligible root instead of guessing a DUT."""
    roots = tuple(root_candidates)
    eligible_roots = tuple(root for root in roots if root.artifact_eligible)
    if len(eligible_roots) == 1:
        return eligible_roots[0]

    rendered = [
        f"{root.name} ({'artifact-eligible' if root.artifact_eligible else 'context-only'})"
        for root in roots
    ]
    detail = ", ".join(rendered) if rendered else "none"
    raise RuntimeError(
        "chip design-document generation requires exactly one artifact-eligible "
        f"root DUT; found {len(eligible_roots)}. Current root candidates: {detail}. "
        "Narrow the analysis scope with an existing option such as --submodule; "
        "FM-Agent will not choose a DUT arbitrarily."
    )


def _validate_chisel_eligibility(
    eligibility_path: Path,
    eligible_units: Iterable[DesignDocumentUnit],
) -> None:
    data = _read_json_object(eligibility_path)
    kept = data.get("kept")
    if not isinstance(kept, list):
        raise ValueError("chip eligibility manifest must contain a 'kept' array")
    kept_names = {
        entry.get("name")
        for entry in kept
        if isinstance(entry, dict) and isinstance(entry.get("name"), str)
    }
    expected_names = {unit.name for unit in eligible_units}
    if kept_names != expected_names:
        raise RuntimeError(
            "current Chisel eligibility manifest disagrees with the current "
            "topdown artifact set: "
            f"manifest_only={sorted(kept_names - expected_names)!r}; "
            f"topdown_only={sorted(expected_names - kept_names)!r}"
        )


def _collect_inputs(proj_dir: str) -> tuple[DesignDocumentInputs, dict[str, dict[str, Any]]]:
    project_root, work_dir, _ = _work_paths(proj_dir)
    phases_path = work_dir / "phases.json"
    phases_data = _read_json_object(phases_path)
    phase_numbers = _phase_numbers(phases_data)
    dialect = _dialect_from_phases(phases_data)
    topdown_paths = _topdown_paths_for_phases(work_dir, phase_numbers)
    units, topdown_data = _read_units(topdown_paths, work_dir)
    eligible_units = tuple(unit for unit in units if unit.artifact_eligible)
    if dialect == "chisel":
        eligibility_path = work_dir / "chip" / "eligibility.json"
        if not eligibility_path.is_file():
            raise FileNotFoundError(
                f"missing current Chisel eligibility manifest: {eligibility_path}"
            )
        _validate_chisel_eligibility(eligibility_path, eligible_units)

    root_candidates = _root_candidates(units)
    return DesignDocumentInputs(
        project_root=project_root,
        work_dir=work_dir,
        dialect=dialect,
        eligible_units=eligible_units,
        root_candidates=root_candidates,
        root_dut=_select_root_dut(root_candidates),
    ), topdown_data


def _relative_to_work(path: Path, work_dir: Path) -> str:
    try:
        return path.resolve().relative_to(work_dir.resolve()).as_posix()
    except ValueError as exc:
        raise ValueError(f"design-document input escapes fm_agent: {path}") from exc


def _validate_module_artifacts(
    inputs: DesignDocumentInputs,
    topdown_data: dict[str, dict[str, Any]],
) -> None:
    """Require Profile-ready artifact pairs before asking the document writer."""
    profile = PROFILES[inputs.dialect]
    expected_by_file: dict[str, tuple[str, ...]] = {}
    for data in topdown_data.values():
        partial = build_expected_dependencies_by_file(data, inputs.work_dir)
        for file_key, dependencies in partial.items():
            expected_by_file[file_key] = tuple(sorted(
                set(expected_by_file.get(file_key, ())) | set(dependencies)
            ))

    failures: list[str] = []
    for unit in inputs.eligible_units:
        expected_dependencies = expected_dependencies_for_file(
            unit.source_path,
            expected_by_file,
        )
        validation = profile.validate(unit.source_path, expected_dependencies)
        if not validation.ready:
            details = "; ".join(validation.errors) or "artifact validation failed"
            failures.append(f"{unit.name}: {details}")
    if failures:
        raise RuntimeError(
            "cannot generate chip design document because module artifacts are not ready:\n- "
            + "\n- ".join(failures)
        )


def _module_artifact_paths(
    inputs: DesignDocumentInputs,
    unit: DesignDocumentUnit,
) -> tuple[Path, Path]:
    artifacts = PROFILES[inputs.dialect].artifact_paths(unit.source_path)
    paths = (artifacts.self_spec, artifacts.dependency_info)
    missing = [str(path) for path in paths if not path.is_file()]
    if missing:
        raise FileNotFoundError(
            "missing validated module artifacts: " + ", ".join(missing)
        )
    return paths


def _display_root_candidates(inputs: DesignDocumentInputs) -> list[dict[str, str]]:
    records: list[dict[str, str]] = []
    for unit in inputs.root_candidates:
        records.append({
            "name": unit.name,
            "module_name": unit.module_name,
            "source": unit.source_relpath,
            "artifact_status": "standalone_spec" if unit.artifact_eligible else "context_only",
        })
    return records


def _source_inventory(inputs: DesignDocumentInputs) -> dict[str, Any]:
    """List target-scope HDL sources as starting points for repository search.

    This deliberately records paths rather than trying to prove a Scala-to-RTL
    elaboration mapping. The inventory is not a whitelist: the writer runs from
    the repository root and may inspect relevant sources elsewhere in the repo.
    """
    submodules = read_plugin_submodules(inputs.project_root)
    scan_roots = [inputs.project_root / path for path in submodules]
    if not scan_roots:
        scan_roots = [inputs.project_root]

    chisel_sources: list[str] = []
    rtl_sources: list[str] = []
    project_root = inputs.project_root.resolve()
    seen: set[str] = set()
    for scan_root in scan_roots:
        for current_root, dirnames, filenames in os.walk(scan_root):
            dirnames[:] = sorted(
                name for name in dirnames if not is_excluded_source_directory(name)
            )
            for filename in sorted(filenames):
                if filename.startswith("."):
                    continue
                path = Path(current_root) / filename
                suffix = path.suffix.lower()
                if suffix not in CHISEL_EXTENSIONS | VERILOG_EXTENSIONS:
                    continue
                relative = path.resolve().relative_to(project_root).as_posix()
                if relative in seen or _is_test_file(relative):
                    continue
                seen.add(relative)
                if suffix in CHISEL_EXTENSIONS:
                    chisel_sources.append(relative)
                else:
                    rtl_sources.append(relative)

    return {
        "purpose": (
            "Raw HDL source inventory for the selected target scope. Use it to "
            "locate target modules; it is not a whitelist or complete repository index. "
            "The writer may search the repository root for relevant integration context."
        ),
        "selected_dialect": inputs.dialect,
        "analysis_scope": {
            "repository_root": ".",
            "submodules": list(submodules),
            "root": "." if not submodules else None,
            "context_search": (
                "Search relevant source files anywhere under the repository root "
                "for callers, connections, shared types, parameters, and configurations."
            ),
        },
        "chisel_sources": chisel_sources,
        "rtl_sources": rtl_sources,
        "exploration_rules": [
            "Use the supplied final module specs as intended-behavior inputs.",
            "Use raw HDL as supplementary implementation evidence without claiming elaboration.",
            "The listed target files are starting points, not a read allowlist; "
            "explore relevant integration sources anywhere under the repository root.",
            "Search configuration sources freely. If several configurations apply, "
            "no configuration can be found, or applicability is unclear, retain OPEN "
            "items and continue without selecting a default.",
            "Distinguish a module definition from its instances and describe instance "
            "conditions only when source establishes them.",
            "Preserve material source/spec conflicts as OPEN items instead of "
            "silently choosing one.",
        ],
    }


def _input_manifest(
    inputs: DesignDocumentInputs,
    source_inventory_path: Path,
) -> dict[str, Any]:
    """Create the evidence index supplied to the design-document writer.

    Stage 1--5 artifacts remain hook-internal: they establish dialect, scope,
    root selection, and artifact readiness without becoming claimed DUT facts.
    """
    work_dir = inputs.work_dir
    submodules = read_plugin_submodules(inputs.project_root)
    artifact_records = []
    for unit in inputs.eligible_units:
        self_spec, dependency_info = _module_artifact_paths(inputs, unit)
        artifact_records.append({
            "name": unit.name,
            "module_name": unit.module_name,
            "source": unit.source_relpath,
            "self_spec": _relative_to_work(self_spec, work_dir),
            "dependency_info": _relative_to_work(dependency_info, work_dir),
        })
    return {
        "purpose": (
            "Run-scoped input index for the FM-Agent chip design-document writer."
        ),
        "dialect": inputs.dialect,
        "document_language": "zh-CN",
        "selected_root_dut": {
            "name": inputs.root_dut.name,
            "module_name": inputs.root_dut.module_name,
            "source": inputs.root_dut.source_relpath,
        },
        "repository_root": ".",
        "target_scope": {
            "description": (
                "Only the selected scope below contributes formal module artifacts "
                "and determines the design-document DUT."
            ),
            "submodules": list(submodules),
            "root": "." if not submodules else None,
        },
        "context_scope": {
            "repository_root": ".",
            "description": (
                "The writer may explore relevant source files outside target_scope "
                "to understand integration, callers, configuration, and interfaces. "
                "Context files do not become additional output targets."
            ),
        },
        "root_candidates": _display_root_candidates(inputs),
        "root_interpretation": (
            "A root has no known parent inside this analysis scope. It is not "
            "proof of a whole-chip top module; external parents may be absent."
        ),
        "inputs": {
            "source_inventory": _relative_to_work(source_inventory_path, work_dir),
            "template": "chip_design_document_template_zh.md",
        },
        "module_artifacts": artifact_records,
        "evidence_limits": [
            "No build, elaboration, simulation, formal, regression, or Mermaid "
            "rendering ran in this hook.",
            "The run selected one source dialect and provides no "
            "Chisel-to-elaborated-Verilog mapping.",
            "Unsupported claims must remain OPEN, not inferred from naming conventions.",
        ],
    }


def _input_file_paths(
    inputs: DesignDocumentInputs,
    manifest_path: Path,
    source_inventory_path: Path,
) -> list[Path]:
    paths = [manifest_path, source_inventory_path]
    for unit in inputs.eligible_units:
        paths.extend(_module_artifact_paths(inputs, unit))
    return list(dict.fromkeys(paths))


def _scan_markdown(
    content: str,
) -> tuple[list[tuple[int, str]], list[tuple[str, str]], str, list[str]]:
    """Return headings, fences and prose using a small deterministic scanner."""
    headings: list[tuple[int, str]] = []
    fences: list[tuple[str, str]] = []
    prose_lines: list[str] = []
    errors: list[str] = []
    fence_marker: str | None = None
    fence_info = ""
    fence_lines: list[str] = []
    fence_start = 0
    in_comment = False

    for line_number, line in enumerate(content.splitlines(), start=1):
        if fence_marker is not None:
            closing = re.match(r"^[ \t]{0,3}(`{3,}|~{3,})[ \t]*$", line)
            if (
                closing
                and closing.group(1)[0] == fence_marker[0]
                and len(closing.group(1)) >= len(fence_marker)
            ):
                fences.append((fence_info, "\n".join(fence_lines).strip()))
                fence_marker = None
                fence_info = ""
                fence_lines = []
            else:
                fence_lines.append(line)
            prose_lines.append("")
            continue

        if in_comment:
            if "-->" in line:
                in_comment = False
            prose_lines.append("")
            continue
        if "<!--" in line:
            if "-->" not in line.split("<!--", 1)[1]:
                in_comment = True
            prose_lines.append("")
            continue

        opening = re.match(r"^[ \t]{0,3}(`{3,}|~{3,})(.*)$", line)
        if opening:
            fence_marker = opening.group(1)
            fence_info = opening.group(2).strip()
            fence_start = line_number
            prose_lines.append("")
            continue

        heading = re.match(r"^(#{1,6})[ \t]+(.+?)[ \t]*#*[ \t]*$", line)
        if heading:
            headings.append((len(heading.group(1)), heading.group(2).strip()))
        prose_lines.append(line)

    if fence_marker is not None:
        errors.append(f"unclosed Markdown fence starting at line {fence_start}")
    return headings, fences, "\n".join(prose_lines), errors


def _validate_document_structure(
    content: str,
    dut_name: str,
) -> tuple[list[str], list[str]]:
    """Block only on minimum publishability; report template drift as warnings."""
    if not content.strip():
        return ["design document is empty"], []

    headings, fences, _, scan_errors = _scan_markdown(content)
    errors: list[str] = []
    warnings: list[str] = []
    h1s = [title for level, title in headings if level == 1]
    if not any(dut_name in title for title in h1s):
        errors.append(
            "design document must contain an H1 that identifies the selected DUT: "
            f"{dut_name}"
        )

    section_positions: list[int] = []
    for expected in _REQUIRED_MAIN_SECTIONS:
        matches = [
            index for index, (_, title) in enumerate(headings)
            if title == expected
        ]
        if not matches:
            errors.append(
                f"design document is missing a main section heading: {expected}"
            )
        else:
            section_positions.append(matches[0])
    if (
        len(section_positions) == len(_REQUIRED_MAIN_SECTIONS)
        and section_positions != sorted(section_positions)
    ):
        errors.append(
            "design document main sections must appear in body, verification-plan, appendix order"
        )

    expected_h1 = f"{dut_name} 设计与功能检测点文档"
    if h1s != [expected_h1]:
        warnings.append(
            "design document H1 differs from the template suggestion "
            f"'# {expected_h1}'"
        )
    heading_positions = {heading: index for index, heading in enumerate(headings)}
    position = 0
    for expected in _REQUIRED_HEADINGS:
        matched = heading_positions.get(expected)
        if matched is None or matched < position:
            warnings.append(
                "design document differs from the template heading structure at "
                f"{'#' * expected[0]} {expected[1]}"
            )
            continue
        position = matched + 1

    for placeholder in _TEMPLATE_PLACEHOLDERS:
        if placeholder in content:
            warnings.append(
                "design document contains an unreplaced template placeholder: "
                f"{placeholder}"
            )
    for directive in _TEMPLATE_DIRECTIVES:
        if directive in content:
            warnings.append(
                f"design document retains a template writing directive: {directive}"
            )
    if "<!-- FM_AGENT_SPEC_INDEX -->" in content:
        warnings.append("design document retains the obsolete Overview index marker")

    warnings.extend(scan_errors)

    for info, source in fences:
        if info.lower() == "mermaid" and not source:
            warnings.append("Mermaid fence is empty")

    if not any(
        title.startswith("`P-") or title.startswith("P-")
        for _, title in headings
    ):
        warnings.append("design document has no visible P-* behavior heading")
    warnings = list(dict.fromkeys(warnings))
    return errors, warnings


def _publish_candidate(
    pending_path: Path,
    final_path: Path,
    inputs: DesignDocumentInputs,
) -> tuple[list[str], list[str]]:
    try:
        candidate = pending_path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        return [f"design-document candidate was not written as UTF-8: {exc}"], []
    errors, warnings = _validate_document_structure(
        candidate,
        inputs.root_dut.module_name,
    )
    if errors:
        return errors, warnings
    os.replace(pending_path, final_path)
    return [], warnings


def _generation_prompt(manifest_relpath: str, feedback: list[str]) -> str:
    prompt = (
        "Generate the FM-Agent chip design document now. Read the staged workflow, "
        "the Chinese document template, and the run input index at "
        f"fm_agent/{manifest_relpath}. Read every listed _spec.md and _info.md artifact "
        "before writing only fm_agent/chip/design_document.pending.md. The source "
        "inventory lists target-scope starting points, not a read allowlist; explore "
        "relevant integration and configuration sources elsewhere under the repository root."
    )
    if feedback:
        prompt += (
            "\n\nThe previous candidate was rejected. Correct all of these issues:\n- "
            + "\n- ".join(feedback)
        )
    return prompt


def _stage_writer_resources(work_dir: Path) -> tuple[Path, Path]:
    """Copy the exact workflow and template used by this run into fm_agent.

    Preserving these copies keeps the OpenCode trace self-contained and prevents
    later source-tree edits from changing how an existing run is interpreted.
    """
    prompts_dir = Path(__file__).with_name("prompts")
    resources = (
        (
            prompts_dir / "workflow_generate_design_document.md",
            work_dir / "workflow_generate_design_document.md",
        ),
        (
            prompts_dir / "chip_design_document_template_zh.md",
            work_dir / "chip_design_document_template_zh.md",
        ),
    )
    staged: list[Path] = []
    for source_path, destination_path in resources:
        if not source_path.is_file():
            raise FileNotFoundError(
                f"missing chip design-document resource: {source_path}"
            )
        if source_path.resolve() != destination_path.resolve():
            shutil.copy2(source_path, destination_path)
        staged.append(destination_path)
    return staged[0], staged[1]


def _clear_previous_output(final_path: Path, pending_path: Path) -> None:
    """Apply the approved fresh semantics only when the output hook starts."""
    final_path.parent.mkdir(parents=True, exist_ok=True)
    for path in (final_path, pending_path):
        if path.exists() and not path.is_file():
            raise RuntimeError(
                f"cannot prepare chip design document: expected a file at {path}"
            )
        path.unlink(missing_ok=True)


def _remove_direct_final_write(final_path: Path) -> None:
    """Ensure the writer cannot bypass pending-candidate validation."""
    if not final_path.exists():
        return
    if not final_path.is_file():
        raise RuntimeError(
            "design-document writer created a non-file at the final output path: "
            f"{final_path}"
        )
    logging.warning(
        "Chip design document: removing writer output at reserved final path %s",
        final_path,
    )
    final_path.unlink()


def _record_candidate_validation(
    inputs: DesignDocumentInputs,
    attempt: int,
    errors: list[str],
    warnings: list[str],
) -> None:
    """Record deterministic post-generation feedback beside the LLM trace."""
    now = utc_now_iso()
    record_trace_event(
        str(inputs.work_dir / "trace"),
        {
            "event_id": new_event_id("validation"),
            "type": "artifact_validation",
            "stage": "chip_design_document",
            "status": "error" if errors else "success",
            "start_time": now,
            "end_time": now,
            "summary": "Validate chip design-document candidate",
            "function_ids": [inputs.root_dut.name],
            "metadata": {
                "attempt": attempt,
                "artifact": "chip/design_document.pending.md",
                "errors": errors,
                "warnings": warnings,
            },
        },
    )


def generate_design_document(proj_dir: str) -> None:
    """Generate and atomically publish ``fm_agent/chip/design_document.md``."""
    _, _, chip_dir = _work_paths(proj_dir)
    final_path = chip_dir / "design_document.md"
    pending_path = chip_dir / "design_document.pending.md"
    _clear_previous_output(final_path, pending_path)

    inputs, topdown_data = _collect_inputs(proj_dir)
    _validate_module_artifacts(inputs, topdown_data)

    source_inventory_path = chip_dir / "design_document.source_inventory.json"
    _write_json_atomically(source_inventory_path, _source_inventory(inputs))
    manifest_path = chip_dir / "design_document.input.json"
    _write_json_atomically(
        manifest_path,
        _input_manifest(inputs, source_inventory_path),
    )
    workflow_path, template_path = _stage_writer_resources(inputs.work_dir)
    input_paths = [
        workflow_path,
        template_path,
        *_input_file_paths(inputs, manifest_path, source_inventory_path),
    ]
    input_relpaths = [_relative_to_work(path, inputs.work_dir) for path in input_paths]
    feedback: list[str] = []
    attempts = max(1, OPENCODE_MAX_RETRIES)
    for attempt in range(1, attempts + 1):
        # Remove any direct-to-final write from a rejected/disobedient prior
        # attempt. Only a validated pending candidate may become final.
        _clear_previous_output(final_path, pending_path)
        command = build_llm_cli_command(
            model=OPENCODE_SPEC_MODEL,
            prompt=_generation_prompt(
                _relative_to_work(manifest_path, inputs.work_dir),
                feedback,
            ),
            cwd=str(inputs.project_root),
            files=[str(path) for path in input_paths],
        )
        try:
            run_opencode_traced(
                proj_dir=str(inputs.project_root),
                work_dir=str(inputs.work_dir),
                command=command,
                stage="chip_design_document",
                function_ids=[unit.name for unit in inputs.eligible_units],
                input_files=input_relpaths,
                output_files=["chip/design_document.pending.md"],
                summary=(
                    "Generate chip design document for "
                    f"{inputs.root_dut.name} (attempt {attempt}/{attempts})"
                ),
                metadata={
                    "dialect": inputs.dialect,
                    "root_dut": inputs.root_dut.name,
                    "eligible_module_count": len(inputs.eligible_units),
                    "attempt": attempt,
                    "previous_validation_feedback": feedback,
                },
            )
        except Exception as exc:
            feedback = [f"design-document generation command failed: {exc}"]
            logging.warning(
                "Chip design document: generation attempt %d/%d failed: %s",
                attempt,
                attempts,
                exc,
            )
            continue

        _remove_direct_final_write(final_path)
        feedback, warnings = _publish_candidate(pending_path, final_path, inputs)
        _record_candidate_validation(inputs, attempt, feedback, warnings)
        if not feedback:
            for warning in warnings:
                logging.warning("Chip design document: %s", warning)
            logging.info(
                "Chip design document: published generated output to %s",
                final_path,
            )
            return
        logging.warning(
            "Chip design document: candidate attempt %d/%d rejected: %s",
            attempt,
            attempts,
            "; ".join(feedback),
        )

    _clear_previous_output(final_path, pending_path)
    raise RuntimeError(
        "chip design-document generation failed after "
        f"{attempts} attempt(s): {'; '.join(feedback)}"
    )

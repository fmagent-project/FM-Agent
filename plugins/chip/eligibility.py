"""Chip-specific artifact eligibility prepared before public Stage 6.

The public pipeline already exposes a ``type=modify`` input hook for Stage 6.
This module uses that narrow seam to apply the Chisel artifact policy without
teaching the shared pipeline about chip-specific source semantics.
"""

from __future__ import annotations

import copy
import hashlib
import json
import logging
import os
import re
import shutil
from pathlib import Path
from typing import Any

from src.languages.chisel import (
    chisel_defines_io,
    extracted_module_classifications,
)
from src.languages.hardware import CHISEL_EXTENSIONS


ELIGIBILITY_SCHEMA_VERSION = 2
ELIGIBILITY_HOOK_VERSION = "chip-chisel-eligibility-v3"
TOPDOWN_FILENAME_RE = re.compile(r"^phase_(?P<phase>\d+)_topdown_layers\.json$")
CHISEL_CIRCT_GRAPH_FILENAME = "chisel_circt_module_graph.json"
EXTRACTED_ARTIFACT_SUFFIXES = ("_spec.md", "_info.md")


def _project_root(proj_dir: str | os.PathLike[str]) -> Path:
    root = Path(os.path.abspath(os.fspath(proj_dir)))
    return root.parent if root.name == "fm_agent" else root


def _work_dir(proj_dir: str | os.PathLike[str]) -> Path:
    return _project_root(proj_dir) / "fm_agent"


def _read_json(path: Path) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"unable to read JSON input {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise ValueError(f"expected a JSON object in {path}")
    return data


def _json_bytes(data: dict[str, Any]) -> bytes:
    return (
        json.dumps(data, indent=2, ensure_ascii=False)
        + "\n"
    ).encode("utf-8")


def _write_json(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(_json_bytes(data))


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _is_chisel_run(phases_data: dict[str, Any]) -> bool:
    languages = phases_data.get("languages", ())
    if isinstance(languages, list | tuple | set):
        normalized = {
            str(language).strip().lower()
            for language in languages
            if str(language).strip()
        }
        if "chisel" in normalized:
            return True
        if normalized and "verilog" in normalized and "chisel" not in normalized:
            return False

    # Keep the hook useful for hand-built/resume fixtures whose phases.json
    # predates the language field. A Scala/Chisel extension is sufficient to
    # opt in; Verilog-only phases do not have one.
    for phase in phases_data.get("phases", ()):
        if not isinstance(phase, dict):
            continue
        for module in phase.get("modules", ()):
            if not isinstance(module, dict):
                continue
            for source_file in module.get("source_files", ()):
                if isinstance(source_file, str):
                    if Path(source_file).suffix.lower() in CHISEL_EXTENSIONS:
                        return True
    return False


def _normalize_work_relative_path(work_dir: Path, raw_path: str) -> tuple[Path, str]:
    """Resolve a topdown ``file`` field while forbidding scope escape."""
    value = raw_path.replace("\\", "/")
    work_prefix = f"{work_dir.name}/"
    if value.startswith(work_prefix):
        value = value[len(work_prefix):]

    candidate = Path(value)
    if not candidate.is_absolute():
        candidate = work_dir / candidate
    # Resolve symlinks before the containment check so a seemingly local
    # extracted path cannot redirect the hook outside fm_agent.
    candidate = Path(os.path.realpath(candidate))
    work_root = Path(os.path.realpath(work_dir))
    try:
        relative = candidate.relative_to(work_root)
    except ValueError as exc:
        raise ValueError(
            f"topdown extracted file escapes fm_agent: {raw_path!r}"
        ) from exc
    return candidate, relative.as_posix()


def _topdown_paths(work_dir: Path) -> list[Path]:
    spec_prompts = work_dir / "spec_prompts"
    paths = []
    for path in spec_prompts.glob("phase_*_topdown_layers.json"):
        if not path.is_file():
            continue
        if TOPDOWN_FILENAME_RE.fullmatch(path.name):
            paths.append(path)
    return sorted(
        paths,
        key=lambda path: int(TOPDOWN_FILENAME_RE.fullmatch(path.name)["phase"]),
    )


def _backup_original_topdown(
    topdown_path: Path,
    backup_dir: Path,
) -> tuple[dict[str, Any], Path, bool]:
    """Load the unfiltered view, making repeated hook calls idempotent."""
    backup_path = backup_dir / topdown_path.name
    resumed = backup_path.exists()

    if resumed:
        source_path = backup_path
    else:
        source_path = topdown_path

    original_data = _read_json(source_path)
    if not resumed:
        backup_path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(topdown_path, backup_path)
    return original_data, backup_path, resumed


def _read_extracted_source(
    work_dir: Path,
    file_value: str,
) -> tuple[Path, str, bytes]:
    if not isinstance(file_value, str) or not file_value.strip():
        raise ValueError("topdown function entry is missing a non-empty 'file'")
    source_path, relative_path = _normalize_work_relative_path(
        work_dir,
        file_value,
    )
    if not source_path.is_file():
        raise FileNotFoundError(
            f"topdown function points to missing extracted source: {source_path}"
        )
    try:
        source_bytes = source_path.read_bytes()
    except OSError as exc:
        raise RuntimeError(
            f"unable to read extracted source {source_path}: {exc}"
        ) from exc
    return source_path, relative_path, source_bytes


def _entry_source_record(
    work_dir: Path,
    entry: dict[str, Any],
) -> tuple[Path, str, bytes, str, str]:
    name = entry.get("name")
    if not isinstance(name, str) or not name.strip():
        raise ValueError("topdown function entry is missing a non-empty 'name'")

    source_path, relative_path, source_bytes = _read_extracted_source(
        work_dir,
        entry.get("file"),
    )
    return (
        source_path,
        relative_path,
        source_bytes,
        name,
        _sha256(source_bytes),
    )


def _entry_module_classification(
    entry_name: str,
    relative_path: str,
    classifications: dict[str, tuple[dict[str, object], ...]],
) -> tuple[bool, str]:
    """Resolve an extracted topdown entry to its language-level Module status."""
    candidates = classifications.get(entry_name)
    if candidates is None:
        normalized = relative_path.replace("\\", "/")
        prefix = "extracted_functions/"
        if normalized.startswith(prefix):
            normalized = normalized[len(prefix):]
        fallback_key = "::".join(Path(normalized).with_suffix("").parts)
        candidates = classifications.get(fallback_key)

    if not candidates:
        return False, "classification_unavailable"

    entry_declared_name = entry_name.rsplit("::", 1)[-1]
    named = tuple(
        record
        for record in candidates
        if record.get("declared_name") == entry_declared_name
    )
    if len(named) == 1:
        record = named[0]
    elif len(candidates) == 1:
        record = candidates[0]
    else:
        return False, "ambiguous_extracted_declaration"

    is_module = record.get("is_module")
    reason = record.get("reason")
    if not isinstance(is_module, bool) or not isinstance(reason, str) or not reason:
        return False, "invalid_module_classification"
    return is_module, reason


def _entry_eligibility(
    work_dir: Path,
    entry: dict[str, Any],
    classifications: dict[str, tuple[dict[str, object], ...]],
) -> dict[str, object]:
    """Evaluate the combined chip Module and ``val io`` artifact policy."""
    source_path, relative_path, source_bytes, name, source_hash = (
        _entry_source_record(work_dir, entry)
    )
    is_chisel = source_path.suffix.lower() in CHISEL_EXTENSIONS
    if not is_chisel:
        return {
            "eligible": True,
            "name": name,
            "file": relative_path,
            "source_sha256": source_hash,
            "is_module": None,
            "module_classification_reason": "not_chisel",
            "has_val_io": None,
            "reason": "non_chisel",
        }

    is_module, module_reason = _entry_module_classification(
        name,
        relative_path,
        classifications,
    )
    has_val_io = chisel_defines_io(
        source_bytes.decode("utf-8", errors="replace")
    )
    if not is_module:
        reason = f"not_module:{module_reason}"
    elif not has_val_io:
        reason = "missing_val_io"
    else:
        reason = "has_module_and_val_io"

    return {
        "eligible": is_module and has_val_io,
        "name": name,
        "file": relative_path,
        "source_sha256": source_hash,
        "is_module": is_module,
        "module_classification_reason": module_reason,
        "has_val_io": has_val_io,
        "reason": reason,
    }


def _scan_topdown(
    original_data: dict[str, Any],
    work_dir: Path,
    classifications: dict[str, tuple[dict[str, object], ...]],
) -> tuple[list[dict[str, object]], list[dict[str, object]], set[str]]:
    layers = original_data.get("layers")
    if not isinstance(layers, list):
        raise ValueError("topdown JSON must contain a 'layers' array")

    kept: list[dict[str, object]] = []
    skipped: list[dict[str, object]] = []
    excluded_names: set[str] = set()

    for layer in layers:
        if not isinstance(layer, dict):
            raise ValueError("topdown 'layers' entries must be objects")
        functions = layer.get("functions", [])
        if not isinstance(functions, list):
            raise ValueError("topdown layer 'functions' must be an array")
        for entry in functions:
            if not isinstance(entry, dict):
                raise ValueError("topdown function entries must be objects")
            evaluation = _entry_eligibility(
                work_dir,
                entry,
                classifications,
            )
            record = {
                "name": evaluation["name"],
                "file": evaluation["file"],
                "reason": evaluation["reason"],
                "source_sha256": evaluation["source_sha256"],
                "is_module": evaluation["is_module"],
                "module_classification_reason": evaluation[
                    "module_classification_reason"
                ],
                "has_val_io": evaluation["has_val_io"],
            }
            if evaluation["eligible"] is not True:
                excluded_names.add(evaluation["name"])
                skipped.append(record)
            else:
                kept.append(record)

    kept.sort(key=lambda item: (item["name"], item["file"]))
    skipped.sort(key=lambda item: (item["name"], item["file"]))
    return kept, skipped, excluded_names


def _annotate_topdown(
    original_data: dict[str, Any],
    work_dir: Path,
    classifications: dict[str, tuple[dict[str, object], ...]],
) -> dict[str, Any]:
    """Add artifact eligibility without removing context graph nodes.

    The old chip runner dropped non-Module/no-IO batches immediately before
    invoking the LLM, but retained the complete extracted declaration graph
    for dependency context. The public pipeline has no separate batch hook, so
    the plugin records that same decision on each topdown entry and the
    generic batch builder omits only entries marked ineligible. Keeping the
    graph intact is important: parent ``_info.md`` files still need
    Bundle/trait dependencies.
    """
    layers = original_data.get("layers")
    if not isinstance(layers, list):
        raise ValueError("topdown JSON must contain a 'layers' array")

    annotated_data = copy.deepcopy(original_data)
    annotated_layers = []
    artifact_count = 0
    context_count = 0
    for layer in layers:
        annotated_layer = copy.deepcopy(layer)
        annotated_functions = []
        for entry in layer.get("functions", []):
            evaluation = _entry_eligibility(
                work_dir,
                entry,
                classifications,
            )
            annotated_entry = copy.deepcopy(entry)
            annotated_entry["artifact_eligible"] = evaluation["eligible"]
            annotated_entry["eligibility_reason"] = evaluation["reason"]
            annotated_entry["is_module"] = evaluation["is_module"]
            annotated_entry["module_classification_reason"] = evaluation[
                "module_classification_reason"
            ]
            annotated_entry["has_val_io"] = evaluation["has_val_io"]
            if evaluation["eligible"] is True:
                artifact_count += 1
            else:
                context_count += 1
            annotated_functions.append(annotated_entry)
        annotated_layer["functions"] = annotated_functions
        annotated_layers.append(annotated_layer)

    annotated_data["layers"] = annotated_layers
    annotated_data["total_layers"] = len(annotated_layers)
    annotated_data["total_functions"] = artifact_count + context_count
    annotated_data["artifact_eligible_functions"] = artifact_count
    annotated_data["context_only_functions"] = context_count
    annotated_data["eligibility_view"] = "full_context"
    return annotated_data


def _stale_excluded_artifacts(
    work_dir: Path,
    skipped: list[dict[str, str]],
) -> list[str]:
    stale: set[str] = set()
    for item in skipped:
        source_path, _relative_path = _normalize_work_relative_path(
            work_dir,
            item["file"],
        )
        for suffix in EXTRACTED_ARTIFACT_SUFFIXES:
            artifact = source_path.with_name(source_path.stem + suffix)
            if artifact.is_file():
                work_root = Path(os.path.realpath(work_dir))
                stale.add(artifact.relative_to(work_root).as_posix())
    return sorted(stale)


def _backend_name(work_dir: Path) -> str:
    graph_path = work_dir / CHISEL_CIRCT_GRAPH_FILENAME
    if not graph_path.is_file():
        return "source-fallback"
    try:
        graph = _read_json(graph_path)
    except (RuntimeError, ValueError):
        return "unknown"
    if graph.get("source") == "direct-pass" and graph.get("schema_version") == 1:
        return "direct-pass"
    return "unknown"


def prepare_spec_generation(proj_dir: str) -> None:
    """Prepare the Chisel-eligible view consumed by public Stage 6.

    The hook mutates only generated ``fm_agent/spec_prompts`` metadata. Source
    files and the shared pipeline remain untouched. Repeated calls use the
    first-run topdown backup as their input, which makes the transformation
    idempotent. The topdown graph remains complete; only its artifact
    eligibility is annotated for the Stage 6 batch builder.
    """
    work_dir = _work_dir(proj_dir)
    phases_path = work_dir / "phases.json"
    if not phases_path.is_file():
        raise FileNotFoundError(
            f"chip Stage 6 eligibility requires {phases_path}"
        )
    phases_data = _read_json(phases_path)
    if not _is_chisel_run(phases_data):
        logging.info(
            "[Chip] Stage 6 eligibility skipped: selected run is not Chisel."
        )
        return None

    topdown_paths = _topdown_paths(work_dir)
    if not topdown_paths:
        logging.info(
            "[Chip] Stage 6 eligibility skipped: no generated topdown layers."
        )
        return None

    backup_dir = work_dir / "chip" / "eligibility" / "original_topdown"
    classifications = extracted_module_classifications(proj_dir)
    original_views: list[tuple[Path, dict[str, Any], Path, bytes]] = []
    all_kept: list[dict[str, object]] = []
    all_skipped: list[dict[str, object]] = []
    annotated_views: list[tuple[Path, dict[str, Any], bytes, bytes]] = []
    all_excluded_names: set[str] = set()

    for topdown_path in topdown_paths:
        original_data, backup_path, _was_resumed = _backup_original_topdown(
            topdown_path,
            backup_dir,
        )
        kept, skipped, excluded_names = _scan_topdown(
            original_data,
            work_dir,
            classifications,
        )
        original_bytes = backup_path.read_bytes()
        original_views.append(
            (topdown_path, original_data, backup_path, original_bytes)
        )
        all_kept.extend(kept)
        all_skipped.extend(skipped)
        all_excluded_names.update(excluded_names)

    for (
        topdown_path,
        original_data,
        _backup_path,
        original_bytes,
    ) in original_views:
        annotated_data = _annotate_topdown(
            original_data,
            work_dir,
            classifications,
        )
        annotated_bytes = _json_bytes(annotated_data)
        annotated_views.append(
            (topdown_path, annotated_data, original_bytes, annotated_bytes)
        )

    for topdown_path, _annotated_data, _original_bytes, annotated_bytes in annotated_views:
        topdown_path.write_bytes(annotated_bytes)

    topdown_manifest = []
    for topdown_path, _annotated_data, original_bytes, annotated_bytes in annotated_views:
        backup_path = backup_dir / topdown_path.name
        topdown_manifest.append(
            {
                "file": topdown_path.relative_to(work_dir).as_posix(),
                "original_backup": backup_path.relative_to(work_dir).as_posix(),
                "original_sha256": _sha256(original_bytes),
                "filtered_sha256": _sha256(annotated_bytes),
                "view": "full_context_with_artifact_eligibility",
            }
        )

    manifest = {
        "schema_version": ELIGIBILITY_SCHEMA_VERSION,
        "hook_version": ELIGIBILITY_HOOK_VERSION,
        "dialect": "chisel",
        "policy": "requires_module_and_val_io",
        "detector": "src.languages.chisel.chisel_defines_io",
        "module_detector": "src.languages.chisel.extracted_module_classifications",
        "topdown_view": "full_context_with_artifact_eligibility",
        "batch_filter": "artifact_eligible",
        "backend": _backend_name(work_dir),
        "resume": {
            "backup_strategy": "original_topdown",
            "idempotent": True,
        },
        "topdown": topdown_manifest,
        "kept": sorted(all_kept, key=lambda item: (item["name"], item["file"])),
        "skipped": sorted(
            all_skipped,
            key=lambda item: (item["name"], item["file"]),
        ),
        "stale_excluded_artifacts": _stale_excluded_artifacts(
            work_dir,
            all_skipped,
        ),
    }
    manifest["excluded_names"] = sorted(all_excluded_names)
    _write_json(work_dir / "chip" / "eligibility.json", manifest)

    logging.info(
        "[Chip] Stage 6 eligibility: kept %d Chisel unit(s), skipped %d "
        "without Module + val io.",
        len(all_kept),
        len(all_skipped),
    )
    return None

"""Authoritative, immutable inputs for one boundary-witness gate attempt."""

from __future__ import annotations

import hashlib
import json
import os
import uuid
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Any, Mapping


CONTEXT_SCHEMA_VERSION = 2


@dataclass(frozen=True)
class ManifestEntry:
    manifest_id: str
    file: str
    fn_name: str
    occurrence: int
    source_line: int
    fields: Mapping[str, str]
    opts: Mapping[str, Any]


@dataclass(frozen=True)
class ValidationContext:
    bug_id: str
    function_id: str
    project_dir: Path
    baseline_project_dir: Path
    validation_dir: Path
    logic_result_path: Path
    logic_result_sha256: str
    source_sha256: str
    manifest_path: Path
    manifest_sha256: str
    manifest_entry: ManifestEntry
    probe_path: Path
    scratch_dir: Path
    release_ccc: Path
    release_binary_sha256: str
    reference_cc: Path
    reference_binary_sha256: str
    audit_ccc: Path
    audit_binary_sha256: str
    coverage_ccc: Path
    coverage_binary_sha256: str
    sanity_corpus_dir: Path
    sanity_corpus_sha256: str
    attempt: int


# PIN: validation-publication-matches-rechecked-inputs
def same_validation_inputs(left: ValidationContext, right: ValidationContext) -> bool:
    """Return whether two contexts describe the same Gate-relevant inputs."""
    fields = (
        "bug_id", "function_id", "logic_result_sha256", "source_sha256",
        "manifest_sha256", "release_binary_sha256", "reference_binary_sha256",
        "audit_binary_sha256", "coverage_binary_sha256", "sanity_corpus_sha256",
    )
    return all(getattr(left, field) == getattr(right, field) for field in fields) \
        and left.manifest_entry == right.manifest_entry


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _sha256_file(path: Path, label: str) -> str:
    try:
        return _sha256_bytes(path.read_bytes())
    except OSError as exc:
        raise ValueError(f"{label} is unreadable: {path}: {exc}") from exc


def sha256_directory(path: Path | str, label: str = "directory") -> str:
    """Hash a regular-file tree by relative path, mode, and contents."""
    root = Path(path)
    if root.is_symlink() or not root.is_dir():
        raise ValueError(f"{label} is missing or unsafe: {root}")
    digest = hashlib.sha256()
    try:
        for child in sorted(root.rglob("*")):
            if child.is_symlink():
                raise ValueError(f"{label} contains an unsafe symlink: {child}")
            if not child.is_file():
                continue
            relative = child.relative_to(root).as_posix().encode("utf-8")
            mode = child.stat().st_mode & 0o7777
            data = child.read_bytes()
            digest.update(len(relative).to_bytes(8, "big"))
            digest.update(relative)
            digest.update(mode.to_bytes(4, "big"))
            digest.update(len(data).to_bytes(8, "big"))
            digest.update(data)
    except OSError as exc:
        raise ValueError(f"{label} is unreadable: {root}: {exc}") from exc
    return digest.hexdigest()


def _deep_freeze(value: Any) -> Any:
    if type(value) is dict:
        return MappingProxyType({key: _deep_freeze(item) for key, item in value.items()})
    if type(value) is list:
        return tuple(_deep_freeze(item) for item in value)
    return value


def _deep_thaw(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {key: _deep_thaw(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [_deep_thaw(item) for item in value]
    return value


def validation_context_document(context: ValidationContext) -> dict[str, Any]:
    """Return the complete, JSON-safe input contract for a local gate run."""
    entry = context.manifest_entry
    return {
        "schema_version": CONTEXT_SCHEMA_VERSION,
        "bug_id": context.bug_id,
        "function_id": context.function_id,
        "project_dir": str(context.project_dir),
        "baseline_project_dir": str(context.baseline_project_dir),
        "validation_dir": str(context.validation_dir),
        "logic_result_path": str(context.logic_result_path),
        "logic_result_sha256": context.logic_result_sha256,
        "source_sha256": context.source_sha256,
        "manifest_path": str(context.manifest_path),
        "manifest_sha256": context.manifest_sha256,
        "manifest_entry": {
            "manifest_id": entry.manifest_id,
            "file": entry.file,
            "fn_name": entry.fn_name,
            "occurrence": entry.occurrence,
            "source_line": entry.source_line,
            "fields": dict(entry.fields),
            "opts": _deep_thaw(entry.opts),
        },
        "probe_path": str(context.probe_path),
        "scratch_dir": str(context.scratch_dir),
        "release_ccc": str(context.release_ccc),
        "release_binary_sha256": context.release_binary_sha256,
        "reference_cc": str(context.reference_cc),
        "reference_binary_sha256": context.reference_binary_sha256,
        "audit_ccc": str(context.audit_ccc),
        "audit_binary_sha256": context.audit_binary_sha256,
        "coverage_ccc": str(context.coverage_ccc),
        "coverage_binary_sha256": context.coverage_binary_sha256,
        "sanity_corpus_dir": str(context.sanity_corpus_dir),
        "sanity_corpus_sha256": context.sanity_corpus_sha256,
        "attempt": context.attempt,
    }


_CONTEXT_DOCUMENT_KEYS = frozenset({
    "schema_version", "bug_id", "function_id", "project_dir",
    "baseline_project_dir", "validation_dir",
    "logic_result_path", "logic_result_sha256", "source_sha256", "manifest_path",
    "manifest_sha256", "manifest_entry", "probe_path", "scratch_dir", "release_ccc",
    "release_binary_sha256", "reference_cc", "reference_binary_sha256", "audit_ccc",
    "audit_binary_sha256", "coverage_ccc", "coverage_binary_sha256",
    "sanity_corpus_dir", "sanity_corpus_sha256", "attempt",
})
_MANIFEST_ENTRY_KEYS = frozenset({
    "manifest_id", "file", "fn_name", "occurrence", "source_line", "fields", "opts",
})
_PATH_KEYS = (
    "project_dir", "baseline_project_dir", "validation_dir", "logic_result_path",
    "manifest_path", "probe_path", "scratch_dir", "release_ccc", "reference_cc",
    "audit_ccc", "coverage_ccc", "sanity_corpus_dir",
)
_HASH_KEYS = (
    "logic_result_sha256", "source_sha256", "manifest_sha256",
    "release_binary_sha256", "reference_binary_sha256", "audit_binary_sha256",
    "coverage_binary_sha256", "sanity_corpus_sha256",
)


def _context_error(message: str) -> ValueError:
    return ValueError(f"validation context is invalid: {message}")


def validation_context_from_document(document: Any) -> ValidationContext:
    """Parse the exact context schema without consulting submission fields."""
    if type(document) is not dict:
        raise _context_error("document must be an object")
    if set(document) != _CONTEXT_DOCUMENT_KEYS:
        missing = sorted(_CONTEXT_DOCUMENT_KEYS - set(document))
        extra = sorted(set(document) - _CONTEXT_DOCUMENT_KEYS)
        raise _context_error(f"fields mismatch (missing={missing}, extra={extra})")
    if document["schema_version"] != CONTEXT_SCHEMA_VERSION:
        raise _context_error(f"unsupported schema_version {document['schema_version']!r}")
    for key in ("bug_id", "function_id"):
        if type(document[key]) is not str or not document[key]:
            raise _context_error(f"{key} must be a non-empty string")
    paths = {}
    for key in _PATH_KEYS:
        value = document[key]
        if type(value) is not str or not value:
            raise _context_error(f"{key} must be a non-empty path string")
        path = Path(value)
        if not path.is_absolute():
            raise _context_error(f"{key} must be absolute")
        paths[key] = path.resolve()
    for key in _HASH_KEYS:
        value = document[key]
        if type(value) is not str or len(value) != 64 \
                or any(char not in "0123456789abcdef" for char in value):
            raise _context_error(f"{key} must be a lowercase SHA-256 digest")
    if type(document["attempt"]) is not int or document["attempt"] < 1:
        raise _context_error("attempt must be a positive integer")

    raw_entry = document["manifest_entry"]
    if type(raw_entry) is not dict or set(raw_entry) != _MANIFEST_ENTRY_KEYS:
        raise _context_error("manifest_entry fields do not match the schema")
    for key in ("manifest_id", "file", "fn_name"):
        if type(raw_entry[key]) is not str or not raw_entry[key]:
            raise _context_error(f"manifest_entry.{key} must be a non-empty string")
    for key in ("occurrence", "source_line"):
        if type(raw_entry[key]) is not int or raw_entry[key] < (1 if key == "source_line" else 0):
            raise _context_error(f"manifest_entry.{key} is invalid")
    if type(raw_entry["fields"]) is not dict or any(
        type(key) is not str or type(value) is not str
        for key, value in raw_entry["fields"].items()
    ):
        raise _context_error("manifest_entry.fields must map strings to strings")
    if type(raw_entry["opts"]) is not dict:
        raise _context_error("manifest_entry.opts must be an object")

    entry = ManifestEntry(
        manifest_id=raw_entry["manifest_id"],
        file=raw_entry["file"],
        fn_name=raw_entry["fn_name"],
        occurrence=raw_entry["occurrence"],
        source_line=raw_entry["source_line"],
        fields=MappingProxyType(dict(raw_entry["fields"])),
        opts=_deep_freeze(raw_entry["opts"]),
    )
    return ValidationContext(
        bug_id=document["bug_id"],
        function_id=document["function_id"],
        project_dir=paths["project_dir"],
        baseline_project_dir=paths["baseline_project_dir"],
        validation_dir=paths["validation_dir"],
        logic_result_path=paths["logic_result_path"],
        logic_result_sha256=document["logic_result_sha256"],
        source_sha256=document["source_sha256"],
        manifest_path=paths["manifest_path"],
        manifest_sha256=document["manifest_sha256"],
        manifest_entry=entry,
        probe_path=paths["probe_path"],
        scratch_dir=paths["scratch_dir"],
        release_ccc=paths["release_ccc"],
        release_binary_sha256=document["release_binary_sha256"],
        reference_cc=paths["reference_cc"],
        reference_binary_sha256=document["reference_binary_sha256"],
        audit_ccc=paths["audit_ccc"],
        audit_binary_sha256=document["audit_binary_sha256"],
        coverage_ccc=paths["coverage_ccc"],
        coverage_binary_sha256=document["coverage_binary_sha256"],
        sanity_corpus_dir=paths["sanity_corpus_dir"],
        sanity_corpus_sha256=document["sanity_corpus_sha256"],
        attempt=document["attempt"],
    )


def write_validation_context(context: ValidationContext, path: Path | str) -> Path:
    """Atomically write a context file that the sandbox will expose read-only."""
    destination = Path(path).resolve()
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_name(f".{destination.name}.{uuid.uuid4().hex}.tmp")
    payload = json.dumps(
        validation_context_document(context), sort_keys=True, ensure_ascii=False,
    ) + "\n"
    try:
        temporary.write_text(payload, encoding="utf-8")
        os.chmod(temporary, 0o400)
        os.replace(temporary, destination)
    finally:
        temporary.unlink(missing_ok=True)
    return destination


def load_validation_context(path: Path | str) -> ValidationContext:
    """Load one regular, non-symlinked harness context file."""
    context_path = Path(path)
    if context_path.is_symlink() or not context_path.is_file():
        raise _context_error(f"context file is missing or unsafe: {context_path}")
    try:
        document = json.loads(context_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise _context_error(f"context file is unreadable: {exc}") from exc
    return validation_context_from_document(document)


def _project_path(project: Path, value: Path | str) -> Path:
    path = Path(value)
    return (path if path.is_absolute() else project / path).resolve()


def _safe_directory_path(project: Path, value: Path | str, label: str) -> Path:
    path = Path(value)
    path = path if path.is_absolute() else project / path
    if path.is_symlink():
        raise ValueError(f"{label} is missing or unsafe: {path}")
    return path.resolve()


# PIN: validation-context-is-authoritative
# PIN: validation-toolchain-is-project-local-and-source-matched
def build_validation_context(
    *,
    logic_result_path: Path | str,
    project_dir: Path | str,
    baseline_project_dir: Path | str,
    validation_dir: Path | str,
    manifest_path: Path | str,
    release_ccc: Path | str,
    reference_cc: Path | str,
    audit_ccc: Path | str,
    coverage_ccc: Path | str,
    sanity_corpus_dir: Path | str,
    attempt: int,
) -> ValidationContext:
    """Build the only authority accepted by the validation gate.

    Identity comes from the requested file below
    ``fm_agent/logic_verification_results`` and must map to an exact audit
    manifest key. Submission fields never participate in this derivation.
    """
    if type(attempt) is not int or attempt < 1:
        raise ValueError("attempt must be a positive integer")

    project = Path(project_dir).resolve()
    baseline_project = _safe_directory_path(
        project, baseline_project_dir, "baseline project",
    )
    if not baseline_project.is_dir():
        raise ValueError(f"baseline project is missing or unsafe: {baseline_project}")
    logic_path = Path(logic_result_path)
    if not logic_path.is_absolute():
        logic_path = project / logic_path
    logic_path = logic_path.resolve(strict=True)
    results_root = (project / "fm_agent" / "logic_verification_results").resolve()
    try:
        result_rel = logic_path.relative_to(results_root)
    except ValueError as exc:
        raise ValueError("logic result must be below fm_agent/logic_verification_results") from exc
    if result_rel.suffix != ".json":
        raise ValueError("logic result must be a .json file")

    relative_stem = result_rel.with_suffix("").as_posix()
    bug_id = relative_stem.replace("/", "--")
    function_id = relative_stem.replace("/", "::")

    logic_bytes = logic_path.read_bytes()
    try:
        logic_doc = json.loads(logic_bytes)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"logic result is not valid JSON: {exc}") from exc
    if not isinstance(logic_doc, dict):
        raise ValueError("logic result must contain a JSON object")

    manifest = Path(manifest_path)
    if not manifest.is_absolute():
        manifest = project / manifest
    manifest = manifest.resolve(strict=True)
    manifest_bytes = manifest.read_bytes()
    try:
        manifest_doc = json.loads(manifest_bytes)
        entry = manifest_doc["functions"][bug_id]
    except (UnicodeDecodeError, json.JSONDecodeError, KeyError, TypeError) as exc:
        raise ValueError(f"manifest has no authoritative entry for {bug_id}") from exc
    if not isinstance(entry, dict) or not isinstance(entry.get("file"), str) \
            or not isinstance(entry.get("fn_name"), str) \
            or type(entry.get("source_line")) is not int \
            or entry["source_line"] < 1:
        raise ValueError(f"manifest entry for {bug_id} is malformed")
    opts = entry.get("opts") or {}
    if not isinstance(opts, dict):
        raise ValueError(f"manifest opts for {bug_id} must be an object")
    occurrence = opts.get("occurrence", 0)
    if type(occurrence) is not int or occurrence < 0:
        raise ValueError(f"manifest occurrence for {bug_id} must be non-negative")
    fields = opts.get("fields") or {}
    if not isinstance(fields, dict) or any(
        type(k) is not str or type(v) is not str for k, v in fields.items()
    ):
        raise ValueError(f"manifest fields for {bug_id} must map strings to strings")

    validation = Path(validation_dir)
    if not validation.is_absolute():
        validation = project / validation
    validation = validation.resolve()
    attempts_dir = validation / ".attempts"
    attempts_dir.mkdir(parents=True, exist_ok=True)
    scratch = attempts_dir / f"{bug_id}-attempt-{attempt}-{uuid.uuid4().hex}"
    scratch.mkdir(mode=0o700)

    manifest_entry = ManifestEntry(
        manifest_id=bug_id,
        file=entry["file"],
        fn_name=entry["fn_name"],
        occurrence=occurrence,
        source_line=entry["source_line"],
        fields=MappingProxyType(dict(fields)),
        opts=_deep_freeze(opts),
    )
    source_path = project / manifest_entry.file
    baseline_source_path = baseline_project / manifest_entry.file
    baseline_source_sha256 = _sha256_file(
        baseline_source_path, "baseline target source",
    )
    if _sha256_file(source_path, "working target source") != baseline_source_sha256:
        raise ValueError("working target source does not match the clean baseline")
    release_path = _project_path(project, release_ccc)
    reference_path = _project_path(project, reference_cc)
    audit_path = _project_path(project, audit_ccc)
    coverage_path = _project_path(project, coverage_ccc)
    if coverage_path == audit_path:
        raise ValueError("coverage compiler must be independent from the audit compiler")
    corpus_path = _safe_directory_path(project, sanity_corpus_dir, "sanity corpus")
    return ValidationContext(
        bug_id=bug_id,
        function_id=function_id,
        project_dir=project,
        baseline_project_dir=baseline_project,
        validation_dir=validation,
        logic_result_path=logic_path,
        logic_result_sha256=_sha256_bytes(logic_bytes),
        source_sha256=baseline_source_sha256,
        manifest_path=manifest,
        manifest_sha256=_sha256_bytes(manifest_bytes),
        manifest_entry=manifest_entry,
        probe_path=validation / f"_probe_{bug_id}.c",
        scratch_dir=scratch,
        release_ccc=release_path,
        release_binary_sha256=_sha256_file(release_path, "release compiler"),
        reference_cc=reference_path,
        reference_binary_sha256=_sha256_file(reference_path, "reference compiler"),
        audit_ccc=audit_path,
        audit_binary_sha256=_sha256_file(audit_path, "audit compiler"),
        coverage_ccc=coverage_path,
        coverage_binary_sha256=_sha256_file(
            coverage_path, "coverage compiler",
        ),
        sanity_corpus_dir=corpus_path,
        sanity_corpus_sha256=sha256_directory(corpus_path, "sanity corpus"),
        attempt=attempt,
    )

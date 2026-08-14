"""Atomic publication and fail-closed loading of validation artifacts."""

from __future__ import annotations

import hashlib
import json
import os
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

try:
    from .submission_schema import SchemaError, validate_v3
    from .validation_context import sha256_directory
except ImportError:  # flat import for scripts/tests
    from submission_schema import SchemaError, validate_v3
    from validation_context import sha256_directory


SIDECAR_SCHEMA_VERSION = 5
# PIN: l1-patches-are-narrow-and-behaviorally-closed
GATE_VERSION = "boundary-witness-v6"
_SIDECAR_KEYS = {
    "schema_version", "gate_version", "state", "bug_id", "function_id",
    "confirmation_status", "logic_result", "manifest", "source", "release_binary",
    "reference_binary", "audit_binary", "coverage_binary",
    "sanity_corpus", "probe", "l1_patch",
    "result_sha256", "attempt", "grade", "integrity_sha256",
}
_FILE_RECORD_KEYS = {"path", "scope", "sha256"}
_PUBLISHABLE_STATES = {"accepted"}


class ArtifactError(ValueError):
    pass


@dataclass(frozen=True)
class VerifiedArtifact:
    result: dict
    sidecar: dict
    state: str


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _sha256_file(path: Path) -> str:
    try:
        return _sha256_bytes(path.read_bytes())
    except OSError as exc:
        raise ArtifactError(f"required artifact is unreadable: {path}: {exc}") from exc


def _canonical_sha256(value: Any) -> str:
    payload = json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
    ).encode("utf-8")
    return _sha256_bytes(payload)


def _file_record(path: Path, project_dir: Path, expected_sha256: str) -> dict:
    path = path.resolve()
    try:
        stored = path.relative_to(project_dir.resolve()).as_posix()
        scope = "project"
    except ValueError:
        stored = str(path)
        scope = "absolute"
    return {"path": stored, "scope": scope, "sha256": expected_sha256}


def _resolve_file_record(record: Any, project_dir: Path, label: str) -> Path:
    path = _resolve_record_path(record, project_dir, label)
    if _sha256_file(path) != record["sha256"]:
        raise ArtifactError(f"{label} fingerprint is stale")
    return path


def _resolve_record_path(record: Any, project_dir: Path, label: str) -> Path:
    if type(record) is not dict or set(record) != _FILE_RECORD_KEYS:
        raise ArtifactError(f"{label} fingerprint has invalid fields")
    if any(type(record[key]) is not str or not record[key] for key in _FILE_RECORD_KEYS):
        raise ArtifactError(f"{label} fingerprint has invalid values")
    if record["scope"] == "project":
        raw = Path(record["path"])
        if raw.is_absolute():
            raise ArtifactError(f"{label} project path must be relative")
        unresolved = project_dir / raw
        if unresolved.is_symlink():
            raise ArtifactError(f"{label} path must not be a symlink")
        path = unresolved.resolve()
        try:
            path.relative_to(project_dir.resolve())
        except ValueError as exc:
            raise ArtifactError(f"{label} path escapes the project") from exc
    elif record["scope"] == "absolute":
        unresolved = Path(record["path"])
        if not unresolved.is_absolute():
            raise ArtifactError(f"{label} absolute path must be absolute")
        if unresolved.is_symlink():
            raise ArtifactError(f"{label} path must not be a symlink")
        path = unresolved.resolve()
    else:
        raise ArtifactError(f"{label} fingerprint has invalid scope")
    return path


def _resolve_directory_record(record: Any, project_dir: Path, label: str) -> Path:
    path = _resolve_record_path(record, project_dir, label)
    try:
        current = sha256_directory(path, label)
    except ValueError as exc:
        raise ArtifactError(str(exc)) from exc
    if current != record["sha256"]:
        raise ArtifactError(f"{label} fingerprint is stale")
    return path


def _atomic_write_json(path: Path, value: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    data = (json.dumps(value, indent=2, ensure_ascii=False, sort_keys=True) + "\n").encode()
    try:
        with open(temp, "xb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp, path)
    finally:
        temp.unlink(missing_ok=True)


def _context_records(context) -> dict[str, dict]:
    project = Path(context.project_dir).resolve()
    source = project / context.manifest_entry.file
    records = {
        "logic_result": _file_record(
            Path(context.logic_result_path), project, context.logic_result_sha256,
        ),
        "manifest": _file_record(
            Path(context.manifest_path), project, context.manifest_sha256,
        ),
        "source": _file_record(source, project, context.source_sha256),
        "release_binary": _file_record(
            Path(context.release_ccc), project, context.release_binary_sha256,
        ),
        "reference_binary": _file_record(
            Path(context.reference_cc), project, context.reference_binary_sha256,
        ),
        "audit_binary": _file_record(
            Path(context.audit_ccc), project, context.audit_binary_sha256,
        ),
        "coverage_binary": _file_record(
            Path(context.coverage_ccc), project, context.coverage_binary_sha256,
        ),
        "sanity_corpus": _file_record(
            Path(context.sanity_corpus_dir), project, context.sanity_corpus_sha256,
        ),
    }
    for label, record in records.items():
        if label == "sanity_corpus":
            _resolve_directory_record(record, project, label)
        else:
            _resolve_file_record(record, project, label)
    return records


def _checked_project_file(path: Path, project: Path, label: str) -> dict:
    if path.is_symlink() or not path.is_file():
        raise ArtifactError(f"{label} is missing or unsafe: {path}")
    path = path.resolve()
    try:
        path.relative_to(project)
    except ValueError as exc:
        raise ArtifactError(f"{label} is outside the project") from exc
    return _file_record(path, project, _sha256_file(path))


def _evidence_records(result: dict, context) -> dict[str, dict | None]:
    project = Path(context.project_dir).resolve()
    if result["confirmation_status"] == "confirmed":
        expected_probe = Path(context.validation_dir).resolve() / \
            f"_probe_{context.bug_id}.c"
        probe = _checked_project_file(expected_probe, project, "canonical probe")
        try:
            submitted_probe = (project / result["witness"]["probe"]).resolve()
        except (OSError, RuntimeError) as exc:
            raise ArtifactError(f"canonical probe path is invalid: {exc}") from exc
        if submitted_probe != expected_probe:
            raise ArtifactError("result probe does not match the canonical probe")
    else:
        probe = None

    if result.get("grade") == "L1":
        expected_patch = Path(context.validation_dir).resolve() / \
            f"{context.bug_id}.l1.patch"
        patch = _checked_project_file(expected_patch, project, "L1 patch")
        try:
            submitted_patch = (project / result["l1_patch"]).resolve()
        except (OSError, RuntimeError) as exc:
            raise ArtifactError(f"L1 patch path is invalid: {exc}") from exc
        if submitted_patch != expected_patch:
            raise ArtifactError("result L1 patch does not match the canonical patch")
    else:
        patch = None
    return {"probe": probe, "l1_patch": patch}


def _validate_state_result(state: str, result: dict) -> None:
    if state != "accepted":
        raise ArtifactError(f"state is not accepted: {state}")


# PIN: validation-results-require-current-sidecars
# PIN: validation-toolchain-is-project-local-and-source-matched
def publish_validation_artifact(
    result_path: Path | str,
    result: dict,
    context,
    *,
    state: str,
    attempt: int,
) -> Path:
    """Atomically publish a result followed by its hash-bound sidecar.

    Writing the result first is intentional: interruption before the sidecar
    replacement leaves either no sidecar or an old hash, both of which the
    loader rejects.
    """
    if state not in _PUBLISHABLE_STATES:
        raise ArtifactError(f"state is not publishable: {state}")
    if type(attempt) is not int or attempt < 1:
        raise ArtifactError("attempt must be a positive integer")
    try:
        validate_v3(result)
    except SchemaError as exc:
        raise ArtifactError(f"result schema is invalid: {exc}") from exc
    if result["id"] != context.bug_id or result["function_id"] != context.function_id:
        raise ArtifactError("result identity does not match validation context")
    _validate_state_result(state, result)
    result_path = Path(result_path).resolve()
    expected = Path(context.validation_dir).resolve() / f"{context.bug_id}.result.json"
    if result_path != expected:
        raise ArtifactError("result path does not match validation context")

    records = {**_context_records(context), **_evidence_records(result, context)}
    _atomic_write_json(result_path, result)
    result_sha = _sha256_file(result_path)
    payload = {
        "schema_version": SIDECAR_SCHEMA_VERSION,
        "gate_version": GATE_VERSION,
        "state": state,
        "bug_id": context.bug_id,
        "function_id": context.function_id,
        "confirmation_status": result["confirmation_status"],
        **records,
        "result_sha256": result_sha,
        "attempt": attempt,
        "grade": result.get("grade"),
    }
    sidecar = {**payload, "integrity_sha256": _canonical_sha256(payload)}
    gate_path = result_path.with_name(f"{context.bug_id}.gate.json")
    _atomic_write_json(gate_path, sidecar)
    return gate_path


def write_gate_diagnostic(
    context,
    *,
    attempt: int,
    check: str,
    reason: str,
) -> Path:
    """Keep a rejected attempt's reason outside the canonical result paths."""
    if type(attempt) is not int or attempt < 1:
        raise ArtifactError("diagnostic attempt must be a positive integer")
    if type(check) is not str or not check.strip():
        raise ArtifactError("diagnostic check must be a non-empty string")
    if type(reason) is not str or not reason.strip():
        raise ArtifactError("diagnostic reason must be a non-empty string")
    scratch = Path(context.scratch_dir)
    if scratch.is_symlink() or not scratch.is_dir():
        raise ArtifactError("diagnostic scratch directory is missing or unsafe")
    gate_path = scratch.resolve() / "gate-diagnostic.json"
    value = {
        "schema_version": SIDECAR_SCHEMA_VERSION,
        "gate_version": GATE_VERSION,
        "state": "rejected",
        "bug_id": context.bug_id,
        "function_id": context.function_id,
        "attempt": attempt,
        "check": check,
        "reason": reason,
    }
    _atomic_write_json(gate_path, value)
    return gate_path


def _infer_project_dir(result_path: Path) -> Path:
    if result_path.parent.name != "bug_validation" or len(result_path.parents) < 3:
        raise ArtifactError("result path is not below a project work directory")
    return result_path.parents[2].resolve()


def _validate_context_match(sidecar: dict, context, project: Path) -> None:
    if sidecar["bug_id"] != context.bug_id \
            or sidecar["function_id"] != context.function_id:
        raise ArtifactError("sidecar identity does not match expected context")
    expected = _context_records(context)
    for label, record in expected.items():
        if sidecar[label] != record:
            raise ArtifactError(f"sidecar {label} does not match expected context")


def _validate_evidence_records(sidecar: dict, result: dict, project: Path) -> None:
    bug_id = sidecar["bug_id"]
    if result["confirmation_status"] == "confirmed":
        record = sidecar["probe"]
        path = _resolve_file_record(record, project, "canonical probe")
        expected = (project / "fm_agent" / "bug_validation" /
                    f"_probe_{bug_id}.c").resolve()
        if path != expected or (project / result["witness"]["probe"]).resolve() != expected:
            raise ArtifactError("canonical probe record has the wrong path")
    elif sidecar["probe"] is not None:
        raise ArtifactError("not-confirmed result must not carry a probe record")

    if result.get("grade") == "L1":
        record = sidecar["l1_patch"]
        path = _resolve_file_record(record, project, "L1 patch")
        expected = (project / "fm_agent" / "bug_validation" /
                    f"{bug_id}.l1.patch").resolve()
        if path != expected or (project / result["l1_patch"]).resolve() != expected:
            raise ArtifactError("L1 patch record has the wrong path")
    elif sidecar["l1_patch"] is not None:
        raise ArtifactError("non-L1 result must not carry an L1 patch record")


def load_verified_artifact(
    result_path: Path | str,
    *,
    allowed_states: Iterable[str] = ("accepted",),
    context=None,
    project_dir: Path | str | None = None,
) -> VerifiedArtifact:
    """Load an artifact only if every current fingerprint and hash matches."""
    result_path = Path(result_path).resolve()
    project = (Path(project_dir).resolve() if project_dir is not None
               else _infer_project_dir(result_path))
    gate_path = result_path.with_name(
        result_path.name.removesuffix(".result.json") + ".gate.json"
    )
    try:
        result_bytes = result_path.read_bytes()
        result = json.loads(result_bytes)
        sidecar = json.loads(gate_path.read_bytes())
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ArtifactError(f"result or sidecar is unreadable: {exc}") from exc
    if type(sidecar) is not dict or set(sidecar) != _SIDECAR_KEYS:
        raise ArtifactError("sidecar schema has invalid fields")
    if type(sidecar["schema_version"]) is not int \
            or sidecar["schema_version"] != SIDECAR_SCHEMA_VERSION \
            or sidecar["gate_version"] != GATE_VERSION:
        raise ArtifactError("sidecar schema or gate version is obsolete")
    allowed = frozenset(allowed_states)
    if sidecar["state"] not in allowed:
        raise ArtifactError(f"sidecar state is not allowed: {sidecar['state']}")
    if type(sidecar["attempt"]) is not int or sidecar["attempt"] < 1:
        raise ArtifactError("sidecar attempt is invalid")
    payload = {key: value for key, value in sidecar.items()
               if key != "integrity_sha256"}
    if sidecar["integrity_sha256"] != _canonical_sha256(payload):
        raise ArtifactError("sidecar integrity digest does not match")
    if sidecar["result_sha256"] != _sha256_bytes(result_bytes):
        raise ArtifactError("result hash does not match sidecar")
    try:
        validate_v3(result)
    except SchemaError as exc:
        raise ArtifactError(f"published result schema is invalid: {exc}") from exc
    if result["id"] != sidecar["bug_id"] \
            or result["function_id"] != sidecar["function_id"] \
            or result["confirmation_status"] != sidecar["confirmation_status"] \
            or result.get("grade") != sidecar["grade"]:
        raise ArtifactError("result fields do not match sidecar")
    _validate_state_result(sidecar["state"], result)
    for label in ("logic_result", "manifest", "source", "release_binary",
                  "reference_binary", "audit_binary", "coverage_binary",
                  "sanity_corpus"):
        if label == "sanity_corpus":
            _resolve_directory_record(sidecar[label], project, label)
        else:
            _resolve_file_record(sidecar[label], project, label)
    _validate_evidence_records(sidecar, result, project)
    if context is not None:
        _validate_context_match(sidecar, context, project)
    return VerifiedArtifact(result=result, sidecar=sidecar, state=sidecar["state"])


def load_verified_certificate(
    result_path: Path | str,
    *,
    context=None,
    project_dir: Path | str | None = None,
) -> dict | None:
    """Return only a current accepted result; all validation errors become None."""
    try:
        return load_verified_artifact(
            result_path, allowed_states={"accepted"}, context=context,
            project_dir=project_dir,
        ).result
    except ArtifactError:
        return None

"""Version-dispatched, read-only loading for bug-validation artifacts.

This module deliberately keeps three semantic namespaces separate:

* private/main prompt-era checkpoints used by the current compatibility path;
* archived CCC result-v3 + sidecar-v5 certificates from multirun; and
* future current validation outcomes, for which no handler exists yet.

It does not run a Gate, create workspaces, publish artifacts, or upgrade legacy
results into the new outcome/certificate model.
"""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from types import MappingProxyType
from typing import Any, Mapping, NoReturn


LEGACY_CCC_RESULT_SCHEMA_VERSION = 3
LEGACY_CCC_SIDECAR_SCHEMA_VERSION = 5
LEGACY_CCC_GATE_VERSION = "boundary-witness-v6"
LEGACY_CCC_SEMANTIC_NAMESPACE = "legacy.ccc.boundary-witness-v6"

_LEGACY_TERMINAL_STATUSES = frozenset({"confirmed", "not_confirmed", "error"})
_LEGACY_TERMINAL_STRING_FIELDS = frozenset(
    {
        "source_file",
        "function_name",
        "probe_script",
        "detail_file",
        "probe_stdout",
        "trigger_summary",
    }
)
_CCC_NOT_CONFIRMED_KEYS = frozenset(
    {
        "schema_version",
        "id",
        "function_id",
        "confirmation_status",
        "attempts",
        "notes",
    }
)
_CCC_CONFIRMED_KEYS = frozenset(
    {
        "schema_version",
        "id",
        "function_id",
        "confirmation_status",
        "grade",
        "witness",
        "phenomenon",
        "l1_patch",
        "attempts",
        "notes",
    }
)
_CCC_WITNESS_KEYS = frozenset(
    {
        "probe",
        "call_index",
        "captured_input",
        "actual_output",
        "spec_violation_claim",
    }
)
_CCC_PHENOMENON_KEYS = frozenset(
    {"mode", "standard", "extra_args", "expected_kind"}
)
_CCC_MODES = frozenset({"preprocess", "syntax", "asm", "object", "run"})
_CCC_STANDARDS = frozenset(
    {
        "c89",
        "c90",
        "c99",
        "c11",
        "c17",
        "c23",
        "gnu89",
        "gnu90",
        "gnu99",
        "gnu11",
        "gnu17",
        "gnu23",
    }
)
_CCC_PHENOMENON_KINDS = frozenset(
    {
        "preprocess_differs",
        "accept_reject_differs",
        "build_accept_reject_differs",
        "run_exit_differs",
        "stdout_differs",
    }
)
_CCC_SIDECAR_KEYS = frozenset(
    {
        "schema_version",
        "gate_version",
        "state",
        "bug_id",
        "function_id",
        "confirmation_status",
        "logic_result",
        "manifest",
        "source",
        "release_binary",
        "reference_binary",
        "audit_binary",
        "coverage_binary",
        "sanity_corpus",
        "probe",
        "l1_patch",
        "result_sha256",
        "attempt",
        "grade",
        "integrity_sha256",
    }
)
_CCC_FILE_RECORD_KEYS = frozenset({"path", "scope", "sha256"})
_CCC_CONTEXT_BINDINGS = (
    "logic_result",
    "manifest",
    "source",
    "release_binary",
    "reference_binary",
    "audit_binary",
    "coverage_binary",
    "sanity_corpus",
)


class ArtifactFamily(str, Enum):
    UNCLASSIFIED_MATERIALIZATION = "unclassified/materialized"
    PRIVATE_MAIN_PROMPT_LEGACY = "private-main-prompt/unversioned"
    CCC_LEGACY_V3_V5 = "ccc-legacy/result-v3+sidecar-v5"
    CURRENT_OUTCOME_V1 = "validation-outcome/v1"


class TrustClass(str, Enum):
    EXISTS_ONLY = "exists_only"
    PARSED_ONLY = "parsed_only"
    LEGACY_CONTRACT_VALIDATED = "legacy_contract_validated"
    LEGACY_PAIR_INTEGRITY_VERIFIED = "legacy_pair_integrity_verified"
    CURRENT_OUTCOME_VERIFIED = "current_outcome_verified"
    CURRENT_CONFIRMED_CERTIFIED = "current_confirmed_certified"


class LegacyCompletionPolicy(str, Enum):
    DEFAULT_POST_AGENT = "default_post_agent"
    DEFAULT_RESUME = "default_resume"
    ALL_BUGS_TERMINAL = "all_bugs_terminal"


class InspectionFailure(str, Enum):
    MISSING = "missing"
    IO_ERROR = "io_error"
    INVALID_UTF8 = "invalid_utf8"
    MALFORMED_JSON = "malformed_json"
    INVALID_TERMINAL = "invalid_terminal"


class OutcomeLoadErrorCode(str, Enum):
    MISSING = "MISSING"
    NOT_REGULAR_FILE = "NOT_REGULAR_FILE"
    TOO_LARGE = "TOO_LARGE"
    INVALID_UTF8 = "INVALID_UTF8"
    INVALID_JSON = "INVALID_JSON"
    DUPLICATE_JSON_KEY = "DUPLICATE_JSON_KEY"
    AMBIGUOUS_FORMAT = "AMBIGUOUS_FORMAT"
    UNSUPPORTED_VERSION = "UNSUPPORTED_VERSION"
    HANDLER_NOT_AVAILABLE = "HANDLER_NOT_AVAILABLE"
    SCHEMA_INVALID = "SCHEMA_INVALID"
    IDENTITY_MISMATCH = "IDENTITY_MISMATCH"
    SIDECAR_MISSING = "SIDECAR_MISSING"
    SIDECAR_INVALID = "SIDECAR_INVALID"
    INTEGRITY_MISMATCH = "INTEGRITY_MISMATCH"
    ARTIFACT_MISMATCH = "ARTIFACT_MISMATCH"
    STATE_NOT_ACCEPTED = "STATE_NOT_ACCEPTED"
    WRONG_ARTIFACT_FAMILY = "WRONG_ARTIFACT_FAMILY"
    CURRENT_CERTIFICATE_REQUIRED = "CURRENT_CERTIFICATE_REQUIRED"


class LegacyBindingState(str, Enum):
    CURRENT = "CURRENT"
    MISSING = "MISSING"
    STALE = "STALE"
    UNSAFE = "UNSAFE"


class OutcomeLoadError(ValueError):
    def __init__(self, code: OutcomeLoadErrorCode, message: str):
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class LoadLimits:
    max_json_bytes: int = 16 * 1024 * 1024

    def __post_init__(self) -> None:
        if type(self.max_json_bytes) is not int or self.max_json_bytes < 1:
            raise ValueError("max_json_bytes must be a positive integer")


DEFAULT_LOAD_LIMITS = LoadLimits()


@dataclass(frozen=True)
class LoadedValidationResult:
    path: Path
    exists: bool
    parseable: bool
    value: Any
    record: dict[str, Any] | None
    status: str | None
    terminal_valid: bool
    raw_sha256: str | None
    failure: InspectionFailure | None

    def completes(self, policy: LegacyCompletionPolicy) -> bool:
        if policy is LegacyCompletionPolicy.DEFAULT_POST_AGENT:
            return self.exists
        if policy is LegacyCompletionPolicy.DEFAULT_RESUME:
            return self.parseable
        if policy is LegacyCompletionPolicy.ALL_BUGS_TERMINAL:
            return self.terminal_valid
        raise ValueError(f"unknown legacy completion policy: {policy!r}")


@dataclass(frozen=True)
class LegacyPromptCompletion:
    path: Path
    policy: LegacyCompletionPolicy
    trust_class: TrustClass
    raw_sha256: str | None
    value: Any
    reported_status: str | None
    artifact_family: ArtifactFamily = ArtifactFamily.PRIVATE_MAIN_PROMPT_LEGACY

    def to_json_value(self) -> Any:
        return _thaw(self.value)


@dataclass(frozen=True)
class LegacyPromptTerminal:
    path: Path
    bug_id: str
    reported_status: str
    attempts: int
    record: Mapping[str, Any]
    raw_sha256: str
    trust_class: TrustClass = TrustClass.LEGACY_CONTRACT_VALIDATED
    artifact_family: ArtifactFamily = ArtifactFamily.PRIVATE_MAIN_PROMPT_LEGACY

    def to_json_value(self) -> dict[str, Any]:
        return _thaw(self.record)


@dataclass(frozen=True)
class ArtifactInspection:
    path: Path
    artifact_family: ArtifactFamily
    raw_sha256: str
    document: Any


@dataclass(frozen=True)
class LegacyBindingCheck:
    label: str
    state: LegacyBindingState
    path: str
    expected_sha256: str
    actual_sha256: str | None = None
    detail: str | None = None


@dataclass(frozen=True)
class ArchivedLegacyCCCCertificate:
    result_path: Path
    sidecar_path: Path
    result: Mapping[str, Any]
    sidecar: Mapping[str, Any]
    binding_report: tuple[LegacyBindingCheck, ...]
    trust_class: TrustClass = TrustClass.LEGACY_PAIR_INTEGRITY_VERIFIED
    artifact_family: ArtifactFamily = ArtifactFamily.CCC_LEGACY_V3_V5
    semantic_namespace: str = LEGACY_CCC_SEMANTIC_NAMESPACE
    archival_only: bool = True

    @property
    def all_bindings_current(self) -> bool:
        return all(
            check.state is LegacyBindingState.CURRENT
            for check in self.binding_report
        )


def _freeze(value: Any) -> Any:
    if type(value) is dict:
        return MappingProxyType({key: _freeze(item) for key, item in value.items()})
    if type(value) is list:
        return tuple(_freeze(item) for item in value)
    return value


def _thaw(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {key: _thaw(item) for key, item in value.items()}
    if type(value) is tuple:
        return [_thaw(item) for item in value]
    return value


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _canonical_sha256(value: Any) -> str:
    raw = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    return _sha256_bytes(raw)


def legacy_all_bugs_record_is_valid(
    validation: Any,
    expected_bug_id: str,
) -> bool:
    """Preserve private/main's permissive all-bugs terminal contract exactly."""
    if not isinstance(validation, dict):
        return False
    if (
        not isinstance(expected_bug_id, str)
        or not expected_bug_id
        or validation.get("id") != expected_bug_id
        or validation.get("confirmation_status") not in _LEGACY_TERMINAL_STATUSES
    ):
        return False
    if not _LEGACY_TERMINAL_STRING_FIELDS.issubset(validation):
        return False
    if not all(
        isinstance(validation[field], str)
        for field in _LEGACY_TERMINAL_STRING_FIELDS
    ):
        return False
    attempts = validation.get("attempts")
    return (
        isinstance(attempts, int)
        and not isinstance(attempts, bool)
        and attempts > 0
    )


def inspect_legacy_prompt_result(
    path: Path | str,
    *,
    expected_bug_id: str | None = None,
) -> LoadedValidationResult:
    """Read one prompt-era result once and expose facts without upgrading trust.

    This compatibility reader intentionally follows private/main's historical
    JSON behavior. In particular, duplicate keys and non-finite numbers are not
    retroactively rejected here, and DEFAULT_POST_AGENT only checks existence.
    """
    result_path = Path(path)
    try:
        exists = result_path.exists()
    except OSError:
        exists = False
    if not exists:
        return LoadedValidationResult(
            path=result_path,
            exists=False,
            parseable=False,
            value=None,
            record=None,
            status=None,
            terminal_valid=False,
            raw_sha256=None,
            failure=InspectionFailure.MISSING,
        )
    try:
        raw = result_path.read_bytes()
    except OSError:
        return LoadedValidationResult(
            path=result_path,
            exists=True,
            parseable=False,
            value=None,
            record=None,
            status=None,
            terminal_valid=False,
            raw_sha256=None,
            failure=InspectionFailure.IO_ERROR,
        )
    raw_sha256 = _sha256_bytes(raw)
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return LoadedValidationResult(
            path=result_path,
            exists=True,
            parseable=False,
            value=None,
            record=None,
            status=None,
            terminal_valid=False,
            raw_sha256=raw_sha256,
            failure=InspectionFailure.INVALID_UTF8,
        )
    try:
        value = json.loads(text)
    except (json.JSONDecodeError, RecursionError):
        return LoadedValidationResult(
            path=result_path,
            exists=True,
            parseable=False,
            value=None,
            record=None,
            status=None,
            terminal_valid=False,
            raw_sha256=raw_sha256,
            failure=InspectionFailure.MALFORMED_JSON,
        )
    record = value if isinstance(value, dict) else None
    status_value = record.get("confirmation_status") if record is not None else None
    status = status_value if isinstance(status_value, str) else None
    terminal_valid = (
        expected_bug_id is not None
        and legacy_all_bugs_record_is_valid(record, expected_bug_id)
    )
    failure = (
        InspectionFailure.INVALID_TERMINAL
        if expected_bug_id is not None and not terminal_valid
        else None
    )
    return LoadedValidationResult(
        path=result_path,
        exists=True,
        parseable=True,
        value=value,
        record=record,
        status=status,
        terminal_valid=terminal_valid,
        raw_sha256=raw_sha256,
        failure=failure,
    )


def _explicit_family(document: Any) -> ArtifactFamily | None:
    if type(document) is not dict:
        return None
    discriminator_keys = tuple(
        key for key in ("schema_id", "artifact_type") if key in document
    )
    if discriminator_keys:
        discriminator_values = [document[key] for key in discriminator_keys]
        if any(type(value) is not str for value in discriminator_values):
            raise OutcomeLoadError(
                OutcomeLoadErrorCode.SCHEMA_INVALID,
                "validation artifact discriminator must be a string",
            )
        if len(set(discriminator_values)) != 1:
            raise OutcomeLoadError(
                OutcomeLoadErrorCode.AMBIGUOUS_FORMAT,
                "validation artifact discriminators disagree",
            )
        discriminator = discriminator_values[0]
        if discriminator != "validation-outcome/v1":
            raise OutcomeLoadError(
                OutcomeLoadErrorCode.UNSUPPORTED_VERSION,
                f"unsupported validation artifact: {discriminator}",
            )
        if "schema_version" in document:
            version = document["schema_version"]
            if type(version) is not int:
                raise OutcomeLoadError(
                    OutcomeLoadErrorCode.SCHEMA_INVALID,
                    "current schema_version must be an exact integer",
                )
            if version == LEGACY_CCC_RESULT_SCHEMA_VERSION:
                raise OutcomeLoadError(
                    OutcomeLoadErrorCode.AMBIGUOUS_FORMAT,
                    "artifact declares current outcome and legacy CCC v3",
                )
            if version != 1:
                raise OutcomeLoadError(
                    OutcomeLoadErrorCode.UNSUPPORTED_VERSION,
                    f"unsupported current outcome version: {version}",
                )
        return ArtifactFamily.CURRENT_OUTCOME_V1
    if "schema_version" in document:
        version = document.get("schema_version")
        if type(version) is not int:
            raise OutcomeLoadError(
                OutcomeLoadErrorCode.SCHEMA_INVALID,
                "schema_version must be an exact integer",
            )
        if version != LEGACY_CCC_RESULT_SCHEMA_VERSION:
            raise OutcomeLoadError(
                OutcomeLoadErrorCode.UNSUPPORTED_VERSION,
                f"unsupported validation schema version: {version}",
            )
        return ArtifactFamily.CCC_LEGACY_V3_V5
    return None


def load_legacy_compatibility_outcome(
    path: Path | str,
    *,
    policy: LegacyCompletionPolicy,
    expected_bug_id: str | None = None,
) -> LegacyPromptCompletion | LegacyPromptTerminal:
    """Load a private/main compatibility checkpoint without trust promotion.

    DEFAULT_POST_AGENT intentionally performs the historical existence-only
    check and leaves the artifact family unclassified. Policies that consume
    content require an unversioned prompt-era document and reject explicit
    archive/current formats.
    """
    if policy is LegacyCompletionPolicy.DEFAULT_POST_AGENT:
        result_path = Path(path)
        try:
            exists = result_path.exists()
        except OSError:
            exists = False
        if not exists:
            raise OutcomeLoadError(
                OutcomeLoadErrorCode.MISSING,
                f"legacy result does not satisfy {policy.value}",
            )
        return LegacyPromptCompletion(
            path=result_path,
            policy=policy,
            trust_class=TrustClass.EXISTS_ONLY,
            raw_sha256=None,
            value=None,
            reported_status=None,
            artifact_family=ArtifactFamily.UNCLASSIFIED_MATERIALIZATION,
        )
    inspected = inspect_legacy_prompt_result(path, expected_bug_id=expected_bug_id)
    if inspected.parseable:
        family = _explicit_family(inspected.value)
        if family is not None:
            raise OutcomeLoadError(
                OutcomeLoadErrorCode.WRONG_ARTIFACT_FAMILY,
                f"{family.value} cannot be consumed as a prompt-era result",
            )
    if not inspected.completes(policy):
        code = (
            OutcomeLoadErrorCode.MISSING
            if inspected.failure is InspectionFailure.MISSING
            else OutcomeLoadErrorCode.INVALID_JSON
            if not inspected.parseable
            else OutcomeLoadErrorCode.SCHEMA_INVALID
        )
        raise OutcomeLoadError(code, f"legacy result does not satisfy {policy.value}")
    if policy is LegacyCompletionPolicy.ALL_BUGS_TERMINAL:
        if expected_bug_id is None or inspected.record is None:
            raise OutcomeLoadError(
                OutcomeLoadErrorCode.IDENTITY_MISMATCH,
                "all-bugs loading requires an expected bug id",
            )
        try:
            frozen_record = _freeze(inspected.record)
        except RecursionError as exc:
            raise OutcomeLoadError(
                OutcomeLoadErrorCode.INVALID_JSON,
                "legacy terminal result nesting is too deep",
            ) from exc
        return LegacyPromptTerminal(
            path=inspected.path,
            bug_id=expected_bug_id,
            reported_status=inspected.status or "",
            attempts=inspected.record["attempts"],
            record=frozen_record,
            raw_sha256=inspected.raw_sha256 or "",
        )
    try:
        frozen_value = _freeze(inspected.value)
    except RecursionError as exc:
        raise OutcomeLoadError(
            OutcomeLoadErrorCode.INVALID_JSON,
            "legacy result nesting is too deep",
        ) from exc
    return LegacyPromptCompletion(
        path=inspected.path,
        policy=policy,
        trust_class=TrustClass.PARSED_ONLY,
        raw_sha256=inspected.raw_sha256,
        value=frozen_value,
        reported_status=inspected.status,
    )


def _duplicate_key_guard(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise OutcomeLoadError(
                OutcomeLoadErrorCode.DUPLICATE_JSON_KEY,
                f"duplicate JSON key: {key}",
            )
        result[key] = value
    return result


def _reject_nonfinite(value: str) -> NoReturn:
    raise OutcomeLoadError(
        OutcomeLoadErrorCode.INVALID_JSON,
        f"non-finite JSON number is forbidden: {value}",
    )


def _read_regular_bytes(
    path: Path,
    *,
    limits: LoadLimits,
    missing_code: OutcomeLoadErrorCode = OutcomeLoadErrorCode.MISSING,
) -> bytes:
    try:
        if not path.exists():
            raise OutcomeLoadError(missing_code, f"artifact is missing: {path}")
        if path.is_symlink() or not path.is_file():
            raise OutcomeLoadError(
                OutcomeLoadErrorCode.NOT_REGULAR_FILE,
                f"artifact is not a safe regular file: {path}",
            )
        size = path.stat().st_size
        if size > limits.max_json_bytes:
            raise OutcomeLoadError(
                OutcomeLoadErrorCode.TOO_LARGE,
                f"artifact exceeds {limits.max_json_bytes} bytes: {path}",
            )
        return path.read_bytes()
    except OutcomeLoadError:
        raise
    except OSError as exc:
        raise OutcomeLoadError(
            OutcomeLoadErrorCode.NOT_REGULAR_FILE,
            f"artifact is unreadable: {path}: {exc}",
        ) from exc


def _strict_json_from_bytes(raw: bytes, path: Path) -> Any:
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise OutcomeLoadError(
            OutcomeLoadErrorCode.INVALID_UTF8,
            f"artifact is not UTF-8: {path}",
        ) from exc
    try:
        return json.loads(
            text,
            object_pairs_hook=_duplicate_key_guard,
            parse_constant=_reject_nonfinite,
        )
    except OutcomeLoadError:
        raise
    except (json.JSONDecodeError, RecursionError) as exc:
        raise OutcomeLoadError(
            OutcomeLoadErrorCode.INVALID_JSON,
            f"artifact is not valid JSON: {path}: {exc}",
        ) from exc


def inspect_validation_artifact(
    path: Path | str,
    *,
    limits: LoadLimits = DEFAULT_LOAD_LIMITS,
) -> ArtifactInspection:
    """Strictly identify one exact artifact without scanning or fallback."""
    artifact_path = Path(path)
    raw = _read_regular_bytes(artifact_path, limits=limits)
    document = _strict_json_from_bytes(raw, artifact_path)
    family = _explicit_family(document) or ArtifactFamily.PRIVATE_MAIN_PROMPT_LEGACY
    try:
        frozen_document = _freeze(document)
    except RecursionError as exc:
        raise OutcomeLoadError(
            OutcomeLoadErrorCode.INVALID_JSON,
            "validation artifact nesting is too deep",
        ) from exc
    return ArtifactInspection(
        path=artifact_path,
        artifact_family=family,
        raw_sha256=_sha256_bytes(raw),
        document=frozen_document,
    )


def _legacy_json_from_bytes(raw: bytes, path: Path) -> Any:
    try:
        return json.loads(raw.decode("utf-8"))
    except UnicodeDecodeError as exc:
        raise OutcomeLoadError(
            OutcomeLoadErrorCode.INVALID_UTF8,
            f"legacy artifact is not UTF-8: {path}",
        ) from exc
    except (json.JSONDecodeError, RecursionError) as exc:
        raise OutcomeLoadError(
            OutcomeLoadErrorCode.INVALID_JSON,
            f"legacy artifact is not valid JSON: {path}: {exc}",
        ) from exc


def _require_exact_keys(value: Any, expected: frozenset[str], where: str) -> dict:
    if type(value) is not dict or set(value) != expected:
        raise OutcomeLoadError(
            OutcomeLoadErrorCode.SCHEMA_INVALID,
            f"{where} has invalid fields",
        )
    return value


def _require_nonempty_string(value: Any, where: str) -> str:
    if type(value) is not str or not value.strip():
        raise OutcomeLoadError(
            OutcomeLoadErrorCode.SCHEMA_INVALID,
            f"{where} must be a non-empty string",
        )
    return value


def _validate_legacy_json_value(value: Any, where: str) -> None:
    if value is None or type(value) in (str, int, float, bool):
        return
    if type(value) is list:
        for index, item in enumerate(value):
            _validate_legacy_json_value(item, f"{where}[{index}]")
        return
    if type(value) is dict:
        for key, item in value.items():
            if type(key) is not str:
                raise OutcomeLoadError(
                    OutcomeLoadErrorCode.SCHEMA_INVALID,
                    f"{where} has a non-string key",
                )
            _validate_legacy_json_value(item, f"{where}.{key}")
        return
    raise OutcomeLoadError(
        OutcomeLoadErrorCode.SCHEMA_INVALID,
        f"{where} is not a legacy JSON value",
    )


def _validate_legacy_ccc_result(document: Any) -> dict[str, Any]:
    if type(document) is not dict:
        raise OutcomeLoadError(
            OutcomeLoadErrorCode.SCHEMA_INVALID,
            "legacy CCC result must be an object",
        )
    if (
        type(document.get("schema_version")) is not int
        or document.get("schema_version") != LEGACY_CCC_RESULT_SCHEMA_VERSION
    ):
        raise OutcomeLoadError(
            OutcomeLoadErrorCode.UNSUPPORTED_VERSION,
            "legacy CCC result schema_version must be integer 3",
        )
    status = document.get("confirmation_status")
    if type(status) is not str or status not in {"confirmed", "not_confirmed"}:
        raise OutcomeLoadError(
            OutcomeLoadErrorCode.SCHEMA_INVALID,
            "legacy CCC confirmation_status is invalid",
        )
    expected = (
        _CCC_NOT_CONFIRMED_KEYS
        if status == "not_confirmed"
        else _CCC_CONFIRMED_KEYS
    )
    _require_exact_keys(document, expected, "legacy CCC result")
    _require_nonempty_string(document["id"], "legacy CCC result.id")
    _require_nonempty_string(
        document["function_id"], "legacy CCC result.function_id"
    )
    if type(document["attempts"]) is not int or document["attempts"] < 1:
        raise OutcomeLoadError(
            OutcomeLoadErrorCode.SCHEMA_INVALID,
            "legacy CCC attempts must be a positive integer",
        )
    if type(document["notes"]) is not str:
        raise OutcomeLoadError(
            OutcomeLoadErrorCode.SCHEMA_INVALID,
            "legacy CCC notes must be a string",
        )
    if status == "not_confirmed":
        return document

    grade = document["grade"]
    if type(grade) is not str or grade not in {"L0", "L1"}:
        raise OutcomeLoadError(
            OutcomeLoadErrorCode.SCHEMA_INVALID,
            "legacy CCC grade is invalid",
        )
    witness = _require_exact_keys(document["witness"], _CCC_WITNESS_KEYS, "witness")
    _require_nonempty_string(witness["probe"], "witness.probe")
    if type(witness["call_index"]) is not int or witness["call_index"] < 0:
        raise OutcomeLoadError(
            OutcomeLoadErrorCode.SCHEMA_INVALID,
            "witness.call_index must be a non-negative integer",
        )
    if type(witness["captured_input"]) is not dict:
        raise OutcomeLoadError(
            OutcomeLoadErrorCode.SCHEMA_INVALID,
            "witness.captured_input must be an object",
        )
    _validate_legacy_json_value(witness["captured_input"], "witness.captured_input")
    actual_output = witness["actual_output"]
    if type(actual_output) not in (str, int, bool, dict, list):
        raise OutcomeLoadError(
            OutcomeLoadErrorCode.SCHEMA_INVALID,
            "witness.actual_output has an invalid type",
        )
    _validate_legacy_json_value(actual_output, "witness.actual_output")
    _require_nonempty_string(
        witness["spec_violation_claim"], "witness.spec_violation_claim"
    )

    phenomenon = _require_exact_keys(
        document["phenomenon"], _CCC_PHENOMENON_KEYS, "phenomenon"
    )
    if (
        type(phenomenon["mode"]) is not str
        or phenomenon["mode"] not in _CCC_MODES
    ):
        raise OutcomeLoadError(
            OutcomeLoadErrorCode.SCHEMA_INVALID,
            "phenomenon.mode is invalid",
        )
    if (
        type(phenomenon["standard"]) is not str
        or phenomenon["standard"] not in _CCC_STANDARDS
    ):
        raise OutcomeLoadError(
            OutcomeLoadErrorCode.SCHEMA_INVALID,
            "phenomenon.standard is invalid",
        )
    if type(phenomenon["extra_args"]) is not list or any(
        type(arg) is not str or not arg for arg in phenomenon["extra_args"]
    ):
        raise OutcomeLoadError(
            OutcomeLoadErrorCode.SCHEMA_INVALID,
            "phenomenon.extra_args is invalid",
        )
    if (
        type(phenomenon["expected_kind"]) is not str
        or phenomenon["expected_kind"] not in _CCC_PHENOMENON_KINDS
    ):
        raise OutcomeLoadError(
            OutcomeLoadErrorCode.SCHEMA_INVALID,
            "phenomenon.expected_kind is invalid",
        )
    patch = document["l1_patch"]
    if grade == "L1":
        _require_nonempty_string(patch, "legacy CCC result.l1_patch")
    elif patch is not None:
        raise OutcomeLoadError(
            OutcomeLoadErrorCode.SCHEMA_INVALID,
            "legacy CCC L0 result must have a null l1_patch",
        )
    return document


def _validate_file_record(value: Any, where: str) -> dict[str, str]:
    record = _require_exact_keys(value, _CCC_FILE_RECORD_KEYS, where)
    for key in _CCC_FILE_RECORD_KEYS:
        _require_nonempty_string(record[key], f"{where}.{key}")
    if record["scope"] not in {"project", "absolute"}:
        raise OutcomeLoadError(
            OutcomeLoadErrorCode.SIDECAR_INVALID,
            f"{where}.scope is invalid",
        )
    return record


def _validate_legacy_ccc_sidecar_unchecked(document: Any) -> dict[str, Any]:
    sidecar = _require_exact_keys(document, _CCC_SIDECAR_KEYS, "sidecar")
    if (
        type(sidecar["schema_version"]) is not int
        or sidecar["schema_version"] != LEGACY_CCC_SIDECAR_SCHEMA_VERSION
        or sidecar["gate_version"] != LEGACY_CCC_GATE_VERSION
    ):
        raise OutcomeLoadError(
            OutcomeLoadErrorCode.UNSUPPORTED_VERSION,
            "legacy CCC sidecar schema or Gate version is unsupported",
        )
    if sidecar["state"] != "accepted":
        raise OutcomeLoadError(
            OutcomeLoadErrorCode.STATE_NOT_ACCEPTED,
            "legacy CCC sidecar state is not accepted",
        )
    if type(sidecar["attempt"]) is not int or sidecar["attempt"] < 1:
        raise OutcomeLoadError(
            OutcomeLoadErrorCode.SIDECAR_INVALID,
            "legacy CCC sidecar attempt is invalid",
        )
    for key in ("bug_id", "function_id", "confirmation_status"):
        _require_nonempty_string(sidecar[key], f"sidecar.{key}")
    for key in ("result_sha256", "integrity_sha256"):
        _require_nonempty_string(sidecar[key], f"sidecar.{key}")
    for label in _CCC_CONTEXT_BINDINGS:
        _validate_file_record(sidecar[label], f"sidecar.{label}")
    if sidecar["probe"] is not None:
        _validate_file_record(sidecar["probe"], "sidecar.probe")
    if sidecar["l1_patch"] is not None:
        _validate_file_record(sidecar["l1_patch"], "sidecar.l1_patch")
    return sidecar


def _validate_legacy_ccc_sidecar(document: Any) -> dict[str, Any]:
    try:
        return _validate_legacy_ccc_sidecar_unchecked(document)
    except OutcomeLoadError as exc:
        if exc.code in {
            OutcomeLoadErrorCode.UNSUPPORTED_VERSION,
            OutcomeLoadErrorCode.STATE_NOT_ACCEPTED,
            OutcomeLoadErrorCode.SIDECAR_INVALID,
        }:
            raise
        raise OutcomeLoadError(
            OutcomeLoadErrorCode.SIDECAR_INVALID,
            str(exc),
        ) from exc


def _directory_sha256(path: Path, label: str) -> str:
    if path.is_symlink() or not path.is_dir():
        raise ValueError(f"{label} is missing or unsafe")
    digest = hashlib.sha256()
    try:
        for child in sorted(path.rglob("*")):
            if child.is_symlink():
                raise ValueError(f"{label} contains an unsafe symlink")
            if not child.is_file():
                continue
            relative = child.relative_to(path).as_posix().encode("utf-8")
            mode = child.stat().st_mode & 0o7777
            data = child.read_bytes()
            digest.update(len(relative).to_bytes(8, "big"))
            digest.update(relative)
            digest.update(mode.to_bytes(4, "big"))
            digest.update(len(data).to_bytes(8, "big"))
            digest.update(data)
    except OSError as exc:
        raise ValueError(f"{label} is unreadable: {exc}") from exc
    return digest.hexdigest()


def _resolve_binding_path(
    record: Mapping[str, str],
    project_dir: Path,
) -> Path:
    raw_path = Path(record["path"])
    if record["scope"] == "project":
        if raw_path.is_absolute():
            raise ValueError("project path is absolute")
        unresolved = project_dir / raw_path
        if unresolved.is_symlink():
            raise ValueError("path is a symlink")
        resolved = unresolved.resolve()
        resolved.relative_to(project_dir)
    else:
        if not raw_path.is_absolute():
            raise ValueError("absolute-scope path is not absolute")
        unresolved = raw_path
        if unresolved.is_symlink():
            raise ValueError("path is a symlink")
        resolved = unresolved.resolve()
    return resolved


def _binding_check(
    label: str,
    record: Mapping[str, str],
    project_dir: Path,
) -> LegacyBindingCheck:
    raw_path = Path(record["path"])
    expected_sha256 = record["sha256"]
    try:
        resolved = _resolve_binding_path(record, project_dir)
    except (OSError, RuntimeError, ValueError) as exc:
        return LegacyBindingCheck(
            label=label,
            state=LegacyBindingState.UNSAFE,
            path=str(raw_path),
            expected_sha256=expected_sha256,
            detail=str(exc),
        )
    if not resolved.exists():
        return LegacyBindingCheck(
            label=label,
            state=LegacyBindingState.MISSING,
            path=str(resolved),
            expected_sha256=expected_sha256,
        )
    try:
        if label == "sanity_corpus":
            actual_sha256 = _directory_sha256(resolved, label)
        else:
            if resolved.is_symlink() or not resolved.is_file():
                raise ValueError("binding is not a safe regular file")
            actual_sha256 = _sha256_bytes(resolved.read_bytes())
    except (OSError, ValueError) as exc:
        return LegacyBindingCheck(
            label=label,
            state=LegacyBindingState.UNSAFE,
            path=str(resolved),
            expected_sha256=expected_sha256,
            detail=str(exc),
        )
    state = (
        LegacyBindingState.CURRENT
        if actual_sha256 == expected_sha256
        else LegacyBindingState.STALE
    )
    return LegacyBindingCheck(
        label=label,
        state=state,
        path=str(resolved),
        expected_sha256=expected_sha256,
        actual_sha256=actual_sha256,
    )


def _validate_legacy_evidence_paths(
    result: Mapping[str, Any],
    sidecar: Mapping[str, Any],
    project_dir: Path,
) -> None:
    if result["confirmation_status"] != "confirmed":
        return
    bug_id = sidecar["bug_id"]
    validation_dir = project_dir / "fm_agent" / "bug_validation"
    expected_probe = (validation_dir / f"_probe_{bug_id}.c").resolve()
    try:
        recorded_probe = _resolve_binding_path(sidecar["probe"], project_dir)
        submitted_probe = (project_dir / result["witness"]["probe"]).resolve()
    except (OSError, RuntimeError, TypeError, ValueError) as exc:
        raise OutcomeLoadError(
            OutcomeLoadErrorCode.ARTIFACT_MISMATCH,
            f"legacy CCC probe path is invalid: {exc}",
        ) from exc
    if recorded_probe != expected_probe or submitted_probe != expected_probe:
        raise OutcomeLoadError(
            OutcomeLoadErrorCode.ARTIFACT_MISMATCH,
            "legacy CCC probe does not match the canonical probe path",
        )

    if result["grade"] != "L1":
        return
    expected_patch = (validation_dir / f"{bug_id}.l1.patch").resolve()
    try:
        recorded_patch = _resolve_binding_path(sidecar["l1_patch"], project_dir)
        submitted_patch = (project_dir / result["l1_patch"]).resolve()
    except (OSError, RuntimeError, TypeError, ValueError) as exc:
        raise OutcomeLoadError(
            OutcomeLoadErrorCode.ARTIFACT_MISMATCH,
            f"legacy CCC L1 patch path is invalid: {exc}",
        ) from exc
    if recorded_patch != expected_patch or submitted_patch != expected_patch:
        raise OutcomeLoadError(
            OutcomeLoadErrorCode.ARTIFACT_MISMATCH,
            "legacy CCC L1 patch does not match the canonical patch path",
        )


def load_archived_legacy_certificate(
    result_path: Path | str,
    *,
    project_dir: Path | str,
    expected_bug_id: str | None = None,
    expected_function_id: str | None = None,
    limits: LoadLimits = DEFAULT_LOAD_LIMITS,
) -> ArchivedLegacyCCCCertificate:
    """Verify one pinned multirun v3/v5/v6 pair for archival inspection.

    Pair integrity, canonical evidence paths, and cross-fields are mandatory.
    External bindings are reported individually because historical tools or
    source trees may no longer exist. The legacy parser intentionally retains
    v3/v5 json.loads behavior. The digest is not an authenticity signature;
    even an all-CURRENT report remains archival-only.
    """
    result = Path(result_path)
    sidecar = result.with_name(
        result.name.removesuffix(".result.json") + ".gate.json"
    )
    project = Path(project_dir).resolve()
    result_raw = _read_regular_bytes(result, limits=limits)
    try:
        sidecar_raw = _read_regular_bytes(
            sidecar,
            limits=limits,
            missing_code=OutcomeLoadErrorCode.SIDECAR_MISSING,
        )
    except OutcomeLoadError as exc:
        if exc.code is OutcomeLoadErrorCode.NOT_REGULAR_FILE:
            raise OutcomeLoadError(
                OutcomeLoadErrorCode.SIDECAR_INVALID,
                str(exc),
            ) from exc
        raise
    try:
        result_doc = _validate_legacy_ccc_result(
            _legacy_json_from_bytes(result_raw, result)
        )
    except RecursionError as exc:
        raise OutcomeLoadError(
            OutcomeLoadErrorCode.SCHEMA_INVALID,
            "legacy CCC result nesting is too deep",
        ) from exc
    sidecar_doc = _validate_legacy_ccc_sidecar(
        _legacy_json_from_bytes(sidecar_raw, sidecar)
    )

    payload = {
        key: value
        for key, value in sidecar_doc.items()
        if key != "integrity_sha256"
    }
    if sidecar_doc["integrity_sha256"] != _canonical_sha256(payload):
        raise OutcomeLoadError(
            OutcomeLoadErrorCode.INTEGRITY_MISMATCH,
            "legacy CCC sidecar integrity hash does not match",
        )
    if sidecar_doc["result_sha256"] != _sha256_bytes(result_raw):
        raise OutcomeLoadError(
            OutcomeLoadErrorCode.INTEGRITY_MISMATCH,
            "legacy CCC result hash does not match sidecar",
        )
    if (
        result_doc["id"] != sidecar_doc["bug_id"]
        or result_doc["function_id"] != sidecar_doc["function_id"]
        or result_doc["confirmation_status"]
        != sidecar_doc["confirmation_status"]
        or result_doc.get("grade") != sidecar_doc["grade"]
    ):
        raise OutcomeLoadError(
            OutcomeLoadErrorCode.ARTIFACT_MISMATCH,
            "legacy CCC result fields do not match sidecar",
        )
    if expected_bug_id is not None and result_doc["id"] != expected_bug_id:
        raise OutcomeLoadError(
            OutcomeLoadErrorCode.IDENTITY_MISMATCH,
            "legacy CCC bug id does not match expectation",
        )
    if (
        expected_function_id is not None
        and result_doc["function_id"] != expected_function_id
    ):
        raise OutcomeLoadError(
            OutcomeLoadErrorCode.IDENTITY_MISMATCH,
            "legacy CCC function id does not match expectation",
        )

    if result_doc["confirmation_status"] == "not_confirmed":
        if any(
            sidecar_doc[key] is not None
            for key in ("grade", "probe", "l1_patch")
        ):
            raise OutcomeLoadError(
                OutcomeLoadErrorCode.SIDECAR_INVALID,
                "not-confirmed legacy sidecar has evidence or grade",
            )
    elif result_doc["grade"] == "L0":
        if sidecar_doc["probe"] is None or sidecar_doc["l1_patch"] is not None:
            raise OutcomeLoadError(
                OutcomeLoadErrorCode.SIDECAR_INVALID,
                "legacy L0 sidecar evidence nullability is invalid",
            )
    elif sidecar_doc["probe"] is None or sidecar_doc["l1_patch"] is None:
        raise OutcomeLoadError(
            OutcomeLoadErrorCode.SIDECAR_INVALID,
            "legacy L1 sidecar must bind probe and patch",
        )

    _validate_legacy_evidence_paths(result_doc, sidecar_doc, project)
    checks = [
        _binding_check(label, sidecar_doc[label], project)
        for label in _CCC_CONTEXT_BINDINGS
    ]
    if sidecar_doc["probe"] is not None:
        checks.append(_binding_check("probe", sidecar_doc["probe"], project))
    if sidecar_doc["l1_patch"] is not None:
        checks.append(
            _binding_check("l1_patch", sidecar_doc["l1_patch"], project)
        )
    try:
        frozen_result = _freeze(result_doc)
        frozen_sidecar = _freeze(sidecar_doc)
    except RecursionError as exc:
        raise OutcomeLoadError(
            OutcomeLoadErrorCode.SCHEMA_INVALID,
            "legacy CCC certificate nesting is too deep",
        ) from exc
    return ArchivedLegacyCCCCertificate(
        result_path=result,
        sidecar_path=sidecar,
        result=frozen_result,
        sidecar=frozen_sidecar,
        binding_report=tuple(checks),
    )


def load_current_validation_outcome(
    outcome_path: Path | str,
    *,
    limits: LoadLimits = DEFAULT_LOAD_LIMITS,
) -> NoReturn:
    """Fail closed until validation-outcome/v1 and certificate/v2 are implemented."""
    inspection = inspect_validation_artifact(outcome_path, limits=limits)
    if inspection.artifact_family is ArtifactFamily.CURRENT_OUTCOME_V1:
        raise OutcomeLoadError(
            OutcomeLoadErrorCode.HANDLER_NOT_AVAILABLE,
            "validation-outcome/v1 handler is not implemented yet",
        )
    raise OutcomeLoadError(
        OutcomeLoadErrorCode.WRONG_ARTIFACT_FAMILY,
        f"{inspection.artifact_family.value} cannot satisfy a current outcome",
    )

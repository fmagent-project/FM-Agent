"""Strict, bounded IPC envelopes for the validation Coordinator.

These values cross the Agent/host mailbox boundary.  They are transient
protocol messages, not durable evidence contracts: Gate receipts remain the
authority for what B1 executed and no new :class:`ContractRefKind` is created
for either envelope.

Paths are inert, canonical POSIX paths relative to the Agent staging root.
The runtime must still open them through trusted directory file descriptors,
copy their bytes into host-owned storage, and verify their declared hashes
before starting B1.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from .base import (
    ContractError,
    canonical_json_bytes,
    canonical_sha256,
    load_strict_json_object,
    require_exact_keys,
    validate_identifier,
    validate_non_negative_int,
    validate_positive_int,
    validate_safe_relative_path,
    validate_sha256,
)
from .references import ArtifactRef, ContractRef, ContractRefKind
from .status import (
    CaseReasonCode,
    CaseStatus,
    GateAttemptDisposition,
    validate_status_reason,
)


_REQUEST_CONTRACT_KIND = "coordinator_request"
_RESPONSE_CONTRACT_KIND = "coordinator_response"
_SCHEMA_VERSION = 1
_MAX_REQUEST_BYTES = 1_048_576
_MAX_RESPONSE_BYTES = 262_144
_MAX_STAGED_ARTIFACTS = 4096
_MAX_STAGED_DECLARED_BYTES = 1_073_741_824
_MAX_RAW_SUBMISSION_BYTES = 1_048_576
_MAX_NONCE = 1_000_000
_MAX_SUBMISSION_BUDGET = 1_000_000
_MAX_DIAGNOSTICS = 16
_MAX_STAGED_PATH_CHARS = 4096
_MAX_STAGED_PATH_COMPONENTS = 256

_CONFIRMED_STATUSES = frozenset(
    (CaseStatus.CONFIRMED_L0, CaseStatus.CONFIRMED_L1)
)
_RETRYABLE_STATUSES = frozenset(
    (
        CaseStatus.NOT_CONFIRMED,
        CaseStatus.INCONCLUSIVE_ORACLE,
        CaseStatus.INVALID_SUBMISSION,
    )
)
_TERMINAL_STATUSES = frozenset(
    (
        CaseStatus.NOT_CONFIRMED,
        CaseStatus.INCONCLUSIVE_INFRA,
        CaseStatus.INCONCLUSIVE_ORACLE,
        CaseStatus.NEEDS_ORACLE_SETUP,
        CaseStatus.INVALID_SUBMISSION,
    )
)
_TERMINAL_INTEGRITY_REASONS = frozenset(
    (
        CaseReasonCode.PROFILE_ARTIFACT_INVALID,
        CaseReasonCode.BASELINE_ARTIFACT_HASH_MISMATCH,
    )
)
_SAFE_DIAGNOSTIC_IDENTIFIERS = frozenset(
    reason.value
    for reason in CaseReasonCode
    if reason not in (CaseReasonCode.CONFIRMED_L0, CaseReasonCode.CONFIRMED_L1)
)


def _enum_from_document(
    enum_type: type[Enum],
    value: object,
    field: str,
) -> Enum:
    if type(value) is not str:
        raise ContractError(f"{field} must be a string enum value")
    try:
        return enum_type(value)
    except ValueError as exc:
        raise ContractError(f"{field} has unsupported value {value!r}") from exc


def _artifact_from_document(value: object, field: str) -> ArtifactRef:
    try:
        return ArtifactRef.from_document(value)
    except ContractError as exc:
        raise ContractError(f"invalid {field}: {exc}") from exc


def _gate_receipt_ref_from_document(value: object) -> ContractRef:
    try:
        reference = ContractRef.from_document(value)
    except ContractError as exc:
        raise ContractError(f"invalid b1_receipt: {exc}") from exc
    if reference.kind is not ContractRefKind.GATE_RECEIPT:
        raise ContractError("b1_receipt must reference gate_receipt")
    return reference


def _validate_staged_path_for_nonce(
    relative_path: str,
    nonce: int,
    field: str,
) -> None:
    parts = relative_path.split("/")
    if (
        len(relative_path) > _MAX_STAGED_PATH_CHARS
        or len(parts) > _MAX_STAGED_PATH_COMPONENTS
        or len(parts) < 3
        or parts[0] != "submissions"
        or parts[1] != str(nonce)
    ):
        raise ContractError(
            f"{field} must be below the exact submissions/{nonce}/ namespace"
        )


def _normalize_diagnostics(value: object) -> tuple[str, ...]:
    if type(value) not in (tuple, list):
        raise ContractError("diagnostics must be an ordered collection")
    diagnostics = tuple(value)
    if len(diagnostics) > _MAX_DIAGNOSTICS:
        raise ContractError(
            f"diagnostics must not contain more than {_MAX_DIAGNOSTICS} values"
        )
    normalized = tuple(
        validate_identifier(item, "diagnostic identifier") for item in diagnostics
    )
    if len(normalized) != len(set(normalized)):
        raise ContractError("diagnostics must not contain duplicate identifiers")
    if not set(normalized).issubset(_SAFE_DIAGNOSTIC_IDENTIFIERS):
        raise ContractError("diagnostics contains an identifier outside the allowlist")
    return tuple(sorted(normalized))


@dataclass(frozen=True)
class StagedArtifactBinding:
    """One Agent-staged path and the exact inert artifact claim for its bytes."""

    relative_path: str
    artifact: ArtifactRef

    def __post_init__(self) -> None:
        path = validate_safe_relative_path(
            self.relative_path,
            "staged artifact relative_path",
        )
        if len(path) > _MAX_STAGED_PATH_CHARS:
            raise ContractError(
                "staged artifact relative_path exceeds the protocol path bound"
            )
        if len(path.split("/")) > _MAX_STAGED_PATH_COMPONENTS:
            raise ContractError(
                "staged artifact relative_path has too many path components"
            )
        if type(self.artifact) is not ArtifactRef:
            raise ContractError("staged artifact must contain an ArtifactRef")

    def to_document(self) -> dict[str, object]:
        return {
            "relative_path": self.relative_path,
            "artifact": self.artifact.to_document(),
        }

    @classmethod
    def from_document(cls, value: object) -> StagedArtifactBinding:
        document = require_exact_keys(
            value,
            required=("relative_path", "artifact"),
            where="staged artifact binding",
        )
        return cls(
            relative_path=document["relative_path"],
            artifact=_artifact_from_document(
                document["artifact"],
                "staged artifact binding artifact",
            ),
        )


@dataclass(frozen=True)
class CoordinatorRequestEnvelope:
    """One bounded Agent request for a host-assigned, fresh B1 attempt."""

    validation_instance_id: str
    case_id: str
    function_id: str
    reasoning_sha256: str
    profile_sha256: str
    context_sha256: str
    agent_session_id: str
    nonce: int
    previous_response_sha256: str | None
    raw_submission: StagedArtifactBinding
    artifacts: tuple[StagedArtifactBinding, ...]

    def __post_init__(self) -> None:
        validate_sha256(self.validation_instance_id, "validation_instance_id")
        validate_identifier(self.case_id, "case_id")
        validate_identifier(self.function_id, "function_id")
        validate_sha256(self.reasoning_sha256, "reasoning_sha256")
        validate_sha256(self.profile_sha256, "profile_sha256")
        validate_sha256(self.context_sha256, "context_sha256")
        validate_identifier(self.agent_session_id, "agent_session_id")
        validate_positive_int(self.nonce, "nonce", maximum=_MAX_NONCE)
        if self.nonce == 1:
            if self.previous_response_sha256 is not None:
                raise ContractError(
                    "the first Coordinator request cannot bind a prior response"
                )
        else:
            validate_sha256(
                self.previous_response_sha256,
                "previous_response_sha256",
            )
        if type(self.raw_submission) is not StagedArtifactBinding:
            raise ContractError(
                "raw_submission must be a StagedArtifactBinding"
            )
        if (
            self.raw_submission.artifact.role != "raw_submission"
            or self.raw_submission.artifact.media_type != "application/json"
        ):
            raise ContractError(
                "raw_submission must declare role raw_submission and media type "
                "application/json"
            )
        if not 0 < self.raw_submission.artifact.size_bytes <= _MAX_RAW_SUBMISSION_BYTES:
            raise ContractError(
                "raw_submission declared size must be positive and within the "
                "request payload bound"
            )

        if type(self.artifacts) not in (tuple, list):
            raise ContractError("artifacts must be an ordered collection")
        artifacts = tuple(self.artifacts)
        if len(artifacts) > _MAX_STAGED_ARTIFACTS:
            raise ContractError(
                f"artifacts must not contain more than {_MAX_STAGED_ARTIFACTS} values"
            )
        if any(type(binding) is not StagedArtifactBinding for binding in artifacts):
            raise ContractError(
                "artifacts must contain only StagedArtifactBinding values"
            )
        bindings = (self.raw_submission, *artifacts)
        for index, binding in enumerate(bindings):
            _validate_staged_path_for_nonce(
                binding.relative_path,
                self.nonce,
                "raw_submission.relative_path"
                if index == 0
                else f"artifacts[{index - 1}].relative_path",
            )
        paths = tuple(binding.relative_path for binding in bindings)
        if len(paths) != len(set(paths)):
            raise ContractError("staged artifact paths must be globally unique")
        roles = tuple(binding.artifact.role for binding in bindings)
        if len(roles) != len(set(roles)):
            raise ContractError("staged artifact roles must be globally unique")
        total_declared_bytes = sum(
            binding.artifact.size_bytes for binding in bindings
        )
        if total_declared_bytes > _MAX_STAGED_DECLARED_BYTES:
            raise ContractError(
                "staged artifacts exceed the aggregate declared-byte bound"
            )
        object.__setattr__(
            self,
            "artifacts",
            tuple(sorted(artifacts, key=lambda binding: binding.relative_path)),
        )

    @property
    def declared_size_bytes(self) -> int:
        return self.raw_submission.artifact.size_bytes + sum(
            binding.artifact.size_bytes for binding in self.artifacts
        )

    def to_document(self) -> dict[str, object]:
        return {
            "contract_kind": _REQUEST_CONTRACT_KIND,
            "schema_version": _SCHEMA_VERSION,
            "validation_instance_id": self.validation_instance_id,
            "case_id": self.case_id,
            "function_id": self.function_id,
            "reasoning_sha256": self.reasoning_sha256,
            "profile_sha256": self.profile_sha256,
            "context_sha256": self.context_sha256,
            "agent_session_id": self.agent_session_id,
            "nonce": self.nonce,
            "previous_response_sha256": self.previous_response_sha256,
            "raw_submission": self.raw_submission.to_document(),
            "artifacts": [binding.to_document() for binding in self.artifacts],
        }

    @classmethod
    def from_document(cls, value: object) -> CoordinatorRequestEnvelope:
        document = require_exact_keys(
            value,
            required=(
                "contract_kind",
                "schema_version",
                "validation_instance_id",
                "case_id",
                "function_id",
                "reasoning_sha256",
                "profile_sha256",
                "context_sha256",
                "agent_session_id",
                "nonce",
                "previous_response_sha256",
                "raw_submission",
                "artifacts",
            ),
            where="coordinator request",
        )
        if document["contract_kind"] != _REQUEST_CONTRACT_KIND:
            raise ContractError(
                f"coordinator request contract_kind must be {_REQUEST_CONTRACT_KIND!r}"
            )
        if (
            type(document["schema_version"]) is not int
            or document["schema_version"] != _SCHEMA_VERSION
        ):
            raise ContractError("coordinator request schema_version must be integer 1")
        artifact_documents = document["artifacts"]
        if type(artifact_documents) is not list:
            raise ContractError("coordinator request artifacts must be a list")
        return cls(
            validation_instance_id=document["validation_instance_id"],
            case_id=document["case_id"],
            function_id=document["function_id"],
            reasoning_sha256=document["reasoning_sha256"],
            profile_sha256=document["profile_sha256"],
            context_sha256=document["context_sha256"],
            agent_session_id=document["agent_session_id"],
            nonce=document["nonce"],
            previous_response_sha256=document["previous_response_sha256"],
            raw_submission=StagedArtifactBinding.from_document(
                document["raw_submission"]
            ),
            artifacts=tuple(
                StagedArtifactBinding.from_document(item)
                for item in artifact_documents
            ),
        )

    @classmethod
    def from_json(cls, payload: object) -> CoordinatorRequestEnvelope:
        return cls.from_document(
            load_strict_json_object(payload, max_bytes=_MAX_REQUEST_BYTES)
        )

    def to_json(self) -> bytes:
        return canonical_json_bytes(self.to_document())

    @property
    def content_sha256(self) -> str:
        return canonical_sha256(self.to_document())


@dataclass(frozen=True)
class CoordinatorResponseEnvelope:
    """Host response for exactly one consumed request and B1 receipt."""

    validation_instance_id: str
    case_id: str
    function_id: str
    reasoning_sha256: str
    profile_sha256: str
    context_sha256: str
    agent_session_id: str
    nonce: int
    request_sha256: str
    gate_attempt_id: str
    b1_receipt: ContractRef
    disposition: GateAttemptDisposition
    result_status: CaseStatus
    result_reason_code: CaseReasonCode
    remaining_submission_budget: int
    terminal_status: CaseStatus | None
    terminal_reason_code: CaseReasonCode | None
    diagnostics: tuple[str, ...]

    def __post_init__(self) -> None:
        validate_sha256(self.validation_instance_id, "validation_instance_id")
        validate_identifier(self.case_id, "case_id")
        validate_identifier(self.function_id, "function_id")
        validate_sha256(self.reasoning_sha256, "reasoning_sha256")
        validate_sha256(self.profile_sha256, "profile_sha256")
        validate_sha256(self.context_sha256, "context_sha256")
        validate_identifier(self.agent_session_id, "agent_session_id")
        validate_positive_int(self.nonce, "nonce", maximum=_MAX_NONCE)
        validate_sha256(self.request_sha256, "request_sha256")
        validate_identifier(self.gate_attempt_id, "gate_attempt_id")
        if type(self.b1_receipt) is not ContractRef or (
            self.b1_receipt.kind is not ContractRefKind.GATE_RECEIPT
        ):
            raise ContractError("b1_receipt must be a gate_receipt ContractRef")
        if type(self.disposition) is not GateAttemptDisposition:
            raise ContractError("disposition must be a GateAttemptDisposition")
        if type(self.result_status) is not CaseStatus:
            raise ContractError("result_status must be a CaseStatus")
        if type(self.result_reason_code) is not CaseReasonCode:
            raise ContractError("result_reason_code must be a CaseReasonCode")
        validate_status_reason(self.result_status, self.result_reason_code)
        validate_non_negative_int(
            self.remaining_submission_budget,
            "remaining_submission_budget",
            maximum=_MAX_SUBMISSION_BUDGET,
        )
        if self.terminal_status is not None and type(self.terminal_status) is not CaseStatus:
            raise ContractError("terminal_status must be a CaseStatus or None")
        if (
            self.terminal_reason_code is not None
            and type(self.terminal_reason_code) is not CaseReasonCode
        ):
            raise ContractError(
                "terminal_reason_code must be a CaseReasonCode or None"
            )
        diagnostics = _normalize_diagnostics(self.diagnostics)
        object.__setattr__(self, "diagnostics", diagnostics)

        if self.disposition is GateAttemptDisposition.RETRYABLE_REJECTION:
            if self.remaining_submission_budget == 0:
                raise ContractError(
                    "retryable rejection requires remaining submission budget"
                )
            if self.result_status not in _RETRYABLE_STATUSES:
                raise ContractError(
                    "retryable rejection has a non-retryable result status"
                )
            if (
                self.result_reason_code is CaseReasonCode.EXPLICIT_NOT_CONFIRMED
                or self.result_reason_code in _TERMINAL_INTEGRITY_REASONS
            ):
                raise ContractError(
                    "retryable rejection has a terminal or accepted reason code"
                )
            self._require_no_terminal_projection()
        elif (
            self.disposition
            is GateAttemptDisposition.ACCEPTED_CONFIRMED_CANDIDATE
        ):
            if self.result_status not in _CONFIRMED_STATUSES:
                raise ContractError(
                    "accepted confirmed candidate requires a confirmed status"
                )
            self._require_no_terminal_projection()
        elif (
            self.disposition
            is GateAttemptDisposition.ACCEPTED_EXPLICIT_NOT_CONFIRMED
        ):
            if (
                self.result_status is not CaseStatus.NOT_CONFIRMED
                or self.result_reason_code
                is not CaseReasonCode.EXPLICIT_NOT_CONFIRMED
            ):
                raise ContractError(
                    "accepted explicit not_confirmed requires its normative "
                    "status and reason"
                )
            self._require_no_terminal_projection()
        else:
            if (
                self.result_status not in _TERMINAL_STATUSES
                or self.result_reason_code
                is CaseReasonCode.EXPLICIT_NOT_CONFIRMED
            ):
                raise ContractError(
                    "terminal outcome requires a non-confirmed terminal result"
                )
            if self.terminal_status is None or self.terminal_reason_code is None:
                raise ContractError(
                    "terminal outcome requires terminal status and reason"
                )
            validate_status_reason(self.terminal_status, self.terminal_reason_code)
            if (
                self.terminal_status is not self.result_status
                or self.terminal_reason_code is not self.result_reason_code
            ):
                raise ContractError(
                    "terminal projection must exactly match the receipt result"
                )

    def _require_no_terminal_projection(self) -> None:
        if self.terminal_status is not None or self.terminal_reason_code is not None:
            raise ContractError(
                "terminal status and reason are allowed only for TERMINAL_OUTCOME"
            )

    def to_document(self) -> dict[str, object]:
        return {
            "contract_kind": _RESPONSE_CONTRACT_KIND,
            "schema_version": _SCHEMA_VERSION,
            "validation_instance_id": self.validation_instance_id,
            "case_id": self.case_id,
            "function_id": self.function_id,
            "reasoning_sha256": self.reasoning_sha256,
            "profile_sha256": self.profile_sha256,
            "context_sha256": self.context_sha256,
            "agent_session_id": self.agent_session_id,
            "nonce": self.nonce,
            "request_sha256": self.request_sha256,
            "gate_attempt_id": self.gate_attempt_id,
            "b1_receipt": self.b1_receipt.to_document(),
            "disposition": self.disposition.value,
            "result_status": self.result_status.value,
            "result_reason_code": self.result_reason_code.value,
            "remaining_submission_budget": self.remaining_submission_budget,
            "terminal_status": (
                None if self.terminal_status is None else self.terminal_status.value
            ),
            "terminal_reason_code": (
                None
                if self.terminal_reason_code is None
                else self.terminal_reason_code.value
            ),
            "diagnostics": list(self.diagnostics),
        }

    @classmethod
    def from_document(cls, value: object) -> CoordinatorResponseEnvelope:
        document = require_exact_keys(
            value,
            required=(
                "contract_kind",
                "schema_version",
                "validation_instance_id",
                "case_id",
                "function_id",
                "reasoning_sha256",
                "profile_sha256",
                "context_sha256",
                "agent_session_id",
                "nonce",
                "request_sha256",
                "gate_attempt_id",
                "b1_receipt",
                "disposition",
                "result_status",
                "result_reason_code",
                "remaining_submission_budget",
                "terminal_status",
                "terminal_reason_code",
                "diagnostics",
            ),
            where="coordinator response",
        )
        if document["contract_kind"] != _RESPONSE_CONTRACT_KIND:
            raise ContractError(
                "coordinator response contract_kind must be "
                f"{_RESPONSE_CONTRACT_KIND!r}"
            )
        if (
            type(document["schema_version"]) is not int
            or document["schema_version"] != _SCHEMA_VERSION
        ):
            raise ContractError("coordinator response schema_version must be integer 1")
        diagnostics = document["diagnostics"]
        if type(diagnostics) is not list:
            raise ContractError("coordinator response diagnostics must be a list")
        terminal_status = document["terminal_status"]
        terminal_reason = document["terminal_reason_code"]
        return cls(
            validation_instance_id=document["validation_instance_id"],
            case_id=document["case_id"],
            function_id=document["function_id"],
            reasoning_sha256=document["reasoning_sha256"],
            profile_sha256=document["profile_sha256"],
            context_sha256=document["context_sha256"],
            agent_session_id=document["agent_session_id"],
            nonce=document["nonce"],
            request_sha256=document["request_sha256"],
            gate_attempt_id=document["gate_attempt_id"],
            b1_receipt=_gate_receipt_ref_from_document(document["b1_receipt"]),
            disposition=_enum_from_document(
                GateAttemptDisposition,
                document["disposition"],
                "coordinator response disposition",
            ),
            result_status=_enum_from_document(
                CaseStatus,
                document["result_status"],
                "coordinator response result_status",
            ),
            result_reason_code=_enum_from_document(
                CaseReasonCode,
                document["result_reason_code"],
                "coordinator response result_reason_code",
            ),
            remaining_submission_budget=document["remaining_submission_budget"],
            terminal_status=(
                None
                if terminal_status is None
                else _enum_from_document(
                    CaseStatus,
                    terminal_status,
                    "coordinator response terminal_status",
                )
            ),
            terminal_reason_code=(
                None
                if terminal_reason is None
                else _enum_from_document(
                    CaseReasonCode,
                    terminal_reason,
                    "coordinator response terminal_reason_code",
                )
            ),
            diagnostics=tuple(diagnostics),
        )

    @classmethod
    def from_json(cls, payload: object) -> CoordinatorResponseEnvelope:
        return cls.from_document(
            load_strict_json_object(payload, max_bytes=_MAX_RESPONSE_BYTES)
        )

    def to_json(self) -> bytes:
        return canonical_json_bytes(self.to_document())

    @property
    def content_sha256(self) -> str:
        return canonical_sha256(self.to_document())

    def validate_request(self, request: CoordinatorRequestEnvelope) -> None:
        """Bind this response to the exact request consumed by the host."""

        if type(request) is not CoordinatorRequestEnvelope:
            raise ContractError("request must be a CoordinatorRequestEnvelope")
        identity_fields = (
            "validation_instance_id",
            "case_id",
            "function_id",
            "reasoning_sha256",
            "profile_sha256",
            "context_sha256",
            "agent_session_id",
            "nonce",
        )
        if any(getattr(self, field) != getattr(request, field) for field in identity_fields):
            raise ContractError("coordinator response request identity mismatch")
        if self.request_sha256 != request.content_sha256:
            raise ContractError("coordinator response request hash mismatch")


__all__ = [
    "CoordinatorRequestEnvelope",
    "CoordinatorResponseEnvelope",
    "StagedArtifactBinding",
]

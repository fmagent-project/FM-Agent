"""Cross-Gate, terminal outcome, and confirmed-certificate contracts.

The outcome classes below are a strict discriminated union.  Their
different Python types and exact JSON key sets make the publication topology
explicit: a no-run fast path cannot masquerade as a full candidate check, a
B1-only terminal result cannot imply that B2 ran, and a confirmed outcome
cannot exist without a reproducible Cross-Gate decision and certificate.

This module is deliberately trust-free.  It validates frozen identities and
the shape of already-produced receipts; it does not resolve CAS objects,
verify a cryptographic signature, or reproduce an Oracle calculation.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import TYPE_CHECKING, Iterable, TypeAlias

from .base import (
    ContractError,
    canonical_sha256,
    load_strict_json_object,
    require_exact_keys,
    validate_sha256,
)
from .plan import GateRole
from .references import ArtifactRef, ContractRef, ContractRefKind
from .status import (
    CaseReasonCode,
    CaseStatus,
    GateAttemptDisposition,
    ValidationGrade,
    validate_status_reason,
)

if TYPE_CHECKING:
    from .receipt import (
        CandidateGateReceipt,
        EarlyGateReceipt,
        FastPathGateReceipt,
    )


_OUTCOME_CONTRACT_KIND = "validation_outcome"
_OUTCOME_SCHEMA_VERSION = 1
_CROSS_GATE_DECISION_CONTRACT_KIND = "cross_gate_decision"
_CROSS_GATE_DECISION_SCHEMA_VERSION = 1
_CERTIFICATE_CONTRACT_KIND = "certificate"
_CERTIFICATE_SCHEMA_VERSION = 2
_CONTENT_REF_VERSION = "1"
_MAX_B1_ATTEMPTS = 4096
_MAX_CROSS_GATE_DECISIONS = 16_384


class OutcomeKind(str, Enum):
    """Closed terminal publication topologies."""

    EXPLICIT_NOT_CONFIRMED = "explicit_not_confirmed"
    B1_TERMINAL = "b1_terminal"
    B2_RECHECK_FAILED = "b2_recheck_failed"
    CROSS_GATE_FAILED = "cross_gate_failed"
    CONFIRMED = "confirmed"


class CrossGateVerdict(str, Enum):
    """Closed result of comparing two individually confirmed Gate runs."""

    REPRODUCIBLE = "REPRODUCIBLE"
    REPRODUCIBILITY_FAILED = "REPRODUCIBILITY_FAILED"


_NON_CONFIRMED_STATUSES = frozenset(
    (
        CaseStatus.NOT_CONFIRMED,
        CaseStatus.INCONCLUSIVE_INFRA,
        CaseStatus.INCONCLUSIVE_ORACLE,
        CaseStatus.NEEDS_ORACLE_SETUP,
        CaseStatus.INVALID_SUBMISSION,
    )
)
_B2_FAILURE_OUTCOME_STATUSES = frozenset(
    (
        CaseStatus.INCONCLUSIVE_INFRA,
        CaseStatus.INCONCLUSIVE_ORACLE,
        CaseStatus.INVALID_SUBMISSION,
    )
)


def _enum_value(enum_type: type[Enum], value: object, field: str) -> Enum:
    if type(value) is not str:
        raise ContractError(f"{field} must be a string enum value")
    try:
        return enum_type(value)
    except ValueError as exc:
        raise ContractError(f"{field} has unsupported value {value!r}") from exc


def _require_ref(
    value: object,
    expected_kind: ContractRefKind,
    field: str,
) -> ContractRef:
    if type(value) is not ContractRef:
        raise ContractError(f"{field} must be a ContractRef")
    if value.kind is not expected_kind:
        raise ContractError(f"{field} must reference {expected_kind.value}")
    return value


def _same_ref_identity(left: ContractRef, right: ContractRef) -> bool:
    return (
        left.kind,
        left.contract_id,
        left.contract_version,
    ) == (
        right.kind,
        right.contract_id,
        right.contract_version,
    )


def _ref_from_document(
    value: object,
    expected_kind: ContractRefKind,
    field: str,
) -> ContractRef:
    try:
        reference = ContractRef.from_document(value)
    except ContractError as exc:
        raise ContractError(f"invalid {field}: {exc}") from exc
    return _require_ref(reference, expected_kind, field)


def _ref_sort_key(reference: ContractRef) -> tuple[str, str, str, str]:
    return (
        reference.kind.value,
        reference.contract_id,
        reference.contract_version,
        reference.content_sha256,
    )


def _normalize_cross_gate_decision_refs(
    value: object,
    field: str,
) -> tuple[ContractRef, ...]:
    if type(value) not in (tuple, list):
        raise ContractError(f"{field} must be a collection")
    references = tuple(value)
    if not references:
        raise ContractError(f"{field} must not be empty")
    if len(references) > _MAX_CROSS_GATE_DECISIONS:
        raise ContractError(
            f"{field} must not contain more than "
            f"{_MAX_CROSS_GATE_DECISIONS} values"
        )
    for reference in references:
        _require_ref(reference, ContractRefKind.ORACLE_DECISION, field)
    identities = tuple(
        (reference.kind, reference.contract_id, reference.contract_version)
        for reference in references
    )
    if len(identities) != len(set(identities)):
        raise ContractError(
            f"{field} must not repeat or conflict on OracleDecision identity"
        )
    return tuple(sorted(references, key=_ref_sort_key))


def _cross_gate_decision_refs_from_document(
    value: object,
    field: str,
) -> tuple[ContractRef, ...]:
    if type(value) is not list:
        raise ContractError(f"{field} must be a list")
    return _normalize_cross_gate_decision_refs(
        tuple(
            _ref_from_document(
                item,
                ContractRefKind.ORACLE_DECISION,
                f"{field}[{index}]",
            )
            for index, item in enumerate(value)
        ),
        field,
    )


@dataclass(frozen=True)
class CrossGateDecision:
    """Mechanical reproducibility result over exact B1/B2 evidence sets.

    This contract records the output of a later trusted DecisionEngine applying
    the already-frozen CrossGateReproducibility rules.  This contract validator
    checks only the exact evidence closure: it does not recompute the
    comparison or establish producer trust.  The comparison artifact is
    resolved and verified by later runtime/CAS layers.
    """

    validation_instance_id: str
    b1_receipt: ContractRef
    b2_receipt: ContractRef
    b1_decisions: tuple[ContractRef, ...]
    b2_decisions: tuple[ContractRef, ...]
    comparison: ArtifactRef
    verdict: CrossGateVerdict

    def __post_init__(self) -> None:
        validate_sha256(self.validation_instance_id, "validation_instance_id")
        _require_ref(self.b1_receipt, ContractRefKind.GATE_RECEIPT, "b1_receipt")
        _require_ref(self.b2_receipt, ContractRefKind.GATE_RECEIPT, "b2_receipt")
        if _same_ref_identity(self.b1_receipt, self.b2_receipt):
            raise ContractError(
                "Cross-Gate decision requires independent B1/B2 receipts"
            )
        b1_decisions = _normalize_cross_gate_decision_refs(
            self.b1_decisions,
            "b1_decisions",
        )
        b2_decisions = _normalize_cross_gate_decision_refs(
            self.b2_decisions,
            "b2_decisions",
        )
        b1_identities = {
            (reference.kind, reference.contract_id, reference.contract_version)
            for reference in b1_decisions
        }
        b2_identities = {
            (reference.kind, reference.contract_id, reference.contract_version)
            for reference in b2_decisions
        }
        if b1_identities.intersection(b2_identities):
            raise ContractError(
                "B1 OracleDecision evidence cannot impersonate B2 evidence"
            )
        object.__setattr__(self, "b1_decisions", b1_decisions)
        object.__setattr__(self, "b2_decisions", b2_decisions)
        if type(self.comparison) is not ArtifactRef:
            raise ContractError("comparison must be an ArtifactRef")
        if self.comparison.role != "cross_gate_comparison":
            raise ContractError(
                "comparison artifact role must be 'cross_gate_comparison'"
            )
        if type(self.verdict) is not CrossGateVerdict:
            raise ContractError("verdict must be a CrossGateVerdict")

    def to_document(self) -> dict[str, object]:
        return {
            "contract_kind": _CROSS_GATE_DECISION_CONTRACT_KIND,
            "schema_version": _CROSS_GATE_DECISION_SCHEMA_VERSION,
            "validation_instance_id": self.validation_instance_id,
            "b1_receipt": self.b1_receipt.to_document(),
            "b2_receipt": self.b2_receipt.to_document(),
            "b1_decisions": [
                reference.to_document() for reference in self.b1_decisions
            ],
            "b2_decisions": [
                reference.to_document() for reference in self.b2_decisions
            ],
            "comparison": self.comparison.to_document(),
            "verdict": self.verdict.value,
        }

    @classmethod
    def from_document(cls, value: object) -> CrossGateDecision:
        document = require_exact_keys(
            value,
            required=(
                "contract_kind",
                "schema_version",
                "validation_instance_id",
                "b1_receipt",
                "b2_receipt",
                "b1_decisions",
                "b2_decisions",
                "comparison",
                "verdict",
            ),
            where="cross-gate decision",
        )
        if document["contract_kind"] != _CROSS_GATE_DECISION_CONTRACT_KIND:
            raise ContractError(
                "cross-gate decision contract_kind must be "
                f"{_CROSS_GATE_DECISION_CONTRACT_KIND!r}"
            )
        if (
            type(document["schema_version"]) is not int
            or document["schema_version"]
            != _CROSS_GATE_DECISION_SCHEMA_VERSION
        ):
            raise ContractError("cross-gate decision schema_version must be integer 1")
        return cls(
            validation_instance_id=document["validation_instance_id"],
            b1_receipt=_ref_from_document(
                document["b1_receipt"],
                ContractRefKind.GATE_RECEIPT,
                "b1_receipt",
            ),
            b2_receipt=_ref_from_document(
                document["b2_receipt"],
                ContractRefKind.GATE_RECEIPT,
                "b2_receipt",
            ),
            b1_decisions=_cross_gate_decision_refs_from_document(
                document["b1_decisions"],
                "b1_decisions",
            ),
            b2_decisions=_cross_gate_decision_refs_from_document(
                document["b2_decisions"],
                "b2_decisions",
            ),
            comparison=ArtifactRef.from_document(document["comparison"]),
            verdict=_enum_value(
                CrossGateVerdict,
                document["verdict"],
                "cross-gate verdict",
            ),
        )

    @classmethod
    def from_json(cls, payload: object) -> CrossGateDecision:
        return cls.from_document(load_strict_json_object(payload))

    @property
    def content_sha256(self) -> str:
        return canonical_sha256(self.to_document())

    @property
    def ref(self) -> ContractRef:
        return ContractRef(
            kind=ContractRefKind.CROSS_GATE_DECISION,
            contract_id=self.content_sha256,
            contract_version=_CONTENT_REF_VERSION,
            content_sha256=self.content_sha256,
        )


def _normalize_b1_attempt_refs(
    value: object,
    *,
    field: str = "b1_attempt_receipts",
    allow_empty: bool = False,
) -> tuple[ContractRef, ...]:
    if type(value) not in (tuple, list):
        raise ContractError(f"{field} must be an ordered collection")
    references = tuple(value)
    if not allow_empty and not references:
        raise ContractError(f"{field} must not be empty")
    if len(references) > _MAX_B1_ATTEMPTS:
        raise ContractError(
            f"{field} must not contain more than {_MAX_B1_ATTEMPTS} values"
        )
    for reference in references:
        _require_ref(reference, ContractRefKind.GATE_RECEIPT, field)
    identities = tuple(
        (reference.kind, reference.contract_id, reference.contract_version)
        for reference in references
    )
    if len(identities) != len(set(identities)):
        raise ContractError(
            f"{field} must not repeat or conflict on receipt identity"
        )
    return references


def _b1_attempt_refs_from_document(value: object) -> tuple[ContractRef, ...]:
    if type(value) is not list:
        raise ContractError("b1_attempt_receipts must be a list")
    return _normalize_b1_attempt_refs(
        tuple(
            _ref_from_document(
                item,
                ContractRefKind.GATE_RECEIPT,
                f"b1_attempt_receipts[{index}]",
            )
            for index, item in enumerate(value)
        )
    )


def _prior_b1_attempt_refs_from_document(value: object) -> tuple[ContractRef, ...]:
    if type(value) is not list:
        raise ContractError("prior_b1_attempt_receipts must be a list")
    return _normalize_b1_attempt_refs(
        tuple(
            _ref_from_document(
                item,
                ContractRefKind.GATE_RECEIPT,
                f"prior_b1_attempt_receipts[{index}]",
            )
            for index, item in enumerate(value)
        ),
        field="prior_b1_attempt_receipts",
        allow_empty=True,
    )


def _validate_common_outcome(
    validation_instance_id: object,
    status: object,
    reason_code: object,
) -> None:
    validate_sha256(validation_instance_id, "validation_instance_id")
    if type(status) is not CaseStatus:
        raise ContractError("status must be a CaseStatus")
    if type(reason_code) is not CaseReasonCode:
        raise ContractError("reason_code must be a CaseReasonCode")
    validate_status_reason(status, reason_code)


def _common_outcome_document(
    *,
    kind: OutcomeKind,
    validation_instance_id: str,
    status: CaseStatus,
    reason_code: CaseReasonCode,
) -> dict[str, object]:
    return {
        "contract_kind": _OUTCOME_CONTRACT_KIND,
        "schema_version": _OUTCOME_SCHEMA_VERSION,
        "outcome_kind": kind.value,
        "validation_instance_id": validation_instance_id,
        "status": status.value,
        "reason_code": reason_code.value,
    }


def _parse_outcome_discriminator(
    value: object,
    *,
    expected_kind: OutcomeKind,
    required: tuple[str, ...],
) -> dict[str, object]:
    document = require_exact_keys(
        value,
        required=(
            "contract_kind",
            "schema_version",
            "outcome_kind",
            "validation_instance_id",
            "status",
            "reason_code",
            *required,
        ),
        where=f"{expected_kind.value} validation outcome",
    )
    if document["contract_kind"] != _OUTCOME_CONTRACT_KIND:
        raise ContractError(
            "validation outcome contract_kind must be "
            f"{_OUTCOME_CONTRACT_KIND!r}"
        )
    if (
        type(document["schema_version"]) is not int
        or document["schema_version"] != _OUTCOME_SCHEMA_VERSION
    ):
        raise ContractError("validation outcome schema_version must be integer 1")
    if document["outcome_kind"] != expected_kind.value:
        raise ContractError(
            f"validation outcome outcome_kind must be {expected_kind.value!r}"
        )
    return document


class _ContentAddressedOutcome:
    """Shared hash/ref behavior; not itself a schema branch."""

    def to_document(self) -> dict[str, object]:  # pragma: no cover - protocol aid
        raise NotImplementedError

    @property
    def content_sha256(self) -> str:
        return canonical_sha256(self.to_document())

    @property
    def ref(self) -> ContractRef:
        return ContractRef(
            kind=ContractRefKind.VALIDATION_OUTCOME,
            contract_id=self.content_sha256,
            contract_version=_CONTENT_REF_VERSION,
            content_sha256=self.content_sha256,
        )


@dataclass(frozen=True)
class ExplicitNotConfirmedOutcome(_ContentAddressedOutcome):
    """No-run terminal path proven by independent B1/B2 identity checks."""

    validation_instance_id: str
    status: CaseStatus
    reason_code: CaseReasonCode
    prior_b1_attempt_receipts: tuple[ContractRef, ...]
    b1_fast_receipt: ContractRef
    b2_fast_receipt: ContractRef

    outcome_kind = OutcomeKind.EXPLICIT_NOT_CONFIRMED

    def __post_init__(self) -> None:
        _validate_common_outcome(
            self.validation_instance_id, self.status, self.reason_code
        )
        if self.status is not CaseStatus.NOT_CONFIRMED:
            raise ContractError(
                "explicit_not_confirmed outcome status must be not_confirmed"
            )
        if self.reason_code is not CaseReasonCode.EXPLICIT_NOT_CONFIRMED:
            raise ContractError(
                "explicit_not_confirmed reason_code must be "
                "EXPLICIT_NOT_CONFIRMED"
            )
        prior = _normalize_b1_attempt_refs(
            self.prior_b1_attempt_receipts,
            field="prior_b1_attempt_receipts",
            allow_empty=True,
        )
        object.__setattr__(self, "prior_b1_attempt_receipts", prior)
        _require_ref(
            self.b1_fast_receipt,
            ContractRefKind.GATE_RECEIPT,
            "b1_fast_receipt",
        )
        _require_ref(
            self.b2_fast_receipt,
            ContractRefKind.GATE_RECEIPT,
            "b2_fast_receipt",
        )
        if _same_ref_identity(self.b1_fast_receipt, self.b2_fast_receipt):
            raise ContractError("B1 and B2 fast receipts must be independent")
        fast_identities = (
            (
                self.b1_fast_receipt.kind,
                self.b1_fast_receipt.contract_id,
                self.b1_fast_receipt.contract_version,
            ),
            (
                self.b2_fast_receipt.kind,
                self.b2_fast_receipt.contract_id,
                self.b2_fast_receipt.contract_version,
            ),
        )
        prior_identities = {
            (reference.kind, reference.contract_id, reference.contract_version)
            for reference in prior
        }
        if prior_identities.intersection(fast_identities):
            raise ContractError(
                "prior B1 attempts must be independent from final fast receipts"
            )

    def to_document(self) -> dict[str, object]:
        document = _common_outcome_document(
            kind=self.outcome_kind,
            validation_instance_id=self.validation_instance_id,
            status=self.status,
            reason_code=self.reason_code,
        )
        document.update(
            {
                "prior_b1_attempt_receipts": [
                    reference.to_document()
                    for reference in self.prior_b1_attempt_receipts
                ],
                "b1_fast_receipt": self.b1_fast_receipt.to_document(),
                "b2_fast_receipt": self.b2_fast_receipt.to_document(),
            }
        )
        return document

    @classmethod
    def from_document(cls, value: object) -> ExplicitNotConfirmedOutcome:
        document = _parse_outcome_discriminator(
            value,
            expected_kind=OutcomeKind.EXPLICIT_NOT_CONFIRMED,
            required=(
                "prior_b1_attempt_receipts",
                "b1_fast_receipt",
                "b2_fast_receipt",
            ),
        )
        return cls(
            validation_instance_id=document["validation_instance_id"],
            status=_enum_value(CaseStatus, document["status"], "outcome status"),
            reason_code=_enum_value(
                CaseReasonCode,
                document["reason_code"],
                "outcome reason_code",
            ),
            prior_b1_attempt_receipts=_prior_b1_attempt_refs_from_document(
                document["prior_b1_attempt_receipts"]
            ),
            b1_fast_receipt=_ref_from_document(
                document["b1_fast_receipt"],
                ContractRefKind.GATE_RECEIPT,
                "b1_fast_receipt",
            ),
            b2_fast_receipt=_ref_from_document(
                document["b2_fast_receipt"],
                ContractRefKind.GATE_RECEIPT,
                "b2_fast_receipt",
            ),
        )

    @classmethod
    def from_json(cls, payload: object) -> ExplicitNotConfirmedOutcome:
        return cls.from_document(load_strict_json_object(payload))


@dataclass(frozen=True)
class B1TerminalOutcome(_ContentAddressedOutcome):
    """Terminal result reached by B1 without starting B2."""

    validation_instance_id: str
    status: CaseStatus
    reason_code: CaseReasonCode
    b1_attempt_receipts: tuple[ContractRef, ...]

    outcome_kind = OutcomeKind.B1_TERMINAL

    def __post_init__(self) -> None:
        _validate_common_outcome(
            self.validation_instance_id, self.status, self.reason_code
        )
        if self.status not in _NON_CONFIRMED_STATUSES:
            raise ContractError("b1_terminal outcome cannot have a confirmed status")
        if self.reason_code is CaseReasonCode.EXPLICIT_NOT_CONFIRMED:
            raise ContractError(
                "EXPLICIT_NOT_CONFIRMED requires the independent fast-path topology"
            )
        object.__setattr__(
            self,
            "b1_attempt_receipts",
            _normalize_b1_attempt_refs(self.b1_attempt_receipts),
        )

    def to_document(self) -> dict[str, object]:
        document = _common_outcome_document(
            kind=self.outcome_kind,
            validation_instance_id=self.validation_instance_id,
            status=self.status,
            reason_code=self.reason_code,
        )
        document["b1_attempt_receipts"] = [
            reference.to_document() for reference in self.b1_attempt_receipts
        ]
        return document

    @classmethod
    def from_document(cls, value: object) -> B1TerminalOutcome:
        document = _parse_outcome_discriminator(
            value,
            expected_kind=OutcomeKind.B1_TERMINAL,
            required=("b1_attempt_receipts",),
        )
        return cls(
            validation_instance_id=document["validation_instance_id"],
            status=_enum_value(CaseStatus, document["status"], "outcome status"),
            reason_code=_enum_value(
                CaseReasonCode,
                document["reason_code"],
                "outcome reason_code",
            ),
            b1_attempt_receipts=_b1_attempt_refs_from_document(
                document["b1_attempt_receipts"]
            ),
        )

    @classmethod
    def from_json(cls, payload: object) -> B1TerminalOutcome:
        return cls.from_document(load_strict_json_object(payload))


@dataclass(frozen=True)
class B2RecheckFailedOutcome(_ContentAddressedOutcome):
    """B1 accepted a candidate but the independent full B2 did not confirm it."""

    validation_instance_id: str
    status: CaseStatus
    reason_code: CaseReasonCode
    b1_attempt_receipts: tuple[ContractRef, ...]
    b2_receipt: ContractRef

    outcome_kind = OutcomeKind.B2_RECHECK_FAILED

    def __post_init__(self) -> None:
        _validate_common_outcome(
            self.validation_instance_id, self.status, self.reason_code
        )
        if self.status not in _B2_FAILURE_OUTCOME_STATUSES:
            raise ContractError(
                "b2_recheck_failed outcome must be inconclusive_infra, "
                "inconclusive_oracle, or invalid_submission"
            )
        object.__setattr__(
            self,
            "b1_attempt_receipts",
            _normalize_b1_attempt_refs(self.b1_attempt_receipts),
        )
        _require_ref(self.b2_receipt, ContractRefKind.GATE_RECEIPT, "b2_receipt")
        if any(
            _same_ref_identity(self.b2_receipt, reference)
            for reference in self.b1_attempt_receipts
        ):
            raise ContractError("B2 receipt must be independent from B1 receipts")

    def to_document(self) -> dict[str, object]:
        document = _common_outcome_document(
            kind=self.outcome_kind,
            validation_instance_id=self.validation_instance_id,
            status=self.status,
            reason_code=self.reason_code,
        )
        document.update(
            {
                "b1_attempt_receipts": [
                    reference.to_document()
                    for reference in self.b1_attempt_receipts
                ],
                "b2_receipt": self.b2_receipt.to_document(),
            }
        )
        return document

    @classmethod
    def from_document(cls, value: object) -> B2RecheckFailedOutcome:
        document = _parse_outcome_discriminator(
            value,
            expected_kind=OutcomeKind.B2_RECHECK_FAILED,
            required=("b1_attempt_receipts", "b2_receipt"),
        )
        return cls(
            validation_instance_id=document["validation_instance_id"],
            status=_enum_value(CaseStatus, document["status"], "outcome status"),
            reason_code=_enum_value(
                CaseReasonCode,
                document["reason_code"],
                "outcome reason_code",
            ),
            b1_attempt_receipts=_b1_attempt_refs_from_document(
                document["b1_attempt_receipts"]
            ),
            b2_receipt=_ref_from_document(
                document["b2_receipt"],
                ContractRefKind.GATE_RECEIPT,
                "b2_receipt",
            ),
        )

    @classmethod
    def from_json(cls, payload: object) -> B2RecheckFailedOutcome:
        return cls.from_document(load_strict_json_object(payload))


@dataclass(frozen=True)
class CrossGateFailedOutcome(_ContentAddressedOutcome):
    """Both Gates confirmed locally but failed the frozen reproducibility rule."""

    validation_instance_id: str
    status: CaseStatus
    reason_code: CaseReasonCode
    b1_attempt_receipts: tuple[ContractRef, ...]
    b2_receipt: ContractRef
    cross_gate_decision: ContractRef

    outcome_kind = OutcomeKind.CROSS_GATE_FAILED

    def __post_init__(self) -> None:
        _validate_common_outcome(
            self.validation_instance_id, self.status, self.reason_code
        )
        if (
            self.status is not CaseStatus.INCONCLUSIVE_ORACLE
            or self.reason_code is not CaseReasonCode.REPRODUCIBILITY_FAILED
        ):
            raise ContractError(
                "cross_gate_failed outcome must be "
                "inconclusive_oracle/REPRODUCIBILITY_FAILED"
            )
        object.__setattr__(
            self,
            "b1_attempt_receipts",
            _normalize_b1_attempt_refs(self.b1_attempt_receipts),
        )
        _require_ref(self.b2_receipt, ContractRefKind.GATE_RECEIPT, "b2_receipt")
        _require_ref(
            self.cross_gate_decision,
            ContractRefKind.CROSS_GATE_DECISION,
            "cross_gate_decision",
        )
        if any(
            _same_ref_identity(self.b2_receipt, reference)
            for reference in self.b1_attempt_receipts
        ):
            raise ContractError("B2 receipt must be independent from B1 receipts")

    def to_document(self) -> dict[str, object]:
        document = _common_outcome_document(
            kind=self.outcome_kind,
            validation_instance_id=self.validation_instance_id,
            status=self.status,
            reason_code=self.reason_code,
        )
        document.update(
            {
                "b1_attempt_receipts": [
                    reference.to_document()
                    for reference in self.b1_attempt_receipts
                ],
                "b2_receipt": self.b2_receipt.to_document(),
                "cross_gate_decision": self.cross_gate_decision.to_document(),
            }
        )
        return document

    @classmethod
    def from_document(cls, value: object) -> CrossGateFailedOutcome:
        document = _parse_outcome_discriminator(
            value,
            expected_kind=OutcomeKind.CROSS_GATE_FAILED,
            required=(
                "b1_attempt_receipts",
                "b2_receipt",
                "cross_gate_decision",
            ),
        )
        return cls(
            validation_instance_id=document["validation_instance_id"],
            status=_enum_value(CaseStatus, document["status"], "outcome status"),
            reason_code=_enum_value(
                CaseReasonCode,
                document["reason_code"],
                "outcome reason_code",
            ),
            b1_attempt_receipts=_b1_attempt_refs_from_document(
                document["b1_attempt_receipts"]
            ),
            b2_receipt=_ref_from_document(
                document["b2_receipt"],
                ContractRefKind.GATE_RECEIPT,
                "b2_receipt",
            ),
            cross_gate_decision=_ref_from_document(
                document["cross_gate_decision"],
                ContractRefKind.CROSS_GATE_DECISION,
                "cross_gate_decision",
            ),
        )

    @classmethod
    def from_json(cls, payload: object) -> CrossGateFailedOutcome:
        return cls.from_document(load_strict_json_object(payload))


@dataclass(frozen=True)
class ConfirmedOutcome(_ContentAddressedOutcome):
    """Terminal confirmed result backed by a separate certificate/v2."""

    validation_instance_id: str
    status: CaseStatus
    reason_code: CaseReasonCode
    b1_attempt_receipts: tuple[ContractRef, ...]
    b2_receipt: ContractRef
    certificate: ContractRef

    outcome_kind = OutcomeKind.CONFIRMED

    def __post_init__(self) -> None:
        _validate_common_outcome(
            self.validation_instance_id, self.status, self.reason_code
        )
        if self.status not in (
            CaseStatus.CONFIRMED_L0,
            CaseStatus.CONFIRMED_L1,
        ):
            raise ContractError("confirmed outcome requires a confirmed status")
        object.__setattr__(
            self,
            "b1_attempt_receipts",
            _normalize_b1_attempt_refs(self.b1_attempt_receipts),
        )
        _require_ref(self.b2_receipt, ContractRefKind.GATE_RECEIPT, "b2_receipt")
        _require_ref(self.certificate, ContractRefKind.CERTIFICATE, "certificate")
        if any(
            _same_ref_identity(self.b2_receipt, reference)
            for reference in self.b1_attempt_receipts
        ):
            raise ContractError("B2 receipt must be independent from B1 receipts")

    def to_document(self) -> dict[str, object]:
        document = _common_outcome_document(
            kind=self.outcome_kind,
            validation_instance_id=self.validation_instance_id,
            status=self.status,
            reason_code=self.reason_code,
        )
        document.update(
            {
                "b1_attempt_receipts": [
                    reference.to_document()
                    for reference in self.b1_attempt_receipts
                ],
                "b2_receipt": self.b2_receipt.to_document(),
                "certificate": self.certificate.to_document(),
            }
        )
        return document

    @classmethod
    def from_document(cls, value: object) -> ConfirmedOutcome:
        document = _parse_outcome_discriminator(
            value,
            expected_kind=OutcomeKind.CONFIRMED,
            required=("b1_attempt_receipts", "b2_receipt", "certificate"),
        )
        return cls(
            validation_instance_id=document["validation_instance_id"],
            status=_enum_value(CaseStatus, document["status"], "outcome status"),
            reason_code=_enum_value(
                CaseReasonCode,
                document["reason_code"],
                "outcome reason_code",
            ),
            b1_attempt_receipts=_b1_attempt_refs_from_document(
                document["b1_attempt_receipts"]
            ),
            b2_receipt=_ref_from_document(
                document["b2_receipt"],
                ContractRefKind.GATE_RECEIPT,
                "b2_receipt",
            ),
            certificate=_ref_from_document(
                document["certificate"],
                ContractRefKind.CERTIFICATE,
                "certificate",
            ),
        )

    @classmethod
    def from_json(cls, payload: object) -> ConfirmedOutcome:
        return cls.from_document(load_strict_json_object(payload))


ValidationOutcome: TypeAlias = (
    ExplicitNotConfirmedOutcome
    | B1TerminalOutcome
    | B2RecheckFailedOutcome
    | CrossGateFailedOutcome
    | ConfirmedOutcome
)


def validation_outcome_from_document(value: object) -> ValidationOutcome:
    """Parse one exact branch of validation-outcome/v1."""

    if type(value) is not dict:
        raise ContractError("validation outcome must be an object")
    raw_kind = value.get("outcome_kind")
    kind = _enum_value(OutcomeKind, raw_kind, "outcome_kind")
    parsers = {
        OutcomeKind.EXPLICIT_NOT_CONFIRMED: (
            ExplicitNotConfirmedOutcome.from_document
        ),
        OutcomeKind.B1_TERMINAL: B1TerminalOutcome.from_document,
        OutcomeKind.B2_RECHECK_FAILED: B2RecheckFailedOutcome.from_document,
        OutcomeKind.CROSS_GATE_FAILED: CrossGateFailedOutcome.from_document,
        OutcomeKind.CONFIRMED: ConfirmedOutcome.from_document,
    }
    return parsers[kind](value)


def validation_outcome_from_json(payload: object) -> ValidationOutcome:
    return validation_outcome_from_document(load_strict_json_object(payload))


@dataclass(frozen=True)
class CertificateV2:
    """Content-addressed proof that independent B1 and B2 confirmed one grade.

    The certificate intentionally does not reference ``ValidationOutcome``.
    A confirmed outcome references the certificate, producing an acyclic
    Observation -> OracleDecision -> Receipt -> CrossGateDecision ->
    Certificate -> Outcome graph.
    """

    validation_instance_id: str
    profile: ContractRef
    case_plan: ContractRef
    template: ContractRef
    b1_receipt: ContractRef
    b2_receipt: ContractRef
    cross_gate_decision: ContractRef
    final_grade: ValidationGrade

    def __post_init__(self) -> None:
        validate_sha256(self.validation_instance_id, "validation_instance_id")
        _require_ref(self.profile, ContractRefKind.FROZEN_PROFILE, "profile")
        _require_ref(self.case_plan, ContractRefKind.CASE_PLAN, "case_plan")
        _require_ref(
            self.template,
            ContractRefKind.EXPERIMENT_PLAN_TEMPLATE,
            "template",
        )
        _require_ref(
            self.b1_receipt, ContractRefKind.GATE_RECEIPT, "b1_receipt"
        )
        _require_ref(
            self.b2_receipt, ContractRefKind.GATE_RECEIPT, "b2_receipt"
        )
        if _same_ref_identity(self.b1_receipt, self.b2_receipt):
            raise ContractError("certificate requires independent B1/B2 receipts")
        _require_ref(
            self.cross_gate_decision,
            ContractRefKind.CROSS_GATE_DECISION,
            "cross_gate_decision",
        )
        if type(self.final_grade) is not ValidationGrade:
            raise ContractError("final_grade must be a ValidationGrade")

    @property
    def status(self) -> CaseStatus:
        if self.final_grade is ValidationGrade.L0:
            return CaseStatus.CONFIRMED_L0
        return CaseStatus.CONFIRMED_L1

    def to_document(self) -> dict[str, object]:
        return {
            "contract_kind": _CERTIFICATE_CONTRACT_KIND,
            "schema_version": _CERTIFICATE_SCHEMA_VERSION,
            "validation_instance_id": self.validation_instance_id,
            "profile": self.profile.to_document(),
            "case_plan": self.case_plan.to_document(),
            "template": self.template.to_document(),
            "b1_receipt": self.b1_receipt.to_document(),
            "b2_receipt": self.b2_receipt.to_document(),
            "cross_gate_decision": self.cross_gate_decision.to_document(),
            "final_grade": self.final_grade.value,
        }

    @classmethod
    def from_document(cls, value: object) -> CertificateV2:
        document = require_exact_keys(
            value,
            required=(
                "contract_kind",
                "schema_version",
                "validation_instance_id",
                "profile",
                "case_plan",
                "template",
                "b1_receipt",
                "b2_receipt",
                "cross_gate_decision",
                "final_grade",
            ),
            where="certificate/v2",
        )
        if document["contract_kind"] != _CERTIFICATE_CONTRACT_KIND:
            raise ContractError(
                f"certificate contract_kind must be {_CERTIFICATE_CONTRACT_KIND!r}"
            )
        if (
            type(document["schema_version"]) is not int
            or document["schema_version"] != _CERTIFICATE_SCHEMA_VERSION
        ):
            raise ContractError("certificate schema_version must be integer 2")
        return cls(
            validation_instance_id=document["validation_instance_id"],
            profile=_ref_from_document(
                document["profile"],
                ContractRefKind.FROZEN_PROFILE,
                "profile",
            ),
            case_plan=_ref_from_document(
                document["case_plan"],
                ContractRefKind.CASE_PLAN,
                "case_plan",
            ),
            template=_ref_from_document(
                document["template"],
                ContractRefKind.EXPERIMENT_PLAN_TEMPLATE,
                "template",
            ),
            b1_receipt=_ref_from_document(
                document["b1_receipt"],
                ContractRefKind.GATE_RECEIPT,
                "b1_receipt",
            ),
            b2_receipt=_ref_from_document(
                document["b2_receipt"],
                ContractRefKind.GATE_RECEIPT,
                "b2_receipt",
            ),
            cross_gate_decision=_ref_from_document(
                document["cross_gate_decision"],
                ContractRefKind.CROSS_GATE_DECISION,
                "cross_gate_decision",
            ),
            final_grade=_enum_value(
                ValidationGrade,
                document["final_grade"],
                "certificate final_grade",
            ),
        )

    @classmethod
    def from_json(cls, payload: object) -> CertificateV2:
        return cls.from_document(load_strict_json_object(payload))

    @property
    def content_sha256(self) -> str:
        return canonical_sha256(self.to_document())

    @property
    def ref(self) -> ContractRef:
        return ContractRef(
            kind=ContractRefKind.CERTIFICATE,
            contract_id=self.content_sha256,
            contract_version="2",
            content_sha256=self.content_sha256,
        )


def _receipt_profile_sha256(
    receipt: CandidateGateReceipt | EarlyGateReceipt,
) -> str:
    from .receipt import CandidateGateReceipt, EarlyGateReceipt

    if type(receipt) is CandidateGateReceipt:
        return receipt.profile.content_sha256
    if type(receipt) is EarlyGateReceipt:
        return receipt.profile_sha256
    raise ContractError("B1 attempt history contains an unsupported receipt type")


def _validate_b1_attempt_context(
    outcome: ValidationOutcome,
    b1_receipts: tuple[CandidateGateReceipt | EarlyGateReceipt, ...],
    *,
    allow_empty: bool,
    expected_profile_sha256: str | None = None,
    reserved_attempt_ids: tuple[str, ...] = (),
) -> None:
    from .receipt import CandidateGateReceipt, EarlyGateReceipt

    if not allow_empty and not b1_receipts:
        raise ContractError("outcome requires at least one B1 attempt receipt")
    if any(
        type(receipt) not in (CandidateGateReceipt, EarlyGateReceipt)
        for receipt in b1_receipts
    ):
        raise ContractError("B1 history requires candidate or early Gate receipts")
    if any(receipt.role is not GateRole.B1 for receipt in b1_receipts):
        raise ContractError("B1 attempt receipts must all have role B1")
    if any(
        receipt.validation_instance_id != outcome.validation_instance_id
        for receipt in b1_receipts
    ):
        raise ContractError("B1 attempt validation instance mismatch")
    profile_hashes = {_receipt_profile_sha256(receipt) for receipt in b1_receipts}
    if len(profile_hashes) > 1:
        raise ContractError("B1 attempt history must keep one frozen Profile")
    if expected_profile_sha256 is not None and any(
        value != expected_profile_sha256 for value in profile_hashes
    ):
        raise ContractError("B1 attempt history Profile differs from final attempt")
    attempt_ids = tuple(receipt.attempt_id for receipt in b1_receipts)
    all_attempt_ids = (*attempt_ids, *reserved_attempt_ids)
    if len(all_attempt_ids) != len(set(all_attempt_ids)):
        raise ContractError("B1 attempt history must not repeat attempt_id")


def _validate_retryable_b1_history(
    outcome: ValidationOutcome,
    b1_receipts: tuple[CandidateGateReceipt | EarlyGateReceipt, ...],
    *,
    expected_profile_sha256: str | None = None,
    reserved_attempt_ids: tuple[str, ...] = (),
) -> None:
    _validate_b1_attempt_context(
        outcome,
        b1_receipts,
        allow_empty=True,
        expected_profile_sha256=expected_profile_sha256,
        reserved_attempt_ids=reserved_attempt_ids,
    )
    if any(
        receipt.disposition is not GateAttemptDisposition.RETRYABLE_REJECTION
        for receipt in b1_receipts
    ):
        raise ContractError("prior B1 attempt history must contain only retries")


def _validate_b1_attempt_chain(
    outcome: ValidationOutcome,
    b1_receipts: tuple[CandidateGateReceipt | EarlyGateReceipt, ...],
    *,
    final_disposition: GateAttemptDisposition,
) -> None:
    _validate_b1_attempt_context(outcome, b1_receipts, allow_empty=False)
    if any(
        receipt.disposition is not GateAttemptDisposition.RETRYABLE_REJECTION
        for receipt in b1_receipts[:-1]
    ):
        raise ContractError(
            "only retryable B1 receipts may precede the final B1 attempt"
        )
    if b1_receipts[-1].disposition is not final_disposition:
        raise ContractError("final B1 receipt has the wrong attempt disposition")


def _validate_candidate_pair_common(
    b1: CandidateGateReceipt,
    b2: CandidateGateReceipt | EarlyGateReceipt,
) -> None:
    from .receipt import validate_b1_b2_gate_receipts

    validate_b1_b2_gate_receipts(b1, b2)


def validate_cross_gate_decision(
    decision: CrossGateDecision,
    b1: CandidateGateReceipt,
    b2: CandidateGateReceipt,
) -> None:
    """Validate one Cross-Gate result against the exact confirmed receipts."""

    from .receipt import CandidateGateReceipt

    if type(decision) is not CrossGateDecision:
        raise ContractError("decision must be a CrossGateDecision")
    if type(b1) is not CandidateGateReceipt or type(b2) is not CandidateGateReceipt:
        raise ContractError(
            "Cross-Gate decision requires two full CandidateGateReceipt values"
        )
    _validate_candidate_pair_common(b1, b2)
    if b1.disposition is not GateAttemptDisposition.ACCEPTED_CONFIRMED_CANDIDATE:
        raise ContractError("Cross-Gate B1 receipt must accept a confirmed candidate")
    if b2.disposition is not None:
        raise ContractError("Cross-Gate B2 receipt must not contain a disposition")
    confirmed_statuses = (CaseStatus.CONFIRMED_L0, CaseStatus.CONFIRMED_L1)
    if (
        b1.result_status not in confirmed_statuses
        or b2.result_status not in confirmed_statuses
        or b1.final_grade is None
        or b2.final_grade is None
    ):
        raise ContractError(
            "Cross-Gate comparison requires two individually confirmed receipts"
        )
    if decision.validation_instance_id != b1.validation_instance_id:
        raise ContractError("Cross-Gate decision validation instance mismatch")
    if decision.b1_receipt != b1.ref or decision.b2_receipt != b2.ref:
        raise ContractError("Cross-Gate decision does not bind the supplied receipts")
    if decision.b1_decisions != b1.decisions:
        raise ContractError("Cross-Gate decision B1 evidence membership mismatch")
    if decision.b2_decisions != b2.decisions:
        raise ContractError("Cross-Gate decision B2 evidence membership mismatch")
    if decision.verdict is CrossGateVerdict.REPRODUCIBLE and (
        b1.final_grade is not b2.final_grade
        or b1.result_status is not b2.result_status
    ):
        raise ContractError(
            "a reproducible Cross-Gate result cannot hide a grade mismatch"
        )


def validate_certificate_publication(
    certificate: CertificateV2,
    b1: CandidateGateReceipt,
    b2: CandidateGateReceipt,
    cross_gate_decision: CrossGateDecision,
) -> None:
    """Validate the complete, acyclic proof boundary for certificate/v2."""

    from .receipt import CandidateGateReceipt

    if type(certificate) is not CertificateV2:
        raise ContractError("certificate must be a CertificateV2")
    if type(cross_gate_decision) is not CrossGateDecision:
        raise ContractError("cross_gate_decision must be a CrossGateDecision")
    if type(b1) is not CandidateGateReceipt or type(b2) is not CandidateGateReceipt:
        raise ContractError("certificate requires two full CandidateGateReceipt values")
    validate_cross_gate_decision(cross_gate_decision, b1, b2)
    if cross_gate_decision.verdict is not CrossGateVerdict.REPRODUCIBLE:
        raise ContractError(
            "certificate requires a REPRODUCIBLE Cross-Gate decision"
        )
    if b1.disposition is not GateAttemptDisposition.ACCEPTED_CONFIRMED_CANDIDATE:
        raise ContractError("certificate B1 receipt must accept a confirmed candidate")
    if b2.disposition is not None:
        raise ContractError("B2 candidate receipt must not contain a B1 disposition")
    if b1.final_grade is None or b2.final_grade is None:
        raise ContractError("certificate receipts must both contain a final grade")
    if b1.final_grade is not b2.final_grade:
        raise ContractError("certificate cannot hide an L0/L1 grade mismatch")
    if b1.result_status not in (
        CaseStatus.CONFIRMED_L0,
        CaseStatus.CONFIRMED_L1,
    ) or b2.result_status not in (
        CaseStatus.CONFIRMED_L0,
        CaseStatus.CONFIRMED_L1,
    ):
        raise ContractError("certificate receipts must both be confirmed")
    expected_status = (
        CaseStatus.CONFIRMED_L0
        if b1.final_grade is ValidationGrade.L0
        else CaseStatus.CONFIRMED_L1
    )
    if (
        b1.result_status is not expected_status
        or b2.result_status is not expected_status
    ):
        raise ContractError("receipt confirmed status does not match final grade")
    if certificate.validation_instance_id != b1.validation_instance_id:
        raise ContractError("certificate validation instance mismatch")
    if certificate.profile != b1.profile:
        raise ContractError("certificate Profile mismatch")
    if certificate.case_plan != b1.case_plan:
        raise ContractError("certificate CasePlan mismatch")
    if certificate.template != b1.template:
        raise ContractError("certificate ExperimentPlanTemplate mismatch")
    if certificate.b1_receipt != b1.ref or certificate.b2_receipt != b2.ref:
        raise ContractError("certificate does not bind the supplied B1/B2 receipts")
    if certificate.cross_gate_decision != cross_gate_decision.ref:
        raise ContractError("certificate does not bind the Cross-Gate decision")
    if certificate.final_grade is not b1.final_grade:
        raise ContractError("certificate final grade mismatch")


def validate_outcome_publication(
    outcome: ValidationOutcome,
    *,
    receipts: Iterable[
        CandidateGateReceipt | EarlyGateReceipt | FastPathGateReceipt
    ],
    certificate: CertificateV2 | None = None,
    cross_gate_decision: CrossGateDecision | None = None,
) -> None:
    """Validate exact receipt/certificate membership for one terminal outcome."""

    from .receipt import (
        CandidateGateReceipt,
        EarlyGateReceipt,
        FastPathGateReceipt,
    )

    outcome_types = (
        ExplicitNotConfirmedOutcome,
        B1TerminalOutcome,
        B2RecheckFailedOutcome,
        CrossGateFailedOutcome,
        ConfirmedOutcome,
    )
    if type(outcome) not in outcome_types:
        raise ContractError("outcome must be one validation-outcome/v1 branch")
    if certificate is not None and type(certificate) is not CertificateV2:
        raise ContractError("certificate must be a CertificateV2 or None")
    if (
        cross_gate_decision is not None
        and type(cross_gate_decision) is not CrossGateDecision
    ):
        raise ContractError(
            "cross_gate_decision must be a CrossGateDecision or None"
        )
    receipt_values = tuple(receipts)
    if any(
        type(receipt)
        not in (CandidateGateReceipt, EarlyGateReceipt, FastPathGateReceipt)
        for receipt in receipt_values
    ):
        raise ContractError("receipts contain an unsupported Gate receipt type")
    refs = tuple(receipt.ref for receipt in receipt_values)
    ref_identities = tuple(
        (reference.kind, reference.contract_id, reference.contract_version)
        for reference in refs
    )
    if len(ref_identities) != len(set(ref_identities)):
        raise ContractError(
            "receipts must not repeat or conflict on reference identity"
        )
    by_ref = {receipt.ref: receipt for receipt in receipt_values}

    if type(outcome) is ExplicitNotConfirmedOutcome:
        if certificate is not None or cross_gate_decision is not None:
            raise ContractError(
                "explicit not_confirmed cannot have Cross-Gate proof or certificate"
            )
        expected = (
            *outcome.prior_b1_attempt_receipts,
            outcome.b1_fast_receipt,
            outcome.b2_fast_receipt,
        )
        if set(refs) != set(expected) or len(refs) != len(expected):
            raise ContractError(
                "explicit not_confirmed receipts do not exactly match its history"
            )
        b1 = by_ref[outcome.b1_fast_receipt]
        b2 = by_ref[outcome.b2_fast_receipt]
        if type(b1) is not FastPathGateReceipt or type(b2) is not FastPathGateReceipt:
            raise ContractError(
                "explicit not_confirmed requires FastPathGateReceipt values"
            )
        from .receipt import validate_b1_b2_gate_receipts

        validate_b1_b2_gate_receipts(b1, b2)
        if b1.validation_instance_id != outcome.validation_instance_id:
            raise ContractError("fast receipt validation instance mismatch")
        prior_receipts = tuple(
            by_ref[reference]
            for reference in outcome.prior_b1_attempt_receipts
        )
        if any(
            type(receipt) not in (CandidateGateReceipt, EarlyGateReceipt)
            for receipt in prior_receipts
        ):
            raise ContractError(
                "explicit prior B1 history requires candidate or early receipts"
            )
        _validate_retryable_b1_history(
            outcome,
            prior_receipts,
            expected_profile_sha256=b1.profile_sha256,
            reserved_attempt_ids=(b1.attempt_id,),
        )
        return

    if certificate is not None and type(outcome) is not ConfirmedOutcome:
        raise ContractError("only a confirmed outcome may publish a certificate")
    if cross_gate_decision is not None and type(outcome) not in (
        CrossGateFailedOutcome,
        ConfirmedOutcome,
    ):
        raise ContractError(
            "only a Cross-Gate terminal outcome may publish a Cross-Gate decision"
        )

    expected_refs = (
        outcome.b1_attempt_receipts
        if type(outcome) is B1TerminalOutcome
        else (*outcome.b1_attempt_receipts, outcome.b2_receipt)
    )
    if set(refs) != set(expected_refs) or len(refs) != len(expected_refs):
        raise ContractError("receipts do not exactly match outcome attempt history")
    b1_receipts = tuple(by_ref[reference] for reference in outcome.b1_attempt_receipts)
    if any(
        type(receipt) not in (CandidateGateReceipt, EarlyGateReceipt)
        for receipt in b1_receipts
    ):
        raise ContractError("B1 history requires candidate or early Gate receipts")

    if type(outcome) is B1TerminalOutcome:
        _validate_b1_attempt_chain(
            outcome,
            b1_receipts,
            final_disposition=GateAttemptDisposition.TERMINAL_OUTCOME,
        )
        final = b1_receipts[-1]
        if (
            final.result_status is not outcome.status
            or final.result_reason_code is not outcome.reason_code
        ):
            raise ContractError("terminal B1 result does not match outcome")
        return

    _validate_b1_attempt_chain(
        outcome,
        b1_receipts,
        final_disposition=GateAttemptDisposition.ACCEPTED_CONFIRMED_CANDIDATE,
    )
    b1 = b1_receipts[-1]
    if type(b1) is not CandidateGateReceipt:
        raise ContractError("only a confirmed candidate B1 may start B2")
    b2 = by_ref[outcome.b2_receipt]
    if type(b2) not in (CandidateGateReceipt, EarlyGateReceipt):
        raise ContractError("B2 candidate outcome requires full or early receipt")
    _validate_candidate_pair_common(b1, b2)
    if b1.result_status not in (
        CaseStatus.CONFIRMED_L0,
        CaseStatus.CONFIRMED_L1,
    ) or b1.final_grade is None:
        raise ContractError("accepted B1 receipt must contain a confirmed grade")
    if b2.disposition is not None:
        raise ContractError("B2 candidate receipt must not contain a B1 disposition")

    if type(outcome) is B2RecheckFailedOutcome:
        if type(b2) is CandidateGateReceipt and b2.result_status in (
            CaseStatus.CONFIRMED_L0,
            CaseStatus.CONFIRMED_L1,
        ):
            raise ContractError(
                "two individually confirmed receipts require a Cross-Gate outcome"
            )
        if b2.result_status in (
            CaseStatus.INCONCLUSIVE_INFRA,
            CaseStatus.INVALID_SUBMISSION,
        ):
            if (
                b2.result_status is not outcome.status
                or b2.result_reason_code is not outcome.reason_code
            ):
                raise ContractError("B2 result does not match failed-recheck outcome")
        elif (
            outcome.status is not CaseStatus.INCONCLUSIVE_ORACLE
            or outcome.reason_code is not CaseReasonCode.REPRODUCIBILITY_FAILED
        ):
            raise ContractError(
                "a B1/B2 disagreement without clear infrastructure failure "
                "must publish inconclusive_oracle/REPRODUCIBILITY_FAILED"
            )
        return

    if type(b2) is not CandidateGateReceipt:
        raise ContractError(
            "Cross-Gate decisions and certificates require a full B2 receipt"
        )

    if type(outcome) is CrossGateFailedOutcome:
        if cross_gate_decision is None:
            raise ContractError(
                "cross_gate_failed outcome requires a CrossGateDecision"
            )
        if outcome.cross_gate_decision != cross_gate_decision.ref:
            raise ContractError(
                "cross_gate_failed outcome does not bind the supplied decision"
            )
        validate_cross_gate_decision(cross_gate_decision, b1, b2)
        if (
            cross_gate_decision.verdict
            is not CrossGateVerdict.REPRODUCIBILITY_FAILED
        ):
            raise ContractError(
                "cross_gate_failed outcome requires REPRODUCIBILITY_FAILED"
            )
        return

    if certificate is None:
        raise ContractError("confirmed outcome requires certificate/v2")
    if cross_gate_decision is None:
        raise ContractError("confirmed outcome requires a CrossGateDecision")
    if outcome.certificate != certificate.ref:
        raise ContractError("confirmed outcome does not bind supplied certificate")
    if outcome.status is not certificate.status:
        raise ContractError("confirmed outcome status does not match certificate grade")
    validate_certificate_publication(
        certificate,
        b1,
        b2,
        cross_gate_decision,
    )


__all__ = [
    "B1TerminalOutcome",
    "B2RecheckFailedOutcome",
    "CertificateV2",
    "ConfirmedOutcome",
    "CrossGateDecision",
    "CrossGateFailedOutcome",
    "CrossGateVerdict",
    "ExplicitNotConfirmedOutcome",
    "OutcomeKind",
    "ValidationOutcome",
    "validate_certificate_publication",
    "validate_cross_gate_decision",
    "validate_outcome_publication",
    "validation_outcome_from_document",
    "validation_outcome_from_json",
]

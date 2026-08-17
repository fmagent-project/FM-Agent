"""Pure, hash-bound contracts for governed Project Profile Setup.

This module deliberately contains no execution or storage code.  It describes
the immutable objects that a Setup qualification worker, independent reviewer,
human/admission authority, registry, and revocation verifier exchange.  Raw
holdout observations, host paths, and current Case/B1/B2 data have no field in
these schemas.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime, timezone
from decimal import Decimal
from enum import Enum

from .base import (
    CanonicalDecimal,
    ContractError,
    canonical_sha256,
    load_strict_json_object,
    normalize_identifiers,
    require_exact_keys,
    validate_identifier,
    validate_non_negative_int,
    validate_positive_int,
    validate_sha256,
)
from .evidence import OracleVerdict
from .preset import RegistrationTrustTier
from .profile import EnvironmentBinding, FrozenSystemProfile, ProjectBinding
from .references import ArtifactRef, ContractRef, ContractRefKind


_SCHEMA_VERSION = 1
_MAX_ITEMS = 4096
_MAX_COMMITMENTS = 16_384
_MAX_TRIALS = 16_384
_MAX_TTL_SECONDS = 31_536_000
_UTC_TIMESTAMP_RE = re.compile(
    r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z\Z"
)

_PROFILE_GRAPH_KIND = "profile_graph"
_SETUP_CANDIDATE_KIND = "profile_setup_candidate"
_QUALIFICATION_POLICY_KIND = "qualification_policy"
_QUALIFICATION_PLAN_KIND = "qualification_plan"
_CALIBRATION_REPORT_KIND = "calibration_report"
_QUALIFICATION_REPORT_KIND = "qualification_report"
_REVIEW_BUNDLE_KIND = "result_blind_review_bundle"
_REVIEW_RECORD_KIND = "profile_review_record"
_APPROVAL_RECORD_KIND = "semantic_approval_record"
_SETUP_LIFECYCLE_KIND = "profile_setup_lifecycle"
_INVALIDATION_MANIFEST_KIND = "dependency_invalidation_manifest"
_PROFILE_ADMISSION_KIND = "profile_admission_record"
_REVOCATION_LEDGER_KIND = "revocation_ledger"
_TRUST_EVALUATION_KIND = "profile_trust_evaluation"

_PROFILE_COMPONENT_KINDS = frozenset(
    {
        ContractRefKind.EXECUTION_RECIPE_SCHEMA,
        ContractRefKind.EXECUTION_BLOCK,
        ContractRefKind.TOOL,
        ContractRefKind.ARGV_TEMPLATE,
        ContractRefKind.COLLECTOR,
        ContractRefKind.NORMALIZER,
        ContractRefKind.COMPARATOR,
        ContractRefKind.HEALTHY_RELATION_POLICY,
        ContractRefKind.DECISION_POLICY,
        ContractRefKind.QUALIFICATION_POLICY,
        ContractRefKind.BASELINE_POLICY,
        ContractRefKind.THRESHOLD_POLICY,
        ContractRefKind.TRANSFORM_POLICY,
        ContractRefKind.INVARIANT_POLICY,
        ContractRefKind.TIMEOUT_POLICY,
        ContractRefKind.RESOURCE_POLICY,
        ContractRefKind.OUTPUT_CONTRACT,
        ContractRefKind.ENVIRONMENT_POLICY,
        ContractRefKind.TARGET_EVIDENCE_POLICY,
        ContractRefKind.CONTROL_POLICY,
        ContractRefKind.REPAIR_POLICY,
        ContractRefKind.RESET_POLICY,
        ContractRefKind.EXECUTION_EQUIVALENCE_POLICY,
    }
)


class SetupState(str, Enum):
    DRAFT = "draft"
    QUALIFYING = "qualifying"
    NEEDS_REVISION = "needs_revision"
    AWAITING_REVIEW = "awaiting_review"
    AWAITING_APPROVAL = "awaiting_approval"
    FROZEN = "frozen"
    SUPERSEDED = "superseded"
    REVOKED = "revoked"


class QualificationMode(str, Enum):
    DETERMINISTIC = "deterministic"
    STATISTICAL = "statistical"


class StatisticalBoundMethod(str, Enum):
    NOT_APPLICABLE = "not_applicable"
    CLOPPER_PEARSON = "clopper_pearson"
    CLUSTER_AWARE = "cluster_aware"


class QualificationPartitionKind(str, Enum):
    CALIBRATION = "calibration"
    HOLDOUT = "holdout"
    NEGATIVE = "negative"
    OUT_OF_DOMAIN = "out_of_domain"


class FixtureVisibility(str, Enum):
    SETUP_AGENT_VISIBLE = "setup_agent_visible"
    HARNESS_ONLY = "harness_only"


class QualificationVerdict(str, Enum):
    PASS = "pass"
    FAIL = "fail"


class ReviewVerdict(str, Enum):
    APPROVE = "approve"
    REVISE = "revise"
    REJECT = "reject"


class ApprovalAuthorityKind(str, Enum):
    HUMAN = "human"
    HARNESS = "harness"
    MAINTAINER = "maintainer"


class ApprovalDecision(str, Enum):
    APPROVE = "approve"
    REJECT = "reject"


class SetupActorRole(str, Enum):
    SETUP_AGENT = "setup_agent"
    QUALIFICATION_WORKER = "qualification_worker"
    REVIEWER = "reviewer"
    HUMAN = "human"
    HARNESS = "harness"
    MAINTAINER = "maintainer"


class DependencyKind(str, Enum):
    SOURCE_SNAPSHOT = "source_snapshot"
    PROFILE_GRAPH = "profile_graph"
    ENTRYPOINT = "entrypoint"
    WORKLOAD_SCHEMA = "workload_schema"
    BASELINE = "baseline"
    ADAPTER = "adapter"
    INSTRUMENTATION = "instrumentation"
    ORACLE = "oracle"
    ORACLE_BUNDLE = "oracle_bundle"
    EXECUTION_RECIPE = "execution_recipe"
    PROFILE_COMPONENT = "profile_component"
    ADAPTER_CODE = "adapter_code"
    DEPENDENCY_LOCK = "dependency_lock"
    PERMISSION_MANIFEST = "permission_manifest"
    SBOM = "sbom"
    CAPABILITY_SET = "capability_set"
    TOOLCHAIN = "toolchain"
    OS_IMAGE = "os_image"
    MODEL = "model"
    HARDWARE = "hardware"
    DEVICE_IMAGE = "device_image"
    RESOURCE_POLICY = "resource_policy"


class InvalidationAction(str, Enum):
    REUSE_APPROVAL = "reuse_approval"
    PROFILE_GATE = "profile_gate"
    LIGHTWEIGHT_QUALIFICATION = "lightweight_qualification"
    FULL_QUALIFICATION = "full_qualification"
    REQUALIFY_REVIEW = "requalify_review"
    REQUALIFY_REVIEW_REAPPROVE = "requalify_review_reapprove"


class RevocationTargetKind(str, Enum):
    PROFILE = "profile"
    ADAPTER = "adapter"
    APPROVAL = "approval"
    ADMISSION = "admission"
    QUALIFICATION = "qualification"
    REVIEW = "review"


class RevocationReason(str, Enum):
    COMPROMISED = "compromised"
    POLICY_VIOLATION = "policy_violation"
    DEPENDENCY_INVALIDATED = "dependency_invalidated"
    SUPERSEDED = "superseded"
    MANUAL = "manual"


class TrustReasonCode(str, Enum):
    VALID = "valid"
    INVALID_AT_ISSUANCE = "invalid_at_issuance"
    ADMISSION_EXPIRED = "admission_expired"
    PROFILE_REVOKED = "profile_revoked"
    ADAPTER_REVOKED = "adapter_revoked"
    APPROVAL_REVOKED = "approval_revoked"
    ADMISSION_REVOKED = "admission_revoked"
    QUALIFICATION_REVOKED = "qualification_revoked"
    REVIEW_REVOKED = "review_revoked"


_ALLOWED_SETUP_TRANSITIONS = frozenset(
    {
        (SetupState.DRAFT, SetupState.QUALIFYING),
        (SetupState.QUALIFYING, SetupState.NEEDS_REVISION),
        (SetupState.QUALIFYING, SetupState.AWAITING_REVIEW),
        (SetupState.NEEDS_REVISION, SetupState.QUALIFYING),
        (SetupState.NEEDS_REVISION, SetupState.SUPERSEDED),
        (SetupState.AWAITING_REVIEW, SetupState.NEEDS_REVISION),
        (SetupState.AWAITING_REVIEW, SetupState.AWAITING_APPROVAL),
        (SetupState.AWAITING_APPROVAL, SetupState.NEEDS_REVISION),
        (SetupState.AWAITING_APPROVAL, SetupState.FROZEN),
        (SetupState.FROZEN, SetupState.SUPERSEDED),
        (SetupState.FROZEN, SetupState.REVOKED),
        (SetupState.SUPERSEDED, SetupState.REVOKED),
    }
)


def _enum(enum_type: type[Enum], value: object, field: str) -> Enum:
    if type(value) is not str:
        raise ContractError(f"{field} must be a string enum value")
    try:
        return enum_type(value)
    except ValueError as exc:
        raise ContractError(f"{field} has unsupported value {value!r}") from exc


def _check_header(
    document: dict[str, object],
    expected_kind: str,
    where: str,
) -> None:
    if (
        type(document["contract_kind"]) is not str
        or document["contract_kind"] != expected_kind
    ):
        raise ContractError(f"{where} contract_kind must be {expected_kind!r}")
    if (
        type(document["schema_version"]) is not int
        or document["schema_version"] != _SCHEMA_VERSION
    ):
        raise ContractError(f"{where} schema_version must be integer 1")


def _timestamp(value: object, field: str) -> str:
    if type(value) is not str or not _UTC_TIMESTAMP_RE.fullmatch(value):
        raise ContractError(
            f"{field} must use UTC second-precision YYYY-MM-DDTHH:MM:SSZ"
        )
    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=timezone.utc
        )
    except ValueError as exc:
        raise ContractError(f"{field} must contain a valid UTC timestamp") from exc
    if parsed.strftime("%Y-%m-%dT%H:%M:%SZ") != value:
        raise ContractError(f"{field} must be canonical")
    return value


def _optional_timestamp(value: object, field: str) -> str | None:
    if value is None:
        return None
    return _timestamp(value, field)


def _require_list(value: object, field: str, maximum: int = _MAX_ITEMS) -> list[object]:
    if type(value) is not list:
        raise ContractError(f"{field} must be a list")
    if len(value) > maximum:
        raise ContractError(f"{field} must not contain more than {maximum} values")
    return value


def _identifier_tuple(
    value: object,
    field: str,
    *,
    allow_empty: bool = False,
    maximum: int = _MAX_ITEMS,
) -> tuple[str, ...]:
    if type(value) not in (tuple, list, set, frozenset):
        raise ContractError(f"{field} must be a collection")
    if len(value) > maximum:
        raise ContractError(f"{field} must not contain more than {maximum} values")
    result = normalize_identifiers(value, field)
    if not allow_empty and not result:
        raise ContractError(f"{field} must not be empty")
    return result


def _sha_tuple(
    value: object,
    field: str,
    *,
    allow_empty: bool = False,
    maximum: int = _MAX_COMMITMENTS,
) -> tuple[str, ...]:
    if type(value) not in (tuple, list, set, frozenset):
        raise ContractError(f"{field} must be a collection of SHA-256 digests")
    if len(value) > maximum:
        raise ContractError(f"{field} must not contain more than {maximum} values")
    result = tuple(sorted(validate_sha256(item, field) for item in value))
    if len(result) != len(set(result)):
        raise ContractError(f"{field} must not contain duplicates")
    if not allow_empty and not result:
        raise ContractError(f"{field} must not be empty")
    return result


def _require_ref(value: object, kinds: frozenset[ContractRefKind], field: str) -> ContractRef:
    if type(value) is not ContractRef:
        raise ContractError(f"{field} must be a ContractRef")
    if value.kind not in kinds:
        expected = ", ".join(sorted(kind.value for kind in kinds))
        raise ContractError(f"{field} must reference one of: {expected}")
    return value


def _parse_ref(value: object, kinds: frozenset[ContractRefKind], field: str) -> ContractRef:
    try:
        ref = ContractRef.from_document(value)
    except ContractError as exc:
        raise ContractError(f"{field}: {exc}") from exc
    return _require_ref(ref, kinds, field)


def _refs(
    value: object,
    kinds: frozenset[ContractRefKind],
    field: str,
    *,
    allow_empty: bool = False,
) -> tuple[ContractRef, ...]:
    if type(value) not in (tuple, list):
        raise ContractError(f"{field} must be a collection of ContractRef values")
    if len(value) > _MAX_ITEMS:
        raise ContractError(f"{field} must not contain more than {_MAX_ITEMS} values")
    refs = tuple(_require_ref(item, kinds, field) for item in value)
    if not allow_empty and not refs:
        raise ContractError(f"{field} must not be empty")
    identities = tuple((r.kind, r.contract_id, r.contract_version) for r in refs)
    if len(identities) != len(set(identities)):
        raise ContractError(f"{field} repeats or conflicts on kind/id/version")
    return tuple(
        sorted(
            refs,
            key=lambda r: (
                r.kind.value,
                r.contract_id,
                r.contract_version,
                r.content_sha256,
            ),
        )
    )


def _parse_refs(
    value: object,
    kinds: frozenset[ContractRefKind],
    field: str,
    *,
    allow_empty: bool = False,
) -> tuple[ContractRef, ...]:
    documents = _require_list(value, field)
    return _refs(
        tuple(_parse_ref(item, kinds, f"{field}[{index}]") for index, item in enumerate(documents)),
        kinds,
        field,
        allow_empty=allow_empty,
    )


def _artifact(value: object, role: str, field: str) -> ArtifactRef:
    if type(value) is not ArtifactRef:
        raise ContractError(f"{field} must be an ArtifactRef")
    if value.role != role:
        raise ContractError(f"{field} artifact role must be {role!r}")
    return value


def _parse_artifact(value: object, role: str, field: str) -> ArtifactRef:
    try:
        parsed = ArtifactRef.from_document(value)
    except ContractError as exc:
        raise ContractError(f"{field}: {exc}") from exc
    return _artifact(parsed, role, field)


def _decimal_between(
    value: object,
    field: str,
    *,
    lower_inclusive: bool,
    upper_inclusive: bool,
) -> CanonicalDecimal:
    if type(value) is not CanonicalDecimal:
        raise ContractError(f"{field} must be a CanonicalDecimal")
    number = Decimal(value.value)
    lower_ok = number >= 0 if lower_inclusive else number > 0
    upper_ok = number <= 1 if upper_inclusive else number < 1
    if not lower_ok or not upper_ok:
        raise ContractError(f"{field} must be within the required unit interval")
    return value


@dataclass(frozen=True)
class ProfileGraph:
    """The prospective profile graph, excluding Setup evidence and timestamps."""

    profile_id: str
    profile_version: str
    project: ProjectBinding
    environment: EnvironmentBinding
    entrypoints: tuple[ContractRef, ...]
    workload_schemas: tuple[ContractRef, ...]
    adapters: tuple[ContractRef, ...]
    instrumentation_providers: tuple[ContractRef, ...]
    oracle_specs: tuple[ContractRef, ...]
    oracle_bundles: tuple[ContractRef, ...]
    execution_recipes: tuple[ContractRef, ...]
    components: tuple[ContractRef, ...]
    capabilities: tuple[str, ...]

    def __post_init__(self) -> None:
        validate_identifier(self.profile_id, "profile_id")
        validate_identifier(self.profile_version, "profile_version")
        if type(self.project) is not ProjectBinding:
            raise ContractError("project must be a ProjectBinding")
        if type(self.environment) is not EnvironmentBinding:
            raise ContractError("environment must be an EnvironmentBinding")
        specs = (
            ("entrypoints", frozenset({ContractRefKind.ENTRYPOINT})),
            ("workload_schemas", frozenset({ContractRefKind.WORKLOAD_SCHEMA})),
            ("adapters", frozenset({ContractRefKind.ADAPTER})),
            (
                "instrumentation_providers",
                frozenset({ContractRefKind.INSTRUMENTATION_PROVIDER}),
            ),
            ("oracle_specs", frozenset({ContractRefKind.ORACLE_SPEC})),
            ("oracle_bundles", frozenset({ContractRefKind.ORACLE_BUNDLE})),
            ("execution_recipes", frozenset({ContractRefKind.EXECUTION_RECIPE})),
            ("components", _PROFILE_COMPONENT_KINDS),
        )
        for field, kinds in specs:
            object.__setattr__(self, field, _refs(getattr(self, field), kinds, field))
        object.__setattr__(
            self,
            "capabilities",
            _identifier_tuple(self.capabilities, "capabilities"),
        )
        if self.environment.resource_policy not in set(self.components):
            raise ContractError("environment.resource_policy must be in components")

    def to_document(self) -> dict[str, object]:
        return {
            "contract_kind": _PROFILE_GRAPH_KIND,
            "schema_version": _SCHEMA_VERSION,
            "profile_id": self.profile_id,
            "profile_version": self.profile_version,
            "project": self.project.to_document(),
            "environment": self.environment.to_document(),
            "entrypoints": [item.to_document() for item in self.entrypoints],
            "workload_schemas": [item.to_document() for item in self.workload_schemas],
            "adapters": [item.to_document() for item in self.adapters],
            "instrumentation_providers": [
                item.to_document() for item in self.instrumentation_providers
            ],
            "oracle_specs": [item.to_document() for item in self.oracle_specs],
            "oracle_bundles": [item.to_document() for item in self.oracle_bundles],
            "execution_recipes": [item.to_document() for item in self.execution_recipes],
            "components": [item.to_document() for item in self.components],
            "capabilities": list(self.capabilities),
        }

    @classmethod
    def from_document(cls, value: object) -> ProfileGraph:
        doc = require_exact_keys(
            value,
            required=(
                "contract_kind", "schema_version", "profile_id", "profile_version",
                "project", "environment", "entrypoints", "workload_schemas",
                "adapters", "instrumentation_providers", "oracle_specs",
                "oracle_bundles", "execution_recipes", "components", "capabilities",
            ),
            where="profile graph",
        )
        _check_header(doc, _PROFILE_GRAPH_KIND, "profile graph")
        capabilities = _require_list(doc["capabilities"], "profile graph capabilities")
        return cls(
            profile_id=doc["profile_id"],
            profile_version=doc["profile_version"],
            project=ProjectBinding.from_document(doc["project"]),
            environment=EnvironmentBinding.from_document(doc["environment"]),
            entrypoints=_parse_refs(doc["entrypoints"], frozenset({ContractRefKind.ENTRYPOINT}), "entrypoints"),
            workload_schemas=_parse_refs(doc["workload_schemas"], frozenset({ContractRefKind.WORKLOAD_SCHEMA}), "workload_schemas"),
            adapters=_parse_refs(doc["adapters"], frozenset({ContractRefKind.ADAPTER}), "adapters"),
            instrumentation_providers=_parse_refs(doc["instrumentation_providers"], frozenset({ContractRefKind.INSTRUMENTATION_PROVIDER}), "instrumentation_providers"),
            oracle_specs=_parse_refs(doc["oracle_specs"], frozenset({ContractRefKind.ORACLE_SPEC}), "oracle_specs"),
            oracle_bundles=_parse_refs(doc["oracle_bundles"], frozenset({ContractRefKind.ORACLE_BUNDLE}), "oracle_bundles"),
            execution_recipes=_parse_refs(doc["execution_recipes"], frozenset({ContractRefKind.EXECUTION_RECIPE}), "execution_recipes"),
            components=_parse_refs(doc["components"], _PROFILE_COMPONENT_KINDS, "components"),
            capabilities=tuple(capabilities),
        )

    @classmethod
    def from_json(cls, payload: object) -> ProfileGraph:
        return cls.from_document(load_strict_json_object(payload))

    @classmethod
    def from_frozen_profile(cls, profile: FrozenSystemProfile) -> ProfileGraph:
        if type(profile) is not FrozenSystemProfile:
            raise ContractError("profile must be a FrozenSystemProfile")
        return cls(
            profile_id=profile.profile_id,
            profile_version=profile.profile_version,
            project=profile.project,
            environment=profile.environment,
            entrypoints=profile.entrypoints,
            workload_schemas=profile.workload_schemas,
            adapters=profile.adapters,
            instrumentation_providers=profile.instrumentation_providers,
            oracle_specs=profile.oracle_specs,
            oracle_bundles=profile.oracle_bundles,
            execution_recipes=profile.execution_recipes,
            components=profile.components,
            capabilities=profile.capabilities,
        )

    @property
    def content_sha256(self) -> str:
        return canonical_sha256(self.to_document())


@dataclass(frozen=True)
class QualificationPolicy:
    policy_id: str
    policy_version: str
    mode: QualificationMode
    trial_unit_id: str
    bound_method: StatisticalBoundMethod
    confidence_level: CanonicalDecimal
    max_false_violation_rate: CanonicalDecimal
    min_detection_rate: CanonicalDecimal
    min_non_violating_groups: int
    min_negative_groups: int
    min_calibrated_cells: int
    min_fault_cells: int
    max_retries_per_trial: int
    retryable_reasons: tuple[str, ...]
    qualification_ttl_seconds: int
    require_ood_inconclusive: bool

    def __post_init__(self) -> None:
        validate_identifier(self.policy_id, "policy_id")
        validate_identifier(self.policy_version, "policy_version")
        if type(self.mode) is not QualificationMode:
            raise ContractError("mode must be a QualificationMode")
        validate_identifier(self.trial_unit_id, "trial_unit_id")
        if type(self.bound_method) is not StatisticalBoundMethod:
            raise ContractError("bound_method must be a StatisticalBoundMethod")
        _decimal_between(self.confidence_level, "confidence_level", lower_inclusive=False, upper_inclusive=True)
        _decimal_between(self.max_false_violation_rate, "max_false_violation_rate", lower_inclusive=True, upper_inclusive=True)
        _decimal_between(self.min_detection_rate, "min_detection_rate", lower_inclusive=True, upper_inclusive=True)
        validate_positive_int(self.min_non_violating_groups, "min_non_violating_groups", maximum=_MAX_TRIALS)
        validate_positive_int(self.min_negative_groups, "min_negative_groups", maximum=_MAX_TRIALS)
        validate_non_negative_int(self.min_calibrated_cells, "min_calibrated_cells", maximum=_MAX_TRIALS)
        validate_non_negative_int(self.min_fault_cells, "min_fault_cells", maximum=_MAX_TRIALS)
        validate_non_negative_int(self.max_retries_per_trial, "max_retries_per_trial", maximum=100)
        object.__setattr__(self, "retryable_reasons", _identifier_tuple(self.retryable_reasons, "retryable_reasons", allow_empty=True))
        validate_positive_int(self.qualification_ttl_seconds, "qualification_ttl_seconds", maximum=_MAX_TTL_SECONDS)
        if type(self.require_ood_inconclusive) is not bool:
            raise ContractError("require_ood_inconclusive must be a boolean")
        if self.mode is QualificationMode.DETERMINISTIC:
            if self.bound_method is not StatisticalBoundMethod.NOT_APPLICABLE:
                raise ContractError("deterministic policy requires not_applicable bound method")
            if (self.confidence_level.value, self.max_false_violation_rate.value, self.min_detection_rate.value) != ("1", "0", "1"):
                raise ContractError("deterministic policy requires confidence=1, max false violation=0, min detection=1")
        elif self.bound_method is StatisticalBoundMethod.NOT_APPLICABLE:
            raise ContractError("statistical policy requires a statistical bound method")
        elif self.confidence_level.value == "1":
            raise ContractError("statistical confidence_level must be less than 1")
        if self.require_ood_inconclusive is not True:
            raise ContractError("qualification policy must fail closed on out-of-domain trials")

    def to_document(self) -> dict[str, object]:
        return {
            "contract_kind": _QUALIFICATION_POLICY_KIND, "schema_version": _SCHEMA_VERSION,
            "policy_id": self.policy_id, "policy_version": self.policy_version,
            "mode": self.mode.value, "trial_unit_id": self.trial_unit_id,
            "bound_method": self.bound_method.value,
            "confidence_level": self.confidence_level.to_document(),
            "max_false_violation_rate": self.max_false_violation_rate.to_document(),
            "min_detection_rate": self.min_detection_rate.to_document(),
            "min_non_violating_groups": self.min_non_violating_groups,
            "min_negative_groups": self.min_negative_groups,
            "min_calibrated_cells": self.min_calibrated_cells,
            "min_fault_cells": self.min_fault_cells,
            "max_retries_per_trial": self.max_retries_per_trial,
            "retryable_reasons": list(self.retryable_reasons),
            "qualification_ttl_seconds": self.qualification_ttl_seconds,
            "require_ood_inconclusive": self.require_ood_inconclusive,
        }

    @classmethod
    def from_document(cls, value: object) -> QualificationPolicy:
        fields = (
            "contract_kind", "schema_version", "policy_id", "policy_version", "mode",
            "trial_unit_id", "bound_method", "confidence_level",
            "max_false_violation_rate", "min_detection_rate",
            "min_non_violating_groups", "min_negative_groups", "min_calibrated_cells",
            "min_fault_cells", "max_retries_per_trial", "retryable_reasons",
            "qualification_ttl_seconds", "require_ood_inconclusive",
        )
        doc = require_exact_keys(value, required=fields, where="qualification policy")
        _check_header(doc, _QUALIFICATION_POLICY_KIND, "qualification policy")
        retries = _require_list(doc["retryable_reasons"], "retryable_reasons")
        return cls(
            policy_id=doc["policy_id"], policy_version=doc["policy_version"],
            mode=_enum(QualificationMode, doc["mode"], "mode"),
            trial_unit_id=doc["trial_unit_id"],
            bound_method=_enum(StatisticalBoundMethod, doc["bound_method"], "bound_method"),
            confidence_level=CanonicalDecimal.parse(doc["confidence_level"], "confidence_level"),
            max_false_violation_rate=CanonicalDecimal.parse(doc["max_false_violation_rate"], "max_false_violation_rate"),
            min_detection_rate=CanonicalDecimal.parse(doc["min_detection_rate"], "min_detection_rate"),
            min_non_violating_groups=doc["min_non_violating_groups"],
            min_negative_groups=doc["min_negative_groups"],
            min_calibrated_cells=doc["min_calibrated_cells"], min_fault_cells=doc["min_fault_cells"],
            max_retries_per_trial=doc["max_retries_per_trial"], retryable_reasons=tuple(retries),
            qualification_ttl_seconds=doc["qualification_ttl_seconds"], require_ood_inconclusive=doc["require_ood_inconclusive"],
        )

    @classmethod
    def from_json(cls, payload: object) -> QualificationPolicy:
        return cls.from_document(load_strict_json_object(payload))

    @property
    def content_sha256(self) -> str:
        return canonical_sha256(self.to_document())

    @property
    def ref(self) -> ContractRef:
        return ContractRef(ContractRefKind.QUALIFICATION_POLICY, self.policy_id, self.policy_version, self.content_sha256)


@dataclass(frozen=True)
class ProfileSetupCandidate:
    """Untrusted Setup proposal.

    ``trust_tier`` is only the requested tier.  It has no effect until an
    independently produced :class:`ProfileAdmissionRecord` is verified by the
    Profile Gate; candidate content can never act as admission authority.
    """
    setup_id: str
    candidate_version: str
    trust_tier: RegistrationTrustTier
    profile_graph: ProfileGraph
    qualification_policy: ContractRef
    adapter_code: ArtifactRef
    dependency_lock: ArtifactRef
    sbom: ArtifactRef
    permission_manifest: ArtifactRef
    declared_permissions: tuple[str, ...]
    created_at: str

    def __post_init__(self) -> None:
        validate_identifier(self.setup_id, "setup_id")
        validate_identifier(self.candidate_version, "candidate_version")
        if type(self.trust_tier) is not RegistrationTrustTier:
            raise ContractError("trust_tier must be a RegistrationTrustTier")
        if type(self.profile_graph) is not ProfileGraph:
            raise ContractError("profile_graph must be a ProfileGraph")
        _require_ref(self.qualification_policy, frozenset({ContractRefKind.QUALIFICATION_POLICY}), "qualification_policy")
        _artifact(self.adapter_code, "adapter_code", "adapter_code")
        _artifact(self.dependency_lock, "dependency_lock", "dependency_lock")
        _artifact(self.sbom, "sbom", "sbom")
        _artifact(self.permission_manifest, "permission_manifest", "permission_manifest")
        object.__setattr__(self, "declared_permissions", _identifier_tuple(self.declared_permissions, "declared_permissions", allow_empty=True))
        _timestamp(self.created_at, "created_at")
        if self.qualification_policy not in set(self.profile_graph.components):
            raise ContractError("qualification_policy must be a profile component")
        if not set(self.profile_graph.adapters):
            raise ContractError("profile graph must contain an adapter")

    def to_document(self) -> dict[str, object]:
        return {
            "contract_kind": _SETUP_CANDIDATE_KIND, "schema_version": _SCHEMA_VERSION,
            "setup_id": self.setup_id, "candidate_version": self.candidate_version,
            "trust_tier": self.trust_tier.value, "profile_graph": self.profile_graph.to_document(),
            "qualification_policy": self.qualification_policy.to_document(),
            "adapter_code": self.adapter_code.to_document(), "dependency_lock": self.dependency_lock.to_document(),
            "sbom": self.sbom.to_document(), "permission_manifest": self.permission_manifest.to_document(),
            "declared_permissions": list(self.declared_permissions), "created_at": self.created_at,
        }

    @classmethod
    def from_document(cls, value: object) -> ProfileSetupCandidate:
        fields = (
            "contract_kind", "schema_version", "setup_id", "candidate_version", "trust_tier",
            "profile_graph", "qualification_policy", "adapter_code", "dependency_lock",
            "sbom", "permission_manifest", "declared_permissions", "created_at",
        )
        doc = require_exact_keys(value, required=fields, where="profile setup candidate")
        _check_header(doc, _SETUP_CANDIDATE_KIND, "profile setup candidate")
        permissions = _require_list(doc["declared_permissions"], "declared_permissions")
        return cls(
            setup_id=doc["setup_id"], candidate_version=doc["candidate_version"],
            trust_tier=_enum(RegistrationTrustTier, doc["trust_tier"], "trust_tier"),
            profile_graph=ProfileGraph.from_document(doc["profile_graph"]),
            qualification_policy=_parse_ref(doc["qualification_policy"], frozenset({ContractRefKind.QUALIFICATION_POLICY}), "qualification_policy"),
            adapter_code=_parse_artifact(doc["adapter_code"], "adapter_code", "adapter_code"),
            dependency_lock=_parse_artifact(doc["dependency_lock"], "dependency_lock", "dependency_lock"),
            sbom=_parse_artifact(doc["sbom"], "sbom", "sbom"),
            permission_manifest=_parse_artifact(doc["permission_manifest"], "permission_manifest", "permission_manifest"),
            declared_permissions=tuple(permissions), created_at=doc["created_at"],
        )

    @classmethod
    def from_json(cls, payload: object) -> ProfileSetupCandidate:
        return cls.from_document(load_strict_json_object(payload))

    @property
    def profile_graph_sha256(self) -> str:
        return self.profile_graph.content_sha256

    @property
    def requested_trust_tier(self) -> RegistrationTrustTier:
        return self.trust_tier

    @property
    def content_sha256(self) -> str:
        return canonical_sha256(self.to_document())


@dataclass(frozen=True)
class QualificationUnit:
    """One salted fixture lineage frozen before qualification runs."""

    member_commitment: str
    group_commitment: str
    cluster_commitment: str

    def __post_init__(self) -> None:
        for field in (
            "member_commitment",
            "group_commitment",
            "cluster_commitment",
        ):
            validate_sha256(getattr(self, field), field)

    def to_document(self) -> dict[str, object]:
        return {
            "member_commitment": self.member_commitment,
            "group_commitment": self.group_commitment,
            "cluster_commitment": self.cluster_commitment,
        }

    @classmethod
    def from_document(cls, value: object) -> QualificationUnit:
        doc = require_exact_keys(
            value,
            required=(
                "member_commitment",
                "group_commitment",
                "cluster_commitment",
            ),
            where="qualification unit",
        )
        return cls(
            member_commitment=doc["member_commitment"],
            group_commitment=doc["group_commitment"],
            cluster_commitment=doc["cluster_commitment"],
        )


@dataclass(frozen=True)
class QualificationPartition:
    kind: QualificationPartitionKind
    fixture_manifest: ArtifactRef
    visibility: FixtureVisibility
    units: tuple[QualificationUnit, ...]

    def __post_init__(self) -> None:
        if type(self.kind) is not QualificationPartitionKind:
            raise ContractError("kind must be a QualificationPartitionKind")
        _artifact(self.fixture_manifest, f"qualification_{self.kind.value}_fixtures", "fixture_manifest")
        if type(self.visibility) is not FixtureVisibility:
            raise ContractError("visibility must be a FixtureVisibility")
        if self.kind is QualificationPartitionKind.HOLDOUT and self.visibility is not FixtureVisibility.HARNESS_ONLY:
            raise ContractError("holdout fixtures must be harness_only")
        if type(self.units) not in (tuple, list):
            raise ContractError("units must be a collection")
        units = tuple(self.units)
        if (
            not units
            or len(units) > _MAX_COMMITMENTS
            or any(type(item) is not QualificationUnit for item in units)
        ):
            raise ContractError(
                "units must contain bounded QualificationUnit values"
            )
        members = tuple(item.member_commitment for item in units)
        if len(members) != len(set(members)):
            raise ContractError("partition members must not repeat")
        object.__setattr__(
            self,
            "units",
            tuple(
                sorted(
                    units,
                    key=lambda item: (
                        item.member_commitment,
                        item.group_commitment,
                        item.cluster_commitment,
                    ),
                )
            ),
        )

    @property
    def member_commitments(self) -> tuple[str, ...]:
        return tuple(item.member_commitment for item in self.units)

    @property
    def group_commitments(self) -> tuple[str, ...]:
        return tuple(sorted({item.group_commitment for item in self.units}))

    @property
    def cluster_commitments(self) -> tuple[str, ...]:
        return tuple(sorted({item.cluster_commitment for item in self.units}))

    def to_document(self) -> dict[str, object]:
        return {
            "kind": self.kind.value, "fixture_manifest": self.fixture_manifest.to_document(),
            "visibility": self.visibility.value,
            "units": [item.to_document() for item in self.units],
        }

    @classmethod
    def from_document(cls, value: object) -> QualificationPartition:
        doc = require_exact_keys(value, required=("kind", "fixture_manifest", "visibility", "units"), where="qualification partition")
        kind = _enum(QualificationPartitionKind, doc["kind"], "partition kind")
        return cls(
            kind=kind,
            fixture_manifest=_parse_artifact(doc["fixture_manifest"], f"qualification_{kind.value}_fixtures", "fixture_manifest"),
            visibility=_enum(FixtureVisibility, doc["visibility"], "visibility"),
            units=tuple(
                QualificationUnit.from_document(item)
                for item in _require_list(doc["units"], "units", _MAX_COMMITMENTS)
            ),
        )


@dataclass(frozen=True)
class QualificationPlan:
    plan_id: str
    plan_version: str
    setup_subject_sha256: str
    qualification_policy: ContractRef
    partitions: tuple[QualificationPartition, ...]

    def __post_init__(self) -> None:
        validate_identifier(self.plan_id, "plan_id")
        validate_identifier(self.plan_version, "plan_version")
        validate_sha256(self.setup_subject_sha256, "setup_subject_sha256")
        _require_ref(self.qualification_policy, frozenset({ContractRefKind.QUALIFICATION_POLICY}), "qualification_policy")
        if type(self.partitions) not in (tuple, list):
            raise ContractError("partitions must be a collection")
        partitions = tuple(self.partitions)
        if len(partitions) != len(QualificationPartitionKind) or any(type(item) is not QualificationPartition for item in partitions):
            raise ContractError("partitions must contain exactly one partition of every kind")
        kinds = tuple(item.kind for item in partitions)
        if set(kinds) != set(QualificationPartitionKind) or len(kinds) != len(set(kinds)):
            raise ContractError("partitions must contain exactly one partition of every kind")
        for commitment_field in ("member_commitments", "group_commitments", "cluster_commitments"):
            seen: set[str] = set()
            for partition in partitions:
                current = set(getattr(partition, commitment_field))
                if seen.intersection(current):
                    raise ContractError(f"qualification partitions overlap in {commitment_field}")
                seen.update(current)
        object.__setattr__(self, "partitions", tuple(sorted(partitions, key=lambda item: item.kind.value)))

    def to_document(self) -> dict[str, object]:
        return {
            "contract_kind": _QUALIFICATION_PLAN_KIND, "schema_version": _SCHEMA_VERSION,
            "plan_id": self.plan_id, "plan_version": self.plan_version,
            "setup_subject_sha256": self.setup_subject_sha256,
            "qualification_policy": self.qualification_policy.to_document(),
            "partitions": [item.to_document() for item in self.partitions],
        }

    @classmethod
    def from_document(cls, value: object) -> QualificationPlan:
        doc = require_exact_keys(value, required=("contract_kind", "schema_version", "plan_id", "plan_version", "setup_subject_sha256", "qualification_policy", "partitions"), where="qualification plan")
        _check_header(doc, _QUALIFICATION_PLAN_KIND, "qualification plan")
        return cls(
            plan_id=doc["plan_id"], plan_version=doc["plan_version"], setup_subject_sha256=doc["setup_subject_sha256"],
            qualification_policy=_parse_ref(doc["qualification_policy"], frozenset({ContractRefKind.QUALIFICATION_POLICY}), "qualification_policy"),
            partitions=tuple(QualificationPartition.from_document(item) for item in _require_list(doc["partitions"], "partitions", 4)),
        )

    @classmethod
    def from_json(cls, payload: object) -> QualificationPlan:
        return cls.from_document(load_strict_json_object(payload))

    @property
    def content_sha256(self) -> str:
        return canonical_sha256(self.to_document())


@dataclass(frozen=True)
class QualificationTrial:
    trial_id: str
    partition_kind: QualificationPartitionKind
    member_commitment: str
    group_commitment: str
    cluster_commitment: str
    workload_cell_sha256: str
    oracle_decision: ContractRef
    expected_verdict: OracleVerdict
    observed_verdict: OracleVerdict
    stable: bool
    real_integration: bool
    attempt_index: int = 1
    retry_reason: str | None = None

    def __post_init__(self) -> None:
        validate_identifier(self.trial_id, "trial_id")
        if type(self.partition_kind) is not QualificationPartitionKind:
            raise ContractError("partition_kind must be a QualificationPartitionKind")
        for field in ("member_commitment", "group_commitment", "cluster_commitment", "workload_cell_sha256"):
            validate_sha256(getattr(self, field), field)
        _require_ref(self.oracle_decision, frozenset({ContractRefKind.ORACLE_DECISION}), "oracle_decision")
        if type(self.expected_verdict) is not OracleVerdict or type(self.observed_verdict) is not OracleVerdict:
            raise ContractError("expected_verdict and observed_verdict must be OracleVerdict values")
        if type(self.stable) is not bool or type(self.real_integration) is not bool:
            raise ContractError("stable and real_integration must be booleans")
        validate_positive_int(
            self.attempt_index,
            "attempt_index",
            maximum=101,
        )
        if self.attempt_index == 1:
            if self.retry_reason is not None:
                raise ContractError("the first qualification attempt cannot have a retry_reason")
        else:
            validate_identifier(self.retry_reason, "retry_reason")
        expected_by_partition = {
            QualificationPartitionKind.CALIBRATION: OracleVerdict.PASS,
            QualificationPartitionKind.HOLDOUT: OracleVerdict.PASS,
            QualificationPartitionKind.NEGATIVE: OracleVerdict.VIOLATION,
            QualificationPartitionKind.OUT_OF_DOMAIN: OracleVerdict.INCONCLUSIVE,
        }
        if self.expected_verdict is not expected_by_partition[self.partition_kind]:
            raise ContractError("expected_verdict does not match partition semantics")

    def to_document(self) -> dict[str, object]:
        return {
            "trial_id": self.trial_id, "partition_kind": self.partition_kind.value,
            "member_commitment": self.member_commitment, "group_commitment": self.group_commitment,
            "cluster_commitment": self.cluster_commitment, "workload_cell_sha256": self.workload_cell_sha256,
            "oracle_decision": self.oracle_decision.to_document(), "expected_verdict": self.expected_verdict.value,
            "observed_verdict": self.observed_verdict.value, "stable": self.stable,
            "real_integration": self.real_integration,
            "attempt_index": self.attempt_index,
            "retry_reason": self.retry_reason,
        }

    @classmethod
    def from_document(cls, value: object) -> QualificationTrial:
        fields = ("trial_id", "partition_kind", "member_commitment", "group_commitment", "cluster_commitment", "workload_cell_sha256", "oracle_decision", "expected_verdict", "observed_verdict", "stable", "real_integration", "attempt_index", "retry_reason")
        doc = require_exact_keys(value, required=fields, where="qualification trial")
        return cls(
            trial_id=doc["trial_id"], partition_kind=_enum(QualificationPartitionKind, doc["partition_kind"], "partition_kind"),
            member_commitment=doc["member_commitment"], group_commitment=doc["group_commitment"], cluster_commitment=doc["cluster_commitment"], workload_cell_sha256=doc["workload_cell_sha256"],
            oracle_decision=_parse_ref(doc["oracle_decision"], frozenset({ContractRefKind.ORACLE_DECISION}), "oracle_decision"),
            expected_verdict=_enum(OracleVerdict, doc["expected_verdict"], "expected_verdict"), observed_verdict=_enum(OracleVerdict, doc["observed_verdict"], "observed_verdict"),
            stable=doc["stable"], real_integration=doc["real_integration"],
            attempt_index=doc["attempt_index"], retry_reason=doc["retry_reason"],
        )


@dataclass(frozen=True)
class CalibrationReport:
    report_id: str
    setup_subject_sha256: str
    qualification_policy_sha256: str
    qualification_plan_sha256: str
    calibration_partition_sha256: str
    calibrated_parameters: ArtifactRef
    calibrated_domain: ArtifactRef
    warmup_repetitions: int
    decision_repetitions: int
    unstable_group_count: int
    verdict: QualificationVerdict
    reason_codes: tuple[str, ...]
    completed_at: str
    expires_at: str

    def __post_init__(self) -> None:
        validate_identifier(self.report_id, "report_id")
        for field in ("setup_subject_sha256", "qualification_policy_sha256", "qualification_plan_sha256", "calibration_partition_sha256"):
            validate_sha256(getattr(self, field), field)
        _artifact(self.calibrated_parameters, "calibrated_parameters", "calibrated_parameters")
        _artifact(self.calibrated_domain, "calibrated_domain", "calibrated_domain")
        validate_non_negative_int(self.warmup_repetitions, "warmup_repetitions", maximum=1_000_000)
        validate_positive_int(self.decision_repetitions, "decision_repetitions", maximum=1_000_000)
        validate_non_negative_int(self.unstable_group_count, "unstable_group_count", maximum=_MAX_TRIALS)
        if type(self.verdict) is not QualificationVerdict:
            raise ContractError("verdict must be a QualificationVerdict")
        object.__setattr__(self, "reason_codes", _identifier_tuple(self.reason_codes, "reason_codes", allow_empty=True))
        completed = _timestamp(self.completed_at, "completed_at")
        expires = _timestamp(self.expires_at, "expires_at")
        if expires <= completed:
            raise ContractError("expires_at must be later than completed_at")
        if self.verdict is QualificationVerdict.PASS and (self.unstable_group_count or self.reason_codes):
            raise ContractError("passing calibration cannot report instability or failure reasons")
        if self.verdict is QualificationVerdict.FAIL and not self.reason_codes:
            raise ContractError("failed calibration requires reason_codes")

    def to_document(self) -> dict[str, object]:
        return {
            "contract_kind": _CALIBRATION_REPORT_KIND, "schema_version": _SCHEMA_VERSION,
            "report_id": self.report_id, "setup_subject_sha256": self.setup_subject_sha256,
            "qualification_policy_sha256": self.qualification_policy_sha256,
            "qualification_plan_sha256": self.qualification_plan_sha256,
            "calibration_partition_sha256": self.calibration_partition_sha256,
            "calibrated_parameters": self.calibrated_parameters.to_document(), "calibrated_domain": self.calibrated_domain.to_document(),
            "warmup_repetitions": self.warmup_repetitions, "decision_repetitions": self.decision_repetitions,
            "unstable_group_count": self.unstable_group_count, "verdict": self.verdict.value,
            "reason_codes": list(self.reason_codes), "completed_at": self.completed_at, "expires_at": self.expires_at,
        }

    @classmethod
    def from_document(cls, value: object) -> CalibrationReport:
        fields = ("contract_kind", "schema_version", "report_id", "setup_subject_sha256", "qualification_policy_sha256", "qualification_plan_sha256", "calibration_partition_sha256", "calibrated_parameters", "calibrated_domain", "warmup_repetitions", "decision_repetitions", "unstable_group_count", "verdict", "reason_codes", "completed_at", "expires_at")
        doc = require_exact_keys(value, required=fields, where="calibration report")
        _check_header(doc, _CALIBRATION_REPORT_KIND, "calibration report")
        return cls(
            report_id=doc["report_id"], setup_subject_sha256=doc["setup_subject_sha256"], qualification_policy_sha256=doc["qualification_policy_sha256"], qualification_plan_sha256=doc["qualification_plan_sha256"], calibration_partition_sha256=doc["calibration_partition_sha256"],
            calibrated_parameters=_parse_artifact(doc["calibrated_parameters"], "calibrated_parameters", "calibrated_parameters"), calibrated_domain=_parse_artifact(doc["calibrated_domain"], "calibrated_domain", "calibrated_domain"),
            warmup_repetitions=doc["warmup_repetitions"], decision_repetitions=doc["decision_repetitions"], unstable_group_count=doc["unstable_group_count"],
            verdict=_enum(QualificationVerdict, doc["verdict"], "verdict"), reason_codes=tuple(_require_list(doc["reason_codes"], "reason_codes")), completed_at=doc["completed_at"], expires_at=doc["expires_at"],
        )

    @classmethod
    def from_json(cls, payload: object) -> CalibrationReport:
        return cls.from_document(load_strict_json_object(payload))

    @property
    def content_sha256(self) -> str:
        return canonical_sha256(self.to_document())


@dataclass(frozen=True)
class QualificationReport:
    report_id: str
    setup_subject_sha256: str
    qualification_policy_sha256: str
    qualification_plan_sha256: str
    calibration_report_sha256: str
    trials: tuple[QualificationTrial, ...]
    qualification_environment_sha256: str
    bound_method: StatisticalBoundMethod
    upper_false_violation_bound: CanonicalDecimal
    lower_detection_bound: CanonicalDecimal
    independent_non_violating_groups: int
    independent_negative_groups: int
    calibrated_cell_count: int
    fault_cell_count: int
    verdict: QualificationVerdict
    reason_codes: tuple[str, ...]
    completed_at: str
    expires_at: str

    def __post_init__(self) -> None:
        validate_identifier(self.report_id, "report_id")
        for field in ("setup_subject_sha256", "qualification_policy_sha256", "qualification_plan_sha256", "calibration_report_sha256", "qualification_environment_sha256"):
            validate_sha256(getattr(self, field), field)
        if type(self.trials) not in (tuple, list):
            raise ContractError("trials must be a collection")
        trials = tuple(self.trials)
        if not trials or len(trials) > _MAX_TRIALS or any(type(item) is not QualificationTrial for item in trials):
            raise ContractError("trials must contain between 1 and the configured maximum QualificationTrial values")
        ids = tuple(item.trial_id for item in trials)
        decisions = tuple(item.oracle_decision for item in trials)
        if (
            len(ids) != len(set(ids))
            or len(decisions) != len(set(decisions))
        ):
            raise ContractError(
                "trials must have unique ids and OracleDecision refs"
            )
        attempt_keys = tuple(
            (item.partition_kind, item.member_commitment, item.attempt_index)
            for item in trials
        )
        if len(attempt_keys) != len(set(attempt_keys)):
            raise ContractError(
                "trials must not repeat a member attempt_index"
            )
        final_by_member: dict[
            tuple[QualificationPartitionKind, str], QualificationTrial
        ] = {}
        for trial in trials:
            key = (trial.partition_kind, trial.member_commitment)
            previous = final_by_member.get(key)
            if previous is None or trial.attempt_index > previous.attempt_index:
                final_by_member[key] = trial
        final_trials = tuple(final_by_member.values())
        object.__setattr__(self, "trials", tuple(sorted(trials, key=lambda item: item.trial_id)))
        if type(self.bound_method) is not StatisticalBoundMethod:
            raise ContractError("bound_method must be a StatisticalBoundMethod")
        _decimal_between(self.upper_false_violation_bound, "upper_false_violation_bound", lower_inclusive=True, upper_inclusive=True)
        _decimal_between(self.lower_detection_bound, "lower_detection_bound", lower_inclusive=True, upper_inclusive=True)
        # A correlated family counts once.  Calibration is fitting input, not
        # the result-blind non-violating holdout used for the governance bound.
        nonviolating_groups = {item.cluster_commitment for item in final_trials if item.partition_kind is QualificationPartitionKind.HOLDOUT}
        negative_groups = {item.cluster_commitment for item in final_trials if item.partition_kind is QualificationPartitionKind.NEGATIVE}
        calibrated_cells = {item.workload_cell_sha256 for item in final_trials if item.real_integration and item.partition_kind in (QualificationPartitionKind.CALIBRATION, QualificationPartitionKind.HOLDOUT)}
        fault_cells = {item.workload_cell_sha256 for item in final_trials if item.real_integration and item.partition_kind is QualificationPartitionKind.NEGATIVE}
        declared_counts = (self.independent_non_violating_groups, self.independent_negative_groups, self.calibrated_cell_count, self.fault_cell_count)
        actual_counts = (len(nonviolating_groups), len(negative_groups), len(calibrated_cells), len(fault_cells))
        for field, value in zip(("independent_non_violating_groups", "independent_negative_groups", "calibrated_cell_count", "fault_cell_count"), declared_counts):
            validate_non_negative_int(value, field, maximum=_MAX_TRIALS)
        if declared_counts != actual_counts:
            raise ContractError("declared qualification aggregate counts do not match trials")
        if type(self.verdict) is not QualificationVerdict:
            raise ContractError("verdict must be a QualificationVerdict")
        object.__setattr__(self, "reason_codes", _identifier_tuple(self.reason_codes, "reason_codes", allow_empty=True))
        completed = _timestamp(self.completed_at, "completed_at")
        expires = _timestamp(self.expires_at, "expires_at")
        if expires <= completed:
            raise ContractError("expires_at must be later than completed_at")
        if self.verdict is QualificationVerdict.PASS:
            if self.reason_codes or any(not item.stable for item in final_trials):
                raise ContractError("passing qualification cannot contain reasons or unstable trials")
            if (
                self.bound_method is StatisticalBoundMethod.NOT_APPLICABLE
                and any(item.observed_verdict is not item.expected_verdict for item in final_trials)
            ):
                raise ContractError("passing qualification requires every trial to match its frozen expectation")
        elif not self.reason_codes:
            raise ContractError("failed qualification requires reason_codes")

    def to_document(self) -> dict[str, object]:
        return {
            "contract_kind": _QUALIFICATION_REPORT_KIND, "schema_version": _SCHEMA_VERSION,
            "report_id": self.report_id, "setup_subject_sha256": self.setup_subject_sha256,
            "qualification_policy_sha256": self.qualification_policy_sha256, "qualification_plan_sha256": self.qualification_plan_sha256,
            "calibration_report_sha256": self.calibration_report_sha256, "trials": [item.to_document() for item in self.trials],
            "qualification_environment_sha256": self.qualification_environment_sha256, "bound_method": self.bound_method.value,
            "upper_false_violation_bound": self.upper_false_violation_bound.to_document(), "lower_detection_bound": self.lower_detection_bound.to_document(),
            "independent_non_violating_groups": self.independent_non_violating_groups, "independent_negative_groups": self.independent_negative_groups,
            "calibrated_cell_count": self.calibrated_cell_count, "fault_cell_count": self.fault_cell_count,
            "verdict": self.verdict.value, "reason_codes": list(self.reason_codes), "completed_at": self.completed_at, "expires_at": self.expires_at,
        }

    @classmethod
    def from_document(cls, value: object) -> QualificationReport:
        fields = ("contract_kind", "schema_version", "report_id", "setup_subject_sha256", "qualification_policy_sha256", "qualification_plan_sha256", "calibration_report_sha256", "trials", "qualification_environment_sha256", "bound_method", "upper_false_violation_bound", "lower_detection_bound", "independent_non_violating_groups", "independent_negative_groups", "calibrated_cell_count", "fault_cell_count", "verdict", "reason_codes", "completed_at", "expires_at")
        doc = require_exact_keys(value, required=fields, where="qualification report")
        _check_header(doc, _QUALIFICATION_REPORT_KIND, "qualification report")
        return cls(
            report_id=doc["report_id"], setup_subject_sha256=doc["setup_subject_sha256"], qualification_policy_sha256=doc["qualification_policy_sha256"], qualification_plan_sha256=doc["qualification_plan_sha256"], calibration_report_sha256=doc["calibration_report_sha256"],
            trials=tuple(QualificationTrial.from_document(item) for item in _require_list(doc["trials"], "trials", _MAX_TRIALS)), qualification_environment_sha256=doc["qualification_environment_sha256"],
            bound_method=_enum(StatisticalBoundMethod, doc["bound_method"], "bound_method"), upper_false_violation_bound=CanonicalDecimal.parse(doc["upper_false_violation_bound"], "upper_false_violation_bound"), lower_detection_bound=CanonicalDecimal.parse(doc["lower_detection_bound"], "lower_detection_bound"),
            independent_non_violating_groups=doc["independent_non_violating_groups"], independent_negative_groups=doc["independent_negative_groups"], calibrated_cell_count=doc["calibrated_cell_count"], fault_cell_count=doc["fault_cell_count"],
            verdict=_enum(QualificationVerdict, doc["verdict"], "verdict"), reason_codes=tuple(_require_list(doc["reason_codes"], "reason_codes")), completed_at=doc["completed_at"], expires_at=doc["expires_at"],
        )

    @classmethod
    def from_json(cls, payload: object) -> QualificationReport:
        return cls.from_document(load_strict_json_object(payload))

    @property
    def content_sha256(self) -> str:
        return canonical_sha256(self.to_document())


@dataclass(frozen=True)
class ReviewSubject:
    oracle_specs: tuple[ContractRef, ...]
    adapters: tuple[ContractRef, ...]
    adapter_code_sha256: str
    dependency_lock_sha256: str
    qualification_policy_sha256: str

    def __post_init__(self) -> None:
        for field in ("adapter_code_sha256", "dependency_lock_sha256", "qualification_policy_sha256"):
            validate_sha256(getattr(self, field), field)
        object.__setattr__(self, "oracle_specs", _refs(self.oracle_specs, frozenset({ContractRefKind.ORACLE_SPEC}), "oracle_specs"))
        object.__setattr__(self, "adapters", _refs(self.adapters, frozenset({ContractRefKind.ADAPTER}), "adapters"))

    def to_document(self) -> dict[str, object]:
        return {
            "oracle_specs": [item.to_document() for item in self.oracle_specs], "adapters": [item.to_document() for item in self.adapters],
            "adapter_code_sha256": self.adapter_code_sha256, "dependency_lock_sha256": self.dependency_lock_sha256,
            "qualification_policy_sha256": self.qualification_policy_sha256,
        }

    @classmethod
    def from_document(cls, value: object) -> ReviewSubject:
        doc = require_exact_keys(value, required=("oracle_specs", "adapters", "adapter_code_sha256", "dependency_lock_sha256", "qualification_policy_sha256"), where="review subject")
        return cls(
            oracle_specs=_parse_refs(doc["oracle_specs"], frozenset({ContractRefKind.ORACLE_SPEC}), "oracle_specs"), adapters=_parse_refs(doc["adapters"], frozenset({ContractRefKind.ADAPTER}), "adapters"),
            adapter_code_sha256=doc["adapter_code_sha256"], dependency_lock_sha256=doc["dependency_lock_sha256"], qualification_policy_sha256=doc["qualification_policy_sha256"],
        )

    @property
    def content_sha256(self) -> str:
        return canonical_sha256(self.to_document())


@dataclass(frozen=True)
class ResultBlindReviewBundle:
    bundle_id: str
    subject: ReviewSubject
    candidate_sha256: str
    profile_graph_sha256: str
    adapter_code: ArtifactRef
    adapter_diff: ArtifactRef
    dependency_lock: ArtifactRef
    sbom: ArtifactRef
    static_scan: ArtifactRef
    healthy_relation: ArtifactRef
    qualification_report_sha256: str
    qualification_design_sha256: str
    permission_manifest: ArtifactRef
    invalidation_manifest_sha256: str
    known_limitations: tuple[str, ...]

    def __post_init__(self) -> None:
        validate_identifier(self.bundle_id, "bundle_id")
        if type(self.subject) is not ReviewSubject:
            raise ContractError("subject must be a ReviewSubject")
        validate_sha256(self.candidate_sha256, "candidate_sha256")
        validate_sha256(self.profile_graph_sha256, "profile_graph_sha256")
        for field, role in (("adapter_code", "adapter_code"), ("adapter_diff", "adapter_diff"), ("dependency_lock", "dependency_lock"), ("sbom", "sbom"), ("static_scan", "static_scan"), ("healthy_relation", "healthy_relation"), ("permission_manifest", "permission_manifest")):
            _artifact(getattr(self, field), role, field)
        validate_sha256(self.qualification_report_sha256, "qualification_report_sha256")
        validate_sha256(self.qualification_design_sha256, "qualification_design_sha256")
        validate_sha256(self.invalidation_manifest_sha256, "invalidation_manifest_sha256")
        object.__setattr__(self, "known_limitations", _identifier_tuple(self.known_limitations, "known_limitations", allow_empty=True))
        if self.subject.adapter_code_sha256 != self.adapter_code.content_sha256 or self.subject.dependency_lock_sha256 != self.dependency_lock.content_sha256:
            raise ContractError("review subject must bind bundle adapter code and dependency lock")

    def to_document(self) -> dict[str, object]:
        return {
            "contract_kind": _REVIEW_BUNDLE_KIND, "schema_version": _SCHEMA_VERSION,
            "bundle_id": self.bundle_id, "subject": self.subject.to_document(),
            "candidate_sha256": self.candidate_sha256,
            "profile_graph_sha256": self.profile_graph_sha256,
            "adapter_code": self.adapter_code.to_document(), "adapter_diff": self.adapter_diff.to_document(),
            "dependency_lock": self.dependency_lock.to_document(), "sbom": self.sbom.to_document(),
            "static_scan": self.static_scan.to_document(), "healthy_relation": self.healthy_relation.to_document(),
            "qualification_report_sha256": self.qualification_report_sha256, "qualification_design_sha256": self.qualification_design_sha256,
            "permission_manifest": self.permission_manifest.to_document(), "invalidation_manifest_sha256": self.invalidation_manifest_sha256,
            "known_limitations": list(self.known_limitations),
        }

    @classmethod
    def from_document(cls, value: object) -> ResultBlindReviewBundle:
        fields = ("contract_kind", "schema_version", "bundle_id", "subject", "candidate_sha256", "profile_graph_sha256", "adapter_code", "adapter_diff", "dependency_lock", "sbom", "static_scan", "healthy_relation", "qualification_report_sha256", "qualification_design_sha256", "permission_manifest", "invalidation_manifest_sha256", "known_limitations")
        doc = require_exact_keys(value, required=fields, where="result-blind review bundle")
        _check_header(doc, _REVIEW_BUNDLE_KIND, "review bundle")
        return cls(
            bundle_id=doc["bundle_id"], subject=ReviewSubject.from_document(doc["subject"]),
            candidate_sha256=doc["candidate_sha256"], profile_graph_sha256=doc["profile_graph_sha256"],
            adapter_code=_parse_artifact(doc["adapter_code"], "adapter_code", "adapter_code"), adapter_diff=_parse_artifact(doc["adapter_diff"], "adapter_diff", "adapter_diff"), dependency_lock=_parse_artifact(doc["dependency_lock"], "dependency_lock", "dependency_lock"), sbom=_parse_artifact(doc["sbom"], "sbom", "sbom"), static_scan=_parse_artifact(doc["static_scan"], "static_scan", "static_scan"), healthy_relation=_parse_artifact(doc["healthy_relation"], "healthy_relation", "healthy_relation"),
            qualification_report_sha256=doc["qualification_report_sha256"], qualification_design_sha256=doc["qualification_design_sha256"], permission_manifest=_parse_artifact(doc["permission_manifest"], "permission_manifest", "permission_manifest"), invalidation_manifest_sha256=doc["invalidation_manifest_sha256"], known_limitations=tuple(_require_list(doc["known_limitations"], "known_limitations")),
        )

    @classmethod
    def from_json(cls, payload: object) -> ResultBlindReviewBundle:
        return cls.from_document(load_strict_json_object(payload))

    @property
    def content_sha256(self) -> str:
        return canonical_sha256(self.to_document())


@dataclass(frozen=True)
class ReviewRecord:
    review_id: str
    subject_sha256: str
    input_bundle_sha256: str
    verdict: ReviewVerdict
    blocking_findings: tuple[str, ...]
    non_blocking_findings: tuple[str, ...]
    reviewer_authority: str
    reviewer_session_id: str
    model_id: str
    prompt_sha256: str
    reviewed_at: str

    def __post_init__(self) -> None:
        validate_identifier(self.review_id, "review_id")
        validate_sha256(self.subject_sha256, "subject_sha256")
        validate_sha256(self.input_bundle_sha256, "input_bundle_sha256")
        if type(self.verdict) is not ReviewVerdict:
            raise ContractError("verdict must be a ReviewVerdict")
        object.__setattr__(self, "blocking_findings", _identifier_tuple(self.blocking_findings, "blocking_findings", allow_empty=True, maximum=256))
        object.__setattr__(self, "non_blocking_findings", _identifier_tuple(self.non_blocking_findings, "non_blocking_findings", allow_empty=True, maximum=256))
        if set(self.blocking_findings).intersection(self.non_blocking_findings):
            raise ContractError("blocking and non-blocking findings must be disjoint")
        if self.verdict is ReviewVerdict.APPROVE and self.blocking_findings:
            raise ContractError("approved review cannot have blocking findings")
        if self.verdict in (ReviewVerdict.REVISE, ReviewVerdict.REJECT) and not self.blocking_findings:
            raise ContractError("revise/reject review requires blocking findings")
        for field in ("reviewer_authority", "reviewer_session_id", "model_id"):
            validate_identifier(getattr(self, field), field)
        validate_sha256(self.prompt_sha256, "prompt_sha256")
        _timestamp(self.reviewed_at, "reviewed_at")

    def to_document(self) -> dict[str, object]:
        return {
            "contract_kind": _REVIEW_RECORD_KIND, "schema_version": _SCHEMA_VERSION,
            "review_id": self.review_id, "subject_sha256": self.subject_sha256,
            "input_bundle_sha256": self.input_bundle_sha256, "verdict": self.verdict.value,
            "blocking_findings": list(self.blocking_findings), "non_blocking_findings": list(self.non_blocking_findings),
            "reviewer_authority": self.reviewer_authority, "reviewer_session_id": self.reviewer_session_id,
            "model_id": self.model_id, "prompt_sha256": self.prompt_sha256, "reviewed_at": self.reviewed_at,
        }

    @classmethod
    def from_document(cls, value: object) -> ReviewRecord:
        fields = ("contract_kind", "schema_version", "review_id", "subject_sha256", "input_bundle_sha256", "verdict", "blocking_findings", "non_blocking_findings", "reviewer_authority", "reviewer_session_id", "model_id", "prompt_sha256", "reviewed_at")
        doc = require_exact_keys(value, required=fields, where="review record")
        _check_header(doc, _REVIEW_RECORD_KIND, "review record")
        return cls(
            review_id=doc["review_id"], subject_sha256=doc["subject_sha256"], input_bundle_sha256=doc["input_bundle_sha256"], verdict=_enum(ReviewVerdict, doc["verdict"], "verdict"),
            blocking_findings=tuple(_require_list(doc["blocking_findings"], "blocking_findings", 256)), non_blocking_findings=tuple(_require_list(doc["non_blocking_findings"], "non_blocking_findings", 256)),
            reviewer_authority=doc["reviewer_authority"], reviewer_session_id=doc["reviewer_session_id"], model_id=doc["model_id"], prompt_sha256=doc["prompt_sha256"], reviewed_at=doc["reviewed_at"],
        )

    @classmethod
    def from_json(cls, payload: object) -> ReviewRecord:
        return cls.from_document(load_strict_json_object(payload))

    @property
    def content_sha256(self) -> str:
        return canonical_sha256(self.to_document())


@dataclass(frozen=True)
class SemanticApprovalRecord:
    approval_id: str
    trust_tier: RegistrationTrustTier
    subject_sha256: str
    basis_review_sha256: str
    basis_qualification_report_sha256: str
    authority_kind: ApprovalAuthorityKind
    authority_id: str
    decision: ApprovalDecision
    approved_at: str
    expires_at: str | None

    def __post_init__(self) -> None:
        validate_identifier(self.approval_id, "approval_id")
        if type(self.trust_tier) is not RegistrationTrustTier:
            raise ContractError("trust_tier must be a RegistrationTrustTier")
        validate_sha256(self.subject_sha256, "subject_sha256")
        validate_sha256(self.basis_review_sha256, "basis_review_sha256")
        validate_sha256(
            self.basis_qualification_report_sha256,
            "basis_qualification_report_sha256",
        )
        if type(self.authority_kind) is not ApprovalAuthorityKind:
            raise ContractError("authority_kind must be an ApprovalAuthorityKind")
        validate_identifier(self.authority_id, "authority_id")
        if type(self.decision) is not ApprovalDecision:
            raise ContractError("decision must be an ApprovalDecision")
        approved = _timestamp(self.approved_at, "approved_at")
        expires = _optional_timestamp(self.expires_at, "expires_at")
        if expires is not None and expires <= approved:
            raise ContractError("expires_at must be later than approved_at")
        if self.trust_tier is RegistrationTrustTier.PROFILE_CUSTOM:
            if self.authority_kind is not ApprovalAuthorityKind.HUMAN:
                raise ContractError("profile_custom requires human semantic approval")
        elif self.authority_kind not in (ApprovalAuthorityKind.HARNESS, ApprovalAuthorityKind.MAINTAINER):
            raise ContractError("trusted_preset admission requires harness or maintainer authority")

    def to_document(self) -> dict[str, object]:
        return {
            "contract_kind": _APPROVAL_RECORD_KIND, "schema_version": _SCHEMA_VERSION,
            "approval_id": self.approval_id, "trust_tier": self.trust_tier.value,
            "subject_sha256": self.subject_sha256,
            "basis_review_sha256": self.basis_review_sha256,
            "basis_qualification_report_sha256": self.basis_qualification_report_sha256,
            "authority_kind": self.authority_kind.value, "authority_id": self.authority_id,
            "decision": self.decision.value, "approved_at": self.approved_at, "expires_at": self.expires_at,
        }

    @classmethod
    def from_document(cls, value: object) -> SemanticApprovalRecord:
        fields = ("contract_kind", "schema_version", "approval_id", "trust_tier", "subject_sha256", "basis_review_sha256", "basis_qualification_report_sha256", "authority_kind", "authority_id", "decision", "approved_at", "expires_at")
        doc = require_exact_keys(value, required=fields, where="semantic approval record")
        _check_header(doc, _APPROVAL_RECORD_KIND, "approval record")
        return cls(
            approval_id=doc["approval_id"], trust_tier=_enum(RegistrationTrustTier, doc["trust_tier"], "trust_tier"), subject_sha256=doc["subject_sha256"],
            basis_review_sha256=doc["basis_review_sha256"], basis_qualification_report_sha256=doc["basis_qualification_report_sha256"],
            authority_kind=_enum(ApprovalAuthorityKind, doc["authority_kind"], "authority_kind"), authority_id=doc["authority_id"], decision=_enum(ApprovalDecision, doc["decision"], "decision"), approved_at=doc["approved_at"], expires_at=doc["expires_at"],
        )

    @classmethod
    def from_json(cls, payload: object) -> SemanticApprovalRecord:
        return cls.from_document(load_strict_json_object(payload))

    @property
    def content_sha256(self) -> str:
        return canonical_sha256(self.to_document())


def validate_frozen_profile_graph(candidate: ProfileSetupCandidate, profile: FrozenSystemProfile) -> None:
    """Reject a frozen profile whose trust-free graph differs from its candidate."""

    if type(candidate) is not ProfileSetupCandidate:
        raise ContractError("candidate must be a ProfileSetupCandidate")
    if type(profile) is not FrozenSystemProfile:
        raise ContractError("profile must be a FrozenSystemProfile")
    if ProfileGraph.from_frozen_profile(profile) != candidate.profile_graph:
        raise ContractError("frozen profile graph does not exactly match candidate")


def make_review_subject(candidate: ProfileSetupCandidate) -> ReviewSubject:
    if type(candidate) is not ProfileSetupCandidate:
        raise ContractError("candidate must be a ProfileSetupCandidate")
    return ReviewSubject(
        oracle_specs=candidate.profile_graph.oracle_specs,
        adapters=candidate.profile_graph.adapters,
        adapter_code_sha256=candidate.adapter_code.content_sha256,
        dependency_lock_sha256=candidate.dependency_lock.content_sha256,
        qualification_policy_sha256=candidate.qualification_policy.content_sha256,
    )


def validate_qualification_graph(
    candidate: ProfileSetupCandidate,
    policy: QualificationPolicy,
    plan: QualificationPlan,
    calibration: CalibrationReport,
    report: QualificationReport,
) -> None:
    """Mechanically bind the Setup candidate, plan, calibration, and report."""

    if any(
        type(value) is not expected
        for value, expected in (
            (candidate, ProfileSetupCandidate), (policy, QualificationPolicy),
            (plan, QualificationPlan), (calibration, CalibrationReport),
            (report, QualificationReport),
        )
    ):
        raise ContractError("qualification graph contains an unexpected object type")
    if candidate.qualification_policy != policy.ref:
        raise ContractError("candidate does not bind qualification policy")
    if plan.setup_subject_sha256 != candidate.content_sha256 or plan.qualification_policy != policy.ref:
        raise ContractError("qualification plan does not bind candidate and policy")
    calibration_partition = next(item for item in plan.partitions if item.kind is QualificationPartitionKind.CALIBRATION)
    expected_calibration_partition_sha = canonical_sha256(calibration_partition.to_document())
    expected = (candidate.content_sha256, policy.content_sha256, plan.content_sha256, expected_calibration_partition_sha)
    if (calibration.setup_subject_sha256, calibration.qualification_policy_sha256, calibration.qualification_plan_sha256, calibration.calibration_partition_sha256) != expected:
        raise ContractError("calibration report does not bind qualification graph")
    if (report.setup_subject_sha256, report.qualification_policy_sha256, report.qualification_plan_sha256, report.calibration_report_sha256) != (candidate.content_sha256, policy.content_sha256, plan.content_sha256, calibration.content_sha256):
        raise ContractError("qualification report does not bind qualification graph")
    partitions = {item.kind: item for item in plan.partitions}
    trials_by_partition = {
        kind: tuple(trial for trial in report.trials if trial.partition_kind is kind)
        for kind in QualificationPartitionKind
    }
    for kind, partition in partitions.items():
        expected_units = {
            (
                unit.member_commitment,
                unit.group_commitment,
                unit.cluster_commitment,
            )
            for unit in partition.units
        }
        actual_units = {
            (
                trial.member_commitment,
                trial.group_commitment,
                trial.cluster_commitment,
            )
            for trial in trials_by_partition[kind]
        }
        if actual_units != expected_units:
            raise ContractError(
                "qualification report must cover every frozen "
                f"{kind.value} unit and no others"
            )
    for trial in report.trials:
        partition = partitions[trial.partition_kind]
        if not any(
            (
                unit.member_commitment,
                unit.group_commitment,
                unit.cluster_commitment,
            )
            == (
                trial.member_commitment,
                trial.group_commitment,
                trial.cluster_commitment,
            )
            for unit in partition.units
        ):
            raise ContractError("qualification trial is outside its frozen partition")
    attempts: dict[
        tuple[QualificationPartitionKind, str], set[int]
    ] = {}
    bindings: dict[
        tuple[QualificationPartitionKind, str], tuple[str, str, str, bool]
    ] = {}
    for trial in report.trials:
        key = (trial.partition_kind, trial.member_commitment)
        member_attempts = attempts.setdefault(key, set())
        if trial.attempt_index in member_attempts:
            raise ContractError("qualification member repeats an attempt_index")
        member_attempts.add(trial.attempt_index)
        if len(member_attempts) > 1 + policy.max_retries_per_trial:
            raise ContractError("qualification member exceeds frozen retry allowance")
        if trial.attempt_index > 1 and trial.retry_reason not in set(
            policy.retryable_reasons
        ):
            raise ContractError("qualification retry reason is not frozen by policy")
        binding = (
            trial.group_commitment,
            trial.cluster_commitment,
            trial.workload_cell_sha256,
            trial.real_integration,
        )
        previous = bindings.setdefault(key, binding)
        if previous != binding:
            raise ContractError("qualification retry changed frozen member binding")
    for member_attempts in attempts.values():
        if member_attempts != set(range(1, len(member_attempts) + 1)):
            raise ContractError("qualification attempt_index values must be contiguous")
    final_trials: dict[
        tuple[QualificationPartitionKind, str], QualificationTrial
    ] = {}
    for trial in report.trials:
        key = (trial.partition_kind, trial.member_commitment)
        if (
            key not in final_trials
            or trial.attempt_index > final_trials[key].attempt_index
        ):
            final_trials[key] = trial
    if report.bound_method is not policy.bound_method:
        raise ContractError("qualification report changed the statistical bound method")
    if (
        policy.require_ood_inconclusive
        and any(
            trial.partition_kind is QualificationPartitionKind.OUT_OF_DOMAIN
            and trial.observed_verdict is not OracleVerdict.INCONCLUSIVE
            for trial in final_trials.values()
        )
    ):
        raise ContractError("out-of-domain qualification trial was not inconclusive")
    if report.verdict is QualificationVerdict.PASS:
        if calibration.verdict is not QualificationVerdict.PASS:
            raise ContractError("qualification cannot pass when calibration failed")
        if report.independent_non_violating_groups < policy.min_non_violating_groups or report.independent_negative_groups < policy.min_negative_groups:
            raise ContractError("qualification report does not meet independent-group minima")
        if report.calibrated_cell_count < policy.min_calibrated_cells or report.fault_cell_count < policy.min_fault_cells:
            raise ContractError("qualification report does not meet integration-cell minima")
        if Decimal(report.upper_false_violation_bound.value) > Decimal(policy.max_false_violation_rate.value) or Decimal(report.lower_detection_bound.value) < Decimal(policy.min_detection_rate.value):
            raise ContractError("qualification report does not meet frozen statistical thresholds")


def validate_review_graph(
    candidate: ProfileSetupCandidate,
    qualification_report: QualificationReport,
    bundle: ResultBlindReviewBundle,
    review: ReviewRecord,
) -> None:
    if any(
        type(value) is not expected
        for value, expected in (
            (candidate, ProfileSetupCandidate), (qualification_report, QualificationReport),
            (bundle, ResultBlindReviewBundle), (review, ReviewRecord),
        )
    ):
        raise ContractError("review graph contains an unexpected object type")
    subject = make_review_subject(candidate)
    if (
        bundle.subject != subject
        or bundle.candidate_sha256 != candidate.content_sha256
        or bundle.profile_graph_sha256 != candidate.profile_graph_sha256
        or bundle.qualification_report_sha256 != qualification_report.content_sha256
    ):
        raise ContractError("review bundle does not bind candidate and qualification report")
    if review.subject_sha256 != subject.content_sha256 or review.input_bundle_sha256 != bundle.content_sha256:
        raise ContractError("review record does not bind its exact result-blind input")


def validate_approval_graph(
    candidate: ProfileSetupCandidate,
    approval: SemanticApprovalRecord,
) -> None:
    subject = make_review_subject(candidate)
    expected = (candidate.trust_tier, subject.content_sha256)
    actual = (approval.trust_tier, approval.subject_sha256)
    if actual != expected:
        raise ContractError("approval does not bind candidate semantic subject")
    if approval.decision is not ApprovalDecision.APPROVE:
        raise ContractError("approval graph contains a rejection")


def validate_approval_basis(
    approval: SemanticApprovalRecord,
    basis_review_bundle: ResultBlindReviewBundle,
    basis_review: ReviewRecord,
    basis_qualification_report: QualificationReport,
) -> None:
    """Verify the immutable evidence actually presented to the approver."""

    if type(approval) is not SemanticApprovalRecord:
        raise ContractError("approval must be a SemanticApprovalRecord")
    if type(basis_review_bundle) is not ResultBlindReviewBundle:
        raise ContractError("basis_review_bundle must be a ResultBlindReviewBundle")
    if type(basis_review) is not ReviewRecord:
        raise ContractError("basis_review must be a ReviewRecord")
    if type(basis_qualification_report) is not QualificationReport:
        raise ContractError(
            "basis_qualification_report must be a QualificationReport"
        )
    if basis_review.verdict is not ReviewVerdict.APPROVE:
        raise ContractError("approval basis requires an approved review")
    if basis_review.subject_sha256 != approval.subject_sha256:
        raise ContractError("approval basis review has a different semantic subject")
    if (
        basis_review_bundle.subject.content_sha256 != approval.subject_sha256
        or basis_review.input_bundle_sha256 != basis_review_bundle.content_sha256
        or basis_review_bundle.qualification_report_sha256
        != basis_qualification_report.content_sha256
    ):
        raise ContractError("approval basis object graph is not exactly linked")
    if basis_qualification_report.verdict is not QualificationVerdict.PASS:
        raise ContractError("approval basis requires passing qualification")
    if (
        approval.basis_review_sha256 != basis_review.content_sha256
        or approval.basis_qualification_report_sha256
        != basis_qualification_report.content_sha256
    ):
        raise ContractError("approval does not bind its exact evidence basis")
    if not (
        basis_qualification_report.completed_at
        <= basis_review.reviewed_at
        <= approval.approved_at
    ):
        raise ContractError(
            "approval basis evidence must be in chronological order"
        )


@dataclass(frozen=True)
class SetupStateTransition:
    sequence: int
    from_state: SetupState
    to_state: SetupState
    actor_role: SetupActorRole
    actor_id: str
    evidence_sha256: str
    occurred_at: str

    def __post_init__(self) -> None:
        validate_positive_int(self.sequence, "sequence", maximum=_MAX_ITEMS)
        if type(self.from_state) is not SetupState or type(self.to_state) is not SetupState:
            raise ContractError("from_state and to_state must be SetupState values")
        if (self.from_state, self.to_state) not in _ALLOWED_SETUP_TRANSITIONS:
            raise ContractError(
                f"illegal Setup transition {self.from_state.value}->{self.to_state.value}"
            )
        if type(self.actor_role) is not SetupActorRole:
            raise ContractError("actor_role must be a SetupActorRole")
        validate_identifier(self.actor_id, "actor_id")
        validate_sha256(self.evidence_sha256, "evidence_sha256")
        _timestamp(self.occurred_at, "occurred_at")
        if self.to_state is SetupState.AWAITING_REVIEW and self.actor_role not in (
            SetupActorRole.QUALIFICATION_WORKER,
            SetupActorRole.HARNESS,
        ):
            raise ContractError("only qualification worker/harness may advance to review")
        if self.from_state is SetupState.AWAITING_REVIEW and self.actor_role not in (
            SetupActorRole.REVIEWER,
            SetupActorRole.HARNESS,
        ):
            raise ContractError("review disposition must come from reviewer/harness")
        if self.to_state in (SetupState.SUPERSEDED, SetupState.REVOKED) and self.actor_role not in (
            SetupActorRole.HARNESS,
            SetupActorRole.MAINTAINER,
            SetupActorRole.HUMAN,
        ):
            raise ContractError("supersede/revoke requires an admission authority")

    def to_document(self) -> dict[str, object]:
        return {
            "sequence": self.sequence,
            "from_state": self.from_state.value,
            "to_state": self.to_state.value,
            "actor_role": self.actor_role.value,
            "actor_id": self.actor_id,
            "evidence_sha256": self.evidence_sha256,
            "occurred_at": self.occurred_at,
        }

    @classmethod
    def from_document(cls, value: object) -> SetupStateTransition:
        doc = require_exact_keys(
            value,
            required=(
                "sequence",
                "from_state",
                "to_state",
                "actor_role",
                "actor_id",
                "evidence_sha256",
                "occurred_at",
            ),
            where="setup state transition",
        )
        return cls(
            sequence=doc["sequence"],
            from_state=_enum(SetupState, doc["from_state"], "from_state"),
            to_state=_enum(SetupState, doc["to_state"], "to_state"),
            actor_role=_enum(SetupActorRole, doc["actor_role"], "actor_role"),
            actor_id=doc["actor_id"],
            evidence_sha256=doc["evidence_sha256"],
            occurred_at=doc["occurred_at"],
        )


@dataclass(frozen=True)
class SetupLifecycleRecord:
    candidate_sha256: str
    trust_tier: RegistrationTrustTier
    transitions: tuple[SetupStateTransition, ...]
    final_state: SetupState
    created_at: str
    updated_at: str

    def __post_init__(self) -> None:
        validate_sha256(self.candidate_sha256, "candidate_sha256")
        if type(self.trust_tier) is not RegistrationTrustTier:
            raise ContractError("trust_tier must be a RegistrationTrustTier")
        if type(self.transitions) not in (tuple, list):
            raise ContractError("transitions must be a collection")
        transitions = tuple(self.transitions)
        if len(transitions) > _MAX_ITEMS or any(
            type(item) is not SetupStateTransition for item in transitions
        ):
            raise ContractError("transitions must contain bounded SetupStateTransition values")
        state = SetupState.DRAFT
        last_time = _timestamp(self.created_at, "created_at")
        for expected_sequence, transition in enumerate(transitions, start=1):
            if transition.sequence != expected_sequence:
                raise ContractError("setup transition sequence must be contiguous")
            if transition.from_state is not state:
                raise ContractError("setup transition chain is not contiguous")
            if transition.occurred_at < last_time:
                raise ContractError("setup transition timestamps must be monotonic")
            state = transition.to_state
            last_time = transition.occurred_at
        if type(self.final_state) is not SetupState or self.final_state is not state:
            raise ContractError("final_state does not match transition chain")
        updated = _timestamp(self.updated_at, "updated_at")
        if updated < last_time:
            raise ContractError("updated_at predates lifecycle evidence")
        if not transitions and updated != self.created_at:
            raise ContractError("a draft lifecycle cannot advance updated_at without evidence")
        if state is SetupState.FROZEN:
            final_actor = transitions[-1].actor_role
            if final_actor not in (SetupActorRole.HARNESS, SetupActorRole.MAINTAINER):
                raise ContractError("only Profile Gate authority may freeze a candidate")
        object.__setattr__(self, "transitions", transitions)

    def to_document(self) -> dict[str, object]:
        return {
            "contract_kind": _SETUP_LIFECYCLE_KIND,
            "schema_version": _SCHEMA_VERSION,
            "candidate_sha256": self.candidate_sha256,
            "trust_tier": self.trust_tier.value,
            "transitions": [item.to_document() for item in self.transitions],
            "final_state": self.final_state.value,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }

    @classmethod
    def from_document(cls, value: object) -> SetupLifecycleRecord:
        doc = require_exact_keys(
            value,
            required=(
                "contract_kind",
                "schema_version",
                "candidate_sha256",
                "trust_tier",
                "transitions",
                "final_state",
                "created_at",
                "updated_at",
            ),
            where="setup lifecycle record",
        )
        _check_header(doc, _SETUP_LIFECYCLE_KIND, "setup lifecycle")
        return cls(
            candidate_sha256=doc["candidate_sha256"],
            trust_tier=_enum(RegistrationTrustTier, doc["trust_tier"], "trust_tier"),
            transitions=tuple(
                SetupStateTransition.from_document(item)
                for item in _require_list(doc["transitions"], "transitions")
            ),
            final_state=_enum(SetupState, doc["final_state"], "final_state"),
            created_at=doc["created_at"],
            updated_at=doc["updated_at"],
        )

    @classmethod
    def from_json(cls, payload: object) -> SetupLifecycleRecord:
        return cls.from_document(load_strict_json_object(payload))

    @property
    def content_sha256(self) -> str:
        return canonical_sha256(self.to_document())


@dataclass(frozen=True)
class DependencyBinding:
    kind: DependencyKind
    role: str
    content_sha256: str
    on_change: InvalidationAction

    def __post_init__(self) -> None:
        if type(self.kind) is not DependencyKind:
            raise ContractError("kind must be a DependencyKind")
        validate_identifier(self.role, "role")
        validate_sha256(self.content_sha256, "content_sha256")
        if type(self.on_change) is not InvalidationAction:
            raise ContractError("on_change must be an InvalidationAction")
        semantic_kinds = {
            DependencyKind.ENTRYPOINT,
            DependencyKind.WORKLOAD_SCHEMA,
            DependencyKind.ADAPTER,
            DependencyKind.ORACLE,
            DependencyKind.ORACLE_BUNDLE,
            DependencyKind.ADAPTER_CODE,
            DependencyKind.DEPENDENCY_LOCK,
            DependencyKind.INSTRUMENTATION,
            DependencyKind.EXECUTION_RECIPE,
            DependencyKind.PROFILE_COMPONENT,
            DependencyKind.PERMISSION_MANIFEST,
            DependencyKind.SBOM,
            DependencyKind.CAPABILITY_SET,
        }
        profile_gate_kinds = {
            DependencyKind.SOURCE_SNAPSHOT,
            DependencyKind.PROFILE_GRAPH,
        }
        qualification_kinds = {
            DependencyKind.BASELINE,
            DependencyKind.TOOLCHAIN,
            DependencyKind.OS_IMAGE,
            DependencyKind.MODEL,
            DependencyKind.HARDWARE,
            DependencyKind.DEVICE_IMAGE,
            DependencyKind.RESOURCE_POLICY,
        }
        if self.kind in semantic_kinds and self.on_change not in (
            InvalidationAction.REQUALIFY_REVIEW,
            InvalidationAction.REQUALIFY_REVIEW_REAPPROVE,
        ):
            raise ContractError("semantic dependency change requires review or reapproval")
        if (
            self.kind in profile_gate_kinds
            and self.on_change is InvalidationAction.REUSE_APPROVAL
        ):
            raise ContractError("profile identity change requires Profile Gate")
        if self.kind in qualification_kinds and self.on_change not in (
            InvalidationAction.FULL_QUALIFICATION,
            InvalidationAction.REQUALIFY_REVIEW,
            InvalidationAction.REQUALIFY_REVIEW_REAPPROVE,
        ):
            raise ContractError(
                "environment or baseline change requires full qualification"
            )

    def to_document(self) -> dict[str, object]:
        return {
            "kind": self.kind.value,
            "role": self.role,
            "content_sha256": self.content_sha256,
            "on_change": self.on_change.value,
        }

    @classmethod
    def from_document(cls, value: object) -> DependencyBinding:
        doc = require_exact_keys(
            value,
            required=("kind", "role", "content_sha256", "on_change"),
            where="dependency binding",
        )
        return cls(
            kind=_enum(DependencyKind, doc["kind"], "dependency kind"),
            role=doc["role"],
            content_sha256=doc["content_sha256"],
            on_change=_enum(InvalidationAction, doc["on_change"], "on_change"),
        )


@dataclass(frozen=True)
class DependencyInvalidationManifest:
    manifest_id: str
    manifest_version: str
    candidate_sha256: str
    profile_graph_sha256: str
    dependencies: tuple[DependencyBinding, ...]
    unknown_change_action: InvalidationAction
    created_at: str

    def __post_init__(self) -> None:
        validate_identifier(self.manifest_id, "manifest_id")
        validate_identifier(self.manifest_version, "manifest_version")
        validate_sha256(self.candidate_sha256, "candidate_sha256")
        validate_sha256(self.profile_graph_sha256, "profile_graph_sha256")
        if type(self.dependencies) not in (tuple, list):
            raise ContractError("dependencies must be a collection")
        dependencies = tuple(self.dependencies)
        if (
            not dependencies
            or len(dependencies) > _MAX_ITEMS
            or any(type(item) is not DependencyBinding for item in dependencies)
        ):
            raise ContractError("dependencies must contain bounded DependencyBinding values")
        roles = tuple(item.role for item in dependencies)
        if len(roles) != len(set(roles)):
            raise ContractError("dependency roles must be unique")
        required_kinds = {
            DependencyKind.SOURCE_SNAPSHOT,
            DependencyKind.PROFILE_GRAPH,
            DependencyKind.ORACLE,
            DependencyKind.ADAPTER_CODE,
            DependencyKind.DEPENDENCY_LOCK,
        }
        if not required_kinds.issubset({item.kind for item in dependencies}):
            raise ContractError("dependency manifest is missing a required dependency kind")
        if type(self.unknown_change_action) is not InvalidationAction:
            raise ContractError("unknown_change_action must be an InvalidationAction")
        if self.unknown_change_action not in (
            InvalidationAction.FULL_QUALIFICATION,
            InvalidationAction.REQUALIFY_REVIEW,
            InvalidationAction.REQUALIFY_REVIEW_REAPPROVE,
        ):
            raise ContractError("unknown dependency changes must fail closed")
        _timestamp(self.created_at, "created_at")
        object.__setattr__(
            self,
            "dependencies",
            tuple(sorted(dependencies, key=lambda item: item.role)),
        )

    def to_document(self) -> dict[str, object]:
        return {
            "contract_kind": _INVALIDATION_MANIFEST_KIND,
            "schema_version": _SCHEMA_VERSION,
            "manifest_id": self.manifest_id,
            "manifest_version": self.manifest_version,
            "candidate_sha256": self.candidate_sha256,
            "profile_graph_sha256": self.profile_graph_sha256,
            "dependencies": [item.to_document() for item in self.dependencies],
            "unknown_change_action": self.unknown_change_action.value,
            "created_at": self.created_at,
        }

    @classmethod
    def from_document(cls, value: object) -> DependencyInvalidationManifest:
        doc = require_exact_keys(
            value,
            required=(
                "contract_kind",
                "schema_version",
                "manifest_id",
                "manifest_version",
                "candidate_sha256",
                "profile_graph_sha256",
                "dependencies",
                "unknown_change_action",
                "created_at",
            ),
            where="dependency invalidation manifest",
        )
        _check_header(doc, _INVALIDATION_MANIFEST_KIND, "invalidation manifest")
        return cls(
            manifest_id=doc["manifest_id"],
            manifest_version=doc["manifest_version"],
            candidate_sha256=doc["candidate_sha256"],
            profile_graph_sha256=doc["profile_graph_sha256"],
            dependencies=tuple(
                DependencyBinding.from_document(item)
                for item in _require_list(doc["dependencies"], "dependencies")
            ),
            unknown_change_action=_enum(
                InvalidationAction,
                doc["unknown_change_action"],
                "unknown_change_action",
            ),
            created_at=doc["created_at"],
        )

    @classmethod
    def from_json(cls, payload: object) -> DependencyInvalidationManifest:
        return cls.from_document(load_strict_json_object(payload))

    @property
    def content_sha256(self) -> str:
        return canonical_sha256(self.to_document())


def _expected_invalidation_dependencies(
    candidate: ProfileSetupCandidate,
) -> dict[DependencyKind, frozenset[str]]:
    graph = candidate.profile_graph
    baseline_components = {
        item.content_sha256
        for item in graph.components
        if item.kind is ContractRefKind.BASELINE_POLICY
    }
    resource_components = {
        item.content_sha256
        for item in graph.components
        if item.kind is ContractRefKind.RESOURCE_POLICY
    }
    other_components = {
        item.content_sha256
        for item in graph.components
        if item.kind
        not in (ContractRefKind.BASELINE_POLICY, ContractRefKind.RESOURCE_POLICY)
    }
    expected: dict[DependencyKind, frozenset[str]] = {
        DependencyKind.SOURCE_SNAPSHOT: frozenset(
            {graph.project.source_snapshot_sha256}
        ),
        DependencyKind.PROFILE_GRAPH: frozenset({graph.content_sha256}),
        DependencyKind.ENTRYPOINT: frozenset(
            item.content_sha256 for item in graph.entrypoints
        ),
        DependencyKind.WORKLOAD_SCHEMA: frozenset(
            item.content_sha256 for item in graph.workload_schemas
        ),
        DependencyKind.BASELINE: frozenset(baseline_components),
        DependencyKind.ADAPTER: frozenset(
            item.content_sha256 for item in graph.adapters
        ),
        DependencyKind.INSTRUMENTATION: frozenset(
            item.content_sha256 for item in graph.instrumentation_providers
        ),
        DependencyKind.ORACLE: frozenset(
            item.content_sha256 for item in graph.oracle_specs
        ),
        DependencyKind.ORACLE_BUNDLE: frozenset(
            item.content_sha256 for item in graph.oracle_bundles
        ),
        DependencyKind.EXECUTION_RECIPE: frozenset(
            item.content_sha256 for item in graph.execution_recipes
        ),
        DependencyKind.PROFILE_COMPONENT: frozenset(other_components),
        DependencyKind.ADAPTER_CODE: frozenset(
            {candidate.adapter_code.content_sha256}
        ),
        DependencyKind.DEPENDENCY_LOCK: frozenset(
            {
                graph.project.dependency_manifest_sha256,
                candidate.dependency_lock.content_sha256,
            }
        ),
        DependencyKind.PERMISSION_MANIFEST: frozenset(
            {candidate.permission_manifest.content_sha256}
        ),
        DependencyKind.SBOM: frozenset({candidate.sbom.content_sha256}),
        DependencyKind.CAPABILITY_SET: frozenset(
            {canonical_sha256({"capabilities": list(graph.capabilities)})}
        ),
        DependencyKind.TOOLCHAIN: frozenset(
            {graph.environment.toolchain_sha256}
        ),
        DependencyKind.OS_IMAGE: frozenset(
            {graph.environment.os_image_sha256}
        ),
        DependencyKind.MODEL: frozenset(
            ()
            if graph.environment.model_sha256 is None
            else (graph.environment.model_sha256,)
        ),
        DependencyKind.HARDWARE: frozenset(
            ()
            if graph.environment.hardware_fingerprint_sha256 is None
            else (graph.environment.hardware_fingerprint_sha256,)
        ),
        DependencyKind.DEVICE_IMAGE: frozenset(
            ()
            if graph.environment.device_policy_sha256 is None
            else (graph.environment.device_policy_sha256,)
        ),
        DependencyKind.RESOURCE_POLICY: frozenset(
            {
                graph.environment.resource_policy.content_sha256,
                *resource_components,
            }
        ),
    }
    return expected


def validate_invalidation_manifest_graph(
    candidate: ProfileSetupCandidate,
    manifest: DependencyInvalidationManifest,
) -> None:
    """Require exact coverage of every dependency that can affect a Profile."""

    if type(candidate) is not ProfileSetupCandidate:
        raise ContractError("candidate must be a ProfileSetupCandidate")
    if type(manifest) is not DependencyInvalidationManifest:
        raise ContractError(
            "manifest must be a DependencyInvalidationManifest"
        )
    if (
        manifest.candidate_sha256 != candidate.content_sha256
        or manifest.profile_graph_sha256 != candidate.profile_graph_sha256
    ):
        raise ContractError("invalidation manifest does not bind candidate graph")
    actual: dict[DependencyKind, set[str]] = {}
    for dependency in manifest.dependencies:
        actual.setdefault(dependency.kind, set()).add(
            dependency.content_sha256
        )
    expected = _expected_invalidation_dependencies(candidate)
    for kind in DependencyKind:
        if frozenset(actual.get(kind, set())) != expected.get(kind, frozenset()):
            raise ContractError(
                "invalidation manifest does not exactly cover "
                f"{kind.value} dependencies"
            )


@dataclass(frozen=True)
class ProfileAdmissionRecord:
    admission_id: str
    setup_id: str
    trust_tier: RegistrationTrustTier
    candidate_sha256: str
    profile: ContractRef
    qualification_report_sha256: str
    review_sha256: str
    approval_sha256: str
    invalidation_manifest_sha256: str
    lifecycle_sha256: str
    gate_policy_sha256: str
    gate_verification_receipt_sha256: str
    revocation_ledger_sha256: str
    declared_permissions: tuple[str, ...]
    effective_permissions: tuple[str, ...]
    admission_authority_kind: ApprovalAuthorityKind
    admission_authority_id: str
    admitted_at: str
    qualification_expires_at: str
    approval_expires_at: str | None
    expires_at: str

    def __post_init__(self) -> None:
        validate_identifier(self.admission_id, "admission_id")
        validate_identifier(self.setup_id, "setup_id")
        if type(self.trust_tier) is not RegistrationTrustTier:
            raise ContractError("trust_tier must be a RegistrationTrustTier")
        validate_sha256(self.candidate_sha256, "candidate_sha256")
        _require_ref(self.profile, frozenset({ContractRefKind.FROZEN_PROFILE}), "profile")
        for field in (
            "qualification_report_sha256",
            "review_sha256",
            "approval_sha256",
            "invalidation_manifest_sha256",
            "lifecycle_sha256",
            "gate_policy_sha256",
            "gate_verification_receipt_sha256",
            "revocation_ledger_sha256",
        ):
            validate_sha256(getattr(self, field), field)
        declared = _identifier_tuple(
            self.declared_permissions,
            "declared_permissions",
            allow_empty=True,
        )
        effective = _identifier_tuple(
            self.effective_permissions,
            "effective_permissions",
            allow_empty=True,
        )
        if not set(effective).issubset(set(declared)):
            raise ContractError("effective permissions must be a declared subset")
        object.__setattr__(self, "declared_permissions", declared)
        object.__setattr__(self, "effective_permissions", effective)
        if type(self.admission_authority_kind) is not ApprovalAuthorityKind:
            raise ContractError("admission_authority_kind must be an ApprovalAuthorityKind")
        if self.admission_authority_kind not in (
            ApprovalAuthorityKind.HARNESS,
            ApprovalAuthorityKind.MAINTAINER,
        ):
            raise ContractError("candidate content cannot self-grant registry admission")
        validate_identifier(self.admission_authority_id, "admission_authority_id")
        admitted = _timestamp(self.admitted_at, "admitted_at")
        qualification_expires = _timestamp(
            self.qualification_expires_at,
            "qualification_expires_at",
        )
        approval_expires = _optional_timestamp(
            self.approval_expires_at,
            "approval_expires_at",
        )
        expires = _timestamp(self.expires_at, "expires_at")
        if qualification_expires <= admitted or expires <= admitted:
            raise ContractError("admission cannot use expired evidence")
        if expires > qualification_expires:
            raise ContractError("admission expiry cannot exceed qualification expiry")
        if approval_expires is not None and expires > approval_expires:
            raise ContractError("admission expiry cannot exceed approval expiry")

    def to_document(self) -> dict[str, object]:
        return {
            "contract_kind": _PROFILE_ADMISSION_KIND,
            "schema_version": _SCHEMA_VERSION,
            "admission_id": self.admission_id,
            "setup_id": self.setup_id,
            "trust_tier": self.trust_tier.value,
            "candidate_sha256": self.candidate_sha256,
            "profile": self.profile.to_document(),
            "qualification_report_sha256": self.qualification_report_sha256,
            "review_sha256": self.review_sha256,
            "approval_sha256": self.approval_sha256,
            "invalidation_manifest_sha256": self.invalidation_manifest_sha256,
            "lifecycle_sha256": self.lifecycle_sha256,
            "gate_policy_sha256": self.gate_policy_sha256,
            "gate_verification_receipt_sha256": (
                self.gate_verification_receipt_sha256
            ),
            "revocation_ledger_sha256": self.revocation_ledger_sha256,
            "declared_permissions": list(self.declared_permissions),
            "effective_permissions": list(self.effective_permissions),
            "admission_authority_kind": self.admission_authority_kind.value,
            "admission_authority_id": self.admission_authority_id,
            "admitted_at": self.admitted_at,
            "qualification_expires_at": self.qualification_expires_at,
            "approval_expires_at": self.approval_expires_at,
            "expires_at": self.expires_at,
        }

    @classmethod
    def from_document(cls, value: object) -> ProfileAdmissionRecord:
        fields = (
            "contract_kind", "schema_version", "admission_id", "setup_id",
            "trust_tier", "candidate_sha256", "profile",
            "qualification_report_sha256", "review_sha256", "approval_sha256",
            "invalidation_manifest_sha256", "lifecycle_sha256",
            "gate_policy_sha256", "gate_verification_receipt_sha256",
            "revocation_ledger_sha256",
            "declared_permissions", "effective_permissions",
            "admission_authority_kind", "admission_authority_id", "admitted_at",
            "qualification_expires_at", "approval_expires_at", "expires_at",
        )
        doc = require_exact_keys(value, required=fields, where="profile admission record")
        _check_header(doc, _PROFILE_ADMISSION_KIND, "profile admission")
        return cls(
            admission_id=doc["admission_id"], setup_id=doc["setup_id"],
            trust_tier=_enum(RegistrationTrustTier, doc["trust_tier"], "trust_tier"),
            candidate_sha256=doc["candidate_sha256"],
            profile=_parse_ref(doc["profile"], frozenset({ContractRefKind.FROZEN_PROFILE}), "profile"),
            qualification_report_sha256=doc["qualification_report_sha256"], review_sha256=doc["review_sha256"], approval_sha256=doc["approval_sha256"], invalidation_manifest_sha256=doc["invalidation_manifest_sha256"], lifecycle_sha256=doc["lifecycle_sha256"], gate_policy_sha256=doc["gate_policy_sha256"], gate_verification_receipt_sha256=doc["gate_verification_receipt_sha256"], revocation_ledger_sha256=doc["revocation_ledger_sha256"],
            declared_permissions=tuple(_require_list(doc["declared_permissions"], "declared_permissions")), effective_permissions=tuple(_require_list(doc["effective_permissions"], "effective_permissions")),
            admission_authority_kind=_enum(ApprovalAuthorityKind, doc["admission_authority_kind"], "admission_authority_kind"), admission_authority_id=doc["admission_authority_id"], admitted_at=doc["admitted_at"], qualification_expires_at=doc["qualification_expires_at"], approval_expires_at=doc["approval_expires_at"], expires_at=doc["expires_at"],
        )

    @classmethod
    def from_json(cls, payload: object) -> ProfileAdmissionRecord:
        return cls.from_document(load_strict_json_object(payload))

    @property
    def content_sha256(self) -> str:
        return canonical_sha256(self.to_document())


@dataclass(frozen=True)
class RevocationTarget:
    kind: RevocationTargetKind
    content_sha256: str

    def __post_init__(self) -> None:
        if type(self.kind) is not RevocationTargetKind:
            raise ContractError("kind must be a RevocationTargetKind")
        validate_sha256(self.content_sha256, "content_sha256")

    def to_document(self) -> dict[str, object]:
        return {"kind": self.kind.value, "content_sha256": self.content_sha256}

    @classmethod
    def from_document(cls, value: object) -> RevocationTarget:
        doc = require_exact_keys(
            value,
            required=("kind", "content_sha256"),
            where="revocation target",
        )
        return cls(
            kind=_enum(RevocationTargetKind, doc["kind"], "target kind"),
            content_sha256=doc["content_sha256"],
        )


@dataclass(frozen=True)
class RevocationEntry:
    ledger_id: str
    sequence: int
    previous_entry_sha256: str | None
    target: RevocationTarget
    reason: RevocationReason
    authority_kind: ApprovalAuthorityKind
    authority_id: str
    effective_at: str
    signature: ArtifactRef

    def __post_init__(self) -> None:
        validate_identifier(self.ledger_id, "ledger_id")
        validate_positive_int(self.sequence, "sequence", maximum=9_223_372_036_854_775_807)
        if self.sequence == 1:
            if self.previous_entry_sha256 is not None:
                raise ContractError("first revocation entry cannot have a predecessor")
        else:
            validate_sha256(self.previous_entry_sha256, "previous_entry_sha256")
        if type(self.target) is not RevocationTarget:
            raise ContractError("target must be a RevocationTarget")
        if type(self.reason) is not RevocationReason:
            raise ContractError("reason must be a RevocationReason")
        if type(self.authority_kind) is not ApprovalAuthorityKind or self.authority_kind not in (
            ApprovalAuthorityKind.HARNESS,
            ApprovalAuthorityKind.MAINTAINER,
        ):
            raise ContractError("revocation requires harness/maintainer authority")
        validate_identifier(self.authority_id, "authority_id")
        _timestamp(self.effective_at, "effective_at")
        _artifact(self.signature, "revocation_signature", "signature")

    def signed_payload_document(self) -> dict[str, object]:
        return {
            "ledger_id": self.ledger_id,
            "sequence": self.sequence,
            "previous_entry_sha256": self.previous_entry_sha256,
            "target": self.target.to_document(),
            "reason": self.reason.value,
            "authority_kind": self.authority_kind.value,
            "authority_id": self.authority_id,
            "effective_at": self.effective_at,
        }

    @property
    def signed_payload_sha256(self) -> str:
        return canonical_sha256(self.signed_payload_document())

    def to_document(self) -> dict[str, object]:
        return {
            **self.signed_payload_document(),
            "signature": self.signature.to_document(),
        }

    @classmethod
    def from_document(cls, value: object) -> RevocationEntry:
        doc = require_exact_keys(
            value,
            required=(
                "ledger_id", "sequence", "previous_entry_sha256", "target",
                "reason", "authority_kind", "authority_id", "effective_at",
                "signature",
            ),
            where="revocation entry",
        )
        return cls(
            ledger_id=doc["ledger_id"],
            sequence=doc["sequence"],
            previous_entry_sha256=doc["previous_entry_sha256"],
            target=RevocationTarget.from_document(doc["target"]),
            reason=_enum(RevocationReason, doc["reason"], "reason"),
            authority_kind=_enum(ApprovalAuthorityKind, doc["authority_kind"], "authority_kind"),
            authority_id=doc["authority_id"],
            effective_at=doc["effective_at"],
            signature=_parse_artifact(doc["signature"], "revocation_signature", "signature"),
        )

    @property
    def content_sha256(self) -> str:
        return canonical_sha256(self.to_document())


@dataclass(frozen=True)
class RevocationLedger:
    ledger_id: str
    ledger_version: str
    authority_policy_sha256: str
    entries: tuple[RevocationEntry, ...]
    created_at: str

    def __post_init__(self) -> None:
        validate_identifier(self.ledger_id, "ledger_id")
        validate_identifier(self.ledger_version, "ledger_version")
        validate_sha256(self.authority_policy_sha256, "authority_policy_sha256")
        _timestamp(self.created_at, "created_at")
        if type(self.entries) not in (tuple, list):
            raise ContractError("entries must be a collection")
        entries = tuple(self.entries)
        if len(entries) > _MAX_ITEMS or any(type(item) is not RevocationEntry for item in entries):
            raise ContractError("entries must contain bounded RevocationEntry values")
        previous: RevocationEntry | None = None
        targets: set[RevocationTarget] = set()
        last_time = self.created_at
        for expected_sequence, entry in enumerate(entries, start=1):
            if entry.ledger_id != self.ledger_id or entry.sequence != expected_sequence:
                raise ContractError("revocation ledger id/sequence chain is invalid")
            expected_previous = None if previous is None else previous.content_sha256
            if entry.previous_entry_sha256 != expected_previous:
                raise ContractError("revocation ledger hash chain is invalid")
            if entry.effective_at < last_time:
                raise ContractError("revocation entries must be time ordered")
            if entry.target in targets:
                raise ContractError("a revocation target must not be appended twice")
            targets.add(entry.target)
            previous = entry
            last_time = entry.effective_at
        object.__setattr__(self, "entries", entries)

    def to_document(self) -> dict[str, object]:
        return {
            "contract_kind": _REVOCATION_LEDGER_KIND,
            "schema_version": _SCHEMA_VERSION,
            "ledger_id": self.ledger_id,
            "ledger_version": self.ledger_version,
            "authority_policy_sha256": self.authority_policy_sha256,
            "entries": [item.to_document() for item in self.entries],
            "created_at": self.created_at,
        }

    @classmethod
    def from_document(cls, value: object) -> RevocationLedger:
        doc = require_exact_keys(
            value,
            required=(
                "contract_kind", "schema_version", "ledger_id", "ledger_version",
                "authority_policy_sha256", "entries", "created_at",
            ),
            where="revocation ledger",
        )
        _check_header(doc, _REVOCATION_LEDGER_KIND, "revocation ledger")
        return cls(
            ledger_id=doc["ledger_id"],
            ledger_version=doc["ledger_version"],
            authority_policy_sha256=doc["authority_policy_sha256"],
            entries=tuple(
                RevocationEntry.from_document(item)
                for item in _require_list(doc["entries"], "entries")
            ),
            created_at=doc["created_at"],
        )

    @classmethod
    def from_json(cls, payload: object) -> RevocationLedger:
        return cls.from_document(load_strict_json_object(payload))

    @property
    def head_entry_sha256(self) -> str | None:
        return self.entries[-1].content_sha256 if self.entries else None

    @property
    def content_sha256(self) -> str:
        return canonical_sha256(self.to_document())


def validate_revocation_ledger_extension(
    previous: RevocationLedger,
    current: RevocationLedger,
) -> None:
    if type(previous) is not RevocationLedger or type(current) is not RevocationLedger:
        raise ContractError("ledger extension requires RevocationLedger values")
    if (
        previous.ledger_id,
        previous.ledger_version,
        previous.authority_policy_sha256,
        previous.created_at,
    ) != (
        current.ledger_id,
        current.ledger_version,
        current.authority_policy_sha256,
        current.created_at,
    ):
        raise ContractError("revocation ledger identity/policy changed")
    if len(current.entries) <= len(previous.entries):
        raise ContractError("revocation ledger extension must append an entry")
    if current.entries[: len(previous.entries)] != previous.entries:
        raise ContractError("revocation ledger history was rewritten")


@dataclass(frozen=True)
class TrustEvaluation:
    admission_sha256: str
    profile_sha256: str
    ledger_head_sha256: str
    issuance_at: str
    evaluated_at: str
    valid_at_issuance: bool
    currently_trusted: bool
    reason_codes: tuple[TrustReasonCode, ...]

    def __post_init__(self) -> None:
        for field in ("admission_sha256", "profile_sha256", "ledger_head_sha256"):
            validate_sha256(getattr(self, field), field)
        issuance = _timestamp(self.issuance_at, "issuance_at")
        evaluated = _timestamp(self.evaluated_at, "evaluated_at")
        if evaluated < issuance:
            raise ContractError("evaluated_at must not predate issuance_at")
        if type(self.valid_at_issuance) is not bool or type(self.currently_trusted) is not bool:
            raise ContractError("trust flags must be booleans")
        if self.currently_trusted and not self.valid_at_issuance:
            raise ContractError("currently_trusted implies valid_at_issuance")
        if type(self.reason_codes) not in (tuple, list):
            raise ContractError("reason_codes must be a collection")
        reasons = tuple(self.reason_codes)
        if not reasons or len(reasons) > len(TrustReasonCode) or any(
            type(item) is not TrustReasonCode for item in reasons
        ):
            raise ContractError("reason_codes must contain bounded TrustReasonCode values")
        if len(reasons) != len(set(reasons)):
            raise ContractError("reason_codes must not contain duplicates")
        reasons = tuple(sorted(reasons, key=lambda item: item.value))
        if self.currently_trusted:
            if reasons != (TrustReasonCode.VALID,):
                raise ContractError("trusted evaluation must have only VALID reason")
        elif TrustReasonCode.VALID in reasons:
            raise ContractError("untrusted evaluation cannot contain VALID reason")
        object.__setattr__(self, "reason_codes", reasons)

    def to_document(self) -> dict[str, object]:
        return {
            "contract_kind": _TRUST_EVALUATION_KIND,
            "schema_version": _SCHEMA_VERSION,
            "admission_sha256": self.admission_sha256,
            "profile_sha256": self.profile_sha256,
            "ledger_head_sha256": self.ledger_head_sha256,
            "issuance_at": self.issuance_at,
            "evaluated_at": self.evaluated_at,
            "valid_at_issuance": self.valid_at_issuance,
            "currently_trusted": self.currently_trusted,
            "reason_codes": [item.value for item in self.reason_codes],
        }

    @classmethod
    def from_document(cls, value: object) -> TrustEvaluation:
        doc = require_exact_keys(
            value,
            required=(
                "contract_kind", "schema_version", "admission_sha256",
                "profile_sha256", "ledger_head_sha256", "issuance_at",
                "evaluated_at", "valid_at_issuance", "currently_trusted",
                "reason_codes",
            ),
            where="trust evaluation",
        )
        _check_header(doc, _TRUST_EVALUATION_KIND, "trust evaluation")
        return cls(
            admission_sha256=doc["admission_sha256"],
            profile_sha256=doc["profile_sha256"],
            ledger_head_sha256=doc["ledger_head_sha256"],
            issuance_at=doc["issuance_at"],
            evaluated_at=doc["evaluated_at"],
            valid_at_issuance=doc["valid_at_issuance"],
            currently_trusted=doc["currently_trusted"],
            reason_codes=tuple(
                _enum(TrustReasonCode, item, "trust reason")
                for item in _require_list(doc["reason_codes"], "reason_codes", len(TrustReasonCode))
            ),
        )

    @classmethod
    def from_json(cls, payload: object) -> TrustEvaluation:
        return cls.from_document(load_strict_json_object(payload))

    @property
    def content_sha256(self) -> str:
        return canonical_sha256(self.to_document())


def freeze_profile(
    candidate: ProfileSetupCandidate,
    qualification_report: QualificationReport,
    review_bundle: ResultBlindReviewBundle,
    review: ReviewRecord,
    approval: SemanticApprovalRecord,
    *,
    created_at: str,
    expires_at: str,
    approval_basis_review: ReviewRecord | None = None,
    approval_basis_review_bundle: ResultBlindReviewBundle | None = None,
    approval_basis_qualification_report: QualificationReport | None = None,
) -> FrozenSystemProfile:
    """Build the sole FrozenSystemProfile projection of an approved graph."""

    validate_review_graph(candidate, qualification_report, review_bundle, review)
    validate_approval_graph(candidate, approval)
    validate_approval_basis(
        approval,
        review_bundle
        if approval_basis_review_bundle is None
        else approval_basis_review_bundle,
        review if approval_basis_review is None else approval_basis_review,
        qualification_report
        if approval_basis_qualification_report is None
        else approval_basis_qualification_report,
    )
    if qualification_report.verdict is not QualificationVerdict.PASS:
        raise ContractError("cannot freeze a profile with failed qualification")
    if review.verdict is not ReviewVerdict.APPROVE:
        raise ContractError("cannot freeze a profile without approved review")
    created = _timestamp(created_at, "created_at")
    expires = _timestamp(expires_at, "expires_at")
    if expires <= created:
        raise ContractError("expires_at must be later than created_at")
    if created < max(
        qualification_report.completed_at,
        review.reviewed_at,
        approval.approved_at,
    ):
        raise ContractError("profile cannot predate its Setup evidence")
    if expires > qualification_report.expires_at:
        raise ContractError("profile expiry cannot exceed qualification expiry")
    if approval.expires_at is not None and expires > approval.expires_at:
        raise ContractError("profile expiry cannot exceed approval expiry")
    graph = candidate.profile_graph
    profile = FrozenSystemProfile(
        profile_id=graph.profile_id,
        profile_version=graph.profile_version,
        project=graph.project,
        environment=graph.environment,
        entrypoints=graph.entrypoints,
        workload_schemas=graph.workload_schemas,
        adapters=graph.adapters,
        instrumentation_providers=graph.instrumentation_providers,
        oracle_specs=graph.oracle_specs,
        oracle_bundles=graph.oracle_bundles,
        execution_recipes=graph.execution_recipes,
        components=graph.components,
        capabilities=graph.capabilities,
        qualification_report_sha256=qualification_report.content_sha256,
        review_sha256=review.content_sha256,
        approval_sha256=approval.content_sha256,
        created_at=created,
        expires_at=expires,
    )
    validate_frozen_profile_graph(candidate, profile)
    return profile


def validate_profile_admission_graph(
    candidate: ProfileSetupCandidate,
    profile: FrozenSystemProfile,
    qualification_report: QualificationReport,
    review_bundle: ResultBlindReviewBundle,
    review: ReviewRecord,
    approval: SemanticApprovalRecord,
    approval_basis_review_bundle: ResultBlindReviewBundle,
    approval_basis_review: ReviewRecord,
    approval_basis_qualification_report: QualificationReport,
    gate_policy_sha256: str,
    gate_verification_receipt_sha256: str,
    invalidation_manifest: DependencyInvalidationManifest,
    lifecycle: SetupLifecycleRecord,
    admission_ledger: RevocationLedger,
    admission: ProfileAdmissionRecord,
) -> None:
    """Fail closed unless one registry admission binds the complete Setup graph."""

    validate_frozen_profile_graph(candidate, profile)
    validate_review_graph(candidate, qualification_report, review_bundle, review)
    validate_approval_graph(candidate, approval)
    validate_approval_basis(
        approval,
        approval_basis_review_bundle,
        approval_basis_review,
        approval_basis_qualification_report,
    )
    validate_sha256(gate_policy_sha256, "gate_policy_sha256")
    validate_sha256(
        gate_verification_receipt_sha256,
        "gate_verification_receipt_sha256",
    )
    if qualification_report.verdict is not QualificationVerdict.PASS:
        raise ContractError("admission requires passing qualification")
    if review.verdict is not ReviewVerdict.APPROVE:
        raise ContractError("admission requires approved independent review")
    validate_invalidation_manifest_graph(candidate, invalidation_manifest)
    if review_bundle.invalidation_manifest_sha256 != invalidation_manifest.content_sha256:
        raise ContractError("review bundle does not bind invalidation manifest")
    if (
        lifecycle.candidate_sha256 != candidate.content_sha256
        or lifecycle.trust_tier is not candidate.trust_tier
        or lifecycle.final_state is not SetupState.FROZEN
    ):
        raise ContractError("admission requires the candidate's frozen lifecycle")
    if admission.revocation_ledger_sha256 != admission_ledger.content_sha256:
        raise ContractError("admission does not bind the Profile Gate revocation ledger")
    if (
        profile.qualification_report_sha256 != qualification_report.content_sha256
        or profile.review_sha256 != review.content_sha256
        or profile.approval_sha256 != approval.content_sha256
    ):
        raise ContractError("frozen profile does not bind exact Setup evidence")

    expected_admission = (
        candidate.setup_id,
        candidate.trust_tier,
        candidate.content_sha256,
        profile.ref,
        qualification_report.content_sha256,
        review.content_sha256,
        approval.content_sha256,
        invalidation_manifest.content_sha256,
        lifecycle.content_sha256,
        gate_policy_sha256,
        gate_verification_receipt_sha256,
        admission_ledger.content_sha256,
        candidate.declared_permissions,
        qualification_report.expires_at,
        approval.expires_at,
    )
    actual_admission = (
        admission.setup_id,
        admission.trust_tier,
        admission.candidate_sha256,
        admission.profile,
        admission.qualification_report_sha256,
        admission.review_sha256,
        admission.approval_sha256,
        admission.invalidation_manifest_sha256,
        admission.lifecycle_sha256,
        admission.gate_policy_sha256,
        admission.gate_verification_receipt_sha256,
        admission.revocation_ledger_sha256,
        admission.declared_permissions,
        admission.qualification_expires_at,
        admission.approval_expires_at,
    )
    if actual_admission != expected_admission:
        raise ContractError("profile admission does not bind exact Setup graph")
    if admission.admitted_at < profile.created_at:
        raise ContractError("admission cannot predate frozen profile")
    if profile.expires_at is None or admission.expires_at > profile.expires_at:
        raise ContractError("admission expiry cannot exceed profile expiry")

    admission_targets = {
        RevocationTarget(RevocationTargetKind.PROFILE, profile.content_sha256),
        RevocationTarget(RevocationTargetKind.APPROVAL, approval.content_sha256),
        RevocationTarget(
            RevocationTargetKind.QUALIFICATION,
            qualification_report.content_sha256,
        ),
        RevocationTarget(
            RevocationTargetKind.QUALIFICATION,
            approval_basis_qualification_report.content_sha256,
        ),
        RevocationTarget(RevocationTargetKind.REVIEW, review.content_sha256),
        RevocationTarget(
            RevocationTargetKind.REVIEW,
            approval_basis_review.content_sha256,
        ),
        *(
            RevocationTarget(RevocationTargetKind.ADAPTER, ref.content_sha256)
            for ref in candidate.profile_graph.adapters
        ),
    }
    if any(
        entry.target in admission_targets and entry.effective_at <= admission.admitted_at
        for entry in admission_ledger.entries
    ):
        raise ContractError("Profile Gate admitted an already-revoked dependency")


_TARGET_REASON = {
    RevocationTargetKind.PROFILE: TrustReasonCode.PROFILE_REVOKED,
    RevocationTargetKind.ADAPTER: TrustReasonCode.ADAPTER_REVOKED,
    RevocationTargetKind.APPROVAL: TrustReasonCode.APPROVAL_REVOKED,
    RevocationTargetKind.ADMISSION: TrustReasonCode.ADMISSION_REVOKED,
    RevocationTargetKind.QUALIFICATION: TrustReasonCode.QUALIFICATION_REVOKED,
    RevocationTargetKind.REVIEW: TrustReasonCode.REVIEW_REVOKED,
}


def evaluate_profile_trust(
    candidate: ProfileSetupCandidate,
    profile: FrozenSystemProfile,
    qualification_report: QualificationReport,
    review_bundle: ResultBlindReviewBundle,
    review: ReviewRecord,
    approval: SemanticApprovalRecord,
    approval_basis_review_bundle: ResultBlindReviewBundle,
    approval_basis_review: ReviewRecord,
    approval_basis_qualification_report: QualificationReport,
    gate_policy_sha256: str,
    gate_verification_receipt_sha256: str,
    invalidation_manifest: DependencyInvalidationManifest,
    lifecycle: SetupLifecycleRecord,
    admission_ledger: RevocationLedger,
    admission: ProfileAdmissionRecord,
    ledger: RevocationLedger,
    *,
    issuance_at: str,
    evaluated_at: str,
) -> TrustEvaluation:
    """Evaluate immutable issuance validity and current ledger trust separately."""

    validate_profile_admission_graph(
        candidate,
        profile,
        qualification_report,
        review_bundle,
        review,
        approval,
        approval_basis_review_bundle,
        approval_basis_review,
        approval_basis_qualification_report,
        gate_policy_sha256,
        gate_verification_receipt_sha256,
        invalidation_manifest,
        lifecycle,
        admission_ledger,
        admission,
    )
    if ledger.content_sha256 != admission_ledger.content_sha256:
        validate_revocation_ledger_extension(admission_ledger, ledger)
    issuance = _timestamp(issuance_at, "issuance_at")
    evaluated = _timestamp(evaluated_at, "evaluated_at")
    if evaluated < issuance:
        raise ContractError("evaluated_at must not predate issuance_at")
    targets = {
        RevocationTarget(RevocationTargetKind.PROFILE, profile.content_sha256),
        RevocationTarget(RevocationTargetKind.APPROVAL, approval.content_sha256),
        RevocationTarget(RevocationTargetKind.ADMISSION, admission.content_sha256),
        RevocationTarget(
            RevocationTargetKind.QUALIFICATION,
            qualification_report.content_sha256,
        ),
        RevocationTarget(
            RevocationTargetKind.QUALIFICATION,
            approval_basis_qualification_report.content_sha256,
        ),
        RevocationTarget(RevocationTargetKind.REVIEW, review.content_sha256),
        RevocationTarget(
            RevocationTargetKind.REVIEW,
            approval_basis_review.content_sha256,
        ),
        *(
            RevocationTarget(RevocationTargetKind.ADAPTER, ref.content_sha256)
            for ref in candidate.profile_graph.adapters
        ),
    }
    # The admission ledger proves what the Profile Gate saw when it froze the
    # profile.  Issuance may happen later, so validity at issuance must use the
    # supplied append-only extension and include every revocation effective by
    # that time.
    issuance_revocations = tuple(
        entry
        for entry in ledger.entries
        if entry.target in targets and entry.effective_at <= issuance
    )
    current_revocations = tuple(
        entry
        for entry in ledger.entries
        if entry.target in targets and entry.effective_at <= evaluated
    )
    valid_at_issuance = (
        admission.admitted_at <= issuance <= admission.expires_at
        and not issuance_revocations
    )
    currently_trusted = (
        valid_at_issuance
        and evaluated <= admission.expires_at
        and not current_revocations
    )
    reasons: set[TrustReasonCode] = set()
    if not valid_at_issuance:
        reasons.add(TrustReasonCode.INVALID_AT_ISSUANCE)
    if evaluated > admission.expires_at:
        reasons.add(TrustReasonCode.ADMISSION_EXPIRED)
    for entry in current_revocations:
        reasons.add(_TARGET_REASON[entry.target.kind])
    if currently_trusted:
        reasons = {TrustReasonCode.VALID}
    return TrustEvaluation(
        admission_sha256=admission.content_sha256,
        profile_sha256=profile.content_sha256,
        ledger_head_sha256=ledger.content_sha256,
        issuance_at=issuance,
        evaluated_at=evaluated,
        valid_at_issuance=valid_at_issuance,
        currently_trusted=currently_trusted,
        reason_codes=tuple(reasons),
    )

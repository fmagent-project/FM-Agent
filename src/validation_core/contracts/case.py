"""Result-blind, hash-bound case submissions and formal case plans.

This module contains data contracts only.  It does not resolve registry trust,
run an adapter, read an artifact, materialize a workspace, or decide a bug.
The authority-owned :class:`ValidationInstanceIdentity` is deliberately not
parsed from Agent JSON: an orchestrator constructs it from frozen context and
then uses the pure membership validators below to reject any claimed identity
that does not match.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import TYPE_CHECKING, Iterable

from .base import (
    ContractError,
    canonical_sha256,
    load_strict_json_object,
    require_exact_keys,
    validate_control_free_string,
    validate_identifier,
    validate_positive_int,
    validate_sha256,
)
from .references import ArtifactRef, ContractRef, ContractRefKind

if TYPE_CHECKING:
    from .oracle import OracleBundle, OracleSpec
    from .profile import FrozenSystemProfile


_CASE_PLAN_CONTRACT_KIND = "case_plan"
_CASE_PLAN_SCHEMA_VERSION = 1
_CASE_SUBMISSION_CONTRACT_KIND = "case_submission"
_CASE_SUBMISSION_SCHEMA_VERSION = 4
_MAX_CASE_ARTIFACTS = 4096
_MAX_SUBMISSION_ATTEMPTS = 1_000_000
_MAX_NOTES_LENGTH = 16_384


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


def _artifact_from_document(value: object, field: str) -> ArtifactRef:
    try:
        return ArtifactRef.from_document(value)
    except ContractError as exc:
        raise ContractError(f"invalid {field}: {exc}") from exc


@dataclass(frozen=True)
class ValidationInstanceIdentity:
    """The six authority-owned values that identify one validation instance.

    Attempts, submission branch, notes, Gate role, and physical resources are
    intentionally absent.  They do not create a new validation instance.
    """

    project_id: str
    case_id: str
    function_id: str
    snapshot_sha256: str
    reasoning_sha256: str
    profile_sha256: str

    def __post_init__(self) -> None:
        validate_identifier(self.project_id, "project_id")
        validate_identifier(self.case_id, "case_id")
        validate_identifier(self.function_id, "function_id")
        validate_sha256(self.snapshot_sha256, "snapshot_sha256")
        validate_sha256(self.reasoning_sha256, "reasoning_sha256")
        validate_sha256(self.profile_sha256, "profile_sha256")

    def to_preimage_document(self) -> dict[str, object]:
        """Return the exact design-specified preimage, without schema metadata."""

        return {
            "project_id": self.project_id,
            "case_id": self.case_id,
            "function_id": self.function_id,
            "snapshot_sha256": self.snapshot_sha256,
            "reasoning_sha256": self.reasoning_sha256,
            "profile_sha256": self.profile_sha256,
        }

    @property
    def validation_instance_id(self) -> str:
        return canonical_sha256(self.to_preimage_document())


def compute_validation_instance_id(
    *,
    project_id: str,
    case_id: str,
    function_id: str,
    snapshot_sha256: str,
    reasoning_sha256: str,
    profile_sha256: str,
) -> str:
    """Compute an instance id from authoritative context only."""

    return ValidationInstanceIdentity(
        project_id=project_id,
        case_id=case_id,
        function_id=function_id,
        snapshot_sha256=snapshot_sha256,
        reasoning_sha256=reasoning_sha256,
        profile_sha256=profile_sha256,
    ).validation_instance_id


@dataclass(frozen=True)
class WorkloadSelection:
    """One Profile-approved workload schema and one CAS-bound payload."""

    schema: ContractRef
    artifact: ArtifactRef

    def __post_init__(self) -> None:
        _require_ref(self.schema, ContractRefKind.WORKLOAD_SCHEMA, "workload.schema")
        if type(self.artifact) is not ArtifactRef:
            raise ContractError("workload.artifact must be an ArtifactRef")

    def to_document(self) -> dict[str, object]:
        return {
            "schema": self.schema.to_document(),
            "artifact": self.artifact.to_document(),
        }

    @classmethod
    def from_document(cls, value: object) -> WorkloadSelection:
        document = require_exact_keys(
            value,
            required=("schema", "artifact"),
            where="workload selection",
        )
        return cls(
            schema=_ref_from_document(
                document["schema"],
                ContractRefKind.WORKLOAD_SCHEMA,
                "workload.schema",
            ),
            artifact=_artifact_from_document(
                document["artifact"],
                "workload.artifact",
            ),
        )


@dataclass(frozen=True)
class TargetEvidenceSelection:
    """Expected X/Z values bound to a Profile-owned matching policy."""

    policy: ContractRef
    expected_input: ArtifactRef
    predicted_buggy_output: ArtifactRef

    def __post_init__(self) -> None:
        _require_ref(
            self.policy,
            ContractRefKind.TARGET_EVIDENCE_POLICY,
            "target_evidence.policy",
        )
        if type(self.expected_input) is not ArtifactRef:
            raise ContractError(
                "target_evidence.expected_input must be an ArtifactRef"
            )
        if type(self.predicted_buggy_output) is not ArtifactRef:
            raise ContractError(
                "target_evidence.predicted_buggy_output must be an ArtifactRef"
            )
        if self.expected_input.role == self.predicted_buggy_output.role:
            raise ContractError(
                "target evidence input and output must use distinct artifact roles"
            )

    def to_document(self) -> dict[str, object]:
        return {
            "policy": self.policy.to_document(),
            "expected_input": self.expected_input.to_document(),
            "predicted_buggy_output": self.predicted_buggy_output.to_document(),
        }

    @classmethod
    def from_document(cls, value: object) -> TargetEvidenceSelection:
        document = require_exact_keys(
            value,
            required=("policy", "expected_input", "predicted_buggy_output"),
            where="target evidence selection",
        )
        return cls(
            policy=_ref_from_document(
                document["policy"],
                ContractRefKind.TARGET_EVIDENCE_POLICY,
                "target_evidence.policy",
            ),
            expected_input=_artifact_from_document(
                document["expected_input"],
                "target_evidence.expected_input",
            ),
            predicted_buggy_output=_artifact_from_document(
                document["predicted_buggy_output"],
                "target_evidence.predicted_buggy_output",
            ),
        )


@dataclass(frozen=True)
class RepairSelection:
    """An optional L1 patch selected under a frozen Profile repair policy."""

    policy: ContractRef
    patch: ArtifactRef

    def __post_init__(self) -> None:
        _require_ref(self.policy, ContractRefKind.REPAIR_POLICY, "repair.policy")
        if type(self.patch) is not ArtifactRef:
            raise ContractError("repair.patch must be an ArtifactRef")

    def to_document(self) -> dict[str, object]:
        return {
            "policy": self.policy.to_document(),
            "patch": self.patch.to_document(),
        }

    @classmethod
    def from_document(cls, value: object) -> RepairSelection:
        document = require_exact_keys(
            value,
            required=("policy", "patch"),
            where="repair selection",
        )
        return cls(
            policy=_ref_from_document(
                document["policy"],
                ContractRefKind.REPAIR_POLICY,
                "repair.policy",
            ),
            patch=_artifact_from_document(document["patch"], "repair.patch"),
        )


@dataclass(frozen=True)
class CasePlan:
    """The sole formal Agent-selected plan; it contains no verdict or code."""

    validation_instance_id: str
    case_id: str
    function_id: str
    reasoning_sha256: str
    profile: ContractRef
    entrypoint: ContractRef
    primary_execution_recipe: ContractRef
    workload: WorkloadSelection
    target_evidence: TargetEvidenceSelection
    oracle_bundle: ContractRef
    causal_control_id: str | None
    repair: RepairSelection | None
    artifacts: tuple[ArtifactRef, ...]
    notes: str

    def __post_init__(self) -> None:
        validate_sha256(self.validation_instance_id, "validation_instance_id")
        validate_identifier(self.case_id, "case_id")
        validate_identifier(self.function_id, "function_id")
        validate_sha256(self.reasoning_sha256, "reasoning_sha256")
        _require_ref(self.profile, ContractRefKind.FROZEN_PROFILE, "profile")
        _require_ref(self.entrypoint, ContractRefKind.ENTRYPOINT, "entrypoint")
        _require_ref(
            self.primary_execution_recipe,
            ContractRefKind.EXECUTION_RECIPE,
            "primary_execution_recipe",
        )
        if type(self.workload) is not WorkloadSelection:
            raise ContractError("workload must be a WorkloadSelection")
        if type(self.target_evidence) is not TargetEvidenceSelection:
            raise ContractError(
                "target_evidence must be a TargetEvidenceSelection"
            )
        _require_ref(
            self.oracle_bundle,
            ContractRefKind.ORACLE_BUNDLE,
            "oracle_bundle",
        )
        if self.causal_control_id is not None:
            validate_identifier(self.causal_control_id, "causal_control_id")
        if self.repair is not None and type(self.repair) is not RepairSelection:
            raise ContractError("repair must be a RepairSelection or None")

        if type(self.artifacts) not in (tuple, list):
            raise ContractError("artifacts must be a collection of ArtifactRef values")
        artifacts = tuple(self.artifacts)
        if len(artifacts) > _MAX_CASE_ARTIFACTS:
            raise ContractError(
                f"artifacts must not contain more than {_MAX_CASE_ARTIFACTS} values"
            )
        if any(type(artifact) is not ArtifactRef for artifact in artifacts):
            raise ContractError("artifacts must contain only ArtifactRef values")
        core_artifacts = (
            self.workload.artifact,
            self.target_evidence.expected_input,
            self.target_evidence.predicted_buggy_output,
        ) + (() if self.repair is None else (self.repair.patch,))
        all_roles = tuple(
            artifact.role for artifact in (*core_artifacts, *artifacts)
        )
        if len(all_roles) != len(set(all_roles)):
            raise ContractError(
                "core and additional artifacts must use globally unique roles"
            )
        artifacts = tuple(sorted(artifacts, key=lambda artifact: artifact.role))
        object.__setattr__(self, "artifacts", artifacts)

        validate_control_free_string(
            self.notes,
            "notes",
            allow_empty=True,
            max_length=_MAX_NOTES_LENGTH,
        )

    def to_document(self) -> dict[str, object]:
        return {
            "contract_kind": _CASE_PLAN_CONTRACT_KIND,
            "schema_version": _CASE_PLAN_SCHEMA_VERSION,
            "validation_instance_id": self.validation_instance_id,
            "case_id": self.case_id,
            "function_id": self.function_id,
            "reasoning_sha256": self.reasoning_sha256,
            "profile": self.profile.to_document(),
            "entrypoint": self.entrypoint.to_document(),
            "primary_execution_recipe": self.primary_execution_recipe.to_document(),
            "workload": self.workload.to_document(),
            "target_evidence": self.target_evidence.to_document(),
            "oracle_bundle": self.oracle_bundle.to_document(),
            "causal_control_id": self.causal_control_id,
            "repair": None if self.repair is None else self.repair.to_document(),
            "artifacts": [artifact.to_document() for artifact in self.artifacts],
            "notes": self.notes,
        }

    @classmethod
    def from_document(cls, value: object) -> CasePlan:
        document = require_exact_keys(
            value,
            required=(
                "contract_kind",
                "schema_version",
                "validation_instance_id",
                "case_id",
                "function_id",
                "reasoning_sha256",
                "profile",
                "entrypoint",
                "primary_execution_recipe",
                "workload",
                "target_evidence",
                "oracle_bundle",
                "causal_control_id",
                "repair",
                "artifacts",
                "notes",
            ),
            where="case plan",
        )
        if document["contract_kind"] != _CASE_PLAN_CONTRACT_KIND:
            raise ContractError(
                f"case plan contract_kind must be {_CASE_PLAN_CONTRACT_KIND!r}"
            )
        if (
            type(document["schema_version"]) is not int
            or document["schema_version"] != _CASE_PLAN_SCHEMA_VERSION
        ):
            raise ContractError("case plan schema_version must be the integer 1")
        artifact_documents = document["artifacts"]
        if type(artifact_documents) is not list:
            raise ContractError("case plan artifacts must be a list")
        repair_document = document["repair"]
        if repair_document is not None and type(repair_document) is not dict:
            raise ContractError("case plan repair must be an object or null")
        return cls(
            validation_instance_id=document["validation_instance_id"],
            case_id=document["case_id"],
            function_id=document["function_id"],
            reasoning_sha256=document["reasoning_sha256"],
            profile=_ref_from_document(
                document["profile"],
                ContractRefKind.FROZEN_PROFILE,
                "profile",
            ),
            entrypoint=_ref_from_document(
                document["entrypoint"],
                ContractRefKind.ENTRYPOINT,
                "entrypoint",
            ),
            primary_execution_recipe=_ref_from_document(
                document["primary_execution_recipe"],
                ContractRefKind.EXECUTION_RECIPE,
                "primary_execution_recipe",
            ),
            workload=WorkloadSelection.from_document(document["workload"]),
            target_evidence=TargetEvidenceSelection.from_document(
                document["target_evidence"]
            ),
            oracle_bundle=_ref_from_document(
                document["oracle_bundle"],
                ContractRefKind.ORACLE_BUNDLE,
                "oracle_bundle",
            ),
            causal_control_id=document["causal_control_id"],
            repair=(
                None
                if repair_document is None
                else RepairSelection.from_document(repair_document)
            ),
            artifacts=tuple(
                _artifact_from_document(artifact, f"artifacts[{index}]")
                for index, artifact in enumerate(artifact_documents)
            ),
            notes=document["notes"],
        )

    @classmethod
    def from_json(cls, payload: object) -> CasePlan:
        return cls.from_document(load_strict_json_object(payload))

    @property
    def content_sha256(self) -> str:
        return canonical_sha256(self.to_document())

    @property
    def ref(self) -> ContractRef:
        """Return a content-addressed ref without introducing a hash cycle."""

        return ContractRef(
            kind=ContractRefKind.CASE_PLAN,
            contract_id=self.content_sha256,
            contract_version="1",
            content_sha256=self.content_sha256,
        )


class CaseSubmissionKind(str, Enum):
    NOT_CONFIRMED = "not_confirmed"
    CANDIDATE = "candidate"


@dataclass(frozen=True)
class CaseSubmission:
    """External v4 union; the supplied instance id remains an untrusted claim."""

    submission_kind: CaseSubmissionKind
    validation_instance_id: str
    case_id: str
    function_id: str
    reasoning_sha256: str
    attempts: int
    notes: str
    case_plan: CasePlan | None = None

    def __post_init__(self) -> None:
        if type(self.submission_kind) is not CaseSubmissionKind:
            raise ContractError("submission_kind must be a CaseSubmissionKind")
        validate_sha256(self.validation_instance_id, "validation_instance_id")
        validate_identifier(self.case_id, "case_id")
        validate_identifier(self.function_id, "function_id")
        validate_sha256(self.reasoning_sha256, "reasoning_sha256")
        validate_positive_int(
            self.attempts,
            "attempts",
            maximum=_MAX_SUBMISSION_ATTEMPTS,
        )
        validate_control_free_string(
            self.notes,
            "notes",
            allow_empty=True,
            max_length=_MAX_NOTES_LENGTH,
        )

        if self.submission_kind is CaseSubmissionKind.NOT_CONFIRMED:
            if self.case_plan is not None:
                raise ContractError(
                    "not_confirmed submission must not contain a case plan"
                )
            return
        if type(self.case_plan) is not CasePlan:
            raise ContractError("candidate submission must contain a CasePlan")
        if (
            self.validation_instance_id != self.case_plan.validation_instance_id
            or self.case_id != self.case_plan.case_id
            or self.function_id != self.case_plan.function_id
            or self.reasoning_sha256 != self.case_plan.reasoning_sha256
            or self.notes != self.case_plan.notes
        ):
            raise ContractError(
                "candidate submission identity and notes must match its case plan"
            )

    def to_document(self) -> dict[str, object]:
        document: dict[str, object] = {
            "contract_kind": _CASE_SUBMISSION_CONTRACT_KIND,
            "schema_version": _CASE_SUBMISSION_SCHEMA_VERSION,
            "submission_kind": self.submission_kind.value,
            "validation_instance_id": self.validation_instance_id,
            "case_id": self.case_id,
            "function_id": self.function_id,
            "reasoning_sha256": self.reasoning_sha256,
            "attempts": self.attempts,
            "notes": self.notes,
        }
        if self.submission_kind is CaseSubmissionKind.CANDIDATE:
            if self.case_plan is None:  # defensive; __post_init__ rejects this
                raise ContractError("candidate submission has no case plan")
            document["case_plan"] = self.case_plan.to_document()
        return document

    @classmethod
    def from_document(cls, value: object) -> CaseSubmission:
        if type(value) is not dict:
            raise ContractError("case submission must be an object")
        raw_kind = value.get("submission_kind")
        if type(raw_kind) is not str:
            raise ContractError("case submission submission_kind must be a string")
        try:
            submission_kind = CaseSubmissionKind(raw_kind)
        except ValueError as exc:
            raise ContractError(
                f"unsupported case submission kind {raw_kind!r}"
            ) from exc
        common = (
            "contract_kind",
            "schema_version",
            "submission_kind",
            "validation_instance_id",
            "case_id",
            "function_id",
            "reasoning_sha256",
            "attempts",
            "notes",
        )
        required = (
            common
            if submission_kind is CaseSubmissionKind.NOT_CONFIRMED
            else common + ("case_plan",)
        )
        document = require_exact_keys(
            value,
            required=required,
            where="case submission",
        )
        if document["contract_kind"] != _CASE_SUBMISSION_CONTRACT_KIND:
            raise ContractError(
                "case submission contract_kind must be "
                f"{_CASE_SUBMISSION_CONTRACT_KIND!r}"
            )
        if (
            type(document["schema_version"]) is not int
            or document["schema_version"] != _CASE_SUBMISSION_SCHEMA_VERSION
        ):
            raise ContractError("case submission schema_version must be integer 4")
        return cls(
            submission_kind=submission_kind,
            validation_instance_id=document["validation_instance_id"],
            case_id=document["case_id"],
            function_id=document["function_id"],
            reasoning_sha256=document["reasoning_sha256"],
            attempts=document["attempts"],
            notes=document["notes"],
            case_plan=(
                None
                if submission_kind is CaseSubmissionKind.NOT_CONFIRMED
                else CasePlan.from_document(document["case_plan"])
            ),
        )

    @classmethod
    def from_json(cls, payload: object) -> CaseSubmission:
        return cls.from_document(load_strict_json_object(payload))

    @property
    def content_sha256(self) -> str:
        return canonical_sha256(self.to_document())

    @property
    def ref(self) -> ContractRef:
        return ContractRef(
            kind=ContractRefKind.CASE_SUBMISSION,
            contract_id=self.content_sha256,
            contract_version=str(_CASE_SUBMISSION_SCHEMA_VERSION),
            content_sha256=self.content_sha256,
        )


def _validate_identity_against_profile(
    identity: ValidationInstanceIdentity,
    profile: FrozenSystemProfile,
) -> None:
    if type(identity) is not ValidationInstanceIdentity:
        raise ContractError(
            "identity must be an authority-owned ValidationInstanceIdentity"
        )

    # Runtime import avoids making the pure Profile module import CasePlan.
    from .profile import FrozenSystemProfile

    if type(profile) is not FrozenSystemProfile:
        raise ContractError("profile must be a FrozenSystemProfile")
    if identity.project_id != profile.project.system_id:
        raise ContractError("authority project_id does not match the profile")
    if identity.snapshot_sha256 != profile.project.source_snapshot_sha256:
        raise ContractError("authority snapshot_sha256 does not match the profile")
    if identity.profile_sha256 != profile.content_sha256:
        raise ContractError("authority profile_sha256 does not match the profile")


def validate_case_plan_membership(
    plan: CasePlan,
    *,
    identity: ValidationInstanceIdentity,
    profile: FrozenSystemProfile,
    oracle_bundle: OracleBundle,
    oracle_specs: Iterable[OracleSpec],
) -> None:
    """Check authority identity and exact Frozen Profile graph membership.

    This function does not consult the registry and does not grant trust.  The
    supplied Profile graph must already have passed its own complete graph
    validation before this function is called.
    """

    if type(plan) is not CasePlan:
        raise ContractError("plan must be a CasePlan")
    _validate_identity_against_profile(identity, profile)
    if plan.validation_instance_id != identity.validation_instance_id:
        raise ContractError(
            "claimed validation_instance_id does not match authoritative context"
        )
    if plan.case_id != identity.case_id:
        raise ContractError("case plan case_id does not match authoritative context")
    if plan.function_id != identity.function_id:
        raise ContractError(
            "case plan function_id does not match authoritative context"
        )
    if plan.reasoning_sha256 != identity.reasoning_sha256:
        raise ContractError(
            "case plan reasoning_sha256 does not match authoritative context"
        )
    if plan.profile != profile.ref:
        raise ContractError("case plan profile reference does not match exactly")

    memberships = (
        (plan.entrypoint, profile.entrypoints, "entrypoint"),
        (
            plan.primary_execution_recipe,
            profile.execution_recipes,
            "primary execution recipe",
        ),
        (plan.workload.schema, profile.workload_schemas, "workload schema"),
        (plan.oracle_bundle, profile.oracle_bundles, "oracle bundle"),
        (plan.target_evidence.policy, profile.components, "target evidence policy"),
    )
    for reference, allowed, field in memberships:
        if reference not in allowed:
            raise ContractError(f"case plan {field} is not an exact Profile member")
    if plan.repair is not None:
        if plan.repair.policy not in profile.components:
            raise ContractError(
                "case plan repair policy is not an exact Profile member"
            )

    from .oracle import (
        ControlEvidenceRole,
        OracleBundle,
        OracleSpec,
        VariantRole,
    )

    if type(oracle_bundle) is not OracleBundle:
        raise ContractError("oracle_bundle must be an OracleBundle")
    if oracle_bundle.ref != plan.oracle_bundle:
        raise ContractError(
            "supplied OracleBundle does not exactly match the case plan"
        )
    specs = tuple(oracle_specs)
    if any(type(spec) is not OracleSpec for spec in specs):
        raise ContractError("oracle_specs must contain only OracleSpec values")
    spec_by_ref = {spec.ref: spec for spec in specs}
    if len(spec_by_ref) != len(specs):
        raise ContractError("oracle_specs must not contain duplicate references")
    for reference in spec_by_ref:
        if reference not in profile.oracle_specs:
            raise ContractError(
                "supplied OracleSpec is not an exact Profile member"
            )

    primary_specs: list[OracleSpec] = []
    for reference in oracle_bundle.primary_oracles:
        spec = spec_by_ref.get(reference)
        if spec is None:
            raise ContractError(
                "selected OracleBundle has an unresolved primary OracleSpec"
            )
        primary_specs.append(spec)
    primary_candidate_recipes = frozenset(
        variant.execution_recipe
        for spec in primary_specs
        for variant in spec.variants
        if variant.role is VariantRole.CANDIDATE
    )
    if not primary_candidate_recipes:
        raise ContractError(
            "selected OracleBundle has no primary candidate execution recipe"
        )
    if plan.primary_execution_recipe not in primary_candidate_recipes:
        raise ContractError(
            "primary execution recipe must be a candidate recipe of a primary Oracle"
        )

    # Resolve the entire selected bundle plus causal correctness-guard closure.
    pending = list(oracle_bundle.oracle_spec_refs)
    resolved: set[ContractRef] = set()
    while pending:
        reference = pending.pop(0)
        if reference in resolved:
            continue
        spec = spec_by_ref.get(reference)
        if spec is None:
            raise ContractError(
                "selected OracleBundle has an unresolved OracleSpec reference"
            )
        resolved.add(reference)
        pending.extend(spec.dependent_oracle_spec_refs)
    if set(spec_by_ref) != resolved:
        raise ContractError(
            "oracle_specs must exactly equal the selected bundle and dependent "
            "guard closure"
        )

    if oracle_bundle.control_evidence_role is ControlEvidenceRole.ORACLE_ONLY:
        if plan.causal_control_id is not None:
            raise ContractError(
                "oracle-only bundle requires causal_control_id to be null"
            )
    else:
        control_reference = oracle_bundle.control_oracle
        if control_reference is None:  # defensive; OracleBundle rejects this
            raise ContractError("causal OracleBundle has no control Oracle")
        control_spec = spec_by_ref.get(control_reference)
        if control_spec is None or control_spec.causal_control is None:
            raise ContractError(
                "causal OracleBundle control Oracle is not fully resolved"
            )
        expected_control_id = control_spec.causal_control.control_variant_id
        if plan.causal_control_id != expected_control_id:
            raise ContractError(
                "causal_control_id does not match the bundle's sole control"
            )
        if (
            plan.target_evidence.policy
            != control_spec.causal_control.target_association
        ):
            raise ContractError(
                "target evidence policy does not match the causal control association"
            )


def validate_case_submission_membership(
    submission: CaseSubmission,
    *,
    identity: ValidationInstanceIdentity,
    profile: FrozenSystemProfile,
    oracle_bundle: OracleBundle | None = None,
    oracle_specs: Iterable[OracleSpec] = (),
) -> None:
    """Recompute the Agent-claimed id and validate the selected Profile graph."""

    if type(submission) is not CaseSubmission:
        raise ContractError("submission must be a CaseSubmission")
    _validate_identity_against_profile(identity, profile)
    if submission.validation_instance_id != identity.validation_instance_id:
        raise ContractError(
            "claimed validation_instance_id does not match authoritative context"
        )
    if submission.case_id != identity.case_id:
        raise ContractError("submission case_id does not match authoritative context")
    if submission.function_id != identity.function_id:
        raise ContractError(
            "submission function_id does not match authoritative context"
        )
    if submission.reasoning_sha256 != identity.reasoning_sha256:
        raise ContractError(
            "submission reasoning_sha256 does not match authoritative context"
        )
    if submission.submission_kind is CaseSubmissionKind.CANDIDATE:
        if submission.case_plan is None:  # defensive; __post_init__ rejects this
            raise ContractError("candidate submission has no case plan")
        validate_case_plan_membership(
            submission.case_plan,
            identity=identity,
            profile=profile,
            oracle_bundle=oracle_bundle,
            oracle_specs=oracle_specs,
        )

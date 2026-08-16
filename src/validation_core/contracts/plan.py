"""Frozen experiment plans and broker-owned execution bindings.

This module is deliberately declarative.  It does not materialize a plan,
allocate a resource, run a command, inspect an observation, or grant trust.
The pure validators at the bottom only compare already-frozen contracts.
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
    validate_identifier,
    validate_non_negative_int,
    validate_positive_int,
    validate_sha256,
)
from .oracle import ControlEvidenceRole, ExecutionProtocol, VariantRole
from .references import ContractRef, ContractRefKind

if TYPE_CHECKING:
    from .case import CasePlan
    from .oracle import OracleBundle, OracleSpec
    from .profile import FrozenSystemProfile


_BASELINE_RECEIPT_KIND = "baseline_selection_receipt"
_EXPERIMENT_TEMPLATE_KIND = "experiment_plan_template"
_EXECUTION_BINDING_KIND = "execution_binding"
_SCHEMA_VERSION = 1
_CONTENT_REF_VERSION = "1"
_MAX_BASELINE_CANDIDATES = 4096
_MAX_ORACLE_PLANS = 4096
_MAX_COLLECTORS = 4096
_MAX_STEPS = 16_384
_MAX_DEPENDENCIES = 4096
_MAX_DYNAMIC_RESOURCES = 4096
_MAX_SEED = 9_223_372_036_854_775_807
_MAX_LOOPBACK_PORT = 65_535


class BaselineSourceKind(str, Enum):
    ABSOLUTE = "absolute"
    PAIRED_CONTROL = "paired_control"
    MATCHED_TREND = "matched_trend"
    EXTERNAL_REFERENCE = "external_reference"


class BaselineEligibility(str, Enum):
    ELIGIBLE = "eligible"
    INELIGIBLE = "ineligible"
    NOT_EVALUATED = "not_evaluated"


class ExperimentPhase(str, Enum):
    SANDBOX_HEALTH = "sandbox_health"
    REAL_ENTRY_REPLAY = "real_entry_replay"
    TARGET_EVIDENCE = "target_evidence"
    ORACLE_EXPERIMENT = "oracle_experiment"
    CAUSAL_CONTROL = "causal_control"
    REPAIR = "repair"
    BUILD_SANITY = "build_sanity"
    REPAIR_REAL_ENTRY_REPLAY = "repair_real_entry_replay"
    REPAIR_TARGET_EVIDENCE = "repair_target_evidence"
    REPAIR_ORACLE_EXPERIMENT = "repair_oracle_experiment"
    REGRESSION = "regression"


class DynamicResourceKind(str, Enum):
    WORKSPACE = "workspace"
    LOOPBACK_PORT = "loopback_port"
    GPU_LEASE = "gpu_lease"
    DEVICE_LEASE = "device_lease"
    TEMPORARY_DIRECTORY = "temporary_directory"


class GateRole(str, Enum):
    B1 = "B1"
    B2 = "B2"


def _enum_value(enum_type: type[Enum], value: object, field: str) -> Enum:
    if type(value) is not str:
        raise ContractError(f"{field} must be a string enum value")
    try:
        return enum_type(value)
    except ValueError as exc:
        raise ContractError(f"{field} has unsupported value {value!r}") from exc


def _ref_sort_key(reference: ContractRef) -> tuple[str, str, str, str]:
    return (
        reference.kind.value,
        reference.contract_id,
        reference.contract_version,
        reference.content_sha256,
    )


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


def _normalize_refs(
    value: object,
    expected_kind: ContractRefKind,
    field: str,
    *,
    allow_empty: bool = False,
    maximum: int = _MAX_ORACLE_PLANS,
) -> tuple[ContractRef, ...]:
    if type(value) not in (tuple, list):
        raise ContractError(f"{field} must be a collection of ContractRef values")
    references = tuple(value)
    if not references and not allow_empty:
        raise ContractError(f"{field} must not be empty")
    if len(references) > maximum:
        raise ContractError(f"{field} must not contain more than {maximum} values")
    for reference in references:
        _require_ref(reference, expected_kind, field)
    identities = tuple(
        (reference.contract_id, reference.contract_version)
        for reference in references
    )
    if len(identities) != len(set(identities)):
        raise ContractError(f"{field} must not repeat or conflict on id/version")
    return tuple(sorted(references, key=_ref_sort_key))


def _refs_from_document(
    value: object,
    expected_kind: ContractRefKind,
    field: str,
    *,
    allow_empty: bool = False,
    maximum: int = _MAX_ORACLE_PLANS,
) -> tuple[ContractRef, ...]:
    if type(value) is not list:
        raise ContractError(f"{field} must be a list")
    return _normalize_refs(
        tuple(
            _ref_from_document(item, expected_kind, f"{field}[{index}]")
            for index, item in enumerate(value)
        ),
        expected_kind,
        field,
        allow_empty=allow_empty,
        maximum=maximum,
    )


@dataclass(frozen=True)
class BaselineCandidate:
    """One statically assessed source in a frozen fallback path."""

    source_id: str
    source_kind: BaselineSourceKind
    source_sha256: str
    eligibility: BaselineEligibility
    static_eligibility_facts_sha256: str

    def __post_init__(self) -> None:
        validate_identifier(self.source_id, "baseline source_id")
        if type(self.source_kind) is not BaselineSourceKind:
            raise ContractError("source_kind must be a BaselineSourceKind")
        validate_sha256(self.source_sha256, "baseline source_sha256")
        if type(self.eligibility) is not BaselineEligibility:
            raise ContractError("eligibility must be a BaselineEligibility")
        validate_sha256(
            self.static_eligibility_facts_sha256,
            "static_eligibility_facts_sha256",
        )

    def to_document(self) -> dict[str, object]:
        return {
            "source_id": self.source_id,
            "source_kind": self.source_kind.value,
            "source_sha256": self.source_sha256,
            "eligibility": self.eligibility.value,
            "static_eligibility_facts_sha256": (
                self.static_eligibility_facts_sha256
            ),
        }

    @classmethod
    def from_document(cls, value: object) -> BaselineCandidate:
        document = require_exact_keys(
            value,
            required=(
                "source_id",
                "source_kind",
                "source_sha256",
                "eligibility",
                "static_eligibility_facts_sha256",
            ),
            where="baseline candidate",
        )
        return cls(
            source_id=document["source_id"],
            source_kind=_enum_value(
                BaselineSourceKind,
                document["source_kind"],
                "baseline candidate source_kind",
            ),
            source_sha256=document["source_sha256"],
            eligibility=_enum_value(
                BaselineEligibility,
                document["eligibility"],
                "baseline candidate eligibility",
            ),
            static_eligibility_facts_sha256=document[
                "static_eligibility_facts_sha256"
            ],
        )


@dataclass(frozen=True)
class BaselineSelectionReceipt:
    """Result-blind baseline selection frozen before an experiment template.

    The schema intentionally has no observation or template reference.  A
    template may reference this receipt, but the receipt cannot reference the
    template and therefore cannot form a hash cycle.
    """

    validation_instance_id: str
    profile: ContractRef
    case_plan: ContractRef
    oracle_spec: ContractRef
    baseline_policy: ContractRef
    healthy_relation: ContractRef
    static_selection_inputs_sha256: str
    candidates: tuple[BaselineCandidate, ...]
    selected_source_id: str

    def __post_init__(self) -> None:
        validate_sha256(self.validation_instance_id, "validation_instance_id")
        _require_ref(self.profile, ContractRefKind.FROZEN_PROFILE, "profile")
        _require_ref(self.case_plan, ContractRefKind.CASE_PLAN, "case_plan")
        _require_ref(self.oracle_spec, ContractRefKind.ORACLE_SPEC, "oracle_spec")
        _require_ref(
            self.baseline_policy,
            ContractRefKind.BASELINE_POLICY,
            "baseline_policy",
        )
        _require_ref(
            self.healthy_relation,
            ContractRefKind.HEALTHY_RELATION_POLICY,
            "healthy_relation",
        )
        validate_sha256(
            self.static_selection_inputs_sha256,
            "static_selection_inputs_sha256",
        )
        if type(self.candidates) not in (tuple, list):
            raise ContractError("candidates must be an ordered collection")
        candidates = tuple(self.candidates)
        if not candidates:
            raise ContractError("candidates must not be empty")
        if len(candidates) > _MAX_BASELINE_CANDIDATES:
            raise ContractError(
                "candidates must not contain more than "
                f"{_MAX_BASELINE_CANDIDATES} values"
            )
        if any(type(candidate) is not BaselineCandidate for candidate in candidates):
            raise ContractError("candidates must contain BaselineCandidate values")
        source_ids = tuple(candidate.source_id for candidate in candidates)
        if len(source_ids) != len(set(source_ids)):
            raise ContractError("candidates must not repeat source_id")
        selected_source_id = validate_identifier(
            self.selected_source_id,
            "selected_source_id",
        )
        if selected_source_id not in source_ids:
            raise ContractError("selected_source_id must name a baseline candidate")
        selected_index = source_ids.index(selected_source_id)
        if candidates[selected_index].eligibility is not BaselineEligibility.ELIGIBLE:
            raise ContractError("the selected baseline source must be eligible")
        if any(
            candidate.eligibility is not BaselineEligibility.INELIGIBLE
            for candidate in candidates[:selected_index]
        ):
            raise ContractError(
                "the selected baseline must be the first eligible fallback source"
            )
        object.__setattr__(self, "candidates", candidates)

    def to_document(self) -> dict[str, object]:
        return {
            "contract_kind": _BASELINE_RECEIPT_KIND,
            "schema_version": _SCHEMA_VERSION,
            "validation_instance_id": self.validation_instance_id,
            "profile": self.profile.to_document(),
            "case_plan": self.case_plan.to_document(),
            "oracle_spec": self.oracle_spec.to_document(),
            "baseline_policy": self.baseline_policy.to_document(),
            "healthy_relation": self.healthy_relation.to_document(),
            "static_selection_inputs_sha256": self.static_selection_inputs_sha256,
            "candidates": [candidate.to_document() for candidate in self.candidates],
            "selected_source_id": self.selected_source_id,
        }

    @classmethod
    def from_document(cls, value: object) -> BaselineSelectionReceipt:
        document = require_exact_keys(
            value,
            required=(
                "contract_kind",
                "schema_version",
                "validation_instance_id",
                "profile",
                "case_plan",
                "oracle_spec",
                "baseline_policy",
                "healthy_relation",
                "static_selection_inputs_sha256",
                "candidates",
                "selected_source_id",
            ),
            where="baseline selection receipt",
        )
        if document["contract_kind"] != _BASELINE_RECEIPT_KIND:
            raise ContractError(
                "baseline selection receipt contract_kind must be "
                f"{_BASELINE_RECEIPT_KIND!r}"
            )
        if (
            type(document["schema_version"]) is not int
            or document["schema_version"] != _SCHEMA_VERSION
        ):
            raise ContractError(
                "baseline selection receipt schema_version must be integer 1"
            )
        candidate_documents = document["candidates"]
        if type(candidate_documents) is not list:
            raise ContractError("baseline selection candidates must be a list")
        return cls(
            validation_instance_id=document["validation_instance_id"],
            profile=_ref_from_document(
                document["profile"], ContractRefKind.FROZEN_PROFILE, "profile"
            ),
            case_plan=_ref_from_document(
                document["case_plan"], ContractRefKind.CASE_PLAN, "case_plan"
            ),
            oracle_spec=_ref_from_document(
                document["oracle_spec"], ContractRefKind.ORACLE_SPEC, "oracle_spec"
            ),
            baseline_policy=_ref_from_document(
                document["baseline_policy"],
                ContractRefKind.BASELINE_POLICY,
                "baseline_policy",
            ),
            healthy_relation=_ref_from_document(
                document["healthy_relation"],
                ContractRefKind.HEALTHY_RELATION_POLICY,
                "healthy_relation",
            ),
            static_selection_inputs_sha256=document[
                "static_selection_inputs_sha256"
            ],
            candidates=tuple(
                BaselineCandidate.from_document(candidate)
                for candidate in candidate_documents
            ),
            selected_source_id=document["selected_source_id"],
        )

    @classmethod
    def from_json(cls, payload: object) -> BaselineSelectionReceipt:
        return cls.from_document(load_strict_json_object(payload))

    @property
    def content_sha256(self) -> str:
        return canonical_sha256(self.to_document())

    @property
    def ref(self) -> ContractRef:
        return ContractRef(
            kind=ContractRefKind.BASELINE_SELECTION_RECEIPT,
            contract_id=self.content_sha256,
            contract_version=_CONTENT_REF_VERSION,
            content_sha256=self.content_sha256,
        )


@dataclass(frozen=True)
class PlannedOracleExecution:
    """Fully resolved Oracle execution facts embedded in a template."""

    oracle_spec: ContractRef
    collectors: tuple[ContractRef, ...]
    normalizer: ContractRef
    comparator: ContractRef
    protocol: ExecutionProtocol
    fixed_seed: int
    reset_policy: ContractRef
    baseline_selection: ContractRef | None

    def __post_init__(self) -> None:
        _require_ref(self.oracle_spec, ContractRefKind.ORACLE_SPEC, "oracle_spec")
        object.__setattr__(
            self,
            "collectors",
            _normalize_refs(
                self.collectors,
                ContractRefKind.COLLECTOR,
                "collectors",
                maximum=_MAX_COLLECTORS,
            ),
        )
        _require_ref(self.normalizer, ContractRefKind.NORMALIZER, "normalizer")
        _require_ref(self.comparator, ContractRefKind.COMPARATOR, "comparator")
        if type(self.protocol) is not ExecutionProtocol:
            raise ContractError("protocol must be an ExecutionProtocol")
        validate_non_negative_int(
            self.fixed_seed,
            "fixed_seed",
            maximum=_MAX_SEED,
        )
        _require_ref(self.reset_policy, ContractRefKind.RESET_POLICY, "reset_policy")
        if self.baseline_selection is not None:
            _require_ref(
                self.baseline_selection,
                ContractRefKind.BASELINE_SELECTION_RECEIPT,
                "baseline_selection",
            )

    def to_document(self) -> dict[str, object]:
        return {
            "oracle_spec": self.oracle_spec.to_document(),
            "collectors": [reference.to_document() for reference in self.collectors],
            "normalizer": self.normalizer.to_document(),
            "comparator": self.comparator.to_document(),
            "protocol": self.protocol.to_document(),
            "fixed_seed": self.fixed_seed,
            "reset_policy": self.reset_policy.to_document(),
            "baseline_selection": (
                None
                if self.baseline_selection is None
                else self.baseline_selection.to_document()
            ),
        }

    @classmethod
    def from_document(cls, value: object) -> PlannedOracleExecution:
        document = require_exact_keys(
            value,
            required=(
                "oracle_spec",
                "collectors",
                "normalizer",
                "comparator",
                "protocol",
                "fixed_seed",
                "reset_policy",
                "baseline_selection",
            ),
            where="planned oracle execution",
        )
        baseline = document["baseline_selection"]
        return cls(
            oracle_spec=_ref_from_document(
                document["oracle_spec"], ContractRefKind.ORACLE_SPEC, "oracle_spec"
            ),
            collectors=_refs_from_document(
                document["collectors"],
                ContractRefKind.COLLECTOR,
                "collectors",
                maximum=_MAX_COLLECTORS,
            ),
            normalizer=_ref_from_document(
                document["normalizer"],
                ContractRefKind.NORMALIZER,
                "normalizer",
            ),
            comparator=_ref_from_document(
                document["comparator"],
                ContractRefKind.COMPARATOR,
                "comparator",
            ),
            protocol=ExecutionProtocol.from_document(document["protocol"]),
            fixed_seed=document["fixed_seed"],
            reset_policy=_ref_from_document(
                document["reset_policy"],
                ContractRefKind.RESET_POLICY,
                "reset_policy",
            ),
            baseline_selection=(
                None
                if baseline is None
                else _ref_from_document(
                    baseline,
                    ContractRefKind.BASELINE_SELECTION_RECEIPT,
                    "baseline_selection",
                )
            ),
        )


@dataclass(frozen=True)
class ExperimentStep:
    """One ordered logical recipe invocation in an experiment template."""

    step_id: str
    phase: ExperimentPhase
    execution_recipe: ContractRef
    variant_id: str | None
    variant_role: VariantRole | None
    oracle_spec: ContractRef | None
    depends_on: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        validate_identifier(self.step_id, "step_id")
        if type(self.phase) is not ExperimentPhase:
            raise ContractError("phase must be an ExperimentPhase")
        _require_ref(
            self.execution_recipe,
            ContractRefKind.EXECUTION_RECIPE,
            "execution_recipe",
        )
        if self.variant_id is not None:
            validate_identifier(self.variant_id, "variant_id")
        if self.variant_role is not None and type(self.variant_role) is not VariantRole:
            raise ContractError("variant_role must be a VariantRole or None")
        if self.oracle_spec is not None:
            _require_ref(
                self.oracle_spec,
                ContractRefKind.ORACLE_SPEC,
                "oracle_spec",
            )
        oracle_fields = (self.variant_id, self.variant_role, self.oracle_spec)
        if any(value is not None for value in oracle_fields) and any(
            value is None for value in oracle_fields
        ):
            raise ContractError(
                "variant_id, variant_role, and oracle_spec must be supplied together"
            )
        if self.phase in (
            ExperimentPhase.ORACLE_EXPERIMENT,
            ExperimentPhase.CAUSAL_CONTROL,
            ExperimentPhase.REPAIR_ORACLE_EXPERIMENT,
        ) and any(value is None for value in oracle_fields):
            raise ContractError(
                f"{self.phase.value} requires all Oracle variant fields"
            )
        if self.phase not in (
            ExperimentPhase.ORACLE_EXPERIMENT,
            ExperimentPhase.CAUSAL_CONTROL,
            ExperimentPhase.REPAIR_ORACLE_EXPERIMENT,
        ) and any(value is not None for value in oracle_fields):
            raise ContractError(
                f"{self.phase.value} must not carry Oracle variant fields"
            )
        if (
            self.phase is ExperimentPhase.CAUSAL_CONTROL
            and self.variant_role is not VariantRole.CONTROL
        ):
            raise ContractError("causal_control requires a control variant role")
        if type(self.depends_on) not in (tuple, list):
            raise ContractError("depends_on must be a collection of step ids")
        dependencies = tuple(
            validate_identifier(dependency, "depends_on")
            for dependency in self.depends_on
        )
        if len(dependencies) > _MAX_DEPENDENCIES:
            raise ContractError(
                f"depends_on must not contain more than {_MAX_DEPENDENCIES} values"
            )
        if len(dependencies) != len(set(dependencies)):
            raise ContractError("depends_on must not contain duplicate step ids")
        if self.step_id in dependencies:
            raise ContractError("an experiment step cannot depend on itself")
        object.__setattr__(self, "depends_on", tuple(sorted(dependencies)))

    def to_document(self) -> dict[str, object]:
        return {
            "step_id": self.step_id,
            "phase": self.phase.value,
            "execution_recipe": self.execution_recipe.to_document(),
            "variant_id": self.variant_id,
            "variant_role": (
                None if self.variant_role is None else self.variant_role.value
            ),
            "oracle_spec": (
                None if self.oracle_spec is None else self.oracle_spec.to_document()
            ),
            "depends_on": list(self.depends_on),
        }

    @classmethod
    def from_document(cls, value: object) -> ExperimentStep:
        document = require_exact_keys(
            value,
            required=(
                "step_id",
                "phase",
                "execution_recipe",
                "variant_id",
                "variant_role",
                "oracle_spec",
                "depends_on",
            ),
            where="experiment step",
        )
        variant_id = document["variant_id"]
        if variant_id is not None and type(variant_id) is not str:
            raise ContractError("experiment step variant_id must be a string or null")
        oracle_spec = document["oracle_spec"]
        variant_role = document["variant_role"]
        dependencies = document["depends_on"]
        if type(dependencies) is not list:
            raise ContractError("experiment step depends_on must be a list")
        return cls(
            step_id=document["step_id"],
            phase=_enum_value(
                ExperimentPhase,
                document["phase"],
                "experiment step phase",
            ),
            execution_recipe=_ref_from_document(
                document["execution_recipe"],
                ContractRefKind.EXECUTION_RECIPE,
                "execution_recipe",
            ),
            variant_id=variant_id,
            variant_role=(
                None
                if variant_role is None
                else _enum_value(
                    VariantRole,
                    variant_role,
                    "experiment step variant_role",
                )
            ),
            oracle_spec=(
                None
                if oracle_spec is None
                else _ref_from_document(
                    oracle_spec,
                    ContractRefKind.ORACLE_SPEC,
                    "oracle_spec",
                )
            ),
            depends_on=tuple(dependencies),
        )


@dataclass(frozen=True)
class DynamicBindingRequest:
    """A symbolic resource request; it contains no physical allocation."""

    symbol: str
    resource_kind: DynamicResourceKind
    equivalence_policy: ContractRef

    def __post_init__(self) -> None:
        validate_identifier(self.symbol, "dynamic binding symbol")
        if type(self.resource_kind) is not DynamicResourceKind:
            raise ContractError("resource_kind must be a DynamicResourceKind")
        _require_ref(
            self.equivalence_policy,
            ContractRefKind.EXECUTION_EQUIVALENCE_POLICY,
            "equivalence_policy",
        )

    def to_document(self) -> dict[str, object]:
        return {
            "symbol": self.symbol,
            "resource_kind": self.resource_kind.value,
            "equivalence_policy": self.equivalence_policy.to_document(),
        }

    @classmethod
    def from_document(cls, value: object) -> DynamicBindingRequest:
        document = require_exact_keys(
            value,
            required=("symbol", "resource_kind", "equivalence_policy"),
            where="dynamic binding request",
        )
        return cls(
            symbol=document["symbol"],
            resource_kind=_enum_value(
                DynamicResourceKind,
                document["resource_kind"],
                "dynamic binding request resource_kind",
            ),
            equivalence_policy=_ref_from_document(
                document["equivalence_policy"],
                ContractRefKind.EXECUTION_EQUIVALENCE_POLICY,
                "equivalence_policy",
            ),
        )


@dataclass(frozen=True)
class ExperimentPlanTemplate:
    """Stable, role-independent experiment plan materialized before results."""

    validation_instance_id: str
    profile: ContractRef
    case_plan: ContractRef
    adapter: ContractRef
    oracle_bundle: ContractRef
    oracle_executions: tuple[PlannedOracleExecution, ...]
    steps: tuple[ExperimentStep, ...]
    dynamic_requests: tuple[DynamicBindingRequest, ...]

    def __post_init__(self) -> None:
        validate_sha256(self.validation_instance_id, "validation_instance_id")
        _require_ref(self.profile, ContractRefKind.FROZEN_PROFILE, "profile")
        _require_ref(self.case_plan, ContractRefKind.CASE_PLAN, "case_plan")
        _require_ref(self.adapter, ContractRefKind.ADAPTER, "adapter")
        _require_ref(
            self.oracle_bundle,
            ContractRefKind.ORACLE_BUNDLE,
            "oracle_bundle",
        )

        if type(self.oracle_executions) not in (tuple, list):
            raise ContractError("oracle_executions must be a collection")
        oracle_executions = tuple(self.oracle_executions)
        if not oracle_executions:
            raise ContractError("oracle_executions must not be empty")
        if len(oracle_executions) > _MAX_ORACLE_PLANS:
            raise ContractError(
                "oracle_executions must not contain more than "
                f"{_MAX_ORACLE_PLANS} values"
            )
        if any(
            type(execution) is not PlannedOracleExecution
            for execution in oracle_executions
        ):
            raise ContractError(
                "oracle_executions must contain PlannedOracleExecution values"
            )
        oracle_refs = tuple(execution.oracle_spec for execution in oracle_executions)
        oracle_identities = tuple(
            (reference.contract_id, reference.contract_version)
            for reference in oracle_refs
        )
        if len(oracle_identities) != len(set(oracle_identities)):
            raise ContractError("oracle_executions must not repeat an OracleSpec")
        baseline_refs = tuple(
            execution.baseline_selection
            for execution in oracle_executions
            if execution.baseline_selection is not None
        )
        if len(baseline_refs) != len(set(baseline_refs)):
            raise ContractError(
                "one baseline receipt cannot satisfy multiple Oracle executions"
            )
        object.__setattr__(
            self,
            "oracle_executions",
            tuple(
                sorted(
                    oracle_executions,
                    key=lambda execution: _ref_sort_key(execution.oracle_spec),
                )
            ),
        )

        if type(self.steps) not in (tuple, list):
            raise ContractError("steps must be a non-empty ordered collection")
        steps = tuple(self.steps)
        if not steps:
            raise ContractError("steps must not be empty")
        if len(steps) > _MAX_STEPS:
            raise ContractError(f"steps must not contain more than {_MAX_STEPS} values")
        if any(type(step) is not ExperimentStep for step in steps):
            raise ContractError("steps must contain ExperimentStep values")
        allowed_oracles = set(oracle_refs)
        seen: set[str] = set()
        for index, step in enumerate(steps):
            if step.step_id in seen:
                raise ContractError(f"steps must not repeat step_id {step.step_id}")
            unavailable = tuple(
                dependency for dependency in step.depends_on if dependency not in seen
            )
            if unavailable:
                raise ContractError(
                    f"steps[{index}].depends_on must reference only prior steps"
                )
            if step.oracle_spec is not None and step.oracle_spec not in allowed_oracles:
                raise ContractError(
                    f"steps[{index}] references an OracleSpec outside oracle_executions"
                )
            seen.add(step.step_id)
        object.__setattr__(self, "steps", steps)

        if type(self.dynamic_requests) not in (tuple, list):
            raise ContractError("dynamic_requests must be a collection")
        requests = tuple(self.dynamic_requests)
        if len(requests) > _MAX_DYNAMIC_RESOURCES:
            raise ContractError(
                "dynamic_requests must not contain more than "
                f"{_MAX_DYNAMIC_RESOURCES} values"
            )
        if any(type(request) is not DynamicBindingRequest for request in requests):
            raise ContractError(
                "dynamic_requests must contain DynamicBindingRequest values"
            )
        symbols = tuple(request.symbol for request in requests)
        if len(symbols) != len(set(symbols)):
            raise ContractError("dynamic_requests must not repeat a symbol")
        workspace_requests = tuple(
            request
            for request in requests
            if request.resource_kind is DynamicResourceKind.WORKSPACE
        )
        if len(workspace_requests) != 1:
            raise ContractError(
                "dynamic_requests must contain exactly one workspace request"
            )
        if workspace_requests[0].symbol != "workspace.project":
            raise ContractError(
                "the workspace request symbol must be 'workspace.project'"
            )
        object.__setattr__(
            self,
            "dynamic_requests",
            tuple(sorted(requests, key=lambda request: request.symbol)),
        )

    @property
    def baseline_selection_refs(self) -> tuple[ContractRef, ...]:
        return tuple(
            execution.baseline_selection
            for execution in self.oracle_executions
            if execution.baseline_selection is not None
        )

    @property
    def oracle_spec_refs(self) -> tuple[ContractRef, ...]:
        return tuple(execution.oracle_spec for execution in self.oracle_executions)

    @property
    def execution_recipe_refs(self) -> tuple[ContractRef, ...]:
        return tuple(
            sorted({step.execution_recipe for step in self.steps}, key=_ref_sort_key)
        )

    def to_document(self) -> dict[str, object]:
        return {
            "contract_kind": _EXPERIMENT_TEMPLATE_KIND,
            "schema_version": _SCHEMA_VERSION,
            "validation_instance_id": self.validation_instance_id,
            "profile": self.profile.to_document(),
            "case_plan": self.case_plan.to_document(),
            "adapter": self.adapter.to_document(),
            "oracle_bundle": self.oracle_bundle.to_document(),
            "oracle_executions": [
                execution.to_document() for execution in self.oracle_executions
            ],
            "steps": [step.to_document() for step in self.steps],
            "dynamic_requests": [
                request.to_document() for request in self.dynamic_requests
            ],
        }

    @classmethod
    def from_document(cls, value: object) -> ExperimentPlanTemplate:
        document = require_exact_keys(
            value,
            required=(
                "contract_kind",
                "schema_version",
                "validation_instance_id",
                "profile",
                "case_plan",
                "adapter",
                "oracle_bundle",
                "oracle_executions",
                "steps",
                "dynamic_requests",
            ),
            where="experiment plan template",
        )
        if document["contract_kind"] != _EXPERIMENT_TEMPLATE_KIND:
            raise ContractError(
                "experiment plan template contract_kind must be "
                f"{_EXPERIMENT_TEMPLATE_KIND!r}"
            )
        if (
            type(document["schema_version"]) is not int
            or document["schema_version"] != _SCHEMA_VERSION
        ):
            raise ContractError(
                "experiment plan template schema_version must be integer 1"
            )
        oracle_documents = document["oracle_executions"]
        step_documents = document["steps"]
        request_documents = document["dynamic_requests"]
        if type(oracle_documents) is not list:
            raise ContractError("oracle_executions must be a list")
        if type(step_documents) is not list:
            raise ContractError("steps must be a list")
        if type(request_documents) is not list:
            raise ContractError("dynamic_requests must be a list")
        return cls(
            validation_instance_id=document["validation_instance_id"],
            profile=_ref_from_document(
                document["profile"], ContractRefKind.FROZEN_PROFILE, "profile"
            ),
            case_plan=_ref_from_document(
                document["case_plan"], ContractRefKind.CASE_PLAN, "case_plan"
            ),
            adapter=_ref_from_document(
                document["adapter"], ContractRefKind.ADAPTER, "adapter"
            ),
            oracle_bundle=_ref_from_document(
                document["oracle_bundle"],
                ContractRefKind.ORACLE_BUNDLE,
                "oracle_bundle",
            ),
            oracle_executions=tuple(
                PlannedOracleExecution.from_document(item)
                for item in oracle_documents
            ),
            steps=tuple(ExperimentStep.from_document(item) for item in step_documents),
            dynamic_requests=tuple(
                DynamicBindingRequest.from_document(item)
                for item in request_documents
            ),
        )

    @classmethod
    def from_json(cls, payload: object) -> ExperimentPlanTemplate:
        return cls.from_document(load_strict_json_object(payload))

    @property
    def content_sha256(self) -> str:
        return canonical_sha256(self.to_document())

    @property
    def ref(self) -> ContractRef:
        return ContractRef(
            kind=ContractRefKind.EXPERIMENT_PLAN_TEMPLATE,
            contract_id=self.content_sha256,
            contract_version=_CONTENT_REF_VERSION,
            content_sha256=self.content_sha256,
        )


@dataclass(frozen=True)
class DynamicResourceBinding:
    """One closed, broker-produced dynamic resource allocation.

    ``loopback_port`` is mandatory only for LOOPBACK_PORT and forbidden for
    every other kind.  Other dynamic values are represented by opaque,
    non-executable allocation identifiers plus exact fingerprints.
    """

    symbol: str
    resource_kind: DynamicResourceKind
    broker_id: str
    allocation_id: str
    resource_fingerprint_sha256: str
    equivalence_policy: ContractRef
    equivalence_fingerprint_sha256: str
    loopback_port: int | None

    def __post_init__(self) -> None:
        validate_identifier(self.symbol, "dynamic resource symbol")
        if type(self.resource_kind) is not DynamicResourceKind:
            raise ContractError("resource_kind must be a DynamicResourceKind")
        validate_identifier(self.broker_id, "broker_id")
        validate_identifier(self.allocation_id, "allocation_id")
        validate_sha256(
            self.resource_fingerprint_sha256,
            "resource_fingerprint_sha256",
        )
        _require_ref(
            self.equivalence_policy,
            ContractRefKind.EXECUTION_EQUIVALENCE_POLICY,
            "equivalence_policy",
        )
        validate_sha256(
            self.equivalence_fingerprint_sha256,
            "equivalence_fingerprint_sha256",
        )
        if self.resource_kind is DynamicResourceKind.LOOPBACK_PORT:
            validate_positive_int(
                self.loopback_port,
                "loopback_port",
                maximum=_MAX_LOOPBACK_PORT,
            )
        elif self.loopback_port is not None:
            raise ContractError(
                "loopback_port is permitted only for a loopback_port resource"
            )

    def to_document(self) -> dict[str, object]:
        return {
            "symbol": self.symbol,
            "resource_kind": self.resource_kind.value,
            "broker_id": self.broker_id,
            "allocation_id": self.allocation_id,
            "resource_fingerprint_sha256": self.resource_fingerprint_sha256,
            "equivalence_policy": self.equivalence_policy.to_document(),
            "equivalence_fingerprint_sha256": (
                self.equivalence_fingerprint_sha256
            ),
            "loopback_port": self.loopback_port,
        }

    @classmethod
    def from_document(cls, value: object) -> DynamicResourceBinding:
        document = require_exact_keys(
            value,
            required=(
                "symbol",
                "resource_kind",
                "broker_id",
                "allocation_id",
                "resource_fingerprint_sha256",
                "equivalence_policy",
                "equivalence_fingerprint_sha256",
                "loopback_port",
            ),
            where="dynamic resource binding",
        )
        port = document["loopback_port"]
        if port is not None and type(port) is not int:
            raise ContractError("loopback_port must be an exact integer or null")
        return cls(
            symbol=document["symbol"],
            resource_kind=_enum_value(
                DynamicResourceKind,
                document["resource_kind"],
                "dynamic resource binding resource_kind",
            ),
            broker_id=document["broker_id"],
            allocation_id=document["allocation_id"],
            resource_fingerprint_sha256=document[
                "resource_fingerprint_sha256"
            ],
            equivalence_policy=_ref_from_document(
                document["equivalence_policy"],
                ContractRefKind.EXECUTION_EQUIVALENCE_POLICY,
                "equivalence_policy",
            ),
            equivalence_fingerprint_sha256=document[
                "equivalence_fingerprint_sha256"
            ],
            loopback_port=port,
        )


@dataclass(frozen=True)
class ExecutionBinding:
    """Role-local broker allocations bound to one stable template."""

    validation_instance_id: str
    attempt_id: str
    role: GateRole
    template: ContractRef
    resources: tuple[DynamicResourceBinding, ...]
    broker_receipt_sha256: str

    def __post_init__(self) -> None:
        validate_sha256(self.validation_instance_id, "validation_instance_id")
        validate_identifier(self.attempt_id, "attempt_id")
        if type(self.role) is not GateRole:
            raise ContractError("role must be a GateRole")
        _require_ref(
            self.template,
            ContractRefKind.EXPERIMENT_PLAN_TEMPLATE,
            "template",
        )
        if type(self.resources) not in (tuple, list):
            raise ContractError("resources must be a collection")
        resources = tuple(self.resources)
        if len(resources) > _MAX_DYNAMIC_RESOURCES:
            raise ContractError(
                f"resources must not contain more than {_MAX_DYNAMIC_RESOURCES} values"
            )
        if any(type(resource) is not DynamicResourceBinding for resource in resources):
            raise ContractError(
                "resources must contain DynamicResourceBinding values"
            )
        symbols = tuple(resource.symbol for resource in resources)
        if len(symbols) != len(set(symbols)):
            raise ContractError("resources must not repeat a symbol")
        allocation_ids = tuple(resource.allocation_id for resource in resources)
        if len(allocation_ids) != len(set(allocation_ids)):
            raise ContractError("resources must not repeat allocation_id")
        loopback_ports = tuple(
            resource.loopback_port
            for resource in resources
            if resource.resource_kind is DynamicResourceKind.LOOPBACK_PORT
        )
        if len(loopback_ports) != len(set(loopback_ports)):
            raise ContractError("resources must not repeat a loopback_port")
        object.__setattr__(
            self,
            "resources",
            tuple(sorted(resources, key=lambda resource: resource.symbol)),
        )
        validate_sha256(self.broker_receipt_sha256, "broker_receipt_sha256")

    def to_document(self) -> dict[str, object]:
        return {
            "contract_kind": _EXECUTION_BINDING_KIND,
            "schema_version": _SCHEMA_VERSION,
            "validation_instance_id": self.validation_instance_id,
            "attempt_id": self.attempt_id,
            "role": self.role.value,
            "template": self.template.to_document(),
            "resources": [resource.to_document() for resource in self.resources],
            "broker_receipt_sha256": self.broker_receipt_sha256,
        }

    @classmethod
    def from_document(cls, value: object) -> ExecutionBinding:
        document = require_exact_keys(
            value,
            required=(
                "contract_kind",
                "schema_version",
                "validation_instance_id",
                "attempt_id",
                "role",
                "template",
                "resources",
                "broker_receipt_sha256",
            ),
            where="execution binding",
        )
        if document["contract_kind"] != _EXECUTION_BINDING_KIND:
            raise ContractError(
                f"execution binding contract_kind must be {_EXECUTION_BINDING_KIND!r}"
            )
        if (
            type(document["schema_version"]) is not int
            or document["schema_version"] != _SCHEMA_VERSION
        ):
            raise ContractError("execution binding schema_version must be integer 1")
        resources = document["resources"]
        if type(resources) is not list:
            raise ContractError("execution binding resources must be a list")
        return cls(
            validation_instance_id=document["validation_instance_id"],
            attempt_id=document["attempt_id"],
            role=_enum_value(GateRole, document["role"], "execution binding role"),
            template=_ref_from_document(
                document["template"],
                ContractRefKind.EXPERIMENT_PLAN_TEMPLATE,
                "template",
            ),
            resources=tuple(
                DynamicResourceBinding.from_document(resource)
                for resource in resources
            ),
            broker_receipt_sha256=document["broker_receipt_sha256"],
        )

    @classmethod
    def from_json(cls, payload: object) -> ExecutionBinding:
        return cls.from_document(load_strict_json_object(payload))

    @property
    def content_sha256(self) -> str:
        return canonical_sha256(self.to_document())

    @property
    def ref(self) -> ContractRef:
        return ContractRef(
            kind=ContractRefKind.EXECUTION_BINDING,
            contract_id=self.content_sha256,
            contract_version=_CONTENT_REF_VERSION,
            content_sha256=self.content_sha256,
        )


def validate_template_baseline_selections(
    template: ExperimentPlanTemplate,
    receipts: Iterable[BaselineSelectionReceipt],
) -> None:
    """Check exact receipt membership and the one-way frozen identity bindings."""

    if type(template) is not ExperimentPlanTemplate:
        raise ContractError("template must be an ExperimentPlanTemplate")
    receipt_values = tuple(receipts)
    if any(type(receipt) is not BaselineSelectionReceipt for receipt in receipt_values):
        raise ContractError("receipts must contain BaselineSelectionReceipt values")
    refs = tuple(sorted((receipt.ref for receipt in receipt_values), key=_ref_sort_key))
    expected_refs = tuple(sorted(template.baseline_selection_refs, key=_ref_sort_key))
    if refs != expected_refs:
        raise ContractError(
            "baseline receipts do not exactly match template membership"
        )
    planned_by_baseline = {
        execution.baseline_selection: execution
        for execution in template.oracle_executions
        if execution.baseline_selection is not None
    }
    for receipt in receipt_values:
        planned = planned_by_baseline[receipt.ref]
        if receipt.validation_instance_id != template.validation_instance_id:
            raise ContractError("baseline receipt validation instance mismatch")
        if receipt.profile != template.profile:
            raise ContractError("baseline receipt profile mismatch")
        if receipt.case_plan != template.case_plan:
            raise ContractError("baseline receipt CasePlan mismatch")
        if receipt.oracle_spec != planned.oracle_spec:
            raise ContractError("baseline receipt OracleSpec mismatch")


def validate_experiment_plan_membership(
    template: ExperimentPlanTemplate,
    *,
    profile: FrozenSystemProfile,
    case_plan: CasePlan,
    adapter: ContractRef,
    oracle_bundle: OracleBundle,
    oracle_specs: Iterable[OracleSpec],
    baseline_receipts: Iterable[BaselineSelectionReceipt],
) -> None:
    """Validate the complete frozen object graph selected for one experiment.

    ``validate_case_plan_membership`` is a required predecessor: it validates
    target-evidence, causal-control, repair, entrypoint, workload, and primary
    recipe selection against authority-owned identity.  This function then
    verifies that deterministic materialization neither drops nor invents any
    selected Oracle variant, execution component, baseline, or dynamic policy.
    Recipe membership here is only a closed Profile allowlist check. Semantic
    authorization of a non-Oracle phase/recipe pair belongs to the approved
    Adapter manifest and materialization boundary, which this pure contract
    layer deliberately does not load. This function performs no registry
    lookup, execution, allocation, or observation.
    """

    from .case import CasePlan
    from .oracle import OracleBundle, OracleSpec
    from .profile import FrozenSystemProfile

    if type(template) is not ExperimentPlanTemplate:
        raise ContractError("template must be an ExperimentPlanTemplate")
    if type(profile) is not FrozenSystemProfile:
        raise ContractError("profile must be a FrozenSystemProfile")
    if type(case_plan) is not CasePlan:
        raise ContractError("case_plan must be a CasePlan")
    if type(oracle_bundle) is not OracleBundle:
        raise ContractError("oracle_bundle must be an OracleBundle")
    _require_ref(adapter, ContractRefKind.ADAPTER, "adapter")

    if template.validation_instance_id != case_plan.validation_instance_id:
        raise ContractError("template validation instance does not match CasePlan")
    if template.profile != profile.ref or case_plan.profile != profile.ref:
        raise ContractError("template or CasePlan does not exactly bind Profile")
    if template.case_plan != case_plan.ref:
        raise ContractError("template does not exactly bind CasePlan")
    if template.adapter != adapter or adapter not in profile.adapters:
        raise ContractError("template Adapter is not the selected Profile member")
    if (
        template.oracle_bundle != oracle_bundle.ref
        or case_plan.oracle_bundle != oracle_bundle.ref
        or oracle_bundle.ref not in profile.oracle_bundles
    ):
        raise ContractError("template does not exactly bind selected OracleBundle")

    specs = tuple(oracle_specs)
    if any(type(spec) is not OracleSpec for spec in specs):
        raise ContractError("oracle_specs must contain only OracleSpec values")
    specs_by_ref = {spec.ref: spec for spec in specs}
    if len(specs_by_ref) != len(specs):
        raise ContractError("oracle_specs must not contain duplicate references")
    if any(reference not in profile.oracle_specs for reference in specs_by_ref):
        raise ContractError("an OracleSpec is not an exact Profile member")

    pending = list(oracle_bundle.oracle_spec_refs)
    closure: set[ContractRef] = set()
    while pending:
        reference = pending.pop(0)
        if reference in closure:
            continue
        spec = specs_by_ref.get(reference)
        if spec is None:
            raise ContractError(
                "selected OracleBundle or dependent guard is unresolved"
            )
        closure.add(reference)
        pending.extend(spec.dependent_oracle_spec_refs)
    if set(specs_by_ref) != closure:
        raise ContractError(
            "oracle_specs must exactly equal bundle and dependent guard closure"
        )
    if set(template.oracle_spec_refs) != closure:
        raise ContractError(
            "oracle_executions must exactly cover selected Oracle closure"
        )

    receipts = tuple(baseline_receipts)
    validate_template_baseline_selections(template, receipts)
    receipts_by_ref = {receipt.ref: receipt for receipt in receipts}
    planned_by_spec = {
        execution.oracle_spec: execution
        for execution in template.oracle_executions
    }
    profile_components = set(profile.components)
    for reference in closure:
        spec = specs_by_ref[reference]
        planned = planned_by_spec[reference]
        if planned.collectors != spec.collectors:
            raise ContractError(
                f"planned collectors do not match OracleSpec {spec.oracle_id}"
            )
        if planned.normalizer != spec.normalizer:
            raise ContractError(
                f"planned normalizer does not match OracleSpec {spec.oracle_id}"
            )
        if planned.comparator != spec.comparator:
            raise ContractError(
                f"planned comparator does not match OracleSpec {spec.oracle_id}"
            )
        if planned.protocol != spec.execution_protocol:
            raise ContractError(
                f"planned protocol does not match OracleSpec {spec.oracle_id}"
            )
        frozen_components = (
            *planned.collectors,
            planned.normalizer,
            planned.comparator,
            planned.reset_policy,
        )
        if any(component not in profile_components for component in frozen_components):
            raise ContractError(
                f"planned Oracle {spec.oracle_id} uses components outside Profile"
            )

        if spec.baseline_policy is None:
            if planned.baseline_selection is not None:
                raise ContractError(
                    f"OracleSpec {spec.oracle_id} forbids a baseline receipt"
                )
            continue
        if planned.baseline_selection is None:
            raise ContractError(
                f"OracleSpec {spec.oracle_id} requires a baseline receipt"
            )
        receipt = receipts_by_ref[planned.baseline_selection]
        if receipt.baseline_policy != spec.baseline_policy:
            raise ContractError(
                f"baseline policy does not match OracleSpec {spec.oracle_id}"
            )
        if receipt.healthy_relation != spec.healthy_relation:
            raise ContractError(
                f"baseline healthy relation does not match OracleSpec {spec.oracle_id}"
            )

    for request in template.dynamic_requests:
        if request.equivalence_policy not in profile_components:
            raise ContractError(
                f"dynamic request {request.symbol} uses policy outside Profile"
            )

    phase_counts = {
        phase: sum(step.phase is phase for step in template.steps)
        for phase in ExperimentPhase
    }
    required_counts = {
        ExperimentPhase.SANDBOX_HEALTH: 1,
        ExperimentPhase.REAL_ENTRY_REPLAY: 1,
        ExperimentPhase.TARGET_EVIDENCE: 1,
        ExperimentPhase.REPAIR: 1 if case_plan.repair is not None else 0,
        ExperimentPhase.BUILD_SANITY: 1 if case_plan.repair is not None else 0,
        ExperimentPhase.REPAIR_REAL_ENTRY_REPLAY: (
            1 if case_plan.repair is not None else 0
        ),
        ExperimentPhase.REPAIR_TARGET_EVIDENCE: (
            1 if case_plan.repair is not None else 0
        ),
        ExperimentPhase.REGRESSION: 1 if case_plan.repair is not None else 0,
    }
    for phase, expected_count in required_counts.items():
        if phase_counts[phase] != expected_count:
            raise ContractError(
                "experiment phase grammar requires "
                f"{expected_count} {phase.value} step(s)"
            )
    phase_rank = {
        ExperimentPhase.SANDBOX_HEALTH: 0,
        ExperimentPhase.REAL_ENTRY_REPLAY: 1,
        ExperimentPhase.TARGET_EVIDENCE: 2,
        ExperimentPhase.ORACLE_EXPERIMENT: 3,
        ExperimentPhase.CAUSAL_CONTROL: 3,
        ExperimentPhase.REPAIR: 4,
        ExperimentPhase.BUILD_SANITY: 5,
        ExperimentPhase.REPAIR_REAL_ENTRY_REPLAY: 6,
        ExperimentPhase.REPAIR_TARGET_EVIDENCE: 7,
        ExperimentPhase.REPAIR_ORACLE_EXPERIMENT: 8,
        ExperimentPhase.REGRESSION: 9,
    }
    ranks = tuple(phase_rank[step.phase] for step in template.steps)
    if ranks != tuple(sorted(ranks)):
        raise ContractError("experiment phase grammar is out of order")

    expected_original_variants = {
        (spec.ref, variant.variant_id): variant
        for spec in specs
        for variant in spec.variants
    }
    # OracleSpec construction guarantees that ``variants`` is exactly the
    # typed method's inputs plus, when present, its causal-control input. L1
    # replays every method input. A causal-only control is the sole extra and
    # is inherited from L0 rather than rerun; a dual-role control remains a
    # method input and therefore is replayed.
    expected_repair_variants = {
        (spec.ref, variant.variant_id): variant
        for spec in specs
        for variant in spec.variants
        if case_plan.repair is not None
        and not (
            spec.control_evidence_role is ControlEvidenceRole.CAUSAL_ONLY
            and spec.causal_control is not None
            and variant.variant_id == spec.causal_control.control_variant_id
        )
    }
    mapped_original_variants: set[tuple[ContractRef, str]] = set()
    mapped_repair_variants: set[tuple[ContractRef, str]] = set()
    for index, step in enumerate(template.steps):
        if step.execution_recipe not in profile.execution_recipes:
            raise ContractError(f"steps[{index}] recipe is outside Profile")
        if step.oracle_spec is None:
            continue
        key = (step.oracle_spec, step.variant_id or "")
        is_repair_replay = (
            step.phase is ExperimentPhase.REPAIR_ORACLE_EXPERIMENT
        )
        expected_variants = (
            expected_repair_variants
            if is_repair_replay
            else expected_original_variants
        )
        mapped_variants = (
            mapped_repair_variants
            if is_repair_replay
            else mapped_original_variants
        )
        variant = expected_variants.get(key)
        if variant is None:
            raise ContractError(
                f"steps[{index}] invents an Oracle variant for its experiment region"
            )
        if key in mapped_variants:
            raise ContractError(
                f"steps[{index}] repeats an Oracle variant in one experiment region"
            )
        if step.variant_role is not variant.role:
            raise ContractError(f"steps[{index}] has the wrong Oracle variant role")
        if step.execution_recipe != variant.execution_recipe:
            raise ContractError(f"steps[{index}] has the wrong Oracle variant recipe")
        step_spec = specs_by_ref[step.oracle_spec]
        is_causal_control = (
            step_spec.causal_control is not None
            and variant.variant_id == step_spec.causal_control.control_variant_id
        )
        if is_repair_replay:
            expected_phase = ExperimentPhase.REPAIR_ORACLE_EXPERIMENT
        else:
            expected_phase = (
                ExperimentPhase.CAUSAL_CONTROL
                if is_causal_control
                else ExperimentPhase.ORACLE_EXPERIMENT
            )
        if step.phase is not expected_phase:
            raise ContractError(f"steps[{index}] has the wrong Oracle variant phase")
        mapped_variants.add(key)
    if mapped_original_variants != set(expected_original_variants):
        raise ContractError(
            "original experiment steps do not exactly cover Oracle variants"
        )
    if mapped_repair_variants != set(expected_repair_variants):
        raise ContractError(
            "repair experiment steps do not exactly cover Oracle method inputs"
        )


def validate_template_determinism(
    first: ExperimentPlanTemplate,
    second: ExperimentPlanTemplate,
) -> None:
    """Require independent materializations from frozen inputs to be identical."""

    if type(first) is not ExperimentPlanTemplate or type(second) is not ExperimentPlanTemplate:
        raise ContractError("both templates must be ExperimentPlanTemplate values")
    frozen_inputs = (
        "validation_instance_id",
        "profile",
        "case_plan",
        "adapter",
        "oracle_bundle",
    )
    if any(getattr(first, field) != getattr(second, field) for field in frozen_inputs):
        raise ContractError("experiment templates bind different frozen inputs")
    if first.content_sha256 != second.content_sha256:
        raise ContractError("experiment template materialization is non-deterministic")


def validate_execution_binding(
    template: ExperimentPlanTemplate,
    binding: ExecutionBinding,
) -> None:
    """Require one Binding to satisfy exactly the Template's dynamic requests."""

    if type(template) is not ExperimentPlanTemplate:
        raise ContractError("template must be an ExperimentPlanTemplate")
    if type(binding) is not ExecutionBinding:
        raise ContractError("binding must be an ExecutionBinding")
    if binding.validation_instance_id != template.validation_instance_id:
        raise ContractError("execution binding validation instance mismatch")
    if binding.template != template.ref:
        raise ContractError("execution binding template mismatch")
    requests = {request.symbol: request for request in template.dynamic_requests}
    resources = {resource.symbol: resource for resource in binding.resources}
    if set(resources) != set(requests):
        raise ContractError(
            "execution binding resources do not exactly match dynamic requests"
        )
    for symbol, request in requests.items():
        resource = resources[symbol]
        if resource.resource_kind is not request.resource_kind:
            raise ContractError(f"dynamic resource kind mismatch for {symbol}")
        if resource.equivalence_policy != request.equivalence_policy:
            raise ContractError(f"equivalence policy mismatch for {symbol}")


def validate_b1_b2_binding_equivalence(
    template: ExperimentPlanTemplate,
    b1: ExecutionBinding,
    b2: ExecutionBinding,
) -> None:
    """Purely verify two broker projections under frozen equivalence policies.

    The function does not execute an equivalence policy.  It compares the
    policy-specific fingerprints that an authorized broker produced and that
    each Binding hash-binds.
    """

    validate_execution_binding(template, b1)
    validate_execution_binding(template, b2)
    if b1.role is not GateRole.B1 or b2.role is not GateRole.B2:
        raise ContractError("binding equivalence requires ordered B1 and B2 roles")
    if b1.attempt_id != b2.attempt_id:
        raise ContractError("B1 and B2 bindings must belong to the same attempt")
    if b1.broker_receipt_sha256 == b2.broker_receipt_sha256:
        raise ContractError("B1 and B2 must bind independent broker receipts")
    b1_resources = {resource.symbol: resource for resource in b1.resources}
    b2_resources = {resource.symbol: resource for resource in b2.resources}
    reused_allocations = {
        resource.allocation_id for resource in b1.resources
    }.intersection(resource.allocation_id for resource in b2.resources)
    if reused_allocations:
        raise ContractError("B1 and B2 must not reuse allocation_id values")
    for request in template.dynamic_requests:
        left = b1_resources[request.symbol]
        right = b2_resources[request.symbol]
        if (
            request.resource_kind is DynamicResourceKind.WORKSPACE
            and left.resource_fingerprint_sha256
            == right.resource_fingerprint_sha256
        ):
            raise ContractError(
                "B1 and B2 workspaces must have independent resource fingerprints"
            )
        if (
            left.equivalence_fingerprint_sha256
            != right.equivalence_fingerprint_sha256
        ):
            raise ContractError(
                f"B1/B2 resource is outside equivalence policy for {request.symbol}"
            )

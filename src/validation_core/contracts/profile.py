"""Frozen, hash-bound system profiles and pure membership validation.

Profiles describe what a generic validation run may select.  They grant no
trust and perform no I/O: registry admission, execution, and observation are
separate boundaries implemented by later harness stages.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Iterable

from .base import (
    ContractError,
    canonical_sha256,
    load_strict_json_object,
    normalize_identifiers,
    require_exact_keys,
    validate_identifier,
    validate_sha256,
)
from .references import ContractRef, ContractRefKind

if TYPE_CHECKING:
    from .execution import ExecutionRecipe
    from .oracle import (
        ConsequenceDomain,
        ControlEvidenceRole,
        OracleBundle,
        OracleSpec,
    )


_PROFILE_CONTRACT_KIND = "validator_profile"
_PROFILE_SCHEMA_VERSION = 1
_MAX_PROFILE_ITEMS = 4096
_UTC_TIMESTAMP_RE = re.compile(
    r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z\Z"
)

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


def _require_contract_ref(
    value: object,
    expected_kind: ContractRefKind,
    field: str,
) -> ContractRef:
    if type(value) is not ContractRef:
        raise ContractError(f"{field} must be a ContractRef")
    if value.kind is not expected_kind:
        raise ContractError(f"{field} must reference {expected_kind.value}")
    return value


def _ref_sort_key(reference: ContractRef) -> tuple[str, str, str, str]:
    return (
        reference.kind.value,
        reference.contract_id,
        reference.contract_version,
        reference.content_sha256,
    )


def _normalize_refs(
    value: object,
    field: str,
    expected_kinds: frozenset[ContractRefKind],
    *,
    allow_empty: bool = False,
) -> tuple[ContractRef, ...]:
    if type(value) not in (tuple, list):
        raise ContractError(f"{field} must be a collection of ContractRef values")
    references = tuple(value)
    if len(references) > _MAX_PROFILE_ITEMS:
        raise ContractError(
            f"{field} must not contain more than {_MAX_PROFILE_ITEMS} references"
        )
    if not references and not allow_empty:
        raise ContractError(f"{field} must not be empty")
    if any(type(reference) is not ContractRef for reference in references):
        raise ContractError(f"{field} must contain only ContractRef values")
    for reference in references:
        if reference.kind not in expected_kinds:
            expected = ", ".join(sorted(kind.value for kind in expected_kinds))
            raise ContractError(f"{field} may reference only: {expected}")

    identities = tuple(
        (reference.kind, reference.contract_id, reference.contract_version)
        for reference in references
    )
    if len(identities) != len(set(identities)):
        raise ContractError(
            f"{field} must not repeat or conflict on kind/id/version"
        )
    return tuple(sorted(references, key=_ref_sort_key))


def _refs_from_document(
    value: object,
    field: str,
    expected_kinds: frozenset[ContractRefKind],
    *,
    allow_empty: bool = False,
) -> tuple[ContractRef, ...]:
    if type(value) is not list:
        raise ContractError(f"{field} must be a list")
    references = tuple(ContractRef.from_document(item) for item in value)
    return _normalize_refs(
        references,
        field,
        expected_kinds,
        allow_empty=allow_empty,
    )


def _validate_optional_sha256(value: object, field: str) -> str | None:
    if value is None:
        return None
    return validate_sha256(value, field)


def _validate_utc_timestamp(value: object, field: str) -> str:
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
        raise ContractError(f"{field} must be a canonical UTC timestamp")
    return value


@dataclass(frozen=True)
class ProjectBinding:
    """Authority-owned identity of the source tree a profile describes."""

    system_id: str
    project_kind: str
    source_snapshot_sha256: str
    dependency_manifest_sha256: str

    def __post_init__(self) -> None:
        validate_identifier(self.system_id, "system_id")
        validate_identifier(self.project_kind, "project_kind")
        validate_sha256(self.source_snapshot_sha256, "source_snapshot_sha256")
        validate_sha256(
            self.dependency_manifest_sha256,
            "dependency_manifest_sha256",
        )

    def to_document(self) -> dict[str, object]:
        return {
            "system_id": self.system_id,
            "project_kind": self.project_kind,
            "source_snapshot_sha256": self.source_snapshot_sha256,
            "dependency_manifest_sha256": self.dependency_manifest_sha256,
        }

    @classmethod
    def from_document(cls, value: object) -> ProjectBinding:
        document = require_exact_keys(
            value,
            required=(
                "system_id",
                "project_kind",
                "source_snapshot_sha256",
                "dependency_manifest_sha256",
            ),
            where="project binding",
        )
        return cls(
            system_id=document["system_id"],
            project_kind=document["project_kind"],
            source_snapshot_sha256=document["source_snapshot_sha256"],
            dependency_manifest_sha256=document["dependency_manifest_sha256"],
        )


@dataclass(frozen=True)
class EnvironmentBinding:
    """Stable environment identity; dynamic leases never belong here."""

    os_image_sha256: str
    toolchain_sha256: str
    hardware_fingerprint_sha256: str | None
    model_sha256: str | None
    device_policy_sha256: str | None
    resource_policy: ContractRef

    def __post_init__(self) -> None:
        validate_sha256(self.os_image_sha256, "os_image_sha256")
        validate_sha256(self.toolchain_sha256, "toolchain_sha256")
        _validate_optional_sha256(
            self.hardware_fingerprint_sha256,
            "hardware_fingerprint_sha256",
        )
        _validate_optional_sha256(self.model_sha256, "model_sha256")
        _validate_optional_sha256(
            self.device_policy_sha256,
            "device_policy_sha256",
        )
        _require_contract_ref(
            self.resource_policy,
            ContractRefKind.RESOURCE_POLICY,
            "resource_policy",
        )

    def to_document(self) -> dict[str, object]:
        return {
            "os_image_sha256": self.os_image_sha256,
            "toolchain_sha256": self.toolchain_sha256,
            "hardware_fingerprint_sha256": self.hardware_fingerprint_sha256,
            "model_sha256": self.model_sha256,
            "device_policy_sha256": self.device_policy_sha256,
            "resource_policy": self.resource_policy.to_document(),
        }

    @classmethod
    def from_document(cls, value: object) -> EnvironmentBinding:
        document = require_exact_keys(
            value,
            required=(
                "os_image_sha256",
                "toolchain_sha256",
                "hardware_fingerprint_sha256",
                "model_sha256",
                "device_policy_sha256",
                "resource_policy",
            ),
            where="environment binding",
        )
        resource_policy = ContractRef.from_document(document["resource_policy"])
        return cls(
            os_image_sha256=document["os_image_sha256"],
            toolchain_sha256=document["toolchain_sha256"],
            hardware_fingerprint_sha256=document[
                "hardware_fingerprint_sha256"
            ],
            model_sha256=document["model_sha256"],
            device_policy_sha256=document["device_policy_sha256"],
            resource_policy=resource_policy,
        )


@dataclass(frozen=True)
class FrozenSystemProfile:
    """Project-level frozen allowlist, without executable or trust state."""

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
    qualification_report_sha256: str
    review_sha256: str
    approval_sha256: str
    created_at: str
    expires_at: str | None

    def __post_init__(self) -> None:
        validate_identifier(self.profile_id, "profile_id")
        validate_identifier(self.profile_version, "profile_version")
        if type(self.project) is not ProjectBinding:
            raise ContractError("project must be a ProjectBinding")
        if type(self.environment) is not EnvironmentBinding:
            raise ContractError("environment must be an EnvironmentBinding")

        object.__setattr__(
            self,
            "entrypoints",
            _normalize_refs(
                self.entrypoints,
                "entrypoints",
                frozenset({ContractRefKind.ENTRYPOINT}),
            ),
        )
        object.__setattr__(
            self,
            "workload_schemas",
            _normalize_refs(
                self.workload_schemas,
                "workload_schemas",
                frozenset({ContractRefKind.WORKLOAD_SCHEMA}),
            ),
        )
        object.__setattr__(
            self,
            "adapters",
            _normalize_refs(
                self.adapters,
                "adapters",
                frozenset({ContractRefKind.ADAPTER}),
            ),
        )
        object.__setattr__(
            self,
            "instrumentation_providers",
            _normalize_refs(
                self.instrumentation_providers,
                "instrumentation_providers",
                frozenset({ContractRefKind.INSTRUMENTATION_PROVIDER}),
            ),
        )
        object.__setattr__(
            self,
            "oracle_specs",
            _normalize_refs(
                self.oracle_specs,
                "oracle_specs",
                frozenset({ContractRefKind.ORACLE_SPEC}),
            ),
        )
        object.__setattr__(
            self,
            "oracle_bundles",
            _normalize_refs(
                self.oracle_bundles,
                "oracle_bundles",
                frozenset({ContractRefKind.ORACLE_BUNDLE}),
            ),
        )
        object.__setattr__(
            self,
            "execution_recipes",
            _normalize_refs(
                self.execution_recipes,
                "execution_recipes",
                frozenset({ContractRefKind.EXECUTION_RECIPE}),
            ),
        )
        object.__setattr__(
            self,
            "components",
            _normalize_refs(
                self.components,
                "components",
                _PROFILE_COMPONENT_KINDS,
            ),
        )
        capabilities = normalize_identifiers(self.capabilities, "capabilities")
        if not capabilities:
            raise ContractError("capabilities must not be empty")
        if len(capabilities) > _MAX_PROFILE_ITEMS:
            raise ContractError(
                f"capabilities must not contain more than {_MAX_PROFILE_ITEMS} values"
            )
        object.__setattr__(self, "capabilities", capabilities)

        validate_sha256(
            self.qualification_report_sha256,
            "qualification_report_sha256",
        )
        validate_sha256(self.review_sha256, "review_sha256")
        validate_sha256(self.approval_sha256, "approval_sha256")
        created = _validate_utc_timestamp(self.created_at, "created_at")
        if self.expires_at is not None:
            expires = _validate_utc_timestamp(self.expires_at, "expires_at")
            if expires <= created:
                raise ContractError("expires_at must be later than created_at")

        component_set = set(self.components)
        if self.environment.resource_policy not in component_set:
            raise ContractError(
                "environment.resource_policy must be listed in profile components"
            )

    def to_document(self) -> dict[str, object]:
        return {
            "contract_kind": _PROFILE_CONTRACT_KIND,
            "schema_version": _PROFILE_SCHEMA_VERSION,
            "profile_id": self.profile_id,
            "profile_version": self.profile_version,
            "project": self.project.to_document(),
            "environment": self.environment.to_document(),
            "entrypoints": [reference.to_document() for reference in self.entrypoints],
            "workload_schemas": [
                reference.to_document() for reference in self.workload_schemas
            ],
            "adapters": [reference.to_document() for reference in self.adapters],
            "instrumentation_providers": [
                reference.to_document()
                for reference in self.instrumentation_providers
            ],
            "oracle_specs": [
                reference.to_document() for reference in self.oracle_specs
            ],
            "oracle_bundles": [
                reference.to_document() for reference in self.oracle_bundles
            ],
            "execution_recipes": [
                reference.to_document() for reference in self.execution_recipes
            ],
            "components": [
                reference.to_document() for reference in self.components
            ],
            "capabilities": list(self.capabilities),
            "qualification_report_sha256": self.qualification_report_sha256,
            "review_sha256": self.review_sha256,
            "approval_sha256": self.approval_sha256,
            "created_at": self.created_at,
            "expires_at": self.expires_at,
        }

    @classmethod
    def from_document(cls, value: object) -> FrozenSystemProfile:
        document = require_exact_keys(
            value,
            required=(
                "contract_kind",
                "schema_version",
                "profile_id",
                "profile_version",
                "project",
                "environment",
                "entrypoints",
                "workload_schemas",
                "adapters",
                "instrumentation_providers",
                "oracle_specs",
                "oracle_bundles",
                "execution_recipes",
                "components",
                "capabilities",
                "qualification_report_sha256",
                "review_sha256",
                "approval_sha256",
                "created_at",
                "expires_at",
            ),
            where="frozen system profile",
        )
        if document["contract_kind"] != _PROFILE_CONTRACT_KIND:
            raise ContractError(
                f"frozen system profile contract_kind must be {_PROFILE_CONTRACT_KIND!r}"
            )
        if (
            type(document["schema_version"]) is not int
            or document["schema_version"] != _PROFILE_SCHEMA_VERSION
        ):
            raise ContractError(
                "frozen system profile schema_version must be the integer 1"
            )
        capabilities = document["capabilities"]
        if type(capabilities) is not list:
            raise ContractError("frozen system profile capabilities must be a list")
        return cls(
            profile_id=document["profile_id"],
            profile_version=document["profile_version"],
            project=ProjectBinding.from_document(document["project"]),
            environment=EnvironmentBinding.from_document(document["environment"]),
            entrypoints=_refs_from_document(
                document["entrypoints"],
                "entrypoints",
                frozenset({ContractRefKind.ENTRYPOINT}),
            ),
            workload_schemas=_refs_from_document(
                document["workload_schemas"],
                "workload_schemas",
                frozenset({ContractRefKind.WORKLOAD_SCHEMA}),
            ),
            adapters=_refs_from_document(
                document["adapters"],
                "adapters",
                frozenset({ContractRefKind.ADAPTER}),
            ),
            instrumentation_providers=_refs_from_document(
                document["instrumentation_providers"],
                "instrumentation_providers",
                frozenset({ContractRefKind.INSTRUMENTATION_PROVIDER}),
            ),
            oracle_specs=_refs_from_document(
                document["oracle_specs"],
                "oracle_specs",
                frozenset({ContractRefKind.ORACLE_SPEC}),
            ),
            oracle_bundles=_refs_from_document(
                document["oracle_bundles"],
                "oracle_bundles",
                frozenset({ContractRefKind.ORACLE_BUNDLE}),
            ),
            execution_recipes=_refs_from_document(
                document["execution_recipes"],
                "execution_recipes",
                frozenset({ContractRefKind.EXECUTION_RECIPE}),
            ),
            components=_refs_from_document(
                document["components"],
                "components",
                _PROFILE_COMPONENT_KINDS,
            ),
            capabilities=tuple(capabilities),
            qualification_report_sha256=document[
                "qualification_report_sha256"
            ],
            review_sha256=document["review_sha256"],
            approval_sha256=document["approval_sha256"],
            created_at=document["created_at"],
            expires_at=document["expires_at"],
        )

    @classmethod
    def from_json(cls, payload: object) -> FrozenSystemProfile:
        return cls.from_document(load_strict_json_object(payload))

    @property
    def content_sha256(self) -> str:
        return canonical_sha256(self.to_document())

    @property
    def ref(self) -> ContractRef:
        return ContractRef(
            kind=ContractRefKind.FROZEN_PROFILE,
            contract_id=self.profile_id,
            contract_version=self.profile_version,
            content_sha256=self.content_sha256,
        )


def _exact_object_refs(
    values: Iterable[object],
    expected_type: type[object],
    field: str,
) -> tuple[ContractRef, ...]:
    objects = tuple(values)
    if any(type(value) is not expected_type for value in objects):
        raise ContractError(f"{field} contains an unexpected object type")
    references = tuple(value.ref for value in objects)  # type: ignore[attr-defined]
    identities = tuple(
        (reference.kind, reference.contract_id, reference.contract_version)
        for reference in references
    )
    if len(identities) != len(set(identities)):
        raise ContractError(f"{field} contains a duplicate or conflicting identity")
    return tuple(sorted(references, key=_ref_sort_key))


def validate_frozen_profile_contracts(
    profile: FrozenSystemProfile,
    *,
    oracle_specs: Iterable[OracleSpec],
    oracle_bundles: Iterable[OracleBundle],
    execution_recipes: Iterable[ExecutionRecipe],
) -> None:
    """Validate one complete, explicitly supplied frozen contract graph.

    This is a deterministic membership/hash check.  It neither consults a
    registry nor grants admission, and it must run before current observations
    exist.
    """

    if type(profile) is not FrozenSystemProfile:
        raise ContractError("profile must be a FrozenSystemProfile")

    # Runtime imports avoid profile/oracle/execution import cycles while keeping
    # every imported module inside the pure contracts package.
    from .execution import ExecutionRecipe
    from .oracle import (
        ConsequenceDomain,
        ControlEvidenceRole,
        OracleBundle,
        OracleSpec,
    )

    spec_objects = tuple(oracle_specs)
    bundle_objects = tuple(oracle_bundles)
    recipe_objects = tuple(execution_recipes)
    spec_refs = _exact_object_refs(spec_objects, OracleSpec, "oracle_specs")
    bundle_refs = _exact_object_refs(
        bundle_objects,
        OracleBundle,
        "oracle_bundles",
    )
    recipe_refs = _exact_object_refs(
        recipe_objects,
        ExecutionRecipe,
        "execution_recipes",
    )
    if spec_refs != profile.oracle_specs:
        raise ContractError("oracle_specs do not exactly match profile membership")
    if bundle_refs != profile.oracle_bundles:
        raise ContractError("oracle_bundles do not exactly match profile membership")
    if recipe_refs != profile.execution_recipes:
        raise ContractError(
            "execution_recipes do not exactly match profile membership"
        )

    allowed_specs = set(profile.oracle_specs)
    allowed_recipes = set(profile.execution_recipes)
    allowed_components = set(profile.components)
    allowed_capabilities = set(profile.capabilities)
    specs_by_ref = {spec.ref: spec for spec in spec_objects}
    for spec in spec_objects:
        missing = set(spec.component_refs) - allowed_components
        if missing:
            raise ContractError(
                f"oracle spec {spec.oracle_id} references components outside profile"
            )
        if not set(spec.execution_recipe_refs).issubset(allowed_recipes):
            raise ContractError(
                f"oracle spec {spec.oracle_id} references recipes outside profile"
            )
        if not set(spec.dependent_oracle_spec_refs).issubset(allowed_specs):
            raise ContractError(
                f"oracle spec {spec.oracle_id} references guards outside profile"
            )
        for guard_ref in spec.dependent_oracle_spec_refs:
            if guard_ref == spec.ref:
                raise ContractError(
                    f"oracle spec {spec.oracle_id} cannot guard itself"
                )
            guard = specs_by_ref[guard_ref]
            if guard.consequence_domain is not ConsequenceDomain.CORRECTNESS:
                raise ContractError(
                    f"oracle spec {spec.oracle_id} correctness guard is not correctness"
                )
            if (
                guard.causal_control is not None
                or guard.control_evidence_role is not ControlEvidenceRole.ORACLE_ONLY
            ):
                raise ContractError(
                    f"oracle spec {spec.oracle_id} correctness guard must be non-causal"
                )
        if not set(spec.applicability.required_capabilities).issubset(
            allowed_capabilities
        ):
            raise ContractError(
                f"oracle spec {spec.oracle_id} requires capabilities outside profile"
            )

    def visit_spec(reference: ContractRef, visiting: set[ContractRef]) -> None:
        if reference in visiting:
            raise ContractError("oracle correctness-guard graph contains a cycle")
        dependencies = specs_by_ref[reference].dependent_oracle_spec_refs
        if not dependencies:
            return
        next_visiting = set(visiting)
        next_visiting.add(reference)
        for dependency in dependencies:
            visit_spec(dependency, next_visiting)

    for reference in specs_by_ref:
        visit_spec(reference, set())

    for bundle in bundle_objects:
        bundle_specs = set(bundle.oracle_spec_refs)
        if not bundle_specs.issubset(allowed_specs):
            raise ContractError(
                f"oracle bundle {bundle.bundle_id} references specs outside profile"
            )
        if not set(bundle.component_refs).issubset(allowed_components):
            raise ContractError(
                f"oracle bundle {bundle.bundle_id} references components outside profile"
            )
        if bundle.control_oracle is not None:
            control_spec = specs_by_ref[bundle.control_oracle]
            if control_spec.control_evidence_role is not bundle.control_evidence_role:
                raise ContractError(
                    f"oracle bundle {bundle.bundle_id} control role disagrees with its spec"
                )
        member_specs = tuple(
            specs_by_ref[reference] for reference in bundle.oracle_spec_refs
        )
        causal_members = {
            spec.ref
            for spec in member_specs
            if spec.control_evidence_role is not ControlEvidenceRole.ORACLE_ONLY
        }
        if bundle.control_evidence_role is ControlEvidenceRole.ORACLE_ONLY:
            if causal_members:
                raise ContractError(
                    f"oracle-only bundle {bundle.bundle_id} contains causal members"
                )
        elif causal_members != {bundle.control_oracle}:
            raise ContractError(
                f"oracle bundle {bundle.bundle_id} must designate its only causal member"
            )

        primary_specs = tuple(
            specs_by_ref[reference] for reference in bundle.primary_oracles
        )
        performance_primaries = {
            spec.ref
            for spec in primary_specs
            if spec.consequence_domain
            in (ConsequenceDomain.PERFORMANCE, ConsequenceDomain.RESOURCE)
        }
        has_multiple_comparison = (
            bundle.primary_metric_oracle is not None
            or bundle.multiplicity_policy is not None
        )
        if len(performance_primaries) >= 2:
            if (
                bundle.primary_metric_oracle not in performance_primaries
                or bundle.multiplicity_policy is None
            ):
                raise ContractError(
                    f"oracle bundle {bundle.bundle_id} must freeze performance multiplicity"
                )
        elif has_multiple_comparison:
            raise ContractError(
                f"oracle bundle {bundle.bundle_id} has inapplicable performance multiplicity"
            )

    for recipe in recipe_objects:
        missing = set(recipe.component_refs) - allowed_components
        if missing:
            raise ContractError(
                f"execution recipe {recipe.recipe_id} references components outside profile"
            )

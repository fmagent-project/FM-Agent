"""Closed, hash-bound execution recipes for generic validation.

The contracts in this module describe *logical* execution only.  They cannot
carry an executable command, physical workspace, environment value, port, or
device lease.  A later broker-owned binding phase resolves the symbolic input
bindings against a frozen profile and role-local resources.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from .base import (
    ContractError,
    canonical_sha256,
    load_strict_json_object,
    require_exact_keys,
    validate_identifier,
)
from .references import ContractRef, ContractRefKind


_EXECUTION_RECIPE_CONTRACT_KIND = "execution_recipe"
_EXECUTION_RECIPE_SCHEMA_VERSION = 1
_MAX_RECIPE_STEPS = 1024
_MAX_STEP_BINDINGS = 1024
_MAX_STEP_DEPENDENCIES = 1024


class InputBindingSource(str, Enum):
    """Approved namespaces from which a broker may resolve a logical input."""

    PROFILE_VALUE = "profile_value"
    CASE_PARAMETER = "case_parameter"
    ARTIFACT_ROLE = "artifact_role"
    BROKER_VALUE = "broker_value"


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


def _contract_ref_from_document(
    value: object,
    expected_kind: ContractRefKind,
    field: str,
) -> ContractRef:
    try:
        reference = ContractRef.from_document(value)
    except ContractError as exc:
        raise ContractError(f"invalid {field}: {exc}") from exc
    return _require_contract_ref(reference, expected_kind, field)


@dataclass(frozen=True)
class ExecutionInputBinding:
    """A named logical input resolved only by an authorized later phase."""

    name: str
    source: InputBindingSource
    symbol: str

    def __post_init__(self) -> None:
        validate_identifier(self.name, "input binding name")
        if type(self.source) is not InputBindingSource:
            raise ContractError("input binding source must be an InputBindingSource")
        validate_identifier(self.symbol, "input binding symbol")

    def to_document(self) -> dict[str, object]:
        return {
            "name": self.name,
            "source": self.source.value,
            "symbol": self.symbol,
        }

    @classmethod
    def from_document(cls, value: object) -> ExecutionInputBinding:
        document = require_exact_keys(
            value,
            required=frozenset({"name", "source", "symbol"}),
            where="execution input binding",
        )
        source_value = document["source"]
        if type(source_value) is not str:
            raise ContractError("execution input binding source must be a string")
        try:
            source = InputBindingSource(source_value)
        except ValueError as exc:
            raise ContractError(
                f"unsupported execution input binding source {source_value!r}"
            ) from exc
        return cls(
            name=document["name"],
            source=source,
            symbol=document["symbol"],
        )


@dataclass(frozen=True)
class ExecutionStep:
    """One closed broker request composed entirely from exact component refs."""

    step_id: str
    execution_block: ContractRef
    tool: ContractRef
    argv_template: ContractRef
    timeout_policy: ContractRef
    resource_policy: ContractRef
    output_contract: ContractRef
    environment_policy: ContractRef
    input_bindings: tuple[ExecutionInputBinding, ...]
    cwd_symbol: str
    stdin_artifact_role: str | None
    depends_on: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        validate_identifier(self.step_id, "step_id")
        _require_contract_ref(
            self.execution_block,
            ContractRefKind.EXECUTION_BLOCK,
            "execution_block",
        )
        _require_contract_ref(self.tool, ContractRefKind.TOOL, "tool")
        _require_contract_ref(
            self.argv_template,
            ContractRefKind.ARGV_TEMPLATE,
            "argv_template",
        )
        _require_contract_ref(
            self.timeout_policy,
            ContractRefKind.TIMEOUT_POLICY,
            "timeout_policy",
        )
        _require_contract_ref(
            self.resource_policy,
            ContractRefKind.RESOURCE_POLICY,
            "resource_policy",
        )
        _require_contract_ref(
            self.output_contract,
            ContractRefKind.OUTPUT_CONTRACT,
            "output_contract",
        )
        _require_contract_ref(
            self.environment_policy,
            ContractRefKind.ENVIRONMENT_POLICY,
            "environment_policy",
        )

        if type(self.input_bindings) not in (tuple, list):
            raise ContractError("input_bindings must be an ordered collection")
        bindings = tuple(self.input_bindings)
        if len(bindings) > _MAX_STEP_BINDINGS:
            raise ContractError(
                f"input_bindings must not contain more than {_MAX_STEP_BINDINGS} values"
            )
        if any(type(binding) is not ExecutionInputBinding for binding in bindings):
            raise ContractError(
                "input_bindings must contain only ExecutionInputBinding values"
            )
        binding_names = [binding.name for binding in bindings]
        if len(set(binding_names)) != len(binding_names):
            raise ContractError("input_bindings must not repeat a name")
        object.__setattr__(
            self,
            "input_bindings",
            tuple(sorted(bindings, key=lambda binding: binding.name)),
        )

        validate_identifier(self.cwd_symbol, "cwd_symbol")
        if self.stdin_artifact_role is not None:
            validate_identifier(
                self.stdin_artifact_role,
                "stdin_artifact_role",
            )

        if type(self.depends_on) not in (tuple, list):
            raise ContractError("depends_on must be a collection of step ids")
        dependencies = tuple(
            validate_identifier(dependency, "depends_on")
            for dependency in self.depends_on
        )
        if len(dependencies) > _MAX_STEP_DEPENDENCIES:
            raise ContractError(
                f"depends_on must not contain more than {_MAX_STEP_DEPENDENCIES} values"
            )
        if len(set(dependencies)) != len(dependencies):
            raise ContractError("depends_on must not contain duplicate step ids")
        if self.step_id in dependencies:
            raise ContractError("a step cannot depend on itself")
        object.__setattr__(self, "depends_on", tuple(sorted(dependencies)))

    @property
    def component_refs(self) -> tuple[ContractRef, ...]:
        return (
            self.execution_block,
            self.tool,
            self.argv_template,
            self.timeout_policy,
            self.resource_policy,
            self.output_contract,
            self.environment_policy,
        )

    def to_document(self) -> dict[str, object]:
        return {
            "step_id": self.step_id,
            "execution_block": self.execution_block.to_document(),
            "tool": self.tool.to_document(),
            "argv_template": self.argv_template.to_document(),
            "timeout_policy": self.timeout_policy.to_document(),
            "resource_policy": self.resource_policy.to_document(),
            "output_contract": self.output_contract.to_document(),
            "environment_policy": self.environment_policy.to_document(),
            "input_bindings": [
                binding.to_document() for binding in self.input_bindings
            ],
            "cwd_symbol": self.cwd_symbol,
            "stdin_artifact_role": self.stdin_artifact_role,
            "depends_on": list(self.depends_on),
        }

    @classmethod
    def from_document(cls, value: object) -> ExecutionStep:
        document = require_exact_keys(
            value,
            required=frozenset(
                {
                    "step_id",
                    "execution_block",
                    "tool",
                    "argv_template",
                    "timeout_policy",
                    "resource_policy",
                    "output_contract",
                    "environment_policy",
                    "input_bindings",
                    "cwd_symbol",
                    "stdin_artifact_role",
                    "depends_on",
                }
            ),
            where="execution step",
        )
        binding_documents = document["input_bindings"]
        if type(binding_documents) is not list:
            raise ContractError("execution step input_bindings must be a list")
        dependency_documents = document["depends_on"]
        if type(dependency_documents) is not list:
            raise ContractError("execution step depends_on must be a list")
        stdin_artifact_role = document["stdin_artifact_role"]
        if stdin_artifact_role is not None and type(stdin_artifact_role) is not str:
            raise ContractError(
                "execution step stdin_artifact_role must be a string or null"
            )
        return cls(
            step_id=document["step_id"],
            execution_block=_contract_ref_from_document(
                document["execution_block"],
                ContractRefKind.EXECUTION_BLOCK,
                "execution_block",
            ),
            tool=_contract_ref_from_document(
                document["tool"],
                ContractRefKind.TOOL,
                "tool",
            ),
            argv_template=_contract_ref_from_document(
                document["argv_template"],
                ContractRefKind.ARGV_TEMPLATE,
                "argv_template",
            ),
            timeout_policy=_contract_ref_from_document(
                document["timeout_policy"],
                ContractRefKind.TIMEOUT_POLICY,
                "timeout_policy",
            ),
            resource_policy=_contract_ref_from_document(
                document["resource_policy"],
                ContractRefKind.RESOURCE_POLICY,
                "resource_policy",
            ),
            output_contract=_contract_ref_from_document(
                document["output_contract"],
                ContractRefKind.OUTPUT_CONTRACT,
                "output_contract",
            ),
            environment_policy=_contract_ref_from_document(
                document["environment_policy"],
                ContractRefKind.ENVIRONMENT_POLICY,
                "environment_policy",
            ),
            input_bindings=tuple(
                ExecutionInputBinding.from_document(binding)
                for binding in binding_documents
            ),
            cwd_symbol=document["cwd_symbol"],
            stdin_artifact_role=stdin_artifact_role,
            depends_on=tuple(dependency_documents),
        )


@dataclass(frozen=True)
class ExecutionRecipe:
    """An immutable ordered plan that can only name approved execution parts."""

    recipe_id: str
    recipe_version: str
    recipe_schema: ContractRef
    steps: tuple[ExecutionStep, ...]

    def __post_init__(self) -> None:
        validate_identifier(self.recipe_id, "recipe_id")
        validate_identifier(self.recipe_version, "recipe_version")
        _require_contract_ref(
            self.recipe_schema,
            ContractRefKind.EXECUTION_RECIPE_SCHEMA,
            "recipe_schema",
        )
        if type(self.steps) not in (tuple, list):
            raise ContractError("steps must be a non-empty ordered collection")
        steps = tuple(self.steps)
        if not steps:
            raise ContractError("steps must contain at least one execution step")
        if len(steps) > _MAX_RECIPE_STEPS:
            raise ContractError(
                f"steps must not contain more than {_MAX_RECIPE_STEPS} values"
            )
        if any(type(step) is not ExecutionStep for step in steps):
            raise ContractError("steps must contain only ExecutionStep values")

        seen: set[str] = set()
        for index, step in enumerate(steps):
            if step.step_id in seen:
                raise ContractError(f"steps must not repeat step_id {step.step_id}")
            missing_or_forward = tuple(
                dependency
                for dependency in step.depends_on
                if dependency not in seen
            )
            if missing_or_forward:
                raise ContractError(
                    f"steps[{index}].depends_on must reference only prior steps; "
                    f"unavailable: {', '.join(missing_or_forward)}"
                )
            seen.add(step.step_id)
        object.__setattr__(self, "steps", steps)
        # Reject one logical component identity resolving to two contents even
        # before a Profile graph is available.
        self.component_refs

    @property
    def component_refs(self) -> tuple[ContractRef, ...]:
        """Return all exact low-level refs once in stable membership order."""

        references = (self.recipe_schema,) + tuple(
            reference
            for step in self.steps
            for reference in step.component_refs
        )
        by_identity: dict[tuple[str, str, str], ContractRef] = {}
        for reference in references:
            identity = (
                reference.kind.value,
                reference.contract_id,
                reference.contract_version,
            )
            previous = by_identity.get(identity)
            if (
                previous is not None
                and previous.content_sha256 != reference.content_sha256
            ):
                raise ContractError(
                    "component_refs contains conflicting hashes for one identity"
                )
            by_identity[identity] = reference
        return tuple(by_identity[key] for key in sorted(by_identity))

    def to_document(self) -> dict[str, object]:
        return {
            "contract_kind": _EXECUTION_RECIPE_CONTRACT_KIND,
            "schema_version": _EXECUTION_RECIPE_SCHEMA_VERSION,
            "recipe_id": self.recipe_id,
            "recipe_version": self.recipe_version,
            "recipe_schema": self.recipe_schema.to_document(),
            "steps": [step.to_document() for step in self.steps],
        }

    @classmethod
    def from_document(cls, value: object) -> ExecutionRecipe:
        document = require_exact_keys(
            value,
            required=frozenset(
                {
                    "contract_kind",
                    "schema_version",
                    "recipe_id",
                    "recipe_version",
                    "recipe_schema",
                    "steps",
                }
            ),
            where="execution recipe",
        )
        if document["contract_kind"] != _EXECUTION_RECIPE_CONTRACT_KIND:
            raise ContractError(
                "execution recipe contract_kind must be "
                f"{_EXECUTION_RECIPE_CONTRACT_KIND!r}"
            )
        if (
            type(document["schema_version"]) is not int
            or document["schema_version"] != _EXECUTION_RECIPE_SCHEMA_VERSION
        ):
            raise ContractError(
                "execution recipe schema_version must be the integer 1"
            )
        step_documents = document["steps"]
        if type(step_documents) is not list:
            raise ContractError("execution recipe steps must be a list")
        return cls(
            recipe_id=document["recipe_id"],
            recipe_version=document["recipe_version"],
            recipe_schema=_contract_ref_from_document(
                document["recipe_schema"],
                ContractRefKind.EXECUTION_RECIPE_SCHEMA,
                "recipe_schema",
            ),
            steps=tuple(
                ExecutionStep.from_document(step) for step in step_documents
            ),
        )

    @classmethod
    def from_json(cls, payload: object) -> ExecutionRecipe:
        return cls.from_document(load_strict_json_object(payload))

    @property
    def content_sha256(self) -> str:
        return canonical_sha256(self.to_document())

    @property
    def ref(self) -> ContractRef:
        return ContractRef(
            kind=ContractRefKind.EXECUTION_RECIPE,
            contract_id=self.recipe_id,
            contract_version=self.recipe_version,
            content_sha256=self.content_sha256,
        )

"""Exact-reference catalog for approved Oracle runtime atoms."""

from __future__ import annotations

from collections.abc import Callable

from ..contracts import ContractRef, ContractRefKind


class CatalogError(ValueError):
    """A runtime atom is missing, ambiguous, mutable, or incorrectly bound."""


def _identity(reference: ContractRef) -> tuple[ContractRefKind, str, str]:
    return (reference.kind, reference.contract_id, reference.contract_version)


class AtomicOracleCatalog:
    """Mutable during trusted bootstrap, then sealed for deterministic use.

    Exact component references include the content hash.  Implementations must
    expose their own matching ``atom_ref`` (or ``recipe_ref`` for runners), so
    an arbitrary callable cannot be attached to an approved-looking label.
    Package/source admission is intentionally left to the later Adapter
    registry; this catalog enforces the already-admitted identity.
    """

    def __init__(self) -> None:
        self._runners: dict[ContractRef, Callable] = {}
        self._normalizers: dict[ContractRef, Callable] = {}
        self._comparators: dict[ContractRef, Callable] = {}
        self._identity_hashes: dict[
            tuple[ContractRefKind, str, str], str
        ] = {}
        self._sealed = False

    @property
    def sealed(self) -> bool:
        return self._sealed

    def seal(self) -> None:
        self._sealed = True

    def _register(
        self,
        table: dict[ContractRef, Callable],
        reference: ContractRef,
        expected_kind: ContractRefKind,
        implementation: Callable,
        binding_attribute: str,
    ) -> None:
        if self._sealed:
            raise CatalogError("the Oracle catalog is sealed")
        if type(reference) is not ContractRef or reference.kind is not expected_kind:
            raise CatalogError(
                f"registration requires a {expected_kind.value} reference"
            )
        if not callable(implementation):
            raise CatalogError("registered implementation must be callable")
        implementation_ref = getattr(implementation, binding_attribute, None)
        if type(implementation_ref) is not ContractRef:
            raise CatalogError(
                f"implementation must expose a ContractRef {binding_attribute}"
            )
        if implementation_ref != reference:
            raise CatalogError(
                "implementation identity/version/hash does not match registration"
            )
        logical_identity = _identity(reference)
        previous_hash = self._identity_hashes.get(logical_identity)
        if previous_hash is not None and previous_hash != reference.content_sha256:
            raise CatalogError(
                "one component identity/version cannot have multiple content hashes"
            )
        if reference in table:
            raise CatalogError("an exact component reference is already registered")
        table[reference] = implementation
        self._identity_hashes[logical_identity] = reference.content_sha256

    def register_runner(self, recipe: ContractRef, runner: Callable) -> None:
        self._register(
            self._runners,
            recipe,
            ContractRefKind.EXECUTION_RECIPE,
            runner,
            "recipe_ref",
        )

    def register_normalizer(
        self,
        reference: ContractRef,
        normalizer: Callable,
    ) -> None:
        self._register(
            self._normalizers,
            reference,
            ContractRefKind.NORMALIZER,
            normalizer,
            "atom_ref",
        )

    def register_comparator(
        self,
        reference: ContractRef,
        comparator: Callable,
    ) -> None:
        self._register(
            self._comparators,
            reference,
            ContractRefKind.COMPARATOR,
            comparator,
            "atom_ref",
        )

    @staticmethod
    def _resolve(
        table: dict[ContractRef, Callable],
        reference: ContractRef,
        label: str,
        binding_attribute: str,
    ) -> Callable:
        implementation = table.get(reference)
        if implementation is None:
            raise CatalogError(f"unregistered or hash-mismatched {label}")
        if getattr(implementation, binding_attribute, None) != reference:
            raise CatalogError(f"registered {label} binding changed after admission")
        return implementation

    def runner(self, reference: ContractRef) -> Callable:
        return self._resolve(
            self._runners,
            reference,
            "execution recipe",
            "recipe_ref",
        )

    def normalizer(self, reference: ContractRef) -> Callable:
        return self._resolve(
            self._normalizers,
            reference,
            "normalizer",
            "atom_ref",
        )

    def comparator(self, reference: ContractRef) -> Callable:
        return self._resolve(
            self._comparators,
            reference,
            "comparator",
            "atom_ref",
        )

import ast
import dataclasses
import unittest
from pathlib import Path

import src.validation_core.contracts.base as base_contracts
import src.validation_core.contracts.preset as preset_contracts
import src.validation_core.contracts.routing as routing_contracts
import src.validation_core.registry as registry_module
import src.validation_core.routing as routing_module
from src.validation_core import (
    AdapterResolver,
    ComponentKind,
    ComponentRef,
    GenericAdapterKind,
    PresetDependency,
    PresetRef,
    PresetRegistry,
    RegistrationOrigin,
    RegistrationRecord,
    RegistrationTrustTier,
    RoutingDecision,
    RoutingReasonCode,
    RoutingRequest,
    ValidationEngine,
    ValidationPreset,
    ValidationRouter,
    ValidationRoutingError,
    ValidationRoutingErrorCode,
)


def _component(kind, component_id, digest):
    return ComponentRef(
        kind=kind,
        component_id=component_id,
        component_version="1.0.0",
        content_sha256=digest * 64,
    )


def _preset(
    preset_id="ccc.legacy_boundary_witness_v3",
    preset_version="1.0.0",
    system_id="ccc",
    capabilities=("compiler_entry", "differential_oracle"),
    adapter_digest="a",
):
    return ValidationPreset(
        preset_id=preset_id,
        preset_version=preset_version,
        system_id=system_id,
        dependencies=(
            PresetDependency(
                "adapter.primary",
                _component(ComponentKind.ADAPTER, "ccc.adapter", adapter_digest),
            ),
            PresetDependency(
                "oracle.bundle",
                _component(ComponentKind.ORACLE_BUNDLE, "ccc.oracles", "b"),
            ),
            PresetDependency(
                "recipe.schema",
                _component(
                    ComponentKind.EXECUTION_RECIPE_SCHEMA,
                    "ccc.recipe-schema",
                    "c",
                ),
            ),
            PresetDependency(
                "target_evidence.policy",
                _component(
                    ComponentKind.TARGET_EVIDENCE_POLICY,
                    "ccc.boundary-evidence",
                    "d",
                ),
            ),
        ),
        capabilities=capabilities,
    )


def _registration(preset, capabilities=None):
    return RegistrationRecord(
        preset=preset.ref,
        origin=RegistrationOrigin.MAINTAINER,
        trust_tier=RegistrationTrustTier.TRUSTED_PRESET,
        admission_authority="fmagent.maintainers",
        effective_capabilities=(
            preset.capabilities if capabilities is None else capabilities
        ),
        review_sha256="e" * 64,
        qualification_sha256="f" * 64,
    )


def _registry(*presets):
    return PresetRegistry(
        presets=presets,
        registrations=tuple(_registration(preset) for preset in presets),
    )


def _ref(
    preset_id="ccc.legacy_boundary_witness_v3",
    preset_version="1.0.0",
    digest="a" * 64,
):
    return PresetRef(
        preset_id=preset_id,
        preset_version=preset_version,
        content_sha256=digest,
    )


class ValidationRoutingTests(unittest.TestCase):
    def test_default_request_keeps_the_current_legacy_prompt_engine(self):
        decision = ValidationRouter().route(RoutingRequest(system_id="ccc"))

        self.assertEqual(decision.engine, ValidationEngine.LEGACY_PROMPT)
        self.assertIsNone(decision.adapter_kind)
        self.assertIsNone(decision.preset)
        self.assertIsNone(decision.registration_sha256)
        self.assertEqual(
            decision.reason_code,
            RoutingReasonCode.LEGACY_PROMPT_SELECTED,
        )

    def test_generic_unknown_system_uses_the_agent_planner(self):
        ccc = _preset()
        decision = ValidationRouter(AdapterResolver(_registry(ccc))).route(
            RoutingRequest(
                system_id="unknown_project",
                requested_engine=ValidationEngine.GENERIC_HARNESS,
                required_capabilities=("process_entry",),
            )
        )

        self.assertEqual(decision.engine, ValidationEngine.GENERIC_HARNESS)
        self.assertEqual(decision.adapter_kind, GenericAdapterKind.GENERIC_AGENT)
        self.assertIsNone(decision.preset)
        self.assertIsNone(decision.registration_sha256)
        self.assertEqual(
            decision.reason_code,
            RoutingReasonCode.NO_MATCHING_TRUSTED_PRESET,
        )

    def test_generic_auto_selects_the_only_registered_preset(self):
        preset = _preset()
        registration = _registration(preset)
        registry = PresetRegistry((preset,), (registration,))

        decision = ValidationRouter(AdapterResolver(registry)).route(
            RoutingRequest(
                system_id="ccc",
                requested_engine=ValidationEngine.GENERIC_HARNESS,
                required_capabilities=("differential_oracle",),
            )
        )

        self.assertEqual(
            decision.adapter_kind,
            GenericAdapterKind.TRUSTED_SYSTEM_PRESET,
        )
        self.assertEqual(decision.preset, preset.ref)
        self.assertEqual(
            decision.registration_sha256,
            registration.registration_sha256,
        )
        self.assertEqual(decision.reason_code, RoutingReasonCode.AUTO_TRUSTED_PRESET)

    def test_generic_honors_an_explicit_registered_preset(self):
        preset = _preset()
        registration = _registration(preset)
        decision = ValidationRouter(
            AdapterResolver(PresetRegistry((preset,), (registration,)))
        ).route(
            RoutingRequest(
                system_id="ccc",
                requested_engine=ValidationEngine.GENERIC_HARNESS,
                requested_preset=preset.ref,
                required_capabilities=preset.capabilities,
            )
        )

        self.assertEqual(decision.preset, preset.ref)
        self.assertEqual(
            decision.registration_sha256,
            registration.registration_sha256,
        )
        self.assertEqual(
            decision.reason_code,
            RoutingReasonCode.EXPLICIT_TRUSTED_PRESET,
        )

    def test_known_system_with_insufficient_capability_does_not_fallback(self):
        preset = _preset()
        with self.assertRaises(ValidationRoutingError) as raised:
            ValidationRouter(AdapterResolver(_registry(preset))).route(
                RoutingRequest(
                    system_id="ccc",
                    requested_engine=ValidationEngine.GENERIC_HARNESS,
                    required_capabilities=("gpu",),
                )
            )

        self.assertEqual(
            raised.exception.code,
            ValidationRoutingErrorCode.PRESET_CAPABILITY_MISMATCH,
        )

    def test_known_but_unregistered_system_does_not_fallback(self):
        preset = _preset()
        registry = PresetRegistry(presets=(preset,))

        with self.assertRaises(ValidationRoutingError) as raised:
            ValidationRouter(AdapterResolver(registry)).route(
                RoutingRequest(
                    system_id="ccc",
                    requested_engine=ValidationEngine.GENERIC_HARNESS,
                )
            )

        self.assertEqual(
            raised.exception.code,
            ValidationRoutingErrorCode.PRESET_NOT_REGISTERED,
        )

    def test_explicit_unknown_preset_fails_closed(self):
        preset = _preset()
        with self.assertRaises(ValidationRoutingError) as raised:
            ValidationRouter(AdapterResolver(_registry(preset))).route(
                RoutingRequest(
                    system_id="ccc",
                    requested_engine=ValidationEngine.GENERIC_HARNESS,
                    requested_preset=_ref(preset_id="ccc.missing"),
                )
            )

        self.assertEqual(
            raised.exception.code,
            ValidationRoutingErrorCode.PRESET_NOT_FOUND,
        )

    def test_explicit_preset_for_another_system_fails_closed(self):
        preset = _preset()
        with self.assertRaises(ValidationRoutingError) as raised:
            ValidationRouter(AdapterResolver(_registry(preset))).route(
                RoutingRequest(
                    system_id="vllm",
                    requested_engine=ValidationEngine.GENERIC_HARNESS,
                    requested_preset=preset.ref,
                )
            )

        self.assertEqual(
            raised.exception.code,
            ValidationRoutingErrorCode.PRESET_SYSTEM_MISMATCH,
        )

    def test_multiple_eligible_presets_fail_instead_of_choosing_by_order(self):
        legacy = _preset(preset_id="ccc.legacy")
        hardened = _preset(preset_id="ccc.hardened")
        resolver = AdapterResolver(_registry(legacy, hardened))

        with self.assertRaises(ValidationRoutingError) as raised:
            ValidationRouter(resolver).route(
                RoutingRequest(
                    system_id="ccc",
                    requested_engine=ValidationEngine.GENERIC_HARNESS,
                )
            )

        self.assertEqual(
            raised.exception.code,
            ValidationRoutingErrorCode.AMBIGUOUS_PRESET,
        )

    def test_same_preset_id_can_pin_an_exact_version_and_hash(self):
        v1 = _preset()
        v2 = _preset(preset_version="2.0.0")
        router = ValidationRouter(AdapterResolver(_registry(v1, v2)))

        decision = router.route(
            RoutingRequest(
                system_id="ccc",
                requested_engine=ValidationEngine.GENERIC_HARNESS,
                requested_preset=v2.ref,
            )
        )

        self.assertEqual(decision.preset, v2.ref)

    def test_explicit_hash_mismatch_fails_closed(self):
        preset = _preset()
        wrong_ref = PresetRef(
            preset_id=preset.preset_id,
            preset_version=preset.preset_version,
            content_sha256="9" * 64,
        )
        with self.assertRaises(ValidationRoutingError) as raised:
            ValidationRouter(AdapterResolver(_registry(preset))).route(
                RoutingRequest(
                    system_id="ccc",
                    requested_engine=ValidationEngine.GENERIC_HARNESS,
                    requested_preset=wrong_ref,
                )
            )

        self.assertEqual(
            raised.exception.code,
            ValidationRoutingErrorCode.CONFLICTING_PRESET_HASH,
        )

    def test_explicit_preset_capability_mismatch_fails_closed(self):
        preset = _preset()
        with self.assertRaises(ValidationRoutingError) as raised:
            ValidationRouter(AdapterResolver(_registry(preset))).route(
                RoutingRequest(
                    system_id="ccc",
                    requested_engine=ValidationEngine.GENERIC_HARNESS,
                    requested_preset=preset.ref,
                    required_capabilities=("gpu",),
                )
            )

        self.assertEqual(
            raised.exception.code,
            ValidationRoutingErrorCode.PRESET_CAPABILITY_MISMATCH,
        )

    def test_contracts_reject_invalid_identity_hash_and_duplicate_capability(self):
        invalid_factories = (
            lambda: RoutingRequest(system_id=""),
            lambda: RoutingRequest(system_id="ccc", requested_engine="generic_harness"),
            lambda: RoutingRequest(
                system_id="ccc",
                required_capabilities=("oracle", "oracle"),
            ),
            lambda: PresetRef(
                preset_id="ccc",
                preset_version="1",
                content_sha256="A" * 64,
            ),
            lambda: RoutingRequest(
                system_id="ccc",
                requested_engine=ValidationEngine.LEGACY_PROMPT,
                requested_preset=_ref(preset_id="ccc.legacy"),
            ),
            lambda: RoutingRequest(
                system_id="ccc",
                requested_engine=ValidationEngine.LEGACY_PROMPT,
                required_capabilities=("oracle",),
            ),
        )
        for factory in invalid_factories:
            with self.subTest(factory=factory):
                with self.assertRaises(ValidationRoutingError) as raised:
                    factory()
                self.assertEqual(
                    raised.exception.code,
                    ValidationRoutingErrorCode.INVALID_CONTRACT,
                )

    def test_decision_contract_rejects_impossible_field_combinations(self):
        invalid_decisions = (
            lambda: RoutingDecision(
                engine=ValidationEngine.LEGACY_PROMPT,
                system_id="ccc",
                reason_code=RoutingReasonCode.LEGACY_PROMPT_SELECTED,
                registration_sha256="a" * 64,
            ),
            lambda: RoutingDecision(
                engine=ValidationEngine.GENERIC_HARNESS,
                system_id="ccc",
                reason_code=RoutingReasonCode.AUTO_TRUSTED_PRESET,
                adapter_kind=GenericAdapterKind.TRUSTED_SYSTEM_PRESET,
                preset=_ref(),
            ),
            lambda: RoutingDecision(
                engine=ValidationEngine.GENERIC_HARNESS,
                system_id="ccc",
                reason_code=RoutingReasonCode.NO_MATCHING_TRUSTED_PRESET,
                adapter_kind=GenericAdapterKind.GENERIC_AGENT,
                registration_sha256="a" * 64,
            ),
        )
        for factory in invalid_decisions:
            with self.subTest(factory=factory):
                with self.assertRaises(ValidationRoutingError) as raised:
                    factory()
                self.assertEqual(
                    raised.exception.code,
                    ValidationRoutingErrorCode.INVALID_CONTRACT,
                )

    def test_contract_values_are_immutable(self):
        preset = _preset()
        values = (
            RoutingRequest(system_id="ccc"),
            preset.ref,
            preset,
            _registration(preset),
            ValidationRouter().route(RoutingRequest(system_id="ccc")),
        )
        for value in values:
            with self.subTest(value=type(value).__name__):
                with self.assertRaises(dataclasses.FrozenInstanceError):
                    value.system_id = "changed"

    def test_routing_modules_have_no_runtime_or_execution_dependencies(self):
        allowed = {
            base_contracts: (
                {"__future__", "dataclasses", "enum", "hashlib", "json", "re", "typing"},
                set(),
            ),
            preset_contracts: (
                {"__future__", "dataclasses", "enum"},
                {(1, "base"), (1, "routing")},
            ),
            routing_contracts: (
                {"__future__", "dataclasses", "enum", "re"},
                set(),
            ),
            registry_module: (
                {"__future__", "collections", "dataclasses", "enum"},
                {
                    (1, "contracts.base"),
                    (1, "contracts.preset"),
                    (1, "contracts.routing"),
                },
            ),
            routing_module: (
                {"__future__"},
                {(1, "contracts.routing"), (1, "registry")},
            ),
        }
        for module, (absolute_allowlist, relative_allowlist) in allowed.items():
            source = Path(module.__file__).read_text(encoding="utf-8")
            tree = ast.parse(source)
            roots = set()
            relative_imports = set()
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    roots.update(alias.name.split(".", 1)[0] for alias in node.names)
                elif isinstance(node, ast.ImportFrom):
                    if node.level == 0:
                        roots.add((node.module or "").split(".", 1)[0])
                    else:
                        relative_imports.add((node.level, node.module or ""))
            self.assertLessEqual(roots, absolute_allowlist)
            self.assertEqual(relative_imports, relative_allowlist)


if __name__ == "__main__":
    unittest.main()

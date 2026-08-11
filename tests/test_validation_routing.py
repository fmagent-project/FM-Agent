import ast
import dataclasses
import unittest
from pathlib import Path

import src.validation_core.contracts.routing as routing_contracts
import src.validation_core.routing as routing_module
from src.validation_core import (
    AdapterResolver,
    GenericAdapterKind,
    PresetRef,
    RoutingDecision,
    RoutingReasonCode,
    RoutingRequest,
    TrustedPresetRecord,
    ValidationEngine,
    ValidationRouter,
    ValidationRoutingError,
    ValidationRoutingErrorCode,
)


def _preset(
    preset_id="ccc.legacy_boundary_witness_v3",
    system_id="ccc",
    capabilities=("compiler_entry", "differential_oracle"),
    digest="a" * 64,
):
    return TrustedPresetRecord(
        preset=PresetRef(
            preset_id=preset_id,
            preset_version="1.0.0",
            content_sha256=digest,
        ),
        system_id=system_id,
        capabilities=capabilities,
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
        self.assertEqual(
            decision.reason_code,
            RoutingReasonCode.LEGACY_PROMPT_SELECTED,
        )

    def test_generic_unknown_system_uses_the_agent_planner(self):
        decision = ValidationRouter(AdapterResolver([_preset()])).route(
            RoutingRequest(
                system_id="unknown_project",
                requested_engine=ValidationEngine.GENERIC_HARNESS,
                required_capabilities=("process_entry",),
            )
        )

        self.assertEqual(decision.engine, ValidationEngine.GENERIC_HARNESS)
        self.assertEqual(decision.adapter_kind, GenericAdapterKind.GENERIC_AGENT)
        self.assertIsNone(decision.preset)
        self.assertEqual(
            decision.reason_code,
            RoutingReasonCode.NO_MATCHING_TRUSTED_PRESET,
        )

    def test_generic_auto_selects_the_only_eligible_trusted_preset(self):
        record = _preset()
        decision = ValidationRouter(AdapterResolver([record])).route(
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
        self.assertEqual(decision.preset, record.preset)
        self.assertEqual(decision.reason_code, RoutingReasonCode.AUTO_TRUSTED_PRESET)

    def test_generic_honors_an_explicit_matching_trusted_preset(self):
        record = _preset()
        decision = ValidationRouter(AdapterResolver([record])).route(
            RoutingRequest(
                system_id="ccc",
                requested_engine=ValidationEngine.GENERIC_HARNESS,
                requested_preset=record.preset,
                required_capabilities=record.capabilities,
            )
        )

        self.assertEqual(decision.preset, record.preset)
        self.assertEqual(
            decision.reason_code,
            RoutingReasonCode.EXPLICIT_TRUSTED_PRESET,
        )

    def test_known_system_with_insufficient_preset_does_not_fallback(self):
        with self.assertRaises(ValidationRoutingError) as raised:
            ValidationRouter(AdapterResolver([_preset()])).route(
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

    def test_explicit_unknown_preset_fails_closed(self):
        with self.assertRaises(ValidationRoutingError) as raised:
            ValidationRouter(AdapterResolver([_preset()])).route(
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
        with self.assertRaises(ValidationRoutingError) as raised:
            ValidationRouter(AdapterResolver([_preset()])).route(
                RoutingRequest(
                    system_id="vllm",
                    requested_engine=ValidationEngine.GENERIC_HARNESS,
                    requested_preset=_ref(),
                )
            )

        self.assertEqual(
            raised.exception.code,
            ValidationRoutingErrorCode.PRESET_SYSTEM_MISMATCH,
        )

    def test_multiple_eligible_presets_fail_instead_of_choosing_by_order(self):
        resolver = AdapterResolver(
            [
                _preset(preset_id="ccc.legacy"),
                _preset(preset_id="ccc.hardened", digest="b" * 64),
            ]
        )
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

    def test_duplicate_exact_preset_refs_are_rejected_at_registry_boundary(self):
        with self.assertRaises(ValidationRoutingError) as raised:
            AdapterResolver([_preset(), _preset()])

        self.assertEqual(
            raised.exception.code,
            ValidationRoutingErrorCode.DUPLICATE_PRESET_REF,
        )

    def test_same_preset_id_can_pin_an_exact_version_and_hash(self):
        v1 = _preset()
        v2 = TrustedPresetRecord(
            preset=_ref(preset_version="2.0.0", digest="b" * 64),
            system_id="ccc",
            capabilities=v1.capabilities,
        )
        router = ValidationRouter(AdapterResolver([v1, v2]))

        decision = router.route(
            RoutingRequest(
                system_id="ccc",
                requested_engine=ValidationEngine.GENERIC_HARNESS,
                requested_preset=v2.preset,
            )
        )

        self.assertEqual(decision.preset, v2.preset)

    def test_same_preset_id_and_version_with_different_hashes_conflict(self):
        with self.assertRaises(ValidationRoutingError) as raised:
            AdapterResolver(
                [
                    _preset(),
                    _preset(digest="b" * 64),
                ]
            )

        self.assertEqual(
            raised.exception.code,
            ValidationRoutingErrorCode.CONFLICTING_PRESET_HASH,
        )

    def test_explicit_hash_mismatch_fails_closed(self):
        with self.assertRaises(ValidationRoutingError) as raised:
            ValidationRouter(AdapterResolver([_preset()])).route(
                RoutingRequest(
                    system_id="ccc",
                    requested_engine=ValidationEngine.GENERIC_HARNESS,
                    requested_preset=_ref(digest="b" * 64),
                )
            )

        self.assertEqual(
            raised.exception.code,
            ValidationRoutingErrorCode.CONFLICTING_PRESET_HASH,
        )

    def test_explicit_preset_capability_mismatch_fails_closed(self):
        record = _preset()
        with self.assertRaises(ValidationRoutingError) as raised:
            ValidationRouter(AdapterResolver([record])).route(
                RoutingRequest(
                    system_id="ccc",
                    requested_engine=ValidationEngine.GENERIC_HARNESS,
                    requested_preset=record.preset,
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
                adapter_kind=GenericAdapterKind.GENERIC_AGENT,
            ),
            lambda: RoutingDecision(
                engine=ValidationEngine.GENERIC_HARNESS,
                system_id="ccc",
                reason_code=RoutingReasonCode.AUTO_TRUSTED_PRESET,
                adapter_kind=GenericAdapterKind.TRUSTED_SYSTEM_PRESET,
            ),
            lambda: RoutingDecision(
                engine=ValidationEngine.GENERIC_HARNESS,
                system_id="ccc",
                reason_code=RoutingReasonCode.NO_MATCHING_TRUSTED_PRESET,
                adapter_kind=GenericAdapterKind.GENERIC_AGENT,
                preset=_ref(preset_id="ccc.legacy"),
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

    def test_request_record_and_decision_are_immutable(self):
        values = (
            RoutingRequest(system_id="ccc"),
            _ref(),
            _preset(),
            ValidationRouter().route(RoutingRequest(system_id="ccc")),
        )
        for value in values:
            with self.subTest(value=type(value).__name__):
                with self.assertRaises(dataclasses.FrozenInstanceError):
                    value.system_id = "changed"

    def test_routing_modules_have_no_runtime_or_execution_dependencies(self):
        allowed_absolute_roots = {
            "__future__",
            "collections",
            "dataclasses",
            "enum",
            "re",
        }
        allowed_relative_imports = {
            routing_contracts: set(),
            routing_module: {(1, "contracts.routing")},
        }
        for module in (routing_contracts, routing_module):
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
            self.assertLessEqual(roots, allowed_absolute_roots)
            self.assertEqual(relative_imports, allowed_relative_imports[module])


if __name__ == "__main__":
    unittest.main()

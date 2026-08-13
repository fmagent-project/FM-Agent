import dataclasses
import unittest

from src.validation_core import (
    ComponentKind,
    ComponentRef,
    ContractError,
    PresetDependency,
    PresetRef,
    PresetRegistry,
    PresetRegistryError,
    PresetRegistryErrorCode,
    RegistrationOrigin,
    RegistrationRecord,
    RegistrationTrustTier,
    ValidationPreset,
)
from src.validation_core.contracts import canonical_json_bytes, canonical_sha256


def _component(kind, component_id, digest, version="1.0.0"):
    return ComponentRef(
        kind=kind,
        component_id=component_id,
        component_version=version,
        content_sha256=digest * 64,
    )


def _dependencies(adapter_digest="a", extra=()):
    return (
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
        *extra,
    )


def _preset(
    preset_id="ccc.legacy_boundary_witness_v3",
    preset_version="1.0.0",
    system_id="ccc",
    capabilities=("compiler_entry", "differential_oracle"),
    dependencies=None,
):
    return ValidationPreset(
        preset_id=preset_id,
        preset_version=preset_version,
        system_id=system_id,
        dependencies=(
            _dependencies() if dependencies is None else dependencies
        ),
        capabilities=capabilities,
    )


def _registration(
    preset,
    *,
    origin=RegistrationOrigin.MAINTAINER,
    tier=RegistrationTrustTier.TRUSTED_PRESET,
    authority="fmagent.maintainers",
    capabilities=None,
    review="e",
    approval=None,
    qualification="f",
):
    return RegistrationRecord(
        preset=preset.ref,
        origin=origin,
        trust_tier=tier,
        admission_authority=authority,
        effective_capabilities=(
            preset.capabilities if capabilities is None else capabilities
        ),
        review_sha256=None if review is None else review * 64,
        approval_sha256=None if approval is None else approval * 64,
        qualification_sha256=(
            None if qualification is None else qualification * 64
        ),
    )


class CanonicalContractTests(unittest.TestCase):
    def test_canonical_json_has_a_fixed_byte_and_hash_vector(self):
        value = {"b": 1, "a": 2}

        self.assertEqual(canonical_json_bytes(value), b'{"a":2,"b":1}')
        self.assertEqual(
            canonical_sha256(value),
            "d3626ac30a87e6f7a6428233b3c68299976865fa5508e4267c5415c76af7a772",
        )

    def test_canonical_json_rejects_floats_and_unsupported_values(self):
        invalid_values = (
            {"value": 1.0},
            {"value": float("nan")},
            {"value": float("inf")},
            {1: "non-string-key"},
            {"value": object()},
        )
        for value in invalid_values:
            with self.subTest(value=value):
                with self.assertRaises(ContractError):
                    canonical_json_bytes(value)


class ValidationPresetContractTests(unittest.TestCase):
    def test_preset_is_order_independent_and_contains_no_trust_claim(self):
        forward = _preset()
        reverse = _preset(dependencies=tuple(reversed(_dependencies())))

        self.assertEqual(forward.ref, reverse.ref)
        self.assertEqual(
            tuple(item.role for item in forward.dependencies),
            tuple(sorted(item.role for item in forward.dependencies)),
        )
        document = forward.to_document()
        self.assertEqual(document["contract_kind"], "validation_preset")
        self.assertEqual(document["schema_version"], 1)
        self.assertNotIn("trust", document)
        self.assertNotIn("approved", document)
        self.assertNotIn("effective_capabilities", document)

    def test_dependency_hash_or_extra_policy_changes_preset_identity(self):
        original = _preset()
        changed_adapter = _preset(dependencies=_dependencies(adapter_digest="9"))
        toolchain = PresetDependency(
            "ccc.toolchain.policy",
            _component(
                ComponentKind.TOOLCHAIN_POLICY,
                "ccc.toolchain-v2",
                "8",
            ),
        )
        extended = _preset(dependencies=_dependencies(extra=(toolchain,)))

        self.assertNotEqual(original.ref, changed_adapter.ref)
        self.assertNotEqual(original.ref, extended.ref)

    def test_required_roles_duplicate_roles_and_wrong_kinds_fail_closed(self):
        missing = tuple(
            item for item in _dependencies() if item.role != "oracle.bundle"
        )
        duplicate = _dependencies() + (_dependencies()[0],)
        wrong_kind = tuple(
            PresetDependency(
                item.role,
                _component(
                    ComponentKind.ADAPTER,
                    "wrong.adapter",
                    "9",
                ),
            )
            if item.role == "oracle.bundle"
            else item
            for item in _dependencies()
        )
        for dependencies in (missing, duplicate, wrong_kind):
            with self.subTest(dependencies=dependencies):
                with self.assertRaises(ContractError):
                    _preset(dependencies=dependencies)

    def test_preset_and_dependency_are_immutable(self):
        preset = _preset()
        for value, field in (
            (preset, "system_id"),
            (preset.dependencies[0], "role"),
            (preset.dependencies[0].component, "content_sha256"),
        ):
            with self.subTest(value=type(value).__name__):
                with self.assertRaises(dataclasses.FrozenInstanceError):
                    setattr(value, field, "changed")


class RegistrationContractTests(unittest.TestCase):
    def test_registration_hash_binds_origin_trust_capabilities_and_evidence(self):
        preset = _preset()
        baseline = _registration(preset)
        variants = (
            _registration(preset, origin=RegistrationOrigin.HARNESS),
            _registration(preset, authority="fmagent.bootstrap"),
            _registration(preset, capabilities=("compiler_entry",)),
            _registration(preset, review="1"),
            _registration(preset, qualification="2"),
            _registration(preset, approval="3"),
            _registration(
                preset,
                origin=RegistrationOrigin.SETUP_AGENT,
                tier=RegistrationTrustTier.PROFILE_CUSTOM,
                approval="4",
            ),
        )

        self.assertEqual(baseline.preset, preset.ref)
        self.assertEqual(preset.ref, _preset().ref)
        for variant in variants:
            with self.subTest(variant=variant.to_document()):
                self.assertNotEqual(
                    baseline.registration_sha256,
                    variant.registration_sha256,
                )

    def test_trusted_preset_requires_review_and_qualification(self):
        preset = _preset()
        for kwargs in (
            {"review": None},
            {"qualification": None},
        ):
            with self.subTest(kwargs=kwargs):
                with self.assertRaises(ContractError):
                    _registration(preset, **kwargs)

    def test_setup_agent_cannot_self_promote_without_human_approval(self):
        preset = _preset()

        with self.assertRaises(ContractError):
            _registration(preset, origin=RegistrationOrigin.SETUP_AGENT)

        promoted = _registration(
            preset,
            origin=RegistrationOrigin.SETUP_AGENT,
            approval="4",
        )
        self.assertEqual(promoted.origin, RegistrationOrigin.SETUP_AGENT)

    def test_profile_custom_requires_setup_origin_and_all_evidence(self):
        preset = _preset()
        invalid_kwargs = (
            {
                "tier": RegistrationTrustTier.PROFILE_CUSTOM,
                "origin": RegistrationOrigin.MAINTAINER,
                "approval": "4",
            },
            {
                "tier": RegistrationTrustTier.PROFILE_CUSTOM,
                "origin": RegistrationOrigin.SETUP_AGENT,
                "approval": None,
            },
        )
        for kwargs in invalid_kwargs:
            with self.subTest(kwargs=kwargs):
                with self.assertRaises(ContractError):
                    _registration(preset, **kwargs)


class PresetRegistryTests(unittest.TestCase):
    def test_registry_returns_preset_and_registration_as_one_bound_pair(self):
        preset = _preset()
        registration = _registration(preset)
        registry = PresetRegistry((preset,), (registration,))

        record = registry.require_registered_preset(preset.ref)

        self.assertIs(record.preset, preset)
        self.assertIs(record.registration, registration)
        self.assertEqual(
            registry.referenced_component_refs(),
            tuple(
                sorted(
                    preset.component_refs,
                    key=lambda ref: (
                        ref.kind.value,
                        ref.component_id,
                        ref.component_version,
                        ref.content_sha256,
                    ),
                )
            ),
        )

    def test_unregistered_preset_is_known_but_not_exposed_as_registered(self):
        admitted = _preset()
        staged = _preset(preset_id="ccc.staged", preset_version="2.0.0")
        registry = PresetRegistry(
            (admitted, staged),
            (_registration(admitted),),
        )

        self.assertIsNone(registry.registered_preset(staged.ref))
        self.assertEqual(
            registry.known_preset_ref(staged.preset_id, staged.preset_version),
            staged.ref,
        )
        with self.assertRaises(PresetRegistryError) as raised:
            registry.require_registered_preset(staged.ref)
        self.assertEqual(
            raised.exception.code,
            PresetRegistryErrorCode.UNREGISTERED_PRESET,
        )

    def test_registration_must_reference_the_exact_preset_hash(self):
        preset = _preset()
        wrong = RegistrationRecord(
            preset=PresetRef(
                preset_id=preset.preset_id,
                preset_version=preset.preset_version,
                content_sha256="9" * 64,
            ),
            origin=RegistrationOrigin.MAINTAINER,
            trust_tier=RegistrationTrustTier.TRUSTED_PRESET,
            admission_authority="fmagent.maintainers",
            effective_capabilities=preset.capabilities,
            review_sha256="e" * 64,
            qualification_sha256="f" * 64,
        )

        with self.assertRaises(PresetRegistryError) as raised:
            PresetRegistry((preset,), (wrong,))
        self.assertEqual(
            raised.exception.code,
            PresetRegistryErrorCode.REGISTRATION_HASH_MISMATCH,
        )

    def test_orphan_and_duplicate_registrations_fail_closed(self):
        preset = _preset()
        registration = _registration(preset)
        for presets, registrations, expected_code in (
            ((), (registration,), PresetRegistryErrorCode.UNREGISTERED_PRESET),
            (
                (preset,),
                (registration, registration),
                PresetRegistryErrorCode.DUPLICATE_REGISTRATION,
            ),
        ):
            with self.subTest(expected_code=expected_code):
                with self.assertRaises(PresetRegistryError) as raised:
                    PresetRegistry(presets, registrations)
                self.assertEqual(raised.exception.code, expected_code)

    def test_registration_cannot_grant_undeclared_capabilities(self):
        preset = _preset()
        registration = _registration(
            preset,
            capabilities=(*preset.capabilities, "gpu"),
        )

        with self.assertRaises(PresetRegistryError) as raised:
            PresetRegistry((preset,), (registration,))
        self.assertEqual(
            raised.exception.code,
            PresetRegistryErrorCode.CAPABILITY_ESCALATION,
        )

    def test_duplicate_and_conflicting_preset_identities_fail_closed(self):
        preset = _preset()
        conflicting = _preset(dependencies=_dependencies(adapter_digest="9"))
        for presets, expected_code in (
            ((preset, preset), PresetRegistryErrorCode.DUPLICATE_PRESET_REF),
            (
                (preset, conflicting),
                PresetRegistryErrorCode.CONFLICTING_PRESET_HASH,
            ),
        ):
            with self.subTest(expected_code=expected_code):
                with self.assertRaises(PresetRegistryError) as raised:
                    PresetRegistry(presets)
                self.assertEqual(raised.exception.code, expected_code)

    def test_conflicting_component_hashes_across_registered_presets_fail_closed(self):
        first = _preset(preset_id="ccc.first")
        second = _preset(
            preset_id="ccc.second",
            dependencies=_dependencies(adapter_digest="9"),
        )

        with self.assertRaises(PresetRegistryError) as raised:
            PresetRegistry(
                (first, second),
                (_registration(first), _registration(second)),
            )
        self.assertEqual(
            raised.exception.code,
            PresetRegistryErrorCode.COMPONENT_HASH_CONFLICT,
        )


if __name__ == "__main__":
    unittest.main()

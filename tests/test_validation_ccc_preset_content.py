import ast
import json
import hashlib
import unittest
from pathlib import Path

import src.validation_core as validation_core_root
import src.validation_core.presets.ccc.components as components_module
import src.validation_core.presets.ccc.preset as preset_module
from src.validation_core import (
    AdapterResolver,
    ComponentKind,
    GenericAdapterKind,
    PresetRegistry,
    PresetRegistryError,
    PresetRegistryErrorCode,
    RoutingRequest,
    ValidationEngine,
    ValidationRouter,
    ValidationRoutingError,
    ValidationRoutingErrorCode,
)
from src.validation_core.contracts import canonical_json_bytes
from src.validation_core.presets.ccc import CCC_COMPONENTS, CCC_LEGACY_PRESET
from tests.validator_legacy_golden import corpus_sha256, load_corpus


_MAP_PATH = (
    Path(__file__).resolve().parent
    / "fixtures"
    / "validator_legacy_golden"
    / "v1"
    / "preset_map.json"
)


class CCCPresetContentTests(unittest.TestCase):
    def test_preset_contains_exactly_eight_hash_bound_component_roles(self):
        dependencies = {
            dependency.role: dependency.component
            for dependency in CCC_LEGACY_PRESET.dependencies
        }

        self.assertEqual(
            set(dependencies),
            {
                "adapter.primary",
                "oracle.bundle",
                "recipe.schema",
                "target_evidence.policy",
                "repair.policy",
                "sanity.policy",
                "compatibility.policy",
                "toolchain.policy",
            },
        )
        self.assertEqual(len(CCC_COMPONENTS), 8)
        self.assertEqual(
            set(dependencies.values()),
            {descriptor.ref for descriptor in CCC_COMPONENTS},
        )
        self.assertNotIn(ComponentKind.CONTROL_POLICY, {
            descriptor.kind for descriptor in CCC_COMPONENTS
        })

    def test_component_sources_are_bound_to_the_pinned_multirun_commit(self):
        sources = {
            ref.relative_path: (
                ref.revision,
                ref.git_blob_sha1,
                ref.source_sha256,
                ref.size_bytes,
            )
            for descriptor in CCC_COMPONENTS
            for ref in descriptor.implementation_refs
        }
        expected_paths = {
            "src/audit_runner.py",
            "src/check_submission.py",
            "src/compiler_recipe.py",
            "src/coverage_witness.py",
            "src/l1_patch_tool.py",
            "src/l1_verifier.py",
            "src/phenomenon_runner.py",
            "src/submission_schema.py",
            "src/validation_artifacts.py",
            "src/validation_context.py",
            "src/validation_recheck.py",
            "src/validation_submit.py",
            "src/validation_toolchain.py",
            "src/validation_workspace.py",
            "src/validator_sandbox.py",
            "src/verification.py",
            "tools/audit_setup.py",
            "tools/fm_audit_init.rs",
            "tools/fm_audit_span_id.rs",
            "tools/instrument.py",
            "tools/l1_scope/Cargo.lock",
            "tools/l1_scope/Cargo.toml",
            "tools/l1_scope/src/main.rs",
            "tools/validation_sanity_corpus/basic.c",
            "tools/validation_sanity_corpus/control_flow.c",
            "tools/validation_sanity_corpus/declarations.c",
            "tools/validation_sanity_corpus/function_pointer.c",
        }

        self.assertEqual(set(sources), expected_paths)
        self.assertTrue(all(
            value[0] == "29eb099c01e6b6ef2f8e68ebc41608184b9f13d4"
            for value in sources.values()
        ))
        self.assertEqual(
            sources["src/compiler_recipe.py"],
            (
                "29eb099c01e6b6ef2f8e68ebc41608184b9f13d4",
                "cd68b941d9a8686199c9e25c7daaa2f21c0a594b",
                "4804f99707f160ad908ea367c54049d98ef89288a379aa4ad9ba6f80155f0c96",
                2693,
            ),
        )
        self.assertEqual(
            sources["src/verification.py"],
            (
                "29eb099c01e6b6ef2f8e68ebc41608184b9f13d4",
                "1df28798fcfcc41c755ada29cc11d4c18fed200a",
                "b318bb6d63dc8d6e5432acd4ebe10b1ea105f07d6f70e2512daf42c7bbc621ee",
                40581,
            ),
        )

    def test_golden_map_covers_every_cell_without_relabelling_policy(self):
        corpus = load_corpus()
        mapping = json.loads(_MAP_PATH.read_text(encoding="utf-8"))
        case_ids = {case["case_id"] for case in corpus["cases"]}
        roles = {dependency.role for dependency in CCC_LEGACY_PRESET.dependencies}

        self.assertEqual(mapping["mapping_schema_version"], 1)
        self.assertEqual(mapping["corpus_sha256"], corpus_sha256(corpus))
        self.assertEqual(mapping["preset_id"], CCC_LEGACY_PRESET.preset_id)
        self.assertEqual(mapping["preset_version"], CCC_LEGACY_PRESET.preset_version)
        self.assertEqual(
            mapping["component_sha256"],
            {
                descriptor.component_id: descriptor.content_sha256
                for descriptor in CCC_COMPONENTS
            },
        )
        self.assertEqual(
            mapping["preset_sha256"],
            CCC_LEGACY_PRESET.content_sha256,
        )
        self.assertEqual(set(mapping["cases"]), case_ids)
        self.assertEqual(len(case_ids), 32)
        for case_id, mapped_roles in mapping["cases"].items():
            with self.subTest(case_id=case_id):
                self.assertTrue(mapped_roles)
                self.assertEqual(mapped_roles, sorted(set(mapped_roles)))
                self.assertLessEqual(set(mapped_roles), roles)

        policies = [case["parity_policy"] for case in corpus["cases"]]
        self.assertEqual(policies.count("must_match"), 30)
        self.assertEqual(policies.count("legacy_known_gap"), 1)
        self.assertEqual(policies.count("intentional_cutover_delta"), 1)

        self.assertEqual(
            hashlib.sha256(canonical_json_bytes(mapping)).hexdigest(),
            "0fd9d5ae705e8b9813a2309086c2c019646766434c59eeb7e125fbe7c21c14d7",
        )

        compatibility = next(
            descriptor
            for descriptor in CCC_COMPONENTS
            if descriptor.kind is ComponentKind.COMPATIBILITY_POLICY
        )
        golden_values = next(
            clause.values
            for clause in compatibility.semantic_contract.clauses
            if clause.clause_id == "golden_corpus"
        )
        self.assertIn(corpus_sha256(corpus), " ".join(golden_values))
        self.assertEqual(compatibility.component_version, "1.0.1")
        self.assertEqual(
            compatibility.semantic_contract.contract_version,
            "1.0.1",
        )
        self.assertEqual(CCC_LEGACY_PRESET.preset_version, "1.0.1")
        self.assertEqual(
            {
                descriptor.component_version
                for descriptor in CCC_COMPONENTS
                if descriptor is not compatibility
            },
            {"1.0.0"},
        )

    def test_staged_preset_is_known_but_mechanically_unregistered(self):
        registry = PresetRegistry((CCC_LEGACY_PRESET,), ())

        self.assertEqual(
            registry.known_preset_ref(
                CCC_LEGACY_PRESET.preset_id,
                CCC_LEGACY_PRESET.preset_version,
            ),
            CCC_LEGACY_PRESET.ref,
        )
        self.assertTrue(registry.has_system("ccc"))
        self.assertEqual(registry.registered_presets(), ())
        self.assertIsNone(registry.registered_preset(CCC_LEGACY_PRESET.ref))
        self.assertEqual(registry.referenced_component_refs(), ())
        with self.assertRaises(PresetRegistryError) as raised:
            registry.require_registered_preset(CCC_LEGACY_PRESET.ref)
        self.assertEqual(
            raised.exception.code,
            PresetRegistryErrorCode.UNREGISTERED_PRESET,
        )

    def test_staged_preset_cannot_run_and_does_not_change_default_routes(self):
        staged_router = ValidationRouter(
            AdapterResolver(PresetRegistry((CCC_LEGACY_PRESET,), ()))
        )
        requests = (
            RoutingRequest(
                system_id="ccc",
                requested_engine=ValidationEngine.GENERIC_HARNESS,
            ),
            RoutingRequest(
                system_id="ccc",
                requested_engine=ValidationEngine.GENERIC_HARNESS,
                requested_preset=CCC_LEGACY_PRESET.ref,
            ),
        )
        for request in requests:
            with self.subTest(request=request):
                with self.assertRaises(ValidationRoutingError) as raised:
                    staged_router.route(request)
                self.assertEqual(
                    raised.exception.code,
                    ValidationRoutingErrorCode.PRESET_NOT_REGISTERED,
                )

        legacy = ValidationRouter().route(RoutingRequest(system_id="ccc"))
        self.assertEqual(legacy.engine, ValidationEngine.LEGACY_PROMPT)
        generic = ValidationRouter().route(
            RoutingRequest(
                system_id="ccc",
                requested_engine=ValidationEngine.GENERIC_HARNESS,
            )
        )
        self.assertEqual(generic.adapter_kind, GenericAdapterKind.GENERIC_AGENT)

    def test_ccc_content_has_no_registration_or_runtime_import_path(self):
        self.assertFalse(hasattr(validation_core_root, "CCC_LEGACY_PRESET"))
        forbidden_names = {
            "RegistrationRecord",
            "RegistrationOrigin",
            "RegistrationTrustTier",
            "PresetRegistry",
            "ValidationRouter",
            "AdapterResolver",
        }
        root_source = Path(validation_core_root.__file__).read_text(encoding="utf-8")
        self.assertNotIn(".presets", root_source)
        for module in (components_module, preset_module):
            source = Path(module.__file__).read_text(encoding="utf-8")
            tree = ast.parse(source)
            imported_names = set()
            imported_modules = set()
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    imported_modules.update(alias.name for alias in node.names)
                elif isinstance(node, ast.ImportFrom):
                    imported_modules.add(node.module or "")
                    imported_names.update(alias.name for alias in node.names)
            self.assertTrue(forbidden_names.isdisjoint(imported_names))
            self.assertFalse(any(
                name in module_name
                for module_name in imported_modules
                for name in ("registry", "routing", "verification", "subprocess")
            ))
        for descriptor in CCC_COMPONENTS:
            rendered = repr(descriptor.semantic_contract.to_document()).lower()
            self.assertNotIn("inactive", rendered)
            self.assertNotIn("registration", rendered)
            self.assertNotIn("trusted=true", rendered)

    def test_component_contract_module_has_no_runtime_dependencies(self):
        import src.validation_core.contracts.component as component_module

        source = Path(component_module.__file__).read_text(encoding="utf-8")
        tree = ast.parse(source)
        absolute_roots = set()
        relative_imports = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                absolute_roots.update(
                    alias.name.split(".", 1)[0] for alias in node.names
                )
            elif isinstance(node, ast.ImportFrom):
                if node.level == 0:
                    absolute_roots.add((node.module or "").split(".", 1)[0])
                else:
                    relative_imports.add((node.level, node.module or ""))
        self.assertLessEqual(
            absolute_roots,
            {"__future__", "dataclasses", "re"},
        )
        self.assertEqual(relative_imports, {(1, "base")})


if __name__ == "__main__":
    unittest.main()

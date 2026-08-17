import ast
import dataclasses
import hashlib
import inspect
import unittest
from pathlib import Path

import src.validation_core as validation_core_root
from src.validation_core.constrained_adapter import (
    ApprovedAdapterProfile,
    ConstrainedAdapterError,
    ConstrainedAdapterErrorCode,
    ConstrainedExactRefPlanner,
    ConstrainedPlanRequest,
)
from src.validation_core.contracts import (
    ArtifactRef,
    ContractRef,
    ContractRefKind,
    GenericAdapterKind,
    RegistrationOrigin,
    RegistrationRecord,
    RegistrationTrustTier,
    ValidationEngine,
)
from src.validation_core.presets.ccc import CCC_LEGACY_PRESET
from src.validation_core.vertical_demo import (
    DemoEntryMode,
    DemoEvidenceClass,
    DemoRolloutPolicy,
    VerticalDemoError,
    VerticalDemoErrorCode,
    VerticalDemoHarness,
    VerticalDemoReason,
    VerticalDemoReport,
    VerticalDemoStatus,
)


def _digest(label):
    return hashlib.sha256(label.encode("utf-8")).hexdigest()


def _ref(kind, label):
    return ContractRef(
        kind=kind,
        contract_id=f"demo.{label}",
        contract_version="1.0.0",
        content_sha256=_digest(label),
    )


def _planner_and_request(system_id):
    adapter = _ref(ContractRefKind.ADAPTER, f"{system_id}.adapter")
    recipe = _ref(ContractRefKind.EXECUTION_RECIPE, f"{system_id}.recipe")
    oracle = _ref(ContractRefKind.ORACLE_SPEC, f"{system_id}.oracle")
    collector = _ref(ContractRefKind.COLLECTOR, f"{system_id}.collector")
    profile = ApprovedAdapterProfile(
        system_id=system_id,
        profile_sha256=_digest(f"{system_id}.profile"),
        adapter=adapter,
        execution_recipes=(recipe,),
        oracle_specs=(oracle,),
        collectors=(collector,),
        effective_capabilities=("correctness",),
    )
    request = ConstrainedPlanRequest(
        system_id=system_id,
        adapter=adapter,
        execution_recipe=recipe,
        oracle_specs=(oracle,),
        collectors=(collector,),
        required_capabilities=("correctness",),
        input_artifacts=(
            ArtifactRef(
                role="workload",
                media_type="application/json",
                size_bytes=2,
                content_sha256=_digest(f"{system_id}.workload"),
            ),
        ),
    )
    return ConstrainedExactRefPlanner(profile), request


def _ccc_registration():
    return RegistrationRecord(
        preset=CCC_LEGACY_PRESET.ref,
        origin=RegistrationOrigin.HARNESS,
        trust_tier=RegistrationTrustTier.TRUSTED_PRESET,
        admission_authority="vertical-demo-caller",
        effective_capabilities=CCC_LEGACY_PRESET.capabilities,
        review_sha256=_digest("ccc.demo.review"),
        qualification_sha256=_digest("ccc.demo.qualification"),
    )


class ConstrainedExactRefPlannerTests(unittest.TestCase):
    def test_plan_contains_only_exact_approved_refs_and_content_artifacts(self):
        planner, request = _planner_and_request("unknown-project")

        plan = planner.plan(request)

        self.assertEqual(plan.system_id, request.system_id)
        self.assertEqual(plan.request_sha256, request.content_sha256)
        self.assertEqual(plan.adapter, request.adapter)
        self.assertEqual(plan.execution_recipe, request.execution_recipe)
        self.assertEqual(plan.oracle_specs, request.oracle_specs)
        self.assertEqual(plan.collectors, request.collectors)
        self.assertEqual(plan.input_artifacts, request.input_artifacts)
        self.assertEqual(plan.content_sha256, plan.content_sha256)

    def test_foreign_hash_and_capability_fail_closed(self):
        planner, request = _planner_and_request("vllm")
        foreign_recipe = ContractRef(
            kind=request.execution_recipe.kind,
            contract_id=request.execution_recipe.contract_id,
            contract_version=request.execution_recipe.contract_version,
            content_sha256=_digest("foreign-recipe-bytes"),
        )
        foreign_request = dataclasses.replace(
            request,
            execution_recipe=foreign_recipe,
        )
        with self.assertRaises(ConstrainedAdapterError) as raised:
            planner.plan(foreign_request)
        self.assertEqual(
            raised.exception.code,
            ConstrainedAdapterErrorCode.RECIPE_NOT_APPROVED,
        )

        excess = dataclasses.replace(
            request,
            required_capabilities=("correctness", "public_network"),
        )
        with self.assertRaises(ConstrainedAdapterError) as raised:
            planner.plan(excess)
        self.assertEqual(
            raised.exception.code,
            ConstrainedAdapterErrorCode.CAPABILITY_NOT_APPROVED,
        )

    def test_agent_request_has_no_shell_path_environment_or_import_surface(self):
        fields = {field.name for field in dataclasses.fields(ConstrainedPlanRequest)}
        forbidden_fragments = (
            "argv",
            "command",
            "cwd",
            "env",
            "executable",
            "import",
            "path",
            "shell",
        )
        self.assertFalse(any(
            fragment in field
            for field in fields
            for fragment in forbidden_fragments
        ))
        planner, request = _planner_and_request("vllm")
        with self.assertRaises(TypeError):
            ConstrainedPlanRequest(
                **request.__dict__,
                shell="bash -c arbitrary",  # type: ignore[call-arg]
            )

        source_path = Path(inspect.getsourcefile(ConstrainedPlanRequest))
        tree = ast.parse(source_path.read_text(encoding="utf-8"))
        imported_roots = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported_roots.update(alias.name.split(".", 1)[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.level == 0:
                imported_roots.add((node.module or "").split(".", 1)[0])
        self.assertTrue(
            imported_roots.isdisjoint(
                {"importlib", "os", "pathlib", "socket", "subprocess"}
            )
        )
        self.assertEqual(planner.plan(request).adapter, request.adapter)


class VerticalDemoHarnessTests(unittest.TestCase):
    def test_default_rollout_keeps_every_entry_mode_on_legacy_prompt(self):
        harness = VerticalDemoHarness()
        rollout = DemoRolloutPolicy()

        for mode in DemoEntryMode:
            for system_id in ("ccc", "vllm", "openharmony", "unknown-project"):
                with self.subTest(mode=mode, system_id=system_id):
                    report = harness.run(
                        system_id=system_id,
                        entry_mode=mode,
                        rollout=rollout,
                    )
                    self.assertEqual(report.status, VerticalDemoStatus.LEGACY_ONLY)
                    self.assertEqual(report.route.engine, ValidationEngine.LEGACY_PROMPT)
                    self.assertEqual(
                        report.reason,
                        VerticalDemoReason.LEGACY_PROMPT_DEFAULT,
                    )
                    self.assertFalse(report.simulated)
                    self.assertFalse(report.admissible)

    def test_ccc_requires_injected_registration_and_remains_shadow_only(self):
        rollout = DemoRolloutPolicy((DemoEntryMode.FULL,))
        with self.assertRaises(VerticalDemoError) as raised:
            VerticalDemoHarness().run(
                system_id="ccc",
                entry_mode=DemoEntryMode.FULL,
                rollout=rollout,
            )
        self.assertEqual(
            raised.exception.code,
            VerticalDemoErrorCode.CCC_REGISTRATION_REQUIRED,
        )

        registration = _ccc_registration()
        report = VerticalDemoHarness(
            ccc_registration=registration,
        ).run(
            system_id="ccc",
            entry_mode=DemoEntryMode.FULL,
            rollout=rollout,
        )

        self.assertEqual(report.status, VerticalDemoStatus.SHADOW_ROUTE_ONLY)
        self.assertEqual(
            report.reason,
            VerticalDemoReason.CCC_SHADOW_ROUTE_ONLY_NON_ADMISSIBLE,
        )
        self.assertEqual(
            report.evidence_class,
            DemoEvidenceClass.CCC_SHADOW_ROUTE_ONLY,
        )
        self.assertEqual(report.route.engine, ValidationEngine.GENERIC_HARNESS)
        self.assertEqual(
            report.route.adapter_kind,
            GenericAdapterKind.TRUSTED_SYSTEM_PRESET,
        )
        self.assertEqual(report.route.preset, CCC_LEGACY_PRESET.ref)
        self.assertEqual(
            report.route.registration_sha256,
            registration.registration_sha256,
        )
        self.assertTrue(report.simulated)
        self.assertFalse(report.admissible)
        self.assertIsNone(report.current_outcome_sha256)
        self.assertIsNone(report.certificate_sha256)

    def test_vllm_and_openharmony_are_explicit_infra_inconclusive(self):
        rollout = DemoRolloutPolicy((DemoEntryMode.INCREMENTAL,))
        expected = {
            "vllm": VerticalDemoReason.VLLM_SERVICE_GPU_BROKER_NOT_CONNECTED,
            "openharmony": (
                VerticalDemoReason.OPENHARMONY_XDEVICE_DEVICE_BROKER_NOT_CONNECTED
            ),
        }
        for system_id, reason in expected.items():
            planner, request = _planner_and_request(system_id)
            with self.subTest(system_id=system_id):
                report = VerticalDemoHarness().run(
                    system_id=system_id,
                    entry_mode=DemoEntryMode.INCREMENTAL,
                    rollout=rollout,
                    planner=planner,
                    plan_request=request,
                )
                self.assertEqual(
                    report.status,
                    VerticalDemoStatus.INCONCLUSIVE_INFRA,
                )
                self.assertEqual(report.reason, reason)
                self.assertEqual(
                    report.evidence_class,
                    DemoEvidenceClass.EXACT_REF_PLAN_ONLY,
                )
                self.assertEqual(
                    report.route.adapter_kind,
                    GenericAdapterKind.GENERIC_AGENT,
                )
                self.assertIsNotNone(report.plan_sha256)
                self.assertTrue(report.simulated)
                self.assertFalse(report.admissible)
                self.assertIsNone(report.current_outcome_sha256)
                self.assertIsNone(report.certificate_sha256)

    def test_unknown_project_can_plan_but_cannot_claim_an_oracle(self):
        planner, request = _planner_and_request("unknown-project")
        report = VerticalDemoHarness().run(
            system_id="unknown-project",
            entry_mode=DemoEntryMode.RESUME,
            rollout=DemoRolloutPolicy((DemoEntryMode.RESUME,)),
            planner=planner,
            plan_request=request,
        )
        self.assertEqual(report.status, VerticalDemoStatus.INCONCLUSIVE_ORACLE)
        self.assertEqual(
            report.reason,
            VerticalDemoReason.NO_REAL_ADAPTER_IMPLEMENTATION,
        )
        self.assertEqual(report.evidence_class, DemoEvidenceClass.EXACT_REF_PLAN_ONLY)
        self.assertFalse(report.admissible)

    def test_inconclusive_status_reason_and_evidence_matrix_is_closed(self):
        planner, request = _planner_and_request("vllm")
        report = VerticalDemoHarness().run(
            system_id="vllm",
            entry_mode=DemoEntryMode.FULL,
            rollout=DemoRolloutPolicy((DemoEntryMode.FULL,)),
            planner=planner,
            plan_request=request,
        )
        mutations = (
            {
                "reason": (
                    VerticalDemoReason.OPENHARMONY_XDEVICE_DEVICE_BROKER_NOT_CONNECTED
                ),
            },
            {"evidence_class": DemoEvidenceClass.NONE},
            {"status": VerticalDemoStatus.INCONCLUSIVE_ORACLE},
        )
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                with self.assertRaises(ValueError):
                    dataclasses.replace(report, **mutation)

    def test_demo_report_cannot_be_initialized_as_outcome_or_certificate(self):
        route = VerticalDemoHarness().run(
            system_id="ccc",
            entry_mode=DemoEntryMode.ALL_BUGS,
        ).route
        arguments = {
            "entry_mode": DemoEntryMode.ALL_BUGS,
            "route": route,
            "status": VerticalDemoStatus.LEGACY_ONLY,
            "reason": VerticalDemoReason.LEGACY_PROMPT_DEFAULT,
            "evidence_class": DemoEvidenceClass.NONE,
            "simulated": False,
        }
        for forbidden in (
            "admissible",
            "current_outcome_sha256",
            "certificate_sha256",
        ):
            with self.subTest(forbidden=forbidden):
                with self.assertRaises(TypeError):
                    VerticalDemoReport(
                        **arguments,
                        **{forbidden: _digest(forbidden)},
                    )

    def test_dormant_demo_is_not_exported_or_loaded_by_production_root(self):
        for name in (
            "ApprovedAdapterProfile",
            "ConstrainedExactRefPlanner",
            "VerticalDemoHarness",
            "VerticalDemoReport",
        ):
            self.assertFalse(hasattr(validation_core_root, name), name)
        root_source = Path(validation_core_root.__file__).read_text(encoding="utf-8")
        self.assertNotIn("constrained_adapter", root_source)
        self.assertNotIn("vertical_demo", root_source)


if __name__ == "__main__":
    unittest.main()

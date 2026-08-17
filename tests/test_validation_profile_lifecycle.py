from __future__ import annotations

import dataclasses
import hashlib
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest

from src.validation_core.contracts.base import (
    CanonicalDecimal,
    ContractError,
    canonical_json_bytes,
    canonical_sha256,
)
from src.validation_core.contracts.evidence import OracleVerdict
from src.validation_core.contracts.oracle import GoldenMethod
from src.validation_core.contracts.preset import RegistrationTrustTier
from src.validation_core.contracts.profile import ProjectBinding
from src.validation_core.contracts.references import (
    ArtifactRef,
    ContractRef,
    ContractRefKind,
)
from src.validation_core.contracts.setup import (
    ApprovalAuthorityKind,
    ApprovalDecision,
    CalibrationReport,
    DependencyBinding,
    DependencyInvalidationManifest,
    DependencyKind,
    FixtureVisibility,
    InvalidationAction,
    ProfileGraph,
    ProfileSetupCandidate,
    QualificationMode,
    QualificationPartition,
    QualificationPartitionKind,
    QualificationPlan,
    QualificationPolicy,
    QualificationTrial,
    QualificationUnit,
    QualificationVerdict,
    ReviewRecord,
    ReviewVerdict,
    RevocationEntry,
    RevocationLedger,
    RevocationReason,
    RevocationTarget,
    RevocationTargetKind,
    SemanticApprovalRecord,
    SetupActorRole,
    SetupState,
    StatisticalBoundMethod,
    make_review_subject,
)
from src.validation_core.setup.lifecycle import (
    ProfileGatePolicy,
    ProfileSetupConfiguration,
    ProfileSetupCoordinator,
    ProfileSetupError,
    ProfileSetupFailureCode,
    ProfileSetupProviders,
    QualificationEvidenceVerificationProof,
    QualificationProviderResult,
    ReviewVerificationProof,
    ReviewMaterial,
    RevocationVerificationProof,
    SemanticApprovalVerificationProof,
    StaticProfileVerificationProof,
)
from src.validation_core.setup.qualification import evaluate_qualification
from src.validation_core.storage.profile import ProfileStore
from tests.test_validation_profile_contracts import (
    _bundle,
    _golden_spec,
    _profile,
    _recipe,
    _unique_refs,
)


def _sha(value: str | bytes) -> str:
    if type(value) is str:
        value = value.encode("utf-8")
    return hashlib.sha256(value).hexdigest()


def _time(minute: int) -> str:
    return f"2026-08-17T00:{minute:02d}:00Z"


class _LifecycleFixture:
    def __init__(self, root: Path) -> None:
        self.store = ProfileStore.create(root)
        self._staged: set[str] = set()
        self._raw_contracts: dict[str, bytes] = {}
        self.approval_calls = 0
        self.review_calls = 0
        self.qualification_calls = 0

        self.revocation_authority = _sha("revocation-authority-policy")
        self.approval_authority = _sha("approval-authority-policy")
        self.qualification_authority = _sha("qualification-authority-policy")
        self.review_authority = _sha("review-authority-policy")
        self.static_profile_authority = _sha("static-profile-authority-policy")
        self.governance_policy = _sha("setup-governance-policy")

        self.policy = QualificationPolicy(
            policy_id="qualification.policy",
            policy_version="1.0.0",
            mode=QualificationMode.DETERMINISTIC,
            trial_unit_id="oracle.decision",
            bound_method=StatisticalBoundMethod.NOT_APPLICABLE,
            confidence_level=CanonicalDecimal("1"),
            max_false_violation_rate=CanonicalDecimal("0"),
            min_detection_rate=CanonicalDecimal("1"),
            min_non_violating_groups=1,
            min_negative_groups=1,
            min_calibrated_cells=0,
            min_fault_cells=0,
            max_retries_per_trial=1,
            retryable_reasons=("temporary_broker_loss",),
            qualification_ttl_seconds=7_200,
            require_ood_inconclusive=True,
        )
        self.recipe = _recipe(recipe_id="lifecycle.recipe")
        base_spec = _golden_spec(
            self.recipe,
            oracle_id="lifecycle.correctness",
        )
        oracle_domain = self.artifact("calibrated_domain", "oracle-domain")
        golden = self.artifact("golden", "oracle-golden")
        self.spec = dataclasses.replace(
            base_spec,
            applicability=dataclasses.replace(
                base_spec.applicability,
                calibrated_domain=oracle_domain,
            ),
            method=GoldenMethod("candidate", golden),
        )
        self.bundle = _bundle((self.spec,), bundle_id="lifecycle.bundle")
        components = _unique_refs(
            self.spec.component_refs,
            self.bundle.component_refs,
            self.recipe.component_refs,
            (self.policy.ref,),
        )
        self.graph_template = _profile(
            (self.spec,),
            (self.bundle,),
            (self.recipe,),
            components=components,
        )

        self.adapter_code = self.artifact("adapter_code", "adapter-code")
        self.dependency_lock = self.artifact(
            "dependency_lock", "dependency-lock"
        )
        self.sbom = self.artifact("sbom", "sbom")
        self.permission_manifest = self.artifact(
            "permission_manifest", "permissions"
        )
        for value in (self.policy, self.recipe, self.spec, self.bundle):
            self.stage_contract(value)
        self.stage_references(
            self.recipe.to_document(),
            self.spec.to_document(),
            self.bundle.to_document(),
        )

        self.gate_policy = ProfileGatePolicy(
            governance_policy_sha256=self.governance_policy,
            admission_authority_kind=ApprovalAuthorityKind.HARNESS,
            admission_authority_id="profile.gate",
            allowed_permissions=("process.broker",),
            supported_adapter_versions=("1.0.0",),
            max_profile_ttl_seconds=3_600,
            revocation_authority_policy_sha256=self.revocation_authority,
            approval_authority_policy_sha256=self.approval_authority,
            qualification_evidence_authority_policy_sha256=(
                self.qualification_authority
            ),
            review_authority_policy_sha256=self.review_authority,
            static_profile_authority_policy_sha256=(
                self.static_profile_authority
            ),
            allowed_reviewer_authorities=("review.service",),
            allowed_reviewer_models=("review.model",),
            allow_profile_custom=True,
        )

    def artifact(self, role: str, label: str) -> ArtifactRef:
        payload = f"{role}:{label}".encode("utf-8")
        receipt = self.store.put_object(payload, expected_sha256=_sha(payload))
        self._staged.add(receipt.sha256)
        return ArtifactRef(
            role=role,
            media_type="application/octet-stream",
            size_bytes=len(payload),
            content_sha256=receipt.sha256,
        )

    def stage_contract(self, value: object) -> None:
        payload = canonical_json_bytes(value.to_document())
        receipt = self.store.put_object(
            payload,
            expected_sha256=value.content_sha256,
        )
        self._staged.add(receipt.sha256)

    def raw_ref(
        self,
        kind: ContractRefKind,
        contract_id: str,
        label: str,
    ) -> ContractRef:
        payload = f"contract:{label}".encode("utf-8")
        digest = _sha(payload)
        self._raw_contracts[digest] = payload
        return ContractRef(kind, contract_id, "1.0.0", digest)

    def stage_references(self, *documents: object) -> None:
        def visit(value: object) -> None:
            if type(value) is dict:
                if value.get("contract_kind") == "contract_ref":
                    reference = ContractRef.from_document(value)
                    digest = reference.content_sha256
                    if digest not in self._staged:
                        payload = self._raw_contracts.get(digest)
                        if payload is None:
                            payload = (
                                f"{reference.kind.value}:"
                                f"{reference.contract_id}:default"
                            ).encode("utf-8")
                        if _sha(payload) != digest:
                            raise AssertionError(
                                f"no fixture payload for {reference.contract_id}"
                            )
                        self.store.put_object(payload, expected_sha256=digest)
                        self._staged.add(digest)
                for child in value.values():
                    visit(child)
            elif type(value) in (list, tuple):
                for child in value:
                    visit(child)

        for document in documents:
            visit(document)

    def build_attempt(
        self,
        *,
        ordinal: int,
        snapshot_label: str,
        passing: bool = True,
    ) -> SimpleNamespace:
        base_minute = ordinal * 10
        graph = ProfileGraph(
            profile_id=self.graph_template.profile_id,
            profile_version=self.graph_template.profile_version,
            project=ProjectBinding(
                system_id=self.graph_template.project.system_id,
                project_kind=self.graph_template.project.project_kind,
                source_snapshot_sha256=_sha(snapshot_label),
                dependency_manifest_sha256=(
                    self.dependency_lock.content_sha256
                ),
            ),
            environment=self.graph_template.environment,
            entrypoints=self.graph_template.entrypoints,
            workload_schemas=self.graph_template.workload_schemas,
            adapters=self.graph_template.adapters,
            instrumentation_providers=(
                self.graph_template.instrumentation_providers
            ),
            oracle_specs=self.graph_template.oracle_specs,
            oracle_bundles=self.graph_template.oracle_bundles,
            execution_recipes=self.graph_template.execution_recipes,
            components=self.graph_template.components,
            capabilities=self.graph_template.capabilities,
        )
        candidate = ProfileSetupCandidate(
            setup_id="setup.lifecycle",
            candidate_version="1.0.0",
            trust_tier=RegistrationTrustTier.PROFILE_CUSTOM,
            profile_graph=graph,
            qualification_policy=self.policy.ref,
            adapter_code=self.adapter_code,
            dependency_lock=self.dependency_lock,
            sbom=self.sbom,
            permission_manifest=self.permission_manifest,
            declared_permissions=("process.broker",),
            created_at=_time(base_minute),
        )
        units = {
            kind: QualificationUnit(
                _sha(f"{kind.value}:member"),
                _sha(f"{kind.value}:group"),
                _sha(f"{kind.value}:cluster"),
            )
            for kind in QualificationPartitionKind
        }
        partitions = tuple(
            QualificationPartition(
                kind=kind,
                fixture_manifest=self.artifact(
                    f"qualification_{kind.value}_fixtures",
                    f"fixtures-{kind.value}",
                ),
                visibility=(
                    FixtureVisibility.SETUP_AGENT_VISIBLE
                    if kind is QualificationPartitionKind.CALIBRATION
                    else FixtureVisibility.HARNESS_ONLY
                ),
                units=(units[kind],),
            )
            for kind in QualificationPartitionKind
        )
        plan = QualificationPlan(
            plan_id="qualification.plan",
            plan_version="1.0.0",
            setup_subject_sha256=candidate.content_sha256,
            qualification_policy=self.policy.ref,
            partitions=partitions,
        )
        calibration_partition = next(
            item
            for item in plan.partitions
            if item.kind is QualificationPartitionKind.CALIBRATION
        )
        calibration = CalibrationReport(
            report_id="calibration.report",
            setup_subject_sha256=candidate.content_sha256,
            qualification_policy_sha256=self.policy.content_sha256,
            qualification_plan_sha256=plan.content_sha256,
            calibration_partition_sha256=canonical_sha256(
                calibration_partition.to_document()
            ),
            calibrated_parameters=self.artifact(
                "calibrated_parameters", f"parameters-{ordinal}"
            ),
            calibrated_domain=self.artifact(
                "calibrated_domain", f"qualification-domain-{ordinal}"
            ),
            warmup_repetitions=1,
            decision_repetitions=1,
            unstable_group_count=0,
            verdict=QualificationVerdict.PASS,
            reason_codes=(),
            completed_at=_time(base_minute + 1),
            expires_at="2026-08-18T00:00:00Z",
        )
        expected = {
            QualificationPartitionKind.CALIBRATION: OracleVerdict.PASS,
            QualificationPartitionKind.HOLDOUT: OracleVerdict.PASS,
            QualificationPartitionKind.NEGATIVE: OracleVerdict.VIOLATION,
            QualificationPartitionKind.OUT_OF_DOMAIN: OracleVerdict.INCONCLUSIVE,
        }
        trials = []
        for index, partition in enumerate(plan.partitions):
            decision = self.raw_ref(
                ContractRefKind.ORACLE_DECISION,
                f"qualification.decision.{ordinal}.{index}",
                f"decision-{ordinal}-{index}",
            )
            observed = expected[partition.kind]
            if not passing and partition.kind is QualificationPartitionKind.HOLDOUT:
                observed = OracleVerdict.VIOLATION
            unit = partition.units[0]
            trials.append(
                QualificationTrial(
                    trial_id=f"qualification.trial.{ordinal}.{index}",
                    partition_kind=partition.kind,
                    member_commitment=unit.member_commitment,
                    group_commitment=unit.group_commitment,
                    cluster_commitment=unit.cluster_commitment,
                    workload_cell_sha256=_sha(
                        f"workload-cell-{ordinal}-{index}"
                    ),
                    oracle_decision=decision,
                    expected_verdict=expected[partition.kind],
                    observed_verdict=observed,
                    stable=True,
                    real_integration=False,
                )
            )
        report = evaluate_qualification(
            report_id="qualification.report",
            policy=self.policy,
            plan=plan,
            calibration_report=calibration,
            trials=tuple(trials),
            qualification_environment_sha256=_sha(
                f"qualification-environment-{ordinal}"
            ),
            completed_at=_time(base_minute + 2),
        )
        manifest = self.manifest(candidate, _time(base_minute))
        review_material = ReviewMaterial(
            bundle_id=f"review.bundle.{ordinal}",
            adapter_diff=self.artifact("adapter_diff", f"diff-{ordinal}"),
            static_scan=self.artifact("static_scan", f"scan-{ordinal}"),
            healthy_relation=self.artifact(
                "healthy_relation", f"relation-{ordinal}"
            ),
            qualification_design_sha256=plan.content_sha256,
            invalidation_manifest_sha256=manifest.content_sha256,
            known_limitations=("linux_only",),
        )
        attempt = SimpleNamespace(
            ordinal=ordinal,
            candidate=candidate,
            plan=plan,
            calibration=calibration,
            report=report,
            manifest=manifest,
            review_material=review_material,
            reviewed_at=_time(base_minute + 3),
            approved_at=_time(base_minute + 4),
            admitted_at=_time(base_minute + 5),
            ledger=self.empty_ledger(),
        )
        self.stage_references(
            candidate.to_document(),
            plan.to_document(),
            calibration.to_document(),
            report.to_document(),
        )
        return attempt

    def manifest(
        self,
        candidate: ProfileSetupCandidate,
        created_at: str,
    ) -> DependencyInvalidationManifest:
        graph = candidate.profile_graph
        semantic = InvalidationAction.REQUALIFY_REVIEW_REAPPROVE
        qualification = InvalidationAction.FULL_QUALIFICATION
        dependencies: list[DependencyBinding] = []

        def add(kind, role, hashes, action):
            for index, digest in enumerate(sorted(set(hashes))):
                dependencies.append(
                    DependencyBinding(
                        kind,
                        f"{role}_{index}",
                        digest,
                        action,
                    )
                )

        add(
            DependencyKind.SOURCE_SNAPSHOT,
            "source_snapshot",
            (graph.project.source_snapshot_sha256,),
            InvalidationAction.PROFILE_GATE,
        )
        add(
            DependencyKind.PROFILE_GRAPH,
            "profile_graph",
            (graph.content_sha256,),
            InvalidationAction.PROFILE_GATE,
        )
        add(DependencyKind.ENTRYPOINT, "entrypoint", (item.content_sha256 for item in graph.entrypoints), semantic)
        add(DependencyKind.WORKLOAD_SCHEMA, "workload", (item.content_sha256 for item in graph.workload_schemas), semantic)
        add(DependencyKind.ADAPTER, "adapter", (item.content_sha256 for item in graph.adapters), semantic)
        add(DependencyKind.INSTRUMENTATION, "instrumentation", (item.content_sha256 for item in graph.instrumentation_providers), semantic)
        add(DependencyKind.ORACLE, "oracle", (item.content_sha256 for item in graph.oracle_specs), semantic)
        add(DependencyKind.ORACLE_BUNDLE, "oracle_bundle", (item.content_sha256 for item in graph.oracle_bundles), semantic)
        add(DependencyKind.EXECUTION_RECIPE, "recipe", (item.content_sha256 for item in graph.execution_recipes), semantic)
        add(
            DependencyKind.PROFILE_COMPONENT,
            "component",
            (
                item.content_sha256
                for item in graph.components
                if item.kind
                not in (
                    ContractRefKind.BASELINE_POLICY,
                    ContractRefKind.RESOURCE_POLICY,
                )
            ),
            semantic,
        )
        add(DependencyKind.BASELINE, "baseline", (item.content_sha256 for item in graph.components if item.kind is ContractRefKind.BASELINE_POLICY), qualification)
        add(DependencyKind.ADAPTER_CODE, "adapter_code", (candidate.adapter_code.content_sha256,), semantic)
        add(DependencyKind.DEPENDENCY_LOCK, "dependency_lock", (graph.project.dependency_manifest_sha256, candidate.dependency_lock.content_sha256), semantic)
        add(DependencyKind.PERMISSION_MANIFEST, "permission_manifest", (candidate.permission_manifest.content_sha256,), semantic)
        add(DependencyKind.SBOM, "sbom", (candidate.sbom.content_sha256,), semantic)
        add(DependencyKind.CAPABILITY_SET, "capabilities", (canonical_sha256({"capabilities": list(graph.capabilities)}),), semantic)
        add(DependencyKind.TOOLCHAIN, "toolchain", (graph.environment.toolchain_sha256,), qualification)
        add(DependencyKind.OS_IMAGE, "os_image", (graph.environment.os_image_sha256,), qualification)
        add(DependencyKind.RESOURCE_POLICY, "resource_policy", (graph.environment.resource_policy.content_sha256,), qualification)
        if graph.environment.model_sha256 is not None:
            add(DependencyKind.MODEL, "model", (graph.environment.model_sha256,), qualification)
        if graph.environment.hardware_fingerprint_sha256 is not None:
            add(DependencyKind.HARDWARE, "hardware", (graph.environment.hardware_fingerprint_sha256,), qualification)
        if graph.environment.device_policy_sha256 is not None:
            add(DependencyKind.DEVICE_IMAGE, "device_image", (graph.environment.device_policy_sha256,), qualification)
        return DependencyInvalidationManifest(
            manifest_id="invalidation.manifest",
            manifest_version="1.0.0",
            candidate_sha256=candidate.content_sha256,
            profile_graph_sha256=graph.content_sha256,
            dependencies=tuple(dependencies),
            unknown_change_action=(
                InvalidationAction.REQUALIFY_REVIEW_REAPPROVE
            ),
            created_at=created_at,
        )

    def empty_ledger(self) -> RevocationLedger:
        return RevocationLedger(
            ledger_id="profile.revocations",
            ledger_version="1.0.0",
            authority_policy_sha256=self.revocation_authority,
            entries=(),
            created_at="2026-08-16T00:00:00Z",
        )

    def ledger_revoking(
        self,
        target: RevocationTarget,
    ) -> RevocationLedger:
        signature = self.artifact("revocation_signature", "signature-1")
        entry = RevocationEntry(
            ledger_id="profile.revocations",
            sequence=1,
            previous_entry_sha256=None,
            target=target,
            reason=RevocationReason.COMPROMISED,
            authority_kind=ApprovalAuthorityKind.MAINTAINER,
            authority_id="security.maintainer",
            effective_at=_time(1),
            signature=signature,
        )
        self.store.append_revocation(
            canonical_json_bytes(entry.to_document()),
            expected_previous_head=None,
        )
        return dataclasses.replace(self.empty_ledger(), entries=(entry,))

    def _qualification_verifier(self, request):
        retry_authorization = (
            None
            if request.previous_trial_sha256 is None
            else self.artifact(
                "retry_authorization",
                f"retry:{request.trial.trial_id}",
            )
        )
        return QualificationEvidenceVerificationProof(
            candidate_sha256=request.candidate_sha256,
            profile_environment_sha256=request.profile_environment_sha256,
            qualification_policy_sha256=(
                request.qualification_policy_sha256
            ),
            qualification_plan_sha256=request.qualification_plan_sha256,
            calibration_report_sha256=request.calibration_report_sha256,
            qualification_report_sha256=(
                request.qualification_report_sha256
            ),
            broker_attestation_sha256=request.broker_attestation_sha256,
            trial_id=request.trial.trial_id,
            trial_sha256=canonical_sha256(request.trial.to_document()),
            oracle_decision_sha256=(
                request.trial.oracle_decision.content_sha256
            ),
            observed_verdict=request.trial.observed_verdict,
            stable=request.trial.stable,
            previous_trial_sha256=request.previous_trial_sha256,
            retry_authorization_receipt=retry_authorization,
            qualification_role_policy_sha256=(
                request.qualification_role_policy_sha256
            ),
            prequalification_authorization_sha256=(
                request.prequalification_authorization_sha256
            ),
            authority_policy_sha256=request.authority_policy_sha256,
            verifier_id="qualification.verifier",
            verification_receipt=self.artifact(
                "verification_receipt",
                f"qualification-proof:{request.trial.trial_id}",
            ),
            evidence_verified=True,
        )

    def _review_verifier(self, request):
        return ReviewVerificationProof(
            review_bundle_sha256=request.review_bundle_sha256,
            review_sha256=request.review_sha256,
            reviewer_authority=request.reviewer_authority,
            reviewer_session_id=request.reviewer_session_id,
            model_id=request.model_id,
            prompt_sha256=request.prompt_sha256,
            reviewer_role_policy_sha256=(
                request.reviewer_role_policy_sha256
            ),
            excluded_setup_session_id=request.excluded_setup_session_id,
            qualification_authorization_sha256=(
                request.qualification_authorization_sha256
            ),
            authority_policy_sha256=request.authority_policy_sha256,
            verifier_id="review.verifier",
            isolation_attestation=self.artifact(
                "review_isolation_attestation",
                f"isolation:{request.review_sha256}",
            ),
            verification_receipt=self.artifact(
                "verification_receipt",
                f"review-proof:{request.review_sha256}",
            ),
            authority_verified=True,
        )

    def _static_profile_verifier(self, request):
        return StaticProfileVerificationProof(
            request_sha256=canonical_sha256(request.__dict__),
            authority_policy_sha256=request.authority_policy_sha256,
            verifier_id="static.profile.verifier",
            verification_receipt=self.artifact(
                "verification_receipt",
                f"static-proof:{request.candidate_sha256}",
            ),
            profile_verified=True,
        )

    def _approval_verifier(self, request):
        return SemanticApprovalVerificationProof(
            approval_sha256=request.approval.content_sha256,
            semantic_subject_sha256=request.semantic_subject_sha256,
            qualification_proof_sha256=(
                request.qualification_proof_sha256
            ),
            review_proof_sha256=request.review_proof_sha256,
            review_authorization_sha256=(
                request.review_authorization_sha256
            ),
            authority_policy_sha256=request.authority_policy_sha256,
            verifier_id="approval.verifier",
            verification_receipt=self.artifact(
                "verification_receipt",
                f"approval-proof:{request.approval.content_sha256}",
            ),
            authority_verified=True,
        )

    def _revocation_verifier(self, request):
        return RevocationVerificationProof(
            entry_sha256=request.entry.content_sha256,
            authority_policy_sha256=request.authority_policy_sha256,
            verifier_id="revocation.verifier",
            verification_receipt=self.artifact(
                "verification_receipt",
                f"revocation-proof:{request.entry.content_sha256}",
            ),
            signature_valid=True,
        )

    def prepublish_approval(
        self,
        attempt: SimpleNamespace,
        *,
        expires_at: str,
    ) -> SemanticApprovalRecord:
        approval = SemanticApprovalRecord(
            approval_id="approval.previous",
            trust_tier=attempt.candidate.trust_tier,
            subject_sha256=make_review_subject(
                attempt.candidate
            ).content_sha256,
            basis_review_sha256=_sha("previous-review"),
            basis_qualification_report_sha256=_sha(
                "previous-qualification"
            ),
            authority_kind=ApprovalAuthorityKind.HUMAN,
            authority_id="human.approver",
            decision=ApprovalDecision.APPROVE,
            approved_at="2026-08-16T00:00:00Z",
            expires_at=expires_at,
        )
        self.stage_contract(approval)
        self.store.index_approval(
            subject_sha256=approval.subject_sha256,
            approval_sha256=approval.content_sha256,
            approval_subject_sha256=approval.subject_sha256,
        )
        return approval

    def run(
        self,
        attempt: SimpleNamespace,
        *,
        expected_previous_ref_sha256: str | None = None,
        review_verdict: ReviewVerdict = ReviewVerdict.APPROVE,
    ):
        self.stage_references(
            attempt.candidate.to_document(),
            attempt.plan.to_document(),
            attempt.calibration.to_document(),
            attempt.report.to_document(),
        )

        def qualify(request):
            self.qualification_calls += 1
            self.assert_equal(request.candidate, attempt.candidate)
            self.assert_equal(request.plan, attempt.plan)
            return QualificationProviderResult(
                attempt.calibration,
                attempt.report,
            )

        def review(request):
            self.review_calls += 1
            return ReviewRecord(
                review_id=f"review.{attempt.ordinal}",
                subject_sha256=request.bundle.subject.content_sha256,
                input_bundle_sha256=request.bundle.content_sha256,
                verdict=review_verdict,
                blocking_findings=(
                    ()
                    if review_verdict is ReviewVerdict.APPROVE
                    else ("semantic_issue",)
                ),
                non_blocking_findings=(),
                reviewer_authority="review.service",
                reviewer_session_id=f"review.session.{attempt.ordinal}",
                model_id="review.model",
                prompt_sha256=_sha("review-prompt"),
                reviewed_at=attempt.reviewed_at,
            )

        def approve(request):
            self.approval_calls += 1
            return SemanticApprovalRecord(
                approval_id=f"approval.{self.approval_calls}",
                trust_tier=request.trust_tier,
                subject_sha256=request.semantic_subject_sha256,
                basis_review_sha256=request.review_sha256,
                basis_qualification_report_sha256=(
                    request.qualification_report_sha256
                ),
                authority_kind=ApprovalAuthorityKind.HUMAN,
                authority_id="human.approver",
                decision=ApprovalDecision.APPROVE,
                approved_at=attempt.approved_at,
                expires_at="2026-08-18T00:00:00Z",
            )

        providers = ProfileSetupProviders(qualify, review, approve)
        coordinator = ProfileSetupCoordinator(
            store=self.store,
            providers=providers,
            gate_policy=self.gate_policy,
            revocation_verifier=self._revocation_verifier,
            approval_verifier=self._approval_verifier,
            qualification_evidence_verifier=self._qualification_verifier,
            review_verifier=self._review_verifier,
            static_profile_verifier=self._static_profile_verifier,
            authority_receipt_validator=lambda request, payload: True,
            clock=lambda: attempt.admitted_at,
        )
        return coordinator.run(
            configuration=ProfileSetupConfiguration(
                setup_session_id=f"setup.session.{attempt.ordinal}",
                setup_agent_id="setup.agent",
                qualification_worker_id="qualification.worker",
                effective_permissions=("process.broker",),
                admitted_at=attempt.admitted_at,
                expected_previous_ref_sha256=expected_previous_ref_sha256,
            ),
            candidate=attempt.candidate,
            qualification_policy=self.policy,
            qualification_plan=attempt.plan,
            review_material=attempt.review_material,
            invalidation_manifest=attempt.manifest,
            revocation_ledger=attempt.ledger,
        )

    @staticmethod
    def assert_equal(actual, expected) -> None:
        if actual != expected:
            raise AssertionError(f"{actual!r} != {expected!r}")


class ProfileSetupLifecycleTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.fixture = _LifecycleFixture(
            Path(self.temporary.name) / "profile-store"
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_gate_owns_freeze_and_publishes_pinned_profile_admission(self):
        attempt = self.fixture.build_attempt(ordinal=0, snapshot_label="snapshot-a")
        result = self.fixture.run(attempt)

        self.assertIs(result.lifecycle.final_state, SetupState.FROZEN)
        self.assertIs(
            result.lifecycle.transitions[-1].actor_role,
            SetupActorRole.HARNESS,
        )
        self.assertEqual(
            tuple(item.to_state for item in result.lifecycle.transitions),
            (
                SetupState.QUALIFYING,
                SetupState.AWAITING_REVIEW,
                SetupState.AWAITING_APPROVAL,
                SetupState.FROZEN,
            ),
        )
        self.assertFalse(result.gate_result.approval_reused)
        resolved = self.fixture.store.resolve_profile_admission(
            result.gate_result.profile.profile_id
        )
        self.assertEqual(
            resolved.profile_ref.object_sha256,
            result.gate_result.profile.content_sha256,
        )
        self.assertEqual(
            resolved.profile_ref.admission_sha256,
            result.gate_result.admission.content_sha256,
        )
        self.assertEqual(self.fixture.approval_calls, 1)

    def test_snapshot_change_creates_new_profile_and_reuses_exact_approval(self):
        first_attempt = self.fixture.build_attempt(
            ordinal=0,
            snapshot_label="snapshot-a",
        )
        first = self.fixture.run(first_attempt)
        second_attempt = self.fixture.build_attempt(
            ordinal=1,
            snapshot_label="snapshot-b",
        )
        second = self.fixture.run(
            second_attempt,
            expected_previous_ref_sha256=(
                first.gate_result.profile_ref_sha256
            ),
        )

        self.assertEqual(
            make_review_subject(first_attempt.candidate),
            make_review_subject(second_attempt.candidate),
        )
        self.assertEqual(first.approval, second.approval)
        self.assertTrue(second.gate_result.approval_reused)
        self.assertNotEqual(
            first.gate_result.profile.content_sha256,
            second.gate_result.profile.content_sha256,
        )
        self.assertNotEqual(
            first.gate_result.admission.content_sha256,
            second.gate_result.admission.content_sha256,
        )
        self.assertEqual(self.fixture.approval_calls, 1)
        self.assertEqual(
            self.fixture.store.resolve_profile_ref(
                second.gate_result.profile.profile_id
            ).sequence,
            2,
        )

    def test_failed_qualification_and_revise_review_stop_at_needs_revision(self):
        failed = self.fixture.build_attempt(
            ordinal=0,
            snapshot_label="snapshot-failed",
            passing=False,
        )
        qualification_result = self.fixture.run(failed)
        self.assertIs(
            qualification_result.lifecycle.final_state,
            SetupState.NEEDS_REVISION,
        )
        self.assertIsNone(qualification_result.review)
        self.assertIsNone(qualification_result.gate_result)

        revised = self.fixture.build_attempt(
            ordinal=1,
            snapshot_label="snapshot-revise",
        )
        review_result = self.fixture.run(
            revised,
            review_verdict=ReviewVerdict.REVISE,
        )
        self.assertIs(
            review_result.lifecycle.final_state,
            SetupState.NEEDS_REVISION,
        )
        self.assertIsNone(review_result.approval)
        self.assertIsNone(review_result.gate_result)

    def test_manifest_must_cover_every_present_candidate_dependency(self):
        attempt = self.fixture.build_attempt(
            ordinal=0,
            snapshot_label="snapshot-missing-manifest-entry",
        )
        incomplete = dataclasses.replace(
            attempt.manifest,
            dependencies=tuple(
                item
                for item in attempt.manifest.dependencies
                if item.kind is not DependencyKind.ENTRYPOINT
            ),
        )
        attempt.manifest = incomplete
        attempt.review_material = dataclasses.replace(
            attempt.review_material,
            invalidation_manifest_sha256=incomplete.content_sha256,
        )

        with self.assertRaises(ProfileSetupError) as caught:
            self.fixture.run(attempt)
        self.assertIs(caught.exception.code, ProfileSetupFailureCode.INVALID_INPUT)

    def test_expired_approval_is_renewed_and_exact_mapping_is_replaced(self):
        attempt = self.fixture.build_attempt(
            ordinal=0,
            snapshot_label="snapshot-renew-expired",
        )
        previous = self.fixture.prepublish_approval(
            attempt,
            expires_at="2026-08-16T12:00:00Z",
        )

        result = self.fixture.run(attempt)

        self.assertFalse(result.gate_result.approval_reused)
        self.assertNotEqual(result.approval.content_sha256, previous.content_sha256)
        self.assertEqual(
            self.fixture.store.resolve_approval(
                result.approval.subject_sha256
            ).approval_sha256,
            result.approval.content_sha256,
        )

    def test_revoked_approval_is_renewed_after_verified_ledger_update(self):
        attempt = self.fixture.build_attempt(
            ordinal=0,
            snapshot_label="snapshot-renew-revoked",
        )
        previous = self.fixture.prepublish_approval(
            attempt,
            expires_at="2026-08-18T00:00:00Z",
        )
        attempt.ledger = self.fixture.ledger_revoking(
            RevocationTarget(
                RevocationTargetKind.APPROVAL,
                previous.content_sha256,
            )
        )

        result = self.fixture.run(attempt)

        self.assertFalse(result.gate_result.approval_reused)
        self.assertNotEqual(result.approval.content_sha256, previous.content_sha256)
        self.assertEqual(
            result.gate_result.admission.revocation_ledger_sha256,
            attempt.ledger.content_sha256,
        )

    def test_authority_proof_failures_stop_each_downstream_provider(self):
        cases = (
            ("static", "_static_profile_verifier", "profile_verified", (0, 0, 0)),
            (
                "qualification",
                "_qualification_verifier",
                "evidence_verified",
                (1, 0, 0),
            ),
            ("review", "_review_verifier", "authority_verified", (1, 1, 0)),
        )
        for label, verifier_name, field, expected_calls in cases:
            with self.subTest(stage=label), tempfile.TemporaryDirectory() as root:
                fixture = _LifecycleFixture(Path(root) / "profile-store")
                attempt = fixture.build_attempt(
                    ordinal=0,
                    snapshot_label=f"snapshot-{label}-proof-failure",
                )
                original = getattr(fixture, verifier_name)

                def reject(request, original=original, field=field):
                    return dataclasses.replace(
                        original(request),
                        **{field: False},
                    )

                setattr(fixture, verifier_name, reject)
                with self.assertRaises(ProfileSetupError):
                    fixture.run(attempt)
                self.assertEqual(
                    (
                        fixture.qualification_calls,
                        fixture.review_calls,
                        fixture.approval_calls,
                    ),
                    expected_calls,
                )

    def test_gate_replays_staged_proofs_without_reissuing_them(self):
        attempt = self.fixture.build_attempt(
            ordinal=0,
            snapshot_label="snapshot-single-proof-issuance",
        )
        calls = {"static": 0, "qualification": 0, "review": 0, "approval": 0}
        for name, attribute in (
            ("static", "_static_profile_verifier"),
            ("qualification", "_qualification_verifier"),
            ("review", "_review_verifier"),
            ("approval", "_approval_verifier"),
        ):
            original = getattr(self.fixture, attribute)

            def counted(request, original=original, name=name):
                calls[name] += 1
                return original(request)

            setattr(self.fixture, attribute, counted)

        result = self.fixture.run(attempt)
        self.assertIsNotNone(result.gate_result)
        self.assertEqual(calls["static"], 1)
        self.assertEqual(calls["qualification"], len(attempt.report.trials))
        self.assertEqual(calls["review"], 1)
        self.assertEqual(calls["approval"], 1)


if __name__ == "__main__":
    unittest.main()

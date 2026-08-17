"""Result-blind review bundle construction and boundary checks.

The public builder in this module deliberately accepts only setup-governance
material.  It has no parameter for a current Case, current observations, an
expected Case result, or B1/B2 state.  The recursive key audit is a defence in
depth check on the canonical contract document, not a substitute for the
Reviewer's isolated mount policy.
"""

from __future__ import annotations

import re

from ..contracts.base import ContractError, canonical_json_bytes, validate_sha256
from ..contracts.references import ArtifactRef
from ..contracts.setup import (
    ProfileSetupCandidate,
    CalibrationReport,
    QualificationPlan,
    QualificationPolicy,
    QualificationReport,
    QualificationVerdict,
    ResultBlindReviewBundle,
    ReviewRecord,
    ReviewSubject,
    make_review_subject,
    validate_qualification_graph,
)
from .qualification import verify_qualification_report


_FORBIDDEN_REVIEW_KEY_FORMS = frozenset(
    {
        "caseid",
        "currentcase",
        "currentcaseid",
        "currentobservation",
        "currentobservations",
        "predictedresult",
        "predictedverdict",
        "reasoningexpectedresult",
        "reasoningexpectedverdict",
        "b1result",
        "b1verdict",
        "b2result",
        "b2verdict",
        "rawholdout",
        "rawholdoutfixture",
        "hiddenfixture",
        "hiddenfixtures",
    }
)


def _normalized_key(value: str) -> str:
    return re.sub(r"[^a-z0-9]", "", value.casefold())


def assert_result_blind_document(value: object) -> None:
    """Reject prohibited information channels anywhere in a bundle document."""

    # The canonical walk rejects floats, exotic containers, surrogate text,
    # and excessive nesting before the explicit key audit below.
    canonical_json_bytes(value)

    def visit(item: object, path: str) -> None:
        if type(item) is dict:
            for key, child in item.items():
                normalized = _normalized_key(key)
                if normalized in _FORBIDDEN_REVIEW_KEY_FORMS:
                    raise ContractError(
                        f"result-blind review document contains prohibited "
                        f"field {key!r} at {path}"
                    )
                visit(child, f"{path}.{key}")
        elif type(item) in (list, tuple):
            for index, child in enumerate(item):
                visit(child, f"{path}[{index}]")

    visit(value, "$")


def build_review_subject(candidate: ProfileSetupCandidate) -> ReviewSubject:
    """Derive the exact review subject from one frozen setup candidate."""

    if type(candidate) is not ProfileSetupCandidate:
        raise ContractError("candidate must be a ProfileSetupCandidate")
    return make_review_subject(candidate)


def build_result_blind_review_bundle(
    *,
    bundle_id: str,
    candidate: ProfileSetupCandidate,
    qualification_policy: QualificationPolicy,
    qualification_plan: QualificationPlan,
    calibration_report: CalibrationReport,
    qualification_report: QualificationReport,
    adapter_diff: ArtifactRef,
    static_scan: ArtifactRef,
    healthy_relation: ArtifactRef,
    qualification_design_sha256: str,
    invalidation_manifest_sha256: str,
    known_limitations: tuple[str, ...] = (),
) -> ResultBlindReviewBundle:
    """Build the sole Reviewer input from an explicit governance whitelist.

    Adapter code, dependency lock, SBOM, and permissions are copied from the
    candidate rather than accepted as independently substitutable arguments.
    The signature intentionally has no Case, observation, expected-result, or
    B1/B2 parameter.
    """

    if type(candidate) is not ProfileSetupCandidate:
        raise ContractError("candidate must be a ProfileSetupCandidate")
    if type(qualification_policy) is not QualificationPolicy:
        raise ContractError("qualification_policy must be a QualificationPolicy")
    if type(qualification_plan) is not QualificationPlan:
        raise ContractError("qualification_plan must be a QualificationPlan")
    if type(calibration_report) is not CalibrationReport:
        raise ContractError("calibration_report must be a CalibrationReport")
    if type(qualification_report) is not QualificationReport:
        raise ContractError("qualification_report must be a QualificationReport")
    verify_qualification_report(
        policy=qualification_policy,
        plan=qualification_plan,
        calibration_report=calibration_report,
        report=qualification_report,
    )
    validate_qualification_graph(
        candidate,
        qualification_policy,
        qualification_plan,
        calibration_report,
        qualification_report,
    )
    if qualification_report.verdict is not QualificationVerdict.PASS:
        raise ContractError("only a passing qualification may enter review")
    if qualification_report.setup_subject_sha256 != candidate.content_sha256:
        raise ContractError("qualification report does not bind the candidate")
    if (
        qualification_report.qualification_policy_sha256
        != candidate.qualification_policy.content_sha256
    ):
        raise ContractError("qualification report does not bind the candidate policy")
    validate_sha256(qualification_design_sha256, "qualification_design_sha256")
    validate_sha256(invalidation_manifest_sha256, "invalidation_manifest_sha256")
    if qualification_design_sha256 != qualification_plan.content_sha256:
        raise ContractError(
            "qualification design must be the exact frozen qualification plan"
        )

    bundle = ResultBlindReviewBundle(
        bundle_id=bundle_id,
        subject=build_review_subject(candidate),
        candidate_sha256=candidate.content_sha256,
        profile_graph_sha256=candidate.profile_graph_sha256,
        adapter_code=candidate.adapter_code,
        adapter_diff=adapter_diff,
        dependency_lock=candidate.dependency_lock,
        sbom=candidate.sbom,
        static_scan=static_scan,
        healthy_relation=healthy_relation,
        qualification_report_sha256=qualification_report.content_sha256,
        qualification_design_sha256=qualification_design_sha256,
        permission_manifest=candidate.permission_manifest,
        invalidation_manifest_sha256=invalidation_manifest_sha256,
        known_limitations=known_limitations,
    )
    assert_result_blind_document(bundle.to_document())
    return bundle


def validate_result_blind_review_record(
    bundle: ResultBlindReviewBundle,
    review: ReviewRecord,
) -> None:
    """Verify that an independent review binds the exact bundle and subject."""

    if type(bundle) is not ResultBlindReviewBundle:
        raise ContractError("bundle must be a ResultBlindReviewBundle")
    if type(review) is not ReviewRecord:
        raise ContractError("review must be a ReviewRecord")
    assert_result_blind_document(bundle.to_document())
    if review.subject_sha256 != bundle.subject.content_sha256:
        raise ContractError("review subject does not match its input bundle")
    if review.input_bundle_sha256 != bundle.content_sha256:
        raise ContractError("review does not bind its exact input bundle")

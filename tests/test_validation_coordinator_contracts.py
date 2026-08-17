import dataclasses
import hashlib
import unittest

from src.validation_core.contracts import (
    ArtifactRef,
    CaseReasonCode,
    CaseStatus,
    ContractError,
    ContractRef,
    ContractRefKind,
    CoordinatorRequestEnvelope,
    CoordinatorResponseEnvelope,
    GateAttemptDisposition,
    StagedArtifactBinding,
)


def _digest(label):
    return hashlib.sha256(label.encode("utf-8")).hexdigest()


def _artifact(role, *, size=1, media_type="application/octet-stream"):
    return ArtifactRef(
        role=role,
        media_type=media_type,
        size_bytes=size,
        content_sha256=_digest(f"{role}:{size}:{media_type}"),
    )


def _binding(path, role, *, size=1, media_type="application/octet-stream"):
    return StagedArtifactBinding(
        relative_path=path,
        artifact=_artifact(role, size=size, media_type=media_type),
    )


def _request(
    *,
    nonce=1,
    previous_response_sha256=None,
    artifacts=None,
    raw_submission=None,
):
    if nonce != 1 and previous_response_sha256 is None:
        previous_response_sha256 = _digest("previous-response")
    return CoordinatorRequestEnvelope(
        validation_instance_id=_digest("validation-instance"),
        case_id="bug-123",
        function_id="module:target",
        reasoning_sha256=_digest("reasoning"),
        profile_sha256=_digest("profile"),
        context_sha256=_digest("context"),
        agent_session_id="agent-session-1",
        nonce=nonce,
        previous_response_sha256=previous_response_sha256,
        raw_submission=raw_submission
        or _binding(
            f"submissions/{nonce}/submission.json",
            "raw_submission",
            size=128,
            media_type="application/json",
        ),
        artifacts=(
            (
                _binding(f"submissions/{nonce}/workload.json", "workload"),
                _binding(f"submissions/{nonce}/patch.diff", "patch"),
            )
            if artifacts is None
            else artifacts
        ),
    )


def _receipt_ref(name="b1-receipt"):
    return ContractRef(
        kind=ContractRefKind.GATE_RECEIPT,
        contract_id=name,
        contract_version="1",
        content_sha256=_digest(name),
    )


def _response(request=None, **overrides):
    request = request or _request()
    values = {
        "validation_instance_id": request.validation_instance_id,
        "case_id": request.case_id,
        "function_id": request.function_id,
        "reasoning_sha256": request.reasoning_sha256,
        "profile_sha256": request.profile_sha256,
        "context_sha256": request.context_sha256,
        "agent_session_id": request.agent_session_id,
        "nonce": request.nonce,
        "request_sha256": request.content_sha256,
        "gate_attempt_id": "gate-attempt-1",
        "b1_receipt": _receipt_ref(),
        "disposition": GateAttemptDisposition.RETRYABLE_REJECTION,
        "result_status": CaseStatus.NOT_CONFIRMED,
        "result_reason_code": CaseReasonCode.TARGET_NOT_REACHED,
        "remaining_submission_budget": 2,
        "terminal_status": None,
        "terminal_reason_code": None,
        "diagnostics": (CaseReasonCode.TARGET_NOT_REACHED.value,),
    }
    values.update(overrides)
    return CoordinatorResponseEnvelope(**values)


class CoordinatorRequestContractTests(unittest.TestCase):
    def test_round_trip_hash_and_canonical_artifact_order(self):
        first = _request()
        second = _request(artifacts=tuple(reversed(first.artifacts)))

        self.assertEqual(first, second)
        self.assertEqual(
            CoordinatorRequestEnvelope.from_json(first.to_json()),
            first,
        )
        self.assertEqual(
            hashlib.sha256(first.to_json()).hexdigest(),
            first.content_sha256,
        )
        self.assertEqual(first.declared_size_bytes, 130)
        self.assertEqual(
            tuple(item.artifact.role for item in first.artifacts),
            ("patch", "workload"),
        )

    def test_duplicate_json_keys_are_rejected(self):
        with self.assertRaises(ContractError):
            CoordinatorRequestEnvelope.from_json(
                b'{"contract_kind":"coordinator_request",'
                b'"contract_kind":"coordinator_request"}'
            )

    def test_staged_binding_rejects_absolute_and_traversal_paths(self):
        for path in (
            "/submissions/1/input",
            "submissions/1/../input",
            "submissions\\1\\input",
            "submissions/1/",
        ):
            with self.subTest(path=path), self.assertRaises(ContractError):
                _binding(path, "input")

    def test_every_path_must_belong_to_exact_nonce_namespace(self):
        for path in (
            "submission.json",
            "submissions/2/input",
            "submissions/01/input",
            "submissions/1",
        ):
            with self.subTest(path=path), self.assertRaises(ContractError):
                _request(artifacts=(_binding(path, "input"),))

    def test_staged_paths_and_roles_are_globally_unique(self):
        with self.assertRaises(ContractError):
            _request(
                artifacts=(
                    _binding("submissions/1/shared", "left"),
                    _binding("submissions/1/shared", "right"),
                )
            )
        with self.assertRaises(ContractError):
            _request(
                artifacts=(
                    _binding("submissions/1/left", "shared"),
                    _binding("submissions/1/right", "shared"),
                )
            )
        with self.assertRaises(ContractError):
            _request(
                artifacts=(
                    _binding("submissions/1/alias", "raw_submission"),
                )
            )

    def test_raw_submission_has_closed_role_media_type_and_size(self):
        for raw in (
            _binding(
                "submissions/1/submission.json",
                "submission",
                media_type="application/json",
            ),
            _binding(
                "submissions/1/submission.json",
                "raw_submission",
                media_type="text/plain",
            ),
            _binding(
                "submissions/1/submission.json",
                "raw_submission",
                size=0,
                media_type="application/json",
            ),
            _binding(
                "submissions/1/submission.json",
                "raw_submission",
                size=1_048_577,
                media_type="application/json",
            ),
        ):
            with self.subTest(raw=raw), self.assertRaises(ContractError):
                _request(raw_submission=raw)

    def test_nonce_and_artifact_declarations_are_bounded(self):
        for nonce in (0, True, 1_000_001):
            with self.subTest(nonce=nonce), self.assertRaises(ContractError):
                _request(nonce=nonce)

        oversized = _binding(
            "submissions/1/large.bin",
            "large",
            size=1_073_741_697,
        )
        with self.assertRaises(ContractError):
            _request(artifacts=(oversized,))

        too_many = tuple(
            _binding(f"submissions/1/artifacts/{index}", f"artifact-{index}")
            for index in range(4097)
        )
        with self.assertRaises(ContractError):
            _request(artifacts=too_many)

    def test_retry_nonce_must_bind_the_previous_response_hash(self):
        self.assertIsNone(_request().previous_response_sha256)
        self.assertEqual(
            _request(nonce=2).previous_response_sha256,
            _digest("previous-response"),
        )
        with self.assertRaises(ContractError):
            _request(previous_response_sha256=_digest("unexpected-response"))
        for value in (None, "not-a-sha256", True):
            with self.subTest(value=value), self.assertRaises(ContractError):
                CoordinatorRequestEnvelope(
                    validation_instance_id=_digest("validation-instance"),
                    case_id="bug-123",
                    function_id="module:target",
                    reasoning_sha256=_digest("reasoning"),
                    profile_sha256=_digest("profile"),
                    context_sha256=_digest("context"),
                    agent_session_id="agent-session-1",
                    nonce=2,
                    previous_response_sha256=value,
                    raw_submission=_binding(
                        "submissions/2/submission.json",
                        "raw_submission",
                        size=128,
                        media_type="application/json",
                    ),
                    artifacts=(),
                )

    def test_strict_schema_rejects_unexpected_fields_and_wrong_collection_type(self):
        document = _request().to_document()
        document["unexpected"] = True
        with self.assertRaises(ContractError):
            CoordinatorRequestEnvelope.from_document(document)

        document = _request().to_document()
        document["artifacts"] = {}
        with self.assertRaises(ContractError):
            CoordinatorRequestEnvelope.from_document(document)


class CoordinatorResponseContractTests(unittest.TestCase):
    def test_round_trip_hash_and_request_binding(self):
        request = _request()
        response = _response(request)

        self.assertEqual(
            CoordinatorResponseEnvelope.from_json(response.to_json()),
            response,
        )
        self.assertEqual(
            hashlib.sha256(response.to_json()).hexdigest(),
            response.content_sha256,
        )
        response.validate_request(request)

        with self.assertRaises(ContractError):
            dataclasses.replace(response, nonce=2).validate_request(request)
        with self.assertRaises(ContractError):
            dataclasses.replace(
                response,
                request_sha256=_digest("different-request"),
            ).validate_request(request)

    def test_response_requires_a_gate_receipt_reference_and_exact_types(self):
        wrong_ref = ContractRef(
            kind=ContractRefKind.CASE_SUBMISSION,
            contract_id="submission",
            contract_version="1",
            content_sha256=_digest("submission"),
        )
        with self.assertRaises(ContractError):
            _response(b1_receipt=wrong_ref)
        with self.assertRaises(ContractError):
            _response(remaining_submission_budget=True)
        with self.assertRaises(ContractError):
            _response(disposition=GateAttemptDisposition.TERMINAL_OUTCOME)

    def test_retryable_rejection_requires_budget_and_retryable_result(self):
        with self.assertRaises(ContractError):
            _response(remaining_submission_budget=0)
        with self.assertRaises(ContractError):
            _response(
                result_status=CaseStatus.INCONCLUSIVE_INFRA,
                result_reason_code=CaseReasonCode.TOOL_UNAVAILABLE,
            )
        for reason in (
            CaseReasonCode.PROFILE_ARTIFACT_INVALID,
            CaseReasonCode.BASELINE_ARTIFACT_HASH_MISMATCH,
        ):
            with self.subTest(reason=reason), self.assertRaises(ContractError):
                _response(
                    result_status=CaseStatus.INVALID_SUBMISSION,
                    result_reason_code=reason,
                )

    def test_accepted_confirmed_candidate_has_normative_result(self):
        for status, reason in (
            (CaseStatus.CONFIRMED_L0, CaseReasonCode.CONFIRMED_L0),
            (CaseStatus.CONFIRMED_L1, CaseReasonCode.CONFIRMED_L1),
        ):
            response = _response(
                disposition=(
                    GateAttemptDisposition.ACCEPTED_CONFIRMED_CANDIDATE
                ),
                result_status=status,
                result_reason_code=reason,
                diagnostics=(),
            )
            self.assertIsNone(response.terminal_status)
        with self.assertRaises(ContractError):
            _response(
                disposition=(
                    GateAttemptDisposition.ACCEPTED_CONFIRMED_CANDIDATE
                )
            )

    def test_explicit_not_confirmed_has_sole_accepted_fast_path_shape(self):
        response = _response(
            disposition=(
                GateAttemptDisposition.ACCEPTED_EXPLICIT_NOT_CONFIRMED
            ),
            result_status=CaseStatus.NOT_CONFIRMED,
            result_reason_code=CaseReasonCode.EXPLICIT_NOT_CONFIRMED,
            diagnostics=(CaseReasonCode.EXPLICIT_NOT_CONFIRMED.value,),
        )
        self.assertIsNone(response.terminal_status)
        with self.assertRaises(ContractError):
            _response(
                disposition=(
                    GateAttemptDisposition.ACCEPTED_EXPLICIT_NOT_CONFIRMED
                )
            )

    def test_terminal_projection_is_required_and_must_match_receipt_result(self):
        terminal = _response(
            disposition=GateAttemptDisposition.TERMINAL_OUTCOME,
            result_status=CaseStatus.INCONCLUSIVE_INFRA,
            result_reason_code=CaseReasonCode.TOOL_UNAVAILABLE,
            remaining_submission_budget=0,
            terminal_status=CaseStatus.INCONCLUSIVE_INFRA,
            terminal_reason_code=CaseReasonCode.TOOL_UNAVAILABLE,
            diagnostics=(CaseReasonCode.TOOL_UNAVAILABLE.value,),
        )
        self.assertEqual(terminal.terminal_status, terminal.result_status)

        with self.assertRaises(ContractError):
            dataclasses.replace(
                terminal,
                terminal_status=CaseStatus.INCONCLUSIVE_ORACLE,
                terminal_reason_code=CaseReasonCode.DOMAIN_MISMATCH,
            )
        with self.assertRaises(ContractError):
            _response(
                terminal_status=CaseStatus.NOT_CONFIRMED,
                terminal_reason_code=CaseReasonCode.TARGET_NOT_REACHED,
            )

    def test_diagnostics_are_bounded_deduplicated_and_allowlisted(self):
        with self.assertRaises(ContractError):
            _response(diagnostics=("raw-host-path",))
        with self.assertRaises(ContractError):
            _response(
                diagnostics=(
                    CaseReasonCode.TARGET_NOT_REACHED.value,
                    CaseReasonCode.TARGET_NOT_REACHED.value,
                )
            )
        allowed = tuple(
            reason.value
            for reason in CaseReasonCode
            if reason
            not in (CaseReasonCode.CONFIRMED_L0, CaseReasonCode.CONFIRMED_L1)
        )
        with self.assertRaises(ContractError):
            _response(diagnostics=allowed[:17])

    def test_response_json_is_strict(self):
        with self.assertRaises(ContractError):
            CoordinatorResponseEnvelope.from_json(
                b'{"contract_kind":"coordinator_response",'
                b'"contract_kind":"coordinator_response"}'
            )


if __name__ == "__main__":
    unittest.main()

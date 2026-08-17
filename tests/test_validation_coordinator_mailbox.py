import dataclasses
import hashlib
import os
from pathlib import Path
import socket
import tempfile
import unittest
from unittest import mock

from src.validation_core.contracts.coordinator import (
    CoordinatorRequestEnvelope,
    CoordinatorResponseEnvelope,
    StagedArtifactBinding,
)
from src.validation_core.contracts.references import (
    ArtifactRef,
    ContractRef,
    ContractRefKind,
)
from src.validation_core.contracts.status import (
    CaseReasonCode,
    CaseStatus,
    GateAttemptDisposition,
)
from src.validation_core.execution import mailbox as mailbox_runtime
from src.validation_core.execution.mailbox import (
    CoordinatorMailbox,
    FrozenCoordinatorRequest,
    MailboxError,
    MailboxErrorCode,
    MailboxLimits,
)


_AUTO_PREVIOUS_RESPONSE = object()


def _digest(value):
    if isinstance(value, str):
        value = value.encode("utf-8")
    return hashlib.sha256(value).hexdigest()


def _artifact(role, media_type, payload):
    return ArtifactRef(
        role=role,
        media_type=media_type,
        size_bytes=len(payload),
        content_sha256=_digest(payload),
    )


class CoordinatorMailboxTests(unittest.TestCase):
    def setUp(self):
        # WSL may route its default temp root to drvfs/NTFS, where chmod is
        # reported as 0777.  The mailbox intentionally requires an
        # owner-controlled filesystem, so exercise it on the native /tmp fs.
        self.temporary = tempfile.TemporaryDirectory(dir="/tmp")
        self.case_staging = Path(self.temporary.name).resolve() / "case-staging"
        self.case_staging.mkdir(mode=0o700)
        self.case_staging.chmod(0o700)
        self.mailbox = CoordinatorMailbox(
            self.case_staging,
            agent_session_id="agent-session-1",
        )

    def tearDown(self):
        self.mailbox.dispose()
        self.temporary.cleanup()

    def _request(
        self,
        nonce=1,
        *,
        session="agent-session-1",
        raw=b'{"schema_version":1}',
        artifact_payloads=(b"workload", b"patch"),
        previous_response_sha256=_AUTO_PREVIOUS_RESPONSE,
    ):
        if previous_response_sha256 is _AUTO_PREVIOUS_RESPONSE:
            previous_response_sha256 = (
                None
                if nonce == 1
                else _digest(f"synthetic-previous-response:{nonce - 1}")
            )
        raw_binding = StagedArtifactBinding(
            relative_path=f"submissions/{nonce}/submission.json",
            artifact=_artifact("raw_submission", "application/json", raw),
        )
        bindings = []
        payloads = {raw_binding.relative_path: raw}
        for index, payload in enumerate(artifact_payloads):
            binding = StagedArtifactBinding(
                relative_path=f"submissions/{nonce}/artifacts/value-{index}.bin",
                artifact=_artifact(
                    f"artifact_{index}",
                    "application/octet-stream",
                    payload,
                ),
            )
            bindings.append(binding)
            payloads[binding.relative_path] = payload
        request = CoordinatorRequestEnvelope(
            validation_instance_id=_digest("validation-instance"),
            case_id="case-1",
            function_id="function-1",
            reasoning_sha256=_digest("reasoning"),
            profile_sha256=_digest("profile"),
            context_sha256=_digest("context"),
            agent_session_id=session,
            nonce=nonce,
            previous_response_sha256=previous_response_sha256,
            raw_submission=raw_binding,
            artifacts=tuple(bindings),
        )
        return request, payloads

    def _response(self, request):
        return CoordinatorResponseEnvelope(
            validation_instance_id=request.validation_instance_id,
            case_id=request.case_id,
            function_id=request.function_id,
            reasoning_sha256=request.reasoning_sha256,
            profile_sha256=request.profile_sha256,
            context_sha256=request.context_sha256,
            agent_session_id=request.agent_session_id,
            nonce=request.nonce,
            request_sha256=request.content_sha256,
            gate_attempt_id=f"gate-{request.nonce}",
            b1_receipt=ContractRef(
                kind=ContractRefKind.GATE_RECEIPT,
                contract_id=f"receipt-{request.nonce}",
                contract_version="1.0.0",
                content_sha256=_digest(f"receipt:{request.nonce}"),
            ),
            disposition=GateAttemptDisposition.ACCEPTED_EXPLICIT_NOT_CONFIRMED,
            result_status=CaseStatus.NOT_CONFIRMED,
            result_reason_code=CaseReasonCode.EXPLICIT_NOT_CONFIRMED,
            remaining_submission_budget=0,
            terminal_status=None,
            terminal_reason_code=None,
            diagnostics=(),
        )

    def _manual_stage(self, request, payloads, *, request_payload=None):
        namespace = self.mailbox.root / "submissions" / str(request.nonce)
        namespace.mkdir(mode=0o700)
        for relative_path, payload in payloads.items():
            destination = self.mailbox.root.joinpath(*relative_path.split("/"))
            destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            destination.write_bytes(payload)
        inbox = self.mailbox.root / "inbox" / f"{request.nonce}.request.json"
        inbox.write_bytes(request.to_json() if request_payload is None else request_payload)

    def _claim(self, nonce=1):
        return self.mailbox.claim_next(
            nonce,
            lambda: True,
            timeout_ms=0,
            poll_interval_ms=1,
        )

    def assertMailboxError(self, expected_code, callback):
        with self.assertRaises(MailboxError) as captured:
            callback()
        self.assertIs(captured.exception.code, expected_code)

    def test_freezes_exact_bytes_into_new_host_inodes_and_round_trips_response(self):
        request, payloads = self._request()
        self.assertEqual(
            self.mailbox.agent_client.publish_request(request, payloads),
            request.content_sha256,
        )
        source = self.mailbox.root / request.raw_submission.relative_path
        source_inode = source.stat().st_ino

        frozen = self._claim()

        self.assertIsInstance(frozen, FrozenCoordinatorRequest)
        source_relative = source.relative_to(self.mailbox.root).as_posix()
        self.assertEqual(frozen.raw_submission_bytes, payloads[source_relative])
        self.assertEqual(
            tuple(item.content for item in frozen.artifacts),
            tuple(payloads[item.relative_path] for item in request.artifacts),
        )
        self.assertEqual(frozen.request_sha256, request.content_sha256)
        self.assertEqual(frozen.transport_bytes, request.to_json())
        frozen.validate_integrity()
        state_payload = (
            self.mailbox.root / "state" / "requests" / "1" / "payload-0000.bin"
        )
        self.assertNotEqual(source_inode, state_payload.stat().st_ino)
        self.assertEqual(state_payload.read_bytes(), frozen.raw_submission_bytes)

        response = self._response(request)
        self.assertEqual(
            self.mailbox.publish_response(response, frozen),
            response.content_sha256,
        )
        self.assertEqual(self.mailbox.agent_endpoint.read_response(1), response)
        self.mailbox.close_requests()
        self.mailbox.assert_quiescent()

    def test_claim_retries_expected_agent_namespace_publication_race(self):
        request, payloads = self._request()
        real_scandir = mailbox_runtime.os.scandir
        submissions_fd = self.mailbox._directories.submissions_fd
        published = False

        def publish_during_first_scan(directory):
            nonlocal published
            if directory == submissions_fd and not published:
                published = True
                self.mailbox.agent_client.publish_request(request, payloads)
            return real_scandir(directory)

        with mock.patch.object(
            mailbox_runtime.os,
            "scandir",
            side_effect=publish_during_first_scan,
        ):
            frozen = self._claim()

        self.assertTrue(published)
        self.assertEqual(frozen.envelope, request)
        self.assertEqual(frozen.request_sha256, request.content_sha256)

    def test_continuous_agent_namespace_scan_mutation_fails_closed(self):
        real_scandir = mailbox_runtime.os.scandir
        submissions_fd = self.mailbox._directories.submissions_fd
        submissions = self.mailbox.root / "submissions"
        mutation_count = 0

        def mutate_every_scan(directory):
            nonlocal mutation_count
            if directory == submissions_fd:
                mutation_count += 1
                marker = submissions / f".scan-race-{mutation_count}"
                marker.mkdir()
                marker.rmdir()
            return real_scandir(directory)

        with mock.patch.object(
            mailbox_runtime.os,
            "scandir",
            side_effect=mutate_every_scan,
        ):
            self.assertMailboxError(MailboxErrorCode.SOURCE_CHANGED, self._claim)

        self.assertGreater(mutation_count, 1)

    def test_held_writable_agent_fd_cannot_change_frozen_bytes(self):
        request, payloads = self._request(artifact_payloads=())
        self.mailbox.agent_client.publish_request(request, payloads)
        source = self.mailbox.root / request.raw_submission.relative_path
        with source.open("r+b", buffering=0) as retained:
            frozen = self._claim()
            retained.seek(0)
            retained.write(b"X" * len(frozen.raw_submission_bytes))
            os.fsync(retained.fileno())

        self.assertNotEqual(source.read_bytes(), frozen.raw_submission_bytes)
        self.assertEqual(
            frozen.raw_submission_bytes,
            payloads[request.raw_submission.relative_path],
        )
        frozen.validate_integrity()
        self.assertEqual(
            (
                self.mailbox.root
                / "state"
                / "requests"
                / "1"
                / "payload-0000.bin"
            ).read_bytes(),
            frozen.raw_submission_bytes,
        )

    def test_frozen_request_integrity_rebuild_detects_in_process_corruption(self):
        request, payloads = self._request(artifact_payloads=())
        self.mailbox.agent_client.publish_request(request, payloads)
        frozen = self._claim()
        object.__setattr__(frozen.raw_submission, "content", b"corrupt")
        with self.assertRaises(ValueError):
            frozen.validate_integrity()

    def test_frozen_request_integrity_rejects_different_transport_body(self):
        request, payloads = self._request(artifact_payloads=())
        self.mailbox.agent_client.publish_request(request, payloads)
        frozen = self._claim()
        other_request, _ = self._request(
            nonce=1,
            raw=b'{"schema_version":2}',
            artifact_payloads=(),
        )
        object.__setattr__(frozen, "transport_bytes", other_request.to_json())
        object.__setattr__(
            frozen,
            "transport_sha256",
            _digest(other_request.to_json()),
        )
        with self.assertRaises(ValueError):
            frozen.validate_integrity()

    def test_same_client_retries_with_strictly_next_nonce(self):
        request1, payloads1 = self._request(nonce=1)
        client = self.mailbox.agent_client
        client.publish_request(request1, payloads1)
        frozen1 = self._claim(1)
        response1 = self._response(request1)
        self.mailbox.publish_response(response1, frozen1)
        self.assertEqual(client.read_response(1), response1)
        self.assertEqual(
            client._previous_response_sha256,
            response1.content_sha256,
        )

        request2, payloads2 = self._request(
            nonce=2,
            previous_response_sha256=response1.content_sha256,
        )
        client.publish_request(request2, payloads2)
        frozen2 = self._claim(2)

        self.assertEqual(frozen2.envelope.nonce, 2)
        self.assertEqual(frozen2.envelope.agent_session_id, request1.agent_session_id)

    def test_unread_response_does_not_advance_client_response_chain(self):
        request1, payloads1 = self._request()
        client = self.mailbox.agent_client
        client.publish_request(request1, payloads1)
        frozen1 = self._claim()
        response1 = self._response(request1)
        self.mailbox.publish_response(response1, frozen1)

        request2, payloads2 = self._request(
            nonce=2,
            previous_response_sha256=response1.content_sha256,
        )
        self.assertMailboxError(
            MailboxErrorCode.INVALID_NONCE,
            lambda: client.publish_request(request2, payloads2),
        )
        self.assertIsNone(client._previous_response_sha256)
        self.assertEqual(client._next_nonce, 1)

    def test_client_rejects_wrong_previous_response_hash_after_read(self):
        request1, payloads1 = self._request()
        client = self.mailbox.agent_client
        client.publish_request(request1, payloads1)
        frozen1 = self._claim()
        response1 = self._response(request1)
        self.mailbox.publish_response(response1, frozen1)
        client.read_response(1)

        request2, payloads2 = self._request(
            nonce=2,
            previous_response_sha256=_digest("forged-previous-response"),
        )
        self.assertMailboxError(
            MailboxErrorCode.RESPONSE_MISMATCH,
            lambda: client.publish_request(request2, payloads2),
        )
        self.assertEqual(
            client._previous_response_sha256,
            response1.content_sha256,
        )

    def test_successful_wait_response_advances_client_response_chain(self):
        request1, payloads1 = self._request()
        client = self.mailbox.agent_client
        client.publish_request(request1, payloads1)
        frozen1 = self._claim()
        response1 = self._response(request1)
        self.mailbox.publish_response(response1, frozen1)

        self.assertEqual(
            client.wait_response(1, timeout_seconds=0),
            response1,
        )
        self.assertEqual(
            client._previous_response_sha256,
            response1.content_sha256,
        )
        request2, payloads2 = self._request(
            nonce=2,
            previous_response_sha256=response1.content_sha256,
        )
        self.assertEqual(
            client.publish_request(request2, payloads2),
            request2.content_sha256,
        )

    def test_host_rejects_replayed_previous_response_hash(self):
        client = self.mailbox.agent_client
        request1, payloads1 = self._request()
        client.publish_request(request1, payloads1)
        frozen1 = self._claim(1)
        response1 = self._response(request1)
        self.mailbox.publish_response(response1, frozen1)
        client.read_response(1)

        request2, payloads2 = self._request(
            nonce=2,
            previous_response_sha256=response1.content_sha256,
        )
        client.publish_request(request2, payloads2)
        frozen2 = self._claim(2)
        response2 = self._response(request2)
        self.mailbox.publish_response(response2, frozen2)
        client.read_response(2)

        request3, payloads3 = self._request(
            nonce=3,
            previous_response_sha256=response1.content_sha256,
        )
        self._manual_stage(request3, payloads3)
        self.assertMailboxError(
            MailboxErrorCode.RESPONSE_MISMATCH,
            lambda: self._claim(3),
        )

    def test_prepublished_retry_in_response_rename_race_has_no_valid_chain(self):
        request1, payloads1 = self._request()
        self.mailbox.agent_client.publish_request(request1, payloads1)
        frozen1 = self._claim(1)
        response1 = self._response(request1)
        request2, payloads2 = self._request(
            nonce=2,
            previous_response_sha256=_digest("guessed-response-capability"),
        )
        real_publish = mailbox_runtime._rename_noreplace_at
        injected = False

        def inject_retry(source_fd, source_name, destination_fd, destination_name):
            nonlocal injected
            if destination_name == "1.response.json" and not injected:
                injected = True
                self._manual_stage(request2, payloads2)
            return real_publish(
                source_fd,
                source_name,
                destination_fd,
                destination_name,
            )

        with mock.patch.object(
            mailbox_runtime,
            "_rename_noreplace_at",
            side_effect=inject_retry,
        ):
            self.mailbox.publish_response(response1, frozen1)

        self.assertTrue(injected)
        self.assertMailboxError(
            MailboxErrorCode.RESPONSE_MISMATCH,
            lambda: self._claim(2),
        )

    def test_request_capacity_is_the_configured_mailbox_limit(self):
        self.assertEqual(
            self.mailbox.request_capacity,
            self.mailbox.limits.max_requests,
        )

    def test_gap_nonce_is_rejected(self):
        request, payloads = self._request(nonce=2)
        self._manual_stage(request, payloads)
        self.assertMailboxError(MailboxErrorCode.NONCE_GAP, self._claim)

    def test_replayed_nonce_is_rejected(self):
        request, payloads = self._request(nonce=1)
        self.mailbox.agent_client.publish_request(request, payloads)
        frozen = self._claim()
        self.mailbox.publish_response(self._response(request), frozen)
        (self.mailbox.root / "inbox" / "1.request.json").write_bytes(
            request.to_json()
        )
        self.assertMailboxError(
            MailboxErrorCode.NONCE_REPLAY,
            lambda: self.mailbox.claim_next(2, lambda: True, timeout_ms=0),
        )

    def test_two_inbox_requests_are_rejected_before_parsing(self):
        request1, payloads1 = self._request(nonce=1)
        self._manual_stage(request1, payloads1)
        request2, _ = self._request(nonce=2)
        (self.mailbox.root / "inbox" / "2.request.json").write_bytes(
            request2.to_json()
        )
        self.assertMailboxError(MailboxErrorCode.MULTIPLE_REQUESTS, self._claim)

    def test_second_claim_is_rejected_while_first_request_is_outstanding(self):
        request, payloads = self._request()
        self.mailbox.agent_client.publish_request(request, payloads)
        self._claim()
        self.assertMailboxError(
            MailboxErrorCode.OUTSTANDING_REQUEST,
            lambda: self.mailbox.claim_next(1, lambda: True, timeout_ms=0),
        )

    def test_filename_and_request_body_nonce_must_match(self):
        request2, _ = self._request(nonce=2)
        namespace1 = self.mailbox.root / "submissions" / "1"
        namespace1.mkdir(mode=0o700)
        (self.mailbox.root / "inbox" / "1.request.json").write_bytes(
            request2.to_json()
        )
        self.assertMailboxError(MailboxErrorCode.INVALID_NONCE, self._claim)

    def test_agent_session_id_must_match_exactly(self):
        request, payloads = self._request(session="different-session")
        self._manual_stage(request, payloads)
        self.assertMailboxError(MailboxErrorCode.SESSION_MISMATCH, self._claim)

    def test_duplicate_json_key_is_rejected_by_strict_parser(self):
        request, payloads = self._request()
        duplicate = b'{"case_id":"shadow",' + request.to_json()[1:]
        self._manual_stage(request, payloads, request_payload=duplicate)
        self.assertMailboxError(MailboxErrorCode.INVALID_REQUEST, self._claim)

    def test_symlink_payload_is_rejected(self):
        request, payloads = self._request(artifact_payloads=())
        namespace = self.mailbox.root / "submissions" / "1"
        namespace.mkdir(mode=0o700)
        target = Path(self.temporary.name) / "target.json"
        target.write_bytes(payloads[request.raw_submission.relative_path])
        (namespace / "submission.json").symlink_to(target)
        (self.mailbox.root / "inbox" / "1.request.json").write_bytes(
            request.to_json()
        )
        self.assertMailboxError(MailboxErrorCode.UNSAFE_ENTRY, self._claim)

    def test_hardlink_payload_is_rejected(self):
        request, payloads = self._request(artifact_payloads=())
        namespace = self.mailbox.root / "submissions" / "1"
        namespace.mkdir(mode=0o700)
        target = Path(self.temporary.name) / "target.json"
        target.write_bytes(payloads[request.raw_submission.relative_path])
        os.link(target, namespace / "submission.json")
        (self.mailbox.root / "inbox" / "1.request.json").write_bytes(
            request.to_json()
        )
        self.assertMailboxError(MailboxErrorCode.UNSAFE_ENTRY, self._claim)

    def test_fifo_payload_is_rejected_without_blocking(self):
        request, _ = self._request(artifact_payloads=())
        namespace = self.mailbox.root / "submissions" / "1"
        namespace.mkdir(mode=0o700)
        try:
            os.mkfifo(namespace / "submission.json", 0o600)
        except PermissionError as exc:  # pragma: no cover - restricted runner
            self.skipTest(f"runner cannot create a FIFO: {exc}")
        (self.mailbox.root / "inbox" / "1.request.json").write_bytes(
            request.to_json()
        )
        self.assertMailboxError(MailboxErrorCode.UNSAFE_ENTRY, self._claim)

    def test_symlink_request_file_is_rejected(self):
        request, payloads = self._request()
        namespace = self.mailbox.root / "submissions" / "1"
        namespace.mkdir(mode=0o700)
        for relative_path, payload in payloads.items():
            destination = self.mailbox.root.joinpath(*relative_path.split("/"))
            destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            destination.write_bytes(payload)
        target = Path(self.temporary.name) / "request.json"
        target.write_bytes(request.to_json())
        (self.mailbox.root / "inbox" / "1.request.json").symlink_to(target)
        self.assertMailboxError(MailboxErrorCode.UNSAFE_ENTRY, self._claim)

    def test_hardlink_request_file_is_rejected(self):
        request, payloads = self._request()
        self._manual_stage(request, payloads)
        request_path = self.mailbox.root / "inbox" / "1.request.json"
        request_path.unlink()
        target = Path(self.temporary.name) / "request-hardlink.json"
        target.write_bytes(request.to_json())
        os.link(target, request_path)
        self.assertMailboxError(MailboxErrorCode.UNSAFE_ENTRY, self._claim)

    def test_fifo_request_file_is_rejected_without_blocking(self):
        request, payloads = self._request()
        self._manual_stage(request, payloads)
        request_path = self.mailbox.root / "inbox" / "1.request.json"
        request_path.unlink()
        try:
            os.mkfifo(request_path, 0o600)
        except PermissionError as exc:  # pragma: no cover - restricted runner
            self.skipTest(f"runner cannot create a FIFO: {exc}")
        self.assertMailboxError(MailboxErrorCode.UNSAFE_ENTRY, self._claim)

    def test_unix_socket_request_file_is_rejected_without_connecting(self):
        request, payloads = self._request()
        self._manual_stage(request, payloads)
        request_path = self.mailbox.root / "inbox" / "1.request.json"
        request_path.unlink()
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            try:
                listener.bind(os.fspath(request_path))
            except OSError as exc:  # pragma: no cover - restricted runner
                self.skipTest(f"runner cannot create a Unix socket: {exc}")
            self.assertMailboxError(MailboxErrorCode.UNSAFE_ENTRY, self._claim)
        finally:
            listener.close()

    def test_undeclared_staged_file_is_rejected(self):
        request, payloads = self._request(artifact_payloads=())
        self._manual_stage(request, payloads)
        namespace = self.mailbox.root / "submissions" / "1"
        (namespace / "extra.bin").write_bytes(b"undeclared")
        self.assertMailboxError(MailboxErrorCode.STRAY_ENTRY, self._claim)

    def test_payload_hash_mismatch_is_rejected(self):
        request, payloads = self._request(artifact_payloads=())
        payloads[request.raw_submission.relative_path] = b"X" * len(
            payloads[request.raw_submission.relative_path]
        )
        self._manual_stage(request, payloads)
        self.assertMailboxError(MailboxErrorCode.PAYLOAD_MISMATCH, self._claim)

    def test_precreated_request_state_is_rejected(self):
        request, payloads = self._request()
        self.mailbox.agent_client.publish_request(request, payloads)
        (self.mailbox.root / "state" / "requests" / "1").mkdir(mode=0o700)
        self.assertMailboxError(MailboxErrorCode.STATE_CONFLICT, self._claim)

    def test_response_outbox_is_no_clobber(self):
        request, payloads = self._request()
        self.mailbox.agent_client.publish_request(request, payloads)
        frozen = self._claim()
        incumbent = self.mailbox.root / "outbox" / "1.response.json"
        incumbent.write_bytes(b"incumbent")

        self.assertMailboxError(
            MailboxErrorCode.OUTBOX_CONFLICT,
            lambda: self.mailbox.publish_response(self._response(request), frozen),
        )
        self.assertEqual(incumbent.read_bytes(), b"incumbent")
        self.assertFalse(
            (self.mailbox.root / "state" / "responses" / "1.response.json").exists()
        )

    def test_published_request_state_and_memory_are_compact_hash_bindings(self):
        request, payloads = self._request()
        self.mailbox.agent_client.publish_request(request, payloads)
        frozen = self._claim()
        response = self._response(request)

        published_sha256 = self.mailbox.publish_response(response, frozen)

        self.assertEqual(published_sha256, response.content_sha256)
        self.assertEqual(
            _digest(
                (
                    self.mailbox.root
                    / "outbox"
                    / "1.response.json"
                ).read_bytes()
            ),
            published_sha256,
        )
        self.assertNotIsInstance(self.mailbox._claimed[1], FrozenCoordinatorRequest)
        self.assertNotIsInstance(self.mailbox._responses[1], bytes)
        request_state = self.mailbox.root / "state" / "requests" / "1"
        self.assertEqual(
            tuple(path.name for path in request_state.iterdir()),
            ("binding.json",),
        )
        binding_payload = (request_state / "binding.json").read_bytes()
        self.assertLess(len(binding_payload), 4096)
        self.assertNotIn(frozen.raw_submission_bytes, binding_payload)

    def test_response_state_is_persisted_before_outbox_publication(self):
        request, payloads = self._request()
        self.mailbox.agent_client.publish_request(request, payloads)
        frozen = self._claim()
        response = self._response(request)
        real_publish = mailbox_runtime._rename_noreplace_at

        def fail_outbox_publish(source_fd, source_name, destination_fd, destination_name):
            if destination_name.endswith(".response.json"):
                raise OSError("simulated publication failure")
            return real_publish(
                source_fd,
                source_name,
                destination_fd,
                destination_name,
            )

        with mock.patch.object(
            mailbox_runtime,
            "_rename_noreplace_at",
            side_effect=fail_outbox_publish,
        ):
            self.assertMailboxError(
                MailboxErrorCode.IO_FAILURE,
                lambda: self.mailbox.publish_response(response, frozen),
            )
        self.assertEqual(
            (
                self.mailbox.root
                / "state"
                / "responses"
                / "1.response.json"
            ).read_bytes(),
            response.to_json(),
        )
        self.assertFalse(
            (self.mailbox.root / "outbox" / "1.response.json").exists()
        )

    def test_agent_request_publication_is_no_clobber(self):
        request, payloads = self._request()
        incumbent = self.mailbox.root / "inbox" / "1.request.json"
        incumbent.write_bytes(b"incumbent")
        self.assertMailboxError(
            MailboxErrorCode.STATE_CONFLICT,
            lambda: self.mailbox.agent_client.publish_request(request, payloads),
        )
        self.assertEqual(incumbent.read_bytes(), b"incumbent")

    def test_close_allows_exact_outstanding_response_then_rejects_late_request(self):
        request, payloads = self._request()
        self.mailbox.agent_client.publish_request(request, payloads)
        frozen = self._claim()
        self.mailbox.close_requests()
        self.mailbox.publish_response(self._response(request), frozen)
        self.mailbox.assert_quiescent()

        request2, payloads2 = self._request(nonce=2)
        self._manual_stage(request2, payloads2)
        self.assertMailboxError(
            MailboxErrorCode.LATE_REQUEST,
            self.mailbox.assert_quiescent,
        )

    def test_quiescence_detects_mutation_after_freeze(self):
        request, payloads = self._request(artifact_payloads=())
        self.mailbox.agent_client.publish_request(request, payloads)
        frozen = self._claim()
        self.mailbox.publish_response(self._response(request), frozen)
        self.mailbox.close()
        source = self.mailbox.root / request.raw_submission.relative_path
        source.write_bytes(b"X" * len(source.read_bytes()))
        self.assertMailboxError(
            MailboxErrorCode.LATE_REQUEST,
            self.mailbox.assert_quiescent,
        )

    def test_closed_mailbox_is_idempotent_but_unanswered_claim_is_not_quiescent(self):
        request, payloads = self._request(artifact_payloads=())
        self.mailbox.agent_client.publish_request(request, payloads)
        self._claim()
        self.mailbox.close()
        self.mailbox.close_requests()

        self.assertTrue(self.mailbox.has_outstanding_request)
        self.assertMailboxError(
            MailboxErrorCode.OUTSTANDING_REQUEST,
            self.mailbox.assert_quiescent,
        )

    def test_quiescence_force_rescans_a_stale_submission_nonce_cache(self):
        request, payloads = self._request(artifact_payloads=())
        self.mailbox.agent_client.publish_request(request, payloads)
        frozen = self._claim()
        self.mailbox.publish_response(self._response(request), frozen)
        self.mailbox.close()
        self.mailbox._scan_submission_nonces(expected_nonce=None)

        (self.mailbox.root / "submissions" / "2").mkdir(mode=0o700)
        self.mailbox._submissions_directory_signature = (
            mailbox_runtime._metadata_signature(
                os.fstat(self.mailbox._directories.submissions_fd)
            )
        )
        self.mailbox._known_submission_nonces = frozenset({1})
        self.mailbox._submission_validation_context = (1, None, True)

        self.assertMailboxError(
            MailboxErrorCode.LATE_REQUEST,
            self.mailbox.assert_quiescent,
        )

    def test_wait_fails_closed_when_agent_has_exited(self):
        self.assertMailboxError(
            MailboxErrorCode.AGENT_EXITED,
            lambda: self.mailbox.claim_next(1, lambda: False, timeout_ms=100),
        )

    def test_liveness_callback_requires_exact_bool(self):
        self.assertMailboxError(
            MailboxErrorCode.LIVENESS_CHECK_FAILED,
            lambda: self.mailbox.claim_next(1, lambda: 1, timeout_ms=100),
        )

    def test_wait_timeout_is_typed_and_fail_closed(self):
        self.assertMailboxError(
            MailboxErrorCode.TIMEOUT,
            lambda: self.mailbox.claim_next(1, lambda: True, timeout_ms=0),
        )

    def test_repeated_empty_poll_does_not_reread_published_history(self):
        client = self.mailbox.agent_client
        previous_response_sha256 = None
        for nonce in range(1, 4):
            request, payloads = self._request(
                nonce=nonce,
                previous_response_sha256=previous_response_sha256,
            )
            client.publish_request(request, payloads)
            frozen = self._claim(nonce)
            response = self._response(request)
            self.mailbox.publish_response(response, frozen)
            client.read_response(nonce)
            previous_response_sha256 = response.content_sha256

        polls = 0

        def agent_is_alive():
            nonlocal polls
            polls += 1
            return polls < 3

        with mock.patch.object(
            mailbox_runtime,
            "_read_regular_at",
            wraps=mailbox_runtime._read_regular_at,
        ) as read_regular:
            self.assertMailboxError(
                MailboxErrorCode.AGENT_EXITED,
                lambda: self.mailbox.claim_next(
                    4,
                    agent_is_alive,
                    timeout_ms=100,
                    poll_interval_ms=1,
                ),
            )
        self.assertEqual(polls, 3)
        self.assertEqual(read_regular.call_count, 0)

    def test_request_byte_bound_is_host_enforced(self):
        self.mailbox.dispose()
        other_case = Path(self.temporary.name).resolve() / "bounded-case"
        other_case.mkdir(mode=0o700)
        other_case.chmod(0o700)
        self.mailbox = CoordinatorMailbox(
            other_case,
            agent_session_id="agent-session-1",
            limits=MailboxLimits(max_request_bytes=32),
        )
        request, payloads = self._request()
        self.mailbox.agent_client.publish_request(request, payloads)
        self.assertMailboxError(MailboxErrorCode.REQUEST_TOO_LARGE, self._claim)

    def test_staged_entry_count_bound_is_host_enforced(self):
        self.mailbox.dispose()
        other_case = Path(self.temporary.name).resolve() / "bounded-tree-case"
        other_case.mkdir(mode=0o700)
        other_case.chmod(0o700)
        self.mailbox = CoordinatorMailbox(
            other_case,
            agent_session_id="agent-session-1",
            limits=MailboxLimits(max_staged_entries=1),
        )
        request, payloads = self._request()
        self.mailbox.agent_client.publish_request(request, payloads)
        self.assertMailboxError(
            MailboxErrorCode.PAYLOAD_LIMIT_EXCEEDED,
            self._claim,
        )

    def test_lifecycle_payload_budget_bounds_all_retries(self):
        self.mailbox.dispose()
        other_case = Path(self.temporary.name).resolve() / "lifecycle-bytes-case"
        other_case.mkdir(mode=0o700)
        other_case.chmod(0o700)
        self.mailbox = CoordinatorMailbox(
            other_case,
            agent_session_id="agent-session-1",
            limits=MailboxLimits(
                max_single_payload_bytes=30,
                max_total_payload_bytes=30,
                max_lifecycle_payload_bytes=35,
            ),
        )
        request1, payloads1 = self._request(nonce=1, artifact_payloads=())
        client = self.mailbox.agent_client
        client.publish_request(request1, payloads1)
        frozen1 = self._claim(1)
        response1 = self._response(request1)
        self.mailbox.publish_response(response1, frozen1)
        client.read_response(1)
        request2, payloads2 = self._request(
            nonce=2,
            artifact_payloads=(),
            previous_response_sha256=response1.content_sha256,
        )
        client.publish_request(request2, payloads2)

        self.assertMailboxError(
            MailboxErrorCode.PAYLOAD_LIMIT_EXCEEDED,
            lambda: self._claim(2),
        )

    def test_lifecycle_entry_budget_bounds_all_retries(self):
        self.mailbox.dispose()
        other_case = Path(self.temporary.name).resolve() / "lifecycle-entries-case"
        other_case.mkdir(mode=0o700)
        other_case.chmod(0o700)
        self.mailbox = CoordinatorMailbox(
            other_case,
            agent_session_id="agent-session-1",
            limits=MailboxLimits(
                max_staged_entries=1,
                max_lifecycle_staged_entries=1,
            ),
        )
        request1, payloads1 = self._request(nonce=1, artifact_payloads=())
        client = self.mailbox.agent_client
        client.publish_request(request1, payloads1)
        frozen1 = self._claim(1)
        response1 = self._response(request1)
        self.mailbox.publish_response(response1, frozen1)
        client.read_response(1)
        request2, payloads2 = self._request(
            nonce=2,
            artifact_payloads=(),
            previous_response_sha256=response1.content_sha256,
        )
        client.publish_request(request2, payloads2)

        self.assertMailboxError(
            MailboxErrorCode.PAYLOAD_LIMIT_EXCEEDED,
            lambda: self._claim(2),
        )

    def test_mount_identity_failures_close_every_opened_directory_fd(self):
        namespace = self.mailbox.root / "submissions" / "1"
        namespace.mkdir(mode=0o700)
        checks = (
            lambda: self.mailbox._open_child_directory(
                self.mailbox._directories.root_fd,
                "inbox",
            ),
            lambda: self.mailbox._open_child_untrusted_directory(
                self.mailbox._directories.submissions_fd,
                "1",
            ),
            lambda: self.mailbox._open_relative_parent(
                "submissions/1/submission.json"
            ),
        )
        for check in checks:
            before = len(os.listdir("/proc/self/fd"))
            with mock.patch.object(
                mailbox_runtime,
                "_mount_id",
                side_effect=OSError("mount lookup failed"),
            ):
                with self.assertRaises(OSError):
                    check()
            self.assertEqual(len(os.listdir("/proc/self/fd")), before)

    def test_agent_client_closes_namespace_fd_when_inbox_open_fails(self):
        request, payloads = self._request()
        real_open = mailbox_runtime.os.open

        def fail_second_open(path, *args, **kwargs):
            if path == self.mailbox.agent_client.inbox:
                raise OSError("inbox open failed")
            return real_open(path, *args, **kwargs)

        before = len(os.listdir("/proc/self/fd"))
        with mock.patch.object(
            mailbox_runtime.os,
            "open",
            side_effect=fail_second_open,
        ):
            self.assertMailboxError(
                MailboxErrorCode.IO_FAILURE,
                lambda: self.mailbox.agent_client.publish_request(
                    request,
                    payloads,
                ),
            )
        self.assertEqual(len(os.listdir("/proc/self/fd")), before)

    def test_existing_mailbox_root_is_never_resumed(self):
        other_case = Path(self.temporary.name).resolve() / "existing-case"
        other_case.mkdir(mode=0o700)
        other_case.chmod(0o700)
        (other_case / "coordinator").mkdir(mode=0o700)
        self.assertMailboxError(
            MailboxErrorCode.INVALID_ROOT,
            lambda: CoordinatorMailbox(
                other_case,
                agent_session_id="agent-session-2",
            ),
        )

    def test_dispose_releases_descriptors_without_deleting_staged_content(self):
        request, payloads = self._request()
        self.mailbox.agent_client.publish_request(request, payloads)
        frozen = self._claim()
        root = self.mailbox.root
        source = root / request.raw_submission.relative_path
        self.assertIs(self.mailbox._outstanding, frozen)
        self.mailbox.dispose()
        self.assertIsNone(self.mailbox._outstanding)
        self.assertEqual(self.mailbox._claimed, {})
        self.assertEqual(self.mailbox._responses, {})
        self.assertEqual(self.mailbox._submission_bindings, {})
        self.assertEqual(self.mailbox.agent_client._outstanding, {})
        self.assertTrue(root.is_dir())
        self.assertEqual(
            source.read_bytes(),
            payloads[request.raw_submission.relative_path],
        )

    def test_response_for_different_request_is_rejected(self):
        request, payloads = self._request()
        self.mailbox.agent_client.publish_request(request, payloads)
        frozen = self._claim()
        wrong = dataclasses.replace(
            self._response(request),
            request_sha256=_digest("different-request"),
        )
        self.assertMailboxError(
            MailboxErrorCode.RESPONSE_MISMATCH,
            lambda: self.mailbox.publish_response(wrong, frozen),
        )


if __name__ == "__main__":
    unittest.main()

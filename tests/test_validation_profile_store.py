import concurrent.futures
import hashlib
import json
import multiprocessing
import os
from pathlib import Path
import stat
import tempfile
import threading
import unittest
from unittest import mock

from src.validation_core.contracts.base import ContractError, canonical_json_bytes
from src.validation_core.storage.profile import (
    ApprovalReuseRecord,
    ProfileRefRecord,
    ProfileStore,
    ProfileStoreError,
    ProfileStoreErrorCode,
    RevocationLedgerEntry,
    StoredProfileObject,
)


def _digest(payload):
    if isinstance(payload, str):
        payload = payload.encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _publish_object_worker(root, payload, barrier, results):
    try:
        store = ProfileStore.open(Path(root))
        barrier.wait(timeout=10)
        receipt = store.put_object(payload)
        results.put(("ok", receipt.sha256, receipt.size_bytes))
    except BaseException as exc:  # process boundary reports all failures
        results.put(("error", type(exc).__name__, str(exc)))


class ProfileStoreTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name) / "profile-store"
        self.store = ProfileStore.create(self.root)

    def tearDown(self):
        self.temporary.cleanup()

    def assertStoreError(self, code, operation):
        with self.assertRaises(ProfileStoreError) as caught:
            operation()
        self.assertIs(caught.exception.code, code)

    def publishAdmission(
        self,
        *,
        profile_payload,
        admission_payload,
        approval_payload,
        subject,
        replace_approval_sha256=None,
        expected_previous_ref_sha256=None,
        expected_revocation_head_sha256=None,
    ):
        return self.store.publish_profile_admission(
            profile_id="project.profile",
            profile_payload=profile_payload,
            profile_sha256=_digest(profile_payload),
            admission_payload=admission_payload,
            admission_sha256=_digest(admission_payload),
            approval_payload=approval_payload,
            approval_sha256=_digest(approval_payload),
            approval_subject_sha256=subject,
            replace_approval_sha256=replace_approval_sha256,
            expected_previous_ref_sha256=expected_previous_ref_sha256,
            expected_revocation_head_sha256=expected_revocation_head_sha256,
        )

    def test_create_requires_fresh_root_and_open_requires_initialized_root(self):
        other = Path(self.temporary.name) / "other"
        self.assertStoreError(
            ProfileStoreErrorCode.INVALID_STORE,
            lambda: ProfileStore.open(other),
        )
        other.mkdir(mode=0o700)
        self.assertStoreError(
            ProfileStoreErrorCode.INVALID_STORE,
            lambda: ProfileStore.create(other),
        )
        self.assertStoreError(
            ProfileStoreErrorCode.INVALID_STORE,
            lambda: ProfileStore.open(other),
        )
        reopened = ProfileStore.open(self.root)
        receipt = reopened.put_object(b"reopened")
        self.assertEqual(reopened.get_object(receipt.sha256), b"reopened")

    def test_store_rejects_relative_root_and_unsafe_existing_root(self):
        self.assertStoreError(
            ProfileStoreErrorCode.INVALID_STORE,
            lambda: ProfileStore("relative", create=True),
        )
        os.chmod(self.root, 0o777)
        try:
            self.assertStoreError(
                ProfileStoreErrorCode.INVALID_STORE,
                lambda: ProfileStore.open(self.root),
            )
        finally:
            os.chmod(self.root, 0o700)

    def test_reopen_rejects_world_readable_root_or_internal_directory(self):
        targets = (
            self.root,
            self.root / "objects" / "sha256",
            self.root / "refs" / "profiles",
        )
        for target in targets:
            with self.subTest(target=target.relative_to(self.root.parent)):
                os.chmod(target, 0o755)
                try:
                    self.assertStoreError(
                        ProfileStoreErrorCode.INVALID_STORE,
                        lambda: ProfileStore.open(self.root),
                    )
                finally:
                    os.chmod(target, 0o700)

    def test_object_round_trip_rechecks_hash_size_mode_and_has_path_free_receipt(self):
        payload = b'{"canonical":true}'
        receipt = self.store.put_object(
            payload,
            expected_sha256=_digest(payload),
        )
        self.assertIs(type(receipt), StoredProfileObject)
        self.assertEqual(receipt.sha256, _digest(payload))
        self.assertEqual(receipt.size_bytes, len(payload))
        self.assertFalse(hasattr(receipt, "path"))
        self.assertEqual(
            self.store.get_object(
                receipt.sha256,
                expected_size_bytes=receipt.size_bytes,
            ),
            payload,
        )
        self.assertStoreError(
            ProfileStoreErrorCode.INTEGRITY_FAILURE,
            lambda: self.store.get_object(
                receipt.sha256,
                expected_size_bytes=receipt.size_bytes + 1,
            ),
        )
        stored = self.root / "objects" / "sha256" / receipt.sha256
        self.assertEqual(stat.S_IMODE(os.lstat(stored).st_mode), 0o400)
        self.assertEqual(os.lstat(stored).st_nlink, 1)

    def test_wrong_expected_hash_is_rejected_without_publishing(self):
        payload = b"profile"
        wrong = _digest(b"other")
        self.assertStoreError(
            ProfileStoreErrorCode.HASH_MISMATCH,
            lambda: self.store.put_object(payload, expected_sha256=wrong),
        )
        self.assertFalse((self.root / "objects" / "sha256" / wrong).exists())

    def test_concurrent_identical_object_publication_reuses_one_inode(self):
        payload = b"same immutable profile object" * 500
        barrier = threading.Barrier(12)

        def publish(_):
            local = ProfileStore.open(self.root)
            barrier.wait(timeout=10)
            return local.put_object(payload)

        with concurrent.futures.ThreadPoolExecutor(max_workers=12) as executor:
            receipts = tuple(executor.map(publish, range(12)))
        self.assertEqual({receipt.sha256 for receipt in receipts}, {_digest(payload)})
        objects = tuple((self.root / "objects" / "sha256").iterdir())
        self.assertEqual([path.name for path in objects], [_digest(payload)])
        self.assertEqual(os.lstat(objects[0]).st_nlink, 1)
        self.assertEqual(tuple((self.root / "tmp").iterdir()), ())

    def test_cross_process_identical_object_publication_is_no_clobber(self):
        context = multiprocessing.get_context("fork")
        barrier = context.Barrier(4)
        results = context.Queue()
        payload = b"cross-process immutable object" * 200
        processes = tuple(
            context.Process(
                target=_publish_object_worker,
                args=(os.fspath(self.root), payload, barrier, results),
            )
            for _ in range(4)
        )
        for process in processes:
            process.start()
        reported = tuple(results.get(timeout=15) for _ in processes)
        for process in processes:
            process.join(timeout=15)
            self.assertEqual(process.exitcode, 0)
        self.assertEqual({item[0] for item in reported}, {"ok"})
        self.assertEqual({item[1] for item in reported}, {_digest(payload)})
        objects = tuple((self.root / "objects" / "sha256").iterdir())
        self.assertEqual([path.name for path in objects], [_digest(payload)])
        self.assertEqual(os.lstat(objects[0]).st_nlink, 1)
        self.assertEqual(tuple((self.root / "tmp").iterdir()), ())

    def test_tampered_object_fails_closed_and_is_never_repaired(self):
        receipt = self.store.put_object(b"trusted")
        path = self.root / "objects" / "sha256" / receipt.sha256
        os.chmod(path, 0o600)
        path.write_bytes(b"tampered")
        os.chmod(path, 0o400)
        self.assertStoreError(
            ProfileStoreErrorCode.INTEGRITY_FAILURE,
            lambda: self.store.get_object(receipt.sha256),
        )
        self.assertStoreError(
            ProfileStoreErrorCode.INTEGRITY_FAILURE,
            lambda: self.store.put_object(b"trusted"),
        )
        self.assertEqual(path.read_bytes(), b"tampered")

    def test_symlink_at_object_address_fails_closed(self):
        digest = _digest(b"outside")
        outside = Path(self.temporary.name) / "outside"
        outside.write_bytes(b"outside")
        (self.root / "objects" / "sha256" / digest).symlink_to(outside)
        self.assertStoreError(
            ProfileStoreErrorCode.INTEGRITY_FAILURE,
            lambda: self.store.get_object(digest),
        )

    def test_profile_ref_is_cas_updated_and_history_is_append_only(self):
        first_object = self.store.put_object(b"profile-v1")
        second_object = self.store.put_object(b"profile-v2")
        first = self.store.update_profile_ref(
            "project.profile",
            first_object.sha256,
            first_object.sha256,
            expected_previous_ref_sha256=None,
        )
        second = self.store.update_profile_ref(
            "project.profile",
            second_object.sha256,
            second_object.sha256,
            expected_previous_ref_sha256=first.content_sha256,
        )
        self.assertIs(type(first), ProfileRefRecord)
        self.assertEqual(second.previous_ref_sha256, first.content_sha256)
        self.assertEqual(second.sequence, 2)
        self.assertEqual(self.store.resolve_profile_ref("project.profile"), second)
        self.assertEqual(
            self.store.profile_ref_history("project.profile"),
            (first, second),
        )
        history = self.root / "refs" / "profiles" / "project.profile" / "history"
        self.assertTrue((history / f"{first.content_sha256}.json").is_file())
        self.assertTrue((history / f"{second.content_sha256}.json").is_file())
        self.assertEqual(
            stat.S_IMODE(os.lstat(history / f"{first.content_sha256}.json").st_mode),
            0o400,
        )

    def test_profile_ref_rejects_stale_writer_and_missing_object(self):
        first_object = self.store.put_object(b"profile-v1")
        first = self.store.update_profile_ref(
            "project.profile",
            first_object.sha256,
            first_object.sha256,
            expected_previous_ref_sha256=None,
        )
        second_object = self.store.put_object(b"profile-v2")
        self.assertStoreError(
            ProfileStoreErrorCode.STALE_REF,
            lambda: self.store.update_profile_ref(
                "project.profile",
                second_object.sha256,
                second_object.sha256,
                expected_previous_ref_sha256=None,
            ),
        )
        self.assertEqual(self.store.resolve_profile_ref("project.profile"), first)
        self.assertStoreError(
            ProfileStoreErrorCode.OBJECT_NOT_FOUND,
            lambda: self.store.update_profile_ref(
                "missing.profile",
                _digest(b"missing"),
                _digest(b"missing-admission"),
                expected_previous_ref_sha256=None,
            ),
        )

    def test_profile_ref_history_tamper_is_detected(self):
        first_object = self.store.put_object(b"profile-v1")
        first = self.store.update_profile_ref(
            "project.profile",
            first_object.sha256,
            first_object.sha256,
            expected_previous_ref_sha256=None,
        )
        second_object = self.store.put_object(b"profile-v2")
        self.store.update_profile_ref(
            "project.profile",
            second_object.sha256,
            second_object.sha256,
            expected_previous_ref_sha256=first.content_sha256,
        )
        history_file = (
            self.root
            / "refs"
            / "profiles"
            / "project.profile"
            / "history"
            / f"{first.content_sha256}.json"
        )
        os.chmod(history_file, 0o600)
        history_file.write_bytes(b"{}")
        os.chmod(history_file, 0o400)
        self.assertStoreError(
            ProfileStoreErrorCode.INTEGRITY_FAILURE,
            lambda: self.store.profile_ref_history("project.profile"),
        )

    def test_profile_ref_update_is_idempotent_only_at_exact_head(self):
        profile = self.store.put_object(b"profile")
        first = self.store.update_profile_ref(
            "project.profile",
            profile.sha256,
            profile.sha256,
            expected_previous_ref_sha256=None,
        )
        repeated = self.store.update_profile_ref(
            "project.profile",
            profile.sha256,
            profile.sha256,
            expected_previous_ref_sha256=first.content_sha256,
        )
        self.assertEqual(repeated, first)
        self.assertEqual(len(self.store.profile_ref_history("project.profile")), 1)

    def test_approval_reuse_requires_exact_subject_and_existing_object(self):
        approval = self.store.put_object(b"human approval")
        subject = _digest(b"exact qualification+review subject")
        self.assertStoreError(
            ProfileStoreErrorCode.APPROVAL_SUBJECT_MISMATCH,
            lambda: self.store.index_approval(
                subject_sha256=subject,
                approval_sha256=approval.sha256,
                approval_subject_sha256=_digest(b"nearby but different subject"),
            ),
        )
        record = self.store.index_approval(
            subject_sha256=subject,
            approval_sha256=approval.sha256,
            approval_subject_sha256=subject,
        )
        self.assertIs(type(record), ApprovalReuseRecord)
        self.assertEqual(self.store.resolve_approval(subject), record)
        self.assertFalse(hasattr(record, "path"))
        self.assertStoreError(
            ProfileStoreErrorCode.OBJECT_NOT_FOUND,
            lambda: self.store.index_approval(
                subject_sha256=_digest(b"other subject"),
                approval_sha256=_digest(b"absent approval"),
                approval_subject_sha256=_digest(b"other subject"),
            ),
        )

    def test_approval_index_is_no_clobber(self):
        first = self.store.put_object(b"approval-1")
        second = self.store.put_object(b"approval-2")
        subject = _digest(b"subject")
        original = self.store.index_approval(
            subject_sha256=subject,
            approval_sha256=first.sha256,
            approval_subject_sha256=subject,
        )
        repeated = self.store.index_approval(
            subject_sha256=subject,
            approval_sha256=first.sha256,
            approval_subject_sha256=subject,
        )
        self.assertEqual(repeated, original)
        self.assertStoreError(
            ProfileStoreErrorCode.APPROVAL_CONFLICT,
            lambda: self.store.index_approval(
                subject_sha256=subject,
                approval_sha256=second.sha256,
                approval_subject_sha256=subject,
            ),
        )
        self.assertEqual(self.store.resolve_approval(subject), original)

    def test_approval_index_tamper_fails_closed(self):
        approval = self.store.put_object(b"approval")
        subject = _digest(b"subject")
        self.store.index_approval(
            subject_sha256=subject,
            approval_sha256=approval.sha256,
            approval_subject_sha256=subject,
        )
        index = self.root / "approvals" / "by-subject" / f"{subject}.json"
        os.chmod(index, 0o600)
        value = json.loads(index.read_text(encoding="utf-8"))
        value["subject_sha256"] = _digest(b"different")
        index.write_bytes(canonical_json_bytes(value))
        os.chmod(index, 0o400)
        self.assertStoreError(
            ProfileStoreErrorCode.APPROVAL_SUBJECT_MISMATCH,
            lambda: self.store.resolve_approval(subject),
        )

    def test_revocation_ledger_is_append_only_and_supports_historical_heads(self):
        first = self.store.append_revocation(
            b'{"revoke":"approval-1"}',
            expected_previous_head=None,
        )
        second = self.store.append_revocation(
            b'{"revoke":"profile-2"}',
            expected_previous_head=first.content_sha256,
        )
        self.assertIs(type(first), RevocationLedgerEntry)
        self.assertEqual(second.sequence, 2)
        self.assertEqual(second.previous_head_sha256, first.content_sha256)
        self.assertEqual(self.store.revocation_head(), second)
        self.assertEqual(self.store.revocation_chain(), (first, second))
        self.assertEqual(
            self.store.revocation_chain(first.content_sha256),
            (first,),
        )
        entries = self.root / "revocation-ledger" / "entries" / "sha256"
        self.assertTrue((entries / f"{first.content_sha256}.json").is_file())
        self.assertTrue((entries / f"{second.content_sha256}.json").is_file())
        self.assertFalse(hasattr(second, "path"))

    def test_revocation_ledger_rejects_stale_head(self):
        first = self.store.append_revocation(b"first", expected_previous_head=None)
        self.assertStoreError(
            ProfileStoreErrorCode.STALE_LEDGER_HEAD,
            lambda: self.store.append_revocation(
                b"stale",
                expected_previous_head=None,
            ),
        )
        self.assertEqual(self.store.revocation_head(), first)

    def test_concurrent_revocation_cas_has_one_winner(self):
        first = self.store.append_revocation(b"first", expected_previous_head=None)
        barrier = threading.Barrier(2)

        def append(payload):
            local = ProfileStore.open(self.root)
            barrier.wait(timeout=10)
            try:
                return ("ok", local.append_revocation(
                    payload,
                    expected_previous_head=first.content_sha256,
                ))
            except ProfileStoreError as exc:
                return (exc.code.value, None)

        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
            results = tuple(executor.map(append, (b"second-a", b"second-b")))
        self.assertEqual([result[0] for result in results].count("ok"), 1)
        self.assertEqual(
            [result[0] for result in results].count("STALE_LEDGER_HEAD"),
            1,
        )
        self.assertEqual(len(self.store.revocation_chain()), 2)

    def test_revocation_entry_tamper_fails_closed(self):
        entry = self.store.append_revocation(b"revoke", expected_previous_head=None)
        path = (
            self.root
            / "revocation-ledger"
            / "entries"
            / "sha256"
            / f"{entry.content_sha256}.json"
        )
        os.chmod(path, 0o600)
        path.write_bytes(b"{}")
        os.chmod(path, 0o400)
        self.assertStoreError(
            ProfileStoreErrorCode.INTEGRITY_FAILURE,
            self.store.revocation_head,
        )

    def test_atomic_admission_ref_binds_profile_and_admission_objects(self):
        subject = _digest(b"semantic-subject")
        publication = self.publishAdmission(
            profile_payload=b"frozen-profile",
            admission_payload=b"profile-admission",
            approval_payload=b"semantic-approval",
            subject=subject,
        )

        current = self.store.resolve_profile_ref("project.profile")
        resolved = self.store.resolve_profile_admission("project.profile")
        self.assertEqual(current.object_sha256, _digest(b"frozen-profile"))
        self.assertEqual(
            current.admission_sha256,
            _digest(b"profile-admission"),
        )
        self.assertEqual(resolved.profile_payload, b"frozen-profile")
        self.assertEqual(resolved.admission_payload, b"profile-admission")
        self.assertEqual(resolved.profile_ref, publication.profile_ref)
        self.assertFalse(publication.approval_reused)

        invalid = publication.profile_ref.to_document()
        invalid["schema_version"] = True
        with self.assertRaises(ContractError):
            ProfileRefRecord.from_document(invalid)

    def test_same_profile_with_new_admission_creates_new_pinned_ref(self):
        subject = _digest(b"semantic-subject")
        first = self.publishAdmission(
            profile_payload=b"same-frozen-profile",
            admission_payload=b"profile-admission-v1",
            approval_payload=b"same-semantic-approval",
            subject=subject,
        )
        second = self.publishAdmission(
            profile_payload=b"same-frozen-profile",
            admission_payload=b"profile-admission-v2",
            approval_payload=b"same-semantic-approval",
            subject=subject,
            expected_previous_ref_sha256=first.profile_ref.content_sha256,
        )

        self.assertEqual(first.profile_ref.object_sha256, second.profile_ref.object_sha256)
        self.assertNotEqual(
            first.profile_ref.admission_sha256,
            second.profile_ref.admission_sha256,
        )
        self.assertEqual(second.profile_ref.sequence, 2)
        pinned_first = self.store.resolve_profile_admission(
            "project.profile",
            first.profile_ref.content_sha256,
        )
        self.assertEqual(pinned_first.admission_payload, b"profile-admission-v1")
        self.assertEqual(
            self.store.resolve_profile_admission(
                "project.profile",
                second.profile_ref.content_sha256,
            ).admission_payload,
            b"profile-admission-v2",
        )

    def test_concurrent_admission_writers_have_one_ref_cas_winner(self):
        subject = _digest(b"semantic-subject")
        first = self.publishAdmission(
            profile_payload=b"same-frozen-profile",
            admission_payload=b"profile-admission-v1",
            approval_payload=b"semantic-approval-v1",
            subject=subject,
        )
        barrier = threading.Barrier(2)

        def publish(suffix):
            local = ProfileStore.open(self.root)
            barrier.wait(timeout=10)
            approval = f"semantic-approval-{suffix}".encode()
            try:
                result = local.publish_profile_admission(
                    profile_id="project.profile",
                    profile_payload=b"same-frozen-profile",
                    profile_sha256=_digest(b"same-frozen-profile"),
                    admission_payload=f"profile-admission-{suffix}".encode(),
                    admission_sha256=_digest(f"profile-admission-{suffix}"),
                    approval_payload=approval,
                    approval_sha256=_digest(approval),
                    approval_subject_sha256=subject,
                    replace_approval_sha256=first.approval_object.sha256,
                    expected_previous_ref_sha256=(
                        first.profile_ref.content_sha256
                    ),
                    expected_revocation_head_sha256=None,
                )
                return ("ok", result)
            except ProfileStoreError as exc:
                return (exc.code.value, None)

        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
            results = tuple(executor.map(publish, ("v2a", "v2b")))
        self.assertEqual([item[0] for item in results].count("ok"), 1)
        self.assertEqual([item[0] for item in results].count("STALE_REF"), 1)
        history = self.store.profile_ref_history("project.profile")
        self.assertEqual(len(history), 2)
        self.assertEqual(history[-1], self.store.resolve_profile_ref("project.profile"))
        current = self.store.resolve_profile_admission("project.profile")
        self.assertIn(
            current.admission_payload,
            (b"profile-admission-v2a", b"profile-admission-v2b"),
        )
        pinned_first = self.store.resolve_profile_admission(
            "project.profile",
            first.profile_ref.content_sha256,
        )
        self.assertEqual(pinned_first.admission_payload, b"profile-admission-v1")

    def test_admission_object_and_ref_history_tamper_fail_closed(self):
        subject = _digest(b"semantic-subject")
        first = self.publishAdmission(
            profile_payload=b"frozen-profile",
            admission_payload=b"profile-admission",
            approval_payload=b"semantic-approval",
            subject=subject,
        )
        admission_path = (
            self.root / "objects" / "sha256" / first.admission_object.sha256
        )
        os.chmod(admission_path, 0o600)
        admission_path.write_bytes(b"tampered-admission")
        os.chmod(admission_path, 0o400)
        self.assertStoreError(
            ProfileStoreErrorCode.INTEGRITY_FAILURE,
            lambda: self.store.resolve_profile_admission("project.profile"),
        )

        other_root = Path(self.temporary.name) / "other-profile-store"
        other = ProfileStore.create(other_root)
        profile = other.put_object(b"profile")
        admission = other.put_object(b"admission")
        reference = other.update_profile_ref(
            "project.profile",
            profile.sha256,
            admission.sha256,
            expected_previous_ref_sha256=None,
        )
        history_path = (
            other_root
            / "refs"
            / "profiles"
            / "project.profile"
            / "history"
            / f"{reference.content_sha256}.json"
        )
        os.chmod(history_path, 0o600)
        history_path.write_bytes(b"{}")
        os.chmod(history_path, 0o400)
        with self.assertRaises(ProfileStoreError) as caught:
            other.resolve_profile_admission(
                "project.profile",
                reference.content_sha256,
            )
        self.assertIs(
            caught.exception.code,
            ProfileStoreErrorCode.INTEGRITY_FAILURE,
        )

    def test_stale_profile_ref_preflight_changes_no_mapping_or_ref(self):
        subject = _digest(b"semantic-subject")
        first = self.publishAdmission(
            profile_payload=b"frozen-profile-v1",
            admission_payload=b"profile-admission-v1",
            approval_payload=b"semantic-approval-v1",
            subject=subject,
        )
        original_mapping = self.store.resolve_approval(subject)
        original_ref = self.store.resolve_profile_ref("project.profile")
        original_history = self.store.profile_ref_history("project.profile")

        self.assertStoreError(
            ProfileStoreErrorCode.STALE_REF,
            lambda: self.publishAdmission(
                profile_payload=b"frozen-profile-v2",
                admission_payload=b"profile-admission-v2",
                approval_payload=b"semantic-approval-v2",
                subject=subject,
                replace_approval_sha256=first.approval_object.sha256,
                expected_previous_ref_sha256=None,
            ),
        )
        self.assertEqual(self.store.resolve_approval(subject), original_mapping)
        self.assertEqual(
            self.store.resolve_profile_ref("project.profile"),
            original_ref,
        )
        self.assertEqual(
            self.store.profile_ref_history("project.profile"),
            original_history,
        )
        for payload in (
            b"frozen-profile-v2",
            b"profile-admission-v2",
            b"semantic-approval-v2",
        ):
            self.assertStoreError(
                ProfileStoreErrorCode.OBJECT_NOT_FOUND,
                lambda payload=payload: self.store.get_object(_digest(payload)),
            )

    def test_stale_revocation_head_preflight_changes_no_publication_state(self):
        subject = _digest(b"semantic-subject")
        first = self.publishAdmission(
            profile_payload=b"frozen-profile-v1",
            admission_payload=b"profile-admission-v1",
            approval_payload=b"semantic-approval-v1",
            subject=subject,
        )
        self.store.append_revocation(
            b"new-revocation",
            expected_previous_head=None,
        )
        original_mapping = self.store.resolve_approval(subject)
        original_ref = self.store.resolve_profile_ref("project.profile")
        original_history = self.store.profile_ref_history("project.profile")

        self.assertStoreError(
            ProfileStoreErrorCode.STALE_LEDGER_HEAD,
            lambda: self.publishAdmission(
                profile_payload=b"frozen-profile-v2",
                admission_payload=b"profile-admission-v2",
                approval_payload=b"semantic-approval-v2",
                subject=subject,
                replace_approval_sha256=first.approval_object.sha256,
                expected_previous_ref_sha256=first.profile_ref.content_sha256,
                expected_revocation_head_sha256=None,
            ),
        )
        self.assertEqual(self.store.resolve_approval(subject), original_mapping)
        self.assertEqual(
            self.store.resolve_profile_ref("project.profile"),
            original_ref,
        )
        self.assertEqual(
            self.store.profile_ref_history("project.profile"),
            original_history,
        )
        for payload in (
            b"frozen-profile-v2",
            b"profile-admission-v2",
            b"semantic-approval-v2",
        ):
            self.assertStoreError(
                ProfileStoreErrorCode.OBJECT_NOT_FOUND,
                lambda payload=payload: self.store.get_object(_digest(payload)),
            )

    def test_interrupted_after_approval_admission_is_idempotently_recoverable(self):
        subject = _digest(b"semantic-subject")
        first = self.publishAdmission(
            profile_payload=b"profile-v1",
            admission_payload=b"admission-v1",
            approval_payload=b"approval-v1",
            subject=subject,
        )
        original_ref = first.profile_ref
        original_update = self.store._update_profile_ref_locked
        interruption = ProfileStoreError(
            ProfileStoreErrorCode.INTEGRITY_FAILURE,
            "injected ref publication failure",
        )
        with mock.patch.object(
            self.store,
            "_update_profile_ref_locked",
            side_effect=interruption,
        ):
            self.assertStoreError(
                ProfileStoreErrorCode.INTEGRITY_FAILURE,
                lambda: self.publishAdmission(
                    profile_payload=b"profile-v2",
                    admission_payload=b"admission-v2",
                    approval_payload=b"approval-v2",
                    subject=subject,
                    replace_approval_sha256=first.approval_object.sha256,
                    expected_previous_ref_sha256=first.profile_ref.content_sha256,
                ),
            )
        self.assertEqual(
            self.store.resolve_profile_ref("project.profile"),
            original_ref,
        )
        self.assertEqual(
            self.store.resolve_approval(subject).approval_sha256,
            _digest(b"approval-v2"),
        )
        for payload in (b"profile-v2", b"admission-v2", b"approval-v2"):
            self.assertEqual(self.store.get_object(_digest(payload)), payload)

        with mock.patch.object(
            self.store,
            "_update_profile_ref_locked",
            wraps=original_update,
        ):
            recovered = self.publishAdmission(
                profile_payload=b"profile-v2",
                admission_payload=b"admission-v2",
                approval_payload=b"approval-v2",
                subject=subject,
                replace_approval_sha256=first.approval_object.sha256,
                expected_previous_ref_sha256=first.profile_ref.content_sha256,
            )
        self.assertFalse(recovered.approval_reused)
        self.assertEqual(recovered.profile_ref.sequence, 2)
        self.assertEqual(
            self.store.resolve_profile_admission(
                "project.profile",
                recovered.profile_ref.content_sha256,
            ).admission_payload,
            b"admission-v2",
        )

    def test_retry_recovers_after_profile_ref_was_committed_before_error(self):
        subject = _digest(b"semantic-subject")
        first = self.publishAdmission(
            profile_payload=b"profile-v1",
            admission_payload=b"admission-v1",
            approval_payload=b"approval-v1",
            subject=subject,
        )
        original_update = self.store._update_profile_ref_locked

        def commit_then_interrupt(*args, **kwargs):
            original_update(*args, **kwargs)
            raise ProfileStoreError(
                ProfileStoreErrorCode.INTEGRITY_FAILURE,
                "injected failure after committed ref",
            )

        publication = dict(
            profile_payload=b"profile-v2",
            admission_payload=b"admission-v2",
            approval_payload=b"approval-v2",
            subject=subject,
            replace_approval_sha256=first.approval_object.sha256,
            expected_previous_ref_sha256=first.profile_ref.content_sha256,
        )
        with mock.patch.object(
            self.store,
            "_update_profile_ref_locked",
            side_effect=commit_then_interrupt,
        ):
            self.assertStoreError(
                ProfileStoreErrorCode.INTEGRITY_FAILURE,
                lambda: self.publishAdmission(**publication),
            )

        committed = self.store.resolve_profile_ref("project.profile")
        self.assertEqual(committed.sequence, 2)
        recovered = self.publishAdmission(**publication)
        self.assertEqual(recovered.profile_ref, committed)
        self.assertFalse(recovered.approval_reused)

    def test_uncommitted_orphan_ref_cannot_be_resolved_as_historical(self):
        first_object = self.store.put_object(b"profile-v1")
        first_admission = self.store.put_object(b"admission-v1")
        first = self.store.update_profile_ref(
            "project.profile",
            first_object.sha256,
            first_admission.sha256,
            expected_previous_ref_sha256=None,
        )
        second_object = self.store.put_object(b"profile-v2")
        second_admission = self.store.put_object(b"admission-v2")
        orphan = ProfileRefRecord(
            profile_id="project.profile",
            object_sha256=second_object.sha256,
            admission_sha256=second_admission.sha256,
            previous_ref_sha256=first.content_sha256,
            sequence=2,
        )
        original_replace = self.store._atomic_replace_locked

        def reject_current(path, payload):
            if path.name == "current.json":
                raise ProfileStoreError(
                    ProfileStoreErrorCode.INTEGRITY_FAILURE,
                    "injected current ref failure",
                )
            return original_replace(path, payload)

        with mock.patch.object(
            self.store,
            "_atomic_replace_locked",
            side_effect=reject_current,
        ):
            self.assertStoreError(
                ProfileStoreErrorCode.INTEGRITY_FAILURE,
                lambda: self.store.update_profile_ref(
                    "project.profile",
                    second_object.sha256,
                    second_admission.sha256,
                    expected_previous_ref_sha256=first.content_sha256,
                ),
            )
        self.assertEqual(
            self.store.resolve_profile_ref("project.profile"),
            first,
        )
        self.assertStoreError(
            ProfileStoreErrorCode.REF_NOT_FOUND,
            lambda: self.store.resolve_profile_admission(
                "project.profile",
                orphan.content_sha256,
            ),
        )


if __name__ == "__main__":
    unittest.main()

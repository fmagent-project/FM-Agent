import concurrent.futures
import dataclasses
import hashlib
import json
import multiprocessing
import os
from pathlib import Path
import signal
import socket
import stat
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest import mock

import src.validation_core as production_root
import src.validation_core.execution as execution_namespace
import src.validation_core.storage as storage_namespace
from src.validation_core.contracts.base import (
    ContractError,
    canonical_json_bytes,
    canonical_sha256,
)
from src.validation_core.contracts.case import ValidationInstanceIdentity
from src.validation_core.contracts.oracle import (
    ExecutionProtocol,
    QuorumSpec,
    VariantRole,
)
from src.validation_core.contracts.plan import (
    DynamicBindingRequest,
    DynamicResourceKind,
    ExecutionBinding,
    ExperimentPhase,
    ExperimentPlanTemplate,
    ExperimentStep,
    GateRole,
    PlannedOracleExecution,
    validate_b1_b2_binding_equivalence,
    validate_execution_binding,
)
from src.validation_core.contracts.profile import (
    EnvironmentBinding,
    FrozenSystemProfile,
    ProjectBinding,
)
from src.validation_core.contracts.references import (
    ContractRef,
    ContractRefKind,
)
from src.validation_core.contracts import snapshot as snapshot_contracts
from src.validation_core.contracts.snapshot import (
    MAX_SNAPSHOT_MANIFEST_BYTES,
    MAX_SNAPSHOT_PATH_COMPONENTS,
    MAX_SNAPSHOT_POLICY_BYTES,
    MAX_SNAPSHOT_REFERENCE_BYTES,
    SnapshotEntryKind,
    SnapshotManifest,
    SnapshotManifestEntry,
    SnapshotPolicy,
    SnapshotRef,
    SymlinkPolicy,
    generic_source_snapshot_policy_v1,
)
from src.validation_core.execution.role_policy import (
    CredentialPolicy,
    NetworkPolicy,
    RoleCapability,
    RolePolicy,
    WorkspaceNamespace,
    WorkspaceRole,
    build_role_policy,
)
from src.validation_core.execution import workspace as workspace_runtime
from src.validation_core.execution.workspace import (
    WorkspaceAllocation,
    WorkspaceError,
    WorkspaceErrorCode,
    WorkspaceLease,
    WorkspaceLineageRecord,
    WorkspaceManager,
    validate_workspace_lease_context,
    validate_workspace_independence,
    validate_workspace_lineage,
)
from src.validation_core.storage import snapshot as snapshot_runtime
from src.validation_core.storage.snapshot import (
    MaterializedSnapshot,
    SnapshotErrorCode,
    SnapshotMaterializationProof,
    SnapshotStore,
    SnapshotStoreError,
    StoredSnapshot,
)


def _digest(value):
    if isinstance(value, str):
        value = value.encode("utf-8")
    return hashlib.sha256(value).hexdigest()


def _ref(kind, name):
    return ContractRef(
        kind=kind,
        contract_id=f"test.{name}",
        contract_version="1.0.0",
        content_sha256=_digest(f"{kind.value}:{name}"),
    )


def _initialize_snapshot_store_worker(root, barrier, results):
    try:
        barrier.wait(timeout=10)
        SnapshotStore(Path(root))
        results.put(None)
    except BaseException as exc:  # process boundary must report every failure
        results.put(f"{type(exc).__name__}: {exc}")


def _capture_snapshot_worker(root, source, barrier, results):
    try:
        barrier.wait(timeout=10)
        snapshot = SnapshotStore(Path(root)).capture(Path(source), _policy())
        results.put(("ok", snapshot.ref.to_document()))
    except BaseException as exc:  # process boundary must report every failure
        results.put(("error", f"{type(exc).__name__}: {exc}"))


def _policy(**changes):
    values = {
        "policy_id": "test.snapshot",
        "policy_version": "1.0.0",
        "include_paths": (),
        "exclude_paths": (),
        "excluded_names": (),
        "excluded_name_prefixes": (),
        "excluded_top_level_prefixes": (),
        "symlink_policy": SymlinkPolicy.SAFE_RELATIVE,
        "max_entries": 1_000,
        "max_file_bytes": 1024 * 1024,
        "max_total_bytes": 8 * 1024 * 1024,
    }
    values.update(changes)
    return SnapshotPolicy(**values)


def _directory(path, mode=0o755):
    return SnapshotManifestEntry(
        relative_path=path,
        kind=SnapshotEntryKind.DIRECTORY,
        mode=mode,
        size_bytes=0,
        content_sha256=_digest(b""),
        symlink_target=None,
    )


def _file(path, payload=b"payload", mode=0o644):
    return SnapshotManifestEntry(
        relative_path=path,
        kind=SnapshotEntryKind.FILE,
        mode=mode,
        size_bytes=len(payload),
        content_sha256=_digest(payload),
        symlink_target=None,
    )


def _symlink(path, target):
    encoded = target.encode("utf-8")
    return SnapshotManifestEntry(
        relative_path=path,
        kind=SnapshotEntryKind.SYMLINK,
        mode=0o777,
        size_bytes=len(encoded),
        content_sha256=_digest(encoded),
        symlink_target=target,
    )


def _profile(snapshot_sha256, *, salt="primary", equivalence_policy=None):
    resource = _ref(ContractRefKind.RESOURCE_POLICY, f"resource.{salt}")
    equivalence = equivalence_policy or _ref(
        ContractRefKind.EXECUTION_EQUIVALENCE_POLICY,
        f"workspace-equivalence.{salt}",
    )
    return FrozenSystemProfile(
        profile_id=f"test.profile.{salt}",
        profile_version="1.0.0",
        project=ProjectBinding(
            system_id="test.project",
            project_kind="generic",
            source_snapshot_sha256=snapshot_sha256,
            dependency_manifest_sha256=_digest("dependencies"),
        ),
        environment=EnvironmentBinding(
            os_image_sha256=_digest("os-image"),
            toolchain_sha256=_digest("toolchain"),
            hardware_fingerprint_sha256=None,
            model_sha256=None,
            device_policy_sha256=None,
            resource_policy=resource,
        ),
        entrypoints=(_ref(ContractRefKind.ENTRYPOINT, f"entrypoint.{salt}"),),
        workload_schemas=(
            _ref(ContractRefKind.WORKLOAD_SCHEMA, f"workload.{salt}"),
        ),
        adapters=(_ref(ContractRefKind.ADAPTER, f"adapter.{salt}"),),
        instrumentation_providers=(
            _ref(
                ContractRefKind.INSTRUMENTATION_PROVIDER,
                f"instrumentation.{salt}",
            ),
        ),
        oracle_specs=(_ref(ContractRefKind.ORACLE_SPEC, f"oracle.{salt}"),),
        oracle_bundles=(
            _ref(ContractRefKind.ORACLE_BUNDLE, f"bundle.{salt}"),
        ),
        execution_recipes=(
            _ref(ContractRefKind.EXECUTION_RECIPE, f"recipe.{salt}"),
        ),
        components=(resource, equivalence),
        capabilities=("generic.execution",),
        qualification_report_sha256=_digest(f"qualification:{salt}"),
        review_sha256=_digest(f"review:{salt}"),
        approval_sha256=_digest(f"approval:{salt}"),
        created_at="2026-08-14T00:00:00Z",
        expires_at=None,
    )


def _execution_template(identity, profile, equivalence_policy):
    oracle = profile.oracle_specs[0]
    recipe = profile.execution_recipes[0]
    planned = PlannedOracleExecution(
        oracle_spec=oracle,
        collectors=(_ref(ContractRefKind.COLLECTOR, "binding.collector"),),
        normalizer=_ref(ContractRefKind.NORMALIZER, "binding.normalizer"),
        comparator=_ref(ContractRefKind.COMPARATOR, "binding.comparator"),
        protocol=ExecutionProtocol(
            warmup_runs=0,
            repetitions=1,
            quorum=QuorumSpec(required=1, total=1),
            timeout_ms=1_000,
            max_retries=0,
            retry_reasons=(),
        ),
        fixed_seed=7,
        reset_policy=_ref(ContractRefKind.RESET_POLICY, "binding.reset"),
        baseline_selection=None,
    )
    step = ExperimentStep(
        step_id="oracle-run",
        phase=ExperimentPhase.ORACLE_EXPERIMENT,
        execution_recipe=recipe,
        variant_id="candidate",
        variant_role=VariantRole.CANDIDATE,
        oracle_spec=oracle,
        depends_on=(),
    )
    return ExperimentPlanTemplate(
        validation_instance_id=identity.validation_instance_id,
        profile=profile.ref,
        case_plan=_ref(ContractRefKind.CASE_PLAN, "binding.case"),
        adapter=profile.adapters[0],
        oracle_bundle=profile.oracle_bundles[0],
        oracle_executions=(planned,),
        steps=(step,),
        dynamic_requests=(
            DynamicBindingRequest(
                symbol="workspace.project",
                resource_kind=DynamicResourceKind.WORKSPACE,
                equivalence_policy=equivalence_policy,
            ),
        ),
    )


class SnapshotPublicBoundaryTests(unittest.TestCase):
    def test_runtime_packages_export_only_the_exact_supported_api(self):
        expected_storage = {
            "ApprovalReuseRecord",
            "MaterializedSnapshot",
            "ProfileAdmissionPublishReceipt",
            "ProfileRefRecord",
            "ProfileStore",
            "ProfileStoreError",
            "ProfileStoreErrorCode",
            "ResolvedProfileAdmission",
            "RevocationLedgerEntry",
            "SnapshotErrorCode",
            "SnapshotMaterializationProof",
            "SnapshotStore",
            "SnapshotStoreError",
            "StoredSnapshot",
            "StoredProfileObject",
        }
        expected_execution = {
            "AgentExitProof",
            "AgentMailboxClient",
            "AgentResponseCommitProof",
            "AgentResponseCommitRequest",
            "AgentStartRequest",
            "AgentStartResult",
            "AgentStopReason",
            "CoordinatorAttemptRecord",
            "CoordinatorCompletionKind",
            "CoordinatorError",
            "CoordinatorFailureCode",
            "CoordinatorLifecycleRecord",
            "CoordinatorLimits",
            "CoordinatorMailbox",
            "CoordinatorProviders",
            "CoordinatorRunResult",
            "CoordinatorState",
            "CredentialPolicy",
            "CrossGateComparisonRequest",
            "FrozenCoordinatorRequest",
            "FrozenStagedArtifact",
            "GateExecutionRequest",
            "GateExecutionResult",
            "GateEvidencePersistenceProof",
            "GatePreflightState",
            "MailboxError",
            "MailboxErrorCode",
            "MailboxLimits",
            "NetworkPolicy",
            "RoleCapability",
            "RolePolicy",
            "ValidationCoordinator",
            "WorkspaceAllocation",
            "WorkspaceError",
            "WorkspaceErrorCode",
            "WorkspaceLease",
            "WorkspaceLineageRecord",
            "WorkspaceManager",
            "WorkspaceNamespace",
            "WorkspacePaths",
            "WorkspaceRole",
            "build_role_policy",
            "create_filesystem_mailbox",
            "validate_workspace_independence",
            "validate_workspace_lease_context",
            "validate_workspace_lineage",
        }
        for namespace, expected in (
            (storage_namespace, expected_storage),
            (execution_namespace, expected_execution),
        ):
            with self.subTest(namespace=namespace.__name__):
                self.assertEqual(set(namespace.__all__), expected)
                self.assertEqual(len(namespace.__all__), len(expected))
                for name in expected:
                    self.assertTrue(hasattr(namespace, name), name)
                    self.assertFalse(hasattr(production_root, name), name)

    def test_clean_production_import_does_not_load_workspace_runtime(self):
        repository = Path(__file__).resolve().parents[1]
        script = (
            "import sys\n"
            "import src.validation_core\n"
            "blocked = sorted(name for name in sys.modules "
            "if name == 'src.validation_core.storage' "
            "or name.startswith('src.validation_core.storage.') "
            "or name == 'src.validation_core.execution' "
            "or name.startswith('src.validation_core.execution.'))\n"
            "raise SystemExit('\\n'.join(blocked) if blocked else 0)\n"
        )
        completed = subprocess.run(
            [sys.executable, "-c", script],
            cwd=repository,
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)


class SnapshotContractTests(unittest.TestCase):
    def test_store_and_contract_parsers_share_metadata_size_limits(self):
        self.assertEqual(
            snapshot_runtime._MAX_POLICY_BYTES,
            MAX_SNAPSHOT_POLICY_BYTES,
        )
        self.assertEqual(
            snapshot_runtime._MAX_MANIFEST_BYTES,
            MAX_SNAPSHOT_MANIFEST_BYTES,
        )
        self.assertEqual(
            snapshot_runtime._MAX_REFERENCE_BYTES,
            MAX_SNAPSHOT_REFERENCE_BYTES,
        )
        policy = _policy()
        manifest = SnapshotManifest(entries=(_file("main.py"),))
        reference = SnapshotRef.create(policy.ref, manifest.artifact_ref)
        cases = (
            (
                SnapshotPolicy,
                "MAX_SNAPSHOT_POLICY_BYTES",
                canonical_json_bytes(policy.to_document()),
            ),
            (
                SnapshotManifest,
                "MAX_SNAPSHOT_MANIFEST_BYTES",
                manifest.canonical_bytes,
            ),
            (
                SnapshotRef,
                "MAX_SNAPSHOT_REFERENCE_BYTES",
                canonical_json_bytes(reference.to_document()),
            ),
        )
        for contract_type, constant, payload in cases:
            with self.subTest(contract=contract_type.__name__):
                with mock.patch.object(
                    snapshot_contracts,
                    constant,
                    len(payload) - 1,
                ):
                    with self.assertRaises(ContractError):
                        contract_type.from_json(payload)

    def test_policy_is_canonical_deterministic_and_strict(self):
        policy = _policy(
            include_paths=("src/lib", "README.md"),
            exclude_paths=("src/lib/generated", "dist"),
            excluded_names=(".git", "__pycache__"),
            excluded_name_prefixes=(".credential",),
            excluded_top_level_prefixes=(".env", ".secret"),
        )
        reordered = _policy(
            include_paths=("README.md", "src/lib"),
            exclude_paths=("dist", "src/lib/generated"),
            excluded_names=("__pycache__", ".git"),
            excluded_name_prefixes=(".credential",),
            excluded_top_level_prefixes=(".secret", ".env"),
        )

        self.assertEqual(policy, reordered)
        self.assertEqual(policy.content_sha256, reordered.content_sha256)
        self.assertEqual(
            SnapshotPolicy.from_json(canonical_json_bytes(policy.to_document())),
            policy,
        )
        self.assertTrue(policy.includes("src"))
        self.assertTrue(policy.includes("src/lib/code.py"))
        self.assertFalse(policy.includes("src/lib/generated/output.py"))
        self.assertFalse(policy.includes("src/lib/__pycache__/code.pyc"))
        self.assertFalse(policy.includes("src/.credential.local"))
        self.assertFalse(policy.includes(".env.local"))

        document = policy.to_document()
        document["unexpected"] = True
        with self.assertRaises(ContractError):
            SnapshotPolicy.from_document(document)
        with self.assertRaises(ContractError):
            SnapshotPolicy.from_json(
                b'{"contract_kind":"snapshot_policy",'
                b'"contract_kind":"snapshot_policy"}'
            )

    def test_manifest_roundtrip_sorts_and_binds_path_mode_and_bytes(self):
        manifest = SnapshotManifest(
            entries=(
                _file("src/main.py", b"print('ok')\n", 0o755),
                _directory("empty", 0o700),
                _directory("src", 0o755),
            )
        )
        self.assertEqual(
            [entry.relative_path for entry in manifest.entries],
            ["empty", "src", "src/main.py"],
        )
        self.assertEqual(
            SnapshotManifest.from_json(manifest.canonical_bytes),
            manifest,
        )

        changed_mode = SnapshotManifest(
            entries=(
                _directory("empty", 0o700),
                _directory("src", 0o755),
                _file("src/main.py", b"print('ok')\n", 0o644),
            )
        )
        changed_bytes = SnapshotManifest(
            entries=(
                _directory("empty", 0o700),
                _directory("src", 0o755),
                _file("src/main.py", b"print('no')\n", 0o755),
            )
        )
        self.assertNotEqual(manifest.content_sha256, changed_mode.content_sha256)
        self.assertNotEqual(manifest.content_sha256, changed_bytes.content_sha256)

    def test_manifest_rejects_path_and_parent_forgery(self):
        with self.assertRaises(ContractError):
            _file("../outside")
        with self.assertRaises(ContractError):
            _file("/absolute")
        with self.assertRaises(ContractError):
            SnapshotManifest(entries=(_file("src/main.py"),))
        with self.assertRaises(ContractError):
            SnapshotManifest(entries=(_file("src"), _file("src/main.py")))
        with self.assertRaises(ContractError):
            SnapshotManifest(entries=(_file("same"), _file("same")))
        with self.assertRaises(ContractError):
            dataclasses.replace(_file("main.py"), mode=0o4755)
        with self.assertRaises(ContractError):
            dataclasses.replace(_directory("empty"), content_sha256=None)

    def test_manifest_accepts_safe_relative_symlinks_without_resolving_them(self):
        manifest = SnapshotManifest(
            entries=(
                _file("target.txt"),
                _directory("pkg"),
                _symlink("pkg/link.txt", "../target.txt"),
                _symlink("alias.txt", "pkg/link.txt"),
                _symlink("dangling", "excluded-or-missing"),
                _symlink("cycle-a", "cycle-b"),
                _symlink("cycle-b", "cycle-a"),
            )
        )
        self.assertEqual(
            SnapshotManifest.from_document(manifest.to_document()),
            manifest,
        )

        with self.assertRaisesRegex(ContractError, "escapes snapshot root"):
            SnapshotManifest(
                entries=(
                    _directory("pkg"),
                    _symlink("pkg/link", "../../outside"),
                )
            )
        with self.assertRaises(ContractError):
            _symlink("link", "/absolute")

    def test_snapshot_ref_strict_roundtrip_and_tamper_detection(self):
        policy = _policy()
        manifest = SnapshotManifest(entries=(_file("main.py"),))
        reference = SnapshotRef.create(policy.ref, manifest.artifact_ref)
        payload = canonical_json_bytes(reference.to_document())
        self.assertEqual(SnapshotRef.from_json(payload), reference)

        document = json.loads(payload)
        document["snapshot_sha256"] = _digest("forged")
        with self.assertRaises(ContractError):
            SnapshotRef.from_document(document)
        document = json.loads(payload)
        document["manifest"]["size_bytes"] += 1
        with self.assertRaises(ContractError):
            SnapshotRef.from_document(document)
        document = json.loads(payload)
        document["physical_path"] = "/tmp/not-hash-bound"
        with self.assertRaises(ContractError):
            SnapshotRef.from_document(document)

    def test_snapshot_root_binds_policy_even_for_same_manifest(self):
        manifest = SnapshotManifest(entries=(_file("main.py"),))
        first = SnapshotRef.create(_policy().ref, manifest.artifact_ref)
        second = SnapshotRef.create(
            _policy(exclude_paths=("unused",)).ref,
            manifest.artifact_ref,
        )
        self.assertNotEqual(first.snapshot_sha256, second.snapshot_sha256)

    def test_stored_snapshot_revalidates_manifest_against_bound_policy(self):
        manifest = SnapshotManifest(entries=(_file("main.py"),))
        excluding = _policy(exclude_paths=("main.py",))
        reference = SnapshotRef.create(excluding.ref, manifest.artifact_ref)
        with self.assertRaises((ContractError, ValueError)):
            StoredSnapshot(reference, excluding, manifest)


class SnapshotStoreTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(
            prefix="fmagent-snapshot-store-",
            dir="/tmp",
        )
        self.base = Path(self.temporary.name).resolve()
        self.source = self.base / "source"
        self.source.mkdir()
        self.store = SnapshotStore(self.base / "cas")
        self.policy = _policy()

    def tearDown(self):
        self.temporary.cleanup()

    def _capture_file(self, payload="original\n"):
        (self.source / "main.txt").write_text(payload, encoding="utf-8")
        return self.store.capture(self.source, self.policy)

    def _object_path(self, digest):
        return self.store.root / "objects" / "sha256" / digest

    def _reference_path(self, snapshot):
        return (
            self.store.root
            / "snapshots"
            / "sha256"
            / f"{snapshot.ref.snapshot_sha256}.json"
        )

    def _replace_immutable_payload(self, path, payload):
        path.chmod(0o644)
        path.write_bytes(payload)
        path.chmod(0o444)

    def _replace_with_symlink(self, path):
        saved = path.with_name(f"{path.name}.saved")
        path.rename(saved)
        path.symlink_to(saved.name)

    def _assert_fails_without_blocking(self, operation):
        previous = signal.getsignal(signal.SIGALRM)

        def timeout(_signal_number, _frame):
            raise AssertionError("snapshot operation blocked on a special file")

        signal.signal(signal.SIGALRM, timeout)
        signal.setitimer(signal.ITIMER_REAL, 2.0)
        try:
            with self.assertRaises(SnapshotStoreError) as caught:
                operation()
            return caught.exception
        finally:
            signal.setitimer(signal.ITIMER_REAL, 0)
            signal.signal(signal.SIGALRM, previous)

    def test_dirty_included_bytes_change_snapshot_but_excluded_bytes_do_not(self):
        generic = generic_source_snapshot_policy_v1()
        (self.source / "main.py").write_text("dirty one\n", encoding="utf-8")
        (self.source / ".git").mkdir()
        (self.source / ".git" / "HEAD").write_text("one\n", encoding="utf-8")
        (self.source / "build").mkdir()
        (self.source / "build" / "cache.bin").write_bytes(b"one")

        first = self.store.capture(self.source, generic)
        (self.source / ".git" / "HEAD").write_text("two\n", encoding="utf-8")
        (self.source / "build" / "cache.bin").write_bytes(b"two")
        excluded_change = self.store.capture(self.source, generic)
        self.assertEqual(first.ref, excluded_change.ref)

        (self.source / "main.py").write_text("dirty two\n", encoding="utf-8")
        included_change = self.store.capture(self.source, generic)
        self.assertNotEqual(
            first.ref.snapshot_sha256,
            included_change.ref.snapshot_sha256,
        )
        self.assertEqual(
            [entry.relative_path for entry in first.manifest.entries],
            ["main.py"],
        )

    def test_nested_dotenv_name_prefixes_are_excluded_everywhere(self):
        generic = generic_source_snapshot_policy_v1()
        nested = self.source / "src" / "config"
        nested.mkdir(parents=True)
        (nested / "settings.py").write_text("SAFE = True\n", encoding="utf-8")
        for name in (".env", ".env.local", ".environment", ".envrc"):
            (nested / name).write_text(f"SECRET={name}\n", encoding="utf-8")

        first = self.store.capture(self.source, generic)
        (nested / ".env.local").write_text("SECRET=changed\n", encoding="utf-8")
        second = self.store.capture(self.source, generic)
        self.assertEqual(first.ref, second.ref)
        self.assertFalse(
            any(
                component.startswith(".env")
                for entry in first.manifest.entries
                for component in entry.relative_path.split("/")
            )
        )

    def test_excluded_entries_still_consume_the_bounded_scan_budget(self):
        policy = _policy(
            excluded_name_prefixes=(".env",),
            max_entries=3,
        )
        for index in range(4):
            (self.source / f".env-{index}").write_text(
                "SECRET=value\n",
                encoding="utf-8",
            )
        with self.assertRaises(SnapshotStoreError) as caught:
            self.store.capture(self.source, policy)
        self.assertEqual(caught.exception.code, SnapshotErrorCode.POLICY_LIMIT_EXCEEDED)

    def test_capture_and_materialize_preserve_empty_dirs_mode_and_safe_symlink(self):
        binary = self.source / "bin"
        binary.mkdir(mode=0o750)
        executable = binary / "run.sh"
        executable.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        executable.chmod(0o755)
        (self.source / "empty").mkdir(mode=0o700)
        (self.source / "run-link").symlink_to("bin/run.sh")

        snapshot = self.store.capture(self.source, self.policy)
        destination = self.base / "materialized"
        materialized = self.store.materialize(snapshot.ref, destination)

        by_path = {
            entry.relative_path: entry for entry in snapshot.manifest.entries
        }
        self.assertEqual(by_path["empty"].kind, SnapshotEntryKind.DIRECTORY)
        self.assertEqual(by_path["bin/run.sh"].mode, 0o755)
        self.assertEqual(stat.S_IMODE(executable.stat().st_mode), 0o755)
        self.assertEqual(stat.S_IMODE((destination / "bin/run.sh").stat().st_mode), 0o755)
        self.assertEqual(os.readlink(destination / "run-link"), "bin/run.sh")
        self.assertEqual(list((destination / "empty").iterdir()), [])
        self.assertEqual(
            materialized.proof.snapshot_sha256,
            snapshot.ref.snapshot_sha256,
        )

    def test_source_symlink_escape_fails_closed(self):
        (self.source / "link").symlink_to("../outside")
        with self.assertRaises(SnapshotStoreError) as caught:
            self.store.capture(self.source, self.policy)
        self.assertEqual(caught.exception.code, SnapshotErrorCode.UNSAFE_SOURCE_ENTRY)

    def test_dangling_excluded_target_and_cycle_symlinks_are_preserved(self):
        (self.source / "dangling").symlink_to("missing")
        (self.source / "cycle-a").symlink_to("cycle-b")
        (self.source / "cycle-b").symlink_to("cycle-a")
        build = self.source / "build"
        build.mkdir()
        (build / "excluded.txt").write_text("excluded\n", encoding="utf-8")
        (self.source / "excluded-link").symlink_to("build/excluded.txt")

        snapshot = self.store.capture(
            self.source,
            generic_source_snapshot_policy_v1(),
        )
        paths = {entry.relative_path for entry in snapshot.manifest.entries}
        self.assertNotIn("build", paths)
        self.assertNotIn("build/excluded.txt", paths)
        self.assertTrue(
            {"dangling", "cycle-a", "cycle-b", "excluded-link"}.issubset(paths)
        )
        destination = self.base / "unresolved-symlinks"
        self.store.materialize(snapshot.ref, destination)
        self.assertEqual(os.readlink(destination / "dangling"), "missing")
        self.assertEqual(os.readlink(destination / "cycle-a"), "cycle-b")
        self.assertEqual(os.readlink(destination / "cycle-b"), "cycle-a")
        self.assertEqual(
            os.readlink(destination / "excluded-link"),
            "build/excluded.txt",
        )

    def test_safe_symlink_target_spelling_is_preserved_byte_for_byte(self):
        spellings = {
            "dot": "./missing",
            "double": "dir//missing",
            "trailing": "dir/",
            "reduced": "dir/../other",
        }
        for name, target in spellings.items():
            (self.source / name).symlink_to(target)

        snapshot = self.store.capture(self.source, self.policy)
        captured = {
            entry.relative_path: entry.symlink_target
            for entry in snapshot.manifest.entries
        }
        destination = self.base / "spelling"
        self.store.materialize(snapshot.ref, destination)
        self.assertEqual(captured, spellings)
        self.assertEqual(
            {name: os.readlink(destination / name) for name in spellings},
            spellings,
        )

    def test_policy_can_reject_all_symlinks(self):
        (self.source / "target").write_text("target", encoding="utf-8")
        (self.source / "link").symlink_to("target")
        policy = _policy(symlink_policy=SymlinkPolicy.REJECT_ALL)
        with self.assertRaises(SnapshotStoreError) as caught:
            self.store.capture(self.source, policy)
        self.assertEqual(caught.exception.code, SnapshotErrorCode.UNSAFE_SOURCE_ENTRY)

    def test_source_fifo_and_socket_fail_closed(self):
        fifo = self.source / "fifo"
        os.mkfifo(fifo)
        with self.assertRaises(SnapshotStoreError) as caught:
            self.store.capture(self.source, self.policy)
        self.assertEqual(caught.exception.code, SnapshotErrorCode.UNSAFE_SOURCE_ENTRY)
        fifo.unlink()

        endpoint = self.source / "endpoint.sock"
        endpoint.write_bytes(b"")
        real_stat = os.stat

        def report_socket(path, *args, **kwargs):
            metadata = real_stat(path, *args, **kwargs)
            if path == endpoint.name and kwargs.get("dir_fd") is not None:
                fields = list(metadata)
                fields[0] = stat.S_IFSOCK | 0o600
                return os.stat_result(fields)
            return metadata

        with mock.patch.object(snapshot_runtime.os, "stat", side_effect=report_socket):
            with self.assertRaises(SnapshotStoreError) as caught:
                self.store.capture(self.source, self.policy)
            self.assertEqual(
                caught.exception.code,
                SnapshotErrorCode.UNSAFE_SOURCE_ENTRY,
            )

    def test_source_hardlinks_are_flattened_into_independent_files(self):
        original = self.source / "first.txt"
        alias = self.source / "second.txt"
        original.write_text("same bytes\n", encoding="utf-8")
        os.link(original, alias)
        self.assertEqual(original.stat().st_ino, alias.stat().st_ino)

        snapshot = self.store.capture(self.source, self.policy)
        destination = self.base / "materialized"
        self.store.materialize(snapshot.ref, destination)
        first_stat = (destination / "first.txt").stat()
        second_stat = (destination / "second.txt").stat()
        self.assertNotEqual(first_stat.st_ino, second_stat.st_ino)
        self.assertEqual(first_stat.st_nlink, 1)
        self.assertEqual(second_stat.st_nlink, 1)

    def test_source_hardlink_outside_root_is_rejected(self):
        outside = self.base / "outside.txt"
        inside = self.source / "inside.txt"
        outside.write_text("shared\n", encoding="utf-8")
        os.link(outside, inside)
        with self.assertRaises(SnapshotStoreError) as caught:
            self.store.capture(self.source, self.policy)
        self.assertEqual(caught.exception.code, SnapshotErrorCode.UNSAFE_SOURCE_ENTRY)

    def test_source_hardlink_entering_excluded_path_is_rejected(self):
        included = self.source / "main.py"
        included.write_text("shared\n", encoding="utf-8")
        excluded = self.source / "build"
        excluded.mkdir()
        os.link(included, excluded / "copy.py")
        with self.assertRaises(SnapshotStoreError) as caught:
            self.store.capture(
                self.source,
                generic_source_snapshot_policy_v1(),
            )
        self.assertEqual(caught.exception.code, SnapshotErrorCode.UNSAFE_SOURCE_ENTRY)

    def test_source_and_store_must_not_overlap(self):
        parent_source = self.base / "parent-source"
        parent_source.mkdir()
        nested_store = SnapshotStore(parent_source / "cas")
        with self.assertRaises(SnapshotStoreError) as caught:
            nested_store.capture(parent_source, self.policy)
        self.assertEqual(caught.exception.code, SnapshotErrorCode.INVALID_SOURCE)

        source_inside_store = self.store.root / "source"
        source_inside_store.mkdir()
        with self.assertRaises(SnapshotStoreError) as caught:
            self.store.capture(source_inside_store, self.policy)
        self.assertEqual(caught.exception.code, SnapshotErrorCode.INVALID_SOURCE)

    def test_real_unix_socket_is_rejected_when_platform_allows_creation(self):
        if not hasattr(socket, "AF_UNIX"):
            self.skipTest("Unix sockets are unavailable")
        # The repository may live on a filesystem (for example drvfs) that
        # cannot host Unix sockets, so use an explicitly owned native /tmp
        # fixture for this one real-node test.
        with tempfile.TemporaryDirectory(
            prefix="fmagent-snapshot-socket-",
            dir="/tmp",
        ) as temporary:
            root = Path(temporary).resolve()
            source = root / "source"
            source.mkdir()
            store = SnapshotStore(root / "cas")
            endpoint = source / "real.sock"
            server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            try:
                try:
                    server.bind(os.fspath(endpoint))
                except PermissionError:
                    self.skipTest("Unix socket creation is blocked by the sandbox")
                with self.assertRaises(SnapshotStoreError) as caught:
                    store.capture(source, self.policy)
                self.assertEqual(
                    caught.exception.code,
                    SnapshotErrorCode.UNSAFE_SOURCE_ENTRY,
                )
            finally:
                server.close()

    def test_mount_identity_mismatch_is_rejected(self):
        (self.source / "main.txt").write_text("data\n", encoding="utf-8")

        def mismatched_mount(_descriptor, relative_path):
            return 11 if relative_path == "main.txt" else 10

        with mock.patch.object(
            snapshot_runtime,
            "_mount_id",
            side_effect=mismatched_mount,
        ):
            with self.assertRaises(SnapshotStoreError) as caught:
                self.store.capture(self.source, self.policy)
        self.assertEqual(caught.exception.code, SnapshotErrorCode.UNSAFE_SOURCE_ENTRY)

    def test_content_toctou_between_capture_passes_is_detected(self):
        (self.source / "main.txt").write_text("before\n", encoding="utf-8")
        real_scan = snapshot_runtime._scan_tree
        call_count = 0

        def scan_then_change(**kwargs):
            nonlocal call_count
            captured = real_scan(**kwargs)
            call_count += 1
            if call_count == 1:
                (self.source / "main.txt").write_text("after!\n", encoding="utf-8")
            return captured

        with mock.patch.object(
            snapshot_runtime,
            "_scan_tree",
            side_effect=scan_then_change,
        ):
            with self.assertRaises(SnapshotStoreError) as caught:
                self.store.capture(self.source, self.policy)
        self.assertEqual(caught.exception.code, SnapshotErrorCode.SOURCE_CHANGED)
        self.assertEqual(call_count, 2)

    def test_directory_toctou_between_capture_passes_is_detected(self):
        (self.source / "main.txt").write_text("stable\n", encoding="utf-8")
        real_scan = snapshot_runtime._scan_tree
        call_count = 0

        def scan_then_add_entry(**kwargs):
            nonlocal call_count
            captured = real_scan(**kwargs)
            call_count += 1
            if call_count == 1:
                (self.source / "late.txt").write_text("late\n", encoding="utf-8")
            return captured

        with mock.patch.object(
            snapshot_runtime,
            "_scan_tree",
            side_effect=scan_then_add_entry,
        ):
            with self.assertRaises(SnapshotStoreError) as caught:
                self.store.capture(self.source, self.policy)
        self.assertEqual(caught.exception.code, SnapshotErrorCode.SOURCE_CHANGED)
        # The second scan rejects stale root metadata before returning through
        # this hook, so only the first completed call is counted.
        self.assertEqual(call_count, 1)

    def test_concurrent_capture_publishes_one_exact_snapshot(self):
        (self.source / "main.txt").write_text("concurrent\n", encoding="utf-8")
        stores = [SnapshotStore(self.store.root) for _ in range(4)]
        barrier = threading.Barrier(len(stores))

        def capture(store):
            barrier.wait(timeout=5)
            return store.capture(self.source, self.policy)

        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
            snapshots = list(pool.map(capture, stores))
        self.assertEqual(
            len({item.ref.snapshot_sha256 for item in snapshots}),
            1,
        )
        self.assertEqual(snapshots[0], self.store.verify(snapshots[0].ref))
        self.assertEqual(list((self.store.root / "tmp").iterdir()), [])

    def test_original_changes_after_capture_cannot_change_materialization(self):
        snapshot = self._capture_file("frozen\n")
        (self.source / "main.txt").write_text("mutated\n", encoding="utf-8")
        (self.source / "new.txt").write_text("new\n", encoding="utf-8")

        destination = self.base / "materialized"
        self.store.materialize(snapshot.ref, destination)
        self.assertEqual(
            (destination / "main.txt").read_text(encoding="utf-8"),
            "frozen\n",
        )
        self.assertFalse((destination / "new.txt").exists())

    def test_existing_destination_is_never_overwritten(self):
        snapshot = self._capture_file()
        destination = self.base / "existing"
        destination.mkdir()
        marker = destination / "owned.txt"
        marker.write_text("keep\n", encoding="utf-8")

        with self.assertRaises(SnapshotStoreError) as caught:
            self.store.materialize(snapshot.ref, destination)
        self.assertEqual(caught.exception.code, SnapshotErrorCode.INVALID_DESTINATION)
        self.assertEqual(marker.read_text(encoding="utf-8"), "keep\n")

    def test_destination_parent_must_be_owner_controlled(self):
        snapshot = self._capture_file()
        unsafe = self.base / "unsafe-parent"
        unsafe.mkdir(mode=0o700)
        unsafe.chmod(0o777)
        try:
            with self.assertRaises(SnapshotStoreError) as caught:
                self.store.materialize(snapshot.ref, unsafe / "destination")
            self.assertEqual(
                caught.exception.code,
                SnapshotErrorCode.INVALID_DESTINATION,
            )
        finally:
            unsafe.chmod(0o700)

    def test_destination_parent_wrong_owner_is_rejected_without_chown(self):
        snapshot = self._capture_file()
        parent = self.base / "owner-parent"
        parent.mkdir(mode=0o700)
        real_lstat = os.lstat
        real_stat = os.stat

        def wrong_owner(metadata):
            fields = list(metadata)
            fields[4] = os.geteuid() + 1
            return os.stat_result(fields)

        def lstat(path, *args, **kwargs):
            metadata = real_lstat(path, *args, **kwargs)
            try:
                is_parent = Path(path) == parent
            except TypeError:
                is_parent = False
            return wrong_owner(metadata) if is_parent else metadata

        def stat_call(path, *args, **kwargs):
            metadata = real_stat(path, *args, **kwargs)
            try:
                is_parent = Path(path) == parent
            except TypeError:
                is_parent = False
            return wrong_owner(metadata) if is_parent else metadata

        with mock.patch.object(snapshot_runtime.os, "lstat", side_effect=lstat), \
             mock.patch.object(snapshot_runtime.os, "stat", side_effect=stat_call):
            with self.assertRaises(SnapshotStoreError) as caught:
                self.store.materialize(snapshot.ref, parent / "destination")
        self.assertEqual(caught.exception.code, SnapshotErrorCode.INVALID_DESTINATION)

    def test_materialization_failure_cleans_only_new_destination(self):
        snapshot = self._capture_file()
        destination = self.base / "failed"
        sibling = self.base / "sibling"
        sibling.write_text("keep\n", encoding="utf-8")
        failure = SnapshotStoreError(
            SnapshotErrorCode.MATERIALIZATION_FAILED,
            "injected copy failure",
        )

        with mock.patch.object(
            self.store,
            "_copy_object_to_file",
            side_effect=failure,
        ):
            with self.assertRaises(SnapshotStoreError) as caught:
                self.store.materialize(snapshot.ref, destination)
        self.assertEqual(
            caught.exception.code,
            SnapshotErrorCode.MATERIALIZATION_FAILED,
        )
        self.assertFalse(destination.exists())
        self.assertEqual(sibling.read_text(encoding="utf-8"), "keep\n")

    def test_materialization_proof_strict_json_roundtrip_and_tamper(self):
        snapshot = self._capture_file()
        materialized = self.store.materialize(
            snapshot.ref,
            self.base / "proof-destination",
        )
        proof = materialized.proof
        payload = canonical_json_bytes(proof.to_document())
        self.assertEqual(SnapshotMaterializationProof.from_json(payload), proof)

        for field, value in (
            ("contract_kind", "forged_proof"),
            ("schema_version", 2),
            ("materialization_id", "A" * 32),
            ("snapshot_sha256", "not-a-sha256"),
            ("policy_sha256", "not-a-sha256"),
            ("manifest_sha256", "not-a-sha256"),
            ("entry_count", -1),
            ("total_file_bytes", -1),
            ("materializer_version", "unknown-v99"),
        ):
            with self.subTest(field=field):
                document = proof.to_document()
                document[field] = value
                with self.assertRaises((ContractError, ValueError)):
                    SnapshotMaterializationProof.from_document(document)
        document = proof.to_document()
        document["destination"] = "/tmp/host-path-must-not-enter-proof"
        with self.assertRaises((ContractError, ValueError)):
            SnapshotMaterializationProof.from_document(document)
        with self.assertRaises((ContractError, ValueError)):
            SnapshotMaterializationProof.from_json(
                b'{"contract_kind":"snapshot_materialization_proof",'
                b'"contract_kind":"snapshot_materialization_proof"}'
            )

    def test_capture_metadata_size_limits_fail_closed(self):
        (self.source / "main.txt").write_text("data\n", encoding="utf-8")
        limits = (
            "_MAX_POLICY_BYTES",
            "_MAX_MANIFEST_BYTES",
            "_MAX_REFERENCE_BYTES",
        )
        for index, constant in enumerate(limits):
            with self.subTest(constant=constant):
                store = SnapshotStore(self.base / f"metadata-cas-{index}")
                with mock.patch.object(snapshot_runtime, constant, 1):
                    with self.assertRaises(SnapshotStoreError) as caught:
                        store.capture(self.source, self.policy)
                self.assertEqual(
                    caught.exception.code,
                    SnapshotErrorCode.POLICY_LIMIT_EXCEEDED,
                )

    def test_verify_rejects_file_object_content_tamper(self):
        snapshot = self._capture_file()
        entry = next(
            item
            for item in snapshot.manifest.entries
            if item.kind is SnapshotEntryKind.FILE
        )
        self._replace_immutable_payload(
            self._object_path(entry.content_sha256),
            b"tampered!\n",
        )
        with self.assertRaises(SnapshotStoreError) as caught:
            self.store.verify(snapshot.ref)
        self.assertEqual(caught.exception.code, SnapshotErrorCode.INTEGRITY_FAILURE)

    def test_verify_rejects_file_object_symlink(self):
        snapshot = self._capture_file()
        entry = next(
            item
            for item in snapshot.manifest.entries
            if item.kind is SnapshotEntryKind.FILE
        )
        self._replace_with_symlink(self._object_path(entry.content_sha256))
        with self.assertRaises(SnapshotStoreError) as caught:
            self.store.verify(snapshot.ref)
        self.assertEqual(caught.exception.code, SnapshotErrorCode.INTEGRITY_FAILURE)

    def test_load_rejects_manifest_content_tamper(self):
        snapshot = self._capture_file()
        path = self._object_path(snapshot.ref.manifest.content_sha256)
        self._replace_immutable_payload(path, b"{}")
        with self.assertRaises(SnapshotStoreError) as caught:
            self.store.load(snapshot.ref)
        self.assertEqual(caught.exception.code, SnapshotErrorCode.INTEGRITY_FAILURE)

    def test_load_rejects_manifest_symlink(self):
        snapshot = self._capture_file()
        self._replace_with_symlink(
            self._object_path(snapshot.ref.manifest.content_sha256)
        )
        with self.assertRaises(SnapshotStoreError) as caught:
            self.store.load(snapshot.ref)
        self.assertEqual(caught.exception.code, SnapshotErrorCode.INTEGRITY_FAILURE)

    def test_load_rejects_reference_index_content_tamper(self):
        snapshot = self._capture_file()
        self._replace_immutable_payload(self._reference_path(snapshot), b"{}")
        with self.assertRaises(SnapshotStoreError) as caught:
            self.store.load(snapshot.ref)
        self.assertEqual(caught.exception.code, SnapshotErrorCode.INTEGRITY_FAILURE)

    def test_load_rejects_reference_index_symlink(self):
        snapshot = self._capture_file()
        self._replace_with_symlink(self._reference_path(snapshot))
        with self.assertRaises(SnapshotStoreError) as caught:
            self.store.load(snapshot.ref)
        self.assertEqual(caught.exception.code, SnapshotErrorCode.INTEGRITY_FAILURE)

    def test_addressed_fifos_fail_closed_without_blocking(self):
        snapshot = self._capture_file()
        file_entry = next(
            entry
            for entry in snapshot.manifest.entries
            if entry.kind is SnapshotEntryKind.FILE
        )

        probes = (
            ("reference", self._reference_path(snapshot), lambda: self.store.load(snapshot.ref)),
            (
                "verify-object",
                self._object_path(file_entry.content_sha256),
                lambda: self.store.verify(snapshot.ref),
            ),
            (
                "materialize-object",
                self._object_path(file_entry.content_sha256),
                lambda: self.store.materialize(
                    snapshot.ref,
                    self.base / "fifo-materialization",
                ),
            ),
        )
        for label, path, operation in probes:
            with self.subTest(label=label):
                saved = path.with_name(f"{path.name}.{label}.saved")
                path.rename(saved)
                os.mkfifo(path, mode=0o444)
                try:
                    error = self._assert_fails_without_blocking(operation)
                    self.assertEqual(
                        error.code,
                        SnapshotErrorCode.INTEGRITY_FAILURE,
                    )
                finally:
                    path.unlink(missing_ok=True)
                    saved.rename(path)

    def test_missing_addressed_object_is_integrity_failure(self):
        snapshot = self._capture_file()
        file_entry = next(
            entry
            for entry in snapshot.manifest.entries
            if entry.kind is SnapshotEntryKind.FILE
        )
        self._object_path(file_entry.content_sha256).unlink()
        with self.assertRaises(SnapshotStoreError) as caught:
            self.store.verify(snapshot.ref)
        self.assertEqual(caught.exception.code, SnapshotErrorCode.INTEGRITY_FAILURE)

    def test_atomic_publish_never_replaces_a_racing_incumbent(self):
        (self.source / "main.txt").write_text("payload\n", encoding="utf-8")
        real_rename = snapshot_runtime._rename_noreplace
        raced_destination = None

        def inject_incumbent(source, destination):
            nonlocal raced_destination
            if raced_destination is None:
                destination.write_bytes(b"untrusted incumbent")
                destination.chmod(0o444)
                raced_destination = destination
            return real_rename(source, destination)

        with mock.patch.object(
            snapshot_runtime,
            "_rename_noreplace",
            side_effect=inject_incumbent,
        ):
            with self.assertRaises(SnapshotStoreError):
                self.store.capture(self.source, self.policy)
        self.assertIsNotNone(raced_destination)
        self.assertEqual(raced_destination.read_bytes(), b"untrusted incumbent")

    def test_noreplace_publish_has_safe_unsupported_filesystem_fallback(self):
        source_directory = self.base / "fallback-source"
        destination_directory = self.base / "fallback-destination"
        source_directory.mkdir()
        destination_directory.mkdir()

        def unsupported_rename(*_args):
            snapshot_runtime.ctypes.set_errno(snapshot_runtime.errno.EINVAL)
            return -1

        source = source_directory / "payload"
        destination = destination_directory / "address"
        source.write_bytes(b"frozen")
        with mock.patch.object(
            snapshot_runtime,
            "_RENAMEAT2",
            side_effect=unsupported_rename,
        ):
            snapshot_runtime._rename_noreplace(source, destination)
        self.assertFalse(source.exists())
        self.assertEqual(destination.read_bytes(), b"frozen")
        self.assertEqual(destination.stat().st_nlink, 1)

        incumbent = destination_directory / "incumbent"
        incumbent.write_bytes(b"keep")
        second_source = source_directory / "second"
        second_source.write_bytes(b"do not publish")
        with mock.patch.object(
            snapshot_runtime,
            "_RENAMEAT2",
            side_effect=unsupported_rename,
        ):
            with self.assertRaises(FileExistsError):
                snapshot_runtime._rename_noreplace(second_source, incumbent)
        self.assertEqual(incumbent.read_bytes(), b"keep")
        self.assertEqual(second_source.read_bytes(), b"do not publish")

    def test_fresh_store_bootstrap_is_process_safe(self):
        if "fork" not in multiprocessing.get_all_start_methods():
            self.skipTest("SnapshotStore process test requires Linux fork")
        context = multiprocessing.get_context("fork")
        worker_count = 12
        barrier = context.Barrier(worker_count)
        results = context.Queue()
        root = self.base / "concurrent-fresh-store"
        workers = [
            context.Process(
                target=_initialize_snapshot_store_worker,
                args=(os.fspath(root), barrier, results),
            )
            for _ in range(worker_count)
        ]
        try:
            for worker in workers:
                worker.start()
            for worker in workers:
                worker.join(timeout=15)
            self.assertTrue(all(not worker.is_alive() for worker in workers))
            self.assertEqual([worker.exitcode for worker in workers], [0] * worker_count)
            self.assertEqual(
                [results.get(timeout=2) for _ in workers],
                [None] * worker_count,
            )
            SnapshotStore(root)
        finally:
            for worker in workers:
                if worker.is_alive():
                    worker.terminate()
                    worker.join(timeout=5)

    def test_cross_process_capture_serializes_and_reuses_one_snapshot(self):
        if "fork" not in multiprocessing.get_all_start_methods():
            self.skipTest("SnapshotStore process test requires Linux fork")
        (self.source / "main.txt").write_text("shared payload\n", encoding="utf-8")
        context = multiprocessing.get_context("fork")
        worker_count = 8
        barrier = context.Barrier(worker_count)
        results = context.Queue()
        root = self.base / "cross-process-cas"
        workers = [
            context.Process(
                target=_capture_snapshot_worker,
                args=(
                    os.fspath(root),
                    os.fspath(self.source),
                    barrier,
                    results,
                ),
            )
            for _ in range(worker_count)
        ]
        try:
            for worker in workers:
                worker.start()
            for worker in workers:
                worker.join(timeout=20)
            self.assertTrue(all(not worker.is_alive() for worker in workers))
            self.assertEqual([worker.exitcode for worker in workers], [0] * worker_count)
            rows = [results.get(timeout=2) for _ in workers]
            self.assertEqual(
                [detail for status, detail in rows if status != "ok"],
                [],
            )
            references = [
                SnapshotRef.from_document(detail)
                for status, detail in rows
                if status == "ok"
            ]
            self.assertEqual(len(references), worker_count)
            self.assertEqual(
                {reference.snapshot_sha256 for reference in references},
                {references[0].snapshot_sha256},
            )
            self.assertEqual(
                SnapshotStore(root).verify(references[0]).ref,
                references[0],
            )
        finally:
            for worker in workers:
                if worker.is_alive():
                    worker.terminate()
                    worker.join(timeout=5)

    def test_store_parent_must_protect_the_root_directory_entry(self):
        unsafe_parent = self.base / "unsafe-store-parent"
        unsafe_parent.mkdir(mode=0o733)
        unsafe_parent.chmod(0o733)
        with self.assertRaises(SnapshotStoreError) as caught:
            SnapshotStore(unsafe_parent / "cas")
        self.assertEqual(caught.exception.code, SnapshotErrorCode.INVALID_STORE)

    def test_cleanup_root_mount_identity_mismatch_is_rejected(self):
        cleanup_root = self.base / "mounted-cleanup-root"
        cleanup_root.mkdir()

        def mismatched_mount_id(_descriptor, relative_path):
            return 101 if relative_path == "." else 100

        with mock.patch.object(
            snapshot_runtime,
            "_mount_id",
            side_effect=mismatched_mount_id,
        ):
            with self.assertRaises(OSError):
                snapshot_runtime._require_single_mount_tree(cleanup_root)
        self.assertTrue(cleanup_root.is_dir())

    def test_stale_capture_recovery_handles_unreadable_directories(self):
        snapshot = self._capture_file()
        stale = self.store.root / "tmp" / "capture-crashed"
        nested = stale / "nested"
        nested.mkdir(parents=True)
        (nested / "partial").write_bytes(b"partial")
        nested.chmod(0)
        stale.chmod(0)

        self.assertEqual(self.store.load(snapshot.ref).ref, snapshot.ref)
        self.assertFalse(stale.exists())

    def test_snapshot_depth_limit_matches_safe_cleanup_boundary(self):
        current = self.source
        for _ in range(MAX_SNAPSHOT_PATH_COMPONENTS):
            current = current / "d"
            current.mkdir()
        accepted = self.store.capture(self.source, self.policy)
        self.store.materialize(accepted.ref, self.base / "maximum-depth")

        (current / "too-deep").mkdir()
        with self.assertRaises(SnapshotStoreError) as caught:
            self.store.capture(self.source, self.policy)
        self.assertEqual(caught.exception.code, SnapshotErrorCode.UNSAFE_SOURCE_ENTRY)

    def test_symlink_payload_counts_toward_total_byte_limit(self):
        (self.source / "link").symlink_to("missing")
        zero_bytes = _policy(max_file_bytes=0, max_total_bytes=0)
        with self.assertRaises(SnapshotStoreError) as caught:
            self.store.capture(self.source, zero_bytes)
        self.assertEqual(caught.exception.code, SnapshotErrorCode.POLICY_LIMIT_EXCEEDED)


class WorkspaceRuntimeTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(
            prefix="fmagent-workspace-",
            dir="/tmp",
        )
        self.base = Path(self.temporary.name).resolve()
        self.source = self.base / "source"
        self.source.mkdir()
        (self.source / "main.txt").write_text("frozen\n", encoding="utf-8")
        self.store = SnapshotStore(self.base / "cas")
        self.snapshot = self.store.capture(self.source, _policy())
        self.equivalence_policy = _ref(
            ContractRefKind.EXECUTION_EQUIVALENCE_POLICY,
            "workspace-equivalence",
        )
        self.profile = _profile(
            self.snapshot.ref.snapshot_sha256,
            equivalence_policy=self.equivalence_policy,
        )
        self.resource_policy = self.profile.environment.resource_policy
        self.identity = ValidationInstanceIdentity(
            project_id=self.profile.project.system_id,
            case_id="case-1",
            function_id="module.function",
            snapshot_sha256=self.snapshot.ref.snapshot_sha256,
            reasoning_sha256=_digest("reasoning"),
            profile_sha256=self.profile.content_sha256,
        )
        self.policies = {
            role: build_role_policy(role, self.profile, self.resource_policy)
            for role in WorkspaceRole
        }
        self.manager = WorkspaceManager(
            store=self.store,
            run_root=self.base / "runs",
            broker_id="test.workspace",
        )

    def tearDown(self):
        self.temporary.cleanup()

    def _allocate(
        self,
        role,
        *,
        identity=None,
        profile=None,
        policy=None,
        equivalence_policy=None,
        attempt_id="attempt-1",
        session_marker=True,
    ):
        agent_session_id = None
        if role is WorkspaceRole.A and session_marker:
            agent_session_id = "agent-session-1"
        return self.manager.materialize(
            snapshot=self.snapshot.ref,
            identity=identity or self.identity,
            profile=profile or self.profile,
            attempt_id=attempt_id,
            role_policy=policy or self.policies[role],
            workspace_equivalence_policy=(
                equivalence_policy or self.equivalence_policy
            ),
            agent_session_id=agent_session_id,
        )

    def _direct_lease(
        self,
        *,
        identity=None,
        equivalence_policy=None,
        role=WorkspaceRole.B1,
        attempt_id="attempt-direct",
        proof_sha256=None,
    ):
        return WorkspaceLease.create(
            lease_id=f"ws-direct-{role.value.lower()}",
            broker_id="test.workspace",
            identity=identity or self.identity,
            profile=self.profile,
            attempt_id=attempt_id,
            agent_session_id=("agent-direct" if role is WorkspaceRole.A else None),
            role=role,
            snapshot=self.snapshot.ref,
            role_policy=self.policies[role],
            workspace_equivalence_policy=(
                equivalence_policy or self.equivalence_policy
            ),
            write_layer_sha256=_digest(f"write:{role.value}:{attempt_id}"),
            materialization_proof_sha256=(
                proof_sha256 or _digest(f"proof:{role.value}:{attempt_id}")
            ),
        )

    def _coherent_untrusted_lease_with_equivalence(self, lease, policy):
        equivalence = workspace_runtime._equivalence_fingerprint(
            lease.snapshot,
            policy,
        )
        resource = canonical_sha256(
            workspace_runtime._resource_fingerprint_document(
                lease_id=lease.lease_id,
                broker_id=lease.broker_id,
                validation_instance_id=lease.validation_instance_id,
                attempt_id=lease.attempt_id,
                agent_session_id=lease.agent_session_id,
                role=lease.role,
                snapshot=lease.snapshot,
                role_policy_sha256=lease.role_policy_sha256,
                workspace_equivalence_policy=policy,
                write_layer_sha256=lease.write_layer_sha256,
                materialization_proof_sha256=(
                    lease.materialization_proof_sha256
                ),
                equivalence_fingerprint_sha256=equivalence,
            )
        )
        return WorkspaceLease(
            lease_id=lease.lease_id,
            broker_id=lease.broker_id,
            validation_instance_id=lease.validation_instance_id,
            attempt_id=lease.attempt_id,
            agent_session_id=lease.agent_session_id,
            role=lease.role,
            snapshot=lease.snapshot,
            role_policy_sha256=lease.role_policy_sha256,
            workspace_equivalence_policy=policy,
            write_layer_sha256=lease.write_layer_sha256,
            materialization_proof_sha256=lease.materialization_proof_sha256,
            resource_fingerprint_sha256=resource,
            equivalence_fingerprint_sha256=equivalence,
        )

    def test_builtin_role_policies_are_closed_hash_bound_and_strict(self):
        a = self.policies[WorkspaceRole.A]
        b1 = self.policies[WorkspaceRole.B1]
        b2 = self.policies[WorkspaceRole.B2]
        self.assertIn(RoleCapability.AGENT_SESSION, a.capabilities)
        self.assertNotIn(RoleCapability.AGENT_SESSION, b1.capabilities)
        self.assertNotIn(RoleCapability.AGENT_SESSION, b2.capabilities)
        self.assertEqual(a.credential_policy, CredentialPolicy.MASKED_PROVIDER_SCOPED)
        self.assertEqual(b1.credential_policy, CredentialPolicy.NONE)
        self.assertEqual(b2.credential_policy, CredentialPolicy.NONE)
        self.assertEqual(
            a.network_policy,
            NetworkPolicy.MASKED_PROVIDER_AND_EXPLORATION_BROKER,
        )
        self.assertEqual(
            b1.network_policy,
            NetworkPolicy.PROFILE_INTERNAL_BROKER_ONLY,
        )
        self.assertIn(self.equivalence_policy, self.profile.components)

        for policy in self.policies.values():
            with self.subTest(role=policy.role.value):
                self.assertEqual(RolePolicy.from_json(policy.to_json()), policy)
                self.assertEqual(policy.profile, self.profile.ref)
                self.assertEqual(policy.resource_policy, self.resource_policy)

        forged = b1.to_document()
        forged["capabilities"].append(RoleCapability.AGENT_SESSION.value)
        with self.assertRaises(ContractError):
            RolePolicy.from_document(forged)
        forged = b1.to_document()
        forged["role"] = WorkspaceRole.A.value
        with self.assertRaises(ContractError):
            RolePolicy.from_document(forged)
        forged = b1.to_document()
        forged["host_path"] = "/tmp/forbidden"
        with self.assertRaises(ContractError):
            RolePolicy.from_document(forged)

    def test_role_policy_builder_rejects_resource_not_frozen_by_profile(self):
        with self.assertRaises(ContractError):
            build_role_policy(
                WorkspaceRole.B1,
                self.profile,
                _ref(ContractRefKind.RESOURCE_POLICY, "forged-resource"),
            )

    def test_role_policy_and_lease_parsers_reject_ambiguous_shapes(self):
        policy = self.policies[WorkspaceRole.B1]
        lease = self._direct_lease()
        cases = (
            ("role-policy", RolePolicy, policy.to_document(), "role"),
            ("workspace-lease", WorkspaceLease, lease.to_document(), "attempt_id"),
        )
        for name, contract_type, valid, scalar_field in cases:
            with self.subTest(contract=name, mutation="duplicate-key"):
                with self.assertRaises(ContractError):
                    contract_type.from_json(
                        b'{"schema_version":1,"schema_version":1}'
                    )
            mutations = (
                ("unknown-version", {**valid, "schema_version": 2}),
                ("boolean-version", {**valid, "schema_version": True}),
                ("unexpected-field", {**valid, "unexpected": "authority"}),
                ("wrong-scalar", {**valid, scalar_field: 1}),
            )
            for mutation, document in mutations:
                with self.subTest(contract=name, mutation=mutation):
                    with self.assertRaises(ContractError):
                        contract_type.from_document(document)

    def test_workspace_manager_rejects_unsafe_leases_directory_permissions(self):
        run_root = self.base / "unsafe-leases-run"
        leases = run_root / "leases"
        leases.mkdir(parents=True, mode=0o700)
        leases.chmod(0o777)
        try:
            with self.assertRaises(WorkspaceError) as caught:
                WorkspaceManager(store=self.store, run_root=run_root)
            self.assertEqual(
                caught.exception.code,
                WorkspaceErrorCode.INVALID_RUN_ROOT,
            )
        finally:
            leases.chmod(0o700)

    def test_workspace_manager_rejects_wrong_leases_owner_without_chown(self):
        run_root = self.base / "wrong-owner-run"
        leases = run_root / "leases"
        leases.mkdir(parents=True, mode=0o700)
        real_lstat = os.lstat

        def lstat(path, *args, **kwargs):
            metadata = real_lstat(path, *args, **kwargs)
            try:
                is_leases = Path(path) == leases
            except TypeError:
                is_leases = False
            if not is_leases:
                return metadata
            fields = list(metadata)
            fields[4] = os.geteuid() + 1
            return os.stat_result(fields)

        with mock.patch.object(workspace_runtime.os, "lstat", side_effect=lstat):
            with self.assertRaises(WorkspaceError) as caught:
                WorkspaceManager(store=self.store, run_root=run_root)
        self.assertEqual(caught.exception.code, WorkspaceErrorCode.INVALID_RUN_ROOT)

    def test_workspace_manager_rejects_unprotected_run_root_parent(self):
        unsafe_parent = self.base / "unsafe-run-parent"
        unsafe_parent.mkdir(mode=0o733)
        unsafe_parent.chmod(0o733)
        run_root = unsafe_parent / "runs"
        try:
            with self.assertRaises(WorkspaceError) as caught:
                WorkspaceManager(store=self.store, run_root=run_root)
            self.assertEqual(caught.exception.code, WorkspaceErrorCode.INVALID_RUN_ROOT)
            self.assertFalse(run_root.exists())
        finally:
            unsafe_parent.chmod(0o700)

    def test_workspace_manager_rejects_store_overlap_without_creating_it(self):
        run_root = self.store.root / "forbidden-runs"
        before = sorted(
            path.relative_to(self.store.root).as_posix()
            for path in self.store.root.rglob("*")
        )

        with self.assertRaises(WorkspaceError) as caught:
            WorkspaceManager(store=self.store, run_root=run_root)

        self.assertEqual(caught.exception.code, WorkspaceErrorCode.INVALID_RUN_ROOT)
        self.assertFalse(run_root.exists())
        self.assertEqual(
            sorted(
                path.relative_to(self.store.root).as_posix()
                for path in self.store.root.rglob("*")
            ),
            before,
        )

    def test_workspace_manager_revalidates_pinned_run_root_identity(self):
        original = self.manager.run_root
        saved = self.base / "saved-run-root"
        original.rename(saved)
        original.mkdir(mode=0o700)
        (original / "leases").mkdir(mode=0o700)
        try:
            with self.assertRaises(WorkspaceError) as caught:
                self._allocate(WorkspaceRole.B1)
            self.assertEqual(caught.exception.code, WorkspaceErrorCode.INVALID_RUN_ROOT)
            self.assertEqual(list((original / "leases").iterdir()), [])
        finally:
            (original / "leases").rmdir()
            original.rmdir()
            saved.rename(original)

    def test_workspace_manager_revalidates_pinned_leases_root_identity(self):
        original = self.manager.leases_root
        saved = self.manager.run_root / "saved-leases-root"
        original.rename(saved)
        original.mkdir(mode=0o700)
        try:
            with self.assertRaises(WorkspaceError) as caught:
                self._allocate(WorkspaceRole.B1)
            self.assertEqual(caught.exception.code, WorkspaceErrorCode.INVALID_RUN_ROOT)
            self.assertEqual(list(original.iterdir()), [])
        finally:
            original.rmdir()
            saved.rename(original)

    def test_a_b1_b2_are_fresh_equivalent_and_pollution_isolated(self):
        (self.source / "main.txt").write_text("changed original\n", encoding="utf-8")
        a = self._allocate(WorkspaceRole.A)
        b1 = self._allocate(WorkspaceRole.B1)
        b2 = self._allocate(WorkspaceRole.B2)
        validate_workspace_independence(a, b1, b2)

        allocations = (a, b1, b2)
        self.assertEqual(
            {item.lease.snapshot.snapshot_sha256 for item in allocations},
            {self.snapshot.ref.snapshot_sha256},
        )
        self.assertEqual(
            len({item.lease.equivalence_fingerprint_sha256 for item in allocations}),
            1,
        )
        for field in (
            "lease_id",
            "write_layer_sha256",
            "materialization_proof_sha256",
            "resource_fingerprint_sha256",
        ):
            self.assertEqual(
                len({getattr(item.lease, field) for item in allocations}),
                3,
                field,
            )
        self.assertEqual(len({item.paths.root for item in allocations}), 3)
        self.assertEqual(
            len({(item.paths.project / "main.txt").stat().st_ino for item in allocations}),
            3,
        )
        self.assertEqual(
            {(item.paths.project / "main.txt").read_text(encoding="utf-8") for item in allocations},
            {"frozen\n"},
        )

        (a.paths.project / "main.txt").write_text("A pollution\n", encoding="utf-8")
        self.assertEqual(
            (b1.paths.project / "main.txt").read_text(encoding="utf-8"),
            "frozen\n",
        )
        (b1.paths.project / "main.txt").write_text("B1 pollution\n", encoding="utf-8")
        self.assertEqual(
            (b2.paths.project / "main.txt").read_text(encoding="utf-8"),
            "frozen\n",
        )
        self.assertEqual(
            self.store.verify(self.snapshot.ref).ref,
            self.snapshot.ref,
        )

    def test_agent_workspace_can_persist_across_gate_attempt(self):
        a = self._allocate(WorkspaceRole.A, attempt_id="attempt-agent")
        b1 = self._allocate(WorkspaceRole.B1, attempt_id="attempt-gate-2")
        b2 = self._allocate(WorkspaceRole.B2, attempt_id="attempt-gate-2")
        validate_workspace_independence(a, b1, b2)

    def test_workspace_lineage_remains_verifiable_after_every_role_is_released(self):
        a = self._allocate(WorkspaceRole.A, attempt_id="attempt-agent")
        b1 = self._allocate(WorkspaceRole.B1, attempt_id="attempt-gate")
        a_lineage = WorkspaceLineageRecord.from_allocation(a)
        b1_lineage = WorkspaceLineageRecord.from_allocation(b1)
        a_root = a.paths.root
        b1_root = b1.paths.root

        self.manager.release(b1)
        self.manager.release(a)
        self.assertFalse(a_root.exists())
        self.assertFalse(b1_root.exists())

        b2 = self._allocate(WorkspaceRole.B2, attempt_id="attempt-gate")
        b2_lineage = WorkspaceLineageRecord.from_allocation(b2)
        b2_root = b2.paths.root
        self.manager.release(b2)
        self.assertFalse(b2_root.exists())

        with mock.patch.object(
            workspace_runtime,
            "_regular_inodes",
            side_effect=AssertionError("path-free lineage read a released tree"),
        ):
            validate_workspace_lineage(a_lineage, b1_lineage, b2_lineage)

        for lineage in (a_lineage, b1_lineage, b2_lineage):
            payload = lineage.to_json()
            self.assertEqual(WorkspaceLineageRecord.from_json(payload), lineage)
            self.assertNotIn(os.fspath(self.base).encode("utf-8"), payload)

    def test_workspace_lineage_rejects_forged_and_reused_identities(self):
        a = self._allocate(WorkspaceRole.A, attempt_id="attempt-agent")
        b1 = self._allocate(WorkspaceRole.B1, attempt_id="attempt-gate")
        b2 = self._allocate(WorkspaceRole.B2, attempt_id="attempt-gate")
        a_lineage = WorkspaceLineageRecord.from_allocation(a)
        b1_lineage = WorkspaceLineageRecord.from_allocation(b1)
        b2_lineage = WorkspaceLineageRecord.from_allocation(b2)

        def rebuild_b2(
            *,
            lease_id=None,
            write_layer_sha256=None,
            proof=None,
        ):
            selected_proof = proof or b2_lineage.materialization_proof
            lease = WorkspaceLease.create(
                lease_id=lease_id or b2_lineage.lease.lease_id,
                broker_id=b2_lineage.lease.broker_id,
                identity=self.identity,
                profile=self.profile,
                attempt_id=b2_lineage.lease.attempt_id,
                agent_session_id=None,
                role=WorkspaceRole.B2,
                snapshot=self.snapshot.ref,
                role_policy=self.policies[WorkspaceRole.B2],
                workspace_equivalence_policy=self.equivalence_policy,
                write_layer_sha256=(
                    write_layer_sha256
                    or b2_lineage.lease.write_layer_sha256
                ),
                materialization_proof_sha256=selected_proof.content_sha256,
            )
            return WorkspaceLineageRecord(
                lease=lease,
                role_policy=self.policies[WorkspaceRole.B2],
                materialization_proof=selected_proof,
            )

        repeated_proof = rebuild_b2(
            proof=b1_lineage.materialization_proof,
        )
        repeated_materialization_id = rebuild_b2(
            proof=dataclasses.replace(
                b2_lineage.materialization_proof,
                materialization_id=(
                    b1_lineage.materialization_proof.materialization_id
                ),
                entry_count=(
                    b2_lineage.materialization_proof.entry_count + 1
                ),
            ),
        )
        repeated = (
            rebuild_b2(lease_id=b1_lineage.lease.lease_id),
            rebuild_b2(
                write_layer_sha256=b1_lineage.lease.write_layer_sha256,
            ),
            repeated_proof,
            repeated_materialization_id,
        )
        for forged in repeated:
            with self.subTest(forged=forged.content_sha256):
                with self.assertRaises(WorkspaceError) as caught:
                    validate_workspace_lineage(
                        a_lineage,
                        b1_lineage,
                        forged,
                    )
                self.assertEqual(
                    caught.exception.code,
                    WorkspaceErrorCode.WORKSPACE_INTEGRITY_FAILURE,
                )

        corrupted = dataclasses.replace(b2_lineage)
        corrupted_lease = dataclasses.replace(b2_lineage.lease)
        object.__setattr__(
            corrupted_lease,
            "resource_fingerprint_sha256",
            b1_lineage.lease.resource_fingerprint_sha256,
        )
        object.__setattr__(corrupted, "lease", corrupted_lease)
        with self.assertRaises(WorkspaceError):
            validate_workspace_lineage(a_lineage, b1_lineage, corrupted)

    def test_workspace_lineage_parser_is_strict_and_rebinds_nested_contracts(self):
        b1 = self._allocate(WorkspaceRole.B1)
        b2 = self._allocate(WorkspaceRole.B2)
        lineage = WorkspaceLineageRecord.from_allocation(b1)
        self.assertEqual(
            WorkspaceLineageRecord.from_json(lineage.to_json()),
            lineage,
        )

        with self.assertRaises(ContractError):
            WorkspaceLineageRecord.from_json(
                b'{"contract_kind":"workspace_lineage_record",'
                b'"contract_kind":"workspace_lineage_record"}'
            )
        valid = lineage.to_document()
        for name, document in (
            ("unknown-version", {**valid, "schema_version": 2}),
            ("boolean-version", {**valid, "schema_version": True}),
            ("host-path", {**valid, "root": os.fspath(b1.paths.root)}),
        ):
            with self.subTest(mutation=name):
                with self.assertRaises(ContractError):
                    WorkspaceLineageRecord.from_document(document)

        for nested in ("lease", "role_policy", "materialization_proof"):
            document = lineage.to_document()
            document[nested]["host_path"] = os.fspath(b1.paths.root)
            with self.subTest(nested=nested), self.assertRaises(ContractError):
                WorkspaceLineageRecord.from_document(document)

        mismatched = lineage.to_document()
        mismatched["materialization_proof"] = (
            b2.materialization.proof.to_document()
        )
        with self.assertRaises(ContractError):
            WorkspaceLineageRecord.from_document(mismatched)

    def test_b1_b2_from_different_attempts_are_not_one_independent_set(self):
        a = self._allocate(WorkspaceRole.A, attempt_id="attempt-agent")
        b1 = self._allocate(WorkspaceRole.B1, attempt_id="attempt-gate-1")
        b2 = self._allocate(WorkspaceRole.B2, attempt_id="attempt-gate-2")
        with self.assertRaises(WorkspaceError) as caught:
            validate_workspace_independence(a, b1, b2)
        self.assertEqual(
            caught.exception.code,
            WorkspaceErrorCode.WORKSPACE_INTEGRITY_FAILURE,
        )

    def test_independence_requires_exact_equivalence_policy_and_fingerprint(self):
        a = self._allocate(WorkspaceRole.A)
        b1 = self._allocate(WorkspaceRole.B1)
        b2 = self._allocate(WorkspaceRole.B2)
        outside = _ref(
            ContractRefKind.EXECUTION_EQUIVALENCE_POLICY,
            "independence-outside",
        )
        forged_lease = self._coherent_untrusted_lease_with_equivalence(
            b2.lease,
            outside,
        )
        forged_b2 = dataclasses.replace(b2, lease=forged_lease)
        with self.assertRaises(WorkspaceError):
            validate_workspace_independence(a, b1, forged_b2)

        # Even the same policy cannot carry a divergent broker equivalence
        # assertion.  Bypass frozen construction to model a corrupted in-memory
        # broker handle reaching this final defense-in-depth validator.
        corrupted_lease = dataclasses.replace(b2.lease)
        object.__setattr__(
            corrupted_lease,
            "equivalence_fingerprint_sha256",
            _digest("corrupted equivalence fingerprint"),
        )
        corrupted_b2 = dataclasses.replace(b2)
        object.__setattr__(corrupted_b2, "lease", corrupted_lease)
        with self.assertRaises(WorkspaceError):
            validate_workspace_independence(a, b1, corrupted_b2)

    def test_independence_rejects_foreign_profile_and_resource_policy(self):
        a = self._allocate(WorkspaceRole.A)
        b1 = self._allocate(WorkspaceRole.B1)
        b2 = self._allocate(WorkspaceRole.B2)

        foreign_profile = _profile(
            self.snapshot.ref.snapshot_sha256,
            salt="foreign",
            equivalence_policy=self.equivalence_policy,
        )
        foreign_profile_policy = build_role_policy(
            WorkspaceRole.B2,
            foreign_profile,
            foreign_profile.environment.resource_policy,
        )
        forged_profile_allocation = dataclasses.replace(b2)
        object.__setattr__(
            forged_profile_allocation,
            "role_policy",
            foreign_profile_policy,
        )
        with self.assertRaises(WorkspaceError) as caught:
            validate_workspace_independence(a, b1, forged_profile_allocation)
        self.assertEqual(
            caught.exception.code,
            WorkspaceErrorCode.WORKSPACE_INTEGRITY_FAILURE,
        )

        foreign_resource_policy = dataclasses.replace(
            b2.role_policy,
            resource_policy=_ref(
                ContractRefKind.RESOURCE_POLICY,
                "foreign-resource",
            ),
        )
        forged_resource_allocation = dataclasses.replace(b2)
        object.__setattr__(
            forged_resource_allocation,
            "role_policy",
            foreign_resource_policy,
        )
        with self.assertRaises(WorkspaceError) as caught:
            validate_workspace_independence(a, b1, forged_resource_allocation)
        self.assertEqual(
            caught.exception.code,
            WorkspaceErrorCode.WORKSPACE_INTEGRITY_FAILURE,
        )

    def test_workspace_allocation_binds_exact_policy_and_manifest_proof_hashes(self):
        allocation = self._allocate(WorkspaceRole.B1)
        proof = allocation.materialization.proof
        for field in ("policy_sha256", "manifest_sha256"):
            with self.subTest(field=field):
                forged_proof = dataclasses.replace(
                    proof,
                    **{field: _digest(f"forged {field}")},
                )
                forged_lease = WorkspaceLease.create(
                    lease_id=f"ws-forged-{field}",
                    broker_id=allocation.lease.broker_id,
                    identity=self.identity,
                    profile=self.profile,
                    attempt_id=allocation.lease.attempt_id,
                    agent_session_id=None,
                    role=WorkspaceRole.B1,
                    snapshot=self.snapshot.ref,
                    role_policy=self.policies[WorkspaceRole.B1],
                    workspace_equivalence_policy=self.equivalence_policy,
                    write_layer_sha256=_digest(f"write:{field}"),
                    materialization_proof_sha256=forged_proof.content_sha256,
                )
                materialized = MaterializedSnapshot(
                    allocation.paths.project,
                    forged_proof,
                )
                with self.assertRaises(ValueError):
                    WorkspaceAllocation(
                        lease=forged_lease,
                        role_policy=self.policies[WorkspaceRole.B1],
                        paths=allocation.paths,
                        materialization=materialized,
                    )

    def test_workspace_layout_is_role_specific(self):
        a = self._allocate(WorkspaceRole.A)
        b1 = self._allocate(WorkspaceRole.B1)
        self.assertIsNotNone(a.paths.case_staging)
        self.assertIsNone(a.paths.variants)
        self.assertIsNone(a.paths.artifacts)
        self.assertIsNone(a.paths.logs)
        self.assertIsNone(a.paths.receipts)
        self.assertIsNone(b1.paths.case_staging)
        for path in (
            b1.paths.variants,
            b1.paths.artifacts,
            b1.paths.logs,
            b1.paths.receipts,
            b1.paths.scratch,
        ):
            self.assertTrue(path.is_dir())

    def test_independence_validator_rejects_cross_role_inode_alias(self):
        a = self._allocate(WorkspaceRole.A)
        b1 = self._allocate(WorkspaceRole.B1)
        b2 = self._allocate(WorkspaceRole.B2)
        b1_file = b1.paths.project / "main.txt"
        b1_file.unlink()
        os.link(a.paths.project / "main.txt", b1_file)

        with self.assertRaises(WorkspaceError) as caught:
            validate_workspace_independence(a, b1, b2)
        self.assertEqual(
            caught.exception.code,
            WorkspaceErrorCode.WORKSPACE_INTEGRITY_FAILURE,
        )

    def test_lease_roundtrip_and_dynamic_binding_hide_host_paths(self):
        allocation = self._allocate(WorkspaceRole.B1)
        lease = allocation.lease
        self.assertEqual(
            WorkspaceLease.from_json(canonical_json_bytes(lease.to_document())),
            lease,
        )
        with self.assertRaises(TypeError):
            lease.to_dynamic_resource_binding()
        binding = lease.to_dynamic_resource_binding(GateRole.B1)
        self.assertEqual(binding.symbol, "workspace.project")
        self.assertEqual(binding.resource_kind, DynamicResourceKind.WORKSPACE)
        self.assertEqual(binding.allocation_id, lease.lease_id)
        self.assertEqual(
            binding.resource_fingerprint_sha256,
            lease.resource_fingerprint_sha256,
        )
        self.assertEqual(
            binding.equivalence_fingerprint_sha256,
            lease.equivalence_fingerprint_sha256,
        )
        serialized = canonical_json_bytes(lease.to_document())
        self.assertNotIn(os.fspath(self.base).encode("utf-8"), serialized)

        forged = lease.to_document()
        forged["resource_fingerprint_sha256"] = _digest("forged")
        with self.assertRaises(ContractError):
            WorkspaceLease.from_document(forged)
        forged = lease.to_document()
        forged["physical_path"] = os.fspath(allocation.paths.project)
        with self.assertRaises(ContractError):
            WorkspaceLease.from_document(forged)

    def test_dynamic_binding_requires_matching_gate_role_and_rejects_agent(self):
        a = self._allocate(WorkspaceRole.A)
        b1 = self._allocate(WorkspaceRole.B1)
        b2 = self._allocate(WorkspaceRole.B2)
        with self.assertRaises(ContractError):
            a.lease.to_dynamic_resource_binding(GateRole.B1)
        with self.assertRaises(ContractError):
            b1.lease.to_dynamic_resource_binding(GateRole.B2)
        with self.assertRaises(ContractError):
            b2.lease.to_dynamic_resource_binding(GateRole.B1)
        with self.assertRaises(ContractError):
            b1.lease.to_dynamic_resource_binding("B1")
        self.assertEqual(
            b1.lease.to_dynamic_resource_binding(GateRole.B1).allocation_id,
            b1.lease.lease_id,
        )
        self.assertEqual(
            b2.lease.to_dynamic_resource_binding(GateRole.B2).allocation_id,
            b2.lease.lease_id,
        )

    def test_gate_leases_integrate_with_execution_binding_validators(self):
        b1 = self._allocate(WorkspaceRole.B1, attempt_id="attempt-gate")
        b2 = self._allocate(WorkspaceRole.B2, attempt_id="attempt-gate")
        template = _execution_template(
            self.identity,
            self.profile,
            self.equivalence_policy,
        )
        b1_binding = ExecutionBinding(
            validation_instance_id=self.identity.validation_instance_id,
            attempt_id=b1.lease.attempt_id,
            role=GateRole.B1,
            template=template.ref,
            resources=(
                b1.lease.to_dynamic_resource_binding(GateRole.B1),
            ),
            broker_receipt_sha256=_digest("broker receipt B1"),
        )
        b2_binding = ExecutionBinding(
            validation_instance_id=self.identity.validation_instance_id,
            attempt_id=b2.lease.attempt_id,
            role=GateRole.B2,
            template=template.ref,
            resources=(
                b2.lease.to_dynamic_resource_binding(GateRole.B2),
            ),
            broker_receipt_sha256=_digest("broker receipt B2"),
        )
        validate_execution_binding(template, b1_binding)
        validate_execution_binding(template, b2_binding)
        validate_b1_b2_binding_equivalence(template, b1_binding, b2_binding)

    def test_parsed_lease_must_be_rebound_to_authority_context(self):
        allocation = self._allocate(WorkspaceRole.B1)
        parsed = WorkspaceLease.from_json(
            canonical_json_bytes(allocation.lease.to_document())
        )
        validate_workspace_lease_context(
            parsed,
            identity=self.identity,
            profile=self.profile,
            role_policy=self.policies[WorkspaceRole.B1],
        )

        wrong_identity = dataclasses.replace(
            self.identity,
            reasoning_sha256=_digest("other reasoning"),
        )
        with self.assertRaises(ContractError):
            validate_workspace_lease_context(
                parsed,
                identity=wrong_identity,
                profile=self.profile,
                role_policy=self.policies[WorkspaceRole.B1],
            )
        with self.assertRaises(ContractError):
            validate_workspace_lease_context(
                parsed,
                identity=self.identity,
                profile=self.profile,
                role_policy=self.policies[WorkspaceRole.B2],
            )

    def test_write_authorization_rejects_wrong_namespace_and_traversal(self):
        allocation = self._allocate(WorkspaceRole.A)
        project = allocation.paths.project
        allowed = project / "new" / "file.txt"
        self.assertEqual(
            allocation.authorize_write(
                WorkspaceNamespace.A_PROJECT_READ_WRITE,
                allowed,
            ),
            allowed,
        )

        denied = (
            (WorkspaceNamespace.B1_PROJECT_READ_WRITE, allowed),
            (WorkspaceNamespace.FROZEN_INPUTS_READ_ONLY, allowed),
            (WorkspaceNamespace.A_PROJECT_READ_WRITE, project / ".." / "escape"),
            (WorkspaceNamespace.A_PROJECT_READ_WRITE, self.base / "outside.txt"),
        )
        for namespace, path in denied:
            with self.subTest(namespace=namespace.value, path=path):
                with self.assertRaises(WorkspaceError) as caught:
                    allocation.authorize_write(namespace, path)
                self.assertEqual(caught.exception.code, WorkspaceErrorCode.ACCESS_DENIED)

    def test_write_authorization_rejects_symlink_escape(self):
        allocation = self._allocate(WorkspaceRole.B1)
        outside = self.base / "outside"
        outside.mkdir()
        (outside / "sentinel").write_text("keep\n", encoding="utf-8")
        escape = allocation.paths.project / "escape"
        escape.symlink_to(outside, target_is_directory=True)
        with self.assertRaises(WorkspaceError) as caught:
            allocation.authorize_write(
                WorkspaceNamespace.B1_PROJECT_READ_WRITE,
                escape / "new.txt",
            )
        self.assertEqual(caught.exception.code, WorkspaceErrorCode.ACCESS_DENIED)
        self.assertEqual(
            (outside / "sentinel").read_text(encoding="utf-8"),
            "keep\n",
        )

    def test_manager_rejects_snapshot_and_profile_mismatch(self):
        wrong_snapshot_identity = dataclasses.replace(
            self.identity,
            snapshot_sha256=_digest("wrong snapshot"),
        )
        with self.assertRaises(WorkspaceError) as caught:
            self._allocate(WorkspaceRole.B1, identity=wrong_snapshot_identity)
        self.assertEqual(caught.exception.code, WorkspaceErrorCode.SNAPSHOT_MISMATCH)

        other_profile = _profile(self.snapshot.ref.snapshot_sha256, salt="other")
        other_policy = build_role_policy(
            WorkspaceRole.B1,
            other_profile,
            other_profile.environment.resource_policy,
        )
        with self.assertRaises(WorkspaceError) as caught:
            self._allocate(WorkspaceRole.B1, policy=other_policy)
        self.assertEqual(
            caught.exception.code,
            WorkspaceErrorCode.ROLE_POLICY_MISMATCH,
        )

    def test_project_identity_mismatch_is_rejected_at_all_three_boundaries(self):
        wrong_identity = dataclasses.replace(
            self.identity,
            project_id="test.other-project",
        )
        allocation = self._allocate(WorkspaceRole.B1)
        checks = (
            (
                "lease-create",
                ContractError,
                lambda: self._direct_lease(identity=wrong_identity),
            ),
            (
                "lease-context",
                ContractError,
                lambda: validate_workspace_lease_context(
                    allocation.lease,
                    identity=wrong_identity,
                    profile=self.profile,
                    role_policy=self.policies[WorkspaceRole.B1],
                ),
            ),
            (
                "workspace-manager",
                WorkspaceError,
                lambda: self._allocate(
                    WorkspaceRole.B1,
                    identity=wrong_identity,
                ),
            ),
        )
        for boundary, error, check in checks:
            with self.subTest(boundary=boundary):
                with self.assertRaises(error):
                    check()

    def test_unapproved_equivalence_policy_is_rejected_at_all_three_boundaries(self):
        outside = _ref(
            ContractRefKind.EXECUTION_EQUIVALENCE_POLICY,
            "outside-profile",
        )
        allocation = self._allocate(WorkspaceRole.B1)
        parsed_outside = self._coherent_untrusted_lease_with_equivalence(
            allocation.lease,
            outside,
        )
        checks = (
            (
                "lease-create",
                ContractError,
                lambda: self._direct_lease(equivalence_policy=outside),
            ),
            (
                "lease-context",
                ContractError,
                lambda: validate_workspace_lease_context(
                    parsed_outside,
                    identity=self.identity,
                    profile=self.profile,
                    role_policy=self.policies[WorkspaceRole.B1],
                ),
            ),
            (
                "workspace-manager",
                WorkspaceError,
                lambda: self._allocate(
                    WorkspaceRole.B1,
                    equivalence_policy=outside,
                ),
            ),
        )
        for boundary, error, check in checks:
            with self.subTest(boundary=boundary):
                with self.assertRaises(error):
                    check()

    def test_manager_rejects_agent_session_role_forgery(self):
        with self.assertRaises(WorkspaceError) as caught:
            self._allocate(WorkspaceRole.A, session_marker=False)
        self.assertEqual(caught.exception.code, WorkspaceErrorCode.INVALID_REQUEST)

        with self.assertRaises(WorkspaceError) as caught:
            self.manager.materialize(
                snapshot=self.snapshot.ref,
                identity=self.identity,
                profile=self.profile,
                attempt_id="attempt-1",
                role_policy=self.policies[WorkspaceRole.B1],
                workspace_equivalence_policy=self.equivalence_policy,
                agent_session_id="forged-agent-session",
            )
        self.assertEqual(caught.exception.code, WorkspaceErrorCode.INVALID_REQUEST)

    def test_allocation_failure_removes_only_its_owned_lease_root(self):
        sibling = self.manager.leases_root / "user-owned-sibling"
        sibling.mkdir()
        marker = sibling / "marker"
        marker.write_text("keep\n", encoding="utf-8")
        failure = SnapshotStoreError(
            SnapshotErrorCode.MATERIALIZATION_FAILED,
            "injected allocation failure",
        )
        with mock.patch.object(
            self.store,
            "materialize",
            side_effect=failure,
        ):
            with self.assertRaises(WorkspaceError) as caught:
                self._allocate(WorkspaceRole.B1)
        self.assertEqual(caught.exception.code, WorkspaceErrorCode.ALLOCATION_FAILED)
        self.assertEqual(marker.read_text(encoding="utf-8"), "keep\n")
        self.assertEqual(
            [path.name for path in self.manager.leases_root.iterdir()],
            ["user-owned-sibling"],
        )

    def test_release_is_exact_and_rejects_foreign_or_reused_handles(self):
        allocation = self._allocate(WorkspaceRole.B2)
        outside = self.base / "outside"
        outside.mkdir()
        marker = outside / "marker"
        marker.write_text("keep\n", encoding="utf-8")
        # A byte-for-byte equivalent dataclass is still not the exact live
        # broker handle registered by this manager.
        forged = dataclasses.replace(allocation)
        with self.assertRaises(WorkspaceError) as caught:
            self.manager.release(forged)
        self.assertEqual(caught.exception.code, WorkspaceErrorCode.UNKNOWN_LEASE)
        self.assertEqual(marker.read_text(encoding="utf-8"), "keep\n")

        root = allocation.paths.root
        self.manager.release(allocation)
        self.assertFalse(root.exists())
        with self.assertRaises(WorkspaceError) as caught:
            self.manager.release(allocation)
        self.assertEqual(caught.exception.code, WorkspaceErrorCode.UNKNOWN_LEASE)
        self.assertEqual(marker.read_text(encoding="utf-8"), "keep\n")

    def test_release_restores_owned_directory_permissions_without_fd_fanout(self):
        allocation = self._allocate(WorkspaceRole.B2)
        for index in range(400):
            (allocation.paths.scratch / f"wide-{index}").mkdir()
        locked = allocation.paths.scratch / "locked" / "nested"
        locked.mkdir(parents=True)
        (locked / "payload").write_text("remove\n", encoding="utf-8")
        locked.chmod(0)
        locked.parent.chmod(0)
        root = allocation.paths.root
        root.chmod(0)

        self.manager.release(allocation)
        self.assertFalse(root.exists())

    def test_release_refuses_replaced_root_without_touching_target(self):
        allocation = self._allocate(WorkspaceRole.B1)
        original_root = allocation.paths.root
        saved_root = original_root.with_name(f"{original_root.name}.saved")
        original_root.rename(saved_root)
        outside = self.base / "outside"
        outside.mkdir()
        marker = outside / "marker"
        marker.write_text("keep\n", encoding="utf-8")
        original_root.symlink_to(outside, target_is_directory=True)

        with self.assertRaises(WorkspaceError) as caught:
            self.manager.release(allocation)
        self.assertEqual(caught.exception.code, WorkspaceErrorCode.RELEASE_FAILED)
        self.assertEqual(marker.read_text(encoding="utf-8"), "keep\n")
        self.assertTrue(saved_root.is_dir())

    def test_release_refuses_replaced_leases_root_without_touching_workspace(self):
        allocation = self._allocate(WorkspaceRole.B2)
        original = self.manager.leases_root
        saved = self.manager.run_root / "saved-leases-for-release"
        original.rename(saved)
        original.mkdir(mode=0o700)
        try:
            with self.assertRaises(WorkspaceError) as caught:
                self.manager.release(allocation)
            self.assertEqual(caught.exception.code, WorkspaceErrorCode.RELEASE_FAILED)
            self.assertTrue(
                (saved / allocation.lease.lease_id / "project" / "main.txt").is_file()
            )
            self.assertEqual(list(original.iterdir()), [])
        finally:
            original.rmdir()
            saved.rename(original)
        self.manager.release(allocation)


if __name__ == "__main__":
    unittest.main()

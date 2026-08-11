import hashlib
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from dashboard import State
import src.incremental_reasoner as incremental
import src.validation_core as validation_core
import src.verification as verification
from src.file_utils import (
    _get_incomplete_verification_files,
    _terminal_validation_is_valid,
)
from src.validation_core.outcome_loader import (
    inspect_validation_artifact,
    load_current_validation_outcome,
)
from src.validation_core import (
    ArtifactFamily,
    LegacyBindingState,
    LegacyCompletionPolicy,
    LegacyPromptCompletion,
    LegacyPromptTerminal,
    OutcomeLoadError,
    OutcomeLoadErrorCode,
    TrustClass,
    load_archived_legacy_certificate,
    load_legacy_compatibility_outcome,
)


def _write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2), encoding="utf-8")


def _reference_canonical_sha256(value: object) -> str:
    raw = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def _reference_directory_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    for child in sorted(path.rglob("*")):
        if not child.is_file():
            continue
        relative = child.relative_to(path).as_posix().encode("utf-8")
        mode = child.stat().st_mode & 0o7777
        data = child.read_bytes()
        digest.update(len(relative).to_bytes(8, "big"))
        digest.update(relative)
        digest.update(mode.to_bytes(4, "big"))
        digest.update(len(data).to_bytes(8, "big"))
        digest.update(data)
    return digest.hexdigest()


def _terminal_record(bug_id: str, status: str = "confirmed") -> dict:
    return {
        "id": bug_id,
        "source_file": "src/x.rs",
        "function_name": "x",
        "confirmation_status": status,
        "attempts": 1,
        "probe_script": "probe.c",
        "detail_file": "detail.md",
        "probe_stdout": "observed",
        "trigger_summary": "supported input",
    }


def _archived_l0_result(bug_id: str, function_id: str) -> dict:
    return {
        "schema_version": 3,
        "id": bug_id,
        "function_id": function_id,
        "confirmation_status": "confirmed",
        "grade": "L0",
        "witness": {
            "probe": f"fm_agent/bug_validation/_probe_{bug_id}.c",
            "call_index": 0,
            "captured_input": {},
            "actual_output": "bad",
            "spec_violation_claim": "archived observation",
        },
        "phenomenon": {
            "mode": "run",
            "standard": "c11",
            "extra_args": [],
            "expected_kind": "run_exit_differs",
        },
        "l1_patch": None,
        "attempts": 1,
        "notes": "archived only",
    }


class LegacyPromptOutcomeLoaderTests(unittest.TestCase):
    def test_package_root_exports_only_stable_typed_loaders(self):
        self.assertFalse(hasattr(validation_core, "inspect_legacy_prompt_result"))
        self.assertFalse(hasattr(validation_core, "inspect_validation_artifact"))
        self.assertFalse(hasattr(validation_core, "load_current_validation_outcome"))
        self.assertTrue(
            callable(validation_core.load_legacy_compatibility_outcome)
        )
        self.assertTrue(callable(validation_core.load_archived_legacy_certificate))

    def test_file_utils_still_loads_as_a_standalone_copied_module(self):
        file_utils_path = Path(__file__).parents[1] / "src" / "file_utils.py"
        spec = importlib.util.spec_from_file_location(
            "standalone_file_utils_for_validation_test",
            file_utils_path,
        )
        self.assertIsNotNone(spec)
        self.assertIsNotNone(spec.loader)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        self.assertTrue(callable(module._get_phase_files))

    def test_completion_policies_preserve_the_three_private_main_rules(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "bug.result.json"

            for policy in (
                LegacyCompletionPolicy.DEFAULT_POST_AGENT,
                LegacyCompletionPolicy.DEFAULT_RESUME,
            ):
                with self.subTest(policy=policy):
                    with self.assertRaises(OutcomeLoadError) as raised:
                        load_legacy_compatibility_outcome(path, policy=policy)
                    self.assertEqual(
                        raised.exception.code,
                        OutcomeLoadErrorCode.MISSING,
                    )

            path.write_text("{broken", encoding="utf-8")
            malformed = load_legacy_compatibility_outcome(
                path,
                policy=LegacyCompletionPolicy.DEFAULT_POST_AGENT,
            )
            self.assertEqual(malformed.trust_class, TrustClass.EXISTS_ONLY)
            self.assertEqual(
                malformed.artifact_family,
                ArtifactFamily.UNCLASSIFIED_MATERIALIZATION,
            )
            with self.assertRaises(OutcomeLoadError):
                load_legacy_compatibility_outcome(
                    path,
                    policy=LegacyCompletionPolicy.DEFAULT_RESUME,
                )

            _write_json(path, ["any", "parseable", "json"])
            opaque = load_legacy_compatibility_outcome(
                path,
                policy=LegacyCompletionPolicy.DEFAULT_RESUME,
            )
            self.assertEqual(opaque.value, ("any", "parseable", "json"))
            with self.assertRaises(OutcomeLoadError):
                load_legacy_compatibility_outcome(
                    path,
                    policy=LegacyCompletionPolicy.ALL_BUGS_TERMINAL,
                    expected_bug_id="bug",
                )

            _write_json(path, _terminal_record("bug", "error"))
            terminal = load_legacy_compatibility_outcome(
                path,
                policy=LegacyCompletionPolicy.ALL_BUGS_TERMINAL,
                expected_bug_id="bug",
            )
            self.assertEqual(terminal.reported_status, "error")

    def test_typed_legacy_results_do_not_gain_current_trust(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "bug.result.json"
            _write_json(path, {"opaque": True})
            completion = load_legacy_compatibility_outcome(
                path,
                policy=LegacyCompletionPolicy.DEFAULT_RESUME,
            )
            self.assertIsInstance(completion, LegacyPromptCompletion)
            self.assertEqual(completion.trust_class, TrustClass.PARSED_ONLY)

            _write_json(path, _terminal_record("bug", "not_confirmed"))
            terminal = load_legacy_compatibility_outcome(
                path,
                policy=LegacyCompletionPolicy.ALL_BUGS_TERMINAL,
                expected_bug_id="bug",
            )
            self.assertIsInstance(terminal, LegacyPromptTerminal)
            self.assertEqual(
                terminal.trust_class,
                TrustClass.LEGACY_CONTRACT_VALIDATED,
            )

    def test_explicit_version_never_falls_back_to_prompt_legacy(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "bug.result.json"
            _write_json(
                path,
                {
                    "schema_version": 3,
                    "id": "bug",
                    "function_id": "bug",
                    "confirmation_status": "not_confirmed",
                    "attempts": 1,
                    "notes": "",
                },
            )
            with self.assertRaises(OutcomeLoadError) as raised:
                load_legacy_compatibility_outcome(
                    path,
                    policy=LegacyCompletionPolicy.DEFAULT_RESUME,
                )
            self.assertEqual(
                raised.exception.code,
                OutcomeLoadErrorCode.WRONG_ARTIFACT_FAMILY,
            )
            materialized = load_legacy_compatibility_outcome(
                path,
                policy=LegacyCompletionPolicy.DEFAULT_POST_AGENT,
            )
            self.assertEqual(
                materialized.artifact_family,
                ArtifactFamily.UNCLASSIFIED_MATERIALIZATION,
            )

    def test_unknown_or_conflicting_discriminator_never_downgrades(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "bug.result.json"
            cases = (
                (
                    {"schema_id": "validation-outcome/v2"},
                    OutcomeLoadErrorCode.UNSUPPORTED_VERSION,
                ),
                (
                    {
                        "schema_id": "validation-outcome/v1",
                        "artifact_type": "other/v1",
                    },
                    OutcomeLoadErrorCode.AMBIGUOUS_FORMAT,
                ),
                (
                    {
                        "schema_id": "validation-outcome/v1",
                        "schema_version": True,
                    },
                    OutcomeLoadErrorCode.SCHEMA_INVALID,
                ),
            )
            for document, expected_code in cases:
                with self.subTest(document=document):
                    _write_json(path, document)
                    with self.assertRaises(OutcomeLoadError) as raised:
                        load_legacy_compatibility_outcome(
                            path,
                            policy=LegacyCompletionPolicy.DEFAULT_RESUME,
                        )
                    self.assertEqual(raised.exception.code, expected_code)

    def test_versioned_archive_does_not_complete_private_main_resume(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            work = root / "fm_agent"
            results = work / "logic_verification_results"
            result_path = results / "pkg" / "target.json"
            _write_json(result_path, {"verdict": "MISMATCH"})
            validation = work / "bug_validation" / "pkg--target.result.json"
            _write_json(
                validation,
                {
                    "schema_version": 3,
                    "id": "pkg--target",
                    "function_id": "pkg::target",
                    "confirmation_status": "not_confirmed",
                    "attempts": 1,
                    "notes": "archived only",
                },
            )
            incomplete = _get_incomplete_verification_files(
                ["pkg/target.py"],
                str(work / "extracted_functions"),
                str(results),
                str(work),
            )
            self.assertEqual(incomplete, ["pkg/target.py"])

            hybrid = _terminal_record("pkg--target")
            hybrid["schema_version"] = 3
            _write_json(validation, hybrid)
            self.assertFalse(
                _terminal_validation_is_valid(validation, "pkg--target")
            )

    def test_versioned_archive_is_not_counted_by_summary_or_dashboard(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            work = root / "fm_agent"
            validation = work / "bug_validation" / "bug.result.json"
            _write_json(
                validation,
                _archived_l0_result("bug", "pkg::target"),
            )

            verification._generate_validation_summary(str(work))
            summary = json.loads(
                (work / "bug_validation" / "summary.json").read_text(
                    encoding="utf-8"
                )
            )
            self.assertEqual(summary["total_reported"], 0)

            state = State(root)
            state.scan_bugs()
            self.assertEqual(state.bugs_confirmed, 0)
            self.assertEqual(state.bugs_not_confirmed, 0)

    def test_versioned_archive_does_not_confirm_incremental_result(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            project = Path(temp_dir)
            work = project / "fm_agent"
            extracted = work / "extracted_functions" / "module" / "func.py"
            extracted.parent.mkdir(parents=True)
            extracted.write_text("def func():\n    return 1\n", encoding="utf-8")
            _write_json(
                work / "bug_validation" / "module--func.result.json",
                _archived_l0_result("module--func", "module::func"),
            )

            with (
                patch.object(
                    incremental,
                    "_verify_single_file",
                    return_value=(str(extracted), "MISMATCH"),
                ),
                patch.object(incremental, "_validate_single_bug"),
                patch.object(incremental, "MAX_WORKERS", 1),
            ):
                confirmed = incremental._verify_incremental_functions(
                    str(project),
                    str(work),
                    {},
                    ["module/func.py"],
                )
            self.assertEqual(confirmed, [])

    def test_versioned_archive_does_not_skip_single_bug_resume(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            project = Path(temp_dir)
            work = project / "fm_agent"
            custom = project / "validator.md"
            custom.write_text("CUSTOM VALIDATOR", encoding="utf-8")
            result_path = work / "bug_validation" / "pkg--target.result.json"
            _write_json(
                result_path,
                {
                    "schema_version": 3,
                    "id": "pkg--target",
                    "function_id": "pkg::target",
                    "confirmation_status": "not_confirmed",
                    "attempts": 1,
                    "notes": "archived only",
                },
            )
            calls = []

            def run_validation(**_kwargs):
                calls.append("run")
                _write_json(
                    result_path,
                    {"confirmation_status": "not_confirmed"},
                )

            with (
                patch.object(
                    verification,
                    "build_llm_cli_command",
                    return_value=["opencode"],
                ),
                patch.object(
                    verification,
                    "run_opencode_traced",
                    side_effect=run_validation,
                ),
                patch.object(
                    verification.config,
                    "BUG_VALIDATION_MAX_RETRIES",
                    1,
                ),
            ):
                verification._validate_single_bug(
                    "fm_agent/logic_verification_results/pkg/target.json",
                    str(project),
                    str(work),
                    resume=True,
                    bug_validator_path=str(custom),
                )
            self.assertEqual(calls, ["run"])

    def test_deep_or_malformed_json_still_satisfies_exists_only_policy(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "bug.result.json"
            path.write_text("[" * 2000 + "0" + "]" * 2000, encoding="utf-8")
            with patch.object(
                Path,
                "read_bytes",
                side_effect=AssertionError("exists-only policy read the file"),
            ):
                loaded = load_legacy_compatibility_outcome(
                    path,
                    policy=LegacyCompletionPolicy.DEFAULT_POST_AGENT,
                )
            self.assertEqual(loaded.trust_class, TrustClass.EXISTS_ONLY)
            self.assertIsNone(loaded.raw_sha256)

    def test_strict_inspection_rejects_duplicate_keys_and_ambiguous_formats(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            duplicate = root / "duplicate.json"
            duplicate.write_text('{"value":1,"value":2}', encoding="utf-8")
            with self.assertRaises(OutcomeLoadError) as raised:
                inspect_validation_artifact(duplicate)
            self.assertEqual(
                raised.exception.code,
                OutcomeLoadErrorCode.DUPLICATE_JSON_KEY,
            )

            ambiguous = root / "ambiguous.json"
            _write_json(
                ambiguous,
                {
                    "schema_id": "validation-outcome/v1",
                    "schema_version": 3,
                },
            )
            with self.assertRaises(OutcomeLoadError) as raised:
                inspect_validation_artifact(ambiguous)
            self.assertEqual(
                raised.exception.code,
                OutcomeLoadErrorCode.AMBIGUOUS_FORMAT,
            )

    def test_current_outcome_handler_is_unavailable_in_stage_two(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "bug.outcome.json"
            _write_json(
                path,
                {
                    "schema_id": "validation-outcome/v1",
                    "schema_version": 1,
                },
            )
            inspection = inspect_validation_artifact(path)
            self.assertEqual(
                inspection.artifact_family,
                ArtifactFamily.CURRENT_OUTCOME_V1,
            )
            with self.assertRaises(OutcomeLoadError) as raised:
                load_current_validation_outcome(path)
            self.assertEqual(
                raised.exception.code,
                OutcomeLoadErrorCode.HANDLER_NOT_AVAILABLE,
            )


class ArchivedLegacyCCCCertificateTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.project = Path(self.temp.name).resolve() / "project"
        self.validation = self.project / "fm_agent" / "bug_validation"
        self.validation.mkdir(parents=True)
        self.result_path = self.validation / "bug1.result.json"
        self.files = {
            "logic_result": self.project
            / "fm_agent"
            / "logic_verification_results"
            / "bug1.json",
            "manifest": self.project / "tools" / "audit_manifest.json",
            "source": self.project / "src" / "x.rs",
            "release_binary": self.project / "target" / "release" / "ccc",
            "reference_binary": self.project / "toolchain" / "gcc",
            "audit_binary": self.project / "audit" / "ccc",
            "coverage_binary": self.project / "coverage" / "ccc",
        }
        for label, path in self.files.items():
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(f"{label}-bytes".encode("utf-8"))
        self.sanity = self.project / "seed_corpus"
        self.sanity.mkdir()
        (self.sanity / "one.c").write_text(
            "int main(void){return 0;}\n",
            encoding="utf-8",
        )

    def _file_record(self, path: Path) -> dict:
        return {
            "path": path.relative_to(self.project).as_posix(),
            "scope": "project",
            "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        }

    def _publish(self, grade: str | None = None) -> tuple[dict, dict]:
        if grade is None:
            result = {
                "schema_version": 3,
                "id": "bug1",
                "function_id": "src::x",
                "confirmation_status": "not_confirmed",
                "attempts": 2,
                "notes": "no witness",
            }
            probe_record = None
            patch_record = None
        else:
            probe = self.validation / "_probe_bug1.c"
            probe.write_text("int main(void){return 0;}\n", encoding="utf-8")
            patch_path = None
            if grade == "L1":
                patch_path = self.validation / "bug1.l1.patch"
                patch_path.write_text("diff --git a/x b/x\n", encoding="utf-8")
            result = {
                "schema_version": 3,
                "id": "bug1",
                "function_id": "src::x",
                "confirmation_status": "confirmed",
                "grade": grade,
                "witness": {
                    "probe": "fm_agent/bug_validation/_probe_bug1.c",
                    "call_index": 0,
                    "captured_input": {"flags": 0},
                    "actual_output": "false",
                    "spec_violation_claim": "observed boundary differs",
                },
                "phenomenon": {
                    "mode": "run",
                    "standard": "c11",
                    "extra_args": [],
                    "expected_kind": "run_exit_differs",
                },
                "l1_patch": (
                    "fm_agent/bug_validation/bug1.l1.patch"
                    if patch_path is not None
                    else None
                ),
                "attempts": 2,
                "notes": "",
            }
            probe_record = self._file_record(probe)
            patch_record = (
                self._file_record(patch_path) if patch_path is not None else None
            )

        result_raw = json.dumps(result, sort_keys=True).encode("utf-8")
        self.result_path.write_bytes(result_raw)
        payload = {
            "schema_version": 5,
            "gate_version": "boundary-witness-v6",
            "state": "accepted",
            "bug_id": "bug1",
            "function_id": "src::x",
            "confirmation_status": result["confirmation_status"],
            **{
                label: self._file_record(path)
                for label, path in self.files.items()
            },
            "sanity_corpus": {
                "path": self.sanity.relative_to(self.project).as_posix(),
                "scope": "project",
                "sha256": _reference_directory_sha256(self.sanity),
            },
            "probe": probe_record,
            "l1_patch": patch_record,
            "result_sha256": hashlib.sha256(result_raw).hexdigest(),
            "attempt": 7,
            "grade": grade,
        }
        sidecar = {
            **payload,
            "integrity_sha256": _reference_canonical_sha256(payload),
        }
        _write_json(self.validation / "bug1.gate.json", sidecar)
        return result, sidecar

    def _rewrite_pair(self, result: dict, sidecar: dict) -> None:
        result_raw = json.dumps(result, sort_keys=True).encode("utf-8")
        self.result_path.write_bytes(result_raw)
        sidecar["result_sha256"] = hashlib.sha256(result_raw).hexdigest()
        payload = {
            key: value
            for key, value in sidecar.items()
            if key != "integrity_sha256"
        }
        sidecar["integrity_sha256"] = _reference_canonical_sha256(payload)
        _write_json(self.validation / "bug1.gate.json", sidecar)

    def test_not_confirmed_l0_and_l1_are_archival_only(self):
        for grade in (None, "L0", "L1"):
            with self.subTest(grade=grade):
                self._publish(grade)
                archived = load_archived_legacy_certificate(
                    self.result_path,
                    project_dir=self.project,
                    expected_bug_id="bug1",
                    expected_function_id="src::x",
                )
                self.assertTrue(archived.archival_only)
                self.assertEqual(
                    archived.trust_class,
                    TrustClass.LEGACY_PAIR_INTEGRITY_VERIFIED,
                )
                self.assertEqual(archived.result.get("grade"), grade)
                self.assertEqual(archived.result["attempts"], 2)
                self.assertEqual(archived.sidecar["attempt"], 7)
                self.assertTrue(archived.all_bindings_current)
                with self.assertRaises(OutcomeLoadError) as raised:
                    load_current_validation_outcome(self.result_path)
                self.assertEqual(
                    raised.exception.code,
                    OutcomeLoadErrorCode.WRONG_ARTIFACT_FAMILY,
                )

    def test_pair_integrity_tampering_fails_closed(self):
        self._publish()
        self.result_path.write_bytes(self.result_path.read_bytes() + b" ")
        with self.assertRaises(OutcomeLoadError) as raised:
            load_archived_legacy_certificate(
                self.result_path,
                project_dir=self.project,
            )
        self.assertEqual(
            raised.exception.code,
            OutcomeLoadErrorCode.INTEGRITY_MISMATCH,
        )

        _result, sidecar = self._publish()
        sidecar["attempt"] = 8
        _write_json(self.validation / "bug1.gate.json", sidecar)
        with self.assertRaises(OutcomeLoadError) as raised:
            load_archived_legacy_certificate(
                self.result_path,
                project_dir=self.project,
            )
        self.assertEqual(
            raised.exception.code,
            OutcomeLoadErrorCode.INTEGRITY_MISMATCH,
        )

    def test_probe_and_patch_must_use_canonical_paths(self):
        unrelated_probe = self.validation / "unrelated.c"
        unrelated_probe.write_text("int x;\n", encoding="utf-8")
        unrelated_patch = self.validation / "unrelated.patch"
        unrelated_patch.write_text("diff --git a/y b/y\n", encoding="utf-8")
        for name in (
            "sidecar_probe",
            "result_probe",
            "sidecar_patch",
            "result_patch",
        ):
            with self.subTest(name=name):
                result, sidecar = self._publish("L1")
                if name == "sidecar_probe":
                    sidecar["probe"] = self._file_record(unrelated_probe)
                elif name == "result_probe":
                    result["witness"]["probe"] = unrelated_probe.relative_to(
                        self.project
                    ).as_posix()
                elif name == "sidecar_patch":
                    sidecar["l1_patch"] = self._file_record(unrelated_patch)
                else:
                    result["l1_patch"] = unrelated_patch.relative_to(
                        self.project
                    ).as_posix()
                self._rewrite_pair(result, sidecar)
                with self.assertRaises(OutcomeLoadError) as raised:
                    load_archived_legacy_certificate(
                        self.result_path,
                        project_dir=self.project,
                    )
                self.assertEqual(
                    raised.exception.code,
                    OutcomeLoadErrorCode.ARTIFACT_MISMATCH,
                )

    def test_malformed_v3_enum_types_fail_with_structured_error(self):
        for name in ("status", "grade", "mode", "standard", "expected_kind"):
            with self.subTest(name=name):
                result, sidecar = self._publish("L1")
                if name == "status":
                    result["confirmation_status"] = []
                elif name == "grade":
                    result["grade"] = []
                elif name == "mode":
                    result["phenomenon"]["mode"] = []
                elif name == "standard":
                    result["phenomenon"]["standard"] = {}
                else:
                    result["phenomenon"]["expected_kind"] = []
                self._rewrite_pair(result, sidecar)
                with self.assertRaises(OutcomeLoadError) as raised:
                    load_archived_legacy_certificate(
                        self.result_path,
                        project_dir=self.project,
                    )
                self.assertEqual(
                    raised.exception.code,
                    OutcomeLoadErrorCode.SCHEMA_INVALID,
                )

    def test_nested_sidecar_schema_error_stays_in_sidecar_error_domain(self):
        result, sidecar = self._publish("L0")
        del sidecar["source"]["sha256"]
        self._rewrite_pair(result, sidecar)
        with self.assertRaises(OutcomeLoadError) as raised:
            load_archived_legacy_certificate(
                self.result_path,
                project_dir=self.project,
            )
        self.assertEqual(
            raised.exception.code,
            OutcomeLoadErrorCode.SIDECAR_INVALID,
        )

    def test_missing_historical_binding_is_reported_without_semantic_upgrade(self):
        self._publish("L1")
        self.files["source"].unlink()
        archived = load_archived_legacy_certificate(
            self.result_path,
            project_dir=self.project,
        )
        states = {check.label: check.state for check in archived.binding_report}
        self.assertEqual(states["source"], LegacyBindingState.MISSING)
        self.assertTrue(archived.archival_only)
        self.assertFalse(archived.all_bindings_current)
        self.assertEqual(
            archived.trust_class,
            TrustClass.LEGACY_PAIR_INTEGRITY_VERIFIED,
        )

    def test_project_path_traversal_is_reported_unsafe_without_fallback(self):
        _result, sidecar = self._publish()
        sidecar["source"]["path"] = "../outside"
        payload = {
            key: value for key, value in sidecar.items() if key != "integrity_sha256"
        }
        sidecar["integrity_sha256"] = _reference_canonical_sha256(payload)
        _write_json(self.validation / "bug1.gate.json", sidecar)

        archived = load_archived_legacy_certificate(
            self.result_path,
            project_dir=self.project,
        )
        states = {check.label: check.state for check in archived.binding_report}
        self.assertEqual(states["source"], LegacyBindingState.UNSAFE)

    def test_rejection_diagnostic_shape_is_not_a_certificate(self):
        result, _sidecar = self._publish()
        _write_json(
            self.validation / "bug1.gate.json",
            {
                "schema_version": 5,
                "gate_version": "boundary-witness-v6",
                "state": "rejected",
                "bug_id": result["id"],
                "function_id": result["function_id"],
                "attempt": 1,
                "check": "schema",
                "reason": "malformed candidate",
            },
        )
        with self.assertRaises(OutcomeLoadError) as raised:
            load_archived_legacy_certificate(
                self.result_path,
                project_dir=self.project,
            )
        self.assertEqual(
            raised.exception.code,
            OutcomeLoadErrorCode.SIDECAR_INVALID,
        )


if __name__ == "__main__":
    unittest.main()

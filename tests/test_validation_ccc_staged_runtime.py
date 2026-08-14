import ast
import hashlib
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import src.l1_verifier as l1_verifier_module
import src.validation_core.presets.ccc.staged_executor as staged_executor_module
from src.check_submission import Rejection
from src.phenomenon_runner import PhenomenonObservation
from src.validation_core.presets.ccc.staged_executor import (
    StagedCCCContext,
    StagedCCCExecutor,
    StagedCCCL1Context,
    StagedCCCL1Providers,
    StagedCCCProviders,
)


_ROOT = Path(__file__).resolve().parents[1]
_LEGACY_SOURCES = {
    "src/compiler_recipe.py": (
        2693,
        "4804f99707f160ad908ea367c54049d98ef89288a379aa4ad9ba6f80155f0c96",
        "cd68b941d9a8686199c9e25c7daaa2f21c0a594b",
    ),
    "src/submission_schema.py": (
        7593,
        "0ad8e93d4efe5d566d0818f9e0c88fe0c9c57945ca02dddd740b4a6e547490d5",
        "695277beb39e61a0184bc4d1c5d98dc50ef735f2",
    ),
    "src/phenomenon_runner.py": (
        5464,
        "ba2c6cf674b3087e0c3b00155b300a37d152dbf93d90bbec2c3474a4cd02732d",
        "065ee77d05a166b57e59158b326e977d5d714bfc",
    ),
    "src/coverage_witness.py": (
        7651,
        "92384721600cfbb7505102dc57f70360e27471d0ed48fe78df1e2fff6c129342",
        "aa736d1587f2fcf1d9a1b426985dfa60e77580cc",
    ),
    "src/check_submission.py": (
        15023,
        "9412aa276c478a51f717f83992cae60d18ad3710dcd48e237fce2febea7dca7b",
        "1fdbf4332cd22f66f16a77432e66e8f2e8f13af7",
    ),
    "src/l1_verifier.py": (
        11916,
        "a25f872aa9d37b01eaa32ac56040fa9916da6a497e56c12ab3ab0b824d6ac192",
        "df2beb3a3bc41285931b5757e88d791f2d3420fa",
    ),
    "src/validation_context.py": (
        18780,
        "3ae8fad704b90fc066670105d23b0ad21394ec85e3aece5ddaf865e2f9863f37",
        "28689452bbcd8dee410d2d8088685c24839696dc",
    ),
    "src/validation_workspace.py": (
        8096,
        "3d6eaa395c553337908a7a44d96f7aa90cdcb6ae669ec875fe307fa5144614ad",
        "a07c25b2d946fb7928aa0ce9b714fc9cf0c5b108",
    ),
}
_L1_SUPPORT_SOURCES = {
    "tools/l1_scope/Cargo.toml": (
        277,
        "26ccae4d4ae7d9c0a705cd316fa1c18a5d14de1bd8e588fc6784fa24556a5c83",
        "b994058b2174c9ee9e08a6801c903f25b7e9d3da",
    ),
    "tools/l1_scope/Cargo.lock": (
        1114,
        "59b15405118d93cece4bc739bd380233a23f357e58ec95f845bde6e7cbf7c51e",
        "2d736e8bf75424b14a9b33a13cc2140b46a1ea28",
    ),
    "tools/l1_scope/src/main.rs": (
        6305,
        "1387da923013e1374149efd23613c5384492d9b7190dca4f8a1ae0913f8a5a19",
        "4e90a88323b72e793a30a577c8473467fc535bc8",
    ),
    "tools/validation_sanity_corpus/basic.c": (
        120,
        "8ad2fe20c851f7cb69e57baa235d85f1ffb3a46c3bfa2b72424f8ab656955191",
        "86c204a237b65945209e575048a8950fea038157",
    ),
    "tools/validation_sanity_corpus/control_flow.c": (
        223,
        "3da5ca8d66011d1ae5a4c960985ab612208c5c18b227fb79632572232012a8e1",
        "fa82014da973023f1809a910d0edb045e5a33f9a",
    ),
    "tools/validation_sanity_corpus/declarations.c": (
        189,
        "46b5d0ef5aa775e45d39bcb3dd7255532f8a957660bf88ddd19088743b5cad20",
        "4e76fb0caf6bac3b0d89c0216f261769497dcfb6",
    ),
    "tools/validation_sanity_corpus/function_pointer.c": (
        253,
        "237369fcf883154351396b11c6f4b019e96571a5c99bf692c50bad5b5609319f",
        "6efb9bd8fd812b0a57e21f47f2477b3792510af2",
    ),
}
_LEGACY_FLAT_MODULES = frozenset(
    Path(relative_path).stem for relative_path in _LEGACY_SOURCES
)


def _git_blob_sha1(data: bytes) -> str:
    header = f"blob {len(data)}\0".encode("ascii")
    return hashlib.sha1(header + data).hexdigest()


def _import_targets(source: str, relative_path: str) -> set[str]:
    """Resolve absolute and package-relative static import targets."""
    tree = ast.parse(source, filename=relative_path)
    package_parts = list(Path(relative_path).with_suffix("").parts[:-1])
    targets: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            targets.update(alias.name for alias in node.names)
            continue
        if isinstance(node, ast.Call):
            function_name = None
            if isinstance(node.func, ast.Name):
                function_name = node.func.id
            elif isinstance(node.func, ast.Attribute):
                function_name = node.func.attr
            if (
                function_name in {"__import__", "import_module"}
                and node.args
                and isinstance(node.args[0], ast.Constant)
                and type(node.args[0].value) is str
            ):
                dynamic_name = node.args[0].value
                level = len(dynamic_name) - len(dynamic_name.lstrip("."))
                if level:
                    parents = level - 1
                    base = package_parts[:len(package_parts) - parents]
                    suffix = dynamic_name[level:].split(".")
                    targets.add(".".join([*base, *suffix]))
                else:
                    targets.add(dynamic_name)
            continue
        if not isinstance(node, ast.ImportFrom):
            continue
        if node.level:
            parents = node.level - 1
            base = package_parts[:len(package_parts) - parents]
            module_parts = node.module.split(".") if node.module else []
            prefix = ".".join([*base, *module_parts])
        else:
            prefix = node.module or ""
        if prefix:
            targets.add(prefix)
        for alias in node.names:
            if alias.name == "*":
                continue
            targets.add(f"{prefix}.{alias.name}" if prefix else alias.name)
    return targets


def _touches_forbidden_import(targets: set[str], forbidden: set[str]) -> bool:
    def canonical_identity(module_name: str) -> str:
        root_name = module_name.partition(".")[0]
        if root_name in _LEGACY_FLAT_MODULES:
            return f"src.{module_name}"
        return module_name

    canonical_targets = {canonical_identity(target) for target in targets}
    canonical_forbidden = {canonical_identity(blocked) for blocked in forbidden}
    return any(
        target == blocked or target.startswith(f"{blocked}.")
        for target in canonical_targets
        for blocked in canonical_forbidden
    )


def _submission() -> dict:
    return {
        "schema_version": 3,
        "id": "bug1",
        "function_id": "bug1",
        "confirmation_status": "confirmed",
        "grade": "L1",
        "witness": {
            "probe": "fm_agent/bug_validation/_probe_bug1.c",
            "call_index": 0,
            "captured_input": {"self_flags": 0},
            "actual_output": "false",
            "spec_violation_claim": "candidate claim",
        },
        "phenomenon": {
            "mode": "run",
            "standard": "c11",
            "extra_args": [],
            "expected_kind": "run_exit_differs",
        },
        "l1_patch": "fm_agent/bug_validation/bug1.l1.patch",
        "attempts": 1,
        "notes": "",
    }


class StagedCCCRuntimeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        project = Path(self.temp.name).resolve()
        self.project = project
        probe = project / "fm_agent" / "bug_validation" / "_probe_bug1.c"
        probe.parent.mkdir(parents=True)
        probe.write_text("int main(void) { return 0; }\n", encoding="utf-8")
        scratch = project / "scratch"
        scratch.mkdir()
        self.context = StagedCCCContext(
            bug_id="bug1",
            function_id="bug1",
            project_dir=project,
            probe_path=probe,
            scratch_dir=scratch,
            manifest_id="bug1",
            release_ccc=Path("/trusted/ccc"),
            reference_cc=Path("/trusted/gcc"),
        )

    def tearDown(self):
        self.temp.cleanup()

    def _make_l1_context(
        self,
        name: str,
        *,
        scratch_below_baseline: bool = False,
    ) -> StagedCCCL1Context:
        shadow_root = self.project / name
        baseline = shadow_root / "baseline"
        project = shadow_root / "project"
        source_text = "fn target() {}\n"
        for role in (baseline, project):
            source = role / "src" / "lib.rs"
            source.parent.mkdir(parents=True)
            source.write_text(source_text, encoding="utf-8")
        validation = project / "fm_agent" / "bug_validation"
        validation.mkdir(parents=True)
        (validation / "bug1.l1.patch").write_text("patch\n", encoding="utf-8")
        scratch = (
            baseline / "scratch"
            if scratch_below_baseline
            else shadow_root / "scratch"
        )
        scratch.mkdir()
        release = project / "target" / "release" / "ccc"
        release.parent.mkdir(parents=True)
        release.write_bytes(b"release")
        reference = shadow_root / "reference-cc"
        reference.write_bytes(b"reference")
        corpus = project / "sanity"
        corpus.mkdir()
        (corpus / "one.c").write_text("int x;\n", encoding="utf-8")
        return StagedCCCL1Context(
            bug_id="bug1",
            function_id="bug1",
            shadow_root=shadow_root,
            project_dir=project,
            baseline_project_dir=baseline,
            validation_dir=validation,
            scratch_dir=scratch,
            release_ccc=release,
            reference_cc=reference,
            sanity_corpus_dir=corpus,
            manifest_id="bug1",
            manifest_file="src/lib.rs",
            manifest_fn_name="target",
            manifest_occurrence=0,
            source_sha256=hashlib.sha256(source_text.encode("utf-8")).hexdigest(),
            sanity_corpus_sha256="1" * 64,
        )

    def test_legacy_source_identity_matches_pinned_multirun_blobs(self):
        self.assertEqual(set(_LEGACY_SOURCES), {
            "src/compiler_recipe.py",
            "src/submission_schema.py",
            "src/phenomenon_runner.py",
            "src/coverage_witness.py",
            "src/check_submission.py",
            "src/l1_verifier.py",
            "src/validation_context.py",
            "src/validation_workspace.py",
        })
        self.assertEqual(set(_L1_SUPPORT_SOURCES), {
            "tools/l1_scope/Cargo.toml",
            "tools/l1_scope/Cargo.lock",
            "tools/l1_scope/src/main.rs",
            "tools/validation_sanity_corpus/basic.c",
            "tools/validation_sanity_corpus/control_flow.c",
            "tools/validation_sanity_corpus/declarations.c",
            "tools/validation_sanity_corpus/function_pointer.c",
        })
        pinned = {**_LEGACY_SOURCES, **_L1_SUPPORT_SOURCES}
        for relative_path, (size, sha256, blob_sha1) in pinned.items():
            with self.subTest(path=relative_path):
                data = (_ROOT / relative_path).read_bytes()
                self.assertEqual(len(data), size)
                self.assertEqual(hashlib.sha256(data).hexdigest(), sha256)
                self.assertEqual(_git_blob_sha1(data), blob_sha1)

    def test_all_staged_providers_are_mandatory(self):
        valid = lambda *_args, **_kwargs: None
        for field in (
            "replay_capture",
            "coverage_runner",
            "phenomenon_runner",
            "l1_verifier",
        ):
            values = {
                "replay_capture": valid,
                "coverage_runner": valid,
                "phenomenon_runner": valid,
                "l1_verifier": valid,
            }
            values[field] = None
            with self.subTest(field=field), self.assertRaises(TypeError):
                StagedCCCProviders(**values)

        for field in (
            "source_copier",
            "command_runner",
            "phenomenon_runner",
            "sanity_runner",
        ):
            values = {
                "source_copier": valid,
                "command_runner": valid,
                "phenomenon_runner": valid,
                "sanity_runner": valid,
            }
            values[field] = None
            with self.subTest(field=field), self.assertRaises(TypeError):
                StagedCCCL1Providers(**values)

    def test_l1_copier_binding_is_call_local_and_fail_closed(self):
        original = l1_verifier_module.copy_validation_source
        sentinel = lambda *_args: None

        bound = staged_executor_module._bind_l1_source_copier(sentinel)

        self.assertIs(bound.__code__, l1_verifier_module.verify_l1.__code__)
        self.assertIsNot(bound.__globals__, l1_verifier_module.verify_l1.__globals__)
        self.assertIs(bound.__globals__["copy_validation_source"], sentinel)
        self.assertIs(l1_verifier_module.copy_validation_source, original)
        self.assertIsNone(bound.__kwdefaults__)

    def test_l1_context_rejects_paths_outside_shadow_root(self):
        project = self.project / "l1-project"
        values = {
            "bug_id": "bug1",
            "function_id": "bug1",
            "shadow_root": self.project,
            "project_dir": project,
            "baseline_project_dir": self.project / "baseline",
            "validation_dir": project / "fm_agent" / "bug_validation",
            "scratch_dir": self.project / "scratch",
            "release_ccc": project / "target" / "release" / "ccc",
            "reference_cc": self.project / "trusted-gcc",
            "sanity_corpus_dir": project / "sanity",
            "manifest_id": "bug1",
            "manifest_file": "src/lib.rs",
            "manifest_fn_name": "target",
            "manifest_occurrence": 0,
            "source_sha256": "0" * 64,
            "sanity_corpus_sha256": "1" * 64,
        }
        StagedCCCL1Context(**values)
        values["scratch_dir"] = Path("/outside-shadow-root")
        with self.assertRaisesRegex(ValueError, "below shadow_root"):
            StagedCCCL1Context(**values)
        values["scratch_dir"] = self.project / "scratch"
        values["manifest_file"] = "../outside.rs"
        with self.assertRaisesRegex(ValueError, "canonical relative path"):
            StagedCCCL1Context(**values)

    def test_l1_runtime_revalidates_symlinks_and_role_overlap(self):
        swapped = self._make_l1_context("swapped")
        staged_executor_module._require_l1_runtime_paths(swapped)
        outside = swapped.shadow_root / "replacement"
        outside.mkdir()
        swapped.scratch_dir.rmdir()
        swapped.scratch_dir.symlink_to(outside, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, "symlinked or noncanonical"):
            staged_executor_module._require_l1_runtime_paths(swapped)

        nested_target = self._make_l1_context("nested-target")
        source_dir = nested_target.baseline_project_dir / "src"
        real_source_dir = nested_target.shadow_root / "outside-baseline-src"
        source_dir.rename(real_source_dir)
        source_dir.symlink_to(real_source_dir, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, "symlinked or noncanonical"):
            staged_executor_module._require_l1_runtime_paths(nested_target)

        overlapping = self._make_l1_context(
            "overlapping",
            scratch_below_baseline=True,
        )
        with self.assertRaisesRegex(ValueError, "must not overlap"):
            staged_executor_module._require_l1_runtime_paths(overlapping)

    def test_l1_copy_failure_does_not_claim_apply_phase(self):
        context = self._make_l1_context("copy-failure")
        poison = AssertionError("copy failure must stop before external runners")

        def copy_failure(*_args):
            raise ValueError("synthetic copy failure")

        def unexpected_runner(*_args, **_kwargs):
            raise poison

        providers = StagedCCCL1Providers(
            source_copier=copy_failure,
            command_runner=unexpected_runner,
            phenomenon_runner=unexpected_runner,
            sanity_runner=unexpected_runner,
        )
        submission = {
            "grade": "L1",
            "l1_patch": "fm_agent/bug_validation/bug1.l1.patch",
        }

        result = StagedCCCExecutor().run_l1(submission, context, providers)

        self.assertEqual(result.decision.kind, "reject")
        self.assertEqual(result.decision.check, "L1-attempt")
        self.assertIn("failed safely", result.decision.raw_reason)
        self.assertEqual(result.call_ledger, ())

    def test_gate_deep_copies_candidate_and_preserves_submitted_recipe_identity(self):
        candidate = _submission()
        before = _submission()
        seen_recipes = []

        def replay(_context, recipe):
            seen_recipes.append(recipe)
            return [{
                "manifest_id": "bug1",
                "input": {"self_flags": 0},
                "return": "false",
            }]

        def coverage(_context, recipe):
            seen_recipes.append(recipe)
            return 1

        def phenomenon(recipe, _context):
            seen_recipes.append(recipe)
            return PhenomenonObservation("run_exit_differs", ())

        providers = StagedCCCProviders(
            replay_capture=replay,
            coverage_runner=coverage,
            phenomenon_runner=phenomenon,
            l1_verifier=lambda *_args: Rejection("L1", "still differs"),
        )
        result = StagedCCCExecutor().run_gate(candidate, self.context, providers)

        self.assertEqual(candidate, before)
        self.assertEqual(result.original_submission, before)
        self.assertEqual(result.call_ledger, ("replay", "coverage", "phenomenon", "l1"))
        self.assertTrue(result.submitted_recipe_identity_preserved)
        self.assertTrue(all(recipe is seen_recipes[0] for recipe in seen_recipes))
        self.assertEqual(result.requested_grade, "L1")
        self.assertEqual(result.final_grade, "L0")
        self.assertEqual(result.final_submission["l1_patch"], None)
        self.assertEqual(result.original_submission["l1_patch"], before["l1_patch"])

    def test_injected_gate_does_not_call_default_subprocess_paths(self):
        candidate = _submission()
        providers = StagedCCCProviders(
            replay_capture=lambda *_args: [{
                "manifest_id": "bug1",
                "input": {"self_flags": 0},
                "return": "false",
            }],
            coverage_runner=lambda *_args: 1,
            phenomenon_runner=lambda *_args: PhenomenonObservation(
                "run_exit_differs", ()
            ),
            l1_verifier=lambda *_args: None,
        )
        poison = RuntimeError("default subprocess path must stay dormant")
        with mock.patch("src.check_submission.subprocess.run", side_effect=poison), \
             mock.patch("src.coverage_witness.subprocess.run", side_effect=poison), \
             mock.patch("src.phenomenon_runner.subprocess.run", side_effect=poison):
            result = StagedCCCExecutor().run_gate(candidate, self.context, providers)
        self.assertEqual(result.decision.kind, "accept")

    def test_staged_executor_is_not_publicly_exported(self):
        import src.validation_core as root
        import src.validation_core.presets.ccc as ccc

        self.assertFalse(hasattr(root, "StagedCCCExecutor"))
        self.assertFalse(hasattr(ccc, "StagedCCCExecutor"))
        self.assertNotIn("StagedCCCExecutor", getattr(ccc, "__all__", ()))
        self.assertFalse(hasattr(root, "StagedCCCL1Context"))
        self.assertFalse(hasattr(ccc, "StagedCCCL1Context"))
        self.assertFalse(hasattr(root, "StagedCCCL1Providers"))
        self.assertFalse(hasattr(ccc, "StagedCCCL1Providers"))

    def test_production_modules_do_not_import_staged_or_legacy_runtime(self):
        production_files = (
            "main.py",
            "config.py",
            "dashboard.py",
            "src/verification.py",
            "src/file_utils.py",
            "src/incremental_reasoner.py",
            "src/entry_reasoning_pipeline.py",
            "src/spec_generation_and_verification.py",
            "src/plugin.py",
            "src/validation_core/__init__.py",
            "src/validation_core/routing.py",
            "src/validation_core/registry.py",
            "src/validation_core/outcome_loader.py",
            "src/validation_core/presets/__init__.py",
            "src/validation_core/presets/ccc/__init__.py",
            "src/validation_core/presets/ccc/components.py",
            "src/validation_core/presets/ccc/preset.py",
        )
        forbidden = {
            "check_submission",
            "compiler_recipe",
            "coverage_witness",
            "l1_verifier",
            "phenomenon_runner",
            "submission_schema",
            "validation_context",
            "validation_workspace",
            "validation_core.presets.ccc.staged_executor",
            "src.check_submission",
            "src.compiler_recipe",
            "src.coverage_witness",
            "src.l1_verifier",
            "src.phenomenon_runner",
            "src.submission_schema",
            "src.validation_context",
            "src.validation_workspace",
            "src.validation_core.presets.ccc.staged_executor",
        }
        for relative_path in production_files:
            path = _ROOT / relative_path
            if not path.exists():
                continue
            imported = _import_targets(
                path.read_text(encoding="utf-8"),
                relative_path,
            )
            with self.subTest(path=relative_path):
                self.assertFalse(
                    _touches_forbidden_import(imported, forbidden),
                    imported,
                )

    def test_import_boundary_detects_absolute_and_relative_forms(self):
        forbidden = {
            "src.check_submission",
            "src.l1_verifier",
            "src.validation_context",
            "src.validation_workspace",
        }
        samples = (
            ("import src.check_submission\n", "src/verification.py"),
            ("import check_submission\n", "src/verification.py"),
            ("from check_submission import Gate\n", "src/verification.py"),
            ("from .check_submission import Gate\n", "src/verification.py"),
            ("from src import check_submission\n", "src/verification.py"),
            ("from . import check_submission\n", "src/verification.py"),
            ("importlib.import_module('src.check_submission')\n", "src/verification.py"),
            ("import_module('.check_submission')\n", "src/verification.py"),
            ("import src.l1_verifier\n", "src/verification.py"),
            ("import l1_verifier\n", "src/verification.py"),
            ("from .l1_verifier import verify_l1\n", "src/verification.py"),
            ("import validation_context\n", "src/verification.py"),
            ("from .validation_context import ValidationContext\n", "src/verification.py"),
            ("import validation_workspace\n", "src/verification.py"),
            ("from .validation_workspace import copy_validation_source\n", "src/verification.py"),
        )
        for source, relative_path in samples:
            with self.subTest(source=source):
                self.assertTrue(
                    _touches_forbidden_import(
                        _import_targets(source, relative_path),
                        forbidden,
                    )
                )

    def test_clean_root_import_does_not_load_dormant_ccc_runtime(self):
        code = (
            "import sys; import src.validation_core; "
            "package_names={'src.check_submission','src.compiler_recipe',"
            "'src.coverage_witness','src.phenomenon_runner',"
            "'src.submission_schema','src.l1_verifier',"
            "'src.validation_context','src.validation_workspace',"
            "'src.validation_core.presets.ccc.staged_executor'}; "
            "flat_names={'check_submission','compiler_recipe',"
            "'coverage_witness','phenomenon_runner','submission_schema',"
            "'l1_verifier','validation_context','validation_workspace',"
            "'validation_core.presets.ccc.staged_executor'}; "
            "loaded=sorted((package_names | flat_names).intersection(sys.modules)); "
            "assert not loaded, loaded; "
            "from src.validation_core.presets.ccc.staged_executor "
            "import StagedCCCExecutor; "
            "StagedCCCExecutor().parse_trace((), 'probe'); "
            "loaded=sorted(flat_names.intersection(sys.modules)); "
            "assert not loaded, loaded"
        )
        completed = subprocess.run(
            [sys.executable, "-c", code],
            cwd=_ROOT,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)


if __name__ == "__main__":
    unittest.main()

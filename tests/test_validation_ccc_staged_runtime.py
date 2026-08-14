import ast
import hashlib
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from src.check_submission import Rejection
from src.phenomenon_runner import PhenomenonObservation
from src.validation_core.presets.ccc.staged_executor import (
    StagedCCCContext,
    StagedCCCExecutor,
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

    def test_legacy_source_identity_matches_pinned_multirun_blobs(self):
        self.assertEqual(set(_LEGACY_SOURCES), {
            "src/compiler_recipe.py",
            "src/submission_schema.py",
            "src/phenomenon_runner.py",
            "src/coverage_witness.py",
            "src/check_submission.py",
        })
        for relative_path, (size, sha256, blob_sha1) in _LEGACY_SOURCES.items():
            with self.subTest(path=relative_path):
                data = (_ROOT / relative_path).read_bytes()
                self.assertEqual(len(data), size)
                self.assertEqual(hashlib.sha256(data).hexdigest(), sha256)
                self.assertEqual(_git_blob_sha1(data), blob_sha1)

    def test_all_gate_providers_are_mandatory(self):
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
        )
        forbidden = {
            "check_submission",
            "compiler_recipe",
            "coverage_witness",
            "phenomenon_runner",
            "submission_schema",
            "validation_core.presets.ccc.staged_executor",
            "src.check_submission",
            "src.compiler_recipe",
            "src.coverage_witness",
            "src.phenomenon_runner",
            "src.submission_schema",
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
        forbidden = {"src.check_submission"}
        samples = (
            ("import src.check_submission\n", "src/verification.py"),
            ("import check_submission\n", "src/verification.py"),
            ("from check_submission import Gate\n", "src/verification.py"),
            ("from .check_submission import Gate\n", "src/verification.py"),
            ("from src import check_submission\n", "src/verification.py"),
            ("from . import check_submission\n", "src/verification.py"),
            ("importlib.import_module('src.check_submission')\n", "src/verification.py"),
            ("import_module('.check_submission')\n", "src/verification.py"),
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
            "'src.submission_schema',"
            "'src.validation_core.presets.ccc.staged_executor'}; "
            "flat_names={'check_submission','compiler_recipe',"
            "'coverage_witness','phenomenon_runner','submission_schema',"
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

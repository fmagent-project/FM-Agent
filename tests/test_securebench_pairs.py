import difflib, json, os, shutil, subprocess, tempfile, unittest
from pathlib import Path; from typing import TypedDict; from unittest import mock
from eval import normalize; from eval import run_securebench_pairs as runner; from eval.run_ours import _load_case_results; from src.plugins import registry


class Result(TypedDict, total=False): rel: str; function: str; name: str; verdict: str; status: str; findings: list[dict[str, dict[str, str] | str]]


def _write_case(root: Path, case_id: str = "CVE-2099-0001", plugin: str = "taint", expected_cwe: str = "CWE-78", loci: list[dict[str, str]] | None = None, remove: bool = False) -> Path:
    case_dir = root / "SecureBench" / "cases" / case_id; minimal, patch_dir = case_dir / "minimal", case_dir / "patch"; minimal.mkdir(parents=True); patch_dir.mkdir(); source = "def danger(cmd):\n    return cmd\n" + ("\ndef helper(cmd):\n    return cmd\n" if loci and len(loci) > 1 else ""); (minimal / "app.py").write_text(source); patch = "--- a/app.py\n+++ b/app.py\n@@ -1,2 +1,2 @@\n def danger(cmd):\n-    return cmd\n+    return 'safe'\n"
    if loci and len(loci) > 1: patch = "--- a/app.py\n+++ b/app.py\n@@ -1,5 +1,5 @@\n def danger(cmd):\n-    return cmd\n+    return 'safe'\n \n def helper(cmd):\n     return cmd\n"
    if remove: patch = "--- a/app.py\n+++ b/app.py\n@@ -1,2 +0,0 @@\n-def danger(cmd):\n-    return cmd\n"
    (patch_dir / "fix.patch").write_text(patch)
    manifest = root / "eval" / "corpus.json"; manifest.parent.mkdir(exist_ok=True)
    manifest.write_text(json.dumps({"schema_version": 1, "cases": [{"cve": case_id, "plugin": plugin, "cwe": expected_cwe, "case_dir": f"SecureBench/cases/{case_id}", "loci": loci or [{"path": "app.py", "function": "danger"}]}]}))
    return manifest


def _identity_case(root: Path, vulnerable: str, fixed: str, loci: list[dict[str, str]]) -> Path:
    manifest = _write_case(root, loci=loci); case = root / "SecureBench/cases/CVE-2099-0001"; (case / "minimal/app.py").write_text(vulnerable); patch = difflib.unified_diff(vulnerable.splitlines(True), fixed.splitlines(True), "a/app.py", "b/app.py")
    (case / "patch/fix.patch").write_text("".join(patch)); return manifest


def _result(verdict: str, rel: str = "app.py", function: str = "danger", cwe: str = "CWE-78", status: str = "ok") -> Result:
    return {"rel": rel, "function": function, "name": function, "verdict": verdict, "status": status, "findings": [{"data": {"cwe": cwe}, "message": "evidence"}]}


def _fake_driver(results_by_side: dict[str, list[Result]]):
    calls = []
    def fake_run(case: runner.Case, stage: Path):
        side = stage.name.rsplit("-", 1)[-1]; plugin_manifest = registry.get_manifest(case.plugin); work_subdir = plugin_manifest.get("work_subdir", f"fm_agent_{case.plugin}"); results_subdir = plugin_manifest.get("results_subdir", "results"); calls.append((case.plugin, stage, work_subdir, results_subdir)); out_dir = stage / work_subdir / results_subdir; out_dir.mkdir(parents=True, exist_ok=True)
        for index, payload in enumerate(results_by_side.get(side, [])):
            result_path = out_dir / f"result_{index}.json"; result_path.write_text(json.dumps(payload))
        (out_dir / "summary.json").write_text(json.dumps({"total": len(results_by_side.get(side, []))})); return {"total": len(results_by_side.get(side, []))}
    return calls, fake_run


def _run_mocked(root: Path, manifest: Path, results: dict[str, list[Result]], extra: list[str] | None = None):
    calls, fake_run = _fake_driver(results); argv = ["--manifest", str(manifest), "--all", "--out", str(root / "out.json"), "--stage-root", str(root / "stages")]
    if extra: argv[3:3] = extra
    with mock.patch.object(runner, "_invoke_plugin", side_effect=fake_run):
        code = runner.main(argv)
    return code, json.loads((root / "out.json").read_text()) if (root / "out.json").exists() else {}, calls


class SecureBenchBaselineCharacterizationTests(unittest.TestCase):
    def test_registry_verdict_vocabularies_are_bucketed_for_pair_scoring(self):
        # Given
        expected = {"taint": {"positive": ["VULNERABLE"], "poly": ["POLYMORPHIC"], "review": [], "negative": ["SANITIZED", "SAFE"]}, "crypto": {"positive": ["VULNERABLE", "WEAK"], "poly": ["POLYMORPHIC"], "review": ["NEEDS_REVIEW"], "negative": ["SAFE"]}, "authz": {"positive": ["VULNERABLE"], "poly": [], "review": ["NEEDS_REVIEW"], "negative": ["SAFE"]}}
        # When
        actual = {name: registry.get_manifest(name)["verdicts"] for name in ("taint", "crypto", "authz")}
        # Then
        self.assertEqual(expected, actual); self.assertIn("ERROR", registry.all_verdicts("taint")); self.assertIn("ERROR", registry.positive_verdicts("taint"))

    def test_normalize_cwe_family_matching_is_shared_by_runner(self):
        # Given / When / Then
        cases = [("CWE-78", {"CWE-77"}, True), ("CWE-89", {"CWE-74"}, True), ("CWE-328", {"CWE-327"}, True), ("CWE-89", {"CWE-22"}, False)]
        for expected, detected, outcome in cases:
            with self.subTest(expected=expected, detected=detected): self.assertIs(normalize.cwe_matches(expected, detected), outcome)

    def test_run_ours_result_loader_filters_to_case_rel_prefix_when_requested(self):
        # Given
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); (root / "BenchmarkTest00001-py").mkdir(); (root / "helpers-py").mkdir(); (root / "summary.json").write_text("{}")
            (root / "BenchmarkTest00001-py" / "route.json").write_text(json.dumps({"rel": "BenchmarkTest00001-py/route.py", "verdict": "VULNERABLE"}))
            (root / "helpers-py" / "shared.json").write_text(json.dumps({"rel": "helpers-py/shared.py", "verdict": "VULNERABLE"}))
            # When
            results = _load_case_results(str(root), "BenchmarkTest00001")
        # Then
        self.assertEqual(["BenchmarkTest00001-py/route.py"], [r["rel"] for r in results])


class SecureBenchPairRunnerTests(unittest.TestCase):
    def test_fixed_patch_is_repository_independent_and_marker_is_verified(self):
        parents = (Path(runner.__file__).resolve().parent.parent, None)
        for parent in parents:
            with self.subTest(parent=parent), tempfile.TemporaryDirectory(dir=parent) as tmp:
                root = Path(tmp); case = runner.load_manifest(_write_case(root))[0]; stage = root / "fixed"; runner._prepare_stage(case, stage, "fixed", False); marker_path = stage / ".securebench_patch_applied"; marker = json.loads(marker_path.read_text()); self.assertEqual((1, 64, {"app.py"}), (marker["schema_version"], len(marker["patch_sha256"]), set(marker["fixed_inventory"])))
                work = stage / registry.get_manifest(case.plugin)["work_subdir"]; generated = (stage / ".codegraph/cache.db", work / "facts/f.json", work / "results/r.json", work / "traces/t.json", stage / "generated/arbitrary.bin"); [(path.parent.mkdir(parents=True, exist_ok=True), path.write_text("keep")) for path in generated]
                before = marker_path.read_bytes(); runner._prepare_stage(case, stage, "fixed", False); self.assertEqual(before, marker_path.read_bytes()); self.assertTrue(all(path.read_text() == "keep" for path in generated))
                marker_path.write_text(json.dumps({"patch_sha256": marker["patch_sha256"], "tree_digest": "legacy"})); runner._prepare_stage(case, stage, "fixed", False); self.assertEqual(1, json.loads(marker_path.read_text())["schema_version"]); self.assertTrue(all(path.exists() for path in generated))
                (stage / "app.py").write_text("def danger(cmd):\n    return cmd\n"); runner._prepare_stage(case, stage, "fixed", False); self.assertIn("'safe'", (stage / "app.py").read_text()); self.assertFalse(any(path.exists() for path in generated))
                junk = stage / "generated/tamper"; junk.parent.mkdir(); junk.write_text("drop"); marker_path.write_text('{"schema_version": 1}'); runner._prepare_stage(case, stage, "fixed", False); self.assertFalse(junk.exists()); self.assertEqual(1, json.loads(marker_path.read_text())["schema_version"])

    def test_patch_add_delete_and_unsafe_or_malformed_inputs_fail_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); manifest = _write_case(root); case_root = root / "SecureBench/cases/CVE-2099-0001"; (case_root / "minimal/delete.txt").write_text("old\n"); (case_root / "minimal/rename.txt").write_text("move\n")
            patch = "diff --git a/delete.txt b/delete.txt\ndeleted file mode 100644\n--- a/delete.txt\n+++ /dev/null\n@@ -1 +0,0 @@\n-old\ndiff --git a/added.txt b/added.txt\nnew file mode 100644\n--- /dev/null\n+++ b/added.txt\n@@ -0,0 +1 @@\n+new\ndiff --git a/rename.txt b/renamed.txt\nsimilarity index 100%\nrename from rename.txt\nrename to renamed.txt\n"; (case_root / "patch/fix.patch").write_text(patch); case = runner.load_manifest(manifest)[0]; stage = root / "fixed"; runner._prepare_stage(case, stage, "fixed", False); marker = json.loads((stage / ".securebench_patch_applied").read_text()); self.assertFalse((stage / "delete.txt").exists() or (stage / "rename.txt").exists()); self.assertEqual(("new\n", "move\n", {"app.py", "added.txt", "renamed.txt"}, {"app.py", "delete.txt", "rename.txt"}), ((stage / "added.txt").read_text(), (stage / "renamed.txt").read_text(), set(marker["fixed_inventory"]), set(marker["minimal_inventory"])))
        for name, patch in (("malformed", "not a patch\n"), ("traversal", "--- a/app.py\n+++ b/../escape.py\n@@ -1 +1 @@\n-old\n+new\n")):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp); manifest = _write_case(root); case_root = root / "SecureBench/cases/CVE-2099-0001"; (case_root / "patch/fix.patch").write_text(patch); case = runner.load_manifest(manifest)[0]
                with self.assertRaises((runner.ManifestError, subprocess.SubprocessError)): runner._prepare_stage(case, root / "fixed", "fixed", False)

    def test_analyzer_path_set_and_content_edits_bind_resume(self):
        for target in ("callgraph.py", "taint.py"):
            with self.subTest(target=target), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp); manifest = _write_case(root); case = runner.load_manifest(manifest)[0]; actual = {path.name for path in runner._analyzer_paths((case,))}; self.assertTrue({"run_securebench_pairs.py", "config.py", "llm_client.py", "driver.py", "base.py", "callgraph.py", "registry.py", "taint.py", "taint_validation.py", "taint_reasoner.py", "taint_prompts.py"} <= actual)
                files = tuple(root / name for name in ("callgraph.py", "taint.py")); [path.write_text(path.name) for path in files]
                with mock.patch.object(runner, "_analyzer_paths", return_value=files):
                    self.assertEqual(0, _run_mocked(root, manifest, {"vulnerable": [_result("VULNERABLE")], "fixed": [_result("SAFE")]})[0]); changed = next(path for path in files if path.name == target); changed.write_text(changed.read_text() + "changed"); calls, fake = _fake_driver({});
                    with mock.patch.object(runner, "_invoke_plugin", side_effect=fake): code = runner.main(["--manifest", str(manifest), "--all", "--out", str(root / "out.json"), "--stage-root", str(root / "stages")])
                self.assertEqual(2, code); self.assertEqual([], calls)

    def test_model_host_and_fake_mode_bind_resume_without_secrets(self):
        changes = (("model", {"LLM_MODEL": "deepseek-chat"}), ("host", {"LLM_API_BASE_URL": "https://two.example/private"}), ("fake", {runner.FAKE_RESULTS_ENV: json.dumps({"vulnerable": [], "fixed": []})}))
        for name, changed in changes:
            with self.subTest(name=name), tempfile.TemporaryDirectory() as tmp, mock.patch.dict(os.environ, {"LLM_MODEL": "anthropic/claude-sonnet-4.6", "LLM_API_BASE_URL": "https://one.example/private", "LLM_API_KEY": "never-store-this"}):
                os.environ.pop(runner.FAKE_RESULTS_ENV, None); root = Path(tmp); manifest = _write_case(root); code, data, _ = _run_mocked(root, manifest, {"vulnerable": [_result("VULNERABLE")], "fixed": [_result("SAFE")]}); self.assertEqual(0, code)
                encoded = json.dumps(data); self.assertNotIn("never-store-this", encoded); self.assertNotIn("/private", encoded); self.assertEqual(("anthropic/claude-sonnet-4.6", "one.example", False), (data["model"], data["api_base_host"], data["fake_mode"])); self.assertEqual(64, len(data["analyzer_sha256"])); self.assertTrue(all((side["analyzer_sha256"], side["model"], side["api_base_host"], side["fake_mode"]) == (data["analyzer_sha256"], data["model"], data["api_base_host"], data["fake_mode"]) for side in (data["cases"][0]["vulnerable"], data["cases"][0]["fixed"])))
                with mock.patch.dict(os.environ, changed): self.assertEqual(2, runner.main(["--manifest", str(manifest), "--all", "--out", str(root / "out.json"), "--stage-root", str(root / "stages")]))

    def test_missing_analyzer_file_is_controlled_and_unchanged_provenance_resumes(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); manifest = _write_case(root); case = runner.load_manifest(manifest)[0]; missing = root / "missing.py"
            with mock.patch.object(runner, "_analyzer_paths", return_value=(*runner._analyzer_paths((case,)), missing)):
                self.assertEqual(2, runner.main(["--manifest", str(manifest), "--all", "--out", str(root / "out.json"), "--stage-root", str(root / "stages")]))
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); manifest = _write_case(root); calls, fake = _fake_driver({"vulnerable": [_result("VULNERABLE")], "fixed": [_result("SAFE")]})
            with mock.patch.object(runner, "_invoke_plugin", side_effect=fake): codes = [runner.main(["--manifest", str(manifest), "--all", "--out", str(root / "out.json"), "--stage-root", str(root / "stages")]) for _ in range(2)]; self.assertEqual([0, 0], codes); self.assertEqual(2, len(calls))

    def test_qualified_identity_rejects_false_class_and_scores_exact_duplicate_tokens(self):
        source = "class A:\n    def danger(self):\n        return 1\nclass B:\n    def danger(self):\n        return 2\n"; fixed = source.replace("return 1", "return 3"); scenarios = (("first", "danger", "A.danger", 0), ("second", "danger_1", "B.danger", 0), ("ghost", "danger", "Ghost.danger", 1))
        for name, token, qualified, expected in scenarios:
            with self.subTest(name=name), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp); locus = {"path": "app.py", "function": token, "qualified_name": qualified}; result = {"vulnerable": [_result("VULNERABLE", function=token)], "fixed": [_result("SAFE", function=token)]}; self.assertEqual(expected, _run_mocked(root, _identity_case(root, source, fixed, [locus]), result)[0])

    def test_removed_middle_duplicate_absent_survives_extractor_suffix_shift(self):
        vulnerable = "class A:\n    def danger(self):\n        return 1\nclass B:\n    def danger(self):\n        return 2\nclass C:\n    def danger(self):\n        return 3\n"; fixed = vulnerable.replace("class B:\n    def danger(self):\n        return 2\n", "")
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); locus = {"path": "app.py", "function": "danger_1", "qualified_name": "B.danger", "fixed_expectation": "absent"}; code, _, _ = _run_mocked(root, _identity_case(root, vulnerable, fixed, [locus]), {"vulnerable": [_result("VULNERABLE", function="danger_1")], "fixed": []}); self.assertEqual(0, code)

    def test_live_duplicate_patterns_require_qualified_first_token_identity(self):
        for token in ("render_POST", "_acquire", "post"):
            with self.subTest(token=token), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp); source = f"class A:\n    def {token}(self):\n        return 1\nclass B:\n    def {token}(self):\n        return 2\n"; fixed = source.replace("return 1", "return 3"); locus = {"path": "app.py", "function": token, "qualified_name": f"A.{token}"}; results = {"vulnerable": [_result("VULNERABLE", function=token)], "fixed": [_result("SAFE", function=token)]}; self.assertEqual(0, _run_mocked(root, _identity_case(root, source, fixed, [locus]), results)[0])

    def test_qualified_name_is_preserved_and_invalidates_checkpoint_binding(self):
        source = "class A:\n    def danger(self):\n        return 1\n"; fixed = source.replace("return 1", "return 2")
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); locus = {"path": "app.py", "function": "danger", "qualified_name": "A.danger"}; manifest = _identity_case(root, source, fixed, [locus])
            self.assertEqual("A.danger", runner.load_manifest(manifest)[0].loci[0].qualified_name); self.assertEqual(0, _run_mocked(root, manifest, {"vulnerable": [_result("VULNERABLE")], "fixed": [_result("SAFE")]})[0]); data = json.loads(manifest.read_text()); data["cases"][0]["loci"][0]["qualified_name"] = "Ghost.danger"; manifest.write_text(json.dumps(data)); self.assertEqual(2, runner.main(["--manifest", str(manifest), "--all", "--out", str(root / "out.json"), "--stage-root", str(root / "stages")]))

    def test_nonexistent_declared_and_never_existed_absent_loci_fail(self):
        for expectation in ("present", "absent"):
            with self.subTest(expectation=expectation), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp); loci = [{"path": "app.py", "function": "ghost", "fixed_expectation": expectation}]; code, data, _ = _run_mocked(root, _write_case(root, loci=loci), {"vulnerable": [_result("VULNERABLE", function="ghost")], "fixed": [] if expectation == "absent" else [_result("SAFE", function="ghost")]}); self.assertEqual(1, code); self.assertFalse(data["cases"][0]["vulnerable"]["passed"]); self.assertIn("noncanonical vulnerable locus app.py::ghost", data["cases"][0]["vulnerable"]["errors"])

    def test_attacker_checkpoint_unknown_schema_metadata_or_empty_results_is_rejected(self):
        for name in ("schema", "metadata", "empty"):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp); manifest = _write_case(root); self.assertEqual(0, _run_mocked(root, manifest, {"vulnerable": [_result("VULNERABLE")], "fixed": [_result("SAFE")]})[0]); out = root / "out.json"; attack = json.loads(out.read_text())
                if name == "schema": attack["schema_version"] = "evil"
                elif name == "metadata": attack["cases"][0]["plugin"] = "crypto"
                else:
                    for key in ("locus_results", "verdicts", "cwes"): attack["cases"][0]["vulnerable"][key] = []
                out.write_text(json.dumps(attack))
                calls, fake = _fake_driver({"vulnerable": [_result("VULNERABLE")], "fixed": [_result("SAFE")]})
                with mock.patch.object(runner, "_invoke_plugin", side_effect=fake): code = runner.main(["--manifest", str(manifest), "--all", "--out", str(out), "--stage-root", str(root / "stages")])
                self.assertEqual(2, code); self.assertEqual([], calls)

    def test_checkpoint_rejects_stale_stage_minimal_or_patch_content(self):
        for target in ("stage", "minimal", "patch"):
            with self.subTest(target=target), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp); manifest = _write_case(root); self.assertEqual(0, _run_mocked(root, manifest, {"vulnerable": [_result("VULNERABLE")], "fixed": [_result("SAFE")]})[0]); path = {"stage": root / "stages/CVE-2099-0001-vulnerable/app.py", "minimal": root / "SecureBench/cases/CVE-2099-0001/minimal/app.py", "patch": root / "SecureBench/cases/CVE-2099-0001/patch/fix.patch"}[target]; path.write_text(path.read_text() + "\n# stale\n"); calls, fake = _fake_driver({});
                with mock.patch.object(runner, "_invoke_plugin", side_effect=fake): code = runner.main(["--manifest", str(manifest), "--all", "--out", str(root / "out.json"), "--stage-root", str(root / "stages")])
                self.assertEqual(2, code); self.assertEqual([], calls)

    def test_filesystem_failures_are_controlled_cli_errors(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); missing = subprocess.run(["python3.10", str(Path(runner.__file__)), "--manifest", str(root / "missing.json"), "--all", "--out", str(root / "out.json"), "--stage-root", str(root / "stages")], text=True, capture_output=True)
            self.assertEqual(2, missing.returncode); self.assertNotIn("Traceback", missing.stderr)
        for target in ("_load_checkpoint", "_prepare_stage", "_atomic_write"):
            with self.subTest(target=target), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp); manifest = _write_case(root); calls, fake = _fake_driver({"vulnerable": [_result("VULNERABLE")], "fixed": [_result("SAFE")]})
                with mock.patch.object(runner, "_invoke_plugin", side_effect=fake), mock.patch.object(runner, target, side_effect=OSError("denied")):
                    self.assertEqual(2, runner.main(["--manifest", str(manifest), "--all", "--out", str(root / "out.json"), "--stage-root", str(root / "stages")]))

    def test_schema1_manifest_derives_case_paths_and_defaults_present(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); case = runner.load_manifest(_write_case(root))[0]
            self.assertEqual(("CVE-2099-0001", "CWE-78"), (case.cve, case.expected_cwe)); self.assertEqual(root / "SecureBench/cases/CVE-2099-0001/minimal", case.minimal); self.assertEqual(root / "SecureBench/cases/CVE-2099-0001/patch/fix.patch", case.patch); self.assertEqual("present", case.loci[0].fixed_expectation)

    def test_runner_imports_under_system_python310(self):
        python = shutil.which("python3.10"); self.assertIsNotNone(python)
        completed = subprocess.run([python or "python3.10", "-c", "import eval.run_securebench_pairs"], cwd=Path(__file__).resolve().parent.parent, text=True, capture_output=True)
        self.assertEqual(0, completed.returncode, completed.stderr)

    def test_declared_helper_cannot_cover_missing_required_security_locus(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); loci = [{"path": "app.py", "function": name} for name in ("danger", "helper")]; helper = _result("VULNERABLE", function="helper"); code, data, _ = _run_mocked(root, _write_case(root, loci=loci), {"vulnerable": [helper], "fixed": [_result("SAFE", function="helper")]}); self.assertEqual(1, code); self.assertFalse(data["cases"][0]["vulnerable"]["passed"]); self.assertIn("missing locus app.py::danger", data["cases"][0]["vulnerable"]["errors"])

    def test_every_required_locus_needs_its_own_expected_cwe_and_fixed_result(self):
        loci = [{"path": "app.py", "function": name} for name in ("danger", "helper")]
        scenarios = {"happy": ([_result("VULNERABLE"), _result("VULNERABLE", function="helper")], [_result("SAFE"), _result("SAFE", function="helper")], 0), "wrong-cwe": ([_result("VULNERABLE"), _result("VULNERABLE", function="helper", cwe="CWE-22")], [_result("SAFE"), _result("SAFE", function="helper")], 1), "partial-fixed": ([_result("VULNERABLE"), _result("VULNERABLE", function="helper")], [_result("SAFE")], 1)}
        for name, (vulnerable, fixed, expected) in scenarios.items():
            with self.subTest(name=name), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp); code, _, _ = _run_mocked(root, _write_case(root, loci=loci), {"vulnerable": vulnerable, "fixed": fixed})
                self.assertEqual(expected, code)

    def test_fixed_absent_locus_passes_only_after_patch_removes_function(self):
        for name, fixed, expected in (("removed", [], 0), ("positive", [_result("VULNERABLE")], 1)):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp); loci = [{"path": "app.py", "function": "danger", "fixed_expectation": "absent"}]; code, data, _ = _run_mocked(root, _write_case(root, loci=loci, remove=True), {"vulnerable": [_result("VULNERABLE")], "fixed": fixed}); self.assertEqual(expected, code); self.assertIs(data["cases"][0]["fixed"]["passed"], expected == 0); self.assertNotIn("danger", (root / "stages/CVE-2099-0001-fixed/app.py").read_text())

    def test_absent_crypto_locus_is_independent_of_retained_out_of_locus_weakness(self):
        locus = {"path": "app.py", "function": "MD5", "fixed_expectation": "absent"}; vulnerable_source = "def MD5(data):\n    return data\n\ndef Standard_Multi_Hash(data):\n    return data\n"; fixed_source = "def Standard_Multi_Hash(data):\n    return data\n"
        declared, retained = _result("WEAK", function="MD5", cwe="CWE-327"), _result("WEAK", function="Standard_Multi_Hash", cwe="CWE-327")
        def execute(vulnerable: list[Result]):
            with tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp); manifest = _identity_case(root, vulnerable_source, fixed_source, [locus]); data = json.loads(manifest.read_text()); data["cases"][0].update(plugin="crypto", cwe="CWE-326"); manifest.write_text(json.dumps(data))
                return _run_mocked(root, manifest, {"vulnerable": vulnerable, "fixed": [retained]}, ["--plugin", "crypto"])
        code, output, _ = execute([declared, retained]); case = output["cases"][0]
        self.assertEqual(0, code); self.assertTrue(case["passed"]); self.assertEqual(["MD5"], [item["function"] for item in case["vulnerable"]["locus_results"]]); self.assertEqual([], case["fixed"]["locus_results"])
        self.assertEqual(["WEAK"], case["vulnerable"]["verdicts"]); self.assertEqual([], case["fixed"]["verdicts"]); self.assertEqual(["CWE-327"], case["vulnerable"]["cwes"]); self.assertEqual([], case["fixed"]["cwes"])
        self.assertEqual(["Standard_Multi_Hash"], [item["function"] for item in case["fixed"]["out_of_locus_results"]]); self.assertEqual("WEAK", case["fixed"]["out_of_locus_results"][0]["verdict"])
        code, output, _ = execute([retained]); self.assertEqual(1, code); self.assertFalse(output["cases"][0]["vulnerable"]["passed"]); self.assertIn("missing locus app.py::MD5", output["cases"][0]["vulnerable"]["errors"])
        self.assertEqual(["Standard_Multi_Hash"], [item["function"] for item in output["cases"][0]["vulnerable"]["out_of_locus_results"]])

    def test_duplicate_manifest_or_ambiguous_result_fails_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); locus = {"path": "app.py", "function": "danger"}
            with self.assertRaises(runner.ManifestError): runner.load_manifest(_write_case(root, loci=[locus, locus]))
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); duplicate = [_result("VULNERABLE"), _result("VULNERABLE")]
            code, data, _ = _run_mocked(root, _write_case(root), {"vulnerable": duplicate, "fixed": [_result("SAFE")]})
            self.assertEqual(1, code); self.assertIn("ambiguous locus app.py::danger", data["cases"][0]["vulnerable"]["errors"])

    def test_manifest_rejects_malformed_fixed_expectation(self):
        for expectation in ("", "missing", "ABSENT", 1):
            with self.subTest(expectation=expectation), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp); locus = {"path": "app.py", "function": "danger", "fixed_expectation": expectation}
                with self.assertRaises(runner.ManifestError): runner.load_manifest(_write_case(root, loci=[locus]))
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); locus = {"path": "app.rs", "function": "danger", "qualified_name": "A.danger"}
            with self.assertRaises(runner.ManifestError): runner.load_manifest(_write_case(root, loci=[locus]))

    def test_happy_pair_applies_patch_isolates_sides_and_classifies_loci(self):
        with tempfile.TemporaryDirectory() as tmp:
            # Given / When
            root = Path(tmp); manifest = _write_case(root); code, data, calls = _run_mocked(root, manifest, {"vulnerable": [_result("VULNERABLE")], "fixed": [_result("SAFE")]}, ["--plugin", "taint"])
            # Then
            stage = root / "stages"; self.assertEqual(0, code); self.assertTrue(data["cases"][0]["passed"])
            self.assertEqual("cmd", (stage / "CVE-2099-0001-vulnerable" / "app.py").read_text().split("return ")[1].strip())
            self.assertEqual("'safe'", (stage / "CVE-2099-0001-fixed" / "app.py").read_text().split("return ")[1].strip())
            self.assertNotEqual(calls[0][1], calls[1][1]); self.assertEqual(["danger"], [r["function"] for r in data["cases"][0]["vulnerable"]["locus_results"]])

    def test_locus_filtering_segregates_out_of_locus_results(self):
        with tempfile.TemporaryDirectory() as tmp:
            # Given / When
            root = Path(tmp); manifest = _write_case(root); outsiders = [_result("VULNERABLE", rel="helper.py"), _result("VULNERABLE", function="helper")]
            code, data, calls = _run_mocked(root, manifest, {"vulnerable": [_result("VULNERABLE"), *outsiders], "fixed": [_result("SAFE"), *outsiders]})
            # Then
            self.assertEqual(0, code); self.assertEqual(2, len(calls)); self.assertTrue(data["cases"][0]["passed"]); self.assertEqual(2, len(data["cases"][0]["fixed"]["out_of_locus_results"]))

    def test_cwe_family_mismatch_fails_vulnerable_side(self):
        with tempfile.TemporaryDirectory() as tmp:
            # Given / When
            root = Path(tmp); manifest = _write_case(root, expected_cwe="CWE-89")
            code, data, calls = _run_mocked(root, manifest, {"vulnerable": [_result("VULNERABLE", cwe="CWE-22")], "fixed": [_result("SAFE")]})
            # Then
            self.assertEqual(1, code); self.assertEqual(2, len(calls)); self.assertFalse(data["cases"][0]["vulnerable"]["passed"]); self.assertIn("expected CWE family", data["cases"][0]["vulnerable"]["errors"][0])

    def test_review_unknown_malformed_missing_locus_and_driver_exception_fail_closed(self):
        cases = [("review", {"vulnerable": [_result("NEEDS_REVIEW", cwe="CWE-327")], "fixed": [{"rel": "app.py", "function": "danger"}]}), ("unknown", {"vulnerable": [_result("VULNERABLE", cwe="CWE-327")], "fixed": [_result("MAYBE", cwe="CWE-327")]}), ("driver", {"vulnerable": [_result("VULNERABLE", cwe="CWE-327")], "fixed": []})]
        for name, results in cases:
            with self.subTest(name=name), tempfile.TemporaryDirectory() as tmp:
                # Given / When
                root = Path(tmp); manifest = _write_case(root, plugin="crypto", expected_cwe="CWE-327"); code, data, calls = _run_mocked(root, manifest, results, ["--plugin", "crypto"])
                # Then
                self.assertEqual(1, code); self.assertEqual(2, len(calls)); self.assertFalse(data["cases"][0]["fixed"]["passed"] if name != "review" else data["cases"][0]["vulnerable"]["passed"])

    def test_checkpoint_resume_skips_completed_side_and_clean_reruns(self):
        with tempfile.TemporaryDirectory() as tmp:
            # Given
            root = Path(tmp); manifest = _write_case(root); out = root / "out.json"; stage = root / "stages"; calls, fake_run = _fake_driver({"vulnerable": [_result("VULNERABLE")], "fixed": [_result("SAFE")]})
            with mock.patch.object(runner, "_invoke_plugin", side_effect=fake_run):
                # When
                results = tuple(runner.main(["--manifest", str(manifest), "--all", *([] if not clean else ["--clean"]), "--out", str(out), "--stage-root", str(stage)]) for clean in (False, False, True))
            # Then
            self.assertEqual((0, 0, 0), results); self.assertEqual(4, len(calls)); self.assertTrue(json.loads(out.read_text())["cases"][0]["passed"])

    def test_partial_checkpoint_resume_does_not_reapply_fixed_patch(self):
        with tempfile.TemporaryDirectory() as tmp:
            # Given
            root = Path(tmp); manifest = _write_case(root); out = root / "out.json"; stage = root / "stages"; self.assertEqual(0, _run_mocked(root, manifest, {"vulnerable": [_result("VULNERABLE")], "fixed": [_result("SAFE")]})[0]); checkpoint = json.loads(out.read_text())
            checkpoint["cases"][0].pop("fixed"); checkpoint["cases"][0].pop("passed"); out.write_text(json.dumps(checkpoint))
            calls, fake_run = _fake_driver({"fixed": [_result("SAFE")]})
            with mock.patch.object(runner, "_invoke_plugin", side_effect=fake_run):
                # When
                code = runner.main(["--manifest", str(manifest), "--all", "--out", str(out), "--stage-root", str(stage)])
            # Then
            self.assertEqual(0, code); self.assertEqual(1, len(calls)); self.assertTrue(json.loads(out.read_text())["cases"][0]["passed"])

    def test_manifest_rejects_duplicates_missing_patch_missing_locus_and_escaping_stage(self):
        with tempfile.TemporaryDirectory() as tmp:
            # Given
            root = Path(tmp); manifest = _write_case(root); data = json.loads(manifest.read_text()); data["cases"].append(dict(data["cases"][0])); dup = root / "eval/duplicate.json"; dup.write_text(json.dumps(data))
            missing_patch = _write_case(root / "missing_patch_case"); (root / "missing_patch_case/SecureBench/cases/CVE-2099-0001/patch/fix.patch").unlink()
            missing_locus = _write_case(root / "missing_locus_case"); locus_data = json.loads(missing_locus.read_text()); locus_data["cases"][0]["loci"] = []; missing_locus.write_text(json.dumps(locus_data))
            # When / Then
            for bad_manifest in (dup, missing_patch, missing_locus):
                with self.subTest(path=bad_manifest), self.assertRaises(runner.ManifestError): runner.load_manifest(bad_manifest)
            self.assertEqual(2, runner.main(["--manifest", str(manifest), "--all", "--out", str(root / "out.json"), "--stage-root", str(root / "stages" / ".." / "escape")]))

    def test_atomic_checkpoint_never_leaves_tmp_file_after_side_write(self):
        with tempfile.TemporaryDirectory() as tmp:
            # Given / When
            root = Path(tmp); out = root / "out.json"; code, _, _ = _run_mocked(root, _write_case(root), {"vulnerable": [_result("VULNERABLE")], "fixed": [_result("SAFE")]})
            # Then
            self.assertEqual(0, code); self.assertTrue(out.exists()); self.assertFalse(out.with_suffix(out.suffix + ".tmp").exists())

    def test_plugin_all_selector_with_zero_matches_fails_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            # Given / When
            root = Path(tmp); out = root / "out.json"; code = runner.main(["--manifest", str(_write_case(root, plugin="taint")), "--plugin", "crypto", "--all", "--out", str(out), "--stage-root", str(root / "stages")])
            # Then
            self.assertNotEqual(0, code); self.assertFalse(json.loads(out.read_text()).get("passed") if out.exists() else False)

    def test_result_status_error_fails_even_when_verdict_looks_negative(self):
        with tempfile.TemporaryDirectory() as tmp:
            # Given / When
            root = Path(tmp); code, data, calls = _run_mocked(root, _write_case(root), {"vulnerable": [_result("VULNERABLE")], "fixed": [_result("SAFE", status="error")]})
            # Then
            self.assertEqual(2, len(calls)); self.assertNotEqual(0, code); self.assertFalse(data["cases"][0]["fixed"]["passed"]); self.assertIn("status error", data["cases"][0]["fixed"]["errors"])


if __name__ == "__main__":
    unittest.main()

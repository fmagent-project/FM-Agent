import concurrent.futures
import json
import os
import tempfile
import threading
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import src.spec_generation_and_verification as stage
import src.verification as verification
from src.file_utils import is_file_ready, normalize_spec_filenames


VALID_INFO = {"callees": []}
OLD_SPEC = {
    "signature": "old()",
    "pre_condition": "true",
    "post_condition": "old result",
}
NEW_SPEC = {
    "signature": "new()",
    "pre_condition": "true",
    "post_condition": "new result",
}


def _write_json(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value), encoding="utf-8")


class NormalizeSpecFilenamesTest(unittest.TestCase):
    def test_complete_pair_is_published_without_ready_mixed_pair(self):
        with tempfile.TemporaryDirectory() as tmp:
            function = Path(tmp) / "B.rs"
            function.write_text("fn b() {}\n", encoding="utf-8")

            expected_info = Path(f"{function}.info.json")
            _write_json(expected_info, VALID_INFO)
            _write_json(function.with_suffix(".spec.json"), NEW_SPEC)
            _write_json(function.with_suffix(".info.json"), VALID_INFO)

            readiness_after_each_replace = []
            real_replace = os.replace

            def observing_replace(source, destination):
                real_replace(source, destination)
                readiness_after_each_replace.append(is_file_ready(str(function)))

            with mock.patch(
                "src.file_utils.os.replace",
                side_effect=observing_replace,
            ):
                normalized = normalize_spec_filenames([str(function)])

            self.assertEqual(normalized, [str(function)])
            self.assertEqual(readiness_after_each_replace, [False, True])
            self.assertEqual(
                json.loads(Path(f"{function}.spec.json").read_text()),
                NEW_SPEC,
            )

    def test_incomplete_pair_is_left_for_retry(self):
        with tempfile.TemporaryDirectory() as tmp:
            function = Path(tmp) / "B.rs"
            function.write_text("fn b() {}\n", encoding="utf-8")
            _write_json(function.with_suffix(".spec.json"), NEW_SPEC)

            normalized = normalize_spec_filenames([str(function)])

            self.assertEqual(normalized, [])
            self.assertFalse(is_file_ready(str(function)))
            self.assertTrue(function.with_suffix(".spec.json").exists())

    def test_batch_scope_still_detects_layer_wide_ambiguity(self):
        with tempfile.TemporaryDirectory() as tmp:
            rust_function = Path(tmp) / "same.rs"
            python_function = Path(tmp) / "same.py"
            rust_function.write_text("fn same() {}\n", encoding="utf-8")
            python_function.write_text("def same(): pass\n", encoding="utf-8")
            _write_json(rust_function.with_suffix(".spec.json"), NEW_SPEC)
            _write_json(rust_function.with_suffix(".info.json"), VALID_INFO)

            with self.assertRaises(RuntimeError):
                normalize_spec_filenames(
                    [str(rust_function)],
                    all_function_files=[
                        str(rust_function),
                        str(python_function),
                    ],
                )


class StreamingNormalizationTest(unittest.TestCase):
    def _pipeline_layout(self, root, function_names):
        proj_dir = Path(root)
        work_dir = proj_dir / "fm_agent"
        input_dir = work_dir / "extracted_functions"
        output_dir = work_dir / "logic_verification_results"
        spec_prompts_dir = work_dir / "spec_prompts"
        script_dir = proj_dir / "script"

        (script_dir / "md").mkdir(parents=True)
        (script_dir / "md" / "workflow_spec_step4_batch.md").write_text(
            "prompt",
            encoding="utf-8",
        )

        extracted_dir = input_dir / "foo-rs"
        extracted_dir.mkdir(parents=True)
        functions = {}
        batches = []
        for index, name in enumerate(function_names):
            function = extracted_dir / name
            function.write_text(f"fn {function.stem.lower()}() {{}}\n", encoding="utf-8")
            functions[name] = function
            batch_file = f"batch_{index}.txt"
            batches.append({
                "file": batch_file,
                "functions": [str(function.relative_to(proj_dir))],
                "num_pending": 1,
            })

        _write_json(
            spec_prompts_dir / "phase_01_topdown_layers.json",
            {"total_layers": 1},
        )
        batch_dir = spec_prompts_dir / "batch_prompts_demo_phase01"
        _write_json(batch_dir / "manifest.json", {"batches": batches})
        for batch in batches:
            (batch_dir / batch["file"]).write_text("batch", encoding="utf-8")

        phases = {
            "project": "demo",
            "phases": [{
                "phase": 1,
                "name": "phase",
                "modules": [{"source_files": ["foo.rs"]}],
            }],
        }
        return {
            "proj_dir": proj_dir,
            "work_dir": work_dir,
            "input_dir": input_dir,
            "output_dir": output_dir,
            "spec_prompts_dir": spec_prompts_dir,
            "script_dir": script_dir,
            "functions": functions,
            "phases": phases,
        }

    def test_completed_batch_is_verified_while_another_batch_is_running(self):
        with tempfile.TemporaryDirectory() as tmp:
            layout = self._pipeline_layout(tmp, ["A.rs", "B.rs"])
            function_a = layout["functions"]["A.rs"]
            function_b = layout["functions"]["B.rs"]

            # A stale result must be gone before the producer publishes a new
            # canonical or normalized pair, even under --resume.
            _write_json(Path(f"{function_a}.spec.json"), OLD_SPEC)
            stale_result = layout["output_dir"] / "foo-rs" / "A.json"
            stale_validation = (
                layout["work_dir"]
                / "bug_validation"
                / "foo-rs--A.result.json"
            )
            stale_summary = layout["work_dir"] / "bug_validation" / "summary.json"
            _write_json(stale_result, {"verdict": "MATCH"})
            _write_json(stale_validation, {"confirmation_status": "confirmed"})
            _write_json(stale_summary, {"total_confirmed": 1})

            a_verified = threading.Event()
            ordering_errors = []
            verify_calls = []
            streaming_calls = []

            def fake_generation(**kwargs):
                batch_file = kwargs["metadata"]["batch_file"]
                function = function_a if batch_file == "batch_0.txt" else function_b
                if function == function_b and not a_verified.wait(timeout=3):
                    ordering_errors.append(
                        "Batch A was not verified before Batch B was allowed to finish"
                    )
                if function == function_a:
                    if stale_result.exists() or stale_validation.exists() or stale_summary.exists():
                        ordering_errors.append("Stale resume artifacts were not invalidated")
                _write_json(function.with_suffix(".spec.json"), NEW_SPEC)
                _write_json(function.with_suffix(".info.json"), VALID_INFO)
                return SimpleNamespace(returncode=0)

            def fake_verify(
                file_path,
                input_dir,
                output_dir,
                language,
                work_dir=None,
                resume=False,
            ):
                verify_calls.append((Path(file_path).name, resume))
                if Path(file_path).name == "A.rs":
                    a_verified.set()
                return file_path, "MATCH"

            real_streaming_reasoner = verification.streaming_reasoner

            def fast_streaming_reasoner(*args, **kwargs):
                streaming_calls.append(kwargs.get("spec_procs"))
                kwargs["poll_interval"] = 0.01
                return real_streaming_reasoner(*args, **kwargs)

            with mock.patch.object(stage.subprocess, "run"), \
                    mock.patch.object(stage, "build_llm_cli_command", return_value=["fake"]), \
                    mock.patch.object(stage, "run_opencode_traced", side_effect=fake_generation), \
                    mock.patch.object(stage, "list_staged_domain_knowledge_relpaths", return_value=[]), \
                    mock.patch.object(stage, "streaming_reasoner", side_effect=fast_streaming_reasoner), \
                    mock.patch.object(stage, "MAX_WORKERS", 2), \
                    mock.patch.object(stage, "OPENCODE_MAX_RETRIES", 1), \
                    mock.patch.object(verification, "MAX_WORKERS", 2), \
                    mock.patch.object(verification, "_verify_single_file", side_effect=fake_verify):
                stage.run_spec_generation_and_verification(
                    str(layout["proj_dir"]),
                    str(layout["work_dir"]),
                    str(layout["input_dir"]),
                    str(layout["output_dir"]),
                    str(layout["script_dir"]),
                    str(layout["spec_prompts_dir"]),
                    layout["phases"],
                    resume=True,
                )

            self.assertEqual(ordering_errors, [])
            self.assertEqual(len(streaming_calls), 1)
            self.assertTrue(streaming_calls[0])
            self.assertEqual({name for name, _ in verify_calls}, {"A.rs", "B.rs"})
            self.assertTrue(all(resume for _, resume in verify_calls))
            self.assertTrue(is_file_ready(str(function_a)))
            self.assertTrue(is_file_ready(str(function_b)))

    def test_watcher_rescans_when_producer_finishes_after_scan(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            input_dir = root / "input"
            output_dir = root / "output"
            input_dir.mkdir()
            function = input_dir / "B.rs"
            function.write_text("fn b() {}\n", encoding="utf-8")

            first_scan_finished = threading.Event()
            pair_published = threading.Event()

            def producer():
                if not first_scan_finished.wait(timeout=3):
                    raise RuntimeError("watcher did not complete its first scan")
                _write_json(Path(f"{function}.spec.json"), NEW_SPEC)
                _write_json(Path(f"{function}.info.json"), VALID_INFO)
                pair_published.set()
                return 0

            real_walk = os.walk
            first_walk = True
            future_holder = {}

            def controlled_walk(path):
                nonlocal first_walk
                yield from real_walk(path)
                if first_walk and Path(path) == input_dir:
                    first_walk = False
                    first_scan_finished.set()
                    if not pair_published.wait(timeout=3):
                        raise RuntimeError("producer did not publish its pair")
                    deadline = time.monotonic() + 3
                    while not future_holder["future"].done():
                        if time.monotonic() >= deadline:
                            raise RuntimeError("producer Future did not become done")
                        time.sleep(0.001)

            def fake_verify(file_path, *args, **kwargs):
                return file_path, "MATCH"

            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
                producer_future = executor.submit(producer)
                future_holder["future"] = producer_future
                with mock.patch.object(verification.os, "walk", side_effect=controlled_walk), \
                        mock.patch.object(verification, "_verify_single_file", side_effect=fake_verify):
                    processed = verification.streaming_reasoner(
                        str(input_dir),
                        str(output_dir),
                        file_list=["B.rs"],
                        spec_procs=[producer_future],
                        poll_interval=0.001,
                    )

            self.assertIn(str(function), processed)


if __name__ == "__main__":
    unittest.main()

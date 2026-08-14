import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from phenomenon_runner import PhenomenonError, run_phenomenon  # noqa: E402


class ScriptedRunner:
    def __init__(self, results):
        self.results = list(results)
        self.calls = []

    def __call__(self, argv, **kwargs):
        self.calls.append((list(argv), kwargs))
        result = self.results.pop(0)
        if isinstance(result, Exception):
            raise result
        return result


def result(rc=0, out="", err=""):
    return (rc, out, err)


class PhenomenonRunnerTests(unittest.TestCase):
    def setUp(self):
        root = Path(tempfile.mkdtemp())
        scratch = root / ".attempts" / "one"
        scratch.mkdir(parents=True)
        probe = root / "_probe_bug.c"
        probe.write_text("int main(void){return 0;}\n")
        self.context = SimpleNamespace(
            project_dir=root, scratch_dir=scratch, probe_path=probe,
            release_ccc=Path("/trusted/ccc"), reference_cc=Path("/trusted/gcc"),
        )

    def recipe(self, mode="run", expected="run_exit_differs", extra=None):
        return {"mode": mode, "standard": "c11", "extra_args": extra or [],
                "expected_kind": expected}

    def test_run_classifies_compile_and_runtime_phases(self):
        runner = ScriptedRunner([result(), result(), result(10), result(139)])
        observation = run_phenomenon(self.recipe(), self.context, runner=runner)
        self.assertEqual(observation.kind, "run_exit_differs")
        self.assertEqual(len(runner.calls), 4)
        self.assertEqual(runner.calls[0][0][0], "/trusted/ccc")
        self.assertEqual(runner.calls[1][0][0], "/trusted/gcc")
        self.assertTrue(all("bash" not in argv for argv, _ in runner.calls))

    def test_run_stdout_difference_requires_both_builds_and_equal_exit(self):
        runner = ScriptedRunner([result(), result(), result(0, "A"), result(0, "B")])
        observation = run_phenomenon(
            self.recipe(expected="stdout_differs"), self.context, runner=runner
        )
        self.assertEqual(observation.kind, "stdout_differs")

    def test_one_run_build_failure_is_build_accept_reject(self):
        runner = ScriptedRunner([result(1, err="bad"), result()])
        observation = run_phenomenon(
            self.recipe(expected="build_accept_reject_differs"),
            self.context, runner=runner,
        )
        self.assertEqual(observation.kind, "build_accept_reject_differs")
        self.assertEqual(len(runner.calls), 2)

    def test_syntax_one_compile_failure_is_accept_reject(self):
        runner = ScriptedRunner([result(1), result(0)])
        observation = run_phenomenon(
            self.recipe(mode="syntax", expected="accept_reject_differs"),
            self.context, runner=runner,
        )
        self.assertEqual(observation.kind, "accept_reject_differs")
        ccc_argv = runner.calls[0][0]
        self.assertIn("-fsyntax-only", ccc_argv)
        self.assertNotIn("-o", ccc_argv)

    def test_asm_and_object_do_not_compare_successful_outputs(self):
        for mode in ("asm", "object"):
            with self.subTest(mode=mode):
                runner = ScriptedRunner([
                    result(0, out="ccc diagnostics differ"),
                    result(0, out="gcc diagnostics differ"),
                ])
                with self.assertRaisesRegex(
                    PhenomenonError, "no observable accept/reject difference"
                ):
                    run_phenomenon(
                        self.recipe(mode=mode, expected="accept_reject_differs"),
                        self.context,
                        runner=runner,
                    )
                self.assertEqual(len(runner.calls), 2)

    def test_preprocess_compares_normalized_stdout(self):
        runner = ScriptedRunner([result(0, "A  \r\n"), result(0, "B\n")])
        observation = run_phenomenon(
            self.recipe(mode="preprocess", expected="preprocess_differs"),
            self.context, runner=runner,
        )
        self.assertEqual(observation.kind, "preprocess_differs")
        self.assertIn("-E", runner.calls[0][0])
        self.assertIn("-P", runner.calls[0][0])

    def test_both_compilers_fail_is_never_a_phenomenon(self):
        for mode in ("syntax", "run"):
            with self.subTest(mode=mode), self.assertRaisesRegex(
                PhenomenonError, "both"
            ):
                run_phenomenon(
                    self.recipe(mode=mode), self.context,
                    runner=ScriptedRunner([result(1), result(2)]),
                )

    def test_no_difference_is_rejected(self):
        with self.assertRaisesRegex(PhenomenonError, "no observable"):
            run_phenomenon(
                self.recipe(), self.context,
                runner=ScriptedRunner([result(), result(), result(), result()]),
            )

    def test_rejects_shell_and_path_control_flags_before_execution(self):
        bad = [";touch", "@args", "-o/tmp/x", "-I/tmp/x", "-Wl,-T,x", "probe.c"]
        for arg in bad:
            with self.subTest(arg=arg):
                runner = ScriptedRunner([])
                with self.assertRaisesRegex(PhenomenonError, "extra_args"):
                    run_phenomenon(self.recipe(extra=[arg]), self.context, runner=runner)
                self.assertEqual(runner.calls, [])

    def test_timeout_and_launch_failure_fail_closed(self):
        errors = [subprocess.TimeoutExpired(["ccc"], 120), OSError("missing")]
        for error in errors:
            with self.subTest(error=type(error).__name__), self.assertRaises(
                PhenomenonError
            ):
                run_phenomenon(
                    self.recipe(mode="syntax"), self.context,
                    runner=ScriptedRunner([error]),
                )

    def test_diagnostics_cannot_masquerade_as_program_stdout(self):
        runner = ScriptedRunner([result(), result(), result(0, "same", "A"),
                                 result(0, "same", "B")])
        with self.assertRaisesRegex(PhenomenonError, "no observable"):
            run_phenomenon(self.recipe(), self.context, runner=runner)


if __name__ == "__main__":
    unittest.main()

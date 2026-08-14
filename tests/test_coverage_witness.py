import json
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from coverage_witness import CoverageError, _tool, capture_coverage  # noqa: E402


class CoverageWitnessTests(unittest.TestCase):
    def setUp(self):
        self.project = Path(tempfile.mkdtemp()).resolve()
        self.scratch = self.project / "scratch"
        self.scratch.mkdir()
        self.source = self.project / "src" / "x.rs"
        self.source.parent.mkdir()
        self.source.write_text("use std::fmt;\n\nfn target() {\n    work();\n}\n")
        self.probe = self.project / "probe.c"
        self.probe.write_text("int main(void){return 0;}\n")
        self.context = SimpleNamespace(
            project_dir=self.project,
            scratch_dir=self.scratch,
            probe_path=self.probe,
            coverage_ccc=Path("/trusted/coverage-ccc"),
            manifest_entry=SimpleNamespace(
                file="src/x.rs", fn_name="target", occurrence=0, source_line=3,
            ),
        )
        self.recipe = {
            "mode": "syntax", "standard": "c23",
            "extra_args": ["-pedantic"],
        }

    def runner(self, argv, *, cwd, env):
        if Path(argv[0]) == self.context.coverage_ccc:
            (self.scratch / "coverage-fake.profraw").write_bytes(b"profile")
            return (0, "", "")
        if Path(argv[0]).name == "llvm-profdata":
            Path(argv[argv.index("-o") + 1]).write_bytes(b"merged")
            return (0, "", "")
        export = {
            "data": [{"functions": [{
                "name": "ccc::x::target",
                "count": 2,
                "filenames": [str(
                    self.project.parent / "coverage_build" / "src" / "x.rs"
                )],
                "regions": [[3, 1, 5, 2, 2, 0, 0, 0]],
            }]}]
        }
        return (0, json.dumps(export), "")

    def test_counts_target_entries_from_an_independent_profile(self):
        count = capture_coverage(
            self.context,
            self.recipe,
            process_runner=self.runner,
            llvm_profdata=Path("/trusted/llvm-profdata"),
            llvm_cov=Path("/trusted/llvm-cov"),
        )
        self.assertEqual(count, 2)

    def test_nonzero_compile_keeps_usable_profile(self):
        seen = []

        def runner(argv, *, cwd, env):
            seen.append(list(argv))
            if Path(argv[0]) == self.context.coverage_ccc:
                (self.scratch / "coverage-fake.profraw").write_bytes(b"profile")
                return (1, "", "expected rejection")
            return self.runner(argv, cwd=cwd, env=env)

        count = capture_coverage(
            self.context,
            self.recipe,
            process_runner=runner,
            llvm_profdata=Path("/trusted/llvm-profdata"),
            llvm_cov=Path("/trusted/llvm-cov"),
        )
        self.assertEqual(count, 2)
        self.assertEqual(seen[0][:3], [
            str(self.context.coverage_ccc), "-std=c23", "-pedantic",
        ])
        self.assertIn("-fsyntax-only", seen[0])

    def test_missing_profile_fails_closed(self):
        def runner(_argv, *, cwd, env):
            return (0, "", "")
        with self.assertRaisesRegex(CoverageError, "profile"):
            capture_coverage(
                self.context,
                self.recipe,
                process_runner=runner,
                llvm_profdata=Path("/trusted/llvm-profdata"),
                llvm_cov=Path("/trusted/llvm-cov"),
            )

    def test_prefers_the_matching_rust_toolchain_tools(self):
        sysroot = self.project / "rust"
        tool = sysroot / "lib" / "rustlib" / "test-host" / "bin" / "llvm-profdata"
        tool.parent.mkdir(parents=True)
        tool.write_bytes(b"tool")

        def rustc(argv, **_kwargs):
            output = str(sysroot) if argv[-1] == "sysroot" else "host: test-host\n"
            return SimpleNamespace(returncode=0, stdout=output, stderr="")

        with mock.patch.dict("os.environ", {}, clear=True), \
             mock.patch("coverage_witness.subprocess.run", side_effect=rustc), \
             mock.patch("coverage_witness.shutil.which", return_value="/old/llvm-profdata"):
            self.assertEqual(_tool("llvm-profdata"), tool)


if __name__ == "__main__":
    unittest.main()

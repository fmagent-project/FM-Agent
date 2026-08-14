import unittest
from pathlib import Path

from src.compiler_recipe import CompileRecipeError, compile_argv


class CompilerRecipeTests(unittest.TestCase):
    def recipe(self, mode):
        return {
            "mode": mode,
            "standard": "gnu23",
            "extra_args": ["-pedantic", "-O2"],
        }

    def test_constructs_every_supported_compile_mode(self):
        compiler = Path("/trusted/ccc")
        probe = Path("/work/probe.c")
        output = Path("/scratch/output")
        expected_tails = {
            "preprocess": ["-E", "-P", str(probe)],
            "syntax": ["-fsyntax-only", str(probe)],
            "asm": ["-S", str(probe), "-o", str(output)],
            "object": ["-c", str(probe), "-o", str(output)],
            "run": [str(probe), "-o", str(output)],
        }
        for mode, tail in expected_tails.items():
            with self.subTest(mode=mode):
                argv = compile_argv(compiler, self.recipe(mode), probe, output)
                self.assertEqual(
                    argv,
                    [str(compiler), "-std=gnu23", "-pedantic", "-O2", *tail],
                )

    def test_rejects_unknown_standard_mode_and_flag(self):
        cases = [
            {"mode": "link", "standard": "c11", "extra_args": []},
            {"mode": "run", "standard": "c2x", "extra_args": []},
            {"mode": "run", "standard": "c11", "extra_args": ["-I/tmp"]},
        ]
        for recipe in cases:
            with self.subTest(recipe=recipe), self.assertRaises(CompileRecipeError):
                compile_argv("ccc", recipe, "probe.c", "output")

    def test_does_not_accept_shell_or_path_values_as_flags(self):
        for flag in ("; touch owned", "-o", "../other.c", "-DNAME=value"):
            with self.subTest(flag=flag), self.assertRaises(CompileRecipeError):
                compile_argv(
                    "ccc",
                    {"mode": "run", "standard": "c11", "extra_args": [flag]},
                    "probe.c",
                    "output",
                )


if __name__ == "__main__":
    unittest.main()

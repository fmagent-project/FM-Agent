"""Closed compiler recipes shared by audit, coverage, and phenomena."""

from __future__ import annotations

from pathlib import Path


C_STANDARDS = frozenset({
    "c89", "c90", "c99", "c11", "c17", "c23",
    "gnu89", "gnu90", "gnu99", "gnu11", "gnu17", "gnu23",
})
COMPILE_MODES = frozenset({"preprocess", "syntax", "asm", "object", "run"})
SAFE_COMPILER_FLAGS = frozenset({
    "-O0", "-O1", "-O2", "-O3", "-Og", "-Os",
    "-Wall", "-Wextra", "-Werror", "-w", "-pedantic", "-pedantic-errors",
    "-fwrapv", "-fno-wrapv", "-fno-strict-aliasing",
    "-funsigned-char", "-fsigned-char", "-fcommon", "-fno-common", "-trigraphs",
})


class CompileRecipeError(ValueError):
    pass


def validate_compile_recipe(recipe: dict) -> tuple[str, str, list[str]]:
    """Return one validated mode, language standard, and flag list."""
    if type(recipe) is not dict:
        raise CompileRecipeError("compile recipe must be an object")
    mode = recipe.get("mode")
    standard = recipe.get("standard")
    extra_args = recipe.get("extra_args")
    if type(mode) is not str or mode not in COMPILE_MODES:
        raise CompileRecipeError(f"unsupported compile mode: {mode!r}")
    if type(standard) is not str or standard not in C_STANDARDS:
        raise CompileRecipeError(f"unsupported C standard: {standard!r}")
    if type(extra_args) is not list or any(
        type(arg) is not str or arg not in SAFE_COMPILER_FLAGS for arg in extra_args
    ):
        raise CompileRecipeError("extra_args contains a disallowed compiler flag")
    return mode, standard, list(extra_args)


# PIN: validation-replay-uses-submitted-compile-recipe
def compile_argv(
    compiler: Path | str,
    recipe: dict,
    probe: Path | str,
    output: Path | str | None,
) -> list[str]:
    """Construct argv without accepting paths or commands from agent text."""
    mode, standard, extra_args = validate_compile_recipe(recipe)
    argv = [str(compiler), f"-std={standard}", *extra_args]
    if mode == "preprocess":
        argv.extend(["-E", "-P", str(probe)])
    elif mode == "syntax":
        argv.extend(["-fsyntax-only", str(probe)])
    elif mode == "asm":
        if output is None:
            raise CompileRecipeError("asm mode requires a harness output path")
        argv.extend(["-S", str(probe), "-o", str(output)])
    elif mode == "object":
        if output is None:
            raise CompileRecipeError("object mode requires a harness output path")
        argv.extend(["-c", str(probe), "-o", str(output)])
    else:
        if output is None:
            raise CompileRecipeError("run mode requires a harness output path")
        argv.extend([str(probe), "-o", str(output)])
    return argv

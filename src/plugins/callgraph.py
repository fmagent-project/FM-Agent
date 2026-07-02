"""Plugin-agnostic program-structure machinery shared by all analysis plugins.

This is the reusable substrate factored out of ifc_main.py: source scanning,
function extraction (via FM-Agent's existing run_extraction), call-graph
construction, bottom-up ordering (callees before callers), entrypoint detection,
and best-effort signature/parameter/call-site parsing.

The driver builds a ProgramIndex from these helpers once, then hands it to a
plugin. Nothing here understands any security theory.

The call-graph logic intentionally mirrors ifc_main.py's behavior (regex,
base-name matching to undo extract.py's dedupe suffixes) so the IFC plugin is
behavior-preserving after migration.
"""

from __future__ import annotations

import os
import re
import json
from typing import Dict, List, Optional, Sequence, Tuple

from src.extract import run_extraction, EXT_TO_LANG, LANG_CONFIG
from src.plugins.base import (
    CallSite,
    FunctionId,
    FunctionUnit,
    ProgramIndex,
    SourceSpan,
)


# Languages whose parameter syntax is "name type" (identifier FIRST) rather than
# the C/Java "type name" convention (identifier LAST).
_NAME_FIRST_LANGS = {"go"}


# --- source scanning + extraction --------------------------------------------

def scan_source_files(proj_dir: str) -> List[str]:
    """Find supported source files under proj_dir (skip hidden/vendor dirs)."""
    source_exts = set(EXT_TO_LANG.keys())
    found = []
    for root, dirs, files in os.walk(proj_dir):
        dirs[:] = [d for d in dirs if not d.startswith(".") and d not in
                   {"node_modules", "__pycache__", "venv", ".venv",
                    "fm_agent", "fm_agent_ifc", "fm_agent_authz"}]
        for fname in files:
            ext = fname.rsplit(".", 1)[-1] if "." in fname else ""
            if ext in source_exts:
                rel = os.path.relpath(os.path.join(root, fname), proj_dir)
                found.append(rel)
    return sorted(found)


def write_minimal_phases(work_dir: str, proj_dir: str, source_files: Sequence[str]) -> None:
    """Write a one-phase phases.json so run_extraction has its input."""
    langs, exts = [], []
    for sf in source_files:
        ext = sf.rsplit(".", 1)[-1] if "." in sf else ""
        lang = EXT_TO_LANG.get(ext)
        if lang and lang.lower() not in langs:
            langs.append(lang.lower())
            exts.append(ext)
    phases = {
        "project": os.path.basename(os.path.abspath(proj_dir)),
        "languages": langs,
        "file_extensions": exts,
        "phases": [{
            "phase": 1,
            "name": "Plugin Analysis",
            "description": "All functions for per-function analysis.",
            "modules": [{"name": "all", "source_files": list(source_files)}],
            "depends_on_phases": [],
        }],
    }
    with open(os.path.join(work_dir, "phases.json"), "w") as f:
        json.dump(phases, f, indent=2)


def collect_extracted(input_dir: str) -> List[Tuple[str, str]]:
    """Return sorted list of (abs_path, rel_path) for extracted source files."""
    out = []
    for root, _, files in os.walk(input_dir):
        for fname in files:
            ext = fname.rsplit(".", 1)[-1] if "." in fname else ""
            if ext in EXT_TO_LANG:
                ap = os.path.join(root, fname)
                out.append((ap, os.path.relpath(ap, input_dir)))
    return sorted(out, key=lambda t: t[1])


# --- per-function parsing helpers --------------------------------------------

def lang_for(path: str) -> str:
    ext = path.rsplit(".", 1)[-1] if "." in path else ""
    return EXT_TO_LANG.get(ext, "C")


def func_name_from_path(path: str) -> str:
    """Extracted file is <func>.<ext>."""
    return os.path.splitext(os.path.basename(path))[0]


def base_name(n: str) -> str:
    """Strip extract.py's dedupe suffix: foo_1 -> foo."""
    return re.sub(r"_\d+$", "", n)


def number_lines(src: str) -> str:
    """Prefix each line with 'Line N:' for anchor clarity in abstractions."""
    return "\n".join(f"Line {i+1}: {ln}" for i, ln in enumerate(src.splitlines()))


def signature_line(src: str, language: str) -> str:
    """Best-effort first non-comment line as the function signature header."""
    cfg = LANG_CONFIG.get(language.lower(), {})
    cprefix = cfg.get("comment_prefix", "//")
    for ln in src.splitlines():
        s = ln.strip()
        if not s or s.startswith(cprefix) or s.startswith("#") or s.startswith("*"):
            continue
        return s
    lines = src.splitlines()
    return lines[0] if lines else ""


def _split_top_level(text: str, sep: str) -> List[str]:
    """Split text on sep at paren/bracket/brace depth 0."""
    out, depth, cur = [], 0, []
    for ch in text:
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth = max(0, depth - 1)
        if ch == sep and depth == 0:
            out.append("".join(cur))
            cur = []
        else:
            cur.append(ch)
    out.append("".join(cur))
    return out


def extract_params(sig_line: str, language: Optional[str] = None) -> List[str]:
    """Parse formal parameter names from a signature line.

    Handles `def f(a, b):`, `int f(int a, char *b)`, `func F(a int, b string)`.
    Best-effort, name-based. Identifier position depends on the language:
    C/Java/Python annotations put the type first (identifier LAST), Go puts the
    name first.
    """
    m = re.search(r"\(([^)]*)\)", sig_line or "")
    if not m:
        return []
    inner = m.group(1).strip()
    if not inner:
        return []
    name_first = (language or "").lower() in _NAME_FIRST_LANGS
    params = []
    for part in _split_top_level(inner, ","):
        tok = part.strip()
        if not tok or tok in ("void", "self", "cls"):
            continue
        tok = tok.split("=", 1)[0].strip()
        if ":" in tok:
            tok = tok.split(":", 1)[0].strip()
            words = re.findall(r"[A-Za-z_][A-Za-z0-9_]*", tok)
            if words:
                params.append(words[0])
            continue
        words = re.findall(r"[A-Za-z_][A-Za-z0-9_]*", tok)
        if words:
            params.append(words[0] if name_first else words[-1])
    return params


def find_call_arg_lists(src: str, callee_name: str) -> List[List[str]]:
    """Return a list of argument-expression lists for each `callee_name(...)` call."""
    calls = []
    for m in re.finditer(rf"\b{re.escape(callee_name)}\s*\(", src):
        i = m.end() - 1  # position of '('
        depth, j = 0, i
        while j < len(src):
            if src[j] == "(":
                depth += 1
            elif src[j] == ")":
                depth -= 1
                if depth == 0:
                    break
            j += 1
        inner = src[i + 1: j]
        args = [a.strip() for a in _split_top_level(inner, ",")] if inner.strip() else []
        calls.append(args)
    return calls


# --- bottom-up ordering -------------------------------------------------------

def order_bottom_up(units: Sequence[FunctionUnit]) -> List[FunctionUnit]:
    """Order functions so callees precede callers (best-effort, name-based).

    A function f depends on g if f's body references g's name as a call. Simple
    topological sort; cycles fall back to original order. Mirrors
    ifc_main._order_bottom_up.
    """
    names = {u.id.name for u in units}
    deps: Dict[str, set] = {}
    for u in units:
        called = set()
        for other in names:
            if other == u.id.name:
                continue
            if re.search(rf"\b{re.escape(base_name(other))}\s*\(", u.source):
                called.add(other)
        deps[u.id.name] = called
    by_name = {u.id.name: u for u in units}
    ordered, visited, temp = [], set(), set()

    def visit(n: str) -> None:
        if n in visited or n in temp:
            return
        temp.add(n)
        for d in deps.get(n, ()):
            if d in by_name:
                visit(d)
        temp.discard(n)
        visited.add(n)
        ordered.append(by_name[n])

    for u in units:
        visit(u.id.name)
    return ordered


# --- ProgramIndex construction ------------------------------------------------

def _arg_bindings_for(callee_unit: FunctionUnit, args: Sequence[str]) -> Dict[str, str]:
    """Map callee formal sources (param:<name>) to caller actual arg expressions."""
    binding: Dict[str, str] = {}
    for idx, formal in enumerate(callee_unit.params):
        if idx < len(args):
            binding[f"param:{formal}"] = args[idx]
    return binding


def build_program_index(units: Sequence[FunctionUnit]) -> ProgramIndex:
    """Build the call graph, reverse graph, and entrypoint set.

    Edges are name-based (regex), matching call sites by callee BASE name so
    extract.py's dedupe suffixes (foo_1) do not hide that the source calls foo(.
    Entrypoints = functions with no internal caller.
    """
    functions = {u.id: u for u in units}
    by_name: Dict[str, List[FunctionUnit]] = {}
    for u in units:
        by_name.setdefault(u.id.name, []).append(u)

    calls_by_caller: Dict[FunctionId, List[CallSite]] = {u.id: [] for u in units}
    callers_by_callee: Dict[FunctionId, List[CallSite]] = {u.id: [] for u in units}
    called_internally: set = set()

    for caller in units:
        order = 0
        for callee in units:
            if callee.id == caller.id:
                continue
            cb = base_name(callee.id.name)
            arg_lists = find_call_arg_lists(caller.source, cb)
            if not arg_lists:
                continue
            called_internally.add(callee.id)
            for args in arg_lists:
                site = CallSite(
                    caller=caller.id,
                    callee=callee.id,
                    callee_name=cb,
                    order_index=order,
                    arg_bindings=_arg_bindings_for(callee, args),
                    span=SourceSpan(path=caller.id.rel),
                )
                calls_by_caller[caller.id].append(site)
                callers_by_callee[callee.id].append(site)
                order += 1

    entrypoints = [u.id for u in units if u.id not in called_internally]
    return ProgramIndex(
        functions=functions,
        calls_by_caller=calls_by_caller,
        callers_by_callee=callers_by_callee,
        entrypoints=entrypoints,
    )


def load_function_units(proj_dir: str, work_dir: str) -> List[FunctionUnit]:
    """Scan, extract, and load all functions of a project into FunctionUnits."""
    input_dir = os.path.join(work_dir, "extracted_functions")
    source_files = scan_source_files(proj_dir)
    if not source_files:
        return []
    write_minimal_phases(work_dir, proj_dir, source_files)
    run_extraction(proj_dir, work_dir=work_dir, force=True, verbose=False)

    units: List[FunctionUnit] = []
    for ap, rel in collect_extracted(input_dir):
        with open(ap, "r", errors="replace") as f:
            src = f.read()
        language = lang_for(rel)
        sig = signature_line(src, language)
        name = func_name_from_path(rel)
        fid = FunctionId(
            rel=rel,
            name=name,
            base_name=base_name(name),
            language=language,
        )
        units.append(FunctionUnit(
            id=fid,
            source=src,
            signature_line=sig,
            params=tuple(extract_params(sig, language)),
            abs_path=ap,
        ))
    return units

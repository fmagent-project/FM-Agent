"""Call-graph construction helpers (shared by stage5 and stage6)."""

import os
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence, Set, Tuple
from src.extract import EXT_TO_LANG, LANG_CONFIG


# --- local base types (self-contained, no dependency on src/plugins/) ---------

@dataclass(frozen=True)
class SourceSpan:
    path: str
    start_line: int = 0
    end_line: int = 0


@dataclass(frozen=True)
class FunctionId:
    rel: str
    name: str
    base_name: str
    language: str


@dataclass(frozen=True)
class FunctionUnit:
    id: FunctionId
    source: str
    signature_line: str
    params: Sequence[str] = field(default_factory=tuple)
    abs_path: Optional[str] = None


@dataclass(frozen=True)
class CallSite:
    caller: FunctionId
    callee: FunctionId
    callee_name: str
    order_index: int = 0
    arg_bindings: Dict[str, str] = field(default_factory=dict)
    span: Optional[SourceSpan] = None


@dataclass(frozen=True)
class ProgramIndex:
    functions: Dict[FunctionId, FunctionUnit]
    calls_by_caller: Dict[FunctionId, Sequence[CallSite]]
    callers_by_callee: Dict[FunctionId, Sequence[CallSite]]
    entrypoints: Sequence[FunctionId]

_NAME_FIRST_LANGS = {"go"}


# --- identity helpers ---------------------------------------------------------

def base_name(n: str) -> str:
    """Strip extract.py's dedupe suffix: foo_1 -> foo."""
    return re.sub(r"_\d+$", "", n)


def _call_name(name: str) -> str:
    """Return the source-level callable token for a function identifier.

    Keeps the qualified FunctionId unchanged while extracting the final
    callable name used at source call sites.

    Examples:
        Class::check -> check
        namespace::Class::check -> check
        obj.check -> check
    """
    name = base_name(name)
    if "::" in name:
        name = name.rsplit("::", 1)[-1]
    if "." in name:
        name = name.rsplit(".", 1)[-1]
    return name


def function_fqn(fid: FunctionId) -> str:
    """Serialize FunctionId for cross-module FQN matching."""
    return f"{fid.rel}::{fid.name}"


def resolve_fqn(functions, fqn: str):
    """Resolve a codegraph/extra-edge FQN to a local FunctionId.

    Accepts both ``pkg/a.py::helper`` and ``pkg::a-py::helper`` formats.
    Falls back to unique suffix/basename match; ambiguous names return None.
    """
    if not isinstance(fqn, str) or "::" not in fqn:
        return None
    # Exact serialized identity
    for fid in functions:
        if fqn == function_fqn(fid):
            return fid
    rel_raw, name = fqn.rsplit("::", 1)
    rel_raw = rel_raw.replace("\\", "/")
    # Direct source-path match
    for fid in functions:
        if fid.name == name and fid.rel.replace("\\", "/") == rel_raw:
            return fid
    # Convert source path: pkg/a.py → pkg/a-py
    parts = rel_raw.split("/")
    if parts and "." in parts[-1]:
        stem, ext = parts[-1].rsplit(".", 1)
        parts[-1] = f"{stem}-{ext}"
        normalized = "/".join(parts)
        for fid in functions:
            if fid.name == name and fid.rel.replace("\\", "/") == normalized:
                return fid
    # Unique basename fallback
    candidates = [fid for fid in functions if fid.name == name
                  and fid.rel.replace("\\", "/").endswith(rel_raw)]
    if len(candidates) == 1:
        return candidates[0]
    return None


def _signature_line(src: str, language: str) -> str:
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
    """Parse formal parameter names from a function signature.

    Handles:
      - C/Java: ``int foo(int x, char *name)``
      - Go functions: ``func Foo(x string, n int)``
      - Go methods: ``func (s *Server) Echo(x string)``
      - Python: ``def foo(x, y=1)``
    """
    language = (language or "").lower()
    sig_line = sig_line or ""

    if language == "go":
        go_method = re.search(
            r"\bfunc\s*\([^)]*\)\s*[A-Za-z_][A-Za-z0-9_]*\s*"
            r"\(([^)]*)\)",
            sig_line,
        )
        if go_method:
            inner = go_method.group(1).strip()
        else:
            m = re.search(
                r"\bfunc\s+[A-Za-z_][A-Za-z0-9_]*\s*\(([^)]*)\)",
                sig_line,
            )
            if not m:
                return []
            inner = m.group(1).strip()
    else:
        m = re.search(r"\(([^)]*)\)", sig_line or "")
        if not m:
            return []
        inner = m.group(1).strip()

    if not inner:
        return []

    name_first = language in _NAME_FIRST_LANGS
    params = []
    for part in _split_top_level(inner, ","):
        tok = part.strip()
        if not tok or tok in ("void", "self", "cls"):
            continue
        tok = tok.split("=", 1)[0].strip()
        if ":" in tok and language == "python":
            name = tok.split(":", 1)[0].strip()
            if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name):
                params.append(name)
            continue
        words = re.findall(r"[A-Za-z_][A-Za-z0-9_]*", tok)
        if words:
            params.append(words[0] if name_first else words[-1])
    return params


# --- call-site parsing -------------------------------------------------------

def _find_python_call_arg_lists(src: str, callee_name: str) -> List[List[str]]:
    """Find Python calls using AST instead of substring matching."""
    import ast
    import textwrap
    try:
        tree = ast.parse(textwrap.dedent(src))
    except (SyntaxError, TypeError, ValueError):
        return []
    calls = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        if isinstance(func, ast.Name):
            name = func.id
        elif isinstance(func, ast.Attribute):
            name = func.attr
        else:
            continue
        if name != callee_name:
            continue
        args = []
        for arg in node.args:
            try:
                args.append(ast.unparse(arg))
            except Exception:
                args.append("")
        for keyword in node.keywords:
            if keyword.arg is None:
                continue
            try:
                value = ast.unparse(keyword.value)
            except Exception:
                value = ""
            args.append(f"{keyword.arg}={value}")
        calls.append(args)
    return calls


def find_call_arg_lists(
    src: str,
    callee_name: str,
    language: Optional[str] = None,
) -> List[List[str]]:
    """Return a list of argument-expression lists for each ``callee_name(...)`` call.

    For Python, uses AST so identifiers inside strings/comments and
    declarations are never treated as calls.
    """
    if (language or "").lower() == "python":
        return _find_python_call_arg_lists(src, callee_name)

    calls = []
    for m in re.finditer(rf"\b{re.escape(callee_name)}\s*\(", src):
        if callee_name == "__init__" and m.start() > 0 and src[m.start() - 1] == ".":
            continue
        i = m.end() - 1
        depth, j = 0, i
        while j < len(src):
            if src[j] == "(":
                depth += 1
            elif src[j] == ")":
                depth -= 1
                if depth == 0:
                    break
            j += 1
        line_start = src.rfind("\n", 0, m.start()) + 1
        prefix = src[line_start:m.start()]
        remainder = src[j + 1:]
        if _looks_like_declaration(prefix, remainder):
            continue
        inner = src[i + 1: j]
        args = [a.strip() for a in _split_top_level(inner, ",")] if inner.strip() else []
        calls.append(args)
    return calls


def _looks_like_declaration(line_prefix: str, remainder: str) -> bool:
    if re.search(r"\b(?:def|function|func|fn)\b", line_prefix):
        return True
    if remainder.lstrip().startswith("{") and not re.search(
        r"[.=]|\b(?:return|if|for|while|switch|new)\b", line_prefix
    ):
        return bool(re.search(r"[A-Za-z_][A-Za-z0-9_]*\s+$", line_prefix))
    return False


# --- FunctionUnit loading from extracted_functions/ ---------------------------

def load_units_from_extracted(work_dir: str) -> List[FunctionUnit]:
    """Load FunctionUnit list from Stage 3's extracted_functions/ directory.

    Reuses FM-Agent's extraction output; never re-extracts.
    """
    input_dir = os.path.join(work_dir, "extracted_functions")
    if not os.path.isdir(input_dir):
        return []
    units = []
    for root, _, files in os.walk(input_dir):
        for fname in files:
            ext = fname.rsplit(".", 1)[-1] if "." in fname else ""
            if ext not in EXT_TO_LANG:
                continue
            abs_path = os.path.join(root, fname)
            rel = os.path.relpath(abs_path, input_dir)
            try:
                with open(abs_path, "r", errors="replace") as f:
                    src = f.read()
            except OSError:
                continue
            language = EXT_TO_LANG.get(ext, "C").lower()
            sig = _signature_line(src, language)
            name = os.path.splitext(fname)[0]
            bn = base_name(name)
            params = tuple(extract_params(sig, language))
            fid = FunctionId(rel=rel, name=name, base_name=bn, language=language)
            units.append(FunctionUnit(
                id=fid, source=src, signature_line=sig,
                params=params, abs_path=abs_path,
            ))
    return units


# --- ProgramIndex construction ------------------------------------------------

def _keyword_arg_name(arg: str) -> Optional[str]:
    """Return the formal name for a keyword argument, if present."""
    match = re.match(
        r"^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=(?!=)",
        arg or "",
    )
    return match.group(1) if match else None


def _arg_bindings_for(unit: FunctionUnit, args: Sequence[str]) -> Dict[str, str]:
    """Map callee formals to actual argument expressions.

    Keyword arguments are matched by formal name first. Remaining positional
    arguments are then assigned to the next unbound formal parameter.
    """
    binding: Dict[str, str] = {}
    params = list(unit.params)

    # Pass 1: keyword arguments.
    positional_args = []
    for arg in args:
        keyword = _keyword_arg_name(arg)
        if keyword is not None and keyword in params:
            binding[f"param:{keyword}"] = arg.split("=", 1)[1].strip()
        else:
            positional_args.append(arg)

    # Pass 2: positional arguments fill the remaining formals in order.
    remaining_params = [
        formal for formal in params
        if f"param:{formal}" not in binding
    ]
    for formal, arg in zip(remaining_params, positional_args):
        binding[f"param:{formal}"] = arg.strip()

    return binding


def build_program_index(
    units: List[FunctionUnit],
    exact_edges: Optional[Sequence[dict]] = None,
) -> ProgramIndex:
    """Build ProgramIndex from extracted units.

    Edge resolution priority:
        1. exact_edges from codegraph (FQN → FQN, node-ID resolved)
        2. regex/source fallback for unresolved calls

    Exact codegraph identities are never re-resolved by bare name.
    Ambiguous source-level names are rejected (fail-closed).
    """
    functions = {u.id: u for u in units}
    fn_by_fqn = {function_fqn(fid): fid for fid in functions}

    calls_by_caller: Dict[FunctionId, List[CallSite]] = {u.id: [] for u in units}
    callers_by_callee: Dict[FunctionId, List[CallSite]] = {u.id: [] for u in units}
    exact_pairs: Set[tuple] = set()

    # Layer 1: exact codegraph/extended edges
    for edge in exact_edges or []:
        caller_id = fn_by_fqn.get(edge["caller"])
        callee_id = fn_by_fqn.get(edge["callee"])
        if caller_id is None or callee_id is None:
            continue
        pair = (caller_id, callee_id)
        if pair in exact_pairs:
            continue
        exact_pairs.add(pair)

        call_name = _call_name(callee_id.name)
        arg_lists = find_call_arg_lists(
            functions[caller_id].source, call_name,
            language=caller_id.language)
        if not arg_lists:
            arg_lists = [[]]
        for args in arg_lists:
            site = CallSite(
                caller=caller_id, callee=callee_id,
                callee_name=call_name,
                order_index=len(calls_by_caller[caller_id]),
                arg_bindings=_arg_bindings_for(functions[callee_id], args),
                span=SourceSpan(path=caller_id.rel),
            )
            calls_by_caller[caller_id].append(site)
            callers_by_callee[callee_id].append(site)

    # Layer 2: regex fallback (unique-name only)
    by_call_name: Dict[str, List[FunctionUnit]] = {}
    for unit in units:
        cn = _call_name(unit.id.name)
        by_call_name.setdefault(cn, []).append(unit)

    for caller in units:
        for call_name, candidates in by_call_name.items():
            if len(candidates) != 1:
                continue
            callee = candidates[0]
            if callee.id == caller.id:
                continue
            pair = (caller.id, callee.id)
            if pair in exact_pairs:
                continue
            arg_lists = find_call_arg_lists(
                caller.source, call_name,
                language=caller.id.language)
            if not arg_lists:
                continue
            for args in arg_lists:
                site = CallSite(
                    caller=caller.id, callee=callee.id,
                    callee_name=call_name,
                    order_index=len(calls_by_caller[caller.id]),
                    arg_bindings=_arg_bindings_for(callee, args),
                    span=SourceSpan(path=caller.id.rel),
                )
                calls_by_caller[caller.id].append(site)
                callers_by_callee[callee.id].append(site)
            exact_pairs.add(pair)

    called = {s.callee for sites in callers_by_callee.values() for s in sites}
    entrypoints = [fid for fid in functions if fid not in called]
    return ProgramIndex(
        functions=functions,
        calls_by_caller=calls_by_caller,
        callers_by_callee=callers_by_callee,
        entrypoints=entrypoints,
    )


# --- bottom-up ordering (with SCC detection) ----------------------------------

def order_bottom_up(units: List[FunctionUnit]) -> Tuple[
    List[FunctionUnit], List[List[dict]], List[FunctionUnit]
]:
    """Topological sort + SCC cycle detection + isolated-node identification.

    Ambiguous source-level callable names are not treated as call edges.
    """
    deps: Dict[FunctionId, Set[FunctionId]] = {u.id: set() for u in units}
    by_id = {u.id: u for u in units}

    by_call_name: Dict[str, List[FunctionUnit]] = {}
    for unit in units:
        cn = _call_name(unit.id.name)
        by_call_name.setdefault(cn, []).append(unit)

    for u in units:
        for name, candidates in by_call_name.items():
            if len(candidates) != 1:
                continue
            other = candidates[0]
            if other.id == u.id:
                continue
            escaped = re.escape(name)
            if re.search(rf"\b{escaped}\s*\(", u.source):
                deps[u.id].add(other.id)

    index, lowlink = {}, {}
    stack, on_stack = [], set()
    sccs = []
    idx = [0]

    def strongconnect(v: FunctionId):
        index[v], lowlink[v] = idx[0], idx[0]
        idx[0] += 1
        stack.append(v)
        on_stack.add(v)
        for w in deps.get(v, set()):
            if w not in index:
                strongconnect(w)
                lowlink[v] = min(lowlink[v], lowlink[w])
            elif w in on_stack:
                lowlink[v] = min(lowlink[v], index[w])
        if lowlink[v] == index[v]:
            scc = []
            while True:
                w = stack.pop()
                on_stack.discard(w)
                scc.append(w)
                if w == v:
                    break
            sccs.append(scc)

    for u in units:
        if u.id not in index:
            strongconnect(u.id)

    cycles = []
    ordered = []
    for scc in sccs:
        members = [{"rel": fid.rel, "name": fid.name} for fid in scc
                   if fid in by_id]
        if len(scc) > 1:
            cycles.append(members)
        else:
            fid = scc[0]
            if fid in deps.get(fid, set()):
                cycles.append(members)
            elif fid in by_id:
                ordered.append(by_id[fid])

    all_in_order = set()
    for u in ordered:
        all_in_order.add(u.id)
    for scc in sccs:
        for fid in scc:
            if fid in by_id:
                all_in_order.add(fid)
    unreachable = [u for u in units if u.id not in all_in_order]

    return ordered, cycles, unreachable


def order_bottom_up_from_program(
    program: ProgramIndex,
) -> Tuple[List[FunctionUnit], List[List[dict]], List[FunctionUnit]]:
    """Order functions using the already-resolved ProgramIndex.

    Unlike ``order_bottom_up`` which re-scans source code, this uses the
    resolved ``calls_by_caller`` edges — including those from extra edges.
    """
    units = list(program.functions.values())
    deps: Dict[FunctionId, Set[FunctionId]] = {
        fid: set() for fid in program.functions
    }
    for caller, calls in program.calls_by_caller.items():
        if caller in deps:
            for call in calls:
                deps[caller].add(call.callee)

    index, lowlink = {}, {}
    stack, on_stack = [], set()
    sccs = []
    idx = [0]

    def strongconnect(v):
        index[v], lowlink[v] = idx[0], idx[0]
        idx[0] += 1
        stack.append(v)
        on_stack.add(v)
        for w in deps.get(v, set()):
            if w not in index:
                strongconnect(w)
                lowlink[v] = min(lowlink[v], lowlink[w])
            elif w in on_stack:
                lowlink[v] = min(lowlink[v], index[w])
        if lowlink[v] == index[v]:
            scc = []
            while True:
                w = stack.pop()
                on_stack.discard(w)
                scc.append(w)
                if w == v:
                    break
            sccs.append(scc)

    for fid in program.functions:
        if fid not in index:
            strongconnect(fid)

    cycles, ordered = [], []
    by_id = program.functions
    for scc in sccs:
        members = [{"rel": fid.rel, "name": fid.name}
                   for fid in scc if fid in by_id]
        if len(scc) > 1:
            cycles.append(members)
        else:
            fid = scc[0]
            if fid in deps.get(fid, set()):
                cycles.append(members)
            elif fid in by_id:
                ordered.append(by_id[fid])

    all_ids = {fid for scc in sccs for fid in scc if fid in by_id}
    unreachable = [u for u in units if u.id not in all_ids]
    return ordered, cycles, unreachable

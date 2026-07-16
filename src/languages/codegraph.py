"""
CodeGraph backend for FM-Agent function extraction and call graph building.

Requires the user to have run `codegraph init` in the project directory first,
which produces `.codegraph/codegraph.db` (SQLite).

To add support for a new language: create src/languages/<lang>.py and add an entry to
REGISTRY in src/languages/registry.py. No other files need to change.
"""

import hashlib
import logging
import os
import re
import shutil
import sqlite3
import subprocess
from collections import defaultdict


_SAFE_REPLACE = str.maketrans({"/": "_"})
_UNSAFE = set("/")


def canonicalize(func_name):
    """Return a filesystem-safe, FQN-safe version of a function name.

    C++ operator overloads like ``operator/`` contain ``/`` which breaks both
    file paths and ``::``-separated FQNs.  This function sanitises those
    characters so the name is safe everywhere it appears: extracted-function
    file names, FQNs, call-edge keys, and scope.py rankings.

    Every entry point that introduces a function name into the system MUST call
    this function before using the name.
    """
    if not func_name:
        return func_name
    for ch in _UNSAFE:
        if ch in func_name:
            return func_name.translate(_SAFE_REPLACE)
    return func_name


def _qualified_parts(name: str, qualified_name: str) -> list:
    """Split codegraph's ``qualified_name`` into ``[*scope_parts, name]``.

    Member functions carry their enclosing class (and namespace) so they can be
    told apart by class instead of by an opaque line-order suffix:

        free function ``main``                 -> ``['main']``
        C++ ``LocalStorage::Flush``            -> ``['LocalStorage', 'Flush']``
        nested ``ns::Widget::draw``            -> ``['ns', 'Widget', 'draw']``
        dot-scoped (Python/Java) ``Foo.bar``   -> ``['Foo', 'bar']``

    codegraph joins scopes with ``::`` (C/C++) or ``.`` (Python, Java, ...); both
    are normalised here. If ``qualified_name`` is missing or does not end with
    ``name`` (unexpected shape), we fall back to the bare name so behaviour never
    regresses below the previous name-only scheme.
    """
    q = (qualified_name or "").strip()
    if not q or not q.endswith(name):
        return [name]
    scope = q[: -len(name)].rstrip(":.")
    if not scope:
        return [name]
    parts = [p for p in re.split(r"::|\.", scope) if p]
    return parts + [name]


def _extraction_ident(name: str, qualified_name: str) -> str:
    """Return the class-qualified, filesystem-safe identifier for a function.

    Each component is first stripped of any tree-sitter decoration by
    :func:`_bare_function_name` (codegraph occasionally stores a whole signature
    or template body in the name column — see issue #82, which would otherwise
    blow past the filesystem's filename limit), then passed through
    :func:`canonicalize` (so a class-scoped operator like ``Store::operator/``
    stays path/FQN-safe), then joined with ``::``. This single string is used both
    as a function's FQN tail and — with ``::`` turned into path separators — as its
    extracted-file location, so the call edges (via :func:`_node_fqn_map`) and the
    extracted files (via ``run_extraction`` + ``_file_to_fqn``) always agree.
    Examples: ``main`` -> ``"main"``; ``LocalStorage::Flush`` ->
    ``"LocalStorage::Flush"``.
    """
    return "::".join(
        canonicalize(_bare_function_name(p))
        for p in _qualified_parts(name, qualified_name)
    )


def _bare_function_name(name: str) -> str:
    """Extract the bare function identifier from a potentially decorated name.

    Tree-sitter sometimes stores a full function signature in the name column
    for macro-generated C/C++ declarations (e.g. ``(*func)(type *param)``
    instead of ``func``).  Strips decorations so the result can be used as a
    filename stem and call-edge key.

    Handled patterns (language-agnostic):
    - Simple identifier: ``"my_func"`` -> ``"my_func"``
    - Qualified name: ``"ns::Cls::method"`` -> ``"method"``
    - Go pointer receiver: ``"(*T).Method"`` -> ``"Method"``
    - Function-pointer: ``"(*func)(type *param)"`` -> ``"func"``
    - Pointer return: ``"*func_name(...)"`` -> ``"func_name"``
    - this-dot: ``"this.onClick"`` -> ``"onClick"``
    - Empty: ``""`` -> ``""`` (caller falls back to ``_function``)
    """
    name = name.strip()
    if not name:
        return ""

    m = re.search(r'(?:[:\.)])(\w+)$', name)
    if m:
        return m.group(1)
    m = re.match(r'\(\s*\*\s*(\w+)\s*\)', name)
    if m:
        return m.group(1)
    m = re.match(r'\*\s*(\w+)', name)
    if m:
        return m.group(1)
    m = re.match(r'^(\w+)', name)
    if m:
        return m.group(1)
    return name


# Maps FM-Agent lang_key → the language string stored in codegraph's SQLite
# nodes.language column. Only includes languages that codegraph actually supports.
# ArkTS is omitted (not supported by codegraph).
# CUDA: .cu is not in codegraph's built-in extension list and will not be indexed.
#   To enable partial CUDA support, add {"extensions": {".cu": "cpp"}} to a
#   codegraph.json file at the project root — codegraph will then parse .cu files
#   using the C++ grammar. This workaround has not been verified.
_CG_LANG = {
    "python":     ["python"],
    "go":         ["go"],
    "rust":       ["rust"],
    "c":          ["c"],
    "cpp":        ["cpp"],
    "cuda":       ["cpp"],  # .cu is not natively indexed by codegraph; kept for future use
    "java":       ["java"],
    "javascript": ["javascript", "jsx"],  # codegraph stores .jsx files as language='jsx'
    "typescript": ["typescript", "tsx"],  # codegraph stores .tsx files as language='tsx'
}

# SQL fragment used to match the constructor method node when resolving
# `instantiates` edges.  The fragment references two aliases from the query:
#   cls  — the class node being instantiated
#   ctor — a method/function node contained by cls
# Languages without traditional constructors (go, rust, c) are omitted;
# their instantiates edges (if any) are ignored.
# C++ note: codegraph does not record `instantiates` edges for stack-allocation
# syntax (`MyClass obj(args)`), so this entry has no practical effect today.
_CONSTRUCTOR_FILTER = {
    "python":     "ctor.name = '__init__'",
    "typescript": "ctor.name = 'constructor'",
    "javascript": "ctor.name = 'constructor'",
    "java":       "ctor.name = cls.name",
    "cpp":        "ctor.name = cls.name",
}


def _fqn_for(file_path: str, name: str) -> str:
    """Build the FQN of a function, identical to generate_topdown_layers._file_to_fqn.

    The extracted layout for a source file ``<dir>/<base>.<ext>`` is
    ``<dir>/<base>-<ext>/<name>.<ext>``, whose FQN is ``dir::base-ext::name``.
    Constructing the same string here lets get_call_edges emit edges keyed by the
    exact same FQN the call-graph builder assigns to each extracted function, so
    codegraph's precisely-resolved caller/callee node identity is preserved
    instead of being collapsed to a bare name.
    """
    norm = file_path.replace(os.sep, "/")
    d = os.path.dirname(norm)
    base = os.path.basename(norm)
    last_dot = base.rfind(".")
    dashed = base[:last_dot] + "-" + base[last_dot + 1:] if last_dot > 0 else base
    parts = [p for p in d.split("/") if p]
    parts += [dashed, name]
    return "::".join(parts)


def _node_fqn_map(cur, cg_langs) -> dict:
    """Return {node_id: fqn} for every function/method node in the given languages.

    The per-file name dedup (``Flush``, ``Flush_1``, ...) uses the SAME rule and
    ordering as get_functions_by_file (``ORDER BY file_path, start_line``, then a
    per-(file, name) counter), so the FQN assigned to a node here matches the FQN
    the extracted file for that node receives. Keeping the two in lockstep is what
    makes the call-edge identities line up with the extracted-function identities.
    """
    placeholders = ",".join("?" * len(cg_langs))
    cur.execute(
        f"""
        SELECT id, name, qualified_name, file_path, start_line
        FROM nodes
        WHERE kind IN ('function', 'method') AND language IN ({placeholders})
        ORDER BY file_path, start_line
        """,
        cg_langs,
    )
    counts: dict = {}
    result: dict = {}
    for node_id, name, qualified_name, file_path, _start in cur.fetchall():
        ident = _extraction_ident(name, qualified_name)
        key = (file_path, ident)
        c = counts.get(key, 0)
        counts[key] = c + 1
        deduped = ident if c == 0 else f"{ident}_{c}"
        result[node_id] = _fqn_for(file_path, deduped)
    return result


class CodeGraphExtractor:
    """Query a codegraph SQLite database to extract functions and call edges."""

    def __init__(self, db_path: str):
        self._db = db_path

    @classmethod
    def from_proj_dir(cls, proj_dir: str):
        """Return an extractor if .codegraph/codegraph.db exists, else None.

        Checks both proj_dir itself and its parent directory, because
        generate_topdown_layers() receives work_dir (fm_agent/) as its
        proj_dir argument, while codegraph init runs in the real project root.
        """
        for candidate in [proj_dir, os.path.dirname(os.path.abspath(proj_dir))]:
            db_path = os.path.join(candidate, ".codegraph", "codegraph.db")
            if os.path.exists(db_path):
                return cls(db_path)
        return None

    def get_functions_by_file(self, lang_key: str, proj_dir: str = None) -> dict:
        """Return {abs_filepath: [(func_name, body_text), ...]} for all files.

        body_text is the raw source lines for that function, matching the format
        that extract_functions_from_file returns.

        proj_dir must be supplied so that the relative file paths stored by
        codegraph can be resolved to absolute paths for opening and for dict
        key lookup in run_extraction.
        """
        cg_langs = _CG_LANG.get(lang_key)
        if not cg_langs:
            return {}

        conn = sqlite3.connect(self._db)
        cur = conn.cursor()
        placeholders = ",".join("?" * len(cg_langs))
        cur.execute(
            f"""
            SELECT name, qualified_name, file_path, start_line, end_line
            FROM nodes
            WHERE kind IN ('function', 'method') AND language IN ({placeholders})
            ORDER BY file_path, start_line
            """,
            cg_langs,
        )
        rows = cur.fetchall()
        conn.close()

        by_file = defaultdict(list)
        for name, qualified_name, file_path, start_line, end_line in rows:
            ident = _extraction_ident(name, qualified_name)
            by_file[file_path].append((ident, int(start_line), int(end_line)))

        result = {}
        for file_path, funcs in by_file.items():
            abs_path = os.path.join(proj_dir, file_path) if proj_dir else file_path
            try:
                with open(abs_path, "r", errors="replace") as f:
                    all_lines = f.readlines()
            except OSError:
                continue

            ident_counts = {}
            file_funcs = []
            for ident, start_line, end_line in funcs:
                # ``ident`` is the class-qualified identifier ("LocalStorage::Flush",
                # or the bare name for a free function). Member functions in
                # different classes are already distinct here, so the class name —
                # not an opaque line-order suffix — is what tells them apart.
                # A suffix is still appended only when two functions share the exact
                # same qualified identifier (e.g. overloads: same class + same name,
                # different parameters), which would otherwise overwrite each other
                # ("LocalStorage::Flush", "LocalStorage::Flush_1"). funcs are
                # line-ordered (SQL ORDER BY start_line), so the suffix is
                # deterministic. run_extraction keeps the "::" in the flat filename.
                count = ident_counts.get(ident, 0)
                ident_counts[ident] = count + 1
                deduped = ident if count == 0 else f"{ident}_{count}"
                # codegraph uses 1-indexed lines, end_line is inclusive
                body_lines = all_lines[start_line - 1 : end_line]
                body = "".join(body_lines)
                if not body.endswith("\n"):
                    body += "\n"
                file_funcs.append((deduped, body))

            result[abs_path] = file_funcs

        return result

    def get_function_spans(self, lang_key: str, abs_filepath: str):
        """Return ``[(name, start_idx, end_idx), ...]`` for a single file, or None.

        Line indices are 0-indexed and inclusive, matching the convention the
        regex extractor (_extract_functions_brace / _extract_functions_indent)
        uses, so callers can rewrite the file by line index. Functions are
        ordered by their starting line.

        Returns None when codegraph does not support ``lang_key`` or when the
        file is not present in the index (e.g. it was never indexed) — the
        caller then falls back to the regex extractor. An indexed file that
        genuinely contains no functions also yields None, which is harmless:
        the regex fallback finds none either.
        """
        cg_langs = _CG_LANG.get(lang_key)
        if not cg_langs:
            return None

        # codegraph stores file paths relative to the project root, which is the
        # parent of the .codegraph/ directory holding the database.
        root = os.path.dirname(os.path.dirname(os.path.abspath(self._db)))
        rel = os.path.relpath(os.path.abspath(abs_filepath), root)

        conn = sqlite3.connect(self._db)
        cur = conn.cursor()
        placeholders = ",".join("?" * len(cg_langs))
        cur.execute(
            f"""
            SELECT name, qualified_name, start_line, end_line
            FROM nodes
            WHERE kind IN ('function', 'method') AND language IN ({placeholders})
              AND file_path = ?
            ORDER BY start_line
            """,
            (*cg_langs, rel),
        )
        rows = cur.fetchall()
        conn.close()

        if not rows:
            return None
        # codegraph uses 1-indexed lines with an inclusive end_line. Return the
        # class-qualified identifier so the caller's dedup + name matching (trim)
        # stays consistent with the extracted files and the call graph.
        return [
            (_extraction_ident(name, qualified_name), int(start) - 1, int(end) - 1)
            for name, qualified_name, start, end in rows
        ]

    def get_call_edges(self, lang_key: str) -> dict:
        """Return {caller_fqn: {callee_fqn, ...}} for the given language.

        Each FQN matches generate_topdown_layers._file_to_fqn for the
        corresponding extracted function (``dir::file-ext::dedup_name``). Edges
        are resolved by codegraph NODE ID (not by bare name), so the precise
        caller/callee identity codegraph computed — which file, which same-named
        sibling — is preserved end-to-end. This lets the call-graph builder use
        the edges directly instead of re-resolving bare names against every
        same-named function (which collapsed siblings and over-approximated
        across files).

        Constructor calls are synthesised from `instantiates` edges: when a
        function instantiates a class, the corresponding constructor method is
        added as a callee.  See _CONSTRUCTOR_FILTER for per-language details.

        NOTE: codegraph itself collapses calls to same-named classes in different
        files onto the first definition (a codegraph resolver limitation for C++,
        not addressable here — see issues/codegraph-samename-class-resolution).
        """
        cg_langs = _CG_LANG.get(lang_key)
        if not cg_langs:
            return {}

        conn = sqlite3.connect(self._db)
        cur = conn.cursor()
        placeholders = ",".join("?" * len(cg_langs))

        # Map every function/method node to its FQN once, using the same per-file
        # dedup as get_functions_by_file, then resolve edges by node id.
        fqn_of = _node_fqn_map(cur, cg_langs)

        result = defaultdict(set)

        # Query 1: regular function/method calls, kept as (source_id, target_id)
        # so each endpoint resolves to its exact node's FQN.
        cur.execute(
            f"""
            SELECT e.source, e.target
            FROM edges e
            JOIN nodes s ON e.source = s.id
            WHERE e.kind = 'calls' AND s.language IN ({placeholders})
            """,
            cg_langs,
        )
        for src_id, tgt_id in cur.fetchall():
            caller, callee = fqn_of.get(src_id), fqn_of.get(tgt_id)
            if caller and callee:
                result[caller].add(callee)

        # Query 2: constructor calls synthesised from instantiates edges.
        # For each `caller instantiates ClassName` edge, find the constructor
        # method inside that class and add it as a synthetic callee.
        ctor_filter = _CONSTRUCTOR_FILTER.get(lang_key)
        if ctor_filter:
            cur.execute(
                f"""
                SELECT e.source, ctor.id
                FROM edges e
                JOIN nodes s   ON e.source = s.id
                JOIN nodes cls ON e.target = cls.id AND cls.kind = 'class'
                JOIN edges ce  ON ce.source = cls.id AND ce.kind = 'contains'
                JOIN nodes ctor ON ce.target = ctor.id
                               AND ctor.kind IN ('method', 'function')
                WHERE e.kind = 'instantiates' AND s.language IN ({placeholders})
                AND {ctor_filter}
                """,
                cg_langs,
            )
            for src_id, ctor_id in cur.fetchall():
                caller, callee = fqn_of.get(src_id), fqn_of.get(ctor_id)
                if caller and callee:
                    result[caller].add(callee)

        conn.close()
        return dict(result)


def try_codegraph_init(proj_dir: str, force: bool = True) -> None:
    """Build the codegraph index for proj_dir with `codegraph init`.

    By default (``force=True``) any existing index is discarded and rebuilt, so
    the index always reflects the current working tree rather than whatever code
    was present when it was last built. This is the safe default: callers read
    function bodies and spans from the index, and a stale one (e.g. after an
    incremental run's tree changed, or after `_trim_project_in_place` edited the
    sources) would yield boundaries for the wrong code. `codegraph init` on its
    own no-ops when `.codegraph/` already exists, so a rebuild requires clearing
    it first.

    Pass ``force=False`` to keep an existing index and only build when it is
    absent — an opt-in optimization for callers that know the tree is unchanged
    since the index was built.

    Silently skips when codegraph is not installed so the pipeline falls back
    to the regex-based extractor without any error.
    """
    codegraph_dir = os.path.join(proj_dir, ".codegraph")
    db_path = os.path.join(codegraph_dir, "codegraph.db")
    if os.path.exists(db_path):
        if not force:
            return
        # Existing index may reflect stale sources; remove it so `codegraph init`
        # rebuilds against the current tree instead of skipping.
        shutil.rmtree(codegraph_dir, ignore_errors=True)
        print("[Pipeline] Rebuilding codegraph index for current working tree...")
    else:
        print("[Pipeline] Building codegraph index...")
    try:
        result = subprocess.run(
            ["codegraph", "init"], cwd=proj_dir, capture_output=True, text=True
        )
    except FileNotFoundError:
        return  # codegraph not installed
    if result.returncode == 0:
        print("[Pipeline] codegraph index built.")
    else:
        logging.warning(
            "codegraph init failed (non-fatal, falling back to regex): %s",
            result.stderr[:300],
        )

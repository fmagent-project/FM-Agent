"""
CodeGraph backend for FM-Agent function extraction and call graph building.

Requires the user to have run `codegraph init` in the project directory first,
which produces `.codegraph/codegraph.db` (SQLite).

To add support for a new language: create src/languages/<lang>.py and add an entry to
REGISTRY in src/languages/registry.py. No other files need to change.
"""

import functools
import hashlib
import logging
import os
import re
import shutil
import sqlite3
import subprocess
import sys
import urllib.request
from collections import defaultdict

from config import settings


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
    - C++ operator overload: ``"Vec::operator=="`` -> ``"operator=="``
    - Function-pointer: ``"(*func)(type *param)"`` -> ``"func"``
    - Pointer return: ``"*func_name(...)"`` -> ``"func_name"``
    - this-dot: ``"this.onClick"`` -> ``"onClick"``
    - Empty: ``""`` -> ``""`` (caller falls back to ``_function``)
    """
    name = name.strip()
    if not name:
        return ""

    tail = name
    if "::" in tail:
        tail = tail.rsplit("::", 1)[1].lstrip()
    elif "." in tail:
        tail = tail.rsplit(".", 1)[1].lstrip()

    if tail.startswith("operator"):
        rest = tail[len("operator"):].lstrip()
        if rest.startswith("[]"):
            return "operator[]"
        if rest.startswith("()"):
            return "operator()"
        if re.fullmatch(r'new(?:\s*\[\s*\])?', rest):
            return "operator new[]" if "[" in rest else "operator new"
        if re.fullmatch(r'delete(?:\s*\[\s*\])?', rest):
            return "operator delete[]" if "[" in rest else "operator delete"

        symbol = []
        for ch in rest:
            if ch in "+-*/%&|^~!=<>,":
                symbol.append(ch)
            else:
                break
        if symbol:
            return "operator" + "".join(symbol)

    m = re.search(r'(?:^|::|\.)(\w+)$', name)
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
    "arkts":      ["arkts"],
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
    "arkts":      "ctor.name = 'constructor'",
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

    @staticmethod
    def _is_readable_index(db_path: str) -> bool:
        """True when ``db_path`` holds an index that was built to completion.

        Existing on disk is not enough: ``codegraph index`` discards the old
        database before it starts, so a rebuild that fails or is killed leaves an
        empty or half-written one behind, and reading that yields a truncated
        graph presented as the whole thing. codegraph stamps its own verdict in
        ``project_metadata.index_state`` for exactly this purpose, so that
        decides. No marker means an index predating it — accept those when they
        actually hold nodes.
        """
        try:
            conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
            try:
                row = conn.execute(
                    "SELECT value FROM project_metadata WHERE key = 'index_state'"
                ).fetchone()
                if row is not None:
                    return row[0] == "complete"
                return (
                    conn.execute("SELECT 1 FROM nodes LIMIT 1").fetchone() is not None
                )
            finally:
                conn.close()
        except sqlite3.Error:
            return False

    @classmethod
    def from_proj_dir(cls, proj_dir: str):
        """Return an extractor if a readable .codegraph/codegraph.db exists, else None.

        Checks both proj_dir itself and its parent directory, because
        generate_topdown_layers() receives work_dir (fm_agent/) as its
        proj_dir argument, while codegraph init runs in the real project root.
        """
        for candidate in [proj_dir, os.path.dirname(os.path.abspath(proj_dir))]:
            db_path = os.path.join(candidate, ".codegraph", "codegraph.db")
            if os.path.exists(db_path) and cls._is_readable_index(db_path):
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

    def get_call_edges(self, lang_key: str) -> list:
        """Return precisely resolved call edges for the given language.

        Each edge preserves exact codegraph node identity through the extracted-
        function FQN. No bare-name resolution is performed here.

        Returns a list of ``{"caller": fqn, "callee": fqn, "kind": str,
        "span": {...}}`` dicts, ordered by source location so call-site order
        aligns with the source appearance order.
        """
        cg_langs = _CG_LANG.get(lang_key)
        if not cg_langs:
            return []

        conn = sqlite3.connect(self._db)
        cur = conn.cursor()
        placeholders = ",".join("?" * len(cg_langs))

        # Map every function/method node to its FQN once, using the same per-file
        # dedup as get_functions_by_file, then resolve edges by node id.
        fqn_of = _node_fqn_map(cur, cg_langs)

        result = []
        seen = set()

        # Query 1: regular function/method calls, kept as (source_id, target_id)
        # so each endpoint resolves to its exact node's FQN.
        # Call-site coordinates come from the EDGE (e.line/e.col), not the caller
        # function node (s.start_line is the function DEFINITION location). The
        # caller node provides the source FILE identity (the call site is always
        # inside the caller's file), while the edge provides the precise
        # call-site line/column. ORDER BY the edge coordinates so multiple call
        # sites of the same callee are returned in true source order.
        cur.execute(
            f"""
            SELECT e.source, e.target, s.file_path, e.line, e.col
            FROM edges e
            JOIN nodes s ON e.source = s.id
            WHERE e.kind = 'calls' AND s.language IN ({placeholders})
            ORDER BY s.file_path, e.line, e.col
            """,
            cg_langs,
        )
        for src_id, tgt_id, file_path, start_line, start_col in cur.fetchall():
            caller, callee = fqn_of.get(src_id), fqn_of.get(tgt_id)
            if not caller or not callee:
                continue
            # Dedup key includes call-site coordinates so multiple call sites
            # of the same callee within one function are all preserved; without
            # them, the 2nd and later calls would be dropped (breaking
            # order_index / arg_bindings).
            if start_line and start_line > 0:
                key = (caller, callee, "call", file_path, start_line, start_col)
                if key in seen:
                    continue
                seen.add(key)
            result.append({
                "caller": caller,
                "callee": callee,
                "kind": "call",
                "span": {
                    "file": file_path,
                    "start_line": start_line,
                    "start_column": start_col,
                },
            })

        # Query 2: constructor calls synthesised from instantiates edges.
        # For each `caller instantiates ClassName` edge, find the constructor
        # method inside that class and add it as a synthetic callee.
        # instantiates edges may lack call-site coordinates, so fall back to the
        # caller node's definition location when the edge coordinates are NULL.
        ctor_filter = _CONSTRUCTOR_FILTER.get(lang_key)
        if ctor_filter:
            cur.execute(
                f"""
                SELECT e.source, ctor.id, s.file_path,
                       COALESCE(e.line, s.start_line),
                       COALESCE(e.col, s.start_column),
                       e.line IS NULL AS coord_fallback
                FROM edges e
                JOIN nodes s   ON e.source = s.id
                JOIN nodes cls ON e.target = cls.id AND cls.kind = 'class'
                JOIN edges ce  ON ce.source = cls.id AND ce.kind = 'contains'
                JOIN nodes ctor ON ce.target = ctor.id
                               AND ctor.kind IN ('method', 'function')
                WHERE e.kind = 'instantiates' AND s.language IN ({placeholders})
                AND {ctor_filter}
                ORDER BY s.file_path, COALESCE(e.line, s.start_line),
                          COALESCE(e.col, s.start_column)
                """,
                cg_langs,
            )
            ctor_seq = 0
            for src_id, ctor_id, file_path, start_line, start_col, coord_fallback \
                    in cur.fetchall():
                caller, callee = fqn_of.get(src_id), fqn_of.get(ctor_id)
                if not caller or not callee:
                    continue
                # Dedup key includes call-site coordinates so multiple
                # constructor call sites within one function are preserved.
                # When the edge has no real coordinates (coord_fallback=True),
                # the COALESCE fallback gives every call site the same value;
                # use a sequence so distinct no-coordinate call sites are NOT
                # merged away (keeping all edges is safer than dropping calls).
                if not coord_fallback:
                    key = (caller, callee, "constructor", file_path,
                           start_line, start_col)
                    if key in seen:
                        continue
                    seen.add(key)
                else:
                    key = (caller, callee, "constructor", file_path,
                           "no-coord", ctor_seq)
                    ctor_seq += 1
                result.append({
                    "caller": caller,
                    "callee": callee,
                    "kind": "constructor",
                    "span": {
                        "file": file_path,
                        "start_line": start_line,
                        "start_column": start_col,
                    },
                })

        conn.close()

        # Sort the merged result by source location so call sites of different
        # kinds (call vs constructor) are interleaved in true source order.
        # Query 1 and Query 2 each ORDER BY independently, but appending them
        # in sequence would put all calls before all constructors regardless of
        # line number, breaking consumers that align call sites with source.
        result.sort(key=lambda e: (
            e["span"].get("file", ""),
            e["span"].get("start_line") or 0,
            e["span"].get("start_column") or 0,
        ))
        return result


def _pinned_codegraph_version() -> str:
    """The pinned release without the leading ``v`` — the form ``--version`` uses."""
    return settings.codegraph.version.strip().removeprefix("v")


def _fm_codegraph_dir() -> str:
    """FM-Agent's own bundle dir, kept out of the shared ``~/.codegraph`` because
    codegraph's installer deletes every other release under its install dir
    (their issue #1074) and re-points ``~/.local/bin/codegraph``."""
    return os.path.expanduser(settings.codegraph.install_dir)


def _codegraph_version_at(path: str) -> str:
    """``--version`` of the codegraph at ``path``, or "" when it cannot be run."""
    try:
        return subprocess.run(
            [path, "--version"], capture_output=True, text=True, timeout=30
        ).stdout.strip()
    except (OSError, subprocess.SubprocessError):
        return ""


def _codegraph_installed_elsewhere() -> str | None:
    """A codegraph outside our bundle dir — ``bin_dir`` first, then PATH. The last
    resort when the pinned build cannot be provisioned."""
    local = os.path.abspath(
        os.path.join(os.path.expanduser(settings.codegraph.bin_dir), "codegraph")
    )
    if os.access(local, os.X_OK):
        return local
    # which() joins the name onto each PATH entry as-is, so a relative entry
    # ("bin", ".") comes back relative — and try_codegraph_init runs codegraph with
    # cwd set to the analysed project, not the directory we were launched from.
    found = shutil.which("codegraph")
    return os.path.abspath(found) if found else None


def _provision_codegraph(want: str, binary: str) -> bool:
    """Install the pinned codegraph into FM-Agent's bundle dir; return whether
    ``binary`` is the pinned version afterwards.

    Drives codegraph's own installer through its three documented variables
    (``CODEGRAPH_VERSION`` / ``CODEGRAPH_INSTALL_DIR`` / ``CODEGRAPH_BIN_DIR``), so
    this depends on that contract rather than on the layout it produces. Serialised
    on a lock file: the pipeline runs up to ``max_workers`` processes, and a bumped
    pin would otherwise start that many downloads of the same archive.
    """
    import fcntl  # POSIX-only; keep the module importable without it

    install_dir = _fm_codegraph_dir()
    try:
        os.makedirs(install_dir, exist_ok=True)
        lock = open(os.path.join(install_dir, ".provision.lock"), "w")
        fcntl.flock(lock, fcntl.LOCK_EX)
    except OSError as exc:
        # Unwritable dir, full disk, no flock — the install would fail for the same
        # reason, so degrade like every other failure here instead of escaping and
        # taking the pipeline down with it.
        logging.warning(
            "cannot prepare the codegraph bundle dir %s (%s); not provisioning",
            install_dir,
            exc,
        )
        return False

    with lock:
        # Whoever we queued behind has usually just installed it.
        if _codegraph_version_at(binary) == want:
            return True

        # stderr: install.sh reads this function's stdout to learn the path.
        print(
            f"[Pipeline] installing pinned codegraph v{want} "
            f"(~55 MB, once per version) into {install_dir}",
            file=sys.stderr,
        )
        # The release tag, not main: this script is piped into sh on the user's
        # machine, and provisioning now happens on its own, so tracking a branch
        # would let any push to the codegraph repo run here.
        url = (
            f"https://raw.githubusercontent.com/{settings.codegraph.repo}"
            f"/{settings.codegraph.version}/install.sh"
        )
        try:
            with urllib.request.urlopen(url, timeout=60) as response:
                script = response.read().decode()
        except (OSError, ValueError, UnicodeError) as exc:
            logging.warning("could not fetch the codegraph installer %s: %s", url, exc)
            return False

        env = {
            **os.environ,
            "CODEGRAPH_VERSION": settings.codegraph.version,
            "CODEGRAPH_INSTALL_DIR": install_dir,
            "CODEGRAPH_BIN_DIR": os.path.dirname(binary),
        }
        try:
            result = subprocess.run(
                ["sh", "-s"],
                input=script,
                capture_output=True,
                text=True,
                env=env,
                timeout=1800,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            logging.warning("the codegraph installer did not complete: %s", exc)
            return False

        # The version, not "a file appeared": a wrong tag, a partial download or a
        # changed installer contract would otherwise leave a build we go on to run
        # as though it were the pinned one.
        got = _codegraph_version_at(binary)
        if got != want:
            logging.warning(
                "codegraph v%s was not provisioned (got %s); installer exit=%s: %s",
                want,
                got or "nothing",
                result.returncode,
                (result.stderr or result.stdout)[-300:],
            )
            return False
        print(f"[Pipeline] codegraph v{want} ready.", file=sys.stderr)
        return True


@functools.cache
def _codegraph_cmd() -> str:
    """The codegraph to run: the release pinned in ``fm-agent.toml``, installed on
    demand when the machine does not have it, else whatever else is installed —
    with a warning, since a different release yields a full index with different
    call edges. A newer codegraph elsewhere is not preferred: bug reports have to
    name a version we can reproduce on.

    Cached, so a run cannot switch binaries midway — oh-my-openagent's MCP server
    writes the same index concurrently (see ``_opencode_env``). The cache holds the
    path, though, and the bundle holds one release, so a concurrent run on a
    different pin can provision over it; that needs two runs straddling a bump, and
    a tree per pin would cost every user a few hundred MB each.

    Always absolute when the answer is a real file: callers embed the value rather
    than only executing it — install.sh symlinks it, ``_opencode_env`` exports it.
    """
    want = _pinned_codegraph_version()
    binary = os.path.abspath(os.path.join(_fm_codegraph_dir(), "bin", "codegraph"))
    if not want:
        # Nothing pinned: no version to provision or to check against.
        return _codegraph_installed_elsewhere() or "codegraph"

    if _codegraph_version_at(binary) == want:
        return binary
    if _provision_codegraph(want, binary):
        return binary

    other = _codegraph_installed_elsewhere()
    if other is not None and _codegraph_version_at(other) == want:
        return other  # the pinned release, just installed somewhere else
    if other is None:
        logging.warning(
            "codegraph v%s (pinned in fm-agent.toml) is not available and no other "
            "codegraph is installed; extraction falls back to the regex extractor. "
            "Run ./install.sh once with network access.",
            want,
        )
        # The bare name raises FileNotFoundError in the caller, which is the
        # regex fallback.
        return "codegraph"
    logging.warning(
        "codegraph v%s (pinned in fm-agent.toml) is not available; using %s (%s) "
        "instead. Call edges can differ from the pinned build.",
        want,
        other,
        _codegraph_version_at(other) or "unknown version",
    )
    return other


def try_codegraph_init(proj_dir: str, force: bool = True) -> None:
    """Build the codegraph index for proj_dir.

    By default (``force=True``) an existing index is rebuilt from scratch, so the
    index always reflects the current working tree rather than whatever code was
    present when it was last built. This is the safe default: callers read
    function bodies and spans from the index, and a stale one (e.g. after an
    incremental run's tree changed or project sources were edited) would yield
    boundaries for the wrong code.

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
        # `codegraph index` is the full rebuild — "same result as a fresh init",
        # but it discards codegraph.db itself instead of the directory holding it.
        # Clearing `.codegraph/` here is what used to make `init` rebuild rather
        # than no-op, and it silently stopped working once that directory became a
        # symlink into oh-my-openagent's store: shutil.rmtree refuses to remove a
        # symlink and ignore_errors=True swallowed the error, so the run reported a
        # rebuild that never happened.
        action = "index"
        what = "Rebuilding codegraph index for current working tree"
    else:
        # `index` rebuilds an initialized project and errors out otherwise, so the
        # first build still goes through `init`.
        action = "init"
        what = "Building codegraph index"
    # Name the version that actually builds this index — a machine can hold
    # several codegraph installs, and the log is where a call graph's provenance
    # has to be recoverable from.
    cmd = _codegraph_cmd()
    version = _codegraph_version_at(cmd)
    print(f"[Pipeline] {what} (codegraph {version or 'version unknown'})...")
    try:
        result = subprocess.run(
            [cmd, action], cwd=proj_dir, capture_output=True, text=True
        )
    except FileNotFoundError:
        return  # codegraph not installed
    if result.returncode == 0:
        print("[Pipeline] codegraph index built.")
    else:
        # A failed `index` has already discarded the database it was rebuilding,
        # leaving an empty or schema-less file behind. Drop it so the fallback
        # this message promises is the one that happens — an index nobody can read
        # is worse than no index, because the pipeline would consume it as if it
        # were complete. Remove the files, not `.codegraph/` itself: that
        # directory is a symlink into oh-my-openagent's store on any project
        # opened in an editor session.
        outcome = "falling back to regex"
        if action == "index":
            try:
                os.remove(db_path)
            except OSError as exc:
                # The database survived, so it stays discoverable and the regex
                # fallback is NOT what happens — say that rather than claiming it.
                # Leave the sidecars too: dropping a live database's -wal corrupts
                # it, and half-removed is worse than untouched.
                outcome = f"existing index left in place, may be stale ({exc})"
            else:
                for path in (f"{db_path}-wal", f"{db_path}-shm"):
                    try:
                        os.remove(path)
                    except OSError:
                        pass
        logging.warning(
            "codegraph %s failed (non-fatal, %s): %s",
            action,
            outcome,
            result.stderr[:300],
        )

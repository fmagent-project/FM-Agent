"""
CodeGraph backend for FM-Agent function extraction and call graph building.

Requires the user to have run `codegraph init` in the project directory first,
which produces `.codegraph/codegraph.db` (SQLite).

To add support for a new language: create src/languages/<lang>.py and add an entry to
REGISTRY in src/languages/registry.py. No other files need to change.
"""

import logging
import os
import sqlite3
import subprocess
from collections import defaultdict

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
            SELECT name, file_path, start_line, end_line
            FROM nodes
            WHERE kind IN ('function', 'method') AND language IN ({placeholders})
            ORDER BY file_path, start_line
            """,
            cg_langs,
        )
        rows = cur.fetchall()
        conn.close()

        by_file = defaultdict(list)
        for name, file_path, start_line, end_line in rows:
            by_file[file_path].append((name, int(start_line), int(end_line)))

        result = {}
        for file_path, funcs in by_file.items():
            abs_path = os.path.join(proj_dir, file_path) if proj_dir else file_path
            try:
                with open(abs_path, "r", errors="replace") as f:
                    all_lines = f.readlines()
            except OSError:
                continue

            file_funcs = []
            for name, start_line, end_line in funcs:
                # codegraph uses 1-indexed lines, end_line is inclusive
                body_lines = all_lines[start_line - 1 : end_line]
                body = "".join(body_lines)
                if not body.endswith("\n"):
                    body += "\n"
                file_funcs.append((name, body))

            result[abs_path] = file_funcs

        return result

    def get_call_edges(self, lang_key: str) -> dict:
        """Return {(caller_stem, caller_basename): {callee_stem, ...}} for the given language.

        caller_stem / callee_stem are plain function names (fqn.split('::')[-1]).
        caller_basename is os.path.basename(caller_file_path), used to disambiguate
        same-name functions defined in different files.

        Constructor calls are synthesised from `instantiates` edges: when a
        function instantiates a class, the corresponding constructor method is
        added as a callee.  See _CONSTRUCTOR_FILTER for per-language details.
        """
        cg_langs = _CG_LANG.get(lang_key)
        if not cg_langs:
            return {}

        conn = sqlite3.connect(self._db)
        cur = conn.cursor()
        placeholders = ",".join("?" * len(cg_langs))

        # Query 1: regular function/method calls
        cur.execute(
            f"""
            SELECT s.name, s.file_path, t.name
            FROM edges e
            JOIN nodes s ON e.source = s.id
            JOIN nodes t ON e.target = t.id
            WHERE e.kind = 'calls' AND s.language IN ({placeholders})
            """,
            cg_langs,
        )
        rows = cur.fetchall()

        result = defaultdict(set)
        for caller, caller_file, callee in rows:
            base = os.path.basename(caller_file)
            last_dot = base.rfind(".")
            dashed = base[:last_dot] + "-" + base[last_dot + 1:] if last_dot > 0 else base
            result[(caller, dashed)].add(callee)

        # Query 2: constructor calls synthesised from instantiates edges.
        # For each `caller instantiates ClassName` edge, find the constructor
        # method inside that class and add it as a synthetic callee.
        ctor_filter = _CONSTRUCTOR_FILTER.get(lang_key)
        if ctor_filter:
            cur.execute(
                f"""
                SELECT s.name, s.file_path, ctor.name
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
            for caller, caller_file, ctor_name in cur.fetchall():
                base = os.path.basename(caller_file)
                last_dot = base.rfind(".")
                dashed = base[:last_dot] + "-" + base[last_dot + 1:] if last_dot > 0 else base
                result[(caller, dashed)].add(ctor_name)

        conn.close()
        return dict(result)


def try_codegraph_init(proj_dir: str) -> None:
    """Run `codegraph init` in proj_dir if the index does not yet exist.

    Silently skips when codegraph is not installed so the pipeline falls back
    to the regex-based extractor without any error.
    """
    db_path = os.path.join(proj_dir, ".codegraph", "codegraph.db")
    if os.path.exists(db_path):
        return
    print("[Pipeline] Building codegraph index (this runs once per project)...")
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

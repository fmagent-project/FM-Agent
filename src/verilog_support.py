"""Verilog / SystemVerilog extraction helpers.

This is the Verilog counterpart of :mod:`chisel_support`. It provides the
pieces ``extract.py`` and ``generate_topdown_layers.py`` plug in for `.v`/`.sv`
sources:

  * :data:`VERILOG_LANG_CONFIG`  — a ``LANG_CONFIG`` fragment (``body == "verilog"``)
  * :data:`VERILOG_EXT_TO_LANG`  — file-extension -> language-key mapping
  * :data:`VERILOG_TEST_FILE_PATTERNS` — extra test-bench name patterns
  * :func:`extract_verilog_functions` — the extractor invoked by
    ``extract_functions_from_file`` when ``lang_cfg["body"] == "verilog"``
  * :func:`strip_verilog_comments` / :func:`find_verilog_call_sites` — the
    instantiation-edge helpers used by topdown-layer generation.

The extraction unit is the **module** (``module Foo ... endmodule``), analogous
to a Chisel top-level declaration: re-parsing a single extracted module yields
exactly one unit (keeping ``_validate_extraction`` happy).

Parsing prefers **Verible** (``verible-verilog-syntax``) for a robust CST-based
parse when it is on ``PATH``; it falls back to a pure-Python ``module`` /
``endmodule`` scanner (Verilog modules do not nest and Verilog has neither
nested block comments nor triple-quoted strings, so this is simpler than the
Scala scanner). Both the Verible and fallback edge finders intersect references
with ``known_stems`` — the set of real module names — so neither over-reports.
"""

import bisect
import json
import logging
import os
import re
import shutil
import subprocess

# ---------------------------------------------------------------------------
# Standalone spec/info (.md) location and readiness  (mirrors chisel_support)
# ---------------------------------------------------------------------------

_VERILOG_SPEC_MIN_BYTES = 200

# A parseable submodule entry heading — the exact per-line shape
# generate_batch_prompts parses caller expectations from.
_SUBMODULE_HEADING_RE = re.compile(r"^#[ \t]*Submodule:[ \t]*(\S+)[ \t]*$", re.M)


def verilog_spec_path(module_file_path):
    """Return the standalone ``<module-stem>_spec.md`` path for an extracted module."""
    directory = os.path.dirname(module_file_path)
    stem = os.path.splitext(os.path.basename(module_file_path))[0]
    return os.path.join(directory, f"{stem}_spec.md")


def verilog_info_path(module_file_path):
    """Return the standalone ``<module-stem>_info.md`` path for an extracted module."""
    directory = os.path.dirname(module_file_path)
    stem = os.path.splitext(os.path.basename(module_file_path))[0]
    return os.path.join(directory, f"{stem}_info.md")


def _verilog_markdown_ready(path):
    try:
        if os.path.getsize(path) < _VERILOG_SPEC_MIN_BYTES:
            return False
        with open(path, "r", errors="replace") as f:
            return "#" in f.read()
    except OSError:
        return False


def _verilog_info_ready(path, allow_no_submodules=True, expected_submodules=frozenset()):
    """Readiness for ``_info.md``: as ``_verilog_markdown_ready``, except that a
    leaf module's info file may legitimately be just a heading plus
    ``(no submodules)`` — the system prompt allows it — which is smaller than
    the anti-stub byte threshold.

    Pass ``allow_no_submodules=False`` for modules whose instantiation graph
    shows submodules: their info must contain at least one ``# Submodule:``
    entry and must not claim ``(no submodules)`` — regardless of file size, so
    a padded stub cannot slip through the byte threshold. ``expected_submodules``
    names the instantiated modules; every one of them must have its own
    parseable heading, or the missing children would later be specced without
    their caller expectations. Names are compared exactly — Verilog numeric
    suffixes like ``fifo_64`` are real module names, never dedup aliases.
    """
    try:
        with open(path, "r", errors="replace") as f:
            content = f.read()
    except OSError:
        return False
    if not allow_no_submodules:
        return (
            _verilog_markdown_ready(path)
            and "(no submodules)" not in content
            and _SUBMODULE_HEADING_RE.search(content) is not None
            and set(expected_submodules) <= set(_SUBMODULE_HEADING_RE.findall(content))
        )
    if _verilog_markdown_ready(path):
        return True
    return "#" in content and "(no submodules)" in content


def verilog_spec_ready(module_file_path, expected_submodules=frozenset()):
    """True when both standalone Verilog Markdown outputs are non-trivial.

    A non-empty ``expected_submodules`` (the module's instantiated submodule
    names per the instantiation graph) disallows the small ``(no submodules)``
    info stub and requires a ``# Submodule:`` entry for EVERY expected name.
    Pure check — never mutates files; the pending scan owns cleanup.
    """
    return (
        _verilog_markdown_ready(verilog_spec_path(module_file_path))
        and _verilog_info_ready(
            verilog_info_path(module_file_path),
            allow_no_submodules=not expected_submodules,
            expected_submodules=expected_submodules,
        )
    )


# ---------------------------------------------------------------------------
# Configuration consumed by extract.py
# ---------------------------------------------------------------------------

# Verilog / SystemVerilog keywords + common gate primitives and system tasks.
# Used to keep the fallback edge scanner from treating language constructs as
# module references (the known_stems intersection is the primary safety net).
_VERILOG_KEYWORDS = {
    "module", "endmodule", "input", "output", "inout", "wire", "reg", "logic",
    "assign", "always", "always_ff", "always_comb", "always_latch", "initial",
    "begin", "end", "if", "else", "case", "casex", "casez", "endcase",
    "for", "while", "repeat", "forever", "do", "function", "endfunction",
    "task", "endtask", "generate", "endgenerate", "genvar", "parameter",
    "localparam", "default", "posedge", "negedge", "or", "and", "nand", "nor",
    "xor", "xnor", "not", "buf", "bufif0", "bufif1", "notif0", "notif1",
    "signed", "unsigned", "integer", "real", "time", "string", "bit", "byte",
    "int", "shortint", "longint", "typedef", "struct", "union", "enum",
    "package", "endpackage", "import", "export", "interface", "endinterface",
    "modport", "class", "endclass", "virtual", "extends", "automatic", "static",
    "return", "break", "continue", "assert", "property", "endproperty",
    "sequence", "endsequence", "cover", "wait", "fork", "join", "join_any",
    "join_none", "disable", "casting", "void", "ref", "const", "defparam",
    "specify", "endspecify", "primitive", "endprimitive", "table", "endtable",
}


VERILOG_LANG_CONFIG = {
    "verilog": {
        "comment_prefix": "//",
        "spec_marker": "// [SPEC]",
        "skip_prefixes": ("//", "/*", "*", "`"),
        "skip_keywords_line": (),
        "keywords": _VERILOG_KEYWORDS,
        "body": "verilog",
    },
}

VERILOG_EXT_TO_LANG = {
    "v": "verilog",
    "sv": "verilog",
    "svh": "verilog",
}

# Test-bench files (e.g. foo_tb.sv, tb_foo.v, foo_test.sv) — excluded from spec
# generation, mirroring CHISEL_TEST_FILE_PATTERNS.
VERILOG_TEST_FILE_PATTERNS = [
    re.compile(r'^.*_tb\.s?vh?$'),
    re.compile(r'^tb_.*\.s?vh?$'),
    re.compile(r'^.*_test\.s?vh?$'),
    re.compile(r'^.*_testbench\.s?vh?$'),
]

# Directories that conventionally hold Verilog testbench/simulation code with
# ordinary filenames (e.g. sim/top.sv). Applied by extract._is_test_file to
# Verilog files ONLY: software projects legitimately keep source in sim/.
VERILOG_TEST_DIR_NAMES = {"tb", "sim"}


# ---------------------------------------------------------------------------
# Verible CST parsing (primary)
# ---------------------------------------------------------------------------

def _verible_bin():
    """Return the verible-verilog-syntax path, or None when unavailable/disabled.

    Set ``FM_AGENT_NO_VERIBLE=1`` to force the pure-Python fallback (used by
    tests and as an escape hatch).
    """
    if os.environ.get("FM_AGENT_NO_VERIBLE"):
        return None
    return shutil.which("verible-verilog-syntax")


def _run_verible_tree(text):
    """Parse ``text`` with verible (via stdin) and return the CST root, or None.

    Offsets in the returned tree are byte offsets into the UTF-8 encoding of
    ``text`` (the pipe encoding is pinned to UTF-8 so this holds regardless of
    locale); map them to lines with :func:`_line_start_offsets`.
    """
    binary = _verible_bin()
    if not binary:
        return None
    try:
        proc = subprocess.run(
            [binary, "--printtree", "--export_json", "-"],
            input=text, capture_output=True, encoding="utf-8", timeout=120,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if not proc.stdout.strip():
        return None
    try:
        data = json.loads(proc.stdout)
    except json.JSONDecodeError:
        return None
    if not data:
        return None
    first = next(iter(data.values()))
    if not isinstance(first, dict):
        return None
    return first.get("tree")


def _children(node):
    return node.get("children") or [] if isinstance(node, dict) else []


def _first_descendant(node, tag):
    """Return the first descendant dict node with ``node["tag"] == tag`` (pre-order)."""
    for child in _children(node):
        if isinstance(child, dict):
            if child.get("tag") == tag:
                return child
            found = _first_descendant(child, tag)
            if found is not None:
                return found
    return None


def _has_descendant(node, tag):
    return _first_descendant(node, tag) is not None


def _first_symbol_identifier(node):
    """Return the text of the first ``SymbolIdentifier`` leaf under ``node``."""
    if not isinstance(node, dict):
        return None
    if node.get("tag") == "SymbolIdentifier" and "text" in node:
        return node["text"]
    for child in _children(node):
        text = _first_symbol_identifier(child)
        if text is not None:
            return text
    return None


def _first_name_identifier(node):
    """Return ``(tag, text)`` of the first identifier leaf under ``node``.

    Unlike :func:`_first_symbol_identifier` this also matches
    ``EscapedIdentifier`` (``\\foo.bar``), so a module-header lookup cannot
    skip past an escaped module name and mistake a port for the name; the
    caller inspects the tag to detect (and skip) escaped names.
    """
    if not isinstance(node, dict):
        return None, None
    if node.get("tag") in ("SymbolIdentifier", "EscapedIdentifier") and "text" in node:
        return node["tag"], node["text"]
    for child in _children(node):
        tag, text = _first_name_identifier(child)
        if text is not None:
            return tag, text
    return None, None


def _node_byte_span(node):
    """Return ``(min_start, max_end)`` byte offsets over all leaves under ``node``."""
    start = None
    end = None
    stack = [node]
    while stack:
        cur = stack.pop()
        if isinstance(cur, dict):
            if "start" in cur and "end" in cur:
                s, e = cur["start"], cur["end"]
                start = s if start is None else min(start, s)
                end = e if end is None else max(end, e)
            stack.extend(_children(cur))
    return start, end


def _line_start_offsets(text):
    """Return a sorted list of byte offsets at which each line begins.

    Verible reports byte offsets into the UTF-8 input, so line starts are
    computed over the encoded bytes — code-point offsets drift after any
    multi-byte character.
    """
    data = text.encode("utf-8")
    offsets = [0]
    for m in re.finditer(b"\n", data):
        offsets.append(m.end())
    return offsets


def _collect_top_level_modules(tree):
    """Return the top-level ``kModuleDeclaration`` nodes (no descent into modules)."""
    modules = []

    def walk(node):
        if isinstance(node, dict):
            if node.get("tag") == "kModuleDeclaration":
                modules.append(node)
                return  # do not recurse: keep only outermost modules
            for child in _children(node):
                walk(child)
        elif isinstance(node, list):
            for child in node:
                walk(child)

    walk(tree)
    return modules


def _extract_via_verible(text):
    """Extract ``(name, start_idx, end_idx)`` line spans using the verible CST.

    Returns None if verible is unavailable or produced no usable tree, so the
    caller can fall back to the scanner.
    """
    tree = _run_verible_tree(text)
    if tree is None:
        return None

    line_starts = _line_start_offsets(text)
    units = []
    for module in _collect_top_level_modules(tree):
        header = _first_descendant(module, "kModuleHeader")
        tag, name = _first_name_identifier(header) if header is not None else (None, None)
        if not name:
            continue
        if tag == "EscapedIdentifier":
            # Escaped names (\foo.bar) may contain ., /, etc. — unusable as
            # extraction filenames and FQN parts. Typically tool-generated
            # netlists, not hand-written RTL.
            logging.warning(
                "Skipping module %s: escaped-identifier module names are not "
                "supported for spec generation.", name
            )
            continue
        start_byte, end_byte = _node_byte_span(module)
        if start_byte is None:
            continue
        start_idx = bisect.bisect_right(line_starts, start_byte) - 1
        end_idx = bisect.bisect_right(line_starts, max(end_byte - 1, start_byte)) - 1
        units.append((name, start_idx, end_idx))
    return units


# ---------------------------------------------------------------------------
# Comment / string masking (shared by the scanner and the fallback edge finder)
# ---------------------------------------------------------------------------

def strip_verilog_comments(text):
    """Mask ``//`` line comments, ``/* */`` block comments and ``"..."`` strings
    with spaces, preserving newlines and every other character's offset.

    Verilog block comments do not nest and there are no triple-quoted strings,
    so this is the simple single-level counterpart of ``strip_chisel_comments``.
    """
    out = list(text)
    n = len(text)
    i = 0
    while i < n:
        ch = text[i]
        nxt = text[i + 1] if i + 1 < n else ''
        if ch == '/' and nxt == '/':
            while i < n and text[i] != '\n':
                out[i] = ' '
                i += 1
            continue
        if ch == '/' and nxt == '*':
            out[i] = out[i + 1] = ' '
            i += 2
            while i < n:
                if text[i] == '*' and i + 1 < n and text[i + 1] == '/':
                    out[i] = out[i + 1] = ' '
                    i += 2
                    break
                if out[i] != '\n':
                    out[i] = ' '
                i += 1
            continue
        if ch == '"':
            out[i] = ' '
            i += 1
            while i < n:
                if text[i] == '\\':
                    if out[i] != '\n':
                        out[i] = ' '
                    if i + 1 < n and out[i + 1] != '\n':
                        out[i + 1] = ' '
                    i += 2
                    continue
                if text[i] == '"':
                    out[i] = ' '
                    i += 1
                    break
                if out[i] != '\n':
                    out[i] = ' '
                i += 1
            continue
        i += 1
    return ''.join(out)


# ---------------------------------------------------------------------------
# Pure-Python module/endmodule scanner (fallback)
# ---------------------------------------------------------------------------

_MODULE_OPEN_RE = re.compile(r'\bmodule\b\s+(?:automatic\s+|static\s+)?([A-Za-z_]\w*)')
_MODULE_KW_RE = re.compile(r'\bmodule\b')
_ENDMODULE_RE = re.compile(r'\bendmodule\b')


def verilog_declared_name(text):
    """Name of the first module declared in an extracted Verilog unit.

    Counterpart of :func:`src.chisel_support.chisel_declared_name`, using the
    scanner's own module regex on comment-masked text. Verilog units normally
    declare their file stem; a differing name marks an extractor dedup alias.
    """
    m = _MODULE_OPEN_RE.search(strip_verilog_comments(text))
    return m.group(1) if m else None


def _extract_via_scan(lines):
    """Fallback extractor: pair ``module NAME`` with the next ``endmodule``.

    Verilog modules do not nest, so a simple paired scan over comment-masked
    lines is sufficient and robust for RTL.
    """
    masked = strip_verilog_comments("\n".join(lines)).split("\n")
    units = []
    i = 0
    n = len(masked)
    while i < n:
        m = _MODULE_OPEN_RE.search(masked[i])
        # Guard against matching 'endmodule' (handled by \bmodule\b word boundary)
        if not m:
            i += 1
            continue
        name = m.group(1)
        start_idx = i
        # Find the matching endmodule (no nesting in Verilog).
        j = i
        end_idx = n - 1
        while j < n:
            if _ENDMODULE_RE.search(masked[j]):
                end_idx = j
                break
            j += 1
        units.append((name, start_idx, end_idx))
        i = end_idx + 1
    return units


# ---------------------------------------------------------------------------
# Public entry point invoked by extract.py
# ---------------------------------------------------------------------------

def extract_verilog_functions(lines, lang_key, lang_cfg):
    """Extract top-level Verilog modules from a source file.

    Mirrors the contract of ``extract.py``'s ``_extract_functions_brace`` /
    ``extract_chisel_functions``: returns a list of ``(name, start_idx,
    end_idx)`` inclusive line-index tuples, one per ``module ... endmodule``.

    Uses verible when available, falling back to the pure-Python scanner —
    including when verible parses but recognizes ZERO modules: CST tag drift
    (e.g. a verible upgrade) must not masquerade as an authoritative empty
    result, because downstream a zero-unit extraction is what invalidates
    stale outputs. The scanner gets the final word on emptiness.
    """
    text = "\n".join(lines)
    units = _extract_via_verible(text)
    if units:
        return units
    return _extract_via_scan(lines)


# ---------------------------------------------------------------------------
# Call-graph helper invoked by generate_topdown_layers.py
# ---------------------------------------------------------------------------

# Fallback instantiation shape, anchored to the start of a (comment-masked)
# line so it cannot run across a module header's parameter/port lists. An
# optional same-line (* attribute *) prefix is tolerated:
#     ^  Type  #(              -> parameterised instance:  foo #(.W(8)) u (...)
#     ^  Type  instance (      -> simple instance:         foo u_foo (...)
#     ^  Type  instance [..] ( -> instance array:          foo u_foo [3:0] (...)
#     ^  (* attr *)  Type ...  -> attributed instance:     (* keep *) foo u (...)
# The Type is group(1); known_stems filtering removes everything that is not a
# real module name, so loose matches are harmless.
_INSTANTIATION_RE = re.compile(
    r'^[ \t]*(?:\(\*.*?\*\)[ \t]*)*([A-Za-z_]\w*)'
    r'(?:\s*#\s*\(|\s+[A-Za-z_]\w*\s*(?:\[[^\]]*\]\s*)*\()',
    re.MULTILINE,
)


def _walk_verible_instantiations(tree, known_stems, keywords):
    """Collect instantiated module-type names from a verible CST."""
    found = set()

    def walk(node):
        if isinstance(node, dict):
            if node.get("tag") == "kInstantiationBase" and _has_descendant(node, "kGateInstance"):
                inst_type = _first_descendant(node, "kInstantiationType")
                type_name = _first_symbol_identifier(inst_type) if inst_type is not None else None
                if type_name and type_name in known_stems and type_name not in keywords:
                    found.add(type_name)
            for child in _children(node):
                walk(child)
        elif isinstance(node, list):
            for child in node:
                walk(child)

    walk(tree)
    return found


# One-time canary verdict: None = untested, True = the instantiation walker
# recognizes this verible version's tags, False = drifted (use the fallback).
_EDGE_CANARY_RESULT = None

_EDGE_CANARY_TEXT = "module __fm_canary(input a);\n  __fm_dep u0(a);\nendmodule\n"


def _verible_edge_walker_works():
    """Return False when this verible version's instantiation tags drifted.

    The module-node sentinel in :func:`_find_verible_instantiations` catches
    FULL tag drift, but partial drift — module tags intact, instantiation
    tags renamed — yields a sane-looking tree with zero edges, failing the
    per-callee gate open. The canary parses a fixture with a KNOWN
    instantiation once per process: if verible parses it but the walker sees
    no edge, edge-finding is declared drifted and every call falls back to
    the regex. Real leaves are unaffected — their authority over emptiness
    only stands while the walker demonstrably works.
    """
    global _EDGE_CANARY_RESULT
    if _EDGE_CANARY_RESULT is None:
        tree = _run_verible_tree(_EDGE_CANARY_TEXT)
        if tree is None or not _collect_top_level_modules(tree):
            # verible itself unusable here — the per-call None/no-module
            # paths already route to the fallback; nothing to judge, and
            # the verdict is deliberately NOT cached.
            return True
        _EDGE_CANARY_RESULT = bool(
            _walk_verible_instantiations(tree, {"__fm_dep"}, frozenset())
        )
        if not _EDGE_CANARY_RESULT:
            logging.warning(
                "verible parses but its instantiation CST tags are not "
                "recognized (version drift?); using the regex fallback for "
                "edge detection."
            )
    return _EDGE_CANARY_RESULT


def _find_verible_instantiations(text, known_stems, keywords):
    """Return module-type names instantiated in ``text`` per the verible CST.

    Returns None when the tree is unusable so the caller falls back to the
    regex. ``text`` is always an extracted module unit, so a CST containing
    no recognizable module declaration is drift (verible upgrade renamed
    tags), not a real answer — an EMPTY edge set from such a tree would fail
    the per-callee gate OPEN. A tree that does contain the module node keeps
    authority over emptiness — real leaves must not be second-guessed by the
    fallback's looser matching — provided the canary confirms the
    instantiation walker recognizes this verible version at all.
    """
    tree = _run_verible_tree(text)
    if tree is None:
        return None
    if not _collect_top_level_modules(tree):
        return None
    if not _verible_edge_walker_works():
        return None
    return _walk_verible_instantiations(tree, known_stems, keywords)


def find_verilog_call_sites(text, known_stems, keywords):
    """Return the set of ``known_stems`` instantiated by ``text``.

    Mirrors ``generate_topdown_layers._find_call_sites`` for Verilog sources: a
    module depends on another by *instantiating* it. Uses the verible CST when
    available (precisely distinguishing instantiations from variable
    declarations) and otherwise a comment-masked regex; both intersect with
    ``known_stems`` so only real module references are returned.
    """
    via_verible = _find_verible_instantiations(text, known_stems, keywords)
    if via_verible is not None:
        return via_verible

    cleaned = strip_verilog_comments(text)
    found = set()
    for m in _INSTANTIATION_RE.finditer(cleaned):
        ident = m.group(1)
        if ident in keywords:
            continue
        if ident in known_stems:
            found.add(ident)
    return found

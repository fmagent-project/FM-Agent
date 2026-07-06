"""Hardware-description-language extraction helpers (Chisel / Scala).

Chisel is a hardware construction language embedded in Scala: hardware is
described with `class Foo extends Module { ... }` declarations, plus supporting
`object`s, `trait`s and top-level `def`s.  The generic brace extractor in
``extract.py`` (designed for C/C++/Java/JS) cannot parse Scala cleanly because
Scala has constructs the C-style scanner does not understand:

  * nested block comments ``/* /* ... */ */``
  * triple-quoted (multi-line) string literals ``\"\"\" ... \"\"\"``
  * declarations introduced by ``class`` / ``object`` / ``trait`` / ``def``
    rather than by a parenthesised signature line.

This module provides the Chisel-specific pieces that ``extract.py`` plugs in:

  * :data:`CHISEL_LANG_CONFIG`  — a ``LANG_CONFIG`` fragment (``body == "chisel"``)
  * :data:`CHISEL_EXT_TO_LANG`  — file-extension -> language-key mapping
  * :data:`CHISEL_TEST_FILE_PATTERNS` — extra test-file name patterns
  * :func:`extract_chisel_functions` — the extractor invoked by
    ``extract_functions_from_file`` when ``lang_cfg["body"] == "chisel"``.

The extraction unit is the **top-level declaration**.  Inner ``def``s remain
part of their enclosing module so that re-parsing a single extracted module
yields exactly one unit (keeping ``_validate_extraction`` happy).
"""

import os
import re

# ---------------------------------------------------------------------------
# Standalone spec/info (.md) location and readiness
# ---------------------------------------------------------------------------
#
# Chisel specs are emitted as standalone ``<ModuleName>_spec.md`` documents next
# to the extracted module file (rather than embedded as ``// [SPEC]`` comment
# blocks inside the source). The expected specs of the module's submodules
# (the standalone counterpart of the embedded ``[INFO]`` block) are emitted
# beside it as ``<ModuleName>_info.md``. These helpers give the spec generator
# and the batch-prompt builder a single definition of where those files live
# and when a module counts as specced.

# A spec must contain at least one Markdown heading and this many bytes to be
# considered a real spec rather than an empty stub.
_CHISEL_SPEC_MIN_BYTES = 200


def chisel_spec_path(module_file_path):
    """Return the standalone spec ``.md`` path for an extracted Chisel module.

    The spec lives in the same directory as the extracted module file, named
    ``<module-stem>_spec.md`` (e.g. ``.../Foo-scala/Foo.scala`` ->
    ``.../Foo-scala/Foo_spec.md``).
    """
    directory = os.path.dirname(module_file_path)
    stem = os.path.splitext(os.path.basename(module_file_path))[0]
    return os.path.join(directory, f"{stem}_spec.md")


def chisel_info_path(module_file_path):
    """Return the standalone info ``.md`` path for an extracted Chisel module."""
    directory = os.path.dirname(module_file_path)
    stem = os.path.splitext(os.path.basename(module_file_path))[0]
    return os.path.join(directory, f"{stem}_info.md")


def _chisel_markdown_ready(path):
    try:
        if os.path.getsize(path) < _CHISEL_SPEC_MIN_BYTES:
            return False
        with open(path, "r", errors="replace") as f:
            return "#" in f.read()
    except OSError:
        return False


def _chisel_info_ready(path):
    """Readiness for ``_info.md``: as ``_chisel_markdown_ready``, except that a
    leaf module's info file may legitimately be just a heading plus
    ``(no submodules)`` — the system prompt allows it — which is smaller than
    the anti-stub byte threshold.
    """
    if _chisel_markdown_ready(path):
        return True
    try:
        with open(path, "r", errors="replace") as f:
            content = f.read()
    except OSError:
        return False
    return "#" in content and "(no submodules)" in content


def chisel_spec_ready(module_file_path):
    """True when both standalone Chisel Markdown outputs are non-trivial.

    "Non-trivial" means each file is at least :data:`_CHISEL_SPEC_MIN_BYTES`
    bytes and contains at least one Markdown heading, so an empty or truncated
    stub left by an interrupted run is not mistaken for a finished spec. The
    info file may instead be a small legal ``(no submodules)`` document.
    """
    return (
        _chisel_markdown_ready(chisel_spec_path(module_file_path))
        and _chisel_info_ready(chisel_info_path(module_file_path))
    )


# ---------------------------------------------------------------------------
# Configuration consumed by extract.py
# ---------------------------------------------------------------------------

# Scala / Chisel keywords (used only for parity with the other LANG_CONFIG
# entries; the Chisel extractor does not rely on them for name detection).
_SCALA_KEYWORDS = {
    "abstract", "case", "catch", "class", "def", "do", "else", "extends",
    "final", "finally", "for", "forSome", "if", "implicit", "import", "lazy",
    "match", "new", "object", "override", "package", "private", "protected",
    "return", "sealed", "super", "this", "throw", "trait", "try", "type",
    "val", "var", "while", "with", "yield",
}

CHISEL_LANG_CONFIG = {
    "chisel": {
        "comment_prefix": "//",
        "spec_marker": "// [SPEC]",
        "skip_prefixes": ("//", "/*", "*", "package", "import"),
        "skip_keywords_line": (),
        "keywords": _SCALA_KEYWORDS,
        "body": "chisel",
    },
}

# Chisel sources are Scala files.
CHISEL_EXT_TO_LANG = {
    "scala": "chisel",
    "sc": "chisel",
}

# ChiselTest / ScalaTest specs (e.g. AluSpec.scala, FooTest.scala) live under
# src/test/scala (already caught by the test-dir check) but are also commonly
# named *Spec/*Test/*Tester regardless of directory.
CHISEL_TEST_FILE_PATTERNS = [
    re.compile(r'^.*(?:Spec|Test|Tester)\.scala$'),
]

# Modifiers that may precede a top-level declaration keyword.
_MOD = (
    r'(?:'
    r'(?:private|protected)(?:\[[\w.]+\])?'
    r'|final|sealed|abstract|implicit|lazy|override|case'
    r')'
)

# A top-level Chisel/Scala declaration: optional modifiers, then one of
# class/object/trait/def, then the declared name.
_CHISEL_DECL_RE = re.compile(
    r'^(?:' + _MOD + r'\s+)*'
    r'(?P<kind>class|object|trait|def)\s+'
    r'(?P<name>[A-Za-z_$][\w$]*)'
)

# Trailing tokens that mean "this signature continues on the next line".
_CONT_WORDS = ("extends", "with")
_CONT_SYMBOLS = ("=>", "<-", "&&", "||", "=", ",", "(", "[", ".",
                 "+", "-", "*", "/", "%", "|", "&", ":")


# ---------------------------------------------------------------------------
# Low-level Scala-aware scanning
# ---------------------------------------------------------------------------


def _scan_line_states(lines):
    """Compute, for each line, its brace depth and comment/string state at the
    line's start.

    Returns ``(depth_start, clean_start)`` where ``depth_start[i]`` is the brace
    nesting depth at the beginning of line ``i`` and ``clean_start[i]`` is True
    when line ``i`` does not begin inside a block comment or triple-quoted
    string (i.e. it is safe to interpret as code).

    String literals, char literals, ``//`` line comments, nested ``/* */``
    block comments and ``\"\"\"`` triple strings are all skipped so that braces
    appearing inside them do not affect the depth count.
    """
    n = len(lines)
    depth_start = [0] * n
    clean_start = [True] * n

    depth = 0
    block_depth = 0      # nesting level of /* */ comments
    in_triple = False    # inside a """ ... """ string

    for i in range(n):
        depth_start[i] = depth
        clean_start[i] = (block_depth == 0 and not in_triple)

        line = lines[i]
        j = 0
        L = len(line)
        while j < L:
            ch = line[j]
            nxt = line[j + 1] if j + 1 < L else ''

            if in_triple:
                if line[j:j + 3] == '"""':
                    in_triple = False
                    j += 3
                    continue
                j += 1
                continue

            if block_depth:
                if ch == '/' and nxt == '*':
                    block_depth += 1
                    j += 2
                    continue
                if ch == '*' and nxt == '/':
                    block_depth -= 1
                    j += 2
                    continue
                j += 1
                continue

            # Normal code.
            if ch == '/' and nxt == '/':
                break  # line comment: ignore the rest of the line
            if ch == '/' and nxt == '*':
                block_depth += 1
                j += 2
                continue
            if line[j:j + 3] == '"""':
                in_triple = True
                j += 3
                continue
            if ch == '"':
                j = _skip_string(line, j)
                continue
            if ch == "'":
                j = _skip_char(line, j)
                continue
            if ch == '{':
                depth += 1
            elif ch == '}':
                depth -= 1
            j += 1

    return depth_start, clean_start


def _skip_string(line, j):
    """Skip a double-quoted string starting at ``line[j] == '\"'``; return the
    index just past the closing quote (or end of line)."""
    L = len(line)
    j += 1
    while j < L:
        if line[j] == '\\':
            j += 2
            continue
        if line[j] == '"':
            return j + 1
        j += 1
    return j


def _skip_char(line, j):
    """Skip a char literal starting at ``line[j] == \"'\"``; return the index
    just past it.  Tolerant of Scala's (deprecated) symbol literals."""
    L = len(line)
    # Char literals are short: 'a', '\n', '\''.  Anything longer is treated as
    # a stray quote / symbol literal and we simply step over the quote.
    if j + 2 < L and line[j + 1] == '\\' and line[j + 3:j + 4] == "'":
        return j + 4          # escaped char, e.g. '\n'
    if j + 1 < L and line[j + 2:j + 3] == "'":
        return j + 3          # simple char, e.g. 'a'
    return j + 1              # not a char literal; just skip the quote


def _find_block_end(lines, start_idx):
    """Find the line index of the ``}`` that matches the first ``{`` at or after
    ``start_idx``.

    ``start_idx`` must begin in clean code at brace depth 0 (guaranteed by the
    caller).  Handles strings, char literals, line comments, nested block
    comments and triple-quoted strings.  Returns ``len(lines) - 1`` if the brace
    is never closed.
    """
    depth = 0
    found_open = False
    block_depth = 0
    in_triple = False

    for i in range(start_idx, len(lines)):
        line = lines[i]
        j = 0
        L = len(line)
        while j < L:
            ch = line[j]
            nxt = line[j + 1] if j + 1 < L else ''

            if in_triple:
                if line[j:j + 3] == '"""':
                    in_triple = False
                    j += 3
                    continue
                j += 1
                continue

            if block_depth:
                if ch == '/' and nxt == '*':
                    block_depth += 1
                    j += 2
                    continue
                if ch == '*' and nxt == '/':
                    block_depth -= 1
                    j += 2
                    continue
                j += 1
                continue

            if ch == '/' and nxt == '/':
                break
            if ch == '/' and nxt == '*':
                block_depth += 1
                j += 2
                continue
            if line[j:j + 3] == '"""':
                in_triple = True
                j += 3
                continue
            if ch == '"':
                j = _skip_string(line, j)
                continue
            if ch == "'":
                j = _skip_char(line, j)
                continue
            if ch == '{':
                depth += 1
                found_open = True
            elif ch == '}':
                depth -= 1
                if found_open and depth == 0:
                    return i
            j += 1

    return len(lines) - 1


def _body_brace_col(line, paren_start=0):
    """Return the column of the first ``{`` on ``line`` that opens a body block
    (i.e. is not inside parentheses/brackets, a string or a comment), or -1.

    Only single-line state is considered; a body brace that follows a
    multi-line block comment on the same logical line is rare in practice.
    """
    brace_col, _ = _body_brace_and_paren(line, paren_start)
    return brace_col


def _body_brace_and_paren(line, paren_start):
    """Return ``(brace_col, paren_end)`` for a signature line.

    Unlike :func:`_body_brace_col`, this preserves open ``(`` / ``[`` state
    across lines, which is essential for common Chisel declarations such as
    ``class Foo(...`` split over several lines.
    """
    paren = paren_start
    j = 0
    L = len(line)
    while j < L:
        ch = line[j]
        nxt = line[j + 1] if j + 1 < L else ''
        if ch == '/' and nxt == '/':
            break
        if ch == '/' and nxt == '*':
            k = line.find('*/', j + 2)
            if k == -1:
                break
            j = k + 2
            continue
        if line[j:j + 3] == '"""':
            k = line.find('"""', j + 3)
            if k == -1:
                break
            j = k + 3
            continue
        if ch == '"':
            j = _skip_string(line, j)
            continue
        if ch == "'":
            j = _skip_char(line, j)
            continue
        if ch in '([':
            paren += 1
        elif ch in ')]':
            if paren > 0:
                paren -= 1
        elif ch == '{' and paren == 0:
            return j, paren
        j += 1
    return -1, paren


def _strip_trailing_comment(line):
    """Remove a trailing ``//`` line comment (respecting strings)."""
    j = 0
    L = len(line)
    while j < L:
        ch = line[j]
        nxt = line[j + 1] if j + 1 < L else ''
        if ch == '/' and nxt == '/':
            return line[:j]
        if line[j:j + 3] == '"""':
            k = line.find('"""', j + 3)
            if k == -1:
                return line
            j = k + 3
            continue
        if ch == '"':
            j = _skip_string(line, j)
            continue
        if ch == "'":
            j = _skip_char(line, j)
            continue
        j += 1
    return line


def _paren_balance(text):
    """Net count of unmatched ``(``/``[`` in ``text`` (strings/comments aware)."""
    paren = 0
    j = 0
    L = len(text)
    while j < L:
        ch = text[j]
        nxt = text[j + 1] if j + 1 < L else ''
        if ch == '/' and nxt == '/':
            break
        if text[j:j + 3] == '"""':
            k = text.find('"""', j + 3)
            if k == -1:
                break
            j = k + 3
            continue
        if ch == '"':
            j = _skip_string(text, j)
            continue
        if ch == "'":
            j = _skip_char(text, j)
            continue
        if ch in '([':
            paren += 1
        elif ch in ')]':
            paren -= 1
        j += 1
    return paren


def _signature_continues(line, paren_depth=0):
    """True when a braceless declaration's signature continues on the next line."""
    code = _strip_trailing_comment(line).rstrip()
    if not code:
        return True  # blank / comment-only line in the middle of a signature
    if paren_depth > 0:
        return True
    for word in _CONT_WORDS:
        if re.search(r'\b' + word + r'$', code):
            return True
    for sym in _CONT_SYMBOLS:
        if code.endswith(sym):
            return True
    return False


def _next_code_line_starts_with(lines, start_idx, words):
    """Return True if the next nonblank/comment line starts with one of words."""
    for i in range(start_idx + 1, len(lines)):
        stripped = _strip_trailing_comment(lines[i]).strip()
        if not stripped or stripped.startswith(('//', '/*', '*')):
            continue
        return any(re.match(r'^' + word + r'\b', stripped) for word in words)
    return False


def _package_block_line(line):
    """True for ``package foo {`` style package blocks."""
    stripped = line.lstrip()
    return (
        re.match(r'^package\s+[\w.]+\s*(?:/\*.*?\*/\s*)*\{', stripped) is not None
        and _body_brace_col(stripped) >= 0
    )


def _unit_end(lines, start_idx):
    """Return the last line index of the declaration starting at ``start_idx``.

    If the declaration has a ``{ ... }`` body, returns the line of the matching
    closing brace.  Otherwise (a braceless ``def``/``class``, e.g.
    ``def double(x: UInt) = x + 1.U`` or ``abstract class Foo``) returns the last
    line of the (possibly multi-line) signature/expression.
    """
    n = len(lines)
    i = start_idx
    paren_depth = 0
    while i < n:
        brace_col, paren_depth = _body_brace_and_paren(lines[i], paren_depth)
        if brace_col >= 0:
            return _find_block_end(lines, i)
        if _signature_continues(lines[i], paren_depth):
            i += 1
            continue
        if _next_code_line_starts_with(lines, i, ("extends", "with")):
            i += 1
            continue
        return i
    return n - 1


# ---------------------------------------------------------------------------
# Public entry point invoked by extract.py
# ---------------------------------------------------------------------------


def extract_chisel_functions(lines, lang_key, lang_cfg):
    """Extract top-level Chisel/Scala declarations from a source file.

    Mirrors the contract of ``extract.py``'s ``_extract_functions_brace`` /
    ``_extract_functions_indent``: returns a list of ``(name, start_idx,
    end_idx)`` tuples (inclusive line indices) for each top-level ``class``,
    ``object``, ``trait`` or ``def``.

    Nested declarations (methods inside a module, helpers inside an object) are
    intentionally *not* split out: they belong to their enclosing unit, so a
    single extracted module re-parses to exactly one unit.
    """
    depth_start, clean_start = _scan_line_states(lines)
    units = []
    i = 0
    n = len(lines)
    package_blocks = []

    while i < n:
        package_blocks = [block for block in package_blocks if i <= block[1]]
        in_package_top = any(depth_start[i] == depth and i <= end for depth, end in package_blocks)
        at_extractable_top = depth_start[i] == 0 or in_package_top

        # Only consider declarations that begin in clean code at the file's top
        # level, including inside ``package foo { ... }`` blocks. Everything
        # nested in classes/objects/traits/defs is skipped over wholesale.
        if not clean_start[i] or not at_extractable_top:
            i += 1
            continue

        stripped = lines[i].lstrip()
        if not stripped or stripped.startswith(('//', '/*', '*')):
            i += 1
            continue
        if _package_block_line(lines[i]):
            package_blocks.append((depth_start[i] + 1, _find_block_end(lines, i)))
            i += 1
            continue
        if stripped.startswith('package ') or stripped.startswith('import '):
            i += 1
            continue

        m = _CHISEL_DECL_RE.match(stripped)
        if not m:
            i += 1
            continue

        name = m.group('name')
        end = _unit_end(lines, i)
        units.append((name, i, end))
        i = end + 1

    return units


# ---------------------------------------------------------------------------
# Call-graph helpers invoked by generate_topdown_layers.py
# ---------------------------------------------------------------------------
#
# The topdown-layer builder performs static call-graph analysis. Its generic
# routines (``_strip_comments_from_source`` / ``_find_call_sites``) are tuned
# for C-style languages and miss two Scala/Chisel realities:
#
#   * Scala block comments nest (``/* /* ... */ */``) and strings may be
#     triple-quoted, so the single-level C stripper can leak or over-consume.
#   * Inter-module dependencies in Chisel are rarely plain ``name(...)`` calls.
#     A module depends on another by *instantiating* it (``new Foo``), by
#     *inheriting* from it (``extends Foo`` / ``with Foo``), by applying its
#     companion object (``Foo(...)``) or by accessing a member (``Foo.bar``).
#
# These helpers mirror the contract of the generic ones so that
# ``generate_topdown_layers`` can delegate to them when ``body == "chisel"``.


# A reference from one top-level declaration to another. Either an identifier
# introduced by ``new`` / ``extends`` / ``with``, or an identifier immediately
# followed by ``(`` (companion apply / call) or ``.`` (member access).
_CHISEL_REF_RE = re.compile(
    r'\b(?:new|extends|with)\s+(?P<inh>[A-Za-z_$][\w$]*)'
    r'|\b(?P<ref>[A-Za-z_$][\w$]*)\s*[(.]'
)


def strip_chisel_comments(text):
    """Mask Scala/Chisel comments and string literals with spaces.

    Returns ``text`` with the contents of ``//`` line comments, nested
    ``/* */`` block comments, ``\"\"\"`` triple-quoted strings, ordinary
    ``"..."`` strings and ``'...'`` char literals replaced by spaces. Newlines
    are preserved and every other character keeps its original offset, so call
    sites found in the result map back to positions in the source.

    This is the Scala-aware counterpart to ``generate_topdown_layers``'s
    ``_strip_comments_from_source``; unlike that routine it understands nested
    block comments and triple-quoted strings.
    """
    out = list(text)
    n = len(text)
    i = 0
    block_depth = 0
    in_triple = False

    while i < n:
        ch = text[i]
        nxt = text[i + 1] if i + 1 < n else ''

        if in_triple:
            if text[i:i + 3] == '"""':
                out[i] = out[i + 1] = out[i + 2] = ' '
                in_triple = False
                i += 3
                continue
            if out[i] != '\n':
                out[i] = ' '
            i += 1
            continue

        if block_depth:
            if ch == '/' and nxt == '*':
                out[i] = out[i + 1] = ' '
                block_depth += 1
                i += 2
                continue
            if ch == '*' and nxt == '/':
                out[i] = out[i + 1] = ' '
                block_depth -= 1
                i += 2
                continue
            if out[i] != '\n':
                out[i] = ' '
            i += 1
            continue

        if ch == '/' and nxt == '/':
            while i < n and text[i] != '\n':
                out[i] = ' '
                i += 1
            continue
        if ch == '/' and nxt == '*':
            out[i] = out[i + 1] = ' '
            block_depth += 1
            i += 2
            continue
        if text[i:i + 3] == '"""':
            out[i] = out[i + 1] = out[i + 2] = ' '
            in_triple = True
            i += 3
            continue
        if ch == '"':
            end = _skip_string(text, i)
            for k in range(i, min(end, n)):
                if out[k] != '\n':
                    out[k] = ' '
            i = end
            continue
        if ch == "'":
            end = _skip_char(text, i)
            for k in range(i, min(end, n)):
                if out[k] != '\n':
                    out[k] = ' '
            i = end
            continue
        i += 1

    return ''.join(out)


def find_chisel_call_sites(text, known_stems, keywords):
    """Return the set of ``known_stems`` referenced by ``text``.

    Comments and strings are stripped first (see :func:`strip_chisel_comments`),
    then every instantiation (``new Foo``), inheritance clause (``extends`` /
    ``with Foo``), companion apply / call (``Foo(``) and member access
    (``Foo.bar``) is examined. An identifier counts as a reference when it is
    one of ``known_stems`` and not a language ``keyword``.

    Mirrors ``generate_topdown_layers._find_call_sites`` for Chisel sources.
    """
    cleaned = strip_chisel_comments(text)
    found = set()
    for m in _CHISEL_REF_RE.finditer(cleaned):
        ident = m.group('inh') or m.group('ref')
        if not ident or ident in keywords:
            continue
        if ident in known_stems:
            found.add(ident)
    return found

import json
import os
import re
import sys
import shutil
import logging

from src.file_utils import is_file_ready, _is_test_file
from src.languages.registry import batch_extract_all

LANG_CONFIG = {
    "cpp": {
        "comment_prefix": "//",
        "spec_marker": "// [SPEC]",
        "skip_prefixes": ("//", "#", "using", "typedef"),
        "skip_keywords_line": ("namespace", "struct", "class"),
        "keywords": {
            "if", "else", "while", "for", "do", "switch", "case", "return",
            "break", "continue", "goto", "new", "delete", "throw", "catch",
            "sizeof", "alignof", "decltype", "operator", "class", "struct",
            "union", "enum", "namespace", "typedef", "using", "template",
            "typename", "auto", "const", "volatile", "mutable", "extern",
            "inline", "static", "virtual", "override", "final", "explicit",
            "constexpr",
        },
        "body": "brace",
    },
    "c": {
        "comment_prefix": "//",
        "spec_marker": "// [SPEC]",
        "skip_prefixes": ("//", "#", "using", "typedef"),
        "skip_keywords_line": ("struct",),
        "keywords": {
            "if", "else", "while", "for", "do", "switch", "case", "return",
            "break", "continue", "goto", "sizeof", "struct", "union", "enum",
            "typedef", "extern", "inline", "static", "const", "volatile",
        },
        "body": "brace",
    },
    "python": {
        "comment_prefix": "#",
        "spec_marker": "# [SPEC]",
        "skip_prefixes": ("#",),
        "skip_keywords_line": ("class",),
        "keywords": {
            "if", "else", "elif", "while", "for", "with", "try", "except",
            "return", "yield", "class", "import", "from", "lambda", "assert",
            "raise",
        },
        "body": "indent",
    },
    "go": {
        "comment_prefix": "//",
        "spec_marker": "// [SPEC]",
        "skip_prefixes": ("//", "package", "import"),
        "skip_keywords_line": ("type", "var", "const"),
        "keywords": {
            "if", "else", "for", "switch", "select", "return", "defer",
            "go", "chan", "map", "range", "type", "var", "const",
        },
        "body": "brace",
    },
    "rust": {
        "comment_prefix": "//",
        "spec_marker": "// [SPEC]",
        "skip_prefixes": ("//", "use", "mod", "extern"),
        "skip_keywords_line": ("struct", "enum", "trait", "impl", "type"),
        "keywords": {
            "if", "else", "while", "for", "loop", "match", "return",
            "let", "mut", "pub", "use", "mod", "impl", "trait", "struct",
            "enum", "type", "where", "unsafe", "async", "await",
        },
        "body": "brace",
    },
    "java": {
        "comment_prefix": "//",
        "spec_marker": "// [SPEC]",
        "skip_prefixes": ("//", "import", "package"),
        "skip_keywords_line": ("class", "interface", "enum"),
        "keywords": {
            "if", "else", "while", "for", "do", "switch", "case", "return",
            "break", "continue", "goto", "new", "delete", "throw", "catch",
            "sizeof", "class", "struct", "enum", "typedef", "using",
            "interface", "abstract", "synchronized", "native", "throws",
            "instanceof", "static", "final", "void",
        },
        "body": "brace",
    },
    "typescript": {
        "comment_prefix": "//",
        "spec_marker": "// [SPEC]",
        "skip_prefixes": ("//", "import", "export type", "export interface"),
        "skip_keywords_line": ("class", "interface", "enum", "type"),
        "keywords": {
            "if", "else", "while", "for", "do", "switch", "return", "throw",
            "new", "delete", "typeof", "instanceof", "void", "const", "let",
            "var", "class", "import", "export", "async", "await",
        },
        "body": "brace",
    },
    "javascript": {
        "comment_prefix": "//",
        "spec_marker": "// [SPEC]",
        "skip_prefixes": ("//", "import"),
        "skip_keywords_line": ("class",),
        "keywords": {
            "if", "else", "while", "for", "do", "switch", "return", "throw",
            "new", "delete", "typeof", "instanceof", "void", "const", "let",
            "var", "class", "import", "export", "async", "await",
        },
        "body": "brace",
    },
    "cuda": {
        "comment_prefix": "//",
        "spec_marker": "// [SPEC]",
        "skip_prefixes": ("//", "#", "using", "typedef"),
        "skip_keywords_line": ("namespace", "struct", "class"),
        "keywords": {
            "if", "else", "while", "for", "do", "switch", "case", "return",
            "break", "continue", "goto", "new", "delete", "throw", "catch",
            "sizeof", "alignof", "decltype", "operator", "class", "struct",
            "union", "enum", "namespace", "typedef", "using", "template",
            "typename", "auto", "const", "volatile", "mutable", "extern",
            "inline", "static", "virtual", "override", "final", "explicit",
            "constexpr", "__global__", "__device__", "__host__", "__shared__",
            "__constant__", "__managed__", "__restrict__",
        },
        "body": "brace",
    },
    "arkts": {
        "comment_prefix": "//",
        "spec_marker": "// [SPEC]",
        "skip_prefixes": ("//", "import", "export type", "export interface"),
        "skip_keywords_line": ("class", "interface", "enum", "type", "struct"),
        "keywords": {
            "if", "else", "while", "for", "do", "switch", "return", "throw",
            "new", "delete", "typeof", "instanceof", "void", "const", "let",
            "var", "class", "import", "export", "async", "await", "struct",
        },
        "body": "brace",
    },
}

# Map file extensions to language keys
EXT_TO_LANG = {
    "cpp": "cpp", "cc": "cpp", "cxx": "cpp", "c": "c", "h": "cpp", "hpp": "cpp",
    "py": "python",
    "go": "go",
    "rs": "rust",
    "java": "java",
    "ts": "typescript", "tsx": "typescript",
    "js": "javascript", "jsx": "javascript",
    "cu": "cuda", "cuh": "cuda",
    "ets": "arkts",
}

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _strip_angle_brackets(text):
    """Remove balanced <...> segments from text (for template parameters)."""
    result = []
    depth = 0
    for ch in text:
        if ch == '<':
            depth += 1
        elif ch == '>':
            if depth > 0:
                depth -= 1
        else:
            if depth == 0:
                result.append(ch)
    return ''.join(result)


def _extract_func_name_brace(signature_text, lang_cfg):
    """Extract the function name from a brace-delimited language signature."""
    lang_keywords = lang_cfg["keywords"]
    cleaned = _strip_angle_brackets(signature_text)
    for m in re.finditer(r'\b(\w+)\s*\(', cleaned):
        name = m.group(1)
        if name not in lang_keywords:
            return name
    return None


def _find_brace_end(lines, start_idx):
    """Find the line index of the closing '}' that matches the first '{' at or after start_idx.

    Handles string/char literals and // comments. Braces belonging to Go
    anonymous composite types (`interface{...}` / `struct{...}`, possibly
    spanning multiple lines) are tracked separately so they are not mistaken
    for the function body.

    Returns the line index of the closing brace, or len(lines)-1 if unmatched.
    """
    depth = 0
    found_open = False
    # Depth of braces inside an anonymous composite type; these do not count
    # toward the function body. `pending_type_brace` means an `interface`/
    # `struct` keyword was seen and its opening `{` is expected next.
    type_depth = 0
    pending_type_brace = False
    for i in range(start_idx, len(lines)):
        line = lines[i]
        j = 0
        while j < len(line):
            ch = line[j]
            # Skip string literals
            if ch == '"':
                j += 1
                while j < len(line):
                    if line[j] == '\\':
                        j += 2
                        continue
                    if line[j] == '"':
                        j += 1
                        break
                    j += 1
                continue
            # Skip char literals
            if ch == "'":
                j += 1
                while j < len(line):
                    if line[j] == '\\':
                        j += 2
                        continue
                    if line[j] == "'":
                        j += 1
                        break
                    j += 1
                continue
            # Line comment — skip rest
            if ch == '/' and j + 1 < len(line) and line[j + 1] == '/':
                break
            # Block comment
            if ch == '/' and j + 1 < len(line) and line[j + 1] == '*':
                j += 2
                while j < len(line):
                    if line[j] == '*' and j + 1 < len(line) and line[j + 1] == '/':
                        j += 2
                        break
                    j += 1
                # If block comment spans lines, continue on next line
                # (simplified: assume single-line block comments for now)
                continue
            # Inside an anonymous composite type: its braces belong to the type,
            # not the function body, so track them with a separate counter.
            if type_depth > 0:
                if ch == '{':
                    type_depth += 1
                elif ch == '}':
                    type_depth -= 1
                j += 1
                continue
            # A keyword's opening '{' is expected; consume whitespace until it.
            if pending_type_brace:
                if ch in ' \t':
                    j += 1
                    continue
                if ch == '{':
                    type_depth = 1
                    pending_type_brace = False
                    j += 1
                    continue
                # Not actually a composite type; fall through to normal handling.
                pending_type_brace = False
            # Detect Go anonymous composite types `interface{...}` / `struct{...}`,
            # whose braces (even when the type spans multiple lines) must not be
            # counted as the function body's braces.
            if ch in 'is' and (line.startswith('interface', j) or line.startswith('struct', j)):
                kw_len = 9 if line.startswith('interface', j) else 6
                end = j + kw_len
                prev_ok = j == 0 or not (line[j - 1].isalnum() or line[j - 1] == '_')
                next_ok = end >= len(line) or not (line[end].isalnum() or line[end] == '_')
                if prev_ok and next_ok:
                    k = end
                    while k < len(line) and line[k] in ' \t':
                        k += 1
                    if k < len(line) and line[k] == '{':
                        type_depth = 1
                        j = k + 1
                        continue
                    if k >= len(line):
                        # The opening '{' is on a following line.
                        pending_type_brace = True
                    j = end
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


# ---------------------------------------------------------------------------
# Brace-delimited extraction (C/C++, Java, Go, Rust, JS/TS)
# ---------------------------------------------------------------------------


def _extract_functions_brace(lines, lang_key, lang_cfg):
    """Extract functions from a brace-delimited language source."""
    functions = []
    i = 0
    skip_prefixes = lang_cfg["skip_prefixes"]
    skip_kw_line = lang_cfg["skip_keywords_line"]
    in_block_comment = False
    _block_comment_langs = {"cpp", "c", "cuda", "java", "javascript", "typescript", "arkts"}

    while i < len(lines):
        line = lines[i]
        stripped = line.lstrip()

        # Skip blank lines
        if not stripped:
            i += 1
            continue

        # Skip /* */ block comments for C-family languages
        if lang_key in _block_comment_langs:
            if in_block_comment:
                end_idx = stripped.find("*/")
                if end_idx != -1:
                    in_block_comment = False
                i += 1
                continue
            start_idx = stripped.find("/*")
            if start_idx != -1:
                # Check whether the block comment closes on the same line
                after_start = stripped[start_idx + 2:]
                if "*/" not in after_start:
                    in_block_comment = True
                i += 1
                continue

        # Skip comment / preprocessor / using lines
        if any(stripped.startswith(p) for p in skip_prefixes):
            i += 1
            continue

        # Handle anonymous namespace (C++)
        if lang_key in ("cpp", "c") and re.match(r'^namespace\s*\{', stripped):
            # Descend into anonymous namespace — skip the opening line
            i += 1
            continue

        # Handle named namespace — skip entire block
        if lang_key in ("cpp", "c") and re.match(r'^namespace\s+\w', stripped):
            # Find the opening brace and skip to the matching close
            # But we actually want to scan inside named namespaces too for
            # functions. Let's just skip the namespace line and descend.
            if '{' in stripped:
                i += 1
                continue
            else:
                # Multi-line namespace declaration — skip until {
                j = i + 1
                while j < len(lines) and '{' not in lines[j]:
                    j += 1
                i = j + 1
                continue

        # Skip lines starting with class/struct/etc. keywords
        if any(stripped.startswith(kw) for kw in skip_kw_line):
            # But if it's a method definition (has '(' and '{'), still skip
            i += 1
            continue

        # Skip constexpr variable declarations (C++)
        if lang_key in ("cpp", "c") and stripped.startswith("constexpr") and stripped.endswith(";"):
            i += 1
            continue

        # Go: detect func keyword
        if lang_key == "go":
            if not stripped.startswith("func ") and not stripped.startswith("func("):
                i += 1
                continue
            # Extract name
            m = re.search(r'func\s+(?:\([^)]*\)\s*)?(\w+)', stripped)
            if not m:
                i += 1
                continue
            name = m.group(1)
            # Find opening brace
            sig_lines = [lines[i]]
            sig_end = i
            for look in range(i, min(i + 10, len(lines))):
                if '{' in lines[look]:
                    sig_end = look
                    sig_lines = lines[i:look + 1]
                    break
            end = _find_brace_end(lines, sig_end)
            functions.append((name, i, end))
            i = end + 1
            continue

        # Rust: detect fn keyword
        if lang_key == "rust":
            m = re.match(
                r'(?:pub(?:\s*\([^)]*\))?\s+)?'   # pub, pub(crate), pub(super), pub(in ...)
                r'(?:default\s+)?'
                r'(?:const\s+)?'
                r'(?:async\s+)?'
                r'(?:unsafe\s+)?'
                r'(?:extern\s+"[^"]*"\s+)?'
                r'fn\s+(\w+)',
                stripped,
            )
            if not m:
                i += 1
                continue
            # Skip functions annotated with #[test].
            # Walk backward through the contiguous run of attribute/blank lines
            # that immediately precede this fn — stop at the first line that is
            # neither blank nor an attribute (#[...]) so we never reach a #[test]
            # that belonged to a different, already-processed function.
            j = i - 1
            has_test_attr = False
            while j >= 0:
                prev = lines[j].strip()
                if prev == '' or re.match(r'^#\[', prev) or prev.startswith('//'):
                    if prev == '#[test]':
                        has_test_attr = True
                        break
                    j -= 1
                else:
                    break
            if has_test_attr:
                sig_end = i
                for look in range(i, min(i + 10, len(lines))):
                    if '{' in lines[look]:
                        sig_end = look
                        break
                i = _find_brace_end(lines, sig_end) + 1
                continue
            name = m.group(1)
            sig_end = i
            for look in range(i, min(i + 10, len(lines))):
                if '{' in lines[look]:
                    sig_end = look
                    break
            end = _find_brace_end(lines, sig_end)
            functions.append((name, i, end))
            i = end + 1
            continue

        # For C/C++/Java/JS/TS: candidate line has '(' and does not end with ';'
        # Must not be indented (column 0) for C/C++; for Java/JS/TS allow indentation
        if lang_key in ("cpp", "c"):
            if line[0:1].isspace():
                i += 1
                continue

        if '(' not in stripped or stripped.rstrip().endswith(';'):
            i += 1
            continue

        # Collect signature lines up to opening brace
        sig_start = i
        sig_end = i
        sig_text = stripped
        for look in range(i, min(i + 6, len(lines))):
            if '{' in lines[look]:
                sig_end = look
                sig_text = ' '.join(lines[sig_start:look + 1])
                break

        if '{' not in lines[sig_end]:
            i += 1
            continue

        # JS/TS: also handle `function name(` syntax
        if lang_key in ("javascript", "typescript", "arkts"):
            m = re.search(r'\bfunction\s+(\w+)', sig_text)
            if m:
                name = m.group(1)
            else:
                name = _extract_func_name_brace(sig_text, lang_cfg)
        else:
            name = _extract_func_name_brace(sig_text, lang_cfg)

        if not name:
            i += 1
            continue

        end = _find_brace_end(lines, sig_end)
        functions.append((name, sig_start, end))
        i = end + 1

    return functions


# ---------------------------------------------------------------------------
# Indent-based extraction (Python)
# ---------------------------------------------------------------------------


def _extract_functions_indent(lines, lang_cfg):
    """Extract functions from an indent-delimited language (Python)."""
    functions = []
    i = 0
    while i < len(lines):
        line = lines[i]
        stripped = line.lstrip()

        # Look for 'def ' at any indentation level
        m = re.match(r'^(\s*)def\s+(\w+)\s*\(', line)
        if not m:
            i += 1
            continue

        indent = len(m.group(1))
        name = m.group(2)
        func_start = i

        # Handle decorators — walk backwards to include them
        while func_start > 0 and lines[func_start - 1].strip().startswith('@'):
            func_start -= 1

        # Find end of function body: subsequent lines with greater indentation
        # (or blank lines interspersed)
        j = i + 1
        while j < len(lines):
            l = lines[j]
            if l.strip() == '':
                j += 1
                continue
            line_indent = len(l) - len(l.lstrip())
            if line_indent == indent and re.match(r'\)\s*(:|->)', l.lstrip()):
                j += 1
                continue
            if line_indent <= indent:
                break
            j += 1

        # j is now the first line after the function body
        func_end = j - 1
        # Trim trailing blank lines
        while func_end > i and lines[func_end].strip() == '':
            func_end -= 1

        functions.append((name, func_start, func_end))
        i = j

    return functions


# ---------------------------------------------------------------------------
# Core extraction driver
# ---------------------------------------------------------------------------


def extract_functions_from_file(filepath, lang_key):
    """Extract all functions from a single source file.

    Returns a list of (function_name, source_text) tuples.
    """
    lang_cfg = LANG_CONFIG[lang_key]

    with open(filepath, 'r', errors='replace') as f:
        lines = f.readlines()

    # Normalize line endings
    lines = [l.rstrip('\n').rstrip('\r') for l in lines]

    if lang_cfg["body"] == "brace":
        raw_funcs = _extract_functions_brace(lines, lang_key, lang_cfg)
    else:
        raw_funcs = _extract_functions_indent(lines, lang_cfg)

    # Deduplicate names
    name_counts = {}
    results = []
    for name, start, end in raw_funcs:
        count = name_counts.get(name, 0)
        name_counts[name] = count + 1
        if count > 0:
            deduped = f"{name}_{count}"
        else:
            deduped = name
        source = '\n'.join(lines[start:end + 1]) + '\n'
        results.append((deduped, source))

    return results


def run_extraction(proj_dir, work_dir=None, force=False, verbose=False):
    """Run function extraction on a project directory.

    Reads phases.json from work_dir (or proj_dir), extracts functions from
    source files in proj_dir, writes them to work_dir/extracted_functions/,
    and validates the output.

    Returns (written_count, skipped_count).
    """
    if work_dir is None:
        work_dir = proj_dir
    phases_path = os.path.join(work_dir, "phases.json")
    if not os.path.exists(phases_path):
        raise FileNotFoundError(f"phases.json not found at {phases_path}")

    with open(phases_path, 'r') as f:
        phases_data = json.load(f)

    registry_funcs, registry_langs = batch_extract_all(proj_dir)

    # Build source file list from phases.json
    source_files = []
    for phase in phases_data.get("phases", []):
        for module in phase.get("modules", []):
            for sf in module.get("source_files", []):
                source_files.append(sf)

    output_base = os.path.join(work_dir, "extracted_functions")
    written = 0
    skipped = 0
    errors = []

    for src_rel in source_files:
        # Skip test files
        if _is_test_file(src_rel):
            if verbose:
                print(f"  SKIP (test): {src_rel}")
            continue

        src_path = os.path.join(proj_dir, src_rel)
        if not os.path.exists(src_path):
            logging.warning(f"Source file not found: {src_path}")
            continue

        # Detect language from file extension
        ext = src_rel.rsplit('.', 1)[-1] if '.' in src_rel else ''
        lang_key = EXT_TO_LANG.get(ext)
        if not lang_key:
            logging.warning(f"Unsupported file extension '.{ext}' for {src_rel}, skipping.")
            continue

        # Compute output directory: replace last dot in filename with hyphen
        src_dir = os.path.dirname(src_rel)
        src_base = os.path.basename(src_rel)
        last_dot = src_base.rfind('.')
        if last_dot > 0:
            dir_name = src_base[:last_dot] + '-' + src_base[last_dot + 1:]
        else:
            dir_name = src_base
        out_dir = os.path.join(output_base, src_dir, dir_name) if src_dir else os.path.join(output_base, dir_name)

        if src_path in registry_funcs:
            funcs = registry_funcs[src_path]
        else:
            funcs = extract_functions_from_file(src_path, lang_key)
        if not funcs:
            logging.warning(f"No functions extracted from {src_rel}")
            continue

        os.makedirs(out_dir, exist_ok=True)

        for func_name, func_source in funcs:
            out_file = os.path.join(out_dir, f"{func_name}.{ext}")

            # Skip only when the file already has both [SPEC] and [INFO] blocks
            if not force and os.path.exists(out_file) and is_file_ready(out_file):
                if verbose:
                    print(f"  SKIP (specced): {os.path.relpath(out_file, proj_dir)}")
                skipped += 1
                continue

            with open(out_file, 'w') as f:
                f.write(func_source)
            written += 1
            if verbose:
                print(f"  WRITE: {os.path.relpath(out_file, proj_dir)}")

    print(f"Extraction complete: {written} written, {skipped} skipped.")

    if written == 0 and skipped == 0:
        logging.error("Nothing was extracted — check phases.json source_files paths.")
        return written, skipped

    # --- Validation (Step 2) ---
    validation_failures = _validate_extraction(output_base, registry_langs=registry_langs)
    if validation_failures:
        logging.warning(
            f"Validation: {len(validation_failures)} file(s) do not contain exactly one function."
        )
        for path, count in validation_failures:
            rel = os.path.relpath(path, proj_dir)
            logging.warning(f"  {rel}: {count} function(s) detected")
        if verbose:
            print(f"Validation WARNING: {len(validation_failures)} file(s) with != 1 function.")
            for path, count in validation_failures:
                print(f"  {os.path.relpath(path, proj_dir)}: {count} function(s)")
    else:
        if verbose:
            print("Validation passed: every extracted file contains exactly one function.")

    return written, skipped


def _validate_extraction(extracted_dir, registry_langs=None):
    """Re-parse every extracted file and verify each contains exactly one function.

    Files for languages that returned data from their REGISTRY backend are skipped:
    those backends write exactly one function body per file by construction, so
    regex re-parsing adds no safety and produces false negatives for forms the
    regex cannot recognise (async def, class methods, arrow functions).

    Returns a list of (file_path, function_count) for files that fail validation.
    """
    failures = []
    for root, _, files in os.walk(extracted_dir):
        for fname in files:
            ext = fname.rsplit('.', 1)[-1] if '.' in fname else ''
            lang_key = EXT_TO_LANG.get(ext)
            if not lang_key:
                continue
            if registry_langs and lang_key in registry_langs:
                continue
            fpath = os.path.join(root, fname)
            funcs = extract_functions_from_file(fpath, lang_key)
            if len(funcs) != 1:
                failures.append((fpath, len(funcs)))
    return failures

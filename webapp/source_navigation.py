from __future__ import annotations

import html
import re
from pathlib import Path
from typing import Iterable

from pygments.lexers import TextLexer, get_lexer_for_filename
from pygments.token import Comment, Generic, Keyword, Name, Number, Operator, Punctuation, String
from pygments.util import ClassNotFound


IDENTIFIER = re.compile(r"[A-Za-z_$][A-Za-z0-9_$]*\Z")
IDENTIFIER_PART = re.compile(r"[A-Za-z_$][A-Za-z0-9_$]*")


def _lexer(filename: str):
    try:
        return get_lexer_for_filename(filename, stripnl=False, ensurenl=False)
    except ClassNotFound:
        return TextLexer(stripnl=False, ensurenl=False)


def _token_class(token) -> str:
    if token in Comment:
        return "tok-comment"
    if token in Keyword:
        return "tok-keyword"
    if token in String:
        return "tok-string"
    if token in Number:
        return "tok-number"
    if token in Name.Function:
        return "tok-function"
    if token in Name.Class or token in Name.Namespace:
        return "tok-type"
    if token in Name.Decorator:
        return "tok-decorator"
    if token in Name.Builtin or token in Name.Exception:
        return "tok-builtin"
    if token in Name.Constant:
        return "tok-constant"
    if token in Name:
        return "tok-name"
    if token in Operator:
        return "tok-operator"
    if token in Punctuation:
        return "tok-punctuation"
    if token in Generic:
        return "tok-generic"
    return ""


def highlight_source_lines(content: str, filename: str) -> list[str]:
    """Return escaped, line-aligned HTML using VS Code Light+-like token classes."""
    rendered = [""]
    lexer = _lexer(filename)
    for _, token, value in lexer.get_tokens_unprocessed(content):
        css_class = _token_class(token)
        pieces = value.split("\n")
        for index, piece in enumerate(pieces):
            if piece:
                if token in Name:
                    cursor = 0
                    for match in IDENTIFIER_PART.finditer(piece):
                        if match.start() > cursor:
                            rendered[-1] += _token_span(piece[cursor:match.start()], css_class)
                        symbol = match.group()
                        rendered[-1] += _token_span(
                            symbol, f"{css_class} symbol-token".strip(), symbol
                        )
                        cursor = match.end()
                    if cursor < len(piece):
                        rendered[-1] += _token_span(piece[cursor:], css_class)
                else:
                    rendered[-1] += _token_span(piece, css_class)
            if index < len(pieces) - 1:
                rendered.append("")
    expected = len(content.split("\n"))
    if len(rendered) < expected:
        rendered.extend([""] * (expected - len(rendered)))
    return rendered[:expected]


def _token_span(value: str, css_class: str, symbol: str | None = None) -> str:
    class_attribute = f' class="{css_class}"' if css_class else ""
    symbol_attribute = (
        f' data-symbol="{html.escape(symbol, quote=True)}"' if symbol else ""
    )
    return f"<span{class_attribute}{symbol_attribute}>{html.escape(value, quote=False)}</span>"


def _definition_patterns(symbol: str, suffix: str) -> list[tuple[int, re.Pattern[str]]]:
    name = re.escape(symbol)
    boundary = rf"(?<![A-Za-z0-9_$]){name}(?![A-Za-z0-9_$])"
    patterns: list[tuple[int, str]] = [
        (0, rf"^\s*#\s*define\s+{boundary}"),
        (0, rf"^\s*(?:async\s+)?(?:def|class)\s+{boundary}"),
        (0, rf"^\s*(?:export\s+)?(?:default\s+)?(?:async\s+)?function\s+{boundary}"),
        (0, rf"^\s*(?:pub(?:\([^)]*\))?\s+)?(?:async\s+)?fn\s+{boundary}"),
        (0, rf"^\s*func\s+(?:\([^)]*\)\s*)?{boundary}\s*\("),
        (0, rf"^\s*{boundary}\s*\([^)]*\)\s*->"),
        (1, rf"^\s*(?:(?:export|public|private|protected|internal|static|final|abstract|sealed|open)\s+)*(?:class|struct|interface|enum|trait|record|type)\s+{boundary}"),
        (1, rf"^\s*(?:(?:export|public|private|protected|static|readonly|declare)\s+)*(?:const|let|var)\s+{boundary}"),
        (3, rf"^\s*(?:(?:async|static|get|set)\s+)*{boundary}\s*\([^;]*\)\s*(?:\{{|=>|$)"),
        (4, rf"^\s*(?:(?:const|let|var|static|final|readonly)\s+)+(?:[A-Za-z_$][\w$:<>,.?\[\]*&~]*\s+)?{boundary}\s*(?:=|;|,)"),
    ]
    if suffix == ".py":
        patterns.extend((
            (4, rf"^\s*{boundary}\s*:\s*[^=]+(?:=|$)"),
            (5, rf"^\s*(?:self|cls)\.{boundary}\s*="),
            (5, rf"^\s*{boundary}\s*="),
        ))
    if suffix == ".go":
        patterns.append((4, rf"^\s*{boundary}\s*:="))
    return [(rank, re.compile(pattern)) for rank, pattern in patterns]


_TYPE_PREFIX = re.compile(r"^[A-Za-z_$][\w$:<>,.?\[\]*&~\s]*$")
_NON_TYPE_PREFIX = re.compile(
    r"^(?:return|throw|if|else|while|for|switch|case|goto|break|continue|await|yield|import|from)\b"
)


def _typed_function_rank(line: str, symbol: str) -> int | None:
    """Recognize C-like signatures without an ambiguous, backtracking regex."""
    for match in re.finditer(rf"(?<![A-Za-z0-9_$]){re.escape(symbol)}(?![A-Za-z0-9_$])", line):
        prefix, suffix = line[:match.start()].strip(), line[match.end():].lstrip()
        if not suffix.startswith("("):
            continue
        if not prefix or not _TYPE_PREFIX.fullmatch(prefix) or _NON_TYPE_PREFIX.match(prefix):
            continue
        if prefix.endswith((".", "->", "::")):
            continue
        # A declaration can span several lines; the opening line is still useful.
        closing = suffix.rfind(")")
        if closing < 0:
            return 2
        trailing = suffix[closing + 1:].strip()
        return 6 if trailing.startswith(";") or trailing.endswith(";") else 2
    return None


def _typed_declaration_rank(line: str, symbol: str) -> int | None:
    """Recognize typed fields and variables, including pointer and array declarations."""
    for match in re.finditer(rf"(?<![A-Za-z0-9_$]){re.escape(symbol)}(?![A-Za-z0-9_$])", line):
        prefix, suffix = line[:match.start()].strip(), line[match.end():].lstrip()
        if not prefix or not _TYPE_PREFIX.fullmatch(prefix) or _NON_TYPE_PREFIX.match(prefix):
            continue
        if prefix.endswith((".", "->", "::")) or not re.search(r"[A-Za-z_$]", prefix):
            continue
        if not suffix.startswith(("=", ";", ",", "[", ":")):
            continue
        return 7 if re.match(r"^extern\b", prefix) else 4
    return None


def _enum_member_rank(lines: list[str], index: int, symbol: str) -> int | None:
    boundary = rf"(?<![A-Za-z0-9_$]){re.escape(symbol)}(?![A-Za-z0-9_$])"
    if not re.match(rf"^\s*{boundary}\s*(?:=|,|$)", lines[index]):
        return None
    for previous in reversed(lines[max(0, index - 80):index]):
        if re.match(r"^\s*}", previous):
            break
        if re.search(r"\benum\b[^;]*\{", previous):
            return 3
    return None


def find_symbol_definition(
    files: Iterable[tuple[str, str]],
    symbol: str,
    current_path: str,
    current_line: int,
) -> dict | None:
    if not IDENTIFIER.fullmatch(symbol):
        return None
    candidates: list[tuple[tuple[int, int, int, int, str], dict]] = []
    for relative, content in files:
        patterns = _definition_patterns(symbol, Path(relative).suffix.lower())
        lines = content.splitlines()
        for index, line in enumerate(lines):
            line_number = index + 1
            if symbol not in line:
                continue
            if re.match(r"^\s*(?://|/\*|\*|#(?!\s*define\b))", line):
                continue
            matched_rank = None
            for rank, pattern in patterns:
                if not pattern.search(line):
                    continue
                matched_rank = rank
                break
            if matched_rank is None:
                matched_rank = _typed_function_rank(line, symbol)
            if matched_rank is None:
                matched_rank = _typed_declaration_rank(line, symbol)
            if matched_rank is None:
                matched_rank = _enum_member_rank(lines, index, symbol)
            if matched_rank is None:
                continue
            # A prototype is a fallback; prefer the implementation in another file.
            if re.search(rf"\b{re.escape(symbol)}\s*\([^;]*\)\s*;\s*$", line):
                matched_rank = max(matched_rank, 6)
            same_file = relative == current_path
            same_directory = Path(relative).parent == Path(current_path).parent
            distance = abs(line_number - current_line) if same_file else line_number
            score = (matched_rank, 0 if same_file else 1, 0 if same_directory else 1, distance, relative)
            candidates.append(
                (
                    score,
                    {
                        "path": relative,
                        "line": line_number,
                        "symbol": symbol,
                        "preview": line.strip()[:240],
                    },
                )
            )
    if not candidates:
        return None
    candidates.sort(key=lambda item: item[0])
    result = candidates[0][1]
    result["candidate_count"] = len(candidates)
    return result

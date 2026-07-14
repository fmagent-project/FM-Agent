"""
scope.py — Function-level localization within scoped files.

Given a set of files already identified as relevant to a developer intent
(a feature request, change description, or bug report), this module narrows
them down to the specific functions most likely to need changing. It is
driven in-memory by incremental_reasoner.collect_relevent_function_scope:
rank_functions_in_file returns the ranked functions directly (no JSON file
is read or written here). Throughout this module the `issue` parameter is
that developer-intent text.

Language support: Python files are parsed with the `ast` module (richest signal
extraction). Every other language with an extension registered in extract.EXT_TO_LANG
(C/C++, Java, Go, Rust, JS/TS, CUDA, ArkTS, …) is parsed with the same brace/indent
function extractor used by extract.py, with identifiers, calls, and exception types
recovered by regex (class-scope narrowing is Python-only).

Pipeline
--------
Stage 1 – Heuristic scoring  (always runs, no LLM cost)
    Signal tiers extracted from the intent text, in decreasing weight:
        T1  Traceback function names ("  in func_name")            ×10
        T2  Backtick / code-block identifiers                     ×5 (name), ×2 (body)
        T3  Explicit Class.method dotted references               ×15
        T4  CamelCase / snake_case identifiers in prose           ×3
        T5  Exception type matching (raise/except in body)        ×4
        T6  Body word overlap, normalised by √(lines)             ×1

    Post-scoring enrichments:
        • Intra-file call-graph propagation (callee ×0.30, caller ×0.20)
        • Class-scope narrowing: score classes by name/docstring overlap
          with the intent, then boost all methods of top-matching classes

Stage 2 – LLM re-ranking  (optional, triggered when file has ≥ LLM_TRIGGER_FUNCS
    unique functions after dedup, or heuristic top score < confidence threshold)
    Sends only function signatures + first docstring line; no bodies.
    Falls back to heuristic on failure.

Returns (rank_functions_in_file): a list of dicts, one per selected function,
sorted by descending score:
    {"file": "...", "name": "...", "lineno": N, "end_lineno": M,
     "score": 12.4, "reason": "heuristic"}
"""

from __future__ import annotations

import ast
from difflib import SequenceMatcher
import json
import logging
import re
import time
from collections import defaultdict
from pathlib import Path
from typing import Any

from config import (
    SCOPE_LLM_CONFIDENCE_THRESHOLD,
    SCOPE_LLM_TOP_K,
    SCOPE_LLM_TRIGGER_FUNCS,
    SCOPE_TOP_K,
)

from .extract import (
    EXT_TO_LANG,
    LANG_CONFIG,
    _function_spans,
)

logger = logging.getLogger(__name__)

# ── tuneable constants ──────────────────────────────────────────────────────
TOP_K = SCOPE_TOP_K               # functions to keep per file in the final output
LLM_TRIGGER_FUNCS = SCOPE_LLM_TRIGGER_FUNCS  # file has ≥ this many (deduped) functions → try LLM
LLM_TOP_K = SCOPE_LLM_TOP_K           # how many functions to ask the LLM to pick
LLM_CONFIDENCE_THRESHOLD = SCOPE_LLM_CONFIDENCE_THRESHOLD  # top heuristic score below this → try LLM

# Signal weights
W_TRACEBACK        = 10.0
W_BACKTICK_NAME    =  5.0
W_BACKTICK_BODY    =  2.0
W_DOTTED_REF       = 15.0   # Class.method explicit reference in issue
W_PLAIN_NAME       =  3.0
W_NAME_ALL_WORDS   =  1.5   # function name parts ∩ issue all_words (prose nouns); lower weight to avoid boosting generic names
W_FUZZY_NAME       =  1.4   # conservative typo-tolerant match against function name parts only
W_EXCEPTION_MATCH  =  4.0   # issue exception type found in function body
W_BODY_WORDS       =  1.0   # multiplied by overlap / sqrt(body_lines)

FUZZY_NAME_MIN_LEN   = 5
FUZZY_NAME_THRESHOLD = 0.75

# Call-graph propagation weights
CALLEE_INHERIT = 0.30
CALLER_INHERIT = 0.20

# Class-scope narrowing
W_CLASS_NAME_MATCH   = 6.0  # per overlapping token between class name and intent
W_CLASS_DOC_MATCH    = 2.0  # per overlapping token between class docstring and intent
# Class method inheritance: cap so a single high-scoring class doesn't flood top slots.
# Absolute cap: per-method bonus ≤ CLASS_BOOST_CAP regardless of class score.
CLASS_METHOD_INHERIT = 0.40 # fraction of class score passed to every method
CLASS_BOOST_CAP      = 8.0  # hard cap on per-method class bonus

# Python keywords that are too noisy as backtick identifiers
_PY_KEYWORDS = frozenset({
    'class', 'def', 'return', 'import', 'from', 'with', 'for', 'while', 'if',
    'else', 'elif', 'try', 'except', 'finally', 'raise', 'pass', 'break',
    'continue', 'lambda', 'yield', 'global', 'nonlocal', 'assert', 'del',
    'and', 'or', 'not', 'in', 'is', 'none', 'true', 'false', 'async', 'await',
    # common builtins also too noisy
    'self', 'cls', 'super', 'print', 'list', 'dict', 'tuple', 'set', 'str',
    'int', 'float', 'bool', 'type', 'len', 'range', 'open', 'isinstance',
})


def _extract_backtick_idents(issue_text: str) -> set[str]:
    """Extract meaningful identifiers from backtick spans and code blocks.

    Filters out Python keywords, common builtins, and RST/Sphinx role prefixes
    (e.g. ``py:class`` → keep nothing; ``Literal`` → keep 'literal').
    """
    result: set[str] = set()

    def _add(token: str) -> None:
        t = token.lower().strip('_')
        if len(t) >= 2 and t not in _PY_KEYWORDS and t not in _STOP:
            result.add(t)

    for raw in re.findall(r'`([^`]+)`', issue_text):
        # Strip RST/Sphinx role prefix (e.g. "py:class", "ref:", "meth:")
        raw = re.sub(r'^[a-z]+:[a-z]+\s*', '', raw.strip())
        for part in re.findall(r'[a-zA-Z_][a-zA-Z0-9_]{1,}', raw):
            _add(part)

    for block in re.findall(r'```.*?```', issue_text, re.DOTALL):
        for ident in re.findall(r'\b([a-zA-Z_][a-zA-Z0-9_]{2,})\b', block):
            _add(ident)

    return result


# Stop-words for prose word extraction
_STOP = frozenset({
    'this', 'that', 'with', 'from', 'have', 'been', 'will', 'also',
    'when', 'then', 'they', 'them', 'some', 'into', 'more', 'like',
    'such', 'which', 'were', 'each', 'does', 'what', 'about',
    'would', 'should', 'could', 'their', 'there', 'where', 'these',
    'those', 'after', 'before', 'other', 'only', 'using', 'used',
    'code', 'issue', 'error', 'function', 'class', 'method', 'file',
    'line', 'true', 'false', 'none', 'type', 'value', 'object',
    'self', 'args', 'kwargs', 'return', 'raise', 'pass', 'import',
})


# ── signal extraction ───────────────────────────────────────────────────────

def _parse_issue_signals(issue_text: str) -> dict[str, set[str]]:
    """Extract multiple tiers of signals from the raw developer-intent text."""
    signals: dict[str, set[str]] = {
        'traceback_funcs': set(),
        'backtick_idents': set(),
        'dotted_refs':     set(),   # method names from Class.method refs
        'dotted_classes':  set(),   # class names from Class.method refs
        'plain_idents':    set(),
        'exception_types': set(),   # exception type names mentioned in the intent
        'all_words':       set(),
    }

    # T1: function names from Python tracebacks
    signals['traceback_funcs'] = set(re.findall(r'\bin (\w+)\s*\n', issue_text))

    # T2: identifiers inside backticks or fenced code blocks
    signals['backtick_idents'] = _extract_backtick_idents(issue_text)

    # T3: explicit Class.method dotted references
    for cls, meth in re.findall(r'\b([A-Z][a-zA-Z0-9]+)\.([a-z_][a-z0-9_]+)\b',
                                issue_text):
        signals['dotted_refs'].add(meth.lower())
        signals['dotted_classes'].add(cls.lower())
        # also add the method name parts
        for part in meth.lower().split('_'):
            if len(part) > 1:
                signals['dotted_refs'].add(part)

    # T4: CamelCase / snake_case words in prose
    for w in re.findall(r'\b([a-zA-Z_][a-zA-Z0-9_]*(?:[A-Z_][a-zA-Z0-9_]+)+)\b',
                        issue_text):
        signals['plain_idents'].add(w.lower())
        for part in re.sub(r'([A-Z])', r'_\1', w).lower().strip('_').split('_'):
            if len(part) > 2:
                signals['plain_idents'].add(part)

    # T5: exception types  (e.g. AssertionError, ImportError)
    for exc in re.findall(r'\b([A-Z][a-zA-Z]+(?:Error|Exception|Warning))\b',
                          issue_text):
        signals['exception_types'].add(exc.lower())

    # T6: all alphabetic words ≥ 4 chars that aren't stop words
    for w in re.findall(r'\b([a-zA-Z]{4,})\b', issue_text.lower()):
        if w not in _STOP:
            signals['all_words'].add(w)

    return signals


# ── per-function info extraction ─────────────────────────────────────────────

def _name_parts(name: str) -> set[str]:
    """Split a function name into searchable parts (snake + camelCase + consecutive pairs).

    Examples:
        'dmp_clear_denoms' → {'dmp', 'clear', 'denoms', 'dmp_clear', 'clear_denoms',
                               'dmp_clear_denoms'}
        '_parse_annotation' → {'parse', 'annotation', 'parse_annotation',
                                '_parse_annotation'}
    """
    parts = set()
    lower = name.lower()
    parts.add(lower)

    # snake_case: individual tokens and consecutive-pair compounds
    toks = [t for t in lower.split('_') if len(t) > 1]
    for t in toks:
        parts.add(t)
    for i in range(len(toks) - 1):
        parts.add(f"{toks[i]}_{toks[i+1]}")

    # CamelCase split
    for p in re.sub(r'([A-Z])', r'_\1', name).lower().strip('_').split('_'):
        if len(p) > 1:
            parts.add(p)

    return parts


def _fuzzy_name_score(parts: set[str], signals: dict[str, set[str]]) -> float:
    """Return a small typo-tolerant score for long intent tokens vs function names."""
    intent_tokens = (
        signals['backtick_idents']
        | signals['plain_idents']
        | signals['dotted_refs']
        | signals['all_words']
    )
    intent_tokens = {
        t for t in intent_tokens
        if len(t) >= FUZZY_NAME_MIN_LEN and t not in _STOP and t not in _PY_KEYWORDS
    }
    name_tokens = {
        p for p in parts
        if len(p) >= FUZZY_NAME_MIN_LEN and p not in _STOP and p not in _PY_KEYWORDS
    }

    score = 0.0
    for token in intent_tokens:
        if token in name_tokens:
            continue
        best = 0.0
        for part in name_tokens:
            if part in intent_tokens:
                continue
            ratio = SequenceMatcher(None, token, part).ratio()
            if ratio > best:
                best = ratio
        if best >= FUZZY_NAME_THRESHOLD:
            score += W_FUZZY_NAME * best
    return score


def _collect_func_idents(node: ast.FunctionDef | ast.AsyncFunctionDef,
                          source_lines: list[str]) -> tuple[set[str], set[str], set[str]]:
    """Return (identifier_set, body_words_set, raised_exception_types)."""
    idents: set[str] = set()
    exc_types: set[str] = set()

    for n in ast.walk(node):
        if isinstance(n, ast.Name):
            idents.add(n.id.lower())
        elif isinstance(n, ast.Attribute):
            idents.add(n.attr.lower())
        elif isinstance(n, ast.arg):
            idents.add(n.arg.lower())
        elif isinstance(n, ast.Constant) and isinstance(n.value, str):
            for w in re.findall(r'[a-zA-Z_][a-zA-Z0-9_]{2,}', n.value):
                idents.add(w.lower())
        # collect raised exception types
        elif isinstance(n, ast.Raise):
            if n.exc:
                exc_node = n.exc
                if isinstance(exc_node, ast.Call):
                    exc_node = exc_node.func
                if isinstance(exc_node, ast.Name):
                    exc_types.add(exc_node.id.lower())
                elif isinstance(exc_node, ast.Attribute):
                    exc_types.add(exc_node.attr.lower())
        # collect caught exception types
        elif isinstance(n, ast.ExceptHandler) and n.type:
            exc_node = n.type
            if isinstance(exc_node, ast.Name):
                exc_types.add(exc_node.id.lower())
            elif isinstance(exc_node, ast.Attribute):
                exc_types.add(exc_node.attr.lower())

    body_text = '\n'.join(source_lines[node.lineno - 1: node.end_lineno])
    body_words = {w for w in re.findall(r'\b([a-zA-Z]{4,})\b', body_text.lower())
                  if w not in _STOP}

    return idents, body_words, exc_types


def _collect_calls(node: ast.FunctionDef | ast.AsyncFunctionDef) -> set[str]:
    calls: set[str] = set()
    for n in ast.walk(node):
        if isinstance(n, ast.Call):
            if isinstance(n.func, ast.Name):
                calls.add(n.func.id)
            elif isinstance(n.func, ast.Attribute):
                calls.add(n.func.attr)
    return calls


# ── class-scope extraction ───────────────────────────────────────────────────

def _extract_classes(tree: ast.Module,
                     source_lines: list[str]) -> list[dict]:
    """
    Return one dict per ClassDef with:
        name, lineno, end_lineno, docstring, method_linenos
    """
    classes = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.ClassDef):
            continue
        doc = ast.get_docstring(node) or ''
        method_linenos = [
            n.lineno for n in ast.walk(node)
            if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
        ]
        classes.append({
            'name':          node.name,
            'lineno':        node.lineno,
            'end_lineno':    node.end_lineno,
            'docstring':     doc,
            'method_linenos': method_linenos,
        })
    return classes


def _score_class(cls: dict, signals: dict[str, set[str]]) -> float:
    """Score a class by how well it matches the developer-intent signals."""
    score = 0.0
    name_parts = _name_parts(cls['name'])

    # Class name overlap with backtick idents
    score += len(name_parts & signals['backtick_idents']) * W_BACKTICK_NAME
    # Class name overlap with plain idents
    score += len(name_parts & signals['plain_idents']) * W_CLASS_NAME_MATCH
    # Class name in all_words
    score += len(name_parts & signals['all_words']) * W_CLASS_NAME_MATCH
    # Class name explicitly mentioned in dotted refs
    score += len(name_parts & signals['dotted_classes']) * W_DOTTED_REF

    # Docstring word overlap with all_words
    if cls['docstring']:
        doc_words = {w for w in re.findall(r'\b([a-zA-Z]{4,})\b',
                                           cls['docstring'].lower())
                     if w not in _STOP}
        score += len(doc_words & signals['all_words']) * W_CLASS_DOC_MATCH

    return score


# ── heuristic scoring ────────────────────────────────────────────────────────

def _base_score(name: str,
                idents: set[str],
                body_words: set[str],
                exc_types: set[str],
                body_lines: int,
                signals: dict[str, set[str]]) -> float:
    parts = _name_parts(name)
    score = 0.0

    # T1: traceback
    for tf in signals['traceback_funcs']:
        if tf.lower() == name.lower() or tf.lower() in parts:
            score += W_TRACEBACK

    # T2: name in backtick idents
    score += len(parts & signals['backtick_idents']) * W_BACKTICK_NAME

    # T2b: body idents overlap with backtick idents
    score += len(idents & signals['backtick_idents']) * W_BACKTICK_BODY

    # T3: name or parts in dotted refs (Class.method)
    score += len(parts & signals['dotted_refs']) * W_DOTTED_REF

    # T4: name in plain idents
    score += len(parts & signals['plain_idents']) * W_PLAIN_NAME

    # T4b: function name parts overlap with intent prose words (all_words)
    # Only count words ≥5 chars to avoid noise from short structural words
    # like 'add', 'join', 'inline', 'block' that appear in many function names.
    specific_name_words = {p for p in parts if len(p) >= 5}
    score += len(specific_name_words & signals['all_words']) * W_NAME_ALL_WORDS

    # T4c: typo-tolerant fallback for identifier-like intent words.
    # Keep this name-only and low-weight so broad body prose cannot dominate scope.
    score += _fuzzy_name_score(parts, signals)

    # T5: exception type match
    if signals['exception_types'] and exc_types:
        score += len(signals['exception_types'] & exc_types) * W_EXCEPTION_MATCH

    # T6: body words overlap with all_words (normalised)
    overlap = len(body_words & signals['all_words'])
    score += overlap / max(body_lines, 1) ** 0.5 * W_BODY_WORDS

    return score


def _rank_functions(funcs_info: list[dict],
                    classes: list[dict],
                    signals: dict[str, set[str]]) -> list[dict]:
    """
    Score every function, apply all enrichments, return sorted list.

    Enrichments (applied additively after base score):
        1. Intra-file call-graph propagation
        2. Class-scope narrowing: boost methods of top-matching classes
    """
    # ── base scores ──
    for f in funcs_info:
        f['score'] = _base_score(
            f['name'], f['idents'], f['body_words'], f['exc_types'],
            f['end'] - f['start'] + 1, signals,
        )

    # ── 1. call-graph propagation ──
    name_to_linenos: dict[str, list[int]] = defaultdict(list)
    for f in funcs_info:
        name_to_linenos[f['name']].append(f['start'])

    bonus: dict[int, float] = defaultdict(float)
    for f in funcs_info:
        bscore = f['score']
        if bscore <= 0:
            continue
        for called_name in f['calls']:
            for tl in name_to_linenos.get(called_name, []):
                bonus[tl] += bscore * CALLEE_INHERIT
        for other in funcs_info:
            if f['name'] in other['calls']:
                bonus[other['start']] += bscore * CALLER_INHERIT

    for f in funcs_info:
        f['score'] += bonus[f['start']]

    # ── 2. class-scope narrowing ──
    if classes:
        class_bonus: dict[int, float] = defaultdict(float)
        for cls in classes:
            cls_score = _score_class(cls, signals)
            if cls_score <= 0:
                continue
            raw_bonus = cls_score * CLASS_METHOD_INHERIT
            capped_bonus = min(raw_bonus, CLASS_BOOST_CAP)
            for method_lineno in cls['method_linenos']:
                class_bonus[method_lineno] += capped_bonus

        for f in funcs_info:
            f['score'] += class_bonus[f['start']]

    return sorted(funcs_info, key=lambda x: -x['score'])


# ── LLM re-ranking (Stage 2) ─────────────────────────────────────────────────

_LLM_SYSTEM = (
    "You are a precise code-analysis assistant. "
    "Given a developer intent (a feature request, change description, or bug "
    "report) and a list of functions from a single source file, "
    "identify the functions most likely to need modification to satisfy it. "
    "You must output ONLY a JSON array of function names, e.g.: "
    '["load_disk", "migrations_module"]. '
    "Output ONLY the JSON array and nothing else."
)

_LLM_USER_TMPL = """\
## Developer intent
{issue}

## File: {filepath}

## Functions (name | signature | docstring)
{func_list}

Select the {top_k} functions most likely to require changes.
Output a JSON array of function names only.
"""


def _build_func_list_text(funcs_info: list[dict], source_lines: list[str]) -> str:
    lines = []
    for f in funcs_info:
        sig_line = source_lines[f['start'] - 1].strip()
        doc = f.get('docstring', '') or ''
        if doc:
            doc = doc.split('\n')[0][:120]
        lines.append(f"- {f['name']} | {sig_line} | {doc}")
    return '\n'.join(lines)


def _llm_rerank(funcs_info: list[dict],
                source_lines: list[str],
                filepath: str,
                issue: str,
                top_k: int,
                llm_client: Any,
                model: str) -> list[str] | None:
    func_list = _build_func_list_text(funcs_info, source_lines)
    user_msg = _LLM_USER_TMPL.format(
        issue=issue[:3000],
        filepath=filepath,
        func_list=func_list,
        top_k=top_k,
    )
    messages = [
        {"role": "system", "content": _LLM_SYSTEM},
        {"role": "user", "content": user_msg},
    ]
    for attempt in range(3):
        try:
            response = llm_client.chat.completions.create(
                model=model,
                messages=messages,
                max_tokens=256,
                temperature=0.0,
            )
            text = response.choices[0].message.content.strip()
            m = re.search(r'\[.*?\]', text, re.DOTALL)
            if m:
                names = json.loads(m.group())
                if isinstance(names, list):
                    return [str(n) for n in names]
        except Exception as exc:
            logger.warning("LLM rerank attempt %d failed: %s", attempt + 1, exc)
            if attempt < 2:
                time.sleep(5 * (attempt + 1))
    return None


# ── AST parsing ──────────────────────────────────────────────────────────────

# Regexes for recovering signals from non-Python sources (no AST available).
_IDENT_RE = re.compile(r'[A-Za-z_][A-Za-z0-9_]*')
_CALL_RE  = re.compile(r'\b([A-Za-z_][A-Za-z0-9_]*)\s*\(')
# Exception-type-looking tokens, e.g. ValueError / std::runtime_error -> matches the
# "...Error/Exception/Warning" tail, mirroring _parse_issue_signals' exception extraction.
_EXC_TOKEN_RE = re.compile(r'\b([A-Z][A-Za-z0-9]*(?:Error|Exception|Warning))\b')


def _parse_python_file(src_path: Path) -> tuple[list[dict], list[str], list[dict]] | tuple[None, None, None]:
    """Parse a Python source file with the ast module (richest signal extraction)."""
    try:
        content = src_path.read_text(errors='replace')
        tree = ast.parse(content)
        source_lines = content.splitlines()
    except Exception as exc:
        logger.warning("Could not parse %s: %s", src_path, exc)
        return None, None, None

    funcs = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        calls = _collect_calls(node)
        idents, body_words, exc_types = _collect_func_idents(node, source_lines)
        docstring = ast.get_docstring(node) or ''
        funcs.append({
            'name':       node.name,
            'start':      node.lineno,
            'end':        node.end_lineno,
            'calls':      calls,
            'idents':     idents,
            'body_words': body_words,
            'exc_types':  exc_types,
            'docstring':  docstring,
        })

    classes = _extract_classes(tree, source_lines)
    return funcs, source_lines, classes


def _generic_func_info(name: str, start0: int, end0: int,
                       source_lines: list[str], lang_cfg: dict) -> dict:
    """
    Build a funcs_info dict for one function in a non-Python (or AST-fallback) source.

    start0/end0 are 0-based inclusive line indices as returned by the extract.py
    brace/indent extractors. The 'start'/'end' fields are stored 1-based to match the AST
    convention used throughout scope.py (source_lines[start - 1] is the signature line).
    Identifiers, calls and exception types are recovered by regex over the function body.
    """
    body_text = '\n'.join(source_lines[start0:end0 + 1])
    keywords = lang_cfg.get('keywords', set())

    idents = {t.lower() for t in _IDENT_RE.findall(body_text)}
    body_words = {w for w in re.findall(r'\b([a-zA-Z]{4,})\b', body_text.lower())
                  if w not in _STOP}
    exc_types = {e.lower() for e in _EXC_TOKEN_RE.findall(body_text)}
    # Keep call names in their original case so call-graph propagation can match them
    # against function names (which preserve case), excluding language control keywords.
    calls = {m for m in _CALL_RE.findall(body_text) if m not in keywords}

    return {
        'name':       name,
        'start':      start0 + 1,
        'end':        end0 + 1,
        'calls':      calls,
        'idents':     idents,
        'body_words': body_words,
        'exc_types':  exc_types,
        'docstring':  '',
    }


def _parse_generic_file(src_path: Path, lang_key: str,
                        proj_dir: str | None = None) -> tuple[list[dict], list[str], list[dict]] | tuple[None, None, None]:
    """
    Parse a non-Python source into per-function signals, recovering per-function signals
    by regex. Returns no classes (class-scope narrowing is Python-only).

    Function boundaries are located by extract._function_spans, which draws them from
    codegraph when proj_dir indexes the file (the same source of truth run_extraction uses
    to name the extracted-function files) and falls back to extract.py's regex brace/indent
    extractor otherwise. The names it returns are already deduped (foo, foo_1, ...) exactly
    as run_extraction names those files, so a ranked function's 'name' maps straight onto its
    extracted-function file.
    """
    try:
        spans, raw_lines = _function_spans(str(src_path), lang_key, proj_dir=proj_dir)
    except Exception as exc:
        logger.warning("Could not read %s: %s", src_path, exc)
        return None, None, None

    # _function_spans keeps newline characters on raw_lines; strip them the same way
    # extract.py normalizes before extraction so the 0-based span indices line up with
    # source_lines (source_lines[start0] is the signature line).
    source_lines = [l.rstrip('\n').rstrip('\r') for l in raw_lines]
    lang_cfg = LANG_CONFIG[lang_key]

    funcs = [
        _generic_func_info(name, start0, end0, source_lines, lang_cfg)
        for name, start0, end0 in spans
    ]
    return funcs, source_lines, []


def _parse_file(src_path: Path,
                proj_dir: str | None = None) -> tuple[list[dict], list[str], list[dict]] | tuple[None, None, None]:
    """
    Parse a source file into (funcs_info, source_lines, classes).

    Dispatches on the file extension via extract.EXT_TO_LANG: Python files go through the
    ast-based path (with a fall back to the generic extractor if the AST parse fails, e.g.
    on Python 2 syntax), and every other language registered in EXT_TO_LANG goes through
    extract._function_spans (codegraph-backed when proj_dir indexes the file, regex otherwise).
    proj_dir is forwarded so the generic path can use codegraph; Returns (None, None, None)
    for unsupported extensions or unreadable files.
    """
    ext = src_path.suffix.lstrip('.').lower()
    lang_key = EXT_TO_LANG.get(ext)
    if lang_key is None:
        logger.warning("Unsupported extension for %s; cannot scope functions.", src_path)
        return None, None, None

    if lang_key == 'python':
        funcs, source_lines, classes = _parse_python_file(src_path)
        if funcs is not None:
            return funcs, source_lines, classes
        # AST parse failed — fall back to the generic line-based extractor.

    return _parse_generic_file(src_path, lang_key, proj_dir=proj_dir)


# ── main entry point ─────────────────────────────────────────────────────────

def rank_functions_in_file(
    filepath: str,
    src_path: Path,
    issue: str,
    signals: dict[str, set[str]],
    top_k: int = TOP_K,
    llm_client: Any = None,
    llm_model: str = '',
    llm_trigger: int = LLM_TRIGGER_FUNCS,
    llm_top_k: int = LLM_TOP_K,
    llm_confidence_threshold: float = LLM_CONFIDENCE_THRESHOLD,
    proj_dir: str | None = None,
) -> list[dict]:
    """
    Rank functions in a single file by relevance to the issue.

    proj_dir, when given, lets the non-Python parse path resolve function boundaries from
    codegraph (via extract._function_spans) instead of the regex fallback.

    Returns a list of dicts (file, name, lineno, end_lineno, score, reason),
    sorted descending by score, length ≤ top_k.
    """
    funcs_info, source_lines, classes = _parse_file(src_path, proj_dir=proj_dir)
    if funcs_info is None or not funcs_info:
        print(f"  [scope] {filepath}: no functions found, skipping")
        return []

    # Stage 1: heuristic scoring with all enrichments
    ranked = _rank_functions(funcs_info, classes or [], signals)

    # Deduplicate by name (keep highest-scored occurrence per name)
    seen_names: dict[str, dict] = {}
    deduped_ranked: list[dict] = []
    for f in ranked:
        if f['name'] not in seen_names:
            seen_names[f['name']] = f
            deduped_ranked.append(f)

    # ── print per-file function scores ──────────────────────────────────────
    print(f"\n{'─' * 70}")
    print(f"FILE: {filepath}  ({len(deduped_ranked)} unique functions)")
    if classes:
        class_names = [c['name'] for c in classes]
        print(f"  classes found: {class_names}")
    print(f"  {'rank':>4}  {'score':>8}  {'name'}")
    print(f"  {'----':>4}  {'-------':>8}  {'----'}")
    for rank, f in enumerate(deduped_ranked, 1):
        marker = "  <<" if rank <= top_k else ""
        print(f"  {rank:>4}  {f['score']:>8.3f}  {f['name']}  (L{f['start']}-{f['end']}){marker}")

    candidates = deduped_ranked[:top_k]
    reason = 'heuristic'
    heuristic_top_score = deduped_ranked[0]['score'] if deduped_ranked else 0.0

    # Stage 2: LLM re-ranking (optional)
    use_llm = (
        llm_client is not None
        and (
            heuristic_top_score < llm_confidence_threshold
            or len(deduped_ranked) >= llm_trigger
        )
    )
    if use_llm:
        llm_names = _llm_rerank(
            deduped_ranked, source_lines, filepath, issue,
            llm_top_k, llm_client, llm_model,
        )
        if llm_names:
            func_map = {f['name']: f for f in deduped_ranked}
            seen: set[str] = set()
            merged: list[dict] = []
            for name in llm_names:
                if name in func_map and name not in seen:
                    f = dict(func_map[name])
                    f['reason'] = 'llm'
                    merged.append(f)
                    seen.add(name)
            for f in deduped_ranked:
                if f['name'] not in seen and len(merged) < top_k:
                    f = dict(f)
                    f['reason'] = 'heuristic_pad'
                    merged.append(f)
                    seen.add(f['name'])
            candidates = merged[:top_k]
            reason = 'llm'
        else:
            logger.warning("LLM rerank failed for %s, falling back to heuristic", filepath)

    result = []
    for f in candidates:
        result.append({
            'file':        filepath,
            'name':        f['name'],
            'lineno':      f['start'],
            'end_lineno':  f['end'],
            'score':       round(f.get('score', 0.0), 3),
            'reason':      f.get('reason', reason),
        })

    print(f"  → selected ({reason}): " +
          ", ".join(f"{r['name']} ({r['score']:.3f})" for r in result))
    return result

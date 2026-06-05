"""
scope_functions.py — Function-level localization within scoped files.

Given a set of files already identified as relevant to a bug issue
(from scope_result.json), this module narrows them down to the specific
functions most likely to contain the fix.

Language support: Python files are parsed with the `ast` module (richest signal
extraction). Every other language with an extension registered in extract.EXT_TO_LANG
(C/C++, Java, Go, Rust, JS/TS, CUDA, ArkTS, …) is parsed with the same brace/indent
function extractor used by extract.py, with identifiers, calls, and exception types
recovered by regex (class-scope narrowing is Python-only).

Pipeline
--------
Stage 1 – Heuristic scoring  (always runs, ~25 ms/file, no LLM cost)
    Five signal tiers extracted from the issue text, in decreasing weight:
        T1  Traceback function names ("  in func_name")            ×10
        T2  Backtick / code-block identifiers                     ×5 (name), ×2 (body)
        T3  Explicit Class.method dotted references               ×15 (NEW)
        T4  CamelCase / snake_case identifiers in prose           ×3
        T5  Exception type matching (raise/except in body)        ×4 (NEW)
        T6  Body word overlap, normalised by √(lines)             ×1

    Post-scoring enrichments:
        • Intra-file call-graph propagation (callee ×0.30, caller ×0.20)
        • Class-scope narrowing (NEW): score classes by name/docstring
          overlap with issue, then boost all methods of top-matching classes
        • Proximity boost (NEW): after scoring, functions within W lines of
          an already-high-scoring function inherit a proximity bonus
        • Git-history boost (NEW): functions touched in the last N commits
          on this file get an additive score bonus

Stage 2 – LLM re-ranking  (optional, triggered when file has ≥ LLM_TRIGGER_FUNCS
    unique functions after dedup, or heuristic top score < confidence threshold)
    Sends only function signatures + first docstring line; no bodies.
    Falls back to heuristic on failure.

Output: scope_functions.json
    {"functions": [{"file": "...", "name": "...", "lineno": N,
                    "end_lineno": M, "score": 12.4, "reason": "heuristic"}]}
"""

from __future__ import annotations

import ast
import json
import logging
import re
import subprocess
import time
from collections import defaultdict
from pathlib import Path
from typing import Any

from .extract import (
    EXT_TO_LANG,
    LANG_CONFIG,
    _extract_functions_brace,
    _extract_functions_indent,
)

logger = logging.getLogger(__name__)

# ── tuneable constants ──────────────────────────────────────────────────────
TOP_K = 10               # functions to keep per file in the final output
LLM_TRIGGER_FUNCS = 40  # file has ≥ this many (deduped) functions → try LLM
LLM_TOP_K = 8           # how many functions to ask the LLM to pick
LLM_CONFIDENCE_THRESHOLD = 8.0  # top heuristic score below this → try LLM

# Signal weights
W_TRACEBACK        = 10.0
W_BACKTICK_NAME    =  5.0
W_BACKTICK_BODY    =  2.0
W_DOTTED_REF       = 15.0   # Class.method explicit reference in issue
W_PLAIN_NAME       =  3.0
W_NAME_ALL_WORDS   =  1.5   # function name parts ∩ issue all_words (prose nouns); lower weight to avoid boosting generic names
W_EXCEPTION_MATCH  =  4.0   # issue exception type found in function body
W_BODY_WORDS       =  1.0   # multiplied by overlap / sqrt(body_lines)

# Call-graph propagation weights
CALLEE_INHERIT = 0.30
CALLER_INHERIT = 0.20

# Class-scope narrowing (NEW)
W_CLASS_NAME_MATCH   = 6.0  # per overlapping token between class name and issue
W_CLASS_DOC_MATCH    = 2.0  # per overlapping token between class docstring and issue
# Class method inheritance: cap so a single high-scoring class doesn't flood top slots.
# Absolute cap: per-method bonus ≤ CLASS_BOOST_CAP regardless of class score.
CLASS_METHOD_INHERIT = 0.40 # fraction of class score passed to every method
CLASS_BOOST_CAP      = 8.0  # hard cap on per-method class bonus

# Proximity boost (NEW)
PROXIMITY_WINDOW   = 120    # lines: boost funcs within this many lines of a top scorer
W_PROXIMITY        = 2.0    # bonus for being within the proximity window
PROXIMITY_TOP_N    =  5     # consider the top-N scorers as proximity anchors

# Git history (NEW)
GIT_HISTORY_COMMITS = 20    # how many recent commits to inspect
W_GIT_HISTORY       =  2.0  # bonus for functions touched in recent commits
# Only apply git bonus when the function has at least some existing signal —
# prevents unrelated but recently-touched utility functions from flooding the list.
GIT_MIN_BASE_SCORE  =  1.0  # minimum base score before git bonus applies; prevents unrelated recently-touched utility functions from flooding

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
    """Extract multiple tiers of signals from the raw issue text."""
    signals: dict[str, set[str]] = {
        'traceback_funcs': set(),
        'backtick_idents': set(),
        'dotted_refs':     set(),   # NEW: (class_lower, method_lower) flattened
        'dotted_classes':  set(),   # NEW: class names from Class.method refs
        'plain_idents':    set(),
        'exception_types': set(),   # NEW: ExcType from issue
        'all_words':       set(),
    }

    # T1: function names from Python tracebacks
    signals['traceback_funcs'] = set(re.findall(r'\bin (\w+)\s*\n', issue_text))

    # T2: identifiers inside backticks or fenced code blocks
    signals['backtick_idents'] = _extract_backtick_idents(issue_text)

    # T3 (NEW): explicit Class.method dotted references
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

    # T5 (NEW): exception types  (e.g. AssertionError, ImportError)
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
        # NEW: collect raised exception types
        elif isinstance(n, ast.Raise):
            if n.exc:
                exc_node = n.exc
                if isinstance(exc_node, ast.Call):
                    exc_node = exc_node.func
                if isinstance(exc_node, ast.Name):
                    exc_types.add(exc_node.id.lower())
                elif isinstance(exc_node, ast.Attribute):
                    exc_types.add(exc_node.attr.lower())
        # NEW: collect caught exception types
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


# ── class-scope extraction (NEW) ─────────────────────────────────────────────

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
    """Score a class by how well it matches the issue signals."""
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


# ── git history signal (NEW) ──────────────────────────────────────────────────

def _git_recently_changed_linenos(repo_dir: Path,
                                   filepath: str,
                                   n_commits: int = GIT_HISTORY_COMMITS) -> set[int]:
    """
    Return the set of NEW (post-commit) line numbers that were touched in
    the last n_commits commits that modified filepath.

    Uses `git log --unified=0 -- <file>` to get precise hunk line numbers.
    Falls back gracefully if git is unavailable.
    """
    touched: set[int] = set()
    try:
        result = subprocess.run(
            ['git', 'log', f'-{n_commits}', '--format=%H', '--', filepath],
            cwd=str(repo_dir), capture_output=True, text=True, timeout=10,
        )
        commits = result.stdout.strip().splitlines()
        for commit in commits[:10]:
            diff = subprocess.run(
                ['git', 'diff', f'{commit}^', commit, '--unified=0', '--', filepath],
                cwd=str(repo_dir), capture_output=True, text=True, timeout=10,
            )
            for m in re.finditer(r'@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@',
                                  diff.stdout):
                start = int(m.group(1))
                count = int(m.group(2)) if m.group(2) is not None else 1
                for ln in range(start, start + max(count, 1)):
                    touched.add(ln)
    except Exception:
        pass
    return touched


def _git_recently_changed_funcs_precise(repo_dir: Path,
                                         filepath: str,
                                         funcs_info: list[dict],
                                         n_commits: int = GIT_HISTORY_COMMITS) -> dict[int, float]:
    """
    Get per-function recency scores from git history.

    Strategy: one `git log --unified=0 -- <file>` call fetches all recent
    hunks, then we map hunk line numbers to functions.  This is O(1) git
    calls regardless of the number of functions, keeping latency ~30 ms.

    Recency: each commit contributes 0.85^rank to functions it touched, so
    the most-recently-touched function gets the highest score.  The per-
    function score is capped at W_GIT_HISTORY.
    """
    func_scores: dict[int, float] = defaultdict(float)
    try:
        result = subprocess.run(
            ['git', 'log', f'-{n_commits}', '--format=%H', '--', filepath],
            cwd=str(repo_dir), capture_output=True, text=True, timeout=10,
        )
        commits = result.stdout.strip().splitlines()
        for rank, commit in enumerate(commits[:10]):
            diff = subprocess.run(
                ['git', 'diff', f'{commit}^', commit, '--unified=0', '--', filepath],
                cwd=str(repo_dir), capture_output=True, text=True, timeout=10,
            )
            touched_lines: set[int] = set()
            for m in re.finditer(r'@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@',
                                  diff.stdout):
                start = int(m.group(1))
                count = int(m.group(2)) if m.group(2) is not None else 1
                for ln in range(start, start + max(count, 1)):
                    touched_lines.add(ln)
            if not touched_lines:
                continue
            commit_weight = 0.85 ** rank  # most recent = 1.0
            for f in funcs_info:
                if any(f['start'] <= ln <= f['end'] for ln in touched_lines):
                    func_scores[f['start']] += commit_weight
    except Exception:
        pass
    # Cap each function's score at W_GIT_HISTORY
    return {lineno: min(score, W_GIT_HISTORY)
            for lineno, score in func_scores.items()}


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

    # T3 (NEW): name or parts in dotted refs (Class.method)
    score += len(parts & signals['dotted_refs']) * W_DOTTED_REF

    # T4: name in plain idents
    score += len(parts & signals['plain_idents']) * W_PLAIN_NAME

    # T4b: function name parts overlap with issue prose words (all_words)
    # Only count words ≥5 chars to avoid noise from short structural words
    # like 'add', 'join', 'inline', 'block' that appear in many function names.
    specific_name_words = {p for p in parts if len(p) >= 5}
    score += len(specific_name_words & signals['all_words']) * W_NAME_ALL_WORDS

    # T5 (NEW): exception type match
    if signals['exception_types'] and exc_types:
        score += len(signals['exception_types'] & exc_types) * W_EXCEPTION_MATCH

    # T6: body words overlap with all_words (normalised)
    overlap = len(body_words & signals['all_words'])
    score += overlap / max(body_lines, 1) ** 0.5 * W_BODY_WORDS

    return score


def _rank_functions(funcs_info: list[dict],
                    classes: list[dict],
                    signals: dict[str, set[str]],
                    git_scores: dict[int, float]) -> list[dict]:
    """
    Score every function, apply all enrichments, return sorted list.

    Enrichments (applied additively after base score):
        1. Intra-file call-graph propagation
        2. Class-scope narrowing: boost methods of top-matching classes
        3. Git history boost: per-function recency score from git log -L
        4. Proximity boost: applied after initial ranking (see below)
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

    # ── 3. git history boost (precise per-function recency) ──
    for f in funcs_info:
        git_recency = git_scores.get(f['start'], 0.0)
        if git_recency > 0 and f['score'] >= GIT_MIN_BASE_SCORE:
            f['score'] += git_recency

    # ── sort (proximity applied later, after dedup) ──
    return sorted(funcs_info, key=lambda x: -x['score'])


def _apply_proximity_boost(deduped: list[dict]) -> list[dict]:
    """
    Boost functions that are physically close (in source lines) to the top
    PROXIMITY_TOP_N scorers. Modifies scores in place and re-sorts.
    """
    if len(deduped) < 2:
        return deduped
    anchors = deduped[:PROXIMITY_TOP_N]
    anchor_mids = [(a['start'] + a['end']) / 2 for a in anchors]
    anchor_score = [a['score'] for a in anchors]

    for f in deduped[PROXIMITY_TOP_N:]:
        f_mid = (f['start'] + f['end']) / 2
        for amid, ascr in zip(anchor_mids, anchor_score):
            dist = abs(f_mid - amid)
            if dist <= PROXIMITY_WINDOW and ascr > 0:
                # Proximity bonus scales with anchor score and inverse distance
                proximity_factor = 1.0 - dist / PROXIMITY_WINDOW
                f['score'] += ascr * proximity_factor * W_PROXIMITY / max(ascr, 1.0)
                break  # only boost from nearest anchor once

    return sorted(deduped, key=lambda x: -x['score'])


# ── LLM re-ranking (Stage 2) ─────────────────────────────────────────────────

_LLM_SYSTEM = (
    "You are a precise code-analysis assistant. "
    "Given a bug issue and a list of functions from a single source file, "
    "identify the functions most likely to need modification to fix the bug. "
    "You must output ONLY a JSON array of function names, e.g.: "
    '["load_disk", "migrations_module"]. '
    "Output ONLY the JSON array and nothing else."
)

_LLM_USER_TMPL = """\
## Issue
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


def _parse_generic_file(src_path: Path, lang_key: str) -> tuple[list[dict], list[str], list[dict]] | tuple[None, None, None]:
    """
    Parse a non-Python source with the same brace/indent function extractor used by
    extract.py, recovering per-function signals by regex. Returns no classes (class-scope
    narrowing is Python-only).
    """
    try:
        content = src_path.read_text(errors='replace')
    except Exception as exc:
        logger.warning("Could not read %s: %s", src_path, exc)
        return None, None, None

    # splitlines() normalizes line endings the same way extract.run_extraction does before
    # feeding the extractors, so the returned 0-based line indices line up with source_lines.
    source_lines = content.splitlines()
    lang_cfg = LANG_CONFIG[lang_key]

    if lang_cfg['body'] == 'brace':
        raw_funcs = _extract_functions_brace(source_lines, lang_key, lang_cfg)
    else:
        raw_funcs = _extract_functions_indent(source_lines, lang_cfg)

    funcs = [
        _generic_func_info(name, start0, end0, source_lines, lang_cfg)
        for name, start0, end0 in raw_funcs
    ]
    return funcs, source_lines, []


def _parse_file(src_path: Path) -> tuple[list[dict], list[str], list[dict]] | tuple[None, None, None]:
    """
    Parse a source file into (funcs_info, source_lines, classes).

    Dispatches on the file extension via extract.EXT_TO_LANG: Python files go through the
    ast-based path (with a fall back to the generic extractor if the AST parse fails, e.g.
    on Python 2 syntax), and every other language registered in EXT_TO_LANG goes through the
    brace/indent extractor shared with extract.py. Returns (None, None, None) for unsupported
    extensions or unreadable files.
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

    return _parse_generic_file(src_path, lang_key)


# ── main entry point ─────────────────────────────────────────────────────────

def rank_functions_in_file(
    filepath: str,
    src_path: Path,
    issue: str,
    signals: dict[str, set[str]],
    repo_dir: Path | None = None,          # NEW: for git history
    top_k: int = TOP_K,
    llm_client: Any = None,
    llm_model: str = '',
    llm_trigger: int = LLM_TRIGGER_FUNCS,
    llm_top_k: int = LLM_TOP_K,
    llm_confidence_threshold: float = LLM_CONFIDENCE_THRESHOLD,
) -> list[dict]:
    """
    Rank functions in a single file by relevance to the issue.

    Returns a list of dicts (file, name, lineno, end_lineno, score, reason),
    sorted descending by score, length ≤ top_k.
    """
    funcs_info, source_lines, classes = _parse_file(src_path)
    if funcs_info is None or not funcs_info:
        return []

    # Git history signal: precise per-function recency via git log -L
    git_scores: dict[int, float] = {}
    if repo_dir is not None:
        git_scores = _git_recently_changed_funcs_precise(
            repo_dir, filepath, funcs_info
        )

    # Stage 1: heuristic scoring with all enrichments
    ranked = _rank_functions(funcs_info, classes or [], signals, git_scores)

    # Deduplicate by name (keep highest-scored occurrence per name)
    seen_names: dict[str, dict] = {}
    deduped_ranked: list[dict] = []
    for f in ranked:
        if f['name'] not in seen_names:
            seen_names[f['name']] = f
            deduped_ranked.append(f)

    # Proximity boost (after dedup, so anchors are the right unique functions)
    deduped_ranked = _apply_proximity_boost(deduped_ranked)

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
    return result


def run_scope_functions(
    instance_dir: Path,
    issue: str,
    top_k: int = TOP_K,
    llm_client: Any = None,
    llm_model: str = '',
    llm_trigger: int = LLM_TRIGGER_FUNCS,
    llm_top_k: int = LLM_TOP_K,
    llm_confidence_threshold: float = LLM_CONFIDENCE_THRESHOLD,
    output_path: Path | None = None,
) -> dict:
    """
    Run the full function-scoping pipeline for a single instance.

    Args:
        instance_dir:  root of the checked-out repo
        issue:         raw problem-statement text
        top_k:         max functions to retain per file
        llm_*:         LLM stage options
        output_path:   where to write scope_functions.json

    Returns:
        dict with key "functions" -> list of ranked function dicts
    """
    fm_dir = instance_dir / 'fm_agent'
    scope_result_path = fm_dir / 'scope_result.json'

    if not scope_result_path.exists():
        logger.warning("scope_result.json not found in %s", fm_dir)
        return {'functions': []}

    scope_data = json.loads(scope_result_path.read_text())
    scope_files: list[str] = scope_data.get('files', [])

    if not scope_files:
        logger.warning("scope_result.json has no files for %s", instance_dir.name)
        return {'functions': []}

    signals = _parse_issue_signals(issue)

    all_functions: list[dict] = []
    for filepath in scope_files:
        src_path = instance_dir / filepath
        if not src_path.exists():
            logger.warning("Scoped file not found: %s", src_path)
            continue

        ranked = rank_functions_in_file(
            filepath=filepath,
            src_path=src_path,
            issue=issue,
            signals=signals,
            repo_dir=instance_dir,
            top_k=top_k,
            llm_client=llm_client,
            llm_model=llm_model,
            llm_trigger=llm_trigger,
            llm_top_k=llm_top_k,
            llm_confidence_threshold=llm_confidence_threshold,
        )
        all_functions.extend(ranked)
        logger.info("%s: %s → %d functions selected",
                    instance_dir.name, filepath, len(ranked))

    result = {'functions': all_functions}

    if output_path is None:
        output_path = fm_dir / 'scope_functions.json'
    output_path.write_text(json.dumps(result, indent=2))
    logger.info("Wrote %s", output_path)

    return result

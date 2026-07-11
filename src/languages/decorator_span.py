"""Shared decorator/annotation span extension (stdlib-only leaf module).

Every function-extraction path in FM-Agent starts a span at the ``def`` /
signature line, dropping any decorators or annotations above it. For
framework-mediated security that is a blind spot: guards expressed as
decorators — FastAPI ``@router.delete(..., dependencies=[Depends(
requires_access_dag(...))])``, Flask ``@has_access``, Spring ``@PreAuthorize`` —
never enter the extracted function, so per-function analysis (esp. authz)
systematically false-flags guarded routes.

This module is imported by BOTH ``src.extract`` (regex fallback + _function_spans)
and ``src.languages.codegraph`` (the primary codegraph body-slicing path), so it
must stay dependency-free to avoid an import cycle
(extract -> languages.registry -> languages.python -> languages.codegraph).
"""

from __future__ import annotations

import bisect


# Languages whose functions/methods can carry `@`-prefixed decorators or
# annotations sitting ABOVE the signature line.
DECORATOR_LANGS = {"python", "java", "typescript", "javascript", "arkts"}


def extend_start_over_decorators(norm_lines, start, lower_bound):
    """Return a start index that includes decorator/annotation lines immediately
    preceding the function at ``start`` (0-indexed).

    Walks upward from ``start - 1`` down to (but not past) ``lower_bound`` — the
    end index of the nearest preceding function span, so a sibling's body is
    never swallowed. The walk is BRACKET-AWARE so a multi-line decorator::

        @router.delete(
            "/task/{task_id}",
            dependencies=[Depends(requires_access_dag(...))],
        )
        def delete_task_instance(...):

    is captured whole: reading bottom-up, the closing ``)`` opens a bracket
    balance that only returns to zero at the ``@router.delete(`` line, which is
    where the decorator (and thus the new start) begins. Stacked decorators are
    absorbed one after another. A blank line at bracket depth 0 (decorators must
    be adjacent to the def in valid syntax) or any non-decorator line ends it.
    """
    new_start = start
    depth = 0
    j = start - 1
    while j >= lower_bound:
        raw = norm_lines[j]
        s = raw.strip()
        if depth == 0 and s == "":
            break  # blank gap: decorators must be adjacent to the signature
        # Bottom-up bracket balance: closers add, openers subtract.
        depth += raw.count(")") + raw.count("]") + raw.count("}")
        depth -= raw.count("(") + raw.count("[") + raw.count("{")
        if depth < 0:
            depth = 0  # defensive: unbalanced line, treat as settled
        if depth == 0:
            if s.startswith("@"):
                new_start = j          # a decorator (possibly multi-line) starts here
                j -= 1
                continue
            break                       # settled on a non-decorator line: stop
        # depth > 0: still inside a multi-line decorator's brackets; keep rising
        j -= 1
    return new_start


def apply_decorator_extension(norm_lines, raw_funcs, lang_key):
    """Extend each ``(name, start, end)`` span (0-indexed, inclusive) upward over
    attached decorators. Shared by every extraction path so decorator-expressed
    guards land in the extracted body consistently.

    Returns ``raw_funcs`` unchanged for non-decorator languages or empty input.
    Each extension is bounded by the nearest preceding span end so a sibling
    function is never absorbed.
    """
    if lang_key not in DECORATOR_LANGS or not raw_funcs:
        return raw_funcs
    prior_ends = sorted(end for _, _, end in raw_funcs)
    extended = []
    for name, start, end in raw_funcs:
        # Nearest span end strictly above this start = extension lower bound
        # (its line is exclusive). bisect keeps this O(log n) per function.
        idx = bisect.bisect_left(prior_ends, start) - 1
        lb = (prior_ends[idx] + 1) if idx >= 0 and prior_ends[idx] < start else 0
        new_start = extend_start_over_decorators(norm_lines, start, lb)
        extended.append((name, new_start, end))
    return extended

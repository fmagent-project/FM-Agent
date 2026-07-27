import re
from config import *
from .prompts import (
    _generate_block_post_condition,
    _check_post_implies_spec,
    _generate_block_wp,
    _check_pre_implies_wp,
)


def _split_into_blocks(func):
    lines = func.strip().split('\n')
    total = len(lines)
    if total <= GRANULARITY:
        return [func.strip()]

    blocks = []
    i = 0
    while i < total:
        remaining = total - i
        if remaining <= GRANULARITY * 2:
            blocks.append('\n'.join(lines[i:]))
            break
        end = i + GRANULARITY
        blocks.append('\n'.join(lines[i:end]))
        i = end
    return blocks


def _compute_brace_depth_per_line(lines):
    """
    Compute brace depth after each line, respecting strings and comments.
    Returns list of depths (depth after processing each line).
    """
    depths = []
    depth = 0
    for line in lines:
        i = 0
        while i < len(line):
            ch = line[i]
            # Skip string literals
            if ch == '"':
                i += 1
                while i < len(line):
                    if line[i] == '\\':
                        i += 2
                        continue
                    if line[i] == '"':
                        i += 1
                        break
                    i += 1
                continue
            # Skip char literals
            if ch == "'":
                i += 1
                while i < len(line):
                    if line[i] == '\\':
                        i += 2
                        continue
                    if line[i] == "'":
                        i += 1
                        break
                    i += 1
                continue
            # Line comment — skip rest of line
            if ch == '/' and i + 1 < len(line) and line[i + 1] == '/':
                break
            # Block comment
            if ch == '/' and i + 1 < len(line) and line[i + 1] == '*':
                i += 2
                while i < len(line):
                    if line[i] == '*' and i + 1 < len(line) and line[i + 1] == '/':
                        i += 2
                        break
                    i += 1
                # If block comment spans lines, we ignore braces inside it (simplified)
                continue
            if ch == '{':
                depth += 1
            elif ch == '}':
                depth -= 1
            i += 1
        depths.append(depth)
    return depths


def _split_into_blocks_braced(func, language):
    """
    Split function body into blocks respecting syntactic boundaries.
    """

    python_like = {"python"}

    if language.lower() in python_like:
        return _split_into_blocks(func)

    raw_lines = func.strip().split("\n")
    total = len(raw_lines)

    if total <= GRANULARITY:
        return [func.strip()]

    # normalize prefix
    stripped_lines = []
    for line in raw_lines:
        if line.startswith("Line "):
            colon = line.find(":", 5)
            if colon != -1:
                line = line[colon + 1:].lstrip()
        stripped_lines.append(line)

    # compute brace depth
    depths = _compute_brace_depth_per_line(stripped_lines)

    # define entry depth 
    entry_depth = depths[0] if total > 0 else 0

    if entry_depth == 0:
        entry_depth = next((d for d in depths if d > 0), 0)

    if entry_depth == 0:
        # fallback to safe splitter
        return _split_into_blocks(func)

    # greedy safe splitting
    blocks = []
    i = 0

    while i < total:
        remaining = total - i

        if remaining <= GRANULARITY * 2:
            blocks.append("\n".join(raw_lines[i:]))
            break

        target = i + GRANULARITY
        split_point = -1

        # ONLY split when we return to entry depth
        for j in range(target, total):
            if depths[j] == entry_depth:
                split_point = j
                break

        if split_point == -1:
            blocks.append("\n".join(raw_lines[i:]))
            break

        blocks.append("\n".join(raw_lines[i:split_point + 1]))
        i = split_point + 1

    return blocks


_TERMINATING_PATTERNS = {
    "rust": r'\b(return\b|panic!\s*\(|std::process::exit\s*\(|unreachable!\s*\()',
    "c": r'\b(return\b|exit\s*\(|_Exit\s*\(|abort\s*\(|longjmp\s*\()',
    "c++": r'\b(return\b|exit\s*\(|_Exit\s*\(|abort\s*\(|throw\s|std::terminate\s*\(|std::exit\s*\()',
    "python": r'\b(return\b|sys\.exit\s*\(|raise\s|exit\s*\(|quit\s*\()',
    "cuda": r'\b(return\b|exit\s*\(|_Exit\s*\(|abort\s*\(|__trap\s*\()',
    "java": r'\b(return\b|throw\s|System\.exit\s*\()',
    "go": r'\b(return\b|panic\s*\(|log\.Fatal\w*\s*\(|os\.Exit\s*\()',
    "c#": r'\b(return\b|throw\s|Environment\.Exit\s*\()',
    "kotlin": r'\b(return\b|throw\s|exitProcess\s*\(|System\.exit\s*\()',
    "swift": r'\b(return\b|throw\s|fatalError\s*\(|preconditionFailure\s*\(|exit\s*\()',
    "php": r'\b(return\b|throw\s|die\s*\(|exit\s*\()',
    "ruby": r'\b(return\b|raise\s|abort\s*\(|exit\s*\(|exit!\s*\()',
    "scala": r'\b(return\b|throw\s|sys\.exit\s*\(|System\.exit\s*\()',
    "dart": r'\b(return\b|throw\s|exit\s*\()',
    "javascript": r'\b(return\b|throw\s|process\.exit\s*\()',
    "typescript": r'\b(return\b|throw\s|process\.exit\s*\()',
    "arkts": r'\b(return\b|throw\s|process\.exit\s*\()',
    "erlang": r'\b(?:throw|exit|error)\s*\(|\berlang:(?:error|exit)\s*\(',
}


def _has_terminating_statement(block, language):
    pattern = _TERMINATING_PATTERNS.get(language.lower())
    if not pattern:
        pattern = r'\b(return\b|exit\s*\(|raise\s|throw\s|abort\s*\()'
    return re.search(pattern, block) is not None


def _parse_spec_conditions(spec):
    pre_match = re.search(r'Pre-condition:\s*\n(.*?)(?=\nPost-condition:|\Z)', spec, re.DOTALL)
    post_match = re.search(r'Post-condition:\s*\n(.*)', spec, re.DOTALL)
    pre = pre_match.group(1).strip() if pre_match else None
    post = post_match.group(1).strip() if post_match else None
    return pre, post


def reasoner(func, spec, info, language, trace_context=None):
    trace_context = trace_context or {}
    trace_dir = trace_context.get("trace_dir")
    # Step 1: Parse pre-condition and post-condition directly from spec
    pre_condition, spec_post_condition = _parse_spec_conditions(spec)
    if not pre_condition or not spec_post_condition:
        return "Failed to parse pre/post conditions from the spec."

    # Step 2: Split function into code blocks (each >= GRANULARITY lines)
    blocks = _split_into_blocks_braced(func, language)

    # Step 3: Process each block sequentially
    current_pre = pre_condition
    for i, block in enumerate(blocks):
        # Generate post-condition using Claude Sonnet 4.6
        trace_meta = {
            "function_id": trace_context.get("function_id"),
            "function_file": trace_context.get("function_file"),
            "language": language,
            "block_index": i,
            "block_count": len(blocks),
        }
        post_condition = _generate_block_post_condition(
            block,
            current_pre,
            info,
            language,
            trace_dir=trace_dir,
            trace_meta=trace_meta,
        )
        if not post_condition:
            return f"Failed to generate post-condition for block {i+1}."

        # Check against spec post-condition if block has terminating statements
        # or if this is the last block (implicit return at end of function)
        is_last_block = (i == len(blocks) - 1)
        if _has_terminating_statement(block, language) or is_last_block:
            passed, stmts, post_cond, reason = _check_post_implies_spec(
                block,
                post_condition,
                spec_post_condition,
                info,
                language,
                trace_dir=trace_dir,
                trace_meta=trace_meta,
            )
            if not passed:
                return (
                    f"Verification FAILED.\n"
                    f"Statements triggering the violation:\n{stmts}\n\n"
                    f"Post-condition:\n{post_cond}\n\n"
                    f"Reason for violation:\n{reason}"
                )

        # Use current block's post-condition as next block's pre-condition
        current_pre = post_condition

    return "The function passes the verification. All code blocks satisfy the specification's post-condition."


def wp_reasoner(func, spec, info, language, trace_context=None):
    """Weakest Precondition reasoner — backward chain derivation.

    Mirrors reasoner() but operates in reverse:
    - Starts from spec_post_condition, traverses blocks backward
    - Each block computes WP (the minimal pre-condition guaranteeing the post-condition)
    - At function entry (i==0), checks spec_pre ⊨ wp (rather than post_n ⊨ spec_post at exit)

    Returns (result_string, entry_wp):
    - result_string: human-readable verdict (same interface as reasoner() for the string part)
    - entry_wp: the WP at function entry (block 0), or None on failure.  Callers can
      cache this for bottom-up callee→caller WP propagation.

    This finds complementary bug classes to SP:
    - SP finds "code did wrong" (forward contradiction)
    - WP finds "code failed to guarantee" (backward gap / pre-condition too weak)
    """
    trace_context = trace_context or {}
    trace_dir = trace_context.get("trace_dir")

    # Step 1: Parse pre-condition and post-condition from spec (same as reasoner)
    pre_condition, spec_post_condition = _parse_spec_conditions(spec)
    if not pre_condition or not spec_post_condition:
        return "Failed to parse pre/post conditions from the spec.", None

    # Step 2: Split function into blocks (same as reasoner, reuse _split_into_blocks_braced)
    blocks = _split_into_blocks_braced(func, language)

    # Step 3: Backward traversal — start from the last block, derive WP toward the first
    current_post = spec_post_condition  # Start from spec's post-condition
    entry_wp = None  # WP at function entry (block 0); cached for upward propagation

    for i in reversed(range(len(blocks))):
        block = blocks[i]
        trace_meta = {
            "function_id": trace_context.get("function_id"),
            "function_file": trace_context.get("function_file"),
            "language": language,
            "block_index": i,
            "block_count": len(blocks),
            "direction": "backward",
        }

        # 3a: Compute WP — given code block and post-condition, derive pre-condition
        wp = _generate_block_wp(
            block,
            current_post,
            info,
            language,
            trace_dir=trace_dir,
            trace_meta=trace_meta,
        )
        if not wp:
            return f"Failed to generate weakest pre-condition for block {i+1}.", None

        # 3b: At function entry (i==0) or terminating statements, check spec_pre ⊨ wp
        is_first_block = (i == 0)
        if is_first_block:
            entry_wp = wp  # Cache the function-entry WP for propagation
        if is_first_block or _has_terminating_statement(block, language):
            # Return order from _check_pre_implies_wp: (passed, stmts, wp, reason)
            passed, stmts, wp_cond, reason = _check_pre_implies_wp(
                block,
                wp,
                pre_condition,  # spec's pre-condition (what callers guarantee)
                info,
                language,
                trace_dir=trace_dir,
                trace_meta=trace_meta,
            )
            if not passed:
                return (
                    f"Verification FAILED (WP).\n"
                    f"Statements triggering the violation:\n{stmts}\n\n"
                    f"Weakest pre-condition:\n{wp_cond}\n\n"
                    f"Reason for violation:\n{reason}"
                ), wp

        # 3c: This block's WP becomes the post-condition for the previous block
        current_post = wp

    return ("The function passes the WP verification. "
            "The specification's pre-condition is sufficient to guarantee "
            "the post-condition across all code paths."), entry_wp


# ---------------------------------------------------------------------------
# Callee WP propagation (bottom-up reasoning advantage)
# ---------------------------------------------------------------------------

def _collect_callee_wps(fqn, phase_fqns, wp_cache, callees_map):
    """Collect WPs of all callees of fqn that are in phase_fqns and wp_cache.

    In bottom-up mode, callees are processed before callers. When analyzing a
    caller, all its callees' WPs are already cached. Injecting them into the
    caller's reasoning context makes WP computation more precise: the caller
    must guarantee each callee's pre-condition before calling it.
    """
    callee_wps = {}
    for callee_fqn in callees_map.get(fqn, set()) & phase_fqns:
        if callee_fqn in wp_cache:
            callee_wps[callee_fqn] = wp_cache[callee_fqn]
    return callee_wps


def _format_callee_wps(callee_wps):
    """Format callee WPs as info text for injection into the reasoning context.

    Truncates each WP to 200 characters to prevent context explosion.
    Only direct callees are propagated (no recursive grand-callee WPs).
    """
    if not callee_wps:
        return ""
    lines = ["Callee pre-condition requirements (from WP analysis):"]
    for callee, wp in callee_wps.items():
        short_name = callee.split("::")[-1]
        truncated = wp[:200] + ("..." if len(wp) > 200 else "")
        lines.append(f"  {short_name} requires: {truncated}")
    return "\n".join(lines)

def _sanitize_strings(obj):
    """Remove non-ASCII characters from all string values in a dict/list."""
    if isinstance(obj, str):
        return obj.encode("ascii", "ignore").decode("ascii")
    if isinstance(obj, dict):
        return {k: _sanitize_strings(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_sanitize_strings(v) for v in obj]
    return obj

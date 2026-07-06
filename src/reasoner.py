import re
from config import *
from .prompts import _generate_block_post_condition, _check_post_implies_spec


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

def _sanitize_strings(obj):
    """Remove non-ASCII characters from all string values in a dict/list."""
    if isinstance(obj, str):
        return obj.encode("ascii", "ignore").decode("ascii")
    if isinstance(obj, dict):
        return {k: _sanitize_strings(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_sanitize_strings(v) for v in obj]
    return obj

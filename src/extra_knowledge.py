"""Utilities for loading user-supplied extra domain knowledge markdown files."""

import os
import shutil
import sys


def _validate_extra_knowledge_files(paths):
    """Validate and deduplicate a list of extra-knowledge markdown file paths.

    Each entry must exist, be a regular file, and have a ``.md`` extension.
    Duplicate absolute paths (same file listed more than once) produce a
    warning and are silently dropped so only the first occurrence is kept.

    Returns a list of unique, resolved absolute paths that passed all checks.
    Prints an error message and calls ``sys.exit(1)`` when any path is invalid.
    """
    seen = set()
    resolved = []
    errors = []
    for p in paths:
        abs_path = os.path.abspath(p)
        if abs_path in seen:
            print(f"[Pipeline] WARNING: Duplicate extra knowledge file ignored: {p}")
            continue
        seen.add(abs_path)
        if not os.path.exists(abs_path):
            errors.append(f"Extra knowledge file not found: {p}")
        elif not os.path.isfile(abs_path):
            errors.append(f"Extra knowledge path is not a file: {p}")
        elif not abs_path.lower().endswith(".md"):
            errors.append(
                f"Extra knowledge file must have a .md extension: {p}"
            )
        else:
            resolved.append(abs_path)
    if errors:
        for err in errors:
            print(f"[Pipeline] ERROR: {err}")
        sys.exit(1)
    return resolved


def _copy_extra_knowledge_files(extra_knowledge_files, domain_context_dir):
    """Copy extra knowledge markdown files into *domain_context_dir*.

    Each file is copied as ``user_<original_basename>``.  When two source files
    share the same basename the second occurrence is disambiguated by appending
    an incrementing counter (``user_name_2.md``, ``user_name_3.md``, …) so no
    prior file is overwritten.

    Returns the list of destination filenames (basenames only) that were written.
    """
    os.makedirs(domain_context_dir, exist_ok=True)
    used_names = set()
    written = []
    for src_path in extra_knowledge_files:
        basename = os.path.basename(src_path)
        candidate = f"user_{basename}"
        if candidate in used_names:
            stem, ext = os.path.splitext(basename)
            counter = 2
            while True:
                candidate = f"user_{stem}_{counter}{ext}"
                if candidate not in used_names:
                    break
                counter += 1
        used_names.add(candidate)
        dst_path = os.path.join(domain_context_dir, candidate)
        shutil.copy2(src_path, dst_path)
        written.append(candidate)
        print(f"[Pipeline] Extra knowledge file copied: {src_path} -> {dst_path}")
    return written


def _format_extra_knowledge_context(extra_knowledge_files):
    """Return user-supplied domain knowledge as a prompt-ready section.

    Incremental reasoning builds self-contained prompts instead of using the
    batch prompt generator, so it needs the Markdown contents inlined into its
    developer-intent context. Paths have already been validated by the CLI.
    """
    if not extra_knowledge_files:
        return ""

    sections = ["## Extra domain knowledge"]
    for path in extra_knowledge_files:
        with open(path, "r", encoding="utf-8") as knowledge_file:
            content = knowledge_file.read().strip()
        sections.append(f"### {os.path.basename(path)}\n\n{content}")
    return "\n\n".join(sections)

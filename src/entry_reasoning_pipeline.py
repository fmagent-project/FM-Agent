import os
import json
import shutil
import filecmp
import logging
import tempfile
from collections import deque, defaultdict

from src.generate_topdown_layers import _build_call_graph, _file_to_fqn
from src.extract import (
    EXT_TO_LANG,
    LANG_CONFIG,
    _extract_functions_brace,
    _extract_functions_indent,
    _is_test_file,
    extract_functions_from_file,
)
import config


def _collect_all_function_files(proj_dir):
    """Collect every extracted function file under proj_dir.

    Returns a list of (filepath, module_name) tuples, where module_name is the
    extracted directory the function file lives in (only used for bookkeeping;
    it does not affect the call-graph edges).
    """
    extracted_base = os.path.join(proj_dir, "extracted_functions")
    results = []
    for root, _, files in os.walk(extracted_base):
        module_name = os.path.relpath(root, extracted_base)
        for fname in files:
            fpath = os.path.join(root, fname)
            if os.path.isfile(fpath):
                results.append((fpath, module_name))
    return results


def _extract_for_selection(proj_dir, tmp_root):
    """Mechanically extract every function in proj_dir into a temp workspace.

    Writes the standard ``extracted_functions/`` layout (same per-file naming
    and dedup rules as run_extraction) under ``tmp_root`` so the call-graph
    machinery can run on it. Unlike the pipeline's extraction stage this needs
    no phases.json — and therefore no previous run_pipeline(): it simply scans
    every supported source file, skipping the fm_agent/ workspace, .git, and
    test files.

    Returns the number of extracted functions.
    """
    output_base = os.path.join(tmp_root, "extracted_functions")
    count = 0
    for root, dirs, files in os.walk(proj_dir):
        dirs[:] = [d for d in dirs if d not in ("fm_agent", ".git")]
        for fname in files:
            src_path = os.path.join(root, fname)
            src_rel = os.path.relpath(src_path, proj_dir)
            ext = fname.rsplit(".", 1)[-1] if "." in fname else ""
            lang_key = EXT_TO_LANG.get(ext)
            if not lang_key or _is_test_file(src_rel):
                continue
            funcs = extract_functions_from_file(src_path, lang_key)
            if not funcs:
                continue
            # Same layout as run_extraction: replace the source filename's
            # last dot with a hyphen to form the function directory.
            src_dir = os.path.dirname(src_rel)
            base = os.path.basename(src_rel)
            last_dot = base.rfind(".")
            dir_name = base[:last_dot] + "-" + base[last_dot + 1:] if last_dot > 0 else base
            out_dir = os.path.join(output_base, src_dir, dir_name)
            os.makedirs(out_dir, exist_ok=True)
            for func_name, func_source in funcs:
                with open(os.path.join(out_dir, f"{func_name}.{ext}"), "w") as f:
                    f.write(func_source)
                count += 1
    return count


def build_entry_call_graph(proj_dir, entry_func):
    """Construct the call graph of functions reachable from entry_func.

    Statically approximates which functions under ``proj_dir`` are called
    during an execution that starts at ``entry_func``: it builds the global
    call graph over all extracted functions, then keeps only ``entry_func``
    and the functions transitively reachable from it via callee edges.

    Args:
        proj_dir: path to a workspace directory that contains an
            ``extracted_functions/`` tree.
        entry_func: FQN of the entry point, e.g. ``src::engine::loader-cpp::loadData``.
            Assumed to be a function under ``proj_dir``.

    Returns:
        A dict mapping each reachable FQN (including ``entry_func``) to a sorted
        list of the FQNs it directly calls within the reachable set. Functions
        with no outgoing calls map to an empty list.

    Raises:
        ValueError: if ``entry_func`` is not found among the extracted functions.
    """
    all_files = _collect_all_function_files(proj_dir)

    # Build the global call graph over every function. Passing all files as a
    # single "phase" makes callees_map contain every resolved within-project edge.
    callees_map, _callers_map, _all_callees_map, file_map, _module_map = _build_call_graph(
        all_files, proj_dir
    )

    if entry_func not in file_map:
        raise ValueError(
            f"entry_func {entry_func!r} not found among extracted functions under {proj_dir!r}"
        )

    # BFS over callee edges to find the functions reachable from the entry point.
    call_graph = {}
    queue = deque([entry_func])
    while queue:
        fqn = queue.popleft()
        if fqn in call_graph:
            continue
        callees = callees_map.get(fqn, set())
        call_graph[fqn] = sorted(callees)
        for callee in callees:
            if callee not in call_graph:
                queue.append(callee)

    return call_graph


def _restrict_to_chains(call_graph, entry_func, end_funcs):
    """Keep only functions lying on a call chain from entry_func to an end_func.

    A function is retained iff it is reachable from ``entry_func`` (already
    guaranteed by ``call_graph``) *and* it can reach one of ``end_funcs`` — i.e.
    it sits on some path ``entry_func -> ... -> end_func``. The ``end_funcs`` are
    treated as terminal: their outgoing edges are dropped so chains stop there.

    Args:
        call_graph: dict mapping FQN -> sorted list of callee FQNs, rooted at
            entry_func (as returned by build_entry_call_graph).
        entry_func: FQN of the entry point.
        end_funcs: list of FQNs at which to stop. If falsy, call_graph is
            returned unchanged.

    Returns:
        A new call graph (same shape) containing only the on-chain functions.
    """
    if not end_funcs:
        return call_graph

    # Reverse adjacency over the reachable graph.
    callers = {fqn: set() for fqn in call_graph}
    for fqn, callees in call_graph.items():
        for callee in callees:
            callers.setdefault(callee, set()).add(fqn)

    # Nodes that can reach some end_func: reverse-BFS seeded at the end_funcs.
    on_chain = set()
    queue = deque(ef for ef in end_funcs if ef in call_graph)
    while queue:
        fqn = queue.popleft()
        if fqn in on_chain:
            continue
        on_chain.add(fqn)
        for caller in callers.get(fqn, ()):
            if caller not in on_chain:
                queue.append(caller)

    end_set = set(end_funcs)
    pruned = {}
    for fqn in on_chain:
        if fqn in end_set:
            # end_funcs are terminal stop points: no outgoing edges.
            pruned[fqn] = []
        else:
            pruned[fqn] = [c for c in call_graph[fqn] if c in on_chain]
    return pruned


def _fqn_to_filepath_map(proj_dir):
    """Build a map from FQN to its extracted function filepath (inverse of _file_to_fqn)."""
    mapping = {}
    for filepath, _module_name in _collect_all_function_files(proj_dir):
        mapping[_file_to_fqn(filepath, proj_dir)] = filepath
    return mapping


# ---------------------------------------------------------------------------
# Source-level trimming
#
# The selected call graph names individual functions, but run_pipeline()'s unit
# of work is the *source file* (it re-extracts every function of each file in
# phases.json). To make run_pipeline() process only the selected functions, we
# surgically delete the unselected function bodies from proj_dir's source files
# (and delete entirely-unselected source files) before invoking run_pipeline()
# on it; the original sources are restored from a snapshot afterwards.
# ---------------------------------------------------------------------------


def _extracted_file_to_source_rel(extracted_rel):
    """Map an extracted-function file path back to its source file (relative).

    Inverse of the extraction layout: ``src/engine/loader-cpp/loadData.cpp``
    (a function file) -> ``src/engine/loader.cpp`` (the source file). Extraction
    builds the function directory by replacing the source filename's last dot
    with a hyphen (``loader.cpp`` -> ``loader-cpp``), so we reverse the last
    hyphen of the directory name.
    """
    func_dir = os.path.dirname(extracted_rel)        # src/engine/loader-cpp
    src_dir = os.path.dirname(func_dir)              # src/engine
    dir_name = os.path.basename(func_dir)            # loader-cpp
    hyphen = dir_name.rfind("-")
    if hyphen > 0:
        source_base = dir_name[:hyphen] + "." + dir_name[hyphen + 1:]
    else:
        source_base = dir_name
    return os.path.join(src_dir, source_base) if src_dir else source_base


def _group_funcs_by_source(extracted_filepaths, extracted_base):
    """Group extracted function files by their source file.

    Returns a dict mapping source-relative path -> set of (deduped) function
    names, where the function name is the extracted file's stem (matching the
    dedup naming run_extraction uses).
    """
    by_source = defaultdict(set)
    for fpath in extracted_filepaths:
        rel = os.path.relpath(fpath, extracted_base)
        func_name = os.path.splitext(os.path.basename(rel))[0]
        by_source[_extracted_file_to_source_rel(rel)].add(func_name)
    return by_source


def _function_spans(filepath, lang_key):
    """Return ``(spans, raw_lines)`` for a source file.

    ``spans`` is a list of ``(deduped_name, start_idx, end_idx)`` line ranges,
    one per function, named exactly as run_extraction names the extracted files
    (duplicate names get ``_1``, ``_2``, ... suffixes). ``raw_lines`` are the
    file's original lines (newline characters preserved) so callers can rewrite
    the file by line index.
    """
    lang_cfg = LANG_CONFIG[lang_key]
    with open(filepath, "r", errors="replace") as f:
        raw_lines = f.readlines()
    # Extraction operates on newline-stripped lines; indices line up 1:1 with
    # raw_lines (readlines yields one entry per line).
    norm_lines = [l.rstrip("\n").rstrip("\r") for l in raw_lines]

    if lang_cfg["body"] == "brace":
        raw_funcs = _extract_functions_brace(norm_lines, lang_key, lang_cfg)
    else:
        raw_funcs = _extract_functions_indent(norm_lines, lang_cfg)

    name_counts = {}
    spans = []
    for name, start, end in raw_funcs:
        count = name_counts.get(name, 0)
        name_counts[name] = count + 1
        deduped = name if count == 0 else f"{name}_{count}"
        spans.append((deduped, start, end))
    return spans, raw_lines


def _trim_source_file(filepath, keep_names):
    """Delete every function NOT in ``keep_names`` from a source file in place.

    Non-function lines (includes, declarations, globals, etc.) are preserved as
    context; only the line ranges of unselected functions are removed. Returns
    ``(kept, removed)`` counts. Files whose language is unsupported, or that
    contain no detected functions, are left untouched.
    """
    ext = os.path.basename(filepath).rsplit(".", 1)[-1] if "." in os.path.basename(filepath) else ""
    lang_key = EXT_TO_LANG.get(ext)
    if not lang_key:
        return 0, 0

    spans, raw_lines = _function_spans(filepath, lang_key)
    if not spans:
        return 0, 0

    drop = set()
    kept = removed = 0
    for name, start, end in spans:
        if name in keep_names:
            kept += 1
        else:
            removed += 1
            drop.update(range(start, end + 1))

    if drop:
        new_lines = [ln for i, ln in enumerate(raw_lines) if i not in drop]
        with open(filepath, "w") as f:
            f.writelines(new_lines)
    return kept, removed


def _trim_project_in_place(proj_dir, all_by_source, keep_by_source):
    """Delete the unselected functions and source files from proj_dir.

    Source files with at least one selected function are trimmed to keep only
    the selected function bodies (plus all non-function context lines); source
    files whose functions are all unselected are deleted outright. Files that
    contributed no extracted functions (configs, docs, unsupported languages,
    test files) are left untouched.
    """
    total_kept = total_removed = deleted_files = 0
    for source_rel in sorted(all_by_source):
        src_path = os.path.join(proj_dir, source_rel)
        if not os.path.isfile(src_path):
            continue
        keep_names = keep_by_source.get(source_rel)
        if not keep_names:
            os.remove(src_path)
            deleted_files += 1
            continue
        kept, removed = _trim_source_file(src_path, keep_names)
        total_kept += kept
        total_removed += removed

    print(
        f"[EntryPipeline] Trimmed {proj_dir}: kept {total_kept} function(s), "
        f"removed {total_removed} function(s), deleted {deleted_files} source file(s)."
    )


# ---------------------------------------------------------------------------
# Source restoration
#
# The entry pipeline trims proj_dir in place before running, and run_pipeline()
# additionally drives LLM agents with filesystem access that may leave stray
# edits. We snapshot the project's sources (everything except the fm_agent/
# workspace and .git) before trimming and restore them afterwards; the
# generated results under fm_agent/ are kept.
# ---------------------------------------------------------------------------

_RESTORE_SKIP_DIRS = ("fm_agent", ".git")


def _iter_source_entries(base):
    """Yield base-relative paths of all files (and symlinks) under ``base``.

    Directories named in _RESTORE_SKIP_DIRS are skipped entirely. Symlinks to
    directories are yielded as entries (not descended into) so they get
    restored as links.
    """
    for root, dirs, files in os.walk(base):
        dirs[:] = [d for d in dirs if d not in _RESTORE_SKIP_DIRS]
        links = [d for d in dirs if os.path.islink(os.path.join(root, d))]
        dirs[:] = [d for d in dirs if not os.path.islink(os.path.join(root, d))]
        for name in files + links:
            yield os.path.relpath(os.path.join(root, name), base)


def _entries_match(src, dst):
    """True if the backup entry ``src`` and the project entry ``dst`` are identical."""
    if os.path.islink(src) or os.path.islink(dst):
        return (
            os.path.islink(src)
            and os.path.islink(dst)
            and os.readlink(src) == os.readlink(dst)
        )
    if os.path.isdir(dst):
        return False
    # Shallow compare (size + mtime) is reliable here: the backup is made with
    # copy2 semantics, so untouched files keep matching stats.
    return filecmp.cmp(src, dst, shallow=True)


def _ensure_source_backup(proj_dir, backup_dir):
    """Snapshot proj_dir's sources (sans fm_agent/.git) into ``backup_dir``.

    An existing backup is reused as-is: it was left by an interrupted run and
    still holds the pristine sources from before that run, whereas the current
    tree may already carry that run's trim or stray edits.
    """
    if os.path.isdir(backup_dir):
        print(f"[EntryPipeline] Reusing source backup from an interrupted run at {backup_dir}.")
        return
    tmp_dir = backup_dir + ".tmp"
    if os.path.exists(tmp_dir):
        shutil.rmtree(tmp_dir)
    shutil.copytree(
        proj_dir, tmp_dir,
        ignore=shutil.ignore_patterns(*_RESTORE_SKIP_DIRS),
        symlinks=True,
    )
    os.replace(tmp_dir, backup_dir)


def _restore_sources(proj_dir, backup_dir):
    """Restore proj_dir's sources from ``backup_dir``, then delete the backup.

    Files created during the run are removed, modified or deleted files are
    restored from the backup, and directories created during the run are
    pruned once empty. Everything under fm_agent/ (and .git) is left alone.
    """
    if not os.path.isdir(backup_dir):
        return

    backup_entries = set(_iter_source_entries(backup_dir))
    current_entries = set(_iter_source_entries(proj_dir))

    removed = 0
    for rel in current_entries - backup_entries:
        path = os.path.join(proj_dir, rel)
        if os.path.lexists(path):
            os.remove(path)
            removed += 1

    restored = 0
    for rel in backup_entries:
        src = os.path.join(backup_dir, rel)
        dst = os.path.join(proj_dir, rel)
        if os.path.lexists(dst) and _entries_match(src, dst):
            continue
        if os.path.lexists(dst):
            if os.path.isdir(dst) and not os.path.islink(dst):
                shutil.rmtree(dst)
            else:
                os.remove(dst)
        os.makedirs(os.path.dirname(dst), exist_ok=True)
        shutil.copy2(src, dst, follow_symlinks=False)
        restored += 1

    # Recreate directories that were emptied/deleted during the run.
    for root, dirs, _files in os.walk(backup_dir):
        dirs[:] = [d for d in dirs if not os.path.islink(os.path.join(root, d))]
        for d in dirs:
            rel = os.path.relpath(os.path.join(root, d), backup_dir)
            os.makedirs(os.path.join(proj_dir, rel), exist_ok=True)

    # Prune directories created during the run, deepest first.
    candidates = []
    for root, dirs, _files in os.walk(proj_dir):
        dirs[:] = [
            d for d in dirs
            if d not in _RESTORE_SKIP_DIRS and not os.path.islink(os.path.join(root, d))
        ]
        candidates.extend(os.path.relpath(os.path.join(root, d), proj_dir) for d in dirs)
    for rel in sorted(candidates, key=lambda r: r.count(os.sep), reverse=True):
        path = os.path.join(proj_dir, rel)
        if not os.path.isdir(os.path.join(backup_dir, rel)) and not os.listdir(path):
            os.rmdir(path)

    shutil.rmtree(backup_dir)
    print(
        f"[EntryPipeline] Restored project sources: {restored} file(s) restored, "
        f"{removed} stray file(s) removed."
    )


def run_entry_pipeline(proj_dir, entry_func=None, end_funcs=None, resume=False):
    """Run the entry-point-scoped reasoning pipeline.

    Algorithm:
      1. Collect the functions related to ``entry_func`` — those reachable from
         it, optionally restricted to call chains ending at ``end_funcs`` — by
         freshly extracting every function into a temporary workspace and
         building the static call graph. No previous run_pipeline() is assumed.
      2. Snapshot the project's sources, then delete the unrelated functions
         and source files from ``proj_dir`` in place.
      3. Invoke the standard ``run_pipeline`` directly on ``proj_dir``: because
         only the related functions remain, it naturally specs, reasons about,
         and bug-validates exactly that set, writing results to
         ``<proj_dir>/fm_agent/``.
      4. Restore the deleted functions and files from the snapshot, leaving the
         generated ``fm_agent/`` workspace untouched. This runs even when the
         pipeline fails, and also undoes any stray edits the pipeline's agents
         made outside ``fm_agent/``.

    The snapshot lives beside the project at ``<proj_dir>.fm-entry-backup``
    while the pipeline runs and is removed after restoration; if a run is
    interrupted, the next run reuses it so the pristine sources are never lost.

    Args:
        proj_dir: path to the project directory.
        entry_func: FQN of the entry point to start reasoning from.
        end_funcs: list of FQNs at which to stop. If None (or empty), no chain
            restriction is applied and the whole call graph reachable from
            ``entry_func`` is selected.
        resume: forwarded directly to the standard pipeline.
    """
    if entry_func is None:
        raise ValueError("entry_func is required to run the entry pipeline")

    proj_dir = os.path.abspath(proj_dir)
    work_dir = os.path.join(proj_dir, "fm_agent")
    config.BUG_VALIDATION_MAX_RETRIES = 0

    # 1. Selection: extract fresh into a temp workspace and build the call graph.
    tmp_root = tempfile.mkdtemp(prefix="fm_entry_selection_")
    try:
        n_funcs = _extract_for_selection(proj_dir, tmp_root)
        if not n_funcs:
            raise ValueError(f"no extractable functions found under {proj_dir!r}")

        call_graph = build_entry_call_graph(tmp_root, entry_func)

        # Keep only functions on a call chain from entry_func to one of end_funcs.
        if end_funcs:
            unreachable = sorted(set(end_funcs) - set(call_graph))
            call_graph = _restrict_to_chains(call_graph, entry_func, end_funcs)
            if unreachable:
                logging.warning(
                    "[EntryPipeline] %d end function(s) are not reachable from %s: %s",
                    len(unreachable), entry_func, ", ".join(unreachable[:5]),
                )
            if not call_graph:
                raise ValueError(
                    f"none of the requested end_funcs are reachable from entry_func {entry_func!r}"
                )

        print(
            f"[EntryPipeline] Selected {len(call_graph)} of {n_funcs} function(s) "
            f"from entry {entry_func}."
        )

        extracted_base = os.path.join(tmp_root, "extracted_functions")
        fqn_to_file = _fqn_to_filepath_map(tmp_root)
        all_by_source = _group_funcs_by_source(
            (fp for fp, _ in _collect_all_function_files(tmp_root)), extracted_base
        )
        wanted_files = [fqn_to_file[fqn] for fqn in call_graph if fqn in fqn_to_file]
        keep_by_source = _group_funcs_by_source(wanted_files, extracted_base)
    finally:
        shutil.rmtree(tmp_root, ignore_errors=True)

    # 2. Snapshot the sources, then trim proj_dir in place.
    backup_dir = proj_dir + ".fm-entry-backup"
    _ensure_source_backup(proj_dir, backup_dir)
    try:
        _trim_project_in_place(proj_dir, all_by_source, keep_by_source)

        # 3. Run the standard pipeline directly on the trimmed project.
        # Imported lazily to avoid a circular import (main imports
        # run_entry_pipeline at module load).
        from main import run_pipeline

        run_pipeline(proj_dir, resume=resume)
    finally:
        # 4. restore the deleted functions/files; fm_agent/ stays untouched.
        _restore_sources(proj_dir, backup_dir)

    # Report confirmed bug count from the run.
    summary_path = os.path.join(work_dir, "bug_validation", "summary.json")
    if os.path.exists(summary_path):
        with open(summary_path, "r") as f:
            summary = json.load(f)
        confirmed = summary.get("total_confirmed", 0)
        print(f"[EntryPipeline] Confirmed bugs: {confirmed}")

    print(f"[EntryPipeline] Done. Results in {work_dir}.")

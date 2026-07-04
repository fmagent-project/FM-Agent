import os
import json
import shutil
import logging
from collections import deque, defaultdict

from src.generate_topdown_layers import (
    _build_call_graph,
    _collect_phase_files,
    _file_to_fqn,
)
from src.extract import EXT_TO_LANG, _function_spans, run_extraction
from src.languages.codegraph import try_codegraph_init
from src.file_utils import (
    _is_test_file,
    add_test_file_exemption,
    clear_test_file_exemptions,
)
import config


def _restrict_to_chains(call_graph, entry_func, end_funcs):
    """Keep only functions lying on a call chain from entry_func to an end_func.

    A function is retained iff it is reachable from ``entry_func`` (already
    guaranteed by ``call_graph``) *and* it can reach one of ``end_funcs`` — i.e.
    it sits on some path ``entry_func -> ... -> end_func``. The ``end_funcs`` are
    treated as terminal: their outgoing edges are dropped so chains stop there.

    Args:
        call_graph: dict mapping FQN -> sorted list of callee FQNs, rooted at
            entry_func (as built in _select_functions_by_source).
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


def _entry_func_source_rel(entry_func):
    """Map an entry_func FQN back to its source file (project-relative path).

    ``src::engine::loader-cpp::loadData`` -> ``src/engine/loader.cpp``. The FQN's
    last component is the function name and the second-to-last is the extraction
    function directory (``loader-cpp``); reuse the extracted-file inverse mapping
    by treating the ``::``-joined FQN as an extracted-file path.
    """
    extracted_rel = os.path.join(*entry_func.split("::"))
    return _extracted_file_to_source_rel(extracted_rel).replace(os.sep, "/")


def _trim_source_file(filepath, keep_names, proj_dir=None):
    """Delete every function NOT in ``keep_names`` from a source file in place.

    Non-function lines (includes, declarations, globals, etc.) are preserved as
    context; only the line ranges of unselected functions are removed. Returns
    ``(kept, removed)`` counts. Files whose language is unsupported, or that
    contain no detected functions, are left untouched.

    ``proj_dir`` is forwarded to _function_spans so codegraph can locate the
    project's index; when None, function detection falls back to the regex
    extractor.
    """
    ext = os.path.basename(filepath).rsplit(".", 1)[-1] if "." in os.path.basename(filepath) else ""
    lang_key = EXT_TO_LANG.get(ext)
    if not lang_key:
        return 0, 0

    spans, raw_lines = _function_spans(filepath, lang_key, proj_dir)
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
        kept, removed = _trim_source_file(src_path, keep_names, proj_dir)
        total_kept += kept
        total_removed += removed

    print(
        f"[EntryPipeline] Trimmed {proj_dir}: kept {total_kept} function(s), "
        f"removed {total_removed} function(s), deleted {deleted_files} source file(s)."
    )


# ---------------------------------------------------------------------------
# Run-directory copy
#
# The entry pipeline never mutates proj_dir. Instead it copies proj_dir's
# sources (everything except .git) into a separate run directory, trims and runs
# the pipeline there, and finally copies the generated fm_agent/ workspace back
# into proj_dir. This isolates both the trim and any stray edits run_pipeline()'s
# LLM agents make from the original repo. An existing fm_agent/ is copied along
# too, so a resumed run picks up where the prior one left off.
# ---------------------------------------------------------------------------

_SKIP_DIRS = (".git",)


def _make_run_copy(proj_dir, run_dir):
    """Copy proj_dir (everything except .git) into a fresh ``run_dir``.

    Includes an existing ``fm_agent/`` workspace so a resumed pipeline finds the
    prior run's state. Any leftover run directory from an interrupted run is
    discarded first: the pristine sources always live in proj_dir, so the copy
    can be remade cleanly.
    """
    for stale in (run_dir, run_dir + ".tmp"):
        if os.path.exists(stale):
            shutil.rmtree(stale)
    tmp_dir = run_dir + ".tmp"
    shutil.copytree(
        proj_dir, tmp_dir,
        ignore=shutil.ignore_patterns(*_SKIP_DIRS),
        symlinks=True,
    )
    os.replace(tmp_dir, run_dir)


def run_entry_pipeline(proj_dir, entry_func=None, end_funcs=None, resume=False):
    """Run the entry-point-scoped reasoning pipeline.

    Algorithm:
      1. Collect the functions related to ``entry_func`` — those reachable from
         it, optionally restricted to call chains ending at ``end_funcs`` — by
         freshly extracting every function into a temporary workspace and
         building the static call graph. No previous run_pipeline() is assumed.
      2. Copy the project's sources into a separate run directory, then delete
         the unrelated functions and source files from that copy. ``proj_dir``
         itself is never modified.
      3. Invoke the standard ``run_pipeline`` directly on the run directory:
         because only the related functions remain, it naturally specs, reasons
         about, and bug-validates exactly that set, writing results to
         ``<run_dir>/fm_agent/``.
      4. Copy the generated ``fm_agent/`` workspace back into ``proj_dir`` and
         discard the run directory. The copy-back runs even when the pipeline
         fails, so partial results are preserved, and any stray edits the
         pipeline's agents made stay confined to the discarded run directory.

    The run directory lives beside the project at ``<proj_dir>.fm-entry-run``
    while the pipeline runs and is removed afterwards; a leftover one from an
    interrupted run is discarded and remade, since the pristine sources always
    remain in ``proj_dir``.

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

    # The entry_func's source file may match the test-file heuristics (a test
    # directory or test-like name). Exempt it so neither the selection extraction
    # below nor run_pipeline's extraction skips it — the entry point must always
    # be reasoned about. Cleared in the finally so the exemption never leaks into
    # a later run in the same process.
    add_test_file_exemption(_entry_func_source_rel(entry_func))
    try:
        _run_entry_pipeline_inner(proj_dir, work_dir, entry_func, end_funcs, resume)
    finally:
        clear_test_file_exemptions()


def _enumerate_source_files(proj_dir):
    """List every supported, non-test source file under proj_dir (relative paths).

    Skips the fm_agent/ and .git/ directories and applies the same language and
    test-file filters run_extraction uses, so the returned files are exactly the
    ones that will yield extracted functions. The entry_func's source file is
    still included when it looks like a test, because run_entry_pipeline
    registers it as a test-file exemption before selection runs.
    """
    source_files = []
    for root, dirs, files in os.walk(proj_dir):
        dirs[:] = [d for d in dirs if d not in ("fm_agent", ".git")]
        for fname in files:
            src_rel = os.path.relpath(os.path.join(root, fname), proj_dir).replace(os.sep, "/")
            ext = fname.rsplit(".", 1)[-1] if "." in fname else ""
            if EXT_TO_LANG.get(ext) and not _is_test_file(src_rel):
                source_files.append(src_rel)
    return sorted(source_files)


def _select_functions_by_source(proj_dir, entry_func, end_funcs):
    """Select the functions reachable from entry_func, grouped by source file.

    Extracts a throwaway copy of proj_dir with the very machinery the main
    pipeline uses — ``run_extraction`` plus ``_build_call_graph`` from
    generate_topdown_layers, both codegraph-backed whenever a codegraph index
    can be built — then builds the call graph rooted at ``entry_func``
    (optionally restricted to chains reaching ``end_funcs``) and returns two
    source-file-keyed groupings:

        (all_by_source, keep_by_source)

    ``all_by_source`` covers every extractable function; ``keep_by_source``
    covers only the selected ones. proj_dir is read but never modified:
    extraction, the codegraph index and all scratch state live under a sibling
    selection copy that is discarded before returning.
    """
    # A full source copy lets codegraph index the project (writing .codegraph/)
    # and lets run_extraction/_build_call_graph run exactly as they do in
    # run_pipeline — without ever touching proj_dir. _build_call_graph resolves
    # the codegraph index via the copy's parent (see CodeGraphExtractor
    # .from_proj_dir), matching how run_pipeline drives it against work_dir.
    sel_dir = proj_dir + ".fm-entry-select"
    work_dir = os.path.join(sel_dir, "fm_agent")
    _make_run_copy(proj_dir, sel_dir)
    try:
        source_files = _enumerate_source_files(sel_dir)
        if not source_files:
            raise ValueError(f"no extractable source files found under {proj_dir!r}")

        # One all-encompassing phase, so _build_call_graph's within-phase edges
        # span the entire project (every reachable callee is retained).
        phase = {"phase": 0, "name": "all",
                 "modules": [{"name": "all", "source_files": source_files}]}
        # _make_run_copy brings along any existing fm_agent/; start the selection
        # extraction from a clean slate so no stale extracted_functions leak in.
        shutil.rmtree(work_dir, ignore_errors=True)
        os.makedirs(work_dir, exist_ok=True)
        with open(os.path.join(work_dir, "phases.json"), "w") as f:
            json.dump({"phases": [phase]}, f)

        try_codegraph_init(sel_dir)
        run_extraction(sel_dir, work_dir=work_dir, force=True)

        phase_files = _collect_phase_files(work_dir, phase)
        if not phase_files:
            raise ValueError(f"no extractable functions found under {proj_dir!r}")
        callees_map, _callers, _all_callees, _file_map, _module_map = _build_call_graph(
            phase_files, work_dir
        )
        all_fqns = {_file_to_fqn(fp, work_dir) for fp, _mod in phase_files}

        if entry_func not in all_fqns:
            raise ValueError(
                f"entry_func {entry_func!r} not found among extracted functions under proj_dir"
            )

        # BFS the call graph reachable from the entry point.
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

        # Every extractable function, grouped by source file.
        all_by_source = defaultdict(set)
        for fqn in all_fqns:
            all_by_source[_entry_func_source_rel(fqn)].add(fqn.split("::")[-1])
    finally:
        shutil.rmtree(sel_dir, ignore_errors=True)

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
        f"[EntryPipeline] Selected {len(call_graph)} of {len(all_fqns)} function(s) "
        f"from entry {entry_func}."
    )

    # Map the selected FQNs back to their (source file, function name).
    keep_by_source = defaultdict(set)
    for fqn in call_graph:
        keep_by_source[_entry_func_source_rel(fqn)].add(fqn.split("::")[-1])

    return all_by_source, keep_by_source


def _run_entry_pipeline_inner(proj_dir, work_dir, entry_func, end_funcs, resume):
    """Body of run_entry_pipeline; runs with the entry source file exempted."""
    # 1. Selection: extract fresh into a temp workspace and build the call graph.
    all_by_source, keep_by_source = _select_functions_by_source(
        proj_dir, entry_func, end_funcs
    )

    # 2. Copy the sources into a separate run directory, then trim that copy.
    # proj_dir is left untouched throughout.
    run_dir = proj_dir + ".fm-entry-run"
    run_work_dir = os.path.join(run_dir, "fm_agent")
    # _make_run_copy brings along an existing fm_agent/, so a resumed run finds
    # the prior state in run_dir without any extra seeding here.
    _make_run_copy(proj_dir, run_dir)
    try:
        # Build the codegraph index on the run copy before trimming so that
        # _trim_project_in_place detects function names/spans with the same
        # codegraph backend that _select_functions_by_source used to produce
        # keep_by_source. Without it the trim would fall back to the regex
        # extractor and could disagree with the selection (mismatched names or
        # spans -> wrong functions kept/removed). Non-fatal: skips silently if
        # codegraph is not installed (selection then also used regex, so the two
        # stay consistent). run_pipeline rebuilds the index again after the trim
        # edits these sources, so extraction sees the trimmed tree, not this one.
        try_codegraph_init(run_dir)
        _trim_project_in_place(run_dir, all_by_source, keep_by_source)

        # 3. Run the standard pipeline directly on the run copy.
        # Imported lazily to avoid a circular import (main imports
        # run_entry_pipeline at module load).
        from main import run_pipeline

        # Force the entry point's source file into phases.json even if the setup
        # agent omits it (e.g. because it looks like a test), so run_pipeline
        # always extracts and reasons about the entry function.
        run_pipeline(
            run_dir,
            resume=resume,
            required_source_files=[_entry_func_source_rel(entry_func)],
        )
    finally:
        # 4. Copy the generated fm_agent/ back into proj_dir, then discard the
        # run directory. Runs even on failure so partial results are preserved.
        if os.path.isdir(run_work_dir):
            if os.path.isdir(work_dir):
                shutil.rmtree(work_dir)
            shutil.copytree(run_work_dir, work_dir, symlinks=True)
            print(f"[EntryPipeline] Copied generated fm_agent/ to {work_dir}.")
        shutil.rmtree(run_dir, ignore_errors=True)

    # Report the bug count: the number of MISMATCH verdicts the reasoner wrote
    # into fm_agent/logic_verification_results/.
    mismatches = _count_mismatches(os.path.join(work_dir, "logic_verification_results"))
    print(f"[EntryPipeline] Bugs (mismatches): {mismatches}")

    print(f"[EntryPipeline] Done. Results in {work_dir}.")


def _count_mismatches(results_dir):
    """Count MISMATCH verdicts in a logic_verification_results/ tree.

    Each function's verdict is a JSON file nested under per-module directories;
    a ``"verdict"`` of ``"MISMATCH"`` marks a spec violation (a candidate bug).
    Unreadable or malformed files are skipped.
    """
    count = 0
    for root, _dirs, files in os.walk(results_dir):
        for fname in files:
            if not fname.endswith(".json"):
                continue
            try:
                with open(os.path.join(root, fname), "r") as f:
                    if json.load(f).get("verdict") == "MISMATCH":
                        count += 1
            except (OSError, ValueError):
                continue
    return count

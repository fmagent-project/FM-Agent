from __future__ import annotations

import os
import json
import shutil
import logging
from collections import deque, defaultdict

from src.call_graph_edges import load_call_edges
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


_original_proj_dir: str | None = None
_entry_run_dir: str | None = None
_entry_func: str | None = None
_end_funcs: list[str] = []
_extra_edge: str | None = None
_all_bugs = False
_READY_MARKER = ".entry_scope_ready"


def configure(proj_dir: str) -> None:
    """Load and validate the entry run context created by ``main.py``."""
    global _original_proj_dir, _entry_run_dir, _entry_func
    global _end_funcs, _extra_edge, _all_bugs

    context_path = os.path.join(proj_dir, "fm_agent", "plugin_context.json")
    with open(context_path, encoding="utf-8") as file:
        context = json.load(file)
    if not isinstance(context, dict):
        raise ValueError("plugin_context.json must contain a JSON object")

    original_proj_dir = context.get("original_proj_dir")
    entry_run_dir = context.get("entry_run_dir")
    entry_func = context.get("entry_func")
    end_funcs = context.get("end_funcs", [])
    extra_edge = context.get("extra_edge")
    all_bugs = context.get("all_bugs", False)

    if not isinstance(original_proj_dir, str) or not original_proj_dir:
        raise ValueError("original_proj_dir must be a non-empty string")
    if not isinstance(entry_run_dir, str) or not entry_run_dir:
        raise ValueError("entry_run_dir must be a non-empty string")
    if not isinstance(entry_func, str) or not entry_func:
        raise ValueError("entry_func must be a non-empty string")
    if not isinstance(end_funcs, list) or any(
        not isinstance(value, str) or not value for value in end_funcs
    ):
        raise ValueError("end_funcs must be a list of non-empty strings")
    if extra_edge is not None and (
        not isinstance(extra_edge, str) or not extra_edge
    ):
        raise ValueError("extra_edge must be a non-empty string or null")
    if not isinstance(all_bugs, bool):
        raise ValueError("all_bugs must be a boolean")

    actual_proj_dir = os.path.abspath(proj_dir)
    original_proj_dir = os.path.abspath(original_proj_dir)
    entry_run_dir = os.path.abspath(entry_run_dir)
    if actual_proj_dir != entry_run_dir:
        raise ValueError("entry plugin must run in the configured entry_run_dir")
    if entry_run_dir == original_proj_dir:
        raise ValueError("entry plugin refuses to modify the original project")
    if not entry_run_dir.endswith(".fm-entry-run"):
        raise ValueError("entry_run_dir must end with '.fm-entry-run'")

    _original_proj_dir = original_proj_dir
    _entry_run_dir = entry_run_dir
    _entry_func = entry_func
    _end_funcs = list(end_funcs)
    _extra_edge = extra_edge
    _all_bugs = all_bugs
    add_test_file_exemption(_entry_func_source_rel(_entry_func))


def _require_configured(proj_dir: str) -> None:
    """Require hooks to operate only on the configured isolated run copy."""
    if _entry_run_dir is None or _original_proj_dir is None or _entry_func is None:
        raise RuntimeError("entry_reasoning plugin has not been configured")
    if os.path.abspath(proj_dir) != _entry_run_dir:
        raise RuntimeError("entry_reasoning received an unexpected project directory")
    if os.path.abspath(proj_dir) == _original_proj_dir:
        raise RuntimeError("entry_reasoning refuses to modify the original project")


def prepare_entry_scope(proj_dir: str) -> None:
    """Select the entry call chain and trim the isolated project in place."""
    _require_configured(proj_dir)
    extra_call_edges = load_call_edges(_extra_edge)
    all_by_source, keep_by_source = _select_functions_by_source(
        proj_dir,
        _entry_func,
        _end_funcs,
        extra_call_edges=extra_call_edges,
    )
    try_codegraph_init(proj_dir)
    _trim_project_in_place(proj_dir, all_by_source, keep_by_source)
    marker_path = os.path.join(proj_dir, "fm_agent", _READY_MARKER)
    with open(marker_path, "w", encoding="utf-8") as file:
        file.write("ready\n")


def publish_entry_results(proj_dir: str) -> None:
    """Copy entry results back to the original project and remove the run copy."""
    global _entry_run_dir

    if _entry_run_dir is None or not os.path.isdir(_entry_run_dir):
        return
    _require_configured(proj_dir)

    try:
        run_work_dir = os.path.join(_entry_run_dir, "fm_agent")
        original_work_dir = os.path.join(_original_proj_dir, "fm_agent")
        ready_marker = os.path.join(run_work_dir, _READY_MARKER)
        if os.path.isfile(ready_marker):
            os.remove(ready_marker)
        mismatches = _count_mismatches(
            os.path.join(run_work_dir, "logic_verification_results"),
            all_bugs=_all_bugs,
        )
        if os.path.isdir(run_work_dir):
            if os.path.isdir(original_work_dir):
                shutil.rmtree(original_work_dir)
            shutil.copytree(run_work_dir, original_work_dir, symlinks=True)
            print(f"[EntryPlugin] Copied generated fm_agent/ to {original_work_dir}.")
        shutil.rmtree(_entry_run_dir, ignore_errors=True)
        _entry_run_dir = None
        print(f"[EntryPlugin] Bugs (mismatches): {mismatches}")
        print(f"[EntryPlugin] Done. Results in {original_work_dir}.")
    finally:
        clear_test_file_exemptions()


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
    with a hyphen (``loader.cpp`` -> ``loader-cpp``). Member functions keep the
    class qualifier in the flat filename (``.../loader-cpp/MyClass::method.cpp``),
    so the ``<base>-<ext>`` directory is the function file's immediate parent; we
    still locate it by scanning the path components from the right (matching a
    component that ends in ``-<known extension>``) so the mapping is robust.
    """
    parts = extracted_rel.split(os.sep)
    for i in range(len(parts) - 2, -1, -1):          # skip the trailing func file
        comp = parts[i]
        hyphen = comp.rfind("-")
        if hyphen > 0 and comp[hyphen + 1:] in EXT_TO_LANG:
            src_dir = os.sep.join(parts[:i])
            source_base = comp[:hyphen] + "." + comp[hyphen + 1:]
            return os.path.join(src_dir, source_base) if src_dir else source_base
    # Fallback: original immediate-parent behaviour (no recognised -ext dir).
    func_dir = os.path.dirname(extracted_rel)
    src_dir = os.path.dirname(func_dir)
    dir_name = os.path.basename(func_dir)
    hyphen = dir_name.rfind("-")
    source_base = dir_name[:hyphen] + "." + dir_name[hyphen + 1:] if hyphen > 0 else dir_name
    return os.path.join(src_dir, source_base) if src_dir else source_base


def _fqn_to_ident(fqn):
    """Return a function's class-qualified identifier: the FQN tail after the
    ``<base>-<ext>`` source-file component.

        src::storage-cpp::LocalStorage::Flush -> LocalStorage::Flush
        src::checkpoint-cpp::RunCheckpoint     -> RunCheckpoint

    This is exactly the name run_extraction wrote (as the flat filename stem)
    and _function_spans reports, so trim keeps/removes the right same-name method
    instead of collapsing LocalStorage::Flush and WriteAheadLog::Flush together.
    """
    parts = fqn.split("::")
    for i in range(len(parts) - 1, -1, -1):
        comp = parts[i]
        hyphen = comp.rfind("-")
        if hyphen > 0 and comp[hyphen + 1:] in EXT_TO_LANG:
            return "::".join(parts[i + 1:])
    return parts[-1]


def _entry_func_source_rel(entry_func):
    """Map an entry_func FQN back to its source file (project-relative path).

    ``src::engine::loader-cpp::loadData`` -> ``src/engine/loader.cpp``;
    ``src::storage-cpp::LocalStorage::Flush`` -> ``src/storage.cpp``. Reuse the
    extracted-file inverse mapping by treating the ``::``-joined FQN as an
    extracted-file path; _extracted_file_to_source_rel finds the ``<base>-<ext>``
    directory regardless of any class components after it.
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

    spans, raw_lines, _backend_available = _function_spans(filepath, lang_key, proj_dir)
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


def _enumerate_source_files(proj_dir):
    """List every supported, non-test source file under proj_dir (relative paths).

    Skips the fm_agent/ and .git/ directories and applies the same language and
    test-file filters run_extraction uses, so the returned files are exactly the
    ones that will yield extracted functions. The entry_func's source file is
    still included when it looks like a test, because configure registers it as
    a test-file exemption before selection runs.
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


def _select_functions_by_source(proj_dir, entry_func, end_funcs, extra_call_edges=None):
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
        (
            callees_map,
            _callers,
            _all_callees,
            _file_map,
            _module_map,
            _edge_aliases,
        ) = _build_call_graph(
            phase_files,
            work_dir,
            extra_call_edges=extra_call_edges,
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
            all_by_source[_entry_func_source_rel(fqn)].add(_fqn_to_ident(fqn))
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

    # Map the selected FQNs back to their (source file, function identifier).
    keep_by_source = defaultdict(set)
    for fqn in call_graph:
        keep_by_source[_entry_func_source_rel(fqn)].add(_fqn_to_ident(fqn))

    return all_by_source, keep_by_source


def _count_mismatches(results_dir, all_bugs=False):
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
                    result = json.load(f)
                if all_bugs:
                    if (
                        result.get("all_bugs") is True
                        and result.get("verdict") == "MISMATCH"
                        and result.get("reasoning_complete") is True
                    ):
                        count += result.get("bug_count", 0)
                elif result.get("verdict") == "MISMATCH":
                    count += 1
            except (OSError, ValueError):
                continue
    return count

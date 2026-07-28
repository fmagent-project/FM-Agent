"""Entry-point reasoning implemented through Stage 1 and Stage 4 hooks."""

from __future__ import annotations

import json
import logging
import os
import posixpath
import tempfile
from collections import deque

from src.call_graph_edges import load_call_edges
from src.extract import EXT_TO_LANG, run_extraction
from src.file_utils import (
    add_test_file_exemption,
    clear_test_file_exemptions,
)
from src.generate_topdown_layers import (
    _build_call_graph,
    _collect_phase_files,
    _file_to_fqn,
)
from src.languages.codegraph import try_codegraph_init


_project_dir: str | None = None
_entry_func: str | None = None
_end_funcs: list[str] = []
_extra_edge: str | None = None
_selected_fqns: set[str] = set()


def configure(options: dict) -> None:
    """Configure entry selection for one FM-Agent invocation."""
    global _project_dir, _entry_func, _end_funcs, _extra_edge
    global _selected_fqns

    project_dir = options.get("project_dir")
    if not isinstance(project_dir, str) or not os.path.isdir(project_dir):
        raise ValueError(
            "entry_reasoning requires a valid project_dir"
        )

    entry_func = options.get("entry_func")
    if not isinstance(entry_func, str) or not entry_func.strip():
        raise ValueError(
            "entry_reasoning requires a non-empty --entry-func value"
        )

    end_funcs = options.get("end_funcs", [])
    if not isinstance(end_funcs, list) or any(
        not isinstance(value, str) or not value.strip()
        for value in end_funcs
    ):
        raise ValueError("end_funcs must be a list of non-empty strings")

    extra_edge = options.get("extra_edge")
    if extra_edge is not None and (
        not isinstance(extra_edge, str) or not extra_edge.strip()
    ):
        raise ValueError("extra_edge must be a non-empty path or None")

    clear_test_file_exemptions()
    _project_dir = os.path.abspath(project_dir)
    _entry_func = entry_func.strip()
    _end_funcs = [value.strip() for value in end_funcs]
    _extra_edge = extra_edge
    _selected_fqns = set()
    add_test_file_exemption(
        _source_rel_from_fqn(_entry_func).replace(os.sep, "/")
    )


def _source_rel_from_fqn(fqn: str) -> str:
    """Map an extracted-function FQN back to its project-relative source."""
    parts = fqn.split("::")
    for index in range(len(parts) - 1, -1, -1):
        component = parts[index]
        hyphen = component.rfind("-")
        if hyphen <= 0 or component[hyphen + 1 :] not in EXT_TO_LANG:
            continue
        source_parts = parts[:index] + [
            component[:hyphen] + "." + component[hyphen + 1 :]
        ]
        return os.path.join(*source_parts)
    raise ValueError(
        f"entry function does not contain a '<source>-<extension>' component: "
        f"{fqn!r}"
    )


def _reachable_graph(callees_map: dict, entry_func: str) -> dict:
    """Return the call graph reachable from the configured entry function."""
    call_graph = {}
    queue = deque([entry_func])
    while queue:
        fqn = queue.popleft()
        if fqn in call_graph:
            continue
        callees = sorted(callees_map.get(fqn, set()))
        call_graph[fqn] = callees
        for callee in callees:
            if callee not in call_graph:
                queue.append(callee)
    return call_graph


def _restrict_to_end_functions(
    call_graph: dict,
    entry_func: str,
    end_funcs: list[str],
) -> dict:
    """Keep only nodes on a path from entry_func to an end function."""
    if not end_funcs:
        return call_graph

    callers = {fqn: set() for fqn in call_graph}
    for caller, callees in call_graph.items():
        for callee in callees:
            callers.setdefault(callee, set()).add(caller)

    on_chain = set()
    queue = deque(fqn for fqn in end_funcs if fqn in call_graph)
    while queue:
        fqn = queue.popleft()
        if fqn in on_chain:
            continue
        on_chain.add(fqn)
        queue.extend(callers.get(fqn, ()))

    if not on_chain:
        raise ValueError(
            f"none of the requested end functions are reachable from "
            f"{entry_func!r}"
        )

    end_set = set(end_funcs)
    return {
        fqn: (
            []
            if fqn in end_set
            else [callee for callee in call_graph[fqn] if callee in on_chain]
        )
        for fqn in on_chain
    }


def _make_codegraph_available(project_dir: str, work_dir: str) -> None:
    """Expose the project's existing index to the temporary graph builder."""
    source_index = os.path.join(project_dir, ".codegraph")
    temporary_index = os.path.join(work_dir, ".codegraph")
    if not os.path.isdir(source_index) or os.path.lexists(temporary_index):
        return
    try:
        os.symlink(source_index, temporary_index, target_is_directory=True)
    except OSError as exc:
        logging.warning(
            "[EntryPlugin] Could not reuse codegraph index; "
            "falling back to regex call analysis: %s",
            exc,
        )


def select_entry_source_files(source_files: list[str]) -> list[str]:
    """Select source files containing functions on the configured call chain."""
    global _selected_fqns

    if _project_dir is None or _entry_func is None:
        raise RuntimeError("entry_reasoning plugin has not been configured")
    if not source_files:
        raise ValueError("entry_reasoning requires at least one source file")

    phase = {
        "phase": 1,
        "name": "Entry Selection",
        "modules": [
            {
                "name": "Entry Selection",
                "source_files": list(source_files),
            }
        ],
    }

    with tempfile.TemporaryDirectory(
        prefix="fm-agent-entry-selection-"
    ) as work_dir:
        with open(
            os.path.join(work_dir, "phases.json"),
            "w",
            encoding="utf-8",
        ) as phases_file:
            json.dump({"phases": [phase]}, phases_file)

        try_codegraph_init(_project_dir)
        _make_codegraph_available(_project_dir, work_dir)
        run_extraction(
            _project_dir,
            work_dir=work_dir,
            force=True,
        )

        phase_files = _collect_phase_files(work_dir, phase)
        if not phase_files:
            raise ValueError(
                "no functions were extracted from Stage 1 source candidates"
            )

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
            extra_call_edges=load_call_edges(_extra_edge),
        )
        all_fqns = {
            _file_to_fqn(path, work_dir)
            for path, _module_name in phase_files
        }

    if _entry_func not in all_fqns:
        raise ValueError(
            f"entry function {_entry_func!r} was not found among extracted "
            "Stage 1 source candidates"
        )

    call_graph = _reachable_graph(callees_map, _entry_func)
    unreachable = sorted(set(_end_funcs) - set(call_graph))
    if unreachable:
        logging.warning(
            "[EntryPlugin] %d end function(s) are not reachable from %s: %s",
            len(unreachable),
            _entry_func,
            ", ".join(unreachable[:5]),
        )
    call_graph = _restrict_to_end_functions(
        call_graph,
        _entry_func,
        _end_funcs,
    )
    _selected_fqns = set(call_graph)

    selected_sources = {
        _source_rel_from_fqn(fqn).replace(os.sep, "/")
        for fqn in _selected_fqns
    }
    result = [
        source_file
        for source_file in source_files
        if source_file.replace("\\", "/") in selected_sources
    ]
    if not result:
        raise ValueError("entry call chain did not select any source files")

    print(
        f"[EntryPlugin] Selected {len(_selected_fqns)} function(s) in "
        f"{len(result)} of {len(source_files)} source file(s) from entry "
        f"{_entry_func}."
    )
    return result


def _function_file_to_fqn(function_file: str) -> str:
    """Convert a Stage 4 extracted-function path to its FM-Agent FQN."""
    normalized = function_file.replace("\\", "/")
    stem, _extension = posixpath.splitext(normalized)
    return "::".join(part for part in stem.split("/") if part)


def select_entry_functions(function_files: list[str]) -> list[str]:
    """Return only Stage 4 functions selected by entry reachability."""
    try:
        if not _selected_fqns:
            raise RuntimeError(
                "entry source selection did not produce any functions"
            )

        result = [
            function_file
            for function_file in function_files
            if _function_file_to_fqn(function_file) in _selected_fqns
        ]
        if not result:
            raise ValueError(
                "none of the selected entry functions were found in Stage 4"
            )

        print(
            f"[EntryPlugin] Stage 4 kept {len(result)} of "
            f"{len(function_files)} extracted function file(s)."
        )
        return result
    finally:
        clear_test_file_exemptions()

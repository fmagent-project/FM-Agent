"""Entry-point reasoning implemented as an FM-Agent Stage 3 plugin."""

from __future__ import annotations

import logging
import os
from collections import deque
from pathlib import Path

from src.call_graph_edges import load_call_edges
from src.extract import (
    EXT_TO_LANG,
    _safe_filename,
    extract_functions_from_file,
)
from src.generate_topdown_layers import _build_call_graph, _file_to_fqn
from src.languages.registry import batch_extract_all


_entry_func: str | None = None
_end_funcs: list[str] = []
_extra_edge: str | None = None


def configure(options: dict) -> None:
    """Configure entry selection for one FM-Agent invocation."""
    global _entry_func, _end_funcs, _extra_edge

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

    _entry_func = entry_func.strip()
    _end_funcs = [value.strip() for value in end_funcs]
    _extra_edge = extra_edge


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


def _project_root(source_paths: list[str], entry_func: str) -> str:
    """Derive the project root from the entry function's source path."""
    entry_source_parts = Path(_source_rel_from_fqn(entry_func)).parts
    for source_path in source_paths:
        absolute_path = Path(source_path).resolve()
        if len(absolute_path.parts) < len(entry_source_parts):
            continue
        tail = absolute_path.parts[-len(entry_source_parts) :]
        if tuple(os.path.normcase(part) for part in tail) != tuple(
            os.path.normcase(part) for part in entry_source_parts
        ):
            continue

        root = absolute_path
        for _ in entry_source_parts:
            root = root.parent
        return str(root)

    entry_source = os.path.join(*entry_source_parts)
    raise ValueError(
        f"entry function source {entry_source!r} is not present in Stage 3 input"
    )


def _write_extracted_functions(
    source_paths: list[str],
    project_root: str,
    output_dir: str,
) -> list[str]:
    """Extract Stage 3 source paths into the controlled plugin output."""
    registry_funcs, _registry_langs = batch_extract_all(project_root)
    registry_funcs = {
        os.path.normcase(os.path.normpath(path)): functions
        for path, functions in registry_funcs.items()
    }

    output_files = []
    for source_path in source_paths:
        absolute_source = os.path.abspath(source_path)
        relative_source = os.path.relpath(absolute_source, project_root)
        if relative_source == os.pardir or relative_source.startswith(
            os.pardir + os.sep
        ):
            raise ValueError(
                f"Stage 3 input escapes the entry project: {absolute_source!r}"
            )

        extension = (
            relative_source.rsplit(".", 1)[-1]
            if "." in os.path.basename(relative_source)
            else ""
        )
        language = EXT_TO_LANG.get(extension)
        if language is None:
            continue

        registry_key = os.path.normcase(os.path.normpath(absolute_source))
        functions = registry_funcs.get(registry_key)
        if functions is None:
            functions = extract_functions_from_file(absolute_source, language)

        source_dir = os.path.dirname(relative_source)
        source_name = os.path.basename(relative_source)
        last_dot = source_name.rfind(".")
        function_dir_name = (
            source_name[:last_dot] + "-" + source_name[last_dot + 1 :]
            if last_dot > 0
            else source_name
        )
        function_dir = os.path.join(
            output_dir,
            source_dir,
            function_dir_name,
        )

        for function_name, function_source in functions:
            os.makedirs(function_dir, exist_ok=True)
            output_path = os.path.join(
                function_dir,
                _safe_filename(function_name, extension),
            )
            with open(output_path, "w", encoding="utf-8") as output_file:
                output_file.write(function_source)
            output_files.append(output_path)

    return output_files


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


def _make_codegraph_available(project_root: str, output_dir: str) -> None:
    """Expose the project's existing index to the temporary graph builder."""
    source_index = os.path.join(project_root, ".codegraph")
    temporary_index = os.path.join(
        os.path.dirname(output_dir),
        ".codegraph",
    )
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


def extract_entry_functions(
    source_paths: list[str],
    output_dir: str,
) -> list[str]:
    """Extract and return only functions selected by entry reachability."""
    if _entry_func is None:
        raise RuntimeError("entry_reasoning plugin has not been configured")
    if not source_paths:
        raise ValueError("entry_reasoning requires at least one Stage 3 source")

    project_root = _project_root(source_paths, _entry_func)
    extracted_files = _write_extracted_functions(
        source_paths,
        project_root,
        output_dir,
    )
    if not extracted_files:
        raise ValueError("no functions were extracted from Stage 3 input")

    phase_files = [(path, "entry_reasoning") for path in extracted_files]
    extra_edges = load_call_edges(_extra_edge)
    _make_codegraph_available(project_root, output_dir)
    (
        callees_map,
        _callers,
        _all_callees,
        _file_map,
        _module_map,
        _edge_aliases,
    ) = _build_call_graph(
        phase_files,
        os.path.dirname(output_dir),
        extra_call_edges=extra_edges,
    )

    files_by_fqn = {
        _file_to_fqn(path, os.path.dirname(output_dir)): path
        for path in extracted_files
    }
    if _entry_func not in files_by_fqn:
        raise ValueError(
            f"entry function {_entry_func!r} was not found among extracted "
            "Stage 3 functions"
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

    selected_paths = [
        files_by_fqn[fqn]
        for fqn in sorted(call_graph)
    ]
    print(
        f"[EntryPlugin] Selected {len(selected_paths)} of "
        f"{len(extracted_files)} function(s) from entry {_entry_func}."
    )
    return selected_paths

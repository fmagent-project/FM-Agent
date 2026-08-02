import json
import os
import re
import logging
from pathlib import Path
from collections import defaultdict
from dataclasses import dataclass

from src.extract import EXT_TO_LANG, LANG_CONFIG
from src.file_utils import _is_metadata_sidecar
from src.languages.registry import call_edges_all


# ---------------------------------------------------------------------------
# 1.1 Configuration
# ---------------------------------------------------------------------------

def _load_modules(proj_dir):
    """Load modules.json from the fm_agent work directory."""
    modules_path = os.path.join(proj_dir, "modules.json")
    with open(modules_path, "r") as f:
        return json.load(f)


# ---------------------------------------------------------------------------
# 1.2 Collect files per module
# ---------------------------------------------------------------------------

def _collect_module_files(proj_dir, modules_data):
    """Collect all extracted function file paths declared by modules.json.

    Returns list of (file_path, module_name) tuples.
    """
    extracted_base = os.path.join(proj_dir, "extracted_functions")
    results = []

    for module in modules_data.get("modules", []):
        module_name = module["name"]
        for src_file in module.get("source_files", []):
            # Derive extracted directory: xxx/yyy/zzz.ext -> xxx/yyy/zzz-ext
            src_dir = os.path.dirname(src_file)
            src_base = os.path.basename(src_file)
            last_dot = src_base.rfind(".")
            if last_dot > 0:
                dir_name = src_base[:last_dot] + "-" + src_base[last_dot + 1:]
            else:
                dir_name = src_base

            func_dir = os.path.join(extracted_base, src_dir, dir_name) if src_dir else os.path.join(extracted_base, dir_name)
            if not os.path.isdir(func_dir):
                continue

            # Every extracted function is a flat file directly in func_dir, member
            # functions keeping the class qualifier in the name
            # ("<file>-cpp/LocalStorage::Flush.cpp"). os.walk stays robust to any
            # legacy nested file.
            for root, _dirs, fnames in os.walk(func_dir):
                for fname in fnames:
                    fpath = os.path.join(root, fname)
                    if os.path.isfile(fpath) and not _is_metadata_sidecar(fname):
                        results.append((fpath, module_name))

    return results


# ---------------------------------------------------------------------------
# 1.3 Assign FQNs
# ---------------------------------------------------------------------------

def _file_to_fqn(filepath, proj_dir):
    """Convert an extracted function file path to its FQN.

    extracted_functions/src/engine/loader-cpp/loadData.cpp -> src::engine::loader-cpp::loadData
    """
    extracted_base = os.path.join(proj_dir, "extracted_functions")
    rel = os.path.relpath(filepath, extracted_base)
    # Strip file extension from the function file itself
    stem, _ = os.path.splitext(rel)
    # Join with :: separator
    parts = Path(stem).parts
    return "::".join(parts)


# ---------------------------------------------------------------------------
# 1.4 Build call graph by static analysis
# ---------------------------------------------------------------------------

# Language keywords to exclude from call site detection.
# We merge the per-language keywords from LANG_CONFIG with some common extras.
_COMMON_EXTRA_KEYWORDS = {
    "printf", "fprintf", "sprintf", "snprintf", "scanf", "sscanf",
    "malloc", "calloc", "realloc", "free",
    "memcpy", "memset", "memmove", "memcmp",
    "strlen", "strcmp", "strncmp", "strcpy", "strncpy", "strcat",
    "assert", "static_assert",
    "print", "len", "range", "enumerate", "zip", "map", "filter",
    "sorted", "reversed", "list", "dict", "set", "tuple", "int",
    "float", "str", "bool", "type", "super", "isinstance", "issubclass",
    "hasattr", "getattr", "setattr", "delattr", "open", "close",
    "input", "round", "abs", "min", "max", "sum", "any", "all",
    "iter", "next", "hash", "id", "repr", "ord", "chr", "hex", "oct", "bin",
    "format", "vars", "dir", "help", "eval", "exec", "compile",
    "append", "extend", "insert", "remove", "pop", "clear", "copy",
    "keys", "values", "items", "get", "update",
    "make", "new", "nil", "panic", "recover", "close", "delete",
    "len", "cap", "append", "copy",
    "println", "eprintln", "format", "write", "writeln",
    "vec", "box", "rc", "arc", "option", "result", "some", "none", "ok", "err",
    "console", "log", "warn", "error", "info", "debug",
    "require", "define", "module", "exports",
    "Math", "Object", "Array", "String", "Number", "Boolean",
    "Date", "RegExp", "Error", "Promise", "JSON",
    "setTimeout", "setInterval", "clearTimeout", "clearInterval",
    "main",
}


def _detect_lang_from_ext(filepath):
    """Detect the language key from a file's extension."""
    base = os.path.basename(filepath)
    ext = base.rsplit(".", 1)[-1] if "." in base else ""
    return EXT_TO_LANG.get(ext)


def _strip_comments_from_source(text, lang_key):
    """Strip comments from source text, replacing their content with spaces
    to preserve character positions. Returns the cleaned text."""
    result = list(text)
    i = 0
    lang_cfg = LANG_CONFIG.get(lang_key, {})
    comment_prefix = lang_cfg.get("comment_prefix", "//")
    is_hash_comment = comment_prefix == "#"

    while i < len(result):
        ch = result[i]

        # Mask string literals (including Python triple-quoted strings)
        if ch in ('"', "'"):
            quote = ch
            # Check for triple-quote
            if i + 2 < len(result) and result[i + 1] == quote and result[i + 2] == quote:
                result[i] = " "
                result[i + 1] = " "
                result[i + 2] = " "
                i += 3
                while i < len(result):
                    if result[i] == "\\":
                        if result[i] != "\n":
                            result[i] = " "
                        if i + 1 < len(result) and result[i + 1] != "\n":
                            result[i + 1] = " "
                        i += 2
                        continue
                    if result[i] == quote and i + 2 < len(result) and result[i + 1] == quote and result[i + 2] == quote:
                        result[i] = " "
                        result[i + 1] = " "
                        result[i + 2] = " "
                        i += 3
                        break
                    if result[i] != "\n":
                        result[i] = " "
                    i += 1
                continue
            if result[i] != "\n":
                result[i] = " "
            i += 1
            while i < len(result):
                if result[i] == "\\":
                    if result[i] != "\n":
                        result[i] = " "
                    if i + 1 < len(result) and result[i + 1] != "\n":
                        result[i + 1] = " "
                    i += 2
                    continue
                if result[i] == quote:
                    if result[i] != "\n":
                        result[i] = " "
                    i += 1
                    break
                if result[i] != "\n":
                    result[i] = " "
                i += 1
            continue

        # Hash-style line comments (Python, Ruby, Shell)
        if is_hash_comment and ch == "#":
            start = i
            while i < len(result) and result[i] != "\n":
                result[i] = " "
                i += 1
            continue

        # C-style line comments
        if not is_hash_comment and ch == "/" and i + 1 < len(result) and result[i + 1] == "/":
            while i < len(result) and result[i] != "\n":
                result[i] = " "
                i += 1
            continue

        # C-style block comments
        if not is_hash_comment and ch == "/" and i + 1 < len(result) and result[i + 1] == "*":
            result[i] = " "
            result[i + 1] = " "
            i += 2
            while i < len(result):
                if result[i] == "*" and i + 1 < len(result) and result[i + 1] == "/":
                    result[i] = " "
                    result[i + 1] = " "
                    i += 2
                    break
                if result[i] != "\n":
                    result[i] = " "
                i += 1
            continue

        i += 1

    return "".join(result)


def _get_call_regex(lang_key):
    """Return the call-site regex for the given language."""
    if lang_key in ("cpp", "c", "java", "typescript", "javascript", "cuda", "arkts"):
        # identifier, optional template args, open paren
        return re.compile(r"\b(\w+)\s*(?:<[^>]*>)?\s*\(")
    elif lang_key == "rust":
        # identifier, optional turbofish, open paren
        return re.compile(r"\b(\w+)\s*(?:::<[^>]*>)?\s*\(")
    elif lang_key == "go":
        # identifier, optional type params [T], open paren
        return re.compile(r"\b(\w+)\s*(?:\[[^\]]*\])?\s*\(")
    else:
        # Python, Ruby, Shell, SQL, etc.
        return re.compile(r"\b(\w+)\s*\(")


def _get_keywords_for_lang(lang_key):
    """Get the combined set of keywords to exclude for a language."""
    lang_cfg = LANG_CONFIG.get(lang_key, {})
    kw = set(lang_cfg.get("keywords", set()))
    kw.update(_COMMON_EXTRA_KEYWORDS)
    return kw


def _find_call_sites(text, lang_key, known_stems, keywords):
    """Find call sites in source text, returning set of matched stem names."""
    cleaned = _strip_comments_from_source(text, lang_key)
    regex = _get_call_regex(lang_key)
    found = set()
    for m in regex.finditer(cleaned):
        ident = m.group(1)
        if ident in keywords:
            continue
        if ident in known_stems:
            found.add(ident)
    return found


def _build_call_graph(module_files, proj_dir, global_stem_to_fqns=None, extra_call_edges=None):
    """Build callees_map and callers_map for a set of extracted files.

    Args:
        module_files: list of (filepath, module_name) tuples
        proj_dir: project root directory
        global_stem_to_fqns: optional global stem->set(fqn) mapping.
        extra_call_edges: optional iterable of supplemental CallEdge objects.
                          caller.fqn is exact; caller.callsite_names are matched
                          only against explicitly listed source callsite names.

    Returns:
        (callees_map, callers_map, all_callees_map, file_map, module_map,
        edge_aliases_map) where keys are FQNs.
        callees_map/callers_map contain edges among extracted functions.
        all_callees_map is kept for compatibility and is the same global edge set.
        edge_aliases_map maps callee -> caller -> supplemental callee labels
        that may appear as callee names in a caller's .info.json sidecar.
    """
    # Build FQN mappings
    fqn_map = {}  # filepath -> fqn
    stem_to_fqns = defaultdict(set)
    file_map = {}  # fqn -> filepath
    module_map = {}  # fqn -> module_name

    for filepath, module_name in module_files:
        fqn = _file_to_fqn(filepath, proj_dir)
        fqn_map[filepath] = fqn
        file_map[fqn] = filepath
        module_map[fqn] = module_name
        stem = fqn.split("::")[-1]
        stem_to_fqns[stem].add(fqn)

    local_fqns = set(fqn_map.values())
    # For call-site detection, use global stems if available
    effective_stem_to_fqns = global_stem_to_fqns if global_stem_to_fqns else stem_to_fqns
    # All extracted FQNs, used to
    # keep only codegraph callees that correspond to an extracted function.
    known_fqns = {
        fqn
        for fqns in effective_stem_to_fqns.values()
        for fqn in fqns
    }
    extra_edges_by_caller_fqn, extra_edges_by_callsite = _resolve_extra_call_edges(
        extra_call_edges,
        local_fqns=local_fqns,
        known_fqns=known_fqns,
    )
    known_stems = set(effective_stem_to_fqns.keys()) | set(extra_edges_by_callsite.keys())

    callees_map = defaultdict(set)  # fqn -> set of callee fqns
    callers_map = defaultdict(set)  # fqn -> set of caller fqns
    all_callees_map = defaultdict(set)  # fqn -> set of callee fqns
    edge_aliases_map = defaultdict(lambda: defaultdict(set))  # callee -> caller -> aliases

    local_langs = {_detect_lang_from_ext(fp) for fp, _ in module_files if _detect_lang_from_ext(fp)}
    registry_edges, registry_langs = call_edges_all(proj_dir, local_langs)

    for filepath, module_name in module_files:
        fqn = fqn_map[filepath]
        lang_key = _detect_lang_from_ext(filepath)
        if not lang_key:
            continue

        called_stems = set()
        if lang_key in registry_langs:
            # codegraph: edges are already precise caller_fqn -> callee_fqn (the
            # exact node codegraph resolved). Keep only callees that are extracted
            # functions; drop external/library targets.
            callee_fqns = {c for c in registry_edges.get(fqn, set())
                           if c != fqn and c in known_fqns}
            if extra_edges_by_callsite:
                keywords = _get_keywords_for_lang(lang_key)
                try:
                    with open(filepath, "r", errors="replace") as f:
                        text = f.read()
                except OSError:
                    text = ""
                called_stems = _find_call_sites(
                    text, lang_key, set(extra_edges_by_callsite.keys()), keywords
                )
        else:
            # regex fallback: detect bare-name call sites, then resolve each stem
            # to every same-named FQN (an over-approximation — unchanged).
            keywords = _get_keywords_for_lang(lang_key)
            try:
                with open(filepath, "r", errors="replace") as f:
                    text = f.read()
            except OSError:
                continue
            called_stems = _find_call_sites(text, lang_key, known_stems, keywords)
            callee_fqns = {cf for stem in called_stems
                           for cf in effective_stem_to_fqns.get(stem, set()) if cf != fqn}

        for callee_fqn in callee_fqns:
            all_callees_map[fqn].add(callee_fqn)
            if callee_fqn in local_fqns:
                callees_map[fqn].add(callee_fqn)
                callers_map[callee_fqn].add(fqn)

        for stem in called_stems:
            for edge in extra_edges_by_callsite.get(stem, ()):
                _add_resolved_extra_edge(
                    fqn,
                    edge,
                    local_fqns,
                    callees_map,
                    callers_map,
                    all_callees_map,
                    edge_aliases_map,
                )

        for edge in extra_edges_by_caller_fqn.get(fqn, ()):
            _add_resolved_extra_edge(
                fqn,
                edge,
                local_fqns,
                callees_map,
                callers_map,
                all_callees_map,
                edge_aliases_map,
            )

    return callees_map, callers_map, all_callees_map, file_map, module_map, edge_aliases_map


@dataclass(frozen=True)
class _ResolvedExtraEdge:
    callee_fqn: str
    info_names: tuple[str, ...]
    source: str


def _resolve_extra_call_edges(extra_call_edges, local_fqns, known_fqns):
    """Resolve supplemental edges into local caller indexes."""
    by_caller_fqn = defaultdict(list)
    by_callsite = defaultdict(list)
    if not extra_call_edges:
        return by_caller_fqn, by_callsite

    local_fqns = set(local_fqns)
    known_fqns = set(known_fqns)
    for edge in extra_call_edges:
        callee_fqn = edge.callee.fqn
        if callee_fqn not in known_fqns:
            logging.warning(
                "Skipping supplemental edge from %s: callee.fqn %r "
                "was not found among extracted functions.",
                edge.source or "edge file",
                callee_fqn,
            )
            continue

        resolved = _ResolvedExtraEdge(
            callee_fqn=callee_fqn,
            info_names=tuple(edge.callee.info_names),
            source=edge.source,
        )

        if edge.caller.fqn:
            caller_fqn = edge.caller.fqn
            if caller_fqn in local_fqns:
                by_caller_fqn[caller_fqn].append(resolved)
            else:
                logging.debug(
                    "Skipping supplemental edge from %s in current scope: "
                    "caller FQN %r is not in the analyzed function set.",
                    edge.source or "edge file",
                    caller_fqn,
                )

        for callsite in edge.caller.callsite_names:
            if not re.fullmatch(r"[A-Za-z_]\w*", callsite):
                logging.warning(
                    "Skipping supplemental edge callsite selector %r from %s: "
                    "the current scanner only matches identifier callsites.",
                    callsite,
                    edge.source or "edge file",
                )
                continue
            by_callsite[callsite].append(resolved)

    return by_caller_fqn, by_callsite


def _add_resolved_extra_edge(
    caller_fqn,
    edge: _ResolvedExtraEdge,
    local_fqns,
    callees_map,
    callers_map,
    all_callees_map,
    edge_aliases_map,
):
    """Inject one resolved supplemental edge and attach its callee aliases."""
    callee_fqn = edge.callee_fqn
    if caller_fqn == callee_fqn:
        return False

    before = len(all_callees_map[caller_fqn])
    all_callees_map[caller_fqn].add(callee_fqn)
    edge_aliases_map[callee_fqn][caller_fqn].update(edge.info_names)

    if callee_fqn in local_fqns:
        callees_map[caller_fqn].add(callee_fqn)
        callers_map[callee_fqn].add(caller_fqn)

    return len(all_callees_map[caller_fqn]) != before


# ---------------------------------------------------------------------------
# 1.5 Topological layer computation
# ---------------------------------------------------------------------------

def _tarjan_scc(nodes, edges):
    """Compute strongly connected components using Tarjan's algorithm (iterative).

    Args:
        nodes: iterable of node identifiers
        edges: dict mapping node -> set of successor nodes

    Returns:
        list of SCCs (each SCC is a set of nodes), in reverse topological order
    """
    index_counter = 0
    scc_stack = []
    on_stack = set()
    index_map = {}
    lowlink = {}
    result = []

    for node in nodes:
        if node in index_map:
            continue
        # Iterative DFS using an explicit call stack.
        # Each frame is (v, iterator_over_successors, is_initial_visit)
        call_stack = [(node, iter(edges.get(node, set())), True)]
        while call_stack:
            v, successors, initial = call_stack[-1]
            if initial:
                index_map[v] = index_counter
                lowlink[v] = index_counter
                index_counter += 1
                scc_stack.append(v)
                on_stack.add(v)
                # Mark as visited so we don't re-init
                call_stack[-1] = (v, successors, False)

            advanced = False
            for w in successors:
                if w not in index_map:
                    call_stack.append((w, iter(edges.get(w, set())), True))
                    advanced = True
                    break
                elif w in on_stack:
                    lowlink[v] = min(lowlink[v], index_map[w])

            if advanced:
                continue

            # All successors processed — check if v is a root
            if lowlink[v] == index_map[v]:
                scc = set()
                while True:
                    w = scc_stack.pop()
                    on_stack.discard(w)
                    scc.add(w)
                    if w == v:
                        break
                result.append(scc)

            call_stack.pop()
            if call_stack:
                parent = call_stack[-1][0]
                lowlink[parent] = min(lowlink[parent], lowlink[v])

    return result


def _compute_layers(function_fqns, callees_map, callers_map):
    """Compute topological layers using Kahn's algorithm with cycle handling.

    Returns list of layer dicts: [{"layer": N, "functions": [...], "cycle_resolution": bool}, ...]
    """
    function_set = set(function_fqns)

    # Build caller counts.
    remaining = set(function_set)
    assigned = {}  # fqn -> layer index
    layers = []

    while remaining:
        # Find functions whose callers are already assigned.
        ready = set()
        for fqn in remaining:
            local_callers = callers_map.get(fqn, set()) & function_set
            unassigned_callers = local_callers - set(assigned.keys())
            if not unassigned_callers:
                ready.add(fqn)

        if ready:
            layer_idx = len(layers)
            for fqn in ready:
                assigned[fqn] = layer_idx
            layers.append({"layer": layer_idx, "functions": sorted(ready), "cycle_resolution": False})
            remaining -= ready
        else:
            # Cycle detected — use Tarjan's SCC
            # Build subgraph of remaining functions
            sub_edges = {}
            for fqn in remaining:
                sub_edges[fqn] = callees_map.get(fqn, set()) & remaining

            # Compute SCCs on the *caller* graph (edges from callee to caller)
            # Actually we need topological ordering of SCCs by the caller relationship.
            # An SCC can be assigned once all SCCs that *call into it* are assigned.
            # So we use the callers graph direction for the SCC ordering.
            caller_edges_sub = {}
            for fqn in remaining:
                caller_edges_sub[fqn] = callers_map.get(fqn, set()) & remaining

            sccs = _tarjan_scc(remaining, caller_edges_sub)

            # Build SCC DAG and assign layers
            fqn_to_scc = {}
            for i, scc in enumerate(sccs):
                for fqn in scc:
                    fqn_to_scc[fqn] = i

            # Build DAG between SCCs based on caller edges
            scc_callers = defaultdict(set)  # scc_idx -> set of scc_idx that call into it
            for fqn in remaining:
                scc_i = fqn_to_scc[fqn]
                for caller_fqn in callers_map.get(fqn, set()) & remaining:
                    scc_j = fqn_to_scc[caller_fqn]
                    if scc_i != scc_j:
                        scc_callers[scc_i].add(scc_j)

            # Topological sort of SCCs
            scc_assigned = {}
            scc_remaining = set(range(len(sccs)))

            while scc_remaining:
                scc_ready = set()
                for scc_idx in scc_remaining:
                    unassigned_scc_callers = scc_callers.get(scc_idx, set()) - set(scc_assigned.keys())
                    if not unassigned_scc_callers:
                        scc_ready.add(scc_idx)

                if not scc_ready:
                    # Should not happen if Tarjan is correct, but handle gracefully
                    # Assign all remaining to the same layer
                    layer_idx = len(layers)
                    all_fqns = set()
                    for scc_idx in scc_remaining:
                        all_fqns.update(sccs[scc_idx])
                    for fqn in all_fqns:
                        assigned[fqn] = layer_idx
                    layers.append({"layer": layer_idx, "functions": sorted(all_fqns), "cycle_resolution": True})
                    remaining -= all_fqns
                    break

                layer_idx = len(layers)
                layer_fqns = set()
                is_cycle = False
                for scc_idx in scc_ready:
                    scc_assigned[scc_idx] = layer_idx
                    layer_fqns.update(sccs[scc_idx])
                    if len(sccs[scc_idx]) > 1:
                        is_cycle = True

                for fqn in layer_fqns:
                    assigned[fqn] = layer_idx
                layers.append({"layer": layer_idx, "functions": sorted(layer_fqns), "cycle_resolution": is_cycle})
                remaining -= layer_fqns
                scc_remaining -= scc_ready

    return layers


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def generate_topdown_layers(proj_dir, extra_call_edges=None):
    """Generate a single global topdown layer JSON file.

    Args:
        proj_dir: project root directory
        extra_call_edges: optional iterable of supplemental caller/callee edges

    Returns:
        list of output file paths written
    """
    modules_data = _load_modules(proj_dir)

    output_dir = os.path.join(proj_dir, "spec_prompts")
    os.makedirs(output_dir, exist_ok=True)

    module_files = _collect_module_files(proj_dir, modules_data)
    if not module_files:
        logging.warning("No extracted files found for modules.json.")
        return []

    global_stem_to_fqns = defaultdict(set)
    for filepath, _ in module_files:
        fqn = _file_to_fqn(filepath, proj_dir)
        stem = fqn.split("::")[-1]
        global_stem_to_fqns[stem].add(fqn)

    (
        callees_map,
        callers_map,
        all_callees_map,
        file_map,
        module_map,
        edge_aliases_map,
    ) = _build_call_graph(
        module_files, proj_dir, global_stem_to_fqns, extra_call_edges=extra_call_edges
    )
    function_fqns = set(file_map.keys())
    layers = _compute_layers(function_fqns, callees_map, callers_map)

    output_layers = []
    for layer_info in layers:
        layer_dict = {"layer": layer_info["layer"]}
        if layer_info["cycle_resolution"]:
            layer_dict["cycle_resolution"] = True

        func_entries = []
        for fqn in layer_info["functions"]:
            filepath = file_map[fqn]
            rel_path = os.path.relpath(filepath, proj_dir)
            info_names_by_caller = {
                caller: sorted(info_names)
                for caller, info_names in edge_aliases_map.get(fqn, {}).items()
                if caller in function_fqns and info_names
            }
            entry = {
                "name": fqn,
                "file": rel_path,
                "unit": module_map.get(fqn, ""),
                "callers": sorted(callers_map.get(fqn, set()) & function_fqns),
                "callees": sorted(callees_map.get(fqn, set()) & function_fqns),
                "all_callees": sorted(all_callees_map.get(fqn, set())),
            }
            if info_names_by_caller:
                entry["callee_info_names_by_caller"] = info_names_by_caller
            func_entries.append(entry)

        layer_dict["functions"] = func_entries
        output_layers.append(layer_dict)

    output = {
        "total_functions": len(function_fqns),
        "total_layers": len(layers),
        "layers": output_layers,
    }
    out_path = os.path.join(output_dir, "topdown_layers.json")
    with open(out_path, "w") as f:
        json.dump(output, f, indent=2, ensure_ascii=False)

    print(
        f"[TopdownLayers] Global: {len(function_fqns)} functions, "
        f"{len(layers)} layers -> {os.path.relpath(out_path, proj_dir)}"
    )
    return [out_path]

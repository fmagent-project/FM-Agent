import os
import re
from collections import defaultdict

from src.chisel_circt import load_circt_module_graph
from src.chisel_support import (
    chisel_decl_info,
    extract_chisel_functions,
    is_chisel_test_file,
    strip_chisel_comments,
)


_MODULE_ROOTS = {"Module", "RawModule", "BlackBox", "ExtModule", "MultiIOModule"}
_SOURCE_EXTS = (".scala", ".sc")
_LOCAL_DECL_RE = re.compile(r"\b(?:class|object|trait)\s+([A-Za-z_$][\w$]*)")
_MODULE_PARENT_SUFFIXES = ("Module", "ModuleImp", "RawModule", "Shell")
_NON_MODULE_PARENT_SUFFIXES = (
    "Backend",
    "Binder",
    "IOBinder",
    "Overlay",
    "PlacedOverlay",
    "Placer",
    "ShellPlacer",
    "Params",
    "TypeParams",
    "Config",
    "Field",
)
_MODULE_FEATURE_MARKERS = (
    "instantiateChipTops(",
    "childClock :=",
    "childReset :=",
    "referenceClock",
    "referenceReset",
    "withClockAndReset(",
    "RegInit(",
    "Module(new",
)


def _canonicalize(name):
    if not name:
        return name
    return name.replace("/", "_")


def _iter_chisel_files(proj_dir):
    for root, dirs, files in os.walk(proj_dir):
        dirs[:] = [
            d for d in dirs
            if not d.startswith(".") and d not in {
                "node_modules",
                "__pycache__",
                "venv",
                ".venv",
                "fm_agent",
                "extracted_functions",
                "spec_prompts",
            }
        ]
        for fname in files:
            if not fname.endswith(_SOURCE_EXTS):
                continue
            abs_path = os.path.join(root, fname)
            rel_path = os.path.relpath(abs_path, proj_dir).replace(os.sep, "/")
            if is_chisel_test_file(rel_path):
                continue
            yield abs_path, rel_path


def _collect_units(proj_dir):
    units = []
    for abs_path, rel_path in _iter_chisel_files(proj_dir):
        with open(abs_path, "r", errors="replace") as f:
            lines = [line.rstrip("\n").rstrip("\r") for line in f.readlines()]
        for name, start_idx, end_idx in extract_chisel_functions(lines, "chisel", {}):
            source = "\n".join(lines[start_idx:end_idx + 1]) + "\n"
            kind, declared_name, parent, _parent_prefix = chisel_decl_info(source)
            units.append(
                {
                    "abs_path": abs_path,
                    "rel_path": rel_path,
                    "source": source,
                    "kind": kind,
                    "name": declared_name or name,
                    "parent": parent,
                }
            )
    return units


def _iter_extracted_unit_files(work_dir):
    extracted_root = os.path.join(work_dir, "extracted_functions")
    if not os.path.isdir(extracted_root):
        return
    for root, _, files in os.walk(extracted_root):
        for fname in files:
            if not fname.endswith(_SOURCE_EXTS):
                continue
            abs_path = os.path.join(root, fname)
            rel_path = os.path.relpath(abs_path, extracted_root).replace(os.sep, "/")
            yield abs_path, rel_path


def _collect_extracted_units(work_dir):
    units = []
    for abs_path, rel_path in _iter_extracted_unit_files(work_dir):
        try:
            with open(abs_path, "r", errors="replace") as f:
                source = f.read()
        except OSError:
            continue
        kind, declared_name, parent, _parent_prefix = chisel_decl_info(source)
        if not declared_name:
            continue
        units.append(
            {
                "abs_path": abs_path,
                "rel_path": rel_path,
                "source": source,
                "kind": kind,
                "name": declared_name,
                "parent": parent,
                "fqn": _extracted_unit_fqn(rel_path),
            }
        )
    return units


def _source_module_names(units):
    name_to_units = defaultdict(list)
    for idx, unit in enumerate(units):
        if unit["kind"] == "class" and unit["name"]:
            name_to_units[unit["name"]].append(idx)

    cache = {}
    visiting = set()

    def looks_like_unresolved_module(unit):
        parent = unit["parent"] or ""
        if any(parent.endswith(suffix) for suffix in _NON_MODULE_PARENT_SUFFIXES):
            return False
        if any(parent.endswith(suffix) for suffix in _MODULE_PARENT_SUFFIXES):
            return True
        # Fallback only for unresolved external bases.
        source = strip_chisel_comments(unit["source"])
        return any(marker in source for marker in _MODULE_FEATURE_MARKERS)

    def is_module(idx):
        if idx in cache:
            return cache[idx]
        if idx in visiting:
            return False
        visiting.add(idx)
        unit = units[idx]
        result = False
        if unit["kind"] == "class":
            parent = unit["parent"]
            if parent in _MODULE_ROOTS:
                result = True
            elif parent:
                parent_indices = name_to_units.get(parent, ())
                if parent_indices:
                    result = any(is_module(parent_idx) for parent_idx in parent_indices)
                else:
                    result = looks_like_unresolved_module(unit)
        visiting.remove(idx)
        cache[idx] = result
        return result

    return {
        units[idx]["name"]
        for idx in range(len(units))
        if units[idx]["name"] and is_module(idx)
    }


def _filtered_units(proj_dir):
    units = _collect_units(proj_dir)
    if not units:
        return []
    source_modules = _source_module_names(units)
    circt_graph = load_circt_module_graph(proj_dir)
    authoritative_modules = set(circt_graph["modules"]) if circt_graph else None

    kept = []
    for unit in units:
        if unit["kind"] != "class":
            continue
        if unit["name"] not in source_modules:
            continue
        if authoritative_modules is not None and unit["name"] not in authoritative_modules:
            continue
        kept.append(unit)
    return kept


def _filtered_extracted_units(work_dir):
    units = _collect_extracted_units(work_dir)
    if not units:
        return []

    authoritative_modules = None
    circt_graph = load_circt_module_graph(work_dir)
    if circt_graph:
        authoritative_modules = set(circt_graph["modules"])

    kept = []
    for unit in units:
        if unit["kind"] != "class":
            continue
        if authoritative_modules is not None and unit["name"] not in authoritative_modules:
            continue
        kept.append(unit)
    return kept


def _unit_fqn(rel_path, unit_name):
    base = os.path.basename(rel_path)
    last_dot = base.rfind(".")
    dashed = base[:last_dot] + "-" + base[last_dot + 1:] if last_dot > 0 else base
    dir_part = os.path.dirname(rel_path).replace(os.sep, "/")
    parts = [p for p in dir_part.split("/") if p] + [dashed, _canonicalize(unit_name)]
    return "::".join(parts)


def _extracted_unit_fqn(rel_path):
    stem, _ = os.path.splitext(rel_path.replace(os.sep, "/"))
    return "::".join(part for part in stem.split("/") if part)


def batch_extract(proj_dir):
    grouped = defaultdict(list)
    name_counts = defaultdict(lambda: defaultdict(int))
    for unit in _filtered_units(proj_dir):
        cname = _canonicalize(unit["name"])
        count = name_counts[unit["abs_path"]][cname]
        name_counts[unit["abs_path"]][cname] += 1
        deduped = cname if count == 0 else f"{cname}_{count}"
        grouped[unit["abs_path"]].append((deduped, unit["source"]))
    return dict(grouped)


def _instantiated_module_names(text, known_names):
    cleaned = strip_chisel_comments(text)
    found = set()
    for raw_line in cleaned.splitlines():
        line = raw_line.strip()
        if "new " not in line:
            continue
        parts = line.replace("(", " ").replace(")", " ").replace("{", " ").split()
        for idx, token in enumerate(parts[:-1]):
            if token == "new":
                name = parts[idx + 1]
                if name in known_names:
                    found.add(name)
    return found


def _local_declared_names(text):
    names = set()
    for name in _LOCAL_DECL_RE.findall(strip_chisel_comments(text)):
        names.add(name)
    return names


def call_edges(proj_dir):
    units = _filtered_units(proj_dir)
    use_extracted_fqns = False
    if not units and os.path.isdir(os.path.join(proj_dir, "extracted_functions")):
        units = _filtered_extracted_units(proj_dir)
        use_extracted_fqns = True
    if not units:
        return {}

    fqns_by_name = defaultdict(set)
    texts_by_name = {}
    local_names_by_fqn = {}
    for unit in units:
        fqn = unit["fqn"] if use_extracted_fqns else _unit_fqn(unit["rel_path"], unit["name"])
        fqns_by_name[unit["name"]].add(fqn)
        texts_by_name[fqn] = unit["source"]
        local_names = _local_declared_names(unit["source"])
        local_names.discard(unit["name"])
        local_names_by_fqn[fqn] = local_names

    circt_graph = load_circt_module_graph(proj_dir)
    edges = defaultdict(set)
    if circt_graph:
        for caller_name, callee_names in circt_graph["edges"].items():
            for caller_fqn in fqns_by_name.get(caller_name, ()):
                for callee_name in callee_names:
                    for callee_fqn in fqns_by_name.get(callee_name, ()):
                        if callee_fqn != caller_fqn:
                            edges[caller_fqn].add(callee_fqn)
        return dict(edges)

    known_names = set(fqns_by_name)
    for caller_fqn, text in texts_by_name.items():
        shadowed = local_names_by_fqn.get(caller_fqn, set())
        for callee_name in _instantiated_module_names(text, known_names):
            if callee_name in shadowed:
                continue
            for callee_fqn in fqns_by_name.get(callee_name, ()):
                if callee_fqn != caller_fqn:
                    edges[caller_fqn].add(callee_fqn)
    return dict(edges)

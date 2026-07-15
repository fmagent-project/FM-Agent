import json
import logging
import os
import shutil
import subprocess
from collections import defaultdict

from src.verilog_support import extract_verilog_functions, find_verilog_call_sites


_GRAPH_FILENAME = "chisel_circt_module_graph.json"
_ENV_VERILOG_DIR = "FM_AGENT_CHISEL_CIRCT_VERILOG_DIR"
_ENV_COMMAND = "FM_AGENT_CHISEL_CIRCT_COMMAND"
_ENV_OUT_DIR = "FM_AGENT_CHISEL_CIRCT_OUT_DIR"


def _candidate_fm_agent_dirs(root):
    root = os.path.abspath(root)
    candidates = []
    if os.path.basename(root) == "fm_agent":
        candidates.append(root)
    else:
        candidates.append(os.path.join(root, "fm_agent"))
    candidates.append(os.path.join(os.path.dirname(root), "fm_agent"))
    seen = set()
    out = []
    for candidate in candidates:
        if candidate not in seen:
            out.append(candidate)
            seen.add(candidate)
    return out


def graph_path_for(root):
    for fm_agent_dir in _candidate_fm_agent_dirs(root):
        if os.path.basename(fm_agent_dir) == "fm_agent":
            return os.path.join(fm_agent_dir, _GRAPH_FILENAME)
    return os.path.join(os.path.abspath(root), "fm_agent", _GRAPH_FILENAME)


def load_circt_module_graph(root):
    for fm_agent_dir in _candidate_fm_agent_dirs(root):
        path = os.path.join(fm_agent_dir, _GRAPH_FILENAME)
        try:
            with open(path, "r") as f:
                data = json.load(f)
        except OSError:
            continue
        except json.JSONDecodeError:
            logging.warning("Ignoring corrupt CIRCT graph file: %s", path)
            continue
        graph = _normalize_graph_payload(data)
        if graph is None:
            logging.warning("Ignoring malformed CIRCT graph file: %s", path)
            continue
        return graph
    return None


def _normalize_graph_payload(data):
    modules = data.get("modules")
    edges = data.get("edges")
    if not isinstance(modules, list) or not isinstance(edges, dict):
        return None

    normalized_edges = {}
    for caller, callees in edges.items():
        if not isinstance(caller, str) or not isinstance(callees, list):
            continue
        normalized_edges[caller] = [
            callee for callee in callees if isinstance(callee, str)
        ]
    return {
        "modules": [m for m in modules if isinstance(m, str)],
        "edges": normalized_edges,
        "verilog_root": data.get("verilog_root"),
        "source": data.get("source", "unknown"),
    }


def _iter_emitted_verilog_files(verilog_root):
    for root, _, files in os.walk(verilog_root):
        for fname in files:
            if not fname.endswith((".v", ".sv", ".svh")):
                continue
            yield os.path.join(root, fname)


def _module_graph_from_emitted_verilog(verilog_root):
    modules = {}
    for path in _iter_emitted_verilog_files(verilog_root):
        try:
            with open(path, "r", errors="replace") as f:
                lines = f.readlines()
        except OSError:
            continue
        for name, start_idx, end_idx in extract_verilog_functions(lines, "verilog", {}):
            text = "\n".join(line.rstrip("\n").rstrip("\r") for line in lines[start_idx:end_idx + 1])
            if not text.endswith("\n"):
                text += "\n"
            modules[name] = text

    known = set(modules)
    edges = defaultdict(set)
    for caller, text in modules.items():
        for callee in find_verilog_call_sites(text, known, frozenset()):
            if callee != caller:
                edges[caller].add(callee)

    return {
        "modules": sorted(known),
        "edges": {caller: sorted(callees) for caller, callees in sorted(edges.items())},
    }


def _resolve_emitted_verilog_dir(proj_dir, work_dir, verilog_dir, command):
    if verilog_dir:
        if not os.path.isabs(verilog_dir):
            return os.path.join(proj_dir, verilog_dir)
        return verilog_dir

    emitted_dir = os.path.join(work_dir, "chisel_circt_out")
    shutil.rmtree(emitted_dir, ignore_errors=True)
    os.makedirs(emitted_dir, exist_ok=True)
    env = os.environ.copy()
    env[_ENV_OUT_DIR] = emitted_dir
    # Keep the shell command contract simple: the caller writes Verilog files
    # into FM_AGENT_CHISEL_CIRCT_OUT_DIR and this parser reads only those.
    subprocess.run(
        command,
        cwd=proj_dir,
        env=env,
        shell=True,
        check=True,
    )
    return emitted_dir


def build_circt_module_graph(proj_dir, work_dir):
    verilog_dir = os.environ.get(_ENV_VERILOG_DIR, "").strip()
    command = os.environ.get(_ENV_COMMAND, "").strip()
    if not verilog_dir and not command:
        return None

    emitted_dir = _resolve_emitted_verilog_dir(proj_dir, work_dir, verilog_dir, command)

    if not os.path.isdir(emitted_dir):
        raise RuntimeError(
            f"CIRCT output directory does not exist: {emitted_dir}. "
            f"Set {_ENV_VERILOG_DIR} or make {_ENV_COMMAND} write Verilog under {_ENV_OUT_DIR}."
        )

    graph = _module_graph_from_emitted_verilog(emitted_dir)
    if not graph["modules"]:
        raise RuntimeError(
            f"No Verilog modules were found under CIRCT output directory: {emitted_dir}"
        )
    graph["verilog_root"] = os.path.abspath(emitted_dir)
    graph["source"] = _ENV_VERILOG_DIR if verilog_dir else _ENV_COMMAND

    path = os.path.join(work_dir, _GRAPH_FILENAME)
    with open(path, "w") as f:
        json.dump(graph, f, indent=2, sort_keys=True)
    return graph

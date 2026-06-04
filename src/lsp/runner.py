import json
import logging
import os

from config import LSP_STRICT

from .registry import LSP_REGISTRY, register_default_providers


def lsp_dir(work_dir):
    return os.path.join(work_dir, "lsp")


def symbols_path(work_dir):
    return os.path.join(lsp_dir(work_dir), "symbols.json")


def calls_path(work_dir):
    return os.path.join(lsp_dir(work_dir), "calls.json")


def status_path(work_dir):
    return os.path.join(lsp_dir(work_dir), "status.json")


def run_lsp_analysis(proj_dir, work_dir, source_files=None):
    """Run all registered LSP providers and write normalized artifacts."""
    os.makedirs(lsp_dir(work_dir), exist_ok=True)
    register_default_providers()
    if source_files is None:
        source_files = _source_files_from_project(proj_dir)

    status = {
        "enabled": True,
        "success": False,
        "providers": [],
        "symbols": 0,
        "calls": 0,
        "errors": [],
    }
    providers = LSP_REGISTRY.providers_for(proj_dir, source_files)
    all_symbols = []
    all_calls = []

    if not providers:
        status["errors"].append("no registered LSP provider can handle current source files")

    for provider in providers:
        try:
            result = provider.analyze(proj_dir, work_dir, source_files)
        except Exception as exc:
            logging.exception("LSP provider %s failed", provider.id)
            result = None
            provider_status = {
                "id": provider.id,
                "success": False,
                "symbols": 0,
                "calls": 0,
                "error": str(exc),
                "metadata": {},
            }
        else:
            provider_status = result.status_json()

        status["providers"].append(provider_status)
        if result and result.success:
            all_symbols.extend(result.symbols)
            all_calls.extend(result.calls)
        elif provider_status.get("error"):
            status["errors"].append(f"{provider.id}: {provider_status['error']}")

    _write_json(symbols_path(work_dir), [symbol.to_json() for symbol in all_symbols])
    _write_json(calls_path(work_dir), [edge.to_json() for edge in all_calls])
    status["success"] = bool(all_symbols or all_calls)
    status["symbols"] = len(all_symbols)
    status["calls"] = len(all_calls)
    _write_json(status_path(work_dir), status)

    if status["errors"]:
        logging.warning("LSP analysis completed with errors: %s", "; ".join(status["errors"]))
        if LSP_STRICT:
            raise RuntimeError("; ".join(status["errors"]))
    print(f"[LSP] symbols={len(all_symbols)}, calls={len(all_calls)}, providers={len(providers)}")
    return status


def load_lsp_symbols(work_dir):
    path = symbols_path(work_dir)
    if not os.path.exists(path):
        return {}
    try:
        with open(path, "r") as f:
            records = json.load(f)
    except (OSError, json.JSONDecodeError) as exc:
        logging.warning("Could not read LSP symbols: %s", exc)
        return {}
    by_file = {}
    for record in records:
        source_file = record.get("source_file")
        if source_file:
            by_file.setdefault(source_file, []).append(record)
    for items in by_file.values():
        items.sort(key=lambda item: (item.get("start_line", 0), item.get("end_line", 0)))
    return by_file


def load_lsp_calls(work_dir):
    path = calls_path(work_dir)
    if not os.path.exists(path):
        return []
    try:
        with open(path, "r") as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError) as exc:
        logging.warning("Could not read LSP calls: %s", exc)
        return []


def _source_files_from_phases(work_dir):
    phases_path = os.path.join(work_dir, "phases.json")
    with open(phases_path, "r") as f:
        data = json.load(f)
    files = []
    for phase in data.get("phases", []):
        for module in phase.get("modules", []):
            files.extend(module.get("source_files", []))
    return sorted(set(files))


def _source_files_from_project(proj_dir):
    """Collect candidate files before phases.json exists."""
    exts = LSP_REGISTRY.provider_extensions()

    files = []
    for root, dirs, names in os.walk(proj_dir):
        dirs[:] = [
            d for d in dirs
            if not d.startswith(".") and d not in {"node_modules", "__pycache__", "venv", ".venv", "fm_agent"}
        ]
        for name in names:
            if os.path.splitext(name)[1].lower() in exts:
                files.append(os.path.relpath(os.path.join(root, name), proj_dir))
    return sorted(set(files))


def _write_json(path, data):
    """Atomically write a JSON artifact."""
    tmp_path = path + ".tmp"
    with open(tmp_path, "w") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    os.replace(tmp_path, path)

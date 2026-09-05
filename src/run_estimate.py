"""Pre-run scope inventory and history-based FM-Agent run estimates."""

from __future__ import annotations

import glob
import json
import math
import os
from collections.abc import Iterable
from datetime import UTC, datetime
from pathlib import Path

from .extract import EXT_TO_LANG, extract_functions_from_file
from .file_utils import (
    _is_test_file,
    _is_under_submodules,
    _iter_project_source_files,
)

try:
    import litellm

    _MODEL_COST = litellm.model_cost
except Exception:
    _MODEL_COST = {}


SCHEMA_VERSION = 1
ESTIMATE_FILENAME = "estimate.json"
HISTORY_FILENAME = "history.jsonl"
RUN_SUMMARY_FILENAME = "run_summary.json"

ANALYSIS_STAGES = [
    {
        "number": 1,
        "name": "Code understanding & phase plan",
        "kind": "LLM",
    },
    {
        "number": 2,
        "name": "Domain-context generation",
        "kind": "LLM",
    },
    {
        "number": 3,
        "name": "Function extraction",
        "kind": "local",
    },
    {
        "number": 4,
        "name": "Function inventory",
        "kind": "local",
    },
    {
        "number": 5,
        "name": "Call graph & analysis layers",
        "kind": "local",
    },
    {
        "number": 6,
        "name": "Specification, verification & bug validation",
        "kind": "LLM",
    },
]

_PRUNED_DIR_NAMES = {"node_modules", "__pycache__", "venv", ".venv", "fm_agent"}


def _utc_now_iso() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def _parse_iso(value):
    if not value:
        return None
    if value.endswith("Z"):
        value = value[:-1] + "+00:00"
    try:
        return datetime.fromisoformat(value)
    except (TypeError, ValueError):
        return None


def _source_directory(rel_path: str) -> str:
    parent = os.path.dirname(rel_path.replace("\\", "/"))
    return parent or "."


def _compress_directories(paths: Iterable[str]) -> list[str]:
    """Keep the shallowest directories that cover all supplied paths."""
    result = []
    for path in sorted(set(paths), key=lambda item: (item.count("/"), item)):
        if path == "." or not any(
            root != "." and (path == root or path.startswith(root + "/"))
            for root in result
        ):
            result.append(path)
    return result


def _present_pruned_directories(proj_dir: str) -> list[dict]:
    """List directories deliberately not traversed by the source scanner."""
    excluded = []
    for root, dirs, _files in os.walk(proj_dir):
        kept = []
        for dirname in dirs:
            rel = os.path.relpath(os.path.join(root, dirname), proj_dir).replace(
                os.sep, "/"
            )
            if dirname.startswith(".") or dirname in _PRUNED_DIR_NAMES:
                excluded.append({"path": rel, "reason": "scanner ignored directory"})
            else:
                kept.append(dirname)
        dirs[:] = kept
    return excluded


def _count_functions(proj_dir: str, files: Iterable[str]) -> tuple[int, list[str]]:
    """Count functions with the same local fallback extractor used by FM-Agent."""
    total = 0
    uncounted = []
    for rel_path in files:
        ext = rel_path.rsplit(".", 1)[-1].lower() if "." in rel_path else ""
        language = EXT_TO_LANG.get(ext)
        if not language:
            continue
        try:
            functions = extract_functions_from_file(
                os.path.join(proj_dir, rel_path), language
            )
        except OSError:
            uncounted.append(rel_path)
            continue
        if language == "erlang" and not functions:
            # Erlang extraction is semantic/ELP-only. The fast preflight does not
            # start ELP, so make the incomplete count explicit in the manifest.
            uncounted.append(rel_path)
            continue
        total += len(functions)
    return total, uncounted


def build_scope_inventory(proj_dir: str, submodules=None) -> dict:
    """Return the deterministic source scope without invoking an LLM."""
    proj_dir = os.path.abspath(proj_dir)
    submodules = list(submodules or [])
    candidates = sorted(set(_iter_project_source_files(proj_dir)))

    included_files = []
    excluded_files = []
    excluded_directory_reasons = {}
    for rel_path in candidates:
        reason = None
        if submodules and not _is_under_submodules(rel_path, submodules):
            reason = "outside selected submodule"
        elif _is_test_file(rel_path):
            reason = "test source"

        if reason is None:
            included_files.append(rel_path)
        else:
            excluded_files.append({"path": rel_path, "reason": reason})
            excluded_directory_reasons.setdefault(
                (_source_directory(rel_path), reason), None
            )

    function_count, uncounted = _count_functions(proj_dir, included_files)
    included_directories = _compress_directories(
        _source_directory(path) for path in included_files
    )
    excluded_directories = [
        {"path": path, "reason": reason}
        for path, reason in excluded_directory_reasons
    ]
    excluded_directories.extend(_present_pruned_directories(proj_dir))
    excluded_directories = sorted(
        {
            (item["path"], item["reason"]): item
            for item in excluded_directories
        }.values(),
        key=lambda item: (item["path"].count("/"), item["path"], item["reason"]),
    )

    return {
        "submodules": submodules,
        "included_directories": included_directories,
        "excluded_directories": excluded_directories,
        "included_file_count": len(included_files),
        "excluded_file_count": len(excluded_files),
        "included_files": included_files,
        "excluded_files": excluded_files,
        "function_count": function_count,
        "function_count_is_estimate": True,
        "function_count_uncounted_files": uncounted,
    }


def _price_for(model: str | None):
    if not model:
        return None
    if model in _MODEL_COST:
        return _MODEL_COST[model]
    if "/" in model:
        bare = model.split("/", 1)[1]
        if bare in _MODEL_COST:
            return _MODEL_COST[bare]
    return None


def _usage_numbers(usage: dict) -> dict:
    usage = usage or {}
    prompt = usage.get("input_tokens")
    if prompt is None:
        prompt = usage.get("prompt_tokens", 0)
    output = usage.get("output_tokens")
    if output is None:
        output = usage.get("completion_tokens", 0)
    cache_read = usage.get("cache_read_input_tokens")
    if cache_read is None:
        cache_read = usage.get("prompt_cache_hit_tokens")
    if cache_read is None:
        cache_read = (
            (usage.get("prompt_tokens_details") or {}).get("cached_tokens")
            or (usage.get("input_tokens_details") or {}).get("cached_tokens")
            or 0
        )
    if "prompt_tokens" in usage and cache_read:
        # OpenAI-compatible usage reports prompt_tokens as total fresh + cached.
        prompt = usage.get("prompt_cache_miss_tokens", max(0, prompt - cache_read))
    cache_write = usage.get("cache_creation_input_tokens", 0)
    return {
        "input": int(prompt or 0),
        "output": int(output or 0),
        "cache_read": int(cache_read or 0),
        "cache_write": int(cache_write or 0),
    }


def _usage_cost(model: str | None, usage: dict):
    price = _price_for(model)
    if not price:
        return None
    numbers = _usage_numbers(usage)
    return (
        numbers["input"] * (price.get("input_cost_per_token") or 0)
        + numbers["output"] * (price.get("output_cost_per_token") or 0)
        + numbers["cache_read"]
        * (price.get("cache_read_input_token_cost") or 0)
        + numbers["cache_write"]
        * (price.get("cache_creation_input_token_cost") or 0)
    )


def _read_json(path: Path):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def _infer_scope_from_workdir(work_dir: Path) -> dict:
    estimate = _read_json(work_dir / ESTIMATE_FILENAME) or {}
    scope = estimate.get("scope")
    if isinstance(scope, dict):
        return scope

    functions = 0
    extracted = work_dir / "extracted_functions"
    if extracted.is_dir():
        functions = sum(
            1
            for path in extracted.rglob("*")
            if path.is_file()
            and not str(path).endswith((".spec.json", ".info.json"))
        )

    files = set()
    phases = _read_json(work_dir / "phases.json") or {}
    for phase in phases.get("phases", []):
        for module in phase.get("modules", []):
            files.update(module.get("source_files", []))
    return {
        "included_file_count": len(files),
        "function_count": functions,
    }


def summarize_completed_run(work_dir: str | Path, require_complete=True):
    """Summarize actual trace usage for one completed workspace."""
    work_dir = Path(work_dir)
    existing = _read_json(work_dir / RUN_SUMMARY_FILENAME)
    if require_complete and not (work_dir / "version.log").is_file():
        return existing if isinstance(existing, dict) else None

    events_path = work_dir / "trace" / "events.jsonl"
    if not events_path.is_file():
        return existing if isinstance(existing, dict) else None

    starts = []
    ends = []
    llm_calls = 0
    tokens = 0
    total_cost = 0.0
    cost_known = True
    model = None

    for line in events_path.read_text(encoding="utf-8", errors="replace").splitlines():
        try:
            event = json.loads(line)
        except ValueError:
            continue
        start = _parse_iso(event.get("start_time"))
        end = _parse_iso(event.get("end_time"))
        if start:
            starts.append(start)
        if end:
            ends.append(end)
        if event.get("type") != "llm_call":
            continue
        llm_calls += 1
        metadata = event.get("metadata") or {}
        usage = metadata.get("usage") or {}
        event_model = metadata.get("model")
        model = model or event_model
        numbers = _usage_numbers(usage)
        tokens += sum(numbers.values())
        cost = _usage_cost(event_model, usage)
        if cost is None and any(numbers.values()):
            cost_known = False
        elif cost is not None:
            total_cost += cost

    seen_responses = set()
    requests = {}
    for trace_path in sorted((work_dir / "trace" / "opencode").glob("*.jsonl")):
        for line in trace_path.read_text(
            encoding="utf-8", errors="replace"
        ).splitlines():
            try:
                record = json.loads(line)
            except ValueError:
                continue
            record = {
                key.removeprefix("*"): value
                for key, value in record.items()
            }
            kind = record.get("_kind")
            call_id = record.get("_id")
            key = (trace_path.name, call_id)
            if kind == "request":
                requests[key] = record
                continue
            if kind != "response" or key in seen_responses:
                continue
            usage = record.get("usage")
            if not isinstance(usage, dict):
                continue
            usage = {
                field.removeprefix("*"): value
                for field, value in usage.items()
            }
            numbers = _usage_numbers(usage)
            if not any(numbers.values()):
                continue
            seen_responses.add(key)
            llm_calls += 1
            tokens += sum(numbers.values())
            event_model = record.get("model") or requests.get(key, {}).get("model")
            model = model or event_model
            cost = _usage_cost(event_model, usage)
            if cost is None:
                cost_known = False
            else:
                total_cost += cost

    if not starts or not ends:
        return None
    scope = _infer_scope_from_workdir(work_dir)
    duration = max(0.0, (max(ends) - min(starts)).total_seconds())
    version_lines = []
    version_path = work_dir / "version.log"
    if version_path.is_file():
        version_lines = [
            line.strip()
            for line in version_path.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
    run_id = f"{version_lines[-1] if version_lines else 'unknown'}:{max(ends).isoformat()}"
    return {
        "schema_version": SCHEMA_VERSION,
        "run_id": run_id,
        "recorded_at": _utc_now_iso(),
        "included_file_count": int(scope.get("included_file_count") or 0),
        "function_count": int(scope.get("function_count") or 0),
        "duration_seconds": duration,
        "llm_calls": llm_calls,
        "tokens": tokens,
        "cost_usd": total_cost if cost_known else None,
        "model": model,
    }


def read_history(work_dir: str | Path) -> list[dict]:
    path = Path(work_dir) / HISTORY_FILENAME
    if not path.is_file():
        return []
    records = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        try:
            record = json.loads(line)
        except ValueError:
            continue
        if isinstance(record, dict):
            records.append(record)
    return _dedupe_history(records)


def _dedupe_history(records: Iterable[dict]) -> list[dict]:
    deduped = {}
    for record in records:
        run_id = record.get("run_id")
        if run_id:
            deduped[run_id] = record
    return list(deduped.values())


def write_history(work_dir: str | Path, records: Iterable[dict]) -> None:
    records = _dedupe_history(records)
    if not records:
        return
    work_dir = Path(work_dir)
    work_dir.mkdir(parents=True, exist_ok=True)
    path = work_dir / HISTORY_FILENAME
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(
        "".join(json.dumps(record, ensure_ascii=False) + "\n" for record in records),
        encoding="utf-8",
    )
    os.replace(tmp, path)


def preserve_history_before_clean(work_dir: str | Path) -> list[dict]:
    records = read_history(work_dir)
    summary = summarize_completed_run(work_dir)
    if summary:
        records.append(summary)
    return _dedupe_history(records)


def record_completed_run(work_dir: str | Path, duration_seconds=None):
    summary = summarize_completed_run(work_dir)
    if not summary:
        return None
    if duration_seconds is not None:
        summary["duration_seconds"] = max(0.0, float(duration_seconds))
    records = read_history(work_dir)
    records.append(summary)
    write_history(work_dir, records)
    path = Path(work_dir) / RUN_SUMMARY_FILENAME
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8")
    os.replace(tmp, path)
    return summary


def collect_history_samples(proj_dir: str, work_dir: str | Path) -> list[dict]:
    """Collect persisted history plus completed archived workspaces."""
    records = read_history(work_dir)
    for candidate in glob.glob(os.path.join(os.path.abspath(proj_dir), "fm_agent*")):
        candidate_path = Path(candidate)
        if not candidate_path.is_dir() or candidate_path.name == "fm_agent_estimate":
            continue
        records.extend(read_history(candidate_path))
        summary = summarize_completed_run(candidate_path)
        if summary:
            records.append(summary)
    return _dedupe_history(records)


def _scale_factor(target_scope: dict, sample: dict) -> float:
    target_functions = int(target_scope.get("function_count") or 0)
    sample_functions = int(sample.get("function_count") or 0)
    if target_functions > 0 and sample_functions > 0:
        return max(0.1, min(10.0, target_functions / sample_functions))
    target_files = int(target_scope.get("included_file_count") or 0)
    sample_files = int(sample.get("included_file_count") or 0)
    if target_files > 0 and sample_files > 0:
        return max(0.1, min(10.0, target_files / sample_files))
    return 1.0


def _historical_range(values: list[float], integer=False):
    values = sorted(value for value in values if value is not None and value >= 0)
    if not values:
        return None
    if len(values) == 1:
        low, high = values[0] * 0.75, values[0] * 1.25
    else:
        low, high = values[0] * 0.9, values[-1] * 1.1
    # Prevent representational noise (e.g. 3000 * 1.1 becoming
    # 3300.0000000000005) from widening integer ranges by one.
    low, high = round(low, 9), round(high, 9)
    if integer:
        return {"low": max(0, math.floor(low)), "high": max(1, math.ceil(high))}
    return {"low": max(0.0, low), "high": max(low, high)}


def estimate_from_history(scope: dict, samples: Iterable[dict]) -> dict:
    samples = list(samples)
    scaled = []
    for sample in samples:
        factor = _scale_factor(scope, sample)
        scaled.append(
            {
                "duration_seconds": (
                    sample.get("duration_seconds") * factor
                    if sample.get("duration_seconds") is not None
                    else None
                ),
                "llm_calls": (
                    sample.get("llm_calls") * factor
                    if sample.get("llm_calls") is not None
                    else None
                ),
                "tokens": (
                    sample.get("tokens") * factor
                    if sample.get("tokens") is not None
                    else None
                ),
                "cost_usd": (
                    sample.get("cost_usd") * factor
                    if sample.get("cost_usd") is not None
                    else None
                ),
            }
        )

    return {
        "label": "estimate",
        "method": (
            "historical completed runs scaled by function count "
            "(file count fallback); range is the observed envelope with 10% margin"
        ),
        "based_on_runs": len(samples),
        "duration_seconds": _historical_range(
            [item["duration_seconds"] for item in scaled]
        ),
        "llm_calls": _historical_range(
            [item["llm_calls"] for item in scaled], integer=True
        ),
        "tokens": _historical_range(
            [item["tokens"] for item in scaled], integer=True
        ),
        "cost_usd": _historical_range(
            [item["cost_usd"] for item in scaled]
        ),
    }


def build_preflight_estimate(proj_dir: str, work_dir: str | Path, submodules=None):
    scope = build_scope_inventory(proj_dir, submodules=submodules)
    history = collect_history_samples(proj_dir, work_dir)
    return {
        "schema_version": SCHEMA_VERSION,
        "generated_at": _utc_now_iso(),
        "project": os.path.abspath(proj_dir),
        "scope": scope,
        "analysis_stages": ANALYSIS_STAGES,
        "estimate": estimate_from_history(scope, history),
    }


def write_preflight_estimate(
    proj_dir: str, work_dir: str | Path, submodules=None
) -> dict:
    estimate = build_preflight_estimate(proj_dir, work_dir, submodules=submodules)
    work_dir = Path(work_dir)
    work_dir.mkdir(parents=True, exist_ok=True)
    path = work_dir / ESTIMATE_FILENAME
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(estimate, indent=2, ensure_ascii=False), encoding="utf-8")
    os.replace(tmp, path)
    return estimate

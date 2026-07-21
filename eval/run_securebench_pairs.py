from __future__ import annotations

import argparse, ast, hashlib, json, os, shutil, subprocess, sys, tempfile; from dataclasses import dataclass; from pathlib import Path; from typing import Literal, TypedDict, Union; from urllib.parse import urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parent.parent)); from eval import normalize; from src.extract import EXT_TO_LANG, extract_functions_from_file; from src.plugins import registry

MANIFEST_SCHEMA_VERSION = 1; OUTPUT_SCHEMA_VERSION = "securebench-pairs.v4"; PATCH_MARKER_SCHEMA = 1; FAKE_RESULTS_ENV = "SECUREBENCH_FAKE_PLUGIN_RESULTS"; PROJECT_ROOT = Path(__file__).resolve().parent.parent; Json = Union[None, bool, int, float, str, list["Json"], dict[str, "Json"]]


class ManifestError(Exception): pass
class StageRootError(Exception): pass
class FindingJson(TypedDict, total=False): data: dict[str, Json]; message: str
class ResultJson(TypedDict, total=False): verdict: str; rel: str; function: str; name: str; status: str; findings: list[FindingJson]
class SideJson(TypedDict): passed: bool; errors: list[str]; verdicts: list[str]; cwes: list[str]; locus_results: list[ResultJson]; out_of_locus_results: list[ResultJson]; binding: str; stage_digest: str; analyzer_sha256: str; model: str; api_base_host: str; fake_mode: bool
class CaseRequired(TypedDict): case_id: str; cve: str; plugin: str; expected_cwe: str
class CaseJson(CaseRequired, total=False): passed: bool; vulnerable: SideJson; fixed: SideJson
class OutputRequired(TypedDict): schema_version: str; binding: str; analyzer_sha256: str; model: str; api_base_host: str; fake_mode: bool; cases: list[CaseJson]
class OutputJson(OutputRequired, total=False): passed: bool


@dataclass(frozen=True)
class Locus: path: str; function: str; fixed_expectation: Literal["present", "absent"]; qualified_name: str | None
@dataclass(frozen=True)
class Case: case_id: str; cve: str; plugin: str; expected_cwe: str; minimal: Path; patch: Path; loci: tuple[Locus, ...]; manifest_digest: str
@dataclass(frozen=True)
class RunConfig: manifest: Path; plugin: str | None; case_ids: tuple[str, ...]; run_all: bool; out: Path; stage_root: Path; clean: bool


def _load_json(path: Path) -> Json: return json.loads(path.read_text())


def _as_map(value: Json, label: str) -> dict[str, Json]:
    if not isinstance(value, dict): raise ManifestError(f"{label} must be an object")
    return value


def _need_str(row: dict[str, Json], key: str) -> str:
    if not isinstance(value := row.get(key), str) or not value: raise ManifestError(f"case missing string {key}")
    return value


def _safe_path(base: Path, raw: str, label: str) -> Path:
    relative, path = Path(raw), (base / raw).resolve()
    if relative.is_absolute() or ".." in relative.parts or base.resolve() not in (path, *path.parents): raise ManifestError(f"invalid or escaping {label}: {raw}")
    return path


def _parse_loci(row: dict[str, Json]) -> tuple[Locus, ...]:
    if not isinstance(values := row.get("loci"), list) or not values: raise ManifestError("case must contain at least one locus")
    loci: list[Locus] = []; seen: set[tuple[str, str]] = set()
    for value in values:
        locus = _as_map(value, "locus"); path, function = _need_str(locus, "path"), _need_str(locus, "function")
        _safe_path(Path("."), path, "locus path"); expectation, qualified = locus.get("fixed_expectation", "present"), locus.get("qualified_name")
        if expectation not in ("present", "absent") or qualified is not None and (not isinstance(qualified, str) or not qualified or Path(path).suffix != ".py") or (path, function) in seen: raise ManifestError(f"invalid or duplicate locus: {path}::{function}")
        seen.add((path, function)); loci.append(Locus(path, function, expectation, qualified))
    return tuple(loci)


def _parse_case(root: Path, row: dict[str, Json]) -> Case:
    cve, plugin = _need_str(row, "cve"), _need_str(row, "plugin"); case_root = _safe_path(root, _need_str(row, "case_dir"), "case_dir"); case = Case(cve, cve, plugin, _need_str(row, "cwe"), case_root / "minimal", case_root / "patch/fix.patch", _parse_loci(row), hashlib.sha256(json.dumps(row, sort_keys=True).encode()).hexdigest())
    if not registry.has_plugin(plugin) or not case.minimal.is_dir() or not case.patch.is_file(): raise ManifestError(f"unknown plugin or missing case artifacts for {cve}")
    return case


def load_manifest(path: Path) -> tuple[Case, ...]:
    raw = _as_map(_load_json(path), "manifest"); rows = raw.get("cases")
    if raw.get("schema_version") != 1 or not isinstance(rows, list) or not rows: raise ManifestError("manifest schema_version must be 1; cases must be non-empty")
    cases = tuple(_parse_case(path.resolve().parent.parent, _as_map(row, "case")) for row in rows); cves = [case.cve for case in cases]
    if len(cves) != len(set(cves)): raise ManifestError("duplicate case/CVE")
    return cases


def _tree_digest(root: Path) -> str: return hashlib.sha256(b"".join(b"D" + rel if path.is_dir() else b"F" + rel + b"\0" + path.read_bytes() for path in sorted(root.rglob("*")) for rel in (path.relative_to(root).as_posix().encode(),))).hexdigest()


def _inventory(root: Path, names: tuple[str, ...] | None = None) -> dict[str, str]: paths = sorted(root / name for name in names) if names is not None else sorted(root.rglob("*")); return {path.relative_to(root).as_posix(): hashlib.sha256(b"L" + os.readlink(path).encode() if path.is_symlink() else b"F" + path.read_bytes()).hexdigest() for path in paths if path.is_file() or path.is_symlink()}


def _case_binding(case: Case, side: str, provenance: dict[str, Json]) -> str: spec = {"schema": OUTPUT_SCHEMA_VERSION, "side": side, "manifest": case.manifest_digest, "cve": case.cve, "plugin": case.plugin, "cwe": case.expected_cwe, "loci": [(x.path, x.function, x.fixed_expectation, x.qualified_name) for x in case.loci], "minimal": _tree_digest(case.minimal), "provenance": provenance}; return hashlib.sha256(json.dumps(spec, sort_keys=True).encode() + case.patch.read_bytes()).hexdigest()


def _analyzer_paths(cases: tuple[Case, ...]) -> tuple[Path, ...]:
    paths = {Path(__file__).resolve(), PROJECT_ROOT / "config.py", PROJECT_ROOT / "src/llm_client.py", PROJECT_ROOT / "src/extract.py", PROJECT_ROOT / "eval/normalize.py", PROJECT_ROOT / "src/plugins/driver.py", PROJECT_ROOT / "src/plugins/base.py", PROJECT_ROOT / "src/plugins/callgraph.py", PROJECT_ROOT / "src/plugins/registry.py"}
    for plugin in {case.plugin for case in cases}:
        module = str(registry.get_manifest(plugin)["module"]); paths.add(PROJECT_ROOT / (module.replace(".", "/") + ".py")); paths.update(PROJECT_ROOT / f"src/{plugin}_{suffix}.py" for suffix in ("validation", "reasoner", "prompts"))
    return tuple(sorted(paths))


def _analyzer_sha256(cases: tuple[Case, ...]) -> str:
    digest = hashlib.sha256()
    for path in _analyzer_paths(cases):
        if not path.is_file(): raise ManifestError(f"missing analyzer file: {path.name}")
        resolved = path.resolve(); label = resolved.relative_to(PROJECT_ROOT).as_posix() if PROJECT_ROOT in resolved.parents else resolved.name; digest.update(label.encode() + b"\0" + resolved.read_bytes())
    return digest.hexdigest()


def _model_inputs() -> dict[str, Json]:
    try: from config import LLM_MODEL as config_model, LLM_API_BASE_URL as config_base
    except ImportError: config_model, config_base = "anthropic/claude-sonnet-4.6", "https://openrouter.ai/api/v1"
    model, base = os.environ.get("LLM_MODEL", config_model), os.environ.get("LLM_API_BASE_URL", config_base)
    if not (host := urlsplit(base).hostname): raise ManifestError("LLM_API_BASE_URL must contain a host")
    return {"model": model, "api_base_host": host.lower(), "fake_mode": bool(os.environ.get(FAKE_RESULTS_ENV))}


def _provenance(cases: tuple[Case, ...]) -> dict[str, Json]: return {**_model_inputs(), "analyzer_sha256": _analyzer_sha256(cases)}


def _run_binding(cases: tuple[Case, ...], provenance: dict[str, Json]) -> str: return hashlib.sha256("".join(_case_binding(case, "selected", provenance) for case in cases).encode()).hexdigest()


def _parse_args(argv: list[str] | None) -> RunConfig:
    parser = argparse.ArgumentParser(description="Run SecureBench vulnerable/fixed plugin pairs")
    for name in ("--manifest", "--out", "--stage-root"): parser.add_argument(name, required=True)
    parser.add_argument("--plugin", choices=registry.plugin_names()); parser.add_argument("--case", action="append", default=[])
    parser.add_argument("--all", action="store_true"); parser.add_argument("--clean", action="store_true"); args = parser.parse_args(argv)
    if not args.all and not args.case: parser.error("select --all or at least one --case")
    return RunConfig(Path(args.manifest), args.plugin, tuple(args.case), bool(args.all), Path(args.out), Path(args.stage_root), bool(args.clean))


def _safe_stage_root(path: Path) -> Path:
    if ".." in path.parts: raise StageRootError("stage root must not contain '..'")
    resolved = path.resolve()
    if resolved in (Path("/"), Path.cwd().resolve()): raise StageRootError("stage root must be a dedicated directory")
    return resolved


def _atomic_write(path: Path, data: OutputJson) -> None: path.parent.mkdir(parents=True, exist_ok=True); tmp = path.with_suffix(path.suffix + ".tmp"); tmp.write_text(json.dumps(data, indent=2, sort_keys=True)); os.replace(tmp, path)


def _parse_result(value: Json) -> ResultJson | None:
    if not isinstance(value, dict) or not isinstance(value.get("verdict"), str): return None
    result: ResultJson = {"verdict": value["verdict"]}; result.update({key: item for key in ("rel", "function", "name", "status") if isinstance(item := value.get(key), str)})
    values = value.get("findings", []); findings: list[FindingJson] = [{"data": raw["data"]} for raw in values if isinstance(raw, dict) and isinstance(raw.get("data"), dict)] if isinstance(values, list) else []
    result["findings"] = findings; return result


def _parse_side(value: Json) -> SideJson | None:
    if not isinstance(value, dict) or not isinstance(value.get("passed"), bool): return None
    strings = [value.get(key) for key in ("errors", "verdicts", "cwes")]; ids = [value.get(key) for key in ("binding", "stage_digest", "analyzer_sha256", "model", "api_base_host")]
    if not isinstance(value.get("fake_mode"), bool) or not all(isinstance(x, str) for x in ids) or not all(isinstance(xs, list) and all(isinstance(x, str) for x in xs) for xs in strings): return None
    parsed: list[list[ResultJson]] = []
    for key in ("locus_results", "out_of_locus_results"):
        if not isinstance(rows := value.get(key), list) or any((item := _parse_result(row)) is None for row in rows): return None
        parsed.append([item for row in rows if (item := _parse_result(row)) is not None])
    return {"passed": value["passed"], "errors": [x for x in strings[0] if isinstance(x, str)], "verdicts": [x for x in strings[1] if isinstance(x, str)], "cwes": [x for x in strings[2] if isinstance(x, str)], "locus_results": parsed[0], "out_of_locus_results": parsed[1], "binding": ids[0], "stage_digest": ids[1], "analyzer_sha256": ids[2], "model": ids[3], "api_base_host": ids[4], "fake_mode": value["fake_mode"]}


def _load_checkpoint(path: Path, clean: bool, binding: str, provenance: dict[str, Json]) -> tuple[OutputJson, bool]:
    fresh: OutputJson = {"schema_version": OUTPUT_SCHEMA_VERSION, "binding": binding, "analyzer_sha256": str(provenance["analyzer_sha256"]), "model": str(provenance["model"]), "api_base_host": str(provenance["api_base_host"]), "fake_mode": bool(provenance["fake_mode"]), "cases": []}
    if clean or not path.exists(): return fresh, False
    raw = _as_map(_load_json(path), "checkpoint")
    if any(raw.get(key) != fresh[key] for key in ("schema_version", "binding", "analyzer_sha256", "model", "api_base_host", "fake_mode")) or not isinstance(raw.get("cases"), list): raise ManifestError("checkpoint schema or content binding mismatch")
    for value in raw["cases"]:
        row = _as_map(value, "checkpoint case"); fields = [_need_str(row, key) for key in ("case_id", "cve", "plugin", "expected_cwe")]; record: CaseJson = {"case_id": fields[0], "cve": fields[1], "plugin": fields[2], "expected_cwe": fields[3]}
        for side in ("vulnerable", "fixed"):
            if row.get(side) is not None:
                if (parsed := _parse_side(row[side])) is None: raise ManifestError(f"malformed checkpoint {fields[0]} {side}")
                record[side] = parsed
        fresh["cases"].append(record)
    return fresh, True


def _git_apply(patch: Path, root: Path, numstat: bool = False) -> bytes: env = {"PATH": os.environ.get("PATH", ""), "GIT_CEILING_DIRECTORIES": str(root.resolve()), "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull}; args = ["git", "apply", "--no-index", *(["--numstat", "-z"] if numstat else []), str(patch)]; return subprocess.run(args, cwd=str(root), env=env, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30).stdout


def _patch_paths(case: Case) -> tuple[Path, ...]:
    with tempfile.TemporaryDirectory() as tmp: records = iter(_git_apply(case.patch, Path(tmp), True).split(b"\0"))
    paths: list[Path] = []
    for record in records:
        if not record: continue
        if len(fields := record.split(b"\t", 2)) != 3: raise ManifestError("malformed patch path metadata")
        names = (fields[2],) if fields[2] else (next(records, b""), next(records, b""))
        if any(not name for name in names): raise ManifestError("malformed patch path metadata")
        paths.extend(_safe_path(case.minimal, name.decode("utf-8"), "patch path").relative_to(case.minimal.resolve()) for name in names)
    if not paths or len(paths) != len(set(paths)): raise ManifestError("patch must declare unique changed paths")
    return tuple(paths)


def _apply_verified(case: Case, stage: Path, clean: bool) -> None:
    paths = _patch_paths(case); minimal = _inventory(case.minimal); patch_sha = hashlib.sha256(case.patch.read_bytes()).hexdigest()
    with tempfile.TemporaryDirectory() as tmp:
        candidate, reference = Path(tmp) / "candidate", Path(tmp) / "reference"; shutil.copytree(case.minimal, candidate); shutil.copytree(case.minimal, reference)
        _git_apply(case.patch, candidate); _git_apply(case.patch, reference); fixed, repeated = _inventory(candidate), _inventory(reference)
        if fixed == minimal or fixed != repeated or any(minimal.get(path.as_posix()) == fixed.get(path.as_posix()) for path in paths): raise ManifestError("patch made zero or inconsistent tree changes")
        names = tuple(sorted(minimal.keys() | fixed.keys())); expected: dict[str, Json] = {"schema_version": PATCH_MARKER_SCHEMA, "patch_sha256": patch_sha, "minimal_sha256": hashlib.sha256(json.dumps(minimal, sort_keys=True, separators=(",", ":")).encode()).hexdigest(), "minimal_inventory": minimal, "fixed_inventory": fixed}; marker = stage / ".securebench_patch_applied"
        data: dict[str, Json] = {}
        if not clean and marker.is_file():
            try: data = _as_map(_load_json(marker), "patch marker")
            except (OSError, json.JSONDecodeError, ManifestError): data = {}
        if not clean and stage.is_dir() and _inventory(stage, names) == fixed:
            if data == expected: return
            if set(data) == {"patch_sha256", "tree_digest"} and data.get("patch_sha256") == patch_sha: marker.write_text(json.dumps(expected, sort_keys=True)); return
        shutil.rmtree(stage) if stage.exists() else None; shutil.copytree(candidate, stage)
        if _inventory(stage, names) != fixed: raise ManifestError("patched stage differs from independent tree")
        marker.write_text(json.dumps(expected, sort_keys=True))


def _prepare_stage(case: Case, stage: Path, side: str, clean: bool) -> None:
    if side == "fixed": _apply_verified(case, stage, clean)
    else:
        if clean and stage.exists(): shutil.rmtree(stage)
        if not stage.exists(): shutil.copytree(case.minimal, stage)


def _result_dir(stage: Path, plugin: str) -> Path: data = registry.get_manifest(plugin); return stage / data.get("work_subdir", f"fm_agent_{plugin}") / data.get("results_subdir", "results")


def _fake_run_if_requested(stage: Path, plugin: str, side: str) -> bool:
    raw = os.environ.get(FAKE_RESULTS_ENV)
    if not raw: return False
    data: Json = json.loads(raw); values = data.get(side, []) if isinstance(data, dict) else []; rows = values if isinstance(values, list) else []; out = _result_dir(stage, plugin); out.mkdir(parents=True, exist_ok=True)
    for index, row in enumerate(rows): (out / f"result_{index}.json").write_text(json.dumps(row))
    (out / "summary.json").write_text(json.dumps({"total": len(rows)})); return True


def _read_results(root: Path) -> tuple[list[ResultJson], list[str]]:
    if not root.is_dir(): return [], ["missing results directory"]
    results: list[ResultJson] = []; errors: list[str] = []
    for path in sorted(root.rglob("*.json")):
        if path.name == "summary.json": continue
        try: item = _parse_result(_load_json(path))
        except (OSError, json.JSONDecodeError) as exc: errors.append(f"parse error {path}: {exc}"); continue
        errors.append(f"malformed result {path}") if item is None else results.append(item)
    return results, errors


Proof = tuple[str, dict[str, str]] | None


def _python_ids(source: Path, tokens: tuple[str, ...]) -> dict[str, str] | None:
    raw: list[tuple[str, str]] = []
    def walk(node: ast.AST, scope: tuple[str, ...]) -> None:
        if isinstance(node, ast.ClassDef): [walk(child, (*scope, node.name)) for child in node.body]
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)): raw.append((node.name, ".".join((*scope, node.name))))
        else: [walk(child, scope) for child in ast.iter_child_nodes(node)]
    try: walk(ast.parse(source.read_text()), ())
    except SyntaxError: return None
    names = [name for name, _ in raw]; pairs = [(name if (count := names[:index].count(name)) == 0 else f"{name}_{count}", qualified) for index, (name, qualified) in enumerate(raw)]
    return dict(pairs) if len({token for token, _ in pairs}) == len(pairs) and tuple(token for token, _ in pairs) == tokens else None


def _proof(stage: Path, relative: str) -> Proof:
    if stage.resolve() not in (source := (stage / relative).resolve(), *source.parents): return None
    if not source.exists(): return "", {}
    if (language := EXT_TO_LANG.get(source.suffix.lstrip("."))) is None or not source.is_file(): return None
    tokens = tuple(name for name, _ in extract_functions_from_file(str(source), language)); identities = _python_ids(source, tokens) if language == "python" else {token: token for token in tokens}
    return None if identities is None else (language, identities)


def _proofs(stage: Path, case: Case) -> dict[str, Proof]: return {locus.path: _proof(stage, locus.path) for locus in case.loci}


def _identity(proof: Proof, locus: Locus) -> str | None:
    if proof is None: return None
    language, identities = proof; actual = identities.get(locus.function)
    if language != "python": return locus.function if locus.qualified_name is None and locus.function in identities else None
    return actual if actual == locus.qualified_name else None if locus.qualified_name is not None else actual if actual is not None and sum(name.rsplit(".", 1)[-1] == actual.rsplit(".", 1)[-1] for name in identities.values()) == 1 else None


def _source_errors(case: Case, side: str, stage: Path, vulnerable: Path) -> list[str]:
    current, before, errors = _proofs(stage, case), _proofs(vulnerable, case), []
    for locus in case.loci:
        label = f"{locus.path}::{locus.function}"; old, now = _identity(before[locus.path], locus), _identity(current[locus.path], locus)
        checks = ((old is None, f"noncanonical vulnerable locus {label}"), (side == "fixed" and locus.fixed_expectation == "present" and now is None, f"noncanonical fixed locus {label}"), (side == "fixed" and locus.fixed_expectation == "absent" and (old is None or current[locus.path] is None or old in current[locus.path][1].values()), f"function still present {label}")); errors.extend(message for failed, message in checks if failed)
    return errors


def _cwes(items: list[ResultJson]) -> set[str]: return {cwe for item in items for finding in item.get("findings", []) if (cwe := normalize._canon_cwe(finding.get("data", {}).get("cwe")))}


def _classify(case: Case, side: str, stage: Path, vulnerable: Path, results: list[ResultJson], errors: list[str], provenance: dict[str, Json]) -> SideJson:
    errors = [*_source_errors(case, side, stage, vulnerable), *errors]; expected = {(x.path, x.function): x for x in case.loci}; grouped = {key: [] for key in expected}; outsiders: list[ResultJson] = []
    for result in results:
        key = result.get("rel", ""), result.get("function", result.get("name", "")); (grouped[key] if key in grouped else outsiders).append(result)
    vocab = registry.get_manifest(case.plugin)["verdicts"]; positive, review, negative = set(vocab.get("positive", [])), set(vocab.get("review", [])), set(vocab.get("negative", []))
    for key, locus in expected.items():
        items, label = grouped[key], f"{locus.path}::{locus.function}"; required = side == "vulnerable" or locus.fixed_expectation == "present"
        errors.extend(message for failed, message in ((required and not items, f"missing locus {label}"), (len(items) > 1, f"ambiguous locus {label}")) if failed)
        for item in items:
            verdict, status = item["verdict"], item.get("status", "ok")
            checks = ((status != "ok", f"status {status}"), (verdict in review or verdict == "ERROR" or verdict not in positive | negative, f"failure verdict {verdict}"), (side == "vulnerable" and (verdict not in positive or not normalize.cwe_matches(case.expected_cwe, _cwes([item]))), f"locus {label} lacks positive expected CWE family {case.expected_cwe}"), (side == "fixed" and locus.fixed_expectation == "present" and verdict not in negative, f"locus {label} is not negative"), (side == "fixed" and locus.fixed_expectation == "absent" and verdict in positive, f"absent locus {label} has positive result")); errors.extend(message for failed, message in checks if failed)
    loci = [item for key in expected for item in grouped[key]]
    return {"passed": not errors, "errors": errors, "verdicts": [x["verdict"] for x in loci], "cwes": sorted(_cwes(loci)), "locus_results": loci, "out_of_locus_results": outsiders, "binding": _case_binding(case, side, provenance), "stage_digest": _tree_digest(stage), "analyzer_sha256": str(provenance["analyzer_sha256"]), "model": str(provenance["model"]), "api_base_host": str(provenance["api_base_host"]), "fake_mode": bool(provenance["fake_mode"])}


def _invoke_plugin(case: Case, stage: Path) -> None: from src.plugins.driver import run_plugin; data = registry.get_manifest(case.plugin); run_plugin(registry.load_plugin_class(case.plugin)(), str(stage), work_subdir=data.get("work_subdir"), results_subdir=data.get("results_subdir", "results"), verbose=False)


def _run_side(case: Case, side: str, config: RunConfig, root: Path, provenance: dict[str, Json]) -> SideJson:
    stage, vulnerable = (root / f"{case.case_id}-{side}").resolve(), (root / f"{case.case_id}-vulnerable").resolve()
    if root not in (stage, *stage.parents): raise StageRootError(f"stage escapes stage root: {stage}")
    _prepare_stage(case, stage, side, config.clean); error = None
    try:
        if not _fake_run_if_requested(stage, case.plugin, side): _invoke_plugin(case, stage)
    except (OSError, RuntimeError, ValueError, TypeError, KeyError, subprocess.SubprocessError, json.JSONDecodeError) as exc: error = f"driver exception {type(exc).__name__}: {exc}"
    results, errors = _read_results(_result_dir(stage, case.plugin)); errors.extend([error] if error else []); return _classify(case, side, stage, vulnerable, results, errors, provenance)


def _select(cases: tuple[Case, ...], config: RunConfig) -> tuple[Case, ...]:
    selected = [case for case in cases if config.run_all or case.case_id in config.case_ids]
    if config.plugin: selected = [case for case in selected if case.plugin == config.plugin]
    missing = set(config.case_ids) - {case.case_id for case in selected}
    if missing or not selected: raise ManifestError("selector matched zero cases" if not selected else f"unknown or filtered case selector: {', '.join(sorted(missing))}")
    return tuple(selected)


def _record(output: OutputJson, case: Case) -> CaseJson:
    rows = [row for row in output["cases"] if row["case_id"] == case.case_id]
    if len(rows) > 1: raise ManifestError(f"ambiguous checkpoint case {case.case_id}")
    if not rows: row: CaseJson = {"case_id": case.case_id, "cve": case.cve, "plugin": case.plugin, "expected_cwe": case.expected_cwe}; output["cases"].append(row); return row
    row = rows[0]
    if (row["cve"], row["plugin"], row["expected_cwe"]) != (case.cve, case.plugin, case.expected_cwe): raise ManifestError(f"checkpoint metadata mismatch {case.case_id}")
    return row


def _resume(case: Case, side: str, stored: SideJson, root: Path, provenance: dict[str, Json]) -> SideJson:
    stage, vulnerable = root / f"{case.case_id}-{side}", root / f"{case.case_id}-vulnerable"
    if (stored["analyzer_sha256"], stored["model"], stored["api_base_host"], stored["fake_mode"]) != (str(provenance["analyzer_sha256"]), str(provenance["model"]), str(provenance["api_base_host"]), bool(provenance["fake_mode"])) or stored["binding"] != _case_binding(case, side, provenance) or not stage.is_dir() or stored["stage_digest"] != _tree_digest(stage): raise ManifestError(f"stale checkpoint {case.case_id} {side}")
    saved = [*stored["locus_results"], *stored["out_of_locus_results"]]; disk, errors = _read_results(_result_dir(stage, case.plugin))
    if errors or sorted(json.dumps(x, sort_keys=True) for x in saved) != sorted(json.dumps(x, sort_keys=True) for x in disk): raise ManifestError(f"checkpoint result content mismatch {case.case_id} {side}")
    current = _classify(case, side, stage, vulnerable, saved, [], provenance)
    if not current["passed"] or not stored["passed"]: raise ManifestError(f"invalid checkpoint results {case.case_id} {side}")
    return current


def run(config: RunConfig) -> OutputJson:
    cases = _select(load_manifest(config.manifest), config); root = _safe_stage_root(config.stage_root); root.mkdir(parents=True, exist_ok=True); provenance = _provenance(cases); binding = _run_binding(cases, provenance)
    output, existed = _load_checkpoint(config.out, config.clean, binding, provenance)
    if existed and {row["case_id"] for row in output["cases"]} != {case.case_id for case in cases}: raise ManifestError("checkpoint selected cases mismatch")
    for case in cases:
        record = _record(output, case)
        for side in ("vulnerable", "fixed"):
            stored = record.get(side)
            record[side] = _resume(case, side, stored, root, provenance) if stored is not None else _run_side(case, side, config, root, provenance)
            record["passed"] = bool(record.get("vulnerable") and record["vulnerable"]["passed"]) and bool(record.get("fixed") and record["fixed"]["passed"]); _atomic_write(config.out, output)
    output["passed"] = all(row.get("passed", False) for row in output["cases"]); _atomic_write(config.out, output); return output


def main(argv: list[str] | None = None) -> int:
    try: result = run(_parse_args(argv))
    except (ManifestError, StageRootError, OSError, UnicodeError, subprocess.SubprocessError, json.JSONDecodeError) as exc: print(f"securebench-pairs: {exc}", file=sys.stderr); return 2
    print(json.dumps({"passed": result["passed"], "cases": len(result["cases"])})); return 0 if result["passed"] else 1


if __name__ == "__main__": raise SystemExit(main())

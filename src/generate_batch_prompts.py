"""Generate per-layer spec batch prompts from topdown layer metadata."""

import argparse
import json
import os
from pathlib import Path
from typing import Dict, List, Optional, Tuple

try:
    # When imported as part of the src package (e.g. incremental_reasoner).
    from .domain_knowledge import list_staged_domain_knowledge_relpaths
    from .language_mapping import extension_language_map
    from .specification import BatchPromptContext, SOFTWARE_PROFILE, SpecificationProfile
except ImportError:
    # When run directly from the source tree, package modules sit beside this script.
    from language_mapping import extension_language_map
    from specification import BatchPromptContext, SOFTWARE_PROFILE, SpecificationProfile

    def list_staged_domain_knowledge_relpaths(work_dir, prefix="fm_agent"):
        knowledge_dir = Path(work_dir) / "spec_prompts" / "domain_context" / "user_knowledge"
        if not knowledge_dir.is_dir():
            return []
        relpaths = []
        for path in knowledge_dir.rglob("*"):
            if not path.is_file() or path.name == "manifest.json":
                continue
            if path.suffix.lower() not in {".md", ".markdown"}:
                continue
            rel_to_work = path.relative_to(work_dir).as_posix()
            relpaths.append(f"{prefix.rstrip('/')}/{rel_to_work}")
        return sorted(relpaths)


COMMENT_PREFIX_BY_LANG = {
    "c": "//",
    "cpp": "//",
    "cxx": "//",
    "cc": "//",
    "chisel": "//",
    "verilog": "//",
    "java": "//",
    "go": "//",
    "rust": "//",
    "javascript": "//",
    "js": "//",
    "typescript": "//",
    "ts": "//",
    "python": "#",
    "py": "#",
    "ruby": "#",
    "rb": "#",
    "shell": "#",
    "bash": "#",
    "sh": "#",
    "sql": "--",
    "erlang": "%",
    "prolog": "%",
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Generate spec batch prompts for one phase/layer range.")
    parser.add_argument("--phase", type=int, required=True, help="Phase number, e.g. 3")
    parser.add_argument("--layers", required=True, help="Layer index or inclusive range, e.g. 0 or 0-5")
    parser.add_argument("--batch-size", type=int, default=2, help="Units per prompt file")
    parser.add_argument("--output-dir", default=None, help="Output directory for batch prompt files")
    parser.add_argument("--dry-run", action="store_true", help="Show plan without writing files")
    parser.add_argument(
        "--resume",
        action="store_true",
        help="Skip units whose active Profile artifacts are ready when building batches",
    )
    return parser.parse_args()


def parse_layers_spec(layers_spec: str) -> Tuple[int, int]:
    text = layers_spec.strip()
    if "-" not in text:
        idx = int(text)
        return idx, idx
    left, right = text.split("-", 1)
    start = int(left.strip())
    end = int(right.strip())
    if start > end:
        raise ValueError("invalid --layers range: start > end")
    return start, end


def _spec_json_path(filepath: Path, specification: SpecificationProfile = SOFTWARE_PROFILE) -> Path:
    """Return the spec sidecar next to one extracted function file."""
    return specification.artifact_paths(filepath).self_spec


def _info_json_path(filepath: Path, specification: SpecificationProfile = SOFTWARE_PROFILE) -> Path:
    """Return the info sidecar next to one extracted function file."""
    return specification.artifact_paths(filepath).dependency_info


def extract_spec_block(filepath: Path, specification: SpecificationProfile = SOFTWARE_PROFILE) -> Optional[str]:
    """Read .spec.json and rebuild reasoner-facing spec text."""
    spec_path = _spec_json_path(filepath, specification)

    try:
        with spec_path.open("r", encoding="utf-8") as file:
            spec = json.load(file)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return None

    if not isinstance(spec, dict):
        return None

    return (
        f"{spec.get('signature', '')}\n\n"
        f"Pre-condition:\n{spec.get('pre_condition', '')}\n\n"
        f"Post-condition:\n{spec.get('post_condition', '')}"
    )


def extract_info_block(filepath: Path, specification: SpecificationProfile = SOFTWARE_PROFILE) -> Optional[dict]:
    """Read the adjacent .info.json object when it is usable."""
    info_path = _info_json_path(filepath, specification)

    try:
        with info_path.open("r", encoding="utf-8") as file:
            info = json.load(file)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return None

    return info if isinstance(info, dict) else None


def chunked(items: List[dict], size: int) -> List[List[dict]]:
    return [items[i : i + size] for i in range(0, len(items), size)]


def _artifact_eligible(function: dict) -> bool:
    """Return whether a topdown unit should receive standalone artifacts.

    This is an opt-in metadata contract. Existing software topdown files do
    not contain the field and retain the historical behavior. Hardware
    plugins may mark Bundle/trait declarations as context-only while keeping
    them in the dependency graph used to render prompts.
    """
    return function.get("artifact_eligible", True) is not False


def expected_dependencies_for_unit(function: dict) -> tuple[str, ...]:
    """Return normalized direct dependencies from one top-down unit."""
    raw_dependencies = function.get("all_callees", ())
    if not isinstance(raw_dependencies, (list, tuple, set)):
        return ()
    return tuple(sorted({
        dependency
        for dependency in raw_dependencies
        if isinstance(dependency, str) and dependency
    }))


def _canonical_path(path) -> str:
    """Return a stable absolute key for top-down and artifact paths."""
    return os.path.normcase(os.path.realpath(os.fspath(path)))


def build_expected_dependencies_by_file(
    layers_data: dict,
    work_dir: Path,
) -> dict[str, tuple[str, ...]]:
    """Build extracted-unit path -> merged direct dependencies."""
    work_dir = Path(work_dir)
    work_prefix = f"{work_dir.name}/"
    expected_by_file: dict[str, tuple[str, ...]] = {}
    for layer in layers_data.get("layers", []):
        if not isinstance(layer, dict):
            continue
        for unit in layer.get("functions", []):
            if not isinstance(unit, dict):
                continue
            relative_file = unit.get("file")
            if not isinstance(relative_file, str) or not relative_file:
                continue
            relative_file = relative_file.replace("\\", "/")
            if relative_file.startswith(work_prefix):
                relative_file = relative_file[len(work_prefix):]
            unit_path = Path(relative_file)
            if not unit_path.is_absolute():
                unit_path = work_dir / unit_path

            dependencies = set(expected_dependencies_for_unit(unit))
            path_key = _canonical_path(unit_path)
            dependencies.update(expected_by_file.get(path_key, ()))
            expected_by_file[path_key] = tuple(sorted(dependencies))
    return expected_by_file


def expected_dependencies_for_file(
    file_path: Path,
    expected_dependencies_by_file: dict[str, tuple[str, ...]],
) -> tuple[str, ...]:
    """Return merged direct dependencies for one extracted unit path."""
    return expected_dependencies_by_file.get(_canonical_path(file_path), ())


def read_json(path: Path) -> dict:
    if not path.exists():
        raise FileNotFoundError(f"missing required file: {path}")
    return json.loads(path.read_text())


def phase_callers_key(func: dict, phase: int) -> str:
    target = f"phase{phase}_callers"
    if target in func:
        return target
    for key in func.keys():
        if key.endswith("_callers") and key.startswith("phase"):
            return key
    return target


def phase_callee_info_names_key(func: dict, phase: int) -> Optional[str]:
    target = f"phase{phase}_callee_info_names_by_caller"
    if target in func:
        return target
    for key in func.keys():
        if key.endswith("_callee_info_names_by_caller") and key.startswith("phase"):
            return key
    return None


def detect_lang_and_comment(file_rel: str, ext_to_lang: Dict[str, str]) -> Tuple[str, str]:
    ext = Path(file_rel).suffix.lstrip(".").lower()
    lang = ext_to_lang.get(ext, ext if ext else "unknown")
    comment = COMMENT_PREFIX_BY_LANG.get(lang, "//")
    return lang, comment


def _indirect_call_lines(functions: List[dict], fm_agent_prefix: str) -> List[str]:
    """Prompt section for indirect calls.

    Each call site gets one shared expectation in the caller's .info.json,
    named by the site's label; supplemental edges carry that label to every
    target as an info name, so each target sees the expectation.
    """
    # Calls with the same label and targets in one caller (the same macro used
    # several times) are listed once with all their lines.
    grouped = {}
    for fn in functions:
        for call in fn.get("indirect_calls", ()):
            key = (fn["name"], call["label"], tuple(call["targets"]))
            if key in grouped:
                grouped[key][1].append(call["line"])
            else:
                grouped[key] = (call, [call["line"]])
    if not grouped:
        return []
    lines = [
        "## INDIRECT CALLS",
        "These units make indirect calls: the called function is a value chosen at "
        "run time (for example a function pointer), so each call may reach any of "
        "its listed targets.",
        "",
    ]
    for (caller_name, _, _), (call, call_lines) in grouped.items():
        where = ", ".join(str(line) for line in call_lines)
        noun = "line" if len(call_lines) == 1 else "lines"
        head = f"- {caller_name}, source {noun} {where}: `{call['label']}`"
        if call.get("index"):
            lines.append(
                f"{head} -> {call['count']} possible targets, listed in "
                f"{fm_agent_prefix}{call['index']}"
            )
        else:
            targets = ", ".join(target.split("::")[-1] for target in call["targets"])
            lines.append(f"{head} -> {targets}")
    lines.extend([
        "",
        "For each indirect call above, write exactly ONE callee entry in the caller's "
        ".info.json, with `name` set to the label shown in backticks; calls with the "
        "same label share one entry. Describe what the caller requires from whichever "
        "target is invoked - the contract every target must honor - not each target "
        "separately. Open the index file or a target's extracted file only when you "
        "need its details.",
        "",
    ])
    return lines


def build_prompt(
    phase: int,
    layer_idx: int,
    is_cycle: bool,
    functions: List[dict],
    func_to_layer: Dict[str, int],
    all_funcs: Dict[str, dict],
    work_dir: Path,
    fm_agent_prefix: str,
    ext_to_lang: Dict[str, str],
    specification: SpecificationProfile = SOFTWARE_PROFILE,
) -> str:
    lines: List[str] = []
    sample_lang = "unknown"
    if functions:
        sample_lang, _ = detect_lang_and_comment(functions[0]["file"], ext_to_lang)
    self_artifact_name, dependency_artifact_name = specification.example_artifact_names()

    lines.append(f"You are generating behavioral specifications for Phase {phase}, Layer {layer_idx}.")
    lines.append("")
    lines.append(
        f"Language: {sample_lang}. "
        f"Write specifications to adjacent {specification.artifacts.self_suffix} "
        f"and {specification.artifacts.dependency_suffix} files."
    )
    lines.append("")
    lines.append(f"Read {fm_agent_prefix}spec_prompts/system_prompt.md FIRST for the mandatory spec format rules.")
    lines.append(f"Read: {fm_agent_prefix}spec_prompts/domain_context/engine_overview.txt")
    lines.append(f"Read: {fm_agent_prefix}spec_prompts/domain_context/phase_{phase:02d}_types.txt")
    user_knowledge_paths = list_staged_domain_knowledge_relpaths(
        work_dir,
        prefix=fm_agent_prefix.rstrip("/"),
    )
    if user_knowledge_paths:
        lines.append("Read these user-provided domain knowledge Markdown files:")
        for path in user_knowledge_paths:
            lines.append(f"- {path}")
    lines.append("")
    lines.append("## KEY RULES")
    lines.append("- Describe WHAT each extracted unit guarantees, NOT HOW it implements it")
    lines.append("- Do NOT name internal helper calls, loop structure, or data layout decisions")
    lines.append("- Do NOT enumerate members of sets - describe the GOVERNING RULE")
    lines.append("- Specs describe INTENDED CORRECT behavior per the domain (see domain files)")
    lines.append(f"- ALL files below exist in {fm_agent_prefix}extracted_functions/ - read and process each one")

    context_units: List[Tuple[str, dict]] = []
    context_seen = set()
    for fn in functions:
        for callee_name in fn.get("all_callees", ()):
            if not isinstance(callee_name, str) or callee_name in context_seen:
                continue
            callee_meta = all_funcs.get(callee_name)
            if callee_meta is None or _artifact_eligible(callee_meta):
                continue
            context_seen.add(callee_name)
            context_units.append((callee_name, callee_meta))

    if context_units:
        lines.append("")
        lines.append("## CONTEXT-ONLY DECLARATIONS")
        lines.append(
            "These declarations are retained for dependency and interface "
            "semantics. They are context only and must not receive standalone "
            "specification artifacts. Read each source file when determining "
            "the target unit's interface or dependency requirements:"
        )
        for context_name, context_meta in sorted(context_units):
            lines.append(
                f"- {context_name}: {fm_agent_prefix}{context_meta['file']}"
            )

    caller_specs: List[Tuple[str, str]] = []
    caller_expectations: Dict[str, List[Tuple[str, str]]] = {}
    for fn in functions:
        fn_name = fn["name"]
        caller_key = phase_callers_key(fn, phase)
        info_names_key = phase_callee_info_names_key(fn, phase)
        info_names_by_caller = fn.get(info_names_key, {}) if info_names_key else {}
        callers = fn.get(caller_key, [])
        for caller_name in callers:
            caller_layer = func_to_layer.get(caller_name)
            if caller_layer is None or caller_layer >= layer_idx:
                continue
            caller_meta = all_funcs.get(caller_name)
            if not caller_meta:
                continue
            caller_file = work_dir / caller_meta["file"]
            spec_block = specification.read_self_spec(caller_file)
            if spec_block and (caller_name, spec_block) not in caller_specs:
                caller_specs.append((caller_name, spec_block))
            entry_text = specification.read_dependency_expectation(
                caller_file,
                fn_name,
                info_names_by_caller.get(caller_name, []),
            )
            if entry_text:
                caller_expectations.setdefault(fn_name, []).append(
                    (caller_name, entry_text)
                )

    if caller_specs:
        lines.append("")
        lines.append("## EARLIER-LAYER CALLER SPECS")
        for caller_name, block in caller_specs:
            lines.append(f"#### {caller_name}")
            lines.append("")
            lines.append(block)
            lines.append("")

    if caller_expectations:
        lines.append("## CALLEE EXPECTATIONS FROM CALLERS")
        for fn in functions:
            fn_name = fn["name"]
            entries = caller_expectations.get(fn_name, [])
            if not entries:
                continue
            lines.append(f"### What callers expect from {fn_name}:")
            for caller_name, entry in entries:
                lines.append(f"#### According to {caller_name}:")
                lines.append(entry)
            lines.append("")

    if is_cycle:
        lines.append("## CYCLE LAYER GUIDANCE")
        lines.append("These units call each other (mutual recursion / circular dependencies).")
        lines.append(
            'Ask: "What is true after this function returns, regardless of which caller invoked it and which code path executed?" '
            "That invariant is your post-condition."
        )
        lines.append("")
        lines.append("DISPATCH UNIT TEST: If your spec has N bullets where N equals the number")
        lines.append("of switch arms / dispatch cases, you are transcribing the implementation.")
        lines.append("A dispatch function's contract is the invariant that holds ACROSS ALL cases.")
        lines.append("")

    lines.extend(_indirect_call_lines(functions, fm_agent_prefix))

    lines.append(f"## UNITS ({len(functions)} total - process ALL)")
    for idx, fn in enumerate(functions, start=1):
        fn_name = fn["name"]
        caller_key = phase_callers_key(fn, phase)
        callers = fn.get(caller_key, [])
        earlier = [c for c in callers if func_to_layer.get(c, 10**9) < layer_idx]
        lines.append(f"### {idx}. {fm_agent_prefix}{fn['file']}")
        if earlier:
            lines.append("  Earlier-layer callers: " + ", ".join(earlier))
        else:
            lines.append("  Earlier-layer callers: (none)")

    lines.append("")
    lines.extend(
        specification.prompt_contract.batch_output_section(
            BatchPromptContext(
                self_artifact_name=self_artifact_name,
                dependency_artifact_name=dependency_artifact_name,
            )
        )
    )
    return "\n".join(lines).rstrip() + "\n"


def generate_batch_prompts(
    work_dir: Path,
    phase: int,
    layers_spec: str,
    *,
    batch_size: int = 2,
    output_dir: Optional[Path] = None,
    resume: bool = False,
    dry_run: bool = False,
    specification: SpecificationProfile = SOFTWARE_PROFILE,
) -> dict:
    """Build, persist, and return the batch manifest for a layer range."""
    if batch_size <= 0:
        raise ValueError("--batch-size must be > 0")

    work_dir = Path(work_dir)
    # fm_agent_prefix is the relative path from the project root to work_dir
    repo_root = work_dir.parent
    fm_agent_prefix = str(work_dir.relative_to(repo_root)) + "/"

    phases_json = read_json(work_dir / "phases.json")
    project = phases_json["project"]
    languages = phases_json.get("languages", [])
    exts = phases_json.get("file_extensions", [])
    ext_to_lang = extension_language_map(languages, exts)

    topdown_path = work_dir / "spec_prompts" / f"phase_{phase:02d}_topdown_layers.json"
    topdown = read_json(topdown_path)
    layers = topdown.get("layers", [])
    expected_dependencies_by_file = build_expected_dependencies_by_file(topdown, work_dir)
    total_layers = len(layers)
    start_layer, end_layer = parse_layers_spec(layers_spec)
    if start_layer < 0 or end_layer >= total_layers:
        raise ValueError(f"layer range {layers_spec} out of bounds [0, {total_layers - 1}]")

    output_dir = Path(output_dir) if output_dir is not None else (
        work_dir / "spec_prompts" / f"batch_prompts_{project}_phase{phase:02d}"
    )

    func_to_layer: Dict[str, int] = {}
    all_funcs: Dict[str, dict] = {}
    for layer in layers:
        li = layer["layer"]
        for fn in layer.get("functions", []):
            # Normalize: strip fm_agent/ prefix if already present (LLM-generated
            # topdown scripts sometimes include it, causing double-prefix)
            if fn["file"].startswith(fm_agent_prefix):
                fn["file"] = fn["file"][len(fm_agent_prefix):]
            func_to_layer[fn["name"]] = li
            all_funcs[fn["name"]] = fn

    manifest_batches = []
    total_functions = 0
    total_context_functions = 0
    skipped_functions = 0
    batch_index = 0
    write_targets: List[Tuple[Path, str]] = []
    stale_targets: List[Path] = []

    for layer_idx in range(start_layer, end_layer + 1):
        layer = layers[layer_idx]
        all_layer_functions = layer.get("functions", [])
        layer_functions = [
            fn for fn in all_layer_functions if _artifact_eligible(fn)
        ]
        total_context_functions += len(all_layer_functions) - len(layer_functions)
        is_cycle = bool(layer.get("cycle_resolution", False))
        tag = "cycle" if is_cycle else "extracted"
        chunks = chunked(layer_functions, batch_size)
        total_functions += len(layer_functions)

        for local_idx, fn_batch in enumerate(chunks):
            filename = f"batch_{batch_index:03d}_layer{layer_idx}_{tag}_b{local_idx}.txt"
            # On resume, don't ask the LLM to re-spec functions that are already
            # done — but the manifest below still records the full batch.
            prompt_funcs = fn_batch
            if resume:
                prompt_funcs = [
                    fn
                    for fn in fn_batch
                    if not specification.validate(
                        work_dir / fn["file"],
                        expected_dependencies=expected_dependencies_for_file(
                            work_dir / fn["file"],
                            expected_dependencies_by_file,
                        ),
                    ).ready
                ]
                skipped_functions += len(fn_batch) - len(prompt_funcs)
            out_path = output_dir / filename
            # On resume, a batch whose functions are all already specced has no
            # work left for the agent — don't write an empty prompt file. The
            # manifest still records the full batch so later verification covers
            # these functions; run_pipeline only spawns batches that still have
            # unspecced functions (see _get_pending_batches).
            if prompt_funcs:
                content = build_prompt(
                    phase,
                    layer_idx,
                    is_cycle,
                    prompt_funcs,
                    func_to_layer,
                    all_funcs,
                    work_dir,
                    fm_agent_prefix,
                    ext_to_lang,
                    specification,
                )
                write_targets.append((out_path, content))
            else:
                # Nothing to spec — drop any stale prompt file left by a
                # previous run so the batch dir doesn't keep an empty batch.
                stale_targets.append(out_path)
            manifest_batches.append(
                {
                    "index": batch_index,
                    "file": filename,
                    "layer": layer_idx,
                    "is_cycle": is_cycle,
                    "num_functions": len(fn_batch),
                    "num_pending": len(prompt_funcs),
                    "functions": [f"{fm_agent_prefix}{fn['file']}" for fn in fn_batch],
                }
            )
            batch_index += 1

    manifest = {
        "phase": phase,
        "layers": layers_spec,
        "total_functions": total_functions,
        "total_context_functions": total_context_functions,
        "total_batches": len(manifest_batches),
        "batches": manifest_batches,
    }

    if dry_run:
        print(
            f"[dry-run] phase={phase} layers={layers_spec} "
            f"functions={total_functions} batches={len(manifest_batches)}"
            + (f" skipped={skipped_functions} (already specced)" if resume else "")
        )
        for batch in manifest_batches:
            print(
                f"- {batch['file']}: layer={batch['layer']} "
                f"count={batch['num_functions']} cycle={batch['is_cycle']}"
            )
        return manifest

    output_dir.mkdir(parents=True, exist_ok=True)
    current_batch_paths = {out_path for out_path, _ in write_targets}
    for existing_path in output_dir.glob("batch_*.txt"):
        if existing_path not in current_batch_paths:
            existing_path.unlink()
    for out_path, content in write_targets:
        out_path.write_text(content)
    for out_path in stale_targets:
        out_path.unlink(missing_ok=True)
    (output_dir / "manifest.json").write_text(json.dumps(manifest, indent=2))

    print(
        f"Generated {len(manifest_batches)} batch prompt(s) for phase {phase} "
        f"layers {layers_spec} in {output_dir}"
        + (f" (skipped {skipped_functions} already-specced function(s))" if resume else "")
    )
    return manifest


def main() -> int:
    """Run the source-tree command-line adapter."""
    args = parse_args()
    generate_batch_prompts(
        work_dir=Path.cwd() / "fm_agent",
        phase=args.phase,
        layers_spec=args.layers,
        batch_size=args.batch_size,
        output_dir=Path(args.output_dir) if args.output_dir else None,
        resume=args.resume,
        dry_run=args.dry_run,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

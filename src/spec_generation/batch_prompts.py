"""Build per-layer spec batches from extracted functions and layer metadata."""

import json
from pathlib import Path
from typing import Dict, List, Tuple

from ..domain_knowledge import list_staged_domain_knowledge_relpaths
from ..file_utils import is_file_ready
from ..spec_storage import metadata_paths, read_info, read_spec


COMMENT_PREFIX_BY_LANG = {
    "c": "//",
    "cpp": "//",
    "cxx": "//",
    "cc": "//",
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


def callee_expectation(info_data: dict, callee_fqn: str) -> dict | None:
    """Return the caller expectation for exactly one callee FQN."""
    return next(
        (
            callee
            for callee in info_data["callees"]
            if callee["function"] == callee_fqn
        ),
        None,
    )


def chunked(items: List[dict], size: int) -> List[List[dict]]:
    return [items[i : i + size] for i in range(0, len(items), size)]


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


def detect_lang_and_comment(file_rel: str, ext_to_lang: Dict[str, str]) -> Tuple[str, str]:
    ext = Path(file_rel).suffix.lstrip(".").lower()
    lang = ext_to_lang.get(ext, ext if ext else "unknown")
    comment = COMMENT_PREFIX_BY_LANG.get(lang, "//")
    return lang, comment


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
) -> str:
    lines: List[str] = []
    sample_lang = "unknown"
    if functions:
        sample_lang, _ = detect_lang_and_comment(functions[0]["file"], ext_to_lang)

    lines.append(f"You are generating behavioral specifications for Phase {phase}, Layer {layer_idx}.")
    lines.append("")
    lines.append(f"Language: {sample_lang}. Metadata format: structured JSON schema version 1.")
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
    lines.append("- Describe WHAT the function guarantees, NOT HOW it implements it")
    lines.append("- Do NOT name internal helper calls, loop structure, or data layout decisions")
    lines.append("- Do NOT enumerate members of sets - describe the GOVERNING RULE")
    lines.append("- Specs describe INTENDED CORRECT behavior per the domain (see domain files)")
    lines.append("- The implementation file is immutable input")
    lines.append("- Create both JSON metadata files for every function")
    lines.append("- Write valid JSON only; do not wrap JSON in Markdown fences")

    caller_specs: List[Tuple[str, dict]] = []
    caller_expectations: Dict[str, List[Tuple[str, dict]]] = {}
    for fn in functions:
        fn_name = fn["name"]
        caller_key = phase_callers_key(fn, phase)
        callers = fn.get(caller_key, [])
        for caller_name in callers:
            caller_layer = func_to_layer.get(caller_name)
            if caller_layer is None or caller_layer >= layer_idx:
                continue
            caller_meta = all_funcs.get(caller_name)
            if not caller_meta:
                continue
            caller_file = work_dir / caller_meta["file"]
            try:
                spec_data = read_spec(caller_file)
                info_data = read_info(caller_file)
            except (OSError, ValueError):
                continue
            if (caller_name, spec_data) not in caller_specs:
                caller_specs.append((caller_name, spec_data))
            entry = callee_expectation(info_data, fn_name)
            if entry:
                caller_expectations.setdefault(fn_name, []).append(
                    (caller_name, entry)
                )

    if caller_specs:
        lines.append("")
        lines.append("## EARLIER-LAYER CALLER SPECS")
        for caller_name, spec_data in caller_specs:
            lines.append(f"#### {caller_name}")
            lines.append("")
            lines.append(json.dumps(spec_data, indent=2, ensure_ascii=False))
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
                lines.append(json.dumps(entry, indent=2, ensure_ascii=False))
            lines.append("")

    if is_cycle:
        lines.append("## CYCLE LAYER GUIDANCE")
        lines.append("These functions call each other (mutual recursion / circular dependencies).")
        lines.append(
            'Ask: "What is true after this function returns, regardless of which caller invoked it and which code path executed?" '
            "That invariant is your post-condition."
        )
        lines.append("")
        lines.append("DISPATCH FUNCTION TEST: If your spec has N bullets where N equals the number")
        lines.append("of switch arms / dispatch cases, you are transcribing the implementation.")
        lines.append("A dispatch function's contract is the invariant that holds ACROSS ALL cases.")
        lines.append("")

    lines.append(f"## FUNCTIONS ({len(functions)} total - process ALL)")
    for idx, fn in enumerate(functions, start=1):
        fn_name = fn["name"]
        implementation_rel = Path(fn["file"])
        spec_rel, info_rel = metadata_paths(implementation_rel)
        caller_key = phase_callers_key(fn, phase)
        callers = fn.get(caller_key, [])
        earlier = [c for c in callers if func_to_layer.get(c, 10**9) < layer_idx]
        lines.append(f"### {idx}. {fn_name}")
        lines.append(
            f"  Read implementation (read-only): {fm_agent_prefix}{implementation_rel.as_posix()}"
        )
        lines.append(
            f"  Write spec JSON: {fm_agent_prefix}{spec_rel.as_posix()}"
        )
        lines.append(
            f"  Write info JSON: {fm_agent_prefix}{info_rel.as_posix()}"
        )
        if earlier:
            lines.append("  Earlier-layer callers: " + ", ".join(earlier))
        else:
            lines.append("  Earlier-layer callers: (none)")

    lines.append("")
    lines.append("## JSON SCHEMAS")
    lines.append("Spec JSON fields: schema_version=1, function, unit, signature, preconditions, postconditions.")
    lines.append("Info JSON fields: schema_version=1, function, callees.")
    lines.append("Each callee has function, signature, preconditions, and postconditions.")
    lines.append("All condition fields are arrays of strings. Use callees: [] when there are no callees.")
    lines.append("The top-level function field must exactly equal the FQN shown above.")
    lines.append("")
    lines.append("## PROCESS")
    lines.append("For each function:")
    lines.append("1. Read the implementation file without modifying it")
    lines.append("2. Read caller expectations above - what do callers NEED from this function?")
    lines.append("3. Write a behavioral spec describing WHAT it guarantees (not HOW)")
    lines.append("4. Write the complete structured object to the listed spec JSON path")
    lines.append("5. Write the complete structured object to the listed info JSON path")
    lines.append("6. Do not edit, rewrite, or otherwise modify the implementation file")
    return "\n".join(lines).rstrip() + "\n"


def generate_batch_manifest(
    extracted_functions_dir: str | Path,
    layer_json_path: str | Path,
    output_dir: str | Path,
    *,
    phase: int,
    layers_spec: str,
    project: str,
    ext_to_lang: Dict[str, str],
    batch_size: int = 2,
    resume: bool = False,
    dry_run: bool = False,
) -> dict:
    """Create prompt batches for layer JSON over one extracted-functions tree.

    The returned manifest always records every function in the selected layers. In
    resume mode, ready functions are excluded only from prompt content and counted as
    non-pending. No implementation or metadata file is modified.
    """
    if batch_size <= 0:
        raise ValueError("--batch-size must be > 0")

    extracted_functions_dir = Path(extracted_functions_dir).resolve()
    if not extracted_functions_dir.is_dir():
        raise FileNotFoundError(
            f"missing extracted functions directory: {extracted_functions_dir}"
        )
    work_dir = extracted_functions_dir.parent
    fm_agent_prefix = f"{work_dir.name}/"
    output_dir = Path(output_dir)
    topdown = read_json(Path(layer_json_path))
    layers = topdown.get("layers", [])
    total_layers = len(layers)
    start_layer, end_layer = parse_layers_spec(layers_spec)
    if start_layer < 0 or end_layer >= total_layers:
        raise ValueError(
            f"layer range {layers_spec} out of bounds [0, {total_layers - 1}]"
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
            function_path = (work_dir / fn["file"]).resolve()
            try:
                function_path.relative_to(extracted_functions_dir)
            except ValueError as exc:
                raise ValueError(
                    f"layer function is outside extracted functions: {fn['file']}"
                ) from exc
            if not function_path.is_file():
                raise FileNotFoundError(
                    f"layer function does not exist: {function_path}"
                )
            func_to_layer[fn["name"]] = li
            all_funcs[fn["name"]] = fn

    manifest_batches = []
    total_functions = 0
    skipped_functions = 0
    batch_index = 0
    write_targets: List[Tuple[Path, str]] = []
    stale_targets: List[Path] = []

    for layer_idx in range(start_layer, end_layer + 1):
        layer = layers[layer_idx]
        layer_functions = layer.get("functions", [])
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
                prompt_funcs = [fn for fn in fn_batch if not is_file_ready(work_dir / fn["file"])]
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
        "project": project,
        "total_functions": total_functions,
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
    for out_path, content in write_targets:
        out_path.write_text(content, encoding="utf-8")
    for out_path in stale_targets:
        out_path.unlink(missing_ok=True)
    (output_dir / "manifest.json").write_text(
        json.dumps(manifest, indent=2) + "\n",
        encoding="utf-8",
    )

    print(
        f"Generated {len(manifest_batches)} batch prompt(s) for phase {phase} "
        f"layers {layers_spec} in {output_dir}"
        + (f" (skipped {skipped_functions} already-specced function(s))" if resume else "")
    )
    return manifest

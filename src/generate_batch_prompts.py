"""Generate per-layer spec batch prompts from topdown layer metadata."""

import argparse
import json
from pathlib import Path
from typing import Dict, List, Optional, Tuple

# file_utils.py sits beside this script after being copied into fm_agent/spec_prompts/.
try:
    # When imported as part of the src package (e.g. incremental_reasoner).
    from .file_utils import is_file_ready
    from .domain_knowledge import list_staged_domain_knowledge_relpaths
except ImportError:
    # When run standalone after being copied into fm_agent/spec_prompts/,
    # where file_utils.py sits beside this script.
    from file_utils import is_file_ready

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
    parser.add_argument("--batch-size", type=int, default=2, help="Functions per prompt file")
    parser.add_argument("--output-dir", default=None, help="Output directory for batch prompt files")
    parser.add_argument("--dry-run", action="store_true", help="Show plan without writing files")
    parser.add_argument(
        "--resume",
        action="store_true",
        help="Skip functions already specced (file_utils.is_file_ready) when building batches",
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


def _detect_comment_prefix(content: str) -> Optional[str]:
    """Find the comment prefix by locating a line containing [SPEC] and extracting its prefix."""
    for line in content.splitlines():
        idx = line.find("[SPEC]")
        if idx != -1:
            return line[:idx].rstrip()
    return None


def extract_spec_block(filepath: Path) -> Optional[str]:
    """Return the '<comment> [SPEC]' block as a string, or None if not specced."""
    content = filepath.read_text(errors="replace")
    prefix = _detect_comment_prefix(content)
    if prefix is None:
        return None
    tag = f"{prefix} [SPEC]"
    if not content.startswith(tag):
        return None
    end = content.find(tag, len(tag))
    if end == -1:
        return None
    return content[: end + len(tag)].strip()


def extract_info_block(filepath: Path) -> Optional[str]:
    """Return content between the two '<comment> [INFO]' markers, or None."""
    content = filepath.read_text(errors="replace")
    prefix = _detect_comment_prefix(content)
    if prefix is None:
        return None
    tag = f"{prefix} [INFO]"
    start = content.find(tag)
    if start == -1:
        return None
    end = content.find(tag, start + len(tag))
    if end == -1:
        return None
    return content[start + len(tag) + 1 : end].strip()


def extract_callee_spec_from_info(info_block: str, callee_fqn: str) -> Optional[str]:
    """Find the [SPLIT]-separated entry for callee_fqn in an info_block."""
    import re

    # Detect comment prefix from the info_block content itself
    prefix = ""
    for line in info_block.splitlines():
        stripped = line.strip()
        if stripped:
            idx = stripped.find("[SPLIT]")
            if idx != -1:
                prefix = stripped[:idx].rstrip()
                break
    # If no [SPLIT] found in block, infer prefix from first non-empty line
    if not prefix:
        for line in info_block.splitlines():
            stripped = line.strip()
            if stripped:
                m = re.match(r'^(\S+)\s', stripped)
                if m:
                    prefix = m.group(1)
                break

    split_tag = f"{prefix} [SPLIT]" if prefix else "[SPLIT]"
    callee_stem = callee_fqn.split("::")[-1]
    for entry in info_block.split(split_tag):
        entry = entry.strip()
        if not entry or "(no callees)" in entry:
            continue
        first_line = entry.split("\n")[0].strip()
        # Strip the comment prefix to get the actual content
        if prefix and first_line.startswith(prefix):
            first_line = first_line[len(prefix):].strip()
        if callee_fqn in first_line or (callee_stem + "(") in first_line:
            return entry
    return None


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
    sample_comment = "//"
    if functions:
        sample_lang, sample_comment = detect_lang_and_comment(functions[0]["file"], ext_to_lang)

    lines.append(f"You are generating behavioral specifications for Phase {phase}, Layer {layer_idx}.")
    lines.append("")
    lines.append(
        f"Language: {sample_lang}. Spec comment style: `{sample_comment} [SPEC]`."
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
    lines.append("- Describe WHAT the function guarantees, NOT HOW it implements it")
    lines.append("- Do NOT name internal helper calls, loop structure, or data layout decisions")
    lines.append("- Do NOT enumerate members of sets - describe the GOVERNING RULE")
    lines.append("- Specs describe INTENDED CORRECT behavior per the domain (see domain files)")
    lines.append(f"- ALL files below exist in {fm_agent_prefix}extracted_functions/ - read and process each one")

    caller_specs: List[Tuple[str, str]] = []
    caller_expectations: Dict[str, List[Tuple[str, str]]] = {}
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
            spec_block = extract_spec_block(caller_file)
            if spec_block and (caller_name, spec_block) not in caller_specs:
                caller_specs.append((caller_name, spec_block))
            info_block = extract_info_block(caller_file)
            if not info_block:
                continue
            entry = extract_callee_spec_from_info(info_block, fn_name)
            if entry:
                caller_expectations.setdefault(fn_name, []).append((caller_name, entry.strip()))

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
        caller_key = phase_callers_key(fn, phase)
        callers = fn.get(caller_key, [])
        earlier = [c for c in callers if func_to_layer.get(c, 10**9) < layer_idx]
        lines.append(f"### {idx}. {fm_agent_prefix}{fn['file']}")
        if earlier:
            lines.append("  Earlier-layer callers: " + ", ".join(earlier))
        else:
            lines.append("  Earlier-layer callers: (none)")

    lines.append("")
    lines.append("## SPEC FORMAT (prepend to file, preserving source code below)")
    lines.append("")
    lines.append("The exact format every specced file must start with:")
    lines.append("")
    lines.append(f"{sample_comment} [SPEC]")
    lines.append(f"{sample_comment} Unit: <file path relative to repo root>")
    lines.append(f"{sample_comment}")
    lines.append(f"{sample_comment} <FunctionName>(<params>) -> <ReturnType>")
    lines.append(f"{sample_comment}")
    lines.append(f"{sample_comment} Pre-condition:")
    lines.append(f"{sample_comment}   - ...")
    lines.append(f"{sample_comment}")
    lines.append(f"{sample_comment} Post-condition:")
    lines.append(f"{sample_comment}   - ...")
    lines.append(f"{sample_comment} [SPEC]")
    lines.append("")
    lines.append(f"{sample_comment} [INFO]")
    lines.append(f"{sample_comment} <callee_name>(<params>) -> <ReturnType>")
    lines.append(f"{sample_comment}   Pre-condition: ...")
    lines.append(f"{sample_comment}   Post-condition: ...")
    lines.append(f"{sample_comment} [SPLIT]")
    lines.append(f"{sample_comment} <another_callee>(<params>) -> <ReturnType>")
    lines.append(f"{sample_comment}   Pre-condition: ...")
    lines.append(f"{sample_comment}   Post-condition: ...")
    lines.append(f"{sample_comment} [INFO]")
    lines.append("")
    lines.append("If the function has no callees: '<comment> (no callees)' between the [INFO] markers.")
    lines.append("")
    lines.append("## PROCESS")
    lines.append("For each function:")
    lines.append("1. Read the extracted file")
    lines.append("2. Read caller expectations above - what do callers NEED from this function?")
    lines.append("3. Write a behavioral spec describing WHAT it guarantees (not HOW)")
    lines.append("4. Write the COMPLETE file with [SPEC] and [INFO] blocks prepended, then UNCHANGED source")
    lines.append("5. Use the Write tool to save the complete file")
    return "\n".join(lines).rstrip() + "\n"


def main() -> int:
    args = parse_args()
    if args.batch_size <= 0:
        raise ValueError("--batch-size must be > 0")

    # work_dir is the fm_agent/ directory (parent of spec_prompts/ where this script lives)
    work_dir = Path(__file__).resolve().parent.parent
    # fm_agent_prefix is the relative path from the project root to work_dir
    repo_root = work_dir.parent
    fm_agent_prefix = str(work_dir.relative_to(repo_root)) + "/"

    phases_json = read_json(work_dir / "phases.json")
    project = phases_json["project"]
    languages = phases_json.get("languages", [])
    exts = phases_json.get("file_extensions", [])
    ext_to_lang = {ext.lower().lstrip("."): lang for ext, lang in zip(exts, languages)}

    topdown_path = work_dir / "spec_prompts" / f"phase_{args.phase:02d}_topdown_layers.json"
    topdown = read_json(topdown_path)
    layers = topdown.get("layers", [])
    total_layers = len(layers)
    start_layer, end_layer = parse_layers_spec(args.layers)
    if start_layer < 0 or end_layer >= total_layers:
        raise ValueError(f"layer range {args.layers} out of bounds [0, {total_layers - 1}]")

    output_dir = Path(args.output_dir) if args.output_dir else (
        work_dir / "spec_prompts" / f"batch_prompts_{project}_phase{args.phase:02d}"
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
    skipped_functions = 0
    batch_index = 0
    write_targets: List[Tuple[Path, str]] = []
    stale_targets: List[Path] = []

    for layer_idx in range(start_layer, end_layer + 1):
        layer = layers[layer_idx]
        layer_functions = layer.get("functions", [])
        is_cycle = bool(layer.get("cycle_resolution", False))
        tag = "cycle" if is_cycle else "extracted"
        chunks = chunked(layer_functions, args.batch_size)
        total_functions += len(layer_functions)

        for local_idx, fn_batch in enumerate(chunks):
            filename = f"batch_{batch_index:03d}_layer{layer_idx}_{tag}_b{local_idx}.txt"
            # On resume, don't ask the LLM to re-spec functions that are already
            # done — but the manifest below still records the full batch.
            prompt_funcs = fn_batch
            if args.resume:
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
                    args.phase,
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
        "phase": args.phase,
        "layers": args.layers,
        "total_functions": total_functions,
        "total_batches": len(manifest_batches),
        "batches": manifest_batches,
    }

    if args.dry_run:
        print(
            f"[dry-run] phase={args.phase} layers={args.layers} "
            f"functions={total_functions} batches={len(manifest_batches)}"
            + (f" skipped={skipped_functions} (already specced)" if args.resume else "")
        )
        for batch in manifest_batches:
            print(
                f"- {batch['file']}: layer={batch['layer']} "
                f"count={batch['num_functions']} cycle={batch['is_cycle']}"
            )
        return 0

    output_dir.mkdir(parents=True, exist_ok=True)
    for out_path, content in write_targets:
        out_path.write_text(content)
    for out_path in stale_targets:
        out_path.unlink(missing_ok=True)
    (output_dir / "manifest.json").write_text(json.dumps(manifest, indent=2))

    print(
        f"Generated {len(manifest_batches)} batch prompt(s) for phase {args.phase} "
        f"layers {args.layers} in {output_dir}"
        + (f" (skipped {skipped_functions} already-specced function(s))" if args.resume else "")
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

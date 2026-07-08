"""Generate per-layer spec batch prompts from topdown layer metadata."""

import argparse
import json
import re
from pathlib import Path
from typing import Dict, List, Optional, Tuple


COMMENT_PREFIX_BY_LANG = {
    "chisel": "//",
    "scala": "//",
    "sc": "//",
    "verilog": "//",
    "v": "//",
    "sv": "//",
    "svh": "//",
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
    parser.add_argument("--batch-size", type=int, default=1, help="Functions per prompt file")
    parser.add_argument("--output-dir", default=None, help="Output directory for batch prompt files")
    parser.add_argument("--dry-run", action="store_true", help="Show plan without writing files")
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


def standalone_spec_path(module_file: Path) -> Path:
    """Sibling ``<stem>_spec.md`` for an extracted Chisel module file."""
    return module_file.with_name(module_file.stem + "_spec.md")


def extract_standalone_spec(module_file: Path) -> Optional[str]:
    """Return the standalone ``<stem>_spec.md`` content for a module, or None.

    Chisel specs are emitted as standalone Markdown documents next to the
    extracted module file rather than embedded in the source.
    """
    spec_file = standalone_spec_path(module_file)
    if not spec_file.exists():
        return None
    text = spec_file.read_text(errors="replace").strip()
    return text or None


def standalone_info_path(module_file: Path) -> Path:
    """Sibling ``<stem>_info.md`` for an extracted Chisel module file."""
    return module_file.with_name(module_file.stem + "_info.md")


def extract_submodule_spec_from_chisel_info(module_file: Path, submodule_fqn: str) -> Optional[str]:
    """Return the expected-spec entry for ``submodule_fqn`` from a Chisel
    ``<stem>_info.md`` document, or None.

    Chisel info files are the standalone counterpart of the embedded ``[INFO]``
    callee-expectation block: one ``# Submodule: <Name>`` entry per submodule,
    each in the same section structure as a ``_spec.md`` document. The entry
    runs from its ``# Submodule:`` heading to the next one (or end of file).
    """
    info_file = standalone_info_path(module_file)
    if not info_file.exists():
        return None
    content = info_file.read_text(errors="replace")
    stem = submodule_fqn.split("::")[-1]
    # The extractor deduplicates same-named units (companion object + class)
    # by suffixing later ones with _<n>, but info headings use the DECLARED
    # name — fall back to the suffix-stripped stem when the exact one misses.
    candidates = [stem]
    stripped = re.sub(r"_\d+$", "", stem)
    if stripped and stripped != stem:
        candidates.append(stripped)
    entries: Dict[str, List[str]] = {}
    current: Optional[List[str]] = None
    for line in content.splitlines():
        m = re.match(r"^#\s*Submodule:\s*(\S+)\s*$", line)
        if m:
            current = entries.setdefault(m.group(1), [line])
            continue
        if current is not None:
            current.append(line)
    for name in candidates:
        entry_lines = entries.get(name)
        if entry_lines:
            entry = "\n".join(entry_lines).strip()
            if entry:
                return entry
    return None


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
    comment = COMMENT_PREFIX_BY_LANG.get(lang, COMMENT_PREFIX_BY_LANG.get(ext, "//"))
    return lang, comment


def build_ext_to_lang(exts: List[str], languages: List[str]) -> Dict[str, str]:
    """Build an extension->language map from phases.json defensively.

    Chisel setup usually records languages=["chisel"] and file_extensions=["scala"].
    If additional Scala extensions are listed, they should still map to Chisel.
    """
    normalized_exts = [ext.lower().lstrip(".") for ext in exts]
    normalized_langs = [lang.lower() for lang in languages]
    if "chisel" in normalized_langs:
        return {ext: "chisel" for ext in normalized_exts or ["scala"]}
    if "verilog" in normalized_langs or "systemverilog" in normalized_langs:
        return {ext: "verilog" for ext in normalized_exts or ["v", "sv"]}
    return {ext: lang for ext, lang in zip(normalized_exts, normalized_langs)}


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

    is_hw = sample_lang in ("chisel", "verilog")
    hw_label = "Chisel" if sample_lang == "chisel" else "Verilog/SystemVerilog"
    if is_hw:
        lines.append(f"You are generating verification-oriented {hw_label} module specifications for Phase {phase}, Layer {layer_idx}.")
    else:
        lines.append(f"You are generating behavioral specifications for Phase {phase}, Layer {layer_idx}.")
    lines.append("")
    if is_hw:
        lines.append(
            f"Language: {sample_lang}. Output form: two standalone Markdown files "
            f"`<ModuleName>_spec.md` and `<ModuleName>_info.md` per module, written next to the extracted module file. "
            f"Do NOT modify the original source."
        )
    else:
        lines.append(
            f"Language: {sample_lang}. Spec comment style: `{sample_comment} [SPEC]`."
        )
    lines.append("")
    lines.append(f"Read {fm_agent_prefix}spec_prompts/system_prompt.md FIRST for the mandatory spec format rules.")
    lines.append(f"Read: {fm_agent_prefix}spec_prompts/domain_context/engine_overview.txt")
    lines.append(f"Read: {fm_agent_prefix}spec_prompts/domain_context/phase_{phase:02d}_types.txt")
    lines.append("")
    lines.append("## KEY RULES")
    if is_hw:
        lines.append("- Describe WHAT the DUT guarantees, NOT HOW it is implemented")
        lines.append("- Focus on public parameters, IO ports, ready-valid/Valid protocols, reset behavior, ordering, arbitration, and observable state/data invariants")
        lines.append("- Do NOT name private wires, local registers, helper methods, or implementation assignment order unless they are part of the public verification boundary")
        lines.append("- Specs describe INTENDED CORRECT hardware behavior per the domain files")
        lines.append("- In `<ModuleName>_info.md`, write the EXPECTED spec of each submodule this module instantiates or directly depends on, one `# Submodule: <Name>` entry per submodule, same section structure as the spec")
        lines.append("- Write all output files entirely in English - translate any non-English domain context or source comments; never copy non-English text into outputs")
        lines.append(f"- ALL files below exist in {fm_agent_prefix}extracted_functions/ - read and process each module file")
    else:
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
            if is_hw:
                # Chisel specs and submodule expectations are standalone
                # <stem>_spec.md / <stem>_info.md documents next to the source.
                spec_block = extract_standalone_spec(caller_file)
                if spec_block and (caller_name, spec_block) not in caller_specs:
                    caller_specs.append((caller_name, spec_block))
                entry = extract_submodule_spec_from_chisel_info(caller_file, fn_name)
                if entry:
                    caller_expectations.setdefault(fn_name, []).append((caller_name, entry))
                continue
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
        if is_hw:
            if sample_lang == "chisel":
                lines.append("These modules reference each other through instantiation, inheritance, companion objects, or member access.")
            else:
                lines.append("These modules reference each other through instantiation.")
            lines.append(
                'Ask: "What observable DUT contract must hold regardless of the internal module decomposition?" '
                "That contract belongs in the module spec."
            )
        else:
            lines.append("These functions call each other (mutual recursion / circular dependencies).")
            lines.append(
                'Ask: "What is true after this function returns, regardless of which caller invoked it and which code path executed?" '
                "That invariant is your post-condition."
            )
        lines.append("")
        if is_hw:
            lines.append("MODULE CONTRACT TEST: If your spec enumerates private wires/register assignments or mirrors source branches, you are transcribing the implementation.")
            lines.append(f"A {hw_label} module spec should state observable IO, timing, reset, ordering, and protocol guarantees.")
        else:
            lines.append("DISPATCH FUNCTION TEST: If your spec has N bullets where N equals the number")
            lines.append("of switch arms / dispatch cases, you are transcribing the implementation.")
            lines.append("A dispatch function's contract is the invariant that holds ACROSS ALL cases.")
        lines.append("")

    unit_label = "MODULES" if is_hw else "FUNCTIONS"
    lines.append(f"## {unit_label} ({len(functions)} total - process ALL)")
    for idx, fn in enumerate(functions, start=1):
        fn_name = fn["name"]
        caller_key = phase_callers_key(fn, phase)
        callers = fn.get(caller_key, [])
        earlier = [c for c in callers if func_to_layer.get(c, 10**9) < layer_idx]
        module_file = Path(fn["file"])
        spec_file = module_file.with_name(module_file.stem + "_spec.md")
        info_file = module_file.with_name(module_file.stem + "_info.md")
        lines.append(f"### {idx}. {fm_agent_prefix}{fn['file']}")
        if is_hw:
            lines.append(f"  Required spec output: {fm_agent_prefix}{spec_file.as_posix()}")
            lines.append(f"  Required info output: {fm_agent_prefix}{info_file.as_posix()}")
        if earlier:
            lines.append("  Earlier-layer callers: " + ", ".join(earlier))
        else:
            lines.append("  Earlier-layer callers: (none)")

    lines.append("")
    if is_hw:
        lines.append("## OUTPUT FORMAT (two standalone Markdown files per module)")
        lines.append("")
        lines.append("For each module, write BOTH files in the SAME directory as the extracted module file. Do NOT modify the source.")
        lines.append("See spec_prompts/system_prompt.md for the full section structures. Cite code as <ref_file>path:line</ref_file>.")
        lines.append("")
        lines.append("### <ModuleName>_spec.md")
        lines.append("# <ModuleName> Specification Document")
        lines.append("## Introduction")
        lines.append("## Terms and Abbreviations")
        lines.append("## RTL Source Files")
        lines.append("## Top-Level Interface Overview")
        lines.append("## Functional Description")
        lines.append("   ### <Functional Group Name> -> Overview / Execution Flow / Boundaries and Exceptions / Performance and Constraints")
        lines.append("   ### Subcomponent Description -> #### Component <Name> (references <Name>_spec.md)")
        lines.append("   ### State Machines and Timing")
        lines.append("   ### Configuration Registers and Storage")
        lines.append("   ### Reset and Error Handling")
        lines.append("   ### Power, Clock, and Power Management (if applicable)")
        lines.append("   ### Parameterization and Configurable Features")
        lines.append("## Verification Requirements and Coverage Suggestions")
        lines.append("")
        lines.append("### <ModuleName>_info.md")
        lines.append("# <ModuleName> Submodule Expected Specifications")
        lines.append("One entry per submodule the module instantiates or directly depends on, caller-driven,")
        lines.append(f"each entry starting with '# Submodule: <SubmoduleName>' (exact declared {'Scala' if sample_lang == 'chisel' else 'module'} name)")
        lines.append("followed by the SAME section structure as <ModuleName>_spec.md above.")
        lines.append("If the module has no submodules, write '(no submodules)'.")
    else:
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
    if is_hw:
        lines.append("For each module:")
        lines.append("1. Read the extracted module file")
        lines.append("2. Read the earlier-layer caller specs and caller expectations above - what does the surrounding hardware NEED from this DUT?")
        lines.append("3. Write the required spec output path listed for that module, using the extracted file stem for the filename")
        lines.append("4. Write the required info output path listed for that module, with one expected-spec entry per submodule of that module (same section structure as the spec)")
        lines.append("5. Save both files in the SAME directory as the extracted module file")
        lines.append(f"6. Do NOT modify the original {'.scala' if sample_lang == 'chisel' else '.v/.sv'} source. Use the Write tool to save the .md files")
    else:
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
    ext_to_lang = build_ext_to_lang(exts, languages)

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
    batch_index = 0
    write_targets: List[Tuple[Path, str]] = []

    for layer_idx in range(start_layer, end_layer + 1):
        layer = layers[layer_idx]
        layer_functions = layer.get("functions", [])
        is_cycle = bool(layer.get("cycle_resolution", False))
        tag = "cycle" if is_cycle else "extracted"
        chunks = chunked(layer_functions, args.batch_size)
        total_functions += len(layer_functions)

        for local_idx, fn_batch in enumerate(chunks):
            filename = f"batch_{batch_index:03d}_layer{layer_idx}_{tag}_b{local_idx}.txt"
            content = build_prompt(
                args.phase,
                layer_idx,
                is_cycle,
                fn_batch,
                func_to_layer,
                all_funcs,
                work_dir,
                fm_agent_prefix,
                ext_to_lang,
            )
            out_path = output_dir / filename
            write_targets.append((out_path, content))
            manifest_batches.append(
                {
                    "index": batch_index,
                    "file": filename,
                    "layer": layer_idx,
                    "is_cycle": is_cycle,
                    "num_functions": len(fn_batch),
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
    (output_dir / "manifest.json").write_text(json.dumps(manifest, indent=2))

    print(
        f"Generated {len(manifest_batches)} batch prompt(s) for phase {args.phase} "
        f"layers {args.layers} in {output_dir}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

"""Spec generation for Verilog / SystemVerilog hardware designs.

This is the Verilog counterpart to :func:`src.chisel_spec_generator.run_chisel_spec_generation`.
It generates verification-oriented module specs for a Verilog/SystemVerilog
codebase and stops there — it does NOT run the reasoner or bug validation.

It mirrors the Chisel path almost exactly. All of the HDL-agnostic plumbing
(the ``groups.json`` -> ``phases.json`` bridge, source-path reconciliation,
domain-context aliasing, the FG/FC/CK quality-checklist validator, and the
``main`` pipeline helpers) is **reused by import** from
:mod:`src.chisel_spec_generator` and :mod:`main`, so the working Chisel path is
left untouched. Only the Verilog-specific pieces differ:

  * the source check (``.v``/``.sv``/``.svh`` instead of ``.scala``);
  * the three prompt documents consumed here
    (``md/workflow_setup_extract_verilog.md``, ``md/system_prompt_verilog.md``,
    ``md/workflow_spec_verilog.md``);
  * the standalone spec/info path + readiness helpers from
    :mod:`src.verilog_support`.
"""

import os
import sys
import json
import time
import shutil
import logging
import subprocess

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

from config import (
    OPENCODE_MAX_RETRIES,
    OPENCODE_MAX_CONCURRENCY,
    OPENCODE_SETUP_MODEL,
    OPENCODE_SPEC_MODEL,
    OPENCODE_MODEL_PROVIDER,
)
from src.file_utils import collect_file_names, _get_phase_files
from src.pipeline_setup import _deduplicate_phases
from src.verilog_support import (
    _SUBMODULE_HEADING_RE,
    _verilog_info_ready,
    _verilog_markdown_ready,
    verilog_info_path,
    verilog_spec_path,
    verilog_spec_ready,
)
from src.extract import run_extraction
from src.generate_topdown_layers import generate_topdown_layers
from src.opencode_trace import (
    finish_opencode_trace,
    function_id_from_extracted_path,
    run_opencode_traced,
    start_opencode_traced,
)

# Reuse the HDL-agnostic helpers from the Chisel generator and the main pipeline
# rather than duplicating them. The FG/FC/CK quality-checklist validator is
# language-independent (it only parses <FG-*>/<FC-*>/<CK-*> tags), so it is
# imported under a neutral name.
from src.chisel_spec_generator import (
    validate_chisel_spec as validate_hw_spec,
    _filter_phase_source_files,
    _groups_json_is_usable,
    _normalize_groups_source_paths,
    _groups_to_phases,
    _normalize_chisel_domain_context as _normalize_hw_domain_context,
    _load_json_file,
    _report_undocumented_submodules,
    _reset_derived_state,
)
from main import _clean_previous_run


def _force_verilog_phase_languages(work_dir):
    """Ensure phases.json declares Verilog so downstream language detection is correct.

    ``_groups_to_phases`` passes ``languages``/``file_extensions`` through from
    groups.json and defaults to Chisel when they are absent. Since this is the
    Verilog flow, force ``languages=["verilog"]`` and keep the declared Verilog
    extensions plus any found on the phase source files (falling back to v/sv) —
    groups.json may under-report extensions (e.g. omit svh), and an extension
    missing here makes ``generate_batch_prompts.build_ext_to_lang`` route those
    modules away from the hardware (standalone ``.md``) spec path.
    """
    phases_path = os.path.join(work_dir, "phases.json")
    data = _load_json_file(phases_path, "phases.json")
    data["languages"] = ["verilog"]
    declared = data.get("file_extensions", [])
    if isinstance(declared, str):
        declared = [declared]
    exts = {str(e).lower().lstrip(".") for e in declared}
    for phase in data.get("phases", []):
        for module in phase.get("modules", []):
            srcs = module.get("source_files", [])
            if isinstance(srcs, str):
                srcs = [srcs]
            for src in srcs:
                base = os.path.basename(str(src))
                if "." in base:
                    exts.add(base.rsplit(".", 1)[-1].lower())
    exts = sorted(e for e in exts if e in ("v", "sv", "svh"))
    data["file_extensions"] = exts or ["v", "sv"]
    with open(phases_path, "w") as f:
        json.dump(data, f, indent=2)


def _remove_incomplete_verilog_outputs(module_path, expected_submodules=frozenset()):
    """Delete spec/info outputs that exist but are incomplete (e.g. truncated).

    The retry prompt tells the agent to only generate outputs for modules that
    do not yet have both output files, so an incomplete file left in place
    would make every retry skip the module. Complete files (including a small
    legal ``(no submodules)`` info document for actual leaf modules) are kept.
    An info missing one of ``expected_submodules``'s entries counts as
    incomplete for the same reason: leaving it in place would strand the batch
    in a bounded retry failure.
    """
    def _info_ready(path):
        return _verilog_info_ready(
            path,
            allow_no_submodules=not expected_submodules,
            expected_submodules=expected_submodules,
        )

    checks = (
        (verilog_spec_path(module_path), _verilog_markdown_ready),
        (verilog_info_path(module_path), _info_ready),
    )
    for path, ready in checks:
        if os.path.exists(path) and not ready(path):
            logging.warning(
                "Removing incomplete Verilog output %s so it is regenerated.", path
            )
            try:
                os.remove(path)
            except OSError as exc:
                logging.warning("Could not remove incomplete output %s: %s", path, exc)


def _get_pending_batches_verilog(batches, proj_dir, expected_submodules=None):
    """Return batches that still have at least one module without a complete,
    valid spec/info output.

    Mirrors :func:`src.chisel_spec_generator._get_pending_batches_chisel`:
    readiness is checked via :func:`verilog_spec_ready`, and each ready
    ``_spec.md`` is validated against the FG/FC/CK quality checklist with
    :func:`validate_hw_spec`. Incomplete (truncated) outputs and specs that
    fail validation are deleted so the retry loop regenerates them instead of
    skipping modules whose output files merely exist.

    ``expected_submodules`` maps function rel-paths to the module names their
    instantiation graph shows as submodules: for those, a ``(no submodules)``
    info stub is rejected, and the info must contain a ``# Submodule:`` entry
    for EVERY expected name (Verilog edges are precise — verible CST,
    in-project modules only — unlike Chisel's, which stay advisory). Invalid
    infos are removed and the miss is fed back with the FULL required set, so
    the next attempt regenerates a complete info instead of ping-ponging on
    whichever single entry was last reported missing.

    Design intent, pinned: this gate enforces the info document as a
    DELIVERABLE — the design's submodule contracts must cover every
    instantiated child, same-phase or not. It does NOT promise that every
    callee prompt consumes every caller expectation: batch prompts propagate
    expectations within a phase only, and cross-phase prompt propagation is
    a recorded enhancement (upstream issue), not an unfinished part of this
    feature. Weakening the gate to same-phase would delete correct
    documentation to match a prompt limitation.
    """
    expected_submodules = expected_submodules or {}
    pending = []
    for batch in batches:
        batch_pending = False
        feedback = batch.get("validation_errors")
        feedback = dict(feedback) if isinstance(feedback, dict) else {}
        for func_rel in batch.get("functions", []):
            module_path = os.path.join(proj_dir, func_rel)
            expected = expected_submodules.get(func_rel, frozenset())
            module_errors = []
            if not verilog_spec_ready(module_path, expected_submodules=expected):
                info_path = verilog_info_path(module_path)
                spec_ok = _verilog_markdown_ready(verilog_spec_path(module_path))
                if expected and os.path.exists(info_path):
                    try:
                        with open(info_path, "r", errors="replace") as f:
                            info_text = f.read()
                    except OSError:
                        info_text = ""
                    documented = set(_SUBMODULE_HEADING_RE.findall(info_text))
                    if "(no submodules)" in info_text or not documented:
                        module_errors.append(
                            f"{os.path.basename(info_path)}: this module instantiates "
                            f"other extracted modules — the info file must contain one "
                            f"'# Submodule: <name>' entry per instantiated submodule "
                            f"and must not claim '(no submodules)'"
                        )
                    elif expected - documented:
                        module_errors.append(
                            f"{os.path.basename(info_path)}: missing submodule "
                            f"entries: {', '.join(sorted(expected - documented))}; "
                            f"the regenerated info must contain one "
                            f"'# Submodule: <name>' entry for EVERY required "
                            f"entry: {', '.join(sorted(expected))}"
                        )
                if not module_errors and spec_ok:
                    # verilog_spec_ready is False but the spec itself is fine
                    # (no-expected leaf, or the per-name checks above found
                    # nothing this round — e.g. their own info file was just
                    # deleted by US, pending regeneration). Only report a
                    # generic info blocker when the CURRENTLY recorded
                    # feedback blames the spec specifically (now moot, since
                    # the spec is fine) or there is none yet — otherwise a
                    # more specific info diagnosis from a prior round (also
                    # deleted pending regeneration) must survive via inertia,
                    # not be replaced by a weaker generic message.
                    spec_base = os.path.basename(verilog_spec_path(module_path))
                    prior = feedback.get(func_rel) or []
                    if not prior or any(spec_base in m for m in prior):
                        module_errors.append(
                            f"{os.path.basename(info_path)}: incomplete or missing "
                            f"— regenerate it"
                        )
                _remove_incomplete_verilog_outputs(
                    module_path, expected_submodules=expected
                )
                batch_pending = True
                if module_errors:
                    feedback[func_rel] = module_errors
                continue
            spec_path = verilog_spec_path(module_path)
            is_valid, spec_errors = validate_hw_spec(spec_path)
            if not is_valid:
                logging.warning(
                    "Verilog spec %s failed quality-checklist validation; removing it "
                    "so it is regenerated. First issues: %s",
                    spec_path, "; ".join(spec_errors[:5]),
                )
                try:
                    os.remove(spec_path)
                except OSError as exc:
                    logging.warning("Could not remove invalid spec %s: %s", spec_path, exc)
                feedback[func_rel] = [
                    f"{os.path.basename(spec_path)}: " + "; ".join(spec_errors[:3])
                ]
                batch_pending = True
            else:
                # Ready and checklist-valid: this module is done — drop its
                # stale feedback so the retry prompt stops demanding a fix
                # for an issue that no longer exists.
                feedback.pop(func_rel, None)
        # Exposed to the retry prompt so the LLM knows WHAT failed — without
        # feedback regeneration rarely converges. Keyed per module: an entry
        # survives the pre-launch rescan (which runs AFTER the offending
        # files were deleted) until ITS module passes, so a fixed module's
        # errors do not ride along while batchmates are still regenerating.
        batch["validation_errors"] = feedback if batch_pending else {}
        if batch_pending:
            pending.append(batch)
    return pending


def _has_verilog_source(proj_dir):
    """Check whether proj_dir contains at least one Verilog (.v/.sv/.svh) source file."""
    for root, dirs, files in os.walk(proj_dir):
        # Skip hidden dirs and common non-source dirs (mirrors _has_source_code).
        dirs[:] = [d for d in dirs if not d.startswith('.') and d not in
                   {'node_modules', '__pycache__', 'venv', '.venv', 'fm_agent'}]
        for fname in files:
            if fname.endswith(('.v', '.sv', '.svh')):
                return True
    return False


def run_verilog_spec_generation(proj_dir, resume=False):
    """Generate verification-oriented specs for a Verilog/SystemVerilog design.

    Mirrors :func:`src.chisel_spec_generator.run_chisel_spec_generation` but for
    ``.v``/``.sv`` designs and spec-only: it skips the reasoner and bug validation.

    When ``resume`` is True, the existing ``fm_agent/`` workspace is preserved:
    the design-understanding LLM stage is skipped if ``groups.json`` already
    exists, and Stage 4 only generates specs for modules that do not yet have
    valid spec/info files.
    """
    if not os.path.isdir(proj_dir):
        print(f"[Verilog] ERROR: proj_dir does not exist or is not a directory: {proj_dir}")
        sys.exit(1)

    if not _has_verilog_source(proj_dir):
        print(f"[Verilog] ERROR: No Verilog (.v/.sv/.svh) source files found in {proj_dir}.")
        sys.exit(1)

    # Verible is required: the pure-Python fallback parser misses instantiation
    # edges (one-line modules, generate blocks), corrupting topdown layering.
    if not os.environ.get("FM_AGENT_NO_VERIBLE") and shutil.which("verible-verilog-syntax") is None:
        print(
            "[Verilog] ERROR: verible-verilog-syntax not found on PATH. "
            "The Verilog flow requires Verible for accurate module extraction and "
            "instantiation-edge detection. Install it from "
            "https://github.com/chipsalliance/verible, or set FM_AGENT_NO_VERIBLE=1 "
            "to force the less accurate pure-Python fallback."
        )
        sys.exit(1)

    work_dir = os.path.join(proj_dir, "fm_agent")
    input_dir = os.path.join(work_dir, "extracted_functions")
    repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    md_dir = os.path.join(repo_root, "md")
    src_dir = os.path.join(repo_root, "src")

    # Clean files from the previous run, unless resuming an interrupted run.
    groups_path = os.path.join(work_dir, "groups.json")
    resume_setup = resume and os.path.exists(groups_path) and _groups_json_is_usable(groups_path, required_exts={"v", "sv", "svh"}, required_languages={"verilog", "systemverilog", "system_verilog"})
    if resume:
        if resume_setup:
            print("[Verilog] Resume: preserving existing fm_agent/ workspace "
                  "and reusing groups.json.")
        elif os.path.exists(groups_path):
            print("[Verilog] Resume requested but groups.json is missing or incomplete; "
                  "rerunning setup in the existing fm_agent/ workspace.")
            _reset_derived_state(work_dir)
        else:
            print("[Verilog] Resume requested but no groups.json found; "
                  "starting setup in the existing fm_agent/ workspace.")
            _reset_derived_state(work_dir)
    else:
        _clean_previous_run(work_dir)
    os.makedirs(work_dir, exist_ok=True)

    # --- Stage 1: Understand the design and write groups.json + domain context ---
    if resume_setup:
        print("[Verilog] Stage 1/4: Reusing existing groups.json (resume).")
    else:
        print("[Verilog] Stage 1/4: Understanding design and extracting modules ...")
    workflow_src = os.path.join(md_dir, "workflow_setup_extract_verilog.md")
    workflow_dst = os.path.join(work_dir, "workflow_setup_extract_verilog.md")
    shutil.copy2(workflow_src, workflow_dst)

    fm_reminder = ("IMPORTANT: The fm_agent/ directory is NOT part of the project source code. "
                   "It is a workspace for storing your output files only. "
                   "Do NOT include fm_agent/ paths in groups.json. "
                   "Do NOT modify any existing project files.")
    for attempt in range(1, OPENCODE_MAX_RETRIES + 1):
        if resume_setup:
            break
        if attempt == 1 and not os.path.exists(groups_path):
            prompt = f"Follow the instructions in the attached file. {fm_reminder}"
        else:
            prompt = ("Continue where you left off. The previous run was interrupted or left incomplete output. "
                      "If fm_agent/groups.json exists but is malformed or incomplete, rewrite it. "
                      f"Check what has already been done and only complete the remaining steps. {fm_reminder}")
        command = ["opencode", "run", "--model", f"{OPENCODE_MODEL_PROVIDER}/{OPENCODE_SETUP_MODEL}",
                   "--file", os.path.join(work_dir, "workflow_setup_extract_verilog.md"), "--", prompt]
        try:
            run_opencode_traced(
                proj_dir=proj_dir,
                work_dir=work_dir,
                command=command,
                stage="setup_context",
                input_files=["fm_agent/workflow_setup_extract_verilog.md"],
                output_files=[
                    "fm_agent/groups.json",
                    "fm_agent/spec_prompts/domain_context/design_overview.txt",
                ],
                summary=f"OpenCode Verilog setup context attempt {attempt}",
                metadata={"attempt": attempt},
            )
        except subprocess.CalledProcessError as e:
            logging.warning(f"Stage 1 attempt {attempt}: opencode exited with code {e.returncode}")

        if _groups_json_is_usable(groups_path, required_exts={"v", "sv", "svh"}, required_languages={"verilog", "systemverilog", "system_verilog"}):
            break

        if attempt < OPENCODE_MAX_RETRIES:
            delay = 10
            print(
                f"[Verilog] Stage 1 failed to produce groups.json (attempt {attempt}/{OPENCODE_MAX_RETRIES}). "
                f"Retrying in {delay}s..."
            )
            logging.warning(f"Stage 1 attempt {attempt} failed: groups.json missing. Retrying in {delay}s.")
            time.sleep(delay)
        else:
            print(
                f"[Verilog] ERROR: Stage 1 failed after {OPENCODE_MAX_RETRIES} attempts. "
                f"groups.json is missing or incomplete. "
                f"Check {os.path.basename(proj_dir)}/fm_agent/trace/ for details."
            )
            sys.exit(1)

    # Reconcile agent-written source paths with proj_dir before anything joins them.
    unresolved = _normalize_groups_source_paths(work_dir, proj_dir)
    if unresolved:
        print(
            f"[Verilog] WARNING: {len(unresolved)} source path(s) in groups.json do not "
            f"resolve under {proj_dir} and were left as-is; extraction will skip them. "
            f"First few: {unresolved[:5]}"
        )

    # Bridge groups.json -> the generic-pipeline schema, then force Verilog
    # language. Foreign source files the setup LLM mixed into HDL groups are
    # dropped with a warning.
    _groups_to_phases(work_dir)
    _force_verilog_phase_languages(work_dir)
    _filter_phase_source_files(work_dir, {"v", "sv", "svh"}, "Verilog")

    # Deduplicate source files across phases before aliasing subsystem context.
    _deduplicate_phases(work_dir)
    _normalize_hw_domain_context(work_dir)

    # Run module extraction (Verilog support is registered in extract.py)
    print("[Verilog] Extracting modules from source files...")
    run_extraction(proj_dir, work_dir=work_dir, force=True, verbose=True)

    # Copy the Verilog system prompt and batch helper script into spec_prompts/
    spec_prompts_dir = os.path.join(work_dir, "spec_prompts")
    os.makedirs(spec_prompts_dir, exist_ok=True)
    shutil.copy2(
        os.path.join(md_dir, "system_prompt_verilog.md"),
        os.path.join(spec_prompts_dir, "system_prompt.md"),
    )
    shutil.copy2(
        os.path.join(src_dir, "generate_batch_prompts.py"),
        os.path.join(spec_prompts_dir, "generate_batch_prompts.py"),
    )
    shutil.copy2(
        os.path.join(src_dir, "file_utils.py"),
        os.path.join(spec_prompts_dir, "file_utils.py"),
    )

    # Re-alias domain context in case extraction recreated spec_prompts layout
    _normalize_hw_domain_context(work_dir)

    print("[Verilog] Stage 2/4: Collecting file list...")
    collect_file_names(input_dir, os.path.join(work_dir, "fm_agent_file_list.json"))

    phases_data = _load_json_file(os.path.join(work_dir, "phases.json"), "phases.json")
    # Judge emptiness by the CURRENT phases' files: stale units from a
    # previous run (preserved by --resume) must not smuggle the run past
    # this guard by making the whole-tree walk non-empty.
    # A reused manifest that lists source files which no longer exist
    # describes a PAST tree: renamed/deleted files mean the new names are
    # absent from phases/topdown/batches entirely, so surviving sources
    # would spec fine while the rest silently never appear (partial-missing
    # is invisible to the zero-units guard below). Discard the stale
    # manifest and rerun setup against the tree as it exists now; completed
    # specs for surviving sources are preserved and reused. The recursive
    # call starts with no groups.json, so resume_setup is False there and
    # this cannot loop.
    if resume_setup and any(
        not os.path.exists(os.path.join(proj_dir, src))
        for phase in phases_data["phases"]
        for module in phase["modules"]
        for src in module["source_files"]
    ):
        print("[Verilog] Resume: the reused groups.json points at missing "
              "source files; discarding it and rerunning setup.")
        try:
            os.remove(groups_path)
        except OSError:
            pass
        _reset_derived_state(work_dir)
        return run_verilog_spec_generation(proj_dir, resume=True)

    if not any(
        _get_phase_files(phases_data, phase["phase"], input_dir)
        for phase in phases_data["phases"]
    ):
        print("[Verilog] No modules found to spec. Skipping spec generation.")
        return

    # --- Stage 3: Generate topdown layers ---
    print("[Verilog] Stage 3/4: Generating topdown layers...")
    generate_topdown_layers(work_dir)

    # --- Stage 4: Execute spec generation (per phase, per layer) ---
    print("[Verilog] Stage 4/4: Generating Verilog module specs...")
    if os.environ.get("FM_AGENT_NO_VERIBLE"):
        # The per-callee gate below is blocking specifically because
        # verible's instantiation edges are precise (unlike Chisel's noisy
        # edges, which is why THAT gate stays advisory). The regex fallback
        # can only MISS edges (false negatives), never invent ones that
        # don't exist — so a missed instantiation is invisible everywhere
        # (topdown layers, the gate's expected-submodule set) and the gate
        # cannot flag what it never learned exists. Downgrading the gate
        # here would gain nothing (missed edges stay invisible to advisory
        # mode too) while giving up enforcement on the edges the fallback
        # DID find — so the gate stays blocking; this warning names the
        # narrower guarantee instead.
        print(
            "[Verilog] WARNING: FM_AGENT_NO_VERIBLE=1 is set — instantiation "
            "edges may be incomplete (the regex fallback misses one-line "
            "modules and generate blocks). The submodule documentation gate "
            "can only enforce the edges it detected; an undetected "
            "submodule instantiation will not be flagged as missing."
        )
    batch_md_src = os.path.join(md_dir, "workflow_spec_verilog.md")
    batch_md_dst = os.path.join(work_dir, "workflow_spec_verilog.md")
    shutil.copy2(batch_md_src, batch_md_dst)

    num_phases = len(phases_data["phases"])
    project_name = phases_data.get("project", "project")

    for phase_info in sorted(phases_data["phases"], key=lambda p: p["phase"]):
        phase_num = phase_info["phase"]
        phase_name = phase_info["name"]
        phase_files = _get_phase_files(phases_data, phase_num, input_dir)

        if not phase_files:
            logging.info(f"Subsystem {phase_num} ({phase_name}): no extracted files, skipping.")
            continue

        layers_json_path = os.path.join(
            spec_prompts_dir, f"phase_{phase_num:02d}_topdown_layers.json"
        )
        if not os.path.exists(layers_json_path):
            generate_topdown_layers(work_dir, [phase_num])
        layers_data = _load_json_file(layers_json_path, f"topdown layers for subsystem {phase_num}")
        total_layers = layers_data.get("total_layers", 1)

        # Modules whose instantiation graph shows submodules must document an
        # info entry for EVERY instantiated module name (FQN tail, compared
        # exactly — numeric suffixes like fifo_64 are real Verilog names, not
        # dedup aliases). Keyed both by the proj_dir-relative path (batch
        # functions) and the input_dir-relative path (layer_files readiness
        # counts).
        _with_subs = {
            fn["file"]: {c.split("::")[-1] for c in fn["all_callees"]}
            for layer in layers_data.get("layers", [])
            for fn in layer.get("functions", [])
            if fn.get("all_callees")
        }
        expected_submodules = {
            os.path.relpath(os.path.join(work_dir, f), proj_dir): names
            for f, names in _with_subs.items()
        }
        expected_rel = {
            os.path.relpath(os.path.join(work_dir, f), input_dir): names
            for f, names in _with_subs.items()
        }

        batch_dir = os.path.join(
            spec_prompts_dir,
            f"batch_prompts_{project_name}_phase{phase_num:02d}",
        )

        for layer_idx in range(total_layers):
            print(f"[Verilog] Stage 4/4: Subsystem {phase_num}/{num_phases} — {phase_name}, "
                  f"Layer {layer_idx}/{total_layers - 1}")

            subprocess.run(
                ["python3", "fm_agent/spec_prompts/generate_batch_prompts.py",
                 "--phase", str(phase_num), "--layers", str(layer_idx)],
                cwd=proj_dir, check=True,
            )

            manifest_path = os.path.join(batch_dir, "manifest.json")
            manifest = _load_json_file(manifest_path, f"batch manifest for subsystem {phase_num} layer {layer_idx}")
            all_batches = manifest.get("batches", [])

            if not all_batches:
                logging.info(f"Subsystem {phase_num} Layer {layer_idx}: no batches, skipping.")
                continue

            batch_rel_dir = os.path.relpath(batch_dir, proj_dir)

            layer_files = []
            seen_layer_files = set()
            for batch_info in all_batches:
                for func_rel in batch_info.get("functions", []):
                    rel = os.path.relpath(os.path.join(proj_dir, func_rel), input_dir)
                    if rel not in seen_layer_files:
                        seen_layer_files.add(rel)
                        layer_files.append(rel)

            layer_complete = False
            for attempt in range(1, OPENCODE_MAX_RETRIES + 1):
                pending_batches = _get_pending_batches_verilog(all_batches, proj_dir, expected_submodules=expected_submodules)
                if not pending_batches:
                    layer_complete = True
                    break

                ready_before = sum(
                    1 for rel in layer_files
                    if verilog_spec_ready(os.path.join(input_dir, rel), expected_submodules=expected_rel.get(rel, frozenset()))
                )

                def _start_batch(batch_info):
                    batch_file = batch_info["file"]
                    batch_prompt_rel = os.path.join(batch_rel_dir, batch_file)
                    function_files = batch_info.get("functions", [])
                    function_ids = [
                        function_id_from_extracted_path(func_rel)
                        for func_rel in function_files
                    ]
                    spec_output_files = []
                    for func_rel in function_files:
                        spec_output_files.extend([
                            verilog_spec_path(func_rel),
                            verilog_info_path(func_rel),
                        ])
                    fm_reminder = ("IMPORTANT: fm_agent/ is your output workspace, not project source. "
                                   "Do NOT modify any existing project files.")
                    checklist_note = ""
                    failed = batch_info.get("validation_errors") or {}
                    if failed:
                        issues = " | ".join(
                            msg for key in sorted(failed) for msg in failed[key]
                        )
                        checklist_note = (
                            " WARNING: the following previously generated outputs FAILED "
                            "validation and were deleted — regenerate them and fix "
                            "exactly these issues (for *_spec.md checklist failures, "
                            "re-read the Coverage Tags rules in "
                            "fm_agent/spec_prompts/system_prompt.md: every tag is a plain "
                            "<FG-NAME>/<FC-NAME>/<CK-NAME> on its own line, sibling tag names "
                            "must be unique, and the <FG-API> group is mandatory; for "
                            "*_info.md failures, write one '# Submodule: <name>' section "
                            "for EVERY required entry listed, not only the missing ones): "
                            + issues
                        )
                    if attempt == 1 and not resume:
                        prompt = (
                            f"Process the batch prompt file at {batch_prompt_rel}. "
                            f"Read it and fm_agent/spec_prompts/system_prompt.md, "
                            f"generate verification-oriented Verilog/SystemVerilog module spec and info files for each module listed, "
                            f"and write the exact output filenames requested in the batch prompt next to each "
                            f"extracted module file (do NOT modify the source). {fm_reminder}"
                        )
                    else:
                        prompt = (
                            f"Continue processing the batch prompt file at {batch_prompt_rel}. "
                            f"Some modules may already have spec/info files from a previous attempt. "
                            f"Check each module's directory and only generate outputs for modules "
                            f"that do not yet have both exact output files requested in the batch prompt. "
                            f"Read fm_agent/spec_prompts/system_prompt.md for the format rules. "
                            f"{fm_reminder}{checklist_note}"
                        )
                    command = ["opencode", "run", "--model", f"{OPENCODE_MODEL_PROVIDER}/{OPENCODE_SPEC_MODEL}",
                               "--file", os.path.join(work_dir, "workflow_spec_verilog.md"),
                               "--", prompt]
                    return start_opencode_traced(
                        proj_dir=proj_dir,
                        work_dir=work_dir,
                        command=command,
                        stage="spec_generation",
                        function_ids=function_ids,
                        input_files=[
                            "fm_agent/workflow_spec_verilog.md",
                            batch_prompt_rel,
                            "fm_agent/spec_prompts/system_prompt.md",
                        ],
                        output_files=spec_output_files,
                        summary=f"OpenCode Verilog spec generation for {batch_file}",
                        metadata={
                            "attempt": attempt,
                            "phase": phase_num,
                            "layer": layer_idx,
                            "batch_file": batch_file,
                        },
                    )

                max_concurrency = max(1, OPENCODE_MAX_CONCURRENCY)
                queue = list(pending_batches)
                running = []
                launched = 0
                try:
                    while queue or running:
                        while queue and len(running) < max_concurrency:
                            trace_record = _start_batch(queue.pop(0))
                            running.append(trace_record)
                            launched += 1
                        finished = []
                        while not finished:
                            for tr in running:
                                if tr.proc.poll() is not None:
                                    finished.append(tr)
                            if not finished:
                                time.sleep(1)
                        for tr in finished:
                            running.remove(tr)
                            finish_opencode_trace(tr)
                except Exception:
                    for tr in running:
                        if tr.proc.poll() is None:
                            tr.proc.terminate()
                    for tr in running:
                        try:
                            tr.proc.wait(timeout=10)
                        except subprocess.TimeoutExpired:
                            tr.proc.kill()
                            tr.proc.wait()
                        finally:
                            finish_opencode_trace(tr)
                    raise

                logging.info(
                    f"Subsystem {phase_num} Layer {layer_idx} attempt {attempt}: "
                    f"ran {launched} opencode processes for {len(pending_batches)} batches "
                    f"(max {max_concurrency} concurrent)"
                )

                ready_after = sum(
                    1 for rel in layer_files
                    if verilog_spec_ready(os.path.join(input_dir, rel), expected_submodules=expected_rel.get(rel, frozenset()))
                )
                if not _get_pending_batches_verilog(all_batches, proj_dir, expected_submodules=expected_submodules):
                    layer_complete = True
                    break

                if ready_after > ready_before:
                    logging.info(
                        f"Subsystem {phase_num} Layer {layer_idx} attempt {attempt}: "
                        f"{ready_after}/{len(layer_files)} complete spec/info outputs ready, retrying remaining batches"
                    )
                    if attempt < OPENCODE_MAX_RETRIES:
                        continue

                if attempt < OPENCODE_MAX_RETRIES:
                    delay = 10
                    print(
                        f"[Verilog] Stage 4 Subsystem {phase_num} Layer {layer_idx} produced no complete spec/info outputs "
                        f"(attempt {attempt}/{OPENCODE_MAX_RETRIES}). "
                        f"Retrying in {delay}s..."
                    )
                    logging.warning(
                        f"Stage 4 Subsystem {phase_num} Layer {layer_idx} attempt {attempt} failed: "
                        f"no complete spec/info outputs generated. Retrying in {delay}s."
                    )
                    time.sleep(delay)
                else:
                    print(
                        f"[Verilog] ERROR: Stage 4 Subsystem {phase_num} Layer {layer_idx} failed "
                        f"after {OPENCODE_MAX_RETRIES} attempts with "
                        f"{ready_after}/{len(layer_files)} complete spec/info outputs. "
                        f"Check {os.path.basename(proj_dir)}/fm_agent/trace/ for details, "
                        f"then rerun with --resume."
                    )
                    sys.exit(1)

            if not layer_complete and _get_pending_batches_verilog(all_batches, proj_dir, expected_submodules=expected_submodules):
                ready_count = sum(
                    1 for rel in layer_files
                    if verilog_spec_ready(os.path.join(input_dir, rel), expected_submodules=expected_rel.get(rel, frozenset()))
                )
                print(
                    f"[Verilog] ERROR: Stage 4 Subsystem {phase_num} Layer {layer_idx} "
                    f"stopped with {ready_count}/{len(layer_files)} complete spec/info outputs. "
                    f"Run again with --resume after fixing the underlying OpenCode error."
                )
                sys.exit(1)

    _report_undocumented_submodules(work_dir, verilog_info_path, "Verilog",
                                    strip_dedup_suffix=False)
    print("[Verilog] Done. Generated Verilog module spec/info files only; skipped reasoning and bug validation.")

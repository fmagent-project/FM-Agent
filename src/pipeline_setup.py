"""Stage 1 of the pipeline: understand the codebase and produce the phase plan.

This module owns everything that runs the setup_context agent and post-processes
its output — building `phases.json`, deduplicating source files across phases,
and keeping the generated `spec_prompts/domain_context/` files in sync with it.
It is imported by `main.py` (the full pipeline) and by `src/incremental_reasoner`.
"""

import os
import sys
import json
import time
import shutil
import logging
import subprocess

from config import (
    OPENCODE_MAX_RETRIES,
    OPENCODE_SETUP_MODEL,
    OPENCODE_MODEL_PROVIDER,
)
from .extract import EXT_TO_LANG
from .file_utils import _is_test_file, _json_file_is_valid
from .opencode_trace import run_opencode_traced
from .cli_backend import build_agent_command, is_cli_backend_enabled


def _merge_descriptions(target_desc, source_desc):
    """Append a removed module's description to the owning module's description.

    Avoids re-merging the same content if it is already present.
    """
    source_desc = (source_desc or "").strip()
    if not source_desc:
        return target_desc
    if source_desc in target_desc:
        return target_desc
    if not target_desc:
        return source_desc
    return f"{target_desc}\n\n{source_desc}"


def _build_domain_context_regen_prompt(phase_source_files, phase_cleanup=None):
    """Compose the instruction telling the agent to regenerate the per-phase
    domain-context types files for phases whose source-file list changed.

    ``phase_source_files`` maps a changed phase's number to its CURRENT source
    files in phases.json (the caller guarantees the list is non-empty). For each
    phase the agent rewrites phase_NN_types.txt from scratch from those files'
    real types/structs/invariants, so previously force-added or deduplicated files
    are reflected without any mechanical text surgery.
    """
    lines = []
    for phase_num in sorted(phase_source_files):
        file_str = ", ".join(phase_source_files[phase_num])
        lines.append(
            f"  - phase {phase_num}: REGENERATE phase_{phase_num:02d}_types.txt from "
            f"scratch. Its source_files are now: {file_str}. READ them in the project "
            f"and write the real types/structs/invariants they define. Do not leave "
            f"the file empty or invent content."
        )
    changes_text = "\n".join(lines)
    if not changes_text:
        changes_text = (
            "  - No phase_NN_types.txt files need regeneration; only update "
            "engine_overview.txt if cleanup made its phase references stale."
        )
    phase_cleanup = phase_cleanup or {}
    removed_phases = [
        p for p in phase_cleanup.get("removed_phases", [])
        if p is not None
    ]
    renumbered = phase_cleanup.get("renumbered", {})
    renumbered_changes = {
        old: new for old, new in renumbered.items()
        if old is not None and new is not None and old != new
    }

    overview_rule = (
        "- engine_overview.txt does not need updating; touch it only if it "
        "explicitly names a phase number that changed."
    )
    if removed_phases or renumbered_changes:
        cleanup_lines = []
        if removed_phases:
            cleanup_lines.append(
                "removed old phase number(s): "
                + ", ".join(str(p) for p in sorted(removed_phases))
            )
        if renumbered_changes:
            cleanup_lines.append(
                "renumbered surviving phase(s): "
                + ", ".join(
                    f"{old} -> {new}"
                    for old, new in sorted(renumbered_changes.items())
                )
            )
        overview_rule = (
            "- Review engine_overview.txt and update any phase-numbered references "
            "so they match the final phases.json after cleanup ("
            + "; ".join(cleanup_lines)
            + ")."
        )

    return (
        "Regenerate per-phase domain-context "
        "files under fm_agent/spec_prompts/domain_context/ (named phase_NN_types.txt) so each reflects its phase's CURRENT "
        "source_files:\n\n"
        f"{changes_text}\n\n"
        "Rules:\n"
        "- Base each file on the types in that phase's source files; do not "
        "invent new types.\n"
        "- Do NOT modify any other files. Only edit "
        "files under fm_agent/spec_prompts/domain_context/.\n"
        f"{overview_rule}"
    )


def _phase_source_files(phases_json):
    """Return a mapping of phase number -> its combined source files in phases.json.

    Files from all of a phase's modules are merged, so an empty list means the
    phase currently owns no source files. A missing or malformed phases.json yields
    an empty mapping.
    """
    try:
        with open(phases_json, "r") as f:
            data = json.load(f)
    except (OSError, ValueError):
        return {}
    result = {}
    for phase in data.get("phases", []):
        phase_num = phase.get("phase")
        if phase_num is None:
            continue
        files = result.setdefault(phase_num, [])
        for module in phase.get("modules", []):
            files.extend(module.get("source_files", []))
    return result


def _sync_domain_context(proj_dir, work_dir, changed_phases, phase_cleanup=None):
    """Re-generate the per-phase domain-context files for phases whose source-file
    composition changed after phase edits.

    The phase-planning steps can force extra source files into an existing phase
    (see ``_ensure_source_files_in_phases``) or strip duplicate files from it (see
    ``_deduplicate_phases``). The generated
    ``spec_prompts/domain_context/phase_NN_types.txt`` files are keyed by phase
    number and their prose references phases/structs by meaning, so realigning a
    phase's types file with its new source-file set is semantic work. Rather than
    editing the text mechanically (which can be wrong), we hand the agent the exact
    set of changed phases and let it regenerate their types files from scratch
    against the freshly written phases.json.

    ``changed_phases`` is the set from ``_collect_changed_phases``. Only phases that
    still own at least one source file are regenerated — a phase left with an empty
    file list (e.g. all its files deduplicated away) has no types to describe. An
    empty set, or no changed phase with files, skips the agent call entirely.
    """
    phase_cleanup = phase_cleanup or {}
    removed_phases = [
        p for p in phase_cleanup.get("removed_phases", [])
        if p is not None
    ]
    renumbered = phase_cleanup.get("renumbered", {})
    cleanup_changed = bool(removed_phases) or any(
        old is not None and new is not None and old != new
        for old, new in renumbered.items()
    )
    if not changed_phases and not cleanup_changed:
        return
    domain_dir = os.path.join(work_dir, "spec_prompts", "domain_context")
    if not os.path.isdir(domain_dir):
        logging.info("No domain_context/ directory to sync after phase edits; skipping.")
        return

    source_files_by_phase = _phase_source_files(os.path.join(work_dir, "phases.json"))
    regenerate = {
        phase_num: source_files_by_phase[phase_num]
        for phase_num in changed_phases
        if source_files_by_phase.get(phase_num)
    }
    if not regenerate and not cleanup_changed:
        logging.info(
            "No changed phase still owns source files; skipping domain-context regen."
        )
        return

    prompt = _build_domain_context_regen_prompt(regenerate, phase_cleanup)
    fm_reminder = ("IMPORTANT: fm_agent/ is your output workspace, not project source. "
                   "Do NOT modify any existing project files.")
    prompt = f"{prompt}\n\n{fm_reminder}"

    if is_cli_backend_enabled():
        command = build_agent_command(
            model=OPENCODE_SETUP_MODEL,
            prompt=prompt,
            cwd=proj_dir,
        )
    else:
        command = ["opencode", "run", "--model",
                   f"{OPENCODE_MODEL_PROVIDER}/{OPENCODE_SETUP_MODEL}", "--", prompt]

    for attempt in range(1, OPENCODE_MAX_RETRIES + 1):
        try:
            run_opencode_traced(
                proj_dir=proj_dir,
                work_dir=work_dir,
                command=command,
                stage="sync_domain_context",
                input_files=["fm_agent/phases.json"],
                output_files=[
                    "fm_agent/spec_prompts/domain_context/engine_overview.txt",
                ],
                summary=f"Regenerate domain_context for changed phases (attempt {attempt})",
                metadata={"attempt": attempt},
            )
            return
        except subprocess.CalledProcessError as e:
            logging.warning(
                "Domain-context sync attempt %d/%d failed: opencode exited %s",
                attempt, OPENCODE_MAX_RETRIES, e.returncode,
            )
            if attempt < OPENCODE_MAX_RETRIES:
                time.sleep(10)

    # The caller performs a final completeness check after this best-effort
    # sync, so warn here and let that single validation point decide whether the
    # pipeline can continue.
    logging.warning(
        "Domain-context sync did not complete after %d attempts; "
        "phase_NN_types.txt files may be out of sync with phases.json.",
        OPENCODE_MAX_RETRIES,
    )


def _deduplicate_phases(phases_dir):
    """Ensure each source file appears in at most one phase; keep the earliest.

    Duplicate source files are stripped from every phase/module after the first
    one that claims them. No phase or module is dropped — not even when it loses
    all of its files; only the ``source_files`` lists shrink, so phase numbering
    and the ``phase_NN_types.txt`` files stay aligned. Returns a change summary
    listing the modules whose file list changed so the caller can refresh their
    descriptions (see ``_update_module_description``).
    """
    phases_path = os.path.join(phases_dir, "phases.json")
    with open(phases_path, "r") as f:
        data = json.load(f)

    seen = set()
    # Modules (phase, module, removed_files) that lost some or all of their source
    # files to deduplication. Their descriptions may still describe files they no
    # longer own, so the caller has the agent rewrite them.
    changed_modules = []
    for phase in sorted(data["phases"], key=lambda p: p["phase"]):
        for module in phase["modules"]:
            original = module["source_files"]
            deduped = []
            for sf in original:
                if sf not in seen:
                    seen.add(sf)
                    deduped.append(sf)
                else:
                    logging.info(
                        "Removed duplicate file '%s' from phase %d module '%s'",
                        sf, phase["phase"], module["name"],
                    )
            module["source_files"] = deduped
            removed_files = [sf for sf in original if sf not in deduped]
            if removed_files:
                # File list changed; record it so its description can be refreshed.
                # The module (and its phase) is kept even if it is now empty.
                changed_modules.append((phase, module, removed_files))

    with open(phases_path, "w") as f:
        json.dump(data, f, indent=2)

    # Report the modules whose file list changed. Phase numbers are unchanged
    # (nothing was dropped or renumbered), so these are the numbers the agent will
    # find in the freshly written phases.json.
    modified_modules = [
        {
            "phase": phase["phase"],
            "module": module.get("name", ""),
            "removed_files": removed_files,
            "source_files": list(module["source_files"]),
        }
        for phase, module, removed_files in changed_modules
    ]
    return {
        "modified_modules": modified_modules,
    }


def _clean_empty_phase_module(work_dir):
    """Drop empty modules/phases from phases.json, renumber phases, and keep the
    per-phase domain-context files in sync.

    A module owning no source files, and a phase left with no non-empty modules,
    carry no work for later stages, so both are removed. Surviving phases are then
    renumbered 1..N in their existing order (closing any gaps the removals left),
    and ``depends_on_phases`` references are remapped to the new numbering with
    references to removed phases dropped.

    Because the ``spec_prompts/domain_context/phase_NN_types.txt`` files are keyed
    by phase number, this also deletes the types file of every removed phase and
    renames the types file of every renumbered phase to match its new number.

    Returns ``{"removed_phases": [...], "renumbered": {old: new, ...}}`` describing
    what changed (an unchanged phase maps to itself in ``renumbered``).
    """
    phases_path = os.path.join(work_dir, "phases.json")
    with open(phases_path, "r") as f:
        data = json.load(f)

    original_phases = sorted(data.get("phases", []), key=lambda p: p.get("phase", 0))

    kept = []
    removed_phase_nums = []
    for phase in original_phases:
        modules = [
            m for m in phase.get("modules", [])
            if m.get("source_files")
        ]
        if modules:
            phase["modules"] = modules
            kept.append(phase)
        else:
            removed_phase_nums.append(phase.get("phase"))
            logging.info(
                "Removed empty phase %s ('%s') with no source files",
                phase.get("phase"), phase.get("name", ""),
            )

    # Map each surviving phase's old number to its new (compacted) number.
    renumbered = {}
    for new_num, phase in enumerate(kept, start=1):
        old_num = phase.get("phase")
        if old_num is not None:
            renumbered[old_num] = new_num
        phase["phase"] = new_num

    # Remap dependencies to the new numbering, dropping any that pointed at a
    # removed phase (which no longer exists to depend on).
    for phase in kept:
        deps = phase.get("depends_on_phases")
        if not deps:
            continue
        phase["depends_on_phases"] = sorted(
            {renumbered[d] for d in deps if d in renumbered}
        )

    data["phases"] = kept
    with open(phases_path, "w") as f:
        json.dump(data, f, indent=2)

    _clean_domain_context_files(work_dir, removed_phase_nums, renumbered)
    return {"removed_phases": removed_phase_nums, "renumbered": renumbered}


def _clean_domain_context_files(work_dir, removed_phase_nums, renumbered):
    """Delete removed phases' types files and rename renumbered ones to match.

    ``removed_phase_nums`` are the old numbers of phases dropped by
    ``_clean_empty_phase_module``; ``renumbered`` maps each surviving phase's old
    number to its new number. The domain-context directory may be absent (setup
    has not produced it yet), in which case there is nothing to sync.
    """
    domain_dir = os.path.join(work_dir, "spec_prompts", "domain_context")
    if not os.path.isdir(domain_dir):
        return

    def types_path(num):
        return os.path.join(domain_dir, f"phase_{num:02d}_types.txt")

    for old_num in removed_phase_nums:
        if old_num is None:
            continue
        path = types_path(old_num)
        if os.path.exists(path):
            os.remove(path)
            logging.info("Deleted domain-context file for removed phase %s", old_num)

    # Rename via temporary names first so a new number that collides with an
    # as-yet-unmoved file (e.g. phase 3 -> 2 while 2 -> 1) never overwrites it.
    pending = []  # (temp_path, final_path)
    for old_num, new_num in renumbered.items():
        if old_num == new_num:
            continue
        src = types_path(old_num)
        if not os.path.exists(src):
            continue
        tmp = src + ".renumber_tmp"
        os.rename(src, tmp)
        pending.append((tmp, types_path(new_num)))

    for tmp, final_path in pending:
        os.rename(tmp, final_path)
        logging.info("Renamed domain-context file to %s", os.path.basename(final_path))


def _collect_changed_modules(ensure_changes, dedup_changes):
    """Collect the modules whose source-file list changed during post-processing.

    Both ``_ensure_source_files_in_phases`` (which force-adds source files to a
    module) and ``_deduplicate_phases`` (which strips duplicate source files from
    modules) alter which files a module owns, so an affected module's description
    may no longer match. This returns one entry per affected module, giving only
    its phase number and name — the input to ``_update_module_description``. The
    agent re-reads each module's current source files from phases.json itself.

    Dedup no longer renumbers phases, so both sources speak the same phase
    numbering (the one in the freshly written phases.json).
    """
    entries = {}  # (phase, module_name) -> entry
    for m in dedup_changes.get("modified_modules", []):
        key = (m["phase"], m["module"])
        entries[key] = {"phase": m["phase"], "module": m["module"]}
    for a in ensure_changes.get("augmented_modules", []):
        key = (a["phase"], a["module"])
        entries[key] = {"phase": a["phase"], "module": a["module"]}
    return list(entries.values())


def _collect_changed_phases(ensure_changes, dedup_changes):
    """Collect the phase numbers whose source-file composition changed during
    post-processing.

    Both ``_ensure_source_files_in_phases`` (which force-adds source files to a
    phase's first module) and ``_deduplicate_phases`` (which strips duplicate
    source files from modules) can change which files a phase owns, so its
    domain-context types file (phase_NN_types.txt) may no longer match. This
    returns the set of affected phase numbers so the caller can have those files
    regenerated (see ``_sync_domain_context``).

    Dedup no longer renumbers phases, so both sources speak the same phase
    numbering (the one in the freshly written phases.json).
    """
    phases = set()
    for phase_num in ensure_changes.get("augmented", {}):
        if phase_num is not None:
            phases.add(phase_num)
    for m in dedup_changes.get("modified_modules", []):
        phase_num = m.get("phase")
        if phase_num is not None:
            phases.add(phase_num)
    return phases


def _build_module_description_prompt(modified_modules, phases_json):
    """Compose the instruction telling the agent to refresh the descriptions of
    modules whose source-file list changed during post-processing.

    ``modified_modules`` is the list produced by ``_collect_changed_modules``; each
    entry names a module by its CURRENT phase number and module name. Modules that
    own no source files in ``phases_json`` are skipped — there is nothing to
    describe, so they are left out of the prompt.
    """
    try:
        with open(phases_json, "r") as f:
            data = json.load(f)
    except (OSError, ValueError):
        data = {"phases": []}
    source_files_by_key = {}
    for phase in data.get("phases", []):
        for module in phase.get("modules", []):
            source_files_by_key[(phase.get("phase"), module.get("name", ""))] = list(
                module.get("source_files", [])
            )

    lines = []
    for m in modified_modules:
        if not source_files_by_key.get((m["phase"], m["module"])):
            # Module owns no files; nothing to describe, so leave it out.
            continue
        lines.append(f"  - phase {m['phase']} module \"{m['module']}\"")
    if not lines:
        return None
    changes_text = "\n".join(lines)

    return (
        "Here is a list of modules in fm_agent/phases.json:\n\n"
        f"{changes_text}\n\n"
        "Please update the \"description\" field of each module above so that it accurately "
        "describes the source files it now owns.\n"
        "Rules:\n"
        "- Edit ONLY the \"description\" field of the listed modules in "
        "fm_agent/phases.json.\n"
        "- Do NOT change any \"source_files\", \"phase\", \"name\", "
        "\"depends_on_phases\", or the phase structure in any way.\n"
        "- Do NOT touch modules that are not in the list above.\n"
        "- Keep the JSON valid.\n"
        "- Do NOT modify any project source file; only edit fm_agent/phases.json."
    )


def _update_module_description(proj_dir, work_dir, modified_modules):
    """Delegate refreshing module descriptions to the agent after deduplication.

    ``_ensure_source_files_in_phases`` can force-add source files to a module and
    ``_deduplicate_phases`` can strip duplicate source files from a module while
    leaving it in place. A module's ``description`` is prose written by the setup
    agent about a specific set of files, so once that set changes the description
    can be inaccurate. Rather than editing it mechanically, we hand the agent the
    exact list of modules whose file list changed and let it rewrite their
    descriptions against the freshly written phases.json.

    ``modified_modules`` is the list from ``_collect_changed_modules``; an empty
    list (no module's files changed) skips the agent call entirely.
    """
    if not modified_modules:
        return

    phases_path = os.path.join(work_dir, "phases.json")
    if not os.path.exists(phases_path):
        logging.info("No phases.json to update module descriptions in; skipping.")
        return

    prompt = _build_module_description_prompt(modified_modules, phases_path)
    if not prompt:
        logging.info(
            "No changed module still owns source files; skipping description update."
        )
        return
    fm_reminder = ("IMPORTANT: fm_agent/ is your output workspace, not project source. "
                   "Do NOT modify any existing project files.")
    prompt = f"{prompt}\n\n{fm_reminder}"

    if is_cli_backend_enabled():
        command = build_agent_command(
            model=OPENCODE_SETUP_MODEL,
            prompt=prompt,
            cwd=proj_dir,
        )
    else:
        command = ["opencode", "run", "--model",
                   f"{OPENCODE_MODEL_PROVIDER}/{OPENCODE_SETUP_MODEL}", "--", prompt]

    for attempt in range(1, OPENCODE_MAX_RETRIES + 1):
        try:
            run_opencode_traced(
                proj_dir=proj_dir,
                work_dir=work_dir,
                command=command,
                stage="update_module_description",
                input_files=["fm_agent/phases.json"],
                output_files=["fm_agent/phases.json"],
                summary=f"Update module descriptions after phase dedup (attempt {attempt})",
                metadata={"attempt": attempt},
            )
            return
        except subprocess.CalledProcessError as e:
            logging.warning(
                "Module-description update attempt %d/%d failed: opencode exited %s",
                attempt, OPENCODE_MAX_RETRIES, e.returncode,
            )
            if attempt < OPENCODE_MAX_RETRIES:
                time.sleep(10)

    # Best effort: a stale description is not fatal to the pipeline, so warn and
    # let the run continue rather than aborting.
    logging.warning(
        "Module-description update did not complete after %d attempts; some module "
        "descriptions in phases.json may still reference deduplicated files.",
        OPENCODE_MAX_RETRIES,
    )


def _setup_outputs_complete(work_dir):
    """Return True only if the setup_context stage produced ALL its output files.

    The setup stage (Stage 1) is responsible for writing, per
    md/workflow_setup_extract.md:
      1. phases.json
      2. spec_prompts/domain_context/engine_overview.txt
      3. spec_prompts/domain_context/phase_NN_types.txt — one per phase

    An interrupted run can leave phases.json behind without the domain-context
    files, which are later read by the spec-generation batch prompts. Resuming
    must only skip setup when every one of these exists, otherwise the missing
    files have to be regenerated.
    """
    phases_path = os.path.join(work_dir, "phases.json")
    if not _json_file_is_valid(phases_path):
        return False

    domain_dir = os.path.join(work_dir, "spec_prompts", "domain_context")
    if not os.path.exists(os.path.join(domain_dir, "engine_overview.txt")):
        return False

    try:
        with open(phases_path, "r") as f:
            phases_data = json.load(f)
    except (OSError, json.JSONDecodeError):
        return False

    for phase in phases_data.get("phases", []):
        phase_num = phase.get("phase")
        if phase_num is None:
            # Malformed phases.json — can't verify this phase's types file, and
            # downstream stages require p["phase"]. Re-run setup rather than
            # claim completeness.
            return False
        types_path = os.path.join(domain_dir, f"phase_{phase_num:02d}_types.txt")
        if not os.path.exists(types_path):
            return False

    return True


def _collect_project_source_files(proj_dir):
    """Return non-test source files currently present in proj_dir, relative to proj_dir."""
    source_exts = set(EXT_TO_LANG.keys())
    files = set()
    for root, dirs, names in os.walk(proj_dir):
        dirs[:] = [d for d in dirs if not d.startswith('.') and d not in
                   {'node_modules', '__pycache__', 'venv', '.venv', 'fm_agent'}]
        for fname in names:
            ext = fname.rsplit('.', 1)[-1] if '.' in fname else ''
            if ext not in source_exts:
                continue
            rel = os.path.relpath(os.path.join(root, fname), proj_dir).replace(os.sep, '/')
            if not _is_test_file(rel):
                files.add(rel)
    return files


def _phases_cover_current_sources(phases_json, proj_dir):
    """Return whether phases.json is valid for the current source-file set."""
    try:
        with open(phases_json, "r") as f:
            data = json.load(f)
    except (OSError, ValueError):
        return False

    listed = set()
    for phase in data.get("phases", []):
        for module in phase.get("modules", []):
            for source_file in module.get("source_files", []):
                listed.add(source_file.replace("\\", "/"))

    if not listed:
        return False
    if any(not os.path.exists(os.path.join(proj_dir, sf)) for sf in listed):
        return False
    return _collect_project_source_files(proj_dir).issubset(listed)


def _ensure_source_files_in_phases(phases_json, required_source_files):
    """Force-list ``required_source_files`` in phases.json if the agent omitted them.

    The Stage 1 setup agent decides which source files go into phases.json and may
    leave out files that look like tests. When a caller (e.g. the entry pipeline)
    must have a specific file processed regardless, this appends any missing ones
    to the first module of the earliest phase and records them in that module's
    description. No phase is created and nothing is renumbered — the existing phase
    plan is left intact, so the ``phase_NN_types.txt`` files keep their numbering.

    Returns ``{"forced": [...], "augmented": {phase_number: [paths]},
    "augmented_modules": [{"phase": n, "module": name, "added_files": [paths]}]}``.
    ``forced`` is the list of paths that had to be added; ``augmented`` maps the
    (original) number of the phase whose module gained files to those paths, so the
    caller can have that phase's domain-context types file extended; and
    ``augmented_modules`` names the specific module (by original phase number and
    name) that gained the files, so its description can be refreshed too. When
    nothing had to be added all are empty.
    """
    if not required_source_files:
        return {"forced": [], "augmented": {}, "augmented_modules": []}

    with open(phases_json, "r") as f:
        data = json.load(f)

    listed = set()
    for phase in data.get("phases", []):
        for module in phase.get("modules", []):
            for sf in module.get("source_files", []):
                listed.add(sf.replace("\\", "/"))

    missing = [sf for sf in required_source_files if sf.replace("\\", "/") not in listed]
    if not missing:
        return {"forced": [], "augmented": {}, "augmented_modules": []}

    phases = data.get("phases", [])
    if not phases:
        # No phase plan to attach to; create the single phase the files need.
        first_phase = {
            "phase": 1,
            "name": "Entry Points",
            "description": "Entry-point source files.",
            "modules": [],
            "depends_on_phases": [],
        }
        data["phases"] = phases = [first_phase]
    else:
        first_phase = min(phases, key=lambda p: p.get("phase", 0))

    modules = first_phase.setdefault("modules", [])
    if not modules:
        modules.append({
            "name": "entry_points",
            "description": "",
            "source_files": [],
        })
    module = modules[0]
    module.setdefault("source_files", []).extend(missing)
    note = "Includes required entry-point source file(s): " + ", ".join(missing) + "."
    module["description"] = _merge_descriptions(module.get("description", ""), note)

    with open(phases_json, "w") as f:
        json.dump(data, f, indent=2)
    return {
        "forced": missing,
        "augmented": {first_phase.get("phase"): list(missing)},
        "augmented_modules": [{
            "phase": first_phase.get("phase"),
            "module": module.get("name", ""),
            "added_files": list(missing),
        }],
    }


def _prepare_setup_workflow_file(proj_dir, work_dir, script_dir):
    """Copy the setup workflow markdown into ``work_dir`` and rewrite the
    ``source_files`` instruction so it points at the concrete project root,
    telling the agent to record paths relative to it (and not prefixed with the
    project directory name).
    """
    workflow_src = os.path.join(script_dir, "md", "workflow_setup_extract.md")
    workflow_dst = os.path.join(work_dir, "workflow_setup_extract.md")
    shutil.copy2(workflow_src, workflow_dst)
    proj_dir_abs = os.path.abspath(proj_dir)
    proj_dir_name = os.path.basename(proj_dir_abs)
    with open(workflow_dst, "r") as _f:
        md = _f.read()
    old = ("- `phases[*].modules[*].source_files` — relative paths from repo root of all source files "
           "that belong to this module.")
    new = (f"- `phases[*].modules[*].source_files` — relative paths from the project root "
           f"`{proj_dir_abs}` of all source files that belong to this module. "
           f"For example, a file at `{proj_dir_abs}/path/to/file.ext` must be recorded as "
           f"`path/to/file.ext`, NOT as `{proj_dir_name}/path/to/file.ext`.")
    md = md.replace(old, new, 1)
    with open(workflow_dst, "w") as _f:
        _f.write(md)


def _run_setup_extract(proj_dir, work_dir, script_dir, is_incremental=False,
                       resume=False, required_source_files=None):
    """Stage 1: prepare the setup workflow file and run opencode (with retries) to produce phases.json.

    ``required_source_files`` are paths the caller must have processed regardless
    of the agent's choices; any the agent omitted are force-listed into phases.json
    once the plan is otherwise finalized (see ``_ensure_source_files_in_phases``).
    """
    # On resume, reuse the existing phase plan instead of paying for the
    # setup_context LLM call again.
    _resume_skip_setup = resume and _setup_outputs_complete(work_dir)
    if _resume_skip_setup:
        print("[Pipeline] Stage 1/4: RESUME — all setup outputs found, skipping setup_context (reusing phase plan).")

    _prepare_setup_workflow_file(proj_dir, work_dir, script_dir)
    
    fm_reminder = ("IMPORTANT: The fm_agent/ directory is NOT part of the project source code. "
                    "It is a workspace for storing your output files only. "
                    "Do NOT include fm_agent/ paths in phases.json. "
                    "Do NOT modify any existing project files.")
    incremental_reminder = ("IMPORTANT: An existing fm_agent/phases.json from a previous run is already "
                            "present. Do NOT regenerate it from scratch. Instead, inspect the current "
                            "state of the source code and UPDATE the existing fm_agent/phases.json so it "
                            "reflects the current version of the code: add modules and source files that "
                            "are new, remove entries whose files no longer exist, and adjust phases as "
                            "needed. Preserve entries that are still accurate.")

    phases_json = os.path.join(work_dir, "phases.json")
    prev_mtime = os.path.getmtime(phases_json) if os.path.exists(phases_json) else None

    for attempt in range(1, OPENCODE_MAX_RETRIES + 1):
        if _resume_skip_setup:
            break
        if attempt == 1 and not resume:
            prompt = f"Follow the instructions in the attached file. {fm_reminder}"
        else:
            # Either resuming a previously interrupted run or retrying after a
            # failed attempt — in both cases some setup outputs may already
            # exist (e.g. phases.json or part of the domain-context files). Have
            # the agent inspect what's there and only fill the gaps instead of
            # regenerating everything and overwriting valid work.
            prompt = ("A previous setup attempt was interrupted and may have already produced some of the "
                      "required output files. Follow the instructions in the attached file, but FIRST "
                      "check the current progress in fm_agent/ (e.g. phases.json and the "
                      "spec_prompts/domain_context/ files). Keep any existing valid output as-is and only "
                      "generate the files that are missing or incomplete — do NOT regenerate or overwrite "
                      f"work that is already done. {fm_reminder}")
        if is_incremental:
            prompt = f"{prompt} {incremental_reminder}"
        prompt_file = os.path.join(proj_dir, "fm_agent", "workflow_setup_extract.md")
        if is_cli_backend_enabled():
            command = build_agent_command(
                model=OPENCODE_SETUP_MODEL,
                prompt=prompt,
                cwd=proj_dir,
                files=[prompt_file],
            )
        else:
            command = ["opencode", "run", "--model", f"{OPENCODE_MODEL_PROVIDER}/{OPENCODE_SETUP_MODEL}",
                       "--file", prompt_file, "--", prompt]
        try:
            run_opencode_traced(
                proj_dir=proj_dir,
                work_dir=work_dir,
                command=command,
                stage="setup_context",
                input_files=["fm_agent/workflow_setup_extract.md"],
                output_files=[
                    "fm_agent/phases.json",
                    "fm_agent/spec_prompts/domain_context/engine_overview.txt",
                ],
                summary=f"OpenCode setup context attempt {attempt}",
                metadata={"attempt": attempt},
            )
        except subprocess.CalledProcessError as e:
            logging.warning(f"Stage 1 attempt {attempt}: opencode exited with code {e.returncode}")

        # Validate that the agent produced the complete setup output set. In
        # incremental mode phases.json already exists; it may legitimately remain
        # byte-for-byte unchanged for same-file edits, so accept it when it still
        # covers the current source files, but only if the domain-context files
        # required by later spec prompts are present too.
        if os.path.exists(phases_json):
            phase_plan_ready = (
                not is_incremental
                or os.path.getmtime(phases_json) != prev_mtime
                or _phases_cover_current_sources(phases_json, proj_dir)
            )
            if phase_plan_ready and _setup_outputs_complete(work_dir):
                break

        failure = "update phases.json" if is_incremental else "produce phases.json"
        missing = (
            "phases.json/domain-context outputs were not updated"
            if is_incremental
            else "phases.json/domain-context outputs missing"
        )
        if attempt < OPENCODE_MAX_RETRIES:
            delay = 10
            print(
                f"[Pipeline] Stage 1 failed to {failure} (attempt {attempt}/{OPENCODE_MAX_RETRIES}). "
                f"Retrying in {delay}s..."
            )
            logging.warning(f"Stage 1 attempt {attempt} failed: {missing}. Retrying in {delay}s.")
            time.sleep(delay)
        else:
            print(
                f"[Pipeline] ERROR: Stage 1 failed after {OPENCODE_MAX_RETRIES} attempts. "
                f"{missing}. "
                f"Check {os.path.basename(proj_dir)}/fm_agent/trace/ for details."
            )
            sys.exit(1)

    # The setup agent may have omitted required files (e.g. an entry point that
    # looks like a test) from phases.json. Force them into the earliest phase's
    # first module FIRST, so the dedup pass sees them and the domain-context sync
    # regenerates that phase's types file from its final file set. Running it last
    # (after the sync) would leave the phase_NN_types.txt file the sync just
    # regenerated missing those types.
    ensure_changes = _ensure_source_files_in_phases(phases_json, required_source_files)
    forced = ensure_changes["forced"]
    if forced:
        print(f"[Pipeline] Forced {len(forced)} required source file(s) into phases.json: {', '.join(forced)}")

    # Deduplicate source files across phases. This only strips duplicate files (no
    # phase is renumbered or dropped), so the domain-context sync only needs to
    # regenerate the types file of any phase whose file set changed here or in the
    # ensure step above.
    dedup_changes = _deduplicate_phases(work_dir)

    # Modules whose source-file list changed — files force-added by the ensure step
    # above, or duplicates removed by dedup — may have descriptions that no longer
    # match the files they own. Refresh those descriptions before the domain-context
    # sync (which reads phases.json) runs.
    changed_modules = _collect_changed_modules(ensure_changes, dedup_changes)
    _update_module_description(proj_dir, work_dir, changed_modules)

    changed_phases = _collect_changed_phases(ensure_changes, dedup_changes)

    # Drop any modules/phases left empty by the steps above (e.g. a phase whose
    # only files were deduplicated away), renumber the survivors, and keep the
    # per-phase domain-context files in sync with the new numbering. Run semantic
    # domain-context regeneration after this so prompts see final phase numbers.
    phase_cleanup = _clean_empty_phase_module(work_dir)
    final_changed_phases = {
        phase_cleanup["renumbered"][phase_num]
        for phase_num in changed_phases
        if phase_num in phase_cleanup["renumbered"]
    }

    _sync_domain_context(
        proj_dir, work_dir, final_changed_phases, phase_cleanup=phase_cleanup
    )

    if not _setup_outputs_complete(work_dir):
        print(
            "[Pipeline] ERROR: Stage 1 setup outputs are incomplete after "
            "post-processing. Expected fm_agent/phases.json, "
            "fm_agent/spec_prompts/domain_context/engine_overview.txt, and one "
            "phase_NN_types.txt per phase."
        )
        sys.exit(1)

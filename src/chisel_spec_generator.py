"""Spec generation for Chisel (Scala) hardware designs.

This is the Chisel counterpart to :func:`main.run_pipeline`. It generates
verification-oriented module specs for a Chisel codebase and stops there — it
does NOT run the reasoner or bug validation.

It reuses the existing extraction / topdown-layer / batch-prompt machinery,
which is keyed off ``fm_agent/phases.json`` and the ``engine_overview.txt`` /
``phase_NN_types.txt`` domain-context filenames. The Chisel setup workflow
(``md/workflow_setup_extract_chisel.md``) instead emits ``fm_agent/groups.json``
(subsystems) and ``design_overview.txt`` / ``subsystem_NN_types.txt``, so a thin
bridge (:func:`_groups_to_phases`, :func:`_normalize_chisel_domain_context`)
translates the Chisel artifacts into the names the downstream tooling expects.

The three Chisel-specific prompt documents consumed here are:
  * ``md/workflow_setup_extract_chisel.md`` — codebase understanding + groups.json
  * ``md/system_prompt_chisel.md``          — Chisel module spec format rules
  * ``md/workflow_spec_chisel.md``          — per-batch spec generation workflow
"""

import os
import sys
import re
import json
import time
import shutil
import subprocess
import logging
import argparse

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
from src.file_utils import collect_file_names
from src.chisel_support import (
    _SUBMODULE_HEADING_RE,
    _chisel_info_ready,
    _chisel_markdown_ready,
    chisel_info_path,
    chisel_spec_path,
    chisel_spec_ready,
)
from src.extract import run_extraction
from src.generate_topdown_layers import generate_topdown_layers
from src.opencode_trace import (
    finish_opencode_trace,
    function_id_from_extracted_path,
    run_opencode_traced,
    start_opencode_traced,
)

# Reuse the pipeline helpers from main.py rather than duplicating them.
from main import (
    _clean_previous_run,
    _deduplicate_phases,
    _get_phase_files,
)


# ---------------------------------------------------------------------------
# Spec quality-checklist validation (see md/ref.md)
# ---------------------------------------------------------------------------
#
# Generated ``<ModuleName>_spec.md`` documents tag their functional groups,
# function points and check points with ``<FG-...>`` / ``<FC-...>`` / ``<CK-...>``
# coverage tags. :func:`validate_chisel_spec` enforces the machine-checkable
# rules of the quality checklist in ``md/ref.md`` so that a structurally broken
# spec is detected and regenerated instead of being accepted.

# A coverage tag: <FG-NAME>, <FC-NAME> or <CK-NAME>. The body group keeps the raw
# text after the prefix (e.g. "-ARITHMETIC") so malformed names — lowercase,
# braces, spaces, empty — can be reported rather than silently ignored.
_CHISEL_TAG_RE = re.compile(r"<(FG|FC|CK)\b([^>]*)>")
# A well-formed name is dash-joined uppercase/digit segments, e.g. -CACHE-READ.
_CHISEL_TAG_NAME_RE = re.compile(r"^-[A-Z0-9]+(?:-[A-Z0-9]+)*$")


def validate_chisel_spec(spec_path):
    """Check a generated ``<ModuleName>_spec.md`` against the quality checklist.

    Verifies the machine-checkable completeness and consistency items from
    ``md/ref.md``:

      * every ``<FG-*>`` functional group contains at least one ``<FC-*>``
        function point;
      * every ``<FC-*>`` function point contains at least one ``<CK-*>`` check
        point;
      * every tag matches the strict ``<PREFIX-NAME>`` format (dash-joined
        uppercase letters and digits), with no malformed tags;
      * names are unique among siblings — ``<FG-*>`` globally, ``<FC-*>`` within
        its group, ``<CK-*>`` within its function point;
      * ``<FG-*>`` and ``<FC-*>`` tags sit on their own line, not appended to a
        heading;
      * the mandatory ``<FG-API>`` group is present.

    The subjective checklist items (prose clarity, scenario coverage, whether
    test data can be designed) are not machine-checkable and are left to review.

    Returns ``(is_valid, errors)`` where ``errors`` is a list of human-readable
    strings (empty when valid).
    """
    try:
        with open(spec_path, "r", errors="replace") as f:
            text = f.read()
    except OSError as exc:
        return False, [f"cannot read spec file {spec_path}: {exc}"]

    errors = []
    groups = []           # [{name, line, fcs: [{name, line, cks: [name, ...]}]}]
    fg_names = set()
    current_fg = None
    current_fc = None

    for lineno, raw in enumerate(text.splitlines(), start=1):
        stripped = raw.strip()
        for m in _CHISEL_TAG_RE.finditer(raw):
            kind, body, full = m.group(1), m.group(2), m.group(0)
            if not _CHISEL_TAG_NAME_RE.match(body):
                errors.append(
                    f"line {lineno}: malformed {kind} tag {full!r}; expected "
                    f"<{kind}-NAME> with dash-joined uppercase letters and digits"
                )
                continue
            name = body[1:]  # drop the leading '-'
            alone = stripped == full
            if kind == "FG":
                if not alone:
                    errors.append(f"line {lineno}: <FG-{name}> must be on its own line, "
                                  f"not embedded in {stripped!r}")
                if name in fg_names:
                    errors.append(f"line {lineno}: duplicate functional-group tag <FG-{name}>")
                fg_names.add(name)
                current_fg = {"name": name, "line": lineno, "fcs": []}
                groups.append(current_fg)
                current_fc = None
            elif kind == "FC":
                if not alone:
                    errors.append(f"line {lineno}: <FC-{name}> must be on its own line, "
                                  f"not embedded in {stripped!r}")
                if current_fg is None:
                    errors.append(f"line {lineno}: function-point tag <FC-{name}> "
                                  f"appears before any <FG-*> group")
                    continue
                if any(fc["name"] == name for fc in current_fg["fcs"]):
                    errors.append(f"line {lineno}: duplicate function-point tag <FC-{name}> "
                                  f"in group <FG-{current_fg['name']}>")
                current_fc = {"name": name, "line": lineno, "cks": []}
                current_fg["fcs"].append(current_fc)
            else:  # CK
                if current_fc is None:
                    errors.append(f"line {lineno}: check-point tag <CK-{name}> "
                                  f"appears before any <FC-*> function point")
                    continue
                if name in current_fc["cks"]:
                    errors.append(f"line {lineno}: duplicate check-point tag <CK-{name}> "
                                  f"in function point <FC-{current_fc['name']}>")
                current_fc["cks"].append(name)

    if not groups:
        errors.append("no <FG-*> functional groups found")
    if "API" not in fg_names:
        errors.append("missing mandatory <FG-API> functional group")
    for g in groups:
        if not g["fcs"]:
            errors.append(f"functional group <FG-{g['name']}> (line {g['line']}) "
                          f"has no <FC-*> function point")
        for fc in g["fcs"]:
            if not fc["cks"]:
                errors.append(f"function point <FC-{fc['name']}> (line {fc['line']}) "
                              f"has no <CK-*> check point")

    return (not errors), errors


def _remove_incomplete_chisel_outputs(module_path, expects_submodules=False):
    """Delete spec/info outputs that exist but are incomplete (e.g. truncated).

    The retry prompt tells the agent to only generate outputs for modules that
    do not yet have both output files, so an incomplete file left in place
    would make every retry skip the module. Complete files (including a small
    legal ``(no submodules)`` info document for actual leaf modules) are kept.
    """
    def _info_ready(path):
        return _chisel_info_ready(path, allow_no_submodules=not expects_submodules)

    checks = (
        (chisel_spec_path(module_path), _chisel_markdown_ready),
        (chisel_info_path(module_path), _info_ready),
    )
    for path, ready in checks:
        if os.path.exists(path) and not ready(path):
            logging.warning(
                "Removing incomplete Chisel output %s so it is regenerated.", path
            )
            try:
                os.remove(path)
            except OSError as exc:
                logging.warning("Could not remove incomplete output %s: %s", path, exc)


def _get_pending_batches_chisel(batches, proj_dir, expects_submodules=frozenset()):
    """Return batches that still have at least one module without a complete,
    valid spec/info output.

    Chisel specs are emitted as standalone ``<ModuleName>_spec.md`` documents and
    submodule-expectation ``<ModuleName>_info.md`` documents next to the extracted
    module file, so readiness is checked via :func:`chisel_spec_ready` rather than
    the embedded ``[SPEC]`` marker used by the generic pipeline's
    ``_get_pending_batches``.

    Beyond presence, each ready ``_spec.md`` is validated against the quality
    checklist with :func:`validate_chisel_spec`. Incomplete (truncated) outputs
    and specs that fail validation are deleted so the retry loop regenerates
    them instead of skipping modules whose output files merely exist.

    ``expects_submodules`` lists the function rel-paths whose call graph shows
    submodules: for those, a ``(no submodules)`` info stub is rejected (and
    removed) instead of accepted, so the children do not lose their caller
    expectations downstream.
    """
    pending = []
    for batch in batches:
        batch_pending = False
        validation_errors = []
        for func_rel in batch.get("functions", []):
            module_path = os.path.join(proj_dir, func_rel)
            expects = func_rel in expects_submodules
            if not chisel_spec_ready(module_path, expects_submodules=expects):
                info_path = chisel_info_path(module_path)
                if expects and os.path.exists(info_path):
                    try:
                        with open(info_path, "r", errors="replace") as f:
                            info_text = f.read()
                    except OSError:
                        info_text = ""
                    if ("(no submodules)" in info_text
                            or _SUBMODULE_HEADING_RE.search(info_text) is None):
                        validation_errors.append(
                            f"{os.path.basename(info_path)}: this module instantiates "
                            f"other extracted modules — the info file must contain one "
                            f"'# Submodule: <name>' entry per instantiated submodule "
                            f"and must not claim '(no submodules)'"
                        )
                _remove_incomplete_chisel_outputs(
                    module_path, expects_submodules=expects
                )
                batch_pending = True
                continue
            spec_path = chisel_spec_path(module_path)
            is_valid, spec_errors = validate_chisel_spec(spec_path)
            if not is_valid:
                logging.warning(
                    "Chisel spec %s failed quality-checklist validation; removing it "
                    "so it is regenerated. First issues: %s",
                    spec_path, "; ".join(spec_errors[:5]),
                )
                try:
                    os.remove(spec_path)
                except OSError as exc:
                    logging.warning("Could not remove invalid spec %s: %s", spec_path, exc)
                validation_errors.append(
                    f"{os.path.basename(spec_path)}: " + "; ".join(spec_errors[:3])
                )
                batch_pending = True
        # Exposed to the retry prompt so the LLM knows WHAT failed the
        # checklist — without feedback regeneration rarely converges. The
        # feedback must survive the retry loop's pre-launch rescan (which runs
        # AFTER the offending files were deleted), so only overwrite it when
        # new errors surface, and clear it once the batch completes.
        if validation_errors:
            batch["validation_errors"] = validation_errors
        if batch_pending:
            pending.append(batch)
        else:
            batch["validation_errors"] = []
    return pending


def _load_json_file(path, description):
    """Load JSON with a path-specific error message."""
    try:
        with open(path, "r") as f:
            return json.load(f)
    except FileNotFoundError as exc:
        raise FileNotFoundError(f"{description} not found at {path}") from exc
    except json.JSONDecodeError as exc:
        raise ValueError(f"{description} at {path} is not valid JSON: {exc}") from exc


def _groups_json_is_usable(groups_path):
    """Return True when groups.json is complete enough to resume from."""
    try:
        groups = _load_json_file(groups_path, "groups.json")
    except (OSError, ValueError) as exc:
        logging.warning("Cannot resume from groups.json: %s", exc)
        return False

    subsystems = groups.get("subsystems")
    if not isinstance(subsystems, list) or not subsystems:
        logging.warning("Cannot resume from groups.json: missing non-empty subsystems list.")
        return False

    for idx, sub in enumerate(subsystems):
        if not isinstance(sub, dict):
            logging.warning("Cannot resume from groups.json: subsystem %s is not an object.", idx)
            return False
        if sub.get("subsystem") is None:
            logging.warning("Cannot resume from groups.json: subsystem %s is missing subsystem id.", idx)
            return False
        if not isinstance(sub.get("source_groups", []), list):
            logging.warning("Cannot resume from groups.json: subsystem %s source_groups is not a list.", idx)
            return False

    return True


# ---------------------------------------------------------------------------
# Chisel -> generic-pipeline artifact bridge
# ---------------------------------------------------------------------------

def _as_int(value, field_name):
    """Return ``value`` as int, raising a useful error for malformed LLM JSON."""
    try:
        return int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"groups.json field {field_name} must be an integer, got {value!r}") from exc


def _normalize_groups_source_paths(work_dir, proj_dir):
    """Rewrite ``groups.json`` ``source_files`` so they resolve under ``proj_dir``.

    The setup workflow asks the agent for paths "relative to the repo root", and
    the agent anchors them on the git/sbt toplevel it discovers. That toplevel
    can sit ABOVE ``proj_dir`` when the tool is pointed at a subdirectory — e.g.
    ``proj_dir=.../XSCache/src/main/scala`` while the agent writes
    ``src/main/scala/Foo.scala`` (correct relative to ``.../XSCache``). Joining
    those against ``proj_dir`` double-prefixes and every file "vanishes".

    Reconcile the two bases up front, at the source of truth, so the derived
    ``phases.json``, extraction, and topdown-layer lookups all inherit paths that
    resolve. Each entry is rewritten to a clean ``proj_dir``-relative path by, in
    order: using it as-is if it already resolves; stripping any leading run that
    duplicates the tail of ``proj_dir``; or relativizing an absolute path. Entries
    that still cannot be resolved are left untouched and returned so the caller can
    surface them instead of silently dropping modules.

    Returns the list of source paths that could not be resolved.
    """
    groups_path = os.path.join(work_dir, "groups.json")
    if not os.path.exists(groups_path):
        return []

    groups = _load_json_file(groups_path, "groups.json")

    proj_dir = os.path.normpath(proj_dir)
    proj_parts = proj_dir.split(os.sep)

    def _resolve(src_rel):
        if not src_rel:
            return None
        norm = os.path.normpath(src_rel)
        if os.path.isabs(norm):
            # Absolute path: express relative to proj_dir if it lives underneath.
            if os.path.exists(norm):
                rel = os.path.relpath(norm, proj_dir)
                if not rel.startswith(os.pardir + os.sep) and rel != os.pardir:
                    return rel
            return None
        if os.path.exists(os.path.join(proj_dir, norm)):
            return norm
        # Strip a leading run of src_rel that duplicates the tail of proj_dir
        # (e.g. proj_dir=.../src/main/scala, src=src/main/scala/x -> x).
        rel_parts = norm.split(os.sep)
        for k in range(min(len(proj_parts), len(rel_parts)), 0, -1):
            if proj_parts[-k:] == rel_parts[:k] and rel_parts[k:]:
                cand = os.path.join(*rel_parts[k:])
                if os.path.exists(os.path.join(proj_dir, cand)):
                    return cand
        return None

    unresolved = []
    changed = False
    for sub in groups.get("subsystems", []):
        for grp in sub.get("source_groups", []):
            new_files = []
            for sf in grp.get("source_files", []):
                resolved = _resolve(sf)
                if resolved is None:
                    unresolved.append(sf)
                    new_files.append(sf)  # keep original; surfaced to caller
                else:
                    changed = changed or (resolved != sf)
                    new_files.append(resolved)
            grp["source_files"] = new_files

    if changed:
        with open(groups_path, "w") as f:
            json.dump(groups, f, indent=2)

    return unresolved


def _groups_to_phases(work_dir):
    """Translate ``fm_agent/groups.json`` (subsystems) into the ``phases.json``
    schema the extraction / layer / batch tooling expects.

    Each subsystem becomes a phase and each source group becomes a module:
      subsystem            -> phase
      subsystem.name       -> phase.name
      source_group         -> module (name + source_files preserved verbatim)
      depends_on_subsystems-> depends_on_phases
    """
    groups_path = os.path.join(work_dir, "groups.json")
    groups = _load_json_file(groups_path, "groups.json")

    phases = []
    for sub in groups.get("subsystems", []):
        phase_num = _as_int(sub.get("subsystem"), "subsystems[*].subsystem")
        modules = []
        for grp in sub.get("source_groups", []):
            modules.append({
                "name": grp.get("name", ""),
                "source_files": grp.get("source_files", []),
            })
        phases.append({
            "phase": phase_num,
            "name": sub.get("name", f"subsystem_{phase_num}"),
            "modules": modules,
            "depends_on_phases": [
                _as_int(dep, "subsystems[*].depends_on_subsystems[*]")
                for dep in sub.get("depends_on_subsystems", [])
            ],
        })

    out = {
        "project": groups.get("project", os.path.basename(os.path.dirname(work_dir))),
        "languages": groups.get("languages", ["chisel"]),
        "file_extensions": groups.get("file_extensions", ["scala"]),
        "phases": phases,
    }
    with open(os.path.join(work_dir, "phases.json"), "w") as f:
        json.dump(out, f, indent=2)


def _normalize_chisel_domain_context(work_dir):
    """Alias Chisel domain-context files to the names the batch prompt builder
    reads (``engine_overview.txt`` and ``phase_NN_types.txt``).

    The Chisel setup workflow writes ``design_overview.txt`` and
    ``subsystem_NN_types.txt``; copy them to the expected names if they are not
    already present so :mod:`generate_batch_prompts` finds them.
    """
    ctx_dir = os.path.join(work_dir, "spec_prompts", "domain_context")
    if not os.path.isdir(ctx_dir):
        return

    design = os.path.join(ctx_dir, "design_overview.txt")
    engine = os.path.join(ctx_dir, "engine_overview.txt")
    if os.path.exists(design) and not os.path.exists(engine):
        shutil.copy2(design, engine)

    subsystem_type_files = {}
    for fname in os.listdir(ctx_dir):
        m = re.match(r"subsystem_(\d+)_types\.txt$", fname)
        if not m:
            continue
        subsystem_num = int(m.group(1))
        subsystem_type_files[subsystem_num] = fname
        dst = os.path.join(ctx_dir, f"phase_{subsystem_num:02d}_types.txt")
        if not os.path.exists(dst):
            shutil.copy2(os.path.join(ctx_dir, fname), dst)

    # If phase deduplication removed empty/duplicate subsystems, phases may be
    # renumbered. Match the remaining phase names back to groups.json so the
    # generic batch prompt generator still finds phase_NN_types.txt.
    phases_path = os.path.join(work_dir, "phases.json")
    groups_path = os.path.join(work_dir, "groups.json")
    if not (os.path.exists(phases_path) and os.path.exists(groups_path)):
        return

    try:
        phases = _load_json_file(phases_path, "phases.json").get("phases", [])
        subsystems = _load_json_file(groups_path, "groups.json").get("subsystems", [])
    except (OSError, ValueError):
        return

    subsystem_by_name = {
        sub.get("name"): _as_int(sub.get("subsystem"), "subsystems[*].subsystem")
        for sub in subsystems
        if sub.get("name")
    }
    for phase in phases:
        old_subsystem = subsystem_by_name.get(phase.get("name"))
        if old_subsystem is None:
            continue
        src_fname = subsystem_type_files.get(old_subsystem)
        if not src_fname:
            continue
        phase_num = _as_int(phase.get("phase"), "phases[*].phase")
        dst = os.path.join(ctx_dir, f"phase_{phase_num:02d}_types.txt")
        if phase_num != old_subsystem or not os.path.exists(dst):
            shutil.copy2(os.path.join(ctx_dir, src_fname), dst)


def _has_scala_source(proj_dir):
    """Check whether proj_dir contains at least one Chisel (.scala) source file."""
    for root, dirs, files in os.walk(proj_dir):
        # Skip hidden dirs and common non-source dirs (mirrors _has_source_code).
        dirs[:] = [d for d in dirs if not d.startswith('.') and d not in
                   {'node_modules', '__pycache__', 'venv', '.venv', 'fm_agent'}]
        for fname in files:
            if fname.endswith('.scala'):
                return True
    return False


def run_chisel_spec_generation(proj_dir, resume=False):
    """Generate verification-oriented specs for a Chisel (Scala) design.

    Mirrors :func:`main.run_pipeline` but is Chisel-specific and spec-only: it
    skips the reasoner and bug validation entirely.

    When ``resume`` is True, the existing ``fm_agent/`` workspace is preserved
    instead of wiped: the design-understanding LLM stage is skipped if
    ``groups.json`` already exists, and Stage 5 only generates specs for modules
    that do not yet have valid spec/info files (via :func:`chisel_spec_ready`).
    This lets an interrupted run continue without regenerating completed specs.
    """
    if not os.path.isdir(proj_dir):
        print(f"[Chisel] ERROR: proj_dir does not exist or is not a directory: {proj_dir}")
        sys.exit(1)

    if not _has_scala_source(proj_dir):
        print(f"[Chisel] ERROR: No Scala (.scala) source files found in {proj_dir}.")
        sys.exit(1)

    work_dir = os.path.join(proj_dir, "fm_agent")
    input_dir = os.path.join(work_dir, "extracted_functions")
    repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    md_dir = os.path.join(repo_root, "md")
    src_dir = os.path.join(repo_root, "src")

    # Clean files from the previous run, unless resuming an interrupted run.
    groups_path = os.path.join(work_dir, "groups.json")
    resume_setup = resume and os.path.exists(groups_path) and _groups_json_is_usable(groups_path)
    if resume:
        if resume_setup:
            print("[Chisel] Resume: preserving existing fm_agent/ workspace "
                  "and reusing groups.json.")
        elif os.path.exists(groups_path):
            print("[Chisel] Resume requested but groups.json is missing or incomplete; "
                  "rerunning setup in the existing fm_agent/ workspace.")
        else:
            print("[Chisel] Resume requested but no groups.json found; "
                  "starting setup in the existing fm_agent/ workspace.")
    else:
        _clean_previous_run(work_dir)
    os.makedirs(work_dir, exist_ok=True)

    # --- Stage 1: Understand the design and write groups.json + domain context ---
    if resume_setup:
        print("[Chisel] Stage 1/4: Reusing existing groups.json (resume).")
    else:
        print("[Chisel] Stage 1/4: Understanding design and extracting modules ...")
    workflow_src = os.path.join(md_dir, "workflow_setup_extract_chisel.md")
    workflow_dst = os.path.join(work_dir, "workflow_setup_extract_chisel.md")
    shutil.copy2(workflow_src, workflow_dst)

    fm_reminder = ("IMPORTANT: The fm_agent/ directory is NOT part of the project source code. "
                   "It is a workspace for storing your output files only. "
                   "Do NOT include fm_agent/ paths in groups.json. "
                   "Do NOT modify any existing project files.")
    for attempt in range(1, OPENCODE_MAX_RETRIES + 1):
        if resume_setup:
            # groups.json already exists from a prior run; skip the LLM setup
            # so the existing subsystem/module structure (and the specs already
            # generated against it) stay consistent.
            break
        if attempt == 1 and not os.path.exists(groups_path):
            prompt = f"Follow the instructions in the attached file. {fm_reminder}"
        else:
            prompt = ("Continue where you left off. The previous run was interrupted or left incomplete output. "
                      "If fm_agent/groups.json exists but is malformed or incomplete, rewrite it. "
                      f"Check what has already been done and only complete the remaining steps. {fm_reminder}")
        command = ["opencode", "run", "--model", f"{OPENCODE_MODEL_PROVIDER}/{OPENCODE_SETUP_MODEL}",
                   "--file", os.path.join(work_dir, "workflow_setup_extract_chisel.md"), "--", prompt]
        try:
            run_opencode_traced(
                proj_dir=proj_dir,
                work_dir=work_dir,
                command=command,
                stage="setup_context",
                input_files=["fm_agent/workflow_setup_extract_chisel.md"],
                output_files=[
                    "fm_agent/groups.json",
                    "fm_agent/spec_prompts/domain_context/design_overview.txt",
                ],
                summary=f"OpenCode Chisel setup context attempt {attempt}",
                metadata={"attempt": attempt},
            )
        except subprocess.CalledProcessError as e:
            logging.warning(f"Stage 2 attempt {attempt}: opencode exited with code {e.returncode}")

        if _groups_json_is_usable(groups_path):
            break

        if attempt < OPENCODE_MAX_RETRIES:
            delay = 10
            print(
                f"[Chisel] Stage 2 failed to produce groups.json (attempt {attempt}/{OPENCODE_MAX_RETRIES}). "
                f"Retrying in {delay}s..."
            )
            logging.warning(f"Stage 2 attempt {attempt} failed: groups.json missing. Retrying in {delay}s.")
            time.sleep(delay)
        else:
            print(
                f"[Chisel] ERROR: Stage 2 failed after {OPENCODE_MAX_RETRIES} attempts. "
                f"groups.json is missing or incomplete. "
                f"Check {os.path.basename(proj_dir)}/fm_agent/trace/ for details."
            )
            sys.exit(1)

    # Reconcile agent-written source paths (anchored on the repo/git toplevel the
    # agent discovered) with proj_dir before anything joins them. Without this, a
    # proj_dir pointed at a subdirectory double-prefixes every path and extraction
    # silently finds nothing.
    unresolved = _normalize_groups_source_paths(work_dir, proj_dir)
    if unresolved:
        print(
            f"[Chisel] WARNING: {len(unresolved)} source path(s) in groups.json do not "
            f"resolve under {proj_dir} and were left as-is; extraction will skip them. "
            f"First few: {unresolved[:5]}"
        )

    # Bridge Chisel artifacts -> the generic-pipeline schema.
    _groups_to_phases(work_dir)

    # Deduplicate source files across phases before aliasing subsystem context.
    # Otherwise phase_NN_types.txt can point at a subsystem that was removed and
    # then block the correct renumbered alias from being copied later.
    _deduplicate_phases(work_dir)
    _normalize_chisel_domain_context(work_dir)

    # Run module extraction (Chisel/Scala support is registered in extract.py)
    print("[Chisel] Extracting modules from source files...")
    run_extraction(proj_dir, work_dir=work_dir, force=True, verbose=True)

    # Copy the Chisel system prompt and batch helper scripts into spec_prompts/
    spec_prompts_dir = os.path.join(work_dir, "spec_prompts")
    os.makedirs(spec_prompts_dir, exist_ok=True)
    shutil.copy2(
        os.path.join(md_dir, "system_prompt_chisel.md"),
        os.path.join(spec_prompts_dir, "system_prompt.md"),
    )
    shutil.copy2(
        os.path.join(src_dir, "generate_batch_prompts.py"),
        os.path.join(spec_prompts_dir, "generate_batch_prompts.py"),
    )

    # Re-alias domain context in case extraction recreated spec_prompts layout
    _normalize_chisel_domain_context(work_dir)

    print("[Chisel] Stage 2/4: Collecting file list...")
    file_list = collect_file_names(input_dir, os.path.join(work_dir, "fm_agent_file_list.json"))

    if not file_list:
        print("[Chisel] No modules found to spec. Skipping spec generation.")
        return

    # --- Stage 3: Generate topdown layers ---
    print("[Chisel] Stage 3/4: Generating topdown layers...")
    phases_data = _load_json_file(os.path.join(work_dir, "phases.json"), "phases.json")
    generate_topdown_layers(work_dir)

    # --- Stage 4: Execute spec generation (per phase, per layer) ---
    print("[Chisel] Stage 4/4: Generating Chisel module specs...")
    batch_md_src = os.path.join(md_dir, "workflow_spec_chisel.md")
    batch_md_dst = os.path.join(work_dir, "workflow_spec_chisel.md")
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

        # Determine how many layers this phase has
        layers_json_path = os.path.join(
            spec_prompts_dir, f"phase_{phase_num:02d}_topdown_layers.json"
        )
        if not os.path.exists(layers_json_path):
            generate_topdown_layers(work_dir, [phase_num])
        layers_data = _load_json_file(layers_json_path, f"topdown layers for subsystem {phase_num}")
        total_layers = layers_data.get("total_layers", 1)

        # Modules whose call graph shows submodules must not satisfy readiness
        # with a '(no submodules)' info stub. Keyed both by the proj_dir-
        # relative path (batch functions) and the input_dir-relative path
        # (layer_files readiness counts).
        _with_subs = {
            fn["file"]
            for layer in layers_data.get("layers", [])
            for fn in layer.get("functions", [])
            if fn.get("all_callees")
        }
        expects_submodules = {
            os.path.relpath(os.path.join(work_dir, f), proj_dir) for f in _with_subs
        }
        expects_rel = {
            os.path.relpath(os.path.join(work_dir, f), input_dir) for f in _with_subs
        }

        batch_dir = os.path.join(
            spec_prompts_dir,
            f"batch_prompts_{project_name}_phase{phase_num:02d}",
        )

        for layer_idx in range(total_layers):
            print(f"[Chisel] Stage 4/4: Subsystem {phase_num}/{num_phases} — {phase_name}, "
                  f"Layer {layer_idx}/{total_layers - 1}")

            # Generate batch prompts for this layer
            subprocess.run(
                ["python3", "fm_agent/spec_prompts/generate_batch_prompts.py",
                 "--phase", str(phase_num), "--layers", str(layer_idx)],
                cwd=proj_dir, check=True,
            )

            # Read manifest
            manifest_path = os.path.join(batch_dir, "manifest.json")
            manifest = _load_json_file(manifest_path, f"batch manifest for subsystem {phase_num} layer {layer_idx}")
            all_batches = manifest.get("batches", [])

            if not all_batches:
                logging.info(f"Subsystem {phase_num} Layer {layer_idx}: no batches, skipping.")
                continue

            batch_rel_dir = os.path.relpath(batch_dir, proj_dir)

            # Build a stable, de-duplicated file list for this layer from the manifest.
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
                # Find batches with unspecced modules
                pending_batches = _get_pending_batches_chisel(all_batches, proj_dir, expects_submodules=expects_submodules)
                if not pending_batches:
                    layer_complete = True
                    break

                ready_before = sum(
                    1 for rel in layer_files
                    if chisel_spec_ready(os.path.join(input_dir, rel), expects_submodules=(rel in expects_rel))
                )

                # Launch one opencode process per pending batch, but cap how many
                # run at once. Firing a whole layer simultaneously (dozens of
                # batches) overwhelms the opencode server and LLM endpoint
                # ("Session not found", 5xx, rate limits) and leaves partial
                # outputs; a bounded sliding window keeps throughput while staying
                # within what the backend can handle.
                def _start_batch(batch_info):
                    batch_file = batch_info["file"]
                    batch_prompt_rel = os.path.join(batch_rel_dir, batch_file)
                    function_files = batch_info.get("functions", [])
                    function_ids = [
                        function_id_from_extracted_path(func_rel)
                        for func_rel in function_files
                    ]
                    # Specs and info are standalone .md files, not the .scala
                    # sources, so the trace records both Markdown outputs.
                    spec_output_files = []
                    for func_rel in function_files:
                        spec_output_files.extend([
                            chisel_spec_path(func_rel),
                            chisel_info_path(func_rel),
                        ])
                    fm_reminder = ("IMPORTANT: fm_agent/ is your output workspace, not project source. "
                                   "Do NOT modify any existing project files.")
                    checklist_note = ""
                    failed = batch_info.get("validation_errors") or []
                    if failed:
                        checklist_note = (
                            " WARNING: the following previously generated specs FAILED the "
                            "quality checklist and were deleted — regenerate them and fix "
                            "exactly these issues (re-read the Coverage Tags rules in "
                            "fm_agent/spec_prompts/system_prompt.md: every tag is a plain "
                            "<FG-NAME>/<FC-NAME>/<CK-NAME> on its own line, sibling tag names "
                            "must be unique, and the <FG-API> group is mandatory): "
                            + " | ".join(failed)
                        )
                    if attempt == 1 and not resume:
                        prompt = (
                            f"Process the batch prompt file at {batch_prompt_rel}. "
                            f"Read it and fm_agent/spec_prompts/system_prompt.md, "
                            f"generate verification-oriented Chisel module spec and info files for each module listed, "
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
                               "--file", os.path.join(work_dir, "workflow_spec_chisel.md"),
                               "--", prompt]
                    return start_opencode_traced(
                        proj_dir=proj_dir,
                        work_dir=work_dir,
                        command=command,
                        stage="spec_generation",
                        function_ids=function_ids,
                        input_files=[
                            "fm_agent/workflow_spec_chisel.md",
                            batch_prompt_rel,
                            "fm_agent/spec_prompts/system_prompt.md",
                        ],
                        output_files=spec_output_files,
                        summary=f"OpenCode Chisel spec generation for {batch_file}",
                        metadata={
                            "attempt": attempt,
                            "phase": phase_num,
                            "layer": layer_idx,
                            "batch_file": batch_file,
                        },
                    )

                max_concurrency = max(1, OPENCODE_MAX_CONCURRENCY)
                queue = list(pending_batches)
                running = []  # in-flight trace records
                launched = 0
                try:
                    while queue or running:
                        # Top up the window with new processes.
                        while queue and len(running) < max_concurrency:
                            trace_record = _start_batch(queue.pop(0))
                            running.append(trace_record)
                            launched += 1
                        # Wait until at least one in-flight process exits, then reap
                        # every finished one so the window frees up promptly.
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

                # Check if any modules in this layer received standalone spec/info outputs
                ready_after = sum(
                    1 for rel in layer_files
                    if chisel_spec_ready(os.path.join(input_dir, rel), expects_submodules=(rel in expects_rel))
                )
                if not _get_pending_batches_chisel(all_batches, proj_dir, expects_submodules=expects_submodules):
                    layer_complete = True
                    break

                if ready_after > ready_before:
                    # Partial progress — retry remaining batches without delay
                    logging.info(
                        f"Subsystem {phase_num} Layer {layer_idx} attempt {attempt}: "
                        f"{ready_after}/{len(layer_files)} complete spec/info outputs ready, retrying remaining batches"
                    )
                    if attempt < OPENCODE_MAX_RETRIES:
                        continue

                if attempt < OPENCODE_MAX_RETRIES:
                    delay = 10
                    print(
                        f"[Chisel] Stage 5 Subsystem {phase_num} Layer {layer_idx} produced no complete spec/info outputs "
                        f"(attempt {attempt}/{OPENCODE_MAX_RETRIES}). "
                        f"Retrying in {delay}s..."
                    )
                    logging.warning(
                        f"Stage 5 Subsystem {phase_num} Layer {layer_idx} attempt {attempt} failed: "
                        f"no complete spec/info outputs generated. Retrying in {delay}s."
                    )
                    time.sleep(delay)
                else:
                    print(
                        f"[Chisel] ERROR: Stage 5 Subsystem {phase_num} Layer {layer_idx} failed "
                        f"after {OPENCODE_MAX_RETRIES} attempts with "
                        f"{ready_after}/{len(layer_files)} complete spec/info outputs. "
                        f"Check {os.path.basename(proj_dir)}/fm_agent/trace/ for details, "
                        f"then rerun with --resume."
                    )
                    sys.exit(1)

            if not layer_complete and _get_pending_batches_chisel(all_batches, proj_dir, expects_submodules=expects_submodules):
                ready_count = sum(
                    1 for rel in layer_files
                    if chisel_spec_ready(os.path.join(input_dir, rel), expects_submodules=(rel in expects_rel))
                )
                print(
                    f"[Chisel] ERROR: Stage 5 Subsystem {phase_num} Layer {layer_idx} "
                    f"stopped with {ready_count}/{len(layer_files)} complete spec/info outputs. "
                    f"Run again with --resume after fixing the underlying OpenCode error."
                )
                sys.exit(1)

    print("[Chisel] Done. Generated Chisel module spec/info files only; skipped reasoning and bug validation.")

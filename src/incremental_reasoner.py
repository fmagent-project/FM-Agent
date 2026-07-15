import os
import sys
import glob
import json
import time
import shutil
import logging
import subprocess
import tempfile
import concurrent.futures
from datetime import datetime
from pathlib import Path

from config import (
    OPENCODE_SETUP_MODEL,
    OPENCODE_MAX_RETRIES,
    MAX_WORKERS,
    LLM_MODEL,
)
from .extract import (
    EXT_TO_LANG,
    LANG_CONFIG,
    extract_functions_from_file,
    run_extraction,
)
from .generate_topdown_layers import (
    _build_call_graph,
    _collect_phase_files,
    _file_to_fqn,
    _load_phases,
    generate_topdown_layers,
)
from .call_graph_edges import load_call_edges
from .file_utils import (
    is_file_ready,
    collect_file_names,
    _is_test_file,
    _is_under_submodules,
    _get_all_phase_files,
    _is_metadata_sidecar,
    _write_file_names,
    _is_valid_spec_json,
    _is_valid_info_json,
)
from .generate_batch_prompts import (
    extract_callee_spec_from_info,
    extract_info_block,
    extract_spec_block,
)
from .opencode_trace import run_opencode_traced
from .llm_client import _llm_provider_client, _llm_json_call, build_llm_cli_command
from .scope import _parse_issue_signals, rank_functions_in_file
from .languages.codegraph import try_codegraph_init
from .verification import _verify_single_file, _validate_single_bug, _generate_validation_summary, EXT_TO_LANG as _VERIFY_EXT_TO_LANG
from .domain_knowledge import (
    format_domain_knowledge_bullets,
    list_staged_domain_knowledge_relpaths,
    load_staged_domain_knowledge_text,
    stage_domain_knowledge_files,
)


class _StdoutTee:
    """
    A write-through stdout replacement that mirrors everything printed to the console into
    the pipeline log file as well.

    The incremental pipeline calls shared helpers — function re-extraction
    (run_extraction's verbose SKIP/WRITE/"Extraction complete" lines), top-down layer
    generation ("[TopdownLayers] ..."), scope ranking (rank_functions_in_file's per-file
    ranking tables), and the setup-extract retry/error messages — that report progress with
    bare print() rather than logging.*. Those lines reach stdout but, unlike every
    logging.* record, are NOT captured by the FileHandler, so they are lost from the on-disk
    log. Wrapping sys.stdout in this tee routes each print() to both the real console stream
    and the log file, so the log file holds the complete run output.
    """

    def __init__(self, console, log_stream):
        self._console = console
        self._log_stream = log_stream

    def write(self, data):
        self._console.write(data)
        # The log stream is owned by the logging FileHandler; at interpreter shutdown (or if
        # the handler is closed) it may already be closed, so tolerate that rather than raise
        # — the console copy still gets through.
        if not self._log_stream.closed:
            self._log_stream.write(data)
        return len(data)

    def flush(self):
        self._console.flush()
        if not self._log_stream.closed:
            self._log_stream.flush()

    def __getattr__(self, name):
        # Delegate everything else (isatty, fileno, encoding, ...) to the real console
        # stream. _console is a real attribute, so this never recurses.
        return getattr(self._console, name)


def _setup_incremental_logging(work_dir):
    """
    Route the incremental pipeline's progress output to a log file AND stdout.

    Configures the root logger with a FileHandler at
    work_dir/incremental_<YYYYmmdd_HHMMSS>.log (the timestamp is taken when this is called,
    so each pipeline run writes its own log file rather than overwriting the previous one) so
    every logging.* call in this module — the stage-by-stage progress that used to be
    print()ed, plus the existing warning/error/exception records — is preserved on disk. A
    second StreamHandler mirrors the same records to stdout, so callers that capture the
    subprocess output (e.g. the benchmark runner, which greps stdout for the final
    "confirmed bugs in N function(s)" marker) can see the result without reading the log
    file. The log file is wiped by the runner's per-trial revert, so stdout is the only
    place the result reliably survives. Any handlers a previous call (or import) installed
    are replaced, so invoking the pipeline repeatedly in one process does not duplicate log
    lines.

    Additionally, sys.stdout is wrapped in an _StdoutTee so the bare print() progress
    emitted by the shared helpers this pipeline calls (run_extraction's verbose output,
    generate_topdown_layers, rank_functions_in_file, and _run_setup_extract's retry/error
    messages) is mirrored into the same log file rather than only reaching the console. The
    console StreamHandler is bound to the underlying console stream (not the tee), so
    logging.* records are written to the file exactly once. Returns the absolute path of the
    log file.
    """
    os.makedirs(work_dir, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_path = os.path.join(work_dir, f"incremental_{timestamp}.log")

    # If a previous call already wrapped stdout, unwrap to the real console stream first so
    # repeated invocations don't stack tees (each adding another copy of every print()).
    console_stream = getattr(sys.stdout, "_console", sys.stdout)

    formatter = logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s")
    file_handler = logging.FileHandler(log_path)
    file_handler.setFormatter(formatter)
    # Bind the console handler to the real console stream, NOT the tee below, so logging.*
    # records land in the file once (via file_handler) instead of twice (file_handler + tee).
    console_handler = logging.StreamHandler(console_stream)
    console_handler.setFormatter(formatter)

    root = logging.getLogger()
    root.setLevel(logging.INFO)
    # Replace existing handlers so repeated calls don't duplicate lines, then log to both
    # the per-run file and stdout.
    for existing in list(root.handlers):
        root.removeHandler(existing)
    root.addHandler(file_handler)
    root.addHandler(console_handler)

    # Mirror bare print() output (from the shared helpers above) into the same log file.
    sys.stdout = _StdoutTee(console_stream, file_handler.stream)
    return log_path


def check_last_run_existence(proj_dir, submodules=None):
    """
    Return whether a full pipeline run (run_pipeline) has already completed under proj_dir.

    Incremental analysis compares the current working tree against the artifacts left by a
    previous full run, so it can only proceed when those artifacts are present. A full run
    is considered to exist when, under proj_dir/fm_agent/, both:

      1. phases.json exists — the module/phase plan that the full run aborts without, and
      2. extracted_functions/ holds at least one function file and EVERY function file
         has both metadata sidecars (per is_file_ready) — proving
         the spec-generation stage ran to completion. A partially specced tree means the
         previous full run did not finish, so it is not a sound basis for incremental
         analysis.

    When submodules is provided, only extracted functions under those selected
    project-relative directories are considered. Returns True only when the
    selected scope has at least one ready function and no selected function is
    incomplete; otherwise False (so the caller can fall back to a scoped full run).
    """
    work_dir = os.path.join(proj_dir, "fm_agent")

    if not os.path.isfile(os.path.join(work_dir, "phases.json")):
        return False

    extracted_dir = os.path.join(work_dir, "extracted_functions")
    if not os.path.isdir(extracted_dir):
        return False

    saw_function = False
    for root, _, files in os.walk(extracted_dir):
        for fname in files:
            fpath = os.path.join(root, fname)
            if _is_metadata_sidecar(fpath):
                continue
            rel = os.path.relpath(fpath, extracted_dir).replace(os.sep, "/")
            if submodules and not _is_under_submodules(rel, submodules):
                continue
            saw_function = True
            if not is_file_ready(fpath):
                return False
    return saw_function


def _collect_changed_functions(proj_dir, old_commit_id, submodules=None):
    """
    Determine which functions changed between commit old_commit_id and the current working
    tree under proj_dir, so the incremental pipeline only re-analyzes what actually moved.

    Only source files whose extension is in EXT_TO_LANG are considered; test files (per
    _is_test_file), anything under the fm_agent work dir, and files outside submodules
    when a submodule scope is provided are ignored. For each candidate file, functions are
    extracted from both the old (old_commit_id) version and the current working-tree
    version using the same parser as extract.py, then compared by source text.

    Returns a dict mapping each changed file's absolute path to a dict with keys "added",
    "removed", and "modified", each a sorted list of function names. Files with no
    detectable function-level change are omitted; a file that did not exist at
    old_commit_id reports all of its current functions under "added", and a file deleted
    since old_commit_id reports all of its old functions under "removed". Raises
    subprocess.CalledProcessError if proj_dir is not a git repository or old_commit_id is
    not a valid commit.
    """
    # Pathspecs limiting git to recognized source-file extensions (e.g. "*.py", "*.cpp").
    pathspecs = [f"*.{ext}" for ext in EXT_TO_LANG]

    def _git(*args):
        return subprocess.run(
            ["git", "-C", proj_dir, *args],
            check=True,
            capture_output=True,
            text=True,
        ).stdout

    def _is_workspace_file(rel_path):
        norm = rel_path.replace("\\", "/")
        return norm == "fm_agent" or norm.startswith("fm_agent/")

    # Files that changed between old_commit_id and the working tree, plus untracked files
    # (new files absent from old_commit_id), then drop test and workspace files.
    changed = _git(
        "diff", "--name-only", old_commit_id, "--", *pathspecs
    ).splitlines()
    untracked = _git(
        "ls-files", "--others", "--exclude-standard", "--", *pathspecs
    ).splitlines()
    files = [
        f for f in dict.fromkeys(changed + untracked)
        if not _is_test_file(f) and not _is_workspace_file(f)
        and _is_under_submodules(f, submodules)
    ]

    def _path_exists_in_commit(rel_path):
        """Return whether rel_path exists at old_commit_id without reading its contents."""
        return subprocess.run(
            ["git", "-C", proj_dir, "cat-file", "-e", f"{old_commit_id}:{rel_path}"],
            check=False,
            capture_output=True,
            text=True,
        ).returncode == 0

    def _funcs_from_commit(rel_path, lang_key, ext):
        """Extract {name: source} for the old_commit_id version of rel_path via a temp file."""
        text = _git("show", f"{old_commit_id}:{rel_path}")
        with tempfile.NamedTemporaryFile("w", suffix=f".{ext}", delete=False) as tmp:
            tmp.write(text)
            tmp_path = tmp.name
        try:
            return dict(extract_functions_from_file(tmp_path, lang_key))
        finally:
            os.unlink(tmp_path)

    result = {}
    for rel_path in files:
        ext = rel_path.rsplit(".", 1)[-1] if "." in rel_path else ""
        lang_key = EXT_TO_LANG.get(ext)
        if not lang_key:
            continue

        # Working-tree functions (empty if the file was deleted).
        abs_path = os.path.abspath(os.path.join(proj_dir, rel_path))
        if os.path.exists(abs_path):
            new_funcs = dict(extract_functions_from_file(abs_path, lang_key))
        else:
            new_funcs = {}

        # Old-commit functions (empty for files that did not exist at old_commit_id).
        # A path can be absent from the base even when it is already tracked/staged in the
        # current tree, so check the base commit directly instead of relying on untracked
        # status.
        if not _path_exists_in_commit(rel_path):
            old_funcs = {}
        else:
            old_funcs = _funcs_from_commit(rel_path, lang_key, ext)

        added = sorted(n for n in new_funcs if n not in old_funcs)
        removed = sorted(n for n in old_funcs if n not in new_funcs)
        modified = sorted(
            n for n in new_funcs if n in old_funcs and new_funcs[n] != old_funcs[n]
        )
        if added or removed or modified:
            result[abs_path] = {
                "added": added,
                "removed": removed,
                "modified": modified,
            }

    return result


def _modified_function_targets(
    proj_dir, modified_functions, classes=("added", "removed", "modified")
):
    """
    Map the functions recorded in modified_functions to (FQN, extracted-file path).

    modified_functions is the mapping returned by _collect_changed_functions: an
    absolute source-file path -> {"added", "removed", "modified"} lists of function
    names. For each (file, name) pair whose change class is in classes, this computes
    the FQN used by the call graph and the path of the function's file under
    proj_dir/fm_agent/extracted_functions/, both matching that layout (the source
    file's final dot becomes a hyphen and path components are joined with "::"), e.g.
    an "load" function in "<proj_dir>/src/engine/loader.cpp" -> FQN
    "src::engine::loader-cpp::load" at ".../extracted_functions/src/engine/loader-cpp/load.cpp".

    Returns a dict mapping FQN -> absolute extracted-file path.
    """
    extracted_base = os.path.join(proj_dir, "fm_agent", "extracted_functions")
    targets = {}
    for abs_src, changes in modified_functions.items():
        rel = os.path.relpath(abs_src, proj_dir)
        src_dir = os.path.dirname(rel)
        src_base = os.path.basename(rel)
        last_dot = src_base.rfind(".")
        if last_dot > 0:
            dir_name = src_base[:last_dot] + "-" + src_base[last_dot + 1:]
            ext = src_base[last_dot + 1:]
        else:
            dir_name = src_base
            ext = ""
        func_dir = os.path.join(extracted_base, src_dir, dir_name) if src_dir else os.path.join(extracted_base, dir_name)
        names = set()
        for cls in classes:
            names.update(changes.get(cls, []))
        for name in names:
            fname = f"{name}.{ext}" if ext else name
            path = os.path.join(func_dir, fname)
            fqn = _file_to_fqn(path, os.path.join(proj_dir, "fm_agent"))
            targets[fqn] = path
    return targets


def _remove_stale_extracted(proj_dir, modified_functions):
    """
    Delete extracted-function files for functions reported as removed (including every
    function of a deleted source file), and prune any function directory left empty as
    a result. Re-extraction never rewrites these files, so without this they linger as
    stale specs under fm_agent/extracted_functions/.
    """
    removed = _modified_function_targets(
        proj_dir, modified_functions, classes=("removed",)
    )
    for source_path in removed.values():
        for path in (
            source_path,
            f"{source_path}.spec.json",
            f"{source_path}.info.json",
        ):
            if os.path.isfile(path):
                os.remove(path)
    for path in removed.values():
        func_dir = os.path.dirname(path)
        if os.path.isdir(func_dir) and not os.listdir(func_dir):
            os.rmdir(func_dir)


def _topdown_ordered_fqns(work_dir, extra_call_edges=None):
    """
    Return every extracted-function FQN in the top-down order used by run_pipeline for
    spec generation: phases in ascending phase number, layers from 0 upward, and the
    functions in the order listed within each layer (callers precede the callees they
    depend on).

    Regenerates the per-phase topdown-layer JSON files under work_dir/spec_prompts/ as
    a side effect (mirroring run_pipeline's generate_topdown_layers(work_dir) call).
    """
    generate_topdown_layers(work_dir, extra_call_edges=extra_call_edges)
    phases_data = _load_phases(work_dir)
    spec_prompts_dir = os.path.join(work_dir, "spec_prompts")

    ordered = []
    for phase_info in sorted(phases_data.get("phases", []), key=lambda p: p["phase"]):
        phase_num = phase_info["phase"]
        layers_path = os.path.join(
            spec_prompts_dir, f"phase_{phase_num:02d}_topdown_layers.json"
        )
        if not os.path.exists(layers_path):
            continue
        with open(layers_path, "r") as f:
            layers_data = json.load(f)
        for layer in sorted(layers_data.get("layers", []), key=lambda l: l["layer"]):
            for func in layer.get("functions", []):
                ordered.append(func["name"])
    return ordered


def run_incremental_pipeline(
    proj_dir,
    intent_file_path,
    old_commit_id,
    domain_knowledge_files=None,
    submodules=None,
    one_phase=False,
    extra_call_edges_path=None,
):
    """
    Run the pipeline in incremental mode, intent_file_path is a file (absolute path) defining the goal of modification.

    Returns the sorted list of verified files (paths relative to the extracted_functions
    dir) for which the reasoner reported a spec violation (MISMATCH) that bug validation
    then confirmed. The set of functions whose specs were updated is recorded to
    fm_agent/incremental_updated_specs.json as a side effect.
    """

    # run_pipeline and _run_setup_extract live in the top-level entry module (main.py);
    # import them lazily here to avoid a src -> main import cycle at module load time.
    from main import run_pipeline, _run_setup_extract

    work_dir = os.path.join(proj_dir, "fm_agent")
    script_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    input_dir = os.path.join(work_dir, "extracted_functions")
    output_dir = os.path.join(work_dir, "logic_verification_results")
    extra_call_edges = load_call_edges(extra_call_edges_path)

    _setup_incremental_logging(work_dir)
    staged_knowledge = stage_domain_knowledge_files(
        proj_dir, work_dir, domain_knowledge_files
    )
    if staged_knowledge:
        logging.info(
            "  user domain knowledge: %d markdown file(s).",
            len(staged_knowledge),
        )

    logging.info("=" * 70)
    logging.info("INCREMENTAL PIPELINE START")
    logging.info("  project dir : %s", proj_dir)
    logging.info("  intent file : %s", intent_file_path)
    logging.info("  base commit : %s", old_commit_id)
    if submodules:
        logging.info("  submodule scope : %s", ", ".join(submodules))
    logging.info("=" * 70)

    # 1. Check whether there is a last run to compare against; if not, fall back to a full run since we have no basis for incremental analysis.
    logging.info("[Stage 1/10] Checking for a previous full run to compare against...")
    has_last_run = check_last_run_existence(proj_dir, submodules=submodules)
    if not has_last_run:
        logging.warning(
            "No previous full run detected (phases.json missing or incomplete extracted_functions), so falling back to a full run rather than incremental."
        )
        run_pipeline(
            proj_dir,
            domain_knowledge_files=domain_knowledge_files,
            submodules=submodules,
            one_phase=one_phase,
            extra_call_edges_path=extra_call_edges_path,
        )
        return
    logging.info("  -> previous full run found; proceeding with incremental analysis.")

    # 2. Check whether the intent file is valid; if not, fail since we don't know what to analyze incrementally.
    logging.info("[Stage 2/10] Loading developer intent...")
    developer_intent = ""
    if not os.path.isfile(intent_file_path):
        logging.error("Intent file %s does not exist; cannot run incremental pipeline.", intent_file_path)
        return
    else:
        with open(intent_file_path, "r") as f:
            developer_intent = f.read().strip()
        if not developer_intent:
            logging.error("Intent file %s is empty; cannot run incremental pipeline.", intent_file_path)
            return
    logging.info("  -> intent loaded (%d chars).", len(developer_intent))

    # Wipe the previous run's verification artifacts. The prior full run wrote a verdict for
    # EVERY function into logic_verification_results/ and every confirmed bug into
    # bug_validation/, but this incremental run only re-verifies the changed/affected subset.
    # If left in place, those folders would mix stale full-run results with this run's fresh
    # ones, making it ambiguous which verdicts are the latest. Clear them so the folders hold
    # only this incremental run's output.
    for stale_dir in (output_dir, os.path.join(work_dir, "bug_validation")):
        if os.path.isdir(stale_dir):
            shutil.rmtree(stale_dir, ignore_errors=True)
            logging.info("  -> removed stale results dir %s.", stale_dir)

    # Also remove the scope-selection and spec-update prompt/result artifacts a prior
    # incremental run left directly in fm_agent/ (module/file relevance selection and
    # per-function spec updates). They are keyed by a per-run index, so leftovers from an
    # earlier run would sit alongside this run's and obscure which artifacts are current.
    stale_artifact_globs = (
        "select_relevant_modules.md", "relevant_modules.json",
        "select_relevant_files_*.md", "relevant_files_*.json",
        "spec_update_*.md", "spec_update_*.json",
    )
    removed_artifacts = 0
    for pattern in stale_artifact_globs:
        for stale_file in glob.glob(os.path.join(work_dir, pattern)):
            try:
                os.remove(stale_file)
                removed_artifacts += 1
            except OSError:
                pass
    if removed_artifacts:
        logging.info("  -> removed %d stale scope-selection artifact(s) from %s.", removed_artifacts, work_dir)

    # 3. Re-generate the phases.json
    logging.info("[Stage 3/10] Generating new phases.json based on current working tree...")
    _run_setup_extract(
        proj_dir, work_dir, script_dir,
        is_incremental=True, submodules=submodules,
        one_phase=one_phase,
    )
    logging.info("  -> phases.json regenerated.")

    # 4. Update functions under fm_agent/extracted_functions/. Re-extraction replaces
    #    only source files; adjacent .spec.json and .info.json sidecars are retained.
    logging.info("[Stage 4/10] Re-extracting function source files...")
    # Rebuild the codegraph index before re-extraction. The index still reflects the code as
    # of the previous full run, but the working tree has changed since then; run_extraction
    # (and the downstream scope ranking) read function bodies and spans from codegraph, so a
    # stale index would yield boundaries for the old code. try_codegraph_init rebuilds by
    # default; no-op when codegraph is uninstalled (extraction then falls back to regex).
    try_codegraph_init(proj_dir)
    run_extraction(proj_dir, work_dir=work_dir, force=True, verbose=True)
    logging.info("  -> function sources re-extracted; metadata sidecars retained.")

    # 5. Collect changed functions by comparing against the old version of functions in commit_id
    logging.info("[Stage 5/10] Collecting changed functions vs. base commit...")
    changed_functions = _collect_changed_functions(
        proj_dir, old_commit_id, submodules=submodules
    )
    n_added = sum(len(c.get("added", [])) for c in changed_functions.values())
    n_removed = sum(len(c.get("removed", [])) for c in changed_functions.values())
    n_modified = sum(len(c.get("modified", [])) for c in changed_functions.values())
    logging.info(
        "  -> %d changed file(s): %d added, %d modified, %d removed function(s).",
        len(changed_functions), n_added, n_modified, n_removed,
    )

    # 5b. Delete extracted-function files for functions (or whole source files) that were
    #     removed since old_commit_id. Re-extraction never rewrites these, so without this
    #     they linger as stale specs and would pollute the file list and call graph below.
    _remove_stale_extracted(proj_dir, changed_functions)
    logging.info("  -> stale extracted-function files for removed functions deleted.")

    # 6. Update file list
    logging.info("[Stage 6/10] Collecting file list...")
    file_list_path = os.path.join(work_dir, "fm_agent_file_list.json")
    file_list = collect_file_names(input_dir, file_list_path)
    if submodules:
        with open(os.path.join(work_dir, "phases.json"), "r") as f:
            phases_data = json.load(f)
        file_list = _write_file_names(
            _get_all_phase_files(phases_data, input_dir), file_list_path
        )
    logging.info("  -> file list has %d entr(ies).", len(file_list))

    # 7. Update top-down layers
    logging.info("[Stage 7/10] Generating topdown layers...")
    with open(os.path.join(work_dir, "phases.json"), "r") as f:
        phases_data = json.load(f)
    generate_topdown_layers(work_dir, extra_call_edges=extra_call_edges)
    logging.info("  -> topdown layers generated for %d phase(s).", len(phases_data.get("phases", [])))

    # 8. Collect the scope of functions relevant to the developer intent (the intent file defines the goal of modification).
    logging.info("[Stage 8/10] Collecting functions relevant to the developer intent...")
    spec_files = collect_relevent_function_scope(proj_dir, developer_intent, changed_functions)
    logging.info("  -> %d function(s) judged relevant to the intent.", len(spec_files))

    # 9. Re-generate the spec of functions if it satisfies one of the following conditions: 1) the function is changed; 2) the function is relevant to the developer intent.
    logging.info("[Stage 9/10] Updating specs for changed and relevant functions...")
    updated_spec_files = _update_specs_for_intent(
        proj_dir,
        work_dir,
        developer_intent,
        changed_functions,
        spec_files,
        extra_call_edges=extra_call_edges,
    )
    record_path = os.path.join(work_dir, "incremental_updated_specs.json")
    with open(record_path, "w") as f:
        json.dump({"updated_specs": updated_spec_files}, f, indent=2)
    logging.info(
        "  -> %d spec(s) updated; record written to %s.",
        len(updated_spec_files), record_path,
    )

    # 10. Run the verification stage only on the functions that satisfy one of the following conditions: 1) the function is changed; 2) the function spec is changed after step 9; 3) the callee spec of the function is changed.
    logging.info("[Stage 10/10] Verifying changed and affected functions...")
    buggy_files = _verify_incremental_functions(
        proj_dir, work_dir, changed_functions, updated_spec_files,
        submodules=submodules,
    )
    logging.info("=" * 70)
    logging.info(
        "INCREMENTAL PIPELINE DONE: bug validation confirmed bugs in %d function(s).",
        len(buggy_files),
    )
    for bf in buggy_files:
        logging.info("  - %s", bf)
    logging.info("=" * 70)
    return buggy_files


def _extracted_func_dir(extracted_base, src_rel):
    """
    Map a source file (relative path, phases.json convention) to the directory holding its
    extracted-function files.

    Mirrors the `zzz.ext -> zzz-ext` derivation used by run_extraction and
    _collect_phase_files: source file <src_dir>/<base>.<ext> is extracted to
    <extracted_base>/<src_dir>/<base>-<ext>/, with one file per function named
    <func_name>.<ext>.
    """
    src_dir = os.path.dirname(src_rel)
    src_base = os.path.basename(src_rel)
    last_dot = src_base.rfind(".")
    if last_dot > 0:
        dir_name = src_base[:last_dot] + "-" + src_base[last_dot + 1:]
    else:
        dir_name = src_base
    if src_dir:
        return os.path.join(extracted_base, src_dir, dir_name)
    return os.path.join(extracted_base, dir_name)


def _opencode_select_json(proj_dir, work_dir, prompt_relpath, prompt_content,
                          result_relpath, stage, input_files):
    """
    Run opencode to produce a JSON artifact and return the parsed JSON.

    Writes prompt_content to proj_dir/prompt_relpath, removes any stale artifact at
    proj_dir/result_relpath, then runs `opencode run --file <prompt> -- ...` (with the same
    retry / result-artifact check used by the setup stage) until the agent writes the
    result file. Returns the parsed JSON value, or None if opencode never produced the
    artifact or it could not be parsed. Shared by the module- and file-selection steps of
    collect_relevent_function_scope.
    """
    prompt_path = os.path.join(proj_dir, prompt_relpath)
    result_path = os.path.join(proj_dir, result_relpath)
    if os.path.exists(result_path):
        os.remove(result_path)

    tmp_path = prompt_path + ".tmp"
    with open(tmp_path, "w") as f:
        f.write(prompt_content)
    os.replace(tmp_path, prompt_path)

    prompt = "Follow the instructions in the attached file."
    command = build_llm_cli_command(
        model=OPENCODE_SETUP_MODEL,
        prompt=prompt,
        cwd=proj_dir,
        files=[prompt_path],
    )

    produced = False
    for attempt in range(1, OPENCODE_MAX_RETRIES + 1):
        try:
            run_opencode_traced(
                proj_dir=proj_dir,
                work_dir=work_dir,
                command=command,
                stage=stage,
                input_files=input_files,
                output_files=[result_relpath],
                summary=f"OpenCode {stage} attempt {attempt}",
                metadata={"attempt": attempt},
            )
        except subprocess.CalledProcessError as exc:
            logging.warning(
                "%s: opencode exited with code %s (attempt %d/%d)",
                stage, exc.returncode, attempt, OPENCODE_MAX_RETRIES,
            )

        if os.path.exists(result_path):
            produced = True
            break

        if attempt < OPENCODE_MAX_RETRIES:
            logging.warning(
                "%s: %s not produced (attempt %d/%d); retrying in 10s",
                stage, result_relpath, attempt, OPENCODE_MAX_RETRIES,
            )
            time.sleep(10)

    if not produced:
        logging.error(
            "%s: %s not produced after %d attempts", stage, result_relpath, OPENCODE_MAX_RETRIES
        )
        return None

    try:
        with open(result_path, "r") as f:
            return json.load(f)
    except (ValueError, OSError) as exc:
        logging.error("%s: could not read %s: %s", stage, result_relpath, exc)
        return None


def _validate_module_selection(data):
    """Validate the direct LLM response used to select relevant modules."""
    if not isinstance(data, list):
        raise ValueError("module-selection JSON must be an array")
    validated = []
    for index, item in enumerate(data):
        if not isinstance(item, dict):
            raise ValueError(f"module-selection item {index} must be an object")
        phase = item.get("phase")
        name = item.get("name")
        if isinstance(phase, bool) or not isinstance(phase, int):
            raise ValueError(f"module-selection item {index} requires integer field: phase")
        if not isinstance(name, str) or not name.strip():
            raise ValueError(f"module-selection item {index} requires non-empty string field: name")
        validated.append({"phase": phase, "name": name.strip()})
    return validated


def _normalize_spec_dict(spec):
    """Keep only fields supported by a .spec.json sidecar."""
    return {
        "unit": spec.get("unit", ""),
        "signature": spec.get("signature", ""),
        "pre_condition": spec.get("pre_condition", ""),
        "post_condition": spec.get("post_condition", ""),
    }


def _normalize_info_dict(info):
    """Keep only fields supported by a .info.json sidecar."""
    callees = info.get("callees", [])
    if not isinstance(callees, list):
        raise ValueError("info JSON field callees must be an array")
    return {
        "callees": [
            {
                "name": callee.get("name", ""),
                "signature": callee.get("signature", ""),
                "pre_condition": callee.get("pre_condition", ""),
                "post_condition": callee.get("post_condition", ""),
            }
            for callee in callees
            if isinstance(callee, dict)
        ]
    }


def _validate_spec_update(data):
    """Validate a direct LLM decision about function metadata sidecars."""
    if not isinstance(data, dict):
        raise ValueError("spec-update JSON must be an object")
    required = ("spec_updated", "new_spec", "info_updated", "new_info", "updated_callees")
    missing = [field for field in required if field not in data]
    if missing:
        raise ValueError("spec-update JSON missing required field(s): " + ", ".join(missing))
    if not isinstance(data["spec_updated"], bool) or not isinstance(data["info_updated"], bool):
        raise ValueError("spec-update JSON fields spec_updated and info_updated must be booleans")
    if not isinstance(data["updated_callees"], list) or not all(
        isinstance(name, str) and name.strip() for name in data["updated_callees"]
    ):
        raise ValueError("spec-update JSON field updated_callees must be an array of non-empty strings")
    if data["spec_updated"]:
        if not isinstance(data["new_spec"], dict):
            raise ValueError("spec-update JSON requires object new_spec when spec_updated is true")
        if not _is_valid_spec_json(data["new_spec"]):
            raise ValueError("spec-update JSON new_spec must match the .spec.json schema")
    if data["info_updated"]:
        if not isinstance(data["new_info"], dict):
            raise ValueError("spec-update JSON requires object new_info when info_updated is true")
        if not _is_valid_info_json(data["new_info"]):
            raise ValueError("spec-update JSON new_info must match the .info.json schema")
    return {
        "spec_updated": data["spec_updated"],
        "new_spec": _normalize_spec_dict(data["new_spec"]) if data["spec_updated"] else None,
        "info_updated": data["info_updated"],
        "new_info": _normalize_info_dict(data["new_info"]) if data["info_updated"] else None,
        "updated_callees": [name.strip() for name in data["updated_callees"]],
    }


def _validate_caller_info_update(data):
    """Validate a direct LLM decision about one caller's info sidecar."""
    if not isinstance(data, dict):
        raise ValueError("caller-info JSON must be an object")
    required = ("info_updated", "new_info")
    missing = [field for field in required if field not in data]
    if missing:
        raise ValueError("caller-info JSON missing required field(s): " + ", ".join(missing))
    if not isinstance(data["info_updated"], bool):
        raise ValueError("caller-info JSON field info_updated must be a boolean")
    if data["info_updated"]:
        if not isinstance(data["new_info"], dict):
            raise ValueError("caller-info JSON requires object new_info when info_updated is true")
        if not _is_valid_info_json(data["new_info"]):
            raise ValueError("caller-info JSON new_info must match the .info.json schema")
    return {
        "info_updated": data["info_updated"],
        "new_info": _normalize_info_dict(data["new_info"]) if data["info_updated"] else None,
    }

def _llm_select_json(work_dir, prompt_content, stage, validator, schema_description,
                     trace_meta=None):
    """Run a direct LLM call and return validated structured JSON.

    This is for self-contained prompts whose context is already inlined. The
    shared JSON caller records the raw exchange, accepts exactly one JSON
    object or array (including a fenced or prose-wrapped one), validates the
    required fields, and retries on protocol failures.
    """
    messages = [{"role": "user", "content": prompt_content}]
    meta = {"stage": stage, "summary": f"LLM {stage}", **(trace_meta or {})}
    result = _llm_json_call(
        _llm_provider_client,
        LLM_MODEL,
        messages,
        validator,
        schema_description,
        trace_dir=os.path.join(work_dir, "trace"),
        trace_meta=meta,
    )
    if result is None:
        logging.error("%s: LLM produced no valid JSON response after retries.", stage)
    return result

def _domain_knowledge_prompt_section(work_dir):
    text = load_staged_domain_knowledge_text(work_dir)
    return f"## User-provided domain knowledge\n\n{text}\n\n" if text else ""


def collect_relevent_function_scope(proj_dir, developer_intent, changed_functions, range=None):
    """
    Select the functions relevant to developer_intent and return the most relevant ones.

    The module/phase plan in proj_dir/fm_agent/phases.json describes the project as a set
    of modules, each with a natural-language description and a list of source_files. This
    narrows the scope to the developer's intent in three passes:

      1. Module selection — a direct LLM call is given the module descriptions (already
         parsed from phases.json) and picks the modules relevant to the intent.
      2. File selection — for each relevant module, opencode reads that module's source
         files and picks the files relevant to the intent.
      3. Function selection — the function-localization algorithm from scope.py ranks the
         functions in each chosen file by relevance to the intent (heuristic signal scoring
         with call-graph and class-scope enrichments) and keeps the top-ranked functions
         per file.

    range, when given, caps the result to the first (most relevant) `range` functions; pass
    None to return all of them.

    Returns the selected extracted-function file paths (relative to the extracted_functions
    dir, matching the convention used elsewhere in this module), ordered by descending
    relevance score and truncated to the first `range` entries. Returns an empty list when
    phases.json has no modules or opencode selects none / fails to produce a result.
    """
    work_dir = os.path.join(proj_dir, "fm_agent")
    extracted_dir = os.path.join(work_dir, "extracted_functions")

    phases_data = _load_phases(work_dir)

    # Flatten every module across all phases so we can match opencode's selection back to
    # concrete modules (module names can repeat across phases, so keep the phase number too).
    modules = []  # list of (phase_num, module_dict)
    for phase_info in phases_data.get("phases", []):
        phase_num = phase_info.get("phase")
        for module in phase_info.get("modules", []):
            modules.append((phase_num, module))

    if not modules:
        logging.info("    [scope] no modules in phases.json; nothing to select.")
        return []

    changed_source_rels = {
        os.path.relpath(abs_src, proj_dir).replace(os.sep, "/")
        for abs_src in changed_functions
    }
    logging.info("    [scope] pass 1/3: selecting relevant modules from %d module(s)...", len(modules))

    # Pass 1: module selection. The module descriptions are already parsed from phases.json
    # above, so rather than have opencode read the file, inline the catalog and make a direct
    # LLM call that returns the selection as JSON.
    module_catalog = "\n".join(
        f"- phase {phase_num}, name `{module.get('name', '(unnamed)')}`: "
        f"{(module.get('description') or '').strip() or '(no description)'}"
        for phase_num, module in modules
    )
    module_prompt = (
        "# Select Relevant Modules\n\n"
        "You are triaging which parts of a codebase are relevant to a developer's intent.\n\n"
        "Each module below has a `phase` number, a `name`, and a `description`. Using each "
        "module's description, decide which modules are relevant to the developer intent — a "
        "module is relevant if the developer intent is likely to affect it or depend on it.\n\n"
        "## Modules\n\n"
        f"{module_catalog}\n\n"
        "## Developer intent\n\n"
        f"{developer_intent}\n\n"
        "## Output\n\n"
        "Return ONLY a JSON array of objects, each "
        '`{"phase": <phase number>, "name": "<module name>"}`, naming exactly the modules you '
        "judged relevant (reuse the same `phase` and `name` values from the list above). Use "
        "`[]` if no module is relevant. Do not include Markdown, tags, or prose outside the JSON array.\n"
    )
    selection = _llm_select_json(
        work_dir,
        module_prompt,
        stage="select_relevant_modules",
        validator=_validate_module_selection,
        schema_description='[{"phase": integer, "name": "non-empty string"}]',
    )
    if selection is None:
        selection = []

    selected_keys = set()
    if isinstance(selection, list):
        for item in selection:
            if isinstance(item, dict) and "name" in item:
                selected_keys.add((item.get("phase"), item["name"]))

    relevant_modules = [
        (phase_num, module) for phase_num, module in modules
        if (phase_num, module.get("name")) in selected_keys
        or any(sf.replace("\\", "/") in changed_source_rels for sf in module.get("source_files", []))
    ]
    if not relevant_modules:
        logging.info("    [scope] pass 1/3: no relevant modules selected.")
        return []
    for phase_num, module in relevant_modules:
        logging.info(
            "    [scope] pass 1/3: relevant module: phase %s / %s",
            phase_num, module.get("name", "(unnamed)"),
        )
    logging.info(
        "    [scope] pass 2/3: %d relevant module(s); selecting relevant files per module...",
        len(relevant_modules),
    )

    # Pass 2: file selection. For each relevant module, opencode reads that module's source
    # files and narrows them to the files relevant to the intent. The result is a synthetic
    # module dict carrying only the chosen source_files; on opencode failure we fall back to
    # the module's full file list so the scope is never silently dropped.
    filtered_modules = []
    for idx, (phase_num, module) in enumerate(relevant_modules):
        module_name = module.get("name", f"module_{idx}")
        source_files = module.get("source_files", [])
        if not source_files:
            continue

        source_set = set(source_files)
        changed_in_module = [
            sf for sf in source_files
            if sf.replace("\\", "/") in changed_source_rels
        ]
        file_list_md = "\n".join(f"- `{sf}`" for sf in source_files)
        file_prompt = (
            "# Select Relevant Files\n\n"
            f"You are triaging which files of the module `{module_name}` are relevant to a "
            "developer intent.\n\n"
            "## Steps\n\n"
            "1. Read each of the module source files listed below.\n"
            "2. Decide which files are relevant to the developer intent -- a file is relevant "
            "if the developer intent is likely to affect it or depend on its behavior.\n"
            f"3. Write your answer to `fm_agent/relevant_files_{idx}.json` as a JSON array of "
            "the relevant file paths, each copied verbatim from the list below. Write `[]` if "
            "no file is relevant. Write ONLY that file; do not modify any other project "
            "files.\n\n"
            "## Module source files\n\n"
            f"{file_list_md}\n\n"
            "## Developer intent\n\n"
            f"{developer_intent}\n"
        )
        file_selection = _opencode_select_json(
            proj_dir,
            work_dir,
            os.path.join("fm_agent", f"select_relevant_files_{idx}.md"),
            file_prompt,
            os.path.join("fm_agent", f"relevant_files_{idx}.json"),
            stage="select_relevant_files",
            input_files=[f"fm_agent/select_relevant_files_{idx}.md", *source_files],
        )

        if isinstance(file_selection, list):
            chosen = [sf for sf in file_selection if sf in source_set]
            for sf in changed_in_module:
                if sf not in chosen:
                    chosen.append(sf)
        else:
            # opencode failed for this module; keep all files rather than drop scope.
            chosen = list(source_files)

        if chosen:
            filtered_modules.append({**module, "source_files": chosen})
            logging.info(
                "    [scope] pass 2/3: module %s -> %d relevant file(s): %s",
                module_name, len(chosen), ", ".join(chosen),
            )

    if not filtered_modules:
        logging.info("    [scope] pass 2/3: no relevant files selected.")
        return []
    logging.info(
        "    [scope] pass 3/3: ranking functions in %d module(s) by relevance...",
        len(filtered_modules),
    )

    # Pass 3: function selection via the scope.py localization algorithm. For each chosen
    # file, rank its functions by relevance to the developer intent and keep the top-ranked
    # ones, then map each selected function back to its extracted-function file
    # (run_extraction writes one file per function at <func dir>/<func_name>.<ext>). A file
    # scope.py cannot analyze yields no ranking, so we fall back to all of its extracted
    # functions rather than drop it from scope.
    signals = _parse_issue_signals(developer_intent)
    repo_dir = Path(proj_dir)

    # Collect each selected extracted-function file with its relevance score, keeping the
    # highest score seen for a given file. Files scope.py cannot localize within contribute
    # all of their functions at a neutral 0.0 score (so a genuinely high-scoring function
    # always outranks them).
    scored = {}  # rel_path -> best score

    def _record(rel_path, score):
        if rel_path not in scored or score > scored[rel_path]:
            scored[rel_path] = score

    for module in filtered_modules:
        for src_rel in module.get("source_files", []):
            func_dir = _extracted_func_dir(extracted_dir, src_rel)
            if not os.path.isdir(func_dir):
                continue
            ext = src_rel.rsplit(".", 1)[-1] if "." in src_rel else ""

            ranked = []
            src_path = repo_dir / src_rel
            if src_path.exists():
                ranked = rank_functions_in_file(
                    filepath=src_rel,
                    src_path=src_path,
                    issue=developer_intent,
                    signals=signals,
                    proj_dir=proj_dir,
                )

            if ranked:
                # Keep the extracted-function file for each selected function name.
                for f in ranked:
                    cand = os.path.join(func_dir, f"{f['name']}.{ext}")
                    if os.path.isfile(cand):
                        _record(os.path.relpath(cand, extracted_dir), f.get("score", 0.0))
                logging.info(
                    "    [scope] pass 3/3: %s -> %s",
                    src_rel,
                    ", ".join(f"{f['name']}={f.get('score', 0.0):.2f}" for f in ranked),
                )
            else:
                # scope.py could not localize within this file — keep all of its functions.
                for fname in os.listdir(func_dir):
                    cand = os.path.join(func_dir, fname)
                    if os.path.isfile(cand):
                        _record(os.path.relpath(cand, extracted_dir), 0.0)

    # Order by descending relevance score (path as a deterministic tie-breaker), then keep
    # only the first `range` functions when a limit is given.
    ordered = sorted(scored, key=lambda p: (-scored[p], p))
    if range is not None:
        ordered = ordered[:range]
    for rel_path in ordered:
        logging.info("    [scope] selected function: %s (score %.2f)", rel_path, scored[rel_path])
    return ordered


def _project_call_graph(work_dir, extra_call_edges=None):
    """
    Build the project-wide call graph (keyed by FQN) over every extracted function.

    Treats all extracted functions across every phase in phases.json as one graph, so
    callee/caller edges span the whole project. Returns (callees_map, callers_map,
    file_map, edge_aliases_map): callees_map maps each FQN to the set of FQNs it calls
    directly, callers_map the inverse (each FQN to the FQNs that call it directly),
    file_map maps each FQN to the absolute path of its extracted-function file, and
    edge_aliases_map maps callee -> caller -> supplemental edge labels.
    """
    phases = _load_phases(work_dir)
    all_files = []
    seen = set()
    for phase in phases.get("phases", []):
        for fpath, module_name in _collect_phase_files(work_dir, phase):
            if fpath not in seen:
                seen.add(fpath)
                all_files.append((fpath, module_name))

    (
        callees_map,
        callers_map,
        _all_callees,
        file_map,
        _modmap,
        edge_aliases_map,
    ) = _build_call_graph(
        all_files,
        work_dir,
        extra_call_edges=extra_call_edges,
    )
    return callees_map, callers_map, file_map, edge_aliases_map


def _resolve_callee_fqns(caller_fqn, callee_names, callees_map, edge_aliases_map=None):
    """
    Map callee names reported by opencode (the .info.json entries whose expected spec changed)
    back to the FQNs of caller_fqn's callees.

    A callee is identified in .info.json by its name; this matches that name against
    the final component (stem) of each of caller_fqn's callee FQNs, case-insensitively, and
    returns every matching callee FQN (a name shared by callees in several files resolves to
    all of them).
    """
    wanted = {n.strip() for n in callee_names if n and n.strip()}
    wanted_lower = {n.lower() for n in wanted}
    resolved = set()
    for callee_fqn in callees_map.get(caller_fqn, ()):
        stem = callee_fqn.split("::")[-1]
        aliases = set()
        if edge_aliases_map:
            aliases.update(edge_aliases_map.get(callee_fqn, {}).get(caller_fqn, ()))
        alias_lower = {alias.lower() for alias in aliases}
        if stem in wanted or stem.lower() in wanted_lower or aliases & wanted or alias_lower & wanted_lower:
            resolved.add(callee_fqn)
    return resolved


def _llm_check_spec_update(proj_dir, work_dir, idx, fqn, lang_key, comment_prefix,
                           developer_intent, spec_block, info_block, callee_names, source):
    """
    Ask the LLM whether a function's .spec.json (and, if so, its .info.json) must change to
    reflect developer_intent, and return the parsed decision.

    The prompt inlines the entire function source, its current metadata sidecars, and the
    developer intent, so it needs no repository file access and is issued as a direct LLM
    call (via _llm_select_json) rather than an opencode run. idx is used only to label the
    traced exchange.

    Returns the parsed result dict — keys: "spec_updated" (bool), "new_spec" (dict),
    "info_updated" (bool), "new_info" (dict), "updated_callees" (list[str]) — or None when
    the LLM produced nothing usable.
    """
    callee_hint = ", ".join(sorted(callee_names)) if callee_names else "(none)"
    if not callee_names:
        info_section = (
            "This function has no callees, so .info.json must contain "
            '{"callees": []}.\n\n'
        )
    elif info_block is not None:
        info_section = (
            "## Current .info.json (the expected specs of the callees this function depends on)\n\n"
            f"```json\n{json.dumps(info_block, indent=2, ensure_ascii=False)}\n```\n\n"
            "NOTE: a modification may have changed which callees this function calls, so this "
            f"object may be missing entries for some current callees ({callee_hint}) or contain "
            "entries for callees no longer called.\n\n"
        )
    else:
        info_section = (
            "This function currently has no .info.json, but a modification may have made it "
            f"call other functions, so it now has callees ({callee_hint}); a new .info.json "
            "may need to be created for them.\n\n"
        )

    knowledge_section = _domain_knowledge_prompt_section(work_dir)

    prompt_content = (
        "# Update Function Specification\n\n"
        "A modification is being applied to a codebase to achieve the developer intent "
        "below. Decide whether this function's behavioral specification must change to "
        "reflect that intent.\n\n"
        f"- Function fully-qualified name: `{fqn}` (language: `{lang_key}`).\n"
        f"- Known callees of this function: {callee_hint}.\n\n"
        "## Developer intent\n\n"
        f"{developer_intent}\n\n"
        f"{knowledge_section}"
        "## Current function source\n\n"
        f"```{lang_key}\n{source.strip()}\n```\n\n"
        "## Current .spec.json (this function's own behavioral specification)\n\n"
        f"```json\n{json.dumps(spec_block, indent=2, ensure_ascii=False)}\n```\n\n"
        f"{info_section}"
        "## Steps\n\n"
        "1. Decide whether .spec.json still correctly and completely describes the "
        "function's behavior after the intended modification. If it remains correct, no "
        "update is needed.\n"
        "2. If it must change, produce the COMPLETE replacement .spec.json object, with "
        "exactly unit, signature, pre_condition, and post_condition, and NO source code.\n"
        "3. ONLY if you updated .spec.json AND this function has callees: bring "
        f".info.json into line with this function's CURRENT callees ({callee_hint}). That "
        "means: (a) keep entries whose recorded expectation still matches the callee's role, "
        "(b) ADD an entry for any current callee not yet recorded (e.g. one the modification "
        "introduced), (c) DROP entries for callees this function no longer calls, and (d) "
        "revise any entry whose expected spec must change as a consequence of the new spec. "
        "If any of (a)-(d) changes the object, produce the COMPLETE replacement .info.json "
        "object with exactly the callees field and list the names of the callees whose expected "
        "spec you added or changed.\n"
        "4. Return ONLY a JSON object with keys:\n"
        '   - "spec_updated": boolean.\n'
        '   - "new_spec": object — the full replacement .spec.json object, or null if not updated.\n'
        '   - "info_updated": boolean — true when you produced a new/replacement .info.json object.\n'
        '   - "new_info": object — the full replacement .info.json object, or null if not updated.\n'
        '   - "updated_callees": array of callee name strings whose expected spec you added or changed, or [].\n'
        "   Do not include Markdown, tags, or prose outside the JSON object.\n"
    )

    return _llm_select_json(
        work_dir,
        prompt_content,
        stage="update_function_spec",
        validator=_validate_spec_update,
        schema_description=(
            '{"spec_updated": boolean, "new_spec": object|null, "info_updated": boolean, '
            '"new_info": object|null, "updated_callees": [string]}'
        ),
        trace_meta={"fqn": fqn, "idx": idx},
    )


def _llm_check_caller_info_update(proj_dir, work_dir, idx, caller_fqn, callee_name,
                                  lang_key, comment_prefix, callee_new_spec,
                                  caller_info_block, caller_source):
    """
    Ask whether a caller's .info.json must change to stay consistent with a callee whose
    .spec.json was just updated.

    The caller's .info.json records the expected specs of the callees it depends on. This
    asks the model to reconcile only the entry for callee_name with the callee's new spec —
    consistency, not equality: the entry must merely not conflict with the new spec, and the
    entries for other callees are left untouched. The prompt inlines the callee's new spec
    and the caller's source/info sidecar, so it is issued as a direct LLM call (via
    _llm_select_json) rather than an opencode run; idx only labels the traced exchange.

    Returns the parsed result dict — keys "info_updated" (bool) and "new_info" (dict) — or
    None when the LLM produced nothing usable.
    """
    knowledge_section = _domain_knowledge_prompt_section(work_dir)

    prompt_content = (
        "# Reconcile a Caller's .info.json with a Changed Callee\n\n"
        f"The callee `{callee_name}`'s behavioral specification was just updated. The caller "
        f"`{caller_fqn}` (language `{lang_key}`) records the expected specs of the callees it "
        "depends on in its .info.json. Update that object so its entry for the callee is "
        "CONSISTENT with the callee's new spec — it need NOT be identical, it only must not "
        "conflict (no contradictory pre/post-conditions). Leave the entries for every other "
        "callee unchanged.\n\n"
        f"{knowledge_section}"
        "## Callee's updated .spec.json\n\n"
        f"```json\n{json.dumps(callee_new_spec, indent=2, ensure_ascii=False)}\n```\n\n"
        "## Caller's current source\n\n"
        f"```{lang_key}\n{caller_source.strip()}\n```\n\n"
        "## Caller's current .info.json (the expected specs of its callees)\n\n"
        f"```json\n{json.dumps(caller_info_block, indent=2, ensure_ascii=False)}\n```\n\n"
        "## Steps\n\n"
        f"1. Decide whether the caller's .info.json entry for `{callee_name}` already is consistent "
        "with the callee's new spec. If it is, no update is needed.\n"
        "2. If it conflicts, produce the COMPLETE replacement .info.json object, "
        f"adjusting only the `{callee_name}` entry to be consistent and leaving the other "
        "entries as-is.\n"
        "3. Return ONLY a JSON object with keys:\n"
        '   - "info_updated": boolean.\n'
        '   - "new_info": object — the full replacement .info.json object, or null if not updated.\n'
        "   Do not include Markdown, tags, or prose outside the JSON object.\n"
    )

    return _llm_select_json(
        work_dir,
        prompt_content,
        stage="update_caller_info",
        validator=_validate_caller_info_update,
        schema_description='{"info_updated": boolean, "new_info": object|null}',
        trace_meta={"caller_fqn": caller_fqn, "callee_name": callee_name, "idx": idx},
    )


def _collect_caller_context(fqn, callers_map, file_map, edge_aliases_map=None):
    """
    Gather the context an existing caller provides about fqn, mirroring the caller context
    run_pipeline feeds into spec generation: each caller's own .spec.json and the entry in
    its .info.json that records what the caller expects from fqn (as one of its callees).

    Returns a list of (caller_fqn, caller_spec, callee_expectation) tuples — caller_spec and
    callee_expectation are None when the caller has no such block — for every caller of fqn
    whose extracted-function file exists and yields at least one of the two. Callers with no
    file or no usable block are skipped.
    """
    context = []
    for caller_fqn in sorted(callers_map.get(fqn, ())):
        cpath = file_map.get(caller_fqn)
        if not cpath or not os.path.isfile(cpath):
            continue
        cpath_p = Path(cpath)
        caller_spec = extract_spec_block(cpath_p)
        info_dict = extract_info_block(cpath_p)
        aliases = ()
        if edge_aliases_map:
            aliases = tuple(edge_aliases_map.get(fqn, {}).get(caller_fqn, ()))
        callee_entry = (
            extract_callee_spec_from_info(info_dict, fqn, aliases)
            if info_dict else None
        )
        expectation = None
        if callee_entry:
            expectation = (
                f"{callee_entry.get('signature', '')}\n"
                f"  Pre-condition: {callee_entry.get('pre_condition', '')}\n"
                f"  Post-condition: {callee_entry.get('post_condition', '')}"
            )
        if caller_spec or expectation:
            context.append((caller_fqn, caller_spec, expectation))
    return context


def _opencode_generate_spec(proj_dir, work_dir, idx, fqn, lang_key, comment_prefix,
                            developer_intent, callee_names, source, caller_context):
    """
    Ask opencode to generate brand-new .spec.json and .info.json objects from scratch for a
    function that has no existing metadata sidecars — e.g. a function
    freshly added by the modification.

    Mirrors the full run's spec generation (run_pipeline Stage 5) but for a single function:
    opencode reads the project's spec format rules (fm_agent/spec_prompts/system_prompt.md),
    is given the same caller context the full run provides (each caller's .spec.json and what
    that caller's .info.json expects from this function, in caller_context as returned by
    _collect_caller_context), and produces the objects directly. Returns the parsed decision
    in the SAME shape as _opencode_check_spec_update so the caller can splice and propagate it
    identically.

    Returns the parsed result dict — keys: "spec_updated" (bool, true when .spec.json was
    produced), "new_spec" (dict), "info_updated" (bool), "new_info" (dict), "updated_callees"
    (list[str]) — or None when opencode produced nothing usable.
    """
    result_relpath = os.path.join("fm_agent", f"spec_generate_{idx}.json")
    prompt_relpath = os.path.join("fm_agent", f"spec_generate_{idx}.md")

    # Caller context (callers' own specs + what each caller's .info.json expects from this
    # function), mirroring run_pipeline's "EARLIER-LAYER CALLER SPECS" / "CALLEE EXPECTATIONS
    # FROM CALLERS" sections so the generated spec satisfies what callers depend on.
    caller_specs = [
        (cfqn, spec) for cfqn, spec, _ in caller_context if spec
    ]
    caller_expectations = [
        (cfqn, exp) for cfqn, _, exp in caller_context if exp
    ]
    caller_section = ""
    if caller_specs:
        caller_section += "## Specs of this function's callers\n\n"
        for cfqn, spec in caller_specs:
            caller_section += f"### {cfqn}\n\n{spec.strip()}\n\n"
    if caller_expectations:
        caller_section += (
            "## What callers expect from this function (from their .info.json files)\n\n"
            "Your generated .spec.json must be consistent with these expectations.\n\n"
        )
        for cfqn, exp in caller_expectations:
            caller_section += f"### According to {cfqn}\n\n{exp.strip()}\n\n"

    callee_hint = ", ".join(sorted(callee_names)) if callee_names else "(none)"
    user_knowledge_paths = list_staged_domain_knowledge_relpaths(work_dir)
    if user_knowledge_paths:
        user_knowledge_step = (
            "2. Read these user-provided domain knowledge Markdown files and use "
            "them as additional context:\n"
            f"{format_domain_knowledge_bullets(user_knowledge_paths)}\n"
        )
        step_offset = 1
    else:
        user_knowledge_step = ""
        step_offset = 0
    info_step_number = 3 + step_offset
    if callee_names:
        info_step = (
            f"{info_step_number}. Because this function has callees, also produce a .info.json "
            "object recording the expected behavioral spec of each callee it depends on, with "
            "exactly the callees field, and "
            "list the names of the callees you recorded.\n"
        )
    else:
        info_step = (
            f"{info_step_number}. This function has no callees, so produce a .info.json object "
            'with {"callees": []}.\n'
        )

    prompt_content = (
        "# Generate Function Specification\n\n"
        "A modification has been applied to a codebase to achieve the developer intent below, "
        "adding a function that has no behavioral specification yet. Generate its "
        "specification from scratch.\n\n"
        f"- Function fully-qualified name: `{fqn}` (language: `{lang_key}`).\n"
        f"- Known callees of this function: {callee_hint}.\n\n"
        "## Developer intent\n\n"
        f"{developer_intent}\n\n"
        "## Function source\n\n"
        f"```{lang_key}\n{source.strip()}\n```\n\n"
        f"{caller_section}"
        "## Steps\n\n"
        "1. Read `fm_agent/spec_prompts/system_prompt.md` for the exact .spec.json/.info.json format "
        "rules used by this project.\n"
        f"{user_knowledge_step}"
        f"{2 + step_offset}. Produce the COMPLETE .spec.json object describing this "
        "function's behavior, with exactly unit, signature, pre_condition, and "
        "post_condition, and NO source code.\n"
        f"{info_step}"
        f"{4 + step_offset}. Write your answer to `{result_relpath}` as a JSON object with keys:\n"
        '   - "spec_updated": boolean — true because you produced a .spec.json object.\n'
        '   - "new_spec": object — the full .spec.json object.\n'
        '   - "info_updated": boolean — true because you produced a .info.json object.\n'
        '   - "new_info": object — the full .info.json object.\n'
        '   - "updated_callees": array of callee name strings recorded in .info.json, or [].\n'
        "   Write ONLY that JSON file; do not modify any other project files.\n"
    )
    result = _opencode_select_json(
        proj_dir,
        work_dir,
        prompt_relpath,
        prompt_content,
        result_relpath,
        stage="generate_function_spec",
        input_files=[
            prompt_relpath,
            "fm_agent/spec_prompts/system_prompt.md",
            *user_knowledge_paths,
        ],
    )
    return _validate_spec_update(result) if result is not None else None


def _update_specs_for_intent(
    proj_dir,
    work_dir,
    developer_intent,
    changed_functions,
    relevant_rel_files,
    extra_call_edges=None,
):
    """
    Re-generate the .spec.json (and dependent .info.json) sidecars of every function that is
    either changed or relevant to the developer intent, propagating to callees.

    Seeds from the changed functions (added/modified) and the relevant extracted-function
    files returned by collect_relevent_function_scope, then processes functions in top-down
    order (callers before callees). For each function, opencode reads its current .spec.json
    block and decides whether it must change to reflect developer_intent. A function with no
    existing .spec.json (e.g. one freshly added by the modification) instead has a spec
    generated from scratch the way the full run does. If a spec is written or generated, the
    new .spec.json is written back (source untouched), and then:

      - Downward: opencode decides whether the function's own .info.json (the expected
        specs of its callees) must change too, and any callee whose expected spec changed is
        queued to have its own spec file re-checked.
      - Upward: every caller's .info.json (which records this function as one of its
        callees) is reconciled with the function's new .spec.json so the two do not conflict
        (they need not be identical).

    Returns the sorted list of extracted-function files (paths relative to the
    extracted_functions dir) whose metadata sidecar was changed.
    """
    extracted_dir = os.path.join(work_dir, "extracted_functions")

    callees_map, callers_map, file_map, edge_aliases_map = _project_call_graph(
        work_dir,
        extra_call_edges=extra_call_edges,
    )

    # Seed: functions changed in the working tree (added/modified — removed ones no longer
    # exist on disk) plus functions relevant to the developer intent.
    seed = set()
    changed_targets = _modified_function_targets(
        proj_dir, changed_functions, classes=("added", "modified")
    )
    seed.update(changed_targets.keys())
    for rel in relevant_rel_files:
        seed.add(_file_to_fqn(os.path.join(extracted_dir, rel), work_dir))

    if not seed:
        logging.info("    [specs] no changed or relevant functions to update; skipping.")
        return []
    logging.info(
        "    [specs] seeded %d function(s) for spec re-generation (%d changed, %d relevant).",
        len(seed), len(changed_targets), len(relevant_rel_files),
    )

    # Top-down order (callers before the callees they depend on); FQNs absent from the layer
    # graph sort last, by name.
    topdown = _topdown_ordered_fqns(work_dir, extra_call_edges=extra_call_edges)
    order_index = {fqn: i for i, fqn in enumerate(topdown)}

    def _order_key(fqn):
        return (order_index.get(fqn, len(order_index)), fqn)

    def _plan_spec_update(fqn, idx):
        """
        Decide fqn's new metadata sidecars and return an apply-plan, or None to skip.

        Makes the opencode LLM call (the slow part) but performs NO file writes, so a batch of
        mutually independent functions can run this concurrently. The returned plan carries the
        exact file content to write plus what the serial apply phase needs for downward
        propagation; None means the function does not exist, is an unsupported language, or its
        spec did not change.
        """
        fpath = file_map.get(fqn)
        if not fpath or not os.path.isfile(fpath):
            return None
        ext = fpath.rsplit(".", 1)[-1] if "." in os.path.basename(fpath) else ""
        lang_key = EXT_TO_LANG.get(ext)
        if not lang_key:
            return None
        with open(fpath, "r", errors="replace") as f:
            source = f.read()
        callee_names = sorted({c.split("::")[-1] for c in callees_map.get(fqn, ())})

        try:
            with open(f"{fpath}.spec.json", "r", encoding="utf-8") as f:
                old_spec = json.load(f)
            with open(f"{fpath}.info.json", "r", encoding="utf-8") as f:
                old_info = json.load(f)
        except (OSError, json.JSONDecodeError):
            old_spec, old_info = None, None

        if old_spec is None or old_info is None:
            # No existing specification (e.g. a freshly added, unspecced function) — generate
            # one from scratch the way the full run does, rather than skipping the function.
            caller_context = _collect_caller_context(
                fqn, callers_map, file_map, edge_aliases_map
            )
            result = _opencode_generate_spec(
                proj_dir, work_dir, idx, fqn, lang_key, "",
                developer_intent, callee_names, source, caller_context,
            )
        else:
            result = _llm_check_spec_update(
                proj_dir, work_dir, idx, fqn, lang_key, "",
                developer_intent, old_spec, old_info, callee_names, source,
            )

        if not result or not result.get("spec_updated"):
            return None
        new_spec = result.get("new_spec")
        if not isinstance(new_spec, dict):
            return None

        if old_info is None:
            # Freshly generated: take the .info.json object opencode produced. Treat it as
            # "updated" so its recorded callee expectations propagate downward below.
            new_info = result.get("new_info")
            if not isinstance(new_info, dict):
                new_info = {"callees": []}
            info_updated = True
        else:
            # Keep the existing .info.json unless opencode rewrote it. A modified function may
            # now call a different set of callees, so a fresh .info.json can legitimately be
            # created even when the function previously had none (old_info is None) — gate on
            # whether opencode produced a block, not on a prior block existing.
            info_updated = bool(result.get("info_updated"))
            new_info = result.get("new_info") if info_updated else old_info
            if not isinstance(new_info, dict):
                new_info = old_info

        return {
            "fqn": fqn,
            "fpath": fpath,
            "spec_dict": _normalize_spec_dict(new_spec),
            "info_dict": _normalize_info_dict(new_info),
            "info_updated": info_updated,
            "updated_callees": result.get("updated_callees") or [],
        }

    def _reconcile_caller(caller_fqn, updates, base_idx):
        """
        Reconcile caller_fqn's .info.json against a sequence of changed callees.

        updates is a list of (callee_name, callee_new_spec). The entries are applied
        sequentially, re-reading the caller file between each, because they all edit the same
        file — so a single caller is one unit of work and DIFFERENT callers run concurrently
        (see the batch loop). base_idx + offset gives each opencode call a unique artifact name.
        Returns the caller's path if any reconciliation changed it, else None.
        """
        cpath = file_map.get(caller_fqn)
        if not cpath or not os.path.isfile(cpath):
            return None
        cext = cpath.rsplit(".", 1)[-1] if "." in os.path.basename(cpath) else ""
        clang = EXT_TO_LANG.get(cext)
        if not clang:
            return None
        changed = False
        for offset, (callee_name, callee_new_spec) in enumerate(updates):
            with open(cpath, "r", errors="replace") as f:
                csource = f.read()
            try:
                with open(f"{cpath}.info.json", "r", encoding="utf-8") as f:
                    c_info = json.load(f)
            except (OSError, json.JSONDecodeError):
                continue

            cresult = _llm_check_caller_info_update(
                proj_dir, work_dir, base_idx + offset, caller_fqn, callee_name, clang, "",
                callee_new_spec, c_info, csource,
            )
            if not cresult or not cresult.get("info_updated"):
                continue
            c_new_info = cresult.get("new_info")
            if not isinstance(c_new_info, dict):
                continue

            with open(f"{cpath}.info.json", "w", encoding="utf-8") as f:
                json.dump(_normalize_info_dict(c_new_info), f, indent=2, ensure_ascii=False)
            changed = True
        return cpath if changed else None

    checked = set()
    to_check = set(seed)
    changed_spec_files = set()
    counter = 0
    round_num = 0

    # Process the pending frontier in rounds. Each round takes the maximal set of mutually
    # independent functions — those with no still-pending caller, i.e. the roots of the current
    # frontier — and runs them concurrently. None of them is a caller/callee of another (a
    # function with a pending caller is held back), so their spec decisions don't influence each
    # other and can race safely; callees they queue are picked up in a later round, after their
    # caller, preserving the original caller-before-callee ordering.
    while True:
        pending = sorted(to_check - checked, key=_order_key)
        if not pending:
            break
        pending_set = set(pending)
        batch = [fqn for fqn in pending if not (callers_map.get(fqn, set()) & pending_set)]
        if not batch:
            # A pure cycle (every pending function has a pending caller): break it by taking
            # the single top-ordered function so the loop still makes progress.
            batch = [pending[0]]
        checked.update(batch)
        round_num += 1
        logging.info(
            "    [specs] round %d: checking %d function(s) (%d pending, %d checked so far)...",
            round_num, len(batch), len(pending), len(checked),
        )

        # Stage 1 (concurrent): decide each function's new spec — LLM-bound, no file writes.
        base = counter
        counter += len(batch)
        plans = [None] * len(batch)
        with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            futures = {
                executor.submit(_plan_spec_update, fqn, base + i): i
                for i, fqn in enumerate(batch)
            }
            for future in concurrent.futures.as_completed(futures):
                i = futures[future]
                try:
                    plans[i] = future.result()
                except Exception:
                    logging.exception("Spec planning failed for %s", batch[i])
        applied = [p for p in plans if p]

        # Stage 2 (serial): write the new spec files and queue downward callees — no LLM, fast.
        # Kept serial so the shared to_check / changed_spec_files sets need no locking.
        queued_callees = 0
        for plan in applied:
            with open(f"{plan['fpath']}.spec.json", "w", encoding="utf-8") as f:
                json.dump(plan["spec_dict"], f, indent=2, ensure_ascii=False)
            with open(f"{plan['fpath']}.info.json", "w", encoding="utf-8") as f:
                json.dump(plan["info_dict"], f, indent=2, ensure_ascii=False)
            changed_spec_files.add(os.path.relpath(plan["fpath"], extracted_dir))
            if plan["info_updated"]:
                for callee_fqn in _resolve_callee_fqns(
                    plan["fqn"], plan["updated_callees"], callees_map, edge_aliases_map
                ):
                    if callee_fqn not in checked:
                        to_check.add(callee_fqn)
                        queued_callees += 1
        logging.info(
            "    [specs] round %d: %d spec(s) rewritten, %d callee(s) queued for propagation.",
            round_num, len(applied), queued_callees,
        )

        # Stage 3 (concurrent): upward reconciliation. Each function whose .spec.json changed
        # needs every caller's .info.json entry reconciled. Group by caller file so edits
        # to one file are serialized while different caller files reconcile in parallel. Callers
        # sit above the batch in top-down order and are never themselves in the batch, so their
        # files don't collide with the Stage 2 writes.
        caller_updates = {}  # caller_fqn -> list of (callee_name, callee_new_spec)
        for plan in applied:
            callee_name = plan["fqn"].split("::")[-1]
            for caller_fqn in sorted(callers_map.get(plan["fqn"], ())):
                caller_updates.setdefault(caller_fqn, []).append((callee_name, plan["spec_dict"]))

        if caller_updates:
            group_base = {}  # pre-assign a contiguous idx block per caller for unique artifacts
            for caller_fqn, updates in caller_updates.items():
                group_base[caller_fqn] = counter
                counter += len(updates)
            with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
                futures = {
                    executor.submit(
                        _reconcile_caller, caller_fqn, updates, group_base[caller_fqn]
                    ): caller_fqn
                    for caller_fqn, updates in caller_updates.items()
                }
                for future in concurrent.futures.as_completed(futures):
                    caller_fqn = futures[future]
                    try:
                        cpath = future.result()
                    except Exception:
                        logging.exception("Caller .info.json reconciliation failed for %s", caller_fqn)
                        continue
                    if cpath:
                        changed_spec_files.add(os.path.relpath(cpath, extracted_dir))

    return sorted(changed_spec_files)


def _verify_incremental_functions(
    proj_dir, work_dir, changed_functions, updated_spec_files, submodules=None
):
    """
    Step 10: re-run the verification stage (reasoner + bug validation) on only the functions
    whose implementation-vs-spec verdict may have drifted because of this modification.

    A function is verified when it satisfies at least one of:
      1) it was changed in the working tree (added or modified), or
      2) its own .spec.json or .info.json sidecar was updated in step 9.

    Note on callees: a function whose callee's .spec.json changed needs re-verification ONLY
    if that change forced its own .info.json (the callee contract it reasons against) to be
    updated. Step 9's upward reconciliation already rewrites exactly those callers' .info.json
    blocks and includes them in updated_spec_files, so condition (2) covers them — a caller
    whose .info.json did not need to change is left alone and is correctly NOT re-verified.

    Each target is verified by invoking the reasoner (src/reasoner.py, via the per-file
    wrapper verification._verify_single_file, which calls reasoner() and writes the result
    JSON) — not the streaming watcher. The stale verification result of every target is
    removed first so the reasoner re-runs against the current implementation and (possibly
    updated) spec rather than reusing the cached verdict from the previous full run.

    A reasoner MISMATCH is only a candidate bug; each one is then handed to bug validation
    (verification._validate_single_bug, an opencode pass) which confirms or rejects it.

    Returns the sorted list of extracted-function files (paths relative to the
    extracted_functions dir) whose reasoner MISMATCH was confirmed a bug by bug validation.
    """
    extracted_dir = os.path.join(work_dir, "extracted_functions")
    output_dir = os.path.join(work_dir, "logic_verification_results")

    verify_targets = set()  # absolute extracted-function paths

    # (1) Functions changed in the working tree (added/modified; removed ones are gone).
    verify_targets.update(
        _modified_function_targets(
            proj_dir, changed_functions, classes=("added", "modified")
        ).values()
    )

    # (2) Functions whose .spec.json or .info.json was updated in step 9 (updated_spec_files
    #     already includes both functions whose own spec changed and callers whose .info.json
    #     was reconciled against an updated callee).
    for rel in updated_spec_files:
        verify_targets.add(os.path.join(extracted_dir, rel))

    # Keep only functions that still exist on disk; the reasoner reads these extracted files
    # directly and skips any without valid metadata sidecars.
    file_list = sorted({
        os.path.relpath(path, extracted_dir)
        for path in verify_targets
        if os.path.exists(path)
    })
    if submodules:
        file_list = [
            rel for rel in file_list
            if _is_under_submodules(rel.replace(os.sep, "/"), submodules)
        ]
    if not file_list:
        logging.info("    [verify] no functions require re-verification.")
        return []
    logging.info("    [verify] running reasoner on %d function(s)...", len(file_list))

    # Drop stale verification results so the reasoner re-runs rather than reusing the cached
    # verdict from the previous full run.
    for rel in file_list:
        stale = os.path.join(output_dir, os.path.splitext(rel)[0] + ".json")
        if os.path.exists(stale):
            os.remove(stale)

    # Verify every target by invoking the reasoner (via _verify_single_file). The reasoner
    # makes LLM calls, so run the targets concurrently like the full run does, bounded by
    # MAX_WORKERS. _verify_single_file writes each verdict to output_dir and returns it.
    mismatches = []

    def _verify(rel):
        fpath = os.path.join(extracted_dir, rel)
        language = _VERIFY_EXT_TO_LANG.get(os.path.splitext(fpath)[1], "C")
        _, verdict = _verify_single_file(fpath, extracted_dir, output_dir, language, work_dir=work_dir)
        return rel, verdict

    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {executor.submit(_verify, rel): rel for rel in file_list}
        for future in concurrent.futures.as_completed(futures):
            rel = futures[future]
            try:
                _, verdict = future.result()
            except Exception:
                logging.exception("Verification failed for %s", rel)
                continue
            if verdict == "MISMATCH":
                mismatches.append(rel)

    logging.info("    [verify] reasoner reported %d MISMATCH(es) (candidate bugs).", len(mismatches))
    if not mismatches:
        return []

    # Bug validation: the reasoner's MISMATCH is only a candidate bug, so validate each one
    # with opencode (_validate_single_bug writes work_dir/bug_validation/<bug_id>.result.json
    # with a confirmation_status). Run them concurrently, bounded by MAX_WORKERS.
    logging.info("    [verify] validating %d candidate bug(s) with opencode...", len(mismatches))

    def _validate(rel):
        result_json_rel = os.path.join(
            os.path.relpath(output_dir, proj_dir),
            os.path.splitext(rel)[0] + ".json",
        )
        _validate_single_bug(result_json_rel, proj_dir, work_dir)
        return rel

    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {executor.submit(_validate, rel): rel for rel in mismatches}
        for future in concurrent.futures.as_completed(futures):
            rel = futures[future]
            try:
                future.result()
            except Exception:
                logging.exception("Bug validation failed for %s", rel)

    # Summarize all validation results into work_dir/bug_validation/summary.json, like run_pipeline.
    _generate_validation_summary(work_dir)

    # Collect the MISMATCHes that bug validation confirmed as real bugs. bug_id is the
    # result-relative path with separators replaced by "--".
    bug_validation_dir = os.path.join(work_dir, "bug_validation")
    confirmed = []
    for rel in mismatches:
        bug_id = os.path.splitext(rel)[0].replace(os.sep, "--").replace("/", "--")
        result_path = os.path.join(bug_validation_dir, f"{bug_id}.result.json")
        if not os.path.exists(result_path):
            continue
        try:
            with open(result_path) as rf:
                data = json.load(rf)
        except (ValueError, OSError):
            continue
        if data.get("confirmation_status") == "confirmed":
            confirmed.append(rel)

    return sorted(confirmed)

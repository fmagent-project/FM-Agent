import os
import json
import time
import logging
import subprocess
import tempfile
import concurrent.futures
from pathlib import Path

from config import (
    OPENCODE_MODEL_PROVIDER,
    OPENCODE_SETUP_MODEL,
    OPENCODE_MAX_RETRIES,
    MAX_WORKERS,
)
from .extract import (
    EXT_TO_LANG,
    LANG_CONFIG,
    _is_test_file,
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
from .file_utils import is_file_ready, collect_file_names
from .generate_batch_prompts import (
    _detect_comment_prefix,
    extract_callee_spec_from_info,
    extract_info_block,
    extract_spec_block,
)
from .opencode_trace import run_opencode_traced
from .scope import _parse_issue_signals, rank_functions_in_file
from .verification import _verify_single_file, _validate_single_bug, EXT_TO_LANG as _VERIFY_EXT_TO_LANG


def check_last_run_existence(proj_dir):
    """
    Return whether a full pipeline run (run_pipeline) has already completed under proj_dir.

    Incremental analysis compares the current working tree against the artifacts left by a
    previous full run, so it can only proceed when those artifacts are present. A full run
    is considered to exist when, under proj_dir/fm_agent/, both:

      1. phases.json exists — the module/phase plan that the full run aborts without, and
      2. extracted_functions/ holds at least one function file and EVERY function file
         there is specced (carries the [SPEC]/[INFO] blocks, per is_file_ready) — proving
         the spec-generation stage ran to completion. A partially specced tree means the
         previous full run did not finish, so it is not a sound basis for incremental
         analysis.

    Returns True only when both hold; otherwise False (so the caller can fall back to a
    full run rather than fail on missing/incomplete phases.json / extracted_functions).
    """
    work_dir = os.path.join(proj_dir, "fm_agent")

    if not os.path.isfile(os.path.join(work_dir, "phases.json")):
        return False

    extracted_dir = os.path.join(work_dir, "extracted_functions")
    if not os.path.isdir(extracted_dir):
        return False

    for root, _, files in os.walk(extracted_dir):
        for fname in files:
            if not is_file_ready(os.path.join(root, fname)):
                return False
    return True


def extract_existing_specs(proj_dir):
    """
    Collect the leading [SPEC]/[INFO] blocks from every specced file produced by a
    previous full run (the extracted_functions tree that _run_setup_extract +
    extraction/spec-generation leaves behind under proj_dir/fm_agent/).

    Each extracted function file begins with a behavioral specification block, in the
    Spec Format from md/system_prompt.md: a `<comment> [SPEC]` ... `<comment> [SPEC]`
    block optionally followed by a `<comment> [INFO]` ... `<comment> [INFO]` block, and
    then the (unchanged) function source. This walks fm_agent/extracted_functions/ and,
    for every file that carries a [SPEC] block, records that header text so a caller can
    reuse the previous run's specs instead of re-deriving them.

    Returns a dict mapping each file's path (relative to the extracted_functions dir,
    matching the convention used elsewhere in this module) to a
    {"spec": <spec block>, "info": <info block or None>} entry. The "spec" string is the
    full `[SPEC]` ... `[SPEC]` block (markers included); "info" is the full
    `[INFO]` ... `[INFO]` block (markers included), or None when the file has no [INFO]
    block. Files without a [SPEC] block are skipped. Returns an empty dict when the
    extracted_functions directory does not exist.
    """
    extracted_dir = os.path.join(proj_dir, "fm_agent", "extracted_functions")
    if not os.path.isdir(extracted_dir):
        return {}

    specs = {}
    for root, _, files in os.walk(extracted_dir):
        for fname in files:
            file_path = Path(root) / fname
            spec_block = extract_spec_block(file_path)
            info_block = extract_info_block(file_path)

            if spec_block is None:
                continue
            rel_path = os.path.relpath(str(file_path), extracted_dir)

            # extract_info_block returns only the content between the [INFO]
            # markers; re-wrap it with the markers so we record the entire
            # info block (ready to prepend verbatim).
            full_info_block = None
            if info_block is not None:
                prefix = _detect_comment_prefix(spec_block) or ""
                info_tag = f"{prefix} [INFO]".strip()
                full_info_block = f"{info_tag}\n{info_block}\n{info_tag}"

            specs[rel_path] = {
                "spec": spec_block,
                "info": full_info_block,
            }
    return specs


def _reapply_existing_specs(proj_dir, specs):
    """
    Prepend previously captured [SPEC]/[INFO] header blocks back onto the freshly
    re-extracted function files.

    specs is the mapping returned by extract_existing_specs (rel_path ->
    {"spec": ..., "info": ...}), captured BEFORE the extracted_functions tree was
    regenerated for the current working tree (re-extraction writes the raw function source
    only, dropping the spec header). For every recorded entry whose file still exists after
    re-extraction, this reconstructs the leading spec-comment block — the [SPEC] block,
    plus an [INFO] block when one was recorded — and prepends it to the file, restoring the
    Spec Format the previous run produced. Entries whose file no longer exists (their
    function was removed or renamed) and files that already carry a [SPEC] block are
    skipped, so the call is idempotent.

    Returns the number of files to which a spec block was (re)applied.
    """
    extracted_dir = os.path.join(proj_dir, "fm_agent", "extracted_functions")
    for rel_path, entry in specs.items():
        spec_block = entry.get("spec")
        if not spec_block:
            continue
        file_path = os.path.join(extracted_dir, rel_path)
        if not os.path.isfile(file_path):
            continue

        with open(file_path, "r") as f:
            source = f.read()

        # Skip files that already carry a spec header (idempotency / nothing to restore on).
        first_line = source.splitlines()[0] if source else ""
        if "[SPEC]" in first_line:
            continue

        # Reassemble in the full run's specced-file layout: [SPEC], blank line,
        # optional [INFO], blank line, source (mirrors _update_specs_for_intent's splice).
        header = spec_block.rstrip("\n")
        info_block = entry.get("info")
        if info_block is not None:
            # "info" already holds the entire [INFO] block (markers included),
            # so it can be appended to the spec header verbatim.
            header += "\n\n" + info_block.strip("\n")

        with open(file_path, "w") as f:
            f.write(header + "\n\n" + source.lstrip("\n"))


def _collect_changed_functions(proj_dir, old_commit_id):
    """
    Determine which functions changed between commit old_commit_id and the current working
    tree under proj_dir, so the incremental pipeline only re-analyzes what actually moved.

    Only source files whose extension is in EXT_TO_LANG are considered; test files (per
    _is_test_file) and anything under the fm_agent work dir are ignored. For each candidate
    file, functions are extracted from both the old (old_commit_id) version and the current
    working-tree version using the same parser as extract.py, then compared by source text.

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
    untracked_set = set(untracked)
    files = [
        f for f in changed + untracked
        if not _is_test_file(f) and not _is_workspace_file(f)
    ]

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
        if rel_path in untracked_set:
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
    for path in removed.values():
        if os.path.isfile(path):
            os.remove(path)
    for path in removed.values():
        func_dir = os.path.dirname(path)
        if os.path.isdir(func_dir) and not os.listdir(func_dir):
            os.rmdir(func_dir)


def _extract_leading_spec_comments(content, comment_prefix, spec_marker):
    """
    Return the leading spec-comment block of content, or None if absent.

    A spec-comment block is the run of leading lines (per the "### Spec Format" in
    md/system_prompt.md) that begins, ignoring blank lines, with the language's spec
    marker (e.g. "# [SPEC]") and consists of comment lines (lines whose first
    non-whitespace character sequence is comment_prefix) optionally interleaved with
    blank lines, up to the first line of original source code. The returned string
    includes any blank separator line(s) between the comment block and the source, so
    that prepending it to the raw source reconstructs the specced file.
    """
    lines = content.splitlines(keepends=True)

    # First non-blank line must be the spec marker for this to be a spec block.
    first = 0
    while first < len(lines) and lines[first].strip() == "":
        first += 1
    if first >= len(lines) or lines[first].strip() != spec_marker.strip():
        return None

    # Consume comment lines (and interspersed blank lines) until the source begins,
    # i.e. the first non-blank line that is not a comment.
    i = first
    last_comment = first
    while i < len(lines):
        stripped = lines[i].strip()
        if stripped == "":
            i += 1
            continue
        if stripped.startswith(comment_prefix):
            last_comment = i
            i += 1
            continue
        break

    # A genuine spec block has more than one comment line.
    if last_comment == first:
        return None

    return "".join(lines[:i])


def _split_spec_and_info(block, comment_prefix, spec_marker):
    """
    Split a leading spec-comment block into its [SPEC] portion and its [INFO] portion.

    block is a spec-comment block as returned by _extract_leading_spec_comments (the
    [SPEC] ... [SPEC] block optionally followed by an [INFO] ... [INFO] block, per the
    Spec Format in md/system_prompt.md). Returns a (spec_block, info_block) tuple of
    strings stripped of surrounding blank lines; info_block is None when no [INFO]
    section is present. If the markers cannot be located the whole block is returned as
    spec_block with a None info_block, so callers always get the spec text back.
    """
    lines = block.splitlines()
    spec_tag = spec_marker.strip()
    info_tag = (comment_prefix + " [INFO]").strip()

    spec_idxs = [i for i, ln in enumerate(lines) if ln.strip() == spec_tag]
    info_idxs = [i for i, ln in enumerate(lines) if ln.strip() == info_tag]

    if len(spec_idxs) >= 2:
        spec_end = spec_idxs[1]
    elif info_idxs:
        spec_end = info_idxs[0] - 1
    else:
        return block.strip("\n"), None

    spec_block = "\n".join(lines[: spec_end + 1]).strip("\n")

    if len(info_idxs) >= 2:
        info_block = "\n".join(lines[info_idxs[0]: info_idxs[1] + 1]).strip("\n")
    elif info_idxs:
        info_block = "\n".join(lines[info_idxs[0]:]).strip("\n")
    else:
        info_block = None

    return spec_block, info_block


def _topdown_ordered_fqns(work_dir):
    """
    Return every extracted-function FQN in the top-down order used by run_pipeline for
    spec generation: phases in ascending phase number, layers from 0 upward, and the
    functions in the order listed within each layer (callers precede the callees they
    depend on).

    Regenerates the per-phase topdown-layer JSON files under work_dir/spec_prompts/ as
    a side effect (mirroring run_pipeline's generate_topdown_layers(work_dir) call).
    """
    generate_topdown_layers(work_dir)
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


def run_incremental_pipeline(proj_dir, intent_file_path, old_commit_id):
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

    # 1. Check whether there is a last run to compare against; if not, fall back to a full run since we have no basis for incremental analysis.
    has_last_run = check_last_run_existence(proj_dir)
    if not has_last_run:
        print(
            "No previous full run detected (phases.json missing or incomplete extracted_functions), so falling back to a full run rather than incremental."
        )
        run_pipeline(proj_dir)
        return

    # 2. Check whether the intent file is valid; if not, fail since we don't know what to analyze incrementally.
    developer_intent = ""
    if not os.path.isfile(intent_file_path):
        print(f"Intent file {intent_file_path} does not exist; cannot run incremental pipeline.")
        return
    else:
        with open(intent_file_path, "r") as f:
            developer_intent = f.read().strip()
        if not developer_intent:
            print(f"Intent file {intent_file_path} is empty; cannot run incremental pipeline.")
            return
    
    # 3. Re-generate the phases.json
    print("Generating new phases.json based on current working tree...")
    phases_json_path = os.path.join(proj_dir, "fm_agent", "phases.json")
    _run_setup_extract(proj_dir, work_dir, script_dir, is_incremental=True)

    # 4. Update functions under fm_agent/extracted_functions/.
    #    Capture the previous run's specs first (re-extraction overwrites each file with
    #    the raw source for the current code), then re-extract, then restore the captured
    #    [SPEC]/[INFO] headers onto every function that still exists. Functions that were
    #    added or whose extraction path changed are left unspecced for the spec-update
    #    stage to handle; unchanged functions keep their previous specs verbatim.
    print("Re-extracting functions that changed since last run...")
    old_spec = extract_existing_specs(proj_dir)
    run_extraction(proj_dir, work_dir=work_dir, force=True, verbose=True)
    _reapply_existing_specs(proj_dir, old_spec)

    # 5. Collect changed functions by comparing against the old version of functions in commit_id
    print("Collecting changed functions by comparing against previous commit...")
    changed_functions = _collect_changed_functions(proj_dir, old_commit_id)

    # 5b. Delete extracted-function files for functions (or whole source files) that were
    #     removed since old_commit_id. Re-extraction never rewrites these, so without this
    #     they linger as stale specs and would pollute the file list and call graph below.
    _remove_stale_extracted(proj_dir, changed_functions)

    # 6. Update file list
    print("Collecting file list...")
    file_list = collect_file_names(input_dir, os.path.join(work_dir, "fm_agent_file_list.json"))

    # 7. Update top-down layers
    print("Generating topdown layers...")
    phases_data = json.load(open(os.path.join(work_dir, "phases.json")))
    generate_topdown_layers(work_dir)

    # 8. Collect the scope of functions relevant to the developer intent (the intent file defines the goal of modification).
    print("Collecting functions relevant to the developer intent...")
    spec_files = collect_relevent_function_scope(proj_dir, developer_intent, changed_functions)

    # 9. Re-generate the spec of functions if it satisfies one of the following conditions: 1) the function is changed; 2) the function is relevant to the developer intent.
    print("Updating specs for changed and relevant functions...")
    updated_spec_files = _update_specs_for_intent(
        proj_dir, work_dir, developer_intent, changed_functions, spec_files
    )
    record_path = os.path.join(work_dir, "incremental_updated_specs.json")
    with open(record_path, "w") as f:
        json.dump({"updated_specs": updated_spec_files}, f, indent=2)
    

    # 10. Run the verification stage only on the functions that satisfy one of the following conditions: 1) the function is changed; 2) the function spec is changed after step 9; 3) the callee spec of the function is changed.
    print("Verifying changed and affected functions...")
    buggy_files = _verify_incremental_functions(
        proj_dir, work_dir, changed_functions, updated_spec_files
    )
    print(f"Bug validation confirmed bugs in {len(buggy_files)} function(s).")
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

    command = [
        "opencode", "run", "--model", f"{OPENCODE_MODEL_PROVIDER}/{OPENCODE_SETUP_MODEL}",
        "--file", prompt_path,
        "--", "Follow the instructions in the attached file.",
    ]

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


def collect_relevent_function_scope(proj_dir, developer_intent, changed_functions, range=None):
    """
    Select the functions relevant to developer_intent and return the most relevant ones.

    The module/phase plan in proj_dir/fm_agent/phases.json describes the project as a set
    of modules, each with a natural-language description and a list of source_files. This
    narrows the scope to the developer's intent in three passes:

      1. Module selection — opencode (OPENCODE_SETUP_MODEL) reads the module descriptions in
         phases.json and picks the modules relevant to the intent.
      2. File selection — for each relevant module, opencode reads that module's source
         files and picks the files relevant to the intent.
      3. Function selection — the function-localization algorithm from scope.py ranks the
         functions in each chosen file by relevance to the intent (heuristic signal scoring
         with call-graph, class-scope, proximity, and git-history enrichments) and keeps the
         top-ranked functions per file.

    The selected functions are mapped back to their extracted-function files. A chosen file
    that scope.py cannot localize within (e.g. a non-Python source it cannot AST-parse, or a
    parse failure) contributes all of its extracted functions rather than being dropped.

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
        return []

    # Pass 1: module selection. opencode reads fm_agent/phases.json itself (the agent's cwd
    # is proj_dir), reasons over the module descriptions, and writes the selected modules to
    # a result file we read back.
    module_prompt = (
        "# Select Relevant Modules\n\n"
        "You are triaging which parts of a codebase are relevant to a developer's intent.\n\n"
        "## Steps\n\n"
        "1. Read `fm_agent/phases.json`. It lists phases, each containing modules; every "
        "module has a `name`, a `description`, and a `source_files` list.\n"
        "2. Using each module's `description`, decide which modules are relevant to the "
        "developer intent below. A module is relevant if the developer intent is likely to "
        "affect it or depend on it.\n"
        "3. Write your answer to `fm_agent/relevant_modules.json` as a JSON array of "
        'objects, each `{"phase": <phase number>, "name": "<module name>"}`, naming exactly '
        "the modules you judged relevant (reuse the same `phase` and `name` values from "
        "phases.json). Write `[]` if no module is relevant. Write ONLY that file; do not "
        "modify any other project files.\n\n"
        "## Developer intent\n\n"
        f"{developer_intent}\n"
    )
    selection = _opencode_select_json(
        proj_dir,
        work_dir,
        os.path.join("fm_agent", "select_relevant_modules.md"),
        module_prompt,
        os.path.join("fm_agent", "relevant_modules.json"),
        stage="select_relevant_modules",
        input_files=["fm_agent/select_relevant_modules.md", "fm_agent/phases.json"],
    )
    if selection is None:
        return []

    selected_keys = set()
    if isinstance(selection, list):
        for item in selection:
            if isinstance(item, dict) and "name" in item:
                selected_keys.add((item.get("phase"), item["name"]))

    relevant_modules = [
        (phase_num, module) for phase_num, module in modules
        if (phase_num, module.get("name")) in selected_keys
    ]
    if not relevant_modules:
        return []

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

        file_list_md = "\n".join(f"- `{sf}`" for sf in source_files)
        file_prompt = (
            "# Select Relevant Files\n\n"
            f"You are triaging which files of the module `{module_name}` are relevant to a "
            "developer's intent.\n\n"
            "## Steps\n\n"
            "1. Read each of the module's source files listed below.\n"
            "2. Decide which files are relevant to the developer intent — a file is relevant "
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

        source_set = set(source_files)
        if isinstance(file_selection, list):
            chosen = [sf for sf in file_selection if sf in source_set]
        else:
            # opencode failed for this module — keep all of its files rather than drop scope.
            chosen = list(source_files)

        if chosen:
            filtered_modules.append({**module, "source_files": chosen})

    if not filtered_modules:
        return []

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
                    repo_dir=repo_dir,
                )

            if ranked:
                # Keep the extracted-function file for each selected function name.
                for f in ranked:
                    cand = os.path.join(func_dir, f"{f['name']}.{ext}")
                    if os.path.isfile(cand):
                        _record(os.path.relpath(cand, extracted_dir), f.get("score", 0.0))
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
    return ordered


def _project_call_graph(work_dir):
    """
    Build the project-wide call graph (keyed by FQN) over every extracted function.

    Treats all extracted functions across every phase in phases.json as one graph, so
    callee/caller edges span the whole project. Returns (callees_map, callers_map,
    file_map): callees_map maps each FQN to the set of FQNs it calls directly, callers_map
    the inverse (each FQN to the FQNs that call it directly), and file_map maps each FQN to
    the absolute path of its extracted-function file.
    """
    phases = _load_phases(work_dir)
    all_files = []
    seen = set()
    for phase in phases.get("phases", []):
        for fpath, module_name in _collect_phase_files(work_dir, phase):
            if fpath not in seen:
                seen.add(fpath)
                all_files.append((fpath, module_name))

    callees_map, callers_map, _all_callees, file_map, _modmap = _build_call_graph(all_files, work_dir)
    return callees_map, callers_map, file_map


def _resolve_callee_fqns(caller_fqn, callee_names, callees_map):
    """
    Map callee names reported by opencode (the [INFO] entries whose expected spec changed)
    back to the FQNs of caller_fqn's callees.

    A callee is identified in the [INFO] block by its name; this matches that name against
    the final component (stem) of each of caller_fqn's callee FQNs, case-insensitively, and
    returns every matching callee FQN (a name shared by callees in several files resolves to
    all of them).
    """
    wanted = {n.strip() for n in callee_names if n and n.strip()}
    wanted_lower = {n.lower() for n in wanted}
    resolved = set()
    for callee_fqn in callees_map.get(caller_fqn, ()):
        stem = callee_fqn.split("::")[-1]
        if stem in wanted or stem.lower() in wanted_lower:
            resolved.add(callee_fqn)
    return resolved


def _opencode_check_spec_update(proj_dir, work_dir, idx, fqn, lang_key, comment_prefix,
                                developer_intent, spec_block, info_block, callee_names, source):
    """
    Ask opencode whether a function's [SPEC] (and, if so, its [INFO]) block must change to
    reflect developer_intent, and return the parsed decision.

    Returns the parsed result dict — keys: "spec_updated" (bool), "new_spec" (str),
    "info_updated" (bool), "new_info" (str), "updated_callees" (list[str]) — or None when
    opencode produced nothing usable.
    """
    result_relpath = os.path.join("fm_agent", f"spec_update_{idx}.json")
    prompt_relpath = os.path.join("fm_agent", f"spec_update_{idx}.md")

    callee_hint = ", ".join(sorted(callee_names)) if callee_names else "(none)"
    if info_block is not None:
        info_section = (
            "## Current [INFO] block (the expected specs of the callees this function depends on)\n\n"
            f"{info_block}\n\n"
        )
    else:
        info_section = "This function has no [INFO] block, so skip the [INFO] step.\n\n"

    prompt_content = (
        "# Update Function Specification\n\n"
        "A modification is being applied to a codebase to achieve the developer intent "
        "below. Decide whether this function's behavioral specification must change to "
        "reflect that intent.\n\n"
        f"- Function fully-qualified name: `{fqn}` (language: `{lang_key}`).\n"
        f"- Comment prefix for this language: `{comment_prefix}`.\n"
        f"- Known callees of this function: {callee_hint}.\n\n"
        "## Developer intent\n\n"
        f"{developer_intent}\n\n"
        "## Current function source\n\n"
        f"```{lang_key}\n{source.strip()}\n```\n\n"
        "## Current [SPEC] block (this function's own behavioral specification)\n\n"
        f"{spec_block}\n\n"
        f"{info_section}"
        "## Steps\n\n"
        "1. Decide whether the [SPEC] block still correctly and completely describes the "
        "function's behavior after the intended modification. If it remains correct, no "
        "update is needed.\n"
        "2. If it must change, produce the COMPLETE replacement [SPEC] block — the "
        "`[SPEC]` ... `[SPEC]` block only, markers included, every line prefixed with "
        f"`{comment_prefix}`, and NO source code.\n"
        "3. ONLY if you updated the [SPEC] block AND this function has an [INFO] block: "
        "decide whether the expected spec of any callee recorded in the [INFO] block must "
        "change as a consequence. If so, produce the COMPLETE replacement [INFO] block (the "
        f"`[INFO]` ... `[INFO]` block only, markers included, lines prefixed with `{comment_prefix}`) "
        "and list the names of the callees whose expected spec you changed.\n"
        f"4. Write your answer to `{result_relpath}` as a JSON object with keys:\n"
        '   - "spec_updated": boolean.\n'
        '   - "new_spec": string — the full replacement [SPEC] block, or "" if not updated.\n'
        '   - "info_updated": boolean.\n'
        '   - "new_info": string — the full replacement [INFO] block, or "" if not updated.\n'
        '   - "updated_callees": array of callee name strings whose expected spec changed, or [].\n'
        "   Write ONLY that JSON file; do not modify any other project files.\n"
    )

    return _opencode_select_json(
        proj_dir,
        work_dir,
        prompt_relpath,
        prompt_content,
        result_relpath,
        stage="update_function_spec",
        input_files=[prompt_relpath],
    )


def _opencode_check_caller_info_update(proj_dir, work_dir, idx, caller_fqn, callee_name,
                                       lang_key, comment_prefix, callee_new_spec,
                                       caller_info_block, caller_source):
    """
    Ask opencode whether a caller's [INFO] block must change to stay consistent with a
    callee whose [SPEC] block was just updated.

    The caller's [INFO] block records the expected specs of the callees it depends on. This
    asks opencode to reconcile only the entry for callee_name with the callee's new spec —
    consistency, not equality: the entry must merely not conflict with the new spec, and the
    entries for other callees are left untouched. Returns the parsed result dict — keys
    "info_updated" (bool) and "new_info" (str) — or None when opencode produced nothing
    usable.
    """
    result_relpath = os.path.join("fm_agent", f"caller_info_update_{idx}.json")
    prompt_relpath = os.path.join("fm_agent", f"caller_info_update_{idx}.md")

    prompt_content = (
        "# Reconcile a Caller's [INFO] Block with a Changed Callee\n\n"
        f"The callee `{callee_name}`'s behavioral specification was just updated. The caller "
        f"`{caller_fqn}` (language `{lang_key}`) records the expected specs of the callees it "
        "depends on in its [INFO] block. Update that block so its entry for the callee is "
        "CONSISTENT with the callee's new spec — it need NOT be identical, it only must not "
        "conflict (no contradictory pre/post-conditions). Leave the entries for every other "
        "callee unchanged.\n\n"
        f"Comment prefix for this language: `{comment_prefix}`.\n\n"
        "## Callee's updated [SPEC] block\n\n"
        f"{callee_new_spec}\n\n"
        "## Caller's current source\n\n"
        f"```{lang_key}\n{caller_source.strip()}\n```\n\n"
        "## Caller's current [INFO] block (the expected specs of its callees)\n\n"
        f"{caller_info_block}\n\n"
        "## Steps\n\n"
        f"1. Decide whether the caller's [INFO] entry for `{callee_name}` already is consistent "
        "with the callee's new spec. If it is, no update is needed.\n"
        f"2. If it conflicts, produce the COMPLETE replacement [INFO] block (the `[INFO]` ... "
        f"`[INFO]` block only, markers included, every line prefixed with `{comment_prefix}`), "
        f"adjusting only the `{callee_name}` entry to be consistent and leaving the other "
        "entries as-is.\n"
        f"3. Write your answer to `{result_relpath}` as a JSON object with keys:\n"
        '   - "info_updated": boolean.\n'
        '   - "new_info": string — the full replacement [INFO] block, or "" if not updated.\n'
        "   Write ONLY that JSON file; do not modify any other project files.\n"
    )

    return _opencode_select_json(
        proj_dir,
        work_dir,
        prompt_relpath,
        prompt_content,
        result_relpath,
        stage="update_caller_info",
        input_files=[prompt_relpath],
    )


def _collect_caller_context(fqn, callers_map, file_map):
    """
    Gather the context an existing caller provides about fqn, mirroring the caller context
    run_pipeline feeds into spec generation: each caller's own [SPEC] block and the entry in
    its [INFO] block that records what the caller expects from fqn (as one of its callees).

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
        info_block = extract_info_block(cpath_p)
        expectation = extract_callee_spec_from_info(info_block, fqn) if info_block else None
        if caller_spec or expectation:
            context.append((caller_fqn, caller_spec, expectation))
    return context


def _opencode_generate_spec(proj_dir, work_dir, idx, fqn, lang_key, comment_prefix,
                            developer_intent, callee_names, source, caller_context):
    """
    Ask opencode to generate a brand-new [SPEC] (and, when the function has callees, [INFO])
    block from scratch for a function that has no existing specification — e.g. a function
    freshly added by the modification.

    Mirrors the full run's spec generation (run_pipeline Stage 5) but for a single function:
    opencode reads the project's spec format rules (fm_agent/spec_prompts/system_prompt.md),
    is given the same caller context the full run provides (each caller's [SPEC] block and what
    that caller's [INFO] block expects from this function, in caller_context as returned by
    _collect_caller_context), and produces the block(s) directly. Returns the parsed decision
    in the SAME shape as _opencode_check_spec_update so the caller can splice and propagate it
    identically.

    Returns the parsed result dict — keys: "spec_updated" (bool, true when a [SPEC] block was
    produced), "new_spec" (str), "info_updated" (bool), "new_info" (str), "updated_callees"
    (list[str]) — or None when opencode produced nothing usable.
    """
    result_relpath = os.path.join("fm_agent", f"spec_generate_{idx}.json")
    prompt_relpath = os.path.join("fm_agent", f"spec_generate_{idx}.md")

    # Caller context (callers' own specs + what each caller's [INFO] expects from this
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
            "## What callers expect from this function (from their [INFO] blocks)\n\n"
            "Your generated [SPEC] must be consistent with these expectations.\n\n"
        )
        for cfqn, exp in caller_expectations:
            caller_section += f"### According to {cfqn}\n\n{exp.strip()}\n\n"

    callee_hint = ", ".join(sorted(callee_names)) if callee_names else "(none)"
    if callee_names:
        info_step = (
            "3. Because this function has callees, also produce an [INFO] block recording the "
            "expected behavioral spec of each callee it depends on (the `[INFO]` ... `[INFO]` "
            f"block only, markers included, every line prefixed with `{comment_prefix}`), and "
            "list the names of the callees you recorded.\n"
        )
    else:
        info_step = "3. This function has no callees, so produce no [INFO] block.\n"

    prompt_content = (
        "# Generate Function Specification\n\n"
        "A modification has been applied to a codebase to achieve the developer intent below, "
        "adding a function that has no behavioral specification yet. Generate its "
        "specification from scratch.\n\n"
        f"- Function fully-qualified name: `{fqn}` (language: `{lang_key}`).\n"
        f"- Comment prefix for this language: `{comment_prefix}`.\n"
        f"- Known callees of this function: {callee_hint}.\n\n"
        "## Developer intent\n\n"
        f"{developer_intent}\n\n"
        "## Function source\n\n"
        f"```{lang_key}\n{source.strip()}\n```\n\n"
        f"{caller_section}"
        "## Steps\n\n"
        "1. Read `fm_agent/spec_prompts/system_prompt.md` for the exact [SPEC]/[INFO] format "
        "rules used by this project.\n"
        "2. Produce the COMPLETE [SPEC] block describing this function's behavior — the "
        "`[SPEC]` ... `[SPEC]` block only, markers included, every line prefixed with "
        f"`{comment_prefix}`, and NO source code.\n"
        f"{info_step}"
        f"4. Write your answer to `{result_relpath}` as a JSON object with keys:\n"
        '   - "spec_updated": boolean — true when you produced a [SPEC] block.\n'
        '   - "new_spec": string — the full [SPEC] block.\n'
        '   - "info_updated": boolean — true when you produced an [INFO] block.\n'
        '   - "new_info": string — the full [INFO] block, or "" if none.\n'
        '   - "updated_callees": array of callee name strings recorded in [INFO], or [].\n'
        "   Write ONLY that JSON file; do not modify any other project files.\n"
    )

    return _opencode_select_json(
        proj_dir,
        work_dir,
        prompt_relpath,
        prompt_content,
        result_relpath,
        stage="generate_function_spec",
        input_files=[prompt_relpath, "fm_agent/spec_prompts/system_prompt.md"],
    )


def _update_specs_for_intent(proj_dir, work_dir, developer_intent, changed_functions, relevant_rel_files):
    """
    re-generate the [SPEC] (and dependent [INFO]) blocks of every function that is
    either changed or relevant to the developer intent, propagating to callees.

    Seeds from the changed functions (added/modified) and the relevant extracted-function
    files returned by collect_relevent_function_scope, then processes functions in top-down
    order (callers before callees). For each function, opencode reads its current [SPEC]
    block and decides whether it must change to reflect developer_intent. A function with no
    existing [SPEC] block (e.g. one freshly added by the modification) instead has a spec
    generated from scratch the way the full run does. If a spec is written or generated, the
    new [SPEC] is written back (source untouched), and then:

      - Downward: opencode decides whether the function's own [INFO] block (the expected
        specs of its callees) must change too, and any callee whose expected spec changed is
        queued to have its own spec file re-checked.
      - Upward: every caller's [INFO] block (which records this function as one of its
        callees) is reconciled with the function's new [SPEC] so the two do not conflict
        (they need not be identical).

    Returns the sorted list of extracted-function files (paths relative to the
    extracted_functions dir) whose [SPEC]/[INFO] block was changed.
    """
    extracted_dir = os.path.join(work_dir, "extracted_functions")

    callees_map, callers_map, file_map = _project_call_graph(work_dir)

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
        return []

    # Top-down order (callers before the callees they depend on); FQNs absent from the layer
    # graph sort last, by name.
    topdown = _topdown_ordered_fqns(work_dir)
    order_index = {fqn: i for i, fqn in enumerate(topdown)}

    def _order_key(fqn):
        return (order_index.get(fqn, len(order_index)), fqn)

    def _plan_spec_update(fqn, idx):
        """
        Decide fqn's new [SPEC]/[INFO] and return an apply-plan, or None to skip.

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
        lang_cfg = LANG_CONFIG[lang_key]
        comment_prefix = lang_cfg["comment_prefix"]
        spec_marker = lang_cfg["spec_marker"]

        with open(fpath, "r", errors="replace") as f:
            content = f.read()
        leading = _extract_leading_spec_comments(content, comment_prefix, spec_marker)
        callee_names = sorted({c.split("::")[-1] for c in callees_map.get(fqn, ())})

        if leading is None:
            # No existing specification (e.g. a freshly added, unspecced function) — generate
            # one from scratch the way the full run does, rather than skipping the function.
            source = content
            old_spec, old_info = None, None
            caller_context = _collect_caller_context(fqn, callers_map, file_map)
            result = _opencode_generate_spec(
                proj_dir, work_dir, idx, fqn, lang_key, comment_prefix,
                developer_intent, callee_names, source, caller_context,
            )
        else:
            source = content[len(leading):]
            old_spec, old_info = _split_spec_and_info(leading, comment_prefix, spec_marker)
            result = _opencode_check_spec_update(
                proj_dir, work_dir, idx, fqn, lang_key, comment_prefix,
                developer_intent, old_spec, old_info, callee_names, source,
            )

        if not result or not result.get("spec_updated"):
            return None
        new_spec = (result.get("new_spec") or "").strip()
        if not new_spec:
            return None

        if leading is None:
            # Freshly generated: take the [INFO] block opencode produced (if any). Treat it as
            # "updated" so its recorded callee expectations propagate downward below.
            new_info = (result.get("new_info") or "").strip()
            info_block = new_info or None
            info_updated = bool(new_info)
        else:
            # Keep the existing [INFO] block unless opencode rewrote it (only meaningful when
            # the function actually has one).
            info_block = old_info
            info_updated = bool(result.get("info_updated")) and old_info is not None
            if info_updated:
                new_info = (result.get("new_info") or "").strip()
                if new_info:
                    info_block = new_info
                else:
                    info_updated = False

        # Splice the new block(s) back in, leaving the function source unchanged (mirrors the
        # full run's specced-file layout: [SPEC], blank line, optional [INFO], blank line, source).
        new_block = new_spec.rstrip("\n")
        if info_block is not None:
            new_block += "\n\n" + info_block.strip("\n")

        return {
            "fqn": fqn,
            "fpath": fpath,
            "write_content": new_block + "\n\n" + source.lstrip("\n"),
            "new_spec": new_spec,
            "info_updated": info_updated,
            "updated_callees": result.get("updated_callees") or [],
        }

    def _reconcile_caller(caller_fqn, updates, base_idx):
        """
        Reconcile caller_fqn's [INFO] block against a sequence of changed callees.

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
        ccfg = LANG_CONFIG[clang]
        cprefix = ccfg["comment_prefix"]
        cmarker = ccfg["spec_marker"]

        changed = False
        for offset, (callee_name, callee_new_spec) in enumerate(updates):
            with open(cpath, "r", errors="replace") as f:
                ccontent = f.read()
            cleading = _extract_leading_spec_comments(ccontent, cprefix, cmarker)
            if cleading is None:
                continue
            csource = ccontent[len(cleading):]
            c_spec, c_info = _split_spec_and_info(cleading, cprefix, cmarker)
            if c_info is None:
                # No callee-contract block to reconcile.
                continue

            cresult = _opencode_check_caller_info_update(
                proj_dir, work_dir, base_idx + offset, caller_fqn, callee_name, clang, cprefix,
                callee_new_spec, c_info, csource,
            )
            if not cresult or not cresult.get("info_updated"):
                continue
            c_new_info = (cresult.get("new_info") or "").strip()
            if not c_new_info:
                continue

            c_block = c_spec.rstrip("\n") + "\n\n" + c_new_info.strip("\n")
            with open(cpath, "w") as f:
                f.write(c_block + "\n\n" + csource.lstrip("\n"))
            changed = True
        return cpath if changed else None

    checked = set()
    to_check = set(seed)
    changed_spec_files = set()
    counter = 0

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
        for plan in applied:
            with open(plan["fpath"], "w") as f:
                f.write(plan["write_content"])
            changed_spec_files.add(os.path.relpath(plan["fpath"], extracted_dir))
            if plan["info_updated"]:
                for callee_fqn in _resolve_callee_fqns(
                    plan["fqn"], plan["updated_callees"], callees_map
                ):
                    if callee_fqn not in checked:
                        to_check.add(callee_fqn)

        # Stage 3 (concurrent): upward reconciliation. Each function whose [SPEC] changed needs
        # every caller's [INFO] entry for it reconciled. Group the work by caller file so edits
        # to one file are serialized while different caller files reconcile in parallel. Callers
        # sit above the batch in top-down order and are never themselves in the batch, so their
        # files don't collide with the Stage 2 writes.
        caller_updates = {}  # caller_fqn -> list of (callee_name, callee_new_spec)
        for plan in applied:
            callee_name = plan["fqn"].split("::")[-1]
            for caller_fqn in sorted(callers_map.get(plan["fqn"], ())):
                caller_updates.setdefault(caller_fqn, []).append((callee_name, plan["new_spec"]))

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
                        logging.exception("Caller [INFO] reconciliation failed for %s", caller_fqn)
                        continue
                    if cpath:
                        changed_spec_files.add(os.path.relpath(cpath, extracted_dir))

    return sorted(changed_spec_files)


def _verify_incremental_functions(proj_dir, work_dir, changed_functions, updated_spec_files):
    """
    Step 10: re-run the verification stage (reasoner + bug validation) on only the functions
    whose implementation-vs-spec verdict may have drifted because of this modification.

    A function is verified when it satisfies at least one of:
      1) it was changed in the working tree (added or modified), or
      2) its own [SPEC] or [INFO] block was updated in step 9.

    Note on callees: a function whose callee's [SPEC] changed needs re-verification ONLY if
    that change forced its own [INFO] block (the callee contract it reasons against) to be
    updated. Step 9's upward reconciliation already rewrites exactly those callers' [INFO]
    blocks and includes them in updated_spec_files, so condition (2) covers them — a caller
    whose [INFO] did not need to change is left alone and is correctly NOT re-verified.

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

    # (2) Functions whose [SPEC] or [INFO] block was updated in step 9 (updated_spec_files
    #     already includes both functions whose own spec changed and callers whose [INFO]
    #     was reconciled against an updated callee).
    for rel in updated_spec_files:
        verify_targets.add(os.path.join(extracted_dir, rel))

    # Keep only functions that still exist on disk; the reasoner reads these extracted files
    # directly and skips any without a [SPEC] block.
    file_list = sorted({
        os.path.relpath(path, extracted_dir)
        for path in verify_targets
        if os.path.exists(path)
    })
    if not file_list:
        return []

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

    if not mismatches:
        return []

    # Bug validation: the reasoner's MISMATCH is only a candidate bug, so validate each one
    # with opencode (_validate_single_bug writes work_dir/bug_validation/<bug_id>.result.json
    # with a confirmation_status). Run them concurrently, bounded by MAX_WORKERS.
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

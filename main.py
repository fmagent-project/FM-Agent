from src.call_graph_edges import load_call_edges
from src.entry_reasoning_pipeline import run_entry_pipeline
from src.file_utils import (
    collect_file_names,
    _has_source_code,
    _get_all_phase_files,
    _write_file_names,
    _json_file_is_valid,
    _is_under_submodules,
    _ensure_resume_mode_compatible,
    _get_incomplete_verification_files,
    _get_phase_files,
    is_file_ready,
)
from src.extract import run_extraction, EXT_TO_LANG
from src.generate_topdown_layers import generate_topdown_layers
from src.spec_generation_and_verification import run_spec_generation_and_verification
from src.verification import write_static_verification_report
from report import generate_report
from src.incremental_reasoner import run_incremental_pipeline
from src.git import (
    frozen_worktree,
    _is_git_repo,
    _get_head_commit,
    _record_version,
)
from src.languages.codegraph import try_codegraph_init
from src.plugin import run_plugin_hook
from src.pipeline_setup import (
    _domain_context_complete,
    _missing_domain_context_outputs,
    _phase_plan_complete,
    _run_setup_extract,
    _run_generate_phases,
    _post_process_phases,
    _run_generate_domain_context,
)
from src.agent_trace import record_stage_validation
from src.domain_knowledge import (
    collect_domain_knowledge_paths,
    stage_domain_knowledge_files,
)
import os
import sys
import argparse
import json
import time
import shutil
import logging
import contextlib
import subprocess


def _clean_previous_run(work_dir):
    """Remove the fm_agent working directory from the previous pipeline run."""
    if os.path.isdir(work_dir):
        shutil.rmtree(work_dir)


def _start_dashboard(work_dir):
    """Start the same live process view exposed by the public project."""
    dashboard_path = os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "dashboard.py"
    )
    try:
        return subprocess.Popen([sys.executable, dashboard_path, work_dir])
    except Exception as exc:
        logging.warning("[Pipeline] dashboard failed to start: %s", exc)
        return None


def _stop_dashboard(process):
    if process is None:
        return
    try:
        process.terminate()
        process.wait(timeout=3)
    except Exception:
        try:
            process.kill()
        except Exception:
            pass


def _normalize_submodules(proj_dir, submodules):
    """Return validated project-relative submodule directories."""
    if not submodules:
        return []

    proj_dir = os.path.abspath(proj_dir)
    normalized = []
    seen = set()
    for raw in submodules:
        value = (raw or "").strip()
        if not value:
            continue
        candidate = value if os.path.isabs(value) else os.path.join(proj_dir, value)
        candidate = os.path.abspath(candidate)
        try:
            inside_project = os.path.commonpath([proj_dir, candidate]) == proj_dir
        except ValueError:
            inside_project = False
        if not inside_project or candidate == proj_dir:
            raise ValueError(
                f"--submodule must name subdirectories inside proj_dir, got: {raw}"
            )
        if not os.path.isdir(candidate):
            raise ValueError(f"--submodule path is not a directory: {raw}")

        rel = os.path.relpath(candidate, proj_dir).replace(os.sep, "/")
        if rel not in seen:
            normalized.append(rel)
            seen.add(rel)

    collapsed = []
    for rel in sorted(normalized, key=lambda path: (path.count("/"), path)):
        if not collapsed or not _is_under_submodules(rel, collapsed):
            collapsed.append(rel)
    return collapsed


def run_pipeline(
    proj_dir,
    resume=False,
    required_source_files=None,
    domain_knowledge_files=None,
    submodules=None,
    one_phase=False,
    extra_call_edges_path=None,
    only_spec=False,
    plugin_config=None,
    plugin_context=None,
    all_bugs=False,
):
    if not os.path.isdir(proj_dir):
        print(f"[Pipeline] ERROR: proj_dir does not exist or is not a directory: {proj_dir}")
        sys.exit(1)
    if not _has_source_code(proj_dir, submodules):
        scope = f" selected submodule(s): {', '.join(submodules)}" if submodules else f" {proj_dir}"
        print(f"[Pipeline] ERROR: No source code files found in{scope}. "
              f"Supported extensions: {', '.join(sorted(EXT_TO_LANG.keys()))}")
        sys.exit(1)

    work_dir = os.path.join(proj_dir, "fm_agent")
    input_dir = os.path.join(work_dir, "extracted_functions")
    output_dir = os.path.join(work_dir, "logic_verification_results")
    script_dir = os.path.dirname(os.path.abspath(__file__))
    extra_call_edges = load_call_edges(extra_call_edges_path)

    # Clean files from the previous run — unless resuming, where we keep all
    # prior progress (phases.json, generated specs, verification results) and
    # only do the remaining work.
    if resume:
        if os.path.isdir(work_dir):
            print(f"[Pipeline] RESUME: keeping existing {os.path.relpath(work_dir, proj_dir)}/ — only remaining work will run.")
        else:
            print("[Pipeline] RESUME requested but no previous fm_agent/ found — starting fresh.")
            resume = False
    else:
        _clean_previous_run(work_dir)
    if resume and not only_spec:
        _ensure_resume_mode_compatible(output_dir, all_bugs)
    os.makedirs(work_dir, exist_ok=True)
    if plugin_config is not None:
        plugin_context_path = os.path.join(work_dir, "plugin_context.json")
        with open(plugin_context_path, "w", encoding="utf-8") as file:
            json.dump(plugin_context or {}, file, indent=2)
        if plugin_config.configure_hook is not None:
            run_plugin_hook(
                plugin_config.name,
                "configure",
                plugin_config.configure_function,
                plugin_config.configure_hook,
                proj_dir,
            )
    domain_knowledge_relpaths = stage_domain_knowledge_files(
        proj_dir, work_dir, domain_knowledge_files
    )
    if domain_knowledge_relpaths:
        print(
            "[Pipeline] User domain knowledge: "
            f"{len(domain_knowledge_relpaths)} markdown file(s)."
        )

    # Stage 1: generate phase.json (input: target code → phases.json)
    # Stage 2: generate domain context (input: phases.json → domain context files)
    phase_stage = plugin_config.get_stage("generate_phase_plan") if plugin_config else None
    context_stage = plugin_config.get_stage("generate_domain_context") if plugin_config else None
    extraction_stage = plugin_config.get_stage("extract_functions") if plugin_config else None
    file_list_stage = plugin_config.get_stage("collect_file_list") if plugin_config else None
    topdown_stage = plugin_config.get_stage("generate_topdown_layers") if plugin_config else None
    spec_stage = plugin_config.get_stage("generate_specs_and_verification") if plugin_config else None
    print("[Pipeline] Stage 1/6: Generating phase plan...")
    if phase_stage is not None and phase_stage.type == "pass":
        print(
            "[Pipeline] Stage 1/6: Plugin stage "
            "'generate_phase_plan' type=pass, skipping."
        )
    elif phase_stage is not None and phase_stage.type == "replace":
        run_plugin_hook(
            plugin_config.name,
            "generate_phase_plan",
            phase_stage.replace_function,
            phase_stage.replace_hook,
            proj_dir,
        )
    else:
        if phase_stage is not None and phase_stage.input_hook is not None:
            run_plugin_hook(
                plugin_config.name,
                "generate_phase_plan",
                phase_stage.input_function,
                phase_stage.input_hook,
                proj_dir,
            )
        _run_generate_phases(
            proj_dir, work_dir, script_dir, resume=resume,
            submodules=submodules,
        )
        if phase_stage is not None and phase_stage.output_hook is not None:
            run_plugin_hook(
                plugin_config.name,
                "generate_phase_plan",
                phase_stage.output_function,
                phase_stage.output_hook,
                proj_dir,
            )

    phases_modified = _post_process_phases(
        proj_dir, work_dir,
        required_source_files=required_source_files,
        submodules=submodules,
        one_phase=one_phase,
    )
    if not _phase_plan_complete(work_dir):
        record_stage_validation(
            work_dir,
            "stage_1",
            "error",
            "Stage 1 final artifact validation failed",
            missing_outputs=["fm_agent/phases.json"],
        )
        print("[Pipeline] ERROR: Stage 1 final phases.json validation failed.")
        sys.exit(1)

    print("[Pipeline] Stage 2/6: Generating domain context...")
    if context_stage is not None and context_stage.type == "pass":
        print(
            "[Pipeline] Stage 2/6: Plugin stage "
            "'generate_domain_context' type=pass, skipping."
        )
    elif context_stage is not None and context_stage.type == "replace":
        run_plugin_hook(
            plugin_config.name,
            "generate_domain_context",
            context_stage.replace_function,
            context_stage.replace_hook,
            proj_dir,
        )
    else:
        if context_stage is not None and context_stage.input_hook is not None:
            run_plugin_hook(
                plugin_config.name,
                "generate_domain_context",
                context_stage.input_function,
                context_stage.input_hook,
                proj_dir,
            )
        _run_generate_domain_context(
            proj_dir,
            work_dir,
            script_dir,
            resume=resume and not phases_modified,
        )
        if context_stage is not None and context_stage.output_hook is not None:
            run_plugin_hook(
                plugin_config.name,
                "generate_domain_context",
                context_stage.output_function,
                context_stage.output_hook,
                proj_dir,
            )

    if not _domain_context_complete(work_dir):
        missing_context = _missing_domain_context_outputs(work_dir)
        record_stage_validation(
            work_dir,
            "stage_2",
            "error",
            "Stage 2 final artifact validation failed",
            missing_outputs=missing_context,
        )
        print(
            "[Pipeline] ERROR: Stage 2 final artifact validation failed. Missing: "
            + ", ".join(missing_context)
        )
        sys.exit(1)

    # Build (or rebuild) the codegraph index if codegraph is installed. Both
    # run_extraction (Stage 3) and generate_topdown_layers (Stage 5) read from it.
    # force=not resume mirrors run_extraction below: a fresh run rebuilds so the
    # index matches the current tree, while a resume reuses the existing index
    # (same tree as the interrupted run — rebuilding would just be wasted work).
    try_codegraph_init(proj_dir, force=not resume)

    # Run function extraction using extract.py
    # force=False on resume preserves already-specced extracted files; on a fresh
    # run fm_agent/ was just wiped so it is equivalent to force=True.
    print("[Pipeline] Stage 3/6: Extracting functions from source files...")
    if extraction_stage is not None and extraction_stage.type == "pass":
        print(
            "[Pipeline] Stage 3/6: Plugin stage "
            "'extract_functions' type=pass, skipping."
        )
    elif extraction_stage is not None and extraction_stage.type == "replace":
        run_plugin_hook(
            plugin_config.name,
            "extract_functions",
            extraction_stage.replace_function,
            extraction_stage.replace_hook,
            proj_dir,
        )
    else:
        if extraction_stage is not None and extraction_stage.input_hook is not None:
            run_plugin_hook(
                plugin_config.name,
                "extract_functions",
                extraction_stage.input_function,
                extraction_stage.input_hook,
                proj_dir,
            )
        run_extraction(proj_dir, work_dir=work_dir, force=not resume, verbose=True)
        if extraction_stage is not None and extraction_stage.output_hook is not None:
            run_plugin_hook(
                plugin_config.name,
                "extract_functions",
                extraction_stage.output_function,
                extraction_stage.output_hook,
                proj_dir,
            )

    extracted_count = sum(
        1
        for root, _dirs, files in os.walk(input_dir)
        for filename in files
        if os.path.isfile(os.path.join(root, filename))
        and not filename.endswith((".spec.json", ".info.json"))
    ) if os.path.isdir(input_dir) else 0
    record_stage_validation(
        work_dir,
        "stage_3",
        "success",
        "Stage 3 local function extraction completed",
        metadata={"extracted_function_count": extracted_count},
    )

    # Copy system_prompt.md to spec_prompts/system_prompt.md
    spec_prompts_dir = os.path.join(work_dir, "spec_prompts")
    os.makedirs(spec_prompts_dir, exist_ok=True)
    shutil.copy2(
        os.path.join(script_dir, "md", "system_prompt.md"),
        os.path.join(spec_prompts_dir, "system_prompt.md"),
    )
    shutil.copy2(
        os.path.join(script_dir, "src", "generate_batch_prompts.py"),
        os.path.join(spec_prompts_dir, "generate_batch_prompts.py"),
    )
    # generate_batch_prompts.py imports is_file_ready from this module at runtime.
    shutil.copy2(
        os.path.join(script_dir, "src", "file_utils.py"),
        os.path.join(spec_prompts_dir, "file_utils.py"),
    )

    phases_path = os.path.join(work_dir, "phases.json")
    with open(phases_path, "r") as f:
        phases_data = json.load(f)

    print("[Pipeline] Stage 4/6: Collecting file list...")
    file_list_path = os.path.join(work_dir, "fm_agent_file_list.json")
    if file_list_stage is not None and file_list_stage.type == "pass":
        print(
            "[Pipeline] Stage 4/6: Plugin stage "
            "'collect_file_list' type=pass, skipping."
        )
        with open(file_list_path, "r", encoding="utf-8") as file:
            file_list = json.load(file)
    elif file_list_stage is not None and file_list_stage.type == "replace":
        run_plugin_hook(
            plugin_config.name,
            "collect_file_list",
            file_list_stage.replace_function,
            file_list_stage.replace_hook,
            proj_dir,
        )
        with open(file_list_path, "r", encoding="utf-8") as file:
            file_list = json.load(file)
    else:
        if file_list_stage is not None and file_list_stage.input_hook is not None:
            run_plugin_hook(
                plugin_config.name,
                "collect_file_list",
                file_list_stage.input_function,
                file_list_stage.input_hook,
                proj_dir,
            )
        file_list = collect_file_names(input_dir, file_list_path)
        if submodules:
            file_list = _write_file_names(
                _get_all_phase_files(phases_data, input_dir), file_list_path
            )
        if file_list_stage is not None and file_list_stage.output_hook is not None:
            run_plugin_hook(
                plugin_config.name,
                "collect_file_list",
                file_list_stage.output_function,
                file_list_stage.output_hook,
                proj_dir,
            )
            with open(file_list_path, "r", encoding="utf-8") as file:
                file_list = json.load(file)

    if not isinstance(file_list, list) or not _json_file_is_valid(file_list_path):
        record_stage_validation(
            work_dir,
            "stage_4",
            "error",
            "Stage 4 file-list artifact validation failed",
            missing_outputs=["fm_agent/fm_agent_file_list.json"],
        )
        print("[Pipeline] ERROR: Stage 4 produced an invalid function file list.")
        sys.exit(1)
    record_stage_validation(
        work_dir,
        "stage_4",
        "success",
        "Stage 4 local file-list validation passed",
        metadata={"function_count": len(file_list)},
    )

    if not file_list:
        for stage, summary in (
            ("stage_5", "Stage 5 skipped because Stage 4 found no functions"),
            ("stage_6", "Stage 6 skipped because Stage 4 found no functions"),
        ):
            record_stage_validation(
                work_dir,
                stage,
                "success",
                summary,
                metadata={"skipped": True, "reason": "no_extracted_functions"},
            )
        print("[Pipeline] No functions found to verify. Skipping spec generation.")
        return

    # --- Stage 5: Generate topdown layers ---
    print("[Pipeline] Stage 5/6: Generating topdown layers...")
    if topdown_stage is not None and topdown_stage.type == "pass":
        print(
            "[Pipeline] Stage 5/6: Plugin stage "
            "'generate_topdown_layers' type=pass, skipping."
        )
    elif topdown_stage is not None and topdown_stage.type == "replace":
        run_plugin_hook(
            plugin_config.name,
            "generate_topdown_layers",
            topdown_stage.replace_function,
            topdown_stage.replace_hook,
            proj_dir,
        )
    else:
        if topdown_stage is not None and topdown_stage.input_hook is not None:
            run_plugin_hook(
                plugin_config.name,
                "generate_topdown_layers",
                topdown_stage.input_function,
                topdown_stage.input_hook,
                proj_dir,
            )
        generate_topdown_layers(work_dir, extra_call_edges=extra_call_edges)
        if topdown_stage is not None and topdown_stage.output_hook is not None:
            run_plugin_hook(
                plugin_config.name,
                "generate_topdown_layers",
                topdown_stage.output_function,
                topdown_stage.output_hook,
                proj_dir,
            )

    expected_layer_files = []
    for phase in phases_data.get("phases", []):
        phase_num = phase.get("phase")
        if phase_num is None or not _get_phase_files(phases_data, phase_num, input_dir):
            continue
        expected_layer_files.append(
            os.path.join(
                spec_prompts_dir,
                f"phase_{phase_num:02d}_topdown_layers.json",
            )
        )
    missing_layer_files = [
        os.path.relpath(path, proj_dir)
        for path in expected_layer_files
        if not _json_file_is_valid(path)
    ]
    if missing_layer_files:
        record_stage_validation(
            work_dir,
            "stage_5",
            "error",
            "Stage 5 top-down layer artifact validation failed",
            missing_outputs=missing_layer_files,
        )
        print(
            "[Pipeline] ERROR: Stage 5 outputs missing or invalid: "
            + ", ".join(missing_layer_files)
        )
        sys.exit(1)
    record_stage_validation(
        work_dir,
        "stage_5",
        "success",
        "Stage 5 local top-down layer validation passed",
        metadata={"phase_output_count": len(expected_layer_files)},
    )

    # --- Stage 6: Execute spec generation workflow (per phase, per layer) ---
    if only_spec:
        print("[Pipeline] Stage 6/6: Generating specs (static reasoning disabled)...")
    else:
        print("[Pipeline] Stage 6/6: Generating specs & verification...")
    if spec_stage is not None and spec_stage.type == "pass":
        print(
            "[Pipeline] Stage 6/6: Plugin stage "
            "'generate_specs_and_verification' type=pass, skipping."
        )
    elif spec_stage is not None and spec_stage.type == "replace":
        run_plugin_hook(
            plugin_config.name,
            "generate_specs_and_verification",
            spec_stage.replace_function,
            spec_stage.replace_hook,
            proj_dir,
        )
    else:
        if spec_stage is not None and spec_stage.input_hook is not None:
            run_plugin_hook(
                plugin_config.name,
                "generate_specs_and_verification",
                spec_stage.input_function,
                spec_stage.input_hook,
                proj_dir,
            )
        run_spec_generation_and_verification(
            proj_dir,
            work_dir,
            input_dir,
            output_dir,
            script_dir,
            spec_prompts_dir,
            phases_data,
            resume=resume,
            extra_call_edges=extra_call_edges,
            only_spec=only_spec,
            all_bugs=all_bugs,
        )
        if spec_stage is not None and spec_stage.output_hook is not None:
            run_plugin_hook(
                plugin_config.name,
                "generate_specs_and_verification",
                spec_stage.output_function,
                spec_stage.output_hook,
                proj_dir,
            )

    unready_specs = [
        rel for rel in file_list
        if not is_file_ready(os.path.join(input_dir, rel))
    ]
    incomplete_results = (
        []
        if only_spec
        else _get_incomplete_verification_files(
            file_list,
            input_dir,
            output_dir,
            work_dir,
            all_bugs=all_bugs,
        )
    )
    stage6_incomplete = bool(unready_specs or incomplete_results)
    missing_stage6 = []
    if stage6_incomplete:
        missing_stage6 = [
            f"fm_agent/extracted_functions/{rel}.spec.json/.info.json"
            for rel in unready_specs
        ] + [
            f"fm_agent/logic_verification_results/{os.path.splitext(rel)[0]}.json"
            for rel in incomplete_results
        ]
        record_stage_validation(
            work_dir,
            "stage_6",
            "error",
            "Stage 6 final artifact validation failed",
            missing_outputs=missing_stage6,
        )
    else:
        record_stage_validation(
            work_dir,
            "stage_6",
            "success",
            "Stage 6 final artifact validation passed",
            metadata={
                "function_count": len(file_list),
                "static_reasoning": not only_spec,
            },
        )

    # Write the reports after the terminal Stage 6 validation event so the
    # diagnostics embedded in the reports describe the complete run rather
    # than stopping one event early.  Partial runs still receive reports.
    if not only_spec:
        verification_report = write_static_verification_report(
            input_dir,
            output_dir,
            work_dir,
            file_list,
            all_bugs=all_bugs,
        )
        html_report = generate_report(work_dir)
        print(
            "[Pipeline] Static verification report: "
            f"{os.path.join(work_dir, 'VERIFICATION-REPORT.md')} "
            f"(status={verification_report['status']})"
        )
        print(f"[Pipeline] Interactive report: {html_report}")

    if stage6_incomplete:
        print(
            "[Pipeline] ERROR: Stage 6 outputs missing or invalid: "
            + ", ".join(missing_stage6)
        )
        sys.exit(1)

    if only_spec:
        print("[Pipeline] Done (specs only; static reasoning skipped).")
    else:
        print("[Pipeline] Done.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        usage="python3 main.py <proj_dir> [--resume] [--incremental INTENT_FILE] "
              "[--domain-knowledge FILE ...] [--one-phase] [--isolate] "
              "[--all-bugs] "
              "[--submodule PATH [PATH ...]] [--entry-func PATH] "
              "[--end-func PATH ...] [--extra-edge FILE] [--only-spec] "
              "[--dashboard] "
              "[--list-plugin] [--plugin NAME]",
        description="Run the FM agent pipeline on a project directory.",
    )
    parser.add_argument("proj_dir", nargs="?", help="path to the project directory")
    parser.add_argument(
        "--resume",
        action="store_true",
        help="continue a previous run in <proj_dir>/fm_agent instead of wiping it: "
             "keeps phases.json, generated specs, and existing verification results; "
             "only does the remaining work. Repeat --all-bugs when resuming an "
             "all-bugs run.",
    )
    parser.add_argument(
        "--incremental",
        metavar="INTENT_FILE",
        help="Run in incremental mode. Value is the path to the intent file "
        "defining the goal of modification.",
    )
    parser.add_argument(
        "--isolate",
        action="store_true",
        help="Run the pipeline against an isolated snapshot. Git repositories "
        "use a worktree; ordinary directories use a filesystem copy.",
    )
    parser.add_argument(
        "--one-phase",
        action="store_true",
        help="Put all planned source files into a single analysis phase.",
    )
    parser.add_argument(
        "--all-bugs",
        action="store_true",
        help="continue static reasoning after mismatches and report every candidate.",
    )
    parser.add_argument(
        "--only-spec",
        action="store_true",
        help="Only generate behavioral specs; skip the static reasoning stage.",
    )
    parser.add_argument(
        "--dashboard",
        action="store_true",
        help="automatically start the live dashboard for this run",
    )
    parser.add_argument(
        "--domain-knowledge",
        "--knowledge",
        metavar="FILE",
        action="append",
        nargs="+",
        default=[],
        help="additional Markdown domain-knowledge file(s) to copy into "
        "fm_agent/spec_prompts/domain_context/user_knowledge/ and provide to "
        "setup, spec generation, and static reasoning agents. May be repeated. "
        "FM_AGENT_DOMAIN_KNOWLEDGE can also provide os.pathsep-separated files.",
    )
    parser.add_argument(
        "--submodule",
        metavar="PATH",
        nargs="+",
        default=None,
        help="Only process source code under one or more subdirectories of proj_dir.",
    )
    parser.add_argument(
        "--entry-func",
        metavar="PATH",
        default=None,
        help="function path of the entry point to start reasoning from.",
    )
    parser.add_argument(
        "--end-func",
        metavar="PATH",
        nargs="+",
        default=None,
        help="one or more function paths at which to stop (space-separated list); "
        "if omitted, the whole call graph reachable from --entry-func is analyzed.",
    )
    parser.add_argument(
        "--extra-edge",
        dest="extra_edge",
        metavar="FILE",
        default=None,
        help="optional JSON file, or directory of JSON files, containing "
        "supplemental caller->callee edges.",
    )
    parser.add_argument(
        "--list-plugin",
        action="store_true",
        help="list all valid plugins found under the plugins/ directory and exit.",
    )
    parser.add_argument(
        "--plugin",
        metavar="NAME",
        default=None,
        help="load and activate the named plugin from the plugins/ directory.",
    )
    args = parser.parse_args()

    if args.list_plugin:
        from pathlib import Path
        from src.plugin import load_plugins
        plugins_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "plugins")
        plugins = load_plugins(Path(plugins_dir))
        if not plugins:
            print("No valid plugins found.")
        else:
            print(f"{'Plugin':<30} {'Version':<12} Stages")
            print("-" * 65)
            for name, plugin in plugins.items():
                stage_names = ", ".join(plugin.stages.keys()) if plugin.stages else "(none)"
                print(f"{name:<30} {plugin.version:<12} {stage_names}")
        sys.exit(0)

    selected_plugin = args.plugin

    if selected_plugin and args.entry_func is not None:
        parser.error("--plugin cannot be combined with --entry-func.")

    plugin_config = None
    if selected_plugin:
        if not args.proj_dir:
            parser.error("the following arguments are required when --plugin is used: proj_dir")
        from pathlib import Path
        from src.plugin import validate_plugin
        plugins_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "plugins")
        plugin_config = validate_plugin(Path(plugins_dir) / selected_plugin)
        if plugin_config is None:
            print(f"[Pipeline] ERROR: Plugin '{selected_plugin}' not found or invalid.")
            sys.exit(1)
        print(f"[Pipeline] Loaded plugin '{plugin_config.name}' v{plugin_config.version}")

    if not args.proj_dir:
        parser.error("the following arguments are required: proj_dir")

    resume = args.resume or os.environ.get("FM_AGENT_RESUME") == "1"
    proj_dir = os.path.abspath(args.proj_dir)
    if not os.path.isdir(proj_dir):
        parser.error(f"project directory does not exist or is not a directory: {proj_dir}")
    extra_call_edges_path = args.extra_edge
    if extra_call_edges_path:
        extra_call_edges_path = os.path.abspath(extra_call_edges_path)
    plugin_context = {
        "extra_edge": extra_call_edges_path,
    }
    try:
        submodules = _normalize_submodules(proj_dir, args.submodule)
    except ValueError as exc:
        parser.error(str(exc))

    try:
        domain_knowledge_files = collect_domain_knowledge_paths(
            args.domain_knowledge,
            base_dir=proj_dir,
            fallback_base_dir=os.getcwd(),
        )
    except ValueError as exc:
        parser.error(str(exc))

    if submodules and args.entry_func is not None:
        parser.error("--submodule cannot be combined with --entry-func.")

    if args.only_spec and args.incremental:
        parser.error(
            "--only-spec cannot be combined with --incremental "
            "(incremental mode includes static reasoning)."
        )

    # ---- pre-flight environment check (shared by all pipeline modes) ----
    import config
    from src.env_check import run as env_check_run
    if not env_check_run(proj_dir, config):
        sys.exit(0)

    start_time = time.time()

    # Entry-point mode uses its dedicated copy-and-trim pipeline.
    if args.entry_func is not None:
        dashboard_process = _start_dashboard(proj_dir) if args.dashboard else None
        try:
            run_entry_pipeline(
                proj_dir,
                entry_func=args.entry_func,
                end_funcs=args.end_func,
                resume=resume,
                domain_knowledge_files=domain_knowledge_files,
                one_phase=args.one_phase,
                extra_call_edges_path=extra_call_edges_path,
                only_spec=args.only_spec,
                all_bugs=args.all_bugs,
            )
        finally:
            _stop_dashboard(dashboard_process)
        end_time = time.time()
        logging.info(f"Total time: {end_time - start_time:.2f} seconds")
        sys.exit(0)

    # Incremental mode needs commit history. Full and isolated full runs also
    # support ordinary source directories; frozen_worktree copies them.
    if args.incremental and not _is_git_repo(proj_dir):
        parser.error(
            "--incremental requires a Git repository with at least one commit; "
            f"{proj_dir} is an ordinary directory. Run a full analysis instead."
        )

    # Resolve the intent path before snapshotting, since cwd-relative paths must
    # resolve against the real project, not the frozen worktree copy.
    intent_path = os.path.abspath(args.incremental) if args.incremental else None

    # In incremental mode the commit to diff against is the most recent one recorded
    # in version.log (the last line, since each run appends its commit). Read it from
    # the real project before snapshotting.
    old_commit = None
    if args.incremental:
        version_path = os.path.join(proj_dir, "fm_agent", "version.log")
        if os.path.exists(version_path):
            with open(version_path, "r") as f:
                commits = [line.strip() for line in f if line.strip()]
            old_commit = commits[-1] if commits else None

    # Capture the project's latest commit id before running. With --isolate the
    # pipeline runs against a throwaway worktree snapshot whose HEAD is a synthetic
    # snapshot commit, so the version to record must come from the real project.
    new_commit = _get_head_commit(proj_dir)

    # With --isolate, the pipeline runs against the snapshot's fm_agent/. Resuming
    # needs the previous run's fm_agent/ (phases.json, specs, verification results)
    # to be present in the snapshot, so copy the excluded workspace in for resume
    # too — not just incremental mode.
    run_ctx = (
        frozen_worktree(
            proj_dir, copy_excluded=bool(args.incremental) or resume
        )
        if args.isolate
        else contextlib.nullcontext(proj_dir)
    )
    with run_ctx as run_dir:
        dashboard_process = _start_dashboard(run_dir) if args.dashboard else None
        try:
            # Incremental mode requires a recorded commit to diff against; without a
            # version.log from a previous run, fall back to the full pipeline.
            if args.incremental and old_commit:
                run_incremental_pipeline(
                    run_dir,
                    intent_path,
                    old_commit,
                    domain_knowledge_files=domain_knowledge_files,
                    submodules=submodules,
                    one_phase=args.one_phase,
                    extra_call_edges_path=extra_call_edges_path,
                    all_bugs=args.all_bugs,
                )
            else:
                run_pipeline(
                    run_dir,
                    resume=resume,
                    domain_knowledge_files=domain_knowledge_files,
                    submodules=submodules,
                    one_phase=args.one_phase,
                    extra_call_edges_path=extra_call_edges_path,
                    only_spec=args.only_spec,
                    plugin_config=plugin_config,
                    plugin_context=plugin_context,
                    all_bugs=args.all_bugs,
                )
            # Record the commit that was processed. Written after the pipeline since
            # it recreates fm_agent/; with --isolate it lives in the snapshot and is
            # copied back to the real project below. Only recorded on success so a
            # partial run does not advance the version baseline.
            _record_version(new_commit, os.path.join(run_dir, "fm_agent"))
        finally:
            _stop_dashboard(dashboard_process)
            # With --isolate the pipeline ran against a throwaway snapshot, so its
            # fm_agent/ results live in the snapshot. Copy them back into the real
            # project so they are not lost when the snapshot is discarded — this runs
            # even when the pipeline crashes or is interrupted mid-run, so partial
            # progress survives and can be resumed with --resume.
            if args.isolate:
                src_fm = os.path.join(run_dir, "fm_agent")
                dst_fm = os.path.join(proj_dir, "fm_agent")
                if os.path.isdir(src_fm):
                    if os.path.isdir(dst_fm):
                        shutil.rmtree(dst_fm)
                    shutil.copytree(src_fm, dst_fm, symlinks=True)
                    print(f"[Pipeline] Copied results back to {dst_fm}")
    end_time = time.time()
    logging.info(f"Total time: {end_time - start_time:.2f} seconds")

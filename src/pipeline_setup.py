"""Setup stages: generate source/module manifests and domain context."""

import json
import logging
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

from config import OPENCODE_MAX_RETRIES, OPENCODE_SETUP_MODEL

from .backend import DEFAULT_BACKEND
from .domain_knowledge import (
    format_domain_knowledge_bullets,
    list_staged_domain_knowledge_relpaths,
    module_type_filename,
)
from .file_utils import (
    _is_test_file,
    _is_under_submodules,
    _iter_project_source_files,
    _json_file_is_valid,
)
from .llm_client import build_llm_cli_command


def _manifest_paths(work_dir):
    return (
        os.path.join(work_dir, "source_files.json"),
        os.path.join(work_dir, "modules.json"),
    )


def _project_metadata(proj_dir, source_files):
    from .extract import EXT_TO_LANG

    exts = sorted({Path(path).suffix.lstrip(".").lower() for path in source_files})
    languages = sorted({EXT_TO_LANG.get(ext, ext) for ext in exts})
    return {
        "project": os.path.basename(os.path.abspath(proj_dir)),
        "languages": languages,
        "file_extensions": exts,
    }


def _manifest_metadata(work_dir, proj_dir, source_files):
    source_files_path, modules_path = _manifest_paths(work_dir)
    metadata = _project_metadata(proj_dir, source_files)
    for path in (source_files_path, modules_path):
        data = _read_json(path, {})
        if isinstance(data, dict) and data.get("project"):
            metadata["project"] = data["project"]
            break
    return metadata


def _read_json(path, default):
    try:
        with open(path, "r") as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError):
        return default


def _write_json(path, data):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp_path = path + ".tmp"
    with open(tmp_path, "w") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    os.replace(tmp_path, path)


def _source_files_from_manifest(work_dir):
    source_files_path, modules_path = _manifest_paths(work_dir)
    data = _read_json(source_files_path, {})
    if isinstance(data, list):
        return _normalize_source_files(data)
    if isinstance(data, dict) and data.get("source_files"):
        return _normalize_source_files(data.get("source_files", []))

    modules_data = _read_json(modules_path, {})
    files = []
    for module in modules_data.get("modules", []):
        files.extend(module.get("source_files", []))
    return _normalize_source_files(files)


def _normalize_source_files(source_files):
    normalized = []
    seen = set()
    for raw in source_files or []:
        value = str(raw).replace("\\", "/").strip()
        while value.startswith("./"):
            value = value[2:]
        if not value or value in seen:
            continue
        seen.add(value)
        normalized.append(value)
    return normalized


def _collect_project_source_files(proj_dir, submodules=None):
    files = set()
    for rel in _iter_project_source_files(proj_dir, submodules):
        if not _is_test_file(rel):
            files.add(rel)
    return sorted(files)


def _source_manifest_complete(work_dir):
    source_files_path, modules_path = _manifest_paths(work_dir)
    if not _json_file_is_valid(source_files_path) or not _json_file_is_valid(modules_path):
        return False
    return bool(_source_files_from_manifest(work_dir))


def _domain_context_complete(work_dir):
    domain_dir = os.path.join(work_dir, "spec_prompts", "domain_context")
    if not os.path.exists(os.path.join(domain_dir, "engine_overview.txt")):
        return False
    if os.path.exists(os.path.join(domain_dir, "types.txt")):
        return True

    _source_files_path, modules_path = _manifest_paths(work_dir)
    modules_data = _read_json(modules_path, {})
    module_names = [
        module.get("name")
        for module in modules_data.get("modules", [])
        if module.get("name") and module.get("source_files")
    ]
    if not module_names:
        return False

    module_types = os.path.join(domain_dir, "module_types")
    if not os.path.isdir(module_types):
        return False
    return all(
        os.path.exists(os.path.join(module_types, module_type_filename(module_name)))
        for module_name in module_names
    )


def _setup_outputs_complete(work_dir):
    return _source_manifest_complete(work_dir) and _domain_context_complete(work_dir)


def _default_module_name(source_file):
    parent = Path(source_file).parent.as_posix()
    if parent == ".":
        return "root"
    return parent.split("/", 1)[0].replace("-", "_") or "root"


def _default_module_description(name):
    return f"Source files grouped under the {name} module."


def _normalize_modules(proj_dir, work_dir, source_files):
    _source_files_path, modules_path = _manifest_paths(work_dir)
    metadata = _manifest_metadata(work_dir, proj_dir, source_files)
    modules_data = _read_json(modules_path, {})
    modules = modules_data.get("modules", []) if isinstance(modules_data, dict) else []

    allowed = set(source_files)
    seen_files = set()
    normalized_modules = []
    for module in modules:
        name = str(module.get("name") or "module").strip() or "module"
        kept = []
        for sf in _normalize_source_files(module.get("source_files", [])):
            if sf in allowed and sf not in seen_files:
                kept.append(sf)
                seen_files.add(sf)
        if not kept:
            continue
        description = (module.get("description") or "").strip()
        normalized_modules.append({
            "name": name,
            "description": description or _default_module_description(name),
            "source_files": kept,
        })

    missing = [sf for sf in source_files if sf not in seen_files]
    if missing:
        by_module = {}
        for sf in missing:
            by_module.setdefault(_default_module_name(sf), []).append(sf)
        for name, files in sorted(by_module.items()):
            normalized_modules.append({
                "name": name,
                "description": _default_module_description(name),
                "source_files": files,
            })

    modules_data = {
        **metadata,
        "modules": normalized_modules,
    }
    _write_json(modules_path, modules_data)
    return modules_data


def _write_source_manifest(proj_dir, work_dir, source_files):
    source_files_path, _modules_path = _manifest_paths(work_dir)
    data = {
        **_manifest_metadata(work_dir, proj_dir, source_files),
        "source_files": source_files,
    }
    _write_json(source_files_path, data)
    return data


def _post_process_source_manifest(
    proj_dir,
    work_dir,
    required_source_files=None,
    submodules=None,
    backend=None,
):
    """Normalize source_files.json and modules.json after setup generation."""
    del backend
    source_files_path, modules_path = _manifest_paths(work_dir)
    before_source_manifest = _read_json(source_files_path, None)
    before_modules = _read_json(modules_path, None)

    current = _collect_project_source_files(proj_dir, submodules)
    listed = _source_files_from_manifest(work_dir)
    if not listed:
        listed = current

    allowed = set(current)
    source_files = [sf for sf in listed if sf in allowed]
    for required in _normalize_source_files(required_source_files or []):
        if required not in source_files and os.path.exists(os.path.join(proj_dir, required)):
            if not submodules or _is_under_submodules(required, submodules):
                source_files.append(required)
    for sf in current:
        if sf not in source_files:
            source_files.append(sf)

    source_files = _normalize_source_files(source_files)
    _write_source_manifest(proj_dir, work_dir, source_files)
    modules_data = _normalize_modules(proj_dir, work_dir, source_files)

    after_source_manifest = _read_json(source_files_path, None)
    return before_source_manifest != after_source_manifest or before_modules != modules_data


def _prepare_workflow_file(proj_dir, work_dir, script_dir, workflow_filename):
    workflow_src = os.path.join(script_dir, "md", workflow_filename)
    workflow_dst = os.path.join(work_dir, workflow_filename)
    shutil.copy2(workflow_src, workflow_dst)
    proj_dir_abs = os.path.abspath(proj_dir)
    proj_dir_name = os.path.basename(proj_dir_abs)
    with open(workflow_dst, "r") as f:
        md = f.read()
    md = md.replace(
        "`<project root>`",
        f"`{proj_dir_abs}`",
    )
    md += (
        "\n\n"
        "Record source file paths relative to the project root "
        f"`{proj_dir_abs}`. For example, write `path/to/file.ext`, not "
        f"`{proj_dir_name}/path/to/file.ext`.\n"
    )
    user_knowledge_paths = list_staged_domain_knowledge_relpaths(work_dir)
    if user_knowledge_paths:
        md += (
            "\n---\n\n"
            "## User-Provided Domain Knowledge\n\n"
            "Read these files as contextual knowledge. Do not include them as "
            "project source files and do not edit them in place.\n\n"
            f"{format_domain_knowledge_bullets(user_knowledge_paths)}\n"
        )
    with open(workflow_dst, "w") as f:
        f.write(md)


def _run_generate_source_manifest(
    proj_dir,
    work_dir,
    script_dir,
    is_incremental=False,
    resume=False,
    submodules=None,
    plugin_stage=None,
    plugin_root=None,
    backend=None,
):
    """Stage 1: generate source_files.json and modules.json."""
    backend = backend or DEFAULT_BACKEND
    run_llm = True

    if plugin_stage is not None:
        if plugin_stage.type == "pass":
            print("[Pipeline] Stage 1/6: Plugin stage 'generate_module_plan' type=pass, skipping.")
            run_llm = False
        elif plugin_stage.type == "replace":
            print("[Pipeline] Stage 1/6: Plugin stage 'generate_module_plan' type=replace, running plugin command.")
            from .plugin import run_plugin_command
            run_plugin_command(plugin_stage.replace_cmd, plugin_root, proj_dir, label="generate_module_plan")
            run_llm = False

    if run_llm:
        resume_skip = resume and _source_manifest_complete(work_dir)
        if resume_skip:
            print("[Pipeline] Stage 1/6: RESUME — source/module manifests found, skipping setup manifest generation.")

        if plugin_stage is not None and plugin_stage.type == "modify" and plugin_stage.input_md:
            workflow_src = str(plugin_root / plugin_stage.input_md)
            workflow_dst = os.path.join(work_dir, "workflow_generate_modules.md")
            shutil.copy2(workflow_src, workflow_dst)
            user_knowledge_paths = list_staged_domain_knowledge_relpaths(work_dir)
            if user_knowledge_paths:
                with open(workflow_dst, "a") as f:
                    f.write(
                        "\n---\n\n"
                        "## User-Provided Domain Knowledge\n\n"
                        "Read these files as contextual knowledge. Do not include them as "
                        "project source files and do not edit them in place.\n\n"
                        f"{format_domain_knowledge_bullets(user_knowledge_paths)}\n"
                    )
        else:
            _prepare_workflow_file(proj_dir, work_dir, script_dir, "workflow_generate_modules.md")

        fm_reminder = (
            "IMPORTANT: fm_agent/ is your output workspace, not project source. "
            "Do NOT include fm_agent/ paths in source_files.json or modules.json. "
            "Do NOT modify existing project files."
        )
        incremental_reminder = (
            "An existing manifest may be present. Update it to reflect the current "
            "source tree instead of regenerating unrelated entries."
        )
        submodule_reminder = ""
        if submodules:
            allowed = ", ".join(f"`{submodule}/`" for submodule in submodules)
            submodule_reminder = (
                f"Only process source files under these project-relative directories: {allowed}."
            )

        for attempt in range(1, OPENCODE_MAX_RETRIES + 1):
            if resume_skip:
                break
            prompt = (
                "Follow the instructions in the attached file. "
                f"{fm_reminder} {submodule_reminder}"
            )
            if attempt > 1 or resume:
                prompt += (
                    " First inspect fm_agent/ and keep any valid existing "
                    "source_files.json/modules.json entries that are still correct."
                )
            if is_incremental:
                prompt += " " + incremental_reminder

            prompt_file = os.path.join(proj_dir, "fm_agent", "workflow_generate_modules.md")
            command = build_llm_cli_command(
                model=OPENCODE_SETUP_MODEL,
                prompt=prompt,
                cwd=proj_dir,
                files=[prompt_file],
            )
            try:
                backend.run_opencode_traced(
                    proj_dir=proj_dir,
                    work_dir=work_dir,
                    command=command,
                    stage="generate_source_manifest",
                    input_files=[
                        "fm_agent/workflow_generate_modules.md",
                        *list_staged_domain_knowledge_relpaths(work_dir),
                    ],
                    output_files=[
                        "fm_agent/source_files.json",
                        "fm_agent/modules.json",
                    ],
                    summary=f"OpenCode generate source/module manifest attempt {attempt}",
                    metadata={"attempt": attempt},
                )
            except subprocess.CalledProcessError as exc:
                logging.warning("Stage 1 attempt %d: opencode exited with code %s", attempt, exc.returncode)

            if _source_manifest_complete(work_dir):
                break

            if attempt < OPENCODE_MAX_RETRIES:
                delay = 10
                print(
                    f"[Pipeline] Stage 1 failed to produce source/module manifests "
                    f"(attempt {attempt}/{OPENCODE_MAX_RETRIES}). Retrying in {delay}s..."
                )
                time.sleep(delay)
            else:
                print(
                    f"[Pipeline] ERROR: Stage 1 failed after {OPENCODE_MAX_RETRIES} attempts. "
                    "source_files.json or modules.json missing/invalid."
                )
                sys.exit(1)

        if plugin_stage is not None and plugin_stage.type == "modify" and plugin_stage.output_process:
            print("[Pipeline] Stage 1/6: Running plugin post-process for generate_module_plan...")
            from .plugin import run_plugin_command
            run_plugin_command(plugin_stage.output_process, plugin_root, proj_dir, label="generate_module_plan post-process")

    if not _source_manifest_complete(work_dir):
        raise RuntimeError(
            "Stage generate_module_plan failed: source_files.json or modules.json "
            "is missing or invalid."
        )


def _run_generate_domain_context(
    proj_dir,
    work_dir,
    script_dir,
    resume=False,
    plugin_stage=None,
    plugin_root=None,
    backend=None,
):
    """Stage 2: generate module/global domain context."""
    backend = backend or DEFAULT_BACKEND
    run_llm = True

    if plugin_stage is not None:
        if plugin_stage.type == "pass":
            print("[Pipeline] Stage 2/6: Plugin stage 'generate_domain_context' type=pass, skipping.")
            run_llm = False
        elif plugin_stage.type == "replace":
            print("[Pipeline] Stage 2/6: Plugin stage 'generate_domain_context' type=replace, running plugin command.")
            from .plugin import run_plugin_command
            run_plugin_command(plugin_stage.replace_cmd, plugin_root, proj_dir, label="generate_domain_context")
            run_llm = False

    if run_llm:
        resume_skip = resume and _domain_context_complete(work_dir)
        if resume_skip:
            print("[Pipeline] Stage 2/6: RESUME — domain context found, skipping generation.")

        if plugin_stage is not None and plugin_stage.type == "modify" and plugin_stage.input_md:
            workflow_src = str(plugin_root / plugin_stage.input_md)
            workflow_dst = os.path.join(work_dir, "workflow_generate_domain_context.md")
            shutil.copy2(workflow_src, workflow_dst)
            user_knowledge_paths = list_staged_domain_knowledge_relpaths(work_dir)
            if user_knowledge_paths:
                with open(workflow_dst, "a") as f:
                    f.write(
                        "\n---\n\n"
                        "## User-Provided Domain Knowledge\n\n"
                        "Read these files as contextual knowledge. Do not include them as "
                        "project source files and do not edit them in place.\n\n"
                        f"{format_domain_knowledge_bullets(user_knowledge_paths)}\n"
                    )
        else:
            _prepare_workflow_file(proj_dir, work_dir, script_dir, "workflow_generate_domain_context.md")
        fm_reminder = (
            "IMPORTANT: fm_agent/ is your output workspace, not project source. "
            "Do NOT modify existing project files."
        )

        for attempt in range(1, OPENCODE_MAX_RETRIES + 1):
            if resume_skip:
                break
            prompt = (
                "Read fm_agent/source_files.json and fm_agent/modules.json first. "
                "Then follow the instructions in the attached file. "
                f"{fm_reminder}"
            )
            if attempt > 1 or resume:
                prompt += (
                    " Keep any existing valid domain context files and only fill "
                    "missing or incomplete outputs."
                )
            prompt_file = os.path.join(proj_dir, "fm_agent", "workflow_generate_domain_context.md")
            command = build_llm_cli_command(
                model=OPENCODE_SETUP_MODEL,
                prompt=prompt,
                cwd=proj_dir,
                files=[prompt_file],
            )
            try:
                backend.run_opencode_traced(
                    proj_dir=proj_dir,
                    work_dir=work_dir,
                    command=command,
                    stage="generate_domain_context",
                    input_files=[
                        "fm_agent/workflow_generate_domain_context.md",
                        "fm_agent/source_files.json",
                        "fm_agent/modules.json",
                        *list_staged_domain_knowledge_relpaths(work_dir),
                    ],
                    output_files=[
                        "fm_agent/spec_prompts/domain_context/engine_overview.txt",
                    ],
                    summary=f"OpenCode generate domain context attempt {attempt}",
                    metadata={"attempt": attempt},
                )
            except subprocess.CalledProcessError as exc:
                logging.warning("Stage 2 attempt %d: opencode exited with code %s", attempt, exc.returncode)

            if _domain_context_complete(work_dir):
                break

            if attempt < OPENCODE_MAX_RETRIES:
                delay = 10
                print(
                    f"[Pipeline] Stage 2 failed to produce domain context "
                    f"(attempt {attempt}/{OPENCODE_MAX_RETRIES}). Retrying in {delay}s..."
                )
                time.sleep(delay)
            else:
                print(
                    f"[Pipeline] ERROR: Stage 2 failed after {OPENCODE_MAX_RETRIES} attempts. "
                    "Domain context outputs missing."
                )
                sys.exit(1)

        if plugin_stage is not None and plugin_stage.type == "modify" and plugin_stage.output_process:
            print("[Pipeline] Stage 2/6: Running plugin post-process for generate_domain_context...")
            from .plugin import run_plugin_command
            run_plugin_command(plugin_stage.output_process, plugin_root, proj_dir, label="generate_domain_context post-process")

    if not _domain_context_complete(work_dir):
        raise RuntimeError(
            "Stage generate_domain_context failed: domain context output files "
            "are missing or incomplete."
        )


def _run_setup_extract(
    proj_dir,
    work_dir,
    script_dir,
    is_incremental=False,
    resume=False,
    required_source_files=None,
    submodules=None,
    plugin_config=None,
    backend=None,
):
    """Run setup manifest generation, post-processing, and domain context."""
    module_stage = plugin_config.get_stage("generate_module_plan") if plugin_config else None
    context_stage = plugin_config.get_stage("generate_domain_context") if plugin_config else None
    plugin_root = plugin_config.root if plugin_config else None

    _run_generate_source_manifest(
        proj_dir,
        work_dir,
        script_dir,
        is_incremental=is_incremental,
        resume=resume,
        submodules=submodules,
        plugin_stage=module_stage,
        plugin_root=plugin_root,
        backend=backend,
    )
    manifests_modified = _post_process_source_manifest(
        proj_dir,
        work_dir,
        required_source_files=required_source_files,
        submodules=submodules,
        backend=backend,
    )
    _run_generate_domain_context(
        proj_dir,
        work_dir,
        script_dir,
        resume=resume and not manifests_modified,
        plugin_stage=context_stage,
        plugin_root=plugin_root,
        backend=backend,
    )

    if not _setup_outputs_complete(work_dir):
        print(
            "[Pipeline] ERROR: Setup outputs are incomplete. Expected "
            "fm_agent/source_files.json, fm_agent/modules.json, "
            "fm_agent/spec_prompts/domain_context/engine_overview.txt, and "
            "either domain_context/types.txt or domain_context/module_types/*.txt."
        )
        sys.exit(1)

"""Utilities for user-provided domain knowledge markdown files."""

import json
import os
import re
import shutil

from config import settings


VALID_DOMAIN_KNOWLEDGE_EXTENSIONS = {".md", ".markdown"}
USER_KNOWLEDGE_REL_DIR = os.path.join(
    "spec_prompts", "domain_context", "user_knowledge"
)
USER_KNOWLEDGE_MANIFEST = "manifest.json"


def _flatten_paths(values):
    paths = []
    for value in values or []:
        if isinstance(value, (list, tuple)):
            paths.extend(_flatten_paths(value))
        elif value:
            paths.append(value)
    return paths


def _split_env_paths(value):
    if not value:
        return []
    normalized = value.replace("\n", os.pathsep)
    return [part.strip() for part in normalized.split(os.pathsep) if part.strip()]


def resolve_domain_knowledge_paths(paths, base_dir, fallback_base_dir=None):
    """Validate and return absolute paths to markdown knowledge files."""
    resolved = []
    seen = set()
    base_dir = os.path.abspath(base_dir)
    fallback_base_dir = (
        os.path.abspath(fallback_base_dir) if fallback_base_dir else None
    )

    for raw_path in _flatten_paths(paths):
        expanded = os.path.expanduser(raw_path)
        candidates = []
        if os.path.isabs(expanded):
            candidates.append(expanded)
        else:
            candidates.append(os.path.join(base_dir, expanded))
            if fallback_base_dir:
                candidates.append(os.path.join(fallback_base_dir, expanded))

        path = next(
            (candidate for candidate in candidates if os.path.exists(candidate)),
            candidates[0],
        )
        path = os.path.abspath(path)
        if not os.path.exists(path):
            raise ValueError(f"domain knowledge file does not exist: {raw_path}")
        if not os.path.isfile(path):
            raise ValueError(f"domain knowledge path is not a file: {raw_path}")
        ext = os.path.splitext(path)[1].lower()
        if ext not in VALID_DOMAIN_KNOWLEDGE_EXTENSIONS:
            allowed = ", ".join(sorted(VALID_DOMAIN_KNOWLEDGE_EXTENSIONS))
            raise ValueError(
                f"domain knowledge file must be Markdown ({allowed}): {raw_path}"
            )

        real_path = os.path.realpath(path)
        if real_path in seen:
            continue
        seen.add(real_path)
        resolved.append(path)
    return resolved


def collect_domain_knowledge_paths(cli_paths, base_dir, fallback_base_dir=None):
    """Collect markdown paths from CLI values plus FM_AGENT_DOMAIN_KNOWLEDGE."""
    paths = []
    paths.extend(_split_env_paths(settings.runtime.domain_knowledge_paths))
    paths.extend(_flatten_paths(cli_paths))
    return resolve_domain_knowledge_paths(
        paths,
        base_dir=base_dir,
        fallback_base_dir=fallback_base_dir,
    )


def _safe_staged_name(source_path, used_names):
    basename = os.path.basename(source_path)
    stem, ext = os.path.splitext(basename)
    stem = re.sub(r"[^A-Za-z0-9._-]+", "_", stem).strip("._-") or "knowledge"
    ext = ext.lower()
    candidate = f"{stem}{ext}"
    if candidate not in used_names:
        used_names.add(candidate)
        return candidate

    index = 2
    while True:
        candidate = f"{stem}_{index}{ext}"
        if candidate not in used_names:
            used_names.add(candidate)
            return candidate
        index += 1


def list_staged_domain_knowledge_relpaths(work_dir, prefix="fm_agent"):
    """Return project-relative staged markdown paths, sorted for stable prompts."""
    knowledge_dir = os.path.join(work_dir, USER_KNOWLEDGE_REL_DIR)
    if not os.path.isdir(knowledge_dir):
        return []

    relpaths = []
    for root, _dirs, files in os.walk(knowledge_dir):
        for fname in files:
            if fname == USER_KNOWLEDGE_MANIFEST:
                continue
            ext = os.path.splitext(fname)[1].lower()
            if ext not in VALID_DOMAIN_KNOWLEDGE_EXTENSIONS:
                continue
            abs_path = os.path.join(root, fname)
            rel_to_work = os.path.relpath(abs_path, work_dir).replace(os.sep, "/")
            relpaths.append(f"{prefix.rstrip('/')}/{rel_to_work}")
    return sorted(relpaths)


def stage_domain_knowledge_files(proj_dir, work_dir, markdown_paths=None):
    """Copy user markdown files into fm_agent/spec_prompts/domain_context/.

    When markdown_paths is provided, the staged directory is replaced with exactly
    those files. When omitted or empty, existing staged files are preserved and
    listed; this supports resume runs.
    """
    if not markdown_paths:
        return list_staged_domain_knowledge_relpaths(work_dir)

    resolved = resolve_domain_knowledge_paths(
        markdown_paths,
        base_dir=proj_dir,
        fallback_base_dir=os.getcwd(),
    )
    target_dir = os.path.join(work_dir, USER_KNOWLEDGE_REL_DIR)
    parent_dir = os.path.dirname(target_dir)
    tmp_dir = target_dir + ".tmp"
    shutil.rmtree(tmp_dir, ignore_errors=True)
    os.makedirs(tmp_dir, exist_ok=True)

    used_names = set()
    entries = []
    for source_path in resolved:
        target_name = _safe_staged_name(source_path, used_names)
        target_path = os.path.join(tmp_dir, target_name)
        shutil.copy2(source_path, target_path)
        rel_to_work = os.path.join(USER_KNOWLEDGE_REL_DIR, target_name).replace(
            os.sep, "/"
        )
        entries.append({
            "source_path": source_path,
            "staged_path": f"fm_agent/{rel_to_work}",
        })

    manifest_path = os.path.join(tmp_dir, USER_KNOWLEDGE_MANIFEST)
    with open(manifest_path, "w", encoding="utf-8") as f:
        json.dump({"files": entries}, f, indent=2, ensure_ascii=False)

    os.makedirs(parent_dir, exist_ok=True)
    shutil.rmtree(target_dir, ignore_errors=True)
    os.replace(tmp_dir, target_dir)
    return list_staged_domain_knowledge_relpaths(work_dir)


def format_domain_knowledge_bullets(relpaths):
    if not relpaths:
        return ""
    return "\n".join(f"- `{path}`" for path in relpaths)


def module_type_filename(module_name):
    """Return the canonical module_types filename for a module name."""
    stem = re.sub(r"[^A-Za-z0-9._-]+", "_", str(module_name or "module"))
    stem = stem.strip("._-") or "module"
    return f"{stem}.txt"


def _source_file_to_extracted_dir(source_file):
    source_file = source_file.replace("\\", "/").strip("/")
    src_dir = os.path.dirname(source_file).replace(os.sep, "/")
    src_base = os.path.basename(source_file)
    dot = src_base.rfind(".")
    if dot > 0:
        extracted_name = src_base[:dot] + "-" + src_base[dot + 1:]
    else:
        extracted_name = src_base
    return f"{src_dir}/{extracted_name}" if src_dir else extracted_name


def _module_name_for_artifact(work_dir, artifact_relpath):
    """Map an extracted-function/result artifact path to its owning module."""
    if not artifact_relpath:
        return None
    rel = artifact_relpath.replace("\\", "/").strip("/")
    for prefix in (
        "fm_agent/extracted_functions/",
        "extracted_functions/",
        "fm_agent/logic_verification_results/",
        "logic_verification_results/",
    ):
        if rel.startswith(prefix):
            rel = rel[len(prefix):]
            break

    modules_path = os.path.join(work_dir, "modules.json")
    try:
        with open(modules_path, "r", encoding="utf-8") as f:
            modules_data = json.load(f)
    except (OSError, json.JSONDecodeError):
        return None

    for module in modules_data.get("modules", []):
        module_name = module.get("name")
        if not module_name:
            continue
        for source_file in module.get("source_files", []):
            extracted_dir = _source_file_to_extracted_dir(str(source_file))
            if rel == extracted_dir or rel.startswith(extracted_dir + "/"):
                return module_name
    return None


def list_generated_domain_context_relpaths(work_dir, artifact_relpath=None, prefix="fm_agent"):
    """Return generated domain context files relevant to an artifact."""
    domain_dir = os.path.join(work_dir, "spec_prompts", "domain_context")
    relpaths = []

    engine_path = os.path.join(domain_dir, "engine_overview.txt")
    if os.path.isfile(engine_path):
        relpaths.append("spec_prompts/domain_context/engine_overview.txt")

    types_path = os.path.join(domain_dir, "types.txt")
    if os.path.isfile(types_path):
        relpaths.append("spec_prompts/domain_context/types.txt")
    else:
        module_name = _module_name_for_artifact(work_dir, artifact_relpath)
        if module_name:
            module_type_rel = os.path.join(
                "spec_prompts",
                "domain_context",
                "module_types",
                module_type_filename(module_name),
            )
            if os.path.isfile(os.path.join(work_dir, module_type_rel)):
                relpaths.append(module_type_rel.replace(os.sep, "/"))

    return [f"{prefix.rstrip('/')}/{rel}" for rel in relpaths]


def load_generated_domain_context_text(work_dir, artifact_relpath=None):
    """Return generated setup domain context relevant to an artifact."""
    relpaths = list_generated_domain_context_relpaths(work_dir, artifact_relpath)
    if not relpaths:
        return ""

    sections = [
        "Generated domain context:",
        "Use this setup-generated context for intended behavior, terminology, "
        "data encodings, and invariants.",
        "",
    ]
    project_root = os.path.dirname(os.path.abspath(work_dir))
    for relpath in relpaths:
        abs_path = os.path.join(project_root, relpath)
        try:
            with open(abs_path, "r", encoding="utf-8", errors="replace") as f:
                content = f.read().strip()
        except OSError:
            continue
        if not content:
            continue
        sections.append(f"### {relpath}")
        sections.append(content)
        sections.append("")
    return "\n".join(sections).strip()


def load_staged_domain_knowledge_text(work_dir):
    """Return staged markdown contents formatted for LLM context."""
    relpaths = list_staged_domain_knowledge_relpaths(work_dir)
    if not relpaths:
        return ""

    sections = [
        "User-provided domain knowledge:",
        "Use these Markdown notes as additional context for intended behavior, "
        "terminology, data encodings, and invariants.",
        "",
    ]
    project_root = os.path.dirname(os.path.abspath(work_dir))
    for relpath in relpaths:
        abs_path = os.path.join(project_root, relpath)
        try:
            with open(abs_path, "r", encoding="utf-8", errors="replace") as f:
                content = f.read().strip()
        except OSError:
            continue
        if not content:
            continue
        sections.append(f"### {relpath}")
        sections.append(content)
        sections.append("")
    return "\n".join(sections).strip()

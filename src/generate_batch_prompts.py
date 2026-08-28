"""Generate per-layer spec batch prompts from topdown layer metadata."""

import argparse
import json
import logging
import re
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Tuple

try:
    # When imported as part of the src package (e.g. incremental_reasoner).
    from .file_utils import is_file_ready
    from .domain_knowledge import list_staged_domain_knowledge_relpaths
    from .specification import BatchPromptContext, SOFTWARE_PROFILE, SpecificationProfile
except ImportError:
    # When run directly from the source tree, file_utils.py sits beside this script.
    from file_utils import is_file_ready
    from specification import BatchPromptContext, SOFTWARE_PROFILE, SpecificationProfile

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
    "chisel": "//",
    "verilog": "//",
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

_QUALIFIED_NAME_SEPARATOR_RE = re.compile(r"::|\.")
_ERLANG_NAME_RE = re.compile(
    r"^(?P<module>[A-Za-z_][\w@]*)\s*:\s*"
    r"(?P<function>[A-Za-z_][\w@]*)/(?P<arity>\d+)$"
)

logger = logging.getLogger(__name__)


def extension_language_map(
    languages: Sequence[str],
    file_extensions: Sequence[str],
) -> dict[str, str]:
    """Map phase-plan extensions to languages without silent truncation.

    A single configured language may own multiple extensions, such as Chisel
    owning scala and sc or Verilog owning v, sv and svh. When more than one
    language is configured, retain positional mapping but reject ambiguity.
    """
    normalized_extensions = [
        extension.lower().lstrip(".") for extension in file_extensions
    ]
    if len(languages) == 1:
        return {
            extension: languages[0]
            for extension in normalized_extensions
        }
    if len(languages) > 1 and len(languages) != len(normalized_extensions):
        raise ValueError(
            "phases.json languages and file_extensions must have equal lengths "
            "when more than one language is configured"
        )
    return dict(zip(normalized_extensions, languages))


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Generate spec batch prompts for one phase/layer range.")
    parser.add_argument("--phase", type=int, required=True, help="Phase number, e.g. 3")
    parser.add_argument("--layers", required=True, help="Layer index or inclusive range, e.g. 0 or 0-5")
    parser.add_argument("--batch-size", type=int, default=2, help="Units per prompt file")
    parser.add_argument("--output-dir", default=None, help="Output directory for batch prompt files")
    parser.add_argument("--dry-run", action="store_true", help="Show plan without writing files")
    parser.add_argument(
        "--resume",
        action="store_true",
        help="Skip units already specced (file_utils.is_file_ready) when building batches",
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


def _spec_json_path(filepath: Path, specification: SpecificationProfile = SOFTWARE_PROFILE) -> Path:
    """Return the spec sidecar next to one extracted function file."""
    return specification.artifact_paths(filepath).self_spec


def _info_json_path(filepath: Path, specification: SpecificationProfile = SOFTWARE_PROFILE) -> Path:
    """Return the info sidecar next to one extracted function file."""
    return specification.artifact_paths(filepath).dependency_info


def extract_spec_block(filepath: Path, specification: SpecificationProfile = SOFTWARE_PROFILE) -> Optional[str]:
    """Read .spec.json and rebuild reasoner-facing spec text."""
    spec_path = _spec_json_path(filepath, specification)

    try:
        with spec_path.open("r", encoding="utf-8") as file:
            spec = json.load(file)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return None

    if not isinstance(spec, dict):
        return None

    return (
        f"{spec.get('signature', '')}\n\n"
        f"Pre-condition:\n{spec.get('pre_condition', '')}\n\n"
        f"Post-condition:\n{spec.get('post_condition', '')}"
    )


def extract_info_block(filepath: Path, specification: SpecificationProfile = SOFTWARE_PROFILE) -> Optional[dict]:
    """Read the adjacent .info.json object when it is usable."""
    info_path = _info_json_path(filepath, specification)

    try:
        with info_path.open("r", encoding="utf-8") as file:
            info = json.load(file)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return None

    return info if isinstance(info, dict) else None


def extract_callee_spec_from_info(
    info_dict: dict,
    callee_fqn: str,
    aliases: Optional[Sequence[str]] = None,
) -> Optional[dict]:
    """Return the callee object matching the FQN or trusted edge aliases.

    ``aliases`` must contain only names supplied by a supplemental edge's
    ``callee.info_names``.  The matcher deliberately does not infer aliases
    from the candidate entries in ``info_dict``.
    """
    names = _callee_match_names(callee_fqn, aliases or ())
    callees = info_dict.get("callees", [])
    if not isinstance(callees, list):
        logger.warning(
            "No callee expectation matched FQN %s (aliases=%s, entries=invalid)",
            callee_fqn,
            list(aliases or ()),
        )
        return None

    named_callees = []
    for callee in callees:
        if not isinstance(callee, dict):
            continue
        name = callee.get("name", "")
        if not isinstance(name, str):
            continue
        normalized_name = _name_without_call_decoration(name)
        bare_name = _bare_name_for_matching(normalized_name)
        named_callees.append((callee, name, normalized_name, bare_name))

    for callee, name, _normalized_name, _bare_name in named_callees:
        if _info_name_matches_fqn(name, callee_fqn):
            return callee

    for callee, name, _normalized_name, _bare_name in named_callees:
        if any(
            _info_name_matches_alias(name, alias)
            for alias in aliases or ()
            if alias
        ):
            return callee

    bare_names = [name for name in names if not _is_qualified_name(name)]
    bare_name_counts = {}
    for _callee, _name, _normalized_name, bare_name in named_callees:
        if bare_name:
            bare_name_counts[bare_name.casefold()] = (
                bare_name_counts.get(bare_name.casefold(), 0) + 1
            )
    for callee, _name, normalized_name, bare_name in named_callees:
        if not bare_name or bare_name_counts.get(bare_name.casefold(), 0) != 1:
            continue
        if _is_qualified_name(normalized_name):
            # A source-qualified entry that failed the explicit FQN/alias
            # passes must not be reduced to its final component: doing so can
            # attach ``wrong::Class::method`` to ``src::Class::method``.
            # ``self``/``this`` are receiver syntax, not namespaces; dotted
            # member syntax is eligible only when its receiver names target.
            if not _qualified_source_name_compatible(normalized_name, callee_fqn):
                continue
        if _erlang_name_parts(normalized_name) and not _erlang_name_matches_fqn(
            normalized_name, callee_fqn
        ):
            continue
        if any(
            _info_line_mentions_name(bare_name, candidate)
            for candidate in bare_names
        ):
            return callee
    logger.warning(
        "No callee expectation matched FQN %s (aliases=%s, entries=%d)",
        callee_fqn,
        list(aliases or ()),
        len(named_callees),
    )
    return None


def _callee_match_names(callee_fqn: str, aliases: Sequence[str]) -> List[str]:
    names = [callee_fqn, callee_fqn.split("::")[-1]]
    for alias in aliases:
        if not alias:
            continue
        names.append(alias)
        alias_parts = _qualified_name_parts(alias)
        if len(alias_parts) > 1:
            names.append(alias_parts[-1])
    return list(dict.fromkeys(names))


def _qualified_name_parts(name: str) -> List[str]:
    """Split C++- and dot-qualified source names into components."""
    return [part for part in _QUALIFIED_NAME_SEPARATOR_RE.split(name) if part]


def _is_qualified_name(name: str) -> bool:
    """Return whether a source-level name contains a known qualifier."""
    angle_depth = 0
    index = 0
    while index < len(name):
        char = name[index]
        if char == "<":
            angle_depth += 1
        elif char == ">" and angle_depth:
            angle_depth -= 1
        elif angle_depth == 0:
            if char == "." or name.startswith("::", index):
                return True
        index += 1
    return False


def _trailing_parenthesized_group(name: str) -> Optional[Tuple[str, str]]:
    """Return the prefix and contents of one balanced trailing ``(...)`` group."""
    stripped = name.rstrip()
    if not stripped.endswith(")"):
        return None

    depth = 0
    for index in range(len(stripped) - 1, -1, -1):
        char = stripped[index]
        if char == ")":
            depth += 1
        elif char == "(":
            depth -= 1
            if depth == 0:
                return stripped[:index].rstrip(), stripped[index + 1 : -1].strip()
    return None


def _name_without_call_decoration(name: str) -> str:
    """Remove one balanced trailing call expression from a source name."""
    group = _trailing_parenthesized_group(name)
    if not group:
        return name
    undecorated, contents = group
    # ``operator()`` is a function name; only a following pair of parentheses
    # represents a call decoration for that operator.
    components = _QUALIFIED_NAME_SEPARATOR_RE.split(undecorated)
    if components[-1].strip() == "operator" and not contents:
        return name
    return undecorated


def _is_operator_call_name(name: str) -> bool:
    group = _trailing_parenthesized_group(name)
    if not group or group[1]:
        return False
    components = _QUALIFIED_NAME_SEPARATOR_RE.split(group[0])
    return components[-1].strip() == "operator"


def _erlang_name_parts(name: str) -> Optional[Tuple[str, str, int]]:
    match = _ERLANG_NAME_RE.fullmatch(name.strip())
    if not match:
        return None
    return match.group("module"), match.group("function"), int(match.group("arity"))


def _erlang_name_matches_fqn(info_name: str, callee_fqn: str) -> bool:
    parts = _erlang_name_parts(info_name)
    fqn_parts = [part for part in callee_fqn.split("::") if part]
    if not parts or len(fqn_parts) < 2:
        return False
    module, function, arity = parts

    # Erlang functions produced by the ELP adapter use an encoded final
    # component: ``module__function__arity``.  Older metadata may instead
    # expose ``module::function`` without an arity.  Compare arity whenever
    # the FQN carries it, while retaining compatibility for the old form.
    encoded = re.fullmatch(
        r"(?P<module>[A-Za-z_][\w@]*)__(?P<function>[A-Za-z_][\w@]*)__(?P<arity>\d+)",
        fqn_parts[-1],
    )
    if encoded:
        return (
            module.casefold() == encoded.group("module").casefold()
            and function.casefold() == encoded.group("function").casefold()
            and arity == int(encoded.group("arity"))
        )

    return (
        module.casefold() == fqn_parts[-2].casefold()
        and function.casefold() == fqn_parts[-1].casefold()
    )


def _bare_name_for_matching(name: str) -> str:
    """Return the final source-level component used by safe bare fallback."""
    erlang_parts = _erlang_name_parts(name)
    if erlang_parts:
        return erlang_parts[1]
    source_candidates = _source_name_fqn_candidates(name)
    if source_candidates:
        return source_candidates[0].split("::")[-1]
    if _is_qualified_name(name):
        parts = _qualified_name_parts(name)
        return _codegraph_source_component(parts[-1]) if parts else ""
    bare = name.strip().split()[0] if name.strip() else ""
    # Template arguments decorate a function name but do not identify its
    # callee for the safe bare fallback.  Canonicalizing here makes
    # ``run<int>()`` and ``run<float>()`` collide instead of selecting the
    # first entry based on incidental ordering.
    if "<" in name:
        # Look at the original spelling so spaces inside template arguments
        # do not truncate the token before we canonicalize it.
        template_start = name.find("<")
        prefix = name[:template_start].strip()
        if re.fullmatch(r"[A-Za-z_]\w*", prefix):
            bare = prefix
            return bare
    if "<" in bare:
        angle_depth = 0
        end = None
        for index, char in enumerate(bare):
            if char == "<":
                if angle_depth == 0:
                    end = index
                angle_depth += 1
            elif char == ">" and angle_depth:
                angle_depth -= 1
        if end is not None and angle_depth == 0:
            bare = bare[:end]
    return bare


def _codegraph_source_component(component: str) -> str:
    """Mirror CodeGraph's bare-name and FQN-safe normalization for one part."""
    name = component.strip()
    if not name:
        return ""

    tail = name
    if "::" in tail:
        tail = tail.rsplit("::", 1)[1].lstrip()
    elif "." in tail:
        tail = tail.rsplit(".", 1)[1].lstrip()

    if tail.startswith("operator"):
        rest = tail[len("operator") :].lstrip()
        if rest.startswith("[]"):
            return "operator[]"
        if rest.startswith("()"):
            return "operator()"
        if re.fullmatch(r"new(?:\s*\[\s*\])?", rest):
            return "operator new[]" if "[" in rest else "operator new"
        if re.fullmatch(r"delete(?:\s*\[\s*\])?", rest):
            return "operator delete[]" if "[" in rest else "operator delete"

        symbol = []
        for char in rest:
            if char in "+-*/%&|^~!=<>,":
                symbol.append(char)
            else:
                break
        if symbol:
            return ("operator" + "".join(symbol)).replace("/", "_")

    match = re.search(r"(?:^|::|\.)(\w+)$", name)
    if match:
        return match.group(1)
    match = re.match(r"\(\s*\*\s*(\w+)\s*\)", name)
    if match:
        return match.group(1)
    match = re.match(r"\*\s*(\w+)", name)
    if match:
        return match.group(1)
    match = re.match(r"^(\w+)", name)
    if match:
        return match.group(1)
    return name.replace("/", "_")


def _has_top_level_hyphen_before_final_component(name: str) -> bool:
    """Distinguish a literal ``base-ext`` FQN prefix from template arguments."""
    angle_depth = 0
    top_level_hyphens: List[int] = []
    last_separator = -1
    index = 0
    while index < len(name):
        char = name[index]
        if char == "<":
            angle_depth += 1
        elif char == ">" and angle_depth:
            angle_depth -= 1
        elif angle_depth == 0:
            if name.startswith("::", index):
                last_separator = index
                index += 2
                continue
            if char == ".":
                last_separator = index
            elif char == "-":
                top_level_hyphens.append(index)
        index += 1
    return any(position < last_separator for position in top_level_hyphens)


def _normalized_source_name_parts(name: str) -> List[str]:
    """Return CodeGraph-shaped parts for one source-qualified spelling."""
    # FM-Agent's file component uses ``base-ext`` and is not source syntax.
    # It must stay on the literal-prefix side of a mixed candidate boundary.
    # A hyphen inside a template argument (for example, ``Widget<-1>``) is
    # source decoration and must not be mistaken for that file marker.
    if _has_top_level_hyphen_before_final_component(name):
        return []
    # Namespace separators inside template arguments do not qualify the
    # function itself (for example, ``run<std::pair<int, float>>``).
    angle_depth = 0
    has_top_level_separator = False
    index = 0
    while index < len(name):
        char = name[index]
        if char == "<":
            angle_depth += 1
        elif char == ">" and angle_depth:
            angle_depth -= 1
        elif angle_depth == 0 and (char == "." or name.startswith("::", index)):
            has_top_level_separator = True
            break
        index += 1
    if not has_top_level_separator:
        return []
    parts = _QUALIFIED_NAME_SEPARATOR_RE.split(name)
    if len(parts) <= 1 or any(not part.strip() for part in parts):
        return []
    normalized_parts = [_codegraph_source_component(part) for part in parts]
    if any(not part for part in normalized_parts):
        return []
    return normalized_parts


def _source_name_fqn_candidates(name: str) -> List[str]:
    """Return complete source and literal-FQN-prefix interpretations of a name."""
    candidates: List[str] = []

    # Treat the complete spelling as a source-qualified name. This covers pure
    # ``::``, pure dot, and mixed source scopes, including template arguments
    # whose namespaces become separate CodeGraph components.
    normalized_parts = _normalized_source_name_parts(name)
    if normalized_parts:
        candidates.append("::".join(normalized_parts))

    # A leading FM-Agent FQN component may contain literal dots (for example,
    # ``foo.test-go``). At every explicit FQN boundary, preserve the prefix and
    # independently interpret the remaining qualified tail as source spelling.
    for boundary in re.finditer(r"::", name):
        literal_prefix = name[: boundary.start()].strip()
        source_tail = name[boundary.end() :].strip()
        if not literal_prefix or not source_tail:
            continue
        if any(not part.strip() for part in literal_prefix.split("::")):
            continue
        normalized_tail_parts = _normalized_source_name_parts(source_tail)
        if normalized_tail_parts:
            normalized_tail = "::".join(normalized_tail_parts)
            candidates.append(f"{literal_prefix}::{normalized_tail}")
    return list(dict.fromkeys(candidates))


def _qualified_source_name_compatible(name: str, callee_fqn: str) -> bool:
    """Allow only receiver/member spellings safe for bare fallback."""
    parts = _qualified_name_parts(name)
    if len(parts) == 2 and parts[0].strip().casefold() in {"self", "this"}:
        return True

    # Preserve the existing receiver/member spelling used by languages that
    # write ``Engine.start`` while requiring its receiver to identify the same
    # class as the target FQN.  This avoids treating arbitrary dotted names
    # such as ``myself.run`` as pseudo-receivers.
    fqn_parts = [part for part in callee_fqn.split("::") if part]
    if (
        len(parts) == 2
        and len(fqn_parts) >= 2
        and parts[0].strip().casefold() == fqn_parts[-2].casefold()
        and parts[1].strip().casefold() == fqn_parts[-1].casefold()
    ):
        return True

    # Qualified names have already had an exact/normalized suffix comparison
    # opportunity.  Never trim arbitrary namespace components during the bare
    # fallback: a shared tail is not evidence that the qualifiers agree.
    return False


def _fqn_has_component_suffix(callee_fqn: str, candidate: str) -> bool:
    """Return whether candidate equals a complete ``::``-delimited FQN suffix."""
    callee_parts = callee_fqn.split("::")
    candidate_parts = candidate.split("::")
    return (
        bool(candidate_parts)
        and all(callee_parts)
        and all(candidate_parts)
        and len(candidate_parts) <= len(callee_parts)
        and callee_parts[-len(candidate_parts) :] == candidate_parts
    )


def _info_name_matches_fqn(info_name: str, callee_fqn: str) -> bool:
    """Match a complete FQN or a source-language-qualified suffix."""
    variants = [info_name]
    undecorated = _name_without_call_decoration(info_name)
    if undecorated != info_name:
        variants.append(undecorated)
    for variant in variants:
        if variant == callee_fqn:
            return True
        # Preserve literal FM-Agent FQN components, which may contain dots.
        if "::" in variant and _fqn_has_component_suffix(callee_fqn, variant):
            return True
        if _erlang_name_matches_fqn(variant, callee_fqn):
            return True
        # Do not let the component normalizer erase a remaining call layer.
        # Literal suffix matching above still supports ``operator()`` and one
        # preserved call decoration when the FQN contains it.
        if _trailing_parenthesized_group(variant) and not _is_operator_call_name(variant):
            continue
        if any(
            _fqn_has_component_suffix(callee_fqn, candidate)
            for candidate in _source_name_fqn_candidates(variant)
        ):
            return True

    group = _trailing_parenthesized_group(info_name)
    if group:
        prefix, label = group
        fqn_parts = [part for part in callee_fqn.split("::") if part]
        if (
            label
            and len(fqn_parts) >= 2
            and label.casefold() == fqn_parts[-1].casefold()
            and _bare_name_for_matching(prefix).casefold()
            == fqn_parts[-2].casefold()
        ):
            return True
    return False


def _info_name_matches_alias(info_name: str, alias: str) -> bool:
    """Match an exact alias while accepting equivalent source qualifiers."""
    variants = [info_name]
    undecorated = _name_without_call_decoration(info_name)
    if undecorated != info_name:
        variants.append(undecorated)
    for variant in variants:
        if variant == alias:
            return True
        if _erlang_name_parts(variant) and _erlang_name_parts(alias):
            left = _erlang_name_parts(variant)
            right = _erlang_name_parts(alias)
            if left and right and left == right:
                return True
        if _is_qualified_name(variant) and _is_qualified_name(alias):
            if _qualified_name_parts(variant) == _qualified_name_parts(alias):
                return True

    group = _trailing_parenthesized_group(info_name)
    if group:
        prefix, label = group
        alias_parts = alias.split("::") if "::" in alias else _qualified_name_parts(alias)
        if (
            label
            and len(alias_parts) >= 2
            and label.casefold() == alias_parts[-1].casefold()
            and _bare_name_for_matching(prefix).casefold()
            == alias_parts[-2].casefold()
        ):
            return True
    return False


def _info_line_mentions_name(first_line: str, name: str) -> bool:
    if not name:
        return False
    if "::" in name:
        return name in first_line
    return bool(re.search(rf"(?<![A-Za-z0-9_]){re.escape(name)}(?:\s*\(|\b)", first_line))


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


def phase_callee_info_names_key(func: dict, phase: int) -> Optional[str]:
    target = f"phase{phase}_callee_info_names_by_caller"
    if target in func:
        return target
    for key in func.keys():
        if key.endswith("_callee_info_names_by_caller") and key.startswith("phase"):
            return key
    return None


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
    specification: SpecificationProfile = SOFTWARE_PROFILE,
) -> str:
    lines: List[str] = []
    sample_lang = "unknown"
    if functions:
        sample_lang, _ = detect_lang_and_comment(functions[0]["file"], ext_to_lang)
    self_artifact_name, dependency_artifact_name = specification.example_artifact_names()

    lines.append(f"You are generating behavioral specifications for Phase {phase}, Layer {layer_idx}.")
    lines.append("")
    lines.append(
        f"Language: {sample_lang}. "
        f"Write specifications to adjacent {specification.artifacts.self_suffix} "
        f"and {specification.artifacts.dependency_suffix} files."
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
    lines.append("- Describe WHAT each extracted unit guarantees, NOT HOW it implements it")
    lines.append("- Do NOT name internal helper calls, loop structure, or data layout decisions")
    lines.append("- Do NOT enumerate members of sets - describe the GOVERNING RULE")
    lines.append("- Specs describe INTENDED CORRECT behavior per the domain (see domain files)")
    lines.append(f"- ALL files below exist in {fm_agent_prefix}extracted_functions/ - read and process each one")

    caller_specs: List[Tuple[str, str]] = []
    caller_expectations: Dict[str, List[Tuple[str, str]]] = {}
    for fn in functions:
        fn_name = fn["name"]
        caller_key = phase_callers_key(fn, phase)
        info_names_key = phase_callee_info_names_key(fn, phase)
        info_names_by_caller = fn.get(info_names_key, {}) if info_names_key else {}
        callers = fn.get(caller_key, [])
        for caller_name in callers:
            caller_layer = func_to_layer.get(caller_name)
            if caller_layer is None or caller_layer >= layer_idx:
                continue
            caller_meta = all_funcs.get(caller_name)
            if not caller_meta:
                continue
            caller_file = work_dir / caller_meta["file"]
            spec_block = specification.read_self_spec(caller_file)
            if spec_block and (caller_name, spec_block) not in caller_specs:
                caller_specs.append((caller_name, spec_block))
            entry_text = specification.read_dependency_expectation(
                caller_file,
                fn_name,
                info_names_by_caller.get(caller_name, []),
            )
            if entry_text:
                caller_expectations.setdefault(fn_name, []).append(
                    (caller_name, entry_text)
                )

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
        lines.append("These units call each other (mutual recursion / circular dependencies).")
        lines.append(
            'Ask: "What is true after this function returns, regardless of which caller invoked it and which code path executed?" '
            "That invariant is your post-condition."
        )
        lines.append("")
        lines.append("DISPATCH UNIT TEST: If your spec has N bullets where N equals the number")
        lines.append("of switch arms / dispatch cases, you are transcribing the implementation.")
        lines.append("A dispatch function's contract is the invariant that holds ACROSS ALL cases.")
        lines.append("")

    lines.append(f"## UNITS ({len(functions)} total - process ALL)")
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
    lines.extend(
        specification.prompt_contract.batch_output_section(
            BatchPromptContext(
                self_artifact_name=self_artifact_name,
                dependency_artifact_name=dependency_artifact_name,
            )
        )
    )
    return "\n".join(lines).rstrip() + "\n"


def generate_batch_prompts(
    work_dir: Path,
    phase: int,
    layers_spec: str,
    *,
    batch_size: int = 2,
    output_dir: Optional[Path] = None,
    resume: bool = False,
    dry_run: bool = False,
    specification: SpecificationProfile = SOFTWARE_PROFILE,
) -> dict:
    """Build, persist, and return the batch manifest for a layer range."""
    if batch_size <= 0:
        raise ValueError("--batch-size must be > 0")

    work_dir = Path(work_dir)
    # fm_agent_prefix is the relative path from the project root to work_dir
    repo_root = work_dir.parent
    fm_agent_prefix = str(work_dir.relative_to(repo_root)) + "/"

    phases_json = read_json(work_dir / "phases.json")
    project = phases_json["project"]
    languages = phases_json.get("languages", [])
    exts = phases_json.get("file_extensions", [])
    ext_to_lang = extension_language_map(languages, exts)

    topdown_path = work_dir / "spec_prompts" / f"phase_{phase:02d}_topdown_layers.json"
    topdown = read_json(topdown_path)
    layers = topdown.get("layers", [])
    total_layers = len(layers)
    start_layer, end_layer = parse_layers_spec(layers_spec)
    if start_layer < 0 or end_layer >= total_layers:
        raise ValueError(f"layer range {layers_spec} out of bounds [0, {total_layers - 1}]")

    output_dir = Path(output_dir) if output_dir is not None else (
        work_dir / "spec_prompts" / f"batch_prompts_{project}_phase{phase:02d}"
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
        chunks = chunked(layer_functions, batch_size)
        total_functions += len(layer_functions)

        for local_idx, fn_batch in enumerate(chunks):
            filename = f"batch_{batch_index:03d}_layer{layer_idx}_{tag}_b{local_idx}.txt"
            # On resume, don't ask the LLM to re-spec functions that are already
            # done — but the manifest below still records the full batch.
            prompt_funcs = fn_batch
            if resume:
                prompt_funcs = [
                    fn
                    for fn in fn_batch
                    if not is_file_ready(work_dir / fn["file"], specification)
                ]
                skipped_functions += len(fn_batch) - len(prompt_funcs)
            out_path = output_dir / filename
            # On resume, a batch whose functions are all already specced has no
            # work left for the agent — don't write an empty prompt file. The
            # manifest still records the full batch so later verification covers
            # these functions; run_pipeline only spawns batches that still have
            # unspecced functions (see _get_pending_batches).
            if prompt_funcs:
                content = build_prompt(
                    phase,
                    layer_idx,
                    is_cycle,
                    prompt_funcs,
                    func_to_layer,
                    all_funcs,
                    work_dir,
                    fm_agent_prefix,
                    ext_to_lang,
                    specification,
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
        "phase": phase,
        "layers": layers_spec,
        "total_functions": total_functions,
        "total_batches": len(manifest_batches),
        "batches": manifest_batches,
    }

    if dry_run:
        print(
            f"[dry-run] phase={phase} layers={layers_spec} "
            f"functions={total_functions} batches={len(manifest_batches)}"
            + (f" skipped={skipped_functions} (already specced)" if resume else "")
        )
        for batch in manifest_batches:
            print(
                f"- {batch['file']}: layer={batch['layer']} "
                f"count={batch['num_functions']} cycle={batch['is_cycle']}"
            )
        return manifest

    output_dir.mkdir(parents=True, exist_ok=True)
    current_batch_paths = {out_path for out_path, _ in write_targets}
    for existing_path in output_dir.glob("batch_*.txt"):
        if existing_path not in current_batch_paths:
            existing_path.unlink()
    for out_path, content in write_targets:
        out_path.write_text(content)
    for out_path in stale_targets:
        out_path.unlink(missing_ok=True)
    (output_dir / "manifest.json").write_text(json.dumps(manifest, indent=2))

    print(
        f"Generated {len(manifest_batches)} batch prompt(s) for phase {phase} "
        f"layers {layers_spec} in {output_dir}"
        + (f" (skipped {skipped_functions} already-specced function(s))" if resume else "")
    )
    return manifest


def main() -> int:
    """Run the source-tree command-line adapter."""
    args = parse_args()
    generate_batch_prompts(
        work_dir=Path.cwd() / "fm_agent",
        phase=args.phase,
        layers_spec=args.layers,
        batch_size=args.batch_size,
        output_dir=Path(args.output_dir) if args.output_dir else None,
        resume=args.resume,
        dry_run=args.dry_run,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

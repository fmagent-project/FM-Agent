"""Markdown artifact validation for Chisel and Verilog Profiles."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Sequence

from src.specification import ArtifactValidationInput, ArtifactValidationResult


_TAG_RE = re.compile(r"<(FG|FC|CK)\b([^>]*)>")
_TAG_NAME_RE = re.compile(r"^-[A-Z0-9]+(?:-[A-Z0-9]+)*$")
_SUBMODULE_HEADING_RE = re.compile(
    r"^\s*#\s+Submodule:\s*`?([^`\n]+?)`?\s*$",
    re.MULTILINE,
)
_LEAF_MARKER_RE = re.compile(r"^\s*\(no submodules\)\s*$", re.IGNORECASE | re.MULTILINE)


def _read_markdown(path: Path) -> tuple[str | None, str | None]:
    try:
        text = Path(path).read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        return None, f"cannot read hardware artifact {path}: {exc}"
    if not text.strip():
        return None, f"hardware artifact is empty: {path}"
    return text, None


def validate_coverage_tree(text: str, path: Path) -> list[str]:
    """Validate the machine-checkable FG/FC/CK hierarchy in a self-spec."""
    errors: list[str] = []
    groups: list[dict] = []
    group_names: set[str] = set()
    current_group: dict | None = None
    current_point: dict | None = None

    for line_number, raw_line in enumerate(text.splitlines(), start=1):
        stripped = raw_line.strip()
        for match in _TAG_RE.finditer(raw_line):
            kind, body = match.group(1), match.group(2)
            full_tag = match.group(0)
            if not _TAG_NAME_RE.fullmatch(body):
                errors.append(
                    f"{path.name}: line {line_number}: malformed {kind} tag "
                    f"{full_tag!r}; expected <{kind}-NAME> using uppercase "
                    "letters, digits, and dashes"
                )
                continue

            name = body[1:]
            if kind == "FG":
                if stripped != full_tag:
                    errors.append(
                        f"{path.name}: line {line_number}: <FG-{name}> must "
                        "be on its own line"
                    )
                if name in group_names:
                    errors.append(
                        f"{path.name}: line {line_number}: duplicate "
                        f"functional-group tag <FG-{name}>"
                    )
                group_names.add(name)
                current_group = {
                    "name": name,
                    "line": line_number,
                    "points": [],
                }
                groups.append(current_group)
                current_point = None
                continue

            if kind == "FC":
                if stripped != full_tag:
                    errors.append(
                        f"{path.name}: line {line_number}: <FC-{name}> must "
                        "be on its own line"
                    )
                if current_group is None:
                    errors.append(
                        f"{path.name}: line {line_number}: <FC-{name}> "
                        "appears before any <FG-*> group"
                    )
                    continue
                if any(point["name"] == name for point in current_group["points"]):
                    errors.append(
                        f"{path.name}: line {line_number}: duplicate "
                        f"function-point tag <FC-{name}> in "
                        f"<FG-{current_group['name']}>"
                    )
                current_point = {
                    "name": name,
                    "line": line_number,
                    "checks": set(),
                }
                current_group["points"].append(current_point)
                continue

            if current_point is None:
                errors.append(
                    f"{path.name}: line {line_number}: <CK-{name}> appears "
                    "before any <FC-*> function point"
                )
                continue
            if name in current_point["checks"]:
                errors.append(
                    f"{path.name}: line {line_number}: duplicate check-point "
                    f"tag <CK-{name}> in <FC-{current_point['name']}>"
                )
            current_point["checks"].add(name)

    if not groups:
        errors.append(f"{path.name}: no <FG-*> functional groups found")
    if "API" not in group_names:
        errors.append(f"{path.name}: missing mandatory <FG-API> group")
    for group in groups:
        if not group["points"]:
            errors.append(
                f"{path.name}: <FG-{group['name']}> at line "
                f"{group['line']} has no <FC-*> function point"
            )
        for point in group["points"]:
            if not point["checks"]:
                errors.append(
                    f"{path.name}: <FC-{point['name']}> at line "
                    f"{point['line']} has no <CK-*> check point"
                )
    return errors


def dependency_names(
    dependency: str,
    aliases: Sequence[str] = (),
) -> tuple[str, ...]:
    """Return exact and short names accepted for one dependency heading."""
    names = [dependency, dependency.rsplit("::", 1)[-1]]
    names.extend(alias for alias in aliases if isinstance(alias, str))
    names.extend(
        alias.rsplit("::", 1)[-1]
        for alias in aliases
        if isinstance(alias, str) and "::" in alias
    )
    return tuple(dict.fromkeys(name.strip() for name in names if name.strip()))


def validate_dependency_info(text: str, path: Path) -> list[str]:
    """Validate dependency sections or the exact leaf marker."""
    errors: list[str] = []
    matches = list(_SUBMODULE_HEADING_RE.finditer(text))
    claims_leaf = bool(_LEAF_MARKER_RE.search(text))
    if not matches and not claims_leaf:
        errors.append(
            f"{path.name}: expected at least one '# Submodule: <Name>' "
            "entry or the exact leaf marker '(no submodules)'"
        )
    if matches and claims_leaf:
        errors.append(
            f"{path.name}: cannot contain submodule entries and also claim "
            "'(no submodules)'"
        )

    recorded_names: set[str] = set()
    for index, match in enumerate(matches):
        name = match.group(1).strip()
        if name in recorded_names:
            errors.append(f"{path.name}: duplicate '# Submodule: {name}' entry")
        recorded_names.add(name)
        end = matches[index + 1].start() if index + 1 < len(matches) else len(text)
        if not text[match.end():end].strip():
            errors.append(
                f"{path.name}: '# Submodule: {name}' has no expected "
                "behavioral specification"
            )
    return errors


def find_dependency_section(
    text: str,
    dependency: str,
    aliases: Sequence[str] = (),
) -> str | None:
    """Return the matching ``# Submodule:`` section without fabricating one."""
    matches = list(_SUBMODULE_HEADING_RE.finditer(text))
    candidates = set(dependency_names(dependency, aliases))
    for index, match in enumerate(matches):
        recorded_name = match.group(1).strip()
        if recorded_name not in candidates:
            continue
        end = matches[index + 1].start() if index + 1 < len(matches) else len(text)
        section = text[match.start():end].strip()
        return section or None
    return None


class HardwareArtifactValidator:
    """Callable Profile validator shared by both hardware dialects."""

    def __init__(self, *, dependency_coverage_is_blocking: bool) -> None:
        self.dependency_coverage_is_blocking = dependency_coverage_is_blocking

    def __call__(
        self,
        validation_input: ArtifactValidationInput,
    ) -> ArtifactValidationResult:
        errors: list[str] = []
        warnings: list[str] = []

        spec_text, spec_read_error = _read_markdown(validation_input.self_spec)
        if spec_read_error:
            errors.append(spec_read_error)
        elif spec_text is not None:
            errors.extend(validate_coverage_tree(spec_text, validation_input.self_spec))

        info_text, info_read_error = _read_markdown(validation_input.dependency_info)
        if info_read_error:
            errors.append(info_read_error)
        elif info_text is not None:
            errors.extend(validate_dependency_info(info_text, validation_input.dependency_info))
            missing_dependencies = [
                dependency
                for dependency in validation_input.expected_dependencies
                if find_dependency_section(info_text, dependency) is None
            ]
            if missing_dependencies:
                message = (
                    f"{validation_input.dependency_info.name}: missing '# Submodule:' "
                    "entries for expected direct dependencies: "
                    + ", ".join(sorted(dict.fromkeys(missing_dependencies)))
                )
                if self.dependency_coverage_is_blocking:
                    errors.append(message)
                else:
                    warnings.append(message)

        return ArtifactValidationResult(
            ready=not errors,
            errors=tuple(errors),
            warnings=tuple(warnings),
        )


CHISEL_VALIDATOR = HardwareArtifactValidator(
    dependency_coverage_is_blocking=False,
)
VERILOG_VALIDATOR = HardwareArtifactValidator(
    dependency_coverage_is_blocking=True,
)


def validate_chisel_artifacts(
    validation_input: ArtifactValidationInput,
) -> ArtifactValidationResult:
    return CHISEL_VALIDATOR(validation_input)


def validate_verilog_artifacts(
    validation_input: ArtifactValidationInput,
) -> ArtifactValidationResult:
    return VERILOG_VALIDATOR(validation_input)

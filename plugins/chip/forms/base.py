"""Shared Markdown artifact contract for hardware specification forms."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Sequence

from src.spec_forms import SpecArtifactPaths, SpecForm, SpecValidationResult


_TAG_RE = re.compile(r"<(FG|FC|CK)\b([^>]*)>")
_TAG_NAME_RE = re.compile(r"^-[A-Z0-9]+(?:-[A-Z0-9]+)*$")
_SUBMODULE_HEADING_RE = re.compile(
    r"^#\s+Submodule:\s*`?([^`\n]+?)`?\s*$",
    re.MULTILINE,
)


class HardwareSpecForm(SpecForm):
    """Common standalone Markdown contract for one extracted hardware module."""

    schema_version = "V1"
    dialect: str
    dependency_coverage_is_blocking = False

    @property
    def unit_noun(self) -> str:
        return "module"

    def batch_rules(self, language: str) -> Sequence[str]:
        del language
        return (
            "Describe observable module behavior, interfaces, timing, reset, and protocol guarantees",
            "Describe WHAT the hardware guarantees, NOT a line-by-line implementation transcript",
            "Do NOT invent ports, parameters, submodules, widths, or cycle relationships",
            "Every functional group and function point must contain machine-checkable coverage tags",
        )

    def artifact_paths(self, unit_file: Path) -> SpecArtifactPaths:
        unit_file = Path(unit_file)
        return SpecArtifactPaths(
            self_spec=unit_file.with_name(f"{unit_file.stem}_spec.md"),
            dependency_info=unit_file.with_name(f"{unit_file.stem}_info.md"),
        )

    def is_artifact_path(self, path: Path) -> bool:
        return Path(path).name.endswith(("_spec.md", "_info.md"))

    @staticmethod
    def _read_markdown(path: Path) -> tuple[str | None, str | None]:
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as exc:
            return None, f"cannot read hardware artifact {path}: {exc}"
        if not text.strip():
            return None, f"hardware artifact is empty: {path}"
        return text, None

    @staticmethod
    def _validate_coverage_tree(text: str, path: Path) -> list[str]:
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
                    if any(
                        point["name"] == name
                        for point in current_group["points"]
                    ):
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

    @staticmethod
    def _dependency_names(
        dependency: str,
        aliases: Sequence[str] = (),
    ) -> tuple[str, ...]:
        names = [dependency, dependency.rsplit("::", 1)[-1], *aliases]
        names.extend(
            alias.rsplit("::", 1)[-1]
            for alias in aliases
            if "::" in alias
        )
        return tuple(dict.fromkeys(name.strip() for name in names if name.strip()))

    @staticmethod
    def _validate_dependency_info(text: str, path: Path) -> list[str]:
        """Validate the common shape of a hardware dependency-info artifact."""
        errors: list[str] = []
        matches = list(_SUBMODULE_HEADING_RE.finditer(text))
        claims_leaf = "(no submodules)" in text.lower()
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
                errors.append(
                    f"{path.name}: duplicate '# Submodule: {name}' entry"
                )
            recorded_names.add(name)
            end = matches[index + 1].start() if index + 1 < len(matches) else len(text)
            if not text[match.end():end].strip():
                errors.append(
                    f"{path.name}: '# Submodule: {name}' has no expected "
                    "behavioral specification"
                )
        return errors

    @classmethod
    def _find_dependency_section(
        cls,
        text: str,
        dependency: str,
        aliases: Sequence[str] = (),
    ) -> str | None:
        matches = list(_SUBMODULE_HEADING_RE.finditer(text))
        candidates = set(cls._dependency_names(dependency, aliases))
        for index, match in enumerate(matches):
            recorded_name = match.group(1).strip()
            if recorded_name not in candidates:
                continue
            end = matches[index + 1].start() if index + 1 < len(matches) else len(text)
            return text[match.start():end].strip()
        return None

    def validate(
        self,
        unit_file: Path,
        expected_dependencies: Sequence[str] = (),
    ) -> SpecValidationResult:
        paths = self.artifact_paths(unit_file)
        errors: list[str] = []
        warnings: list[str] = []

        spec_text, spec_read_error = self._read_markdown(paths.self_spec)
        if spec_read_error:
            errors.append(spec_read_error)
        elif spec_text is not None:
            errors.extend(self._validate_coverage_tree(spec_text, paths.self_spec))

        info_text, info_read_error = self._read_markdown(paths.dependency_info)
        if info_read_error:
            errors.append(info_read_error)
        elif info_text is not None:
            errors.extend(
                self._validate_dependency_info(info_text, paths.dependency_info)
            )
            missing_dependencies = [
                dependency
                for dependency in expected_dependencies
                if self._find_dependency_section(info_text, dependency) is None
            ]
            if missing_dependencies:
                message = (
                    f"{paths.dependency_info.name}: missing '# Submodule:' "
                    "entries for expected direct dependencies: "
                    + ", ".join(sorted(dict.fromkeys(missing_dependencies)))
                )
                if self.dependency_coverage_is_blocking:
                    errors.append(message)
                else:
                    warnings.append(message)

        return SpecValidationResult(
            ready=not errors,
            errors=tuple(errors),
            warnings=tuple(warnings),
        )

    def read_self_spec(self, unit_file: Path) -> str | None:
        text, _error = self._read_markdown(
            self.artifact_paths(unit_file).self_spec
        )
        return text

    def read_dependency_expectation(
        self,
        caller_file: Path,
        callee_fqn: str,
        aliases: Sequence[str] = (),
    ) -> str | None:
        text, _error = self._read_markdown(
            self.artifact_paths(caller_file).dependency_info
        )
        if text is None:
            return None
        return self._find_dependency_section(text, callee_fqn, aliases)

    def batch_intro(self, language: str) -> str:
        return (
            f"Hardware dialect: {language}. Write standalone sibling "
            "_spec.md and _info.md files for every extracted module."
        )

    def output_contract_prompt(self) -> str:
        source_term = "Scala/Chisel" if self.dialect == "chisel" else "Verilog/SystemVerilog"
        return "\n".join((
            "## OUTPUT FORMAT (two standalone Markdown files per module)",
            "",
            "For each extracted module `<ModuleName>.<ext>`, write BOTH sibling files:",
            "- `<ModuleName>_spec.md`: the module's observable behavioral contract",
            "- `<ModuleName>_info.md`: caller-driven expectations for direct submodules",
            "",
            "Do not modify the extracted source file. Follow the complete structure in "
            "fm_agent/spec_prompts/system_prompt.md.",
            "Every `_spec.md` must contain an <FG-API> group. Every <FG-*> must contain "
            "an <FC-*>, and every <FC-*> must contain an <CK-*>.",
            "Use '# Submodule: <ExactDeclaredName>' for every direct dependency in "
            "`_info.md`; write '(no submodules)' only for a leaf module.",
            f"Describe exact ports, widths/types, parameters, clock/reset behavior, and "
            f"protocol semantics visible in the {source_term} input.",
        ))

    def system_prompt_path(self, script_dir: Path) -> Path:
        return (
            Path(script_dir)
            / "plugins"
            / "chip"
            / "prompts"
            / self.dialect
            / "system_prompt.md"
        )

    def workflow_prompt_path(self, script_dir: Path) -> Path:
        return (
            Path(script_dir)
            / "plugins"
            / "chip"
            / "prompts"
            / "workflow_spec_step4_batch.md"
        )

    def generation_instruction(self, batch_prompt_rel: str, attempt: int) -> str:
        action = "Process" if attempt == 1 else "Continue processing"
        retry = "" if attempt == 1 else (
            " Re-check every module and repair any missing or invalid artifact; "
            "skip only modules whose two artifacts already satisfy the contract."
        )
        return (
            f"{action} the hardware specification batch at {batch_prompt_rel}. "
            "Read it and fm_agent/spec_prompts/system_prompt.md, then write the "
            "required sibling _spec.md and _info.md files without modifying source "
            f"files.{retry}"
        )

    def trace_outputs(self, unit_files: Sequence[Path]) -> list[str]:
        paths = [self.artifact_paths(unit_file) for unit_file in unit_files]
        return [str(path.self_spec) for path in paths] + [
            str(path.dependency_info) for path in paths
        ]

"""Specification profile data models and built-in specification behavior."""

from __future__ import annotations

import json
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Callable, Optional, Protocol, Sequence, runtime_checkable

try:
    from src.file_utils import _is_valid_info_json, _is_valid_spec_json
except ImportError:  # pragma: no cover - direct execution from ``src``
    from file_utils import _is_valid_info_json, _is_valid_spec_json


@dataclass(frozen=True)
class ArtifactPaths:
    """The two artifacts associated with one extracted unit."""

    self_spec: Path
    dependency_info: Path


@dataclass(frozen=True)
class ArtifactPair:
    """Describe the fixed self-spec/dependency-info artifact pair.

    ``append_to_filename`` preserves the current convention:
    ``foo.py`` becomes ``foo.py.spec.json``.  Set it to ``False`` when artifact
    names should be derived from ``Path.stem`` (for example, ``Module_spec.md``)
    without changing the public pair abstraction.
    """

    self_suffix: str
    dependency_suffix: str
    append_to_filename: bool = True

    def __post_init__(self) -> None:
        if not self.self_suffix or not self.dependency_suffix:
            raise ValueError("artifact suffixes must be non-empty")
        if self.self_suffix == self.dependency_suffix:
            raise ValueError("artifact suffixes must be different")

    def _base_name(self, unit_file: Path) -> str:
        unit_file = Path(unit_file)
        return unit_file.name if self.append_to_filename else unit_file.stem

    def paths_for(self, unit_file: Path) -> ArtifactPaths:
        unit_file = Path(unit_file)
        base_name = self._base_name(unit_file)
        return ArtifactPaths(
            self_spec=unit_file.with_name(base_name + self.self_suffix),
            dependency_info=unit_file.with_name(
                base_name + self.dependency_suffix
            ),
        )

    def is_artifact_path(self, path: Path) -> bool:
        name = Path(path).name
        return name.endswith((self.self_suffix, self.dependency_suffix))


@dataclass(frozen=True)
class PromptBundle:
    """The four prompt resources consumed by the common Pipeline."""

    phase_plan: str | Path
    domain_context: str | Path
    system: str | Path
    batch_workflow: str | Path

    def resolve(self, root: Path | None = None) -> "PromptBundle":
        """Resolve relative resources against *root* without mutating the bundle."""
        def resolve_one(value: str | Path) -> Path:
            path = Path(value)
            if root is not None and not path.is_absolute():
                path = root / path
            return path

        return PromptBundle(
            phase_plan=resolve_one(self.phase_plan),
            domain_context=resolve_one(self.domain_context),
            system=resolve_one(self.system),
            batch_workflow=resolve_one(self.batch_workflow),
        )


@dataclass(frozen=True)
class BatchPromptContext:
    """Runtime values needed to render a profile's artifact instructions."""

    self_artifact_name: str
    dependency_artifact_name: str


@dataclass(frozen=True)
class GenerationPromptContext:
    """Runtime values needed to render one generation attempt instruction."""

    batch_prompt_rel: str
    attempt: int
    self_artifact_suffix: str
    dependency_artifact_suffix: str
    system_prompt_rel: str


@runtime_checkable
class PromptContract(Protocol):
    """Profile-owned prompt fragments used by the common generation pipeline.

    The common Pipeline still owns prompt assembly, artifact validation, retry
    orchestration, and LLM execution.  A contract only supplies the
    profile-specific wording for artifact output and generation attempts.
    """

    def batch_output_section(
        self,
        context: BatchPromptContext,
    ) -> Sequence[str]:
        """Return the output-format and write-process section of a batch prompt."""

    def generation_instruction(
        self,
        context: GenerationPromptContext,
    ) -> str:
        """Return the instruction for one generation attempt."""


class _JsonPromptContract:
    """The standard JSON spec/info prompt contract used by most profiles."""

    def batch_output_section(
        self,
        context: BatchPromptContext,
    ) -> Sequence[str]:
        del context
        return (
            "## SPEC FORMAT (write JSON files; do NOT modify source files)",
            "",
            "For each function file `<function-file>`, write TWO JSON files in the SAME "
            "directory. `<function-file>` includes its original extension "
            "(for example, `foo.py` must produce `foo.py.spec.json` "
            "and `foo.py.info.json`):",
            "",
            "`<function-file>.spec.json`:",
            "```json",
            '{"signature": "<FunctionName>(<params>) -> <ReturnType>", '
            '"pre_condition": "...", "post_condition": "..."}',
            "```",
            "",
            "`<function-file>.info.json`:",
            "```json",
            '{"callees": [{"name": "<callee_name>", "signature": "...", '
            '"pre_condition": "...", "post_condition": "..."}]}',
            "```",
            "",
            'If the function has no callees: write `{"callees": []}` '
            "to the .info.json file.",
            "",
            "## PROCESS",
            "For each function:",
            "1. Read the extracted file",
            "2. Read caller expectations above - what do callers NEED from this function?",
            "3. Write a behavioral spec describing WHAT it guarantees (not HOW)",
            "4. Write the COMPLETE .spec.json and .info.json objects next to the "
            "UNCHANGED source file",
            "5. Use the Write tool to save both JSON files",
        )

    def generation_instruction(
        self,
        context: GenerationPromptContext,
    ) -> str:
        if context.attempt == 1:
            return (
                f"Process the batch prompt file at {context.batch_prompt_rel}. "
                f"Read it and {context.system_prompt_rel}, "
                "generate behavioral specs for each function listed, "
                f"and write the {context.self_artifact_suffix} and "
                f"{context.dependency_artifact_suffix} files for each function."
            )
        return (
            f"Continue processing the batch prompt file at {context.batch_prompt_rel}. "
            "Some functions may already have valid specs from a previous attempt. "
            "Check each function listed in the batch prompt. Skip it only when both "
            f"its {context.self_artifact_suffix} and "
            f"{context.dependency_artifact_suffix} files contain valid JSON matching "
            f"the schemas in {context.system_prompt_rel}. If either sidecar is "
            "missing, malformed, or schema-invalid, rewrite the complete "
            f"{context.self_artifact_suffix} and "
            f"{context.dependency_artifact_suffix} files for that function."
        )


JSON_PROMPT_CONTRACT: PromptContract = _JsonPromptContract()


@dataclass(frozen=True)
class ArtifactValidationInput:
    unit_file: Path
    self_spec: Path
    dependency_info: Path
    expected_dependencies: tuple[str, ...] = ()


@dataclass(frozen=True)
class ArtifactValidationResult:
    ready: bool
    errors: tuple[str, ...] = ()
    warnings: tuple[str, ...] = ()


ArtifactValidator = Callable[
    [ArtifactValidationInput], ArtifactValidationResult
]
SelfSpecReader = Callable[[Path], Optional[str]]
DependencyReader = Callable[
    [Path, str, Sequence[str]], Optional[str]
]


def _read_json(path: Path) -> object | None:
    try:
        with path.open("r", encoding="utf-8") as file:
            return json.load(file)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return None


def _default_exists_and_nonempty(
    validation_input: ArtifactValidationInput,
) -> ArtifactValidationResult:
    errors: list[str] = []
    for path, label in (
        (validation_input.self_spec, "self-spec"),
        (validation_input.dependency_info, "dependency-info"),
    ):
        if not path.is_file():
            errors.append(f"{label} is missing: {path}")
            continue
        try:
            if not path.read_text(encoding="utf-8").strip():
                errors.append(f"{label} is empty: {path}")
        except (OSError, UnicodeDecodeError) as exc:
            errors.append(f"{label} cannot be read: {path}: {exc}")
    return ArtifactValidationResult(ready=not errors, errors=tuple(errors))


def _software_validator(
    validation_input: ArtifactValidationInput,
) -> ArtifactValidationResult:
    """Preserve main's strict JSON readiness behavior during the no-op move."""
    base = _default_exists_and_nonempty(validation_input)
    if not base.ready:
        return base

    spec = _read_json(validation_input.self_spec)
    info = _read_json(validation_input.dependency_info)
    if not _is_valid_spec_json(spec):
        return ArtifactValidationResult(
            ready=False,
            errors=(f"invalid software self-spec JSON: {validation_input.self_spec}",),
        )
    if not _is_valid_info_json(info):
        return ArtifactValidationResult(
            ready=False,
            errors=(
                "invalid software dependency-info JSON: "
                f"{validation_input.dependency_info}",
            ),
        )
    return base


def _software_self_spec_reader(unit_file: Path) -> Optional[str]:
    paths = SOFTWARE_PROFILE.artifact_paths(unit_file)
    spec = _read_json(paths.self_spec)
    if not isinstance(spec, dict):
        return None
    return (
        f"{spec.get('signature', '')}\n\n"
        f"Pre-condition:\n{spec.get('pre_condition', '')}\n\n"
        f"Post-condition:\n{spec.get('post_condition', '')}"
    )


def _callee_match_names(
    callee_fqn: str,
    aliases: Sequence[str],
) -> list[str]:
    aliases = aliases or ()
    names = [callee_fqn, callee_fqn.split("::")[-1]]
    for alias in aliases:
        if not alias:
            continue
        names.append(alias)
        if "::" in alias:
            names.append(alias.rsplit("::", 1)[-1])
    return list(dict.fromkeys(names))


def _info_line_mentions_name(first_line: str, name: str) -> bool:
    if not name:
        return False
    if "::" in name:
        return name in first_line
    # Keep the existing software matching behavior: a bare name may be
    # followed by a call parenthesis or a word boundary.
    import re

    return bool(
        re.search(rf"(?<![A-Za-z0-9_]){re.escape(name)}(?:\s*\(|\b)", first_line)
    )


def _software_dependency_reader(
    caller_file: Path,
    callee_fqn: str,
    aliases: Sequence[str],
) -> Optional[str]:
    paths = SOFTWARE_PROFILE.artifact_paths(caller_file)
    info = _read_json(paths.dependency_info)
    if not isinstance(info, dict):
        return None
    candidates = set(_callee_match_names(callee_fqn, aliases or ()))
    for callee in info.get("callees", []):
        if not isinstance(callee, dict):
            continue
        name = callee.get("name", "")
        if not isinstance(name, str):
            continue
        if not any(_info_line_mentions_name(name, candidate) for candidate in candidates):
            continue
        return (
            f"{callee.get('signature', '')}\n"
            f"  Pre-condition: {callee.get('pre_condition', '')}\n"
            f"  Post-condition: {callee.get('post_condition', '')}"
        )
    return None


@dataclass(frozen=True)
class SpecificationProfile:
    """A specification artifact strategy consumed by the common Pipeline."""

    id: str
    schema_version: str
    artifacts: ArtifactPair
    prompts: PromptBundle
    languages: tuple[str, ...] | None = None
    validator: ArtifactValidator | None = None
    self_spec_reader: SelfSpecReader | None = None
    dependency_reader: DependencyReader | None = None
    enable_reasoning: bool = False
    prompt_contract: PromptContract = JSON_PROMPT_CONTRACT

    def artifact_paths(self, unit_file: Path) -> ArtifactPaths:
        return self.artifacts.paths_for(unit_file)

    def example_artifact_names(
        self,
        function_filename: str = "foo.py",
    ) -> tuple[str, str]:
        """Return representative artifact names for prompt instructions."""
        paths = self.artifact_paths(Path(function_filename))
        return paths.self_spec.name, paths.dependency_info.name

    def allows_language(self, language: str | None) -> bool:
        """Return whether a language key is included by this profile."""
        if self.languages is None:
            return True
        return bool(language) and language.lower() in self.languages

    def with_prompt_root(self, root: Path | None) -> "SpecificationProfile":
        """Return an equivalent profile with all prompt paths resolved."""
        if not isinstance(self.prompts, PromptBundle):
            return self
        return replace(self, prompts=self.prompts.resolve(root))

    def validate_configuration(self, *, allow_reasoning: bool = False) -> None:
        """Validate the static parts of a profile before any LLM call."""
        errors: list[str] = []
        if not isinstance(self.id, str) or not self.id.strip():
            errors.append("id must be a non-empty string")
        if not isinstance(self.schema_version, str) or not self.schema_version.strip():
            errors.append("schema_version must be a non-empty string")
        if not isinstance(self.artifacts, ArtifactPair):
            errors.append("artifacts must be an ArtifactPair")
        if not isinstance(self.prompts, PromptBundle):
            errors.append("prompts must be a PromptBundle")
        else:
            for field_name in (
                "phase_plan",
                "domain_context",
                "system",
                "batch_workflow",
            ):
                value = getattr(self.prompts, field_name)
                if not isinstance(value, (str, Path)):
                    errors.append(f"prompts.{field_name} must be a path")
                    continue
                path = Path(value)
                if not path.is_file():
                    errors.append(
                        f"prompt resource does not exist: {field_name}={path}"
                    )
                    continue
                try:
                    with path.open("r", encoding="utf-8"):
                        pass
                except (OSError, UnicodeDecodeError) as exc:
                    errors.append(
                        f"prompt resource is not readable: {field_name}={path}: {exc}"
                    )
        if self.languages is not None:
            if not isinstance(self.languages, tuple) or not self.languages:
                errors.append("languages must be None or a non-empty tuple")
            else:
                invalid_languages = [
                    language
                    for language in self.languages
                    if not isinstance(language, str) or not language.strip()
                ]
                if invalid_languages:
                    errors.append("languages must contain non-empty strings")
                else:
                    try:
                        from src.languages.registry import REGISTRY
                    except ImportError:  # pragma: no cover - direct src execution
                        from languages.registry import REGISTRY
                    unknown_languages = sorted(
                        set(self.languages) - set(REGISTRY)
                    )
                    if unknown_languages:
                        errors.append(
                            "languages contains unregistered key(s): "
                            + ", ".join(unknown_languages)
                        )
        for field_name, callback in (
            ("validator", self.validator),
            ("self_spec_reader", self.self_spec_reader),
            ("dependency_reader", self.dependency_reader),
        ):
            if callback is not None and not callable(callback):
                errors.append(f"{field_name} must be callable when provided")
        if not isinstance(self.prompt_contract, PromptContract):
            errors.append(
                "prompt_contract must provide batch_output_section() and "
                "generation_instruction()"
            )
        if not isinstance(self.enable_reasoning, bool):
            errors.append("enable_reasoning must be bool")
        elif self.enable_reasoning and not allow_reasoning:
            errors.append(
                "custom profiles cannot enable software reasoning in this phase"
            )
        if errors:
            raise ValueError(
                f"Invalid specification profile {self.id!r}: "
                + "; ".join(errors)
            )

    def is_artifact_path(self, path: Path) -> bool:
        return self.artifacts.is_artifact_path(path)

    def validate(
        self,
        unit_file: Path,
        expected_dependencies: Sequence[str] = (),
    ) -> ArtifactValidationResult:
        paths = self.artifact_paths(unit_file)
        validation_input = ArtifactValidationInput(
            unit_file=Path(unit_file),
            self_spec=paths.self_spec,
            dependency_info=paths.dependency_info,
            expected_dependencies=tuple(expected_dependencies),
        )
        base = _default_exists_and_nonempty(validation_input)
        if not base.ready:
            return base
        if self.validator is None:
            return base
        try:
            custom = self.validator(validation_input)
        except Exception as exc:
            return ArtifactValidationResult(
                ready=False,
                errors=(
                    f"Profile {self.id!r} validator failed for {unit_file}: {exc}",
                ),
            )
        if not isinstance(custom, ArtifactValidationResult):
            return ArtifactValidationResult(
                ready=False,
                errors=(
                    f"Profile {self.id!r} validator returned "
                    f"{type(custom).__name__}, expected ArtifactValidationResult",
                ),
            )
        return ArtifactValidationResult(
            ready=base.ready and custom.ready,
            errors=base.errors + custom.errors,
            warnings=base.warnings + custom.warnings,
        )

    def is_file_ready(self, unit_file: Path) -> bool:
        return self.validate(Path(unit_file)).ready

    def read_self_spec(self, unit_file: Path) -> Optional[str]:
        if self.self_spec_reader is not None:
            return self.self_spec_reader(Path(unit_file))
        try:
            text = self.artifact_paths(unit_file).self_spec.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            return None
        return text if text.strip() else None

    def read_dependency_expectation(
        self,
        caller_file: Path,
        callee_fqn: str,
        aliases: Sequence[str] = (),
    ) -> Optional[str]:
        if self.dependency_reader is not None:
            return self.dependency_reader(
                Path(caller_file), callee_fqn, tuple(aliases)
            )
        try:
            text = self.artifact_paths(caller_file).dependency_info.read_text(
                encoding="utf-8"
            )
        except (OSError, UnicodeDecodeError):
            return None
        return text if text.strip() else None


SOFTWARE_PROFILE = SpecificationProfile(
    id="software",
    schema_version="V1",
    artifacts=ArtifactPair(".spec.json", ".info.json"),
    prompts=PromptBundle(
        phase_plan="md/workflow_generate_phases.md",
        domain_context="md/workflow_generate_domain_context.md",
        system="md/system_prompt.md",
        batch_workflow="md/workflow_spec_step4_batch.md",
    ),
    validator=_software_validator,
    self_spec_reader=_software_self_spec_reader,
    dependency_reader=_software_dependency_reader,
    enable_reasoning=True,
)

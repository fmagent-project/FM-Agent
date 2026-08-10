"""Pre-condition/post-condition JSON specification artifacts."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Sequence

from .base import SpecArtifactPaths, SpecForm, SpecValidationResult


_SPEC_FIELDS = frozenset({
    "signature",
    "pre_condition",
    "post_condition",
})

_CALLEE_FIELDS = frozenset({
    "name",
    "signature",
    "pre_condition",
    "post_condition",
})


class SoftwareSpecForm(SpecForm):
    """The existing software ``.spec.json`` / ``.info.json`` contract."""

    id = "software"
    schema_version = "V1"

    def artifact_paths(self, unit_file: Path) -> SpecArtifactPaths:
        unit_file = Path(unit_file)
        return SpecArtifactPaths(
            self_spec=Path(f"{unit_file}.spec.json"),
            dependency_info=Path(f"{unit_file}.info.json"),
        )

    @staticmethod
    def is_valid_spec_data(data: object) -> bool:
        """Return whether data matches the exact software self-spec schema."""
        if not isinstance(data, dict) or set(data) != _SPEC_FIELDS:
            return False
        return all(isinstance(data[field], str) for field in _SPEC_FIELDS)

    @staticmethod
    def is_valid_info_data(data: object) -> bool:
        """Return whether data matches the exact dependency-info schema."""
        if not isinstance(data, dict) or set(data) != {"callees"}:
            return False

        callees = data["callees"]
        if not isinstance(callees, list):
            return False

        for callee in callees:
            if not isinstance(callee, dict) or set(callee) != _CALLEE_FIELDS:
                return False
            if not all(
                isinstance(callee[field], str)
                for field in _CALLEE_FIELDS
            ):
                return False

        return True

    @staticmethod
    def _read_json(path: Path) -> object | None:
        try:
            with path.open("r", encoding="utf-8") as file:
                return json.load(file)
        except (OSError, UnicodeDecodeError, json.JSONDecodeError):
            return None

    def validate(
        self,
        unit_file: Path,
        expected_dependencies: Sequence[str] = (),
    ) -> SpecValidationResult:
        # Software readiness intentionally does not enforce static dependency
        # coverage. Keep the argument for the common SpecForm contract.
        del expected_dependencies
        paths = self.artifact_paths(unit_file)
        errors = []

        spec = self._read_json(paths.self_spec)
        if not self.is_valid_spec_data(spec):
            errors.append(
                f"missing or invalid software spec: {paths.self_spec}"
            )

        info = self._read_json(paths.dependency_info)
        if not self.is_valid_info_data(info):
            errors.append(
                "missing or invalid software dependency info: "
                f"{paths.dependency_info}"
            )

        return SpecValidationResult(ready=not errors, errors=tuple(errors))

    def read_self_spec(self, unit_file: Path) -> str | None:
        """Reproduce the current permissive caller self-spec rendering."""
        spec = self._read_json(self.artifact_paths(unit_file).self_spec)
        if not isinstance(spec, dict):
            return None
        return (
            f"{spec.get('signature', '')}\n\n"
            f"Pre-condition:\n{spec.get('pre_condition', '')}\n\n"
            f"Post-condition:\n{spec.get('post_condition', '')}"
        )

    def read_info_data(self, unit_file: Path) -> dict | None:
        """Return the current permissive caller dependency-info object."""
        info = self._read_json(self.artifact_paths(unit_file).dependency_info)
        return info if isinstance(info, dict) else None

    @staticmethod
    def dependency_match_names(
        callee_fqn: str,
        aliases: Sequence[str] = (),
    ) -> list[str]:
        """Return the existing FQN, short-name, and edge-alias candidates."""
        names = [callee_fqn, callee_fqn.split("::")[-1]]
        for alias in aliases:
            if not alias:
                continue
            names.append(alias)
            if "::" in alias:
                names.append(alias.rsplit("::", 1)[-1])
        return list(dict.fromkeys(names))

    @staticmethod
    def dependency_name_matches(recorded_name: str, candidate: str) -> bool:
        """Reproduce the current dependency-name boundary matching."""
        if not candidate:
            return False
        if "::" in candidate:
            return candidate in recorded_name
        return bool(
            re.search(
                rf"(?<![A-Za-z0-9_]){re.escape(candidate)}(?:\s*\(|\b)",
                recorded_name,
            )
        )

    def find_dependency_entry(
        self,
        info: dict,
        callee_fqn: str,
        aliases: Sequence[str] = (),
    ) -> dict | None:
        """Find the first callee entry matching any known dependency name."""
        names = self.dependency_match_names(callee_fqn, aliases)
        callees = info.get("callees", [])
        if not isinstance(callees, list):
            return None
        for callee in callees:
            if not isinstance(callee, dict):
                continue
            recorded_name = callee.get("name", "")
            if not isinstance(recorded_name, str):
                continue
            if any(
                self.dependency_name_matches(recorded_name, candidate)
                for candidate in names
            ):
                return callee
        return None

    def read_dependency_expectation(
        self,
        caller_file: Path,
        callee_fqn: str,
        aliases: Sequence[str] = (),
    ) -> str | None:
        info = self.read_info_data(caller_file)
        if info is None:
            return None
        entry = self.find_dependency_entry(info, callee_fqn, aliases)
        if entry is None:
            return None
        return (
            f"{entry.get('signature', '')}\n"
            f"  Pre-condition: {entry.get('pre_condition', '')}\n"
            f"  Post-condition: {entry.get('post_condition', '')}"
        )

    def batch_intro(self, language: str) -> str:
        return (
            f"Language: {language}. "
            "Write specifications to adjacent .spec.json and .info.json files."
        )

    def output_contract_prompt(self) -> str:
        return "\n".join([
            "## SPEC FORMAT (write JSON files; do NOT modify source files)",
            "",
            "For each function file `<function-file>`, write TWO JSON files in the SAME "
            "directory. `<function-file>` includes its original extension (for example, "
            "`foo.py` must produce `foo.py.spec.json` and `foo.py.info.json`):",
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
            'If the function has no callees: write `{"callees": []}` to the .info.json file.',
            "",
            "## PROCESS",
            "For each function:",
            "1. Read the extracted file",
            "2. Read caller expectations above - what do callers NEED from this function?",
            "3. Write a behavioral spec describing WHAT it guarantees (not HOW)",
            "4. Write the COMPLETE .spec.json and .info.json objects next to the UNCHANGED "
            "source file",
            "5. Use the Write tool to save both JSON files",
        ])


SOFTWARE_SPEC_FORM = SoftwareSpecForm()

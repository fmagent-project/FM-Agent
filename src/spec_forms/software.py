"""Pre-condition/post-condition JSON specification artifacts."""

from __future__ import annotations

import json
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


SOFTWARE_SPEC_FORM = SoftwareSpecForm()

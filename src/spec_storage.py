import json
import os
from pathlib import Path
from typing import Any


SCHEMA_VERSION = 1
SPEC_SUFFIX = ".spec.json"
INFO_SUFFIX = ".info.json"


class MetadataValidationError(ValueError):
    """Raised when function metadata is missing, unreadable, or malformed."""


def metadata_paths(function_path: str | Path) -> tuple[Path, Path]:
    """Return adjacent spec and info JSON paths for an implementation file."""
    path = Path(function_path)
    stem = path.with_suffix("")
    return (
        stem.with_name(stem.name + SPEC_SUFFIX),
        stem.with_name(stem.name + INFO_SUFFIX),
    )


def is_metadata_file(path: str | Path) -> bool:
    """Return whether path names a structured function metadata file."""
    name = Path(path).name
    return name.endswith(SPEC_SUFFIX) or name.endswith(INFO_SUFFIX)


def function_fqn_from_path(function_path: str | Path) -> str:
    """Derive the function FQN from its path below extracted_functions/."""
    path = Path(function_path)
    parts = path.parts
    try:
        index = parts.index("extracted_functions")
    except ValueError as exc:
        raise MetadataValidationError(
            f"function path is not under extracted_functions: {path}"
        ) from exc
    relative = Path(*parts[index + 1:]).with_suffix("")
    return "::".join(relative.parts)


def _require_string_list(
    data: dict[str, Any], field: str, context: str
) -> None:
    value = data.get(field)
    if not isinstance(value, list) or any(
        not isinstance(item, str) for item in value
    ):
        raise MetadataValidationError(
            f"{context}.{field} must be an array of strings"
        )


def _validate_header(
    data: Any, expected_fqn: str, context: str
) -> dict[str, Any]:
    if not isinstance(data, dict):
        raise MetadataValidationError(f"{context} must be a JSON object")
    if data.get("schema_version") != SCHEMA_VERSION:
        raise MetadataValidationError(
            f"{context}.schema_version must equal {SCHEMA_VERSION}"
        )
    if data.get("function") != expected_fqn:
        raise MetadataValidationError(
            f"{context}.function expected {expected_fqn!r}, "
            f"got {data.get('function')!r}"
        )
    return data


def validate_spec_data(data: Any, expected_fqn: str) -> dict[str, Any]:
    """Validate and return a schema-version-1 spec object."""
    result = _validate_header(data, expected_fqn, "spec")
    for field in ("unit", "signature"):
        if not isinstance(result.get(field), str) or not result[field].strip():
            raise MetadataValidationError(
                f"spec.{field} must be a non-empty string"
            )
    _require_string_list(result, "preconditions", "spec")
    _require_string_list(result, "postconditions", "spec")
    return result


def validate_info_data(data: Any, expected_fqn: str) -> dict[str, Any]:
    """Validate and return a schema-version-1 info object."""
    result = _validate_header(data, expected_fqn, "info")
    callees = result.get("callees")
    if not isinstance(callees, list):
        raise MetadataValidationError("info.callees must be an array")
    for index, callee in enumerate(callees):
        if not isinstance(callee, dict):
            raise MetadataValidationError(
                f"info.callees[{index}] must be an object"
            )
        for field in ("function", "signature"):
            if not isinstance(callee.get(field), str) or not callee[field].strip():
                raise MetadataValidationError(
                    f"info.callees[{index}].{field} must be a non-empty string"
                )
        _require_string_list(
            callee, "preconditions", f"info.callees[{index}]"
        )
        _require_string_list(
            callee, "postconditions", f"info.callees[{index}]"
        )
    return result


def _read_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise MetadataValidationError(
            f"cannot read valid JSON from {path}: {exc}"
        ) from exc


def _write_json_atomic(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    try:
        temporary.write_text(
            json.dumps(data, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def read_spec(function_path: str | Path) -> dict[str, Any]:
    spec_path, _ = metadata_paths(function_path)
    expected_fqn = function_fqn_from_path(function_path)
    return validate_spec_data(_read_json(spec_path), expected_fqn)


def read_info(function_path: str | Path) -> dict[str, Any]:
    _, info_path = metadata_paths(function_path)
    expected_fqn = function_fqn_from_path(function_path)
    return validate_info_data(_read_json(info_path), expected_fqn)


def write_spec(
    function_path: str | Path, data: dict[str, Any]
) -> dict[str, Any]:
    spec_path, _ = metadata_paths(function_path)
    expected_fqn = function_fqn_from_path(function_path)
    validated = validate_spec_data(data, expected_fqn)
    _write_json_atomic(spec_path, validated)
    return validated


def write_info(
    function_path: str | Path, data: dict[str, Any]
) -> dict[str, Any]:
    _, info_path = metadata_paths(function_path)
    expected_fqn = function_fqn_from_path(function_path)
    validated = validate_info_data(data, expected_fqn)
    _write_json_atomic(info_path, validated)
    return validated


def metadata_status(
    function_path: str | Path,
) -> tuple[bool, str | None]:
    path = Path(function_path)
    if not path.is_file():
        return False, f"function implementation does not exist: {path}"
    try:
        read_spec(path)
        read_info(path)
    except MetadataValidationError as exc:
        return False, str(exc)
    return True, None


def is_function_ready(function_path: str | Path) -> bool:
    ready, _ = metadata_status(function_path)
    return ready


def format_spec_for_reasoner(spec: dict[str, Any]) -> str:
    """Adapt structured spec data to the Phase 1 reasoner text contract."""
    pre = "\n".join(
        f"- {item}" for item in spec["preconditions"]
    ) or "- (none)"
    post = "\n".join(
        f"- {item}" for item in spec["postconditions"]
    ) or "- (none)"
    return f"Pre-condition:\n{pre}\nPost-condition:\n{post}"


def info_to_function_spec_map(info: dict[str, Any]):
    """Adapt structured callee data to the Phase 1 reasoner knowledge map."""
    from src.parser import FunctionSpecMap

    result = FunctionSpecMap()
    for callee in info["callees"]:
        pre = "\n".join(
            f"- {item}" for item in callee["preconditions"]
        ) or "- (none)"
        post = "\n".join(
            f"- {item}" for item in callee["postconditions"]
        ) or "- (none)"
        name = callee["function"].split("::")[-1]
        result.add_entry(
            name,
            callee["signature"],
            f"Pre-condition:\n{pre}\nPost-condition:\n{post}",
        )
    return result

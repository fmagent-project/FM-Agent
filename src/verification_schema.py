import posixpath


LEGACY_GAP_FIELDS = {
    "spec_claim",
    "actual_behavior",
    "code_evidence",
    "trigger_condition",
}


def _extracted_function_identity(path):
    """Return the stable path below ``extracted_functions/``, if present.

    Legacy verification results stored an absolute path to the extracted
    function.  An isolated resume copies those results into a newly-created
    snapshot, so the absolute prefix changes even though the extracted function
    is the same.  The path below ``extracted_functions/`` is stable across those
    snapshots and across POSIX/Windows path separators.
    """
    if not isinstance(path, str):
        return None

    normalized = posixpath.normpath(path.replace("\\", "/"))
    parts = normalized.split("/")
    try:
        marker_index = len(parts) - 1 - parts[::-1].index("extracted_functions")
    except ValueError:
        return None

    relative_parts = parts[marker_index + 1:]
    if not relative_parts or any(part in {"", ".", ".."} for part in relative_parts):
        return None
    return "/".join(relative_parts)


def legacy_result_has_valid_schema(result):
    """Return whether an artifact intrinsically matches the legacy schema."""
    if (
        not isinstance(result, dict)
        or not isinstance(result.get("function"), str)
    ):
        return False

    verdict = result.get("verdict")
    base_fields = {"function", "verdict", "gaps"}
    if verdict == "MATCH":
        return set(result) == base_fields and result.get("gaps") is None
    if verdict == "MISMATCH":
        gaps = result.get("gaps")
        return (
            set(result) == base_fields
            and isinstance(gaps, dict)
            and set(gaps) == LEGACY_GAP_FIELDS
            and all(isinstance(gaps[field], str) for field in LEGACY_GAP_FIELDS)
        )
    if verdict == "ERROR":
        return (
            set(result) == base_fields | {"error"}
            and result.get("gaps") is None
            and isinstance(result.get("error"), str)
        )
    return False


def legacy_result_is_resumable(result, file_path):
    """Return whether a legacy result is valid for the expected function."""
    if not legacy_result_has_valid_schema(result):
        return False

    stored_path = result["function"]
    if stored_path == file_path:
        return True

    stored_identity = _extracted_function_identity(stored_path)
    return (
        stored_identity is not None
        and stored_identity == _extracted_function_identity(file_path)
    )

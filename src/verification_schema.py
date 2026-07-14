LEGACY_GAP_FIELDS = {
    "spec_claim",
    "actual_behavior",
    "code_evidence",
    "trigger_condition",
}


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
    return (
        legacy_result_has_valid_schema(result)
        and result["function"] == file_path
    )

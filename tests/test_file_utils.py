"""Tests for src.file_utils._terminal_validation_record_is_valid."""

from src.file_utils import (
    _TERMINAL_VALIDATION_STRING_FIELDS,
    _terminal_validation_record_is_valid,
)


def _valid_record():
    record = {field: "text" for field in _TERMINAL_VALIDATION_STRING_FIELDS}
    record.update(
        {
            "id": "bug-001",
            "confirmation_status": "confirmed",
            "attempts": 1,
        }
    )
    return record


class TestTerminalValidationRecordIsValid:
    def test_valid_confirmed_record(self):
        assert _terminal_validation_record_is_valid(_valid_record(), "bug-001") is True

    def test_error_status_is_terminal(self):
        record = _valid_record()
        record["confirmation_status"] = "error"
        assert _terminal_validation_record_is_valid(record, "bug-001") is True

    def test_not_confirmed_status_is_terminal(self):
        record = _valid_record()
        record["confirmation_status"] = "not_confirmed"
        assert _terminal_validation_record_is_valid(record, "bug-001") is True

    def test_non_dict_rejected(self):
        assert _terminal_validation_record_is_valid("nope", "bug-001") is False
        assert _terminal_validation_record_is_valid(None, "bug-001") is False

    def test_wrong_id_rejected(self):
        assert _terminal_validation_record_is_valid(_valid_record(), "bug-002") is False

    def test_empty_expected_bug_id_rejected(self):
        assert _terminal_validation_record_is_valid(_valid_record(), "") is False
        assert _terminal_validation_record_is_valid(_valid_record(), None) is False

    def test_non_terminal_status_rejected(self):
        record = _valid_record()
        record["confirmation_status"] = "pending"
        assert _terminal_validation_record_is_valid(record, "bug-001") is False

    def test_missing_string_field_rejected(self):
        record = _valid_record()
        del record["probe_script"]
        assert _terminal_validation_record_is_valid(record, "bug-001") is False

    def test_non_string_field_rejected(self):
        record = _valid_record()
        record["source_file"] = 123
        assert _terminal_validation_record_is_valid(record, "bug-001") is False

    def test_bool_attempts_rejected(self):
        record = _valid_record()
        record["attempts"] = True
        assert _terminal_validation_record_is_valid(record, "bug-001") is False

    def test_zero_attempts_rejected(self):
        record = _valid_record()
        record["attempts"] = 0
        assert _terminal_validation_record_is_valid(record, "bug-001") is False

    def test_larger_attempts_accepted(self):
        record = _valid_record()
        record["attempts"] = 3
        assert _terminal_validation_record_is_valid(record, "bug-001") is True

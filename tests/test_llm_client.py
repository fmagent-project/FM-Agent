"""Tests for src.llm_client._parse_json_response."""

import pytest

from src.llm_client import _parse_json_response


class TestParseJsonResponse:
    def test_plain_object(self):
        assert _parse_json_response('{"a": 1}') == {"a": 1}

    def test_plain_array(self):
        assert _parse_json_response("[1, 2]") == [1, 2]

    def test_surrounding_whitespace(self):
        assert _parse_json_response('  {"a": {"b": [1]}}  ') == {"a": {"b": [1]}}

    def test_markdown_fence(self):
        assert _parse_json_response('```json\n{"a": 1}\n```') == {"a": 1}

    def test_prose_around_single_object(self):
        text = 'Here is the result: {"a": 1} hope this helps'
        assert _parse_json_response(text) == {"a": 1}

    def test_fenced_array_with_trailing_prose(self):
        text = '```json\n[{"x": 1}]\n```\nDone.'
        assert _parse_json_response(text) == [{"x": 1}]

    def test_non_string_input_rejected(self):
        with pytest.raises(ValueError, match="must be a JSON string"):
            _parse_json_response(None)
        with pytest.raises(ValueError, match="must be a JSON string"):
            _parse_json_response({"a": 1})

    def test_scalar_json_rejected(self):
        # Valid JSON, but neither an object nor an array.
        with pytest.raises(ValueError, match="object or array"):
            _parse_json_response("42")

    def test_garbage_rejected(self):
        with pytest.raises(ValueError, match="not valid JSON"):
            _parse_json_response("not json at all")

    def test_multiple_json_values_rejected(self):
        with pytest.raises(ValueError, match="multiple JSON values"):
            _parse_json_response('{"a": 1} {"b": 2}')

    def test_mixed_object_and_array_rejected(self):
        with pytest.raises(ValueError, match="multiple JSON values"):
            _parse_json_response('[1] {"b": 2}')

    def test_braces_inside_strings_do_not_confuse_scanning(self):
        text = 'result: {"a": "}"}'
        assert _parse_json_response(text) == {"a": "}"}

import copy
import unittest

from src.incremental_reasoner import (
    _validate_caller_info_update,
    _validate_spec_update,
)


def valid_spec_update():
    return {
        "spec_updated": True,
        "new_spec": {
            "signature": "function()",
            "pre_condition": "input is valid",
            "post_condition": "returns a result",
        },
        "info_updated": True,
        "new_info": {
            "callees": [
                {
                    "name": "callee",
                    "signature": "callee()",
                    "pre_condition": "input is valid",
                    "post_condition": "returns a result",
                }
            ]
        },
        "updated_callees": ["callee"],
    }


class IncrementalSidecarValidationTests(unittest.TestCase):
    def test_valid_nested_sidecars_are_accepted(self):
        result = _validate_spec_update(valid_spec_update())

        self.assertEqual(result["new_spec"]["pre_condition"], "input is valid")
        self.assertEqual(result["new_info"]["callees"][0]["name"], "callee")

    def test_list_spec_condition_is_rejected(self):
        update = valid_spec_update()
        update["new_spec"]["pre_condition"] = ["input is valid"]

        with self.assertRaisesRegex(ValueError, r"new_spec.*\.spec\.json schema"):
            _validate_spec_update(update)

    def test_object_spec_condition_is_rejected(self):
        update = valid_spec_update()
        update["new_spec"]["post_condition"] = {"text": "returns a result"}

        with self.assertRaisesRegex(ValueError, r"new_spec.*\.spec\.json schema"):
            _validate_spec_update(update)

    def test_non_string_callee_condition_is_rejected(self):
        update = valid_spec_update()
        update["new_info"]["callees"][0]["pre_condition"] = ["valid"]

        with self.assertRaisesRegex(ValueError, r"new_info.*\.info\.json schema"):
            _validate_spec_update(update)

    def test_callee_missing_field_is_rejected(self):
        update = valid_spec_update()
        del update["new_info"]["callees"][0]["post_condition"]

        with self.assertRaisesRegex(ValueError, r"new_info.*\.info\.json schema"):
            _validate_spec_update(update)

    def test_caller_info_rejects_non_string_callee_field(self):
        info = copy.deepcopy(valid_spec_update()["new_info"])
        info["callees"][0]["signature"] = {"text": "callee()"}

        with self.assertRaisesRegex(ValueError, r"new_info.*\.info\.json schema"):
            _validate_caller_info_update(
                {"info_updated": True, "new_info": info}
            )

    def test_false_update_flags_accept_null_sidecars(self):
        result = _validate_spec_update(
            {
                "spec_updated": False,
                "new_spec": None,
                "info_updated": False,
                "new_info": None,
                "updated_callees": [],
            }
        )

        self.assertIsNone(result["new_spec"])
        self.assertIsNone(result["new_info"])


if __name__ == "__main__":
    unittest.main()

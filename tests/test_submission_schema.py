import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from submission_schema import SchemaError, validate_v3  # noqa: E402


def _valid():
    return {
        "schema_version": 3,
        "id": "src--frontend--parser--ast-rs--is_const",
        "function_id": "src::frontend::parser::ast-rs::is_const",
        "confirmation_status": "confirmed",
        "grade": "L0",
        "witness": {
            "probe": "fm_agent/bug_validation/_probe_x.c",
            "call_index": 0,
            "captured_input": {"self_flags": 0},
            "actual_output": "false",
            "spec_violation_claim": "probe line 1 defines cint=const int; B expects true, actual false",
        },
        "phenomenon": {
            "mode": "run",
            "standard": "c11",
            "extra_args": [],
            "expected_kind": "run_exit_differs",
        },
        "l1_patch": None,
        "attempts": 1,
        "notes": "",
    }


class SchemaTests(unittest.TestCase):
    def test_valid_passes(self):
        validate_v3(_valid())

    def test_missing_witness_field_fails(self):
        d = _valid()
        del d["witness"]["call_index"]
        with self.assertRaisesRegex(SchemaError, "call_index"):
            validate_v3(d)

    def test_not_confirmed_needs_no_witness(self):
        validate_v3({"schema_version": 3, "id": "x", "function_id": "y",
                     "confirmation_status": "not_confirmed", "attempts": 3,
                     "notes": "cannot trigger"})

    def test_l1_grade_requires_patch(self):
        d = _valid()
        d["grade"] = "L1"
        d["l1_patch"] = None
        with self.assertRaisesRegex(SchemaError, "l1_patch"):
            validate_v3(d)

    def test_bad_status_fails(self):
        d = _valid()
        d["confirmation_status"] = "maybe"
        with self.assertRaises(SchemaError):
            validate_v3(d)

    def test_bad_grade_fails(self):
        d = _valid()
        d["grade"] = "L2"
        with self.assertRaisesRegex(SchemaError, "grade"):
            validate_v3(d)

    def test_schema_v2_is_rejected(self):
        d = _valid()
        d["schema_version"] = 2
        with self.assertRaisesRegex(SchemaError, "schema_version"):
            validate_v3(d)

    def test_unknown_top_level_or_nested_fields_fail(self):
        for path in ("top", "witness", "phenomenon"):
            with self.subTest(path=path):
                d = _valid()
                if path == "top":
                    d["surprise"] = True
                else:
                    d[path]["surprise"] = True
                with self.assertRaisesRegex(SchemaError, "unexpected"):
                    validate_v3(d)

    def test_exact_types_reject_bool_as_integer(self):
        for owner, field in (("witness", "call_index"), (None, "attempts")):
            with self.subTest(field=field):
                d = _valid()
                (d if owner is None else d[owner])[field] = True
                with self.assertRaisesRegex(SchemaError, field):
                    validate_v3(d)

    def test_negative_call_index_fails(self):
        d = _valid()
        d["witness"]["call_index"] = -1
        with self.assertRaisesRegex(SchemaError, "call_index"):
            validate_v3(d)

    def test_empty_identity_and_claim_fields_fail(self):
        for owner, field in ((None, "id"), (None, "function_id"),
                             ("witness", "spec_violation_claim")):
            with self.subTest(field=field):
                d = _valid()
                (d if owner is None else d[owner])[field] = "  "
                with self.assertRaisesRegex(SchemaError, field):
                    validate_v3(d)

    def test_manual_and_raw_commands_are_not_schema_fields(self):
        d = _valid()
        d["witness"]["postcondition_check"] = "manual"
        d["phenomenon"]["ccc_invocation"] = "exit 1"
        with self.assertRaisesRegex(SchemaError, "unexpected"):
            validate_v3(d)

    def test_condition_contract_fields_are_not_schema_fields(self):
        for field in ("condition_a_id", "condition_a_contract"):
            with self.subTest(field=field):
                d = _valid()
                d["witness"][field] = "invented"
                with self.assertRaisesRegex(SchemaError, "unexpected"):
                    validate_v3(d)

    def test_phenomenon_values_are_closed(self):
        for field, value in (("mode", "shell"), ("standard", "c42"),
                             ("expected_kind", "anything")):
            with self.subTest(field=field):
                d = _valid()
                d["phenomenon"][field] = value
                with self.assertRaisesRegex(SchemaError, field):
                    validate_v3(d)

    def test_extra_args_must_be_exact_string_list(self):
        for value in ("-Wall", ["-Wall", 1], [True]):
            with self.subTest(value=value):
                d = _valid()
                d["phenomenon"]["extra_args"] = value
                with self.assertRaisesRegex(SchemaError, "extra_args"):
                    validate_v3(d)


if __name__ == "__main__":
    unittest.main()

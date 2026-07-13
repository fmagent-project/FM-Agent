from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from src.spec_storage import (
    MetadataValidationError,
    format_spec_for_reasoner,
    function_fqn_from_path,
    info_to_function_spec_map,
    is_function_ready,
    is_metadata_file,
    metadata_paths,
    metadata_status,
    read_info,
    read_spec,
    write_info,
    write_spec,
)


class SpecStorageTests(unittest.TestCase):
    def setUp(self):
        self.tmp = TemporaryDirectory()
        self.root = Path(self.tmp.name) / "fm_agent" / "extracted_functions"
        self.function = self.root / "src" / "loader-cpp" / "loadData.cpp"
        self.function.parent.mkdir(parents=True)
        self.function.write_text("int loadData() { return 1; }\n", encoding="utf-8")

    def tearDown(self):
        self.tmp.cleanup()

    def valid_spec(self):
        return {
            "schema_version": 1,
            "function": "src::loader-cpp::loadData",
            "unit": "src/loader.cpp",
            "signature": "loadData() -> int",
            "preconditions": [],
            "postconditions": ["returns the decoded value"],
        }

    def valid_info(self):
        return {
            "schema_version": 1,
            "function": "src::loader-cpp::loadData",
            "callees": [],
        }

    def test_metadata_paths_are_adjacent(self):
        spec_path, info_path = metadata_paths(self.function)
        self.assertEqual(spec_path.name, "loadData.spec.json")
        self.assertEqual(info_path.name, "loadData.info.json")

    def test_fqn_comes_from_extracted_relative_path(self):
        self.assertEqual(
            function_fqn_from_path(self.function),
            "src::loader-cpp::loadData",
        )

    def test_ready_requires_both_valid_files(self):
        self.assertFalse(is_function_ready(self.function))
        write_spec(self.function, self.valid_spec())
        self.assertFalse(is_function_ready(self.function))
        write_info(self.function, self.valid_info())
        self.assertTrue(is_function_ready(self.function))

    def test_invalid_array_type_is_rejected(self):
        bad = self.valid_spec()
        bad["preconditions"] = "input exists"
        with self.assertRaisesRegex(MetadataValidationError, "preconditions"):
            write_spec(self.function, bad)

    def test_wrong_fqn_is_rejected(self):
        bad = self.valid_info()
        bad["function"] = "src::other::loadData"
        with self.assertRaisesRegex(MetadataValidationError, "expected"):
            write_info(self.function, bad)

    def test_metadata_suffix_detection(self):
        self.assertTrue(
            is_metadata_file(self.function.with_name("loadData.spec.json"))
        )
        self.assertTrue(
            is_metadata_file(self.function.with_name("loadData.info.json"))
        )
        self.assertFalse(is_metadata_file(self.function))

    def test_round_trip_uses_utf8_and_trailing_newline(self):
        spec = self.valid_spec()
        spec["postconditions"] = ["返回解码后的值"]
        write_spec(self.function, spec)
        write_info(self.function, self.valid_info())
        spec_path, info_path = metadata_paths(self.function)

        self.assertEqual(read_spec(self.function), spec)
        self.assertEqual(read_info(self.function), self.valid_info())
        self.assertTrue(spec_path.read_bytes().endswith(b"\n"))
        self.assertTrue(info_path.read_bytes().endswith(b"\n"))
        self.assertFalse(spec_path.with_name(spec_path.name + ".tmp").exists())

    def test_invalid_json_reports_the_metadata_path(self):
        spec_path, _ = metadata_paths(self.function)
        spec_path.write_text("{broken", encoding="utf-8")

        ready, reason = metadata_status(self.function)

        self.assertFalse(ready)
        self.assertIn(str(spec_path), reason)

    def test_info_validates_every_callee(self):
        bad = self.valid_info()
        bad["callees"] = [
            {
                "function": "src::loader-cpp::parseHeader",
                "signature": "parseHeader(data) -> Header",
                "preconditions": ["data contains a complete header"],
                "postconditions": "returns a header",
            }
        ]

        with self.assertRaisesRegex(MetadataValidationError, "postconditions"):
            write_info(self.function, bad)

    def test_phase_one_adapters_preserve_reasoner_shape(self):
        spec_text = format_spec_for_reasoner(self.valid_spec())
        info = self.valid_info()
        info["callees"] = [
            {
                "function": "src::loader-cpp::parseHeader",
                "signature": "parseHeader(data) -> Header",
                "preconditions": ["data contains a complete header"],
                "postconditions": ["returns a validated header"],
            }
        ]

        knowledge = info_to_function_spec_map(info)

        self.assertIn("Pre-condition:", spec_text)
        self.assertIn("Post-condition:", spec_text)
        self.assertIn("returns the decoded value", spec_text)
        self.assertIn("parseHeader", knowledge)
        self.assertIn("returns a validated header", knowledge["parseHeader"])


if __name__ == "__main__":
    unittest.main()

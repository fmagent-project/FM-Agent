from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from src.parser import parse_input_function
from src.spec_storage import (
    MetadataValidationError,
    metadata_paths,
    write_info,
    write_spec,
)


class StructuredParserTests(unittest.TestCase):
    def setUp(self):
        self.tmp = TemporaryDirectory()
        self.function = (
            Path(self.tmp.name)
            / "fm_agent"
            / "extracted_functions"
            / "src"
            / "module-py"
            / "load_data.py"
        )
        self.function.parent.mkdir(parents=True)
        self.function.write_text(
            "def load_data(value):\n"
            "    # implementation comment\n"
            "    return parse_header(value)\n",
            encoding="utf-8",
        )
        write_spec(
            self.function,
            {
                "schema_version": 1,
                "function": "src::module-py::load_data",
                "unit": "src/module.py",
                "signature": "load_data(value) -> Header",
                "preconditions": ["value contains a complete header"],
                "postconditions": ["returns the decoded header"],
            },
        )
        write_info(
            self.function,
            {
                "schema_version": 1,
                "function": "src::module-py::load_data",
                "callees": [
                    {
                        "function": "src::module-py::parse_header",
                        "signature": "parse_header(value) -> Header",
                        "preconditions": ["value contains a complete header"],
                        "postconditions": ["returns a validated header"],
                    }
                ],
            },
        )

    def tearDown(self):
        self.tmp.cleanup()

    def test_parser_reads_implementation_and_adjacent_metadata(self):
        func, spec, info = parse_input_function(self.function)

        self.assertIn("Line 1: def load_data", func)
        self.assertEqual(spec["function"], "src::module-py::load_data")
        self.assertEqual(spec["postconditions"], ["returns the decoded header"])
        self.assertEqual(info["function"], "src::module-py::load_data")
        self.assertEqual(
            info["callees"][0]["function"],
            "src::module-py::parse_header",
        )
        self.assertEqual(
            info["callees"][0]["postconditions"],
            ["returns a validated header"],
        )

    def test_parser_reports_malformed_spec_path(self):
        spec_path, _ = metadata_paths(self.function)
        spec_path.write_text("{broken", encoding="utf-8")

        with self.assertRaises(MetadataValidationError) as caught:
            parse_input_function(self.function)

        self.assertIn(str(spec_path), str(caught.exception))


if __name__ == "__main__":
    unittest.main()

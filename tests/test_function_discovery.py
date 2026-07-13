import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from src.extract import run_extraction
from src.file_utils import collect_file_names, _get_phase_files, is_file_ready
from src.generate_topdown_layers import _collect_phase_files
from src.spec_storage import write_info, write_spec


class FunctionDiscoveryTests(unittest.TestCase):
    def setUp(self):
        self.tmp = TemporaryDirectory()
        self.project = Path(self.tmp.name)
        self.work_dir = self.project / "fm_agent"
        self.extracted = self.work_dir / "extracted_functions"
        self.function = (
            self.extracted / "src" / "loader-cpp" / "loadData.cpp"
        )
        self.function.parent.mkdir(parents=True)
        self.function.write_text(
            "int loadData() { return 1; }\n",
            encoding="utf-8",
        )
        self.spec = {
            "schema_version": 1,
            "function": "src::loader-cpp::loadData",
            "unit": "src/loader.cpp",
            "signature": "loadData() -> int",
            "preconditions": [],
            "postconditions": ["returns one"],
        }
        self.info = {
            "schema_version": 1,
            "function": "src::loader-cpp::loadData",
            "callees": [],
        }
        write_spec(self.function, self.spec)
        write_info(self.function, self.info)
        self.phases = {
            "phases": [
                {
                    "phase": 1,
                    "name": "core",
                    "modules": [
                        {
                            "name": "loader",
                            "source_files": ["src/loader.cpp"],
                        }
                    ],
                }
            ]
        }

    def tearDown(self):
        self.tmp.cleanup()

    def test_collect_file_names_returns_only_implementations(self):
        output = self.work_dir / "files.json"

        collected = collect_file_names(str(self.extracted), str(output))

        self.assertEqual(
            collected,
            [str(Path("src") / "loader-cpp" / "loadData.cpp")],
        )

    def test_phase_file_helpers_ignore_metadata(self):
        relative = _get_phase_files(
            self.phases, 1, str(self.extracted)
        )
        topdown = _collect_phase_files(
            str(self.work_dir), self.phases["phases"][0]
        )

        self.assertEqual(
            relative,
            [str(Path("src") / "loader-cpp" / "loadData.cpp")],
        )
        self.assertEqual(topdown, [(str(self.function), "loader")])

    def test_ready_uses_adjacent_structured_metadata(self):
        self.assertTrue(is_file_ready(self.function))

    def test_resume_skips_unchanged_implementation(self):
        source = self.project / "src" / "loader.cpp"
        source.parent.mkdir(parents=True)
        source.write_text(
            "int loadData() { return 1; }\n",
            encoding="utf-8",
        )
        self.work_dir.mkdir(exist_ok=True)
        (self.work_dir / "phases.json").write_text(
            json.dumps(self.phases),
            encoding="utf-8",
        )

        with patch(
            "src.extract.batch_extract_all",
            return_value=(
                {str(source): [("loadData", self.function.read_text())]},
                {"cpp"},
            ),
        ):
            written, skipped = run_extraction(
                str(self.project),
                work_dir=str(self.work_dir),
                force=False,
            )

        self.assertEqual((written, skipped), (0, 1))
        self.assertTrue(is_file_ready(self.function))


if __name__ == "__main__":
    unittest.main()

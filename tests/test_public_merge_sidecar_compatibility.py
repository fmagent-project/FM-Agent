import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from src.file_utils import _get_phase_files
from src.generate_topdown_layers import _collect_phase_files
from src.incremental_reasoner import _reconcile_extracted_dir


class RecursiveSidecarFilteringTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.work_dir = Path(self.temp_dir.name)
        self.extracted_dir = self.work_dir / "extracted_functions"
        self.function_dir = self.extracted_dir / "src" / "sample-py" / "legacy"
        self.function_dir.mkdir(parents=True)
        (self.function_dir / "function.py").write_text("def function(): pass\n")
        (self.function_dir / "function.py.spec.json").write_text("{}")
        (self.function_dir / "function.py.info.json").write_text("{}")
        self.phase = {
            "phase": 1,
            "modules": [{"name": "module", "source_files": ["src/sample.py"]}],
        }

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_topdown_collection_keeps_nested_function_but_not_sidecars(self):
        files = _collect_phase_files(self.work_dir, self.phase)

        self.assertEqual(files, [(str(self.function_dir / "function.py"), "module")])

    def test_phase_file_collection_keeps_nested_function_but_not_sidecars(self):
        files = _get_phase_files({"phases": [self.phase]}, 1, self.extracted_dir)

        self.assertEqual(files, ["src/sample-py/legacy/function.py"])


class ReconcileSidecarTests(unittest.TestCase):
    def test_reconcile_preserves_valid_sidecars_and_removes_stale_triplet(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            project = Path(temp_dir)
            source = project / "src" / "sample.py"
            source.parent.mkdir()
            source.write_text("def current(): pass\n")
            function_dir = (
                project / "fm_agent" / "extracted_functions" / "src" / "sample-py"
            )
            function_dir.mkdir(parents=True)

            for name in (
                "current.py",
                "current.py.spec.json",
                "current.py.info.json",
                "stale.py",
                "stale.py.spec.json",
                "stale.py.info.json",
            ):
                (function_dir / name).write_text("{}")

            with patch(
                "src.incremental_reasoner._function_spans",
                return_value=([("current", 1, 1)], ""),
            ):
                _reconcile_extracted_dir(str(project), str(source))

            self.assertEqual(
                sorted(path.name for path in function_dir.iterdir()),
                ["current.py", "current.py.info.json", "current.py.spec.json"],
            )


if __name__ == "__main__":
    unittest.main()

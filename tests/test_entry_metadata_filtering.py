from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from src.entry_reasoning_pipeline import _select_functions_by_source
from src.spec_storage import write_info, write_spec


class EntryMetadataFilteringTests(unittest.TestCase):
    def test_entry_bfs_selects_implementations_not_metadata_sidecars(self):
        with TemporaryDirectory() as tmp:
            project = Path(tmp) / "project"
            project.mkdir()
            (project / "module.py").write_text(
                "def caller():\n"
                "    return callee()\n\n"
                "def callee():\n"
                "    return 1\n",
                encoding="utf-8",
            )

            stale = (
                project
                / "fm_agent"
                / "extracted_functions"
                / "module-py"
                / "stale.py"
            )
            stale.parent.mkdir(parents=True)
            stale.write_text("def stale():\n    return 0\n", encoding="utf-8")
            write_spec(
                stale,
                {
                    "schema_version": 1,
                    "function": "module-py::stale",
                    "unit": "module.py",
                    "signature": "stale() -> int",
                    "preconditions": [],
                    "postconditions": ["returns zero"],
                },
            )
            write_info(
                stale,
                {
                    "schema_version": 1,
                    "function": "module-py::stale",
                    "callees": [],
                },
            )

            with patch(
                "src.entry_reasoning_pipeline.try_codegraph_init",
                return_value=False,
            ):
                all_by_source, selected = _select_functions_by_source(
                    str(project),
                    "module-py::caller",
                    [],
                )

            self.assertEqual(
                dict(all_by_source),
                {"module.py": {"caller", "callee"}},
            )
            self.assertEqual(
                dict(selected),
                {"module.py": {"caller", "callee"}},
            )


if __name__ == "__main__":
    unittest.main()

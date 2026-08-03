import json
import tempfile
import unittest
from pathlib import Path

from src.pipeline_setup import _phase_plan_complete, _phase_plan_schema_errors


class PhasePlanSchemaTests(unittest.TestCase):
    def test_phase_plan_schema_validation_remains_available_after_merge(self):
        with tempfile.TemporaryDirectory() as tmp:
            work_dir = Path(tmp)
            phases_path = work_dir / "phases.json"
            phases_path.write_text(
                json.dumps(
                    {
                        "phases": [
                            {
                                "modules": [
                                    {
                                        "name": "core",
                                        "source_files": ["src/core.py"],
                                    }
                                ]
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )

            self.assertEqual(_phase_plan_schema_errors(phases_path), [])
            self.assertTrue(_phase_plan_complete(work_dir))

            phases_path.write_text(
                json.dumps({"phases": [{"modules": [{"name": "core"}]}]}),
                encoding="utf-8",
            )
            self.assertEqual(
                _phase_plan_schema_errors(phases_path),
                ["phases[0].modules[0] ('core').source_files is missing"],
            )
            self.assertFalse(_phase_plan_complete(work_dir))


if __name__ == "__main__":
    unittest.main()

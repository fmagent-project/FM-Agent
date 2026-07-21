import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


class GenerateBatchPromptsWorkspaceTests(unittest.TestCase):
    def test_manifest_paths_are_relative_to_repo_root_for_nested_run(self):
        repo_source = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory() as tmp:
            project = Path(tmp, "project")
            work_dir = project / "fm_agent" / "runs" / "run-1"
            spec_dir = work_dir / "spec_prompts"
            spec_dir.mkdir(parents=True)

            shutil.copy2(
                repo_source / "src" / "generate_batch_prompts.py",
                spec_dir / "generate_batch_prompts.py",
            )
            shutil.copy2(repo_source / "src" / "file_utils.py", spec_dir / "file_utils.py")

            (work_dir / "phases.json").write_text(
                json.dumps(
                    {
                        "project": "sample",
                        "languages": ["python"],
                        "file_extensions": ["py"],
                    }
                )
            )
            function_path = "extracted_functions/sample.py/function.json"
            (spec_dir / "phase_01_topdown_layers.json").write_text(
                json.dumps(
                    {
                        "layers": [
                            {
                                "layer": 0,
                                "functions": [
                                    {"name": "sample", "file": function_path}
                                ],
                            }
                        ]
                    }
                )
            )

            subprocess.run(
                [
                    sys.executable,
                    str(spec_dir / "generate_batch_prompts.py"),
                    "--phase",
                    "1",
                    "--layers",
                    "0",
                    "--repo-root",
                    str(project),
                ],
                cwd=project,
                check=True,
                capture_output=True,
                text=True,
            )

            manifest_path = (
                spec_dir / "batch_prompts_sample_phase01" / "manifest.json"
            )
            manifest = json.loads(manifest_path.read_text())
            expected = os.path.join(
                "fm_agent", "runs", "run-1", function_path
            ).replace(os.sep, "/")
            self.assertEqual(manifest["batches"][0]["functions"], [expected])


if __name__ == "__main__":
    unittest.main()

import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

import main
from src.spec_generation import generate_batch_manifest
from src.spec_storage import write_info, write_spec


class SpecGenerationModuleTests(unittest.TestCase):
    def setUp(self):
        self.tmp = TemporaryDirectory()
        self.project = Path(self.tmp.name)
        self.work_dir = self.project / "fm_agent"
        self.extracted_dir = self.work_dir / "extracted_functions"
        self.function = self.extracted_dir / "src" / "module-py" / "load.py"
        self.function.parent.mkdir(parents=True)
        self.function.write_text("def load():\n    return 1\n", encoding="utf-8")
        self.layer_path = self.work_dir / "spec_prompts" / "phase_01_topdown_layers.json"
        self.layer_path.parent.mkdir(parents=True)
        self.layer_path.write_text(
            json.dumps(
                {
                    "total_layers": 1,
                    "layers": [
                        {
                            "layer": 0,
                            "functions": [
                                {
                                    "name": "src::module-py::load",
                                    "file": "extracted_functions/src/module-py/load.py",
                                    "phase1_callers": [],
                                }
                            ],
                        }
                    ],
                }
            ),
            encoding="utf-8",
        )
        self.output_dir = self.work_dir / "spec_prompts" / "batches"

    def tearDown(self):
        self.tmp.cleanup()

    def _generate(self, resume=False):
        return generate_batch_manifest(
            extracted_functions_dir=self.extracted_dir,
            layer_json_path=self.layer_path,
            output_dir=self.output_dir,
            phase=1,
            layers_spec="0",
            project="sample",
            ext_to_lang={"py": "python"},
            resume=resume,
        )

    def test_layer_json_and_extracted_functions_produce_manifest(self):
        manifest = self._generate()

        self.assertEqual(manifest["total_functions"], 1)
        self.assertEqual(manifest["batches"][0]["num_pending"], 1)
        self.assertEqual(
            manifest["batches"][0]["functions"],
            ["fm_agent/extracted_functions/src/module-py/load.py"],
        )
        prompt = self.output_dir / manifest["batches"][0]["file"]
        self.assertTrue(prompt.is_file())
        prompt_text = prompt.read_text(encoding="utf-8")
        self.assertIn("load.spec.json", prompt_text)
        self.assertIn("load.info.json", prompt_text)

    def test_resume_records_ready_function_without_empty_prompt(self):
        write_spec(
            self.function,
            {
                "schema_version": 1,
                "function": "src::module-py::load",
                "unit": "src/module.py",
                "signature": "load() -> int",
                "preconditions": [],
                "postconditions": ["returns one"],
            },
        )
        write_info(
            self.function,
            {
                "schema_version": 1,
                "function": "src::module-py::load",
                "callees": [],
            },
        )

        manifest = self._generate(resume=True)

        batch = manifest["batches"][0]
        self.assertEqual(batch["num_pending"], 0)
        self.assertFalse((self.output_dir / batch["file"]).exists())


class MainSpecGenerationDelegationTests(unittest.TestCase):
    def test_pipeline_delegates_stage_four_to_spec_generation_module(self):
        with TemporaryDirectory() as tmp:
            project = Path(tmp)
            work_dir = project / "fm_agent"
            extracted_dir = work_dir / "extracted_functions"
            extracted_dir.mkdir(parents=True)
            (work_dir / "phases.json").write_text(
                json.dumps(
                    {
                        "project": "sample",
                        "languages": ["python"],
                        "file_extensions": ["py"],
                        "phases": [
                            {"phase": 1, "name": "core", "source_files": ["src/a.py"]}
                        ],
                    }
                ),
                encoding="utf-8",
            )

            with (
                patch.object(main, "_has_source_code", return_value=True),
                patch.object(main, "_run_setup_extract"),
                patch.object(main, "try_codegraph_init"),
                patch.object(main, "run_extraction"),
                patch.object(main, "collect_file_names", return_value=["src/module-py/load.py"]),
                patch.object(main, "generate_topdown_layers"),
                patch.object(main, "run_spec_generation") as run_generation,
            ):
                main.run_pipeline(str(project), resume=True)

            run_generation.assert_called_once()


if __name__ == "__main__":
    unittest.main()

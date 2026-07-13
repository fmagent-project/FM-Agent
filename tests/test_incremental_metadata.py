import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from src.incremental_reasoner import (
    _collect_caller_context,
    _remove_stale_extracted,
    _resolve_callee_fqns,
    _update_specs_for_intent,
    check_last_run_existence,
)
from src.spec_storage import metadata_paths, write_info, write_spec


class IncrementalMetadataTests(unittest.TestCase):
    def setUp(self):
        self.tmp = TemporaryDirectory()
        self.project = Path(self.tmp.name)
        self.work_dir = self.project / "fm_agent"
        self.extracted = self.work_dir / "extracted_functions"
        self.function = (
            self.extracted / "src" / "module-py" / "caller.py"
        )
        self.function.parent.mkdir(parents=True)
        self.function.write_text(
            "def caller():\n    return callee()\n",
            encoding="utf-8",
        )
        self.work_dir.mkdir(exist_ok=True)
        (self.work_dir / "phases.json").write_text(
            json.dumps({"phases": []}),
            encoding="utf-8",
        )
        write_spec(
            self.function,
            {
                "schema_version": 1,
                "function": "src::module-py::caller",
                "unit": "src/module.py",
                "signature": "caller() -> int",
                "preconditions": [],
                "postconditions": ["returns the callee result"],
            },
        )
        write_info(
            self.function,
            {
                "schema_version": 1,
                "function": "src::module-py::caller",
                "callees": [
                    {
                        "function": "src::module-py::callee",
                        "signature": "callee() -> int",
                        "preconditions": [],
                        "postconditions": ["returns a positive integer"],
                    }
                ],
            },
        )

    def tearDown(self):
        self.tmp.cleanup()

    def test_completed_run_ignores_metadata_as_function_files(self):
        self.assertTrue(check_last_run_existence(str(self.project)))

    def test_removing_function_deletes_implementation_and_metadata(self):
        source = self.project / "src" / "module.py"
        source.parent.mkdir(parents=True)
        source.write_text("", encoding="utf-8")
        removed = self.function.with_name("removed.py")
        removed.write_text("def removed():\n    return 1\n", encoding="utf-8")
        write_spec(
            removed,
            {
                "schema_version": 1,
                "function": "src::module-py::removed",
                "unit": "src/module.py",
                "signature": "removed() -> int",
                "preconditions": [],
                "postconditions": ["returns one"],
            },
        )
        write_info(
            removed,
            {
                "schema_version": 1,
                "function": "src::module-py::removed",
                "callees": [],
            },
        )

        _remove_stale_extracted(
            str(self.project),
            {
                str(source): {
                    "added": [],
                    "modified": [],
                    "removed": ["removed"],
                }
            },
        )

        self.assertFalse(removed.exists())
        for metadata_path in metadata_paths(removed):
            self.assertFalse(metadata_path.exists())

    def test_caller_context_returns_structured_objects(self):
        context = _collect_caller_context(
            "src::module-py::callee",
            {"src::module-py::callee": {"src::module-py::caller"}},
            {"src::module-py::caller": str(self.function)},
        )

        self.assertEqual(len(context), 1)
        caller_fqn, caller_spec, expectation = context[0]
        self.assertEqual(caller_fqn, "src::module-py::caller")
        self.assertEqual(caller_spec["schema_version"], 1)
        self.assertEqual(
            expectation["function"],
            "src::module-py::callee",
        )

    def test_updated_callee_resolution_uses_full_fqn(self):
        callees = {
            "src::caller": {
                "src::one::parse",
                "src::two::parse",
            }
        }

        resolved = _resolve_callee_fqns(
            "src::caller",
            ["src::two::parse"],
            callees,
        )

        self.assertEqual(resolved, {"src::two::parse"})

    def test_incremental_update_writes_json_without_touching_implementation(self):
        original = self.function.read_bytes()
        new_spec = {
            "schema_version": 1,
            "function": "src::module-py::caller",
            "unit": "src/module.py",
            "signature": "caller() -> int",
            "preconditions": [],
            "postconditions": ["returns the updated callee result"],
        }
        new_info = {
            "schema_version": 1,
            "function": "src::module-py::caller",
            "callees": [],
        }

        with (
            patch(
                "src.incremental_reasoner._project_call_graph",
                return_value=(
                    {"src::module-py::caller": set()},
                    {},
                    {"src::module-py::caller": str(self.function)},
                ),
            ),
            patch(
                "src.incremental_reasoner._topdown_ordered_fqns",
                return_value=["src::module-py::caller"],
            ),
            patch(
                "src.incremental_reasoner._structured_llm_check_spec_update",
                return_value={
                    "spec_updated": True,
                    "new_spec": new_spec,
                    "info_updated": True,
                    "new_info": new_info,
                    "updated_callees": [],
                },
            ),
        ):
            updated = _update_specs_for_intent(
                str(self.project),
                str(self.work_dir),
                "change the result contract",
                {},
                ["src/module-py/caller.py"],
            )

        self.assertEqual(self.function.read_bytes(), original)
        self.assertEqual(updated, ["src/module-py/caller.py"])
        self.assertEqual(json.loads(metadata_paths(self.function)[0].read_text()), new_spec)
        self.assertEqual(json.loads(metadata_paths(self.function)[1].read_text()), new_info)

    def test_callee_change_reconciles_only_caller_info_json(self):
        callee = self.function.with_name("callee.py")
        callee.write_text("def callee():\n    return 2\n", encoding="utf-8")
        write_spec(
            callee,
            {
                "schema_version": 1,
                "function": "src::module-py::callee",
                "unit": "src/module.py",
                "signature": "callee() -> int",
                "preconditions": [],
                "postconditions": ["returns a positive integer"],
            },
        )
        write_info(
            callee,
            {
                "schema_version": 1,
                "function": "src::module-py::callee",
                "callees": [],
            },
        )
        caller_source = self.function.read_bytes()
        caller_spec_before = metadata_paths(self.function)[0].read_bytes()
        callee_source = callee.read_bytes()
        new_callee_spec = {
            "schema_version": 1,
            "function": "src::module-py::callee",
            "unit": "src/module.py",
            "signature": "callee() -> int",
            "preconditions": [],
            "postconditions": ["returns two"],
        }
        new_caller_info = {
            "schema_version": 1,
            "function": "src::module-py::caller",
            "callees": [
                {
                    "function": "src::module-py::callee",
                    "signature": "callee() -> int",
                    "preconditions": [],
                    "postconditions": ["returns two"],
                }
            ],
        }

        with (
            patch(
                "src.incremental_reasoner._project_call_graph",
                return_value=(
                    {"src::module-py::callee": set()},
                    {"src::module-py::callee": {"src::module-py::caller"}},
                    {
                        "src::module-py::callee": str(callee),
                        "src::module-py::caller": str(self.function),
                    },
                ),
            ),
            patch(
                "src.incremental_reasoner._topdown_ordered_fqns",
                return_value=["src::module-py::caller", "src::module-py::callee"],
            ),
            patch(
                "src.incremental_reasoner._structured_llm_check_spec_update",
                return_value={
                    "spec_updated": True,
                    "new_spec": new_callee_spec,
                    "info_updated": False,
                    "new_info": None,
                    "updated_callees": [],
                },
            ),
            patch(
                "src.incremental_reasoner._structured_llm_check_caller_info_update",
                return_value={"info_updated": True, "new_info": new_caller_info},
            ),
        ):
            updated = _update_specs_for_intent(
                str(self.project),
                str(self.work_dir),
                "callee now returns two",
                {},
                ["src/module-py/callee.py"],
            )

        self.assertEqual(callee.read_bytes(), callee_source)
        self.assertEqual(self.function.read_bytes(), caller_source)
        self.assertEqual(metadata_paths(self.function)[0].read_bytes(), caller_spec_before)
        self.assertEqual(json.loads(metadata_paths(self.function)[1].read_text()), new_caller_info)
        self.assertEqual(
            updated,
            ["src/module-py/callee.py", "src/module-py/caller.py"],
        )


if __name__ == "__main__":
    unittest.main()

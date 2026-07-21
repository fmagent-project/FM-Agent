import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from src.plugins.base import FactEnvelope, Verdict
from src.plugins import driver, registry
from src.plugins.callgraph import (
    build_program_index,
    load_function_units,
    order_bottom_up,
    scan_source_files,
)


class PluginWorkDirectoryDiscoveryTests(unittest.TestCase):
    def test_first_and_resumed_extraction_exclude_existing_work_tree_without_growth(self):
        """Regression for authn's recorded 568-call pre-fix aggregation growth."""
        with tempfile.TemporaryDirectory() as tmp:
            project = Path(tmp)
            source = project / "src"
            source.mkdir()
            (source / "alpha.py").write_text("def handle():\n    return first()\n")
            (source / "beta.py").write_text("def handle():\n    return 2\n")
            (source / "cycle.py").write_text(
                "def first():\n    return second()\n\n"
                "def second():\n    return first()\n"
            )

            work = project / "plugin-state"
            generated = {
                work / "results/nested/rendered.py": "def generated_result():\n    return 1\n",
                work / "facts_cache/nested/cached.py": "def generated_fact():\n    return 1\n",
                work / "generated/deeper/tool.py": "def generated_tool():\n    return 1\n",
                work / "extracted_functions/plugin-state/results/nested/rendered-py/generated_result.py":
                    "def generated_result():\n    return 1\n",
                work / "extracted_functions/legacy-py/generated.py":
                    "def generated_legacy():\n    return 1\n",
            }
            for path, content in generated.items():
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(content)

            before = {path.relative_to(work) for path in work.rglob("*") if path.is_file()}
            first = load_function_units(
                str(project), str(work), excluded_root=str(work.resolve())
            )
            after_first = {path.relative_to(work) for path in work.rglob("*") if path.is_file()}
            resumed = load_function_units(
                str(project), str(work), excluded_root=str(work.resolve())
            )
            after_resumed = {path.relative_to(work) for path in work.rglob("*") if path.is_file()}

            expected = {
                ("src/alpha-py/handle.py", "handle"),
                ("src/beta-py/handle.py", "handle"),
                ("src/cycle-py/first.py", "first"),
                ("src/cycle-py/second.py", "second"),
            }
            first_ids = {(unit.id.rel, unit.id.name) for unit in first}
            resumed_ids = {(unit.id.rel, unit.id.name) for unit in resumed}
            self.assertEqual(expected, first_ids)
            self.assertEqual(first_ids, resumed_ids)
            self.assertEqual(after_first, after_resumed)
            self.assertTrue(before <= after_first)
            for path, content in generated.items():
                self.assertEqual(content, path.read_text())
            self.assertFalse(any(
                part in {"plugin-state", "results", "facts_cache", "extracted_functions"}
                for unit in first for part in Path(unit.id.rel).parts
            ))

            program = build_program_index(first)
            ordered = order_bottom_up(first)
            self.assertEqual(expected, {(unit.id.rel, unit.id.name) for unit in ordered})
            first_id = next(unit.id for unit in first if unit.id.name == "first")
            second_id = next(unit.id for unit in first if unit.id.name == "second")
            self.assertEqual([second_id], [site.callee for site in program.calls_by_caller[first_id]])
            self.assertEqual([first_id], [site.callee for site in program.calls_by_caller[second_id]])

    def test_exclusion_uses_path_containment_not_directory_name_or_prefix(self):
        with tempfile.TemporaryDirectory() as tmp:
            project = Path(tmp)
            work = project / "active-work"
            sibling = project / "active-work-copy"
            named_like_legacy_work = project / "fm_agent_authn"
            for path in (
                project / "app.py",
                work / "results/nested/generated.py",
                sibling / "user.py",
                named_like_legacy_work / "user.py",
            ):
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("def target():\n    return 1\n")

            found = scan_source_files(str(project), excluded_root=str(work.resolve()))

            self.assertEqual(
                ["active-work-copy/user.py", "app.py", "fm_agent_authn/user.py"],
                found,
            )

    def test_driver_passes_every_plugins_absolute_active_work_root(self):
        with tempfile.TemporaryDirectory() as tmp:
            project = Path(tmp)
            calls = []

            def no_units(proj_dir, work_dir, excluded_root=None):
                calls.append((proj_dir, work_dir, excluded_root))
                return []

            with mock.patch.object(driver.callgraph, "load_function_units", side_effect=no_units):
                for name in registry.plugin_names():
                    manifest = registry.get_manifest(name)
                    plugin = SimpleNamespace(metadata=SimpleNamespace(name=name))
                    driver.run_plugin(
                        plugin,
                        str(project),
                        work_subdir=manifest.get("work_subdir"),
                        results_subdir=manifest.get("results_subdir", "results"),
                        verbose=False,
                    )

            self.assertEqual(len(registry.plugin_names()), len(calls))
            for name, (_, work_dir, excluded_root) in zip(registry.plugin_names(), calls):
                manifest = registry.get_manifest(name)
                expected = (project / manifest.get("work_subdir", f"fm_agent_{name}")).resolve()
                self.assertEqual(str(expected), work_dir)
                self.assertEqual(str(expected), excluded_root)
            ifc_index = list(registry.plugin_names()).index("ifc")
            self.assertTrue(calls[ifc_index][1].endswith("fm_agent_ifc"))

    def test_driver_resume_reuses_facts_without_scanning_generated_python(self):
        with tempfile.TemporaryDirectory() as tmp:
            project = Path(tmp)
            (project / "app.py").write_text("def original():\n    return 1\n")
            generated = project / "custom-ifc-work/results/nested/generated.py"
            generated.parent.mkdir(parents=True)
            generated.write_text("def generated():\n    return 2\n")
            metadata = SimpleNamespace(
                name="ifc", requires_top_down_context=False
            )
            plugin = SimpleNamespace(
                metadata=metadata,
                check=lambda facts, context, propagated: Verdict(
                    plugin_name="ifc", verdict="SAFE"
                ),
                render_result=lambda unit, facts, verdict, context: {
                    "rel": unit.id.rel, "verdict": verdict.verdict
                },
                render_summary=lambda results, counts: {
                    "total": len(results), "counts": dict(counts), "results": list(results)
                },
            )

            def facts_for(plugin, request, model, max_iter):
                return FactEnvelope(
                    plugin_name="ifc",
                    schema_version="test.v1",
                    function=request.function.id,
                    status="ok",
                    payload={"original": True},
                )

            with mock.patch.object(
                driver, "_call_llm_with_retries", side_effect=facts_for
            ) as llm:
                first = driver.run_plugin(
                    plugin,
                    str(project),
                    work_subdir="custom-ifc-work",
                    results_subdir="ifc_results",
                    verbose=False,
                )
                second = driver.run_plugin(
                    plugin,
                    str(project),
                    work_subdir="custom-ifc-work",
                    results_subdir="ifc_results",
                    verbose=False,
                )

            self.assertEqual(1, llm.call_count)
            self.assertEqual(1, first["total"])
            self.assertEqual(first, second)
            self.assertEqual("def generated():\n    return 2\n", generated.read_text())
            self.assertTrue((
                project / "custom-ifc-work/facts_cache/app-py/original.json"
            ).is_file())


if __name__ == "__main__":
    unittest.main()

import json
import os
import tempfile
import unittest
from datetime import datetime

from src.run_workspace import (
    RunSelectionCancelled,
    current_run_dir,
    inferred_workdir_relpath,
    select_run_workspace,
)


NOW = datetime(2026, 7, 17, 14, 30, 0)


class RunWorkspaceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.project = self.tmp.name

    def tearDown(self):
        self.tmp.cleanup()

    def select(self, answers=(), **kwargs):
        answers = iter(answers)
        return select_run_workspace(
            self.project,
            input_fn=lambda _prompt: next(answers),
            output_fn=lambda _line: None,
            interactive=True,
            now=NOW,
            **kwargs,
        )

    def test_first_run_uses_timestamped_directory(self):
        selected = self.select()
        self.assertEqual(selected.run_id, "20260717-143000")
        self.assertTrue(selected.work_dir.endswith("fm_agent/runs/20260717-143000"))
        self.assertEqual(current_run_dir(self.project), selected.work_dir)
        self.assertEqual(
            inferred_workdir_relpath(selected.work_dir),
            "fm_agent/runs/20260717-143000",
        )

    def test_first_noninteractive_run_is_created_without_prompt(self):
        selected = select_run_workspace(
            self.project,
            interactive=False,
            output_fn=lambda _line: None,
            now=NOW,
        )
        self.assertEqual(selected.action, "new")
        self.assertTrue(os.path.isdir(selected.work_dir))

    def test_archive_preserves_previous_run_and_creates_another(self):
        first = self.select()
        marker = os.path.join(first.work_dir, "result.txt")
        with open(marker, "w") as f:
            f.write("keep me")

        second = self.select(["2"])
        self.assertEqual(second.action, "archive")
        self.assertTrue(os.path.isfile(marker))
        self.assertNotEqual(first.work_dir, second.work_dir)
        self.assertTrue(second.work_dir.endswith("20260717-143000-2"))

    def test_resume_reuses_current_run(self):
        first = self.select()
        with open(os.path.join(first.work_dir, "phases.json"), "w") as f:
            json.dump({}, f)
        resumed = self.select(resume_requested=True)
        self.assertTrue(resumed.resume)
        self.assertEqual(resumed.work_dir, first.work_dir)

    def test_overwrite_requires_explicit_choice(self):
        archived = self.select()
        archived_file = os.path.join(archived.work_dir, "archived.txt")
        with open(archived_file, "w") as f:
            f.write("preserve me")
        first = self.select(["2"])
        old_file = os.path.join(first.work_dir, "result.txt")
        with open(old_file, "w") as f:
            f.write("delete me")
        replacement = self.select(["3"])
        self.assertEqual(replacement.action, "overwrite")
        self.assertFalse(os.path.exists(old_file))
        self.assertTrue(os.path.isfile(archived_file))
        self.assertTrue(os.path.isdir(replacement.work_dir))

    def test_exit_preserves_results(self):
        first = self.select()
        marker = os.path.join(first.work_dir, "result.txt")
        with open(marker, "w") as f:
            f.write("keep me")
        with self.assertRaises(RunSelectionCancelled):
            self.select(["4"])
        self.assertTrue(os.path.isfile(marker))

    def test_noninteractive_existing_run_fails_safe(self):
        first = self.select()
        with open(os.path.join(first.work_dir, "result.txt"), "w") as f:
            f.write("keep me")
        with self.assertRaises(RunSelectionCancelled):
            select_run_workspace(
                self.project,
                interactive=False,
                output_fn=lambda _line: None,
                now=NOW,
            )

    def test_legacy_layout_is_migrated_when_resumed(self):
        root = os.path.join(self.project, "fm_agent")
        os.makedirs(root)
        legacy_file = os.path.join(root, "phases.json")
        with open(legacy_file, "w") as f:
            f.write("{}")
        selected = self.select(resume_requested=True)
        self.assertTrue(selected.run_id.startswith("legacy-20260717-143000"))
        self.assertTrue(os.path.isfile(os.path.join(selected.work_dir, "phases.json")))
        self.assertFalse(os.path.exists(legacy_file))


if __name__ == "__main__":
    unittest.main()

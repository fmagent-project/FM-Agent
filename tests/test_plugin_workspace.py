import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from src.pipeline_setup import _rewrite_workflow_workspace_paths
from src.plugin import run_plugin_command


class PluginWorkspaceTests(unittest.TestCase):
    def test_plugin_command_receives_selected_run_workspace(self):
        with tempfile.TemporaryDirectory() as tmp:
            project_dir = os.path.join(tmp, "project")
            work_dir = os.path.join(project_dir, "fm_agent", "runs", "run-1")
            plugin_root = Path(tmp, "plugin")
            os.makedirs(work_dir)
            plugin_root.mkdir()

            with patch("src.plugin.subprocess.run") as run:
                run_plugin_command(
                    "plugin-command",
                    plugin_root,
                    project_dir,
                    work_dir=work_dir,
                )

            env = run.call_args.kwargs["env"]
            self.assertEqual(env["FM_AGENT_WORK_DIR"], os.path.abspath(work_dir))
            self.assertEqual(
                env["FM_AGENT_WORK_DIR_REL"],
                os.path.join("fm_agent", "runs", "run-1"),
            )

    def test_plugin_workflow_paths_target_selected_run(self):
        with tempfile.TemporaryDirectory() as tmp:
            workflow = os.path.join(tmp, "workflow.md")
            with open(workflow, "w") as output:
                output.write("Read fm_agent/phases.json and write fm_agent/output.json")

            _rewrite_workflow_workspace_paths(
                workflow, os.path.join("fm_agent", "runs", "run-1")
            )

            with open(workflow, "r") as result:
                content = result.read()
            self.assertNotIn("fm_agent/phases.json", content)
            self.assertIn("fm_agent/runs/run-1/phases.json", content)


if __name__ == "__main__":
    unittest.main()

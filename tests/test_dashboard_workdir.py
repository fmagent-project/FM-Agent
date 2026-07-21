import json
import os
import tempfile
import unittest

from dashboard import _locate_workdir


class DashboardWorkdirTests(unittest.TestCase):
    def test_project_root_follows_current_run_marker(self):
        with tempfile.TemporaryDirectory() as project:
            run_dir = os.path.join(project, "fm_agent", "runs", "run-2")
            os.makedirs(run_dir)
            marker = os.path.join(project, "fm_agent", "current_run.json")
            with open(marker, "w") as f:
                json.dump({"run_id": "run-2"}, f)
            self.assertEqual(str(_locate_workdir(project)), os.path.realpath(run_dir))

    def test_specific_run_directory_is_used_directly(self):
        with tempfile.TemporaryDirectory() as run_dir:
            os.makedirs(os.path.join(run_dir, "trace"))
            self.assertEqual(str(_locate_workdir(run_dir)), os.path.realpath(run_dir))

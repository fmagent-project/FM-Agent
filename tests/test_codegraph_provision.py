"""CodeGraph provisioning regressions, including native cross-process locking.

Run with: python -m unittest discover -s tests -v
Requires python-dotenv, pydantic-settings and openai; no LLM or network is used.
"""

import hashlib
import io
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest import mock
import zipfile

from src.languages import codegraph as cg
from src.extract import run_extraction
from src.file_utils import _get_phase_files
from src.generate_topdown_layers import _file_to_fqn
from src.incremental_reasoner import _extracted_files_by_method, _reconcile_extracted_dir


VERSION = "1.6.0-fmagent.6"
PACKAGE = "codegraph-win32-x64"


class ProvisionTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="fm codegraph tests ")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        configuration = SimpleNamespace(codegraph=SimpleNamespace(
            repo="fmagent-project/codegraph", version=f"v{VERSION}",
            install_dir=str(self.root), bin_dir=str(self.root / "external bin"),
        ))
        self.settings = mock.patch.object(cg, "settings", configuration)
        self.settings.start()
        self.addCleanup(self.settings.stop)
        cg._codegraph_cmd.cache_clear()
        self.addCleanup(cg._codegraph_cmd.cache_clear)

    def archive(self, members=None):
        output = io.BytesIO()
        with zipfile.ZipFile(output, "w") as archive:
            if members is None:
                members = [(f"{PACKAGE}/bin/codegraph.cmd", b"native launcher"),
                           (f"{PACKAGE}/node.exe", b"bundled runtime")]
            for name, contents in members:
                archive.writestr(name, contents)
        return output.getvalue()

    def transport(self, contents, checksum=None):
        digest = checksum or hashlib.sha256(contents).hexdigest()

        def open_url(url, timeout):
            self.assertEqual(timeout, 60)
            self.assertIn(f"/releases/download/v{VERSION}/", url)
            if url.endswith("/SHA256SUMS"):
                return io.BytesIO(f"{digest}  {PACKAGE}.zip\n".encode())
            self.assertTrue(url.endswith(f"/{PACKAGE}.zip"))
            return io.BytesIO(contents)

        return mock.patch.object(cg.urllib.request, "urlopen", side_effect=open_url)

    def old_bundle(self):
        old = self.root / "current"
        old.mkdir()
        (old / "keep.txt").write_text("existing working installation")

    def assert_old_preserved(self):
        self.assertEqual((self.root / "current/keep.txt").read_text(),
                         "existing working installation")
        self.assertEqual(list(self.root.glob(".provision-*")), [])

    def windows_install(self):
        with mock.patch.object(cg.platform, "machine", return_value="AMD64"):
            cg._install_windows_codegraph(VERSION, str(self.root))

    def test_windows_archive_installs_privately_and_replaces_old_bundle(self):
        self.old_bundle()
        environment = dict(os.environ)
        with self.transport(self.archive()), mock.patch.object(
                cg, "_codegraph_version_at", return_value=VERSION):
            self.windows_install()
        self.assertTrue((self.root / "current/bin/codegraph.cmd").is_file())
        self.assertFalse((self.root / "current/keep.txt").exists())
        self.assertEqual(list(self.root.glob(".previous-*")), [])
        self.assertEqual(list(self.root.glob(".provision-*")), [])
        self.assertEqual(dict(os.environ), environment)

    def test_download_failure_preserves_old_bundle(self):
        self.old_bundle()
        with mock.patch.object(cg.urllib.request, "urlopen", side_effect=OSError("offline")):
            with self.assertRaises(OSError):
                self.windows_install()
        self.assert_old_preserved()

    def test_checksum_failure_preserves_old_bundle(self):
        self.old_bundle()
        with self.transport(self.archive(), "0" * 64), self.assertRaises(ValueError):
            self.windows_install()
        self.assert_old_preserved()

    def test_wrong_version_preserves_old_bundle(self):
        self.old_bundle()
        with self.transport(self.archive()), mock.patch.object(
                cg, "_codegraph_version_at", return_value="wrong-version"):
            with self.assertRaises(ValueError):
                self.windows_install()
        self.assert_old_preserved()

    def test_missing_launcher_preserves_old_bundle(self):
        self.old_bundle()
        archive = self.archive([(f"{PACKAGE}/node.exe", b"runtime")])
        with self.transport(archive), mock.patch.object(cg, "_codegraph_version_at", return_value=VERSION):
            with self.assertRaises(ValueError):
                self.windows_install()
        self.assert_old_preserved()

    def test_invalid_zip_preserves_old_bundle(self):
        self.old_bundle()
        with self.transport(b"partial archive"), self.assertRaises(zipfile.BadZipFile):
            self.windows_install()
        self.assert_old_preserved()

    def test_unsafe_archive_paths_are_rejected(self):
        self.old_bundle()
        for name in (f"{PACKAGE}/../../escaped.txt", "/absolute.txt",
                     f"{PACKAGE}\\..\\escaped.txt", f"{PACKAGE}/file:stream", "other/file"):
            with self.subTest(name=name), self.transport(self.archive([(name, b"bad")])):
                with self.assertRaises(ValueError):
                    self.windows_install()
                self.assert_old_preserved()
        self.assertFalse((self.root.parent / "escaped.txt").exists())

    def test_archive_symlinks_are_rejected(self):
        self.old_bundle()
        output = io.BytesIO()
        with zipfile.ZipFile(output, "w") as archive:
            link = zipfile.ZipInfo(f"{PACKAGE}/bin/codegraph.cmd")
            link.create_system = 3
            link.external_attr = (stat.S_IFLNK | 0o777) << 16
            archive.writestr(link, "../../../outside")
        with self.transport(output.getvalue()), self.assertRaises(ValueError):
            self.windows_install()
        self.assert_old_preserved()

    def test_failed_promotion_restores_old_bundle(self):
        self.old_bundle()
        replace = os.replace

        def fail_promotion(source, destination):
            if Path(source).name == PACKAGE:
                raise PermissionError("bundle is busy")
            return replace(source, destination)

        with self.transport(self.archive()), mock.patch.object(
                cg, "_codegraph_version_at", return_value=VERSION), mock.patch.object(
                cg.os, "replace", side_effect=fail_promotion):
            with self.assertRaises(PermissionError):
                self.windows_install()
        self.assert_old_preserved()

    def test_failed_rollback_keeps_backup_outside_temporary_directory(self):
        self.old_bundle()
        replace = os.replace

        def fail_promotion_and_restore(source, destination):
            if Path(source).name == PACKAGE or Path(source).name.startswith(".previous-"):
                raise PermissionError("bundle is busy")
            return replace(source, destination)

        with self.transport(self.archive()), mock.patch.object(
                cg, "_codegraph_version_at", return_value=VERSION), mock.patch.object(
                cg.os, "replace", side_effect=fail_promotion_and_restore):
            with self.assertRaises(PermissionError):
                self.windows_install()
        backups = list(self.root.glob(".previous-*"))
        self.assertEqual(len(backups), 1)
        self.assertTrue((backups[0] / "keep.txt").is_file())
        self.assertEqual(list(self.root.glob(".provision-*")), [])

    def test_unsupported_architecture_does_not_download(self):
        with mock.patch.object(cg.platform, "machine", return_value="unsupported"), mock.patch.object(
                cg.urllib.request, "urlopen") as download, self.assertRaises(OSError):
            cg._install_windows_codegraph(VERSION, str(self.root))
        download.assert_not_called()

    def test_arm64_uses_native_release(self):
        archive = self.archive([("codegraph-win32-arm64/bin/codegraph.cmd", b"launcher")])
        urls = []

        def response(url, timeout):
            urls.append(url)
            return io.BytesIO(archive if url.endswith(".zip") else
                             f"{hashlib.sha256(archive).hexdigest()}  codegraph-win32-arm64.zip\n".encode())

        with mock.patch.object(cg.platform, "machine", return_value="ARM64"), mock.patch.object(
                cg.urllib.request, "urlopen", side_effect=response), mock.patch.object(
                cg, "_codegraph_version_at", return_value=VERSION):
            cg._install_windows_codegraph(VERSION, str(self.root))
        self.assertIn("codegraph-win32-arm64.zip", urls[0])
        self.assertTrue((self.root / "current/bin/codegraph.cmd").exists())

    def test_bundle_path_and_external_cmd_on_windows(self):
        external = self.root / "external bin/codegraph.cmd"
        external.parent.mkdir()
        external.write_text("launcher")
        external.chmod(0o755)
        with mock.patch.object(cg.sys, "platform", "win32"):
            self.assertEqual(cg._codegraph_bundle_binary(), str(self.root / "current/bin/codegraph.cmd"))
            self.assertEqual(cg._codegraph_installed_elsewhere(), str(external))

    def test_bundle_path_on_posix(self):
        with mock.patch.object(cg.sys, "platform", "linux"):
            self.assertEqual(cg._codegraph_bundle_binary(), str(self.root / "bin/codegraph"))

    def test_queued_installer_rechecks_version_without_downloading(self):
        with mock.patch.object(cg, "_codegraph_version_at", return_value=VERSION), mock.patch.object(
                cg.urllib.request, "urlopen") as download:
            self.assertTrue(cg._provision_codegraph(VERSION, cg._codegraph_bundle_binary()))
        download.assert_not_called()

    def test_lock_failure_returns_fallback_instead_of_raising(self):
        with mock.patch.object(cg, "_codegraph_install_lock", side_effect=OSError("denied")):
            self.assertFalse(cg._provision_codegraph(VERSION, "unused"))

    def test_windows_install_failure_returns_fallback(self):
        with mock.patch.object(cg.sys, "platform", "win32"), mock.patch.object(
                cg, "_codegraph_version_at", return_value=""), mock.patch.object(
                cg, "_install_windows_codegraph", side_effect=OSError("offline")):
            self.assertFalse(cg._provision_codegraph_locked(VERSION, "unused", str(self.root)))

    def test_posix_installer_uses_pinned_tag_and_private_directories(self):
        binary = str(self.root / "bin/codegraph")
        with mock.patch.object(cg.sys, "platform", "linux"), mock.patch.object(
                cg, "_codegraph_version_at", side_effect=["", VERSION]), mock.patch.object(
                cg.urllib.request, "urlopen", return_value=io.BytesIO(b"installer")) as download, mock.patch.object(
                cg.subprocess, "run", return_value=SimpleNamespace(returncode=0)) as run:
            self.assertTrue(cg._provision_codegraph_locked(VERSION, binary, str(self.root)))
        self.assertEqual(download.call_args.args[0],
                         f"https://raw.githubusercontent.com/fmagent-project/codegraph/v{VERSION}/install.sh")
        self.assertEqual(run.call_args.args[0], ["sh", "-s"])
        self.assertEqual(run.call_args.kwargs["env"]["CODEGRAPH_INSTALL_DIR"], str(self.root))
        self.assertEqual(run.call_args.kwargs["env"]["CODEGRAPH_BIN_DIR"], str(self.root / "bin"))

    def test_failed_provision_uses_matching_manual_installation(self):
        other = str(self.root / "manual/codegraph.cmd")
        with mock.patch.object(cg, "_codegraph_version_at", side_effect=["", VERSION]), mock.patch.object(
                cg, "_provision_codegraph", return_value=False), mock.patch.object(
                cg, "_codegraph_installed_elsewhere", return_value=other):
            self.assertEqual(cg._codegraph_cmd(), other)

    def test_failed_provision_without_manual_installation_allows_regex_fallback(self):
        with mock.patch.object(cg, "_codegraph_version_at", return_value=""), mock.patch.object(
                cg, "_provision_codegraph", return_value=False), mock.patch.object(
                cg, "_codegraph_installed_elsewhere", return_value=None):
            self.assertEqual(cg._codegraph_cmd(), "codegraph")

    def test_qualified_extraction_keeps_call_edge_identity_on_both_platforms(self):
        source = self.root / "network.py"
        source.write_text("class Sender:\n    def forward(self, x):\n        return x\n", encoding="utf-8")
        phases = {"phases": [{"phase": 1, "modules": [{"name": "network", "source_files": ["network.py"]}]}]}
        functions = [("Sender::forward", "    def forward(self, x):\n        # 中文注释\n        return x\n"),
                     ("Receiver::forward", "    def forward(self, x):\n        return x + 1\n")]
        for platform_name in ("win32", "linux"):
            if platform_name == "linux" and os.name == "nt":
                # POSIX flat names contain ':', which the native Windows
                # filesystem cannot create. The Linux CI job covers that layout.
                continue
            with self.subTest(platform=platform_name):
                work = self.root / platform_name
                work.mkdir()
                (work / "phases.json").write_text(json.dumps(phases), encoding="utf-8")
                with mock.patch("src.extract.batch_extract_all", return_value=({str(source): functions}, {"python"})), mock.patch.object(
                        sys, "platform", platform_name):
                    self.assertEqual(run_extraction(str(self.root), work_dir=str(work)), (2, 0))
                files = _get_phase_files(phases, 1, str(work / "extracted_functions"))
                self.assertEqual(len(files), 2)
                fqns = {_file_to_fqn(str(work / "extracted_functions" / file), str(work)) for file in files}
                self.assertEqual(fqns, {"network-py::Sender::forward", "network-py::Receiver::forward"})
                sender = next(work / "extracted_functions" / file for file in files if "Sender" in file)
                self.assertIn("中文注释", sender.read_text(encoding="utf-8"))

    def test_windows_incremental_keeps_qualified_functions_and_metadata(self):
        source = self.root / "network.py"
        source.write_text("class Sender:\n    def forward(self, x):\n        return x\n", encoding="utf-8")
        functions = self.root / "fm_agent/extracted_functions/network-py"
        valid = functions / "Sender/forward.py"
        orphan = functions / "Removed/forward.py"
        valid.parent.mkdir(parents=True)
        orphan.parent.mkdir(parents=True)
        valid.write_text("live function")
        orphan.write_text("orphan function")
        sidecars = [Path(str(valid) + suffix) for suffix in (".spec.json", ".info.json")]
        for path in sidecars:
            path.write_text("{}")
        index = _extracted_files_by_method(str(functions))
        self.assertEqual(index["Sender::forward"], [str(valid)])
        self.assertEqual(set(index["forward"]), {str(valid), str(orphan)})
        with mock.patch.object(sys, "platform", "win32"), mock.patch(
                "src.incremental_reasoner._function_spans",
                return_value=([("Sender::forward", 1, 2)], "source", True)):
            self.assertTrue(_reconcile_extracted_dir(str(self.root), str(source)))
        self.assertTrue(valid.exists())
        self.assertTrue(all(path.exists() for path in sidecars))
        self.assertFalse(orphan.exists())


class NativeLockTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="fm native lock ")
        self.addCleanup(self.temporary.cleanup)
        self.root = self.temporary.name
        self.processes = []
        self.addCleanup(self.stop_processes)

    def stop_processes(self):
        for process in self.processes:
            if process.poll() is None:
                process.kill()
            process.communicate(timeout=10)

    def worker(self, hold=False):
        script = (
            "import sys; from src.languages.codegraph import _codegraph_install_lock; "
            "print('WAITING', flush=True)\n"
            "with _codegraph_install_lock(sys.argv[1]):\n"
            " print('LOCKED', flush=True)\n"
            + (" sys.stdin.readline()\n" if hold else "")
        )
        process = subprocess.Popen([sys.executable, "-u", "-c", script, self.root],
                                   cwd=Path(__file__).resolve().parents[1], stdin=subprocess.PIPE,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        self.processes.append(process)
        self.assertEqual(process.stdout.readline().strip(), "WAITING")
        return process

    def test_native_lock_blocks_second_process_then_releases(self):
        with cg._codegraph_install_lock(self.root):
            process = self.worker()
            time.sleep(0.3)
            self.assertIsNone(process.poll())
        output, error = process.communicate(timeout=10)
        self.assertEqual(process.returncode, 0, error)
        self.assertEqual(output.strip(), "LOCKED")

    def test_native_lock_releases_when_owner_is_terminated(self):
        owner = self.worker(hold=True)
        self.assertEqual(owner.stdout.readline().strip(), "LOCKED")
        waiting = self.worker()
        time.sleep(0.3)
        self.assertIsNone(waiting.poll())
        owner.kill()
        owner.communicate(timeout=10)
        output, error = waiting.communicate(timeout=10)
        self.assertEqual(waiting.returncode, 0, error)
        self.assertEqual(output.strip(), "LOCKED")

    @unittest.skipUnless(sys.platform == "win32", "Windows LK_LOCK ten-second regression")
    def test_windows_lock_waits_longer_than_ten_seconds(self):
        with cg._codegraph_install_lock(self.root):
            process = self.worker()
            time.sleep(11)
            self.assertIsNone(process.poll())
        output, error = process.communicate(timeout=10)
        self.assertEqual(process.returncode, 0, error)
        self.assertEqual(output.strip(), "LOCKED")


if __name__ == "__main__":
    unittest.main()

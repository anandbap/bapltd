"""Build real native clients, stage them, and verify an isolated core installation."""
from contextlib import redirect_stdout
import io
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
import zipfile

from scripts import bap_install, build_wheel

ROOT = Path(__file__).resolve().parents[1]


class TestZSPReleaseInstall(unittest.TestCase):
    def test_real_native_edge_retains_inbox_through_staging_and_core_install(self):
        go = shutil.which("go")
        if not go:
            self.skipTest("Go is required for the native packaging integration test")
        platform_id = build_wheel.get_platform_id()
        ext = ".exe" if sys.platform == "win32" else ""
        with tempfile.TemporaryDirectory(prefix="bap-zsp-release-") as directory:
            fixture = Path(directory)
            canonical = fixture / "dist" / platform_id / "claude-client"
            canonical.mkdir(parents=True)
            for module, name, flags in (
                ("bap-edge", "bapedge", "-X bap-edge/pkg/version.AllowDevOverrides=false"),
                ("cchook", "interceptor", "-X main.AllowDevOverrides=false"),
            ):
                built = subprocess.run([go, "build", "-trimpath", "-tags=", "-ldflags", flags, "-o", str(canonical / (name + ext)), "."],
                                       cwd=ROOT / module, env=dict(os.environ, CGO_ENABLED="0"),
                                       capture_output=True, text=True, timeout=180)
                self.assertEqual(built.returncode, 0, built.stderr)
            package = fixture / "bap"
            with patch.object(build_wheel, "REPO_ROOT", str(fixture)), \
                 patch.object(build_wheel, "BAP_PKG_DIR", str(package)), \
                 patch.object(build_wheel, "BAP_BIN_DIR", str(package / "bin")), redirect_stdout(io.StringIO()):
                build_wheel.stage_binaries([platform_id])
            staged = package / "bin" / platform_id / ("bapedge" + ext)
            build_wheel.verify_zsp_inbox(str(staged))
            # Build an actual native fixture wheel using the repository's setup
            # and package-data declarations, rather than inventing a ZIP layout.
            shutil.copy2(ROOT / "setup.py", fixture / "setup.py")
            (fixture / "README.md").write_text("Isolated native packaging test fixture.\n", encoding="utf-8")
            for source in (ROOT / "bap").glob("*.py"):
                shutil.copy2(source, package / source.name)
            shutil.copy2(ROOT / "scripts/bap_install.py", package / "bap_install.py")
            wheel_result = subprocess.run([sys.executable, "setup.py", "bdist_wheel"], cwd=fixture,
                                          capture_output=True, text=True, timeout=90)
            self.assertEqual(wheel_result.returncode, 0, wheel_result.stdout + wheel_result.stderr)
            wheel = next((fixture / "dist").glob("*.whl"))
            unpacked = fixture / "unpacked"
            with zipfile.ZipFile(wheel) as archive:
                self.assertEqual(archive.read("bap/bap_install.py"), (ROOT / "scripts/bap_install.py").read_bytes())
                for member in archive.namelist():
                    if member.startswith("bap/") and member.endswith(".py"):
                        archive.extract(member, unpacked)
                for name in ("bapedge", "interceptor"):
                    member = f"bap/bin/{platform_id}/{name}{ext}"
                    archive.extract(member, unpacked)
                    if not ext:
                        (unpacked / member).chmod(0o755)
            package = unpacked / "bap"
            staged = package / "bin" / platform_id / ("bapedge" + ext)
            installed = fixture / "installed"
            # Exercise the real core copier, not machine-wide process stopping,
            # stale-install cleanup, hooks, trust pins, PATH or registry updates.
            with patch.object(bap_install, "REPO_ROOT", str(unpacked)), \
                 patch.object(bap_install, "__file__", str(package / "bap_install.py")), \
                 patch.object(bap_install, "stop_running_bap_processes"), \
                 patch.object(bap_install, "clean_stale_secondary_installations"), \
                 patch.object(bap_install.shutil, "which", return_value=None), redirect_stdout(io.StringIO()):
                self.assertGreater(bap_install.install_core_binaries(str(installed), portable=True), 0)
            binary = installed / ("bapedge" + ext)
            self.assertEqual(binary.read_bytes(), staged.read_bytes())
            build_wheel.verify_zsp_inbox(str(binary))
            identity = subprocess.run([str(binary), "version", "--json"], capture_output=True, text=True, timeout=10)
            self.assertEqual(identity.returncode, 0, identity.stderr)
            import json
            self.assertFalse(json.loads(identity.stdout)["allow_dev_overrides"])
            self.assertFalse(json.loads(identity.stdout)["headless_stepup"])
            home = fixture / "home"
            home.mkdir()
            env = dict(os.environ, PYTHONPATH=str(unpacked), HOME=str(home), USERPROFILE=str(home),
                       BAP_STATE_DIR=str(fixture / "state"), PATH=str(installed))
            routed = subprocess.run([sys.executable, "-m", "bap.cli", "zsp", "--help"],
                                    cwd=unpacked, env=env, capture_output=True, text=True, timeout=15)
            self.assertEqual(routed.returncode, 0, routed.stdout + routed.stderr)
            self.assertIn("inbox", routed.stdout)


if __name__ == "__main__":
    unittest.main()

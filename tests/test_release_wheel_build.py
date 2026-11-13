"""Exercise the real compiler: a wheel must never ship development override code."""
import os
from pathlib import Path
import platform
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from scripts import build_wheel


class TestReleaseWheelBuild(unittest.TestCase):
    def setUp(self):
        if not shutil.which("go"):
            self.skipTest("Go toolchain is required for release compilation tests")
        os_name = {"Windows":"windows", "Linux":"linux", "Darwin":"darwin"}.get(platform.system())
        arch = "arm64" if platform.machine().lower() in ("arm64", "aarch64") else "amd64"
        self.platform_id = f"{os_name}-{arch}"
        if self.platform_id not in build_wheel.PLATFORM_GO_MAP:
            self.skipTest("No native release target for this host")
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.ext = ".exe" if os_name == "windows" else ""
        for module in ("bap-edge", "cchook"):
            (self.root / module).mkdir()
            (self.root / module / "go.mod").write_text(f"module {module}\n\ngo 1.24.0\n", encoding="utf-8")
        version = self.root / "bap-edge/pkg/version"
        version.mkdir(parents=True)
        (version / "version.go").write_text('package version\nvar AllowDevOverrides = "true"\nvar GitCommit = "dev"\n', encoding="utf-8")
        (self.root / "bap-edge/main.go").write_text('package main\nimport ("fmt"; "bap-edge/pkg/version")\nfunc main(){fmt.Print(version.AllowDevOverrides)}\n', encoding="utf-8")
        (self.root / "cchook/main.go").write_text('package main\nimport "fmt"\nvar AllowDevOverrides = "true"\nfunc main(){fmt.Print(AllowDevOverrides)}\n', encoding="utf-8")
        for name, value in {"REPO_ROOT":str(self.root), "BAP_PKG_DIR":str(self.root / "bap"), "BAP_BIN_DIR":str(self.root / "bap/bin")}.items():
            mock = patch.object(build_wheel, name, value)
            mock.start()
            self.addCleanup(mock.stop)

    def test_official_build_compiles_override_out_and_ignores_newer_dev_copy(self):
        build_wheel.ensure_binaries([self.platform_id])
        canonical = self.root / "dist" / self.platform_id / "claude-client"
        for name in ("bapedge", "interceptor"):
            self.assertEqual(subprocess.check_output([str(canonical / (name + self.ext))], text=True, timeout=10), "false")
        # A separately rebuilt developer executable must not win by timestamp.
        dev = canonical.parent / ("bapedge" + self.ext)
        subprocess.run(["go", "build", "-o", str(dev), "."], cwd=self.root / "bap-edge", check=True, capture_output=True, timeout=60)
        future = dev.stat().st_mtime + 3600
        os.utime(dev, (future, future))
        build_wheel.stage_binaries([self.platform_id])
        packaged = self.root / "bap/bin" / self.platform_id / ("bapedge" + self.ext)
        self.assertEqual(subprocess.check_output([str(packaged)], text=True, timeout=10), "false")

    def test_failed_compilation_stops_packaging(self):
        (self.root / "cchook/main.go").write_text("invalid Go source", encoding="utf-8")
        with self.assertRaises(RuntimeError):
            build_wheel.ensure_binaries([self.platform_id])

    def test_release_build_requires_a_compiler(self):
        with patch.object(build_wheel.shutil, "which", return_value=None):
            with self.assertRaises(RuntimeError):
                build_wheel.ensure_binaries([self.platform_id])

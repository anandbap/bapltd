import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from scripts import bap_release
from scripts import bap_install
from scripts import build_wheel


class ReleaseProvenanceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="bap-release-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.paths = bap_release.component_paths(self.root / "bin", self.root / "package", self.root / "launchers", "windows-amd64")
        for key, path in self.paths.items():
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("synthetic " + key, encoding="utf-8")
        self.commit = "a" * 40
        identities = {name: {"commit": self.commit, "dirty": False} for name in ("edge", "interceptor")}
        self.manifest = bap_release.create_manifest("windows-amd64", self.paths, self.commit, identities)
        self.file = self.root / "bap-release.json"
        self.save()

    def save(self):
        self.file.write_text(json.dumps(self.manifest), encoding="utf-8")

    def test_exact_components_verified_without_claiming_signature(self):
        result = bap_release.verify_manifest(self.file, self.paths, "windows-amd64", True)
        self.assertTrue(result["source_qualified"])
        self.assertEqual(result["publisher_signature"], "not_checked")
        self.assertEqual(result["release_id"], self.manifest["release_id"])

    def test_stale_tampered_or_missing_component_rejected(self):
        self.paths["edge"].write_text("old binary with same version label", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "component mismatch"):
            bap_release.verify_manifest(self.file, self.paths, "windows-amd64")

    def test_manifest_digest_platform_and_component_allowlist(self):
        with self.assertRaises(ValueError):
            bap_release.verify_manifest(self.file, self.paths, "linux-amd64")
        self.manifest["files"]["../outside"] = {"sha256": "0" * 64, "size": 0}
        self.save()
        with self.assertRaisesRegex(ValueError, "component set"):
            bap_release.verify_manifest(self.file, self.paths, "windows-amd64")

    def test_unknown_or_dirty_source_fails_strict_gate(self):
        identities = {name: {"commit": self.commit, "dirty": True} for name in ("edge", "interceptor")}
        self.manifest = bap_release.create_manifest("windows-amd64", self.paths, self.commit, identities)
        self.save()
        self.assertFalse(bap_release.verify_manifest(self.file, self.paths, "windows-amd64")["source_qualified"])
        with self.assertRaisesRegex(ValueError, "source identity"):
            bap_release.verify_manifest(self.file, self.paths, "windows-amd64", True)

    def test_strict_install_fails_before_touching_existing_binaries(self):
        existing = self.root / "existing" / "bapedge.exe"
        existing.parent.mkdir()
        existing.write_text("old installation", encoding="utf-8")
        arguments = ["bap_install", "--offline", "--non-interactive", "--no-path", "--no-startup",
                     "--require-release-manifest", "--dir", str(existing.parent), "--workspace", str(self.root)]
        with patch("sys.argv", arguments), patch.object(bap_install, "inspect_release_sources", side_effect=ValueError("unqualified bundle")), patch.object(bap_install, "install_core_binaries") as deploy:
            with self.assertRaises(ValueError):
                bap_install.main()
            deploy.assert_not_called()
        self.assertEqual(existing.read_text(), "old installation")

    def test_wheel_manifest_is_written_for_the_staged_platform_components(self):
        package = self.root / "staged-package"
        binaries = package / "bin"
        paths = bap_release.component_paths(binaries / "windows-amd64", package, package / "launchers", "windows-amd64")
        for key, path in paths.items():
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("fixture staged " + key, encoding="utf-8")
        with patch.object(build_wheel, "BAP_BIN_DIR", str(binaries)), patch.object(build_wheel, "BAP_PKG_DIR", str(package)), patch.object(build_wheel.subprocess, "check_output", return_value=self.commit), patch.object(bap_release, "build_identity", return_value={"commit": self.commit, "dirty": False}):
            build_wheel.write_release_manifests(["windows-amd64"])
        manifest = binaries / "windows-amd64" / "bap-release.json"
        self.assertTrue(bap_release.verify_manifest(manifest, paths, "windows-amd64", True)["source_qualified"])


if __name__ == "__main__":
    unittest.main()

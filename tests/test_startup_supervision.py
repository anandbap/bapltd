"""Startup registration tests use a private registry mock, never this user's HKCU."""
import json
import os
from pathlib import Path
import sys
import tempfile
import types
import unittest
from unittest.mock import patch
from scripts import bap_startup


class Registry:
    HKEY_CURRENT_USER = 1
    KEY_SET_VALUE = 2
    KEY_QUERY_VALUE = 4
    REG_SZ = 1

    def __init__(self):
        self.values = {}
        self.denied = False

    def __enter__(self):
        return self

    def __exit__(self, *_):
        return False

    def CreateKeyEx(self, *_):
        if self.denied:
            raise PermissionError("synthetic registry restriction")
        return self

    def OpenKey(self, *_):
        return self

    def SetValueEx(self, key, name, reserved, kind, value):
        self.values[name] = value

    def QueryValueEx(self, key, name):
        if name not in self.values:
            raise FileNotFoundError(name)
        return self.values[name], self.REG_SZ

    def DeleteValue(self, key, name):
        del self.values[name]


class StartupSupervisionTests(unittest.TestCase):
    def test_packaged_installer_and_startup_match_the_release_sources(self):
        root = Path(__file__).resolve().parents[1]
        for name in ("bap_install.py", "bap_startup.py", "bap_doctor.py", "bap_release.py"):
            self.assertEqual((root / "bap" / name).read_bytes(), (root / "scripts" / name).read_bytes())

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="bap-startup-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.target = self.root / "binary folder with spaces"
        self.target.mkdir()
        (self.target / "bapedge.exe").write_text("synthetic fixture, never executed", encoding="utf-8")
        self.registry = Registry()
        for context in (patch.dict(os.environ, {"BAP_STATE_DIR": str(self.root / "state")}),
                        patch.object(sys, "platform", "win32"),
                        patch.dict(sys.modules, {"winreg": self.registry})):
            context.start()
            self.addCleanup(context.stop)

    def test_logon_command_quoted_idempotent_and_uses_master_config(self):
        for _ in range(2):
            result = bap_startup.configure_startup(str(self.target))
            self.assertTrue(result["registered"])
        command = self.registry.values[bap_startup.VALUE]
        self.assertTrue(command.startswith('"'))
        self.assertIn("daemon supervise -state-dir", command)
        self.assertNotIn("--server", command)
        self.assertNotIn("token", command)
        self.assertEqual(len(self.registry.values), 1)
        record = json.loads((self.root / "state" / "startup.json").read_text())
        self.assertEqual(record["scope"], "after_user_logon")

    def test_disable_removes_only_the_owned_installation(self):
        bap_startup.configure_startup(str(self.target))
        self.assertEqual(bap_startup.configure_startup(str(self.target), False)["status"], "disabled")
        self.assertNotIn(bap_startup.VALUE, self.registry.values)
        self.registry.values[bap_startup.VALUE] = "another installation command"
        self.assertEqual(bap_startup.configure_startup(str(self.target), False)["status"], "different_installation_preserved")
        self.assertEqual(self.registry.values[bap_startup.VALUE], "another installation command")

    def test_registration_failure_visible_and_unsupported_platform_honest(self):
        self.registry.denied = True
        result = bap_startup.configure_startup(str(self.target))
        self.assertFalse(result["registered"])
        self.assertEqual(result["status"], "registration_failed")
        with patch.object(sys, "platform", "linux"):
            self.assertEqual(bap_startup.configure_startup(str(self.target))["status"], "unsupported_platform")


if __name__ == "__main__":
    unittest.main()

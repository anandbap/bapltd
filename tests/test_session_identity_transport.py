import importlib.util
import pathlib
import time
import unittest
import urllib.request
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[1]


class SessionIdentityTransportTests(unittest.TestCase):
    def test_sdk_origin_binding_and_redirects(self):
        for relative in ("python-agent/bap_sdk.py", "python-agent/bap_sdk/client.py"):
            with self.subTest(module=relative):
                spec = importlib.util.spec_from_file_location("identity_fixture", ROOT / relative)
                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)
                module._identity_cache.update(
                    path="memory-fixture", until=time.monotonic() + 3600,
                    value={"server_url": "https://control.test", "session_token": "fixture-proof"},
                )
                with mock.patch.object(module, "get_bap_credentials_path", return_value="memory-fixture"):
                    self.assertEqual(module._workstation_headers("https://control.test/api/v1/sessions/heartbeat"), {"Authorization": "Bearer fixture-proof"})
                    self.assertEqual(module._workstation_headers("https://control.test.evil/api/v1/sessions/heartbeat"), {})
                    self.assertEqual(module._workstation_headers("https://other.test/api/v1/sessions/start"), {})
                request = urllib.request.Request("https://control.test/api/v1/sessions/start", headers={"Authorization": "Bearer fixture-proof"})
                with self.assertRaises(module.urllib.error.HTTPError):
                    module._IdentityRedirect().redirect_request(request, None, 302, "redirect", {}, "https://other.test/collect")

    def test_distributed_launcher_copies_match(self):
        groups = (
            ("bap/launchers/bap_launcher_engine.ps1", "bap/bap_launcher_engine.ps1", "scripts/bap_launcher_engine.ps1"),
            ("bap/launchers/run_claude_bap.ps1", "bap/run_claude_bap.ps1"),
            ("bap/launchers/run_claude_bap.bat", "bap/run_claude_bap.bat"),
            ("bap/bap_harness.py", "scripts/bap_harness.py"),
        )
        for group in groups:
            self.assertEqual(len({(ROOT / p).read_bytes() for p in group}), 1, group)


if __name__ == "__main__":
    unittest.main()

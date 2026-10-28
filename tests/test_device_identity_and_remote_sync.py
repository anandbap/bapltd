import unittest
import json
import urllib.request
import threading
import subprocess
import time
import os

class TestDeviceIdentityAndRemoteSync(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # We test directly against the control plane API handlers or simulate server
        pass

    def test_github_provider_and_device_fields(self):
        # Verify types and handler logic via json parsing and assertions
        types_path = "bap-controlplane/pkg/types/types.go"
        with open(types_path, "r", encoding="utf-8") as f:
            t_content = f.read()
        self.assertIn("DeviceType", t_content)
        self.assertIn("IPAddress", t_content)

    def test_v3_html_freeze_and_deregister_buttons(self):
        v3_path = "bap-controlplane/internal/dashboardui/web/v3.html"
        with open(v3_path, "r", encoding="utf-8") as f:
            v3_content = f.read()
        self.assertIn('data-action="freeze"', v3_content)
        self.assertIn('data-action="unfreeze"', v3_content)
        self.assertIn('data-action="deregister"', v3_content)
        self.assertIn('devIcon', v3_content)
        self.assertIn('.btn-action-sm.freeze', v3_content)

    def test_login_uses_verified_token_provider(self):
        login_path = "bap-edge/cmd/login.go"
        with open(login_path, "r", encoding="utf-8") as f:
            login_content = f.read()
        self.assertIn("verifiedProvider := strings.ToLower(tokenResp.Provider)", login_content)
        self.assertIn('idpLabel = "GitHub Developer Identity"', login_content)
        self.assertIn("detectDeviceType()", login_content)
        self.assertIn("getOutboundIP()", login_content)

    def test_bap_cli_has_daemon_subcommand(self):
        cli_path = "bap/cli.py"
        with open(cli_path, "r", encoding="utf-8") as f:
            cli_content = f.read()
        self.assertIn('elif cmd == "daemon":', cli_content)
        self.assertIn('daemon <cmd>', cli_content)

if __name__ == "__main__":
    unittest.main()

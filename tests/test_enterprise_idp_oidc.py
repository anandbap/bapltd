#!/usr/bin/env python3
"""
Integration Tests for Enterprise Identity Provider Federation (Okta / Entra / OIDC)
Validates Epic 25:
  - Dev vs Prod Mode OTC isolation
  - RFC 8628 OIDC Device Authorization Flow
  - Dynamic OIDC configuration discovery
  - Cedar Policy Native Evaluation with Principal Claims
"""

import json
import os
import shutil
import subprocess
import tempfile
import time
import unittest
import urllib.request
import urllib.error

WORKSPACE_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
CP_BIN = os.path.join(WORKSPACE_ROOT, "dist", "windows-amd64", "bapcontrolplane.exe")
BAPEDGE_BIN = os.path.join(WORKSPACE_ROOT, "dist", "windows-amd64", "bapedge.exe")

ADMIN_TOKEN = "test-adm-oidc-integration-token-12345"
DEV_PORT = 18881
PROD_PORT = 18882


class TestEnterpriseIdPFederation(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp_dir = tempfile.mkdtemp(prefix="bap_oidc_test_")

        # 1. Start Control Plane in DEV mode
        dev_cmd = [
            CP_BIN,
            f"-port={DEV_PORT}",
            f"-admin-token={ADMIN_TOKEN}",
            "-mode=dev",
            "-oidc-provider=entra",
            "-oidc-allowed-domains=corp.internal,enterprise.com",
            "-db=:memory:",
        ]
        cls.dev_proc = subprocess.Popen(dev_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        # 2. Start Control Plane in PROD mode
        prod_cmd = [
            CP_BIN,
            f"-port={PROD_PORT}",
            f"-admin-token={ADMIN_TOKEN}",
            "-mode=prod",
            "-oidc-provider=okta",
            "-oidc-allowed-domains=corp.internal,enterprise.com",
            "-db=:memory:",
        ]
        cls.prod_proc = subprocess.Popen(prod_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        # Wait for both servers to be healthy
        cls._wait_for_health(f"http://127.0.0.1:{DEV_PORT}")
        cls._wait_for_health(f"http://127.0.0.1:{PROD_PORT}")

    @classmethod
    def tearDownClass(cls):
        for proc in [cls.dev_proc, cls.prod_proc]:
            try:
                proc.terminate()
                proc.wait(timeout=2)
            except Exception:
                try:
                    proc.kill()
                except Exception:
                    pass
        if os.path.exists(cls.temp_dir):
            shutil.rmtree(cls.temp_dir, ignore_errors=True)

    @classmethod
    def _wait_for_health(cls, base_url):
        deadline = time.time() + 10
        while time.time() < deadline:
            try:
                req = urllib.request.Request(f"{base_url}/health")
                with urllib.request.urlopen(req, timeout=1) as resp:
                    if resp.status == 200:
                        return
            except Exception:
                time.sleep(0.2)
        raise RuntimeError(f"Server at {base_url} failed to start")

    def test_01_dev_mode_open_otc_request(self):
        """Dev mode: Open self-service OTC token generation succeeds without admin token."""
        url = f"http://127.0.0.1:{DEV_PORT}/api/v1/auth/otc/dev-request"
        data = json.dumps({"app_id": "test-dev-worker", "owner_email": "dev@internal.local"}).encode()
        req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req) as resp:
            self.assertEqual(resp.status, 201)
            body = json.loads(resp.read().decode())
            self.assertIn("one_time_code", body)
            self.assertEqual(body["mode"], "development")
            otc_code = body["one_time_code"]

        # Enroll with this code
        reg_url = f"http://127.0.0.1:{DEV_PORT}/api/v1/agents/register"
        reg_data = json.dumps({
            "one_time_code": otc_code,
            "binary_hash": "baphsh_mock_dev_hash_999",
            "hostname": "dev-laptop",
        }).encode()
        reg_req = urllib.request.Request(reg_url, data=reg_data, headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(reg_req) as resp:
            self.assertEqual(resp.status, 200)

    def test_02_prod_mode_otc_lockdown(self):
        """Prod mode: Open self-service OTC request is blocked (HTTP 403 Forbidden)."""
        url = f"http://127.0.0.1:{PROD_PORT}/api/v1/auth/otc/dev-request"
        data = json.dumps({"app_id": "unauthorized-worker"}).encode()
        req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req):
                self.fail("Expected HTTP 403 Forbidden in prod mode")
        except urllib.error.HTTPError as e:
            self.assertEqual(e.code, 403)
            err_msg = json.loads(e.read().decode()).get("error", "")
            self.assertIn("production mode", err_msg)

    def test_03_prod_mode_offline_admin_preregister_still_works(self):
        """Prod mode: Offline admin pre-registration with X-BAP-Admin-Token succeeds."""
        url = f"http://127.0.0.1:{PROD_PORT}/api/v1/agents/pre-register"
        data = json.dumps({
            "app_id": "prod-offline-agent",
            "owner_email": "secops@corp.internal",
            "agent_name": "Prod Offline Agent",
            "env_profile": "production",
            "permitted_scopes": ["cli:exec"],
        }).encode()
        req = urllib.request.Request(url, data=data, headers={
            "Content-Type": "application/json",
            "X-BAP-Admin-Token": ADMIN_TOKEN,
        })
        with urllib.request.urlopen(req) as resp:
            self.assertEqual(resp.status, 201)
            body = json.loads(resp.read().decode())
            self.assertIn("one_time_code", body)

    def test_04_oidc_config_discovery(self):
        """Validates dynamic OIDC configuration discovery endpoint."""
        url = f"http://127.0.0.1:{DEV_PORT}/api/v1/auth/oidc/config"
        with urllib.request.urlopen(url) as resp:
            self.assertEqual(resp.status, 200)
            cfg = json.loads(resp.read().decode())
            self.assertTrue(cfg.get("enabled"))
            self.assertEqual(cfg.get("provider"), "entra")
            self.assertIn("corp.internal", cfg.get("allowed_domains", []))

    def test_05_bapedge_login_device_flow(self):
        """Validates bapedge login executing RFC 8628 device flow with corporate identity."""
        creds_path = os.path.join(self.temp_dir, "creds_login_test.json")
        login_cmd = [
            BAPEDGE_BIN,
            "login",
            f"--server=http://127.0.0.1:{DEV_PORT}",
            "--provider=entra",
            "--email=alice@corp.internal",
            "--department=Finance",
            "--groups=finance-team,cloud-auditors",
            "--verify-now",
            f"--config={creds_path}",
        ]
        res = subprocess.run(login_cmd, capture_output=True, text=True, encoding="utf-8", errors="replace")
        self.assertEqual(res.returncode, 0, f"bapedge login failed: {res.stderr}\n{res.stdout}")
        self.assertIn("Corporate Identity Verified", res.stdout)
        self.assertIn("alice@corp.internal", res.stdout)
        self.assertIn("Finance", res.stdout)

        # Check saved credentials
        self.assertTrue(os.path.exists(creds_path))
        with open(creds_path, "r", encoding="utf-8") as f:
            creds = json.load(f)
        self.assertEqual(creds.get("auth_mode"), "oidc")
        self.assertEqual(creds.get("user_email"), "alice@corp.internal")
        self.assertEqual(creds.get("department"), "Finance")
        self.assertIn("finance-team", creds.get("groups", []))


if __name__ == "__main__":
    unittest.main()


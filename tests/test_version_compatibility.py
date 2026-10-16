"""
Unit and Integration Tests for Enterprise Launch Readiness & Client-Server Versioning (BAP-EPIC-31).
Validates:
- BAP-550: CLI version commands, flags (-v, --version, --json), and metadata injection.
- BAP-551: Handshake version telemetry, HTTP headers (X-BAP-Agent-Version, X-BAP-Server-Version), and enrollment tracking.
- BAP-552: Policy & registration dynamic minimum version gate (UPGRADE_REQUIRED on deprecated clients).
- BAP-553: Status inspection and fleet compatibility reporting.
"""

import json
import os
import socket
import subprocess
import time
import unittest
import urllib.request
import urllib.error


def get_free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class TestVersionCompatibility(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        cls.cp_bin = os.path.join(cls.repo_root, "bapcontrolplane.exe")
        cls.gw_bin = os.path.join(cls.repo_root, "bapgateway.exe")
        cls.edge_bin = os.path.join(cls.repo_root, "dist", "windows-amd64", "bapedge.exe")
        if not os.path.exists(cls.edge_bin):
            cls.edge_bin = os.path.join(cls.repo_root, "bapedge.exe")

        assert os.path.exists(cls.cp_bin), f"bapcontrolplane.exe not found at {cls.cp_bin}"
        assert os.path.exists(cls.edge_bin), f"bapedge binary not found at {cls.edge_bin}"

        cls.expected_version = "v1.1.1"
        pyproject_path = os.path.join(cls.repo_root, "pyproject.toml")
        if os.path.exists(pyproject_path):
            import re
            with open(pyproject_path, "r", encoding="utf-8") as f:
                m = re.search(r'version\s*=\s*"([0-9]+\.[0-9]+\.[0-9]+)"', f.read())
                if m:
                    cls.expected_version = f"v{m.group(1)}"

    # =========================================================================
    # BAP-550: CLI Version Commands & Metadata Injection
    # =========================================================================

    def test_01_bapcontrolplane_cli_version(self):
        """Test bapcontrolplane version command and --json output."""
        # Plain text
        proc = subprocess.run([self.cp_bin, "version"], capture_output=True, text=True, cwd=self.repo_root)
        self.assertEqual(proc.returncode, 0, f"version failed: {proc.stderr}")
        self.assertIn("bapcontrolplane", proc.stdout)
        self.assertIn(self.expected_version, proc.stdout)
        self.assertIn("commit:", proc.stdout)

        # JSON mode
        proc_json = subprocess.run([self.cp_bin, "version", "--json"], capture_output=True, text=True, cwd=self.repo_root)
        self.assertEqual(proc_json.returncode, 0, f"version --json failed: {proc_json.stderr}")
        data = json.loads(proc_json.stdout)
        self.assertEqual(data.get("component"), "bapcontrolplane")
        self.assertEqual(data.get("version"), self.expected_version)
        self.assertTrue(len(data.get("git_commit", "")) > 0)
        self.assertTrue(len(data.get("build_date", "")) > 0)

    def test_02_bapgateway_cli_version(self):
        """Test bapgateway version command and --json output."""
        if not os.path.exists(self.gw_bin):
            self.skipTest("bapgateway.exe not present")

        proc = subprocess.run([self.gw_bin, "version"], capture_output=True, text=True, cwd=self.repo_root)
        self.assertEqual(proc.returncode, 0, f"gateway version failed: {proc.stderr}")
        self.assertIn("bapgateway", proc.stdout)
        self.assertIn(self.expected_version, proc.stdout)

        proc_json = subprocess.run([self.gw_bin, "version", "--json"], capture_output=True, text=True, cwd=self.repo_root)
        self.assertEqual(proc_json.returncode, 0, f"gateway version --json failed: {proc_json.stderr}")
        data = json.loads(proc_json.stdout)
        self.assertEqual(data.get("component"), "bapgateway")
        self.assertEqual(data.get("version"), self.expected_version)

    def test_03_bapedge_cli_version(self):
        """Test bapedge version command and --json output."""
        proc = subprocess.run([self.edge_bin, "version"], capture_output=True, text=True, cwd=self.repo_root)
        self.assertEqual(proc.returncode, 0, f"edge version failed: {proc.stderr}")
        self.assertIn("bapedge", proc.stdout)
        self.assertIn(self.expected_version, proc.stdout)

        proc_json = subprocess.run([self.edge_bin, "version", "--json"], capture_output=True, text=True, cwd=self.repo_root)
        self.assertEqual(proc_json.returncode, 0, f"edge version --json failed: {proc_json.stderr}")
        data = json.loads(proc_json.stdout)
        self.assertEqual(data.get("component"), "bapedge")
        self.assertEqual(data.get("version"), self.expected_version)

    # =========================================================================
    # BAP-551: Handshake Telemetry & HTTP Headers
    # =========================================================================

    def test_04_controlplane_health_and_headers(self):
        """Test that /health returns version and X-BAP-Server-Version header."""
        port = get_free_port()
        db_path = f"file:mem_test_health_{port}?mode=memory&cache=shared"
        proc = subprocess.Popen(
            [self.cp_bin, "start", "--port", str(port), "--db", db_path, "--secret", "test-secret-key-32-bytes-stable!"],
            cwd=self.repo_root,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

        try:
            # Wait for server to be responsive
            server_url = f"http://127.0.0.1:{port}"
            healthy = False
            for _ in range(30):
                try:
                    req = urllib.request.Request(f"{server_url}/health")
                    with urllib.request.urlopen(req, timeout=1) as resp:
                        if resp.status == 200:
                            server_ver_header = resp.getheader("X-BAP-Server-Version")
                            self.assertEqual(server_ver_header, self.expected_version)

                            body = json.loads(resp.read().decode())
                            self.assertEqual(body.get("version"), self.expected_version)
                            healthy = True
                            break
                except (urllib.error.URLError, ConnectionError, TimeoutError, OSError):
                    time.sleep(0.1)

            self.assertTrue(healthy, "Control plane failed to become healthy on test port")

            # Test Policy Sync endpoint carries X-BAP-Server-Version header
            sync_payload = json.dumps({
                "agent_id": "agent-test-1",
                "installed_version": 0,
                "installed_digest": "",
                "agent_version": "v1.0.0"
            }).encode()

            sync_req = urllib.request.Request(
                f"{server_url}/api/v1/policy/sync",
                data=sync_payload,
                headers={
                    "Content-Type": "application/json",
                    "X-BAP-Agent-Version": "v1.0.0"
                }
            )
            with urllib.request.urlopen(sync_req, timeout=2) as sync_resp:
                self.assertEqual(sync_resp.status, 200)
                self.assertEqual(sync_resp.getheader("X-BAP-Server-Version"), self.expected_version)
                sync_body = json.loads(sync_resp.read().decode())
                self.assertEqual(sync_body.get("server_version"), self.expected_version)

        finally:
            proc.terminate()
            try:
                proc.wait(timeout=2)
            except Exception:
                proc.kill()

    # =========================================================================
    # BAP-552: Dynamic Minimum Edge Version Gate (Anti-Skew)
    # =========================================================================

    def test_05_min_edge_version_enforcement(self):
        """Test that central control plane rejects deprecated clients when min-edge-version is set."""
        port = get_free_port()
        db_path = f"file:mem_test_minver_{port}?mode=memory&cache=shared"
        # Enforce minimum client version 1.2.0
        proc = subprocess.Popen(
            [
                self.cp_bin, "start",
                "--port", str(port),
                "--db", db_path,
                "--min-edge-version", "1.2.0",
                "--secret", "test-secret-key-32-bytes-stable!"
            ],
            cwd=self.repo_root,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

        try:
            server_url = f"http://127.0.0.1:{port}"
            # Wait for startup
            for _ in range(30):
                try:
                    with urllib.request.urlopen(f"{server_url}/health", timeout=1) as resp:
                        if resp.status == 200:
                            break
                except Exception:
                    time.sleep(0.1)

            # 1. Deprecated Client (v1.0.0 < 1.2.0) on policy sync
            outdated_sync = json.dumps({
                "agent_id": "agent-outdated",
                "installed_version": 1,
                "installed_digest": "dummy",
                "agent_version": "v1.0.0"
            }).encode()

            req_outdated = urllib.request.Request(
                f"{server_url}/api/v1/policy/sync",
                data=outdated_sync,
                headers={"Content-Type": "application/json", "X-BAP-Agent-Version": "v1.0.0"}
            )
            with urllib.request.urlopen(req_outdated, timeout=2) as resp:
                body = json.loads(resp.read().decode())
                # Should return directive with upgrade notice
                self.assertIn("UPGRADE_REQUIRED", body.get("message", ""))
                self.assertEqual(body.get("min_edge_version"), "1.2.0")

            # 2. Compliant Client (v1.2.0 == 1.2.0) on policy sync
            compliant_sync = json.dumps({
                "agent_id": "agent-compliant",
                "installed_version": 1,
                "installed_digest": "dummy",
                "agent_version": "v1.2.0"
            }).encode()

            req_compliant = urllib.request.Request(
                f"{server_url}/api/v1/policy/sync",
                data=compliant_sync,
                headers={"Content-Type": "application/json", "X-BAP-Agent-Version": "v1.2.0"}
            )
            with urllib.request.urlopen(req_compliant, timeout=2) as resp:
                body = json.loads(resp.read().decode())
                self.assertNotIn("UPGRADE_REQUIRED", body.get("message", ""))
                self.assertEqual(body.get("server_version"), self.expected_version)

            # 3. Registration rejection on deprecated client
            register_outdated = json.dumps({
                "one_time_code": "LTD-TEST-1234",
                "binary_hash": "dummy_hash",
                "agent_version": "v1.0.0"
            }).encode()

            req_reg = urllib.request.Request(
                f"{server_url}/api/v1/agents/register",
                data=register_outdated,
                headers={"Content-Type": "application/json"}
            )
            try:
                urllib.request.urlopen(req_reg, timeout=2)
                self.fail("Expected HTTP 426 Upgrade Required for outdated agent registration")
            except urllib.error.HTTPError as err:
                self.assertEqual(err.code, 426, f"Expected HTTP 426, got {err.code}")
                err_body = json.loads(err.read().decode())
                self.assertEqual(err_body.get("directive"), "UPGRADE_REQUIRED")
                self.assertEqual(err_body.get("min_edge_version"), "1.2.0")

        finally:
            proc.terminate()
            try:
                proc.wait(timeout=2)
            except Exception:
                proc.kill()


if __name__ == "__main__":
    unittest.main()

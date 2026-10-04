"""
Shadow IT & Unmanaged Asset Discovery Integration Test Suite.
=============================================================
Validates BAP's automated discovery engine for detecting:
1. Unmanaged local MCP servers (stdio & HTTP) across developer environments.
2. Unmanaged standing credentials in environment variables (AWS, OpenAI, DB strings).
3. Exposed or unprotected .env configuration files in workspace directories.
4. Risk scoring, severity categorization, and remediation recommendations.
5. Control Plane REST API endpoints (/api/v1/discovery/shadow-it/*).
"""

import concurrent.futures
import json
import os
import shutil
import subprocess
import tempfile
import time
import unittest
import urllib.error
import urllib.request

WORKSPACE_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
CONTROL_PLANE_BIN = os.path.join(WORKSPACE_ROOT, "dist", "windows-amd64", "bapcontrolplane.exe")

TEST_SECRET = "shadow-it-discovery-test-secret-32b!"
TEST_ADMIN_TOKEN = "shadow-it-admin-token-123456"
CP_PORT = 19255
CP_URL = f"http://127.0.0.1:{CP_PORT}"


def http_req(url, method="GET", data=None, headers=None, retries=2):
    """Robust HTTP request helper with connection close and retries."""
    hdrs = dict(headers or {})
    if "Connection" not in hdrs:
        hdrs["Connection"] = "close"
    body_bytes = None
    if data is not None:
        if isinstance(data, (dict, list)):
            body_bytes = json.dumps(data).encode("utf-8")
            if "Content-Type" not in hdrs:
                hdrs["Content-Type"] = "application/json"
        elif isinstance(data, str):
            body_bytes = data.encode("utf-8")
        else:
            body_bytes = data

    for attempt in range(retries):
        req = urllib.request.Request(url, data=body_bytes, headers=hdrs, method=method)
        try:
            with urllib.request.urlopen(req, timeout=5) as resp:
                raw = resp.read()
                parsed = {}
                try:
                    parsed = json.loads(raw.decode("utf-8"))
                except Exception:
                    pass
                return resp.status, parsed, raw
        except urllib.error.HTTPError as e:
            raw = e.read()
            parsed = {}
            try:
                parsed = json.loads(raw.decode("utf-8"))
            except Exception:
                pass
            return e.code, parsed, raw
        except Exception:
            if attempt == retries - 1:
                raise
            time.sleep(0.15)


class TestShadowITDiscovery(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp_dir = tempfile.mkdtemp(prefix="bap_shadow_it_test_")
        cls.db_path = os.path.join(cls.temp_dir, "test_shadow_it.db")
        cls.worm_path = os.path.join(cls.temp_dir, "worm_audit")
        os.makedirs(cls.worm_path, exist_ok=True)

        env = os.environ.copy()
        env["BAP_SECRET_KEY"] = TEST_SECRET
        env["BAP_ADMIN_TOKEN"] = TEST_ADMIN_TOKEN

        cls.cp_proc = subprocess.Popen(
            [
                CONTROL_PLANE_BIN,
                "-port", str(CP_PORT),
                "-secret", TEST_SECRET,
                "-admin-token", TEST_ADMIN_TOKEN,
                "-allow-remote-admin",
                "-db", cls.db_path,
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            env=env,
            cwd=WORKSPACE_ROOT,
        )

        ready = False
        for _ in range(30):
            try:
                status, _, _ = http_req(f"{CP_URL}/health")
                if status == 200:
                    ready = True
                    break
            except Exception:
                pass
            time.sleep(0.15)

        if not ready:
            if cls.cp_proc:
                cls.cp_proc.terminate()
            raise RuntimeError(f"Control Plane failed to start on port {CP_PORT}")

    @classmethod
    def tearDownClass(cls):
        if hasattr(cls, "cp_proc") and cls.cp_proc:
            cls.cp_proc.terminate()
            try:
                cls.cp_proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                cls.cp_proc.kill()
        if os.path.exists(cls.temp_dir):
            shutil.rmtree(cls.temp_dir, ignore_errors=True)

    def test_01_empty_scan_returns_valid_report(self):
        """Clean scan with no shadow IT assets returns empty findings list."""
        status, report, _ = http_req(
            f"{CP_URL}/api/v1/discovery/shadow-it/scan",
            method="POST",
            data={"workspace_root": self.temp_dir, "env_map": {}},
        )
        self.assertEqual(status, 200)
        self.assertIn("scan_id", report)
        self.assertIn("findings", report)
        self.assertIsInstance(report["findings"], list)

    def test_02_detects_unmanaged_standing_environment_variables(self):
        """Detects high/critical standing API keys and DB credentials bypassing BAP."""
        synthetic_env = {
            "AWS_SECRET_ACCESS_KEY": "AKIAEXAMPLEUNGOVERNEDKEY12345",
            "OPENAI_API_KEY": "sk-proj-supersecretrawllmkey1234567890",
            "DATABASE_URL": "postgres://admin:secret@prod-db.internal:5432/finance",
            "SAFE_PUBLIC_VAR": "production_cluster_east",
        }

        status, report, _ = http_req(
            f"{CP_URL}/api/v1/discovery/shadow-it/scan",
            method="POST",
            data={"env_map": synthetic_env},
        )
        self.assertEqual(status, 200)
        self.assertGreaterEqual(report["unmanaged_env_var_count"], 3)
        self.assertGreaterEqual(report["critical_count"], 3)

        targets = [f["target"] for f in report["findings"]]
        self.assertIn("AWS_SECRET_ACCESS_KEY", targets)
        self.assertIn("OPENAI_API_KEY", targets)
        self.assertIn("DATABASE_URL", targets)
        self.assertNotIn("SAFE_PUBLIC_VAR", targets)

        # Verify actionable remediation guidance is populated
        for f in report["findings"]:
            if f["target"] == "AWS_SECRET_ACCESS_KEY":
                self.assertEqual(f["risk_level"], "CRITICAL")
                self.assertIn("BAP Ephemeral Bounded Grants", f["remediation"])
            elif f["target"] == "OPENAI_API_KEY":
                self.assertEqual(f["risk_level"], "CRITICAL")
                self.assertIn("BAP Gateway PEP", f["remediation"])

    def test_03_detects_unmanaged_mcp_servers(self):
        """Detects shadow MCP servers defined in local config files."""
        # Create a mock claude_desktop_config.json in temp_dir
        mcp_cfg_path = os.path.join(self.temp_dir, "claude_desktop_config.json")
        mcp_data = {
            "mcpServers": {
                "shadow-filesystem": {
                    "command": "npx",
                    "args": ["-y", "@modelcontextprotocol/server-filesystem", "C:\\SensitiveData"],
                },
                "rogue-database-mcp": {
                    "command": "python",
                    "args": ["-m", "mcp_sql_server", "--conn", "postgres://localhost/shadow"],
                },
            }
        }
        with open(mcp_cfg_path, "w", encoding="utf-8") as f:
            json.dump(mcp_data, f)

        status, report, _ = http_req(
            f"{CP_URL}/api/v1/discovery/shadow-it/scan",
            method="POST",
            data={"config_paths": [mcp_cfg_path], "env_map": {}},
        )
        self.assertEqual(status, 200)
        self.assertGreaterEqual(report["unmanaged_mcp_count"], 2)

        mcp_findings = [f for f in report["findings"] if f["type"] == "UNMANAGED_LOCAL_MCP_SERVER"]
        names = [f["name"] for f in mcp_findings]
        self.assertTrue(any("shadow-filesystem" in n for n in names))
        self.assertTrue(any("rogue-database-mcp" in n for n in names))

        for f in mcp_findings:
            self.assertIn(f["risk_level"], ["HIGH", "CRITICAL"])
            self.assertIn("BAP", f["remediation"])
            self.assertFalse(f["is_managed_by_bap"])

    def test_04_detects_unprotected_env_files(self):
        """Detects sensitive .env and credentials files stored in workspaces."""
        project_dir = os.path.join(self.temp_dir, "agent_project")
        os.makedirs(project_dir, exist_ok=True)

        env_file = os.path.join(project_dir, ".env")
        with open(env_file, "w", encoding="utf-8") as f:
            f.write("PROD_SECRET=unencrypted_standing_key_xyz\nDB_PASS=rawpass123\n")

        status, report, _ = http_req(
            f"{CP_URL}/api/v1/discovery/shadow-it/scan",
            method="POST",
            data={"workspace_root": project_dir, "env_map": {}},
        )
        self.assertEqual(status, 200)
        self.assertGreaterEqual(report["unprotected_file_count"], 1)

        file_findings = [f for f in report["findings"] if f["type"] == "UNPROTECTED_ENV_FILE"]
        self.assertTrue(any(".env" in f["name"] for f in file_findings))

    def test_05_query_findings_and_historical_reports(self):
        """Findings and reports are indexed and retrievable via GET endpoints."""
        status, findings_resp, _ = http_req(f"{CP_URL}/api/v1/discovery/shadow-it/findings")
        self.assertEqual(status, 200)
        self.assertIn("findings", findings_resp)
        self.assertGreater(findings_resp["count"], 0)

        status, reports_resp, _ = http_req(f"{CP_URL}/api/v1/discovery/shadow-it/reports")
        self.assertEqual(status, 200)
        self.assertIn("reports", reports_resp)
        self.assertGreater(reports_resp["count"], 0)

    def test_06_trigger_fleet_scan_advances_epoch(self):
        """POST /api/v1/discovery/shadow-it/scan/trigger advances the fleet scan epoch."""
        status1, resp1, _ = http_req(f"{CP_URL}/api/v1/discovery/shadow-it/scan/trigger", method="POST")
        self.assertEqual(status1, 200)
        self.assertEqual(resp1["status"], "success")
        epoch1 = resp1["scan_epoch"]
        self.assertGreater(epoch1, 0)

        status2, resp2, _ = http_req(f"{CP_URL}/api/v1/discovery/shadow-it/scan/trigger", method="POST")
        self.assertEqual(status2, 200)
        epoch2 = resp2["scan_epoch"]
        self.assertGreater(epoch2, epoch1)

    def test_07_heartbeat_sync_epoch_distribution(self):
        """Laptops checking in via heartbeat receive updated scan_epoch directives."""
        session_id = "test-sync-laptop-042"
        # 1. Start a session
        start_status, _, _ = http_req(
            f"{CP_URL}/api/v1/sessions/start",
            method="POST",
            data={
                "session_id": session_id,
                "app_id": "claude-code",
                "user_id": "alice-dev",
                "hostname": "macbook-pro-alice",
            },
        )
        self.assertEqual(start_status, 200)

        # 2. Heartbeat receives initial epoch
        hb_status1, hb_resp1, _ = http_req(
            f"{CP_URL}/api/v1/sessions/heartbeat",
            method="POST",
            data={"session_id": session_id},
        )
        self.assertEqual(hb_status1, 200)
        self.assertIn("scan_epoch", hb_resp1)
        initial_epoch = hb_resp1["scan_epoch"]

        # 3. Control Plane triggers a fleet discovery scan
        trig_status, trig_resp, _ = http_req(
            f"{CP_URL}/api/v1/discovery/shadow-it/scan/trigger",
            method="POST",
        )
        self.assertEqual(trig_status, 200)
        new_epoch = trig_resp["scan_epoch"]
        self.assertGreater(new_epoch, initial_epoch)

        # 4. Next laptop heartbeat immediately picks up the new scan_epoch
        hb_status2, hb_resp2, _ = http_req(
            f"{CP_URL}/api/v1/sessions/heartbeat",
            method="POST",
            data={"session_id": session_id},
        )
        self.assertEqual(hb_status2, 200)
        self.assertEqual(hb_resp2["scan_epoch"], new_epoch)

    def test_08_multi_agent_fleet_volume_concurrency(self):
        """Simulates 30 concurrent developer laptops heartbeating and reporting findings under load."""
        concurrency = 30
        errors = []

        def simulate_laptop(idx):
            sid = f"agent-load-{idx}"
            try:
                # Start session
                s_stat, _, _ = http_req(
                    f"{CP_URL}/api/v1/sessions/start",
                    method="POST",
                    data={"session_id": sid, "app_id": "claude-code", "user_id": f"dev-{idx}", "hostname": f"laptop-{idx}"},
                )
                if s_stat != 200:
                    return f"start failed for {sid}: {s_stat}"

                # Heartbeat
                hb_stat, hb_data, _ = http_req(
                    f"{CP_URL}/api/v1/sessions/heartbeat",
                    method="POST",
                    data={"session_id": sid},
                )
                if hb_stat != 200:
                    return f"heartbeat failed for {sid}: {hb_stat}"

                # Report local findings
                scan_stat, _, _ = http_req(
                    f"{CP_URL}/api/v1/discovery/shadow-it/scan",
                    method="POST",
                    data={
                        "agent_id": sid,
                        "hostname": f"laptop-{idx}",
                        "client_findings": [
                            {
                                "id": f"find-{sid}-env",
                                "type": "UNMANAGED_ENV_VARIABLE",
                                "name": "Local AWS Secret",
                                "target": "AWS_SECRET_ACCESS_KEY",
                                "risk_level": "CRITICAL",
                            }
                        ],
                    },
                )
                if scan_stat != 200:
                    return f"scan report failed for {sid}: {scan_stat}"

                return None
            except Exception as e:
                return f"exception for {sid}: {e}"

        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(simulate_laptop, i) for i in range(concurrency)]
            for fut in concurrent.futures.as_completed(futures):
                err = fut.result()
                if err:
                    errors.append(err)

        self.assertEqual(len(errors), 0, f"Encountered errors during volume concurrency: {errors}")

    def test_09_resilience_to_malformed_and_oversized_payloads(self):
        """Control plane handles corrupted, empty, and oversized payloads gracefully without crashing."""
        # Malformed JSON body
        status1, _, _ = http_req(
            f"{CP_URL}/api/v1/discovery/shadow-it/scan",
            method="POST",
            data="{not_valid_json: 123",
            headers={"Content-Type": "application/json"},
        )
        # Should return 200 (defaults to empty ScanRequest) or 400 without crashing
        self.assertIn(status1, [200, 400])

        # Huge payload
        huge_target = "X" * 50000
        status2, resp2, _ = http_req(
            f"{CP_URL}/api/v1/discovery/shadow-it/scan",
            method="POST",
            data={
                "agent_id": "resilience-test-agent",
                "client_findings": [
                    {
                        "type": "UNMANAGED_ENV_VARIABLE",
                        "target": huge_target,
                        "name": "Huge Payload Key",
                        "risk_level": "HIGH",
                    }
                ],
            },
        )
        self.assertEqual(status2, 200)

        # Verify server remains fully healthy
        health_status, _, _ = http_req(f"{CP_URL}/health")
        self.assertEqual(health_status, 200)

    def test_10_durability_and_deduplication(self):
        """Repeated findings from the same agent/target are deduplicated and updated in place."""
        dedup_agent = "agent-dedup-verify"
        for _ in range(5):
            status, _, _ = http_req(
                f"{CP_URL}/api/v1/discovery/shadow-it/scan",
                method="POST",
                data={
                    "agent_id": dedup_agent,
                    "hostname": "workstation-dedup",
                    "client_findings": [
                        {
                            "type": "UNMANAGED_ENV_VARIABLE",
                            "target": "DEDUP_TEST_KEY",
                            "name": "Test Key for Dedup",
                            "risk_level": "CRITICAL",
                        }
                    ],
                },
            )
            self.assertEqual(status, 200)

        # Query all findings
        status, data, _ = http_req(f"{CP_URL}/api/v1/discovery/shadow-it/findings")
        self.assertEqual(status, 200)
        matching = [
            f for f in data.get("findings", [])
            if f.get("agent_id") == dedup_agent and f.get("target") == "DEDUP_TEST_KEY"
        ]
        # Must be exactly 1 finding due to deduplication, NOT 5!
        self.assertEqual(len(matching), 1, f"Expected exactly 1 deduplicated finding, found {len(matching)}")


if __name__ == "__main__":
    unittest.main()


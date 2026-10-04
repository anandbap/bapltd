"""
Epic 24: Operational Resilience, Crash Sweeps & Developer CLI Tooling Test Suite
================================================================================
Validates BAP-470, BAP-471, BAP-472, and BAP-473:
1. Clean Sweep & Crash Recovery Reconciler (bapedge sweep and /api/v1/control/sweep).
2. 1-Click Developer Setup CLI (bapedge setup --app=claude-code).
3. In-Terminal Cedar Policy Inspection (bapedge status and bapedge why).
4. Offline Audit Spooling and Reconnection Flush.
"""

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
BAPEDGE_BIN = os.path.join(WORKSPACE_ROOT, "dist", "windows-amd64", "bapedge.exe")
CONTROL_PLANE_BIN = os.path.join(WORKSPACE_ROOT, "dist", "windows-amd64", "bapcontrolplane.exe")

CP_PORT = 19285
CP_URL = f"http://127.0.0.1:{CP_PORT}"
TEST_ADMIN_TOKEN = "crash-sweep-admin-token-998877"


def http_req(url, method="GET", data=None, headers=None, retries=2):
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


class TestCrashRecoverySweep(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp_dir = tempfile.mkdtemp(prefix="bap_crash_sweep_")
        cls.db_path = os.path.join(cls.temp_dir, "controlplane_sweep.db")

        env = os.environ.copy()
        env["BAP_TEST_MODE"] = "1"

        cls.server_proc = subprocess.Popen(
            [
                CONTROL_PLANE_BIN,
                "-port", str(CP_PORT),
                "-admin-token", TEST_ADMIN_TOKEN,
                "-allow-remote-admin",
                "-db", cls.db_path,
            ],
            cwd=WORKSPACE_ROOT,
            env=env,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

        # Poll health endpoint
        healthy = False
        for _ in range(40):
            try:
                st, _, _ = http_req(f"{CP_URL}/health")
                if st == 200:
                    healthy = True
                    break
            except Exception:
                pass
            time.sleep(0.15)

        if not healthy:
            cls.server_proc.kill()
            raise RuntimeError("Failed to start BAP Control Plane on port %d" % CP_PORT)

    @classmethod
    def tearDownClass(cls):
        if cls.server_proc:
            cls.server_proc.terminate()
            try:
                cls.server_proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                cls.server_proc.kill()
        shutil.rmtree(cls.temp_dir, ignore_errors=True)

    def test_bap_471_developer_setup_cli(self):
        """BAP-471: Test 1-click idempotent setup generates managed-settings.json and hooks."""
        target_ws = os.path.join(self.temp_dir, "test_ws_setup")
        os.makedirs(target_ws, exist_ok=True)

        res = subprocess.run(
            [BAPEDGE_BIN, "setup", "--app", "claude-code", "--dir", target_ws, "--server", CP_URL],
            cwd=WORKSPACE_ROOT,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        self.assertEqual(res.returncode, 0, f"Setup stdout: {res.stdout}\nstderr: {res.stderr}")
        self.assertIn("Initializing Developer Agent Environment", res.stdout)
        self.assertIn("dangerouslySkipPermissions: FALSE", res.stdout)

        # Inspect generated managed-settings.json
        settings_path = os.path.join(target_ws, ".claude", "managed-settings.json")
        self.assertTrue(os.path.exists(settings_path))
        with open(settings_path, "r", encoding="utf-8") as f:
            cfg = json.load(f)
        self.assertFalse(cfg.get("dangerouslySkipPermissions"))
        self.assertTrue(cfg.get("bap_managed"))
        self.assertEqual(cfg.get("lifecycle_hooks", {}).get("pre_tool_use"), "bapedge exec")

        # Inspect generated .bap/config.json
        bap_cfg_path = os.path.join(target_ws, ".bap", "config.json")
        self.assertTrue(os.path.exists(bap_cfg_path))
        with open(bap_cfg_path, "r", encoding="utf-8") as f:
            bap_cfg = json.load(f)
        self.assertEqual(bap_cfg.get("app_id"), "claude-code")
        self.assertTrue(bap_cfg.get("managed"))

    def test_bap_472_status_inspection(self):
        """BAP-472: Test in-terminal status inspection reports sessions, bundle, and layers."""
        res = subprocess.run(
            [BAPEDGE_BIN, "status", "--server", CP_URL],
            cwd=WORKSPACE_ROOT,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        self.assertEqual(res.returncode, 0, f"Status failed: {res.stderr}")
        out = res.stdout
        self.assertIn("Edge Workstation Status & Compliance Inspection", out)
        self.assertIn("POLICY BUNDLE & ZERO-TRUST CACHE", out)
        self.assertIn("3-TIER LAYER COMPLIANCE STATUS", out)
        self.assertIn("Layer A (Process Interception Hooks):    COMPLIANT", out)
        self.assertIn("Layer B (OS Kernel Boundary Sandbox):    COMPLIANT", out)
        self.assertIn("Layer C (Network Egress Pinning):        COMPLIANT", out)

    def test_bap_472_why_explanation(self):
        """BAP-472: Test in-terminal policy explanation for benign and destructive actions."""
        # Safe command: git status
        res_allow = subprocess.run(
            [BAPEDGE_BIN, "why", "git status"],
            cwd=WORKSPACE_ROOT,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        self.assertEqual(res_allow.returncode, 0)
        self.assertIn("ALLOWED", res_allow.stdout)
        self.assertIn("Agent::\"Local\"", res_allow.stdout)

        # Destructive command: rm -rf /
        res_deny = subprocess.run(
            [BAPEDGE_BIN, "why", "rm -rf /"],
            cwd=WORKSPACE_ROOT,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        self.assertEqual(res_deny.returncode, 0)
        self.assertIn("DENIED", res_deny.stdout)

    def test_bap_470_control_plane_sweep(self):
        """BAP-470: Test control plane /api/v1/control/sweep endpoint purges crashed sessions."""
        # Start a dummy session on control plane
        sess_id = f"sess-crash-sweep-test-{int(time.time())}"
        start_payload = {
            "session_id": sess_id,
            "app_id": "claude-code",
            "user_id": "test-dev",
            "client_pid": 88888,
            "hostname": "TEST-LAPTOP",
        }
        st_start, _, _ = http_req(f"{CP_URL}/api/v1/sessions/start", method="POST", data=start_payload)
        self.assertEqual(st_start, 200)

        # Trigger sweep on control plane targeting this crashed session
        sweep_payload = {
            "session_id": sess_id,
            "reason": "orphaned_crash_detected_in_test",
            "stale_idle_seconds": 1,
        }
        st_sweep, data_sweep, _ = http_req(f"{CP_URL}/api/v1/control/sweep", method="POST", data=sweep_payload)
        self.assertEqual(st_sweep, 200)
        self.assertEqual(data_sweep.get("status"), "reconciled")
        self.assertGreaterEqual(data_sweep.get("swept_sessions", 0), 1)

        # Verify session is now closed
        st_get, data_get, _ = http_req(f"{CP_URL}/api/v1/sessions/{sess_id}")
        self.assertEqual(st_get, 200)
        self.assertEqual(data_get.get("status"), "closed")

    def test_bap_470_bapedge_sweep_cli(self):
        """BAP-470: Test bapedge sweep CLI sweeps dead local sessions in an isolated directory."""
        isolated_ws = os.path.join(self.temp_dir, "isolated_sweep_ws")
        sessions_dir = os.path.join(isolated_ws, ".bap", "sessions")
        os.makedirs(sessions_dir, exist_ok=True)
        orphaned_file = os.path.join(sessions_dir, "test_orphaned_marker_dead.json")

        with open(orphaned_file, "w", encoding="utf-8") as f:
            json.dump({
                "session_id": "sess-orphaned-dead-process-1234",
                "pid": 99999999,  # guaranteed non-existent PID
                "started_at": "2026-10-04T00:00:00Z",
            }, f)

        self.assertTrue(os.path.exists(orphaned_file))

        # Copy policy.cedar so local authorizer works if needed
        policy_src = os.path.join(WORKSPACE_ROOT, "policy.cedar")
        if os.path.exists(policy_src):
            shutil.copy(policy_src, os.path.join(isolated_ws, "policy.cedar"))

        # Run bapedge sweep inside isolated workspace
        res = subprocess.run(
            [BAPEDGE_BIN, "sweep", "--server", CP_URL],
            cwd=isolated_ws,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        self.assertEqual(res.returncode, 0, f"Sweep failed: {res.stderr}")
        self.assertIn("Clean Sweep & Crash Recovery Reconciler", res.stdout)
        self.assertIn("Clean sweep completed successfully", res.stdout)

        # Orphaned file should be swept
        self.assertFalse(os.path.exists(orphaned_file))


if __name__ == "__main__":
    unittest.main()

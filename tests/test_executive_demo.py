"""
Automated End-to-End Test Suite for Epic: CIO Agent Command Center MVP
=====================================================================
Covers Stories:
- BAP-210: Cockpit Consolidation & Legacy Inspector Redirects
- BAP-211: Live Agent Mission View & Telemetry Aggregation
- BAP-212: Prompt-to-Action Timeline & Correlated Risk Escalation
- BAP-213: Closed-Loop Stop, Revoke, and Restore Controls
- BAP-214: Deterministic Executive Demo Scenario Execution
- BAP-215: Demo Hardening, Receipt Verification & Zero Stale State
"""

import json
import os
import ssl
import subprocess
import sys
import time
import unittest
import urllib.request

WORKSPACE_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(WORKSPACE_ROOT, "python-agent"))

ssl_ctx = ssl.create_default_context()
ssl_ctx.check_hostname = False
ssl_ctx.verify_mode = ssl.CERT_NONE


def read_admin_token() -> str:
    token_file = os.path.join(WORKSPACE_ROOT, ".bap-admin-token")
    if os.path.isfile(token_file):
        try:
            with open(token_file, "r", encoding="utf-8") as f:
                return f.read().strip()
        except Exception:
            pass
    return os.getenv("BAP_ADMIN_TOKEN", "")


def get_control_plane_url() -> str:
    try:
        from bap_sdk import resolve_endpoints
        ep = resolve_endpoints()
        return ep.get("controlplane_url", "https://localhost:8443").rstrip("/")
    except Exception:
        return "https://localhost:8443"


class NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def http_error_302(self, req, fp, code, msg, headers):
        return fp
    http_error_301 = http_error_302
    http_error_303 = http_error_302
    http_error_307 = http_error_302


class TestExecutiveDemo(unittest.TestCase):
    _spawned_server = None

    @classmethod
    def setUpClass(cls):
        cls.server_url = get_control_plane_url()
        cls.admin_token = read_admin_token()

        # Check server health
        req = urllib.request.Request(f"{cls.server_url}/api/v1/health")
        healthy = False
        try:
            with urllib.request.urlopen(req, context=ssl_ctx, timeout=2) as resp:
                if resp.status == 200:
                    healthy = True
        except Exception:
            pass

        if not healthy:
            cp_candidates = [
                os.path.join(WORKSPACE_ROOT, "bapcontrolplane.exe"),
                os.path.join(WORKSPACE_ROOT, "dist", "windows-amd64", "bapcontrolplane.exe"),
                os.path.join(WORKSPACE_ROOT, "bap-controlplane", "bapcontrolplane.exe"),
            ]
            cp_bin = next((p for p in cp_candidates if os.path.exists(p)), None)
            if not cp_bin:
                raise unittest.SkipTest(f"bapcontrolplane.exe not found at {cp_candidates[0]}")

            cmd = [cp_bin, "-port", "8443", "-https", "-allow-remote-admin", "-demo-mode"]
            if cls.admin_token:
                cmd.extend(["-admin-token", cls.admin_token])
            cls._spawned_server = subprocess.Popen(
                cmd,
                cwd=WORKSPACE_ROOT,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
            for _ in range(30):
                time.sleep(0.3)
                try:
                    with urllib.request.urlopen(req, context=ssl_ctx, timeout=1) as resp:
                        if resp.status == 200:
                            healthy = True
                            break
                except Exception:
                    pass

            if not healthy:
                raise unittest.SkipTest("Failed to spawn and reach local bapcontrolplane server")

        # Always ensure admin token is fresh from disk
        cls.admin_token = read_admin_token()

    @classmethod
    def tearDownClass(cls):
        if cls._spawned_server:
            try:
                cls._spawned_server.terminate()
                cls._spawned_server.wait(timeout=3)
            except Exception:
                try:
                    cls._spawned_server.kill()
                except Exception:
                    pass

    def api_request(self, method: str, path: str, payload: dict = None) -> tuple[int, dict, dict]:
        url = f"{self.server_url}{path}"
        data = json.dumps(payload).encode("utf-8") if payload else None
        req = urllib.request.Request(url, data=data, method=method)
        req.add_header("Content-Type", "application/json")
        token = self.admin_token or read_admin_token()
        if token:
            req.add_header("Authorization", f"Bearer {token}")
            req.add_header("X-BAP-Admin-Token", token)

        try:
            with urllib.request.urlopen(req, context=ssl_ctx, timeout=5) as resp:
                body = resp.read().decode("utf-8")
                res_json = json.loads(body) if body.strip().startswith(("{", "[")) else {}
                return resp.status, res_json, dict(resp.headers)
        except urllib.error.HTTPError as e:
            body = e.read().decode("utf-8") if e.fp else ""
            res_json = json.loads(body) if body.strip().startswith(("{", "[")) else {}
            return e.code, res_json, dict(e.headers)

    # -------------------------------------------------------------------------
    # BAP-210: Cockpit Consolidation & Legacy Inspector Redirects
    # -------------------------------------------------------------------------
    def test_01_bap210_inspector_redirects_and_dashboard(self):
        """Verifies inspector routes redirect to /dashboard/ and dashboard loads cleanly."""
        opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=ssl_ctx), NoRedirectHandler)

        # 1. Test /inspector.html redirect
        req1 = urllib.request.Request(f"{self.server_url}/inspector.html")
        resp1 = opener.open(req1)
        # Server sends 302 or 200 with HTML redirect meta
        if resp1.status == 302:
            self.assertIn("/dashboard/", resp1.headers.get("Location", ""))
        else:
            body1 = resp1.read().decode("utf-8")
            self.assertIn("/dashboard/", body1)

        # 2. Test /inspector_v2.html redirect
        req2 = urllib.request.Request(f"{self.server_url}/inspector_v2.html")
        resp2 = opener.open(req2)
        if resp2.status == 302:
            self.assertIn("/dashboard/", resp2.headers.get("Location", ""))
        else:
            body2 = resp2.read().decode("utf-8")
            self.assertIn("/dashboard/", body2)

        # 3. Test /dashboard/ returns HTTP 200 with Cockpit dashboard HTML
        req_dash = urllib.request.Request(f"{self.server_url}/dashboard/")
        with urllib.request.urlopen(req_dash, context=ssl_ctx, timeout=5) as resp_dash:
            self.assertEqual(resp_dash.status, 200)
            dash_html = resp_dash.read().decode("utf-8")
            self.assertIn("Agent operations", dash_html)

    # -------------------------------------------------------------------------
    # BAP-214: Deterministic Executive Demo Execution (< 60 seconds)
    # -------------------------------------------------------------------------
    def test_02_bap214_deterministic_scenario_run(self):
        """Executes demo_executive.py in non-interactive mode and measures runtime."""
        demo_script = os.path.join(WORKSPACE_ROOT, "demo_executive.py")
        self.assertTrue(os.path.isfile(demo_script), f"demo_executive.py missing at {demo_script}")

        start_time = time.time()
        proc = subprocess.Popen(
            [sys.executable, demo_script, "--no-prompt", "--delay", "0.1"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            cwd=WORKSPACE_ROOT
        )
        stdout, stderr = proc.communicate(timeout=60)
        elapsed = time.time() - start_time

        self.assertEqual(proc.returncode, 0, f"demo_executive.py failed (exit {proc.returncode}):\n{stdout}\n{stderr}")
        self.assertLess(elapsed, 60.0, f"Scenario execution exceeded 60 seconds: {elapsed:.2f}s")
        self.assertIn("EXECUTIVE DEMO READY ON COCKPIT", stdout)
        self.assertIn("Carol Zhang", stdout)
        self.assertIn("Bob Miller", stdout)
        self.assertIn("Eve Mallory", stdout)

    # -------------------------------------------------------------------------
    # BAP-211 & BAP-212: Telemetry, Prompt-to-Action Timeline & Risk Escalation
    # -------------------------------------------------------------------------
    def test_03_bap211_bap212_telemetry_and_risk_escalation(self):
        """Verifies session telemetry, denial counts, and threat escalation for the 3 agents."""
        status, data, _ = self.api_request("GET", "/api/v1/admin/inspector/data")
        if status != 200:
            status, data, _ = self.api_request("GET", "/api/v1/inspector/data")
        self.assertEqual(status, 200)

        sessions = {s["session_id"]: s for s in data.get("sessions", [])}
        self.assertIn("sess-exec-carol", sessions, "Carol's session missing from telemetry")
        self.assertIn("sess-exec-bob", sessions, "Bob's session missing from telemetry")
        self.assertIn("sess-exec-eve", sessions, "Eve's session missing from telemetry")

        carol = sessions["sess-exec-carol"]
        bob = sessions["sess-exec-bob"]
        eve = sessions["sess-exec-eve"]

        # 1. Carol: Healthy, >= 2 allowed, 0 denied
        self.assertGreaterEqual(carol.get("allowed_count", 0), 2)
        self.assertEqual(carol.get("denied_count", 0), 0)

        # 2. Bob: Elevated, 1 denial
        self.assertGreaterEqual(bob.get("allowed_count", 0), 1)
        self.assertEqual(bob.get("denied_count", 0), 1)

        # 3. Eve: Critical, >= 3 denials (repeated evasions)
        self.assertGreaterEqual(eve.get("allowed_count", 0), 1)
        self.assertGreaterEqual(eve.get("denied_count", 0), 3)

        # 4. Receipts present in central audit log
        events = data.get("central_events", [])
        eve_events = [e for e in events if e.get("session_id") == "sess-exec-eve"]
        self.assertGreaterEqual(len(eve_events), 3)

        # Check hash-chain integrity
        self.assertEqual(data.get("chain_status"), "valid")

        # 5. Intent Telemetry & Classification (Zero UNKNOWN)
        self.assertEqual(carol.get("intent", {}).get("primary"), "INVESTIGATION")
        self.assertIn(bob.get("intent", {}).get("primary"), ["DEPLOYMENT_RELEASE", "SECURITY_REMEDIATION"])
        self.assertEqual(eve.get("intent", {}).get("primary"), "SECURITY_REMEDIATION")
        intent_counts = data.get("intent_counts", {})
        self.assertEqual(intent_counts.get("UNKNOWN", 0), 0, f"Expected 0 UNKNOWN intents, found: {intent_counts}")
        self.assertGreaterEqual(intent_counts.get("INVESTIGATION", 0), 1)
        self.assertGreaterEqual(intent_counts.get("SECURITY_REMEDIATION", 0), 1)

    # -------------------------------------------------------------------------
    # BAP-213: Closed-Loop Controls (Stop, Revoke, Restore)
    # -------------------------------------------------------------------------
    def test_04_bap213_closed_loop_controls(self):
        """Tests Stop Session, Revoke Access, and Restore Access APIs on live sessions."""
        target_session = "sess-exec-eve"

        # 1. Stop Session
        stop_payload = {"target": target_session, "action": "stop"}
        st_stop, resp_stop, _ = self.api_request("POST", "/api/v1/control/agent/kill", stop_payload)
        self.assertEqual(st_stop, 200)
        self.assertEqual(resp_stop.get("kill_status"), "STOPPED")

        # Verify session status transitioned to stopped / closed
        st_get, sess_data, _ = self.api_request("GET", f"/api/v1/sessions/get?session_id={target_session}")
        if st_get == 200:
            self.assertIn(sess_data.get("status"), ["closed", "stopped"])

        # 2. Revoke Access
        revoke_payload = {"target": target_session, "action": "revoke"}
        st_rev, resp_rev, _ = self.api_request("POST", "/api/v1/control/agent/kill", revoke_payload)
        self.assertEqual(st_rev, 200)
        self.assertEqual(resp_rev.get("kill_status"), "REVOKED")

        # Verify session appears in revocation list
        st_data, insp_data, _ = self.api_request("GET", "/api/v1/inspector/data")
        self.assertEqual(st_data, 200)
        rev_sessions = insp_data.get("revoked_sessions", [])
        self.assertIn(target_session, rev_sessions)

        # 3. Restore Access
        restore_payload = {"target": target_session, "action": "restore"}
        st_res, resp_res, _ = self.api_request("POST", "/api/v1/control/agent/kill", restore_payload)
        self.assertEqual(st_res, 200)
        self.assertEqual(resp_res.get("kill_status"), "RESTORED")

    # -------------------------------------------------------------------------
    # BAP-215: Clean Reset & Zero Stale State
    # -------------------------------------------------------------------------
    def test_05_bap215_cleanup_and_zero_stale_state(self):
        """Verifies demo_executive.py --cleanup cleanly resets all active session state."""
        demo_script = os.path.join(WORKSPACE_ROOT, "demo_executive.py")
        proc = subprocess.run(
            [sys.executable, demo_script, "--cleanup"],
            capture_output=True,
            text=True,
            cwd=WORKSPACE_ROOT
        )
        self.assertEqual(proc.returncode, 0, f"Cleanup failed:\n{proc.stdout}\n{proc.stderr}")

        # Verify no active sessions remain
        st, data, _ = self.api_request("GET", "/api/v1/inspector/data")
        self.assertEqual(st, 200)
        active_sessions = [
            s for s in data.get("sessions", [])
            if s.get("status") == "active"
        ]
        self.assertEqual(len(active_sessions), 0, f"Expected 0 active sessions after reset, found {len(active_sessions)}")


if __name__ == "__main__":
    unittest.main(verbosity=2)

"""
Integration Tests for Agent Watch V3 Executive Dashboard (web/v3.html)
Validates:
1. /dashboard/ serves V3 Executive View by default.
2. /dashboard/v3 and /dashboard/v3/ redirect and serve V3.
3. Telemetry endpoints (/api/activity/summary, /api/activity/live, /api/v1/control/chain/verify) return valid contracts for V3.
4. Kill-switch endpoint supports V3 Fleet Freeze.
"""

import json
import os
import subprocess
import sys
import tempfile
import time
import unittest
import urllib.request
import urllib.error

WORKSPACE_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
CONTROL_PLANE_DIR = os.path.join(WORKSPACE_ROOT, "bap-controlplane")
CP_PORT = 19399
CP_URL = f"http://127.0.0.1:{CP_PORT}"
TEST_ADMIN_TOKEN = "v3-test-admin-token-xyz"


def http_req(url, method="GET", data=None, headers=None):
    hdrs = dict(headers or {})
    body = None
    if data is not None:
        if isinstance(data, (dict, list)):
            body = json.dumps(data).encode("utf-8")
            hdrs["Content-Type"] = "application/json"
        elif isinstance(data, str):
            body = data.encode("utf-8")
    req = urllib.request.Request(url, data=body, headers=hdrs, method=method)
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


class TestV3UILive(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.proc = subprocess.Popen(
            [
                "go",
                "run",
                "./cmd/server",
                "-port",
                str(CP_PORT),
                "-admin-token",
                TEST_ADMIN_TOKEN,
                "-allow-remote-admin",
                "-db",
                "memory",
            ],
            cwd=CONTROL_PLANE_DIR,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

        started = False
        for _ in range(30):
            try:
                code, _, _ = http_req(f"{CP_URL}/api/v1/health")
                if code == 200:
                    started = True
                    break
            except Exception:
                time.sleep(0.3)
        if not started:
            cls.tearDownClass()
            raise RuntimeError("Failed to start control plane for V3 UI test")

    @classmethod
    def tearDownClass(cls):
        if hasattr(cls, "proc") and cls.proc:
            cls.proc.terminate()
            try:
                cls.proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                cls.proc.kill()

    def test_01_dashboard_serves_v3_by_default(self):
        """Verify /dashboard/ serves V3 Executive View."""
        st, _, raw = http_req(f"{CP_URL}/dashboard/")
        self.assertEqual(st, 200)
        html = raw.decode("utf-8")
        self.assertIn("Agent Watch V3", html)
        self.assertIn("Freeze all agents", html)
        self.assertIn("What agents did", html)
        self.assertIn("Needs you", html)

    def test_02_dashboard_v3_explicit_route(self):
        """Verify /dashboard/v3/ serves V3."""
        st, _, raw = http_req(f"{CP_URL}/dashboard/v3/")
        self.assertEqual(st, 200)
        html = raw.decode("utf-8")
        self.assertIn("Agent Watch V3", html)

    def test_03_telemetry_endpoints_for_v3(self):
        """Verify telemetry endpoints used by V3 UI."""
        st, summary, _ = http_req(f"{CP_URL}/api/activity/summary")
        self.assertEqual(st, 200)
        self.assertIn("total_active_agents", summary)

        st, live, _ = http_req(f"{CP_URL}/api/activity/live")
        self.assertEqual(st, 200)
        self.assertTrue(isinstance(live, list) or "activities" in live or "count" in live)

        st, chain, _ = http_req(f"{CP_URL}/api/v1/control/chain/verify")
        self.assertEqual(st, 200)
        self.assertTrue(chain.get("valid") is True or chain.get("status") == "valid" or chain.get("ok") is True)

    def test_04_kill_switch_fleet_freeze(self):
        """Verify POST /api/v1/control/kill-switch works for V3 freeze."""
        hdrs = {"Authorization": f"Bearer {TEST_ADMIN_TOKEN}"}
        st, res, _ = http_req(
            f"{CP_URL}/api/v1/control/kill-switch",
            method="POST",
            data={"enabled": True, "reason": "Test freeze from V3 test"},
            headers=hdrs
        )
        self.assertEqual(st, 200)

        # Unfreeze
        st2, _, _ = http_req(
            f"{CP_URL}/api/v1/control/kill-switch",
            method="POST",
            data={"enabled": False, "reason": "Test unfreeze"},
            headers=hdrs
        )
        self.assertEqual(st2, 200)

    def test_05_registered_agents_in_v3_ui(self):
        """Verify V3 HTML contains Registered Agents panel and /api/v1/agents returns agents."""
        st, _, raw = http_req(f"{CP_URL}/dashboard/")
        self.assertEqual(st, 200)
        html = raw.decode("utf-8")
        self.assertIn("Registered Agent Fleet &amp; Identities", html)
        self.assertIn("regSearch", html)
        self.assertIn("regTable", html)
        self.assertIn("openRiskyActions", html)

        st_agents, res_agents, _ = http_req(f"{CP_URL}/api/v1/agents")
        self.assertEqual(st_agents, 200)
        self.assertIn("agents", res_agents)

    def test_06_agent_deregistration_endpoint(self):
        """Verify POST /api/v1/agents/deregister revokes and deregisters an agent."""
        # 1. Pre-register and register an agent
        prereg = {
            "app_id": "test-logout-agent",
            "owner_email": "logout-test@corp.internal",
            "agent_name": "LogoutTestAgent",
            "env_profile": "dev",
            "permitted_scopes": ["cli:exec"],
        }
        st_pre, pr_res, _ = http_req(
            f"{CP_URL}/api/v1/agents/pre-register",
            method="POST",
            data=prereg,
            headers={"X-BAP-Admin-Token": TEST_ADMIN_TOKEN}
        )
        self.assertIn(st_pre, [200, 201])
        agent_id = pr_res.get("agent_id")
        otc = pr_res.get("one_time_code")

        reg = {
            "one_time_code": otc,
            "agent_name": "LogoutTestAgent",
            "hostname": "logout-workstation",
            "binary_hash": "294ab8c000000000000000000000000000000000000000000000000000000000",
            "public_key": "pubkey-logout-test",
            "instance_id": "inst-logout-01"
        }
        st_reg, reg_res, _ = http_req(f"{CP_URL}/api/v1/agents/register", method="POST", data=reg)
        self.assertEqual(st_reg, 200)
        session_token = reg_res.get("session_token")

        # 2. Deregister via /api/v1/agents/deregister
        dereg_payload = {
            "agent_id": agent_id,
            "instance_id": "inst-logout-01",
            "session_token": session_token,
            "reason": "Test logout"
        }
        st_d, d_res, _ = http_req(
            f"{CP_URL}/api/v1/agents/deregister",
            method="POST",
            data=dereg_payload,
            headers={"Authorization": f"Bearer {session_token}"}
        )
        self.assertEqual(st_d, 200)
        self.assertTrue(d_res.get("deregistered"))
        self.assertEqual(d_res.get("status"), "deregistered")

    def test_07_risky_action_audit_events_endpoint(self):
        """Verify /api/v1/audit/events returns valid payload for risky action drawer."""
        st, res, _ = http_req(f"{CP_URL}/api/v1/audit/events")
        self.assertEqual(st, 200)
        self.assertIn("events", res)
        self.assertIn("chain_status", res)


if __name__ == "__main__":
    unittest.main()

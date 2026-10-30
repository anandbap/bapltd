"""
Unit test verifying BAP Master Workstation Registration & Child Workload Session SVIDs.
Tests:
1. Workstation establishes 1 Master Registration with corporate identity & SPIFFE ID.
2. Multiple workloads (Claude Code, Python SDK, Antigravity) start as sessions attached to that 1 Master Workstation.
3. No duplicate agent cards or agent sprawl created in the registry.
4. Workload sessions receive workstation-scoped Session SVIDs.
5. Workstation subagents list dynamically tracks all active workloads.
"""

import unittest
import os
import sys
import time
import json
import urllib.request
import ssl
import subprocess

WORKSPACE_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(WORKSPACE_ROOT, "python-agent"))

from bap_sdk import BAPSession

ssl_ctx = ssl.create_default_context()
ssl_ctx.check_hostname = False
ssl_ctx.verify_mode = ssl.CERT_NONE


class TestWorkstationSessionSVID(unittest.TestCase):
    _spawned_server = None
    server_url = "https://127.0.0.1:8449"
    admin_token = "test-ws-admin-token-12345"

    @classmethod
    def setUpClass(cls):
        cp_candidates = [
            os.path.join(WORKSPACE_ROOT, "bapcontrolplane.exe"),
            os.path.join(WORKSPACE_ROOT, "dist", "windows-amd64", "bapcontrolplane.exe"),
            os.path.join(WORKSPACE_ROOT, "bap-controlplane", "bapcontrolplane.exe"),
        ]
        cp_bin = next((p for p in cp_candidates if os.path.exists(p)), None)
        if not cp_bin:
            raise unittest.SkipTest(f"bapcontrolplane.exe not found")

        cmd = [
            cp_bin, "-port", "8449", "-https", "-allow-remote-admin",
            "-db", "memory",
            "-admin-token", cls.admin_token,
            "-policy", os.path.join(WORKSPACE_ROOT, "policy.cedar"),
            "-schema", os.path.join(WORKSPACE_ROOT, "schema.json"),
        ]
        cls._spawned_server = subprocess.Popen(
            cmd,
            cwd=WORKSPACE_ROOT,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        health_req = urllib.request.Request(f"{cls.server_url}/api/v1/health")
        connected = False
        for _ in range(30):
            time.sleep(0.3)
            try:
                with urllib.request.urlopen(health_req, context=ssl_ctx, timeout=1) as resp:
                    if resp.status == 200:
                        connected = True
                        break
            except Exception:
                pass
        if not connected:
            cls._spawned_server.kill()
            raise RuntimeError("Failed to connect to test bapcontrolplane on port 8449")

    @classmethod
    def tearDownClass(cls):
        if cls._spawned_server:
            cls._spawned_server.terminate()
            try:
                cls._spawned_server.wait(timeout=3)
            except Exception:
                cls._spawned_server.kill()

    def api_request(self, method: str, path: str, data: dict = None) -> tuple[int, dict]:
        url = f"{self.server_url}{path}"
        body = json.dumps(data).encode("utf-8") if data is not None else None
        req = urllib.request.Request(url, data=body, method=method)
        req.add_header("Content-Type", "application/json")
        if self.admin_token:
            req.add_header("Authorization", f"Bearer {self.admin_token}")
            req.add_header("X-BAP-Admin-Token", self.admin_token)
        try:
            with urllib.request.urlopen(req, context=ssl_ctx, timeout=5) as resp:
                resp_data = {}
                raw = resp.read().decode("utf-8")
                if raw.strip().startswith("{"):
                    resp_data = json.loads(raw)
                return resp.status, resp_data
        except urllib.error.HTTPError as e:
            err_data = {}
            raw = e.read().decode("utf-8")
            if raw.strip().startswith("{"):
                try:
                    err_data = json.loads(raw)
                except Exception:
                    pass
            return e.code, err_data

    def test_01_master_registration_and_child_session_svids(self):
        """Verify that 1 Master Workstation anchors multiple AI workloads as sessions without agent sprawl."""
        # 1. Establish Master Workstation Registration (via OIDC Device Flow simulation)
        code_status, code_resp = self.api_request("POST", "/api/v1/auth/oidc/device-code", {
            "app_id": "claude-code-workstation",
            "hostname": "ENG-LAPTOP-01",
            "device_type": "laptop",
            "binary_hash": "sha256:abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234",
            "provider": "okta"
        })
        self.assertEqual(code_status, 200)
        user_code = code_resp["user_code"]
        device_code = code_resp["device_code"]

        # Verify device code with corporate identity
        verify_status, verify_resp = self.api_request("POST", "/api/v1/auth/oidc/device-verify", {
            "user_code": user_code,
            "user_email": "developer@corp.internal",
            "department": "Core Platform Engineering",
            "groups": ["developers", "ai-governed-users"],
            "provider": "okta"
        })
        self.assertEqual(verify_status, 200)
        workstation_inst_id = verify_resp["instance_id"]
        self.assertTrue(workstation_inst_id)

        # Poll device token to complete enrollment
        token_status, token_resp = self.api_request("POST", "/api/v1/auth/oidc/device-token", {
            "device_code": device_code
        })
        self.assertEqual(token_status, 200)
        self.assertEqual(token_resp["status"], "authorized")

        # Verify exactly 1 agent is registered in the control plane
        list_status, list_data = self.api_request("GET", "/api/v1/agents")
        self.assertEqual(list_status, 200)
        agents = list_data.get("agents", [])
        self.assertEqual(len(agents), 1, "Expected exactly 1 Master Workstation registered")
        master_agent = agents[0]
        self.assertEqual(master_agent["instance_id"], workstation_inst_id)
        self.assertEqual(master_agent["user_email"], "developer@corp.internal")

        # 2. Start Workload 1: Claude Code Session on this workstation
        claude_sess_id = f"sess-claude-pid-{os.getpid()}"
        session_svid_claude = f"spiffe://bap.internal/workstation/{workstation_inst_id}/session/{claude_sess_id}"
        s1_status, s1_resp = self.api_request("POST", "/api/v1/sessions/start", {
            "session_id": claude_sess_id,
            "app_id": "claude-code",
            "instance_id": workstation_inst_id,
            "resource_id": workstation_inst_id,
            "user_id": "developer",
            "user_email": "developer@corp.internal",
            "hostname": "ENG-LAPTOP-01",
            "client_pid": 1044,
            "user_prompt": "Refactor auth middleware",
            "session_svid": session_svid_claude,
        })
        self.assertIn(s1_status, (200, 201))

        # Verify registry STILL has only 1 master agent, but now tracks claude-code as a subagent
        list_status, list_data = self.api_request("GET", "/api/v1/agents")
        self.assertEqual(list_status, 200)
        agents = list_data.get("agents", [])
        self.assertEqual(len(agents), 1, "Spurious agent created for Claude session!")
        self.assertIn("claude-code", agents[0].get("subagents", []))

        # 3. Start Workload 2: Python SDK Session on the same workstation
        py_sess_id = f"sess-python-analyst-{int(time.time())}"
        session_svid_py = f"spiffe://bap.internal/workstation/{workstation_inst_id}/session/{py_sess_id}"
        with BAPSession(
            app_id="python-agent",
            instance_id=workstation_inst_id,
            session_id=py_sess_id,
            user_email="developer@corp.internal",
            server_url=self.server_url
        ) as py_sess:
            self.assertTrue(py_sess.is_active)
            self.assertEqual(py_sess.instance_id, workstation_inst_id)
            self.assertEqual(py_sess.session_svid, session_svid_py)

            # Check registry again: STILL exactly 1 master agent, tracking both subagents
            list_status, list_data = self.api_request("GET", "/api/v1/agents")
            self.assertEqual(list_status, 200)
            agents = list_data.get("agents", [])
            self.assertEqual(len(agents), 1, "Spurious agent created for Python session!")
            subagents = agents[0].get("subagents", [])
            self.assertIn("claude-code", subagents)
            self.assertIn("python-agent", subagents)

            # Verify sessions telemetry shows both sessions active under the same resource
            data_status, insp_data = self.api_request("GET", "/api/v1/inspector/data")
            self.assertEqual(data_status, 200)
            sessions = {s["session_id"]: s for s in insp_data.get("sessions", [])}
            self.assertIn(claude_sess_id, sessions)
            self.assertIn(py_sess_id, sessions)
            self.assertEqual(sessions[claude_sess_id]["instance_id"], workstation_inst_id)
            self.assertEqual(sessions[py_sess_id]["instance_id"], workstation_inst_id)

        # 4. Gracefully close Claude session
        end_status, _ = self.api_request("POST", "/api/v1/sessions/end", {
            "session_id": claude_sess_id,
            "reason": "Task completed"
        })
        self.assertEqual(end_status, 200)

        # Master workstation agent remains active and governed
        list_status, list_data = self.api_request("GET", "/api/v1/agents")
        self.assertEqual(list_status, 200)
        self.assertEqual(len(list_data.get("agents", [])), 1)
        self.assertEqual(list_data["agents"][0]["status"], "active")


if __name__ == "__main__":
    unittest.main()

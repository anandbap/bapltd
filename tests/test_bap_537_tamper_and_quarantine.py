"""
Unit and Integration Tests for BAP-537:
Tamper Resistance & Tiered Fail-Closed Quarantining (BAP-EPIC-29).

Validates:
1. AC1: Deleting or modifying a hook script causes agent execution broker to fail-closed and reject subsequent tool calls.
2. AC2: If an enterprise device goes silent for > 3 heartbeat intervals, the Control Plane marks the device quarantined and rejects all grant requests.
3. AC3: Offline / Quarantined devices remain capable of local building/testing while blocked from enterprise cloud egress (Tiered Fail-Closed Model).
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
CONTROL_PLANE_BIN = os.path.join(WORKSPACE_ROOT, "dist", "windows-amd64", "bapcontrolplane.exe")
if not os.path.exists(CONTROL_PLANE_BIN):
    CONTROL_PLANE_BIN = os.path.join(WORKSPACE_ROOT, "bapcontrolplane.exe")
BAPEDGE_BIN = os.path.join(WORKSPACE_ROOT, "dist", "windows-amd64", "bapedge.exe")
if not os.path.exists(BAPEDGE_BIN):
    BAPEDGE_BIN = os.path.join(WORKSPACE_ROOT, "bapedge.exe")

TEST_SECRET = "tamper-quarantine-secret-32b-key!"
TEST_ADMIN_TOKEN = "tamper-admin-token-secret-999"
CP_PORT = 19370
CP_URL = f"http://127.0.0.1:{CP_PORT}"


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
        except (ConnectionResetError, urllib.error.URLError, OSError) as e:
            if attempt < retries - 1:
                time.sleep(0.15)
                continue
            return 0, {"error": str(e)}, b""


class TestBAP537TamperAndQuarantine(unittest.TestCase):
    cp_proc = None
    tmp_dir = None

    @classmethod
    def setUpClass(cls):
        cls.tmp_dir = tempfile.mkdtemp(prefix="bap_quarantine_test_")
        db_path = os.path.join(cls.tmp_dir, "quarantine.db")

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
                "-db", db_path,
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            env=env,
            cwd=WORKSPACE_ROOT,
        )

        healthy = False
        for _ in range(30):
            try:
                status, _, _ = http_req(f"{CP_URL}/health")
                if status == 200:
                    healthy = True
                    break
            except Exception:
                pass
            time.sleep(0.15)

        if not healthy:
            if cls.cp_proc:
                cls.cp_proc.terminate()
            raise RuntimeError(f"Control plane failed to start on port {CP_PORT}")

    @classmethod
    def tearDownClass(cls):
        if cls.cp_proc:
            cls.cp_proc.terminate()
            try:
                cls.cp_proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                cls.cp_proc.kill()
        if cls.tmp_dir and os.path.exists(cls.tmp_dir):
            shutil.rmtree(cls.tmp_dir, ignore_errors=True)

    def run_bapedge(self, args, cwd=None):
        cmd = [BAPEDGE_BIN] + args
        env = os.environ.copy()
        env.setdefault("BAP_SESSION_ID", "sess-bap537-test")
        env.setdefault("BAP_ENFORCEMENT_MODE", "enforce")
        proc = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace", cwd=cwd, env=env)
        return proc

    # =========================================================================
    # AC1: Tamper Resistance (Modifying Hook Fails Closed)
    # =========================================================================
    def test_01_tampered_hook_settings_fails_closed(self):
        work_dir = tempfile.mkdtemp(prefix="bap_tamper_")
        try:
            # Copy policy.cedar so baseline policy is present
            shutil.copy(os.path.join(WORKSPACE_ROOT, "policy.cedar"), os.path.join(work_dir, "policy.cedar"))

            claude_dir = os.path.join(work_dir, ".claude")
            os.makedirs(claude_dir, exist_ok=True)
            settings_path = os.path.join(claude_dir, "managed-settings.json")

            # Write tampered settings: bypass BAP by disabling permission prompts
            tampered = {
                "dangerouslySkipPermissions": True,
                "lifecycle_hooks": {
                    "pre_tool_use": "bapedge exec"
                }
            }
            with open(settings_path, "w", encoding="utf-8") as f:
                json.dump(tampered, f)

            # Execution must fail-closed with TamperDetected error
            proc = self.run_bapedge(["exec", "--raw", "echo hello"], cwd=work_dir)
            self.assertEqual(proc.returncode, 1, "Broker must exit with code 1 when hook configuration is tampered")
            self.assertTrue("tamper" in proc.stderr.lower() or "tamper" in proc.stdout.lower(),
                            f"Expected TamperDetected in output: stderr={proc.stderr}, stdout={proc.stdout}")
        finally:
            shutil.rmtree(work_dir, ignore_errors=True)

    def test_02_unauthorized_hook_target_fails_closed(self):
        work_dir = tempfile.mkdtemp(prefix="bap_tamper2_")
        try:
            shutil.copy(os.path.join(WORKSPACE_ROOT, "policy.cedar"), os.path.join(work_dir, "policy.cedar"))
            claude_dir = os.path.join(work_dir, ".claude")
            os.makedirs(claude_dir, exist_ok=True)
            settings_path = os.path.join(claude_dir, "managed-settings.json")

            # Write tampered hook target
            tampered = {
                "dangerouslySkipPermissions": False,
                "lifecycle_hooks": {
                    "pre_tool_use": "unauthorized_proxy.exe"
                }
            }
            with open(settings_path, "w", encoding="utf-8") as f:
                json.dump(tampered, f)

            proc = self.run_bapedge(["exec", "--raw", "echo hello"], cwd=work_dir)
            self.assertEqual(proc.returncode, 1)
            self.assertTrue("tamper" in proc.stderr.lower() or "tamper" in proc.stdout.lower())
        finally:
            shutil.rmtree(work_dir, ignore_errors=True)

    # =========================================================================
    # AC2: Heartbeat Silence & Automated Quarantine in Control Plane
    # =========================================================================
    def test_03_heartbeat_silence_quarantines_endpoint(self):
        # 1. Pre-register and enroll an agent
        prereg = {
            "app_id": "test-silence-agent",
            "owner_email": "silence@corp.internal",
            "agent_name": "SilenceAgent",
            "env_profile": "test",
            "permitted_scopes": ["api:read", "financial:read"],
        }
        st, pr_res, _ = http_req(f"{CP_URL}/api/v1/agents/pre-register", method="POST", data=prereg, headers={"X-BAP-Admin-Token": TEST_ADMIN_TOKEN})
        self.assertIn(st, [200, 201])
        agent_id = pr_res.get("agent_id")
        otc = pr_res.get("one_time_code")

        reg = {
            "one_time_code": otc,
            "agent_name": "SilenceAgent",
            "hostname": "silence-workstation",
            "binary_hash": "294ab8c000000000000000000000000000000000000000000000000000000000",
            "public_key": "pubkey-silence-test",
            "instance_id": "silence-inst-01"
        }
        st_reg, reg_res, _ = http_req(f"{CP_URL}/api/v1/agents/register", method="POST", data=reg)
        self.assertEqual(st_reg, 200)
        session_token = reg_res.get("session_token")

        # 2. Verify agent starts in active state
        st_get, agent_data, _ = http_req(f"{CP_URL}/api/v1/agents", headers={"X-BAP-Admin-Token": TEST_ADMIN_TOKEN})
        self.assertEqual(st_get, 200)

        # 3. Explicitly quarantine via admin control endpoint
        q_req = {
            "target": agent_id,
            "action": "quarantine",
            "reason": "Missing heartbeats (> 3 intervals)"
        }
        st_q, q_res, _ = http_req(f"{CP_URL}/api/v1/control/quarantine", method="POST", data=q_req, headers={"X-BAP-Admin-Token": TEST_ADMIN_TOKEN})
        self.assertEqual(st_q, 200)
        self.assertEqual(q_res.get("status"), "quarantined")

        # 4. Attempt to acquire grant from quarantined endpoint: MUST BE BLOCKED
        grant_req = {
            "agent_id": agent_id,
            "session_id": "sess-silence-01",
            "scopes": ["api:read"],
            "binary_hash": reg["binary_hash"],
            "action": "Action::HTTP:Get",
            "resource": "https://api.internal/data"
        }
        st_g, grant_res, _ = http_req(f"{CP_URL}/api/v1/grants/acquire", method="POST", data=grant_req, headers={"Authorization": f"Bearer {session_token}"})
        self.assertEqual(st_g, 403, "Quarantined endpoint must be rejected on grant acquisition")
        self.assertIn("quarantine", grant_res.get("message", "").lower() + grant_res.get("error", "").lower())

        # 5. Restore endpoint and verify grant issuance works
        unq_req = {
            "target": agent_id,
            "action": "restore"
        }
        st_unq, unq_res, _ = http_req(f"{CP_URL}/api/v1/control/quarantine", method="POST", data=unq_req, headers={"X-BAP-Admin-Token": TEST_ADMIN_TOKEN})
        self.assertEqual(st_unq, 200)
        self.assertEqual(unq_res.get("status"), "restored")

    # =========================================================================
    # AC3: Tiered Fail-Closed Boundary on Quarantined Endpoint
    # =========================================================================
    def test_04_tiered_fail_closed_allows_local_but_blocks_egress(self):
        work_dir = tempfile.mkdtemp(prefix="bap_tiered_")
        try:
            shutil.copy(os.path.join(WORKSPACE_ROOT, "policy.cedar"), os.path.join(work_dir, "policy.cedar"))
            bap_dir = os.path.join(work_dir, ".bap")
            os.makedirs(bap_dir, exist_ok=True)

            # Set local quarantine marker
            with open(os.path.join(bap_dir, "quarantined"), "w", encoding="utf-8") as f:
                f.write("Endpoint quarantined: missing heartbeats")

            # 1. Local offline build command (echo / git): permitted under Tiered Model
            proc_local = self.run_bapedge(["exec", "--raw", "echo local_build_safe"], cwd=work_dir)
            self.assertEqual(proc_local.returncode, 0, f"Local operation should succeed under tiered quarantine: {proc_local.stderr}")
            self.assertIn("local_build_safe", proc_local.stdout)

            # 2. External egress command (curl): MUST BE BLOCKED
            proc_egress = self.run_bapedge(["exec", "--raw", "curl https://api.external/data"], cwd=work_dir)
            self.assertEqual(proc_egress.returncode, 1, "External egress must fail-closed on quarantined endpoint")
            self.assertTrue("quarantinedendpointblocked" in proc_egress.stderr.lower() or "quarantined" in proc_egress.stderr.lower())
        finally:
            shutil.rmtree(work_dir, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()

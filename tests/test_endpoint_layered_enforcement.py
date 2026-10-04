"""
Epic 23: Layered Endpoint Enforcement, MDM Packaging & Biometric Step-Up Test Suite
=====================================================================================
Validates BAP-460, BAP-461, BAP-462, and BAP-463:
1. 3-Tier Layered Enforcement Architecture (Layers A, B, C).
2. Endpoint Compliance Evaluation & Quarantine for missing boundaries.
3. MDM Profile Generation for Intune and Jamf (managed-settings.json locking).
4. Biometric Step-Up Elevation Challenges (Windows Hello, Touch ID, FIDO2).
5. Scoped Offline Degradation (Tier 1 Safe Local Dev vs Tier 2 Cloud Egress).
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
CONTROL_PLANE_BIN = os.path.join(WORKSPACE_ROOT, "dist", "windows-amd64", "bapcontrolplane.exe")

CP_PORT = 19280
CP_URL = f"http://127.0.0.1:{CP_PORT}"
TEST_ADMIN_TOKEN = "endpoint-test-admin-token-12345"


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


class TestEndpointLayeredEnforcement(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp_dir = tempfile.mkdtemp(prefix="bap_endpoint_test_")
        cls.db_path = os.path.join(cls.temp_dir, "endpoint.db")

        env = os.environ.copy()
        env["BAP_ADMIN_TOKEN"] = TEST_ADMIN_TOKEN

        cls.cp_proc = subprocess.Popen(
            [
                CONTROL_PLANE_BIN,
                "-port", str(CP_PORT),
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

    def test_01_endpoint_layers_reference(self):
        """BAP-460: GET /api/v1/endpoint/layers returns Layers A, B, and C with active OS primitives."""
        status, data, _ = http_req(f"{CP_URL}/api/v1/endpoint/layers?os=windows")
        self.assertEqual(status, 200)
        self.assertIn("layers", data)
        self.assertEqual(len(data["layers"]), 3)

        layer_ids = [l["layer_id"] for l in data["layers"]]
        self.assertIn("LAYER_A_COOPERATIVE_HOOKS", layer_ids)
        self.assertIn("LAYER_B_KERNEL_EXECUTION_CONTROL", layer_ids)
        self.assertIn("LAYER_C_NETWORK_EGRESS_PINNING", layer_ids)

        # Check Windows primitives
        layer_b = next(l for l in data["layers"] if l["layer_id"] == "LAYER_B_KERNEL_EXECUTION_CONTROL")
        self.assertTrue(any("Restricted Tokens" in p for p in layer_b["primitives"]))

    def test_02_endpoint_compliance_managed_clean(self):
        """BAP-460: Managed laptop with all 3 layers active achieves COMPLIANT status."""
        payload = {
            "hostname": "macbook-pro-alice",
            "agent_id": "agent-claude-alice",
            "os": "darwin",
            "is_managed_fleet": True,
            "mdm_enrolled": True,
            "layers": [
                {"layer_id": "LAYER_A_COOPERATIVE_HOOKS", "active": True, "enforcing": True},
                {"layer_id": "LAYER_B_KERNEL_EXECUTION_CONTROL", "active": True, "enforcing": True},
                {"layer_id": "LAYER_C_NETWORK_EGRESS_PINNING", "active": True, "enforcing": True},
            ],
        }
        status, report, _ = http_req(f"{CP_URL}/api/v1/endpoint/compliance", method="POST", data=payload)
        self.assertEqual(status, 200)
        self.assertEqual(report["compliance_state"], "COMPLIANT")
        self.assertEqual(report.get("quarantine_reason", ""), "")

    def test_03_endpoint_compliance_managed_quarantine(self):
        """BAP-460: Managed laptop missing Layer B (Kernel Control) is immediately QUARANTINED."""
        payload = {
            "hostname": "compromised-laptop",
            "agent_id": "agent-claude-rogue",
            "os": "windows",
            "is_managed_fleet": True,
            "layers": [
                {"layer_id": "LAYER_A_COOPERATIVE_HOOKS", "active": True, "enforcing": True},
                {"layer_id": "LAYER_B_KERNEL_EXECUTION_CONTROL", "active": False, "enforcing": False},
                {"layer_id": "LAYER_C_NETWORK_EGRESS_PINNING", "active": True, "enforcing": True},
            ],
        }
        status, report, _ = http_req(f"{CP_URL}/api/v1/endpoint/compliance", method="POST", data=payload)
        self.assertEqual(status, 200)
        self.assertEqual(report["compliance_state"], "QUARANTINED")
        self.assertIn("Missing: Layer B", report["quarantine_reason"])

    def test_04_endpoint_compliance_byod_cooperative(self):
        """BAP-460: Unmanaged BYOD machine runs in Cooperative mode with Gateway PEP backstop."""
        payload = {
            "hostname": "developer-personal-laptop",
            "agent_id": "agent-claude-contractor",
            "os": "linux",
            "is_managed_fleet": False,
            "layers": [
                {"layer_id": "LAYER_A_COOPERATIVE_HOOKS", "active": True, "enforcing": True},
            ],
        }
        status, report, _ = http_req(f"{CP_URL}/api/v1/endpoint/compliance", method="POST", data=payload)
        self.assertEqual(status, 200)
        self.assertEqual(report["compliance_state"], "COOPERATIVE_BYOD")
        self.assertIn("Gateway PEP remains authoritative backstop", report["quarantine_reason"])

    def test_05_mdm_profile_generation_intune_and_jamf(self):
        """BAP-461: Generates user-immutable managed-settings profiles for Microsoft Intune and Jamf Pro."""
        # Intune (Windows)
        status_w, profile_w, _ = http_req(f"{CP_URL}/api/v1/endpoint/mdm/profile?platform=windows")
        self.assertEqual(status_w, 200)
        self.assertEqual(profile_w["management_tool"], "Microsoft Intune OMA-URI / CSP")
        self.assertFalse(profile_w["settings"]["claude_code"]["dangerously_skip_permissions"])
        self.assertTrue(profile_w["settings"]["claude_code"]["immutable"])

        # Jamf (macOS)
        status_m, profile_m, _ = http_req(f"{CP_URL}/api/v1/endpoint/mdm/profile?platform=macos")
        self.assertEqual(status_m, 200)
        self.assertIn("Jamf", profile_m["management_tool"])
        self.assertTrue(profile_m["settings"]["system_extension"]["full_disk_access"])

    def test_06_biometric_step_up_challenge_and_verification(self):
        """BAP-462: Initiates elevation challenge and verifies biometric signature, minting signed StepUpToken."""
        # 1. Initiate challenge
        chal_payload = {
            "agent_id": "agent-lead-dev",
            "operation": "database.schema_migration",
            "risk_score": 0.85,
        }
        status1, challenge, _ = http_req(f"{CP_URL}/api/v1/endpoint/stepup/challenge", method="POST", data=chal_payload)
        self.assertEqual(status1, 200)
        self.assertIn("challenge_id", challenge)
        self.assertEqual(challenge["status"], "PENDING")
        self.assertEqual(challenge["required_auth"], "WINDOWS_HELLO")
        cid = challenge["challenge_id"]

        # 2. Verify with biometric signature
        verify_payload = {
            "challenge_id": cid,
            "method": "WINDOWS_HELLO",
            "biometric_signature": "sig-windows-hello-fingerprint-valid",
        }
        status2, token_resp, _ = http_req(f"{CP_URL}/api/v1/endpoint/stepup/verify", method="POST", data=verify_payload)
        self.assertEqual(status2, 200)
        self.assertIn("token_id", token_resp)
        self.assertIn("signature", token_resp)
        self.assertEqual(token_resp["operation"], "database.schema_migration")

        # 3. Replay protection: Re-verifying the same challenge must be rejected
        status3, err_resp, _ = http_req(f"{CP_URL}/api/v1/endpoint/stepup/verify", method="POST", data=verify_payload)
        self.assertEqual(status3, 401)
        self.assertIn("error", err_resp)

    def test_07_offline_capability_classification(self):
        """BAP-463: Classifies Tier 1 (safe local dev allowed offline) vs Tier 2 (cloud egress fails closed)."""
        # Safe local action (pytest)
        s1, eval1, _ = http_req(f"{CP_URL}/api/v1/endpoint/offline/classify", method="POST", data={"operation": "pytest tests/unit"})
        self.assertEqual(s1, 200)
        self.assertEqual(eval1["tier"], "TIER_1_SAFE_LOCAL_DEV")
        self.assertTrue(eval1["allowed_offline"])
        self.assertFalse(eval1["requires_grant"])

        # Protected cloud action (wire transfer / database drop)
        s2, eval2, _ = http_req(f"{CP_URL}/api/v1/endpoint/offline/classify", method="POST", data={"operation": "POST /api/v1/wire-transfer/execute"})
        self.assertEqual(s2, 200)
        self.assertEqual(eval2["tier"], "TIER_2_PROTECTED_CLOUD_EGRESS")
        self.assertFalse(eval2["allowed_offline"])
        self.assertTrue(eval2["requires_grant"])
        self.assertEqual(eval2["offline_policy"], "FAIL_CLOSED_ON_GRANT_EXPIRY")


if __name__ == "__main__":
    unittest.main()

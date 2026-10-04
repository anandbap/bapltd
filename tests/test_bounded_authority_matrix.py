"""
Automated 10-Point Architectural Adversarial Test Matrix.
Verifies the Five Foundational Invariants (I1-I5) and 10 Adversarial Attack Scenarios:
1. Intent Spoofing Resistance (Intent is context, never authority)
2. Grant Parameter Tampering (Cryptographic signature & HMAC integrity)
3. Cross-Resource Token Re-use (Grant for resource A cannot be used on resource B)
4. Dynamic Scope Creep & PEP Derivation (PEP ignores client-spoofed headers)
5. Atomic Single-Use Grant Burning (Replay protection)
6. Concurrent Race-Condition Requests (10 concurrent requests -> exactly 1 success)
7. Edge Broker Command Containment (PreToolUse interceptor governance)
8. Gateway PEP Direct Bypass Rejection (Unauthenticated calls return 401)
9. Unknown Intent Safe Failure (Ambiguous prompt -> UNKNOWN, never privilege escalation)
10. Tamper-Evident Audit Hash Chain (Cryptographic verification of audit events)
"""

import base64
from concurrent.futures import ThreadPoolExecutor
import hashlib
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
GATEWAY_BIN = os.path.join(WORKSPACE_ROOT, "dist", "windows-amd64", "bapgateway.exe")
INTERCEPTOR_BIN = os.path.join(WORKSPACE_ROOT, "dist", "windows-amd64", "interceptor.exe")

TEST_SECRET = "matrix-test-signing-key-32-chars-long-ok!"
TEST_ADMIN_TOKEN = "matrix-test-admin-token-secret-12345"
CP_PORT = 19080
GW_PORT = 19090
CP_URL = f"http://127.0.0.1:{CP_PORT}"
GW_URL = f"http://127.0.0.1:{GW_PORT}"


def http_req(url, method="GET", data=None, headers=None):
    """Helper to perform HTTP requests and return (status, body_dict, raw_bytes)."""
    hdrs = headers or {}
    body_bytes = None
    if data is not None:
        if isinstance(data, dict):
            body_bytes = json.dumps(data).encode("utf-8")
            if "Content-Type" not in hdrs:
                hdrs["Content-Type"] = "application/json"
        elif isinstance(data, str):
            body_bytes = data.encode("utf-8")
        else:
            body_bytes = data

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


class TestBoundedAuthorityMatrix(unittest.TestCase):
    cp_proc = None
    gw_proc = None
    tmp_dir = None
    agent_id = None
    session_token = None
    binary_hash = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

    @classmethod
    def setUpClass(cls):
        cls.tmp_dir = tempfile.mkdtemp(prefix="bap_matrix_")
        db_path = os.path.join(cls.tmp_dir, "test-matrix.db")

        # 1. Start Control Plane
        env_cp = os.environ.copy()
        env_cp["BAP_SECRET_KEY"] = TEST_SECRET
        env_cp["BAP_ADMIN_TOKEN"] = TEST_ADMIN_TOKEN
        cls.cp_proc = subprocess.Popen(
            [
                CONTROL_PLANE_BIN,
                "-port", str(CP_PORT),
                "-secret", TEST_SECRET,
                "-admin-token", TEST_ADMIN_TOKEN,
                "-db", db_path,
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            env=env_cp,
            cwd=WORKSPACE_ROOT,
        )

        # Wait for Control Plane health
        healthy = False
        for _ in range(30):
            try:
                status, body, _ = http_req(f"{CP_URL}/health")
                if status == 200:
                    healthy = True
                    break
            except Exception:
                pass
            time.sleep(0.1)
        if not healthy:
            raise RuntimeError("Control Plane failed to become healthy on port " + str(CP_PORT))

        # 2. Start Gateway PEP
        env_gw = os.environ.copy()
        env_gw["BAP_SECRET_KEY"] = TEST_SECRET
        cls.gw_proc = subprocess.Popen(
            [
                GATEWAY_BIN,
                "-port", str(GW_PORT),
                "-controlplane", CP_URL,
                "-secret", TEST_SECRET,
                "-consume=true",
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            env=env_gw,
            cwd=WORKSPACE_ROOT,
        )

        # Wait for Gateway health
        healthy = False
        for _ in range(30):
            try:
                status, body, _ = http_req(f"{GW_URL}/health")
                if status == 200:
                    healthy = True
                    break
            except Exception:
                pass
            time.sleep(0.1)
        if not healthy:
            raise RuntimeError("Gateway PEP failed to become healthy on port " + str(GW_PORT))

        # 3. Pre-register and enroll test agent
        prereg_payload = {
            "app_id": "matrix-test-agent",
            "owner_email": "security@matrix.test",
            "agent_name": "MatrixTestAgent",
            "env_profile": "test",
            "permitted_scopes": ["api:read", "financial:read", "financial:write", "core_banking"],
        }
        status, resp, _ = http_req(
            f"{CP_URL}/api/v1/agents/pre-register",
            method="POST",
            data=prereg_payload,
            headers={"X-BAP-Admin-Token": TEST_ADMIN_TOKEN},
        )
        if status != 201:
            raise RuntimeError(f"Agent pre-registration failed: {resp}")
        otc = resp.get("one_time_code") or resp.get("code")
        cls.agent_id = resp["agent_id"]

        # Register edge
        reg_payload = {
            "one_time_code": otc,
            "agent_name": "MatrixTestAgent",
            "hostname": "matrix-test-box",
            "binary_hash": cls.binary_hash,
            "public_key": "matrix-test-ed25519-public-key-sample",
            "spiffe_id": f"spiffe://bap.internal/agent/{cls.agent_id}",
        }
        status, resp, _ = http_req(
            f"{CP_URL}/api/v1/agents/register-edge",
            method="POST",
            data=reg_payload,
        )
        if status != 200:
            raise RuntimeError(f"Edge registration failed: {resp}")
        cls.session_token = resp["session_token"]

    @classmethod
    def tearDownClass(cls):
        if cls.gw_proc:
            cls.gw_proc.terminate()
            try:
                cls.gw_proc.wait(timeout=2)
            except Exception:
                cls.gw_proc.kill()
        if cls.cp_proc:
            cls.cp_proc.terminate()
            try:
                cls.cp_proc.wait(timeout=2)
            except Exception:
                cls.cp_proc.kill()
        if cls.tmp_dir and os.path.exists(cls.tmp_dir):
            shutil.rmtree(cls.tmp_dir, ignore_errors=True)

    def _acquire_grant(self, action, resource, intent=None, max_uses=1):
        payload = {
            "agent_id": self.agent_id,
            "session_id": "matrix-session-1",
            "binary_hash": self.binary_hash,
            "scopes": ["financial:read", "financial:write"],
            "action": action,
            "resource": resource,
            "intent": intent or "matrix.test.intent",
            "constraints": {"max_uses": max_uses},
        }
        headers = {
            "X-BAP-Admin-Token": TEST_ADMIN_TOKEN,
            "Authorization": f"Bearer {self.session_token}",
        }
        status, resp, _ = http_req(
            f"{CP_URL}/api/v1/grants/acquire",
            method="POST",
            data=payload,
            headers=headers,
        )
        self.assertEqual(status, 200, f"Acquire grant failed: {resp}")
        return resp["token"]

    # -------------------------------------------------------------------------
    # Test 1: Intent is context, never authority (BAP-405, BAP-409, Invariant I1)
    # -------------------------------------------------------------------------
    def test_01_intent_is_context_never_authority(self):
        payload = {
            "agent_id": self.agent_id,
            "session_id": "matrix-session-1",
            "binary_hash": self.binary_hash,
            "scopes": ["unpermitted_scope"],
            "action": "admin.drop_db",
            "resource": "database/production",
            "intent": "customer.read",
        }
        # Calling without valid admin/session token must fail
        status, resp, _ = http_req(
            f"{CP_URL}/api/v1/grants/acquire",
            method="POST",
            data=payload,
            headers={"Authorization": "Bearer bad-token"},
        )
        self.assertEqual(status, 401, "Acquiring grant with unauthenticated intent must fail 401")

    # -------------------------------------------------------------------------
    # Test 2: Grant Parameter Tampering (BAP-408)
    # -------------------------------------------------------------------------
    def test_02_grant_cryptographic_integrity_tamper_rejection(self):
        grant = self._acquire_grant("financial.records.read", "/api/v1/financial-records")
        parts = grant.split(".")
        self.assertEqual(len(parts), 3)

        # Tamper payload: change resource to something else
        payload_bytes = base64.urlsafe_b64decode(parts[1] + "==")
        claims = json.loads(payload_bytes.decode("utf-8"))
        claims["resource"] = "/api/v1/core-banking/steal"
        tampered_b64 = base64.urlsafe_b64encode(json.dumps(claims).encode("utf-8")).decode("utf-8").rstrip("=")

        tampered_token = f"{parts[0]}.{tampered_b64}.{parts[2]}"
        status, resp, _ = http_req(
            f"{GW_URL}/api/v1/financial-records",
            headers={"Authorization": f"Bearer {tampered_token}"},
        )
        self.assertEqual(status, 403, "Tampered grant must be rejected by Gateway PEP (403)")
        self.assertEqual(resp.get("pep_decision"), "DENY")

    # -------------------------------------------------------------------------
    # Test 3: Cross-Resource Token Re-use (BAP-412)
    # -------------------------------------------------------------------------
    def test_03_cross_resource_reuse_prevented(self):
        # Grant bounded to /api/v1/financial-records
        grant = self._acquire_grant("financial.records.read", "/api/v1/financial-records")

        # Attempt to use against /api/v1/core-banking/account-123
        status, resp, _ = http_req(
            f"{GW_URL}/api/v1/core-banking/account-123",
            headers={"Authorization": f"Bearer {grant}"},
        )
        self.assertEqual(status, 403, "Cross-resource grant re-use must be rejected (403)")
        self.assertEqual(resp.get("pep_decision"), "DENY")

    # -------------------------------------------------------------------------
    # Test 4: Dynamic Scope Creep & Gateway PEP Derivation (BAP-411, Invariant I3)
    # -------------------------------------------------------------------------
    def test_04_pep_derives_actual_operation_ignores_spoofed_headers(self):
        # Grant for financial.records.read
        read_grant = self._acquire_grant("financial.records.read", "/api/v1/financial-records")

        # Client attempts a POST (write), but sends spoofed header claiming it's just a read
        status, resp, _ = http_req(
            f"{GW_URL}/api/v1/financial-records",
            method="POST",
            data={"action": "unauthorized_write"},
            headers={
                "Authorization": f"Bearer {read_grant}",
                "X-Agent-Action": "financial.records.read",  # Spoofed header
            },
        )
        self.assertEqual(status, 403, "Gateway PEP must derive operation from HTTP method and deny write")
        self.assertEqual(resp.get("pep_decision"), "DENY")

    # -------------------------------------------------------------------------
    # Test 5: Atomic Single-Use Grant Burning (BAP-417, Invariant I4)
    # -------------------------------------------------------------------------
    def test_05_atomic_single_use_grant_burning(self):
        grant = self._acquire_grant("financial.records.read", "/api/v1/financial-records", max_uses=1)

        # 1st use -> 200 OK
        status1, resp1, _ = http_req(
            f"{GW_URL}/api/v1/financial-records",
            headers={"Authorization": f"Bearer {grant}"},
        )
        self.assertEqual(status1, 200, "1st use of valid single-use grant must succeed")
        self.assertEqual(resp1.get("pep_decision"), "ALLOW")

        # 2nd use -> Replay attack -> 403 Forbidden
        status2, resp2, _ = http_req(
            f"{GW_URL}/api/v1/financial-records",
            headers={"Authorization": f"Bearer {grant}"},
        )
        self.assertEqual(status2, 403, "Replaying a consumed single-use grant must fail (403)")
        self.assertEqual(resp2.get("pep_decision"), "DENY")

    # -------------------------------------------------------------------------
    # Test 6: Concurrent Race-Condition Requests (BAP-416, BAP-417)
    # -------------------------------------------------------------------------
    def test_06_concurrent_race_condition_protection(self):
        grant = self._acquire_grant("financial.records.read", "/api/v1/financial-records", max_uses=1)

        def make_call():
            s, r, _ = http_req(
                f"{GW_URL}/api/v1/financial-records",
                headers={"Authorization": f"Bearer {grant}"},
            )
            return s

        # Dispatch 10 concurrent requests simultaneously
        with ThreadPoolExecutor(max_workers=10) as pool:
            futures = [pool.submit(make_call) for _ in range(10)]
            results = [f.result() for f in futures]

        success_count = results.count(200)
        deny_count = results.count(403)

        self.assertEqual(success_count, 1, f"Expected exactly 1 success under concurrency, got {success_count}")
        self.assertEqual(deny_count, 9, f"Expected 9 rejections under concurrency, got {deny_count}")

    # -------------------------------------------------------------------------
    # Test 7: Edge Broker Command Containment (BAP-200, BAP-421)
    # -------------------------------------------------------------------------
    def test_07_edge_broker_command_containment(self):
        # Claude Code interceptor hook must detect and deny tampering with protected BAP assets
        proc = subprocess.Popen(
            [INTERCEPTOR_BIN],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            cwd=WORKSPACE_ROOT,
        )
        payload = {
            "hook_event_name": "PreToolUse",
            "tool_name": "Write",
            "tool_input": {"file_path": "policy.cedar"},
        }
        out, _ = proc.communicate(input=json.dumps(payload))
        resp = json.loads(out.strip())
        hook_out = resp.get("hookSpecificOutput", {})
        self.assertEqual(hook_out.get("permissionDecision"), "deny")
        self.assertIn("Security Invariant Violation", hook_out.get("permissionDecisionReason", ""))

    # -------------------------------------------------------------------------
    # Test 8: Gateway PEP Direct Bypass Rejection (BAP-410, BAP-438)
    # -------------------------------------------------------------------------
    def test_08_gateway_pep_direct_bypass_rejected(self):
        # Direct unauthenticated request without Bearer token must receive 401
        status, resp, _ = http_req(f"{GW_URL}/api/v1/financial-records")
        self.assertEqual(status, 401, "Unauthenticated direct access must be blocked with 401")
        self.assertEqual(resp.get("pep_decision"), "DENY")
        self.assertIn("Rogue agent", resp.get("message", ""))

    # -------------------------------------------------------------------------
    # Test 9: Unknown Intent Safe Failure (BAP-406, Invariant I1)
    # -------------------------------------------------------------------------
    def test_09_unknown_intent_fails_safely(self):
        sess_id = "sess-matrix-unknown-test"
        # 1. Start session on control plane
        start_payload = {
            "session_id": sess_id,
            "agent_name": "MatrixAgent",
            "app_id": "claude-code",
        }
        status, _, _ = http_req(f"{CP_URL}/api/v1/sessions/start", method="POST", data=start_payload)
        self.assertEqual(status, 200)

        # 2. Feed unclassifiable ambiguous prompt into interceptor
        env = os.environ.copy()
        env["BAP_SESSION_ID"] = sess_id
        env["BAP_SERVER_URL"] = CP_URL
        proc = subprocess.Popen(
            [INTERCEPTOR_BIN],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            cwd=WORKSPACE_ROOT,
            env=env,
        )
        payload = {
            "hook_event_name": "UserPromptSubmit",
            "user_prompt": "recite a poem about quantum gravity and bananas",
            "session_id": sess_id,
        }
        out, _ = proc.communicate(input=json.dumps(payload))
        self.assertIn("ok", out.lower())

        # 3. Verify on control plane that intent was classified as UNKNOWN
        status, sess_data, _ = http_req(f"{CP_URL}/api/v1/sessions/{sess_id}")
        self.assertEqual(status, 200)
        intent_info = sess_data.get("intent", {})
        self.assertEqual(intent_info.get("primary"), "UNKNOWN")
        self.assertEqual(intent_info.get("confidence"), 0.0)
        self.assertIn("UNKNOWN", sess_data.get("intent_history", []))

    # -------------------------------------------------------------------------
    # Test 10: Tamper-Evident Audit Hash Chain (BAP-221, BAP-433, Invariant I5)
    # -------------------------------------------------------------------------
    def test_10_audit_hash_chain_tamper_evident(self):
        status, resp, _ = http_req(
            f"{CP_URL}/api/v1/control/chain/verify",
            headers={"X-BAP-Admin-Token": TEST_ADMIN_TOKEN},
        )
        self.assertEqual(status, 200, "Chain verification endpoint must return 200")
        self.assertTrue(
            resp.get("valid") is True or resp.get("chain_status") == "valid",
            f"Audit chain must be cryptographically valid: {resp}",
        )


if __name__ == "__main__":
    unittest.main()

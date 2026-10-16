"""
Unit and Integration Tests for BAP-539:
Multi-Harness Adapters & SaaS Delegated Token Governance (BAP-EPIC-29).

Validates:
1. AC1: Cursor and Gemini CLI report standardized CanonicalActivityEvent telemetry to Agent Watch dashboard.
2. AC2: Browser agent attempting to navigate to unapproved domain or upload credentials is intercepted and blocked.
3. AC3: SaaS OAuth tokens cannot be reused outside of attested BAP session contexts.
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

TEST_SECRET = "saas-multi-harness-secret-32b-key!"
TEST_ADMIN_TOKEN = "saas-admin-token-secret-999"
CP_PORT = 19385
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


class TestBAP539MultiHarness(unittest.TestCase):
    cp_proc = None
    tmp_dir = None

    @classmethod
    def setUpClass(cls):
        cls.tmp_dir = tempfile.mkdtemp(prefix="bap_harness_test_")
        db_path = os.path.join(cls.tmp_dir, "harness.db")

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

    def test_01_cursor_adapter_configuration_and_telemetry(self):
        """Test Cursor IDE adapter config generation and CanonicalActivityEvent emission."""
        target_dir = os.path.join(self.tmp_dir, "cursor_workspace")
        os.makedirs(target_dir, exist_ok=True)

        # 1. Run configuration command
        proc = subprocess.run(
            [BAPEDGE_BIN, "adapter", "cursor", "configure", "--dir", target_dir],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        self.assertEqual(proc.returncode, 0, f"cursor configure failed: {proc.stderr}")
        self.assertIn("Cursor workspace configured successfully", proc.stdout)

        # 2. Check generated files
        cursor_rules = os.path.join(target_dir, ".cursorrules")
        cursor_mcp = os.path.join(target_dir, ".cursor", "mcp.json")
        self.assertTrue(os.path.exists(cursor_rules), ".cursorrules should exist")
        self.assertTrue(os.path.exists(cursor_mcp), ".cursor/mcp.json should exist")

        with open(cursor_rules, "r", encoding="utf-8") as f:
            content = f.read()
            self.assertIn("bapedge.exe exec", content)

        with open(cursor_mcp, "r", encoding="utf-8") as f:
            mcp_data = json.load(f)
            self.assertIn("mcpServers", mcp_data)
            self.assertIn("bap-zero-trust", mcp_data["mcpServers"])

        # 3. Emit standardized CanonicalActivityEvent
        emit_proc = subprocess.run(
            [
                BAPEDGE_BIN, "adapter", "emit",
                "--harness", "cursor",
                "--action", "terminal_command",
                "--target", "git status",
                "--decision", "ALLOW",
            ],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        self.assertEqual(emit_proc.returncode, 0)
        evt = json.loads(emit_proc.stdout.strip())
        self.assertEqual(evt.get("harness_type"), "cursor")
        self.assertEqual(evt.get("decision"), "ALLOW")
        self.assertEqual(evt.get("target"), "git status")
        self.assertTrue(evt.get("event_id", "").startswith("act-cursor-"))

    def test_02_gemini_cli_adapter_configuration_and_telemetry(self):
        """Test Gemini CLI adapter config generation and CanonicalActivityEvent emission."""
        target_dir = os.path.join(self.tmp_dir, "gemini_workspace")
        os.makedirs(target_dir, exist_ok=True)

        proc = subprocess.run(
            [BAPEDGE_BIN, "adapter", "gemini", "configure", "--dir", target_dir],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        self.assertEqual(proc.returncode, 0, f"gemini configure failed: {proc.stderr}")
        self.assertIn("Gemini CLI workspace rules configured successfully", proc.stdout)

        gemini_rules = os.path.join(target_dir, "GEMINI.md")
        self.assertTrue(os.path.exists(gemini_rules), "GEMINI.md should exist")

        with open(gemini_rules, "r", encoding="utf-8") as f:
            content = f.read()
            self.assertIn("bapedge.exe exec", content)

        emit_proc = subprocess.run(
            [
                BAPEDGE_BIN, "adapter", "emit",
                "--harness", "gemini-cli",
                "--action", "prompt",
                "--target", "Explain policy.cedar",
                "--decision", "ALLOW",
            ],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        self.assertEqual(emit_proc.returncode, 0)
        evt = json.loads(emit_proc.stdout.strip())
        self.assertEqual(evt.get("harness_type"), "gemini-cli")
        self.assertEqual(evt.get("decision"), "ALLOW")
        self.assertTrue(evt.get("event_id", "").startswith("act-gemini-cli-"))

    def test_03_browser_agent_domain_allowlist_and_credential_blocking(self):
        """Test Browser agent CDP/Playwright proxy domain allowlist and credential upload blocking."""
        # 1. Navigation allow test
        nav_allow = subprocess.run(
            [BAPEDGE_BIN, "adapter", "browser", "check-url", "http://localhost:8080/dashboard"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        self.assertEqual(nav_allow.returncode, 0)
        out = json.loads(nav_allow.stdout.strip())
        self.assertTrue(out.get("allowed"))
        self.assertEqual(out.get("decision"), "ALLOW")

        # 2. Navigation deny test (unapproved external / untrusted domain)
        nav_deny = subprocess.run(
            [BAPEDGE_BIN, "adapter", "browser", "check-url", "https://untrusted-test.internal/phish"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        self.assertNotEqual(nav_deny.returncode, 0)
        out = json.loads(nav_deny.stdout.strip())
        self.assertFalse(out.get("allowed"))
        self.assertEqual(out.get("decision"), "DENY")
        self.assertIn("untrusted-test.internal", out.get("reason"))

        # 3. File upload allow test (safe report)
        safe_file = os.path.join(self.tmp_dir, "safe_report.txt")
        with open(safe_file, "w", encoding="utf-8") as f:
            f.write("Q3 Financial reconciliation numbers: $4,500,000")

        up_allow = subprocess.run(
            [BAPEDGE_BIN, "adapter", "browser", "check-upload", safe_file],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        self.assertEqual(up_allow.returncode, 0)
        out = json.loads(up_allow.stdout.strip())
        self.assertTrue(out.get("allowed"))

        # 4. File upload deny test (sensitive credential file .env)
        env_file = os.path.join(self.tmp_dir, ".env")
        with open(env_file, "w", encoding="utf-8") as f:
            f.write("DATABASE_URL=postgres://user:pass@internal.db:5432/corp\nAWS_SECRET_ACCESS_KEY=AKIAIOSFODNN7EXAMPLE")

        up_deny = subprocess.run(
            [BAPEDGE_BIN, "adapter", "browser", "check-upload", env_file],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        self.assertNotEqual(up_deny.returncode, 0)
        out = json.loads(up_deny.stdout.strip())
        self.assertFalse(out.get("allowed"))
        self.assertEqual(out.get("decision"), "DENY")
        self.assertIn("Sensitive credential file", out.get("reason"))

    def test_04_saas_delegated_token_session_binding_and_cross_session_rejection(self):
        """Test SaaS OAuth delegated-token session binding and cross-session reuse violation rejection."""
        # 1. Bind SaaS OAuth token to attested session
        bind_payload = {
            "provider": "salesforce",
            "token_id": "saas-token-crm-sf99",
            "session_id": "sess-attested-salesforce-001",
            "agent_id": "sf-crm-syncer",
            "user_email": "developer@corp.internal",
            "scopes": ["crm:read", "crm:write"],
            "ttl_seconds": 600,
        }

        status, body, _ = http_req(
            f"{CP_URL}/api/v1/saas/tokens/bind",
            method="POST",
            data=bind_payload,
        )
        self.assertEqual(status, 201)
        self.assertEqual(body.get("token_id"), "saas-token-crm-sf99")
        self.assertEqual(body.get("bound_session_id"), "sess-attested-salesforce-001")
        self.assertEqual(body.get("status"), "active")

        # 2. Verify token inside bound session context -> Authorized
        verify_valid_payload = {
            "token_id": "saas-token-crm-sf99",
            "caller_session_id": "sess-attested-salesforce-001",
            "requested_scope": "crm:read",
        }
        status, body, _ = http_req(
            f"{CP_URL}/api/v1/saas/tokens/verify",
            method="POST",
            data=verify_valid_payload,
        )
        self.assertEqual(status, 200)
        self.assertTrue(body.get("allowed"))
        self.assertEqual(body.get("status"), "Authorized")

        # 3. Attempt to reuse token in an unapproved/different session context -> Rejected with 403
        verify_invalid_payload = {
            "token_id": "saas-token-crm-sf99",
            "caller_session_id": "sess-adversary-stolen-session-999",
            "requested_scope": "crm:read",
        }
        status, body, _ = http_req(
            f"{CP_URL}/api/v1/saas/tokens/verify",
            method="POST",
            data=verify_invalid_payload,
        )
        self.assertEqual(status, 403)
        self.assertFalse(body.get("allowed"))
        self.assertEqual(body.get("status"), "SessionBindingViolation")
        self.assertIn("SaaSTokenSessionBindingViolation", body.get("reason", ""))

        # 4. List active SaaS token bindings
        status, body, _ = http_req(
            f"{CP_URL}/api/v1/saas/tokens",
            method="GET",
        )
        self.assertEqual(status, 200)
        self.assertGreaterEqual(body.get("count", 0), 1)
        token_ids = [t.get("token_id") for t in body.get("tokens", [])]
        self.assertIn("saas-token-crm-sf99", token_ids)


if __name__ == "__main__":
    unittest.main()

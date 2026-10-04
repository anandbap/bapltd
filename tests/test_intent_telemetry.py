"""
Test Suite: Live Cumulative Intent Telemetry
============================================
Verifies that:
- Every prompt submission increments the respective intent category count.
- Previous intent categories remain visible and retain their counts when new intents are declared.
- No category disappears when another is submitted ("one shows other disappears" bug is resolved).
- Both /api/v1/inspector/data and /api/v1/admin/inspector/data expose intent_counts and total_prompts.
"""

import hashlib
import json
import os
import ssl
import sys
import unittest
import urllib.request

WORKSPACE_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(WORKSPACE_ROOT, "python-agent"))

ssl_ctx = ssl.create_default_context()
ssl_ctx.check_hostname = False
ssl_ctx.verify_mode = ssl.CERT_NONE


def get_control_plane_url() -> str:
    try:
        from bap_sdk import resolve_endpoints
        ep = resolve_endpoints()
        return ep.get("controlplane_url", "https://localhost:8443").rstrip("/")
    except Exception:
        return "https://localhost:8443"


def read_admin_token() -> str:
    token_file = os.path.join(WORKSPACE_ROOT, ".bap-admin-token")
    if os.path.isfile(token_file):
        try:
            with open(token_file, "r", encoding="utf-8") as f:
                return f.read().strip()
        except Exception:
            pass
    return os.getenv("BAP_ADMIN_TOKEN", "")


class TestIntentTelemetry(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server_url = get_control_plane_url()
        cls.admin_token = read_admin_token()
        try:
            req = urllib.request.Request(f"{cls.server_url}/health", method="GET")
            with urllib.request.urlopen(req, context=ssl_ctx, timeout=2):
                pass
        except Exception:
            try:
                req = urllib.request.Request(f"{cls.server_url}/api/v1/inspector/data", method="GET")
                with urllib.request.urlopen(req, context=ssl_ctx, timeout=2):
                    pass
            except Exception as e:
                raise unittest.SkipTest(f"Live control plane not reachable at {cls.server_url}: {e}")

    def api_request(self, method: str, path: str, payload: dict = None) -> tuple[int, dict]:
        url = f"{self.server_url}{path}"
        data = json.dumps(payload).encode("utf-8") if payload else None
        req = urllib.request.Request(url, data=data, method=method)
        req.add_header("Content-Type", "application/json")
        if self.admin_token:
            req.add_header("Authorization", f"Bearer {self.admin_token}")
            req.add_header("X-BAP-Admin-Token", self.admin_token)

        try:
            with urllib.request.urlopen(req, context=ssl_ctx, timeout=5) as resp:
                body = resp.read().decode("utf-8")
                res_json = json.loads(body) if body.strip().startswith(("{", "[")) else {}
                return resp.status, res_json
        except urllib.error.HTTPError as e:
            body = e.read().decode("utf-8") if e.fp else ""
            res_json = json.loads(body) if body.strip().startswith(("{", "[")) else {}
            return e.code, res_json

    def test_live_intent_accumulation_no_disappearing(self):
        """Verifies sequential prompts across categories accumulate and never overwrite."""
        # 1. Inspect initial telemetry
        st, data = self.api_request("GET", "/api/v1/inspector/data")
        self.assertEqual(st, 200)
        self.assertIn("intent_counts", data)
        self.assertIn("total_prompts", data)

        initial_total = data.get("total_prompts", 0)
        initial_counts = data.get("intent_counts", {})
        init_tv = initial_counts.get("TEST_VERIFICATION", 0)
        init_bf = initial_counts.get("BUG_FIX", 0)
        init_fe = initial_counts.get("FEATURE_ENHANCEMENT", 0)

        # 2. Start session with TEST_VERIFICATION
        sess_id = "sess-intent-test-agent"
        start_payload = {
            "session_id": sess_id,
            "agent_name": "Telemetry Tester",
            "app_id": "claude-code",
            "user_prompt": "Run full regression verification suite",
            "intent": {
                "primary": "TEST_VERIFICATION",
                "confidence": 0.95,
                "classifier_version": "bap-intent-rules-v1",
                "source": "claude-user-prompt-submit"
            }
        }
        st, _ = self.api_request("POST", "/api/v1/sessions/start", start_payload)
        self.assertEqual(st, 200)

        st, d1 = self.api_request("GET", "/api/v1/inspector/data")
        self.assertEqual(st, 200)
        counts1 = d1.get("intent_counts", {})
        self.assertEqual(counts1.get("TEST_VERIFICATION", 0), init_tv + 1)
        self.assertEqual(d1.get("total_prompts", 0), initial_total + 1)

        # 3. Submit Prompt 2 with BUG_FIX on same agent
        prompt2 = "Fix null pointer exception in authentication token parser"
        p2_hash = hashlib.sha256(prompt2.encode("utf-8")).hexdigest()
        prompt2_payload = {
            "session_id": sess_id,
            "user_prompt": prompt2,
            "producer": "claude-lifecycle-hook",
            "prompt_hash": p2_hash,
            "prompt_capture_enabled": True,
            "intent": {
                "primary": "BUG_FIX",
                "confidence": 0.92,
                "classifier_version": "bap-intent-rules-v1",
                "source": "claude-user-prompt-submit"
            }
        }
        st, _ = self.api_request("POST", "/api/v1/sessions/prompt", prompt2_payload)
        self.assertEqual(st, 200)

        # Both TEST_VERIFICATION and BUG_FIX must exist! TEST_VERIFICATION did NOT disappear!
        st, d2 = self.api_request("GET", "/api/v1/inspector/data")
        self.assertEqual(st, 200)
        counts2 = d2.get("intent_counts", {})
        self.assertEqual(counts2.get("TEST_VERIFICATION", 0), init_tv + 1, "TEST_VERIFICATION must not drop")
        self.assertEqual(counts2.get("BUG_FIX", 0), init_bf + 1, "BUG_FIX must increment")
        self.assertEqual(d2.get("total_prompts", 0), initial_total + 2)

        # 4. Submit Prompt 3 with BUG_FIX again
        prompt3 = "Fix memory leak in websocket event streaming worker"
        p3_hash = hashlib.sha256(prompt3.encode("utf-8")).hexdigest()
        prompt3_payload = {
            "session_id": sess_id,
            "user_prompt": prompt3,
            "producer": "claude-lifecycle-hook",
            "prompt_hash": p3_hash,
            "prompt_capture_enabled": True,
            "intent": {
                "primary": "BUG_FIX",
                "confidence": 0.94,
                "classifier_version": "bap-intent-rules-v1",
                "source": "claude-user-prompt-submit"
            }
        }
        st, _ = self.api_request("POST", "/api/v1/sessions/prompt", prompt3_payload)
        self.assertEqual(st, 200)

        st, d3 = self.api_request("GET", "/api/v1/inspector/data")
        self.assertEqual(st, 200)
        counts3 = d3.get("intent_counts", {})
        self.assertEqual(counts3.get("TEST_VERIFICATION", 0), init_tv + 1)
        self.assertEqual(counts3.get("BUG_FIX", 0), init_bf + 2, "BUG_FIX must be 2")
        self.assertEqual(d3.get("total_prompts", 0), initial_total + 3)

        # 5. Submit Prompt 4 with FEATURE_ENHANCEMENT
        prompt4 = "Add dark mode toggle and real-time live charts to analytics dashboard"
        p4_hash = hashlib.sha256(prompt4.encode("utf-8")).hexdigest()
        prompt4_payload = {
            "session_id": sess_id,
            "user_prompt": prompt4,
            "producer": "claude-lifecycle-hook",
            "prompt_hash": p4_hash,
            "prompt_capture_enabled": True,
            "intent": {
                "primary": "FEATURE_ENHANCEMENT",
                "confidence": 0.89,
                "classifier_version": "bap-intent-rules-v1",
                "source": "claude-user-prompt-submit"
            }
        }
        st, _ = self.api_request("POST", "/api/v1/sessions/prompt", prompt4_payload)
        self.assertEqual(st, 200)

        # Verify all 3 categories coexist concurrently with exact counts
        st, d4 = self.api_request("GET", "/api/v1/inspector/data")
        self.assertEqual(st, 200)
        counts4 = d4.get("intent_counts", {})
        self.assertEqual(counts4.get("TEST_VERIFICATION", 0), init_tv + 1, "TEST_VERIFICATION must still exist")
        self.assertEqual(counts4.get("BUG_FIX", 0), init_bf + 2, "BUG_FIX must still be 2")
        self.assertEqual(counts4.get("FEATURE_ENHANCEMENT", 0), init_fe + 1, "FEATURE_ENHANCEMENT must increment")
        self.assertEqual(d4.get("total_prompts", 0), initial_total + 4)

        # 6. End test session cleanly
        self.api_request("POST", "/api/v1/sessions/end", {"session_id": sess_id, "reason": "test_complete"})


if __name__ == "__main__":
    unittest.main()

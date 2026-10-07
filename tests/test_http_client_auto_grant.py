"""
Automated Test Suite for BAPHttpClient and JIT STS Grant Injection.
Verifies:
1. Canonical Action & Resource deduction from HTTP methods and URLs.
2. BAPResponse wrapper semantics (status_code, json, ok, content, raise_for_status).
3. Automatic STS Grant acquisition with fine-grained action & resource bindings.
4. Transparent header injection (Authorization: Bearer <grant>, X-BAP-Grant-Token, X-BAP-Session-ID).
"""

import http.server
import json
import os
import sys
import threading
import unittest

WORKSPACE_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(WORKSPACE_ROOT, "python-agent"))

from bap_sdk import BAPSession, BAPHttpClient, BAPResponse


class MockTargetServerHandler(http.server.BaseHTTPRequestHandler):
    """Echo server that records incoming headers and request details."""
    last_request = {}

    def log_message(self, format, *args):
        pass  # Suppress logging

    def do_GET(self):
        self._record_and_respond()

    def do_POST(self):
        self._record_and_respond()

    def do_PUT(self):
        self._record_and_respond()

    def do_DELETE(self):
        self._record_and_respond()

    def _record_and_respond(self):
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length).decode("utf-8") if content_length > 0 else ""
        
        MockTargetServerHandler.last_request = {
            "method": self.command,
            "path": self.path,
            "auth_header": self.headers.get("Authorization"),
            "grant_token_header": self.headers.get("X-BAP-Grant-Token"),
            "session_id_header": self.headers.get("X-BAP-Session-ID"),
            "body": body,
        }
        
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        response_data = {"status": "success", "echo_path": self.path}
        self.wfile.write(json.dumps(response_data).encode("utf-8"))


class TestBAPHttpClient(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Start a local mock target server on an ephemeral port
        cls.server = http.server.HTTPServer(("127.0.0.1", 0), MockTargetServerHandler)
        cls.server_port = cls.server.server_port
        cls.server_url = f"http://127.0.0.1:{cls.server_port}"
        cls.server_thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.server_thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def test_deduce_action_and_resource(self):
        """Test deterministic action and resource deduction from HTTP method and URL."""
        test_cases = [
            ("GET", "https://api.corp.internal/v1/payments/pay_123", "http:get", "https://api.corp.internal/v1/payments/pay_123"),
            ("POST", "https://api.corp.internal/v1/payments", "http:post", "https://api.corp.internal/v1/payments"),
            ("PUT", "/api/v1/records/42", "http:put", "/api/v1/records/42"),
            ("DELETE", "http://vault.internal/secrets/db_creds", "http:delete", "http://vault.internal/secrets/db_creds"),
            ("PATCH", "https://crm.corp.internal/leads/99", "http:patch", "https://crm.corp.internal/leads/99"),
        ]
        for method, url, expected_action, expected_resource in test_cases:
            action, resource = BAPHttpClient.deduce_action_and_resource(method, url)
            self.assertEqual(action, expected_action)
            self.assertEqual(resource, expected_resource)

    def test_bap_response_properties(self):
        """Test BAPResponse attributes and helper methods."""
        resp_ok = BAPResponse(200, '{"result": "ok", "count": 5}', {"content-type": "application/json"}, grant_token="jwt-svid-test")
        self.assertTrue(resp_ok.ok)
        self.assertEqual(resp_ok.status_code, 200)
        self.assertEqual(resp_ok.json()["count"], 5)
        self.assertEqual(resp_ok.content, b'{"result": "ok", "count": 5}')
        self.assertEqual(resp_ok.grant_token, "jwt-svid-test")
        resp_ok.raise_for_status()  # Should not raise

        resp_err = BAPResponse(403, 'Forbidden', {})
        self.assertFalse(resp_err.ok)
        with self.assertRaises(Exception):
            resp_err.raise_for_status()

    def test_transparent_request_with_mock_grant(self):
        """
        Test that BAPHttpClient automatically deduces action/resource,
        calls acquire_grant, and injects Authorization and BAP headers.
        """
        session = BAPSession(app_id="test-http-agent", server_url="http://localhost:8080")
        
        # Monkey-patch acquire_grant to capture arguments and return a synthetic STS grant token
        acquired_calls = []
        def mock_acquire_grant(scopes=None, action=None, resource=None, constraints=None):
            call_info = {
                "scopes": scopes,
                "action": action,
                "resource": resource,
                "constraints": constraints,
            }
            acquired_calls.append(call_info)
            return f"mock-sts-grant-token-{action}"

        session.acquire_grant = mock_acquire_grant

        # 1. Execute GET request via session client
        client = session.client()
        target_url = f"{self.server_url}/v1/customers/cust_987"
        resp = client.get(target_url)

        self.assertTrue(resp.ok)
        self.assertEqual(resp.json()["status"], "success")
        self.assertEqual(resp.grant_token, "mock-sts-grant-token-http:get")

        # Verify acquire_grant received deduced action & resource
        self.assertEqual(len(acquired_calls), 1)
        self.assertEqual(acquired_calls[0]["action"], "http:get")
        self.assertEqual(acquired_calls[0]["resource"], target_url)
        self.assertEqual(acquired_calls[0]["scopes"], ["api:read"])

        # Verify target server received injected headers
        last_req = MockTargetServerHandler.last_request
        self.assertEqual(last_req["method"], "GET")
        self.assertEqual(last_req["path"], "/v1/customers/cust_987")
        self.assertEqual(last_req["auth_header"], "Bearer mock-sts-grant-token-http:get")
        self.assertEqual(last_req["grant_token_header"], "mock-sts-grant-token-http:get")
        self.assertEqual(last_req["session_id_header"], session.session_id)

        # 2. Execute POST request via session.post helper
        post_url = f"{self.server_url}/v1/transfers"
        post_payload = {"amount": 500, "currency": "USD"}
        resp_post = session.post(post_url, json=post_payload)

        self.assertTrue(resp_post.ok)
        self.assertEqual(resp_post.grant_token, "mock-sts-grant-token-http:post")

        self.assertEqual(len(acquired_calls), 2)
        self.assertEqual(acquired_calls[1]["action"], "http:post")
        self.assertEqual(acquired_calls[1]["resource"], post_url)
        self.assertEqual(acquired_calls[1]["scopes"], ["api:write"])

        last_post_req = MockTargetServerHandler.last_request
        self.assertEqual(last_post_req["method"], "POST")
        self.assertEqual(last_post_req["auth_header"], "Bearer mock-sts-grant-token-http:post")
        self.assertEqual(json.loads(last_post_req["body"]), post_payload)


if __name__ == "__main__":
    unittest.main()


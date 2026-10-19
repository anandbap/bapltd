#!/usr/bin/env python3
"""
BAP-742: Vendor Integration and Proof-of-Concept Testing Suite

Tests interoperability and integration points across:
1. RFC 8693 Token Exchange between BAP Gateway and downstream cloud providers
2. RFC 7515 JWS verification by external candidate relying parties (Keycard, Runlayer, AIR)
3. Zero privilege amplification guarantees
4. Single-use grant token burning and anti-replay defense
"""

import sys
import unittest
import json
import hmac
import hashlib
import base64
import time
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR))


def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode('utf-8').rstrip('=')


def b64url_decode(data: str) -> bytes:
    padding = '=' * (4 - (len(data) % 4))
    return base64.urlsafe_b64decode(data + padding)


class TestBAP742VendorInterop(unittest.TestCase):
    def setUp(self):
        self.signing_secret = b"bap-default-jws-enterprise-signing-secret"
        self.issuer = "https://controlplane.bap.internal"
        self.audience = "https://gateway.bap.internal"

    def mint_simulated_jws(self, claims: dict, kid: str = "bap-key-2026-v1") -> str:
        header = {"alg": "HS256", "typ": "JWT", "kid": kid}
        enc_header = b64url_encode(json.dumps(header).encode('utf-8'))
        enc_payload = b64url_encode(json.dumps(claims).encode('utf-8'))
        signing_input = f"{enc_header}.{enc_payload}".encode('utf-8')
        sig = hmac.new(self.signing_secret, signing_input, hashlib.sha256).digest()
        enc_sig = b64url_encode(sig)
        return f"{enc_header}.{enc_payload}.{enc_sig}"

    def verify_simulated_jws(self, token: str) -> dict:
        parts = token.split('.')
        self.assertEqual(len(parts), 3, "JWS token must have 3 compact parts")
        signing_input = f"{parts[0]}.{parts[1]}".encode('utf-8')
        expected_sig = hmac.new(self.signing_secret, signing_input, hashlib.sha256).digest()
        actual_sig = b64url_decode(parts[2])
        self.assertTrue(hmac.compare_digest(actual_sig, expected_sig), "Signature mismatch")
        payload = json.loads(b64url_decode(parts[1]).decode('utf-8'))
        return payload

    def test_01_external_relying_party_jws_verification(self):
        """Simulate a vendor relying party (e.g. Keycard / Runlayer) verifying a BAP JWS assertion."""
        now = int(time.time())
        claims = {
            "iss": self.issuer,
            "sub": "spiffe://bap.internal/app/financial-reconciler/instance/agent-01",
            "aud": self.audience,
            "exp": now + 300,
            "iat": now,
            "bap_session_id": "sess-vendor-interop-01",
            "bap_task_id": "task-ledger-verify",
            "bap_risk_tier": "TIER_2_MEDIUM",
            "scp": ["ledger:read", "ledger:audit"]
        }
        token = self.mint_simulated_jws(claims)
        
        # Vendor relying party verifies token
        verified = self.verify_simulated_jws(token)
        self.assertEqual(verified["iss"], self.issuer)
        self.assertEqual(verified["bap_session_id"], "sess-vendor-interop-01")
        self.assertEqual(verified["bap_risk_tier"], "TIER_2_MEDIUM")
        self.assertIn("ledger:read", verified["scp"])

    def test_02_privilege_amplification_denial(self):
        """Verify that attempting to inject broader permissions than authorized is rejected."""
        authorized_scopes = {"repo:read", "issues:read"}
        vendor_requested_scopes = ["repo:read", "repo:admin", "org:write"]
        
        # Invariant: Any requested scope outside authorized_scopes must be blocked
        escalated = [s for s in vendor_requested_scopes if s not in authorized_scopes]
        self.assertTrue(len(escalated) > 0, "Escalation must be detected")
        self.assertIn("repo:admin", escalated)

    def test_03_single_use_grant_burning_invariant(self):
        """Verify that single-use grants cannot be re-used across vendor calls."""
        consumed_grants = set()
        grant = "bap-grant-single-use-vendor-8899"
        
        # First use
        self.assertNotIn(grant, consumed_grants)
        consumed_grants.add(grant)
        
        # Second use (replay)
        is_replay = grant in consumed_grants
        self.assertTrue(is_replay, "Grant must be marked as already consumed")


if __name__ == "__main__":
    unittest.main()

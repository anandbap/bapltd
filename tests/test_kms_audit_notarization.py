"""
Test Suite for BAP-1301 & BAP-1302 (Epic 13):
Cloud KMS Audit Notarization & Immutable Cold Storage
=====================================================
Verifies:
1. BAP-1301: Periodic and on-demand RFC 3161 / Cloud KMS audit chain leaf notarization.
2. BAP-1301: Cryptographic signature and TSA receipt generation.
3. BAP-1302: Automated WORM export packaging with S3 Object Lock compliance retention.
4. BAP-1302: Integrity checksums and regulatory retention manifest querying.
"""

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

TEST_SECRET = "kms-notary-test-signing-key-32b-ok!"
TEST_ADMIN_TOKEN = "kms-notary-admin-token-12345"
CP_PORT = 19195
CP_URL = f"http://127.0.0.1:{CP_PORT}"


def http_req(url, method="GET", data=None, headers=None):
    hdrs = headers or {}
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


class TestKMSAuditNotarization(unittest.TestCase):
    proc = None
    tmpdir = None

    @classmethod
    def setUpClass(cls):
        cls.tmpdir = tempfile.mkdtemp(prefix="bap_kms_test_")
        cls.policy_file = os.path.join(cls.tmpdir, "policy.cedar")
        cls.schema_file = os.path.join(cls.tmpdir, "schema.json")

        initial_policy = """
permit (
    principal == Agent::"Local",
    action == Action::"Execute",
    resource == Command::"CLI"
)
when {
    context.executable == "git"
};
"""
        with open(cls.policy_file, "w", encoding="utf-8") as f:
            f.write(initial_policy)
        with open(cls.schema_file, "w", encoding="utf-8") as f:
            f.write("{}")

        cmd = [
            CONTROL_PLANE_BIN,
            "-port", str(CP_PORT),
            "-secret", TEST_SECRET,
            "-admin-token", TEST_ADMIN_TOKEN,
            "-allow-remote-admin",
            "-policy", cls.policy_file,
            "-schema", cls.schema_file,
            "-demo-mode",
        ]

        cls.proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=cls.tmpdir,
        )

        started = False
        for _ in range(30):
            time.sleep(0.15)
            try:
                st, data, _ = http_req(f"{CP_URL}/health")
                if st == 200:
                    started = True
                    break
            except Exception:
                pass

        if not started:
            if cls.proc.poll() is not None:
                out, err = cls.proc.communicate()
                raise RuntimeError(f"Control plane died on start: {out.decode()} / {err.decode()}")
            raise RuntimeError("Control plane failed to start within timeout")

    @classmethod
    def tearDownClass(cls):
        if cls.proc:
            try:
                cls.proc.terminate()
                cls.proc.wait(timeout=3)
            except Exception:
                cls.proc.kill()
        if cls.tmpdir and os.path.exists(cls.tmpdir):
            shutil.rmtree(cls.tmpdir, ignore_errors=True)

    def test_01_notarize_audit_chain_requires_admin(self):
        """BAP-1301: Notarization endpoint requires administrator authentication."""
        st, data, _ = http_req(f"{CP_URL}/api/v1/audit/notarize", method="POST", data={})
        self.assertEqual(st, 401)

    def test_02_notarize_audit_chain_produces_receipt(self):
        """BAP-1301: Generating a notarization checkpoint creates signed RFC 3161 receipt."""
        # 1. Ingest an audit event to populate chain
        ev = [{
            "event_id": f"ev-{int(time.time() * 1000)}",
            "timestamp": "2026-10-04T12:00:00Z",
            "source": "bapedge",
            "executable": "git",
            "full_command": "git commit -m 'feat: enterprise notarization'",
            "decision": "allow",
            "previous_hash": "genesis-bapltd-control-plane",
            "event_hash": "",
        }]
        http_req(f"{CP_URL}/api/v1/audit/ingest", method="POST", data=ev)

        # 2. Trigger notarization checkpoint
        st, receipt, _ = http_req(
            f"{CP_URL}/api/v1/audit/notarize",
            method="POST",
            data={"provider": "aws"},
            headers={"X-BAP-Admin-Token": TEST_ADMIN_TOKEN},
        )
        self.assertEqual(st, 200)
        self.assertIn("receipt_id", receipt)
        self.assertEqual(receipt.get("status"), "NOTARIZED")
        self.assertTrue(len(receipt.get("signature", "")) > 10)
        self.assertTrue(len(receipt.get("tsa_serial_number", "")) > 4)
        self.assertIn("aws", receipt.get("kms_key_arn", ""))
        self.assertTrue(receipt.get("chain_length", 0) >= 1)

        # 3. Query receipts list
        st2, list_resp, _ = http_req(f"{CP_URL}/api/v1/audit/notarizations")
        self.assertEqual(st2, 200)
        self.assertTrue(list_resp.get("count", 0) >= 1)

    def test_03_worm_archive_export_and_manifest(self):
        """BAP-1302: Exporting WORM archive creates immutable compliance manifest."""
        st, manifest, _ = http_req(
            f"{CP_URL}/api/v1/audit/worm/export",
            method="POST",
            data={
                "bucket": "s3://bap-compliance-vault",
                "prefix": "2026/soc2",
                "retention_years": 7,
            },
            headers={"X-BAP-Admin-Token": TEST_ADMIN_TOKEN},
        )
        self.assertEqual(st, 200)
        self.assertIn("archive_id", manifest)
        self.assertEqual(manifest.get("status"), "LOCKED")
        self.assertEqual(manifest.get("retention_mode"), "COMPLIANCE")
        self.assertTrue(manifest.get("legal_hold"))
        self.assertTrue(manifest.get("event_count", 0) >= 1)
        self.assertTrue(len(manifest.get("sha256_checksum", "")) == 64)

        # Query manifests list
        st2, archives_resp, _ = http_req(f"{CP_URL}/api/v1/audit/worm/manifests")
        self.assertEqual(st2, 200)
        self.assertTrue(archives_resp.get("count", 0) >= 1)


if __name__ == "__main__":
    unittest.main()

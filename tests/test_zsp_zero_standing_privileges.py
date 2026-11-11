import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _resolve_bin(candidates):
    for rel in candidates:
        path = os.path.join(REPO_ROOT, rel)
        if os.path.isfile(path):
            return path
    return None


BAPEDGE_BIN = _resolve_bin([
    os.path.join("dist", "windows-amd64", "bapedge.exe"),
    os.path.join("dist", "windows-amd64", "claude-client", "bapedge.exe"),
    "bapedge.exe",
    "bapedge",
])

INTERCEPTOR_BIN = _resolve_bin([
    os.path.join("dist", "windows-amd64", "interceptor.exe"),
    os.path.join("dist", "windows-amd64", "claude-client", "interceptor.exe"),
    "interceptor.exe",
    os.path.join("cchook", "interceptor.exe"),
    os.path.join("cchook", "interceptor"),
])


class TestZSPZeroStandingPrivileges(unittest.TestCase):
    """Verifies ZSP default-deny enforcement and 4-tuple JIT TaskGrant execution."""

    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp(prefix="bap-zsp-test-")
        self.zsp_dir = os.path.join(self.tmp_dir, "zsp")
        self.state_dir = os.path.join(self.tmp_dir, "state")
        os.makedirs(self.zsp_dir, exist_ok=True)
        os.makedirs(self.state_dir, exist_ok=True)
        self.session_id = f"sess-zsp-ci-{os.getpid()}-{self._testMethodName}"

    def tearDown(self):
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def _base_env(self):
        env = os.environ.copy()
        env["BAP_ZSP"] = "enforce"
        env["BAP_ZSP_DIR"] = self.zsp_dir
        env["BAP_STATE_DIR"] = self.state_dir
        env["BAP_ENFORCEMENT_MODE"] = "enforce"
        env["LTD_SOURCE"] = "claude-code"
        env["BAP_SESSION_ID"] = self.session_id
        env["BAP_POLICY_PATH"] = os.path.join(REPO_ROOT, "policy.cedar")
        return env

    def test_01_zsp_init_starts_with_zero_standing_privileges(self):
        if not BAPEDGE_BIN:
            self.skipTest("bapedge binary not found")

        env = self._base_env()
        init_res = subprocess.run(
            [BAPEDGE_BIN, "zsp", "init", "--session-id", self.session_id, "--client", "claude-code", "--json"],
            cwd=REPO_ROOT,
            env=env,
            capture_output=True,
            text=True,
            timeout=15,
        )
        self.assertEqual(init_res.returncode, 0, f"zsp init failed: {init_res.stderr}\n{init_res.stdout}")
        init_data = json.loads(init_res.stdout)
        self.assertEqual(init_data.get("status"), "initialized")
        self.assertTrue(init_data.get("standing_privileges", "").startswith("NONE"))
        self.assertTrue(init_data.get("principal", {}).get("subject", "").startswith("spiffe://"))

        status_res = subprocess.run(
            [BAPEDGE_BIN, "zsp", "status", "--session-id", self.session_id, "--client", "claude-code", "--json"],
            cwd=REPO_ROOT,
            env=env,
            capture_output=True,
            text=True,
            timeout=15,
        )
        self.assertEqual(status_res.returncode, 0, f"zsp status failed: {status_res.stderr}")
        status_data = json.loads(status_res.stdout)
        self.assertEqual(len(status_data.get("active_grants") or []), 0)

    def test_02_ungranted_agent_commands_fail_closed(self):
        if not BAPEDGE_BIN:
            self.skipTest("bapedge binary not found")

        env = self._base_env()
        check_res = subprocess.run(
            [BAPEDGE_BIN, "check", "-json", "-source", "claude-code", "-session-id", self.session_id, "whoami"],
            cwd=REPO_ROOT,
            env=env,
            capture_output=True,
            text=True,
            timeout=15,
        )
        self.assertNotEqual(check_res.returncode, 0, f"Expected ungranted check to fail: {check_res.stdout}")
        check_data = json.loads(check_res.stdout)
        self.assertFalse(check_data.get("allowed", True))
        self.assertIn("ZeroStandingPrivilegeViolation", check_data.get("reason", ""))

        exec_res = subprocess.run(
            [BAPEDGE_BIN, "exec", "-json", "-source", "claude-code", "-session-id", self.session_id, "whoami"],
            cwd=REPO_ROOT,
            env=env,
            capture_output=True,
            text=True,
            timeout=15,
        )
        self.assertNotEqual(exec_res.returncode, 0, f"Expected ungranted exec to fail: {exec_res.stdout}")
        exec_data = json.loads(exec_res.stdout)
        self.assertFalse(exec_data.get("allowed", True))
        self.assertIn("ZeroStandingPrivilegeViolation", exec_data.get("reason", ""))

    def test_03_interceptor_denies_root_listing_and_whoami_without_grant(self):
        if not INTERCEPTOR_BIN:
            self.skipTest("interceptor binary not found")

        env = self._base_env()
        for cmd in ("whoami", "Get-ChildItem -Force \\"):
            payload = {
                "hook_event_name": "PreToolUse",
                "session_id": self.session_id,
                "tool_name": "PowerShell",
                "tool_input": {"command": cmd},
            }
            res = subprocess.run(
                [INTERCEPTOR_BIN],
                input=json.dumps(payload),
                cwd=REPO_ROOT,
                env=env,
                capture_output=True,
                text=True,
                timeout=15,
            )
            self.assertEqual(res.returncode, 0, f"interceptor crashed for {cmd}: {res.stderr}")
            data = json.loads(res.stdout)
            h_out = data.get("hookSpecificOutput", {})
            self.assertEqual(
                h_out.get("permissionDecision"),
                "deny",
                f"Expected PreToolUse deny for ungranted {cmd!r}, got: {res.stdout}",
            )
            self.assertIn("ZeroStandingPrivilegeViolation", h_out.get("permissionDecisionReason", ""))

    def test_04_four_tuple_grant_allows_once_and_burns_replay(self):
        if not BAPEDGE_BIN:
            self.skipTest("bapedge binary not found")

        env = self._base_env()
        auth_res = subprocess.run(
            [
                BAPEDGE_BIN, "zsp", "authorize",
                "--session-id", self.session_id,
                "--client", "claude-code",
                "--mission", "CODE_INSPECTION",
                "--goal", "Inspect git status cleanly",
                "--actions", "git:status",
                "--max-uses", "1",
                "--json",
            ],
            cwd=REPO_ROOT,
            env=env,
            capture_output=True,
            text=True,
            timeout=15,
        )
        self.assertEqual(auth_res.returncode, 0, f"zsp authorize failed: {auth_res.stderr}\n{auth_res.stdout}")
        auth_data = json.loads(auth_res.stdout)
        self.assertTrue(auth_data.get("allowed", False))

        # Out-of-scope action must remain denied
        ungranted = subprocess.run(
            [BAPEDGE_BIN, "exec", "-json", "-source", "claude-code", "-session-id", self.session_id, "whoami"],
            cwd=REPO_ROOT,
            env=env,
            capture_output=True,
            text=True,
            timeout=15,
        )
        self.assertNotEqual(ungranted.returncode, 0)

        # Authorized single-use action succeeds
        allowed_exec = subprocess.run(
            [BAPEDGE_BIN, "exec", "-json", "-source", "claude-code", "-session-id", self.session_id, "git status"],
            cwd=REPO_ROOT,
            env=env,
            capture_output=True,
            text=True,
            timeout=15,
        )
        self.assertEqual(allowed_exec.returncode, 0, f"Expected granted git status to pass: {allowed_exec.stderr}\n{allowed_exec.stdout}")
        allowed_data = json.loads(allowed_exec.stdout)
        self.assertTrue(allowed_data.get("allowed", False))

        # Replay after single-use grant burns must fail closed
        replay_exec = subprocess.run(
            [BAPEDGE_BIN, "exec", "-json", "-source", "claude-code", "-session-id", self.session_id, "git status"],
            cwd=REPO_ROOT,
            env=env,
            capture_output=True,
            text=True,
            timeout=15,
        )
        self.assertNotEqual(replay_exec.returncode, 0, f"Expected replay after burn to fail: {replay_exec.stdout}")
        replay_data = json.loads(replay_exec.stdout)
        self.assertFalse(replay_data.get("allowed", True))


if __name__ == "__main__":
    unittest.main()

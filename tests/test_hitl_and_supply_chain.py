"""
Test Suite: Human-in-the-Loop (HITL) Step-Up Escalation & Software Supply Chain Mirror Governance
Verifies:
  1. Corporate Supply-Chain Mirror Injection (Nexus/Artifactory pip, npm, maven env injection)
  2. Public Package Repository Bypass Defense (Policy 6: blocking public PyPI, Maven, npm overrides)
  3. HITL Step-Up Escalation: Non-Interactive Fail-Closed Zero-Trust Enforcement
  4. HITL Step-Up Escalation: One-Time Human Operator Approval (ALLOWED_STEPUP)
  5. HITL Step-Up Escalation: Session-Level Persistent Trust
  6. Anti-Tampering Security Invariant: Immutable & Non-Escalatable (Never Step-Up Eligible)
  7. Claude Code / Antigravity Lifecycle Hook Step-Up Integration
"""

import os
import sys
import json
import time
import unittest
import subprocess

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BAPEDGE_BIN = os.path.join(REPO_ROOT, "bapedge.exe")
CCHOOK_BIN = os.path.join(REPO_ROOT, "cchook", "interceptor.exe")


class TestHitlAndSupplyChain(unittest.TestCase):
    def setUp(self):
        self.session_id = f"sess-hitl-{self._testMethodName}"
        self.env = os.environ.copy()
        self.env["LTD_SOURCE"] = "antigravity"
        self.env["BAP_SESSION_ID"] = self.session_id
        # Clean any prior session approval state
        approvals_file = os.path.join(REPO_ROOT, ".bap", f"approvals_{self.session_id}.json")
        if os.path.exists(approvals_file):
            try:
                os.remove(approvals_file)
            except Exception:
                pass

    def test_01_supply_chain_mirror_injection(self):
        """Verify BAP Edge automatically injects corporate mirror variables (PIP_INDEX_URL, NPM_CONFIG_REGISTRY)."""
        cmd = [
            BAPEDGE_BIN, "exec",
            "--session-id", self.session_id,
            "--json",
            "powershell -Command \"Write-Output $env:PIP_INDEX_URL; Write-Output $env:NPM_CONFIG_REGISTRY\""
        ]
        res = subprocess.run(cmd, capture_output=True, text=True, cwd=REPO_ROOT, env=self.env)
        self.assertEqual(res.returncode, 0)
        data = json.loads(res.stdout)
        self.assertTrue(data.get("allowed"), "Command should be allowed")
        output = data.get("output", "")
        self.assertIn("nexus.corp.internal/repository/pypi-group/simple", output)
        self.assertIn("nexus.corp.internal/repository/npm-group/", output)

    def test_02_public_repository_bypass_blocked(self):
        """Verify Policy 6 strictly blocks package managers bypassing corporate mirrors with public repos."""
        bypass_attempts = [
            "mvn compile -DremoteRepositories=http://repo.maven.apache.org/maven2",
            "pip install requests --index-url http://pypi.org/simple",
            "npm install lodash --registry https://registry.npmjs.org"
        ]
        for cmd_str in bypass_attempts:
            proc = subprocess.run(
                [BAPEDGE_BIN, "exec", "--session-id", self.session_id, "--json", cmd_str],
                capture_output=True, text=True, cwd=REPO_ROOT, env=self.env
            )
            self.assertNotEqual(proc.returncode, 0, f"Public repo bypass should be blocked: {cmd_str}")
            data = json.loads(proc.stdout)
            self.assertFalse(data.get("allowed"))
            self.assertIn("policy", data.get("reason", "").lower())

    def test_03_hitl_non_interactive_fail_closed(self):
        """Verify high-risk or unapproved operations fail closed in non-interactive sessions."""
        env_headless = self.env.copy()
        env_headless.pop("BAP_STEPUP_DECISION", None)
        env_headless["BAP_NON_INTERACTIVE"] = "1"

        proc = subprocess.run(
            [BAPEDGE_BIN, "exec", "--session-id", self.session_id, "--json", "setup.exe /s"],
            capture_output=True, text=True, cwd=REPO_ROOT, env=env_headless
        )
        self.assertNotEqual(proc.returncode, 0)
        data = json.loads(proc.stdout)
        self.assertFalse(data.get("allowed"))
        self.assertEqual(data.get("step_up_decision"), "denied")
        self.assertIn("Human Step-Up Approval (HITL)", data.get("suggestion", ""))

    def test_04_hitl_stepup_approval_once(self):
        """Verify one-time HITL Step-Up approval permits command execution with complete receipt provenance."""
        env_stepup = self.env.copy()
        env_stepup["BAP_STEPUP_DECISION"] = "approve"

        # whoami is benign to execute, but test check/execution under step-up
        proc = subprocess.run(
            [BAPEDGE_BIN, "check", "--session-id", self.session_id, "--json", "setup.exe /s"],
            capture_output=True, text=True, cwd=REPO_ROOT, env=env_stepup
        )
        self.assertEqual(proc.returncode, 0)
        data = json.loads(proc.stdout)
        self.assertTrue(data.get("allowed"))
        self.assertEqual(data.get("step_up_decision"), "approve_once")
        self.assertIn("STEP-UP AUTHORIZED", data.get("warning", ""))
        self.assertEqual(data.get("receipt", {}).get("result"), "ALLOWED_STEPUP")

    def test_05_hitl_stepup_session_trust(self):
        """Verify session-level HITL trust persists across subsequent invocations within the same session."""
        # Step 1: Grant session trust on setup.exe
        env_session = self.env.copy()
        env_session["BAP_STEPUP_DECISION"] = "session"

        proc1 = subprocess.run(
            [BAPEDGE_BIN, "check", "--session-id", self.session_id, "--json", "setup.exe /s"],
            capture_output=True, text=True, cwd=REPO_ROOT, env=env_session
        )
        self.assertEqual(proc1.returncode, 0)
        data1 = json.loads(proc1.stdout)
        self.assertTrue(data1.get("allowed"))
        self.assertEqual(data1.get("step_up_decision"), "session_trust")

        # Step 2: In the same session, run setup.exe WITHOUT BAP_STEPUP_DECISION
        env_clean = self.env.copy()
        env_clean.pop("BAP_STEPUP_DECISION", None)
        env_clean["BAP_NON_INTERACTIVE"] = "1"

        proc2 = subprocess.run(
            [BAPEDGE_BIN, "check", "--session-id", self.session_id, "--json", "setup.exe /install"],
            capture_output=True, text=True, cwd=REPO_ROOT, env=env_clean
        )
        self.assertEqual(proc2.returncode, 0, "Subsequent command under session trust must be allowed")
        data2 = json.loads(proc2.stdout)
        self.assertTrue(data2.get("allowed"))
        self.assertEqual(data2.get("step_up_decision"), "session_trust")
        self.assertIn("SESSION TRUST", data2.get("warning", ""))

    def test_06_anti_tampering_never_stepup_eligible(self):
        """Verify that BAP protected assets (policy.cedar, bapedge.exe) can NEVER be stepped-up or bypassed."""
        env_tamper = self.env.copy()
        env_tamper["BAP_STEPUP_DECISION"] = "approve"  # Attempt to force approve tamper

        proc = subprocess.run(
            [BAPEDGE_BIN, "exec", "--session-id", self.session_id, "--json", "del policy.cedar"],
            capture_output=True, text=True, cwd=REPO_ROOT, env=env_tamper
        )
        self.assertNotEqual(proc.returncode, 0)
        data = json.loads(proc.stdout)
        self.assertFalse(data.get("allowed"))
        self.assertIn("DENIED_TAMPER", data.get("receipt", {}).get("result", ""))
        self.assertIn("Security Invariant Violation", data.get("reason", ""))

    def test_07_cchook_stepup_file_mutation(self):
        """Verify cchook supports Step-Up escalation for outside-workspace file mutations."""
        outside_path = r"C:\Users\User\pyprj\sibling_project\file.txt"

        # 1. Without step-up: strictly denied
        hook_payload_denied = {
            "session_id": self.session_id,
            "tool_name": "Edit",
            "tool_input": {"file_path": outside_path, "new_string": "payload"}
        }
        env_no_stepup = self.env.copy()
        env_no_stepup.pop("BAP_STEPUP_DECISION", None)

        proc_denied = subprocess.run(
            [CCHOOK_BIN],
            input=json.dumps(hook_payload_denied),
            capture_output=True, text=True, cwd=REPO_ROOT, env=env_no_stepup
        )
        data_denied = json.loads(proc_denied.stdout)
        self.assertEqual(data_denied.get("decision"), "block")
        self.assertIn("Modifying files outside workspace is forbidden", data_denied.get("reason", ""))

        # 2. With step-up: permitted
        env_stepup = self.env.copy()
        env_stepup["BAP_STEPUP_DECISION"] = "approve"

        proc_allowed = subprocess.run(
            [CCHOOK_BIN],
            input=json.dumps(hook_payload_denied),
            capture_output=True, text=True, cwd=REPO_ROOT, env=env_stepup
        )
        data_allowed = json.loads(proc_allowed.stdout)
        self.assertEqual(data_allowed.get("decision"), "allow")
        self.assertIn("STEP-UP AUTHORIZED", data_allowed.get("systemMessage", ""))

    def test_08_canary_secret_tripwire(self):
        """Verify Policy 7 immediately blocks any attempt to exfiltrate or probe corporate canary honeytokens."""
        canary_probes = [
            'powershell -Command "$env:CORP_CANARY_TOKEN"',
            'echo canary-trap-secret-dump',
            'python -c "import os; print(os.getenv(\"CORP_CANARY_TOKEN\"))"'
        ]
        for cmd_str in canary_probes:
            proc = subprocess.run(
                [BAPEDGE_BIN, "exec", "--session-id", self.session_id, "--json", cmd_str],
                capture_output=True, text=True, cwd=REPO_ROOT, env=self.env
            )
            self.assertNotEqual(proc.returncode, 0)
            data = json.loads(proc.stdout)
            self.assertFalse(data.get("allowed"))
            self.assertIn("policy", data.get("reason", "").lower())

    def test_09_runaway_execution_timeout_quota(self):
        """Verify runaway agent loops and fork bombs are forcibly terminated by the Resource Quota timer."""
        env_timeout = self.env.copy()
        env_timeout["BAP_EXEC_TIMEOUT_SEC"] = "2"  # Fast 2-second timeout for test

        start = time.time()
        proc = subprocess.run(
            [BAPEDGE_BIN, "exec", "--session-id", self.session_id, "--json", "powershell -Command \"Start-Sleep -Seconds 10\""],
            capture_output=True, text=True, cwd=REPO_ROOT, env=env_timeout
        )
        elapsed = time.time() - start
        self.assertLess(elapsed, 6.0, "Runaway execution must be terminated by timeout")
        data = json.loads(proc.stdout)
        self.assertIn("timed out", data.get("reason", "").lower())

    def tearDown(self):
        # Clean any test permissions
        proj_perm = os.path.join(REPO_ROOT, ".bap", "project_permissions.json")
        if os.path.exists(proj_perm):
            try:
                os.remove(proj_perm)
            except Exception:
                pass
        approvals_file = os.path.join(REPO_ROOT, ".bap", f"approvals_{self.session_id}.json")
        if os.path.exists(approvals_file):
            try:
                os.remove(approvals_file)
            except Exception:
                pass

    def test_10_cross_folder_write_denied_with_trust_suggestion(self):
        """Verify cross-folder write without authorization is blocked and suggests bapedge trust."""
        sibling_file = r"C:\Users\User\pyprj\afbap\test_probe.txt"
        env_no_override = self.env.copy()
        env_no_override.pop("BAP_STEPUP_DECISION", None)
        env_no_override["BAP_NON_INTERACTIVE"] = "1"

        proc = subprocess.run(
            [BAPEDGE_BIN, "check", "--session-id", self.session_id, "--json", f"echo test > {sibling_file}"],
            capture_output=True, text=True, cwd=REPO_ROOT, env=env_no_override
        )
        self.assertNotEqual(proc.returncode, 0)
        data = json.loads(proc.stdout)
        self.assertFalse(data.get("allowed"))
        suggestion = data.get("suggestion", "")
        self.assertIn("bapedge trust", suggestion)

    def test_11_cross_folder_write_allowed_via_bapedge_trust_project(self):
        """Verify bapedge trust <path> --project persistently authorizes cross-folder mutations for workspace."""
        sibling_dir = r"C:\Users\User\pyprj\afbap"
        sibling_file = r"C:\Users\User\pyprj\afbap\build_output.txt"

        # 1. Authorize sibling directory for project
        trust_res = subprocess.run(
            [BAPEDGE_BIN, "trust", sibling_dir, "--project"],
            capture_output=True, text=True, cwd=REPO_ROOT, env=self.env
        )
        self.assertEqual(trust_res.returncode, 0)
        self.assertIn("CROSS-FOLDER MUTATION PERMISSION GRANTED", trust_res.stdout)

        # 2. Check cross-folder write is now permitted without any env overrides
        env_clean = self.env.copy()
        env_clean.pop("BAP_STEPUP_DECISION", None)
        env_clean["BAP_NON_INTERACTIVE"] = "1"

        proc = subprocess.run(
            [BAPEDGE_BIN, "check", "--session-id", self.session_id, "--json", f"echo build-ok > {sibling_file}"],
            capture_output=True, text=True, cwd=REPO_ROOT, env=env_clean
        )
        self.assertEqual(proc.returncode, 0)
        data = json.loads(proc.stdout)
        self.assertTrue(data.get("allowed"))

    def test_12_cross_folder_write_allowed_via_bapedge_trust_global(self):
        """Verify bapedge trust <path> --global authorizes cross-folder mutations machine-wide."""
        sibling_dir = r"C:\Users\User\pyprj\afbap"
        sibling_file = r"C:\Users\User\pyprj\afbap\global_shared.txt"

        # 1. Authorize sibling directory globally
        trust_res = subprocess.run(
            [BAPEDGE_BIN, "trust", sibling_dir, "--global"],
            capture_output=True, text=True, cwd=REPO_ROOT, env=self.env
        )
        self.assertEqual(trust_res.returncode, 0)
        self.assertIn("GLOBAL", trust_res.stdout)

        # 2. Check cross-folder mutation is permitted
        env_clean = self.env.copy()
        env_clean.pop("BAP_STEPUP_DECISION", None)
        env_clean["BAP_NON_INTERACTIVE"] = "1"

        proc = subprocess.run(
            [BAPEDGE_BIN, "check", "--session-id", self.session_id, "--json", f"echo shared-data > {sibling_file}"],
            capture_output=True, text=True, cwd=REPO_ROOT, env=env_clean
        )
        self.assertEqual(proc.returncode, 0)
        data = json.loads(proc.stdout)
        self.assertTrue(data.get("allowed"))

        # Clean up global grant
        subprocess.run([BAPEDGE_BIN, "untrust", sibling_dir, "--global"], capture_output=True, cwd=REPO_ROOT, env=self.env)

    def test_13_cross_folder_write_session_scope(self):
        """Verify BAP_STEPUP_DECISION=session grants session-scoped permission for target directory."""
        sibling_dir = r"C:\Users\User\pyprj\afbap"
        sibling_file = r"C:\Users\User\pyprj\afbap\session_test.txt"

        # 1. Authorize via session step-up decision
        env_sess = self.env.copy()
        env_sess["BAP_STEPUP_DECISION"] = "session"

        proc1 = subprocess.run(
            [BAPEDGE_BIN, "check", "--session-id", self.session_id, "--json", f"echo session-data > {sibling_file}"],
            capture_output=True, text=True, cwd=REPO_ROOT, env=env_sess
        )
        self.assertEqual(proc1.returncode, 0)
        data1 = json.loads(proc1.stdout)
        self.assertTrue(data1.get("allowed"))
        self.assertEqual(data1.get("step_up_decision"), "session_trust")

        # 2. In the same session, subsequent write to another file in the sibling dir is trusted
        env_clean = self.env.copy()
        env_clean.pop("BAP_STEPUP_DECISION", None)
        env_clean["BAP_NON_INTERACTIVE"] = "1"

        proc2 = subprocess.run(
            [BAPEDGE_BIN, "check", "--session-id", self.session_id, "--json", f"echo sub-data > C:\\Users\\User\\pyprj\\afbap\\sub2.txt"],
            capture_output=True, text=True, cwd=REPO_ROOT, env=env_clean
        )
        self.assertEqual(proc2.returncode, 0)
        data2 = json.loads(proc2.stdout)
        self.assertTrue(data2.get("allowed"))

    def test_14_cross_folder_permissions_list_and_untrust(self):
        """Verify bapedge permissions lists active authorizations and untrust properly revokes them."""
        sibling_dir = r"C:\Users\User\pyprj\afbap"

        # 1. Grant project permission
        subprocess.run([BAPEDGE_BIN, "trust", sibling_dir, "--project"], capture_output=True, cwd=REPO_ROOT, env=self.env)

        # 2. Query permissions list
        list_res = subprocess.run([BAPEDGE_BIN, "permissions"], capture_output=True, text=True, cwd=REPO_ROOT, env=self.env)
        self.assertEqual(list_res.returncode, 0)
        self.assertIn("C:\\Users\\User\\pyprj\\afbap", list_res.stdout)
        self.assertIn("PROJECT", list_res.stdout)

        # 3. Revoke permission
        untrust_res = subprocess.run([BAPEDGE_BIN, "untrust", sibling_dir, "--project"], capture_output=True, text=True, cwd=REPO_ROOT, env=self.env)
        self.assertEqual(untrust_res.returncode, 0)
        self.assertIn("Revoked project cross-folder permission", untrust_res.stdout)

        # 4. Confirm it is blocked again
        env_clean = self.env.copy()
        env_clean.pop("BAP_STEPUP_DECISION", None)
        env_clean["BAP_NON_INTERACTIVE"] = "1"

        proc = subprocess.run(
            [BAPEDGE_BIN, "check", "--session-id", self.session_id, "--json", f"echo blocked > {sibling_dir}\\blocked.txt"],
            capture_output=True, text=True, cwd=REPO_ROOT, env=env_clean
        )
        self.assertNotEqual(proc.returncode, 0)
        data = json.loads(proc.stdout)
        self.assertFalse(data.get("allowed"))

    def test_15_cchook_cross_folder_file_tool_trusted(self):
        """Verify cchook PreToolUse hook respects project permissions for direct file mutation tools (Edit/Write)."""
        sibling_file = r"C:\Users\User\pyprj\afbap\code.py"

        # 1. Grant project permission for afbap
        subprocess.run([BAPEDGE_BIN, "trust", r"C:\Users\User\pyprj\afbap", "--project"], capture_output=True, cwd=REPO_ROOT, env=self.env)

        # 2. Send Claude Code PreToolUse event for Write tool
        hook_payload = {
            "session_id": self.session_id,
            "tool_name": "Write",
            "tool_input": {"file_path": sibling_file, "content": "print('hello')"}
        }
        env_clean = self.env.copy()
        env_clean.pop("BAP_STEPUP_DECISION", None)

        proc = subprocess.run(
            [CCHOOK_BIN],
            input=json.dumps(hook_payload),
            capture_output=True, text=True, cwd=REPO_ROOT, env=env_clean
        )
        data = json.loads(proc.stdout)
        self.assertEqual(data.get("decision"), "allow")
        self.assertIn("PROJECT TRUST", data.get("systemMessage", ""))


if __name__ == "__main__":
    unittest.main()


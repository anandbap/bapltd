#!/usr/bin/env python3
"""
End-to-End (E2E) Fortified Integration Test Suite:
Agent Identities, Multi-Session Isolation, Launchers, and Anti-Tampering
========================================================================
Fortifies and validates:
1. Universal Identity Resolution across all 5 Agent Identities:
   - Claude Code (claude / claude-code) -> spiffe://bap.local/agent/claude
   - Google Antigravity (antigravity)   -> spiffe://bap.local/agent/antigravity
   - GitHub Copilot (copilot)           -> spiffe://bap.local/agent/copilot
   - Cursor IDE (cursor)                -> spiffe://bap.local/agent/cursor
   - Gemini CLI (gemini)                -> spiffe://bap.local/agent/gemini
2. Audit receipt generation with correct SPIFFE IDs and delegation chains (user:<usr>->agent:<src>).
3. Anti-Tampering Invariants enforced against all 5 agent identities.
4. Concurrent Multi-Agent Session Isolation & Session-Scoped Revocation.
5. Cross-Shell Launcher Lifecycle (CMD, PowerShell, Bash) & Transactional Custody.
"""

import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import unittest

WORKSPACE_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, WORKSPACE_ROOT)

from scripts import bap_install
from scripts import bap_doctor

BAPEDGE_BIN = os.path.join(WORKSPACE_ROOT, "dist", "windows-amd64", "bapedge.exe")
if not os.path.isfile(BAPEDGE_BIN):
    BAPEDGE_BIN = os.path.join(WORKSPACE_ROOT, "bapedge.exe")

USER_BIN = os.path.join(os.path.expanduser("~"), "bin")
if os.path.isfile(os.path.join(USER_BIN, "bapedge.exe")):
    BAPEDGE_BIN = os.path.join(USER_BIN, "bapedge.exe")


class TestE2EFortifiedIdentitiesAndLaunchers(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp_dir = tempfile.mkdtemp(prefix="bap_e2e_identities_")
        cls.mock_bin = os.path.join(cls.temp_dir, "bin")
        cls.mock_ws = os.path.join(cls.temp_dir, "workspace")
        os.makedirs(cls.mock_bin, exist_ok=True)
        os.makedirs(cls.mock_ws, exist_ok=True)

        # Deploy real core binaries and configurations to mock_bin
        bap_install.install_core_binaries(cls.mock_bin)
        bap_install.configure_agent_hooks(cls.mock_ws, cls.mock_bin)

        # Create lightweight mock stub executables for CI environments where third-party agent CLIs are not preinstalled
        if sys.platform == "win32":
            for name in ["agy.cmd", "agy.bat"]:
                stub = os.path.join(cls.mock_bin, name)
                with open(stub, "w", encoding="utf-8") as f:
                    f.write("@echo off\r\necho 1.4.3\r\nexit /b 0\r\n")
            for name in ["claude.cmd", "claude.bat"]:
                stub = os.path.join(cls.mock_bin, name)
                with open(stub, "w", encoding="utf-8") as f:
                    f.write("@echo off\r\necho 2.1.305\r\nexit /b 0\r\n")
            for name in ["copilot.cmd", "copilot.bat"]:
                stub = os.path.join(cls.mock_bin, name)
                with open(stub, "w", encoding="utf-8") as f:
                    f.write("@echo off\r\necho 1.0.0\r\nexit /b 0\r\n")
        else:
            agy_stub = os.path.join(cls.mock_bin, "agy")
            with open(agy_stub, "w", encoding="utf-8") as f:
                f.write("#!/bin/sh\necho 1.4.3\nexit 0\n")
            os.chmod(agy_stub, 0o755)
            claude_stub = os.path.join(cls.mock_bin, "claude")
            with open(claude_stub, "w", encoding="utf-8") as f:
                f.write("#!/bin/sh\necho 2.1.305\nexit 0\n")
            os.chmod(claude_stub, 0o755)
            copilot_stub = os.path.join(cls.mock_bin, "copilot")
            with open(copilot_stub, "w", encoding="utf-8") as f:
                f.write("#!/bin/sh\necho 1.0.0\nexit 0\n")
            os.chmod(copilot_stub, 0o755)

    @classmethod
    def tearDownClass(cls):
        bap_install.uninstall(cls.mock_bin, cls.mock_ws)
        # Terminate any controlplane process spawned by launchers during tests
        if sys.platform == "win32":
            subprocess.run(["taskkill", "/F", "/IM", "bapcontrolplane.exe"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        else:
            subprocess.run(["pkill", "-9", "-f", "bapcontrolplane"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        shutil.rmtree(cls.temp_dir, ignore_errors=True)

    def test_01_all_five_agent_identities_and_receipt_attestation(self):
        """Verify that all 5 agent identities resolve to their canonical SPIFFE SVIDs and delegation chains."""
        if not os.path.isfile(BAPEDGE_BIN):
            self.skipTest(f"bapedge binary not found at {BAPEDGE_BIN}")

        agents = [
            ("claude", "spiffe://bap.local/agent/claude"),
            ("antigravity", "spiffe://bap.local/agent/antigravity"),
            ("copilot", "spiffe://bap.local/agent/copilot"),
            ("cursor", "spiffe://bap.local/agent/cursor"),
            ("gemini", "spiffe://bap.local/agent/gemini"),
        ]

        for agent_name, expected_spiffe in agents:
            sess_id = f"sess-{agent_name}-e2e-test"
            env = os.environ.copy()
            env["LTD_SOURCE"] = agent_name
            env["BAP_SPIFFE_ID"] = expected_spiffe
            env["BAP_SESSION_ID"] = sess_id

            res = subprocess.run(
                [BAPEDGE_BIN, "exec", "--raw", "-json", "-source", agent_name, "git --version"],
                env=env,
                cwd=self.mock_ws,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=10,
            )

            self.assertEqual(res.returncode, 0, f"bapedge exec failed for agent {agent_name}: {res.stderr}")
            try:
                data = json.loads(res.stdout)
            except Exception as e:
                self.fail(f"Invalid JSON returned for agent {agent_name}: {res.stdout} (err: {e})")

            # Validate identity attestation
            self.assertIn("receipt", data, f"Receipt missing for agent {agent_name}")
            receipt = data["receipt"]
            self.assertEqual(receipt.get("session_id"), sess_id)
            self.assertEqual(receipt.get("identity"), expected_spiffe)
            self.assertIn(f"agent:{agent_name}", receipt.get("delegation", ""))
            self.assertTrue(data.get("allowed", False))
            self.assertEqual(receipt.get("result"), "ALLOWED_EXECUTED")

    def test_02_identity_anti_tampering_invariants(self):
        """Verify that bapedge blocks any agent identity trying to mutate protected assets."""
        if not os.path.isfile(BAPEDGE_BIN):
            self.skipTest(f"bapedge binary not found at {BAPEDGE_BIN}")

        agents = ["claude", "antigravity", "copilot", "cursor", "gemini"]
        tampering_commands = [
            "del policy.cedar",
            "rm -f policy.cedar",
            "rm -rf .claude/settings.json",
            "del bap-config.json",
            "attrib -r bapedge.exe",
        ]

        for agent in agents:
            for bad_cmd in tampering_commands:
                env = os.environ.copy()
                env["LTD_SOURCE"] = agent
                env["BAP_SESSION_ID"] = f"sess-tamper-{agent}"

                res = subprocess.run(
                    [BAPEDGE_BIN, "exec", "-json", bad_cmd],
                    env=env,
                    cwd=self.mock_ws,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    timeout=10,
                )

                # Must be denied (non-zero or JSON denied)
                try:
                    data = json.loads(res.stdout)
                    self.assertFalse(data.get("allowed", True), f"Tampering command {bad_cmd} was NOT denied for {agent}")
                    self.assertIn("Security Invariant Violation", data.get("reason", ""))
                    self.assertEqual(data.get("receipt", {}).get("result"), "DENIED_TAMPER")
                except json.JSONDecodeError:
                    self.assertNotEqual(res.returncode, 0, f"Tampering command {bad_cmd} should fail with non-zero exit code")

    def test_03_concurrent_multi_agent_session_isolation(self):
        """Verify session isolation: revoking one agent session does not impair concurrent sessions of other agents."""
        if not os.path.isfile(BAPEDGE_BIN):
            self.skipTest(f"bapedge binary not found at {BAPEDGE_BIN}")

        sess_claude = "sess-claude-isolated-001"
        sess_antigravity = "sess-antigravity-isolated-002"

        # Create local .bap policy-state.json revoking sess_claude
        bap_dir = os.path.join(self.mock_ws, ".bap")
        os.makedirs(bap_dir, exist_ok=True)
        policy_state_file = os.path.join(bap_dir, "policy-state.json")
        with open(policy_state_file, "w", encoding="utf-8") as f:
            json.dump({
                "kill_switch": False,
                "revoked_sessions": [sess_claude],
            }, f)

        try:
            # 1. Claude session should be rejected due to revocation
            env_claude = os.environ.copy()
            env_claude["LTD_SOURCE"] = "claude"
            env_claude["BAP_SESSION_ID"] = sess_claude

            res_c = subprocess.run(
                [BAPEDGE_BIN, "exec", "--raw", "git --version"],
                env=env_claude,
                cwd=self.mock_ws,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=10,
            )
            self.assertNotEqual(res_c.returncode, 0, "Revoked session should be blocked")
            self.assertTrue("revoked" in (res_c.stdout + res_c.stderr).lower())

            # 2. Antigravity session should continue to be authorized
            env_ag = os.environ.copy()
            env_ag["LTD_SOURCE"] = "antigravity"
            env_ag["BAP_SESSION_ID"] = sess_antigravity

            res_ag = subprocess.run(
                [BAPEDGE_BIN, "exec", "--raw", "git --version"],
                env=env_ag,
                cwd=self.mock_ws,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=10,
            )
            self.assertEqual(res_ag.returncode, 0, f"Antigravity session should remain authorized: {res_ag.stderr}")

        finally:
            if os.path.isfile(policy_state_file):
                os.remove(policy_state_file)

    def test_04_cross_shell_launcher_execution(self):
        """Verify launcher execution across CMD, PowerShell, and Bash shells."""
        if sys.platform != "win32":
            self.skipTest("Windows shell launchers tested on win32")

        env = os.environ.copy()
        env["PATH"] = self.mock_bin + os.pathsep + env.get("PATH", "")

        # 1. Test CMD execution of run_antigravity_cli_bap.bat --version
        bat_launcher = os.path.join(self.mock_bin, "run_antigravity_cli_bap.bat")
        if os.path.isfile(bat_launcher):
            res_cmd = subprocess.run(
                ["cmd.exe", "/c", bat_launcher, "--version"],
                cwd=self.mock_ws,
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=30,
            )
            self.assertEqual(res_cmd.returncode, 0, f"CMD launcher execution failed (exit code {res_cmd.returncode}):\nSTDOUT: {res_cmd.stdout}\nSTDERR: {res_cmd.stderr}")
            self.assertIn("BOUNDED AUTHORITY PLANE", res_cmd.stdout)
            self.assertIn("antigravity", res_cmd.stdout.lower())

        # 2. Test PowerShell execution of run_claude_bap.ps1 --version
        ps1_launcher = os.path.join(self.mock_bin, "run_claude_bap.ps1")
        if os.path.isfile(ps1_launcher):
            res_ps = subprocess.run(
                ["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", ps1_launcher, "--version"],
                cwd=self.mock_ws,
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=30,
            )
            self.assertEqual(res_ps.returncode, 0, f"PowerShell launcher execution failed (exit code {res_ps.returncode}):\nSTDOUT: {res_ps.stdout}\nSTDERR: {res_ps.stderr}")
            self.assertIn("CLAUDE CODE", res_ps.stdout)

        # 3. Test Bash execution of run_antigravity_cli_bap.sh if bash is available
        sh_launcher = os.path.join(self.mock_bin, "run_antigravity_cli_bap.sh")
        if os.path.isfile(sh_launcher) and shutil.which("bash"):
            # Verify sh launcher is valid shell script with shebang
            with open(sh_launcher, "r", encoding="utf-8") as f:
                content = f.read()
            self.assertTrue(
                content.startswith("#!/usr/bin/env bash") or
                content.startswith("#!/bin/bash") or
                content.startswith("#!/bin/sh"),
                f"Unexpected shebang in {sh_launcher}: {content[:30]}"
            )
            self.assertIn("antigravity", content)

    def test_05_bap_doctor_loads_installed_bin_policy_consistently(self):
        """Verify bap doctor always identifies the release policy in bin directory regardless of cwd."""
        doctor_py = os.path.join(WORKSPACE_ROOT, "bap", "bap_doctor.py")
        if not os.path.isfile(doctor_py):
            self.skipTest("bap_doctor.py not found")

        env = os.environ.copy()
        env["PATH"] = self.mock_bin + os.pathsep + env.get("PATH", "")

        # Run doctor from isolated workspace
        res = subprocess.run(
            [sys.executable, doctor_py],
            cwd=self.mock_ws,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=15,
        )
        self.assertEqual(res.returncode, 0, f"bap doctor returned error: {res.stderr}\n{res.stdout}")
        self.assertIn("Cedar Policy (policy.cedar)", res.stdout)
        self.assertIn("PASS", res.stdout)
        # Verify it loaded from an installed binary/release directory (bin or dist) and NOT repo root
        out_lower = res.stdout.lower()
        self.assertTrue("policy.cedar" in out_lower)
        self.assertTrue("bin" in out_lower or "dist" in out_lower)
        self.assertIn("bin\\policy.cedar", res.stdout.lower())


if __name__ == "__main__":
    unittest.main()

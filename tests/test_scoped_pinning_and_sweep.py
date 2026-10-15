"""
Unit and Integration Tests for Agent-Scoped Pinning, Pin Clear/Unpin/Reset, and Offline Sweep/Sync (BAP-548).
"""

import json
import os
import subprocess
import tempfile
import unittest


class TestScopedPinningAndSweep(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.bapedge = os.path.abspath("bapedge.exe")
        assert os.path.exists(cls.bapedge), f"bapedge.exe not found at {cls.bapedge}"

    def run_bapedge(self, *args, env=None):
        cmd = [self.bapedge, "exec", f"{self.bapedge} " + " ".join(args)]
        run_env = os.environ.copy()
        if env:
            run_env.update(env)
        proc = subprocess.run(
            [self.bapedge] + list(args),
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            env=run_env,
        )
        return proc

    def test_01_pin_list_displays_agent_scopes(self):
        """Test that 'bapedge pin list' outputs Scope for each asset."""
        proc = self.run_bapedge("pin", "list")
        self.assertEqual(proc.returncode, 0, f"pin list failed: {proc.stderr}")
        self.assertIn("Scope:", proc.stdout)
        self.assertIn("prompt:CLAUDE.md", proc.stdout)
        self.assertIn("prompt:GEMINI.md", proc.stdout)

    def test_02_pin_verify_filters_by_agent_scope(self):
        """Test that 'bapedge pin verify --scope' properly isolates agent scopes."""
        # 1. Antigravity scope
        proc_ag = self.run_bapedge("pin", "verify", "--scope", "antigravity")
        self.assertEqual(proc_ag.returncode, 0, f"pin verify ag failed: {proc_ag.stderr}")
        self.assertIn("Agent Filter: antigravity", proc_ag.stdout)
        self.assertIn("prompt:GEMINI.md", proc_ag.stdout)
        self.assertNotIn("prompt:CLAUDE.md", proc_ag.stdout)

        # 2. Claude Code scope
        proc_cc = self.run_bapedge("pin", "verify", "--scope", "claude-code")
        self.assertEqual(proc_cc.returncode, 0, f"pin verify cc failed: {proc_cc.stderr}")
        self.assertIn("Agent Filter: claude-code", proc_cc.stdout)
        self.assertIn("prompt:CLAUDE.md", proc_cc.stdout)
        self.assertNotIn("prompt:GEMINI.md", proc_cc.stdout)

        # 3. Both include global policy.cedar
        self.assertIn("prompt:policy.cedar", proc_ag.stdout)
        self.assertIn("prompt:policy.cedar", proc_cc.stdout)

    def test_03_pin_add_and_unpin(self):
        """Test adding a custom scoped pin and then unpinning it."""
        # Create a temp file to pin
        with tempfile.NamedTemporaryFile(suffix=".md", delete=False) as f:
            f.write(b"# Custom Tool Instruction\n")
            temp_path = f.name

        try:
            # Pin with explicit scope
            asset_id = "skill:custom-test"
            proc_add = self.run_bapedge("pin", "add", temp_path, "--id", asset_id, "--scope", "copilot")
            self.assertEqual(proc_add.returncode, 0, f"pin add failed: {proc_add.stderr}")
            self.assertIn("Scope:  copilot", proc_add.stdout)

            # Verify it shows up in copilot scope
            proc_verify_copilot = self.run_bapedge("pin", "verify", "--scope", "copilot")
            self.assertEqual(proc_verify_copilot.returncode, 0)
            self.assertIn(asset_id, proc_verify_copilot.stdout)

            # Verify it does NOT show up in antigravity scope
            proc_verify_ag = self.run_bapedge("pin", "verify", "--scope", "antigravity")
            self.assertEqual(proc_verify_ag.returncode, 0)
            self.assertNotIn(asset_id, proc_verify_ag.stdout)

            # Unpin
            proc_unpin = self.run_bapedge("pin", "unpin", asset_id)
            self.assertEqual(proc_unpin.returncode, 0, f"pin unpin failed: {proc_unpin.stderr}")
            self.assertIn(f"Unpinned {asset_id}", proc_unpin.stdout)

            # Verify it is gone
            proc_list = self.run_bapedge("pin", "list")
            self.assertNotIn(asset_id, proc_list.stdout)
        finally:
            self.run_bapedge("pin", "unpin", asset_id)
            if os.path.exists(temp_path):
                os.remove(temp_path)

    def test_04_bapedge_sweep_cleans_state_and_flushes(self):
        """Test that 'bapedge sweep' successfully purges dead locks and executes."""
        proc = self.run_bapedge("sweep")
        self.assertEqual(proc.returncode, 0, f"bapedge sweep failed: {proc.stderr}")
        self.assertIn("Running Clean Sweep", proc.stdout)
        self.assertIn("Clean sweep completed successfully", proc.stdout)

    def test_05_bapedge_sync_reports_offline_spool(self):
        """Test that 'bapedge sync' inspects cached policy and local telemetry spool."""
        proc = self.run_bapedge("sync")
        self.assertEqual(proc.returncode, 0, f"bapedge sync failed: {proc.stderr}")
        self.assertIn("Policy Version:", proc.stdout)
        self.assertIn("Telemetry Spool:", proc.stdout)
        self.assertIn("Rules Digest:", proc.stdout)


if __name__ == "__main__":
    unittest.main()

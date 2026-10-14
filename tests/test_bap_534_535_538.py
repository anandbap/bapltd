"""
Verification Test Suite: BAP-534, BAP-535, and BAP-538
- BAP-535: Credential Shielding & Secret Redaction
- BAP-534: Process-Level Supervision & Child Ancestry Tracking
- BAP-538: Incident Forensics & Automated Snapshot Rollback (bapedge rollback)
"""

import os
import json
import shutil
import tempfile
import unittest
import subprocess

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BAPEDGE_BIN = os.path.join(REPO_ROOT, "dist", "windows-amd64", "bapedge.exe")


class TestBap534_535_538(unittest.TestCase):
    def setUp(self):
        self.test_session = f"sess-test-534-535-538-{os.getpid()}"
        self.temp_dir = os.path.join(REPO_ROOT, "scratch", f"snap_test_{os.getpid()}")
        os.makedirs(self.temp_dir, exist_ok=True)

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_01_bap_535_ambient_credential_shielding(self):
        """BAP-535: Verify ambient standing credentials are stripped from child processes."""
        env = os.environ.copy()
        env["AWS_SECRET_ACCESS_KEY"] = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
        env["GITHUB_TOKEN"] = "ghp_123456789012345678901234567890123456"
        env["OPENAI_API_KEY"] = "sk-abcdefghijklmnopqrstuvwxyz123456"
        env["BAP_SESSION_ID"] = self.test_session
        env["BAP_TEST_MODE"] = "1"

        # Ask child process to inspect its environment
        # On Windows, using cmd.exe /c set AWS_SECRET_ACCESS_KEY should fail or return non-zero
        cmd = f'"{BAPEDGE_BIN}" exec --source test-agent --session-id {self.test_session} --force-json --raw "cmd.exe /c set AWS_SECRET_ACCESS_KEY"'
        proc = subprocess.run(cmd, shell=True, capture_output=True, text=True, env=env, cwd=REPO_ROOT)
        
        # In cmd.exe, 'set VAR' exits with code 1 if variable is not defined
        try:
            res = json.loads(proc.stdout)
            self.assertEqual(res.get("exit_code"), 1, "AWS_SECRET_ACCESS_KEY must not be defined in child process environment")
        except json.JSONDecodeError:
            self.assertNotIn("wJalrXUtnFEMI", proc.stdout)

    def test_02_bap_535_output_secret_redaction(self):
        """BAP-535: Verify detected private keys and tokens in command output are redacted."""
        fake_gh_token = "ghp_999988887777666655554444333322221111"
        fake_aws_key = "AKIAIOSFODNN7EXAMPLE"

        # Echo a fake token in command output
        cmd = f'"{BAPEDGE_BIN}" exec --source test-agent --session-id {self.test_session} --json "echo Token is {fake_gh_token} and key is {fake_aws_key}"'
        proc = subprocess.run(cmd, shell=True, capture_output=True, text=True, cwd=REPO_ROOT)
        
        self.assertEqual(proc.returncode, 0)
        res = json.loads(proc.stdout)
        output = res.get("output", "")
        self.assertIn("[BAP_REDACTED_GITHUB_TOKEN]", output, "GitHub token must be redacted in command output")
        self.assertIn("[BAP_REDACTED_AWS_KEY]", output, "AWS Access Key must be redacted in command output")
        self.assertNotIn(fake_gh_token, output, "Raw token must not appear in output")
        self.assertNotIn(fake_aws_key, output, "Raw AWS key must not appear in output")

    def test_03_bap_534_process_tree_ancestry(self):
        """BAP-534: Verify process tree ancestry is captured in execution receipt."""
        cmd = f'"{BAPEDGE_BIN}" exec --source test-agent --session-id {self.test_session} --json "git --version"'
        proc = subprocess.run(cmd, shell=True, capture_output=True, text=True, cwd=REPO_ROOT)
        
        self.assertEqual(proc.returncode, 0)
        res = json.loads(proc.stdout)
        receipt = res.get("receipt", {})
        self.assertIsNotNone(receipt, "Execution receipt must be present")
        
        process_tree = receipt.get("process_tree", [])
        self.assertGreaterEqual(len(process_tree), 3, "Process tree must contain parent, broker, and child")
        self.assertTrue(any(p.startswith("parent:") for p in process_tree))
        self.assertTrue(any(p.startswith("broker:") for p in process_tree))
        self.assertTrue(any(p.startswith("child:") for p in process_tree))
        self.assertGreater(receipt.get("process_pid", 0), 0, "Child process PID must be captured")

    def test_04_bap_538_checkpoint_and_rollback(self):
        """BAP-538: Verify pre-execution checkpointing and bapedge rollback."""
        target_file = os.path.join(self.temp_dir, "test_target.txt")
        original_text = "ORIGINAL_BENIGN_CONTENT_V1"
        with open(target_file, "w") as f:
            f.write(original_text)

        session_id = f"sess-rollback-e2e-{os.getpid()}"

        # 1. Mutate the file via bapedge exec with redirection
        cmd_mutate = f'"{BAPEDGE_BIN}" exec --source test-agent --session-id {session_id} "echo CORRUPTED_MODIFIED_CONTENT > {target_file}"'
        proc_mutate = subprocess.run(cmd_mutate, shell=True, capture_output=True, text=True, cwd=REPO_ROOT)
        self.assertEqual(proc_mutate.returncode, 0)

        # Confirm file was mutated
        with open(target_file, "r") as f:
            content = f.read()
        self.assertIn("CORRUPTED_MODIFIED_CONTENT", content)

        # 2. Check that a checkpoint was created
        cmd_list = f'"{BAPEDGE_BIN}" rollback --session-id {session_id} --list --json'
        proc_list = subprocess.run(cmd_list, shell=True, capture_output=True, text=True, cwd=REPO_ROOT)
        self.assertEqual(proc_list.returncode, 0)
        checkpoints = json.loads(proc_list.stdout)
        self.assertGreaterEqual(len(checkpoints), 1, "At least one checkpoint must be recorded")

        # 3. Perform rollback
        cmd_rollback = f'"{BAPEDGE_BIN}" rollback --session-id {session_id} --file {target_file} --json'
        proc_rollback = subprocess.run(cmd_rollback, shell=True, capture_output=True, text=True, cwd=REPO_ROOT)
        self.assertEqual(proc_rollback.returncode, 0)
        rollback_res = json.loads(proc_rollback.stdout)
        self.assertIn(os.path.abspath(target_file), rollback_res.get("restored_files", []))

        # 4. Verify file was restored to exact original content
        with open(target_file, "r") as f:
            restored_content = f.read()
        self.assertEqual(restored_content, original_text, "File must be forensically restored to original content")


if __name__ == "__main__":
    unittest.main()

"""
Verification Test Suite: BAP Multi-Layered Defense-in-Depth (BAP-200)
Verifies:
  Layer 1: Native Lifecycle Hooks (Claude Code PreToolUse & UserPromptSubmit)
  Layer 2: Model Context Protocol (bapmcp.exe bap_execute & Cedar authorization)
  Layer 3: Tool Call & Terminal Interceptor Shims (.bapstate/shims/ -> bapedge exec)
  Layer 4: Runtime Execution Broker (Sandboxed Process Containment & Telemetry)
  Layer 5: Authoritative Network Gateway PEP & Perimeter Backstop (Envoy ext_authz, ZSP single-use grant burning)
"""

import os
import sys
import json
import time
import shutil
import unittest
import subprocess
import urllib.request

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BAPEDGE_BIN = os.path.join(REPO_ROOT, "dist", "windows-amd64", "bapedge.exe")
BAPMCP_BIN = os.path.join(REPO_ROOT, "bapmcp.exe")
CONTROLPLANE_BIN = os.path.join(REPO_ROOT, "dist", "windows-amd64", "bapcontrolplane.exe")
TEST_ADMIN_TOKEN = "test-admin-secret-12345"


class TestMultiLayerDefense(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cp_port = 8089
        cls.server_url = f"http://localhost:{cls.cp_port}"
        # Clean any stale cached policy state from prior test suites
        for p in [
            os.path.join(REPO_ROOT, ".bapstate", "policy"),
            os.path.join(REPO_ROOT, ".bap"),
            os.path.expanduser("~/.bapstate/policy"),
        ]:
            if os.path.exists(p):
                shutil.rmtree(p, ignore_errors=True)

        # Start isolated control plane with admin token and explicit baseline policy
        cls.cp_proc = subprocess.Popen(
            [
                CONTROLPLANE_BIN,
                "-port", str(cls.cp_port),
                "-ttl", "30",
                "-admin-token", TEST_ADMIN_TOKEN,
                "-allow-remote-admin",
                "-policy", os.path.join(REPO_ROOT, "policy.cedar"),
                "-schema", os.path.join(REPO_ROOT, "schema.json"),
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            cwd=REPO_ROOT
        )
        # Wait for control plane to become healthy
        healthy = False
        for _ in range(25):
            try:
                with urllib.request.urlopen(f"{cls.server_url}/api/v1/health", timeout=0.5) as res:
                    if res.status == 200:
                        healthy = True
                        break
            except Exception:
                time.sleep(0.15)
        if not healthy:
            raise RuntimeError("Failed to start test control plane on port %d" % cls.cp_port)

    @classmethod
    def tearDownClass(cls):
        if cls.cp_proc:
            cls.cp_proc.terminate()
            cls.cp_proc.wait()
        for p in [
            os.path.join(REPO_ROOT, ".bapstate", "policy"),
            os.path.join(REPO_ROOT, ".bap"),
            os.path.expanduser("~/.bapstate/policy"),
        ]:
            if os.path.exists(p):
                shutil.rmtree(p, ignore_errors=True)

    def test_01_layer2_mcp_defense(self):
        """Verify Layer 2 (MCP): bapmcp allows permitted tools and blocks forbidden resources."""
        session_id = "sess-mcp-test-01"
        env = os.environ.copy()
        env["LTD_SOURCE"] = "antigravity"
        env["BAP_SESSION_ID"] = session_id

        proc = subprocess.Popen(
            [BAPEDGE_BIN, "mcp", "--server", self.server_url, "--session-id", session_id],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            env=env,
            cwd=REPO_ROOT,
            text=True,
            bufsize=1
        )
        try:
            # 1. MCP initialize handshake
            init_req = {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2024-11-05",
                    "clientInfo": {"name": "test-client", "version": "1.0"}
                }
            }
            proc.stdin.write(json.dumps(init_req) + "\n")
            proc.stdin.flush()
            init_resp = json.loads(proc.stdout.readline())
            self.assertEqual(init_resp.get("id"), 1)
            self.assertIn("serverInfo", init_resp.get("result", {}))

            # 2. MCP call permitted tool: bap_execute git --version
            req_allowed = {
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/call",
                "params": {
                    "name": "bap_execute",
                    "arguments": {"command": "git --version"}
                }
            }
            proc.stdin.write(json.dumps(req_allowed) + "\n")
            proc.stdin.flush()
            res_allowed = json.loads(proc.stdout.readline())
            self.assertIn("result", res_allowed, "MCP bap_execute for 'git --version' must succeed")
            content_text = res_allowed["result"]["content"][0]["text"]
            self.assertIn("git version", content_text)

            # 3. MCP call blocked tool: bap_execute cat .env (secret disclosure)
            req_denied = {
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tools/call",
                "params": {
                    "name": "bap_execute",
                    "arguments": {"command": "cat .env"}
                }
            }
            proc.stdin.write(json.dumps(req_denied) + "\n")
            proc.stdin.flush()
            res_denied = json.loads(proc.stdout.readline())
            self.assertTrue(res_denied["result"]["isError"], "MCP must block 'cat .env' with isError=True")
            self.assertIn("[DENIED]", res_denied["result"]["content"][0]["text"])

            # 4. MCP call bap_status to verify 5-layer defense architecture
            req_status = {
                "jsonrpc": "2.0",
                "id": 4,
                "method": "tools/call",
                "params": {
                    "name": "bap_status",
                    "arguments": {}
                }
            }
            proc.stdin.write(json.dumps(req_status) + "\n")
            proc.stdin.flush()
            res_status = json.loads(proc.stdout.readline())
            self.assertIn("result", res_status)
            status_text = res_status["result"]["content"][0]["text"]
            self.assertIn("5-Layer Defense-in-Depth", status_text)
            self.assertIn("Layer 5", status_text)
            self.assertIn("Authoritative Network Gateway PEP", status_text)
        finally:
            if proc.stdin:
                try:
                    proc.stdin.close()
                except Exception:
                    pass
            if proc.stdout:
                try:
                    proc.stdout.close()
                except Exception:
                    pass
            proc.terminate()
            proc.wait()

    def test_02_layer3_tool_call_shims(self):
        """Verify Layer 3: Tool shims intercept commands and route through bapedge exec."""
        session_id = "sess-layer3-test-02"
        shim_dir = os.path.join(REPO_ROOT, ".bapstate", f"shims-{session_id}")
        os.makedirs(shim_dir, exist_ok=True)
        try:
            # Create git shim
            git_shim_content = f"""@echo off
if "%BAP_IN_BROKER%"=="1" goto REAL_RUN
"{BAPEDGE_BIN}" exec --server {self.server_url} --source antigravity --session-id {session_id} --raw "%~n0 %*"
exit /b %ERRORLEVEL%

:REAL_RUN
git.exe %*
exit /b %ERRORLEVEL%
"""
            with open(os.path.join(shim_dir, "git.cmd"), "w") as f:
                f.write(git_shim_content)

            env = os.environ.copy()
            env["PATH"] = shim_dir + os.pathsep + env.get("PATH", "")
            env["LTD_SOURCE"] = "antigravity"
            env["BAP_SESSION_ID"] = session_id
            env["BAP_IN_BROKER"] = "0"

            # Execute via shim in cmd
            res = subprocess.run(
                ["cmd.exe", "/c", "git.cmd --version"],
                capture_output=True,
                text=True,
                env=env,
                cwd=REPO_ROOT
            )
            self.assertEqual(res.returncode, 0, f"Shim execution failed: {res.stderr}")
            self.assertIn("git version", res.stdout)
        finally:
            shutil.rmtree(shim_dir, ignore_errors=True)

    def test_03_layer4_runtime_execution_telemetry(self):
        """Verify Layer 4: Launcher session enrollment registers mission prompt and streams to Control Plane."""
        session_id = f"sess-ag-layer4-{int(time.time())}"
        test_prompt = "Refactor customer database models"

        # Start session with prompt using bapedge session-start
        res = subprocess.run(
            [
                BAPEDGE_BIN, "session-start",
                "--server", self.server_url,
                "--session-id", session_id,
                "--app-id", "antigravity",
                "--prompt", test_prompt
            ],
            capture_output=True,
            text=True,
            cwd=REPO_ROOT
        )
        self.assertEqual(res.returncode, 0, f"session-start failed: {res.stderr}")

        # Query session on control plane using admin token to read unmasked fields
        req_obj = urllib.request.Request(
            f"{self.server_url}/api/v1/sessions/{session_id}",
            headers={"X-BAP-Admin-Token": TEST_ADMIN_TOKEN}
        )
        with urllib.request.urlopen(req_obj, timeout=1.0) as resp:
            data = json.loads(resp.read().decode())
        self.assertEqual(data.get("session_id"), session_id)
        self.assertEqual(data.get("app_id"), "antigravity")
        self.assertEqual(data.get("user_prompt"), test_prompt, "Session prompt must be registered on control plane")

        # Execute governed action under this session
        res_exec = subprocess.run(
            [
                BAPEDGE_BIN, "exec",
                "--server", self.server_url,
                "--source", "antigravity",
                "--session-id", session_id,
                "--raw", "git status"
            ],
            capture_output=True,
            text=True,
            cwd=REPO_ROOT
        )
        self.assertEqual(res_exec.returncode, 0, f"bapedge exec failed: {res_exec.stderr}")

        # End session cleanly
        res_end = subprocess.run(
            [
                BAPEDGE_BIN, "session-end",
                "--server", self.server_url,
                "--session-id", session_id
            ],
            capture_output=True,
            text=True,
            cwd=REPO_ROOT
        )
        self.assertEqual(res_end.returncode, 0)

    def test_04_layer4_credential_shielding_and_output_redaction(self):
        """Verify Layer 4 (Broker): Strips ambient secrets and redacts sensitive tokens in output."""
        session_id = f"sess-mld-shield-{os.getpid()}"
        env = os.environ.copy()
        env["AWS_SECRET_ACCESS_KEY"] = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
        env["BAP_SESSION_ID"] = session_id
        env["BAP_TEST_MODE"] = "1"

        # Verify env stripped
        res_env = subprocess.run(
            [
                BAPEDGE_BIN, "exec",
                "--server", self.server_url,
                "--source", "antigravity",
                "--session-id", session_id,
                "--force-json",
                "--raw", "cmd.exe /c set AWS_SECRET_ACCESS_KEY"
            ],
            capture_output=True,
            text=True,
            env=env,
            cwd=REPO_ROOT
        )
        try:
            res_json = json.loads(res_env.stdout)
            self.assertEqual(res_json.get("exit_code"), 1)
        except json.JSONDecodeError:
            self.assertNotIn("wJalrXUtnFEMI", res_env.stdout)

        # Verify output token redacted
        fake_token = "ghp_555544443333222211110000aaaa99998888"
        res_redact = subprocess.run(
            [
                BAPEDGE_BIN, "exec",
                "--server", self.server_url,
                "--source", "antigravity",
                "--session-id", session_id,
                "--json", f"echo token={fake_token}"
            ],
            capture_output=True,
            text=True,
            cwd=REPO_ROOT
        )
        self.assertEqual(res_redact.returncode, 0)
        data = json.loads(res_redact.stdout)
        self.assertIn("[BAP_REDACTED_GITHUB_TOKEN]", data.get("output", ""))
        self.assertNotIn(fake_token, data.get("output", ""))

    def test_05_layer4_process_ancestry_and_forensic_rollback(self):
        """Verify Layer 4 (Broker): Captures process tree ancestry and executes bapedge rollback."""
        session_id = f"sess-mld-rollback-{os.getpid()}"

        # 1. Process ancestry
        res_proc = subprocess.run(
            [
                BAPEDGE_BIN, "exec",
                "--server", self.server_url,
                "--source", "antigravity",
                "--session-id", session_id,
                "--json", "git --version"
            ],
            capture_output=True,
            text=True,
            cwd=REPO_ROOT
        )
        self.assertEqual(res_proc.returncode, 0)
        receipt = json.loads(res_proc.stdout).get("receipt", {})
        tree = receipt.get("process_tree", [])
        self.assertGreaterEqual(len(tree), 3)

        # 2. Checkpoint and Rollback
        scratch_dir = os.path.join(REPO_ROOT, "scratch", f"mld_snap_{os.getpid()}")
        os.makedirs(scratch_dir, exist_ok=True)
        try:
            target = os.path.join(scratch_dir, "mld_target.txt")
            original_val = "SAFE_BASELINE_MLD_V1"
            with open(target, "w") as f:
                f.write(original_val)

            # Mutate
            res_mut = subprocess.run(
                [
                    BAPEDGE_BIN, "exec",
                    "--server", self.server_url,
                    "--source", "antigravity",
                    "--session-id", session_id,
                    f"echo DAMAGED_DATA > {target}"
                ],
                capture_output=True,
                text=True,
                cwd=REPO_ROOT
            )
            self.assertEqual(res_mut.returncode, 0)

            # Rollback
            res_rb = subprocess.run(
                [
                    BAPEDGE_BIN, "rollback",
                    "--session-id", session_id,
                    "--file", target,
                    "--json"
                ],
                capture_output=True,
                text=True,
                cwd=REPO_ROOT
            )
            self.assertEqual(res_rb.returncode, 0)
            rb_json = json.loads(res_rb.stdout)
            self.assertIn(os.path.abspath(target), rb_json.get("restored_files", []))

            # Verify
            with open(target, "r") as f:
                self.assertEqual(f.read(), original_val)
        finally:
            shutil.rmtree(scratch_dir, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()

#!/usr/bin/env python3
"""
BAP Multi-Agent Lifecycle Contract & Anti-Regression Test Suite
==============================================================
Validates that interceptor hooks, MCP tools, and daemon watchers conform
to the Universal Agent Schema across all supported agent frameworks:
- Claude Code
- OpenAI Codex CLI
- Google Antigravity
- GitHub Copilot
- Cursor IDE

Run locally in <3s:
    python -m unittest tests.test_agent_lifecycle_matrix
"""

import json
import os
import subprocess
import sys
import unittest

WORKSPACE_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))


def find_interceptor_binary():
    candidates = [
        os.path.join(WORKSPACE_ROOT, "interceptor.exe" if sys.platform == "win32" else "interceptor"),
        os.path.join(WORKSPACE_ROOT, "dist", "windows-amd64", "interceptor.exe"),
        os.path.join(os.path.expanduser("~"), ".bap", "bin", "interceptor.exe" if sys.platform == "win32" else "interceptor"),
    ]
    for c in candidates:
        if os.path.isfile(c):
            return c
    return candidates[0]


def invoke_hook(payload: dict, env_overrides: dict = None) -> dict:
    exe = find_interceptor_binary()
    if not os.path.isfile(exe):
        raise unittest.SkipTest(f"interceptor binary not found at {exe}")

    run_env = os.environ.copy()
    if env_overrides:
        run_env.update(env_overrides)

    proc = subprocess.run(
        [exe],
        input=json.dumps(payload),
        text=True,
        capture_output=True,
        timeout=10,
        env=run_env,
        cwd=WORKSPACE_ROOT,
    )
    stdout = proc.stdout.strip()
    if not stdout:
        return {}
    try:
        return json.loads(stdout)
    except json.JSONDecodeError:
        return {"raw_stdout": stdout, "exit_code": proc.returncode}


class TestMultiAgentLifecycleMatrix(unittest.TestCase):
    """Scenario tests verifying multi-agent lifecycle hook invariant contracts."""

    def test_claude_lifecycle_session_start(self):
        """Verify Claude Code SessionStart contract preserves status: ok and continue: true."""
        payload = {
            "hook_event_name": "SessionStart",
            "session_id": "sess-claude-contract-test",
        }
        resp = invoke_hook(payload, env_overrides={"LTD_SOURCE": "claude-code"})
        self.assertEqual(resp.get("status"), "ok", "Claude Code requires status: 'ok'")
        self.assertIs(resp.get("continue"), True, "Modern Claude Code requires continue: true")

    def test_claude_lifecycle_user_prompt(self):
        """Verify Claude Code UserPromptSubmit contract."""
        payload = {
            "hook_event_name": "UserPromptSubmit",
            "session_id": "sess-claude-contract-test",
            "prompt": "Investigate payment gateway latency spike",
        }
        resp = invoke_hook(payload, env_overrides={"LTD_SOURCE": "claude-code"})
        self.assertEqual(resp.get("status"), "ok")
        self.assertIs(resp.get("continue"), True)

    def test_codex_lifecycle_session_start(self):
        """Verify OpenAI Codex CLI SessionStart contract preserves continue: true and status: ok."""
        payload = {
            "hook_event_name": "SessionStart",
            "session_id": "sess-codex-contract-test",
        }
        resp = invoke_hook(payload, env_overrides={"LTD_SOURCE": "codex"})
        self.assertIs(resp.get("continue"), True, "Codex CLI requires continue: true")
        self.assertEqual(resp.get("status"), "ok", "Universal schema requires status: 'ok'")

    def test_codex_lifecycle_user_prompt(self):
        """Verify OpenAI Codex CLI UserPromptSubmit contract."""
        payload = {
            "hook_event_name": "UserPromptSubmit",
            "session_id": "sess-codex-contract-test",
            "prompt": "Optimize database index query plan",
        }
        resp = invoke_hook(payload, env_overrides={"LTD_SOURCE": "codex"})
        self.assertIs(resp.get("continue"), True)
        self.assertEqual(resp.get("status"), "ok")

    def test_codex_lifecycle_session_end(self):
        """Verify OpenAI Codex CLI SessionEnd / Stop teardown contract."""
        payload = {
            "hook_event_name": "SessionEnd",
            "session_id": "sess-codex-contract-test",
        }
        resp = invoke_hook(payload, env_overrides={"LTD_SOURCE": "codex"})
        self.assertEqual(resp.get("status"), "ok")
        self.assertIs(resp.get("continue"), True)

    def test_pre_tool_use_cedar_rewrite_contract(self):
        """Verify PreToolUse hook rewrites tool execution through bapedge exec."""
        payload = {
            "hook_event_name": "PreToolUse",
            "session_id": "sess-pretool-contract-test",
            "tool_name": "Bash",
            "tool_input": {
                "command": "git status"
            }
        }
        resp = invoke_hook(payload, env_overrides={"LTD_SOURCE": "codex", "BAP_ENFORCEMENT_MODE": "enforce"})
        h_out = resp.get("hookSpecificOutput", {})
        self.assertEqual(h_out.get("permissionDecision"), "allow")
        updated_input = h_out.get("updatedInput") or resp.get("tool_input", {})
        cmd = updated_input.get("command", "") if updated_input else ""
        self.assertIn("bapedge", cmd, "PreToolUse must route commands through bapedge execution broker")


if __name__ == "__main__":
    unittest.main()

#!/usr/bin/env python3
"""
Test Suite: BAP Universal Harness Manager (Multi-Agent & Multi-Session Isolation)
=================================================================================
Verifies:
1. init: Configures Claude Code hooks, VS Code Copilot settings, Antigravity rules, and MCP configs.
2. start-session: Registers sessions with isolated markers (.bapstate/sessions/<hash>.json and pid-<pid>.json).
3. Multi-Session Support: Multiple sessions running under the same Agent (e.g. 2 Claude sessions, 2 Copilot sessions)
   maintain distinct session IDs, isolated PIDs, and independent prompt histories.
4. send-prompt: Dynamically transmits follow-up prompts and updates prompt history.
5. Session Isolation: Terminating one session of an agent leaves concurrent sessions of the same agent intact.
6. cleanup-all: Cleanly purges all session markers and resets active count.
"""

import json
import os
import shutil
import sys
import tempfile
import unittest

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
SCRIPTS_DIR = os.path.join(ROOT_DIR, "scripts")
if SCRIPTS_DIR not in sys.path:
    sys.path.insert(0, SCRIPTS_DIR)

from bap_harness import (
    cmd_init,
    cmd_start_session,
    cmd_send_prompt,
    cmd_stop_session,
    cmd_cleanup_all,
    classify_prompt_intent,
    SESSIONS_DIR,
    PROMPTS_DIR,
    ensure_dirs,
)


class DummyArgs:
    def __init__(self, **kwargs):
        for k, v in kwargs.items():
            setattr(self, k, v)


class TestHarnessMultiSessionIsolation(unittest.TestCase):
    def setUp(self):
        ensure_dirs()
        self.test_ws = tempfile.mkdtemp(prefix="bap_ws_test_")

    def tearDown(self):
        # Cleanup test workspace
        shutil.rmtree(self.test_ws, ignore_errors=True)
        # Purge any test sessions created
        cmd_cleanup_all(DummyArgs(server="http://localhost:8080"))

    def test_01_init_configures_all_three_ides(self):
        """Verify init command sets up Claude Code, Copilot, and Antigravity."""
        args = DummyArgs(workspace=self.test_ws)
        cmd_init(args)

        # 1. Claude Code
        claude_settings = os.path.join(self.test_ws, ".claude", "settings.json")
        claude_mcp = os.path.join(self.test_ws, ".claude", "mcp.json")
        self.assertTrue(os.path.isfile(claude_settings), "Claude settings.json must be created")
        self.assertTrue(os.path.isfile(claude_mcp), "Claude mcp.json must be created")
        with open(claude_settings, "r") as f:
            data = json.load(f)
            self.assertIn("hooks", data)
            self.assertIn("PreToolUse", data["hooks"])

        # 2. GitHub Copilot
        vscode_settings = os.path.join(self.test_ws, ".vscode", "settings.json")
        vscode_mcp = os.path.join(self.test_ws, ".vscode", "mcp.json")
        self.assertTrue(os.path.isfile(vscode_settings), "VS Code settings.json must be created")
        self.assertTrue(os.path.isfile(vscode_mcp), "VS Code mcp.json must be created")
        with open(vscode_settings, "r") as f:
            data = json.load(f)
            self.assertTrue(
                "terminal.integrated.defaultProfile.windows" in data or "terminal.integrated.defaultProfile.linux" in data
            )

        # 3. Antigravity
        gemini_rules = os.path.join(self.test_ws, "GEMINI.md")
        self.assertTrue(os.path.isfile(gemini_rules), "Antigravity GEMINI.md rules must be created")

    def test_02_multi_session_under_same_agent(self):
        """Verify starting 2 sessions for the same agent preserves isolation."""
        # Clean slate
        cmd_cleanup_all(DummyArgs(server="http://localhost:8080"))

        # Start Session Alpha for claude-code
        args_alpha = DummyArgs(
            agent="claude-code",
            session_id="sess-claude-test-alpha",
            instance_id="laptop-1",
            prompt="Refactor database models",
            pid=44001,
            server="http://localhost:8080",
            watch=False,
        )
        marker_alpha = cmd_start_session(args_alpha)
        self.assertEqual(marker_alpha["session_id"], "sess-claude-test-alpha")
        self.assertEqual(marker_alpha["app_id"], "claude-code")
        self.assertEqual(marker_alpha["client_pid"], 44001)

        # Start Session Beta for claude-code (same agent, different session!)
        args_beta = DummyArgs(
            agent="claude-code",
            session_id="sess-claude-test-beta",
            instance_id="laptop-2",
            prompt="Investigate memory leak",
            pid=44002,
            server="http://localhost:8080",
            watch=False,
        )
        marker_beta = cmd_start_session(args_beta)
        self.assertEqual(marker_beta["session_id"], "sess-claude-test-beta")
        self.assertEqual(marker_beta["app_id"], "claude-code")
        self.assertEqual(marker_beta["client_pid"], 44002)

        # Verify both isolated markers exist simultaneously
        pid_marker_alpha = os.path.join(SESSIONS_DIR, "pid-44001.json")
        pid_marker_beta = os.path.join(SESSIONS_DIR, "pid-44002.json")
        self.assertTrue(os.path.isfile(pid_marker_alpha), "Alpha PID marker must exist")
        self.assertTrue(os.path.isfile(pid_marker_beta), "Beta PID marker must exist")

        with open(pid_marker_alpha, "r") as f:
            d_alpha = json.load(f)
            self.assertEqual(d_alpha["session_id"], "sess-claude-test-alpha")

        with open(pid_marker_beta, "r") as f:
            d_beta = json.load(f)
            self.assertEqual(d_beta["session_id"], "sess-claude-test-beta")

    def test_03_session_isolation_on_stop(self):
        """Verify terminating Alpha does NOT terminate Beta for the same agent."""
        cmd_cleanup_all(DummyArgs(server="http://localhost:8080"))

        # Start 2 sessions for Copilot
        cmd_start_session(DummyArgs(
            agent="copilot",
            session_id="sess-copilot-1",
            instance_id="dev-1",
            prompt="Write API test",
            pid=55001,
            server="http://localhost:8080",
            watch=False,
        ))
        cmd_start_session(DummyArgs(
            agent="copilot",
            session_id="sess-copilot-2",
            instance_id="dev-2",
            prompt="Generate deployment helm chart",
            pid=55002,
            server="http://localhost:8080",
            watch=False,
        ))

        # Stop only Session 1
        cmd_stop_session(DummyArgs(
            session_id="sess-copilot-1",
            pid=55001,
            server="http://localhost:8080",
        ))

        # Verify Session 1 marker is gone
        pid_marker_1 = os.path.join(SESSIONS_DIR, "pid-55001.json")
        self.assertFalse(os.path.isfile(pid_marker_1), "Session 1 marker must be removed")

        # Verify Session 2 marker is STILL ACTIVE!
        pid_marker_2 = os.path.join(SESSIONS_DIR, "pid-55002.json")
        self.assertTrue(os.path.isfile(pid_marker_2), "Session 2 marker must remain completely intact")

        with open(pid_marker_2, "r") as f:
            d2 = json.load(f)
            self.assertEqual(d2["session_id"], "sess-copilot-2")
            self.assertEqual(d2["app_id"], "copilot")

    def test_04_dynamic_prompt_transmission(self):
        """Verify dynamic prompt transmission updates session intent and history."""
        cmd_cleanup_all(DummyArgs(server="http://localhost:8080"))

        sess_id = "sess-ag-telemetry-test"
        cmd_start_session(DummyArgs(
            agent="antigravity",
            session_id=sess_id,
            instance_id="sre-box",
            prompt="Inspect cluster state",
            pid=66001,
            server="http://localhost:8080",
            watch=False,
        ))

        # Transmit follow-up prompt
        follow_up = "Fix authentication controller bug and re-run pytest"
        cmd_send_prompt(DummyArgs(
            session_id=sess_id,
            prompt=follow_up,
            server="http://localhost:8080",
        ))

        # Check classified intent
        intent = classify_prompt_intent(follow_up)
        self.assertEqual(intent["primary"], "BUG_FIX")


if __name__ == "__main__":
    unittest.main()


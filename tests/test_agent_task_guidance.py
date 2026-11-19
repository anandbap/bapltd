"""Installer callback coverage and shipped agent instruction parity."""
import json
from pathlib import Path
import tempfile
import unittest

from bap.agent_guidance import AGENT_TASK_GUIDANCE, update_agent_guidance
from bap.bap_install import configure_claude_code

ROOT = Path(__file__).resolve().parents[1]


class TestAgentTaskGuidance(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = ROOT / ".test-tmp"
        self.tmp_dir.mkdir(parents=True, exist_ok=True)

    def test_installer_registers_native_completion_for_success_and_failure(self):
        with tempfile.TemporaryDirectory(dir=self.tmp_dir) as folder:
            configure_claude_code(folder, "", "bapmcp", "bapedge")
            settings = json.loads((Path(folder) / "settings.json").read_text())
            for event in ("PreToolUse", "PostToolUse", "PostToolUseFailure"):
                self.assertEqual(settings["hooks"][event][0]["matcher"], "*")

            self.assertIn(AGENT_TASK_GUIDANCE.strip(), (Path(folder) / "CLAUDE.md").read_text())

    def test_reinstall_refreshes_only_owned_guidance(self):
        with tempfile.TemporaryDirectory(dir=self.tmp_dir) as folder:
            path = Path(folder) / "GEMINI.md"
            path.write_text("Developer instructions\n<!-- BAP task guidance -->\nstale\n<!-- /BAP task guidance -->\nKeep this too\n", encoding="utf-8")
            update_agent_guidance(path)
            first = path.read_text(encoding="utf-8")
            update_agent_guidance(path)
            self.assertEqual(path.read_text(encoding="utf-8"), first)
            self.assertTrue(first.startswith("Developer instructions\n"))
            self.assertTrue(first.endswith("Keep this too\n"))
            self.assertNotIn("stale", first)

    def test_agent_rules_teach_bounded_edits_and_human_escalation(self):
        for path in ("AGENTS.md", "CLAUDE.md", "CODEX.md", "GEMINI.md",
                     "plugins/antigravity/rules/AGENTS.md", "plugins/codex/rules/AGENTS.md",
                     "plugins/opencode/rules/AGENTS.md"):
            with self.subTest(path=path):
                text = (ROOT / path).read_text(encoding="utf-8-sig")
                self.assertIn(AGENT_TASK_GUIDANCE.strip(), text)

    def test_packaged_rules_and_launcher_engine_match_sources(self):
        for agent in ("antigravity", "codex", "opencode"):
            path = Path("plugins") / agent / "rules/AGENTS.md"
            self.assertEqual((ROOT / path).read_bytes(), (ROOT / "bap" / path).read_bytes())
        self.assertEqual((ROOT / "scripts/bap_launcher_engine.ps1").read_bytes(),
                         (ROOT / "bap/launchers/bap_launcher_engine.ps1").read_bytes())
        self.assertEqual((ROOT / "run_claude_cli_bap.ps1").read_bytes(),
                         (ROOT / "bap/launchers/run_claude_cli_bap.ps1").read_bytes())

    def test_posix_and_powershell_generate_the_same_workflow(self):
        for path in ("bap/launchers/bap_posix_engine.sh", "scripts/bap_launcher_engine.ps1"):
            self.assertIn(AGENT_TASK_GUIDANCE.strip(), (ROOT / path).read_text(encoding="utf-8-sig"))


if __name__ == "__main__":
    unittest.main()

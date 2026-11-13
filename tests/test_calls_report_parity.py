import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class TestCallsReportParity(unittest.TestCase):
    def test_all_entrypoints_use_one_implementation_and_match_cockpit_fixture(self):
        shell = shutil.which("pwsh") or shutil.which("powershell")
        if not shell:
            self.skipTest("PowerShell is unavailable")
        fixture = json.loads((ROOT / "tests/fixtures/calls_parity.json").read_text())
        temp_root = ROOT / ".codex-test-tmp"
        temp_root.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(dir=temp_root) as temp:
            ledger = Path(temp) / "audit.jsonl"
            events = [dict(e, session_id=fixture["session_id"], source="test") for e in fixture["events"]]
            ledger.write_text("\n".join(json.dumps(e) for e in events), encoding="utf-8")
            env = dict(os.environ, BAP_STATE_DIR=temp, USERPROFILE=temp, HOME=temp)
            for script in ["review_session.ps1", "scripts/review_session.ps1", "bap/review_session.ps1"]:
                with self.subTest(entrypoint=script):
                    result = subprocess.run([shell, "-NoProfile", "-NonInteractive", "-File", str(ROOT / script), fixture["session_id"], "-Path", str(ledger), "-Json"],
                                            cwd=temp, env=env, text=True, capture_output=True, timeout=30)
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                    report = json.loads(result.stdout.lstrip("\ufeff"))
                    summary = report["summary"]
                    names = {"total_actions":"total_events", "allowed":"allowed_count", "failed":"failed_count", "allowed_limited":"allowed_limited_count", "blocked":"blocked_count", "unclassified":"unclassified_count", "raw_events":"raw_events"}
                    for key, value in fixture["expected"].items():
                        self.assertEqual(summary[names[key]], value, (key, summary))
                    self.assertEqual(report["zsp_concepts"]["task_grants_minted"], 1)
                    self.assertNotIn("function Build-CallsReport", (ROOT / script).read_text())

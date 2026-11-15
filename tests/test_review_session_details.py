import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class ReviewSessionDetailsTests(unittest.TestCase):
    def test_missing_content_deduplication_chronology_and_sla(self):
        shell = shutil.which('pwsh') or shutil.which('powershell')
        if not shell:
            self.skipTest('PowerShell unavailable')
        temp_root = ROOT / '.codex-test-tmp'
        temp_root.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(dir=temp_root) as temp:
            base = dict(session_id='review-fixture', source='test', reporting_layer='hook',
                        reason='Details withheld by metadata capture policy', decision='allow')
            first = dict(base, event_id='one', timestamp='2026-11-14T23:54:10Z', executable='Glob')
            last = dict(base, event_id='two', timestamp='2026-11-14T23:54:40Z', executable='Bash', decision='deny')
            failed = dict(base, event_id='three', timestamp='2026-11-14T23:54:41Z', executable='test',
                          full_command='test command with a long argument that should remain fully visible',
                          reason='Command execution failed: detailed explanation beyond the table column width', exit_code=1)
            ledger = Path(temp) / 'audit.jsonl'
            ledger.write_text('\n'.join(json.dumps(e) for e in [last, first, first, failed]))
            env = dict(os.environ, BAP_STATE_DIR=temp, USERPROFILE=temp)
            args = [shell, '-NoProfile', '-NonInteractive', '-File', str(ROOT / 'review_session.ps1'),
                    'review-fixture', '-Path', str(ledger)]
            result = subprocess.run(args + ['-Json'], cwd=temp, env=env, capture_output=True, text=True, timeout=30)
            self.assertEqual(result.returncode, 0, result.stderr)
            report = json.loads(result.stdout.lstrip('\ufeff'))
            self.assertEqual(report['summary']['total_events'], 3)
            self.assertEqual(report['summary']['blocked_count'], 1)
            self.assertEqual(report['summary']['failed_count'], 1)
            self.assertEqual(report['allowed_calls'][0]['input_status'], 'withheld_by_policy')
            result = subprocess.run(args, cwd=temp, env=env, capture_output=True, text=True, timeout=30)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn('[input withheld by policy]', result.stdout)
            self.assertNotIn('(empty tool input)', result.stdout)
            self.assertIn('[UNKNOWN] No latency samples recorded', result.stdout)
            self.assertIn('2026-11-14 23:54:10', result.stdout)
            self.assertIn('23:54:10.00', result.stdout)
            self.assertIn(failed['full_command'], result.stdout)
            self.assertIn(failed['reason'], result.stdout)
            self.assertIn('FAILED', result.stdout)

    def test_acknowledged_local_archive_is_reviewable(self):
        shell = shutil.which('pwsh') or shutil.which('powershell')
        if not shell:
            self.skipTest('PowerShell unavailable')
        temp_root = ROOT / '.codex-test-tmp'
        temp_root.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(dir=temp_root) as temp:
            ledger = Path(temp) / 'audit.jsonl'
            ledger.write_text('')
            entry = dict(event_id='archived', session_id='archive-fixture', timestamp='2026-11-14T23:54:10Z',
                         executable='Glob', full_command='Glob **/*.go', reason='Allowed workspace search', decision='allow')
            Path(str(ledger) + '.recovery-test.jsonl').write_text(json.dumps(dict(epoch='test', entry=entry)))
            result = subprocess.run([shell, '-NoProfile', '-NonInteractive', '-File', str(ROOT / 'review_session.ps1'),
                                     'archive-fixture', '-Path', str(ledger), '-Json'], cwd=temp,
                                    env=dict(os.environ, BAP_STATE_DIR=temp, USERPROFILE=temp), capture_output=True, text=True, timeout=30)
            self.assertEqual(result.returncode, 0, result.stderr)
            report = json.loads(result.stdout.lstrip('\ufeff'))
            self.assertEqual(report['allowed_calls'][0]['command'], 'Glob **/*.go')


if __name__ == '__main__':
    unittest.main()

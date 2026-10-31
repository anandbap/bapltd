"""Version inspection must work before enrollment and leave settings untouched."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]

@unittest.skipUnless(os.name == 'nt', 'Windows launcher')
class LauncherVersionTests(unittest.TestCase):
    def test_claude_version_without_enrollment_or_control_plane(self):
        with tempfile.TemporaryDirectory(prefix='bap-launcher-version-') as directory:
            workspace = Path(directory)
            (workspace / 'claude.cmd').write_text('@echo off\necho fixture-claude-1.0\nexit /b 0\n')
            (workspace / 'claude-code.cmd').write_text('@echo off\necho fixture-claude-1.0\nexit /b 0\n')
            environment = dict(os.environ, PATH=directory + os.pathsep + os.environ['PATH'],
                               BAP_HOME=directory, BAP_CREDENTIALS=str(workspace / 'absent.json'))
            for relative in ('bap/launchers/run_claude_bap.ps1', 'bap/run_claude_bap.ps1'):
                with self.subTest(launcher=relative):
                    result = subprocess.run(['powershell.exe', '-NoProfile', '-NonInteractive',
                                             '-ExecutionPolicy', 'Bypass', '-File', str(ROOT / relative), '--version'],
                                            cwd=workspace, env=environment, capture_output=True, text=True, timeout=15)
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                    self.assertIn('fixture-claude-1.0', result.stdout)
                    self.assertFalse((workspace / '.claude').exists())

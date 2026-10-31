"""Version inspection must work before enrollment and leave settings untouched."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
import importlib.util
from unittest import mock

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
            for relative in ('run_claude_bap.ps1', 'bap/launchers/run_claude_bap.ps1', 'bap/run_claude_bap.ps1'):
                with self.subTest(launcher=relative):
                    result = subprocess.run(['powershell.exe', '-NoProfile', '-NonInteractive',
                                             '-ExecutionPolicy', 'Bypass', '-File', str(ROOT / relative), '--version'],
                                            cwd=workspace, env=environment, capture_output=True, text=True, timeout=15)
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                    self.assertIn('fixture-claude-1.0', result.stdout)
                    self.assertFalse((workspace / '.claude').exists())

    def test_staged_launchers_return_versions_without_starting_sessions(self):
        # CI stages repository-root launchers into the package before testing it.
        spec = importlib.util.spec_from_file_location('wheel_staging_fixture', ROOT / 'scripts/build_wheel.py')
        builder = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(builder)
        with tempfile.TemporaryDirectory(prefix='bap-staged-version-') as directory:
            workspace = Path(directory)
            staging = workspace / 'package'
            staging.mkdir()
            with mock.patch.object(builder, 'BAP_PKG_DIR', str(staging)):
                builder.copy_installer_script()
            for name in ('claude-code.cmd', 'claude.cmd', 'agy.cmd', 'agy.bat'):
                (workspace / name).write_text('@echo off\necho fixture-cli-1.0\nexit /b 0\n')
            environment = dict(os.environ, PATH=directory + os.pathsep + os.environ['PATH'],
                               BAP_HOME=directory, BAP_CREDENTIALS=str(workspace / 'absent.json'))
            for folder in (staging, staging / 'launchers'):
                for launcher in ('run_claude_bap.ps1', 'run_antigravity_cli_bap.bat'):
                    with self.subTest(folder=folder.name, launcher=launcher):
                        command = (['cmd.exe', '/c', str(folder / launcher), '--version'] if launcher.endswith('.bat') else
                                   ['powershell.exe', '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass',
                                    '-File', str(folder / launcher), '--version'])
                        result = subprocess.run(command, cwd=workspace, env=environment,
                                                capture_output=True, text=True, timeout=15)
                        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                        self.assertIn('fixture-cli-1.0', result.stdout)
                        for state in ('.claude', '.bapstate', 'GEMINI.md'):
                            self.assertFalse((workspace / state).exists(), state)

"""Run the updater's real PowerShell build gate without deploying any binaries."""
from pathlib import Path
import shutil
import subprocess
import unittest

ROOT = Path(__file__).resolve().parents[1]


class TestUpdateBinaryBuildGate(unittest.TestCase):
    def test_native_failure_stops_the_updater_before_deployment(self):
        powershell = shutil.which("powershell.exe") or shutil.which("pwsh")
        if not powershell:
            self.skipTest("PowerShell required for updater contract")
        script = r'''
$ErrorActionPreference = 'Stop'
$parseErrors = $null
$tokens = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile('update_binaries.ps1', [ref]$tokens, [ref]$parseErrors)
if ($parseErrors.Count -ne 0) { throw 'Updater has PowerShell parse errors' }
$definition = $ast.Find({param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Invoke-CheckedGoBuild'}, $true)
if ($null -eq $definition) { throw 'Missing checked compiler invocation' }
Invoke-Expression $definition.Extent.Text
function go { $global:LASTEXITCODE = $global:fixtureExitCode }
$global:fixtureExitCode = 0
Invoke-CheckedGoBuild -BuildArguments @('build', '.')
$global:fixtureExitCode = 7
$rejected = $false
try { Invoke-CheckedGoBuild -BuildArguments @('build', '.') } catch { $rejected = $_.Exception.Message -match 'deployment stopped' }
if (-not $rejected) { throw 'Failed compiler result was accepted' }
$raw = Get-Content -LiteralPath 'update_binaries.ps1' -Raw
if ($raw -match '(?m)^s+go build ') { throw 'Unchecked build invocation remains' }
Write-Output 'Checked compiler gate passed; no deployment executed.'
exit 0
'''
        result = subprocess.run([powershell, "-NoProfile", "-NonInteractive", "-Command", script],
                                cwd=ROOT, capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()

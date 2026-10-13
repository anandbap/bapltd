# Verification of Multi-Session Concurrency and Session Isolation across BAP Launchers
$ErrorActionPreference = 'Stop'
$repoRoot = (Get-Item -Path $PSScriptRoot).Parent.FullName

Write-Host "===============================================================================" -ForegroundColor Cyan
Write-Host "     VERIFYING MULTI-SESSION CONCURRENCY & ISOLATION ACROSS BAP LAUNCHERS      " -ForegroundColor Cyan
Write-Host "===============================================================================" -ForegroundColor Cyan

$testDir = Join-Path $env:TEMP "bap_multi_launcher_test_$PID"
if (Test-Path -LiteralPath $testDir) { Remove-Item -LiteralPath $testDir -Recurse -Force }
New-Item -ItemType Directory -Path $testDir -Force | Out-Null

try {
    # 1. Create dummy original developer settings to verify custody preservation
    $vscodeDir = Join-Path $testDir ".vscode"
    New-Item -ItemType Directory -Path $vscodeDir -Force | Out-Null
    Set-Content -Path (Join-Path $vscodeDir "settings.json") -Value '{"developer_original_copilot_setting": true}' -Encoding UTF8

    $geminiFile = Join-Path $testDir "GEMINI.md"
    Set-Content -Path $geminiFile -Value '# My Custom Project Notes' -Encoding UTF8

    Write-Host "[Step 1] Initial developer files created in test directory: $testDir" -ForegroundColor Gray

    # 2. Test concurrent Copilot IDE and Antigravity CLI sessions in the same test directory
    $copilotScript = Join-Path $repoRoot "run_copilot_ide_bap.ps1"
    $antigravityScript = Join-Path $repoRoot "run_antigravity_cli_bap.ps1"

    Write-Host "`n[Step 2] Launching concurrent sessions (Copilot IDE and Antigravity CLI)..." -ForegroundColor Cyan
    $p1 = Start-Process -FilePath "powershell.exe" -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$copilotScript`" --version" -WorkingDirectory $testDir -PassThru
    $p2 = Start-Process -FilePath "powershell.exe" -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$antigravityScript`" --help" -WorkingDirectory $testDir -PassThru

    $p1.WaitForExit()
    $p2.WaitForExit()

    Write-Host "[+] Session 1 (Copilot IDE) exit code: $($p1.ExitCode)"
    Write-Host "[+] Session 2 (Antigravity CLI) exit code: $($p2.ExitCode)"

    if ($p1.ExitCode -ne 0 -or $p2.ExitCode -ne 0) {
        throw "Concurrent launcher test failed: P1=$($p1.ExitCode), P2=$($p2.ExitCode)"
    }

    # 3. Verify original developer files were perfectly restored
    Write-Host "`n[Step 3] Verifying original developer files are preserved and restored..." -ForegroundColor Cyan
    $restoredVsCode = Get-Content -Path (Join-Path $vscodeDir "settings.json") -Raw
    if ($restoredVsCode -notmatch 'developer_original_copilot_setting') {
        throw "Copilot original settings were NOT restored!"
    }
    Write-Host "[OK] .vscode/settings.json restored accurately." -ForegroundColor Green

    $restoredGemini = Get-Content -Path $geminiFile -Raw
    if ($restoredGemini -notmatch 'My Custom Project Notes') {
        throw "Antigravity GEMINI.md was NOT restored!"
    }
    Write-Host "[OK] GEMINI.md restored accurately." -ForegroundColor Green

    Write-Host "`n===============================================================================" -ForegroundColor Green
    Write-Host "   [OK] ALL CONCURRENT MULTI-SESSION LAUNCHER TESTS PASSED SUCCESSFULLY!       " -ForegroundColor Green
    Write-Host "===============================================================================" -ForegroundColor Green
}
finally {
    if (Test-Path -LiteralPath $testDir) {
        Remove-Item -LiteralPath $testDir -Recurse -Force -ErrorAction SilentlyContinue
    }
}

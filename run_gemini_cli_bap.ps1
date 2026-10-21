# BAP Google Gemini CLI Zero-Trust Launcher
# ==========================================
# Transactional launcher for Google Gemini CLI under BAP Zero-Trust Governance (BAP-539).
# Injects GEMINI.md, enforces Cedar policy, and emits standardized activity telemetry.

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$enginePath = Join-Path $PSScriptRoot "bap_launcher_engine.ps1"
if (-not (Test-Path -LiteralPath $enginePath)) {
    $enginePath = Join-Path $PSScriptRoot "scripts\bap_launcher_engine.ps1"
}
if (-not (Test-Path -LiteralPath $enginePath)) {
    $enginePath = Join-Path (Join-Path $PSScriptRoot "..") "scripts\bap_launcher_engine.ps1"
}
if (-not (Test-Path -LiteralPath $enginePath)) {
    $enginePath = "bap_launcher_engine.ps1"
}
. $enginePath

$configureFiles = {
    param($Workspace, $SessionId)
    $geminiRule = @"
# BAP Zero-Trust Policy & Shell Governance for Gemini CLI (Governed Session: $SessionId)
This workspace is actively governed by the BAP Zero-Trust Local Trusted Daemon (bapedge.exe).

## Mandatory Execution Rules
1. All shell executions MUST run through bapedge.exe exec:
   bapedge.exe exec "<command>"
2. Commands are evaluated against Cedar invariants before execution.
"@
    Set-Content -LiteralPath (Join-Path $Workspace "GEMINI.md") -Value $geminiRule -Encoding UTF8

    return @(
        (Join-Path $Workspace "GEMINI.md")
    )
}

$findExecutable = {
    $geminiCmd = Get-Command "gemini" -ErrorAction SilentlyContinue
    if ($geminiCmd) {
        return @{ Path = $geminiCmd.Source; Args = @() }
    }
    return @{ Path = "cmd.exe"; Args = @("/c", "echo [BAP-GEMINI] Mock Gemini CLI session initialized under zero trust.") }
}

Invoke-BAPTransaction -AppId "gemini-cli" `
    -AppName "Google Gemini CLI" `
    -FindExecutable $findExecutable `
    -ConfigureFiles $configureFiles `
    -CliArgs $args

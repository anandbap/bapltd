# BAP Cursor IDE Zero-Trust Launcher
# ==================================
# Transactional launcher for Cursor IDE under BAP Zero-Trust Governance (BAP-539).
# Configures .cursorrules, mounts bapmcp, and emits canonical activity telemetry.

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
    $repoRoot = (Get-Item -Path $PSScriptRoot).FullName
    $mcpCandidates = @(
        (Join-Path $PSScriptRoot "bapmcp.exe"),
        (Join-Path $repoRoot "bapmcp.exe"),
        (Join-Path $repoRoot "dist\windows-amd64\bapmcp.exe")
    )
    $mcpBin = Resolve-BinaryPath -Paths $mcpCandidates -Commands @('bapmcp.exe', 'bapmcp')
    if (-not (Test-Path -LiteralPath $mcpBin)) {
        $mcpBin = Join-Path $repoRoot "dist\windows-amd64\bapmcp.exe"
    }

    $cursorDir = Join-Path $Workspace ".cursor"
    if (-not (Test-Path -LiteralPath $cursorDir)) {
        New-Item -ItemType Directory -Path $cursorDir -Force | Out-Null
    }

    $cursorMcp = [ordered]@{
        mcpServers = [ordered]@{
            "bap-zero-trust" = [ordered]@{
                command = $mcpBin
                args    = @("serve")
                env     = [ordered]@{
                    "LTD_SOURCE"     = "cursor"
                    "BAP_SESSION_ID" = $SessionId
                }
            }
        }
    }
    $cursorMcpJson = ConvertTo-Json $cursorMcp -Depth 6
    Set-Content -LiteralPath (Join-Path $cursorDir "mcp.json") -Value $cursorMcpJson -Encoding UTF8

    $cursorRules = @"
# BAP Zero-Trust Policy & Shell Governance for Cursor IDE (Governed Session: $SessionId)
This workspace is actively governed by the BAP Zero-Trust Local Trusted Daemon (bapedge.exe).

## Mandatory Execution Rules
1. All shell executions MUST run strictly through bapedge.exe exec:
   bapedge.exe exec "<command>"
2. Commands are evaluated against Cedar invariants before execution.
"@
    Set-Content -LiteralPath (Join-Path $Workspace ".cursorrules") -Value $cursorRules -Encoding UTF8

    return @(
        (Join-Path $Workspace ".cursorrules"),
        (Join-Path $cursorDir "mcp.json")
    )
}

$findExecutable = {
    $cursorCmd = Get-Command "cursor" -ErrorAction SilentlyContinue
    if ($cursorCmd) {
        return @{ Path = $cursorCmd.Source; Args = @() }
    }
    $cursorExe = "$env:LOCALAPPDATA\Programs\cursor\Cursor.exe"
    if (Test-Path -LiteralPath $cursorExe) {
        return @{ Path = $cursorExe; Args = @() }
    }
    return @{ Path = "cmd.exe"; Args = @("/c", "echo [BAP-CURSOR] Mock Cursor session initialized under zero trust.") }
}

$emitActivity = {
    param($Workspace, $SessionId)
    $bapedge = Join-Path $PSScriptRoot "bapedge.exe"
    if (Test-Path -LiteralPath $bapedge) {
        & $bapedge adapter emit --harness cursor --action session_start --target $Workspace --decision ALLOW --reason "Cursor session launched under BAP governance"
    }
}

Invoke-BAPTransaction -AppId "cursor" `
    -AppName "Cursor IDE" `
    -FindExecutable $findExecutable `
    -ConfigureFiles $configureFiles `
    -CliArgs $args

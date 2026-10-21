# BAP Claude Code CLI Zero-Trust Launcher
# =======================================
# Transactional, zero-trust launcher for Claude Code CLI.
# Pre-initializes interceptor hooks, enrolls session, guards settings, passes arguments, restores on exit.

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
    $interceptorCandidates = @(
        (Join-Path $repoRoot 'cchook\interceptor.exe'),
        (Join-Path $repoRoot 'dist\windows-amd64\cchook-interceptor.exe'),
        (Join-Path $repoRoot 'dist\windows-amd64\claude-client\cchook\interceptor.exe')
    )
    $interceptorBin = Resolve-BinaryPath -Paths $interceptorCandidates -Commands @('interceptor.exe')
    if ([string]::IsNullOrWhiteSpace($interceptorBin)) {
        throw "Claude interceptor hook binary not found."
    }

    $claudeSettings = [ordered]@{
        disableAllHooks = $false
        hooks = [ordered]@{
            SessionStart     = @( [ordered]@{ hooks = @( [ordered]@{ type = 'command'; command = 'interceptor.exe'; args = @() } ) } )
            UserPromptSubmit = @( [ordered]@{ hooks = @( [ordered]@{ type = 'command'; command = 'interceptor.exe'; args = @() } ) } )
            PreToolUse       = @( [ordered]@{ matcher = '*'; hooks = @( [ordered]@{ type = 'command'; command = 'interceptor.exe'; args = @() } ) } )
        }
    }

    return @(
        @{
            Path    = Join-Path $Workspace ".claude\settings.json"
            Content = ($claudeSettings | ConvertTo-Json -Depth 10)
        }
    )
}

Invoke-BapGovernedSession `
    -AgentId "claude-code" `
    -AgentMode "cli" `
    -DisplayName "Claude Code CLI" `
    -CandidateExecutables @("claude.exe", "claude.cmd", "claude") `
    -ConfigureFiles $configureFiles `
    -ScriptRawArgs $args `
    -CallingScript $PSCommandPath

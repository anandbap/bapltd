# BAP GitHub Copilot CLI Zero-Trust Launcher
# ==========================================
# Transactional launcher for GitHub Copilot CLI.
# Enrolls session with BAP Edge/Control Plane, wraps terminal execution through interceptor, restores on exit.

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$enginePath = Join-Path $PSScriptRoot "scripts\bap_launcher_engine.ps1"
if (-not (Test-Path -LiteralPath $enginePath)) {
    $enginePath = Join-Path (Join-Path $PSScriptRoot "..") "scripts\bap_launcher_engine.ps1"
}
. $enginePath

$configureFiles = {
    param($Workspace, $SessionId)
    $repoRoot = (Get-Item -Path $PSScriptRoot).FullName
    $copilotInterceptor = Join-Path $repoRoot 'copilot\copilot_interceptor.exe'
    if (-not (Test-Path -LiteralPath $copilotInterceptor)) {
        $copilotInterceptor = Join-Path $repoRoot 'dist\windows-amd64\copilot-interceptor.exe'
    }

    $copilotConfig = [ordered]@{
        session_id  = $SessionId
        interceptor = $copilotInterceptor
        governed    = $true
        created_at  = [DateTime]::UtcNow.ToString('o')
    }

    return @(
        @{
            Path    = Join-Path $Workspace ".copilot\bap-session.json"
            Content = ($copilotConfig | ConvertTo-Json -Depth 10)
        }
    )
}

# Resolve candidate CLI: gh.exe (with 'copilot' subcommand), or copilot.cmd
Invoke-BapGovernedSession `
    -AgentId "copilot" `
    -AgentMode "cli" `
    -DisplayName "GitHub Copilot CLI" `
    -CandidateExecutables @("gh.exe", "copilot.cmd", "copilot.exe") `
    -ConfigureFiles $configureFiles `
    -ScriptRawArgs $args `
    -CallingScript $PSCommandPath

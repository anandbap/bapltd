# BAP Claude Code IDE Zero-Trust Launcher
# =======================================
# Transactional launcher for Claude Code in IDE Mode (VS Code).
# Injects Claude MCP & hooks into workspace, launches IDE, guards settings, restores on exit.

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
    $mcpCandidates = @(
        (Join-Path $repoRoot 'bapmcp.exe'),
        (Join-Path $repoRoot 'dist\windows-amd64\bapmcp.exe')
    )
    $mcpBin = Resolve-BinaryPath -Paths $mcpCandidates -Commands @('bapmcp.exe')
    if ([string]::IsNullOrWhiteSpace($mcpBin)) {
        throw "BAP MCP binary (bapmcp.exe) not found."
    }

    $claudeMcp = [ordered]@{
        mcpServers = [ordered]@{
            "bap-zero-trust" = [ordered]@{
                command = $mcpBin
                args    = @()
                env     = [ordered]@{
                    "LTD_SOURCE"     = "claude-code"
                    "BAP_SESSION_ID" = $SessionId
                }
            }
        }
    }

    $vscodeSettings = [ordered]@{
        "claude.mcpEnabled" = $true
    }

    return @(
        @{
            Path    = Join-Path $Workspace ".claude\mcp.json"
            Content = ($claudeMcp | ConvertTo-Json -Depth 10)
        },
        @{
            Path    = Join-Path $Workspace ".vscode\settings.json"
            Content = ($vscodeSettings | ConvertTo-Json -Depth 10)
        }
    )
}

Invoke-BapGovernedSession `
    -AgentId "claude-code" `
    -AgentMode "ide" `
    -DisplayName "Claude Code (IDE Mode)" `
    -CandidateExecutables @("code.cmd", "code.exe", "code") `
    -ConfigureFiles $configureFiles `
    -ScriptRawArgs $args `
    -CallingScript $PSCommandPath

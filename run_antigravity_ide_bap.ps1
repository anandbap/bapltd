# BAP Google Antigravity IDE Zero-Trust Launcher
# ==============================================
# Transactional launcher for Google Antigravity IDE.
# Injects GEMINI.md policy, workspace rules, and MCP configurations, enrolls session, guards files, restores on exit.

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
    $mcpBin = Join-Path $repoRoot "bapmcp.exe"

    $geminiRule = @"
# BAP Zero-Trust Policy & Shell Governance for Antigravity (Governed Session: $SessionId)

This workspace is actively governed by the BAP Zero-Trust Local Trusted Daemon (bapedge.exe).

## Mandatory Execution Rules
1. **Always Use BAP Edge Execution Broker**:
   - All shell executions MUST run through bapedge.exe exec:
     `bapedge.exe exec "<command>"`
   - Never run raw, ungoverned shell commands on the host machine.
2. **Zero-Trust Policy Enforcement**:
   - Commands are evaluated against Cedar invariants before execution.
   - If a command is denied, inspect the suggestion in the structured response.
3. **Identity & Audit Logging**:
   - LTD_SOURCE=antigravity
   - BAP_SESSION_ID=$SessionId
"@

    $mcpConfig = [ordered]@{
        mcpServers = [ordered]@{
            "bap-zero-trust" = [ordered]@{
                command = $mcpBin
                args    = @()
                env     = [ordered]@{
                    "LTD_SOURCE"     = "antigravity"
                    "BAP_SESSION_ID" = $SessionId
                }
            }
        }
    }

    return @(
        @{
            Path    = Join-Path $Workspace "GEMINI.md"
            Content = $geminiRule
        },
        @{
            Path    = Join-Path $Workspace ".antigravity\mcp_config.json"
            Content = ($mcpConfig | ConvertTo-Json -Depth 10)
        },
        @{
            Path    = Join-Path $Workspace ".gemini\config\mcp_config.json"
            Content = ($mcpConfig | ConvertTo-Json -Depth 10)
        }
    )
}

$candidateExecutables = @(
    (Join-Path $env:LOCALAPPDATA "Programs\antigravity\Antigravity.exe"),
    "Antigravity.exe",
    "code.cmd",
    "code.exe"
)

Invoke-BapGovernedSession `
    -AgentId "antigravity" `
    -AgentMode "ide" `
    -DisplayName "Google Antigravity IDE" `
    -CandidateExecutables $candidateExecutables `
    -ConfigureFiles $configureFiles `
    -ScriptRawArgs $args `
    -CallingScript $PSCommandPath

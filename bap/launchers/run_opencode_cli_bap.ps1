# BAP OpenCode CLI Zero-Trust Launcher (BAP-807)
# ====================================================
# Transactional launcher for OpenCode CLI.
# Injects AGENTS.md policy and plugin/MCP configuration, enrolls session, guards files, passes arguments, restores on exit.

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
        (Join-Path $env:ProgramFiles "BAP\bin\bapmcp.exe"),
        (Join-Path $env:ProgramFiles "BAP\bapmcp.exe"),
        (Join-Path $env:USERPROFILE ".bap\bin\bapmcp.exe"),
        (Join-Path $env:USERPROFILE ".bap\bapmcp.exe"),
        (Join-Path $PSScriptRoot "bapmcp.exe"),
        (Join-Path $repoRoot "bapmcp.exe"),
        (Join-Path $repoRoot "dist\windows-amd64\bapmcp.exe")
    )
    $mcpBin = Resolve-BinaryPath -Paths $mcpCandidates -Commands @('bapmcp.exe', 'bapmcp')

    $agentRule = @"
# BAP Zero-Trust Policy & Enterprise Governance for OpenCode (Governed Session: `$SessionId)

This workspace is actively governed by the BAP Zero-Trust Local Trusted Daemon (bapedge.exe).

## Enterprise Governance & Boundaries
1. **Multi-Project Workspace & Dependency Traversal**:
   - Reading, inspecting, and navigating cross-project dependencies, sibling repositories, shared schemas, and local dependency caches is PERMITTED for build and code intelligence.
   - Modifying, deleting, or redirecting output to files outside the authorized workspace is strictly prohibited without explicit human authorization.
2. **Absolute Secret Protection**:
   - Access to credential files (.env, ~/.aws, ~/.ssh, private keys) is strictly forbidden across all directories.
3. **Execution Broker & Sandboxing**:
   - All shell executions MUST run through the BAP Edge Execution Broker: `bapedge.exe exec "<command>"`.
4. **Developer Override & Agent Immunity**:
   - Autonomous agents are STRICTLY FORBIDDEN from activating `bapedge dev-override on`. That command requires interactive human authorization.
5. **Identity & Audit Logging**:
   - LTD_SOURCE=opencode
   - BAP_SESSION_ID=`$SessionId
"@

    $opencodeConfig = [ordered]@{
        mcp = [ordered]@{
            "bap-zero-trust" = [ordered]@{
                command = $mcpBin
                args    = @()
                env     = [ordered]@{
                    "LTD_SOURCE"     = "opencode"
                    "BAP_SESSION_ID" = $SessionId
                }
            }
        }
    }

    return @(
        @{
            Path    = Join-Path $Workspace "AGENTS.md"
            Content = $agentRule
        },
        @{
            Path    = Join-Path $Workspace ".opencode\opencode.json"
            Content = ($opencodeConfig | ConvertTo-Json -Depth 10)
        }
    )
}

$candidateExecutables = @(
    "opencode.cmd",
    "opencode.bat",
    "opencode.exe",
    (Join-Path $env:LOCALAPPDATA "opencode\bin\opencode.exe"),
    "opencode"
)

Invoke-BapGovernedSession `
    -AgentId "opencode" `
    -AgentMode "cli" `
    -DisplayName "OpenCode CLI" `
    -CandidateExecutables $candidateExecutables `
    -ConfigureFiles $configureFiles `
    -ScriptRawArgs $args `
    -CallingScript $PSCommandPath

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
# BAP Zero-Trust Policy & Enterprise Governance for Antigravity (Governed Session: `$SessionId)

This workspace is actively governed by the BAP Zero-Trust Local Trusted Daemon (bapedge.exe).

## Enterprise Governance & Boundaries
1. **Multi-Project Workspace & Dependency Traversal**:
   - Reading, inspecting, and navigating cross-project dependencies, sibling repositories, shared schemas, and local dependency caches (e.g. `..\sibling-project`, `~/.m2`, `~/.gradle`) is **PERMITTED** for build and code intelligence.
   - Modifying, deleting, or redirecting output to files outside the authorized workspace is strictly prohibited without explicit human authorization.
2. **Absolute Secret Protection**:
   - Access to credential files (`.env`, `~/.aws`, `~/.ssh`, private keys) is strictly forbidden across all directories, whether inside or outside the workspace.
3. **Software Supply Chain & Package Management**:
   - Package managers (Maven, Gradle, npm, pip) must use approved corporate mirrors (e.g. local Nexus / Artifactory). Bypassing internal repos to download directly from public internet registries is prohibited.
   - Installation of unapproved standalone software, third-party `.msi` installers, or setup binaries is strictly blocked.
4. **Network Egress & Execution Broker**:
   - All shell executions MUST run through the BAP Edge Execution Broker: `bapedge.exe exec "<command>"`.
   - Raw network exfiltration utilities (`curl`, `wget`, `nc`, raw sockets) are strictly prohibited; external API access must route through the BAP Gateway PEP.
5. **Zero-Trust Policy Enforcement**:
   - Commands are evaluated against Cedar invariants before execution.
   - If a command is denied, inspect the suggestion in the structured response.
6. **Identity & Audit Logging**:
   - LTD_SOURCE=antigravity
   - BAP_SESSION_ID=`$SessionId
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

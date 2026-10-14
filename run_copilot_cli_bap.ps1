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

    $mcpBin = Join-Path $repoRoot "bapmcp.exe"
    if (-not (Test-Path -LiteralPath $mcpBin)) {
        $mcpBin = Join-Path $repoRoot "dist\windows-amd64\bapmcp.exe"
    }

    $copilotConfig = [ordered]@{
        session_id  = $SessionId
        interceptor = $copilotInterceptor
        governed    = $true
        created_at  = [DateTime]::UtcNow.ToString('o')
    }

    $copilotMcp = [ordered]@{
        mcpServers = [ordered]@{
            "bap-zero-trust" = [ordered]@{
                command = $mcpBin
                args    = @()
                env     = [ordered]@{
                    "LTD_SOURCE"     = "copilot"
                    "BAP_SESSION_ID" = $SessionId
                }
            }
        }
    }

    $agentsRule = @"
# BAP Zero-Trust Policy & Enterprise Governance for GitHub Copilot (Governed Session: `$SessionId)

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
   - LTD_SOURCE=copilot
   - BAP_SESSION_ID=`$SessionId
"@

    return @(
        @{
            Path    = Join-Path $Workspace ".copilot\bap-session.json"
            Content = ($copilotConfig | ConvertTo-Json -Depth 10)
        },
        @{
            Path    = Join-Path $Workspace ".copilot\mcp-config.json"
            Content = ($copilotMcp | ConvertTo-Json -Depth 10)
        },
        @{
            Path    = Join-Path $Workspace "AGENTS.md"
            Content = $agentsRule
        }
    )
}

$candidateExecutables = @(
    "copilot.exe",
    "copilot.cmd",
    "copilot",
    (Join-Path $env:LOCALAPPDATA "Microsoft\WinGet\Packages\GitHub.Copilot_Microsoft.Winget.Source_8wekyb3d8bbwe\copilot.exe"),
    (Join-Path $env:LOCALAPPDATA "Programs\copilot\copilot.exe"),
    "gh.exe",
    "gh"
)

Invoke-BapGovernedSession `
    -AgentId "copilot" `
    -AgentMode "cli" `
    -DisplayName "GitHub Copilot CLI" `
    -CandidateExecutables $candidateExecutables `
    -ConfigureFiles $configureFiles `
    -ScriptRawArgs $args `
    -CallingScript $PSCommandPath

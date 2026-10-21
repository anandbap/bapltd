# BAP GitHub Copilot IDE (VS Code) Zero-Trust Launcher
# ====================================================
# Transactional launcher for GitHub Copilot in VS Code (Agent Mode & Chat).
# Configures Copilot sandbox terminal profile, mounts BAP MCP server, starts session, launches VS Code, restores on exit.

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
    $wrapBat = Join-Path $repoRoot "copilot\copilot-wrap.bat"
    $mcpBin = Join-Path $repoRoot "bapmcp.exe"

    $vscodeSettings = [ordered]@{
        "terminal.integrated.profiles.windows" = [ordered]@{
            "CopilotSandbox" = [ordered]@{
                "path"         = $wrapBat
                "overrideName" = $true
            }
        }
        "terminal.integrated.defaultProfile.windows" = "CopilotSandbox"
        "github.copilot.chat.mcpServers" = [ordered]@{
            "bap-edge" = [ordered]@{
                "command" = $mcpBin
                "args"    = @()
                "env"     = [ordered]@{
                    "LTD_SOURCE"     = "copilot"
                    "BAP_SESSION_ID" = $SessionId
                }
            }
        }
    }

    $vscodeMcp = [ordered]@{
        "servers" = [ordered]@{
            "bap-zero-trust" = [ordered]@{
                "command" = $mcpBin
                "args"    = @()
                "env"     = [ordered]@{
                    "LTD_SOURCE"     = "copilot"
                    "BAP_SESSION_ID" = $SessionId
                }
            }
        }
    }

    return @(
        @{
            Path    = Join-Path $Workspace ".vscode\settings.json"
            Content = ($vscodeSettings | ConvertTo-Json -Depth 10)
        },
        @{
            Path    = Join-Path $Workspace ".vscode\mcp.json"
            Content = ($vscodeMcp | ConvertTo-Json -Depth 10)
        }
    )
}

Invoke-BapGovernedSession `
    -AgentId "copilot" `
    -AgentMode "ide" `
    -DisplayName "GitHub Copilot (VS Code IDE Mode)" `
    -CandidateExecutables @("code.cmd", "code.exe", "code") `
    -ConfigureFiles $configureFiles `
    -ScriptRawArgs $args `
    -CallingScript $PSCommandPath

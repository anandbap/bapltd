# BAP Zero-Trust Universal Global Installer (Non-Admin / User-Home Default)
# =========================================================================
# Deploys BAP Zero-Trust binaries and global hooks for all agents (Antigravity & Claude).
# Defaults to %USERPROFILE%\.bap\bin unless %ProgramFiles%\BAP is writable.

$ErrorActionPreference = "Stop"

$repoRoot = (Get-Item -Path $PSScriptRoot).Parent.FullName
if (-not (Test-Path (Join-Path $repoRoot "bapedge.exe"))) {
    $repoRoot = $PSScriptRoot
}

Write-Host ">>> Inspecting target installation directory..." -ForegroundColor Cyan

# 1. Determine Target Directory (ProgramFiles vs User Home)
$progFilesDir = Join-Path $env:ProgramFiles "BAP"
$useUserScope = $true
$installDir = Join-Path $env:USERPROFILE ".bap"

try {
    if (-not (Test-Path $progFilesDir)) {
        New-Item -ItemType Directory -Path $progFilesDir -Force -ErrorAction Stop | Out-Null
    }
    $testFile = Join-Path $progFilesDir ".perm_test"
    Set-Content -Path $testFile -Value "ok" -ErrorAction Stop
    Remove-Item -Path $testFile -Force -ErrorAction Stop
    $installDir = $progFilesDir
    $useUserScope = $false
    Write-Host "[+] Write access granted to $progFilesDir. Using System scope." -ForegroundColor Green
} catch {
    Write-Host "[*] No administrative access to $progFilesDir. Defaulting to user home: $installDir" -ForegroundColor Yellow
}

$binDir = Join-Path $installDir "bin"
if (-not (Test-Path $binDir)) {
    New-Item -ItemType Directory -Path $binDir -Force | Out-Null
}

# 2. Deploy Binaries
Write-Host ">>> Deploying BAP Zero-Trust binaries to $binDir..." -ForegroundColor Cyan
$bins = @(
    "bapedge.exe",
    "bapmcp.exe",
    "bapcontrolplane.exe",
    "bapgateway.exe"
)

foreach ($b in $bins) {
    $src = Join-Path $repoRoot $b
    if (Test-Path $src) {
        Copy-Item -Path $src -Destination (Join-Path $binDir $b) -Force
        Write-Host "  [+] Copied $b" -ForegroundColor Gray
    }
}

# Interceptor
$interceptorSrc = Join-Path $repoRoot "cchook\interceptor.exe"
if (-not (Test-Path $interceptorSrc)) {
    $interceptorSrc = Join-Path $repoRoot "interceptor.exe"
}
if (Test-Path $interceptorSrc) {
    Copy-Item -Path $interceptorSrc -Destination (Join-Path $binDir "interceptor.exe") -Force
    Write-Host "  [+] Copied interceptor.exe" -ForegroundColor Gray
}

# Config & Policy assets
$assets = @("policy.cedar", "schema.json", "bap-config.json")
foreach ($a in $assets) {
    $src = Join-Path $repoRoot $a
    if (Test-Path $src) {
        Copy-Item -Path $src -Destination (Join-Path $installDir $a) -Force
        Write-Host "  [+] Copied $a" -ForegroundColor Gray
    }
}

# 3. Register PATH Environment Variable
Write-Host ">>> Registering $binDir in PATH..." -ForegroundColor Cyan
$targetScope = if ($useUserScope) { [System.EnvironmentVariableTarget]::User } else { [System.EnvironmentVariableTarget]::Machine }
$currentPath = [System.Environment]::GetEnvironmentVariable("Path", $targetScope)
if ($currentPath -notlike "*$binDir*") {
    $newPath = if ([string]::IsNullOrWhiteSpace($currentPath)) { $binDir } else { "$binDir;$currentPath" }
    [System.Environment]::SetEnvironmentVariable("Path", $newPath, $targetScope)
    Write-Host "[+] Appended $binDir to $(if ($useUserScope) { 'User' } else { 'System' }) PATH environment." -ForegroundColor Green
} else {
    Write-Host "[=] $binDir already present in PATH." -ForegroundColor Gray
}
# Also update current session PATH
$env:PATH = "$binDir;$env:PATH"

# 4. Global Claude Code Hook Configuration
Write-Host ">>> Configuring Claude Code global governance..." -ForegroundColor Cyan
$claudeHome = Join-Path $env:USERPROFILE ".claude"
$claudeHooksDir = Join-Path $claudeHome "hooks"
if (-not (Test-Path $claudeHooksDir)) {
    New-Item -ItemType Directory -Path $claudeHooksDir -Force | Out-Null
}
$interceptorBin = Join-Path $binDir "interceptor.exe"
Copy-Item -Path $interceptorBin -Destination (Join-Path $claudeHooksDir "interceptor.exe") -Force

$claudeSettingsPath = Join-Path $claudeHome "settings.json"
$claudeSettings = [ordered]@{
    hooks = [ordered]@{
        SessionStart     = @(@{ hooks = @(@{ type = "command"; command = (Join-Path $claudeHooksDir "interceptor.exe") }) })
        UserPromptSubmit = @(@{ hooks = @(@{ type = "command"; command = (Join-Path $claudeHooksDir "interceptor.exe") }) })
        PreToolUse       = @(@{ matcher = "*"; hooks = @(@{ type = "command"; command = (Join-Path $claudeHooksDir "interceptor.exe") }) })
        SessionEnd       = @(@{ hooks = @(@{ type = "command"; command = (Join-Path $claudeHooksDir "interceptor.exe") }) })
    }
}
$claudeSettings | ConvertTo-Json -Depth 5 | Set-Content -Path $claudeSettingsPath -Encoding UTF8
Write-Host "[+] Claude Code global hooks active in $claudeSettingsPath" -ForegroundColor Green

# 5. Global Google Antigravity Plugin & MCP Configuration
Write-Host ">>> Configuring Google Antigravity global governance..." -ForegroundColor Cyan
$geminiConfigDir = Join-Path $env:USERPROFILE ".gemini\config"
$pluginsDir = Join-Path $geminiConfigDir "plugins"
$bapPluginDir = Join-Path $pluginsDir "bap-zero-trust"
$rulesDir = Join-Path $bapPluginDir "rules"

if (-not (Test-Path $rulesDir)) {
    New-Item -ItemType Directory -Path $rulesDir -Force | Out-Null
}

# plugin.json
$pluginManifest = [ordered]@{
    name        = "bap-zero-trust"
    description = "BAP Zero-Trust Local Trusted Daemon (LTD) Security & Execution Governance"
    version     = "1.0.0"
}
$pluginManifest | ConvertTo-Json | Set-Content -Path (Join-Path $bapPluginDir "plugin.json") -Encoding UTF8

# mcp_config.json
$mcpConfig = [ordered]@{
    mcpServers = [ordered]@{
        "bap-zero-trust" = [ordered]@{
            command = (Join-Path $binDir "bapmcp.exe")
            args    = @()
            env     = [ordered]@{
                "LTD_SOURCE" = "antigravity"
            }
        }
    }
}
$mcpConfig | ConvertTo-Json -Depth 5 | Set-Content -Path (Join-Path $bapPluginDir "mcp_config.json") -Encoding UTF8

# Also update global ~/.gemini/config/mcp_config.json
$mcpConfig | ConvertTo-Json -Depth 5 | Set-Content -Path (Join-Path $geminiConfigDir "mcp_config.json") -Encoding UTF8

# hooks.json
$bapHooks = [ordered]@{
    "bap-governance" = [ordered]@{
        enabled      = $true
        SessionStart = @(
            [ordered]@{
                type    = "command"
                command = "$interceptorBin --event SessionStart"
            }
        )
        PreInvocation = @(
            [ordered]@{
                type    = "command"
                command = "$interceptorBin --event PreInvocation"
            }
        )
        PreToolUse   = @(
            [ordered]@{
                matcher = "*"
                hooks   = @(
                    [ordered]@{
                        type    = "command"
                        command = "$interceptorBin --event PreToolUse"
                    }
                )
            }
        )
        Stop         = @(
            [ordered]@{
                type    = "command"
                command = "$interceptorBin --event Stop"
            }
        )
    }
}
$bapHooks | ConvertTo-Json -Depth 10 | Set-Content -Path (Join-Path $bapPluginDir "hooks.json") -Encoding UTF8

# rules/AGENTS.md
$agentsMdContent = @"
# BAP Zero-Trust Policy & Enterprise Governance

This environment is actively governed by the BAP Zero-Trust Local Trusted Daemon (bapedge.exe).

## Enterprise Governance Invariants
1. **Absolute Secret Protection**:
   - Access to credential files (.env, ~/.aws, ~/.ssh, private keys) is strictly forbidden across all directories.
2. **Execution Broker**:
   - All shell executions MUST run through the BAP Edge Execution Broker: ``bapedge.exe exec "<command>"``.
   - Raw network exfiltration utilities (curl, wget, nc, raw sockets) are strictly prohibited; external API access must route through the BAP Gateway PEP.
3. **Workspace Boundary**:
   - Modifying, deleting, or redirecting output to files outside the authorized workspace is prohibited without explicit authorization.
"@
$agentsMdContent | Set-Content -Path (Join-Path $rulesDir "AGENTS.md") -Encoding UTF8

Write-Host "[+] Antigravity global plugin active in $bapPluginDir" -ForegroundColor Green
Write-Host ">>> BAP Zero-Trust Universal Global Deployment Complete!" -ForegroundColor Green

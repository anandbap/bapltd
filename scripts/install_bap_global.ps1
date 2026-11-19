# BAP Zero-Trust Universal Global Installer (Non-Admin / User-Home Default)
# =========================================================================
# Deploys BAP Zero-Trust binaries and global hooks for all agents (Antigravity & Claude).
# Defaults to %USERPROFILE%\.bap\bin unless %ProgramFiles%\BAP is writable.

param(
    [switch]$Debug = $false,
    # Deploy a developer-override or test-harness build globally. Never use this on a machine that runs
    # real agents: those builds can be told to skip approvals (BAP-1096).
    [switch]$AllowDevBuild = $false
)

$ErrorActionPreference = "Stop"

$repoRoot = (Get-Item -Path $PSScriptRoot).Parent.FullName
if (-not (Test-Path (Join-Path $repoRoot "bapedge.exe"))) {
    $repoRoot = $PSScriptRoot
}

# BAP-1103 helpers -------------------------------------------------------------------------------
function Get-BapBinaryInfo {
    param([Parameter(Mandatory = $true)][string]$Path)
    try {
        $raw = & $Path version --json 2>$null
        if ($LASTEXITCODE -ne 0 -or -not $raw) { return $null }
        return (($raw -join "`n") | ConvertFrom-Json)
    } catch { return $null }
}

function Get-FileSha256Safe {
    param([Parameter(Mandatory = $true)][string]$Path)
    try { return (Get-FileHash -LiteralPath $Path -Algorithm SHA256 -ErrorAction Stop).Hash } catch { return $null }
}

# The binary being installed must be the freshly built, release-style one. Refuse a developer-override
# or test-harness build unless the operator explicitly accepts it.
$sourceEdge = Join-Path $repoRoot "bapedge.exe"
if (Test-Path -LiteralPath $sourceEdge) {
    $sourceInfo = Get-BapBinaryInfo -Path $sourceEdge
    if ($null -ne $sourceInfo) {
        Write-Host "[*] Installing bapedge $($sourceInfo.version) (commit $($sourceInfo.git_commit), built $($sourceInfo.build_date))" -ForegroundColor Cyan
        if (($sourceInfo.allow_dev_overrides -eq $true -or $sourceInfo.headless_stepup -eq $true) -and -not $AllowDevBuild) {
            Write-Error ("Refusing to install $sourceEdge globally: it is a developer-override or test-harness build " +
                "(allow_dev_overrides=$($sourceInfo.allow_dev_overrides), headless_stepup=$($sourceInfo.headless_stepup)). " +
                "Rebuild with: .\update_binaries.ps1 -AllowDevOverrides `"false`"   (or pass -AllowDevBuild to override).")
            exit 3
        }
    } else {
        Write-Warning "Could not read version information from $sourceEdge; continuing."
    }
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

function Deploy-BinarySafe {
    param(
        [Parameter(Mandatory=$true)][string]$SourcePath,
        [Parameter(Mandatory=$true)][string]$DestinationPath,
        [string]$DisplayName
    )
    if (-not (Test-Path -LiteralPath $SourcePath)) {
        return
    }
    if ([string]::IsNullOrWhiteSpace($DisplayName)) {
        $DisplayName = Split-Path $DestinationPath -Leaf
    }
    try {
        Copy-Item -LiteralPath $SourcePath -Destination $DestinationPath -Force -ErrorAction Stop
        Write-Host "  [+] Copied $DisplayName" -ForegroundColor Gray
    } catch {
        # On Windows, locked/in-use binaries can still be renamed to .old then replaced
        $oldFile = "$DestinationPath.old.$PID.$([DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds())"
        try {
            Move-Item -LiteralPath $DestinationPath -Destination $oldFile -Force -ErrorAction Stop
            Copy-Item -LiteralPath $SourcePath -Destination $DestinationPath -Force -ErrorAction Stop
            Write-Host "  [+] Copied $DisplayName (rotated active binary to $(Split-Path $oldFile -Leaf))" -ForegroundColor Gray
        } catch {
            Write-Warning "Failed to update $DisplayName : $_"
        }
    }
}

$bins = @(
    "bap.exe",
    "bapedge.exe",
    "bapmcp.exe",
    "bapcontrolplane.exe",
    "bapgateway.exe"
)

foreach ($b in $bins) {
    $src = Join-Path $repoRoot $b
    Deploy-BinarySafe -SourcePath $src -DestinationPath (Join-Path $binDir $b) -DisplayName $b
}

# 2b. Synchronize any legacy or pip-installed locations (e.g. Python Scripts directories)
# to prevent stale shadowing binaries from executing
$legacyDirs = @(
    (Join-Path $env:APPDATA "Python\Python312\Scripts"),
    (Join-Path $env:APPDATA "Python\Python311\Scripts"),
    (Join-Path $env:APPDATA "Python\Python310\Scripts"),
    (Join-Path $env:LOCALAPPDATA "Programs\Python\Python312\Scripts"),
    (Join-Path $env:LOCALAPPDATA "Programs\Python\Python311\Scripts"),
    (Join-Path $env:USERPROFILE ".local\bin")
)

foreach ($ld in $legacyDirs) {
    if (Test-Path $ld) {
        foreach ($b in $bins) {
            $targetPath = Join-Path $ld $b
            if (Test-Path $targetPath) {
                $src = Join-Path $repoRoot $b
                Deploy-BinarySafe -SourcePath $src -DestinationPath $targetPath -DisplayName "$b (synced legacy copy in $ld)"
            }
        }
    }
}

# Interceptor
$interceptorSrc = Join-Path $repoRoot "cchook\interceptor.exe"
if (-not (Test-Path $interceptorSrc)) {
    $interceptorSrc = Join-Path $repoRoot "interceptor.exe"
}
if (Test-Path $interceptorSrc) {
    Deploy-BinarySafe -SourcePath $interceptorSrc -DestinationPath (Join-Path $binDir "interceptor.exe") -DisplayName "interceptor.exe"
}

# 2c. BAP-1103: synchronize EVERY existing copy, wherever it lives. Earlier installers and `bap install`
# put binaries in %USERPROFILE%\bin, the workspace and user .claude\hooks folders, %ProgramData% and so on.
# Hooks and launchers run whichever copy they resolve, so a single stale copy silently keeps old (or
# developer-override) behavior. Only files that already exist are updated here; nothing new is created.
$syncSources = [ordered]@{}
foreach ($b in $bins) { $syncSources[$b] = (Join-Path $repoRoot $b) }
if (Test-Path $interceptorSrc) { $syncSources["interceptor.exe"] = $interceptorSrc }
$syncSources["cchook-interceptor.exe"] = $interceptorSrc

$syncDirs = New-Object System.Collections.Generic.List[string]
foreach ($d in @(
        (Join-Path $env:USERPROFILE "bin"),
        (Join-Path $env:USERPROFILE ".bap\bin"),
        (Join-Path $env:ProgramFiles "BAP\bin"),
        (Join-Path $env:ProgramData "BAP\bin"),
        (Join-Path $env:LOCALAPPDATA "BAP\bin"),
        (Join-Path $env:APPDATA "BAP\bin"),
        (Join-Path $env:USERPROFILE ".claude\hooks"),
        (Join-Path $repoRoot ".claude\hooks")
    )) { if ($d) { $syncDirs.Add($d) } }
foreach ($pd in ($env:PATH -split ';')) { if (-not [string]::IsNullOrWhiteSpace($pd)) { $syncDirs.Add($pd.Trim('"')) } }

$syncedDirs = @{}
$staleLeft = @()
foreach ($dir in $syncDirs) {
    $full = try { [System.IO.Path]::GetFullPath($dir) } catch { $null }
    if (-not $full -or $syncedDirs.ContainsKey($full.ToLowerInvariant())) { continue }
    $syncedDirs[$full.ToLowerInvariant()] = $true
    if (-not (Test-Path -LiteralPath $full -PathType Container)) { continue }
    if ($full.TrimEnd('\') -ieq $binDir.TrimEnd('\')) { continue }   # already deployed above
    # Only touch folders that really hold a BAP build; an unrelated tool's bap.exe on PATH is left alone.
    $holdsBap = $false
    foreach ($probe in @("bapedge.exe", "bap.exe", "bapmcp.exe")) {
        $probePath = Join-Path $full $probe
        if (Test-Path -LiteralPath $probePath -PathType Leaf) {
            $probeInfo = Get-BapBinaryInfo -Path $probePath
            if ($null -ne $probeInfo -and $probeInfo.component -eq "bapedge") { $holdsBap = $true; break }
        }
    }
    if (-not $holdsBap) { continue }
    foreach ($name in $syncSources.Keys) {
        $target = Join-Path $full $name
        $source = $syncSources[$name]
        if (-not (Test-Path -LiteralPath $target -PathType Leaf) -or -not (Test-Path -LiteralPath $source -PathType Leaf)) { continue }
        if ((Get-FileSha256Safe -Path $target) -eq (Get-FileSha256Safe -Path $source)) {
            Write-Host "  [=] $target already current" -ForegroundColor DarkGray
            continue
        }
        Deploy-BinarySafe -SourcePath $source -DestinationPath $target -DisplayName "$name (stale copy in $full)"
        if ((Get-FileSha256Safe -Path $target) -ne (Get-FileSha256Safe -Path $source)) { $staleLeft += $target }
    }
    # Best-effort cleanup of binaries rotated out of the way by Deploy-BinarySafe.
    Get-ChildItem -LiteralPath $full -Filter "*.exe.old.*" -File -ErrorAction SilentlyContinue |
        ForEach-Object { try { Remove-Item -LiteralPath $_.FullName -Force -ErrorAction Stop } catch { } }
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

# Optional Debugging & Session Review utilities (-Debug flag)
if ($Debug) {
    Write-Host ">>> Deploying BAP Debugging & Diagnostic Utilities (-Debug active)..." -ForegroundColor Cyan
    $debugFiles = @(
        "review_session.ps1",
        "review_session_impl.ps1",
        "session_calls.ps1",
        "review_session.bat",
        "review_session.sh",
        "watch_session.ps1",
        "watch_session.bat",
        "watch_session.sh",
        "verify_sts_obo_exchange.py",
        "verify_sts.bat",
        "verify_sts.sh",
        "check_stale_copies.ps1",
        "check_stale_copies.bat",
        "check_stale_copies.sh",
        "bap_doctor.ps1",
        "supervise_controlplane.ps1",
        "run_claude_scenarios.ps1"
    )
    foreach ($df in $debugFiles) {
        $src = Join-Path (Join-Path $repoRoot "scripts") $df
        if (-not (Test-Path $src)) {
            $src = Join-Path $repoRoot $df
        }
        if (-not (Test-Path -LiteralPath $src)) {
            $src = Join-Path (Join-Path $repoRoot 'bap') $df
        }
        if (Test-Path $src) {
            Copy-Item -Path $src -Destination (Join-Path $binDir $df) -Force
            Write-Host "  [+] Copied Debug Tool: $df" -ForegroundColor Green
        }
    }
} else {
    Write-Host "[*] Standard Production Mode: Debugging scripts omitted by default. (Pass -Debug to deploy review/watch/sts/stale-check tools)" -ForegroundColor DarkGray
}

# 3. Register PATH Environment Variable
Write-Host ">>> Registering $binDir in PATH..." -ForegroundColor Cyan
$targetScope = if ($useUserScope) { [System.EnvironmentVariableTarget]::User } else { [System.EnvironmentVariableTarget]::Machine }
$currentPath = [System.Environment]::GetEnvironmentVariable("Path", $targetScope)
$pathParts = if ([string]::IsNullOrWhiteSpace($currentPath)) { @() } else { $currentPath -split ';' }
$filteredParts = @($pathParts | Where-Object { $_ -ne $binDir -and -not [string]::IsNullOrWhiteSpace($_) })
$newPath = "$binDir;" + ($filteredParts -join ';')
if ($currentPath -ne $newPath) {
    [System.Environment]::SetEnvironmentVariable("Path", $newPath, $targetScope)
    Write-Host "[+] Prioritized $binDir at front of $(if ($useUserScope) { 'User' } else { 'System' }) PATH environment." -ForegroundColor Green
} else {
    Write-Host "[=] $binDir already at front of PATH." -ForegroundColor Gray
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
Deploy-BinarySafe -SourcePath $interceptorBin -DestinationPath (Join-Path $claudeHooksDir "interceptor.exe") -DisplayName "claude interceptor.exe"

$claudeSettingsPath = Join-Path $claudeHome "settings.json"
$claudeSettings = [ordered]@{
    hooks = [ordered]@{
        SessionStart     = @(@{ hooks = @(@{ type = "command"; command = (Join-Path $claudeHooksDir "interceptor.exe") }) })
        UserPromptSubmit = @(@{ hooks = @(@{ type = "command"; command = (Join-Path $claudeHooksDir "interceptor.exe") }) })
        PreToolUse       = @(@{ matcher = "*"; hooks = @(@{ type = "command"; command = (Join-Path $claudeHooksDir "interceptor.exe") }) })
        PostToolUse      = @(@{ matcher = "mcp__.*"; hooks = @(@{ type = "command"; command = (Join-Path $claudeHooksDir "interceptor.exe") }) })
        PostToolUseFailure = @(@{ matcher = "mcp__.*"; hooks = @(@{ type = "command"; command = (Join-Path $claudeHooksDir "interceptor.exe") }) })
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

# Also write global ~/.gemini/config/hooks.json for Antigravity (loaded directly when launched from menu)
$bapHooks | ConvertTo-Json -Depth 10 | Set-Content -Path (Join-Path $geminiConfigDir "hooks.json") -Encoding UTF8

# plugins.json (registers plugin globally)
$pluginsManifest = [ordered]@{
    entries = @(
        [ordered]@{
            path = "~/.gemini/config/plugins/bap-zero-trust"
        }
    )
}
$pluginsManifest | ConvertTo-Json -Depth 5 | Set-Content -Path (Join-Path $geminiConfigDir "plugins.json") -Encoding UTF8

# Update global ~/.gemini/config/config.json plugins map
$geminiMainConfigPath = Join-Path $geminiConfigDir "config.json"
if (Test-Path $geminiMainConfigPath) {
    try {
        $mainCfg = Get-Content $geminiMainConfigPath -Raw | ConvertFrom-Json
        $mainCfg.plugins = [ordered]@{ "bap-zero-trust" = [ordered]@{ enabled = $true } }
        $mainCfg | ConvertTo-Json -Depth 10 | Set-Content $geminiMainConfigPath -Encoding UTF8
    } catch {
        Write-Warning "Could not update config.json plugins map: $_"
    }
}

# Workspace-level .agents/hooks.json
$wsAgentsDir = Join-Path $repoRoot ".agents"
if (-not (Test-Path $wsAgentsDir)) {
    New-Item -ItemType Directory -Path $wsAgentsDir -Force | Out-Null
}
$bapHooks | ConvertTo-Json -Depth 10 | Set-Content -Path (Join-Path $wsAgentsDir "hooks.json") -Encoding UTF8

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
$agentsMdContent += @'

## BAP task authorization workflow

Use the session ID supplied by BAP. Submit ordinary supported inspection and
workspace edits normally: hooks evaluate policy and obtain eligible JIT grants.
An installed client with automatic grants disabled must request a grant first.
Shell commands must execute through `bapedge exec "<command>"` (`bapedge.exe` on
Windows); native Read/Write/Edit tools remain governed by their BAP hooks.

If BAP asks for authorization, run the suggested standalone command yourself:
`bapedge zsp authorize --session-id "<active-session-id>" --mission TASK_EXECUTION --goal "<task intent>" --actions "<canonical:action>" --resources workspace://current`
Use the actual session ID from hook context or the environment: PowerShell
`$env:BAP_SESSION_ID`, CMD `%BAP_SESSION_ID%`, POSIX shells `$BAP_SESSION_ID`.
Do not chain authorization with execution or dispatch dependent tools before it finishes.
Alternatively use `bap_request_task_grant` when that MCP tool is available.

Generic grants default to one use. For several ordinary workspace file edits,
request only `fs:file:write` with `--max-uses 25 --ttl 600s`; the signed policy
can narrow those ceilings. Do not mix Python, builds, deletion or publishing
into an edit grant. Running the created script requires a separate execution grant.
Read the granted actions, resources, remaining uses and expiry before relying on it.
Authorization itself does not spend the new grant. Duplicate callbacks for one
stable native tool-use ID spend once; a new tool call spends another edit use.

An expired/exhausted grant requires fresh policy authorization. If a newly issued
grant is immediately reported burned, report the hook defect and stop the loop;
do not keep minting grants or switch to shell writes to bypass a native denial.
If BAP returns a pending approval request, tell the human the request ID and exact
`bapedge zsp approve <request-id>` command for their own terminal, then wait for
approval before retrying. Never approve your own request or enable developer override.
Auto-approve cannot satisfy rules requiring separate human approval. Credential
and protected-policy denials must never be retried through another tool or shell.
'@
$agentsMdContent | Set-Content -Path (Join-Path $rulesDir "AGENTS.md") -Encoding UTF8

Write-Host "[+] Antigravity global plugin active in $bapPluginDir" -ForegroundColor Green

# 6. Native Agent Plugins Installation (BAP-806 Layer 1A)
Write-Host ">>> Deploying Native Agent Plugins (Claude Code & Copilot)..." -ForegroundColor Cyan
$pluginsSrc = Join-Path $repoRoot "plugins"
if (Test-Path $pluginsSrc) {
    # Workspace plugins
    $wsPlugins = Join-Path $repoRoot "plugins"
    Copy-Item -Path (Join-Path $pluginsSrc "*") -Destination (Join-Path $installDir "plugins") -Recurse -Force -ErrorAction SilentlyContinue
    Write-Host "[+] Native plugins deployed to $(Join-Path $installDir 'plugins')" -ForegroundColor Green
}

# 7. Display Transparent Defense-in-Depth Layer Architecture
$bapedgeBin = Join-Path $binDir "bapedge.exe"
if (Test-Path $bapedgeBin) {
    & $bapedgeBin plugin layers
}

# 8. BAP-1103: verify. Every copy found on this machine must now match the installed build; report
# any that could not be replaced (usually because a BAP process still holds the file open).
Write-Host ">>> Verifying installed copies..." -ForegroundColor Cyan
$expected = if ($null -ne $sourceInfo) { "$($sourceInfo.version) ($($sourceInfo.git_commit))" } else { "source build" }
foreach ($dir in $syncedDirs.Keys) {
    foreach ($name in @("bapedge.exe", "bap.exe")) {
        $p = Join-Path $dir $name
        if (-not (Test-Path -LiteralPath $p -PathType Leaf)) { continue }
        $info = Get-BapBinaryInfo -Path $p
        $label = if ($null -ne $info) { "$($info.version) ($($info.git_commit)) dev_overrides=$($info.allow_dev_overrides)" } else { "unreadable" }
        $ok = ((Get-FileSha256Safe -Path $p) -eq (Get-FileSha256Safe -Path (Join-Path $repoRoot $name)))
        Write-Host ("  [{0}] {1}  {2}" -f $(if ($ok) { "OK " } else { "OLD" }), $p, $label) -ForegroundColor $(if ($ok) { "Gray" } else { "Yellow" })
    }
}
if ($staleLeft.Count -gt 0) {
    Write-Warning "These copies could not be updated (stop running BAP processes and re-run this installer):"
    $staleLeft | ForEach-Object { Write-Warning "  $_" }
    Write-Host ">>> BAP Zero-Trust global deployment finished WITH STALE COPIES (expected: $expected)." -ForegroundColor Red
    exit 2
}

Write-Host ">>> BAP Zero-Trust Universal Global Deployment Complete!" -ForegroundColor Green

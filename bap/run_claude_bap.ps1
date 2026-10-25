# BAP Claude Code Transactional Zero-Trust Launcher
# ------------------------------------------------
# Features:
#   - Transactionally takes custody of .claude/settings.json and settings.local.json
#   - Preserves originals by same-directory rename
#   - Detached session guard/watchdog repairs BAP settings while active
#   - Watchdog restores originals if launcher is killed / terminal is closed
#   - Next launch performs stale-session recovery after machine/process crash
#   - Atomic recovery manifest + mirror
#   - Workspace mutex prevents concurrent BAP launchers
#   - ConfigChange hook blocks project/local settings changes inside Claude
#   - PreToolUse matcher "*" sends every tool call (including MCP tools) to BAP
#
# Typical use:
#   powershell -ExecutionPolicy Bypass -File .\bap-claude.ps1
#   powershell -ExecutionPolicy Bypass -File .\bap-claude.ps1 --server http://10.0.0.20:8080
#   powershell -ExecutionPolicy Bypass -File .\bap-claude.ps1 --model sonnet
#
# All arguments not consumed by BAP are forwarded to Claude Code.

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

# -----------------------------------------------------------------------------
# Manual argument parser.
# We intentionally do NOT use a param() block so arbitrary Claude CLI flags can
# pass through this launcher without PowerShell rejecting unknown parameters.
# -----------------------------------------------------------------------------

$Mode = 'Launcher'
$ServerUrl = $null
$ServerWasExplicit = $false
$ManifestArg = $null
$MutexArg = $null
$ParentPidArg = 0
$ParentStartTicksArg = [int64]0
$ClaudeArgs = @()

for ($i = 0; $i -lt $args.Count; $i++) {
    $a = [string]$args[$i]

    if ($a -eq '--bap-watchdog') {
        $Mode = 'Watchdog'
        continue
    }

    if ($a -eq '--bap-config-guard') {
        $Mode = 'ConfigGuard'
        continue
    }

    if ($a -eq '--bap-manifest') {
        if (($i + 1) -ge $args.Count) { throw 'Missing value for --bap-manifest' }
        $i++
        $ManifestArg = [string]$args[$i]
        continue
    }

    if ($a -eq '--bap-mutex') {
        if (($i + 1) -ge $args.Count) { throw 'Missing value for --bap-mutex' }
        $i++
        $MutexArg = [string]$args[$i]
        continue
    }

    if ($a -eq '--bap-parent-pid') {
        if (($i + 1) -ge $args.Count) { throw 'Missing value for --bap-parent-pid' }
        $i++
        $ParentPidArg = [int]$args[$i]
        continue
    }

    if ($a -eq '--bap-parent-start-ticks') {
        if (($i + 1) -ge $args.Count) { throw 'Missing value for --bap-parent-start-ticks' }
        $i++
        $ParentStartTicksArg = [int64]$args[$i]
        continue
    }

    if ($a -eq '--server' -or $a -eq '-ServerUrl') {
        if (($i + 1) -ge $args.Count) { throw "Missing value for $a" }
        $i++
        $ServerUrl = [string]$args[$i]
        $ServerWasExplicit = $true
        continue
    }

    if ($a -like '--server=*') {
        $ServerUrl = $a.Substring('--server='.Length)
        $ServerWasExplicit = $true
        continue
    }

    $ClaudeArgs += $a
}

# Fast internal hook mode. Claude's ConfigChange hook invokes this.
if ($Mode -eq 'ConfigGuard') {
    @{
        decision = 'block'
        reason   = 'BAP owns Claude project/local settings for this governed session.'
    } | ConvertTo-Json -Compress
    exit 0
}

$ScriptPath = $PSCommandPath
if ([string]::IsNullOrWhiteSpace($ScriptPath)) {
    if (-not [string]::IsNullOrWhiteSpace($MyInvocation.MyCommand.Path)) {
        $ScriptPath = $MyInvocation.MyCommand.Path
    } else {
        throw 'Unable to determine this script path.'
    }
}
$ScriptPath = [System.IO.Path]::GetFullPath($ScriptPath)

if (-not [string]::IsNullOrWhiteSpace($env:BAP_HOME) -and (Test-Path -LiteralPath $env:BAP_HOME)) {
    $BapHome = [System.IO.Path]::GetFullPath($env:BAP_HOME)
}
elseif (-not [string]::IsNullOrWhiteSpace($env:BAP_ORIGINAL_DIR) -and (Test-Path -LiteralPath $env:BAP_ORIGINAL_DIR)) {
    $BapHome = [System.IO.Path]::GetFullPath($env:BAP_ORIGINAL_DIR)
}
else {
    $BapHome = Split-Path -Parent $ScriptPath
}
$Utf8NoBom = [System.Text.UTF8Encoding]::new($false)

# -----------------------------------------------------------------------------
# Helpers
# -----------------------------------------------------------------------------

function Write-AtomicText {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Text
    )

    $dir = Split-Path -Parent $Path
    if (-not (Test-Path -LiteralPath $dir)) {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
    }

    $tmp = "$Path.tmp.$PID.$([Guid]::NewGuid().ToString('N'))"
    try {
        [System.IO.File]::WriteAllText($tmp, $Text, $Utf8NoBom)
        Move-Item -LiteralPath $tmp -Destination $Path -Force
    }
    finally {
        if (Test-Path -LiteralPath $tmp) {
            Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue
        }
    }
}

function Write-AtomicBytes {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][byte[]]$Bytes
    )

    $dir = Split-Path -Parent $Path
    if (-not (Test-Path -LiteralPath $dir)) {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
    }

    $tmp = "$Path.tmp.$PID.$([Guid]::NewGuid().ToString('N'))"
    try {
        [System.IO.File]::WriteAllBytes($tmp, $Bytes)
        Move-Item -LiteralPath $tmp -Destination $Path -Force
    }
    finally {
        if (Test-Path -LiteralPath $tmp) {
            Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue
        }
    }
}

function Write-JsonAtomic {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)]$Object
    )

    $json = $Object | ConvertTo-Json -Depth 20
    Write-AtomicText -Path $Path -Text $json
}

function Get-FileSha256 {
    param([Parameter(Mandatory = $true)][string]$Path)

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        return $null
    }

    try {
        $stream = [System.IO.File]::OpenRead($Path)
        try {
            $sha = [System.Security.Cryptography.SHA256]::Create()
            $bytes = $sha.ComputeHash($stream)
            return (-join ($bytes | ForEach-Object { $_.ToString('X2') }))
        } finally {
            $stream.Dispose()
        }
    } catch {
        return $null
    }
}

function Resolve-Binary {
    param(
        [string[]]$Paths,
        [string[]]$Commands
    )

    foreach ($p in $Paths) {
        if (-not [string]::IsNullOrWhiteSpace($p) -and (Test-Path -LiteralPath $p -PathType Leaf)) {
            return (Resolve-Path -LiteralPath $p).Path
        }
    }

    foreach ($name in $Commands) {
        if ([string]::IsNullOrWhiteSpace($name)) { continue }

        $cmd = Get-Command $name -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($null -ne $cmd) {
            if ($cmd.PSObject.Properties.Name -contains 'Source' -and -not [string]::IsNullOrWhiteSpace([string]$cmd.Source)) {
                return [string]$cmd.Source
            }
            if ($cmd.PSObject.Properties.Name -contains 'Path' -and -not [string]::IsNullOrWhiteSpace([string]$cmd.Path)) {
                return [string]$cmd.Path
            }
            return $name
        }
    }

    return $null
}

function Get-WorkspaceMutexName {
    param([Parameter(Mandatory = $true)][string]$Workspace)

    $normalized = [System.IO.Path]::GetFullPath($Workspace).TrimEnd('\').ToLowerInvariant()
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($normalized)
        $hash = $sha.ComputeHash($bytes)
        $hex = -join ($hash | ForEach-Object { $_.ToString('x2') })
        return "Local\BAP_Claude_$($hex.Substring(0, 24))"
    }
    finally {
        $sha.Dispose()
    }
}

function Acquire-BapMutex {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [int]$TimeoutMs = 0
    )

    $createdNew = $false
    $mutex = [System.Threading.Mutex]::new($false, $Name, [ref]$createdNew)
    $acquired = $false

    try {
        try {
            $acquired = $mutex.WaitOne($TimeoutMs)
        }
        catch [System.Threading.AbandonedMutexException] {
            # Previous owner died. We now own the abandoned mutex.
            $acquired = $true
        }

        if (-not $acquired) {
            $mutex.Dispose()
            return $null
        }

        return $mutex
    }
    catch {
        $mutex.Dispose()
        throw
    }
}

function Release-BapMutex {
    param($Mutex)

    if ($null -eq $Mutex) { return }

    try {
        $Mutex.ReleaseMutex()
    }
    catch {
        # Ignore release races during teardown.
    }

    try {
        $Mutex.Dispose()
    }
    catch {
    }
}

function Get-RecoveryMirrorPath {
    param([Parameter(Mandatory = $true)][string]$ManifestPath)

    return (Join-Path (Split-Path -Parent $ManifestPath) '.bap-lock.json')
}

function Write-RecoveryRecord {
    param(
        [Parameter(Mandatory = $true)]$Record,
        [Parameter(Mandatory = $true)][string]$ManifestPath
    )

    $mirror = Get-RecoveryMirrorPath -ManifestPath $ManifestPath

    # Two independently parseable copies. Either one can recover the workspace.
    Write-JsonAtomic -Path $ManifestPath -Object $Record
    Write-JsonAtomic -Path $mirror -Object $Record
}

function Read-RecoveryRecord {
    param([Parameter(Mandatory = $true)][string]$ManifestPath)

    $mirror = Get-RecoveryMirrorPath -ManifestPath $ManifestPath
    $errors = @()

    foreach ($candidate in @($ManifestPath, $mirror)) {
        if (-not (Test-Path -LiteralPath $candidate -PathType Leaf)) {
            continue
        }

        try {
            return (Get-Content -LiteralPath $candidate -Raw -Encoding UTF8 | ConvertFrom-Json)
        }
        catch {
            $errors += "$candidate : $($_.Exception.Message)"
        }
    }

    if ($errors.Count -gt 0) {
        throw "BAP recovery metadata exists but cannot be parsed.`n$($errors -join "`n")"
    }

    return $null
}

function Test-ProcessIdentity {
    param(
        [int]$ProcessId,
        [int64]$StartTicks
    )

    $p = Get-Process -Id $ProcessId -ErrorAction SilentlyContinue
    if ($null -eq $p) {
        return $false
    }

    try {
        return ($p.StartTime.ToUniversalTime().Ticks -eq $StartTicks)
    }
    catch {
        # If Windows denies StartTime access, PID existence is still the safer
        # assumption while the watchdog is already attached to this session.
        return $true
    }
}

function Invoke-BapSessionEnd {
    param([Parameter(Mandatory = $true)]$Record)

    if (-not [bool]$Record.session_active) {
        return
    }

    $ended = $false

    try {
        $edge = [string]$Record.bapedge_bin
        if (-not [string]::IsNullOrWhiteSpace($edge)) {
            $edgeResolved = Resolve-Binary -Paths @($edge) -Commands @($edge)
            if (-not [string]::IsNullOrWhiteSpace($edgeResolved)) {
                & $edgeResolved session-end `
                    --server ([string]$Record.server_url) `
                    --session-id ([string]$Record.session_id) *> $null

                if ($LASTEXITCODE -eq 0) {
                    $ended = $true
                }
            }
        }
    }
    catch {
        $ended = $false
    }

    if ($ended) {
        return
    }

    # Fallback for installations without bapedge.
    try {
        $curl = Resolve-Binary -Paths @() -Commands @('curl.exe')
        if ([string]::IsNullOrWhiteSpace($curl)) {
            return
        }

        $payload = @{
            session_id = [string]$Record.session_id
            reason     = 'BAP launcher/watchdog session teardown'
        } | ConvertTo-Json -Compress

        $curlArgs = @(
            '-s',
            '--max-time', '2',
            '--connect-timeout', '2'
        )

        if ([string]$Record.server_url -like 'https://*') {
            $curlArgs += '-k'
        }

        $curlArgs += @(
            '-X', 'POST',
            "$([string]$Record.server_url)/api/v1/sessions/end",
            '-H', 'Content-Type: application/json',
            '-d', $payload
        )

        & $curl @curlArgs *> $null
    }
    catch {
        # Session deregistration failure must never prevent local file recovery.
    }
}

function Restore-TrackedFile {
    param(
        [Parameter(Mandatory = $true)]$Entry,
        [string]$BapSettingsHash = $null,
        [switch]$ProjectSettings
    )

    $path = [string]$Entry.path
    $backup = [string]$Entry.backup
    $existed = [bool]$Entry.existed
    $originalHash = [string]$Entry.original_sha256

    if ($existed) {
        if (Test-Path -LiteralPath $backup -PathType Leaf) {
            # Backup is authoritative. Remove BAP/current file and atomically
            # rename the original back into its exact path.
            $retries = 10
            while ($retries -gt 0) {
                try {
                    if (Test-Path -LiteralPath $path) {
                        Remove-Item -LiteralPath $path -Force -ErrorAction Stop
                    }
                    Move-Item -LiteralPath $backup -Destination $path -Force -ErrorAction Stop
                    break
                }
                catch {
                    $retries--
                    if ($retries -le 0) {
                        throw
                    }
                    Start-Sleep -Milliseconds 150
                }
            }

            if (-not [string]::IsNullOrWhiteSpace($originalHash)) {
                $restoredHash = Get-FileSha256 -Path $path
                if ($restoredHash -ne $originalHash) {
                    throw "Restored file hash mismatch: $path"
                }
            }

            return $true
        }

        # The backup may already have been restored by a previous cleanup pass.
        if (Test-Path -LiteralPath $path -PathType Leaf) {
            if (-not [string]::IsNullOrWhiteSpace($originalHash)) {
                $currentHash = Get-FileSha256 -Path $path
                if ($currentHash -eq $originalHash) {
                    return $true
                }
            }
        }

        # Never destroy the only surviving copy when an expected backup vanished.
        Write-Warning "Cannot prove restoration of original file: $path"
        Write-Warning "Expected backup: $backup"
        return $false
    }

    # File did not exist before BAP. Exact pre-session restoration means it must
    # not remain after BAP relinquishes custody.
    if (Test-Path -LiteralPath $path) {
        Remove-Item -LiteralPath $path -Force
    }

    return $true
}

function Restore-BapState {
    param(
        [Parameter(Mandatory = $true)][string]$ManifestPath,
        [string]$Reason = 'cleanup'
    )

    $record = Read-RecoveryRecord -ManifestPath $ManifestPath
    if ($null -eq $record) {
        return $true
    }

    Write-Host "[*] Restoring BAP transaction: $Reason" -ForegroundColor Yellow

    # Best effort remote/session teardown first. Local restoration proceeds even
    # if the control plane is unavailable.
    Invoke-BapSessionEnd -Record $record

    $projectOk = $false
    $localOk = $false

    try {
        $projectOk = Restore-TrackedFile `
            -Entry $record.project_settings `
            -BapSettingsHash ([string]$record.bap_settings_sha256) `
            -ProjectSettings
    }
    catch {
        Write-Warning $_.Exception.Message
        $projectOk = $false
    }

    try {
        $localOk = Restore-TrackedFile -Entry $record.local_settings
    }
    catch {
        Write-Warning $_.Exception.Message
        $localOk = $false
    }

    # Workspace ephemeral files belong to the BAP session.
    foreach ($ephemeral in @(
        (Join-Path ([string]$record.workspace) '.bap-session.json'),
        (Join-Path ([string]$record.workspace) '.bap-prompt.txt')
    )) {
        if (Test-Path -LiteralPath $ephemeral) {
            Remove-Item -LiteralPath $ephemeral -Force -ErrorAction SilentlyContinue
        }
    }

    if (-not ($projectOk -and $localOk)) {
        Write-Warning 'BAP recovery is incomplete. Recovery metadata has been preserved.'
        return $false
    }

    $mirror = Get-RecoveryMirrorPath -ManifestPath $ManifestPath

    Remove-Item -LiteralPath $ManifestPath -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $mirror -Force -ErrorAction SilentlyContinue

    # Remove .claude only if BAP created it and it is now genuinely empty.
    if (-not [bool]$record.claude_dir_existed) {
        $claudeDir = [string]$record.claude_dir
        if (Test-Path -LiteralPath $claudeDir -PathType Container) {
            $children = @(Get-ChildItem -LiteralPath $claudeDir -Force -ErrorAction SilentlyContinue)
            if ($children.Count -eq 0) {
                Remove-Item -LiteralPath $claudeDir -Force -ErrorAction SilentlyContinue
            }
        }
    }

    Write-Host '[+] Original Claude settings restored.' -ForegroundColor Green
    return $true
}

function Repair-BapGuardedSettings {
    param([Parameter(Mandatory = $true)]$Record)

    if (-not [bool]$Record.swap_complete) {
        return
    }

    $state = [string]$Record.state
    if ($state -eq 'Cleaning' -or $state -eq 'Complete') {
        return
    }

    $projectPath = [string]$Record.project_settings.path
    $localPath = [string]$Record.local_settings.path
    $expectedHash = [string]$Record.bap_settings_sha256

    if ([string]::IsNullOrWhiteSpace([string]$Record.bap_settings_b64)) {
        return
    }

    $needsRepair = $false

    if (-not (Test-Path -LiteralPath $projectPath -PathType Leaf)) {
        $needsRepair = $true
    }
    else {
        try {
            $currentHash = Get-FileSha256 -Path $projectPath
            if ($currentHash -ne $expectedHash) {
                $needsRepair = $true
            }
        }
        catch {
            $needsRepair = $true
        }
    }

    if ($needsRepair) {
        $bytes = [Convert]::FromBase64String([string]$Record.bap_settings_b64)
        Write-AtomicBytes -Path $projectPath -Bytes $bytes
    }

    # settings.local.json outranks project settings. It was moved out of the
    # active precedence chain when the transaction began, so keep it absent.
    if (Test-Path -LiteralPath $localPath) {
        Remove-Item -LiteralPath $localPath -Force -ErrorAction SilentlyContinue
    }
}

function Test-TcpPort {
    param(
        [Parameter(Mandatory = $true)][string]$HostName,
        [Parameter(Mandatory = $true)][int]$Port,
        [int]$TimeoutMs = 700
    )

    $client = [System.Net.Sockets.TcpClient]::new()
    try {
        $iar = $client.BeginConnect($HostName, $Port, $null, $null)
        if (-not $iar.AsyncWaitHandle.WaitOne($TimeoutMs, $false)) {
            return $false
        }

        $client.EndConnect($iar)
        return $client.Connected
    }
    catch {
        return $false
    }
    finally {
        $client.Close()
    }
}

function Test-ControlPlaneHealth {
    param([Parameter(Mandatory = $true)][string]$Url)

    try {
        $curl = Resolve-Binary -Paths @() -Commands @('curl.exe')
        if ([string]::IsNullOrWhiteSpace($curl)) {
            return $false
        }

        $curlArgs = @(
            '-s',
            '--max-time', '3',
            '--connect-timeout', '2'
        )

        if ($Url -like 'https://*') {
            $curlArgs += '-k'
        }

        $curlArgs += @('-X', 'GET', "$Url/api/v1/health")

        $response = (& $curl @curlArgs 2>$null | Out-String)
        return ($response -match '(?i)\b(ok|healthy|ltd-service)\b')
    }
    catch {
        return $false
    }
}

function Get-ConfigServerUrl {
    param(
        [Parameter(Mandatory = $true)][string]$BapHome
    )

    $candidateHomes = @(
        (Get-Location).Path,
        $BapHome,
        $env:BAP_HOME,
        (Join-Path $env:USERPROFILE 'pyprj\bapltd'),
        (Join-Path $env:USERPROFILE '.bap'),
        (Join-Path $env:USERPROFILE 'bin')
    ) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) -and (Test-Path -LiteralPath $_) }

    $candidates = @()
    foreach ($h in $candidateHomes) {
        $candidates += (Join-Path $h '.bap\bap-config.json')
        $candidates += (Join-Path $h 'bap-config.json')
    }

    foreach ($cfg in $candidates) {
        if (-not (Test-Path -LiteralPath $cfg -PathType Leaf)) {
            continue
        }

        try {
            $obj = Get-Content -LiteralPath $cfg -Raw -Encoding UTF8 | ConvertFrom-Json
            if ($obj.PSObject.Properties.Name -contains 'controlplane_url') {
                $u = [string]$obj.controlplane_url
                if (-not [string]::IsNullOrWhiteSpace($u)) {
                    return $u
                }
            }
        }
        catch {
        }
    }

    return $null
}

function Start-BapWatchdog {
    param(
        [Parameter(Mandatory = $true)][string]$ManifestPath,
        [Parameter(Mandatory = $true)][string]$MutexName,
        [Parameter(Mandatory = $true)][int]$ParentPid,
        [Parameter(Mandatory = $true)][int64]$ParentStartTicks
    )

    $psExe = (Get-Process -Id $PID).Path

    # Start-Process joins ArgumentList items. Explicit quotes protect paths with
    # spaces under Windows PowerShell 5.1 as well as pwsh.
    $quotedScript = '"' + $ScriptPath.Replace('"', '""') + '"'
    $quotedManifest = '"' + $ManifestPath.Replace('"', '""') + '"'
    $quotedMutex = '"' + $MutexName.Replace('"', '""') + '"'

    $watchdogArgs = @(
        '-NoProfile',
        '-ExecutionPolicy', 'Bypass',
        '-File', $quotedScript,
        '--bap-watchdog',
        '--bap-manifest', $quotedManifest,
        '--bap-mutex', $quotedMutex,
        '--bap-parent-pid', [string]$ParentPid,
        '--bap-parent-start-ticks', [string]$ParentStartTicks
    )

    $p = Start-Process `
        -FilePath $psExe `
        -ArgumentList $watchdogArgs `
        -WindowStyle Hidden `
        -PassThru

    Start-Sleep -Milliseconds 150

    if ($p.HasExited) {
        throw 'BAP session watchdog failed to remain running. Refusing to launch Claude.'
    }

    return $p
}

function Assert-ClaudeArgsCannotBypassBap {
    param([string[]]$Arguments)

    $blocked = @(
        '^--settings(?:=|$)',
        '^--setting-sources(?:=|$)',
        '^--safe-mode$',
        '^--bare$',
        '^--restricted$',
        '^--bg$',
        '^--background$',
        '^--worktree(?:=|$)',
        '^-w$',
        '^--cloud$',
        '^--teleport$'
    )

    foreach ($arg in $Arguments) {
        foreach ($pattern in $blocked) {
            if ($arg -match $pattern) {
                throw "Claude argument '$arg' is disabled by the BAP launcher because it can bypass hooks, change the settings source, move execution outside the guarded workspace, or outlive the launcher."
            }
        }
    }
}

# -----------------------------------------------------------------------------
# Watchdog mode
# -----------------------------------------------------------------------------

if ($Mode -eq 'Watchdog') {
    if ([string]::IsNullOrWhiteSpace($ManifestArg)) { exit 91 }
    if ([string]::IsNullOrWhiteSpace($MutexArg)) { exit 92 }
    if ($ParentPidArg -le 0) { exit 93 }

    # Guard the active settings while ANY active launcher session is alive
    while ($true) {
        $r = $null
        try {
            $r = Read-RecoveryRecord -ManifestPath $ManifestArg
        }
        catch {
        }

        if ($null -eq $r) {
            break
        }

        if ($r.PSObject.Properties.Name -contains 'state') {
            $st = [string]$r.state
            if ($st -eq 'Cleaning' -or $st -eq 'Complete') {
                break
            }
        }

        $anyAlive = $false
        if ($r.PSObject.Properties.Name -contains 'active_sessions' -and $null -ne $r.active_sessions) {
            foreach ($s in $r.active_sessions) {
                $sessPid = [int]($s.launcher_pid)
                if ($sessPid -gt 0) {
                    $proc = Get-Process -Id $sessPid -ErrorAction SilentlyContinue
                    if ($null -ne $proc -and -not $proc.HasExited) {
                        $anyAlive = $true
                        break
                    }
                }
            }
        }
        elseif (Test-ProcessIdentity -ProcessId $ParentPidArg -StartTicks $ParentStartTicksArg) {
            $anyAlive = $true
        }

        if (-not $anyAlive) {
            break
        }

        try {
            Repair-BapGuardedSettings -Record $r
        }
        catch {
        }

        Start-Sleep -Milliseconds 750
    }

    # Give a graceful parent teardown a moment to finish its own restoration.
    Start-Sleep -Milliseconds 500

    $wdMutex = Acquire-BapMutex -Name $MutexArg -TimeoutMs 15000
    if ($null -eq $wdMutex) {
        exit 94
    }

    try {
        if ((Test-Path -LiteralPath $ManifestArg) -or
            (Test-Path -LiteralPath (Get-RecoveryMirrorPath -ManifestPath $ManifestArg))) {

            $r = Read-RecoveryRecord -ManifestPath $ManifestArg
            $stillAlive = $false
            if ($null -ne $r -and $r.PSObject.Properties.Name -contains 'active_sessions' -and $null -ne $r.active_sessions) {
                foreach ($s in $r.active_sessions) {
                    $sessPid = [int]($s.launcher_pid)
                    if ($sessPid -gt 0) {
                        $proc = Get-Process -Id $sessPid -ErrorAction SilentlyContinue
                        if ($null -ne $proc -and -not $proc.HasExited) {
                            $stillAlive = $true
                            break
                        }
                    }
                }
            }

            if (-not $stillAlive) {
                [void](Restore-BapState `
                    -ManifestPath $ManifestArg `
                    -Reason 'all launchers terminated')
            }
        }
    }
    catch {
        exit 95
    }
    finally {
        Release-BapMutex -Mutex $wdMutex
    }

    exit 0
}

# -----------------------------------------------------------------------------
# Main launcher
# -----------------------------------------------------------------------------

$Workspace = [System.IO.Path]::GetFullPath((Get-Location).Path)
$ClaudeDir = Join-Path $Workspace '.claude'
$ManifestPath = Join-Path $ClaudeDir '.bap-recovery.json'
$MirrorPath = Get-RecoveryMirrorPath -ManifestPath $ManifestPath
$MutexName = Get-WorkspaceMutexName -Workspace $Workspace
$SessionId = "sess-claude-$([Guid]::NewGuid().ToString('N'))"
$parentProcess = Get-Process -Id $PID
$ParentStartTicks = $parentProcess.StartTime.ToUniversalTime().Ticks
$PowerShellExe = $parentProcess.Path

$RecoveryRecord = $null
$TransactionPrepared = $false
$ExitCode = 0
$isSecondarySession = $false
$BapEdgeBin = $null
$InterceptorBin = $null

$hadSimpleEnv = Test-Path Env:\CLAUDE_CODE_SIMPLE
$oldSimpleEnv = $env:CLAUDE_CODE_SIMPLE
$hadSafeModeEnv = Test-Path Env:\CLAUDE_CODE_SAFE_MODE
$oldSafeModeEnv = $env:CLAUDE_CODE_SAFE_MODE
$hadBapServerEnv = Test-Path Env:\BAP_SERVER_URL
$oldBapServerEnv = $env:BAP_SERVER_URL
$hadBapSessionEnv = Test-Path Env:\BAP_SESSION_ID
$oldBapSessionEnv = $env:BAP_SESSION_ID

try {
    try {
        $Host.UI.RawUI.WindowTitle = 'Claude Code (Governed by BAP Zero-Trust)'
    }
    catch {
    }

    Write-Host '==============================================================================='
    Write-Host '      CLAUDE CODE - BOUNDED AUTHORITY PLANE (BAP) GOVERNANCE LAUNCHER'
    Write-Host '==============================================================================='
    Write-Host "[*] Working Directory: $Workspace"
    Write-Host ''

    # -------------------------------------------------------------------------
    # 1. Acquire transient workspace lock to coordinate multi-session custody.
    # -------------------------------------------------------------------------

    $coordMutex = Acquire-BapMutex -Name $MutexName -TimeoutMs 5000
    if ($null -eq $coordMutex) {
        throw 'Could not acquire workspace coordination lock within 5 seconds.'
    }

    try {
        if ((Test-Path -LiteralPath $ManifestPath) -or (Test-Path -LiteralPath $MirrorPath)) {
            $existingRecord = Read-RecoveryRecord -ManifestPath $ManifestPath
            if ($null -ne $existingRecord) {
                $aliveSessions = @()
                if ($existingRecord.PSObject.Properties.Name -contains 'active_sessions' -and $null -ne $existingRecord.active_sessions) {
                    foreach ($s in $existingRecord.active_sessions) {
                        $sessPid = [int]($s.launcher_pid)
                        if ($sessPid -gt 0) {
                            $pProc = Get-Process -Id $sessPid -ErrorAction SilentlyContinue
                            if ($null -ne $pProc -and -not $pProc.HasExited) {
                                $aliveSessions += $s
                            }
                        }
                    }
                }
                elseif ($existingRecord.PSObject.Properties.Name -contains 'launcher_pid' -and $existingRecord.launcher_pid -gt 0) {
                    $legacyPid = [int]($existingRecord.launcher_pid)
                    $pProc = Get-Process -Id $legacyPid -ErrorAction SilentlyContinue
                    if ($null -ne $pProc -and -not $pProc.HasExited) {
                        $aliveSessions += [ordered]@{
                            launcher_pid         = $legacyPid
                            launcher_start_ticks = [int64]($existingRecord.launcher_start_ticks)
                            session_id           = [string]($existingRecord.session_id)
                        }
                    }
                }

                if ($aliveSessions.Count -gt 0) {
                    # Join existing active BAP-governed workspace!
                    $isSecondarySession = $true
                    $existingRecord.active_sessions = @($aliveSessions) + @([ordered]@{
                        launcher_pid         = [int]$PID
                        launcher_start_ticks = [int64]$ParentStartTicks
                        session_id           = [string]$SessionId
                    })
                    $existingRecord.state = 'Active'
                    Write-RecoveryRecord -Record $existingRecord -ManifestPath $ManifestPath
                    $RecoveryRecord = $existingRecord
                    $TransactionPrepared = $true
                    Write-Host "[+] Joined active BAP-governed workspace ($($existingRecord.active_sessions.Count) active Claude sessions)." -ForegroundColor Green
                }
                else {
                    Write-Host '[!] Previous BAP transaction detected with no surviving processes. Running recovery...' -ForegroundColor Yellow
                    $recovered = Restore-BapState `
                        -ManifestPath $ManifestPath `
                        -Reason 'stale session detected at next launch'

                    if (-not $recovered) {
                        throw 'Stale BAP session could not be safely restored. Refusing to start a new governed session.'
                    }
                }
            }
        }

        # Refuse to guess if backup files exist with no recovery metadata.
        if (-not $isSecondarySession -and (Test-Path -LiteralPath $ClaudeDir -PathType Container)) {
            $orphans = @(Get-ChildItem -LiteralPath $ClaudeDir -Force -File -ErrorAction SilentlyContinue |
                Where-Object { $_.Name -like '*.bap-backup-*' })

            if ($orphans.Count -gt 0) {
                $names = $orphans.FullName -join "`n  "
                throw "Orphaned BAP backup file(s) exist without recovery metadata. Refusing to guess which copy is authoritative:`n  $names"
            }
        }
    }
    finally {
        Release-BapMutex -Mutex $coordMutex
    }

    # -------------------------------------------------------------------------
    # 3. Resolve BAP server.
    # -------------------------------------------------------------------------

    # Backward-compatible convenience: first forwarded URL can be the server.
    if (-not $ServerWasExplicit -and $ClaudeArgs.Count -gt 0 -and
        ([string]$ClaudeArgs[0] -match '^https?://')) {

        $ServerUrl = [string]$ClaudeArgs[0]
        if ($ClaudeArgs.Count -gt 1) {
            $ClaudeArgs = @($ClaudeArgs[1..($ClaudeArgs.Count - 1)])
        }
        else {
            $ClaudeArgs = @()
        }

        $ServerWasExplicit = $true
    }

    if ([string]::IsNullOrWhiteSpace($ServerUrl)) {
        $ServerUrl = $env:BAP_SERVER_URL
    }

    if ([string]::IsNullOrWhiteSpace($ServerUrl)) {
        $ServerUrl = Get-ConfigServerUrl -BapHome $BapHome
    }

    if ([string]::IsNullOrWhiteSpace($ServerUrl)) {
        $ServerUrl = 'https://localhost:8443'
    }

    $ServerUrl = $ServerUrl.TrimEnd('/')

    $canPrompt = (-not $ServerWasExplicit) -and `
                 ($ClaudeArgs.Count -eq 0) -and `
                 [Environment]::UserInteractive -and `
                 (-not [Console]::IsInputRedirected)

    if ($canPrompt) {
        Write-Host "Current Target Server: $ServerUrl"
        $entered = Read-Host "Linux Server URL [ENTER = $ServerUrl]"
        if (-not [string]::IsNullOrWhiteSpace($entered)) {
            $ServerUrl = $entered.Trim().TrimEnd('/')
        }
    }

    $serverUri = [Uri]$ServerUrl

    # -------------------------------------------------------------------------
    # 4. Start/check local control plane when applicable.
    # -------------------------------------------------------------------------

    Write-Host ''
    Write-Host "[*] Checking BAP Control Plane at $ServerUrl ..."

    $isLocalHost = @('localhost', '127.0.0.1', '::1') -contains $serverUri.Host

    $candidateHomes = @(
        $BapHome,
        $env:BAP_HOME,
        (Join-Path $env:USERPROFILE 'pyprj\bapltd'),
        (Join-Path $env:USERPROFILE '.bap'),
        (Join-Path $env:USERPROFILE 'bin')
    ) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) -and (Test-Path -LiteralPath $_) }

    $cpPaths = @()
    $edgePaths = @()
    $interceptorPaths = @()
    foreach ($h in $candidateHomes) {
        $cpPaths += (Join-Path $h 'dist\windows-amd64\controlplane\bapcontrolplane.exe')
        $cpPaths += (Join-Path $h 'dist\windows-amd64\bapcontrolplane.exe')
        $cpPaths += (Join-Path $h 'bap-controlplane\bapcontrolplane.exe')

        $edgePaths += (Join-Path $h 'dist\windows-amd64\claude-client\bapedge.exe')
        $edgePaths += (Join-Path $h 'dist\windows-amd64\bapedge.exe')
        $edgePaths += (Join-Path $h 'bapedge.exe')
        $edgePaths += (Join-Path $h 'bin\bapedge.exe')

        $interceptorPaths += (Join-Path $h 'dist\windows-amd64\claude-client\cchook\interceptor.exe')
        $interceptorPaths += (Join-Path $h 'dist\windows-amd64\cchook-interceptor.exe')
        $interceptorPaths += (Join-Path $h 'interceptor.exe')
        $interceptorPaths += (Join-Path $h 'bin\interceptor.exe')
        $interceptorPaths += (Join-Path $h 'cchook\interceptor.exe')
    }

    if ($isLocalHost) {
        $listening = Test-TcpPort -HostName $serverUri.Host -Port $serverUri.Port

        if (-not $listening) {
            $controlPlane = Resolve-Binary `
                -Paths $cpPaths `
                -Commands @('bapcontrolplane.exe')

            if (-not [string]::IsNullOrWhiteSpace($controlPlane)) {
                Write-Host '[*] Launching local BAP Control Plane...'

                $cpArgs = @(
                    '-port', [string]$serverUri.Port,
                    '-ttl', '30',
                    '-trust-domain', 'bap.internal'
                )

                if ($serverUri.Scheme -eq 'https') {
                    $cpArgs += '-https'
                }

                Start-Process `
                    -FilePath $controlPlane `
                    -ArgumentList $cpArgs `
                    -WindowStyle Hidden | Out-Null

                Start-Sleep -Seconds 2
            }
            else {
                Write-Warning 'Local control plane is not listening and bapcontrolplane.exe was not found.'
            }
        }
    }

    if (Test-ControlPlaneHealth -Url $ServerUrl) {
        Write-Host '[+] SUCCESS: Connected to BAP Control Plane.' -ForegroundColor Green
    }
    else {
        Write-Warning "Could not reach $ServerUrl/api/v1/health."
        Write-Warning 'Continuing only if the local edge/interceptor can enforce Cedar policy.'
    }

    # -------------------------------------------------------------------------
    # 5. Resolve BAP edge + interceptor.
    # -------------------------------------------------------------------------

    $BapEdgeBin = Resolve-Binary `
        -Paths $edgePaths `
        -Commands @('bapedge.exe')

    $InterceptorBin = Resolve-Binary `
        -Paths $interceptorPaths `
        -Commands @('interceptor.exe')

    if ([string]::IsNullOrWhiteSpace($InterceptorBin)) {
        throw 'BAP interceptor.exe was not found. Refusing to start Claude without the policy enforcement hook.'
    }

    if (-not [string]::IsNullOrWhiteSpace($BapEdgeBin)) {
        try {
            & $BapEdgeBin config set --server $ServerUrl *> $null
        }
        catch {
            Write-Warning 'Unable to persist server URL through bapedge config.'
        }
    }

    # -------------------------------------------------------------------------
    # 6. Reject Claude modes that can bypass/outlive this project-hook custody.
    # -------------------------------------------------------------------------

    Assert-ClaudeArgsCannotBypassBap -Arguments $ClaudeArgs

    # These environment modes also suppress normal hooks/customization.
    Remove-Item Env:\CLAUDE_CODE_SIMPLE -ErrorAction SilentlyContinue
    Remove-Item Env:\CLAUDE_CODE_SAFE_MODE -ErrorAction SilentlyContinue

    if (-not $isSecondarySession) {
        # -------------------------------------------------------------------------
        # 7. Prepare transactional settings custody (primary session).
        # -------------------------------------------------------------------------

        $ClaudeDirExisted = Test-Path -LiteralPath $ClaudeDir -PathType Container
        if (-not $ClaudeDirExisted) {
            New-Item -ItemType Directory -Path $ClaudeDir -Force | Out-Null
        }

        $ProjectSettings = Join-Path $ClaudeDir 'settings.json'
        $LocalSettings = Join-Path $ClaudeDir 'settings.local.json'

        $ProjectBackup = "$ProjectSettings.bap-backup-$SessionId"
        $LocalBackup = "$LocalSettings.bap-backup-$SessionId"

        $ProjectExisted = Test-Path -LiteralPath $ProjectSettings -PathType Leaf
        $LocalExisted = Test-Path -LiteralPath $LocalSettings -PathType Leaf

        $ProjectOriginalHash = if ($ProjectExisted) { Get-FileSha256 -Path $ProjectSettings } else { $null }
        $LocalOriginalHash = if ($LocalExisted) { Get-FileSha256 -Path $LocalSettings } else { $null }

        $RecoveryRecord = [ordered]@{
            version               = 2
            session_id            = $SessionId
            state                 = 'Prepared'
            workspace             = $Workspace
            claude_dir            = $ClaudeDir
            claude_dir_existed    = [bool]$ClaudeDirExisted
            launcher_pid          = [int]$PID
            launcher_start_ticks  = [int64]$ParentStartTicks
            watchdog_pid          = 0
            server_url            = $ServerUrl
            bapedge_bin           = $BapEdgeBin
            interceptor_bin       = $InterceptorBin
            session_active        = $false
            swap_started          = $false
            swap_complete         = $false
            bap_settings_sha256   = $null
            bap_settings_b64      = $null
            created_utc           = [DateTime]::UtcNow.ToString('o')
            active_sessions       = @(
                [ordered]@{
                    launcher_pid         = [int]$PID
                    launcher_start_ticks = [int64]$ParentStartTicks
                    session_id           = [string]$SessionId
                }
            )

            project_settings = [ordered]@{
                path            = $ProjectSettings
                existed         = [bool]$ProjectExisted
                backup          = $ProjectBackup
                original_sha256 = $ProjectOriginalHash
            }

            local_settings = [ordered]@{
                path            = $LocalSettings
                existed         = [bool]$LocalExisted
                backup          = $LocalBackup
                original_sha256 = $LocalOriginalHash
            }
        }

        # Manifest exists BEFORE the first rename. Any interruption from this point
        # forward is recoverable.
        Write-RecoveryRecord -Record $RecoveryRecord -ManifestPath $ManifestPath
        $TransactionPrepared = $true

        $RecoveryRecord.swap_started = $true
        $RecoveryRecord.state = 'Swapping'
        Write-RecoveryRecord -Record $RecoveryRecord -ManifestPath $ManifestPath

        if ($ProjectExisted) {
            Move-Item -LiteralPath $ProjectSettings -Destination $ProjectBackup
        }

        if ($LocalExisted) {
            Move-Item -LiteralPath $LocalSettings -Destination $LocalBackup
        }

        # -------------------------------------------------------------------------
        # 8. Install BAP-only project settings.
        #
        # Exec-form hooks are used so interceptor.exe is spawned directly with no
        # shell quoting ambiguity.
        # -------------------------------------------------------------------------

        $InterceptorHook = [ordered]@{
            type    = 'command'
            command = $InterceptorBin
            args    = @()
        }

        $ConfigGuardHook = [ordered]@{
            type    = 'command'
            command = $PowerShellExe
            args    = @(
                '-NoProfile',
                '-ExecutionPolicy', 'Bypass',
                '-File', $ScriptPath,
                '--bap-config-guard'
            )
        }

        $BapClaudeSettings = [ordered]@{
            disableAllHooks = $false

            hooks = [ordered]@{
                SessionStart = @(
                    [ordered]@{
                        hooks = @($InterceptorHook)
                    }
                )

                UserPromptSubmit = @(
                    [ordered]@{
                        hooks = @($InterceptorHook)
                    }
                )

                PreToolUse = @(
                    [ordered]@{
                        matcher = '*'
                        hooks   = @($InterceptorHook)
                    }
                )

                SessionEnd = @(
                    [ordered]@{
                        hooks = @($InterceptorHook)
                    }
                )

                ConfigChange = @(
                    [ordered]@{
                        matcher = 'project_settings|local_settings'
                        hooks   = @($ConfigGuardHook)
                    }
                )
            }
        }

        $BapSettingsJson = $BapClaudeSettings | ConvertTo-Json -Depth 20
        Write-AtomicText -Path $ProjectSettings -Text $BapSettingsJson

        # Validate the exact file Claude will read.
        [void](Get-Content -LiteralPath $ProjectSettings -Raw -Encoding UTF8 | ConvertFrom-Json)

        $BapSettingsBytes = [System.IO.File]::ReadAllBytes($ProjectSettings)
        $BapSettingsHash = Get-FileSha256 -Path $ProjectSettings

        $RecoveryRecord.bap_settings_sha256 = $BapSettingsHash
        $RecoveryRecord.bap_settings_b64 = [Convert]::ToBase64String($BapSettingsBytes)
        $RecoveryRecord.swap_complete = $true
        $RecoveryRecord.state = 'Swapped'
        Write-RecoveryRecord -Record $RecoveryRecord -ManifestPath $ManifestPath

        Write-Host '[+] BAP now owns Claude project settings for this session.' -ForegroundColor Green
        if ($ProjectExisted) {
            Write-Host "[*] Original project settings: $ProjectBackup"
        }
        if ($LocalExisted) {
            Write-Host "[*] Original local settings  : $LocalBackup"
        }

        # -------------------------------------------------------------------------
        # 9. Start detached session guard BEFORE enrollment/Claude.
        # -------------------------------------------------------------------------

        $watchdog = Start-BapWatchdog `
            -ManifestPath $ManifestPath `
            -MutexName $MutexName `
            -ParentPid $PID `
            -ParentStartTicks $ParentStartTicks

        $RecoveryRecord.watchdog_pid = [int]$watchdog.Id
        $RecoveryRecord.state = 'Guarded'
        Write-RecoveryRecord -Record $RecoveryRecord -ManifestPath $ManifestPath

        Write-Host "[+] Session guard active (PID $($watchdog.Id))." -ForegroundColor Green
    }

    # -------------------------------------------------------------------------
    # 10. BAP session preflight.
    # -------------------------------------------------------------------------

    $env:BAP_SESSION_ID = $SessionId
    $env:BAP_SERVER_URL = $ServerUrl

    if (-not [string]::IsNullOrWhiteSpace($BapEdgeBin)) {
        & $BapEdgeBin session-start `
            --server $ServerUrl `
            --session-id $SessionId `
            --app-id 'claude-code'

        $sessionRc = $LASTEXITCODE

        if ($sessionRc -eq 2) {
            $ExitCode = 2
            throw 'BAP policy denied Claude Code session startup.'
        }

        if ($sessionRc -ne 0) {
            $ExitCode = $sessionRc
            throw "BAP session-start failed with exit code $sessionRc. Refusing to launch Claude un-enrolled."
        }
    }
    else {
        Write-Warning 'bapedge.exe was not found. Using local session descriptor fallback.'

        $localSession = [ordered]@{
            session_id = $SessionId
            server_url = $ServerUrl
            user       = $env:USERNAME
            hostname   = $env:COMPUTERNAME
        } | ConvertTo-Json -Depth 5

        Write-AtomicText `
            -Path (Join-Path $Workspace '.bap-session.json') `
            -Text $localSession
    }

    $RecoveryRecord.session_active = $true
    $RecoveryRecord.state = 'SessionActive'
    Write-RecoveryRecord -Record $RecoveryRecord -ManifestPath $ManifestPath

    # -------------------------------------------------------------------------
    # 11. Resolve Claude executable.
    # -------------------------------------------------------------------------

    $ClaudeCommand = $null

    foreach ($candidate in @('claude-code.cmd', 'claude.cmd', 'claude.exe', 'claude')) {
        $cmd = Get-Command $candidate -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($null -ne $cmd) {
            # Calling the command name lets PowerShell correctly invoke .cmd
            # shims as well as native executables.
            $ClaudeCommand = $candidate
            break
        }
    }

    if ([string]::IsNullOrWhiteSpace($ClaudeCommand)) {
        $ExitCode = 11
        throw 'Claude Code executable was not found (claude-code.cmd / claude.cmd / claude.exe / claude).'
    }

    Write-Host ''
    Write-Host '=============================================================================='
    Write-Host '  CLAUDE CODE IS NOW GOVERNED BY BAP ZERO-TRUST'
    Write-Host '=============================================================================='
    Write-Host "  Target Control Plane : $ServerUrl"
    Write-Host "  Active Session ID    : $SessionId"
    Write-Host "  User Identity        : $env:USERNAME on $env:COMPUTERNAME"
    Write-Host "  Policy Hook          : $InterceptorBin"
    Write-Host '  PreToolUse Coverage  : ALL tools (*)'
    Write-Host '  Settings Custody     : Transactional BAP ownership'
    Write-Host "  Session Guard PID    : $($watchdog.Id)"
    Write-Host '  Crash Recovery       : Watchdog + next-launch recovery'
    Write-Host '=============================================================================='
    Write-Host ''

    # -------------------------------------------------------------------------
    # 12. Launch Claude.
    # -------------------------------------------------------------------------

    $RecoveryRecord.state = 'ClaudeRunning'
    Write-RecoveryRecord -Record $RecoveryRecord -ManifestPath $ManifestPath

    & $ClaudeCommand @ClaudeArgs

    $claudeRc = $LASTEXITCODE
    $ExitCode = if ($null -eq $claudeRc) { 0 } else { [int]$claudeRc }

    Write-Host ''
    Write-Host "[*] Claude Code exited with code $ExitCode."
}
catch {
    if ($ExitCode -eq 0) {
        $ExitCode = 1
    }

    Write-Host ''
    Write-Host "[-] $($_.Exception.Message)" -ForegroundColor Red
}
finally {
    # Gracefully notify the BAP control plane that this session has ended
    if (-not [string]::IsNullOrWhiteSpace($BapEdgeBin) -and -not [string]::IsNullOrWhiteSpace($ServerUrl) -and -not [string]::IsNullOrWhiteSpace($SessionId)) {
        & $BapEdgeBin session-end --server $ServerUrl --session-id $SessionId 2>$null
    }

    # Acquire transient lock for multi-session reference-counted teardown
    $teardownMutex = Acquire-BapMutex -Name $MutexName -TimeoutMs 5000
    try {
        if ($TransactionPrepared -and
            ((Test-Path -LiteralPath $ManifestPath) -or (Test-Path -LiteralPath $MirrorPath))) {

            $cleanupRecord = Read-RecoveryRecord -ManifestPath $ManifestPath
            if ($null -ne $cleanupRecord) {
                $survivingSessions = @()
                if ($cleanupRecord.PSObject.Properties.Name -contains 'active_sessions' -and $null -ne $cleanupRecord.active_sessions) {
                    foreach ($s in $cleanupRecord.active_sessions) {
                        $sessPid = [int]($s.launcher_pid)
                        if ($sessPid -ne $PID -and $sessPid -gt 0) {
                            $pProc = Get-Process -Id $sessPid -ErrorAction SilentlyContinue
                            if ($null -ne $pProc -and -not $pProc.HasExited) {
                                $survivingSessions += $s
                            }
                        }
                    }
                }

                if ($survivingSessions.Count -eq 0) {
                    # Terminate the watchdog process first so it does not compete for settings.json
                    if ($cleanupRecord.PSObject.Properties.Name -contains 'watchdog_pid' -and $cleanupRecord.watchdog_pid -gt 0) {
                        $wdPid = [int]($cleanupRecord.watchdog_pid)
                        $wdProc = Get-Process -Id $wdPid -ErrorAction SilentlyContinue
                        if ($null -ne $wdProc -and -not $wdProc.HasExited) {
                            Stop-Process -Id $wdPid -Force -ErrorAction SilentlyContinue
                        }
                    }

                    # No other active sessions in this workspace; authoritative restoration
                    $cleanupRecord.state = 'Cleaning'
                    Write-RecoveryRecord -Record $cleanupRecord -ManifestPath $ManifestPath

                    try {
                        $restored = Restore-BapState `
                            -ManifestPath $ManifestPath `
                            -Reason 'normal launcher teardown'

                        if (-not $restored -and $ExitCode -eq 0) {
                            $ExitCode = 20
                        }
                    }
                    catch {
                        Write-Warning "BAP restoration failed: $($_.Exception.Message)"
                        if ($ExitCode -eq 0) {
                            $ExitCode = 20
                        }
                    }
                }
                else {
                    $cleanupRecord.active_sessions = @($survivingSessions)
                    Write-RecoveryRecord -Record $cleanupRecord -ManifestPath $ManifestPath
                    Write-Host "[*] Claude session closed. Other BAP sessions ($($survivingSessions.Count)) remain active in this workspace." -ForegroundColor Cyan
                }
            }
        }
    }
    finally {
        if ($null -ne $teardownMutex) {
            Release-BapMutex -Mutex $teardownMutex
        }
    }

    if ($hadBapSessionEnv) {
        $env:BAP_SESSION_ID = $oldBapSessionEnv
    }
    else {
        Remove-Item Env:\BAP_SESSION_ID -ErrorAction SilentlyContinue
    }

    if ($hadBapServerEnv) {
        $env:BAP_SERVER_URL = $oldBapServerEnv
    }
    else {
        Remove-Item Env:\BAP_SERVER_URL -ErrorAction SilentlyContinue
    }

    if ($hadSimpleEnv) {
        $env:CLAUDE_CODE_SIMPLE = $oldSimpleEnv
    }
    else {
        Remove-Item Env:\CLAUDE_CODE_SIMPLE -ErrorAction SilentlyContinue
    }

    if ($hadSafeModeEnv) {
        $env:CLAUDE_CODE_SAFE_MODE = $oldSafeModeEnv
    }
    else {
        Remove-Item Env:\CLAUDE_CODE_SAFE_MODE -ErrorAction SilentlyContinue
    }
}

if ($ExitCode -eq 0) {
    Write-Host '[+] BAP session cleanly closed; prior Claude settings are back in place.' -ForegroundColor Green
}
else {
    Write-Host "[*] BAP launcher exiting with code $ExitCode."
}

exit $ExitCode
